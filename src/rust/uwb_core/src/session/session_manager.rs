// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::BTreeMap;

use log::{debug, error, warn};
use tokio::sync::{mpsc, oneshot};

use crate::session::error::{Error, Result};
use crate::session::params::AppConfigParams;
use crate::session::uwb_session::{Response as SessionResponse, ResponseSender, UwbSession};
use crate::uci::notification::{SessionNotification as UciSessionNotification, SessionRangeData};
use crate::uci::params::{
    Controlee, SessionId, SessionState, SessionType, UpdateMulticastListAction,
};
use crate::uci::uci_manager::UciManager;

const MAX_SESSION_COUNT: usize = 5;

/// The SessionManager organizes the state machine of the existing UWB ranging sessions, sends
/// the session-related requests to the UciManager, and handles the session notifications from the
/// UciManager.
/// Using the actor model, SessionManager delegates the requests to SessionManagerActor.
pub(crate) struct SessionManager {
    cmd_sender: mpsc::UnboundedSender<(SessionCommand, ResponseSender)>,
}

impl SessionManager {
    pub fn new<T: UciManager>(
        uci_manager: T,
        uci_notf_receiver: mpsc::UnboundedReceiver<UciSessionNotification>,
    ) -> Self {
        let (cmd_sender, cmd_receiver) = mpsc::unbounded_channel();
        let mut actor = SessionManagerActor::new(cmd_receiver, uci_manager, uci_notf_receiver);
        tokio::spawn(async move { actor.run().await });

        Self { cmd_sender }
    }

    async fn init_session(
        &mut self,
        session_id: SessionId,
        session_type: SessionType,
        params: AppConfigParams,
        range_data_sender: mpsc::UnboundedSender<SessionRangeData>,
    ) -> Result<()> {
        let result = self
            .send_cmd(SessionCommand::InitSession {
                session_id,
                session_type,
                params,
                range_data_sender,
            })
            .await
            .map(|_| ());
        if result.is_err() && result != Err(Error::DuplicatedSessionId(session_id)) {
            let _ = self.deinit_session(session_id).await;
        }
        result
    }

    async fn deinit_session(&mut self, session_id: SessionId) -> Result<()> {
        self.send_cmd(SessionCommand::DeinitSession { session_id }).await?;
        Ok(())
    }

    async fn start_ranging(&mut self, session_id: SessionId) -> Result<AppConfigParams> {
        match self.send_cmd(SessionCommand::StartRanging { session_id }).await? {
            SessionResponse::AppConfigParams(params) => Ok(params),
            _ => panic!("start_ranging() should reply AppConfigParams result"),
        }
    }

    async fn stop_ranging(&mut self, session_id: SessionId) -> Result<()> {
        self.send_cmd(SessionCommand::StopRanging { session_id }).await?;
        Ok(())
    }

    async fn reconfigure(&mut self, session_id: SessionId, params: AppConfigParams) -> Result<()> {
        self.send_cmd(SessionCommand::Reconfigure { session_id, params }).await?;
        Ok(())
    }

    async fn update_controller_multicast_list(
        &mut self,
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: Vec<Controlee>,
    ) -> Result<()> {
        self.send_cmd(SessionCommand::UpdateControllerMulticastList {
            session_id,
            action,
            controlees,
        })
        .await?;
        Ok(())
    }

    // Send the |cmd| to the SessionManagerActor.
    async fn send_cmd(&self, cmd: SessionCommand) -> Result<SessionResponse> {
        let (result_sender, result_receiver) = oneshot::channel();
        self.cmd_sender.send((cmd, result_sender)).map_err(|cmd| {
            error!("Failed to send cmd: {:?}", cmd.0);
            Error::TokioFailure
        })?;
        result_receiver.await.unwrap_or(Err(Error::TokioFailure))
    }
}

struct SessionManagerActor<T: UciManager> {
    // Receive the commands and the corresponding response senders from SessionManager.
    cmd_receiver: mpsc::UnboundedReceiver<(SessionCommand, ResponseSender)>,

    // The UciManager for delegating UCI requests.
    uci_manager: T,
    // Receive the notification from |uci_manager|.
    uci_notf_receiver: mpsc::UnboundedReceiver<UciSessionNotification>,

    active_sessions: BTreeMap<SessionId, UwbSession>,
}

impl<T: UciManager> SessionManagerActor<T> {
    fn new(
        cmd_receiver: mpsc::UnboundedReceiver<(SessionCommand, ResponseSender)>,
        uci_manager: T,
        uci_notf_receiver: mpsc::UnboundedReceiver<UciSessionNotification>,
    ) -> Self {
        Self { cmd_receiver, uci_manager, uci_notf_receiver, active_sessions: BTreeMap::new() }
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                cmd = self.cmd_receiver.recv() => {
                    match cmd {
                        None => {
                            debug!("SessionManager is about to drop.");
                            break;
                        },
                        Some((cmd, result_sender)) => {
                            self.handle_cmd(cmd, result_sender);
                        }
                    }
                }

                Some(notf) = self.uci_notf_receiver.recv() => {
                    self.handle_uci_notification(notf);
                }
            }
        }
    }

    fn handle_cmd(&mut self, cmd: SessionCommand, result_sender: ResponseSender) {
        match cmd {
            SessionCommand::InitSession { session_id, session_type, params, range_data_sender } => {
                if self.active_sessions.contains_key(&session_id) {
                    let _ = result_sender.send(Err(Error::DuplicatedSessionId(session_id)));
                    return;
                }
                if self.active_sessions.len() == MAX_SESSION_COUNT {
                    let _ = result_sender.send(Err(Error::MaxSessionsExceeded));
                    return;
                }

                if !params.is_type_matched(session_type) {
                    error!("session_type {:?} doesn't match with the params", session_type);
                    let _ = result_sender.send(Err(Error::InvalidArguments));
                    return;
                }

                let mut session = UwbSession::new(
                    self.uci_manager.clone(),
                    session_id,
                    session_type,
                    range_data_sender,
                );
                session.initialize(params, result_sender);

                // We store the session first. If the initialize() fails, then SessionManager will
                // call deinit_session() to remove it.
                self.active_sessions.insert(session_id, session);
            }
            SessionCommand::DeinitSession { session_id } => {
                match self.active_sessions.remove(&session_id) {
                    None => {
                        let _ = result_sender.send(Err(Error::UnknownSessionId(session_id)));
                    }
                    Some(mut session) => {
                        session.deinitialize(result_sender);
                    }
                }
            }
            SessionCommand::StartRanging { session_id } => {
                match self.active_sessions.get_mut(&session_id) {
                    None => {
                        let _ = result_sender.send(Err(Error::UnknownSessionId(session_id)));
                    }
                    Some(session) => {
                        session.start_ranging(result_sender);
                    }
                }
            }
            SessionCommand::StopRanging { session_id } => {
                match self.active_sessions.get_mut(&session_id) {
                    None => {
                        let _ = result_sender.send(Err(Error::UnknownSessionId(session_id)));
                    }
                    Some(session) => {
                        session.stop_ranging(result_sender);
                    }
                }
            }
            SessionCommand::Reconfigure { session_id, params } => {
                match self.active_sessions.get_mut(&session_id) {
                    None => {
                        let _ = result_sender.send(Err(Error::UnknownSessionId(session_id)));
                    }
                    Some(session) => {
                        session.reconfigure(params, result_sender);
                    }
                }
            }
            SessionCommand::UpdateControllerMulticastList { session_id, action, controlees } => {
                match self.active_sessions.get_mut(&session_id) {
                    None => {
                        let _ = result_sender.send(Err(Error::UnknownSessionId(session_id)));
                    }
                    Some(session) => {
                        session.update_controller_multicast_list(action, controlees, result_sender);
                    }
                }
            }
        }
    }

    fn handle_uci_notification(&mut self, notf: UciSessionNotification) {
        match notf {
            UciSessionNotification::Status { session_id, session_state, reason_code } => {
                if session_state == SessionState::SessionStateDeinit {
                    debug!("Session {:?} is deinitialized", session_id);
                    let _ = self.active_sessions.remove(&session_id);
                    return;
                }

                match self.active_sessions.get_mut(&session_id) {
                    Some(session) => session.on_session_status_changed(session_state),
                    None => {
                        warn!(
                            "Received notification of the unknown Session {:?}: {:?}, {:?}",
                            session_id, session_state, reason_code
                        );
                    }
                }
            }
            UciSessionNotification::UpdateControllerMulticastList {
                session_id,
                remaining_multicast_list_size: _,
                status_list,
            } => match self.active_sessions.get_mut(&session_id) {
                Some(session) => session.on_controller_multicast_list_udpated(status_list),
                None => {
                    warn!(
                        "Received the notification of the unknown Session {}: {:?}",
                        session_id, status_list
                    );
                }
            },
            UciSessionNotification::RangeData(data) => {
                match self.active_sessions.get_mut(&data.session_id) {
                    Some(session) => session.on_range_data_received(data),
                    None => warn!("Received range data of the unknown Session: {:?}", data),
                }
            }
        }
    }
}

#[derive(Debug)]
enum SessionCommand {
    InitSession {
        session_id: SessionId,
        session_type: SessionType,
        params: AppConfigParams,
        range_data_sender: mpsc::UnboundedSender<SessionRangeData>,
    },
    DeinitSession {
        session_id: SessionId,
    },
    StartRanging {
        session_id: SessionId,
    },
    StopRanging {
        session_id: SessionId,
    },
    Reconfigure {
        session_id: SessionId,
        params: AppConfigParams,
    },
    UpdateControllerMulticastList {
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: Vec<Controlee>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    use crate::session::params::ccc_app_config_params::*;
    use crate::session::params::ccc_started_app_config_params::CccStartedAppConfigParams;
    use crate::session::params::fira_app_config_params::*;
    use crate::session::params::utils::{u32_to_bytes, u64_to_bytes, u8_to_bytes};
    use crate::uci::error::StatusCode;
    use crate::uci::mock_uci_manager::MockUciManager;
    use crate::uci::notification::{RangingMeasurements, UciNotification};
    use crate::uci::params::{
        AppConfigTlv, AppConfigTlvType, ControleeStatus, MulticastUpdateStatusCode,
        RangingMeasurementType, ReasonCode, SetAppConfigResponse,
        ShortAddressTwoWayRangingMeasurement,
    };
    use crate::utils::init_test_logging;

    fn generate_params() -> AppConfigParams {
        FiraAppConfigParamsBuilder::new()
            .device_type(DeviceType::Controller)
            .multi_node_mode(MultiNodeMode::Unicast)
            .device_mac_address(UwbAddress::Short([1, 2]))
            .dst_mac_address(vec![UwbAddress::Short([3, 4])])
            .device_role(DeviceRole::Initiator)
            .vendor_id([0xFE, 0xDC])
            .static_sts_iv([0xDF, 0xCE, 0xAB, 0x12, 0x34, 0x56])
            .build()
            .unwrap()
    }

    fn generate_ccc_params() -> AppConfigParams {
        CccAppConfigParamsBuilder::new()
            .protocol_version(CccProtocolVersion { major: 2, minor: 1 })
            .uwb_config(CccUwbConfig::Config0)
            .pulse_shape_combo(CccPulseShapeCombo {
                initiator_tx: PulseShape::PrecursorFree,
                responder_tx: PulseShape::PrecursorFreeSpecial,
            })
            .ran_multiplier(3)
            .channel_number(CccUwbChannel::Channel9)
            .chaps_per_slot(ChapsPerSlot::Value9)
            .num_responder_nodes(1)
            .slots_per_rr(3)
            .sync_code_index(12)
            .hopping_mode(CccHoppingMode::ContinuousAes)
            .build()
            .unwrap()
    }

    async fn setup_session_manager<F>(setup_uci_manager_fn: F) -> (SessionManager, MockUciManager)
    where
        F: FnOnce(&mut MockUciManager),
    {
        init_test_logging();
        let (notf_sender, notf_receiver) = mpsc::unbounded_channel();
        let mut uci_manager = MockUciManager::new();
        uci_manager.expect_open_hal(vec![], Ok(()));
        setup_uci_manager_fn(&mut uci_manager);
        uci_manager.set_session_notification_sender(notf_sender).await;
        let _ = uci_manager.open_hal().await;
        (SessionManager::new(uci_manager.clone(), notf_receiver), uci_manager)
    }

    #[tokio::test]
    async fn test_init_deinit_session() {
        let session_id = 0x123;
        let session_type = SessionType::FiraRangingSession;
        let params = generate_params();

        let tlvs = params.generate_tlvs();
        let (mut session_manager, mut mock_uci_manager) =
            setup_session_manager(move |uci_manager| {
                let init_notfs = vec![UciNotification::Session(UciSessionNotification::Status {
                    session_id,
                    session_state: SessionState::SessionStateInit,
                    reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                })];
                let set_app_config_notfs =
                    vec![UciNotification::Session(UciSessionNotification::Status {
                        session_id,
                        session_state: SessionState::SessionStateIdle,
                        reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                    })];
                uci_manager.expect_session_init(session_id, session_type, init_notfs, Ok(()));
                uci_manager.expect_session_set_app_config(
                    session_id,
                    tlvs,
                    set_app_config_notfs,
                    Ok(SetAppConfigResponse {
                        status: StatusCode::UciStatusOk,
                        config_status: vec![],
                    }),
                );
                uci_manager.expect_session_deinit(session_id, Ok(()));
            })
            .await;

        // Deinit a session before initialized should fail.
        let result = session_manager.deinit_session(session_id).await;
        assert_eq!(result, Err(Error::UnknownSessionId(session_id)));

        // Initialize a normal session should be successful.
        let result = session_manager
            .init_session(session_id, session_type, params.clone(), mpsc::unbounded_channel().0)
            .await;
        assert_eq!(result, Ok(()));

        // Initialize a session multiple times without deinitialize should fail.
        let result = session_manager
            .init_session(session_id, session_type, params, mpsc::unbounded_channel().0)
            .await;
        assert_eq!(result, Err(Error::DuplicatedSessionId(session_id)));

        // Deinitialize the session should be successful.
        let result = session_manager.deinit_session(session_id).await;
        assert_eq!(result, Ok(()));

        // Deinit a session after deinitialized should fail.
        let result = session_manager.deinit_session(session_id).await;
        assert_eq!(result, Err(Error::UnknownSessionId(session_id)));

        assert!(mock_uci_manager.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_init_session_timeout() {
        let session_id = 0x123;
        let session_type = SessionType::FiraRangingSession;
        let params = generate_params();

        let (mut session_manager, mut mock_uci_manager) =
            setup_session_manager(move |uci_manager| {
                let notfs = vec![]; // Not sending SessionStatus notification.
                uci_manager.expect_session_init(session_id, session_type, notfs, Ok(()));
            })
            .await;

        let result = session_manager
            .init_session(session_id, session_type, params, mpsc::unbounded_channel().0)
            .await;
        assert_eq!(result, Err(Error::Timeout));

        assert!(mock_uci_manager.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_start_stop_ranging() {
        let session_id = 0x123;
        let session_type = SessionType::FiraRangingSession;
        let params = generate_params();
        let tlvs = params.generate_tlvs();

        let (mut session_manager, mut mock_uci_manager) =
            setup_session_manager(move |uci_manager| {
                let state_init_notf =
                    vec![UciNotification::Session(UciSessionNotification::Status {
                        session_id,
                        session_state: SessionState::SessionStateInit,
                        reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                    })];
                let state_idle_notf =
                    vec![UciNotification::Session(UciSessionNotification::Status {
                        session_id,
                        session_state: SessionState::SessionStateIdle,
                        reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                    })];
                let state_active_notf =
                    vec![UciNotification::Session(UciSessionNotification::Status {
                        session_id,
                        session_state: SessionState::SessionStateActive,
                        reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                    })];
                uci_manager.expect_session_init(session_id, session_type, state_init_notf, Ok(()));
                uci_manager.expect_session_set_app_config(
                    session_id,
                    tlvs,
                    state_idle_notf.clone(),
                    Ok(SetAppConfigResponse {
                        status: StatusCode::UciStatusOk,
                        config_status: vec![],
                    }),
                );
                uci_manager.expect_range_start(session_id, state_active_notf, Ok(()));
                uci_manager.expect_range_stop(session_id, state_idle_notf, Ok(()));
            })
            .await;

        let result = session_manager
            .init_session(session_id, session_type, params.clone(), mpsc::unbounded_channel().0)
            .await;
        assert_eq!(result, Ok(()));
        let result = session_manager.start_ranging(session_id).await;
        assert_eq!(result, Ok(params));
        let result = session_manager.stop_ranging(session_id).await;
        assert_eq!(result, Ok(()));

        assert!(mock_uci_manager.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_ccc_start_ranging() {
        let session_id = 0x123;
        let session_type = SessionType::Ccc;
        // params that is passed to UciManager::session_set_app_config().
        let params = generate_ccc_params();
        let tlvs = params.generate_tlvs();
        // The params that is received from UciManager::session_get_app_config().
        let received_config_map = HashMap::from([
            (AppConfigTlvType::StsIndex, u32_to_bytes(3)),
            (AppConfigTlvType::CccHopModeKey, u32_to_bytes(5)),
            (AppConfigTlvType::CccUwbTime0, u64_to_bytes(7)),
            (AppConfigTlvType::RangingInterval, u32_to_bytes(96)),
            (AppConfigTlvType::PreambleCodeIndex, u8_to_bytes(9)),
        ]);
        let received_tlvs = received_config_map
            .iter()
            .map(|(key, value)| AppConfigTlv { cfg_id: *key, v: value.clone() })
            .collect();
        let started_params =
            CccStartedAppConfigParams::from_config_map(received_config_map).unwrap();

        let (mut session_manager, mut mock_uci_manager) =
            setup_session_manager(move |uci_manager| {
                let state_init_notf =
                    vec![UciNotification::Session(UciSessionNotification::Status {
                        session_id,
                        session_state: SessionState::SessionStateInit,
                        reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                    })];
                let state_idle_notf =
                    vec![UciNotification::Session(UciSessionNotification::Status {
                        session_id,
                        session_state: SessionState::SessionStateIdle,
                        reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                    })];
                let state_active_notf =
                    vec![UciNotification::Session(UciSessionNotification::Status {
                        session_id,
                        session_state: SessionState::SessionStateActive,
                        reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                    })];
                uci_manager.expect_session_init(session_id, session_type, state_init_notf, Ok(()));
                uci_manager.expect_session_set_app_config(
                    session_id,
                    tlvs,
                    state_idle_notf,
                    Ok(SetAppConfigResponse {
                        status: StatusCode::UciStatusOk,
                        config_status: vec![],
                    }),
                );
                uci_manager.expect_range_start(session_id, state_active_notf, Ok(()));
                uci_manager.expect_session_get_app_config(session_id, vec![], Ok(received_tlvs));
            })
            .await;

        let result = session_manager
            .init_session(session_id, session_type, params.clone(), mpsc::unbounded_channel().0)
            .await;
        assert_eq!(result, Ok(()));
        let result = session_manager.start_ranging(session_id).await;
        assert_eq!(result, Ok(AppConfigParams::CccStarted(started_params)));

        assert!(mock_uci_manager.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_update_controller_multicast_list() {
        let session_id = 0x123;
        let session_type = SessionType::FiraRangingSession;
        let params = generate_params();
        let tlvs = params.generate_tlvs();
        let action = UpdateMulticastListAction::AddControlee;
        let controlees = vec![Controlee { short_address: 0x13, subsession_id: 0x24 }];

        let controlees_clone = controlees.clone();
        let (mut session_manager, mut mock_uci_manager) =
            setup_session_manager(move |uci_manager| {
                let state_init_notf =
                    vec![UciNotification::Session(UciSessionNotification::Status {
                        session_id,
                        session_state: SessionState::SessionStateInit,
                        reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                    })];
                let state_idle_notf =
                    vec![UciNotification::Session(UciSessionNotification::Status {
                        session_id,
                        session_state: SessionState::SessionStateIdle,
                        reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                    })];
                let multicast_list_notf = vec![UciNotification::Session(
                    UciSessionNotification::UpdateControllerMulticastList {
                        session_id,
                        remaining_multicast_list_size: 1,
                        status_list: vec![ControleeStatus {
                            mac_address: 0x13,
                            subsession_id: 0x24,
                            status: MulticastUpdateStatusCode::StatusOkMulticastListUpdate,
                        }],
                    },
                )];
                uci_manager.expect_session_init(session_id, session_type, state_init_notf, Ok(()));
                uci_manager.expect_session_set_app_config(
                    session_id,
                    tlvs,
                    state_idle_notf,
                    Ok(SetAppConfigResponse {
                        status: StatusCode::UciStatusOk,
                        config_status: vec![],
                    }),
                );
                uci_manager.expect_session_update_controller_multicast_list(
                    session_id,
                    action,
                    controlees_clone,
                    multicast_list_notf,
                    Ok(()),
                );
            })
            .await;

        let result = session_manager
            .init_session(session_id, session_type, params, mpsc::unbounded_channel().0)
            .await;
        assert_eq!(result, Ok(()));
        let result =
            session_manager.update_controller_multicast_list(session_id, action, controlees).await;
        assert_eq!(result, Ok(()));

        assert!(mock_uci_manager.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_ccc_update_controller_multicast_list() {
        let session_id = 0x123;
        let session_type = SessionType::Ccc;
        let params = generate_ccc_params();
        let tlvs = params.generate_tlvs();
        let action = UpdateMulticastListAction::AddControlee;
        let controlees = vec![Controlee { short_address: 0x13, subsession_id: 0x24 }];

        let (mut session_manager, mut mock_uci_manager) =
            setup_session_manager(move |uci_manager| {
                let state_init_notf =
                    vec![UciNotification::Session(UciSessionNotification::Status {
                        session_id,
                        session_state: SessionState::SessionStateInit,
                        reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                    })];
                let state_idle_notf =
                    vec![UciNotification::Session(UciSessionNotification::Status {
                        session_id,
                        session_state: SessionState::SessionStateIdle,
                        reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                    })];
                uci_manager.expect_session_init(session_id, session_type, state_init_notf, Ok(()));
                uci_manager.expect_session_set_app_config(
                    session_id,
                    tlvs,
                    state_idle_notf,
                    Ok(SetAppConfigResponse {
                        status: StatusCode::UciStatusOk,
                        config_status: vec![],
                    }),
                );
            })
            .await;

        let result = session_manager
            .init_session(session_id, session_type, params, mpsc::unbounded_channel().0)
            .await;
        assert_eq!(result, Ok(()));
        // CCC session doesn't support update_controller_multicast_list.
        let result =
            session_manager.update_controller_multicast_list(session_id, action, controlees).await;
        assert_eq!(result, Err(Error::InvalidArguments));

        assert!(mock_uci_manager.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_update_controller_multicast_list_without_notification() {
        let session_id = 0x123;
        let session_type = SessionType::FiraRangingSession;
        let params = generate_params();
        let tlvs = params.generate_tlvs();
        let action = UpdateMulticastListAction::AddControlee;
        let controlees = vec![Controlee { short_address: 0x13, subsession_id: 0x24 }];

        let controlees_clone = controlees.clone();
        let (mut session_manager, mut mock_uci_manager) =
            setup_session_manager(move |uci_manager| {
                let state_init_notf =
                    vec![UciNotification::Session(UciSessionNotification::Status {
                        session_id,
                        session_state: SessionState::SessionStateInit,
                        reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                    })];
                let state_idle_notf =
                    vec![UciNotification::Session(UciSessionNotification::Status {
                        session_id,
                        session_state: SessionState::SessionStateIdle,
                        reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                    })];
                uci_manager.expect_session_init(session_id, session_type, state_init_notf, Ok(()));
                uci_manager.expect_session_set_app_config(
                    session_id,
                    tlvs,
                    state_idle_notf,
                    Ok(SetAppConfigResponse {
                        status: StatusCode::UciStatusOk,
                        config_status: vec![],
                    }),
                );
                uci_manager.expect_session_update_controller_multicast_list(
                    session_id,
                    action,
                    controlees_clone,
                    vec![], // Not sending notification.
                    Ok(()),
                );
            })
            .await;

        let result = session_manager
            .init_session(session_id, session_type, params, mpsc::unbounded_channel().0)
            .await;
        assert_eq!(result, Ok(()));
        // This method should timeout waiting for the notification.
        let result =
            session_manager.update_controller_multicast_list(session_id, action, controlees).await;
        assert_eq!(result, Err(Error::Timeout));

        assert!(mock_uci_manager.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_receive_session_range_data() {
        let session_id = 0x123;
        let session_type = SessionType::FiraRangingSession;
        let params = generate_params();
        let tlvs = params.generate_tlvs();
        let range_data = SessionRangeData {
            sequence_number: 1,
            session_id,
            current_ranging_interval_ms: 3,
            ranging_measurement_type: RangingMeasurementType::TwoWay,
            ranging_measurements: RangingMeasurements::Short(vec![
                ShortAddressTwoWayRangingMeasurement {
                    mac_address: 0x123,
                    status: StatusCode::UciStatusOk,
                    nlos: 0,
                    distance: 4,
                    aoa_azimuth: 5,
                    aoa_azimuth_fom: 6,
                    aoa_elevation: 7,
                    aoa_elevation_fom: 8,
                    aoa_destination_azimuth: 9,
                    aoa_destination_azimuth_fom: 10,
                    aoa_destination_elevation: 11,
                    aoa_destination_elevation_fom: 12,
                    slot_index: 0,
                },
            ]),
        };

        let range_data_clone = range_data.clone();
        let (mut session_manager, mut mock_uci_manager) =
            setup_session_manager(move |uci_manager| {
                let init_notfs = vec![UciNotification::Session(UciSessionNotification::Status {
                    session_id,
                    session_state: SessionState::SessionStateInit,
                    reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                })];
                let set_app_config_notfs = vec![
                    UciNotification::Session(UciSessionNotification::Status {
                        session_id,
                        session_state: SessionState::SessionStateIdle,
                        reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                    }),
                    UciNotification::Session(UciSessionNotification::RangeData(range_data_clone)),
                ];
                uci_manager.expect_session_init(session_id, session_type, init_notfs, Ok(()));
                uci_manager.expect_session_set_app_config(
                    session_id,
                    tlvs,
                    set_app_config_notfs,
                    Ok(SetAppConfigResponse {
                        status: StatusCode::UciStatusOk,
                        config_status: vec![],
                    }),
                );
            })
            .await;

        let (range_data_sender, mut range_data_receiver) = mpsc::unbounded_channel();
        let result =
            session_manager.init_session(session_id, session_type, params, range_data_sender).await;
        assert_eq!(result, Ok(()));

        let received_range_data = range_data_receiver.recv().await.unwrap();
        assert_eq!(received_range_data, range_data);

        assert!(mock_uci_manager.wait_expected_calls_done().await);
    }
}
