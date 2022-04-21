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
use crate::session::uwb_session::UwbSession;
use crate::uci::notification::UciNotification;
use crate::uci::params::{SessionId, SessionState, SessionType};
use crate::uci::uci_manager::UciManager;

const MAX_SESSION_COUNT: usize = 5;

/// The SessionManager organizes the state machine of the existing UWB ranging sessions, sends
/// the session-related requests to the UciManager, and handles the session notifications from the
/// UciManager.
/// Using the actor model, SessionManager delegates the requests to SessionManagerActor.
pub(crate) struct SessionManager {
    cmd_sender: mpsc::UnboundedSender<(SessionCommand, oneshot::Sender<Result<()>>)>,
}

impl SessionManager {
    pub fn new<T: UciManager>(
        uci_manager: T,
        uci_notf_receiver: mpsc::UnboundedReceiver<UciNotification>,
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
    ) -> Result<()> {
        let result =
            self.send_cmd(SessionCommand::InitSession { session_id, session_type, params }).await;
        if result.is_err() && result != Err(Error::DuplicatedSessionId(session_id)) {
            let _ = self.deinit_session(session_id).await;
        }
        result
    }

    async fn deinit_session(&mut self, session_id: SessionId) -> Result<()> {
        self.send_cmd(SessionCommand::DeinitSession { session_id }).await
    }

    // Send the |cmd| to the SessionManagerActor.
    async fn send_cmd(&self, cmd: SessionCommand) -> Result<()> {
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
    cmd_receiver: mpsc::UnboundedReceiver<(SessionCommand, oneshot::Sender<Result<()>>)>,

    // The UciManager for delegating UCI requests.
    uci_manager: T,
    // Receive the notification from |uci_manager|.
    uci_notf_receiver: mpsc::UnboundedReceiver<UciNotification>,

    active_sessions: BTreeMap<SessionId, UwbSession>,
}

impl<T: UciManager> SessionManagerActor<T> {
    fn new(
        cmd_receiver: mpsc::UnboundedReceiver<(SessionCommand, oneshot::Sender<Result<()>>)>,
        uci_manager: T,
        uci_notf_receiver: mpsc::UnboundedReceiver<UciNotification>,
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

                Some(uci_notf) = self.uci_notf_receiver.recv() => {
                    self.handle_uci_notification(uci_notf);
                }
            }
        }
    }

    fn handle_cmd(&mut self, cmd: SessionCommand, result_sender: oneshot::Sender<Result<()>>) {
        match cmd {
            SessionCommand::InitSession { session_id, session_type, params } => {
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

                let mut session =
                    UwbSession::new(self.uci_manager.clone(), session_id, session_type);
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
        }
    }

    fn handle_uci_notification(&mut self, notf: UciNotification) {
        // TODO(akahuang): Remove this after handling multiple kind of notifications.
        #[allow(clippy::single_match)]
        match notf {
            UciNotification::SessionStatus { session_id, session_state, reason_code } => {
                if session_state == SessionState::SessionStateDeinit {
                    debug!("Session {:?} is deinitialized", session_id);
                    let _ = self.active_sessions.remove(&session_id);
                    return;
                }

                match self.active_sessions.get_mut(&session_id) {
                    Some(session) => session.set_state(session_state),
                    None => {
                        warn!(
                            "Received notification of the unknown Session {:?}: {:?}, {:?}",
                            session_id, session_state, reason_code
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
enum SessionCommand {
    InitSession { session_id: SessionId, session_type: SessionType, params: AppConfigParams },
    DeinitSession { session_id: SessionId },
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::session::params::fira_app_config_params::*;
    use crate::uci::error::StatusCode;
    use crate::uci::mock_uci_manager::MockUciManager;
    use crate::uci::params::{ReasonCode, SetAppConfigResponse};
    use crate::utils::init_test_logging;

    fn generate_params() -> AppConfigParams {
        AppConfigParams::Fira(
            FiraAppConfigParamsBuilder::new()
                .device_type(DeviceType::Controller)
                .multi_node_mode(MultiNodeMode::Unicast)
                .device_mac_address(UwbAddress::Short([1, 2]))
                .dst_mac_address(vec![UwbAddress::Short([3, 4])])
                .device_role(DeviceRole::Initiator)
                .vendor_id([0xFE, 0xDC])
                .static_sts_iv([0xDF, 0xCE, 0xAB, 0x12, 0x34, 0x56])
                .build()
                .unwrap(),
        )
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
        let _ = uci_manager.open_hal(notf_sender).await;
        (SessionManager::new(uci_manager.clone(), notf_receiver), uci_manager)
    }

    #[tokio::test]
    async fn test_init_deinit_session() {
        let session_id = 0x123;
        let session_type = SessionType::FiraRangingSession;
        let params = generate_params();

        let tlvs = params.generate_tlvs();
        let session_id_clone = session_id;
        let session_type_clone = session_type;
        let (mut session_manager, mut mock_uci_manager) =
            setup_session_manager(move |uci_manager| {
                let init_notfs = vec![UciNotification::SessionStatus {
                    session_id,
                    session_state: SessionState::SessionStateInit,
                    reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                }];
                let set_app_config_notfs = vec![UciNotification::SessionStatus {
                    session_id,
                    session_state: SessionState::SessionStateIdle,
                    reason_code: ReasonCode::StateChangeWithSessionManagementCommands,
                }];
                uci_manager.expect_session_init(
                    session_id_clone,
                    session_type_clone,
                    init_notfs,
                    Ok(()),
                );
                uci_manager.expect_session_set_app_config(
                    session_id_clone,
                    tlvs,
                    set_app_config_notfs,
                    Ok(SetAppConfigResponse {
                        status: StatusCode::UciStatusOk,
                        config_status: vec![],
                    }),
                );
                uci_manager.expect_session_deinit(session_id_clone, Ok(()));
            })
            .await;

        // Deinit a session before initialized should fail.
        let result = session_manager.deinit_session(session_id).await;
        assert_eq!(result, Err(Error::UnknownSessionId(session_id)));

        // Initialize a normal session should be successful.
        let result = session_manager.init_session(session_id, session_type, params.clone()).await;
        assert_eq!(result, Ok(()));

        // Initialize a session multiple times without deinitialize should fail.
        let result = session_manager.init_session(session_id, session_type, params).await;
        assert_eq!(result, Err(Error::DuplicatedSessionId(session_id)));

        // Deinitialize the session should be successful.
        let result = session_manager.deinit_session(session_id).await;
        assert_eq!(result, Ok(()));

        // Deinit a session after deinitialized should fail.
        let result = session_manager.deinit_session(session_id).await;
        assert_eq!(result, Err(Error::UnknownSessionId(session_id)));

        assert!(mock_uci_manager.wait_expected_calls_done().await);
    }
}
