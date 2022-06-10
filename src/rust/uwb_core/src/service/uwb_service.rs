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

//! This module defines the UwbService and its related components.

use log::{debug, error, warn};
use tokio::sync::{mpsc, oneshot};

use crate::error::{Error, Result};
use crate::params::app_config_params::AppConfigParams;
use crate::params::uci_packets::{
    Controlee, CountryCode, DeviceState, PowerStats, RawVendorMessage, ReasonCode, SessionId,
    SessionState, SessionType, UpdateMulticastListAction,
};
use crate::session::session_manager::{SessionManager, SessionNotification};
use crate::uci::notification::{CoreNotification, SessionRangeData};
use crate::uci::uci_manager::UciManager;

/// The notification that is sent from UwbService to its caller.
#[non_exhaustive] // Adding new enum fields doesn't break the downstream build.
#[derive(Debug, PartialEq)]
pub enum UwbNotification {
    /// Notify the UWB service has been reset due to internal error. All the sessions are closed.
    ServiceReset {
        /// Indicate the reset is successful or not.
        success: bool,
    },
    /// Notify the status of the UCI device.
    UciDeviceStatus(DeviceState),
    /// Notify the state of the session with the id |session_id| is changed.
    SessionState {
        /// The identifier of the session.
        session_id: SessionId,
        /// The current state of the session.
        session_state: SessionState,
        /// The reason of the state change.
        reason_code: ReasonCode,
    },
    /// Notify the ranging data of the session with the id |session_id| is received.
    RangeData {
        /// The identifier of the ranging session.
        session_id: SessionId,
        /// The received range data.
        range_data: SessionRangeData,
    },
    /// Notify the vendor notification is received.
    VendorNotification {
        /// The group id of the message.
        gid: u32,
        /// The opcode of the message.
        oid: u32,
        /// The payload of the message.
        payload: Vec<u8>,
    },
}

/// The entry class (a.k.a top shim) of the core library. The class accepts requests from the
/// client, and delegates the requests to other components. It should provide the
/// backward-compatible interface for the client of the library.
pub struct UwbService {
    cmd_sender: mpsc::UnboundedSender<(Command, ResponseSender)>,
}

impl UwbService {
    /// Create a new UwbService instance.
    pub(super) fn new<U: UciManager>(
        notf_sender: mpsc::UnboundedSender<UwbNotification>,
        uci_manager: U,
    ) -> Self {
        let (cmd_sender, cmd_receiver) = mpsc::unbounded_channel();
        let mut actor = UwbServiceActor::new(cmd_receiver, notf_sender, uci_manager);
        tokio::spawn(async move { actor.run().await });

        Self { cmd_sender }
    }

    /// Enable the UWB service.
    pub async fn enable(&mut self) -> Result<()> {
        self.send_cmd(Command::Enable).await?;
        Ok(())
    }

    /// Disable the UWB service.
    pub async fn disable(&mut self) -> Result<()> {
        self.send_cmd(Command::Disable).await?;
        Ok(())
    }

    /// Initialize a new ranging session with the given parameters.
    pub async fn init_session(
        &mut self,
        session_id: SessionId,
        session_type: SessionType,
        params: AppConfigParams,
    ) -> Result<()> {
        self.send_cmd(Command::InitSession { session_id, session_type, params }).await?;
        Ok(())
    }

    /// Destroy the session.
    pub async fn deinit_session(&mut self, session_id: SessionId) -> Result<()> {
        self.send_cmd(Command::DeinitSession { session_id }).await?;
        Ok(())
    }

    /// Start ranging of the session.
    pub async fn start_ranging(&mut self, session_id: SessionId) -> Result<AppConfigParams> {
        match self.send_cmd(Command::StartRanging { session_id }).await? {
            Response::AppConfigParams(params) => Ok(params),
            _ => panic!("start_ranging() should return AppConfigParams"),
        }
    }

    /// Stop ranging.
    pub async fn stop_ranging(&mut self, session_id: SessionId) -> Result<()> {
        self.send_cmd(Command::StopRanging { session_id }).await?;
        Ok(())
    }

    /// Reconfigure the parameters of the session.
    pub async fn reconfigure(
        &mut self,
        session_id: SessionId,
        params: AppConfigParams,
    ) -> Result<()> {
        self.send_cmd(Command::Reconfigure { session_id, params }).await?;
        Ok(())
    }

    /// Update the list of the controlees to the ongoing session.
    pub async fn update_controller_multicast_list(
        &mut self,
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: Vec<Controlee>,
    ) -> Result<()> {
        self.send_cmd(Command::UpdateControllerMulticastList { session_id, action, controlees })
            .await?;
        Ok(())
    }

    /// Set the country code. Android-specific method.
    pub async fn android_set_country_code(&mut self, country_code: CountryCode) -> Result<()> {
        self.send_cmd(Command::AndroidSetCountryCode { country_code }).await?;
        Ok(())
    }

    /// Get the power statistics. Android-specific method.
    pub async fn android_get_power_stats(&mut self) -> Result<PowerStats> {
        match self.send_cmd(Command::AndroidGetPowerStats).await? {
            Response::PowerStats(stats) => Ok(stats),
            _ => panic!("android_get_power_stats() should return PowerStats"),
        }
    }

    /// Send a vendor-specific UCI message.
    pub async fn send_vendor_cmd(
        &mut self,
        gid: u32,
        oid: u32,
        payload: Vec<u8>,
    ) -> Result<RawVendorMessage> {
        match self.send_cmd(Command::SendVendorCmd { gid, oid, payload }).await? {
            Response::RawVendorMessage(msg) => Ok(msg),
            _ => panic!("send_vendor_cmd() should return RawVendorMessage"),
        }
    }

    /// Send the |cmd| to UwbServiceActor.
    async fn send_cmd(&self, cmd: Command) -> Result<Response> {
        let (result_sender, result_receiver) = oneshot::channel();
        self.cmd_sender.send((cmd, result_sender)).map_err(|cmd| {
            error!("Failed to send cmd: {:?}", cmd.0);
            Error::Unknown
        })?;
        result_receiver.await.unwrap_or_else(|e| {
            error!("Failed to receive the result for cmd: {:?}", e);
            Err(Error::Unknown)
        })
    }
}

struct UwbServiceActor<U: UciManager> {
    cmd_receiver: mpsc::UnboundedReceiver<(Command, ResponseSender)>,
    notf_sender: mpsc::UnboundedSender<UwbNotification>,
    uci_manager: U,
    session_manager: Option<SessionManager>,
    core_notf_receiver: mpsc::UnboundedReceiver<CoreNotification>,
    session_notf_receiver: mpsc::UnboundedReceiver<SessionNotification>,
    vendor_notf_receiver: mpsc::UnboundedReceiver<RawVendorMessage>,
}

impl<U: UciManager> UwbServiceActor<U> {
    fn new(
        cmd_receiver: mpsc::UnboundedReceiver<(Command, ResponseSender)>,
        notf_sender: mpsc::UnboundedSender<UwbNotification>,
        uci_manager: U,
    ) -> Self {
        Self {
            cmd_receiver,
            notf_sender,
            uci_manager,
            session_manager: None,
            core_notf_receiver: mpsc::unbounded_channel().1,
            session_notf_receiver: mpsc::unbounded_channel().1,
            vendor_notf_receiver: mpsc::unbounded_channel().1,
        }
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                cmd = self.cmd_receiver.recv() => {
                    match cmd {
                        None => {
                            debug!("UwbService is about to drop.");
                            break;
                        },
                        Some((cmd, result_sender)) => {
                            let result = self.handle_cmd(cmd).await;
                            let timeout_occurs = matches!(result, Err(Error::Timeout));
                            let _ = result_sender.send(result);

                            // The UCI HAL might be stuck at a weird state when the timeout occurs.
                            // Reset the HAL and clear the internal state, and hope the HAL goes
                            // back to the normal situation.
                            if timeout_occurs {
                                warn!("The command timeout, reset the service.");
                                self.reset_service().await;
                            }
                        }
                    }
                }
                Some(core_notf) = self.core_notf_receiver.recv() => {
                    self.handle_core_notification(core_notf).await;
                }
                Some(session_notf) = self.session_notf_receiver.recv() => {
                    self.handle_session_notification(session_notf).await;
                }
                Some(vendor_notf) = self.vendor_notf_receiver.recv() => {
                    self.handle_vendor_notification(vendor_notf).await;
                }
            }
        }
    }

    async fn handle_cmd(&mut self, cmd: Command) -> Result<Response> {
        match cmd {
            Command::Enable => {
                self.enable_service().await?;
                Ok(Response::Null)
            }
            Command::Disable => {
                self.disable_service(false).await?;
                Ok(Response::Null)
            }
            Command::InitSession { session_id, session_type, params } => {
                if let Some(session_manager) = self.session_manager.as_mut() {
                    session_manager.init_session(session_id, session_type, params).await?;
                    Ok(Response::Null)
                } else {
                    error!("The service is not enabled yet");
                    Err(Error::BadParameters)
                }
            }
            Command::DeinitSession { session_id } => {
                if let Some(session_manager) = self.session_manager.as_mut() {
                    session_manager.deinit_session(session_id).await?;
                    Ok(Response::Null)
                } else {
                    error!("The service is not enabled yet");
                    Err(Error::BadParameters)
                }
            }
            Command::StartRanging { session_id } => {
                if let Some(session_manager) = self.session_manager.as_mut() {
                    let params = session_manager.start_ranging(session_id).await?;
                    Ok(Response::AppConfigParams(params))
                } else {
                    error!("The service is not enabled yet");
                    Err(Error::BadParameters)
                }
            }
            Command::StopRanging { session_id } => {
                if let Some(session_manager) = self.session_manager.as_mut() {
                    session_manager.stop_ranging(session_id).await?;
                    Ok(Response::Null)
                } else {
                    error!("The service is not enabled yet");
                    Err(Error::BadParameters)
                }
            }
            Command::Reconfigure { session_id, params } => {
                if let Some(session_manager) = self.session_manager.as_mut() {
                    session_manager.reconfigure(session_id, params).await?;
                    Ok(Response::Null)
                } else {
                    error!("The service is not enabled yet");
                    Err(Error::BadParameters)
                }
            }
            Command::UpdateControllerMulticastList { session_id, action, controlees } => {
                if let Some(session_manager) = self.session_manager.as_mut() {
                    session_manager
                        .update_controller_multicast_list(session_id, action, controlees)
                        .await?;
                    Ok(Response::Null)
                } else {
                    error!("The service is not enabled yet");
                    Err(Error::BadParameters)
                }
            }
            Command::AndroidSetCountryCode { country_code } => {
                self.uci_manager.android_set_country_code(country_code).await?;
                Ok(Response::Null)
            }
            Command::AndroidGetPowerStats => {
                let stats = self.uci_manager.android_get_power_stats().await?;
                Ok(Response::PowerStats(stats))
            }
            Command::SendVendorCmd { gid, oid, payload } => {
                let msg = self.uci_manager.raw_vendor_cmd(gid, oid, payload).await?;
                Ok(Response::RawVendorMessage(msg))
            }
        }
    }

    async fn handle_core_notification(&mut self, notf: CoreNotification) {
        debug!("Receive core notification: {:?}", notf);
        match notf {
            CoreNotification::DeviceStatus(state) => {
                if state == DeviceState::DeviceStateError {
                    warn!("Received DeviceStateError notification, reset the service");
                    self.reset_service().await;
                } else {
                    let _ = self.notf_sender.send(UwbNotification::UciDeviceStatus(state));
                }
            }
            CoreNotification::GenericError(_status) => {}
        }
    }

    async fn handle_session_notification(&mut self, notf: SessionNotification) {
        match notf {
            SessionNotification::SessionState { session_id, session_state, reason_code } => {
                let _ = self.notf_sender.send(UwbNotification::SessionState {
                    session_id,
                    session_state,
                    reason_code,
                });
            }
            SessionNotification::RangeData { session_id, range_data } => {
                let _ =
                    self.notf_sender.send(UwbNotification::RangeData { session_id, range_data });
            }
        }
    }

    async fn handle_vendor_notification(&mut self, notf: RawVendorMessage) {
        let _ = self.notf_sender.send(UwbNotification::VendorNotification {
            gid: notf.gid,
            oid: notf.oid,
            payload: notf.payload,
        });
    }

    async fn enable_service(&mut self) -> Result<()> {
        if self.session_manager.is_some() {
            debug!("The service is already enabled, skip.");
            return Ok(());
        }

        let (core_notf_sender, core_notf_receiver) = mpsc::unbounded_channel();
        let (uci_session_notf_sender, uci_session_notf_receiver) = mpsc::unbounded_channel();
        let (vendor_notf_sender, vendor_notf_receiver) = mpsc::unbounded_channel();
        self.uci_manager.set_core_notification_sender(core_notf_sender).await;
        self.uci_manager.set_session_notification_sender(uci_session_notf_sender).await;
        self.uci_manager.set_vendor_notification_sender(vendor_notf_sender).await;
        self.uci_manager.open_hal().await?;

        let (session_notf_sender, session_notf_receiver) = mpsc::unbounded_channel();
        self.core_notf_receiver = core_notf_receiver;
        self.session_notf_receiver = session_notf_receiver;
        self.vendor_notf_receiver = vendor_notf_receiver;
        self.session_manager = Some(SessionManager::new(
            self.uci_manager.clone(),
            uci_session_notf_receiver,
            session_notf_sender,
        ));
        Ok(())
    }

    async fn disable_service(&mut self, force: bool) -> Result<()> {
        self.core_notf_receiver = mpsc::unbounded_channel().1;
        self.session_notf_receiver = mpsc::unbounded_channel().1;
        self.vendor_notf_receiver = mpsc::unbounded_channel().1;
        self.session_manager = None;
        self.uci_manager.close_hal(force).await?;
        Ok(())
    }

    async fn reset_service(&mut self) {
        let _ = self.disable_service(true).await;
        let result = self.enable_service().await;
        if result.is_err() {
            error!("Failed to reset the service.");
        }
        let _ = self.notf_sender.send(UwbNotification::ServiceReset { success: result.is_ok() });
    }
}

#[derive(Debug)]
enum Command {
    Enable,
    Disable,
    InitSession {
        session_id: SessionId,
        session_type: SessionType,
        params: AppConfigParams,
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
    AndroidSetCountryCode {
        country_code: CountryCode,
    },
    AndroidGetPowerStats,
    SendVendorCmd {
        gid: u32,
        oid: u32,
        payload: Vec<u8>,
    },
}

#[derive(Debug)]
enum Response {
    Null,
    AppConfigParams(AppConfigParams),
    PowerStats(PowerStats),
    RawVendorMessage(RawVendorMessage),
}
type ResponseSender = oneshot::Sender<Result<Response>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::uci_packets::{SessionState, SetAppConfigResponse, StatusCode};
    use crate::session::session_manager::test_utils::{
        generate_params, range_data_notf, session_range_data, session_status_notf,
    };
    use crate::uci::mock_uci_manager::MockUciManager;
    use crate::uci::notification::UciNotification;

    #[tokio::test]
    async fn test_open_close_uci() {
        let mut uci_manager = MockUciManager::new();
        uci_manager.expect_open_hal(vec![], Ok(()));
        uci_manager.expect_close_hal(false, Ok(()));
        let mut service = UwbService::new(mpsc::unbounded_channel().0, uci_manager);

        let result = service.enable().await;
        assert!(result.is_ok());
        let result = service.disable().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_session_e2e() {
        let session_id = 0x123;
        let session_type = SessionType::FiraRangingSession;
        let params = generate_params();
        let tlvs = params.generate_tlvs();
        let range_data = session_range_data(session_id);

        let mut uci_manager = MockUciManager::new();
        uci_manager.expect_open_hal(vec![], Ok(()));
        uci_manager.expect_session_init(
            session_id,
            session_type,
            vec![session_status_notf(session_id, SessionState::SessionStateInit)],
            Ok(()),
        );
        uci_manager.expect_session_set_app_config(
            session_id,
            tlvs,
            vec![session_status_notf(session_id, SessionState::SessionStateIdle)],
            Ok(SetAppConfigResponse { status: StatusCode::UciStatusOk, config_status: vec![] }),
        );
        uci_manager.expect_range_start(
            session_id,
            vec![
                session_status_notf(session_id, SessionState::SessionStateActive),
                range_data_notf(range_data.clone()),
            ],
            Ok(()),
        );
        uci_manager.expect_range_stop(
            session_id,
            vec![session_status_notf(session_id, SessionState::SessionStateIdle)],
            Ok(()),
        );
        uci_manager.expect_session_deinit(
            session_id,
            vec![session_status_notf(session_id, SessionState::SessionStateDeinit)],
            Ok(()),
        );

        let (notf_sender, mut notf_receiver) = mpsc::unbounded_channel();
        let mut service = UwbService::new(notf_sender, uci_manager.clone());
        service.enable().await.unwrap();

        // Initialize a normal session.
        let result = service.init_session(session_id, session_type, params.clone()).await;
        assert!(result.is_ok());
        let session_notf = notf_receiver.recv().await.unwrap();
        assert_eq!(
            session_notf,
            UwbNotification::SessionState {
                session_id,
                session_state: SessionState::SessionStateInit,
                reason_code: ReasonCode::StateChangeWithSessionManagementCommands
            }
        );
        let session_notf = notf_receiver.recv().await.unwrap();
        assert_eq!(
            session_notf,
            UwbNotification::SessionState {
                session_id,
                session_state: SessionState::SessionStateIdle,
                reason_code: ReasonCode::StateChangeWithSessionManagementCommands
            }
        );

        // Start the ranging process, and should receive the range data.
        let result = service.start_ranging(session_id).await;
        assert!(result.is_ok());
        let session_notf = notf_receiver.recv().await.unwrap();
        assert_eq!(
            session_notf,
            UwbNotification::SessionState {
                session_id,
                session_state: SessionState::SessionStateActive,
                reason_code: ReasonCode::StateChangeWithSessionManagementCommands
            }
        );
        let session_notf = notf_receiver.recv().await.unwrap();
        assert_eq!(session_notf, UwbNotification::RangeData { session_id, range_data });

        // Stop the ranging process.
        let result = service.stop_ranging(session_id).await;
        assert!(result.is_ok());
        let session_notf = notf_receiver.recv().await.unwrap();
        assert_eq!(
            session_notf,
            UwbNotification::SessionState {
                session_id,
                session_state: SessionState::SessionStateIdle,
                reason_code: ReasonCode::StateChangeWithSessionManagementCommands
            }
        );

        // Deinitialize the session, and should receive the deinitialized notification.
        let result = service.deinit_session(session_id).await;
        assert!(result.is_ok());
        let session_notf = notf_receiver.recv().await.unwrap();
        assert_eq!(
            session_notf,
            UwbNotification::SessionState {
                session_id,
                session_state: SessionState::SessionStateDeinit,
                reason_code: ReasonCode::StateChangeWithSessionManagementCommands
            }
        );

        assert!(uci_manager.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_session_api_without_enabled() {
        let session_id = 0x123;
        let session_type = SessionType::FiraRangingSession;
        let params = generate_params();
        let action = UpdateMulticastListAction::AddControlee;
        let controlees = vec![Controlee { short_address: 0x13, subsession_id: 0x24 }];

        let uci_manager = MockUciManager::new();
        let mut service = UwbService::new(mpsc::unbounded_channel().0, uci_manager);

        let result = service.init_session(session_id, session_type, params.clone()).await;
        assert!(result.is_err());
        let result = service.deinit_session(session_id).await;
        assert!(result.is_err());
        let result = service.start_ranging(session_id).await;
        assert!(result.is_err());
        let result = service.stop_ranging(session_id).await;
        assert!(result.is_err());
        let result = service.reconfigure(session_id, params).await;
        assert!(result.is_err());
        let result = service.update_controller_multicast_list(session_id, action, controlees).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_android_set_country_code() {
        let country_code = CountryCode::new(b"US").unwrap();
        let mut uci_manager = MockUciManager::new();
        uci_manager.expect_android_set_country_code(country_code.clone(), Ok(()));
        let mut service = UwbService::new(mpsc::unbounded_channel().0, uci_manager);

        let result = service.android_set_country_code(country_code).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_android_get_power_stats() {
        let stats = PowerStats {
            status: StatusCode::UciStatusOk,
            idle_time_ms: 123,
            tx_time_ms: 456,
            rx_time_ms: 789,
            total_wake_count: 5,
        };
        let mut uci_manager = MockUciManager::new();
        uci_manager.expect_android_get_power_stats(Ok(stats.clone()));
        let mut service = UwbService::new(mpsc::unbounded_channel().0, uci_manager);

        let result = service.android_get_power_stats().await.unwrap();
        assert_eq!(result, stats);
    }

    #[tokio::test]
    async fn test_send_vendor_cmd() {
        let gid = 0x09;
        let oid = 0x35;
        let cmd_payload = vec![0x12, 0x34];
        let resp_payload = vec![0x56, 0x78];

        let mut uci_manager = MockUciManager::new();
        uci_manager.expect_raw_vendor_cmd(
            gid,
            oid,
            cmd_payload.clone(),
            Ok(RawVendorMessage { gid, oid, payload: resp_payload.clone() }),
        );
        let mut service = UwbService::new(mpsc::unbounded_channel().0, uci_manager);

        let result = service.send_vendor_cmd(gid, oid, cmd_payload).await.unwrap();
        assert_eq!(result, RawVendorMessage { gid, oid, payload: resp_payload });
    }

    #[tokio::test]
    async fn test_vendor_notification() {
        let gid = 5;
        let oid = 7;
        let payload = vec![0x13, 0x47];

        let mut uci_manager = MockUciManager::new();
        uci_manager.expect_open_hal(
            vec![UciNotification::Vendor(RawVendorMessage { gid, oid, payload: payload.clone() })],
            Ok(()),
        );
        let (notf_sender, mut notf_receiver) = mpsc::unbounded_channel();
        let mut service = UwbService::new(notf_sender, uci_manager);
        service.enable().await.unwrap();

        let expected_notf = UwbNotification::VendorNotification { gid, oid, payload };
        let notf = notf_receiver.recv().await.unwrap();
        assert_eq!(notf, expected_notf);
    }

    #[tokio::test]
    async fn test_core_device_status_notification() {
        let state = DeviceState::DeviceStateReady;

        let mut uci_manager = MockUciManager::new();
        uci_manager.expect_open_hal(
            vec![UciNotification::Core(CoreNotification::DeviceStatus(state))],
            Ok(()),
        );
        let (notf_sender, mut notf_receiver) = mpsc::unbounded_channel();
        let mut service = UwbService::new(notf_sender, uci_manager);
        service.enable().await.unwrap();

        let expected_notf = UwbNotification::UciDeviceStatus(state);
        let notf = notf_receiver.recv().await.unwrap();
        assert_eq!(notf, expected_notf);
    }

    #[tokio::test]
    async fn test_reset_service_after_timeout() {
        let mut uci_manager = MockUciManager::new();
        // The first open_hal() returns timeout.
        uci_manager.expect_open_hal(vec![], Err(Error::Timeout));
        // Then UwbService should close_hal() and open_hal() to reset the HAL.
        uci_manager.expect_close_hal(true, Ok(()));
        uci_manager.expect_open_hal(vec![], Ok(()));
        let (notf_sender, mut notf_receiver) = mpsc::unbounded_channel();
        let mut service = UwbService::new(notf_sender, uci_manager.clone());

        let result = service.enable().await;
        assert_eq!(result, Err(Error::Timeout));

        let expected_notf = UwbNotification::ServiceReset { success: true };
        let notf = notf_receiver.recv().await.unwrap();
        assert_eq!(notf, expected_notf);

        assert!(uci_manager.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_reset_service_when_error_state() {
        let mut uci_manager = MockUciManager::new();
        // The first open_hal() send DeviceStateError notification.
        uci_manager.expect_open_hal(
            vec![UciNotification::Core(CoreNotification::DeviceStatus(
                DeviceState::DeviceStateError,
            ))],
            Ok(()),
        );
        // Then UwbService should close_hal() and open_hal() to reset the HAL.
        uci_manager.expect_close_hal(true, Ok(()));
        uci_manager.expect_open_hal(vec![], Ok(()));
        let (notf_sender, mut notf_receiver) = mpsc::unbounded_channel();
        let mut service = UwbService::new(notf_sender, uci_manager.clone());

        let result = service.enable().await;
        assert_eq!(result, Ok(()));

        let expected_notf = UwbNotification::ServiceReset { success: true };
        let notf = notf_receiver.recv().await.unwrap();
        assert_eq!(notf, expected_notf);

        assert!(uci_manager.wait_expected_calls_done().await);
    }
}
