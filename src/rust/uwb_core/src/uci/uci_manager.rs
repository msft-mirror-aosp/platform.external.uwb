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

use std::convert::TryInto;
use std::time::Duration;

use async_trait::async_trait;
use log::{debug, error, warn};
use tokio::sync::{mpsc, oneshot};
use uwb_uci_packets::{Packet, UciCommandPacket};

use crate::uci::command::UciCommand;
use crate::uci::error::{UciError, UciResult};
use crate::uci::message::UciMessage;
use crate::uci::notification::UciNotification;
use crate::uci::params::{
    AppConfigTlv, AppConfigTlvType, CapTlv, Controlee, CoreSetConfigResponse, CountryCode,
    DeviceConfigId, DeviceConfigTlv, DeviceState, GetDeviceInfoResponse, PowerStats,
    RawVendorMessage, ResetConfig, SessionId, SessionState, SessionType, SetAppConfigResponse,
    UpdateMulticastListAction,
};
use crate::uci::response::UciResponse;
use crate::uci::timeout_uci_hal::TimeoutUciHal;
use crate::uci::uci_hal::{RawUciMessage, UciHal};
use crate::utils::PinSleep;

const UCI_TIMEOUT_MS: u64 = 800;
const MAX_RETRY_COUNT: usize = 3;

/// The UciManager organizes the state machine of the UWB HAL, and provides the interface which
/// abstracts the UCI commands, responses, and notifications.
#[async_trait]
pub(crate) trait UciManager {
    // Open the UCI HAL.
    // All the other methods should be called after the open_hal() completes successfully.
    async fn open_hal(
        &mut self,
        notf_sender: mpsc::UnboundedSender<UciNotification>,
    ) -> UciResult<()>;

    // Close the UCI HAL.
    async fn close_hal(&mut self) -> UciResult<()>;

    // Send the standard UCI Commands.
    async fn device_reset(&mut self, reset_config: ResetConfig) -> UciResult<()>;
    async fn core_get_device_info(&mut self) -> UciResult<GetDeviceInfoResponse>;
    async fn core_get_caps_info(&mut self) -> UciResult<Vec<CapTlv>>;
    async fn core_set_config(
        &mut self,
        config_tlvs: Vec<DeviceConfigTlv>,
    ) -> UciResult<CoreSetConfigResponse>;
    async fn core_get_config(
        &mut self,
        config_ids: Vec<DeviceConfigId>,
    ) -> UciResult<Vec<DeviceConfigTlv>>;
    async fn session_init(
        &mut self,
        session_id: SessionId,
        session_type: SessionType,
    ) -> UciResult<()>;
    async fn session_deinit(&mut self, session_id: SessionId) -> UciResult<()>;
    async fn session_set_app_config(
        &mut self,
        session_id: SessionId,
        config_tlvs: Vec<AppConfigTlv>,
    ) -> UciResult<SetAppConfigResponse>;
    async fn session_get_app_config(
        &mut self,
        session_id: SessionId,
        config_ids: Vec<AppConfigTlvType>,
    ) -> UciResult<Vec<AppConfigTlv>>;
    async fn session_get_count(&mut self) -> UciResult<usize>;
    async fn session_get_state(&mut self, session_id: SessionId) -> UciResult<SessionState>;
    async fn session_update_controller_multicast_list(
        &mut self,
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: Vec<Controlee>,
    ) -> UciResult<()>;
    async fn range_start(&mut self, session_id: SessionId) -> UciResult<()>;
    async fn range_stop(&mut self, session_id: SessionId) -> UciResult<()>;
    async fn range_get_ranging_count(&mut self, session_id: SessionId) -> UciResult<usize>;

    // Send the Android-specific UCI commands
    async fn android_set_country_code(&mut self, country_code: CountryCode) -> UciResult<()>;
    async fn android_get_power_stats(&mut self) -> UciResult<PowerStats>;

    // Send a raw vendor command.
    async fn raw_vendor_cmd(
        &mut self,
        gid: u32,
        oid: u32,
        payload: Vec<u8>,
    ) -> UciResult<RawVendorMessage>;
}

/// UciManagerImpl is the main implementation of UciManager. Using the actor model, UciManagerImpl
/// delegates the requests to UciManagerActor.
#[derive(Clone)]
pub(crate) struct UciManagerImpl {
    cmd_sender: mpsc::UnboundedSender<(UciManagerCmd, oneshot::Sender<UciResult<UciResponse>>)>,
}

impl UciManagerImpl {
    pub fn new<T: UciHal>(hal: T) -> Self {
        let (cmd_sender, cmd_receiver) = mpsc::unbounded_channel();
        let mut actor = UciManagerActor::new(hal, cmd_receiver);
        tokio::spawn(async move { actor.run().await });

        Self { cmd_sender }
    }

    // Send the |cmd| to the UciManagerActor.
    async fn send_cmd(&self, cmd: UciManagerCmd) -> UciResult<UciResponse> {
        let (result_sender, result_receiver) = oneshot::channel();
        match self.cmd_sender.send((cmd, result_sender)) {
            Ok(()) => result_receiver.await.unwrap_or(Err(UciError::HalFailed)),
            Err(cmd) => {
                error!("Failed to send cmd: {:?}", cmd.0);
                Err(UciError::HalFailed)
            }
        }
    }
}

#[async_trait]
impl UciManager for UciManagerImpl {
    async fn open_hal(
        &mut self,
        notf_sender: mpsc::UnboundedSender<UciNotification>,
    ) -> UciResult<()> {
        match self.send_cmd(UciManagerCmd::OpenHal { notf_sender }).await {
            Ok(UciResponse::OpenHal) => Ok(()),
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn close_hal(&mut self) -> UciResult<()> {
        match self.send_cmd(UciManagerCmd::CloseHal).await {
            Ok(UciResponse::CloseHal) => Ok(()),
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn device_reset(&mut self, reset_config: ResetConfig) -> UciResult<()> {
        let cmd = UciCommand::DeviceReset { reset_config };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::DeviceReset(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn core_get_device_info(&mut self) -> UciResult<GetDeviceInfoResponse> {
        let cmd = UciCommand::CoreGetDeviceInfo;
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::CoreGetDeviceInfo(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn core_get_caps_info(&mut self) -> UciResult<Vec<CapTlv>> {
        let cmd = UciCommand::CoreGetCapsInfo;
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::CoreGetCapsInfo(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn core_set_config(
        &mut self,
        config_tlvs: Vec<DeviceConfigTlv>,
    ) -> UciResult<CoreSetConfigResponse> {
        let cmd = UciCommand::CoreSetConfig { config_tlvs };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::CoreSetConfig(resp)) => Ok(resp),
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn core_get_config(
        &mut self,
        cfg_id: Vec<DeviceConfigId>,
    ) -> UciResult<Vec<DeviceConfigTlv>> {
        let cmd = UciCommand::CoreGetConfig { cfg_id };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::CoreGetConfig(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn session_init(
        &mut self,
        session_id: SessionId,
        session_type: SessionType,
    ) -> UciResult<()> {
        let cmd = UciCommand::SessionInit { session_id, session_type };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionInit(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn session_deinit(&mut self, session_id: SessionId) -> UciResult<()> {
        let cmd = UciCommand::SessionDeinit { session_id };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionDeinit(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn session_set_app_config(
        &mut self,
        session_id: SessionId,
        config_tlvs: Vec<AppConfigTlv>,
    ) -> UciResult<SetAppConfigResponse> {
        let cmd = UciCommand::SessionSetAppConfig { session_id, config_tlvs };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionSetAppConfig(resp)) => Ok(resp),
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn session_get_app_config(
        &mut self,
        session_id: SessionId,
        app_cfg: Vec<AppConfigTlvType>,
    ) -> UciResult<Vec<AppConfigTlv>> {
        let cmd = UciCommand::SessionGetAppConfig { session_id, app_cfg };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionGetAppConfig(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn session_get_count(&mut self) -> UciResult<usize> {
        let cmd = UciCommand::SessionGetCount;
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionGetCount(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn session_get_state(&mut self, session_id: SessionId) -> UciResult<SessionState> {
        let cmd = UciCommand::SessionGetState { session_id };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionGetState(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn session_update_controller_multicast_list(
        &mut self,
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: Vec<Controlee>,
    ) -> UciResult<()> {
        let cmd =
            UciCommand::SessionUpdateControllerMulticastList { session_id, action, controlees };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionUpdateControllerMulticastList(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn range_start(&mut self, session_id: SessionId) -> UciResult<()> {
        let cmd = UciCommand::RangeStart { session_id };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::RangeStart(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn range_stop(&mut self, session_id: SessionId) -> UciResult<()> {
        let cmd = UciCommand::RangeStop { session_id };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::RangeStop(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn range_get_ranging_count(&mut self, session_id: SessionId) -> UciResult<usize> {
        let cmd = UciCommand::RangeGetRangingCount { session_id };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::RangeGetRangingCount(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn android_set_country_code(&mut self, country_code: CountryCode) -> UciResult<()> {
        let cmd = UciCommand::AndroidSetCountryCode { country_code };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::AndroidSetCountryCode(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn android_get_power_stats(&mut self) -> UciResult<PowerStats> {
        let cmd = UciCommand::AndroidGetPowerStats;
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::AndroidGetPowerStats(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }

    async fn raw_vendor_cmd(
        &mut self,
        gid: u32,
        oid: u32,
        payload: Vec<u8>,
    ) -> UciResult<RawVendorMessage> {
        let cmd = UciCommand::RawVendorCmd { gid, oid, payload };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::RawVendorCmd(resp)) => resp,
            Ok(_) => Err(UciError::ResponseMismatched),
            Err(e) => Err(e),
        }
    }
}

struct UciManagerActor<T: UciHal> {
    // The UCI HAL.
    hal: TimeoutUciHal<T>,
    // Receive the commands and the corresponding response senders from UciManager.
    cmd_receiver: mpsc::UnboundedReceiver<(UciManagerCmd, oneshot::Sender<UciResult<UciResponse>>)>,

    // Set to true when |hal| is opened successfully.
    is_hal_opened: bool,
    // Receive the response and the notification from |hal|. Only used when |hal| is opened
    // successfully.
    msg_receiver: mpsc::UnboundedReceiver<RawUciMessage>,
    // Send the notification to the UciManager. Only valid when |hal| is opened successfully.
    notf_sender: Option<mpsc::UnboundedSender<UciNotification>>,

    // The response sender of UciManager's open_hal() method. Used to wait for the device ready
    // notification.
    open_hal_result_sender: Option<oneshot::Sender<UciResult<UciResponse>>>,
    // The timeout of waiting for the notification of device ready notification.
    wait_device_status_timeout: PinSleep,

    // Used for the logic of retrying the command. Only valid when waiting for the response of a
    // UCI command.
    retryer: Option<Retryer>,
    // The timeout of waiting for the response. Only used when waiting for the response of a UCI
    // command.
    wait_resp_timeout: PinSleep,
}

impl<T: UciHal> UciManagerActor<T> {
    fn new(
        hal: T,
        cmd_receiver: mpsc::UnboundedReceiver<(
            UciManagerCmd,
            oneshot::Sender<UciResult<UciResponse>>,
        )>,
    ) -> Self {
        Self {
            hal: TimeoutUciHal::new(hal),
            cmd_receiver,
            is_hal_opened: false,
            msg_receiver: mpsc::unbounded_channel().1,
            notf_sender: None,
            open_hal_result_sender: None,
            wait_device_status_timeout: PinSleep::new(Duration::MAX),
            retryer: None,
            wait_resp_timeout: PinSleep::new(Duration::MAX),
        }
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                // Handle the next command. Only when the previous command already received the
                // response.
                cmd = self.cmd_receiver.recv(), if !self.is_waiting_resp() => {
                    match cmd {
                        None => {
                            debug!("UciManager is about to drop.");
                            return;
                        },
                        Some((cmd, result_sender)) => {
                            self.handle_cmd(cmd, result_sender).await;
                        }
                    }
                }

                // Handle the UCI response or notification from HAL. Only when HAL is opened.
                msg = self.msg_receiver.recv(), if self.is_hal_opened => {
                    match msg {
                        None => {
                            warn!("UciHal dropped the msg_sender unexpectedly.");
                            self.on_hal_closed();
                        },
                        Some(msg) => {
                            match msg.try_into() {
                                Ok(UciMessage::Response(resp)) => {
                                    self.handle_response(resp).await;
                                }
                                Ok(UciMessage::Notification(notf)) => {
                                    self.handle_notification(notf).await;
                                }
                                Err(e)=> {
                                    error!("Failed to parse received message: {:?}", e);
                                }
                            }
                        },
                    }
                }

                // Timeout waiting for the response of the UCI command.
                _ = &mut self.wait_resp_timeout, if self.is_waiting_resp() => {
                    self.retryer.take().unwrap().send_result(Err(UciError::Timeout));
                }

                // Timeout waiting for the notification of the device status.
                _ = &mut self.wait_device_status_timeout, if self.is_waiting_device_status() => {
                    if let Some(result_sender) = self.open_hal_result_sender.take() {
                        let _ = result_sender.send(Err(UciError::Timeout));
                    }
                }
            }
        }
    }

    async fn handle_cmd(
        &mut self,
        cmd: UciManagerCmd,
        result_sender: oneshot::Sender<UciResult<UciResponse>>,
    ) {
        debug!("Received cmd: {:?}", cmd);

        match cmd {
            UciManagerCmd::OpenHal { notf_sender } => {
                if self.is_hal_opened {
                    warn!("The UCI HAL is already opened, skip.");
                    let _ = result_sender.send(Err(UciError::WrongState));
                    return;
                }

                let (msg_sender, msg_receiver) = mpsc::unbounded_channel();
                match self.hal.open(msg_sender).await {
                    Ok(()) => {
                        self.on_hal_open(msg_receiver, notf_sender);
                        self.wait_device_status_timeout =
                            PinSleep::new(Duration::from_millis(UCI_TIMEOUT_MS));
                        self.open_hal_result_sender.replace(result_sender);
                    }
                    Err(e) => {
                        error!("Failed to open hal: {:?}", e);
                        let _ = result_sender.send(Err(e));
                    }
                }
            }

            UciManagerCmd::CloseHal => {
                if !self.is_hal_opened {
                    warn!("The UCI HAL is already closed, skip.");
                    let _ = result_sender.send(Err(UciError::WrongState));
                    return;
                }

                let result = self.hal.close().await.map(|_| UciResponse::CloseHal);
                if result.is_ok() {
                    self.on_hal_closed();
                }
                let _ = result_sender.send(result);
            }

            UciManagerCmd::SendUciCommand { cmd } => {
                debug_assert!(self.retryer.is_none());
                self.retryer = Some(Retryer { cmd, result_sender, retry_count: MAX_RETRY_COUNT });
                self.retry_command().await;
            }
        }
    }

    async fn retry_command(&mut self) {
        if let Some(mut retryer) = self.retryer.take() {
            if !retryer.could_retry() {
                retryer.send_result(Err(UciError::Timeout));
                return;
            }

            match self.send_uci_command(retryer.cmd.clone()).await {
                Ok(_) => {
                    self.wait_resp_timeout = PinSleep::new(Duration::from_millis(UCI_TIMEOUT_MS));
                    self.retryer = Some(retryer);
                }
                Err(e) => {
                    retryer.send_result(Err(e));
                }
            }
        }
    }

    async fn send_uci_command(&mut self, cmd: UciCommand) -> UciResult<()> {
        if !self.is_hal_opened {
            warn!("The UCI HAL is already closed, skip.");
            return Err(UciError::WrongState);
        }

        let packet = TryInto::<UciCommandPacket>::try_into(cmd)?;
        self.hal.send_command(packet.to_vec()).await?;
        Ok(())
    }

    async fn handle_response(&mut self, resp: UciResponse) {
        if resp.need_retry() {
            self.retry_command().await;
            return;
        }

        if let Some(retryer) = self.retryer.take() {
            retryer.send_result(Ok(resp));
        } else {
            warn!("Received an UCI response unexpectedly: {:?}", resp);
        }
    }

    async fn handle_notification(&mut self, notf: UciNotification) {
        if notf.need_retry() {
            self.retry_command().await;
            return;
        }

        match notf.clone() {
            UciNotification::CoreDeviceStatus(status) => {
                if let Some(result_sender) = self.open_hal_result_sender.take() {
                    let result = match status {
                        DeviceState::DeviceStateReady | DeviceState::DeviceStateActive => {
                            Ok(UciResponse::OpenHal)
                        }
                        _ => Err(UciError::HalFailed),
                    };
                    let _ = result_sender.send(result);
                }
            }
            UciNotification::SessionStatus { session_id, session_state, reason_code: _ } => {
                if matches!(session_state, SessionState::SessionStateInit) {
                    if let Err(e) = self.hal.notify_session_initialized(session_id).await {
                        warn!("notify_session_initialized() failed: {:?}", e);
                    }
                }
            }
            _ => {}
        }

        if let Some(notf_sender) = self.notf_sender.as_mut() {
            let _ = notf_sender.send(notf);
        }
    }

    fn on_hal_open(
        &mut self,
        msg_receiver: mpsc::UnboundedReceiver<RawUciMessage>,
        notf_sender: mpsc::UnboundedSender<UciNotification>,
    ) {
        self.is_hal_opened = true;
        self.msg_receiver = msg_receiver;
        self.notf_sender = Some(notf_sender);
    }

    fn on_hal_closed(&mut self) {
        self.is_hal_opened = false;
        self.msg_receiver = mpsc::unbounded_channel().1;
        self.notf_sender = None;
    }

    fn is_waiting_resp(&self) -> bool {
        self.retryer.is_some()
    }
    fn is_waiting_device_status(&self) -> bool {
        self.open_hal_result_sender.is_some()
    }
}

struct Retryer {
    cmd: UciCommand,
    result_sender: oneshot::Sender<UciResult<UciResponse>>,
    retry_count: usize,
}

impl Retryer {
    fn could_retry(&mut self) -> bool {
        if self.retry_count == 0 {
            return false;
        }
        self.retry_count -= 1;
        true
    }

    fn send_result(self, result: UciResult<UciResponse>) {
        let _ = self.result_sender.send(result);
    }
}

#[derive(Debug)]
enum UciManagerCmd {
    OpenHal { notf_sender: mpsc::UnboundedSender<UciNotification> },
    CloseHal,
    SendUciCommand { cmd: UciCommand },
}
