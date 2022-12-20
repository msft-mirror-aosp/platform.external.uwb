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
use num_traits::{FromPrimitive, ToPrimitive};
use tokio::sync::{mpsc, oneshot};

use crate::uci::command::UciCommand;
//use crate::uci::error::{Error, Result};
use crate::error::{Error, Result};
use crate::params::uci_packets::{
    AppConfigTlv, AppConfigTlvType, CapTlv, Controlee, ControleesV2, CoreSetConfigResponse,
    CountryCode, DeviceConfigId, DeviceConfigTlv, DeviceState, GetDeviceInfoResponse, GroupId,
    MessageType, PowerStats, RawUciMessage, ResetConfig, SessionId, SessionState, SessionType,
    SessionUpdateActiveRoundsDtTagResponse, SetAppConfigResponse, UciControlPacketPacket,
    UciDataPacketPacket, UpdateMulticastListAction,
};
use crate::uci::message::UciMessage;
use crate::uci::notification::{
    CoreNotification, DataRcvNotification, SessionNotification, UciNotification,
};
use crate::uci::response::UciResponse;
use crate::uci::timeout_uci_hal::TimeoutUciHal;
use crate::uci::uci_hal::{UciHal, UciHalPacket};
use crate::uci::uci_logger::{UciLogger, UciLoggerMode, UciLoggerWrapper};
use crate::utils::{clean_mpsc_receiver, PinSleep};
use uwb_uci_packets::UciDefragPacket;

const UCI_TIMEOUT_MS: u64 = 800;
const MAX_RETRY_COUNT: usize = 3;

/// The UciManager organizes the state machine of the UWB HAL, and provides the interface which
/// abstracts the UCI commands, responses, and notifications.
#[async_trait]
pub(crate) trait UciManager: 'static + Send + Sync + Clone {
    async fn set_logger_mode(&self, logger_mode: UciLoggerMode) -> Result<()>;
    // Set the sendor of the UCI notificaions.
    async fn set_core_notification_sender(
        &mut self,
        core_notf_sender: mpsc::UnboundedSender<CoreNotification>,
    );
    async fn set_session_notification_sender(
        &mut self,
        session_notf_sender: mpsc::UnboundedSender<SessionNotification>,
    );
    async fn set_vendor_notification_sender(
        &mut self,
        vendor_notf_sender: mpsc::UnboundedSender<RawUciMessage>,
    );
    async fn set_data_rcv_notification_sender(
        &mut self,
        data_rcv_notf_sender: mpsc::UnboundedSender<DataRcvNotification>,
    );

    // Open the UCI HAL.
    // All the UCI commands should be called after the open_hal() completes successfully.
    async fn open_hal(&self) -> Result<()>;

    // Close the UCI HAL.
    async fn close_hal(&self, force: bool) -> Result<()>;

    // Send the standard UCI Commands.
    async fn device_reset(&self, reset_config: ResetConfig) -> Result<()>;
    async fn core_get_device_info(&self) -> Result<GetDeviceInfoResponse>;
    async fn core_get_caps_info(&self) -> Result<Vec<CapTlv>>;
    async fn core_set_config(
        &self,
        config_tlvs: Vec<DeviceConfigTlv>,
    ) -> Result<CoreSetConfigResponse>;
    async fn core_get_config(
        &self,
        config_ids: Vec<DeviceConfigId>,
    ) -> Result<Vec<DeviceConfigTlv>>;
    async fn session_init(&self, session_id: SessionId, session_type: SessionType) -> Result<()>;
    async fn session_deinit(&self, session_id: SessionId) -> Result<()>;
    async fn session_set_app_config(
        &self,
        session_id: SessionId,
        config_tlvs: Vec<AppConfigTlv>,
    ) -> Result<SetAppConfigResponse>;
    async fn session_get_app_config(
        &self,
        session_id: SessionId,
        config_ids: Vec<AppConfigTlvType>,
    ) -> Result<Vec<AppConfigTlv>>;
    async fn session_get_count(&self) -> Result<u8>;
    async fn session_get_state(&self, session_id: SessionId) -> Result<SessionState>;
    async fn session_update_controller_multicast_list(
        &self,
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: Vec<Controlee>,
    ) -> Result<()>;
    async fn session_update_controller_multicast_list_v2(
        &self,
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: ControleesV2,
    ) -> Result<()>;
    // Update active ranging rounds update for DT
    async fn session_update_active_rounds_dt_tag(
        &self,
        session_id: u32,
        ranging_round_indexes: Vec<u8>,
    ) -> Result<SessionUpdateActiveRoundsDtTagResponse>;

    async fn range_start(&self, session_id: SessionId) -> Result<()>;
    async fn range_stop(&self, session_id: SessionId) -> Result<()>;
    async fn range_get_ranging_count(&self, session_id: SessionId) -> Result<usize>;

    // Send the Android-specific UCI commands
    async fn android_set_country_code(&self, country_code: CountryCode) -> Result<()>;
    async fn android_get_power_stats(&self) -> Result<PowerStats>;

    // Send a raw uci command.
    async fn raw_uci_cmd(&self, gid: u32, oid: u32, payload: Vec<u8>) -> Result<RawUciMessage>;
}

/// UciManagerImpl is the main implementation of UciManager. Using the actor model, UciManagerImpl
/// delegates the requests to UciManagerActor.
#[derive(Clone)]
pub(crate) struct UciManagerImpl {
    cmd_sender: mpsc::UnboundedSender<(UciManagerCmd, oneshot::Sender<Result<UciResponse>>)>,
}

impl UciManagerImpl {
    pub fn new<T: UciHal, U: UciLogger>(hal: T, logger: U, logger_mode: UciLoggerMode) -> Self {
        let (cmd_sender, cmd_receiver) = mpsc::unbounded_channel();
        let mut actor = UciManagerActor::new(hal, logger, logger_mode, cmd_receiver);
        tokio::spawn(async move { actor.run().await });

        Self { cmd_sender }
    }

    // Send the |cmd| to the UciManagerActor.
    async fn send_cmd(&self, cmd: UciManagerCmd) -> Result<UciResponse> {
        let (result_sender, result_receiver) = oneshot::channel();
        match self.cmd_sender.send((cmd, result_sender)) {
            Ok(()) => result_receiver.await.unwrap_or(Err(Error::Unknown)),
            Err(cmd) => {
                error!("Failed to send cmd: {:?}", cmd.0);
                Err(Error::Unknown)
            }
        }
    }
}

#[async_trait]
impl UciManager for UciManagerImpl {
    async fn set_logger_mode(&self, logger_mode: UciLoggerMode) -> Result<()> {
        match self.send_cmd(UciManagerCmd::SetLoggerMode { logger_mode }).await {
            Ok(UciResponse::SetLoggerMode) => Ok(()),
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }
    async fn set_core_notification_sender(
        &mut self,
        core_notf_sender: mpsc::UnboundedSender<CoreNotification>,
    ) {
        let _ = self.send_cmd(UciManagerCmd::SetCoreNotificationSender { core_notf_sender }).await;
    }
    async fn set_session_notification_sender(
        &mut self,
        session_notf_sender: mpsc::UnboundedSender<SessionNotification>,
    ) {
        let _ = self
            .send_cmd(UciManagerCmd::SetSessionNotificationSender { session_notf_sender })
            .await;
    }
    async fn set_vendor_notification_sender(
        &mut self,
        vendor_notf_sender: mpsc::UnboundedSender<RawUciMessage>,
    ) {
        let _ =
            self.send_cmd(UciManagerCmd::SetVendorNotificationSender { vendor_notf_sender }).await;
    }
    async fn set_data_rcv_notification_sender(
        &mut self,
        data_rcv_notf_sender: mpsc::UnboundedSender<DataRcvNotification>,
    ) {
        let _ = self
            .send_cmd(UciManagerCmd::SetDataRcvNotificationSender { data_rcv_notf_sender })
            .await;
    }

    async fn open_hal(&self) -> Result<()> {
        match self.send_cmd(UciManagerCmd::OpenHal).await {
            Ok(UciResponse::OpenHal) => {
                // According to the UCI spec: "The Host shall send CORE_GET_DEVICE_INFO_CMD to
                // retrieve the device information.", we call get_device_info() after successfully
                // opening the HAL.
                let device_info = self.core_get_device_info().await;
                debug!("UCI device info: {:?}", device_info);

                Ok(())
            }
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn close_hal(&self, force: bool) -> Result<()> {
        match self.send_cmd(UciManagerCmd::CloseHal { force }).await {
            Ok(UciResponse::CloseHal) => Ok(()),
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn device_reset(&self, reset_config: ResetConfig) -> Result<()> {
        let cmd = UciCommand::DeviceReset { reset_config };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::DeviceReset(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn core_get_device_info(&self) -> Result<GetDeviceInfoResponse> {
        let cmd = UciCommand::CoreGetDeviceInfo;
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::CoreGetDeviceInfo(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn core_get_caps_info(&self) -> Result<Vec<CapTlv>> {
        let cmd = UciCommand::CoreGetCapsInfo;
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::CoreGetCapsInfo(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn core_set_config(
        &self,
        config_tlvs: Vec<DeviceConfigTlv>,
    ) -> Result<CoreSetConfigResponse> {
        let cmd = UciCommand::CoreSetConfig { config_tlvs };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::CoreSetConfig(resp)) => Ok(resp),
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn core_get_config(&self, cfg_id: Vec<DeviceConfigId>) -> Result<Vec<DeviceConfigTlv>> {
        let cmd = UciCommand::CoreGetConfig { cfg_id };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::CoreGetConfig(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn session_init(&self, session_id: SessionId, session_type: SessionType) -> Result<()> {
        let cmd = UciCommand::SessionInit { session_id, session_type };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionInit(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn session_deinit(&self, session_id: SessionId) -> Result<()> {
        let cmd = UciCommand::SessionDeinit { session_id };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionDeinit(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn session_set_app_config(
        &self,
        session_id: SessionId,
        config_tlvs: Vec<AppConfigTlv>,
    ) -> Result<SetAppConfigResponse> {
        let cmd = UciCommand::SessionSetAppConfig { session_id, config_tlvs };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionSetAppConfig(resp)) => Ok(resp),
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn session_get_app_config(
        &self,
        session_id: SessionId,
        app_cfg: Vec<AppConfigTlvType>,
    ) -> Result<Vec<AppConfigTlv>> {
        let cmd = UciCommand::SessionGetAppConfig { session_id, app_cfg };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionGetAppConfig(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn session_get_count(&self) -> Result<u8> {
        let cmd = UciCommand::SessionGetCount;
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionGetCount(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn session_get_state(&self, session_id: SessionId) -> Result<SessionState> {
        let cmd = UciCommand::SessionGetState { session_id };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionGetState(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn session_update_controller_multicast_list(
        &self,
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: Vec<Controlee>,
    ) -> Result<()> {
        if !(1..=8).contains(&controlees.len()) {
            warn!("Number of controlees should be between 1 to 8");
            return Err(Error::BadParameters);
        }
        let cmd =
            UciCommand::SessionUpdateControllerMulticastList { session_id, action, controlees };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionUpdateControllerMulticastList(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn session_update_controller_multicast_list_v2(
        &self,
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: ControleesV2,
    ) -> Result<()> {
        let controlees_len = match controlees {
            ControleesV2::NoSessionKey(ref controlee_vec) => controlee_vec.len(),
            ControleesV2::ShortSessionKey(ref controlee_vec) => controlee_vec.len(),
            ControleesV2::LongSessionKey(ref controlee_vec) => controlee_vec.len(),
        };
        if !(1..=8).contains(&controlees_len) {
            warn!("Number of controlees should be between 1 to 8");
            return Err(Error::BadParameters);
        }
        let cmd =
            UciCommand::SessionUpdateControllerMulticastListV2 { session_id, action, controlees };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionUpdateControllerMulticastList(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn session_update_active_rounds_dt_tag(
        &self,
        session_id: u32,
        ranging_round_indexes: Vec<u8>,
    ) -> Result<SessionUpdateActiveRoundsDtTagResponse> {
        let cmd = UciCommand::SessionUpdateActiveRoundsDtTag { session_id, ranging_round_indexes };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::SessionUpdateActiveRoundsDtTag(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn range_start(&self, session_id: SessionId) -> Result<()> {
        let cmd = UciCommand::RangeStart { session_id };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::RangeStart(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn range_stop(&self, session_id: SessionId) -> Result<()> {
        let cmd = UciCommand::RangeStop { session_id };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::RangeStop(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn range_get_ranging_count(&self, session_id: SessionId) -> Result<usize> {
        let cmd = UciCommand::RangeGetRangingCount { session_id };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::RangeGetRangingCount(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn android_set_country_code(&self, country_code: CountryCode) -> Result<()> {
        let cmd = UciCommand::AndroidSetCountryCode { country_code };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::AndroidSetCountryCode(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn android_get_power_stats(&self) -> Result<PowerStats> {
        let cmd = UciCommand::AndroidGetPowerStats;
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::AndroidGetPowerStats(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }

    async fn raw_uci_cmd(&self, gid: u32, oid: u32, payload: Vec<u8>) -> Result<RawUciMessage> {
        let cmd = UciCommand::RawUciCmd { gid, oid, payload };
        match self.send_cmd(UciManagerCmd::SendUciCommand { cmd }).await {
            Ok(UciResponse::RawUciCmd(resp)) => resp,
            Ok(_) => Err(Error::Unknown),
            Err(e) => Err(e),
        }
    }
}

struct RawCmdSignature {
    gid: GroupId,
    oid: u8,
}

impl RawCmdSignature {
    pub fn is_same_signature(&self, packet: &UciControlPacketPacket) -> bool {
        packet.get_group_id() == self.gid && packet.get_opcode() == self.oid
    }
}

struct UciManagerActor<T: UciHal, U: UciLogger> {
    // The UCI HAL.
    hal: TimeoutUciHal<T>,
    // UCI Log.
    logger: UciLoggerWrapper<U>,
    // Receive the commands and the corresponding response senders from UciManager.
    cmd_receiver: mpsc::UnboundedReceiver<(UciManagerCmd, oneshot::Sender<Result<UciResponse>>)>,

    // Set to true when |hal| is opened successfully.
    is_hal_opened: bool,
    // Receive response, notification and data packets from |hal|. Only used when |hal| is opened
    // successfully.
    packet_receiver: mpsc::UnboundedReceiver<UciHalPacket>,
    // Defrag the UCI packets.
    defrager: uwb_uci_packets::PacketDefrager,

    // The response sender of UciManager's open_hal() method. Used to wait for the device ready
    // notification.
    open_hal_result_sender: Option<oneshot::Sender<Result<UciResponse>>>,
    // The timeout of waiting for the notification of device ready notification.
    wait_device_status_timeout: PinSleep,

    // Used for the logic of retrying the command. Only valid when waiting for the response of a
    // UCI command.
    retryer: Option<Retryer>,
    // The timeout of waiting for the response. Only used when waiting for the response of a UCI
    // command.
    wait_resp_timeout: PinSleep,

    // Used to identify if response corseponds to the last vendor command, if so return
    // a raw packet as a response to the sender.
    last_raw_cmd: Option<RawCmdSignature>,

    // Send the notifications to the caller of UciManager.
    core_notf_sender: mpsc::UnboundedSender<CoreNotification>,
    session_notf_sender: mpsc::UnboundedSender<SessionNotification>,
    vendor_notf_sender: mpsc::UnboundedSender<RawUciMessage>,
    data_rcv_notf_sender: mpsc::UnboundedSender<DataRcvNotification>,
}

impl<T: UciHal, U: UciLogger> UciManagerActor<T, U> {
    fn new(
        hal: T,
        logger: U,
        logger_mode: UciLoggerMode,
        cmd_receiver: mpsc::UnboundedReceiver<(
            UciManagerCmd,
            oneshot::Sender<Result<UciResponse>>,
        )>,
    ) -> Self {
        Self {
            hal: TimeoutUciHal::new(hal),
            logger: UciLoggerWrapper::new(logger, logger_mode),
            cmd_receiver,
            is_hal_opened: false,
            packet_receiver: mpsc::unbounded_channel().1,
            defrager: Default::default(),
            open_hal_result_sender: None,
            wait_device_status_timeout: PinSleep::new(Duration::MAX),
            retryer: None,
            wait_resp_timeout: PinSleep::new(Duration::MAX),
            last_raw_cmd: None,
            core_notf_sender: mpsc::unbounded_channel().0,
            session_notf_sender: mpsc::unbounded_channel().0,
            vendor_notf_sender: mpsc::unbounded_channel().0,
            data_rcv_notf_sender: mpsc::unbounded_channel().0,
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
                            break;
                        },
                        Some((cmd, result_sender)) => {
                            self.handle_cmd(cmd, result_sender).await;
                        }
                    }
                }

                // Handle the UCI response, notification or data packet from HAL. Only when HAL
                // is opened.
                packet = self.packet_receiver.recv(), if self.is_hal_opened => {
                    self.handle_hal_packet(packet).await;
                }

                // Timeout waiting for the response of the UCI command.
                _ = &mut self.wait_resp_timeout, if self.is_waiting_resp() => {
                    self.retryer.take().unwrap().send_result(Err(Error::Timeout));
                }

                // Timeout waiting for the notification of the device status.
                _ = &mut self.wait_device_status_timeout, if self.is_waiting_device_status() => {
                    if let Some(result_sender) = self.open_hal_result_sender.take() {
                        let _ = result_sender.send(Err(Error::Timeout));
                    }
                }
            }
        }

        if self.is_hal_opened {
            debug!("The HAL is still opened when exit, close the HAL");
            let _ = self.hal.close().await;
            self.on_hal_closed();
        }
    }

    async fn handle_cmd(
        &mut self,
        cmd: UciManagerCmd,
        result_sender: oneshot::Sender<Result<UciResponse>>,
    ) {
        debug!("Received cmd: {:?}", cmd);

        match cmd {
            UciManagerCmd::SetLoggerMode { logger_mode } => {
                self.logger.set_logger_mode(logger_mode);
                let _ = result_sender.send(Ok(UciResponse::SetLoggerMode));
            }
            UciManagerCmd::SetCoreNotificationSender { core_notf_sender } => {
                self.core_notf_sender = core_notf_sender;
                let _ = result_sender.send(Ok(UciResponse::SetNotification));
            }
            UciManagerCmd::SetSessionNotificationSender { session_notf_sender } => {
                self.session_notf_sender = session_notf_sender;
                let _ = result_sender.send(Ok(UciResponse::SetNotification));
            }
            UciManagerCmd::SetVendorNotificationSender { vendor_notf_sender } => {
                self.vendor_notf_sender = vendor_notf_sender;
                let _ = result_sender.send(Ok(UciResponse::SetNotification));
            }
            UciManagerCmd::SetDataRcvNotificationSender { data_rcv_notf_sender } => {
                self.data_rcv_notf_sender = data_rcv_notf_sender;
                let _ = result_sender.send(Ok(UciResponse::SetNotification));
            }
            UciManagerCmd::OpenHal => {
                if self.is_hal_opened {
                    warn!("The UCI HAL is already opened, skip.");
                    let _ = result_sender.send(Err(Error::BadParameters));
                    return;
                }

                let (packet_sender, packet_receiver) = mpsc::unbounded_channel();
                let result = self.hal.open(packet_sender).await;
                self.logger.log_hal_open(&result);
                match result {
                    Ok(()) => {
                        self.on_hal_open(packet_receiver);
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

            UciManagerCmd::CloseHal { force } => {
                if force {
                    debug!("Force closing the UCI HAL");
                    let close_result = self.hal.close().await;
                    self.logger.log_hal_close(&close_result);
                    self.on_hal_closed();
                    let _ = result_sender.send(Ok(UciResponse::CloseHal));
                } else {
                    if !self.is_hal_opened {
                        warn!("The UCI HAL is already closed, skip.");
                        let _ = result_sender.send(Err(Error::BadParameters));
                        return;
                    }

                    let result = self.hal.close().await;
                    self.logger.log_hal_close(&result);
                    if result.is_ok() {
                        self.on_hal_closed();
                    }
                    let _ = result_sender.send(result.map(|_| UciResponse::CloseHal));
                }
            }

            UciManagerCmd::SendUciCommand { cmd } => {
                debug_assert!(self.retryer.is_none());

                // Remember that this command is a raw UCI command, we'll use this later
                // to send a raw UCI response.
                if let UciCommand::RawUciCmd { gid, oid, payload: _ } = cmd.clone() {
                    let gid = GroupId::from_u32(gid);
                    let oid = oid.to_u8();
                    if oid.is_none() || gid.is_none() {
                        let _ = result_sender.send(Err(Error::BadParameters));
                        return;
                    }
                    self.last_raw_cmd =
                        Some(RawCmdSignature { gid: gid.unwrap(), oid: oid.unwrap() });
                }

                self.retryer = Some(Retryer { cmd, result_sender, retry_count: MAX_RETRY_COUNT });
                self.retry_command().await;
            }
        }
    }

    async fn retry_command(&mut self) {
        if let Some(mut retryer) = self.retryer.take() {
            if !retryer.could_retry() {
                retryer.send_result(Err(Error::Timeout));
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

    async fn send_uci_command(&mut self, cmd: UciCommand) -> Result<()> {
        if !self.is_hal_opened {
            warn!("The UCI HAL is already closed, skip.");
            return Err(Error::BadParameters);
        }
        let result = self.hal.send_command(cmd.clone()).await;
        if result.is_ok() {
            self.logger.log_uci_command(&cmd);
        }
        result
    }

    async fn handle_hal_packet(&mut self, packet: Option<UciHalPacket>) {
        let defrag_packet = match packet {
            Some(rx_packet) => self.defrager.defragment_packet(&rx_packet),
            None => {
                warn!("UciHal dropped the packet_sender unexpectedly.");
                self.on_hal_closed();
                return;
            }
        };
        let defrag_packet = match defrag_packet {
            Some(p) => p,
            None => return,
        };

        match defrag_packet {
            UciDefragPacket::Control(packet) => {
                self.logger.log_uci_response_or_notification(&packet);
                // Handle response to raw UCI cmd. We want to send it back as
                // raw UCI message instead of standard response message.
                if let Some(raw_cmd) = &self.last_raw_cmd {
                    if packet.get_message_type() == MessageType::Response {
                        let resp = if raw_cmd.is_same_signature(&packet) {
                            UciResponse::RawUciCmd(Ok(RawUciMessage::from(packet)))
                        } else {
                            UciResponse::RawUciCmd(Err(Error::Unknown))
                        };
                        self.handle_response(resp).await;
                        self.last_raw_cmd = None;
                        return;
                    }
                }

                match packet.try_into() {
                    Ok(UciMessage::Response(resp)) => {
                        self.handle_response(resp).await;
                    }
                    Ok(UciMessage::Notification(notf)) => {
                        self.handle_notification(notf).await;
                    }
                    Err(e) => {
                        error!("Failed to parse received message: {:?}", e);
                    }
                }
            }
            UciDefragPacket::Data(packet) => {
                // TODO(b/261762781): Log the data packet (size)
                self.handle_data_rcv(packet);
            }
        }
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

        match notf {
            UciNotification::Core(core_notf) => {
                if let CoreNotification::DeviceStatus(status) = core_notf {
                    if let Some(result_sender) = self.open_hal_result_sender.take() {
                        let result = match status {
                            DeviceState::DeviceStateReady | DeviceState::DeviceStateActive => {
                                Ok(UciResponse::OpenHal)
                            }
                            _ => Err(Error::Unknown),
                        };
                        let _ = result_sender.send(result);
                    }
                }
                let _ = self.core_notf_sender.send(core_notf);
            }
            UciNotification::Session(session_notf) => {
                if let SessionNotification::Status {
                    session_id,
                    session_state: SessionState::SessionStateInit,
                    reason_code: _,
                } = session_notf
                {
                    if let Err(e) = self.hal.notify_session_initialized(session_id).await {
                        warn!("notify_session_initialized() failed: {:?}", e);
                    }
                }
                let _ = self.session_notf_sender.send(session_notf);
            }
            UciNotification::Vendor(vendor_notf) => {
                let _ = self.vendor_notf_sender.send(vendor_notf);
            }
        }
    }

    fn handle_data_rcv(&mut self, packet: UciDataPacketPacket) {
        match packet.try_into() {
            Ok(data_rcv) => {
                let _ = self.data_rcv_notf_sender.send(data_rcv);
            }
            Err(e) => {
                error!("Unable to parse incoming Data packet, error {:?}", e);
            }
        }
    }

    fn on_hal_open(&mut self, packet_receiver: mpsc::UnboundedReceiver<UciHalPacket>) {
        self.is_hal_opened = true;
        self.packet_receiver = packet_receiver;
    }

    fn on_hal_closed(&mut self) {
        self.is_hal_opened = false;
        self.packet_receiver = mpsc::unbounded_channel().1;
        self.last_raw_cmd = None;
    }

    fn is_waiting_resp(&self) -> bool {
        self.retryer.is_some()
    }
    fn is_waiting_device_status(&self) -> bool {
        self.open_hal_result_sender.is_some()
    }
}

impl<T: UciHal, U: UciLogger> Drop for UciManagerActor<T, U> {
    fn drop(&mut self) {
        // mpsc receiver is about to be dropped. Clean shutdown the mpsc message.
        clean_mpsc_receiver(&mut self.packet_receiver);
    }
}

struct Retryer {
    cmd: UciCommand,
    result_sender: oneshot::Sender<Result<UciResponse>>,
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

    fn send_result(self, result: Result<UciResponse>) {
        let _ = self.result_sender.send(result);
    }
}

#[derive(Debug)]
enum UciManagerCmd {
    SetLoggerMode {
        logger_mode: UciLoggerMode,
    },
    SetCoreNotificationSender {
        core_notf_sender: mpsc::UnboundedSender<CoreNotification>,
    },
    SetSessionNotificationSender {
        session_notf_sender: mpsc::UnboundedSender<SessionNotification>,
    },
    SetVendorNotificationSender {
        vendor_notf_sender: mpsc::UnboundedSender<RawUciMessage>,
    },
    SetDataRcvNotificationSender {
        data_rcv_notf_sender: mpsc::UnboundedSender<DataRcvNotification>,
    },
    OpenHal,
    CloseHal {
        force: bool,
    },
    SendUciCommand {
        cmd: UciCommand,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;
    use uwb_uci_packets::{
        Controlee_V2_0_0_Byte_Version, MessageControl, SessionGetCountCmdBuilder,
        SessionGetCountRspBuilder,
    };

    use crate::params::uci_packets::{AppConfigStatus, AppConfigTlvType, CapTlvType, StatusCode};
    use crate::uci::mock_uci_hal::MockUciHal;
    use crate::uci::mock_uci_logger::{MockUciLogger, UciLogEvent};
    use crate::uci::uci_logger::NopUciLogger;
    use crate::utils::init_test_logging;

    // TODO(b/261886903): Check if this should be in a common library file as same function
    // is defined in uci_hal_android.rs also.
    fn into_uci_hal_packets<T: Into<uwb_uci_packets::UciControlPacketPacket>>(
        builder: T,
    ) -> Vec<UciHalPacket> {
        let packets: Vec<uwb_uci_packets::UciControlPacketHalPacket> = builder.into().into();
        packets.into_iter().map(|packet| packet.into()).collect()
    }

    async fn setup_uci_manager_with_open_hal<F>(
        setup_hal_fn: F,
        uci_logger_mode: UciLoggerMode,
        log_sender: mpsc::UnboundedSender<UciLogEvent>,
    ) -> (UciManagerImpl, MockUciHal)
    where
        F: FnOnce(&mut MockUciHal),
    {
        init_test_logging();

        // Open the hal.
        let mut hal = MockUciHal::new();
        let notf = into_uci_hal_packets(uwb_uci_packets::DeviceStatusNtfBuilder {
            device_state: uwb_uci_packets::DeviceState::DeviceStateReady,
        });
        hal.expected_open(Some(notf), Ok(()));

        // Get the device info.
        let cmd = UciCommand::CoreGetDeviceInfo;
        let resp = into_uci_hal_packets(uwb_uci_packets::GetDeviceInfoRspBuilder {
            status: uwb_uci_packets::StatusCode::UciStatusOk,
            uci_version: 0x1234,
            mac_version: 0x5678,
            phy_version: 0x90ab,
            uci_test_version: 0x1357,
            vendor_spec_info: vec![0x1, 0x2],
        });
        hal.expected_send_command(cmd, resp, Ok(()));

        setup_hal_fn(&mut hal);

        // Verify open_hal() is working.
        let uci_manager =
            UciManagerImpl::new(hal.clone(), MockUciLogger::new(log_sender), uci_logger_mode);
        let result = uci_manager.open_hal().await;
        assert!(result.is_ok());

        (uci_manager, hal)
    }

    #[tokio::test]
    async fn test_open_hal_without_notification() {
        init_test_logging();

        let mut hal = MockUciHal::new();
        hal.expected_open(None, Ok(()));
        let uci_manager =
            UciManagerImpl::new(hal.clone(), NopUciLogger::default(), UciLoggerMode::Disabled);

        let result = uci_manager.open_hal().await;
        assert!(matches!(result, Err(Error::Timeout)));
        assert!(hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_close_hal_explicitly() {
        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            |hal| {
                hal.expected_close(Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.close_hal(false).await;
        assert!(result.is_ok());
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_close_hal_when_exit() {
        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            |hal| {
                // UciManager should close the hal if the hal is still opened when exit.
                hal.expected_close(Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        drop(uci_manager);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_close_hal_without_open_hal() {
        init_test_logging();

        let mut hal = MockUciHal::new();
        let uci_manager =
            UciManagerImpl::new(hal.clone(), NopUciLogger::default(), UciLoggerMode::Disabled);

        let result = uci_manager.close_hal(false).await;
        assert!(matches!(result, Err(Error::BadParameters)));
        assert!(hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_device_reset_ok() {
        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            |hal| {
                let cmd = UciCommand::DeviceReset { reset_config: ResetConfig::UwbsReset };
                let resp = into_uci_hal_packets(uwb_uci_packets::DeviceResetRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.device_reset(ResetConfig::UwbsReset).await;
        assert!(result.is_ok());
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_core_get_device_info_ok() {
        let status = StatusCode::UciStatusOk;
        let uci_version = 0x1234;
        let mac_version = 0x5678;
        let phy_version = 0x90ab;
        let uci_test_version = 0x1357;
        let vendor_spec_info = vec![0x1, 0x2];
        let vendor_spec_info_clone = vendor_spec_info.clone();

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::CoreGetDeviceInfo;
                let resp = into_uci_hal_packets(uwb_uci_packets::GetDeviceInfoRspBuilder {
                    status,
                    uci_version,
                    mac_version,
                    phy_version,
                    uci_test_version,
                    vendor_spec_info: vendor_spec_info_clone,
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let expected_result = GetDeviceInfoResponse {
            uci_version,
            mac_version,
            phy_version,
            uci_test_version,
            vendor_spec_info,
        };
        let result = uci_manager.core_get_device_info().await.unwrap();
        assert_eq!(result, expected_result);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_core_get_caps_info_ok() {
        let tlv = CapTlv { t: CapTlvType::SupportedFiraPhyVersionRange, v: vec![0x12, 0x34, 0x56] };
        let tlv_clone = tlv.clone();

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::CoreGetCapsInfo;
                let resp = into_uci_hal_packets(uwb_uci_packets::GetCapsInfoRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                    tlvs: vec![tlv_clone],
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.core_get_caps_info().await.unwrap();
        assert_eq!(result[0], tlv);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_core_set_config_ok() {
        let tlv = DeviceConfigTlv {
            cfg_id: uwb_uci_packets::DeviceConfigId::DeviceState,
            v: vec![0x12, 0x34, 0x56],
        };
        let tlv_clone = tlv.clone();
        let status = StatusCode::UciStatusOk;
        let config_status = vec![];
        let config_status_clone = config_status.clone();

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::CoreSetConfig { config_tlvs: vec![tlv_clone] };
                let resp = into_uci_hal_packets(uwb_uci_packets::SetConfigRspBuilder {
                    status,
                    cfg_status: config_status_clone,
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let expected_result = CoreSetConfigResponse { status, config_status };
        let result = uci_manager.core_set_config(vec![tlv]).await.unwrap();
        assert_eq!(result, expected_result);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_core_get_config_ok() {
        let cfg_id = DeviceConfigId::DeviceState;
        let tlv = DeviceConfigTlv { cfg_id, v: vec![0x12, 0x34, 0x56] };
        let tlv_clone = tlv.clone();

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::CoreGetConfig { cfg_id: vec![cfg_id] };
                let resp = into_uci_hal_packets(uwb_uci_packets::GetConfigRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                    tlvs: vec![tlv_clone],
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let expected_result = vec![tlv];
        let result = uci_manager.core_get_config(vec![cfg_id]).await.unwrap();
        assert_eq!(result, expected_result);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_session_init_ok() {
        let session_id = 0x123;
        let session_type = SessionType::FiraRangingSession;

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::SessionInit { session_id, session_type };
                let mut resp = into_uci_hal_packets(uwb_uci_packets::SessionInitRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                });
                let mut notf = into_uci_hal_packets(uwb_uci_packets::SessionStatusNtfBuilder {
                    session_id,
                    session_state: uwb_uci_packets::SessionState::SessionStateInit,
                    reason_code:
                        uwb_uci_packets::ReasonCode::StateChangeWithSessionManagementCommands,
                });
                resp.append(&mut notf);

                hal.expected_send_command(cmd, resp, Ok(()));
                hal.expected_notify_session_initialized(session_id, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.session_init(session_id, session_type).await;
        assert!(result.is_ok());
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_session_deinit_ok() {
        let session_id = 0x123;

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::SessionDeinit { session_id };
                let resp = into_uci_hal_packets(uwb_uci_packets::SessionDeinitRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.session_deinit(session_id).await;
        assert!(result.is_ok());
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_session_set_app_config_ok() {
        let session_id = 0x123;
        let config_tlv = AppConfigTlv::new(AppConfigTlvType::DeviceType, vec![0x12, 0x34, 0x56]);
        let config_tlv_clone = config_tlv.clone();

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            |hal| {
                let cmd = UciCommand::SessionSetAppConfig {
                    session_id,
                    config_tlvs: vec![config_tlv_clone],
                };
                let resp = into_uci_hal_packets(uwb_uci_packets::SessionSetAppConfigRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                    cfg_status: vec![],
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let expected_result =
            SetAppConfigResponse { status: StatusCode::UciStatusOk, config_status: vec![] };
        let result =
            uci_manager.session_set_app_config(session_id, vec![config_tlv]).await.unwrap();
        assert_eq!(result, expected_result);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_session_get_app_config_ok() {
        let session_id = 0x123;
        let config_id = AppConfigTlvType::DeviceType;
        let tlv = AppConfigTlv::new(AppConfigTlvType::DeviceType, vec![0x12, 0x34, 0x56]);
        let tlv_clone = tlv.clone();

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::SessionGetAppConfig { session_id, app_cfg: vec![config_id] };
                let resp = into_uci_hal_packets(uwb_uci_packets::SessionGetAppConfigRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                    tlvs: vec![tlv_clone.into_inner()],
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let expected_result = vec![tlv];
        let result = uci_manager.session_get_app_config(session_id, vec![config_id]).await.unwrap();
        assert_eq!(result, expected_result);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_session_get_count_ok() {
        let session_count = 5;

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::SessionGetCount;
                let resp = into_uci_hal_packets(uwb_uci_packets::SessionGetCountRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                    session_count,
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.session_get_count().await.unwrap();
        assert_eq!(result, session_count);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_session_get_state_ok() {
        let session_id = 0x123;
        let session_state = SessionState::SessionStateActive;

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::SessionGetState { session_id };
                let resp = into_uci_hal_packets(uwb_uci_packets::SessionGetStateRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                    session_state,
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.session_get_state(session_id).await.unwrap();
        assert_eq!(result, session_state);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_session_update_controller_multicast_list_ok() {
        let session_id = 0x123;
        let action = UpdateMulticastListAction::AddControlee;
        let controlee = Controlee { short_address: 0x4567, subsession_id: 0x90ab };
        let controlee_clone = controlee.clone();

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::SessionUpdateControllerMulticastList {
                    session_id,
                    action,
                    controlees: vec![controlee_clone],
                };
                let resp = into_uci_hal_packets(
                    uwb_uci_packets::SessionUpdateControllerMulticastListRspBuilder {
                        status: uwb_uci_packets::StatusCode::UciStatusOk,
                    },
                );

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager
            .session_update_controller_multicast_list(session_id, action, vec![controlee])
            .await;
        assert!(result.is_ok());
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_session_update_controller_multicast_list_v2_ok() {
        let session_id = 0x123;
        let action = UpdateMulticastListAction::AddControlee;
        let controlee = Controlee_V2_0_0_Byte_Version {
            short_address: 0x4567,
            subsession_id: 0x90ab,
            message_control: MessageControl::SubSessionKeyNotConfigured,
        };
        let controlee_clone = controlee.clone();

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::SessionUpdateControllerMulticastListV2 {
                    session_id,
                    action,
                    controlees: ControleesV2::NoSessionKey(vec![controlee_clone]),
                };
                let resp = into_uci_hal_packets(
                    uwb_uci_packets::SessionUpdateControllerMulticastListRspBuilder {
                        status: uwb_uci_packets::StatusCode::UciStatusOk,
                    },
                );

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager
            .session_update_controller_multicast_list_v2(
                session_id,
                action,
                ControleesV2::NoSessionKey(vec![controlee]),
            )
            .await;
        assert!(result.is_ok());
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_set_active_ranging_rounds_dt_tag() {
        let ranging_rounds = SessionUpdateActiveRoundsDtTagResponse {
            status: StatusCode::UciStatusErrorRoundIndexNotActivated,
            ranging_round_indexes: vec![3],
        };

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::SessionUpdateActiveRoundsDtTag {
                    session_id: 1,
                    ranging_round_indexes: vec![3, 5],
                };
                let resp = into_uci_hal_packets(
                    uwb_uci_packets::SessionUpdateActiveRoundsDtTagRspBuilder {
                        status: StatusCode::UciStatusErrorRoundIndexNotActivated,
                        ranging_round_indexes: vec![3],
                    },
                );

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.session_update_active_rounds_dt_tag(1, vec![3, 5]).await.unwrap();

        assert_eq!(result, ranging_rounds);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_range_start_ok() {
        let session_id = 0x123;

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::RangeStart { session_id };
                let resp = into_uci_hal_packets(uwb_uci_packets::RangeStartRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.range_start(session_id).await;
        assert!(result.is_ok());
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_range_stop_ok() {
        let session_id = 0x123;

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::RangeStop { session_id };
                let resp = into_uci_hal_packets(uwb_uci_packets::RangeStopRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.range_stop(session_id).await;
        assert!(result.is_ok());
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_range_get_ranging_count_ok() {
        let session_id = 0x123;
        let count = 3;

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::RangeGetRangingCount { session_id };
                let resp = into_uci_hal_packets(uwb_uci_packets::RangeGetRangingCountRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                    count,
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.range_get_ranging_count(session_id).await.unwrap();
        assert_eq!(result, count as usize);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_android_set_country_code_ok() {
        let country_code = CountryCode::new(b"US").unwrap();
        let country_code_clone = country_code.clone();

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::AndroidSetCountryCode { country_code: country_code_clone };
                let resp = into_uci_hal_packets(uwb_uci_packets::AndroidSetCountryCodeRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.android_set_country_code(country_code).await;
        assert!(result.is_ok());
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_android_get_power_stats_ok() {
        let power_stats = PowerStats {
            status: StatusCode::UciStatusOk,
            idle_time_ms: 123,
            tx_time_ms: 456,
            rx_time_ms: 789,
            total_wake_count: 5,
        };
        let power_stats_clone = power_stats.clone();

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::AndroidGetPowerStats;
                let resp = into_uci_hal_packets(uwb_uci_packets::AndroidGetPowerStatsRspBuilder {
                    stats: power_stats_clone,
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.android_get_power_stats().await.unwrap();
        assert_eq!(result, power_stats);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_raw_uci_cmd_vendor_gid_ok() {
        let gid = 0xF; // Vendor reserved GID.
        let oid = 0x3;
        let cmd_payload = vec![0x11, 0x22, 0x33, 0x44];
        let cmd_payload_clone = cmd_payload.clone();
        let resp_payload = vec![0x55, 0x66, 0x77, 0x88];
        let resp_payload_clone = resp_payload.clone();

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::RawUciCmd { gid, oid, payload: cmd_payload_clone };
                let resp = into_uci_hal_packets(uwb_uci_packets::UciVendor_F_ResponseBuilder {
                    opcode: oid as u8,
                    payload: Some(Bytes::from(resp_payload_clone)),
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let expected_result = RawUciMessage { gid, oid, payload: resp_payload };
        let result = uci_manager.raw_uci_cmd(gid, oid, cmd_payload).await.unwrap();
        assert_eq!(result, expected_result);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_raw_uci_cmd_fira_gid_ok() {
        let gid = 0x1; // SESSION_CONFIG GID.
        let oid = 0x3;
        let cmd_payload = vec![0x11, 0x22, 0x33, 0x44];
        let cmd_payload_clone = cmd_payload.clone();
        let resp_payload = vec![0x00, 0x01, 0x07, 0x00];
        let status = StatusCode::UciStatusOk;
        let cfg_id = AppConfigTlvType::DstMacAddress;
        let app_config = AppConfigStatus { cfg_id, status };
        let cfg_status = vec![app_config];

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::RawUciCmd { gid, oid, payload: cmd_payload_clone };
                let resp = into_uci_hal_packets(uwb_uci_packets::SessionSetAppConfigRspBuilder {
                    status,
                    cfg_status,
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let expected_result = RawUciMessage { gid, oid, payload: resp_payload };
        let result = uci_manager.raw_uci_cmd(gid, oid, cmd_payload).await.unwrap();
        assert_eq!(result, expected_result);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_raw_uci_cmd_wrong_gid() {
        // Send a raw UCI command with CORE GID, but UCI HAL returns a UCI response
        // with SESSION_CONFIG GID.
        // In this case, UciManager should return Error::Unknown.

        let gid = 0x0; // CORE GID.
        let oid = 0x1;
        let cmd_payload = vec![0x11, 0x22, 0x33, 0x44];
        let cmd_payload_clone = cmd_payload.clone();
        let status = StatusCode::UciStatusOk;
        let cfg_id = AppConfigTlvType::DstMacAddress;
        let app_config = AppConfigStatus { cfg_id, status };
        let cfg_status = vec![app_config];

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::RawUciCmd { gid, oid, payload: cmd_payload_clone };
                let resp = into_uci_hal_packets(uwb_uci_packets::SessionSetAppConfigRspBuilder {
                    status,
                    cfg_status,
                });

                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let expected_result = Err(Error::Unknown);
        let result = uci_manager.raw_uci_cmd(gid, oid, cmd_payload).await;
        assert_eq!(result, expected_result);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_session_get_count_retry_no_response() {
        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            |hal| {
                let cmd = UciCommand::SessionGetCount;
                hal.expected_send_command(cmd, vec![], Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.session_get_count().await;
        assert!(matches!(result, Err(Error::Timeout)));
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_session_get_count_timeout() {
        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            |hal| {
                let cmd = UciCommand::SessionGetCount;
                hal.expected_send_command(cmd, vec![], Err(Error::Timeout));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.session_get_count().await;
        assert!(matches!(result, Err(Error::Timeout)));
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_session_get_count_retry_too_many_times() {
        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            |hal| {
                let cmd = UciCommand::SessionGetCount;
                let retry_resp = into_uci_hal_packets(uwb_uci_packets::SessionGetCountRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusCommandRetry,
                    session_count: 0,
                });

                for _ in 0..MAX_RETRY_COUNT {
                    hal.expected_send_command(cmd.clone(), retry_resp.clone(), Ok(()));
                }
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.session_get_count().await;
        assert!(matches!(result, Err(Error::Timeout)));
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_session_get_count_retry_notification() {
        let session_count = 5;

        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::SessionGetCount;
                let retry_resp = into_uci_hal_packets(uwb_uci_packets::SessionGetCountRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusCommandRetry,
                    session_count: 0,
                });
                let resp = into_uci_hal_packets(uwb_uci_packets::SessionGetCountRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                    session_count,
                });

                hal.expected_send_command(cmd.clone(), retry_resp.clone(), Ok(()));
                hal.expected_send_command(cmd.clone(), retry_resp, Ok(()));
                hal.expected_send_command(cmd, resp, Ok(()));
            },
            UciLoggerMode::Disabled,
            mpsc::unbounded_channel::<UciLogEvent>().0,
        )
        .await;

        let result = uci_manager.session_get_count().await.unwrap();
        assert_eq!(result, session_count);
        assert!(mock_hal.wait_expected_calls_done().await);
    }

    #[tokio::test]
    async fn test_log_manager_interaction() {
        let (log_sender, mut log_receiver) = mpsc::unbounded_channel::<UciLogEvent>();
        let (uci_manager, mut mock_hal) = setup_uci_manager_with_open_hal(
            move |hal| {
                let cmd = UciCommand::SessionGetCount;
                let resp1 = into_uci_hal_packets(uwb_uci_packets::SessionGetCountRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                    session_count: 1,
                });
                let resp2 = into_uci_hal_packets(uwb_uci_packets::SessionGetCountRspBuilder {
                    status: uwb_uci_packets::StatusCode::UciStatusOk,
                    session_count: 2,
                });
                hal.expected_send_command(cmd.clone(), resp1, Ok(()));
                hal.expected_send_command(cmd, resp2, Ok(()));
            },
            UciLoggerMode::Disabled,
            log_sender,
        )
        .await;

        // Under Disabled mode, initialization and first command and response are not logged.
        uci_manager.session_get_count().await.unwrap();
        assert!(log_receiver.try_recv().is_err());

        // Second command and response after change in logger mode are logged.
        uci_manager.set_logger_mode(UciLoggerMode::Filtered).await.unwrap();
        uci_manager.session_get_count().await.unwrap();
        let packet: Vec<u8> = log_receiver.recv().await.unwrap().try_into().unwrap();
        let cmd_packet: Vec<u8> = SessionGetCountCmdBuilder {}.build().into();
        assert_eq!(&packet, &cmd_packet);
        let packet: Vec<u8> = log_receiver.recv().await.unwrap().try_into().unwrap();
        let rsp_packet: Vec<u8> =
            SessionGetCountRspBuilder { status: StatusCode::UciStatusOk, session_count: 2 }
                .build()
                .into();
        assert_eq!(&packet, &rsp_packet);

        assert!(mock_hal.wait_expected_calls_done().await);
    }
}
