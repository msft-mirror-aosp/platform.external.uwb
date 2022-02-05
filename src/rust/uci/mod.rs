/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

pub mod uci_hmsgs;
pub mod uci_hrcv;

use crate::adaptation::{UwbAdaptation, UwbAdaptationImpl};
use crate::error::UwbErr;
use crate::event_manager::EventManager;
use crate::uci::uci_hrcv::UciResponse;
use android_hardware_uwb::aidl::android::hardware::uwb::{
    UwbEvent::UwbEvent, UwbStatus::UwbStatus,
};
use log::{debug, error, info, warn};
use std::future::Future;
use std::option::Option;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::{select, task};
use uwb_uci_packets::{
    GetCapsInfoCmdBuilder, GetDeviceInfoCmdBuilder, GetDeviceInfoRspPacket, Packet,
    RangeStartCmdBuilder, RangeStopCmdBuilder, SessionDeinitCmdBuilder,
    SessionGetAppConfigCmdBuilder, SessionGetCountCmdBuilder, SessionGetStateCmdBuilder,
    SessionState, SessionStatusNtfPacket, StatusCode, UciCommandPacket,
};

pub type Result<T> = std::result::Result<T, UwbErr>;
pub type UciResponseHandle = oneshot::Sender<UciResponse>;
type SyncUwbAdaptation = Box<dyn UwbAdaptation + std::marker::Send + std::marker::Sync>;

// Commands sent from JNI.
#[derive(Debug)]
pub enum JNICommand {
    // Blocking UCI commands
    UciGetCapsInfo,
    UciGetDeviceInfo,
    UciSessionInit(u32, u8),
    UciSessionDeinit(u32),
    UciSessionGetCount,
    UciStartRange(u32),
    UciStopRange(u32),
    UciGetSessionState(u32),
    UciSessionUpdateMulticastList {
        session_id: u32,
        action: u8,
        no_of_controlee: u8,
        address_list: Vec<i16>,
        sub_session_id_list: Vec<i32>,
    },
    UciSetCountryCode {
        code: Vec<u8>,
    },
    UciSetAppConfig {
        session_id: u32,
        no_of_params: u32,
        // TODO this field should be removed, in tandem with a change to the Uwb APEX
        app_config_param_len: u32,
        app_configs: Vec<u8>,
    },
    UciGetAppConfig {
        session_id: u32,
        no_of_params: u32,
        app_config_param_len: u32,
        app_configs: Vec<u8>,
    },
    UciRawVendorCmd {
        gid: u32,
        oid: u32,
        payload: Vec<u8>,
    },

    // Non blocking commands
    Enable,
    Disable(bool),
    Exit,
}

// Responses from the HAL.
#[derive(Debug)]
pub enum HalCallback {
    Event { event: UwbEvent, event_status: UwbStatus },
    UciRsp(uci_hrcv::UciResponse),
    UciNtf(uci_hrcv::UciNotification),
}

#[derive(Debug, PartialEq)]
pub enum UwbState {
    None,
    W4HalOpen,
    Ready,
    W4UciResp,
    W4HalClose,
}

#[derive(Clone)]
struct Retryer {
    received: Arc<Notify>,
    failed: Arc<Notify>,
    retry: Arc<Notify>,
}

impl Retryer {
    fn new() -> Self {
        Self {
            received: Arc::new(Notify::new()),
            failed: Arc::new(Notify::new()),
            retry: Arc::new(Notify::new()),
        }
    }

    async fn command_failed(&self) {
        self.failed.notified().await
    }

    async fn immediate_retry(&self) {
        self.retry.notified().await
    }

    async fn command_serviced(&self) {
        self.received.notified().await
    }

    fn received(&self) {
        self.received.notify_one()
    }

    fn retry(&self) {
        self.retry.notify_one()
    }

    fn failed(&self) {
        self.failed.notify_one()
    }

    fn send_with_retry(self, adaptation: Arc<SyncUwbAdaptation>, bytes: Vec<u8>) {
        tokio::task::spawn(async move {
            let mut received_response = false;
            for retry in 0..MAX_RETRIES {
                adaptation.send_uci_message(&bytes).await.unwrap_or_else(|e| {
                    error!("Sending UCI message failed: {:?}", e);
                });
                select! {
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS)) => warn!("UWB chip did not respond within {}ms deadline. Retrying (#{})...", RETRY_DELAY_MS, retry + 1),
                    _ = self.command_serviced() => {
                        received_response = true;
                        break;
                    }
                    _ = self.immediate_retry() => debug!("UWB chip requested immediate retry. Retrying (#{})...", retry + 1),
                }
            }
            if !received_response {
                error!("After {} retries, no response from UWB chip", MAX_RETRIES);
                adaptation.core_initialization().await.unwrap_or_else(|e| {
                    error!("Resetting chip due to no responses failed: {:?}", e);
                });
                self.failed();
            }
        });
    }
}

//TODO pull in libfutures instead of open-coding this
async fn option_future<R, T: Future<Output = R>>(mf: Option<T>) -> Option<R> {
    if let Some(f) = mf {
        Some(f.await)
    } else {
        None
    }
}

struct Driver<T: EventManager> {
    adaptation: Arc<SyncUwbAdaptation>,
    event_manager: T,
    cmd_receiver: mpsc::UnboundedReceiver<(JNICommand, Option<UciResponseHandle>)>,
    rsp_receiver: mpsc::UnboundedReceiver<HalCallback>,
    response_channel: Option<(UciResponseHandle, Retryer)>,
    state: UwbState,
}

// Creates a future that handles messages from JNI and the HAL.
async fn drive<T: EventManager + Send + Sync>(
    adaptation: SyncUwbAdaptation,
    event_manager: T,
    cmd_receiver: mpsc::UnboundedReceiver<(JNICommand, Option<UciResponseHandle>)>,
    rsp_receiver: mpsc::UnboundedReceiver<HalCallback>,
) -> Result<()> {
    Driver::new(Arc::new(adaptation), event_manager, cmd_receiver, rsp_receiver).drive().await
}

const MAX_RETRIES: usize = 10;
const RETRY_DELAY_MS: u64 = 300;

impl<T: EventManager> Driver<T> {
    fn new(
        adaptation: Arc<SyncUwbAdaptation>,
        event_manager: T,
        cmd_receiver: mpsc::UnboundedReceiver<(JNICommand, Option<UciResponseHandle>)>,
        rsp_receiver: mpsc::UnboundedReceiver<HalCallback>,
    ) -> Self {
        Self {
            adaptation,
            event_manager,
            cmd_receiver,
            rsp_receiver,
            response_channel: None,
            state: UwbState::None,
        }
    }

    // Continually handles messages.
    async fn drive(mut self) -> Result<()> {
        loop {
            match self.drive_once().await {
                Err(UwbErr::Exit) => return Ok(()),
                Err(e) => error!("drive_once: {:?}", e),
                Ok(()) => (),
            }
        }
    }

    fn handle_blocking_jni_cmd(
        &mut self,
        tx: oneshot::Sender<UciResponse>,
        cmd: JNICommand,
    ) -> Result<()> {
        log::debug!("Received blocking cmd {:?}", cmd);
        let command: UciCommandPacket = match cmd {
            JNICommand::UciGetDeviceInfo => GetDeviceInfoCmdBuilder {}.build().into(),
            JNICommand::UciGetCapsInfo => GetCapsInfoCmdBuilder {}.build().into(),
            JNICommand::UciSessionInit(session_id, session_type) => {
                uci_hmsgs::build_session_init_cmd(session_id, session_type).build().into()
            }
            JNICommand::UciSessionDeinit(session_id) => {
                SessionDeinitCmdBuilder { session_id }.build().into()
            }
            JNICommand::UciSessionGetCount => SessionGetCountCmdBuilder {}.build().into(),
            JNICommand::UciStartRange(session_id) => {
                RangeStartCmdBuilder { session_id }.build().into()
            }
            JNICommand::UciStopRange(session_id) => {
                RangeStopCmdBuilder { session_id }.build().into()
            }
            JNICommand::UciGetSessionState(session_id) => {
                SessionGetStateCmdBuilder { session_id }.build().into()
            }
            JNICommand::UciSessionUpdateMulticastList {
                session_id,
                action,
                no_of_controlee,
                ref address_list,
                ref sub_session_id_list,
            } => uci_hmsgs::build_multicast_list_update_cmd(
                session_id,
                action,
                no_of_controlee,
                address_list,
                sub_session_id_list,
            )
            .build()
            .into(),
            JNICommand::UciSetCountryCode { ref code } => {
                uci_hmsgs::build_set_country_code_cmd(code).build().into()
            }
            JNICommand::UciSetAppConfig { session_id, no_of_params, ref app_configs, .. } => {
                uci_hmsgs::build_set_app_config_cmd(session_id, no_of_params, app_configs)?
                    .build()
                    .into()
            }
            JNICommand::UciGetAppConfig { session_id, ref app_configs, .. } => {
                SessionGetAppConfigCmdBuilder { session_id, app_cfg: app_configs.to_vec() }
                    .build()
                    .into()
            }
            JNICommand::UciRawVendorCmd { gid, oid, payload } => {
                uci_hmsgs::build_uci_vendor_cmd_packet(gid, oid, payload)?
            }
            _ => {
                error!("Unexpected blocking cmd received {:?}", cmd);
                return Ok(());
            }
        };

        log::debug!("Sending HAL UCI message {:?}", command);

        let retryer = Retryer::new();
        self.response_channel = Some((tx, retryer.clone()));
        retryer.send_with_retry(self.adaptation.clone(), command.to_vec());
        self.set_state(UwbState::W4UciResp);
        Ok(())
    }

    async fn handle_non_blocking_jni_cmd(&mut self, cmd: JNICommand) -> Result<()> {
        log::debug!("Received non blocking cmd {:?}", cmd);
        match cmd {
            JNICommand::Enable => {
                self.adaptation.hal_open().await?;
                self.adaptation.core_initialization().await?;
                self.set_state(UwbState::W4HalOpen);
            }
            JNICommand::Disable(_graceful) => {
                self.adaptation.hal_close().await?;
                self.set_state(UwbState::W4HalClose);
            }
            JNICommand::Exit => {
                return Err(UwbErr::Exit);
            }
            _ => {
                error!("Unexpected non blocking cmd received {:?}", cmd);
                return Ok(());
            }
        }
        Ok(())
    }

    async fn handle_hal_notification(&self, response: uci_hrcv::UciNotification) -> Result<()> {
        log::debug!("Received hal notification {:?}", response);
        match response {
            uci_hrcv::UciNotification::DeviceStatusNtf(response) => {
                self.event_manager.device_status_notification_received(response)?;
            }
            uci_hrcv::UciNotification::GenericError(response) => {
                if let (StatusCode::UciStatusCommandRetry, Some((_, retryer))) =
                    (response.get_status(), self.response_channel.as_ref())
                {
                    retryer.retry();
                }
                self.event_manager.core_generic_error_notification_received(response)?;
            }
            uci_hrcv::UciNotification::SessionStatusNtf(response) => {
                self.invoke_hal_session_init_if_necessary(&response).await;
                self.event_manager.session_status_notification_received(response)?;
            }
            uci_hrcv::UciNotification::ShortMacTwoWayRangeDataNtf(response) => {
                self.event_manager.short_range_data_notification_received(response)?;
            }
            uci_hrcv::UciNotification::ExtendedMacTwoWayRangeDataNtf(response) => {
                self.event_manager.extended_range_data_notification_received(response)?;
            }
            uci_hrcv::UciNotification::SessionUpdateControllerMulticastListNtf(response) => {
                self.event_manager
                    .session_update_controller_multicast_list_notification_received(response)?;
            }
            uci_hrcv::UciNotification::RawVendorNtf { gid, oid, payload } => {
                self.event_manager.vendor_uci_notification_received(gid, oid, payload)?;
            }
        }
        Ok(())
    }

    // Handles a single message from JNI or the HAL.
    async fn drive_once(&mut self) -> Result<()> {
        select! {
            Some(()) = option_future(self.response_channel.as_ref()
                .map(|(_, retryer)| retryer.command_failed())) => {
                // TODO: Do we want to flush the incoming queue of commands when this happens?
                self.set_state(UwbState::W4HalOpen);
                self.response_channel = None
            }
            // Note: If a blocking command is awaiting a response, any non-blocking commands are not
            // dequeued until the blocking cmd's response is received.
            Some((cmd, tx)) = self.cmd_receiver.recv(), if self.can_process_cmd() => {
                match tx {
                    Some(tx) => { // Blocking JNI commands processing.
                        self.handle_blocking_jni_cmd(tx, cmd)?;
                    },
                    None => { // Non Blocking JNI commands processing.
                        self.handle_non_blocking_jni_cmd(cmd).await?;
                    }
                }
            }
            Some(rsp) = self.rsp_receiver.recv() => {
                match rsp {
                    HalCallback::Event{event, event_status} => {
                        log::info!("Received HAL event: {:?} with status: {:?}", event, event_status);
                        match event {
                            UwbEvent::POST_INIT_CPLT => {
                                self.set_state(UwbState::Ready);
                            }
                            UwbEvent::CLOSE_CPLT => {
                                self.set_state(UwbState::None);
                            }
                            _ => (),
                        }
                    },
                    HalCallback::UciRsp(response) => {
                        log::debug!("Received HAL UCI message {:?}", response);
                        self.set_state(UwbState::Ready);
                        if let Some((channel, retryer)) = self.response_channel.take() {
                            retryer.received();
                            channel.send(response).unwrap_or_else(|_| {
                                error!("Unable to send response, receiver gone");
                            });
                        } else {
                            error!("Received response packet, but no response channel available");
                        }
                    },
                    HalCallback::UciNtf(response) => {
                        self.handle_hal_notification(response).await?;
                    }
                }
            }
        }
        Ok(())
    }

    // Triggers the session init HAL API, if a new session is initialized.
    async fn invoke_hal_session_init_if_necessary(&self, response: &SessionStatusNtfPacket) {
        if let SessionState::SessionStateInit = response.get_session_state() {
            info!(
                "Session {:?} initialized, invoking session init HAL API",
                response.get_session_id()
            );
            self.adaptation
                // HAL API accepts signed int, so cast received session_id as i32.
                .session_initialization(response.get_session_id() as i32)
                .await
                .unwrap_or_else(|e| error!("Error invoking session init HAL API : {:?}", e));
        }
    }

    fn set_state(&mut self, state: UwbState) {
        info!("UWB state change from {:?} to {:?}", self.state, state);
        self.state = state;
    }

    fn can_process_cmd(&mut self) -> bool {
        self.state == UwbState::None || self.state == UwbState::Ready
    }
}

// Controller for sending tasks for the native thread to handle.
pub struct Dispatcher {
    cmd_sender: mpsc::UnboundedSender<(JNICommand, Option<UciResponseHandle>)>,
    join_handle: task::JoinHandle<Result<()>>,
    runtime: Runtime,
    pub device_info: Option<GetDeviceInfoRspPacket>,
}

impl Dispatcher {
    pub fn new<T: 'static + EventManager + Send + Sync>(event_manager: T) -> Result<Self> {
        let (rsp_sender, rsp_receiver) = mpsc::unbounded_channel::<HalCallback>();
        // TODO when simplifying constructors, avoid spare runtime
        let adaptation: SyncUwbAdaptation = Box::new(
            Builder::new_current_thread().build()?.block_on(UwbAdaptationImpl::new(rsp_sender))?,
        );

        Self::new_with_args(event_manager, adaptation, rsp_receiver)
    }

    #[cfg(test)]
    pub fn new_for_testing<T: 'static + EventManager + Send + Sync>(
        event_manager: T,
        adaptation: SyncUwbAdaptation,
        rsp_receiver: mpsc::UnboundedReceiver<HalCallback>,
    ) -> Result<Self> {
        Self::new_with_args(event_manager, adaptation, rsp_receiver)
    }

    fn new_with_args<T: 'static + EventManager + Send + Sync>(
        event_manager: T,
        adaptation: SyncUwbAdaptation,
        rsp_receiver: mpsc::UnboundedReceiver<HalCallback>,
    ) -> Result<Self> {
        info!("initializing dispatcher");
        let (cmd_sender, cmd_receiver) =
            mpsc::unbounded_channel::<(JNICommand, Option<UciResponseHandle>)>();

        // We create a new thread here both to avoid reusing the Java service thread and because
        // binder threads will call into this.
        let runtime = Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("uwb-uci-handler")
            .enable_all()
            .build()?;
        let join_handle =
            runtime.spawn(drive(adaptation, event_manager, cmd_receiver, rsp_receiver));
        Ok(Dispatcher { cmd_sender, join_handle, runtime, device_info: None })
    }

    pub fn send_jni_command(&self, cmd: JNICommand) -> Result<()> {
        self.cmd_sender.send((cmd, None))?;
        Ok(())
    }

    // TODO: Consider implementing these separate for different commands so we can have more
    // specific return types.
    pub fn block_on_jni_command(&self, cmd: JNICommand) -> Result<UciResponse> {
        let (tx, rx) = oneshot::channel();
        self.cmd_sender.send((cmd, Some(tx)))?;
        let ret = self.runtime.block_on(rx)?;
        log::trace!("{:?}", ret);
        Ok(ret)
    }

    pub fn exit(&mut self) -> Result<()> {
        self.send_jni_command(JNICommand::Exit)?;
        let _ = self.runtime.block_on(&mut self.join_handle);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptation::MockUwbAdaptation;
    use crate::event_manager::MockEventManager;

    #[test]
    fn test_driver() -> Result<()> {
        // TODO: Remove this once we call it somewhere real.
        logger::init(
            logger::Config::default().with_tag_on_device("uwb").with_min_level(log::Level::Error),
        );

        let (rsp_sender, rsp_receiver) = mpsc::unbounded_channel::<HalCallback>();
        let mut mock_adaptation = Box::new(MockUwbAdaptation::new(rsp_sender));
        let mock_event_manager = MockEventManager::new();

        mock_adaptation.expect_hal_open(Ok(()));
        mock_adaptation.expect_core_initialization(Ok(()));

        let mut dispatcher = Dispatcher::new_for_testing(
            mock_event_manager,
            mock_adaptation as SyncUwbAdaptation,
            rsp_receiver,
        )?;
        dispatcher.send_jni_command(JNICommand::Enable)?;
        dispatcher.send_jni_command(JNICommand::UciGetDeviceInfo)?;
        dispatcher.exit()?;
        Ok(())
    }
}
