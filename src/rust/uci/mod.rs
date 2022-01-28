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

pub mod state_machine;
pub mod uci_hmsgs;
pub mod uci_hrcv;

use crate::adaptation::{UwbAdaptation, UwbAdaptationImpl};
use crate::error::UwbErr;
use crate::event_manager::{EventManager, Manager};
use crate::uci::uci_hrcv::UciResponse;
use android_hardware_uwb::aidl::android::hardware::uwb::{
    UwbEvent::UwbEvent, UwbStatus::UwbStatus,
};
use log::{debug, error, info, warn};
use num_traits::ToPrimitive;
use std::future::Future;
use std::option::Option;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::{select, task};
use uwb_uci_packets::{
    GetDeviceInfoCmdBuilder, GetDeviceInfoRspPacket, Packet, RangeStartCmdBuilder,
    RangeStopCmdBuilder, SessionDeinitCmdBuilder, SessionGetAppConfigCmdBuilder,
    SessionGetCountCmdBuilder, SessionGetStateCmdBuilder, SessionState, SessionStatusNtfPacket,
    StatusCode,
};

#[cfg(test)]
use crate::event_manager::EventManagerTest;

pub type Result<T> = std::result::Result<T, UwbErr>;
pub type UciResponseHandle = oneshot::Sender<UciResponse>;
type SyncUwbAdaptation = Box<dyn UwbAdaptation + std::marker::Send + std::marker::Sync>;

// Commands sent from JNI.
#[derive(Debug)]
pub enum JNICommand {
    // Blocking UCI commands
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
        address_list: Vec<u8>,
        sub_session_id_list: Vec<i32>,
    },
    UciSetCountryCode {
        code: Vec<u8>,
    },
    UciSetAppConfig {
        session_id: u32,
        no_of_params: u32,
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
                // TODO this must be non-blocking to avoid blocking the runtime if the HAL locks up.
                // Will address in follow-up CL moving adaptation to be asynchronous.
                adaptation.send_uci_message(&bytes);
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
                adaptation.core_initialization();
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

struct Driver<T: Manager> {
    adaptation: Arc<SyncUwbAdaptation>,
    event_manager: T,
    cmd_receiver: mpsc::UnboundedReceiver<(JNICommand, Option<UciResponseHandle>)>,
    rsp_receiver: mpsc::UnboundedReceiver<HalCallback>,
    response_channel: Option<(UciResponseHandle, Retryer)>,
}

// Creates a future that handles messages from JNI and the HAL.
async fn drive<T: Manager>(
    adaptation: SyncUwbAdaptation,
    event_manager: T,
    cmd_receiver: mpsc::UnboundedReceiver<(JNICommand, Option<UciResponseHandle>)>,
    rsp_receiver: mpsc::UnboundedReceiver<HalCallback>,
) -> Result<()> {
    Driver::new(Arc::new(adaptation), event_manager, cmd_receiver, rsp_receiver).drive().await
}

const MAX_RETRIES: usize = 10;
const RETRY_DELAY_MS: u64 = 100;

impl<T: Manager> Driver<T> {
    fn new(
        adaptation: Arc<SyncUwbAdaptation>,
        event_manager: T,
        cmd_receiver: mpsc::UnboundedReceiver<(JNICommand, Option<UciResponseHandle>)>,
        rsp_receiver: mpsc::UnboundedReceiver<HalCallback>,
    ) -> Self {
        Self { adaptation, event_manager, cmd_receiver, rsp_receiver, response_channel: None }
    }

    // Continually handles messages.
    async fn drive(mut self) -> Result<()> {
        loop {
            self.drive_once().await?
        }
    }

    fn handle_blocking_jni_cmd(
        &mut self,
        tx: oneshot::Sender<UciResponse>,
        cmd: JNICommand,
    ) -> Result<()> {
        log::debug!("Received blocking cmd {:?}", cmd);
        let bytes = match cmd {
            JNICommand::UciGetDeviceInfo => GetDeviceInfoCmdBuilder {}.build().to_vec(),
            JNICommand::UciSessionInit(session_id, session_type) => {
                uci_hmsgs::build_session_init_cmd(session_id, session_type).build().to_vec()
            }
            JNICommand::UciSessionDeinit(session_id) => {
                SessionDeinitCmdBuilder { session_id }.build().to_vec()
            }
            JNICommand::UciSessionGetCount => SessionGetCountCmdBuilder {}.build().to_vec(),
            JNICommand::UciStartRange(session_id) => {
                RangeStartCmdBuilder { session_id }.build().to_vec()
            }
            JNICommand::UciStopRange(session_id) => {
                RangeStopCmdBuilder { session_id }.build().to_vec()
            }
            JNICommand::UciGetSessionState(session_id) => {
                SessionGetStateCmdBuilder { session_id }.build().to_vec()
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
            .to_vec(),
            JNICommand::UciSetCountryCode { ref code } => {
                uci_hmsgs::build_set_country_code_cmd(code).build().to_vec()
            }
            JNICommand::UciSetAppConfig {
                session_id,
                no_of_params,
                app_config_param_len,
                ref app_configs,
            } => uci_hmsgs::build_set_app_config_cmd(
                session_id,
                no_of_params,
                app_config_param_len,
                app_configs,
            )?
            .build()
            .to_vec(),
            JNICommand::UciGetAppConfig {
                session_id,
                no_of_params,
                app_config_param_len,
                ref app_configs,
            } => SessionGetAppConfigCmdBuilder { session_id, app_cfg: app_configs.to_vec() }
                .build()
                .to_vec(),
            JNICommand::UciRawVendorCmd { gid, oid, payload } => {
                uci_hmsgs::build_uci_vendor_cmd_packet(gid, oid, payload)?.to_vec()
            }
            _ => {
                error!("Unexpected blocking cmd received {:?}", cmd);
                return Ok(());
            }
        };

        let retryer = Retryer::new();
        self.response_channel = Some((tx, retryer.clone()));
        retryer.send_with_retry(self.adaptation.clone(), bytes);
        Ok(())
    }

    fn handle_non_blocking_jni_cmd(&mut self, cmd: JNICommand) -> Result<()> {
        log::debug!("Received non blocking cmd {:?}", cmd);
        match cmd {
            JNICommand::Enable => {
                // TODO: This mimics existing behavior, but I think we've got a few
                // issues here:
                // * We've got two different initialization sites (Enable *and*
                // adaptation construction)
                // * We have multiple functions required to finish building a
                //   correct Enable (so there are bad states to leave it in)
                // * We have Disable, but the adaptation isn't optional, so we
                // will end up with an invalid but still present adaptation.
                //
                // A future patch should probably make a single constructor for
                // everything, and it should probably be called here rather than
                // mutating an existing adaptation. The adaptation should be made
                // optional.
                if let Some(adaptation) = Arc::get_mut(&mut self.adaptation) {
                    adaptation.initialize();
                    adaptation.hal_open();
                    adaptation
                        .core_initialization()
                        .unwrap_or_else(|e| error!("Error invoking core init HAL API : {:?}", e));
                } else {
                    error!("Attempted to enable Uci while it was still in use.");
                }
            }
            JNICommand::Disable(graceful) => {
                self.adaptation.hal_close();
            }
            JNICommand::Exit => return Err(UwbErr::Exit),
            _ => {
                error!("Unexpected non blocking cmd received {:?}", cmd);
                return Ok(());
            }
        }
        Ok(())
    }

    fn handle_hal_notification(&self, response: uci_hrcv::UciNotification) -> Result<()> {
        log::debug!("Received hal notification {:?}", response);
        match response {
            uci_hrcv::UciNotification::DeviceStatusNtf(response) => {
                self.event_manager.device_status_notification_received(response);
            }
            uci_hrcv::UciNotification::GenericError(response) => {
                match (response.get_status(), self.response_channel.as_ref()) {
                    (StatusCode::UciStatusCommandRetry, Some((_, retryer))) => retryer.retry(),
                    _ => (),
                }
                self.event_manager.core_generic_error_notification_received(response);
            }
            uci_hrcv::UciNotification::SessionStatusNtf(response) => {
                self.invoke_hal_session_init_if_necessary(&response);
                self.event_manager.session_status_notification_received(response);
            }
            uci_hrcv::UciNotification::ShortMacTwoWayRangeDataNtf(response) => {
                self.event_manager.short_range_data_notification_received(response);
            }
            uci_hrcv::UciNotification::ExtendedMacTwoWayRangeDataNtf(response) => {
                self.event_manager.extended_range_data_notification_received(response);
            }
            uci_hrcv::UciNotification::SessionUpdateControllerMulticastListNtf(response) => {
                self.event_manager
                    .session_update_controller_multicast_list_notification_received(response);
            }
            uci_hrcv::UciNotification::RawVendorNtf { gid, oid, payload } => {
                self.event_manager.vendor_uci_notification_received(gid, oid, payload);
            }
            _ => log::error!("Unexpected hal notification received {:?}", response),
        }
        Ok(())
    }

    // Handles a single message from JNI or the HAL.
    async fn drive_once(&mut self) -> Result<()> {
        // TODO: Handle messages for real instead of just logging them.
        select! {
            Some(()) = option_future(self.response_channel.as_ref()
                .map(|(_, retryer)| retryer.command_failed())) => {
                // TODO: Do we want to flush the incoming queue of commands when this happens?
                self.response_channel = None
            }
            // Note: If a blocking command is awaiting a response, any non-blocking commands are not
            // dequeued until the blocking cmd's response is received.
            Some((cmd, tx)) = self.cmd_receiver.recv(), if self.response_channel.is_none() => {
                match tx {
                    Some(tx) => { // Blocking JNI commands processing.
                        // TODO: If we do something similar to communication to the HAL (using a channel
                        // to hide the asynchrony, we can remove the field and make this straight line code.
                        self.handle_blocking_jni_cmd(tx, cmd)?;
                    },
                    None => { // Non Blocking JNI commands processing.
                        self.handle_non_blocking_jni_cmd(cmd)?;
                    }
                }
            }
            Some(rsp) = self.rsp_receiver.recv() => {
                match rsp {
                    HalCallback::Event{event, event_status} => {
                        log::info!("Received hal event: {:?} with status: {:?}", event, event_status);
                    },
                    HalCallback::UciRsp(response) => {
                        log::debug!("Received hal response {:?}", response);
                        if let Some((channel, retryer)) = self.response_channel.take() {
                            retryer.received();
                            channel.send(response);
                        } else {
                            error!("Received response packet, but no response channel available");
                        }
                    },
                    HalCallback::UciNtf(response) => {
                        self.handle_hal_notification(response)?;
                    }
                }
            }
        }
        Ok(())
    }

    // Triggers the session init HAL API, if a new session is initialized.
    fn invoke_hal_session_init_if_necessary(&self, response: &SessionStatusNtfPacket) -> () {
        let session_id =
            response.get_session_id().to_i32().expect("Failed converting session_id to u32");
        if let SessionState::SessionStateInit = response.get_session_state() {
            info!("Session {:?} initialized, invoking session init HAL API", session_id);
            self.adaptation
                .session_initialization(session_id)
                .unwrap_or_else(|e| error!("Error invoking session init HAL API : {:?}", e));
        }
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
    pub fn new<T: 'static + Manager + std::marker::Send>(event_manager: T) -> Result<Dispatcher> {
        info!("initializing dispatcher");
        let (cmd_sender, cmd_receiver) =
            mpsc::unbounded_channel::<(JNICommand, Option<UciResponseHandle>)>();
        let (rsp_sender, rsp_receiver) = mpsc::unbounded_channel::<HalCallback>();
        let adaptation: SyncUwbAdaptation = Box::new(UwbAdaptationImpl::new(None, rsp_sender));
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

    fn exit(&mut self) -> Result<()> {
        self.send_jni_command(JNICommand::Exit)?;
        let _ = self.runtime.block_on(&mut self.join_handle);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver() -> Result<()> {
        // TODO: Remove this once we call it somewhere real.
        logger::init(
            logger::Config::default().with_tag_on_device("uwb").with_min_level(log::Level::Error),
        );

        let event_manager = EventManagerTest::new();
        let mut dispatcher = Dispatcher::new(event_manager)?;
        dispatcher.send_jni_command(JNICommand::Enable)?;
        dispatcher.exit()?;
        Ok(())
    }
}
