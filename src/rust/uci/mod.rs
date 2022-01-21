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

use crate::adaptation::UwbAdaptation;
use crate::error::UwbErr;
use crate::event_manager::EventManager;
use crate::uci::uci_hrcv::UciResponse;
use android_hardware_uwb::aidl::android::hardware::uwb::{
    UwbEvent::UwbEvent, UwbStatus::UwbStatus,
};
use log::{debug, error, info, warn};
use num_traits::ToPrimitive;
use std::future::Future;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::{select, task};
use uwb_uci_packets::{
    GetDeviceInfoCmdBuilder, GetDeviceInfoRspBuilder, Packet, RangeStartCmdBuilder,
    RangeStopCmdBuilder, SessionDeinitCmdBuilder, SessionGetCountCmdBuilder,
    SessionGetStateCmdBuilder, SessionState, SessionStatusNtfPacket, StatusCode,
};

pub type Result<T> = std::result::Result<T, UwbErr>;
pub type UciResponseHandle = oneshot::Sender<UciResponse>;

// TODO: Use real values for these enums.

// Commands sent from JNI.
#[derive(Debug)]
pub enum JNICommand {
    UwaEnable,
    UwaDisable(bool),
    Exit,
}

// Commands sent from JNI, which blocks until it gets a response.
#[derive(Debug)]
pub enum BlockingJNICommand {
    GetDeviceInfo,
    UwaSessionInit(u32, u8),
    UwaSessionDeinit(u32),
    UwaSessionGetCount,
    UwaStartRange(u32),
    UwaStopRange(u32),
    UwaGetSessionState(u32),
    UwaSessionUpdateMulticastList {
        session_id: u32,
        action: u8,
        no_of_controlee: u8,
        address_list: Vec<u8>,
        sub_session_id_list: Vec<i32>,
    },
    UwaSetCountryCode {
        code: Vec<u8>,
    },
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

    fn send_with_retry(self, adaptation: Arc<UwbAdaptation>, bytes: Vec<u8>) {
        tokio::task::spawn(async move {
            let mut received_response = false;
            for retry in 0..MAX_RETRIES {
                // TODO this mut be non-blocking to avoid blocking the runtime if the HAL locks up.
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

struct Driver {
    adaptation: Arc<UwbAdaptation>,
    event_manager: EventManager,
    cmd_receiver: mpsc::UnboundedReceiver<JNICommand>,
    blocking_cmd_receiver: mpsc::UnboundedReceiver<(BlockingJNICommand, UciResponseHandle)>,
    rsp_receiver: mpsc::UnboundedReceiver<HalCallback>,
    response_channel: Option<(UciResponseHandle, Retryer)>,
}

// Creates a future that handles messages from JNI and the HAL.
async fn drive(
    adaptation: UwbAdaptation,
    event_manager: EventManager,
    cmd_receiver: mpsc::UnboundedReceiver<JNICommand>,
    blocking_cmd_receiver: mpsc::UnboundedReceiver<(BlockingJNICommand, UciResponseHandle)>,
    rsp_receiver: mpsc::UnboundedReceiver<HalCallback>,
) -> Result<()> {
    Driver::new(
        Arc::new(adaptation),
        event_manager,
        cmd_receiver,
        blocking_cmd_receiver,
        rsp_receiver,
    )
    .drive()
    .await
}

const MAX_RETRIES: usize = 10;
const RETRY_DELAY_MS: u64 = 100;

impl Driver {
    fn new(
        adaptation: Arc<UwbAdaptation>,
        event_manager: EventManager,
        cmd_receiver: mpsc::UnboundedReceiver<JNICommand>,
        blocking_cmd_receiver: mpsc::UnboundedReceiver<(BlockingJNICommand, UciResponseHandle)>,
        rsp_receiver: mpsc::UnboundedReceiver<HalCallback>,
    ) -> Self {
        Self {
            adaptation,
            event_manager,
            cmd_receiver,
            blocking_cmd_receiver,
            rsp_receiver,
            response_channel: None,
        }
    }

    // Continually handles messages.
    async fn drive(mut self) -> Result<()> {
        loop {
            self.drive_once().await?
        }
    }

    // Handles a single message from JNI or the HAL.
    async fn drive_once(&mut self) -> Result<()> {
        // TODO: Handle messages for real instead of just logging them.
        select! {
            Some(()) = option_future(self.response_channel.as_ref().map(|(_, retryer)| retryer.command_failed())) => {
                // TODO: Do we want to flush the incoming queue of commands when this happens?
                self.response_channel = None
            }
            Some(cmd) = self.cmd_receiver.recv() => {
                log::info!("{:?}", cmd);
                match cmd {
                    JNICommand::UwaEnable => {
                        // TODO: This mimics existing behavior, but I think we've got a few issues
                        // here:
                        // * We've got two different initialization sites (UwaEnable *and*
                        // adaptation construction)
                        // * We have multiple functions required to finish building a correct
                        //   UwaEnable (so there are bad states to leave it in)
                        // * We have UwaDisable, but the adaptation isn't optional, so we will end
                        // up with an invalid but still present adaptation.
                        //
                        // A future patch should probably make a single constructor for everything,
                        // and it should probably be called here rather than mutating an existing
                        // adaptation. The adaptation should be made optional.
                        if let Some(adaptation) = Arc::get_mut(&mut self.adaptation) {
                            adaptation.initialize();
                        } else {
                            error!("Attempted to enable Uwa while it was still in use.");
                        }
                        self.adaptation.hal_open();
                        self.adaptation.core_initialization()
                            .unwrap_or_else(|e| error!("Error invoking core init HAL API : {:?}", e));
                    },
                    JNICommand::UwaDisable(graceful) => {
                        self.adaptation.hal_close();
                    },
                    JNICommand::Exit => return Err(UwbErr::Exit),
                }
            }
            Some((cmd, tx)) = self.blocking_cmd_receiver.recv(), if self.response_channel.is_none() => {
                // TODO: If we do something similar to communication to the HAL (using a channel
                // to hide the asynchrony, we can remove the field and make this straightline code.
                log::info!("{:?}", cmd);
                let bytes = match cmd {
                    BlockingJNICommand::GetDeviceInfo =>
                        GetDeviceInfoCmdBuilder {}.build().to_vec()
                    ,
                    BlockingJNICommand::UwaSessionInit(session_id, session_type) =>
                        uci_hmsgs::build_session_init_cmd(session_id, session_type).build().to_vec()
                    ,
                    BlockingJNICommand::UwaSessionDeinit(session_id) =>
                        SessionDeinitCmdBuilder { session_id }.build().to_vec()
                    ,
                    BlockingJNICommand::UwaSessionGetCount =>
                        SessionGetCountCmdBuilder {}.build().to_vec()
                    ,
                    BlockingJNICommand::UwaStartRange(session_id) =>
                        RangeStartCmdBuilder { session_id }.build().to_vec()
                    ,
                    BlockingJNICommand::UwaStopRange(session_id) =>
                        RangeStopCmdBuilder { session_id }.build().to_vec()
                    ,
                    BlockingJNICommand::UwaGetSessionState(session_id) =>
                        SessionGetStateCmdBuilder { session_id }.build().to_vec()
                    ,
                    BlockingJNICommand::UwaSessionUpdateMulticastList{session_id, action, no_of_controlee, ref address_list, ref sub_session_id_list} =>
                        uci_hmsgs::build_multicast_list_update_cmd(session_id, action, no_of_controlee, address_list, sub_session_id_list).build().to_vec()
                    ,
                    BlockingJNICommand::UwaSetCountryCode{ref code} =>
                        uci_hmsgs::build_set_country_code_cmd(code)?.build().to_vec()
                    ,
                };

                let retryer = Retryer::new();
                self.response_channel = Some((tx, retryer.clone()));
                retryer.send_with_retry(self.adaptation.clone(), bytes);
            }
            Some(rsp) = self.rsp_receiver.recv() => {
                match rsp {
                    HalCallback::Event{event, event_status} => {
                        log::info!("Received HAL event: {:?} with status: {:?}", event, event_status);
                    },
                    HalCallback::UciRsp(response) => {
                        if let Some((channel, retryer)) = self.response_channel.take() {
                            retryer.received();
                            channel.send(response);
                        } else {
                            error!("Received response packet, but no response channel available");
                        }
                    },
                    HalCallback::UciNtf(response) => {
                        match response {
                            uci_hrcv::UciNotification::DeviceStatusNtf(response) => {
                                self.event_manager.device_status_notification_received(response);
                            },
                            uci_hrcv::UciNotification::GenericError(response) => {
                                match (response.get_status(), self.response_channel.as_ref()) {
                                    (StatusCode::UciStatusCommandRetry, Some((_, retryer))) => retryer.retry(),
                                    _ => ()
                                }
                                self.event_manager.core_generic_error_notification_received(response);
                            },
                            uci_hrcv::UciNotification::SessionStatusNtf(response) => {
                                self.invoke_hal_session_init_if_necessary(&response);
                                self.event_manager.session_status_notification_received(response);
                            },
                            uci_hrcv::UciNotification::ShortMacTwoWayRangeDataNtf(response) => {
                                self.event_manager.short_range_data_notification(response);
                            },
                            uci_hrcv::UciNotification::ExtendedMacTwoWayRangeDataNtf(response) => {
                                self.event_manager.extended_range_data_notification(response);
                            },
                            uci_hrcv::UciNotification::SessionUpdateControllerMulticastListNtf(response) => {
                                self.event_manager.session_update_controller_multicast_list_notification(response);
                            },
                            _ => log::warn!("Notification type not handled yet {:?}", response),
                        }
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
    cmd_sender: mpsc::UnboundedSender<JNICommand>,
    blocking_cmd_sender: mpsc::UnboundedSender<(BlockingJNICommand, UciResponseHandle)>,
    join_handle: task::JoinHandle<Result<()>>,
    runtime: Runtime,
    pub device_info: Option<GetDeviceInfoRspBuilder>,
}

impl Dispatcher {
    pub fn new(event_manager: EventManager) -> Result<Dispatcher> {
        info!("initializing dispatcher");
        let (cmd_sender, cmd_receiver) = mpsc::unbounded_channel::<JNICommand>();
        let (blocking_cmd_sender, blocking_cmd_receiver) =
            mpsc::unbounded_channel::<(BlockingJNICommand, UciResponseHandle)>();
        let (rsp_sender, rsp_receiver) = mpsc::unbounded_channel::<HalCallback>();
        let adaptation = UwbAdaptation::new(None, rsp_sender);
        // We create a new thread here both to avoid reusing the Java service thread and because
        // binder threads will call into this.
        let runtime = Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("uwb-uci-handler")
            .enable_all()
            .build()?;
        let join_handle = runtime.spawn(drive(
            adaptation,
            event_manager,
            cmd_receiver,
            blocking_cmd_receiver,
            rsp_receiver,
        ));
        Ok(Dispatcher { cmd_sender, blocking_cmd_sender, join_handle, runtime, device_info: None })
    }

    pub fn send_jni_command(&self, cmd: JNICommand) -> Result<()> {
        self.cmd_sender.send(cmd)?;
        Ok(())
    }

    // TODO: Consider implementing these separate for different commands so we can have more
    // specific return types.
    pub fn block_on_jni_command(&self, cmd: BlockingJNICommand) -> Result<UciResponse> {
        let (tx, rx) = oneshot::channel();
        self.blocking_cmd_sender.send((cmd, tx))?;
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
        // TODO : Consider below ways to write the unit test
        // 1
        // Create test-only methods on EventManager that allow you to construct one without Java
        // (and to have dummy/tracked effects when callbacks get called).
        //
        // 2 and recommended way
        // Take the signature of EventManager and make it a trait, which would allow you to impl that
        // trait again on a test-only mock type

        //let mut dispatcher = Dispatcher::new()?;
        //dispatcher.send_hal_response(HalCallback::A)?;
        //dispatcher.send_jni_command(JNICommand::UwaEnable)?;
        //dispatcher.block_on_jni_command(BlockingJNICommand::GetDeviceInfo)?;
        //dispatcher.exit()?;
        //assert!(dispatcher.send_hal_response(HalCallback::B).is_err());
        Ok(())
    }
}
