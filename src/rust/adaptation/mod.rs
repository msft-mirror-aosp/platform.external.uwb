//! Definition of UwbClientCallback

use crate::error::UwbErr;
use crate::uci::uci_hrcv;
use crate::uci::uci_logger::{UciLogMode, UciLogger, UciLoggerImpl};
use crate::uci::HalCallback;
use android_hardware_uwb::aidl::android::hardware::uwb::{
    IUwb::IUwbAsync,
    IUwbChip::IUwbChipAsync,
    IUwbClientCallback::{BnUwbClientCallback, IUwbClientCallbackAsyncServer},
    UwbEvent::UwbEvent,
    UwbStatus::UwbStatus,
};
use android_hardware_uwb::binder::{BinderFeatures, Interface, Result as BinderResult, Strong};
use async_trait::async_trait;
use binder_tokio::{Tokio, TokioRuntime};
use log::error;
use std::sync::Arc;
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use uwb_uci_packets::{Packet, UciCommandPacket, UciPacketChild, UciPacketPacket};

type Result<T> = std::result::Result<T, UwbErr>;
type SyncUciLogger = Arc<dyn UciLogger + Send + Sync>;

pub struct UwbClientCallback {
    rsp_sender: mpsc::UnboundedSender<HalCallback>,
    logger: SyncUciLogger,
}

impl UwbClientCallback {
    fn new(rsp_sender: mpsc::UnboundedSender<HalCallback>, logger: SyncUciLogger) -> Self {
        UwbClientCallback { rsp_sender, logger }
    }

    async fn log_uci_packet(&self, packet: UciPacketPacket) {
        match packet.specialize() {
            UciPacketChild::UciResponse(pkt) => self.logger.log_uci_response(pkt).await,
            UciPacketChild::UciNotification(pkt) => self.logger.log_uci_notification(pkt).await,
            _ => {}
        }
    }
}

impl Interface for UwbClientCallback {}

#[async_trait]
impl IUwbClientCallbackAsyncServer for UwbClientCallback {
    async fn onHalEvent(&self, event: UwbEvent, event_status: UwbStatus) -> BinderResult<()> {
        self.rsp_sender
            .send(HalCallback::Event { event, event_status })
            .unwrap_or_else(|e| error!("Error sending evt callback: {:?}", e));
        Ok(())
    }

    async fn onUciMessage(&self, data: &[u8]) -> BinderResult<()> {
        match UciPacketPacket::parse(data) {
            Ok(packet) => {
                self.log_uci_packet(packet.clone()).await;
                let packet_msg = uci_hrcv::uci_message(packet);
                match packet_msg {
                    Ok(uci_hrcv::UciMessage::Response(evt)) => self
                        .rsp_sender
                        .send(HalCallback::UciRsp(evt))
                        .unwrap_or_else(|e| error!("Error sending uci response: {:?}", e)),
                    Ok(uci_hrcv::UciMessage::Notification(evt)) => self
                        .rsp_sender
                        .send(HalCallback::UciNtf(evt))
                        .unwrap_or_else(|e| error!("Error sending uci notification: {:?}", e)),
                    _ => error!("UCI message which is neither a UCI RSP or NTF: {:?}", data),
                }
            }
            _ => error!("Failed to parse packet: {:?}", data),
        }
        Ok(())
    }
}

async fn get_hal_service() -> Result<Strong<dyn IUwbChipAsync<Tokio>>> {
    let service_name: &str = "android.hardware.uwb.IUwb/default";
    let i_uwb: Strong<dyn IUwbAsync<Tokio>> = binder_tokio::get_interface(service_name).await?;
    let chip_names = i_uwb.getChips().await?;
    let i_uwb_chip = i_uwb.getChip(&chip_names[0]).await?.into_async();
    Ok(i_uwb_chip)
}

#[async_trait]
pub trait UwbAdaptation {
    async fn finalize(&mut self, exit_status: bool);
    async fn hal_open(&self) -> Result<()>;
    async fn hal_close(&self) -> Result<()>;
    async fn core_initialization(&self) -> Result<()>;
    async fn session_initialization(&self, session_id: i32) -> Result<()>;
    async fn send_uci_message(&self, cmd: UciCommandPacket) -> Result<()>;
}

#[derive(Clone)]
pub struct UwbAdaptationImpl {
    hal: Strong<dyn IUwbChipAsync<Tokio>>,
    rsp_sender: mpsc::UnboundedSender<HalCallback>,
    logger: SyncUciLogger,
}

impl UwbAdaptationImpl {
    pub async fn new(rsp_sender: mpsc::UnboundedSender<HalCallback>) -> Result<Self> {
        let hal = get_hal_service().await?;
        let logger = UciLoggerImpl::new(UciLogMode::Filtered).await;
        Ok(UwbAdaptationImpl { hal, rsp_sender, logger: Arc::new(logger) })
    }
}

#[async_trait]
impl UwbAdaptation for UwbAdaptationImpl {
    async fn finalize(&mut self, _exit_status: bool) {}

    async fn hal_open(&self) -> Result<()> {
        let m_cback = BnUwbClientCallback::new_async_binder(
            UwbClientCallback::new(self.rsp_sender.clone(), self.logger.clone()),
            TokioRuntime(Handle::current()),
            BinderFeatures::default(),
        );
        Ok(self.hal.open(&m_cback).await?)
    }

    async fn hal_close(&self) -> Result<()> {
        self.logger.close_file().await;
        Ok(self.hal.close().await?)
    }

    async fn core_initialization(&self) -> Result<()> {
        Ok(self.hal.coreInit().await?)
    }

    async fn session_initialization(&self, session_id: i32) -> Result<()> {
        Ok(self.hal.sessionInit(session_id).await?)
    }

    async fn send_uci_message(&self, cmd: UciCommandPacket) -> Result<()> {
        self.logger.log_uci_command(cmd.clone()).await;
        self.hal.sendUciMessage(&cmd.to_vec()).await?;
        // TODO should we be validating the returned number?
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(non_snake_case)]
    use super::*;
    use crate::uci::uci_logger::MockUciLogger;
    use log::warn;
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;

    enum ExpectedCall {
        Finalize {
            expected_exit_status: bool,
        },
        HalOpen {
            out: Result<()>,
        },
        HalClose {
            out: Result<()>,
        },
        CoreInitialization {
            out: Result<()>,
        },
        SessionInitialization {
            expected_session_id: i32,
            out: Result<()>,
        },
        SendUciMessage {
            expected_data: Vec<u8>,
            rsp_data: Option<Vec<u8>>,
            notf_data: Option<Vec<u8>>,
            out: Result<()>,
        },
    }

    pub struct MockUwbAdaptation {
        rsp_sender: mpsc::UnboundedSender<HalCallback>,
        expected_calls: StdMutex<VecDeque<ExpectedCall>>,
    }

    impl MockUwbAdaptation {
        pub fn new(rsp_sender: mpsc::UnboundedSender<HalCallback>) -> Self {
            Self { rsp_sender, expected_calls: StdMutex::new(VecDeque::new()) }
        }

        #[allow(dead_code)]
        pub fn expect_finalize(&mut self, expected_exit_status: bool) {
            self.expected_calls
                .lock()
                .unwrap()
                .push_back(ExpectedCall::Finalize { expected_exit_status });
        }
        #[allow(dead_code)]
        pub fn expect_hal_open(&mut self, out: Result<()>) {
            self.expected_calls.lock().unwrap().push_back(ExpectedCall::HalOpen { out });
        }
        #[allow(dead_code)]
        pub fn expect_hal_close(&mut self, out: Result<()>) {
            self.expected_calls.lock().unwrap().push_back(ExpectedCall::HalClose { out });
        }
        #[allow(dead_code)]
        pub fn expect_core_initialization(&mut self, out: Result<()>) {
            self.expected_calls.lock().unwrap().push_back(ExpectedCall::CoreInitialization { out });
        }
        #[allow(dead_code)]
        pub fn expect_session_initialization(&mut self, expected_session_id: i32, out: Result<()>) {
            self.expected_calls
                .lock()
                .unwrap()
                .push_back(ExpectedCall::SessionInitialization { expected_session_id, out });
        }
        #[allow(dead_code)]
        pub fn expect_send_uci_message(
            &mut self,
            expected_data: Vec<u8>,
            rsp_data: Option<Vec<u8>>,
            notf_data: Option<Vec<u8>>,
            out: Result<()>,
        ) {
            self.expected_calls.lock().unwrap().push_back(ExpectedCall::SendUciMessage {
                expected_data,
                rsp_data,
                notf_data,
                out,
            });
        }

        fn create_uwb_client_callback(
            rsp_sender: mpsc::UnboundedSender<HalCallback>,
        ) -> UwbClientCallback {
            // Add tests for the mock logger.
            UwbClientCallback::new(rsp_sender, Arc::new(MockUciLogger::new()))
        }

        async fn send_client_event(&self, event: UwbEvent, status: UwbStatus) {
            let uwb_client_callback =
                MockUwbAdaptation::create_uwb_client_callback(self.rsp_sender.clone());
            let _ = uwb_client_callback.onHalEvent(event, status).await;
        }

        async fn send_client_message(&self, rsp_data: Vec<u8>) {
            let uwb_client_callback =
                MockUwbAdaptation::create_uwb_client_callback(self.rsp_sender.clone());
            let _ = uwb_client_callback.onUciMessage(&rsp_data).await;
        }
    }

    impl Drop for MockUwbAdaptation {
        fn drop(&mut self) {
            assert!(self.expected_calls.lock().unwrap().is_empty());
        }
    }

    #[async_trait]
    impl UwbAdaptation for MockUwbAdaptation {
        async fn finalize(&mut self, exit_status: bool) {
            let mut expected_calls = self.expected_calls.lock().unwrap();
            match expected_calls.pop_front() {
                Some(ExpectedCall::Finalize { expected_exit_status })
                    if expected_exit_status == exit_status =>
                {
                    return;
                }
                Some(call) => {
                    expected_calls.push_front(call);
                }
                None => {}
            }
            warn!("unpected finalize() called");
        }

        async fn hal_open(&self) -> Result<()> {
            let expected_out = {
                let mut expected_calls = self.expected_calls.lock().unwrap();
                match expected_calls.pop_front() {
                    Some(ExpectedCall::HalOpen { out }) => Some(out),
                    Some(call) => {
                        expected_calls.push_front(call);
                        None
                    }
                    None => None,
                }
            };

            match expected_out {
                Some(out) => {
                    let status = if out.is_ok() { UwbStatus::OK } else { UwbStatus::FAILED };
                    self.send_client_event(UwbEvent::OPEN_CPLT, status).await;
                    out
                }
                None => {
                    warn!("unpected hal_open() called");
                    Err(UwbErr::Undefined)
                }
            }
        }

        async fn hal_close(&self) -> Result<()> {
            let expected_out = {
                let mut expected_calls = self.expected_calls.lock().unwrap();
                match expected_calls.pop_front() {
                    Some(ExpectedCall::HalClose { out }) => Some(out),
                    Some(call) => {
                        expected_calls.push_front(call);
                        None
                    }
                    None => None,
                }
            };

            match expected_out {
                Some(out) => {
                    let status = if out.is_ok() { UwbStatus::OK } else { UwbStatus::FAILED };
                    self.send_client_event(UwbEvent::CLOSE_CPLT, status).await;
                    out
                }
                None => {
                    warn!("unpected hal_close() called");
                    Err(UwbErr::Undefined)
                }
            }
        }

        async fn core_initialization(&self) -> Result<()> {
            let expected_out = {
                let mut expected_calls = self.expected_calls.lock().unwrap();
                match expected_calls.pop_front() {
                    Some(ExpectedCall::CoreInitialization { out }) => Some(out),
                    Some(call) => {
                        expected_calls.push_front(call);
                        None
                    }
                    None => None,
                }
            };

            match expected_out {
                Some(out) => {
                    let status = if out.is_ok() { UwbStatus::OK } else { UwbStatus::FAILED };
                    self.send_client_event(UwbEvent::POST_INIT_CPLT, status).await;
                    out
                }
                None => {
                    warn!("unpected core_initialization() called");
                    Err(UwbErr::Undefined)
                }
            }
        }

        async fn session_initialization(&self, session_id: i32) -> Result<()> {
            let expected_out = {
                let mut expected_calls = self.expected_calls.lock().unwrap();
                match expected_calls.pop_front() {
                    Some(ExpectedCall::SessionInitialization { expected_session_id, out })
                        if expected_session_id == session_id =>
                    {
                        Some(out)
                    }
                    Some(call) => {
                        expected_calls.push_front(call);
                        None
                    }
                    None => None,
                }
            };

            match expected_out {
                Some(out) => out,
                None => {
                    warn!("unpected session_initialization() called");
                    Err(UwbErr::Undefined)
                }
            }
        }

        async fn send_uci_message(&self, cmd: UciCommandPacket) -> Result<()> {
            let expected_out = {
                let mut expected_calls = self.expected_calls.lock().unwrap();
                match expected_calls.pop_front() {
                    Some(ExpectedCall::SendUciMessage {
                        expected_data,
                        rsp_data,
                        notf_data,
                        out,
                    }) if expected_data == cmd.to_vec() => Some((rsp_data, notf_data, out)),
                    Some(call) => {
                        expected_calls.push_front(call);
                        None
                    }
                    None => None,
                }
            };

            match expected_out {
                Some((rsp_data, notf_data, out)) => {
                    if let Some(rsp) = rsp_data {
                        self.send_client_message(rsp).await;
                    }
                    if let Some(notf) = notf_data {
                        self.send_client_message(notf).await;
                    }
                    out
                }
                None => {
                    warn!("unpected send_uci_message() called");
                    Err(UwbErr::Undefined)
                }
            }
        }
    }

    fn create_uwb_client_callback(
        rsp_sender: mpsc::UnboundedSender<HalCallback>,
    ) -> UwbClientCallback {
        // Add tests for the mock logger.
        UwbClientCallback::new(rsp_sender, Arc::new(MockUciLogger::new()))
    }

    #[tokio::test]
    async fn test_onHalEvent() {
        let uwb_event_test = UwbEvent(0);
        let uwb_status_test = UwbStatus(1);
        let (rsp_sender, _) = mpsc::unbounded_channel::<HalCallback>();
        let uwb_client_callback_test = create_uwb_client_callback(rsp_sender);
        let result = uwb_client_callback_test.onHalEvent(uwb_event_test, uwb_status_test).await;
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn test_onUciMessage_good() {
        let data = [
            0x40, 0x02, 0x00, 0x0b, 0x01, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x01,
            0x0a,
        ];
        let (rsp_sender, mut rsp_receiver) = mpsc::unbounded_channel::<HalCallback>();
        let uwb_client_callback_test = create_uwb_client_callback(rsp_sender);
        let result = uwb_client_callback_test.onUciMessage(&data).await;
        assert_eq!(result, Ok(()));
        let response = rsp_receiver.recv().await;
        assert!(matches!(
            response,
            Some(HalCallback::UciRsp(uci_hrcv::UciResponse::GetDeviceInfoRsp(_)))
        ));
    }

    #[tokio::test]
    async fn test_onUciMessage_bad() {
        let data = [
            0x42, 0x02, 0x00, 0x0b, 0x01, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x01,
            0x0a,
        ];
        let (rsp_sender, mut rsp_receiver) = mpsc::unbounded_channel::<HalCallback>();
        let uwb_client_callback_test = create_uwb_client_callback(rsp_sender);
        let result = uwb_client_callback_test.onUciMessage(&data).await;
        assert_eq!(result, Ok(()));
        let response = rsp_receiver.try_recv();
        assert!(response.is_err());
    }
}
