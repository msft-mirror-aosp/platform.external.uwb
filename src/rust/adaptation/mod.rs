//! Definition of UwbClientCallback

use crate::error::UwbErr;
use crate::uci::uci_hrcv;
use crate::uci::HalCallback;
use android_hardware_uwb::aidl::android::hardware::uwb::{
    IUwb::{BnUwb, IUwb},
    IUwbChip::{BnUwbChip, IUwbChip},
    IUwbClientCallback::{BnUwbClientCallback, IUwbClientCallback},
    UwbEvent::UwbEvent,
    UwbStatus::UwbStatus,
};
use android_hardware_uwb::binder::{
    self, BinderFeatures, Interface, Result as BinderResult, Strong,
};
use log::{error, info, warn};
use std::result::Result;
use tokio::sync::mpsc;
use uwb_uci_packets::{UciPacketChild, UciPacketPacket};

pub struct UwbClientCallback {
    rsp_sender: mpsc::UnboundedSender<HalCallback>,
}

impl UwbClientCallback {
    fn new(rsp_sender: mpsc::UnboundedSender<HalCallback>) -> Self {
        UwbClientCallback { rsp_sender }
    }
}

impl Interface for UwbClientCallback {}

impl IUwbClientCallback for UwbClientCallback {
    fn onHalEvent(&self, event: UwbEvent, event_status: UwbStatus) -> BinderResult<()> {
        self.rsp_sender
            .send(HalCallback::Event { event, event_status })
            .unwrap_or_else(|e| error!("Error sending evt callback: {:?}", e));
        Ok(())
    }

    fn onUciMessage(&self, data: &[u8]) -> BinderResult<()> {
        match UciPacketPacket::parse(data) {
            Ok(evt) => {
                let packetMsg = uci_hrcv::uci_message(evt);
                match packetMsg {
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

fn get_hal_service() -> Option<Strong<dyn IUwbChip>> {
    let service_name: &str = "android.hardware.uwb.IUwb/default";
    let i_uwb: Strong<dyn IUwb> = match binder::get_interface(service_name) {
        Ok(chip) => chip,
        Err(e) => {
            warn!("Failed to connect to the AIDL HAL service.");
            return None;
        }
    };
    let chip_names = match i_uwb.getChips() {
        Ok(names) => names,
        Err(e) => {
            warn!("Failed to retrieve the HAL chip names.");
            return None;
        }
    };
    let i_uwb_chip = match i_uwb.getChip(&chip_names[0]) {
        Ok(chip) => chip,
        Err(e) => {
            warn!("Failed to retrieve the HAL chip.");
            return None;
        }
    };
    Some(i_uwb_chip)
}

pub trait UwbAdaptation {
    fn finalize(&mut self, exit_status: bool);
    fn hal_open(&self);
    fn hal_close(&self);
    fn core_initialization(&self) -> Result<(), UwbErr>;
    fn session_initialization(&self, session_id: i32) -> Result<(), UwbErr>;
    fn send_uci_message(&self, data: &[u8]) -> Result<(), UwbErr>;
}

#[derive(Clone)]
pub struct UwbAdaptationImpl {
    hal: Strong<dyn IUwbChip>,
    rsp_sender: mpsc::UnboundedSender<HalCallback>,
}

impl UwbAdaptationImpl {
    pub fn new(rsp_sender: mpsc::UnboundedSender<HalCallback>) -> Result<Self, UwbErr> {
        let hal = get_hal_service().ok_or(UwbErr::HalUnavailable)?;
        Ok(UwbAdaptationImpl { hal, rsp_sender })
    }

    fn get_supported_android_uci_version(&self) -> Result<i32, UwbErr> {
        Ok(self.hal.getSupportedAndroidUciVersion()?)
    }

    fn get_supported_android_capabilities(&self) -> Result<i64, UwbErr> {
        Ok(self.hal.getSupportedAndroidCapabilities()?)
    }
}

impl UwbAdaptation for UwbAdaptationImpl {
    fn finalize(&mut self, exit_status: bool) {}

    fn hal_open(&self) {
        let m_cback = BnUwbClientCallback::new_binder(
            UwbClientCallback { rsp_sender: self.rsp_sender.clone() },
            BinderFeatures::default(),
        );
        self.hal.open(&m_cback);
    }

    fn hal_close(&self) {
        self.hal.close();
    }

    fn core_initialization(&self) -> Result<(), UwbErr> {
        Ok(self.hal.coreInit()?)
    }

    fn session_initialization(&self, session_id: i32) -> Result<(), UwbErr> {
        Ok(self.hal.sessionInit(session_id)?)
    }

    fn send_uci_message(&self, data: &[u8]) -> Result<(), UwbErr> {
        self.hal.sendUciMessage(data)?;
        // TODO should we be validating the returned number?
        Ok(())
    }
}

#[cfg(test)]
pub struct MockUwbAdaptation {
    rsp_sender: mpsc::UnboundedSender<HalCallback>,
}

#[cfg(test)]
impl MockUwbAdaptation {
    pub fn new(rsp_sender: mpsc::UnboundedSender<HalCallback>) -> Self {
        Self { rsp_sender }
    }
}

#[cfg(test)]
impl UwbAdaptation for MockUwbAdaptation {
    fn finalize(&mut self, exit_status: bool) {}
    fn hal_open(&self) {}
    fn hal_close(&self) {}
    fn core_initialization(&self) -> Result<(), UwbErr> {
        let uwb_event_test = UwbEvent::POST_INIT_CPLT;
        let uwb_status_test = UwbStatus::OK;
        let uwb_client_callback_test = UwbClientCallback::new(self.rsp_sender.clone());
        let result = uwb_client_callback_test.onHalEvent(uwb_event_test, uwb_status_test);
        Ok(())
    }
    fn session_initialization(&self, session_id: i32) -> Result<(), UwbErr> {
        Ok(())
    }
    fn send_uci_message(&self, data: &[u8]) -> Result<(), UwbErr> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onHalEvent() {
        let uwb_event_test = UwbEvent(0);
        let uwb_status_test = UwbStatus(1);
        let (rsp_sender, _) = mpsc::unbounded_channel::<HalCallback>();
        let uwb_client_callback_test = UwbClientCallback::new(rsp_sender);
        let result = uwb_client_callback_test.onHalEvent(uwb_event_test, uwb_status_test);
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn test_onUciMessage_good() {
        let data = [
            0x40, 0x02, 0x00, 0x0b, 0x01, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x01,
            0x0a,
        ];
        let (rsp_sender, mut rsp_receiver) = mpsc::unbounded_channel::<HalCallback>();
        let uwb_client_callback_test = UwbClientCallback::new(rsp_sender);
        let result = uwb_client_callback_test.onUciMessage(&data);
        assert_eq!(result, Ok(()));
        let response = rsp_receiver.recv().await;
        assert!(matches!(
            response,
            Some(HalCallback::UciRsp(uci_hrcv::UciResponse::GetDeviceInfoRsp(_)))
        ));
    }

    #[test]
    fn test_onUciMessage_bad() {
        let data = [
            0x42, 0x02, 0x00, 0x0b, 0x01, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x01,
            0x0a,
        ];
        let (rsp_sender, mut rsp_receiver) = mpsc::unbounded_channel::<HalCallback>();
        let uwb_client_callback_test = UwbClientCallback::new(rsp_sender);
        let result = uwb_client_callback_test.onUciMessage(&data);
        assert_eq!(result, Ok(()));
        let response = rsp_receiver.try_recv();
        assert!(response.is_err());
    }
}
