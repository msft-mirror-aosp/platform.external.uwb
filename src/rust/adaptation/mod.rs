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

#[derive(Clone)]
pub struct UwbAdaptation {
    hal: Option<Strong<dyn IUwbChip>>,
    rsp_sender: mpsc::UnboundedSender<HalCallback>,
}

impl UwbAdaptation {
    pub fn new(
        hal: Option<Strong<dyn IUwbChip>>,
        rsp_sender: mpsc::UnboundedSender<HalCallback>,
    ) -> UwbAdaptation {
        UwbAdaptation { hal, rsp_sender }
    }

    pub fn initialize(&mut self) {
        self.initialize_hal_device_context();
    }

    pub fn finalize(&mut self, exit_status: bool) {}

    fn initialize_hal_device_context(&mut self) {
        // TODO: If we can initialize this in new(), we can properly error if it fails and remove
        // the checks in the functions below.
        self.hal = get_hal_service();
        if (self.hal.is_none()) {
            info!("Failed to retrieve the UWB HAL!");
        }
    }

    pub fn hal_open(&self) {
        let m_cback = BnUwbClientCallback::new_binder(
            UwbClientCallback { rsp_sender: self.rsp_sender.clone() },
            BinderFeatures::default(),
        );
        if let Some(hal) = &self.hal {
            hal.open(&m_cback);
        } else {
            warn!("Failed to open HAL");
        }
    }

    pub fn hal_close(&self) {
        if let Some(hal) = &self.hal {
            hal.close();
        }
    }

    pub fn core_initialization(&self) -> Result<(), UwbErr> {
        if let Some(hal) = &self.hal {
            return Ok(hal.coreInit()?);
        }
        Err(UwbErr::failed())
    }

    pub fn session_initialization(&self, session_id: i32) -> Result<(), UwbErr> {
        if let Some(hal) = &self.hal {
            return Ok(hal.sessionInit(session_id)?);
        }
        Err(UwbErr::failed())
    }

    fn get_supported_android_uci_version(&self) -> Result<i32, UwbErr> {
        if let Some(hal) = &self.hal {
            return Ok(hal.getSupportedAndroidUciVersion()?);
        }
        Err(UwbErr::failed())
    }

    fn get_supported_android_capabilities(&self) -> Result<i64, UwbErr> {
        if let Some(hal) = &self.hal {
            return Ok(hal.getSupportedAndroidCapabilities()?);
        }
        Err(UwbErr::failed())
    }

    pub fn send_uci_message(&self, data: &[u8]) {
        if let Some(hal) = &self.hal {
            hal.sendUciMessage(data);
        } else {
            warn!("Failed to send uci message");
        }
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
