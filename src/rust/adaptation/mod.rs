//! Definition of UwbClientCallback

use crate::error::UwbErr;
use crate::uci::HALResponse;
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
use log::{info, warn};
use std::result::Result;
use tokio::sync::mpsc;

pub struct UwbClientCallback {
    rsp_sender: mpsc::UnboundedSender<HALResponse>,
}

impl UwbClientCallback {
    fn new(rsp_sender: mpsc::UnboundedSender<HALResponse>) -> Self {
        UwbClientCallback { rsp_sender }
    }
}

impl Interface for UwbClientCallback {}

impl IUwbClientCallback for UwbClientCallback {
    fn onHalEvent(&self, _event: UwbEvent, _event_status: UwbStatus) -> BinderResult<()> {
        // TODO: Implement
        Ok(())
    }

    fn onUciMessage(&self, _data: &[u8]) -> BinderResult<()> {
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
}

impl UwbAdaptation {
    pub fn new(hal: Option<Strong<dyn IUwbChip>>) -> UwbAdaptation {
        UwbAdaptation { hal }
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

    fn hal_open(&self, rsp_sender: mpsc::UnboundedSender<HALResponse>) {
        let m_cback = BnUwbClientCallback::new_binder(
            UwbClientCallback { rsp_sender },
            BinderFeatures::default(),
        );
        if let Some(hal) = &self.hal {
            hal.open(&m_cback);
        } else {
            warn!("Failed to open HAL");
        }
    }

    fn hal_close(&self) {
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

    fn session_initialization(&self, session_id: i32) -> Result<(), UwbErr> {
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

    fn send_uci_message(&self, data: &[u8]) {
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
        let (rsp_sender, _) = mpsc::unbounded_channel::<HALResponse>();
        let uwb_client_callback_test = UwbClientCallback::new(rsp_sender);
        let result = uwb_client_callback_test.onHalEvent(uwb_event_test, uwb_status_test);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_onUciMessage() {
        let data = [1, 2, 3, 4];
        let (rsp_sender, _) = mpsc::unbounded_channel::<HALResponse>();
        let uwb_client_callback_test = UwbClientCallback::new(rsp_sender);
        let result = uwb_client_callback_test.onUciMessage(&data);
        // TODO: Once we implement the callback, we can send a real response packet and check the
        // receiver.
        assert_eq!(result, Ok(()));
    }
}
