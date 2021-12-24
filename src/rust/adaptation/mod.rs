//! Definition of UwbClientCallback

use crate::error::UwbErr;
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

type THalUwbEventCback = fn(event: UwbEvent, status: UwbStatus);
type THalUwbUciMsgCback = fn(p_data: &[u8]);
type THalApiOpen =
    fn(&UwbAdaptation, event_cback: THalUwbEventCback, msg_cback: THalUwbUciMsgCback);
type THalApiClose = fn(&UwbAdaptation);
type THalApiWrite = fn(&UwbAdaptation, data: &[u8]);
type THalApiCoreInit = fn(&UwbAdaptation) -> Result<(), UwbErr>;
type THalApiSessionInit = fn(&UwbAdaptation, session_id: i32) -> Result<(), UwbErr>;
type THalApiGetSupportedAndroidUciVersion = fn(&UwbAdaptation) -> Result<(i32), UwbErr>;
type THalApiGetSupportedAndroidCapabilities = fn(&UwbAdaptation) -> Result<(i64), UwbErr>;

#[derive(Clone, Copy)]
pub struct UwbClientCallback {
    pub event_cb: THalUwbEventCback,
    pub uci_message_cb: THalUwbUciMsgCback,
}

impl UwbClientCallback {
    fn new(event_cb: THalUwbEventCback, uci_message_cb: THalUwbUciMsgCback) -> Self {
        UwbClientCallback { event_cb, uci_message_cb }
    }
}

impl Interface for UwbClientCallback {}

impl IUwbClientCallback for UwbClientCallback {
    fn onHalEvent(&self, event: UwbEvent, event_status: UwbStatus) -> BinderResult<()> {
        (self.event_cb)(event, event_status);
        Ok(())
    }

    fn onUciMessage(&self, data: &[u8]) -> BinderResult<()> {
        (self.uci_message_cb)(data);
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

#[derive(Clone, Copy, Default)]
pub struct THalUwbEntry {
    open: Option<THalApiOpen>,
    close: Option<THalApiClose>,
    send_uci_message: Option<THalApiWrite>,
    core_initialization: Option<THalApiCoreInit>,
    session_initialization: Option<THalApiSessionInit>,
    get_supported_android_uci_version: Option<THalApiGetSupportedAndroidUciVersion>,
    get_supported_android_capabilities: Option<THalApiGetSupportedAndroidCapabilities>,
}

#[derive(Clone)]
pub struct UwbAdaptation {
    m_hal_entry_funcs: THalUwbEntry,
    m_hal: Option<Strong<dyn IUwbChip>>,
}

impl UwbAdaptation {
    pub fn new(
        m_hal_entry_funcs: THalUwbEntry,
        m_hal: Option<Strong<dyn IUwbChip>>,
    ) -> UwbAdaptation {
        UwbAdaptation { m_hal_entry_funcs: m_hal_entry_funcs, m_hal: m_hal }
    }

    pub fn initialize(&mut self) {
        self.initialize_hal_device_context();
    }

    pub fn finalize(&mut self, exit_status: bool) {}

    pub fn get_hal_entry_funcs(&self) -> THalUwbEntry {
        self.m_hal_entry_funcs
    }

    fn initialize_hal_device_context(&mut self) {
        self.m_hal_entry_funcs.open = Some(UwbAdaptation::hal_open);
        self.m_hal_entry_funcs.close = Some(UwbAdaptation::hal_close);
        self.m_hal_entry_funcs.send_uci_message = Some(UwbAdaptation::send_uci_message);
        self.m_hal_entry_funcs.core_initialization = Some(UwbAdaptation::core_initialization);
        self.m_hal_entry_funcs.session_initialization = Some(UwbAdaptation::session_initialization);
        self.m_hal_entry_funcs.get_supported_android_uci_version =
            Some(UwbAdaptation::get_supported_android_uci_version);
        self.m_hal_entry_funcs.get_supported_android_capabilities =
            Some(UwbAdaptation::get_supported_android_capabilities);
        self.m_hal = get_hal_service();
        if (self.m_hal.is_none()) {
            info!("Failed to retrieve the UWB HAL!");
        }
    }

    fn hal_open(&self, hal_cback: THalUwbEventCback, data_cback: THalUwbUciMsgCback) {
        let m_cback = BnUwbClientCallback::new_binder(
            UwbClientCallback { event_cb: hal_cback, uci_message_cb: data_cback },
            BinderFeatures::default(),
        );
        if let Some(hal) = &self.m_hal {
            hal.open(&m_cback);
        } else {
            warn!("Failed to open HAL");
        }
    }

    fn hal_close(&self) {
        if let Some(hal) = &self.m_hal {
            hal.close();
        }
    }

    pub fn core_initialization(&self) -> Result<(), UwbErr> {
        if let Some(hal) = &self.m_hal {
            return Ok(hal.coreInit()?);
        }
        Err(UwbErr::failed())
    }

    fn session_initialization(&self, session_id: i32) -> Result<(), UwbErr> {
        if let Some(hal) = &self.m_hal {
            return Ok(hal.sessionInit(session_id)?);
        }
        Err(UwbErr::failed())
    }

    fn get_supported_android_uci_version(&self) -> Result<i32, UwbErr> {
        if let Some(hal) = &self.m_hal {
            return Ok(hal.getSupportedAndroidUciVersion()?);
        }
        Err(UwbErr::failed())
    }

    fn get_supported_android_capabilities(&self) -> Result<i64, UwbErr> {
        if let Some(hal) = &self.m_hal {
            return Ok(hal.getSupportedAndroidCapabilities()?);
        }
        Err(UwbErr::failed())
    }

    fn send_uci_message(&self, data: &[u8]) {
        if let Some(hal) = &self.m_hal {
            hal.sendUciMessage(data);
        } else {
            warn!("Failed to send uci message");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn test_onHalEvent() {
        static EVENT_CALLED: AtomicBool = AtomicBool::new(false);
        fn t_hal_uwb_event_cback_tmpl(event: UwbEvent, status: UwbStatus) {
            EVENT_CALLED.store(true, Ordering::Relaxed);
        }
        fn t_hal_uwb_uci_msg_cback_tmpl(p_data: &[u8]) {
            EVENT_CALLED.store(true, Ordering::Relaxed);
        }
        let uwb_event_test = UwbEvent(0);
        let uwb_status_test = UwbStatus(1);
        let t_hal_uwb_event_cback_test: THalUwbEventCback = t_hal_uwb_event_cback_tmpl;
        let t_hal_uwb_uci_msg_cback_test: THalUwbUciMsgCback = t_hal_uwb_uci_msg_cback_tmpl;
        let uwb_client_callback_test =
            UwbClientCallback::new(t_hal_uwb_event_cback_test, t_hal_uwb_uci_msg_cback_test);
        let result = uwb_client_callback_test.onHalEvent(uwb_event_test, uwb_status_test);
        assert!(EVENT_CALLED.load(Ordering::Relaxed));
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_onUciMessage() {
        static MSG_CALLED: AtomicBool = AtomicBool::new(false);
        fn t_hal_uwb_event_cback_tmpl(event: UwbEvent, status: UwbStatus) {
            MSG_CALLED.store(true, Ordering::Relaxed);
        }
        fn t_hal_uwb_uci_msg_cback_tmpl(p_data: &[u8]) {
            MSG_CALLED.store(true, Ordering::Relaxed);
        }
        let data = [1, 2, 3, 4];
        let t_hal_uwb_event_cback_test: THalUwbEventCback = t_hal_uwb_event_cback_tmpl;
        let t_hal_uwb_uci_msg_cback_test: THalUwbUciMsgCback = t_hal_uwb_uci_msg_cback_tmpl;
        let uwb_client_callback_test =
            UwbClientCallback::new(t_hal_uwb_event_cback_test, t_hal_uwb_uci_msg_cback_test);
        let result = uwb_client_callback_test.onUciMessage(&data);
        assert!(MSG_CALLED.load(Ordering::Relaxed));
        assert_eq!(result, Ok(()));
    }
}
