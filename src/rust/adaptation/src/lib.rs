//! Definition of UwbClientCallback

use android_hardware_uwb::aidl::android::hardware::uwb::{
    IUwbClientCallback::{BnUwbClientCallback, IUwbClientCallback},
    UwbEvent::UwbEvent,
    UwbStatus::UwbStatus,
};
use android_hardware_uwb::binder::{BinderFeatures, Interface, Result as BinderResult};

type THalUwbEventCback = fn(event: UwbEvent, status: UwbStatus) -> ();
type THalUwbUciMsgCback = fn(p_data: &[u8]) -> ();

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn test_onHalEvent() {
        static EVENT_CALLED: AtomicBool = AtomicBool::new(false);
        fn t_hal_uwb_event_cback_tmpl(event: UwbEvent, status: UwbStatus) -> () {
            EVENT_CALLED.store(true, Ordering::Relaxed);
        }
        fn t_hal_uwb_uci_msg_cback_tmpl(p_data: &[u8]) -> () {
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
        fn t_hal_uwb_event_cback_tmpl(event: UwbEvent, status: UwbStatus) -> () {
            MSG_CALLED.store(true, Ordering::Relaxed);
        }
        fn t_hal_uwb_uci_msg_cback_tmpl(p_data: &[u8]) -> () {
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
