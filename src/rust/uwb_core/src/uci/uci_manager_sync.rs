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

//! This module offers a synchornized interface at UCI level.
//!
//! The module is designed with the replacement for Android UCI JNI adaptation in mind. The handling
//! of UciNotifications is different in UciManager and UciManagerSync as the sync version has its
//! behavior aligned with the Android JNI UCI, and routes the UciNotifications to NotificationManager.

use log::{debug, error};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tokio::sync::mpsc;
use tokio::task;

use crate::error::{Error, Result};
use crate::params::{
    AppConfigTlv, AppConfigTlvType, CapTlv, Controlee, CoreSetConfigResponse, CountryCode,
    DeviceConfigId, DeviceConfigTlv, GetDeviceInfoResponse, PowerStats, RawVendorMessage,
    ResetConfig, SessionId, SessionState, SessionType, SetAppConfigResponse,
    UpdateMulticastListAction,
};
use crate::uci::notification::{CoreNotification, SessionNotification};
use crate::uci::uci_hal::UciHal;
use crate::uci::uci_manager::{UciManager, UciManagerImpl};

/// The NotificationManager trait is needed to process UciNotification relayed from UciManagerSync.
///
/// The UciManagerSync assumes the NotificationManager takes the responsibility to properly handle
/// the notifications, including tracking the state of HAL. UciManagerSync and lower levels only
/// redirect and categorize the notifications. The notifications are processed through callbacks.
/// NotificationManager can be !Send and !Sync, as interfacing with other programs may require.
pub trait NotificationManager: 'static {
    /// Callback for CoreNotification.
    fn on_core_notification(&mut self, core_notification: CoreNotification) -> Result<()>;

    /// Callback for SessionNotification.
    fn on_session_notification(&mut self, session_notification: SessionNotification) -> Result<()>;

    /// Callback for RawVendorMessage.
    fn on_vendor_notification(&mut self, vendor_notification: RawVendorMessage) -> Result<()>;
}

/// Builder for NotificationManager. Builder is sent between threads.
pub trait NotificationManagerBuilder<T: NotificationManager>: 'static + Send + Sync {
    /// Builds NotificationManager. The build operation Consumes Builder.
    fn build(self) -> Option<T>;
}

struct NotificationDriver<U: NotificationManager> {
    core_notification_receiver: mpsc::UnboundedReceiver<CoreNotification>,
    session_notification_receiver: mpsc::UnboundedReceiver<SessionNotification>,
    vendor_notification_receiver: mpsc::UnboundedReceiver<RawVendorMessage>,
    notification_manager: U,
}
impl<U: NotificationManager> NotificationDriver<U> {
    fn new(
        core_notification_receiver: mpsc::UnboundedReceiver<CoreNotification>,
        session_notification_receiver: mpsc::UnboundedReceiver<SessionNotification>,
        vendor_notification_receiver: mpsc::UnboundedReceiver<RawVendorMessage>,
        notification_manager: U,
    ) -> Self {
        Self {
            core_notification_receiver,
            session_notification_receiver,
            vendor_notification_receiver,
            notification_manager,
        }
    }
    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(ntf) = self.core_notification_receiver.recv() =>{
                    self.notification_manager.on_core_notification(ntf).unwrap_or_else(|e|{
                        error!("NotificationDriver: CoreNotification callback error: {:?}",e);
                    });
                }
                Some(ntf) = self.session_notification_receiver.recv() =>{
                    self.notification_manager.on_session_notification(ntf).unwrap_or_else(|e|{
                        error!("NotificationDriver: SessionNotification callback error: {:?}",e);
                    });
                }
                Some(ntf) = self.vendor_notification_receiver.recv() =>{
                    self.notification_manager.on_vendor_notification(ntf).unwrap_or_else(|e|{
                        error!("NotificationDriver: RawVendorMessage callback error: {:?}",e);
                });
                }
                else =>{
                    debug!("NotificationDriver dropping.");
                    break;
                }
            }
        }
    }
}
/// The UciManagerSync provides a synchornized version of UciManager using the runtime supplied
/// at its initialization.
///
/// Note the processing of UciNotification is different: they are handled by NotificationManager
/// provided at construction, and the async version set_X_notification_sender methods are removed.
pub struct UciManagerSync {
    runtime: Runtime,
    uci_manager_impl: UciManagerImpl,
}
impl UciManagerSync {
    /// UciHal and NotificationManagerBuilder required at construction as they are required before
    /// open_hal is called. runtime is taken with ownership for blocking on async steps only.
    pub fn new<T: UciHal, U: NotificationManager, V: NotificationManagerBuilder<U>>(
        hal: T,
        notification_manager_builder: V,
    ) -> Result<Self> {
        let uci_manager_runtime = RuntimeBuilder::new_multi_thread().enable_all().build().unwrap();
        // UciManagerImpl::new uses tokio::spawn, so it is called inside the runtime as async fn.
        let mut uci_manager_impl = uci_manager_runtime.block_on(async { UciManagerImpl::new(hal) });
        let (core_notification_sender, core_notification_receiver) =
            mpsc::unbounded_channel::<CoreNotification>();
        let (session_notification_sender, session_notification_receiver) =
            mpsc::unbounded_channel::<SessionNotification>();
        let (vendor_notification_sender, vendor_notification_receiver) =
            mpsc::unbounded_channel::<RawVendorMessage>();
        uci_manager_runtime.block_on(async {
            uci_manager_impl.set_core_notification_sender(core_notification_sender).await;
            uci_manager_impl.set_session_notification_sender(session_notification_sender).await;
            uci_manager_impl.set_vendor_notification_sender(vendor_notification_sender).await;
        });
        // The potentially !Send NotificationManager is created in a separate thread.
        let (driver_status_sender, mut driver_status_receiver) = mpsc::unbounded_channel::<bool>();
        std::thread::spawn(move || {
            let notification_runtime =
                match RuntimeBuilder::new_current_thread().enable_all().build() {
                    Ok(nr) => nr,
                    Err(_) => {
                        // unwrap safe since receiver is in scope
                        driver_status_sender.send(false).unwrap();
                        return;
                    }
                };

            let local = task::LocalSet::new();
            let notification_manager = match notification_manager_builder.build() {
                Some(nm) => {
                    // unwrap safe since receiver is in scope
                    driver_status_sender.send(true).unwrap();
                    nm
                }
                None => {
                    // unwrap safe since receiver is in scope
                    driver_status_sender.send(false).unwrap();
                    return;
                }
            };
            let mut notification_driver = NotificationDriver::new(
                core_notification_receiver,
                session_notification_receiver,
                vendor_notification_receiver,
                notification_manager,
            );
            local.spawn_local(async move {
                task::spawn_local(async move { notification_driver.run().await }).await.unwrap();
            });
            notification_runtime.block_on(local);
        });
        match driver_status_receiver.blocking_recv() {
            Some(true) => Ok(Self { runtime: uci_manager_runtime, uci_manager_impl }),
            _ => Err(Error::Unknown),
        }
    }

    /// Start UCI HAL and blocking until UCI commands can be sent.
    pub fn open_hal(&mut self) -> Result<()> {
        self.runtime.block_on(self.uci_manager_impl.open_hal())
    }

    /// Stop the UCI HAL.
    pub fn close_hal(&mut self, force: bool) -> Result<()> {
        self.runtime.block_on(self.uci_manager_impl.close_hal(force))
    }

    // Methods for sending UCI commands. Functions are blocked until UCI response is received.
    /// Send UCI command for device reset.
    pub fn device_reset(&mut self, reset_config: ResetConfig) -> Result<()> {
        self.runtime.block_on(self.uci_manager_impl.device_reset(reset_config))
    }

    /// Send UCI command for getting device info.
    pub fn core_get_device_info(&mut self) -> Result<GetDeviceInfoResponse> {
        self.runtime.block_on(self.uci_manager_impl.core_get_device_info())
    }

    /// Send UCI command for getting capability info
    pub fn core_get_caps_info(&mut self) -> Result<Vec<CapTlv>> {
        self.runtime.block_on(self.uci_manager_impl.core_get_caps_info())
    }

    /// Send UCI command for setting core configuration.
    pub fn core_set_config(
        &mut self,
        config_tlvs: Vec<DeviceConfigTlv>,
    ) -> Result<CoreSetConfigResponse> {
        self.runtime.block_on(self.uci_manager_impl.core_set_config(config_tlvs))
    }

    /// Send UCI command for getting core configuration.
    pub fn core_get_config(
        &mut self,
        config_ids: Vec<DeviceConfigId>,
    ) -> Result<Vec<DeviceConfigTlv>> {
        self.runtime.block_on(self.uci_manager_impl.core_get_config(config_ids))
    }

    /// Send UCI command for initiating session.
    pub fn session_init(&mut self, session_id: SessionId, session_type: SessionType) -> Result<()> {
        self.runtime.block_on(self.uci_manager_impl.session_init(session_id, session_type))
    }

    /// Send UCI command for deinitiating session.
    pub fn session_deinit(&mut self, session_id: SessionId) -> Result<()> {
        self.runtime.block_on(self.uci_manager_impl.session_deinit(session_id))
    }

    /// Send UCI command for setting app config.
    pub fn session_set_app_config(
        &mut self,
        session_id: SessionId,
        config_tlvs: Vec<AppConfigTlv>,
    ) -> Result<SetAppConfigResponse> {
        self.runtime.block_on(self.uci_manager_impl.session_set_app_config(session_id, config_tlvs))
    }

    /// Send UCI command for getting app config.
    pub fn session_get_app_config(
        &mut self,
        session_id: SessionId,
        config_ids: Vec<AppConfigTlvType>,
    ) -> Result<Vec<AppConfigTlv>> {
        self.runtime.block_on(self.uci_manager_impl.session_get_app_config(session_id, config_ids))
    }

    /// Send UCI command for getting count of sessions.
    pub fn session_get_count(&mut self) -> Result<u8> {
        self.runtime.block_on(self.uci_manager_impl.session_get_count())
    }

    /// Send UCI command for getting state of session.
    pub fn session_get_state(&mut self, session_id: SessionId) -> Result<SessionState> {
        self.runtime.block_on(self.uci_manager_impl.session_get_state(session_id))
    }

    /// Send UCI command for updating multicast list for multicast session.
    pub fn session_update_controller_multicast_list(
        &mut self,
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: Vec<Controlee>,
    ) -> Result<()> {
        self.runtime.block_on(
            self.uci_manager_impl
                .session_update_controller_multicast_list(session_id, action, controlees),
        )
    }

    /// Send UCI command for starting ranging of the session.
    pub fn range_start(&mut self, session_id: SessionId) -> Result<()> {
        self.runtime.block_on(self.uci_manager_impl.range_start(session_id))
    }

    /// Send UCI command for stopping ranging of the session.
    pub fn range_stop(&mut self, session_id: SessionId) -> Result<()> {
        self.runtime.block_on(self.uci_manager_impl.range_stop(session_id))
    }

    /// Send UCI command for getting ranging count.
    pub fn range_get_ranging_count(&mut self, session_id: SessionId) -> Result<usize> {
        self.runtime.block_on(self.uci_manager_impl.range_get_ranging_count(session_id))
    }

    /// Set the country code. Android-specific method.
    pub fn android_set_country_code(&mut self, country_code: CountryCode) -> Result<()> {
        self.runtime.block_on(self.uci_manager_impl.android_set_country_code(country_code))
    }

    /// Get the power statistics. Android-specific method.
    pub fn android_get_power_stats(&mut self) -> Result<PowerStats> {
        self.runtime.block_on(self.uci_manager_impl.android_get_power_stats())
    }

    /// Send UCI command for a vendor-specific message.
    pub fn raw_vendor_cmd(
        &mut self,
        gid: u32,
        oid: u32,
        payload: Vec<u8>,
    ) -> Result<RawVendorMessage> {
        self.runtime.block_on(self.uci_manager_impl.raw_vendor_cmd(gid, oid, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::rc::Rc;

    use tokio::runtime::Builder;
    use uwb_uci_packets::DeviceState;

    use crate::error::Error;
    use crate::uci::mock_uci_hal::MockUciHal;
    use crate::uci::uci_hal::UciHalPacket;

    struct MockNotificationManager {
        device_state_sender: mpsc::UnboundedSender<DeviceState>,
        // nonsend_counter is an example of a !Send property.
        nonsend_counter: Rc<RefCell<usize>>,
    }
    impl NotificationManager for MockNotificationManager {
        fn on_core_notification(&mut self, core_notification: CoreNotification) -> Result<()> {
            match core_notification {
                CoreNotification::DeviceStatus(device_state) => {
                    self.nonsend_counter.replace_with(|&mut prev| prev + 1);
                    self.device_state_sender.send(device_state).map_err(|_| Error::Unknown)?;
                }
                CoreNotification::GenericError(_) => {}
            };
            Ok(())
        }
        fn on_session_notification(
            &mut self,
            _session_notification: SessionNotification,
        ) -> Result<()> {
            Ok(())
        }
        fn on_vendor_notification(&mut self, _vendor_notification: RawVendorMessage) -> Result<()> {
            Ok(())
        }
    }

    struct MockNotificationManagerBuilder {
        device_state_sender: mpsc::UnboundedSender<DeviceState>,
        // initial_count is an example for a parameter undetermined at compile time.
        initial_count: usize,
    }
    impl NotificationManagerBuilder<MockNotificationManager> for MockNotificationManagerBuilder {
        fn build(self) -> Option<MockNotificationManager> {
            Some(MockNotificationManager {
                device_state_sender: self.device_state_sender,
                nonsend_counter: Rc::new(RefCell::new(self.initial_count)),
            })
        }
    }

    fn into_raw_messages<T: Into<uwb_uci_packets::UciPacketPacket>>(
        builder: T,
    ) -> Vec<UciHalPacket> {
        let packets: Vec<uwb_uci_packets::UciPacketHalPacket> = builder.into().into();
        packets.into_iter().map(|packet| packet.into()).collect()
    }

    #[test]
    fn test_sync_uci_open_hal() {
        let mut hal = MockUciHal::new();
        let notf = into_raw_messages(uwb_uci_packets::DeviceStatusNtfBuilder {
            device_state: uwb_uci_packets::DeviceState::DeviceStateReady,
        });
        hal.expected_open(Some(notf), Ok(()));
        let test_rt = Builder::new_multi_thread().enable_all().build().unwrap();
        let (device_state_sender, mut device_state_receiver) =
            mpsc::unbounded_channel::<DeviceState>();
        let mut uci_manager_sync = UciManagerSync::new(
            hal,
            MockNotificationManagerBuilder { device_state_sender, initial_count: 0 },
        )
        .unwrap();
        assert!(uci_manager_sync.open_hal().is_ok());
        let device_state = test_rt.block_on(async { device_state_receiver.recv().await });
        assert_eq!(device_state, Some(DeviceState::DeviceStateReady));
    }
}
