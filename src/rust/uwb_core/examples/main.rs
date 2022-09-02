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

//! A simple example for the usage of the uwb_core library.

use async_trait::async_trait;
use log::debug;
use tokio::sync::mpsc;

use uwb_core::error::{Error as UwbError, Result as UwbResult};
use uwb_core::params::uci_packets::{DeviceState, ReasonCode, SessionId, SessionState};
use uwb_core::service::{UwbServiceBuilder, UwbServiceCallback};
use uwb_core::uci::{SessionRangeData, UciHal, UciHalPacket};

/// A placeholder implementation for UciHal.
struct UciHalImpl {}
#[async_trait]
impl UciHal for UciHalImpl {
    async fn open(&mut self, _packet_sender: mpsc::UnboundedSender<UciHalPacket>) -> UwbResult<()> {
        debug!("UciHalImpl::open() is called");
        Ok(())
    }
    async fn close(&mut self) -> UwbResult<()> {
        debug!("UciHalImpl::close() is called");
        Ok(())
    }
    async fn send_packet(&mut self, packet: UciHalPacket) -> UwbResult<()> {
        debug!("UciHalImpl::send_packet({:?}) is called", packet);
        Ok(())
    }
}

/// A placeholder implementation for UwbServiceCallback.
struct UwbServiceCallbackImpl {}
impl UwbServiceCallback for UwbServiceCallbackImpl {
    fn on_service_reset(&mut self, success: bool) {
        debug!("UwbService is reset, success: {}", success);
    }

    fn on_uci_device_status_changed(&mut self, state: DeviceState) {
        debug!("UCI device status: {:?}", state);
    }

    fn on_session_state_changed(
        &mut self,
        session_id: SessionId,
        session_state: SessionState,
        reason_code: ReasonCode,
    ) {
        debug!(
            "Session {:?}'s state is changed to {:?}, reason: {:?}",
            session_id, session_state, reason_code
        );
    }

    fn on_range_data_received(&mut self, session_id: SessionId, range_data: SessionRangeData) {
        debug!("Received range data {:?} from Session {:?}", range_data, session_id);
    }

    fn on_vendor_notification_received(&mut self, gid: u32, oid: u32, payload: Vec<u8>) {
        debug!("Received vendor notification: gid={}, oid={}, payload={:?}", gid, oid, payload);
    }
}

fn main() {
    env_logger::init();

    // Initialize the UWB service.
    let mut service = UwbServiceBuilder::new()
        .callback(UwbServiceCallbackImpl {})
        .uci_hal(UciHalImpl {})
        .build()
        .unwrap();

    // Call the public methods of UWB service under tokio runtime.
    let result: UwbResult<()> = service.enable();

    // Enumerate the error code for backward-compatibility.
    // WARNING: Modifying or removing the current fields are prohibited in general,
    // unless we could confirm that there is no client using the modified field.
    if let Err(err) = result {
        match err {
            UwbError::BadParameters => {}
            UwbError::MaxSessionsExceeded => {}
            UwbError::MaxRrRetryReached => {}
            UwbError::ProtocolSpecific => {}
            UwbError::RemoteRequest => {}
            UwbError::Timeout => {}
            UwbError::CommandRetry => {}
            UwbError::DuplicatedSessionId => {}
            UwbError::Unknown => {}

            // UwbError is non_exhaustive so we need to add a wild branch here.
            // With this wild branch, adding a new enum field doesn't break the build.
            _ => debug!("Received unknown error: {:?}", err),
        }
    }
}
