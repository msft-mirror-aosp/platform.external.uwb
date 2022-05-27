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
use uwb_core::service::{UwbNotification, UwbServiceBuilder};
use uwb_core::uci::{RawUciMessage, UciHal};

/// A placeholder implementation for UciHal.
struct UciHalImpl {}
#[async_trait]
impl UciHal for UciHalImpl {
    async fn open(&mut self, _msg_sender: mpsc::UnboundedSender<RawUciMessage>) -> UwbResult<()> {
        debug!("UciHalImpl::open() is called");
        Ok(())
    }
    async fn close(&mut self) -> UwbResult<()> {
        debug!("UciHalImpl::close() is called");
        Ok(())
    }
    async fn send_command(&mut self, cmd: RawUciMessage) -> UwbResult<()> {
        debug!("UciHalImpl::send_command({:?}) is called", cmd);
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let _ = env_logger::init();

    // Initialize the UWB service.
    let (notf_sender, mut notf_receiver) = mpsc::unbounded_channel();
    let mut service =
        UwbServiceBuilder::new().uci_hal(UciHalImpl {}).notf_sender(notf_sender).build().unwrap();

    // Handle the notifications from UWB service at another tokio task.
    tokio::spawn(async move {
        while let Some(notf) = notf_receiver.recv().await {
            // Enumerate the notification for backward-compatibility.
            // WARNING: Modifying or removing the current fields are prohibited in general,
            // unless we could confirm that there is no client using the modified field.
            match notf {
                UwbNotification::ServiceReset { success } => {
                    debug!("UwbService is reset, success: {}", success);
                }
                UwbNotification::UciDeviceStatus(state) => {
                    debug!("UCI device status: {:?}", state);
                }
                UwbNotification::SessionState { session_id, session_state, reason_code } => {
                    debug!(
                        "Session {:?}'s state is changed to {:?}, reason: {:?}",
                        session_id, session_state, reason_code
                    );
                }
                UwbNotification::RangeData { session_id, range_data } => {
                    debug!("Received range data {:?} from Session {:?}", range_data, session_id);
                }
                UwbNotification::VendorNotification { gid, oid, payload } => {
                    debug!(
                        "Received vendor notification: gid={}, oid={}, payload={:?}",
                        gid, oid, payload
                    );
                }

                // UwbNotification is non_exhaustive so we need to add a wild branch here.
                // With this wild branch, adding a new enum field doesn't break the build.
                _ => {
                    debug!("Received unknown notifitication: {:?}", notf);
                }
            }
        }
    });

    // Call the public methods of UWB service under tokio runtime.
    let result: UwbResult<()> = service.enable().await;

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
