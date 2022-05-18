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

use uwb_core::service::{UwbNotification, UwbServiceBuilder};
use uwb_core::uci::{RawUciMessage, UciHal, UciResult};

/// A placeholder implementation for UciHal.
struct UciHalImpl {}
#[async_trait]
impl UciHal for UciHalImpl {
    async fn open(&mut self, _msg_sender: mpsc::UnboundedSender<RawUciMessage>) -> UciResult<()> {
        debug!("UciHalImpl::open() is called");
        Ok(())
    }
    async fn close(&mut self) -> UciResult<()> {
        debug!("UciHalImpl::close() is called");
        Ok(())
    }
    async fn send_command(&mut self, cmd: RawUciMessage) -> UciResult<()> {
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
            match notf {
                UwbNotification::SessionDeinited { session_id } => {
                    debug!("Session {:?} is de-initialized", session_id);
                }
                UwbNotification::RangeDataReceived { session_id, range_data } => {
                    debug!("Received range data {:?} from Session {:?}", range_data, session_id);
                }
                UwbNotification::VendorNotification { gid, oid, payload } => {
                    debug!(
                        "Received vendor notification: gid={}, oid={}, payload={:?}",
                        gid, oid, payload
                    );
                }
            }
        }
    });

    // Call the public methods of UWB service under tokio runtime.
    let _ = service.enable().await;
}
