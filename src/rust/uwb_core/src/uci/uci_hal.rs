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

//! This module defines the UciHal trait, used for the UCI hardware abstration layer.

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::error::Result;
use crate::params::uci_packets::SessionId;

/// The type of the message that is used to communicate with the UciHal trait.
pub type RawUciMessage = Vec<u8>;

/// The trait for the UCI hardware abstration layer. The client of this library should implement
/// this trait and inject into the library.
/// Note: Each method should be completed in 1000 ms.
#[async_trait]
pub trait UciHal: 'static + Send {
    /// Open the UCI HAL and power on the UWB Subsystem.
    ///
    /// All the other API should be called after the open() completes successfully. Once the method
    /// completes successfully, the UciHal instance should store |msg_sender| and send the UCI
    /// messages (responses or notifications) back to the caller via the |msg_sender|.
    async fn open(&mut self, msg_sender: mpsc::UnboundedSender<RawUciMessage>) -> Result<()>;

    /// Close the UCI HAL.
    ///
    /// After calling this method, the instance would drop |msg_sender| received from open() method.
    async fn close(&mut self) -> Result<()>;

    /// Write the UCI command to the UWB Subsystem.
    ///
    /// The caller should call this method after the response of the previous send_command() is
    /// received.
    async fn send_command(&mut self, cmd: RawUciMessage) -> Result<()>;

    /// Notify the HAL that the UWB session is initialized successfully.
    async fn notify_session_initialized(&mut self, _session_id: SessionId) -> Result<()> {
        Ok(())
    }
}
