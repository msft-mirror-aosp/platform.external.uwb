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

//! This module defines the UwbServiceBuilder, the builder of the UwbService.

use tokio::sync::mpsc;

use crate::service::uwb_service::{UwbNotification, UwbService};
use crate::uci::uci_hal::UciHal;
use crate::uci::uci_manager::UciManagerImpl;

/// The builder of UwbService, used to keep the backward compatibility when adding new parameters
/// of creating a UwbService instance.
pub struct UwbServiceBuilder<U: UciHal> {
    notf_sender: mpsc::UnboundedSender<UwbNotification>,
    uci_hal: Option<U>,
}

#[allow(clippy::new_without_default)]
impl<U: UciHal> UwbServiceBuilder<U> {
    /// Create a new builder.
    pub fn new() -> Self {
        Self { notf_sender: mpsc::unbounded_channel().0, uci_hal: None }
    }

    /// Set the notf_sender field.
    pub fn notf_sender(mut self, notf_sender: mpsc::UnboundedSender<UwbNotification>) -> Self {
        self.notf_sender = notf_sender;
        self
    }

    /// Set the uci_hal field.
    pub fn uci_hal(mut self, uci_hal: U) -> Self {
        self.uci_hal = Some(uci_hal);
        self
    }

    /// Build the UwbService.
    pub fn build(self) -> Option<UwbService> {
        let uci_manager = UciManagerImpl::new(self.uci_hal?);
        Some(UwbService::new(self.notf_sender, uci_manager))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uci::mock_uci_hal::MockUciHal;

    #[tokio::test]
    async fn test_uci_hal() {
        let result = UwbServiceBuilder::<MockUciHal>::new().build();
        assert!(result.is_none());

        let result = UwbServiceBuilder::new().uci_hal(MockUciHal::new()).build();
        assert!(result.is_some());
    }
}
