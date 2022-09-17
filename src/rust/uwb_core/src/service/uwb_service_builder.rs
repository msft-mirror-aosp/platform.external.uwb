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

use tokio::runtime::Runtime;

use crate::service::uwb_service::{UwbService, UwbServiceCallback};
use crate::uci::uci_hal::UciHal;
use crate::uci::uci_logger::{UciLogger, UciLoggerMode};
use crate::uci::uci_manager::UciManagerImpl;

/// Create the default runtime for UwbService.
pub fn default_runtime() -> Option<Runtime> {
    tokio::runtime::Builder::new_multi_thread().thread_name("UwbService").enable_all().build().ok()
}

/// The builder of UwbService, used to keep the backward compatibility when adding new parameters
/// of creating a UwbService instance.
pub struct UwbServiceBuilder<C, U, L>
where
    C: UwbServiceCallback,
    U: UciHal,
    L: UciLogger,
{
    runtime: Option<Runtime>,
    callback: Option<C>,
    uci_hal: Option<U>,
    uci_logger: Option<L>,
    uci_logger_mode: UciLoggerMode,
}

impl<C, U, L> Default for UwbServiceBuilder<C, U, L>
where
    C: UwbServiceCallback,
    U: UciHal,
    L: UciLogger,
{
    fn default() -> Self {
        Self {
            runtime: None,
            callback: None,
            uci_hal: None,
            uci_logger: None,
            uci_logger_mode: UciLoggerMode::Disabled,
        }
    }
}

impl<C, U, L> UwbServiceBuilder<C, U, L>
where
    C: UwbServiceCallback,
    U: UciHal,
    L: UciLogger,
{
    /// Create a new builder.
    pub fn new() -> Self {
        Default::default()
    }

    /// Set the runtime field.
    pub fn runtime(mut self, runtime: Runtime) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Set the callback field.
    pub fn callback(mut self, callback: C) -> Self {
        self.callback = Some(callback);
        self
    }

    /// Set the uci_hal field.
    pub fn uci_hal(mut self, uci_hal: U) -> Self {
        self.uci_hal = Some(uci_hal);
        self
    }

    /// Set the uci_logger field.
    pub fn uci_logger(mut self, uci_logger: L) -> Self {
        self.uci_logger = Some(uci_logger);
        self
    }

    /// Set the uci_logger_mode field.
    pub fn uci_logger_mode(mut self, uci_logger_mode: UciLoggerMode) -> Self {
        self.uci_logger_mode = uci_logger_mode;
        self
    }

    /// Build the UwbService.
    pub fn build(mut self) -> Option<UwbService> {
        let runtime = self.runtime.take().or_else(default_runtime)?;
        let uci_hal = self.uci_hal.take()?;
        let uci_logger = self.uci_logger.take()?;
        let uci_logger_mode = self.uci_logger_mode;
        let uci_manager = runtime
            .block_on(async move { UciManagerImpl::new(uci_hal, uci_logger, uci_logger_mode) });
        Some(UwbService::new(runtime, self.callback.take()?, uci_manager))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::mock_uwb_service_callback::MockUwbServiceCallback;
    use crate::uci::mock_uci_hal::MockUciHal;
    use crate::uci::uci_logger::UciLoggerNull;

    #[test]
    fn test_build_fail() {
        let result =
            UwbServiceBuilder::<MockUwbServiceCallback, MockUciHal, UciLoggerNull>::new().build();
        assert!(result.is_none());
    }

    #[test]
    fn test_build_ok() {
        let result = UwbServiceBuilder::new()
            .callback(MockUwbServiceCallback::new())
            .uci_hal(MockUciHal::new())
            .uci_logger(UciLoggerNull::default())
            .build();
        assert!(result.is_some());
    }
}
