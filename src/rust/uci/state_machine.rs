/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use log::{info, warn};

/// Enum for all states for state machine used by UWB
/// UwbStateNone -> not yet started
/// UwbStateW4HalOpen -> waiting for HalUwbOpenCpltEvt
/// UwbStateIdle -> normal operation(device is in idle state)
/// UwbStateActive -> UWB device is active
/// UwbStateW4HalClose -> waiting for HalUwbCloseCpltEvt
/// UwbStateClosing -> end
///
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UwbState {
    UwbStateNone = 0x00,
    UwbStateW4HalOpen = 0x01,
    UwbStateIdle = 0x02,
    UwbStateActive = 0x03,
    UwbStateW4HalClose = 0x04,
    UwbStateClosing = 0x05,
}

/// Enum for all Hal events for UWB
/// HalUwbOpenCpltEvt -> Hal open complete event
/// HalUwbCloseCpltEvt -> hal close complete event
/// HalUwbErrorEvt -> Hal error
///
#[derive(Debug, PartialEq)]
pub enum HalEvent {
    HalUwbOpenCpltEvt = 0x00,
    HalUwbCloseCpltEvt = 0x01,
    HalUwbErrorEvt = 0x02,
}

#[derive(Debug)]
pub struct StateMachine {
    state: UwbState,
}

impl StateMachine {
    pub fn new() -> Self {
        Self { state: UwbState::UwbStateNone }
    }

    pub fn get_state(&self) -> UwbState {
        self.state
    }

    pub fn set_state(&mut self, state: UwbState) {
        info!("UWB state change from {:?} to {:?} ", self.get_state(), state);
        self.state = state;
    }

    pub fn is_hal_initialized(&self) -> bool {
        match self.get_state() {
            UwbState::UwbStateW4HalClose | UwbState::UwbStateNone => false,
            _ => true,
        }
    }

    pub fn de_init(&mut self) {
        self.set_state(UwbState::UwbStateNone);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onHalEvent() {
        let mut sample_SM = StateMachine::new();
        assert_eq!(sample_SM.get_state(), UwbState::UwbStateNone);
        sample_SM.set_state(UwbState::UwbStateW4HalOpen);
        assert_eq!(sample_SM.get_state(), UwbState::UwbStateW4HalOpen);
        sample_SM.de_init();
        assert_eq!(sample_SM.get_state(), UwbState::UwbStateNone);
    }
}
