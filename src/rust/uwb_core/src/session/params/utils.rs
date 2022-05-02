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

use log::error;

pub(super) fn u8_to_bytes(value: u8) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

pub(super) fn u16_to_bytes(value: u16) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

pub(super) fn u32_to_bytes(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

pub(super) fn validate(value: bool, err_msg: &str) -> Option<()> {
    match value {
        true => Some(()),
        false => {
            error!("{}", err_msg);
            None
        }
    }
}
