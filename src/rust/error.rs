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

use android_hardware_uwb::aidl::android::hardware::uwb::UwbStatus::UwbStatus;
use tokio::sync::mpsc;

#[derive(Debug, thiserror::Error)]
pub enum UwbErr {
    #[error("UWBStatus error: {0:?}")]
    Status(UwbStatus),
    #[error("Binder error: {0}")]
    Binder(#[from] binder::Status),
    #[error("JNI error: {0}")]
    Jni(#[from] jni::errors::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SendError for JNICommand: {0}")]
    SendJNICommand(#[from] mpsc::error::SendError<crate::uci::JNICommand>),
    #[error("SendError for HALResponse: {0}")]
    SendHALResponse(#[from] mpsc::error::SendError<crate::uci::HALResponse>),
    #[error("Could not parse: {0}")]
    Parse(#[from] uwb_uci_packets::Error),
    #[error("Could not specialize: {0:?}")]
    Specialize(Vec<u8>),
    #[error("Exit")]
    Exit,
    #[error("Unknown error")]
    Undefined,
}

impl UwbErr {
    pub fn failed() -> Self {
        UwbErr::Status(UwbStatus::FAILED)
    }

    pub fn refused() -> Self {
        UwbErr::Status(UwbStatus::REFUSED)
    }
}
