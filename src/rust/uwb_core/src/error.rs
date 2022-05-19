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

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Bad parameters")]
    BadParameters,
    #[error("Max session exceeded")]
    MaxSessionsExceeded,
    #[error("Max ranging round retries reached")]
    MaxRrRetryReached,
    #[error("The session fails with a protocol specific reason")]
    ProtocolSpecific,
    #[error("The remote device has requested to change the session")]
    RemoteRequest,
    #[error("The response or notification is not received in timeout")]
    Timeout,
    #[error("The command should be retried")]
    CommandRetry,
    #[error("Duplicated SessionId")]
    DuplicatedSessionId,
    #[error("The unknown error")]
    Unknown,

    #[cfg(test)]
    #[error("The result of the mock method is not assigned")]
    MockUndefined,
}
pub type Result<T> = std::result::Result<T, Error>;
