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

//! Defines error type for uci_hal_android

use android_hardware_uwb::binder::{ExceptionCode, Status as BinderStatus, StatusCode};
use uwb_core::error::Error as UwbCoreError;

/// Union of the different errors with into implementations that project the error to the nearest
/// equivalent in each error type.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// uwb_core::error::Error
    #[error("UwbCore error: {0:?}")]
    UwbCoreError(#[from] UwbCoreError),
    /// android_hardware_uwb::binder::StatusCode
    #[error("Binder StatusCode error: {0:?}")]
    StatusCode(#[from] StatusCode),
    /// android_hardware_uwb::binder::Status
    #[error("Binder Status error: {0:?}")]
    BinderStatus(#[from] BinderStatus),
}

/// The From traits allow conversion of Result types and ? macro.
impl From<Error> for BinderStatus {
    fn from(error: Error) -> BinderStatus {
        match error {
            Error::BinderStatus(a) => a,
            Error::StatusCode(StatusCode::OK) => BinderStatus::ok(),
            Error::StatusCode(e) => {
                BinderStatus::new_exception(status_code_to_exception_code(e), None)
            }
            Error::UwbCoreError(e) => {
                BinderStatus::new_exception(uwb_core_error_to_exception_code(e), None)
            }
        }
    }
}

impl From<Error> for UwbCoreError {
    fn from(error: Error) -> UwbCoreError {
        match error {
            Error::BinderStatus(e) => exception_code_to_uwb_error(e.exception_code()),
            Error::StatusCode(e) => status_code_to_uwb_core_error(e),
            Error::UwbCoreError(a) => a,
        }
    }
}

fn status_code_to_exception_code(status_code: StatusCode) -> ExceptionCode {
    match status_code {
        // StatusCode::OK should not be reached from a Result type.
        StatusCode::OK => ExceptionCode::NONE,
        StatusCode::NO_MEMORY => ExceptionCode::TRANSACTION_FAILED,
        StatusCode::INVALID_OPERATION => ExceptionCode::ILLEGAL_ARGUMENT,
        StatusCode::BAD_VALUE => ExceptionCode::ILLEGAL_ARGUMENT,
        StatusCode::BAD_TYPE => ExceptionCode::ILLEGAL_ARGUMENT,
        StatusCode::NAME_NOT_FOUND => ExceptionCode::ILLEGAL_ARGUMENT,
        StatusCode::PERMISSION_DENIED => ExceptionCode::SECURITY,
        StatusCode::NO_INIT => ExceptionCode::ILLEGAL_ARGUMENT,
        StatusCode::ALREADY_EXISTS => ExceptionCode::ILLEGAL_ARGUMENT,
        StatusCode::DEAD_OBJECT => ExceptionCode::ILLEGAL_ARGUMENT,
        StatusCode::FAILED_TRANSACTION => ExceptionCode::TRANSACTION_FAILED,
        StatusCode::BAD_INDEX => ExceptionCode::ILLEGAL_ARGUMENT,
        StatusCode::NOT_ENOUGH_DATA => ExceptionCode::ILLEGAL_ARGUMENT,
        StatusCode::WOULD_BLOCK => ExceptionCode::TRANSACTION_FAILED,
        StatusCode::TIMED_OUT => ExceptionCode::TRANSACTION_FAILED,
        StatusCode::UNKNOWN_TRANSACTION => ExceptionCode::ILLEGAL_ARGUMENT,
        StatusCode::FDS_NOT_ALLOWED => ExceptionCode::ILLEGAL_ARGUMENT,
        StatusCode::UNEXPECTED_NULL => ExceptionCode::ILLEGAL_ARGUMENT,
        _ => ExceptionCode::TRANSACTION_FAILED,
    }
}

fn status_code_to_uwb_core_error(status_code: StatusCode) -> UwbCoreError {
    match status_code {
        // StatusCode::OK should not be reached from a Result type.
        StatusCode::OK => UwbCoreError::Unknown,
        StatusCode::NO_MEMORY => UwbCoreError::Unknown,
        StatusCode::INVALID_OPERATION => UwbCoreError::BadParameters,
        StatusCode::BAD_VALUE => UwbCoreError::BadParameters,
        StatusCode::BAD_TYPE => UwbCoreError::BadParameters,
        StatusCode::NAME_NOT_FOUND => UwbCoreError::BadParameters,
        StatusCode::PERMISSION_DENIED => UwbCoreError::BadParameters,
        StatusCode::NO_INIT => UwbCoreError::BadParameters,
        StatusCode::ALREADY_EXISTS => UwbCoreError::Unknown,
        StatusCode::DEAD_OBJECT => UwbCoreError::Unknown,
        StatusCode::FAILED_TRANSACTION => UwbCoreError::Unknown,
        StatusCode::BAD_INDEX => UwbCoreError::BadParameters,
        StatusCode::NOT_ENOUGH_DATA => UwbCoreError::BadParameters,
        StatusCode::WOULD_BLOCK => UwbCoreError::Unknown,
        StatusCode::TIMED_OUT => UwbCoreError::Timeout,
        StatusCode::UNKNOWN_TRANSACTION => UwbCoreError::BadParameters,
        StatusCode::FDS_NOT_ALLOWED => UwbCoreError::Unknown,
        StatusCode::UNEXPECTED_NULL => UwbCoreError::Unknown,
        _ => UwbCoreError::Unknown,
    }
}

fn uwb_core_error_to_exception_code(uwb_core_error: UwbCoreError) -> ExceptionCode {
    match uwb_core_error {
        UwbCoreError::BadParameters => ExceptionCode::ILLEGAL_ARGUMENT,
        _ => ExceptionCode::TRANSACTION_FAILED,
    }
}

fn exception_code_to_uwb_error(exception_code: ExceptionCode) -> UwbCoreError {
    match exception_code {
        ExceptionCode::ILLEGAL_ARGUMENT
        | ExceptionCode::ILLEGAL_STATE
        | ExceptionCode::UNSUPPORTED_OPERATION
        | ExceptionCode::NULL_POINTER => UwbCoreError::BadParameters,
        _ => UwbCoreError::Unknown,
    }
}
/// Result type associated with Error:
pub type Result<T> = std::result::Result<T, Error>;
