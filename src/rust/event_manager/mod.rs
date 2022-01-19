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

use crate::uci::uci_hrcv::UciNotification;
use jni::errors::Result;
use jni::objects::{GlobalRef, JObject, JValue};
use jni::{AttachGuard, JNIEnv, JavaVM};
use log::error;
use num_traits::ToPrimitive;
use std::convert::TryInto;
use uwb_uci_packets::{
    DeviceStatusNtfPacket, GenericErrorPacket, SessionStatusNtfPacket,
    ShortMacTwoWayRangeDataNtfPacket,
};

// TODO: Reconsider the best way to cache the JNIEnv.  We currently attach and detach for every
// call, which the documentation warns could be expensive.  We could attach the thread permanently,
// but that would not allow us to detach when we drop this structure.  We could cache the
// AttachGuard in the EventManager, but it is not Send, so we should wait to see how this is used
// and how expensive the current approach is.  We can call JavaVM's get_env method if we're already
// attached.

// TODO: We could consider caching the method ids rather than recomputing them each time at the cost
// of less safety.

// Manages calling Java callbacks through the JNI.
pub struct EventManager {
    jvm: JavaVM,
    obj: GlobalRef,
}

impl EventManager {
    /// Creates a new EventManager.
    pub fn new(env: JNIEnv, obj: JObject) -> Result<Self> {
        let jvm = env.get_java_vm()?;
        let obj = env.new_global_ref(obj)?;
        Ok(EventManager { jvm, obj })
    }

    pub fn device_status_notification_received(&self, data: DeviceStatusNtfPacket) -> Result<()> {
        let state = data.get_device_state().to_u8().expect("Failed converting device_state to u8");
        let env = self.jvm.attach_current_thread()?;
        let result = env.call_method(
            self.obj.as_obj(),
            "onDeviceStatusNotificationReceived",
            "(I)V",
            &[JValue::Int(state.try_into().expect("Could not convert device_state"))],
        );
        self.cleanup_and_return(env, result)
    }

    pub fn session_status_notification_received(&self, data: SessionStatusNtfPacket) -> Result<()> {
        let session_id =
            data.get_session_id().to_u32().expect("Failed converting session_id to u32");
        let state =
            data.get_session_state().to_u8().expect("Failed converting session_state to u8");
        let reason_code =
            data.get_reason_code().to_u8().expect("Failed coverting reason_code to u32");
        let env = self.jvm.attach_current_thread()?;
        let result = env.call_method(
            self.obj.as_obj(),
            "onSessionStatusNotificationReceived",
            "(JII)V",
            &[
                JValue::Long(session_id.try_into().expect("Could not convert session_id")),
                JValue::Int(state.try_into().expect("Could not convert session_state")),
                JValue::Int(reason_code.try_into().expect("Could not convert reason_code")),
            ],
        );
        self.cleanup_and_return(env, result)
    }

    pub fn core_generic_error_notification_received(&self, data: GenericErrorPacket) -> Result<()> {
        let status = data.get_status().to_u8().expect("Failed converting status to u8");
        let env = self.jvm.attach_current_thread()?;
        let result = env.call_method(
            self.obj.as_obj(),
            "onCoreGenericErrorNotificationReceived",
            "(I)V",
            &[JValue::Int(status.try_into().expect("Could not convert status"))],
        );
        self.cleanup_and_return(env, result)
    }

    fn cleanup_and_return<T>(&self, env: AttachGuard, result: Result<T>) -> Result<()> {
        self.clear_exception(env);
        // Discard the value returned by the call.
        result.map(|_| ())
    }

    // Attempts to clear an exception.  If we do not do this, the exception continues being thrown
    // when the control flow returns to Java.  We discard errors here (after logging them) rather
    // than propagating them to the caller since there's nothing they can do with that information.
    fn clear_exception(&self, env: AttachGuard) {
        match env.exception_check() {
            Ok(true) => match env.exception_clear() {
                Ok(()) => {} // We successfully cleared the exception.
                Err(e) => error!("Error clearing JNI exception: {:?}", e),
            },
            Ok(false) => {} // No exception found.
            Err(e) => error!("Error checking JNI exception: {:?}", e),
        }
    }
}
