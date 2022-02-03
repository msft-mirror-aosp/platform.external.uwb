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

use jni::errors::Result;
use jni::objects::{GlobalRef, JClass, JObject, JValue, JValue::Void};
use jni::signature::JavaType;
use jni::sys::jobjectArray;
use jni::{AttachGuard, JNIEnv, JavaVM};
use log::error;
use num_traits::ToPrimitive;
use std::convert::TryInto;
use std::vec::Vec;
use uwb_uci_packets::{
    DeviceStatusNtfPacket, ExtendedAddressTwoWayRangingMeasurement,
    ExtendedMacTwoWayRangeDataNtfPacket, GenericErrorPacket, RangeDataNtfPacket,
    SessionStatusNtfPacket, SessionUpdateControllerMulticastListNtfPacket,
    ShortAddressTwoWayRangingMeasurement, ShortMacTwoWayRangeDataNtfPacket,
};

const UWB_RANGING_DATA_CLASS: &str = "com/android/server/uwb/data/UwbRangingData";
const UWB_TWO_WAY_MEASUREMENT_CLASS: &str = "com/android/server/uwb/data/UwbTwoWayMeasurement";
const MULTICAST_LIST_UPDATE_STATUS_CLASS: &str =
    "com/android/server/uwb/data/UwbMulticastListUpdateStatus";
const SHORT_MAC_ADDRESS_LEN: usize = 2;
const EXTENDED_MAC_ADDRESS_LEN: usize = 8;

// TODO: Reconsider the best way to cache the JNIEnv.  We currently attach and detach for every
// call, which the documentation warns could be expensive.  We could attach the thread permanently,
// but that would not allow us to detach when we drop this structure.  We could cache the
// AttachGuard in the EventManager, but it is not Send, so we should wait to see how this is used
// and how expensive the current approach is.  We can call JavaVM's get_env method if we're already
// attached.

// TODO: We could consider caching the method ids rather than recomputing them each time at the cost
// of less safety.

pub trait EventManager {
    fn device_status_notification_received(&self, data: DeviceStatusNtfPacket) -> Result<()>;
    fn core_generic_error_notification_received(&self, data: GenericErrorPacket) -> Result<()>;
    fn session_status_notification_received(&self, data: SessionStatusNtfPacket) -> Result<()>;
    fn short_range_data_notification_received(
        &self,
        data: ShortMacTwoWayRangeDataNtfPacket,
    ) -> Result<()>;
    fn extended_range_data_notification_received(
        &self,
        data: ExtendedMacTwoWayRangeDataNtfPacket,
    ) -> Result<()>;
    fn session_update_controller_multicast_list_notification_received(
        &self,
        data: SessionUpdateControllerMulticastListNtfPacket,
    ) -> Result<()>;
    fn vendor_uci_notification_received(&self, gid: u32, oid: u32, payload: Vec<u8>) -> Result<()>;
}

// Manages calling Java callbacks through the JNI.
pub struct EventManagerImpl {
    jvm: JavaVM,
    obj: GlobalRef,
    // cache used to lookup uwb classes in callback.
    class_loader_obj: GlobalRef,
}

impl EventManager for EventManagerImpl {
    fn device_status_notification_received(&self, data: DeviceStatusNtfPacket) -> Result<()> {
        let env = self.jvm.attach_current_thread()?;
        let result = self.handle_device_status_notification_received(&env, data);
        self.clear_exception(env);
        result
    }

    fn core_generic_error_notification_received(&self, data: GenericErrorPacket) -> Result<()> {
        let env = self.jvm.attach_current_thread()?;
        let result = self.handle_core_generic_error_notification_received(&env, data);
        self.clear_exception(env);
        result
    }

    fn session_status_notification_received(&self, data: SessionStatusNtfPacket) -> Result<()> {
        let env = self.jvm.attach_current_thread()?;
        let result = self.handle_session_status_notification_received(&env, data);
        self.clear_exception(env);
        result
    }

    fn short_range_data_notification_received(
        &self,
        data: ShortMacTwoWayRangeDataNtfPacket,
    ) -> Result<()> {
        let env = self.jvm.attach_current_thread()?;
        let result = self.handle_short_range_data_notification_received(&env, data);
        self.clear_exception(env);
        result
    }

    fn extended_range_data_notification_received(
        &self,
        data: ExtendedMacTwoWayRangeDataNtfPacket,
    ) -> Result<()> {
        let env = self.jvm.attach_current_thread()?;
        let result = self.handle_extended_range_data_notification_received(&env, data);
        self.clear_exception(env);
        result
    }

    fn session_update_controller_multicast_list_notification_received(
        &self,
        data: SessionUpdateControllerMulticastListNtfPacket,
    ) -> Result<()> {
        let env = self.jvm.attach_current_thread()?;
        let result =
            self.handle_session_update_controller_multicast_list_notification_received(&env, data);
        self.clear_exception(env);
        result
    }
    fn vendor_uci_notification_received(&self, gid: u32, oid: u32, payload: Vec<u8>) -> Result<()> {
        let env = self.jvm.attach_current_thread()?;
        let result = self.handle_vendor_uci_notification_received(&env, gid, oid, payload);
        self.clear_exception(env);
        result
    }
}

impl EventManagerImpl {
    /// Creates a new EventManagerImpl.
    pub fn new(env: JNIEnv, obj: JObject) -> Result<Self> {
        let jvm = env.get_java_vm()?;
        let obj = env.new_global_ref(obj)?;
        let class_loader_obj = EventManagerImpl::get_classloader_obj(&env)?;
        let class_loader_obj = env.new_global_ref(class_loader_obj)?;
        Ok(EventManagerImpl { jvm, obj, class_loader_obj })
    }

    fn get_classloader_obj<'a>(env: &'a JNIEnv) -> Result<JObject<'a>> {
        // Use UwbRangingData class to find the classloader used by the java service.
        let ranging_data_class = env.find_class(&UWB_RANGING_DATA_CLASS)?;
        let ranging_data_class_class = env.get_object_class(ranging_data_class)?;
        let get_class_loader_method = env.get_method_id(
            ranging_data_class_class,
            "getClassLoader",
            "()Ljava/lang/ClassLoader;",
        )?;
        let class_loader = env.call_method_unchecked(
            ranging_data_class,
            get_class_loader_method,
            JavaType::Object("java/lang/ClassLoader".into()),
            &[Void],
        )?;
        class_loader.l()
    }

    fn find_class<'a>(&'a self, env: &'a JNIEnv, class_name: &'a str) -> Result<JClass<'a>> {
        let class_value = env.call_method(
            self.class_loader_obj.as_obj(),
            "findClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(JObject::from(env.new_string(class_name)?))],
        )?;
        class_value.l().map(|value| JClass::from(value))
    }

    fn handle_device_status_notification_received(
        &self,
        env: &JNIEnv,
        data: DeviceStatusNtfPacket,
    ) -> Result<()> {
        let state =
            data.get_device_state().to_i32().expect("Failed converting device_state to i32");
        env.call_method(
            self.obj.as_obj(),
            "onDeviceStatusNotificationReceived",
            "(I)V",
            &[JValue::Int(state)],
        )
        .map(|_| ()) // drop void method return
    }

    fn handle_session_status_notification_received(
        &self,
        env: &JNIEnv,
        data: SessionStatusNtfPacket,
    ) -> Result<()> {
        let session_id =
            data.get_session_id().to_i64().expect("Failed converting session_id to i64");
        let state =
            data.get_session_state().to_i32().expect("Failed converting session_state to i32");
        let reason_code =
            data.get_reason_code().to_i32().expect("Failed converting reason_code to i32");
        env.call_method(
            self.obj.as_obj(),
            "onSessionStatusNotificationReceived",
            "(JII)V",
            &[JValue::Long(session_id), JValue::Int(state), JValue::Int(reason_code)],
        )
        .map(|_| ()) // drop void method return
    }

    fn handle_core_generic_error_notification_received(
        &self,
        env: &JNIEnv,
        data: GenericErrorPacket,
    ) -> Result<()> {
        let status = data.get_status().to_i32().expect("Failed converting status to i32");
        env.call_method(
            self.obj.as_obj(),
            "onCoreGenericErrorNotificationReceived",
            "(I)V",
            &[JValue::Int(status)],
        )
        .map(|_| ()) // drop void method return
    }

    fn create_zeroed_two_way_measurement_java<'a>(
        env: &'a JNIEnv,
        two_way_measurement_class: JClass,
        mac_address_java: jobjectArray,
    ) -> Result<JObject<'a>> {
        env.new_object(
            two_way_measurement_class,
            "([BIIIIIIIIIIII)V",
            &[
                JValue::Object(JObject::from(mac_address_java)),
                JValue::Int(0),
                JValue::Int(0),
                JValue::Int(0),
                JValue::Int(0),
                JValue::Int(0),
                JValue::Int(0),
                JValue::Int(0),
                JValue::Int(0),
                JValue::Int(0),
                JValue::Int(0),
                JValue::Int(0),
                JValue::Int(0),
            ],
        )
    }

    fn create_short_mac_two_way_measurement_java<'a>(
        env: &'a JNIEnv,
        two_way_measurement_class: JClass,
        two_way_measurement: &'a ShortAddressTwoWayRangingMeasurement,
    ) -> Result<JObject<'a>> {
        let mac_address_arr = two_way_measurement.mac_address.to_ne_bytes();
        let mac_address_java = env.new_byte_array(
            SHORT_MAC_ADDRESS_LEN.to_i32().expect("Failed converting mac address len to i32"),
        )?;
        // Convert from [u8] to [i8] since java does not support unsigned byte.
        let mac_address_arr_i8 = mac_address_arr.map(|x| x as i8);
        env.set_byte_array_region(mac_address_java, 0, &mac_address_arr_i8)?;
        env.new_object(
            two_way_measurement_class,
            "([BIIIIIIIIIIII)V",
            &[
                JValue::Object(JObject::from(mac_address_java)),
                JValue::Int(
                    two_way_measurement.status.to_i32().expect("Failed converting status to i32"),
                ),
                JValue::Int(
                    two_way_measurement.nlos.to_i32().expect("Failed converting nlos to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .distance
                        .to_i32()
                        .expect("Failed converting distance to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_azimuth
                        .to_i32()
                        .expect("Failed converting aoa azimuth to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_azimuth_fom
                        .to_i32()
                        .expect("Failed converting aoa azimuth fom to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_elevation
                        .to_i32()
                        .expect("Failed converting aoa elevation to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_elevation_fom
                        .to_i32()
                        .expect("Failed converting aoa elevation fom to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_destination_azimuth
                        .to_i32()
                        .expect("Failed converting dest aoa azimuth to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_destination_azimuth_fom
                        .to_i32()
                        .expect("Failed converting dest aoa azimuth fom to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_destination_elevation
                        .to_i32()
                        .expect("Failed converting dest aoa elevation to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_destination_elevation_fom
                        .to_i32()
                        .expect("Failed converting dest aoa elevation azimuth to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .slot_index
                        .to_i32()
                        .expect("Failed converting slot index to i32"),
                ),
            ],
        )
    }

    fn create_extended_mac_two_way_measurement_java<'a>(
        env: &'a JNIEnv,
        two_way_measurement_class: JClass,
        two_way_measurement: &'a ExtendedAddressTwoWayRangingMeasurement,
    ) -> Result<JObject<'a>> {
        let mac_address_arr = two_way_measurement.mac_address.to_ne_bytes();
        let mac_address_java = env.new_byte_array(
            EXTENDED_MAC_ADDRESS_LEN.to_i32().expect("Failed converting mac address len to i32"),
        )?;
        // Convert from [u8] to [i8] since java does not support unsigned byte.
        let mac_address_arr_i8 = mac_address_arr.map(|x| x as i8);
        env.set_byte_array_region(mac_address_java, 0, &mac_address_arr_i8)?;
        env.new_object(
            two_way_measurement_class,
            "([BIIIIIIIIIIII)V",
            &[
                JValue::Object(JObject::from(mac_address_java)),
                JValue::Int(
                    two_way_measurement.status.to_i32().expect("Failed converting status to i32"),
                ),
                JValue::Int(
                    two_way_measurement.nlos.to_i32().expect("Failed converting nlos to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .distance
                        .to_i32()
                        .expect("Failed converting distance to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_azimuth
                        .to_i32()
                        .expect("Failed converting aoa azimuth to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_azimuth_fom
                        .to_i32()
                        .expect("Failed converting aoa azimuth fom to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_elevation
                        .to_i32()
                        .expect("Failed converting aoa elevation to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_elevation_fom
                        .to_i32()
                        .expect("Failed converting aoa elevation fom to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_destination_azimuth
                        .to_i32()
                        .expect("Failed converting dest aoa azimuth to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_destination_azimuth_fom
                        .to_i32()
                        .expect("Failed converting dest aoa azimuth fom to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_destination_elevation
                        .to_i32()
                        .expect("Failed converting dest aoa elevation to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .aoa_destination_elevation_fom
                        .to_i32()
                        .expect("Failed converting dest aoa elevation azimuth to i32"),
                ),
                JValue::Int(
                    two_way_measurement
                        .slot_index
                        .to_i32()
                        .expect("Failed converting slot index to i32"),
                ),
            ],
        )
    }

    fn create_range_data_java<'a>(
        &'a self,
        env: &'a JNIEnv,
        data: RangeDataNtfPacket,
        two_way_measurements_java: jobjectArray,
        num_two_way_measurements: i32,
    ) -> Result<JObject<'a>> {
        let ranging_data_class = self.find_class(env, &UWB_RANGING_DATA_CLASS)?;
        env.new_object(
            ranging_data_class,
            "(JJIJIII[Lcom/android/server/uwb/data/UwbTwoWayMeasurement;)V",
            &[
                JValue::Long(
                    data.get_sequence_number().to_i64().expect("Failed converting seq num to i64"),
                ),
                JValue::Long(
                    data.get_session_id().to_i64().expect("Failed converting session id to i64"),
                ),
                JValue::Int(
                    data.get_rcr_indicator()
                        .to_i32()
                        .expect("Failed converting rcr indicator to i32"),
                ),
                JValue::Long(
                    data.get_current_ranging_interval()
                        .to_i64()
                        .expect("Failed converting current ranging interval to i32"),
                ),
                JValue::Int(
                    data.get_ranging_measurement_type()
                        .to_i32()
                        .expect("Failed converting ranging measurement type to i32"),
                ),
                JValue::Int(
                    data.get_mac_address_indicator()
                        .to_i32()
                        .expect("Failed converting mac address indicator to i32"),
                ),
                JValue::Int(num_two_way_measurements),
                JValue::Object(JObject::from(two_way_measurements_java)),
            ],
        )
    }

    fn handle_short_range_data_notification_received(
        &self,
        env: &JNIEnv,
        data: ShortMacTwoWayRangeDataNtfPacket,
    ) -> Result<()> {
        let two_way_measurement_class = self.find_class(&env, &UWB_TWO_WAY_MEASUREMENT_CLASS)?;
        let two_way_measurement_initial_java =
            EventManagerImpl::create_zeroed_two_way_measurement_java(
                &env,
                two_way_measurement_class,
                env.new_byte_array(
                    EXTENDED_MAC_ADDRESS_LEN
                        .to_i32()
                        .expect("Failed converting mac address len to i32"),
                )?,
            )?;
        let num_two_way_measurements: i32 = data
            .get_two_way_ranging_measurements()
            .len()
            .to_i32()
            .expect("Failed converting len to i32");
        let two_way_measurements_java = env.new_object_array(
            num_two_way_measurements,
            two_way_measurement_class,
            two_way_measurement_initial_java,
        )?;
        for (i, two_way_measurement) in data.get_two_way_ranging_measurements().iter().enumerate() {
            let two_way_measurement_java =
                EventManagerImpl::create_short_mac_two_way_measurement_java(
                    &env,
                    two_way_measurement_class,
                    two_way_measurement,
                )?;
            env.set_object_array_element(
                two_way_measurements_java,
                i.to_i32().expect("Failed converting idx to i32"),
                two_way_measurement_java,
            )?
        }
        let ranging_data_java = self.create_range_data_java(
            &env,
            data.into(),
            two_way_measurements_java,
            num_two_way_measurements,
        )?;
        env.call_method(
            self.obj.as_obj(),
            "onRangeDataNotificationReceived",
            "(Lcom/android/server/uwb/data/UwbRangingData;)V",
            &[JValue::Object(JObject::from(ranging_data_java))],
        )
        .map(|_| ()) // drop void method return
    }

    fn handle_extended_range_data_notification_received(
        &self,
        env: &JNIEnv,
        data: ExtendedMacTwoWayRangeDataNtfPacket,
    ) -> Result<()> {
        let two_way_measurement_class = self.find_class(&env, &UWB_TWO_WAY_MEASUREMENT_CLASS)?;
        let two_way_measurement_initial_java =
            EventManagerImpl::create_zeroed_two_way_measurement_java(
                &env,
                two_way_measurement_class,
                env.new_byte_array(
                    EXTENDED_MAC_ADDRESS_LEN
                        .to_i32()
                        .expect("Failed converting mac address len to i32"),
                )?,
            )?;
        let num_two_way_measurements: i32 = data
            .get_two_way_ranging_measurements()
            .len()
            .to_i32()
            .expect("Failed converting len to i32");
        let two_way_measurements_java = env.new_object_array(
            num_two_way_measurements,
            two_way_measurement_class,
            two_way_measurement_initial_java,
        )?;
        for (i, two_way_measurement) in data.get_two_way_ranging_measurements().iter().enumerate() {
            let two_way_measurement_java =
                EventManagerImpl::create_extended_mac_two_way_measurement_java(
                    &env,
                    two_way_measurement_class,
                    two_way_measurement,
                )?;
            env.set_object_array_element(
                two_way_measurements_java,
                i.to_i32().expect("Failed converting idx to i32"),
                two_way_measurement_java,
            )?;
        }
        let ranging_data_java = self.create_range_data_java(
            &env,
            data.into(),
            two_way_measurements_java,
            num_two_way_measurements,
        )?;
        env.call_method(
            self.obj.as_obj(),
            "onRangeDataNotificationReceived",
            "(Lcom/android/server/uwb/data/UwbRangingData;)V",
            &[JValue::Object(JObject::from(ranging_data_java))],
        )
        .map(|_| ()) // drop void method return
    }

    pub fn handle_session_update_controller_multicast_list_notification_received(
        &self,
        env: &JNIEnv,
        data: SessionUpdateControllerMulticastListNtfPacket,
    ) -> Result<()> {
        let uwb_multicast_update_class =
            self.find_class(&env, &MULTICAST_LIST_UPDATE_STATUS_CLASS)?;

        let controlee_status = data.get_controlee_status();
        let count: i32 =
            controlee_status.len().try_into().expect("Failed to convert controlee status length");
        let mut mac_address_list: Vec<i32> = Vec::new();
        let mut subsession_id_list: Vec<i64> = Vec::new();
        let mut status_list: Vec<i32> = Vec::new();

        for iter in controlee_status {
            mac_address_list.push(iter.mac_address.into());
            subsession_id_list.push(iter.subsession_id.into());
            status_list.push(iter.status.into());
        }

        let mac_address_jintarray = env.new_int_array(count)?;
        env.set_int_array_region(mac_address_jintarray, 0, mac_address_list.as_ref())?;
        let subsession_id_jlongarray = env.new_long_array(count)?;
        env.set_long_array_region(subsession_id_jlongarray, 0, subsession_id_list.as_ref())?;
        let status_jintarray = env.new_int_array(count)?;
        env.set_int_array_region(status_jintarray, 0, status_list.as_ref())?;

        let uwb_multicast_update_object = env.new_object(
            uwb_multicast_update_class,
            "(JII[I[J[I)V",
            &[
                JValue::Long(
                    data.get_session_id().try_into().expect("Could not convert session_id"),
                ),
                JValue::Int(
                    data.get_remaining_multicast_list_size()
                        .try_into()
                        .expect("Could not convert remaining multicast list size"),
                ),
                JValue::Int(count.try_into().expect("Could not convert count")),
                JValue::Object(JObject::from(mac_address_jintarray)),
                JValue::Object(JObject::from(subsession_id_jlongarray)),
                JValue::Object(JObject::from(status_jintarray)),
            ],
        )?;

        env.call_method(
            self.obj.as_obj(),
            "onMulticastListUpdateNotificationReceived",
            "(Lcom/android/server/uwb/data/UwbMulticastListUpdateStatus;)V",
            &[JValue::Object(JObject::from(uwb_multicast_update_object))],
        )
        .map(|_| ()) // drop void method return
    }

    pub fn handle_vendor_uci_notification_received(
        &self,
        env: &JNIEnv,
        gid: u32,
        oid: u32,
        payload: Vec<u8>,
    ) -> Result<()> {
        let gid: i32 = gid.try_into().expect("Failed to convert gid");
        let oid: i32 = oid.try_into().expect("Failed to convert gid");
        let payload_jbytearray = env.byte_array_from_slice(payload.as_ref())?;

        env.call_method(
            self.obj.as_obj(),
            "onVendorUciNotificationReceived",
            "(IIB])V",
            &[
                JValue::Int(gid),
                JValue::Int(oid),
                JValue::Object(JObject::from(payload_jbytearray)),
            ],
        )
        .map(|_| ()) // drop void method return
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

#[cfg(test)]
pub struct MockEventManager {}

#[cfg(test)]
impl MockEventManager {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
impl EventManager for MockEventManager {
    fn device_status_notification_received(&self, _data: DeviceStatusNtfPacket) -> Result<()> {
        Ok(())
    }
    fn core_generic_error_notification_received(&self, _data: GenericErrorPacket) -> Result<()> {
        Ok(())
    }
    fn session_status_notification_received(&self, _data: SessionStatusNtfPacket) -> Result<()> {
        Ok(())
    }
    fn short_range_data_notification_received(
        &self,
        _data: ShortMacTwoWayRangeDataNtfPacket,
    ) -> Result<()> {
        Ok(())
    }
    fn extended_range_data_notification_received(
        &self,
        _data: ExtendedMacTwoWayRangeDataNtfPacket,
    ) -> Result<()> {
        Ok(())
    }
    fn session_update_controller_multicast_list_notification_received(
        &self,
        _data: SessionUpdateControllerMulticastListNtfPacket,
    ) -> Result<()> {
        Ok(())
    }
    fn vendor_uci_notification_received(
        &self,
        _gid: u32,
        _oid: u32,
        _payload: Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }
}
