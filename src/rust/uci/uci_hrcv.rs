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

use crate::uci::uci_packets::{
    CoreOpCode, CoreResponseChild, CoreResponsePacket, GetCapsInfoRspBuilder, GetCapsInfoRspPacket,
    GetDeviceInfoRspBuilder, GetDeviceInfoRspPacket, StatusCode, UciCommandPacket, TLV,
};

fn uwb_ucif_process_event(evt: CoreResponsePacket) {
    match evt.specialize() {
        CoreResponseChild::GetDeviceInfoRsp(evt) => {
            get_device_info_rsp(evt);
        }
        CoreResponseChild::GetCapsInfoRsp(evt) => {
            get_caps_info_rsp(evt);
        }
        _ => {}
    }
}

fn get_device_info_rsp(evt: GetDeviceInfoRspPacket) {
    let evt_data = GetDeviceInfoRspBuilder {
        status: evt.get_status(),
        uci_version: evt.get_uci_version(),
        mac_version: evt.get_mac_version(),
        phy_version: evt.get_phy_version(),
        uci_test_version: evt.get_uci_test_version(),
        vendor_spec_info: evt.get_vendor_spec_info().to_vec(),
    };
    //callback(UWB_GET_DEVICE_INFO_REVT, evt_data)
    //TODO : callback through JNI.
}

fn get_caps_info_rsp(evt: GetCapsInfoRspPacket) {
    let evt_data =
        GetCapsInfoRspBuilder { status: evt.get_status(), tlvs: evt.get_tlvs().to_vec() };
    //callback(UWB_CORE_GET_DEVICE_CAPABILITY_REVT, evt_data)
    //TODO : callback through JNI.
}
