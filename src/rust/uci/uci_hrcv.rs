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

use crate::error::UwbErr;
use log::{info, warn};
use uwb_uci_packets::{
    AndroidNotificationBuilder, CoreNotificationBuilder, CoreNotificationChild,
    CoreNotificationPacket, CoreOpCode, CoreResponseChild, CoreResponsePacket,
    DeviceResetRspBuilder, DeviceStatusNtfBuilder, GenericErrorBuilder, GenericErrorPacket,
    GetCapsInfoRspBuilder, GetCapsInfoRspPacket, GetConfigRspBuilder, GetDeviceInfoRspBuilder,
    GetDeviceInfoRspPacket, Packet, RangeDataNtfBuilder, RangeStartRspBuilder, RangeStartRspPacket,
    RangingNotificationBuilder, RangingResponseChild, RangingResponsePacket, SessionInitRspBuilder,
    SessionInitRspPacket, SessionNotificationBuilder, SessionResponseChild, SessionResponsePacket,
    SessionStatusNtfBuilder, SessionUpdateControllerMulticastListNtfBuilder, SetConfigRspBuilder,
    StatusCode, UciCommandPacket, UciNotificationChild, UciNotificationPacket, UciResponseChild,
    UciResponsePacket, TLV,
};

#[derive(Debug)]
pub enum UciResponse {
    // TODO: Remove this once we have real data we can use.
    Fake,
    GetDeviceInfoRsp(GetDeviceInfoRspBuilder),
    GetCapsInfoRsp(GetCapsInfoRspBuilder),
    SetConfigRsp(SetConfigRspBuilder),
    GetConfigRsp(GetConfigRspBuilder),
    DeviceResetRsp(DeviceResetRspBuilder),
    SessionInitRsp(SessionInitRspBuilder),
    RangeStartRsp(RangeStartRspBuilder),
    //TODO add all after deciding whether we can use same enum for session cmd respones
}

pub enum UciNotification {
    GenericError(GenericErrorBuilder),
    DeviceStatusNtf(DeviceStatusNtfBuilder),
    SessionStatusNtf(SessionStatusNtfBuilder),
    SessionUpdateControllerMulticastListNtf(SessionUpdateControllerMulticastListNtfBuilder),
    RangeDataNtf(RangeDataNtfBuilder),
    AndroidNotification(AndroidNotificationBuilder),
}

pub fn uci_response(bytes: &[u8]) -> Result<UciResponse, UwbErr> {
    let evt = UciResponsePacket::parse(bytes)?;
    match evt.specialize() {
        UciResponseChild::CoreResponse(evt) => core_response(evt),
        UciResponseChild::SessionResponse(evt) => session_response(evt),
        UciResponseChild::RangingResponse(evt) => ranging_response(evt),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

pub fn uci_notification(evt: UciNotificationPacket) -> Result<UciNotification, UwbErr> {
    match evt.specialize() {
        UciNotificationChild::CoreNotification(evt) => core_notification(evt),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn core_response(evt: CoreResponsePacket) -> Result<UciResponse, UwbErr> {
    match evt.specialize() {
        CoreResponseChild::GetDeviceInfoRsp(evt) => Ok(get_device_info_rsp(evt)),
        CoreResponseChild::GetCapsInfoRsp(evt) => Ok(get_caps_info_rsp(evt)),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn session_response(evt: SessionResponsePacket) -> Result<UciResponse, UwbErr> {
    match evt.specialize() {
        SessionResponseChild::SessionInitRsp(evt) => Ok(session_init_rsp(evt)),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn ranging_response(evt: RangingResponsePacket) -> Result<UciResponse, UwbErr> {
    match evt.specialize() {
        RangingResponseChild::RangeStartRsp(evt) => Ok(range_start_rsp(evt)),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn core_notification(evt: CoreNotificationPacket) -> Result<UciNotification, UwbErr> {
    match evt.specialize() {
        CoreNotificationChild::GenericError(evt) => Ok(generic_error(evt)),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn get_device_info_rsp(evt: GetDeviceInfoRspPacket) -> UciResponse {
    let evt_data = GetDeviceInfoRspBuilder {
        status: evt.get_status(),
        uci_version: evt.get_uci_version(),
        mac_version: evt.get_mac_version(),
        phy_version: evt.get_phy_version(),
        uci_test_version: evt.get_uci_test_version(),
        vendor_spec_info: evt.get_vendor_spec_info().to_vec(),
    };
    UciResponse::GetDeviceInfoRsp(evt_data)
}

fn get_caps_info_rsp(evt: GetCapsInfoRspPacket) -> UciResponse {
    let evt_data =
        GetCapsInfoRspBuilder { status: evt.get_status(), tlvs: evt.get_tlvs().to_vec() };
    UciResponse::GetCapsInfoRsp(evt_data)
}

fn session_init_rsp(evt: SessionInitRspPacket) -> UciResponse {
    let evt_data = SessionInitRspBuilder { status: evt.get_status() };
    UciResponse::SessionInitRsp(evt_data)
}

fn range_start_rsp(evt: RangeStartRspPacket) -> UciResponse {
    let evt_data = RangeStartRspBuilder { status: evt.get_status() };
    UciResponse::RangeStartRsp(evt_data)
}

fn generic_error(evt: GenericErrorPacket) -> UciNotification {
    let evt_data = GenericErrorBuilder { status: evt.get_status() };
    UciNotification::GenericError(evt_data)
}
