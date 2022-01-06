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
use uwb_uci_packets::*;

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
    SessionDeinitRsp(SessionDeinitRspBuilder),
    SessionGetAppConfigRsp(SessionGetAppConfigRspBuilder),
    SessionSetAppConfigRsp(SessionSetAppConfigRspBuilder),
    SessionGetStateRsp(SessionGetStateRspBuilder),
    SessionGetCountRsp(SessionGetCountRspBuilder),
    SessionUpdateControllerMulticastListRsp(SessionUpdateControllerMulticastListRspBuilder),
    RangeStartRsp(RangeStartRspBuilder),
    RangeStopRsp(RangeStopRspBuilder),
    RangeGetRangingCountRsp(RangeGetRangingCountRspBuilder),
    AndroidSetCountryCodeRsp(AndroidSetCountryCodeRspBuilder),
    AndroidGetPowerStatsRsp(AndroidGetPowerStatsRspBuilder),
}

pub enum UciNotification {
    GenericError(GenericErrorBuilder),
    DeviceStatusNtf(DeviceStatusNtfBuilder),
    SessionStatusNtf(SessionStatusNtfBuilder),
    SessionUpdateControllerMulticastListNtf(SessionUpdateControllerMulticastListNtfBuilder),
    ShortMacRangeDataNtf(ShortMacRangeDataNtfBuilder),
    ExtendedMacRangeDataNtf(ExtendedMacRangeDataNtfBuilder),
}

pub fn uci_response(bytes: &[u8]) -> Result<UciResponse, UwbErr> {
    let evt = UciResponsePacket::parse(bytes)?;
    match evt.specialize() {
        UciResponseChild::CoreResponse(evt) => core_response(evt),
        UciResponseChild::SessionResponse(evt) => session_response(evt),
        UciResponseChild::RangingResponse(evt) => ranging_response(evt),
        UciResponseChild::AndroidResponse(evt) => android_response(evt),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

pub fn uci_notification(bytes: &[u8]) -> Result<UciNotification, UwbErr> {
    let evt = UciNotificationPacket::parse(bytes)?;
    match evt.specialize() {
        UciNotificationChild::CoreNotification(evt) => core_notification(evt),
        UciNotificationChild::SessionNotification(evt) => session_notification(evt),
        UciNotificationChild::RangingNotification(evt) => ranging_notification(evt),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn core_response(evt: CoreResponsePacket) -> Result<UciResponse, UwbErr> {
    match evt.specialize() {
        CoreResponseChild::GetDeviceInfoRsp(evt) => Ok(get_device_info_rsp(evt)),
        CoreResponseChild::GetCapsInfoRsp(evt) => Ok(get_caps_info_rsp(evt)),
        CoreResponseChild::SetConfigRsp(evt) => Ok(set_config_rsp(evt)),
        CoreResponseChild::GetConfigRsp(evt) => Ok(get_config_rsp(evt)),
        CoreResponseChild::DeviceResetRsp(evt) => Ok(device_reset_rsp(evt)),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn session_response(evt: SessionResponsePacket) -> Result<UciResponse, UwbErr> {
    match evt.specialize() {
        SessionResponseChild::SessionInitRsp(evt) => Ok(session_init_rsp(evt)),
        SessionResponseChild::SessionDeinitRsp(evt) => Ok(session_deinit_rsp(evt)),
        SessionResponseChild::SessionSetAppConfigRsp(evt) => Ok(session_set_app_config_rsp(evt)),
        SessionResponseChild::SessionGetAppConfigRsp(evt) => Ok(session_get_app_config_rsp(evt)),
        SessionResponseChild::SessionGetStateRsp(evt) => Ok(session_get_state_rsp(evt)),
        SessionResponseChild::SessionGetCountRsp(evt) => Ok(session_get_count_rsp(evt)),
        SessionResponseChild::SessionUpdateControllerMulticastListRsp(evt) => {
            Ok(session_update_controller_multicast_list_rsp(evt))
        }
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn ranging_response(evt: RangingResponsePacket) -> Result<UciResponse, UwbErr> {
    match evt.specialize() {
        RangingResponseChild::RangeStartRsp(evt) => Ok(range_start_rsp(evt)),
        RangingResponseChild::RangeStopRsp(evt) => Ok(range_stop_rsp(evt)),
        RangingResponseChild::RangeGetRangingCountRsp(evt) => Ok(range_get_ranging_count_rsp(evt)),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn android_response(evt: AndroidResponsePacket) -> Result<UciResponse, UwbErr> {
    match evt.specialize() {
        AndroidResponseChild::AndroidSetCountryCodeRsp(evt) => {
            Ok(android_set_country_code_rsp(evt))
        }
        AndroidResponseChild::AndroidGetPowerStatsRsp(evt) => Ok(android_get_power_start_rsp(evt)),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn core_notification(evt: CoreNotificationPacket) -> Result<UciNotification, UwbErr> {
    match evt.specialize() {
        CoreNotificationChild::DeviceStatusNtf(evt) => Ok(device_status_ntf(evt)),
        CoreNotificationChild::GenericError(evt) => Ok(generic_error(evt)),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn session_notification(evt: SessionNotificationPacket) -> Result<UciNotification, UwbErr> {
    match evt.specialize() {
        SessionNotificationChild::SessionStatusNtf(evt) => Ok(session_status_ntf(evt)),
        SessionNotificationChild::SessionUpdateControllerMulticastListNtf(evt) => {
            Ok(session_update_controller_multicast_list_ntf(evt))
        }
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn ranging_notification(evt: RangingNotificationPacket) -> Result<UciNotification, UwbErr> {
    match evt.specialize() {
        RangingNotificationChild::RangeDataNtf(evt) => range_data_ntf(evt),
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

fn set_config_rsp(evt: SetConfigRspPacket) -> UciResponse {
    let evt_data =
        SetConfigRspBuilder { status: evt.get_status(), cfg_status: evt.get_cfg_status().to_vec() };
    UciResponse::SetConfigRsp(evt_data)
}

fn get_config_rsp(evt: GetConfigRspPacket) -> UciResponse {
    let evt_data = GetConfigRspBuilder { status: evt.get_status(), tlvs: evt.get_tlvs().to_vec() };
    UciResponse::GetConfigRsp(evt_data)
}

fn device_reset_rsp(evt: DeviceResetRspPacket) -> UciResponse {
    let evt_data = DeviceResetRspBuilder { status: evt.get_status() };
    UciResponse::DeviceResetRsp(evt_data)
}

fn session_init_rsp(evt: SessionInitRspPacket) -> UciResponse {
    let evt_data = SessionInitRspBuilder { status: evt.get_status() };
    UciResponse::SessionInitRsp(evt_data)
}

fn session_deinit_rsp(evt: SessionDeinitRspPacket) -> UciResponse {
    let evt_data = SessionDeinitRspBuilder { status: evt.get_status() };
    UciResponse::SessionDeinitRsp(evt_data)
}

fn session_set_app_config_rsp(evt: SessionSetAppConfigRspPacket) -> UciResponse {
    let evt_data = SessionSetAppConfigRspBuilder {
        status: evt.get_status(),
        cfg_status: evt.get_cfg_status().to_vec(),
    };
    UciResponse::SessionSetAppConfigRsp(evt_data)
}

fn session_get_app_config_rsp(evt: SessionGetAppConfigRspPacket) -> UciResponse {
    let evt_data =
        SessionGetAppConfigRspBuilder { status: evt.get_status(), tlvs: evt.get_tlvs().to_vec() };
    UciResponse::SessionGetAppConfigRsp(evt_data)
}

fn session_get_state_rsp(evt: SessionGetStateRspPacket) -> UciResponse {
    let evt_data = SessionGetStateRspBuilder {
        status: evt.get_status(),
        session_state: evt.get_session_state(),
    };
    UciResponse::SessionGetStateRsp(evt_data)
}

fn session_get_count_rsp(evt: SessionGetCountRspPacket) -> UciResponse {
    let evt_data = SessionGetCountRspBuilder {
        status: evt.get_status(),
        session_count: evt.get_session_count(),
    };
    UciResponse::SessionGetCountRsp(evt_data)
}

fn session_update_controller_multicast_list_rsp(
    evt: SessionUpdateControllerMulticastListRspPacket,
) -> UciResponse {
    let evt_data = SessionUpdateControllerMulticastListRspBuilder { status: evt.get_status() };
    UciResponse::SessionUpdateControllerMulticastListRsp(evt_data)
}

fn range_start_rsp(evt: RangeStartRspPacket) -> UciResponse {
    let evt_data = RangeStartRspBuilder { status: evt.get_status() };
    UciResponse::RangeStartRsp(evt_data)
}

fn range_stop_rsp(evt: RangeStopRspPacket) -> UciResponse {
    let evt_data = RangeStopRspBuilder { status: evt.get_status() };
    UciResponse::RangeStopRsp(evt_data)
}

fn range_get_ranging_count_rsp(evt: RangeGetRangingCountRspPacket) -> UciResponse {
    let evt_data =
        RangeGetRangingCountRspBuilder { status: evt.get_status(), count: evt.get_count() };
    UciResponse::RangeGetRangingCountRsp(evt_data)
}

fn android_set_country_code_rsp(evt: AndroidSetCountryCodeRspPacket) -> UciResponse {
    let evt_data = AndroidSetCountryCodeRspBuilder { status: evt.get_status() };
    UciResponse::AndroidSetCountryCodeRsp(evt_data)
}

fn android_get_power_start_rsp(evt: AndroidGetPowerStatsRspPacket) -> UciResponse {
    let evt_data = AndroidGetPowerStatsRspBuilder { stats: evt.get_stats().clone() };
    UciResponse::AndroidGetPowerStatsRsp(evt_data)
}

fn generic_error(evt: GenericErrorPacket) -> UciNotification {
    let evt_data = GenericErrorBuilder { status: evt.get_status() };
    UciNotification::GenericError(evt_data)
}

fn device_status_ntf(evt: DeviceStatusNtfPacket) -> UciNotification {
    let evt_data = DeviceStatusNtfBuilder { device_state: evt.get_device_state() };
    UciNotification::DeviceStatusNtf(evt_data)
}

fn session_status_ntf(evt: SessionStatusNtfPacket) -> UciNotification {
    let evt_data = SessionStatusNtfBuilder {
        session_id: evt.get_session_id(),
        session_state: evt.get_session_state(),
        reason_code: evt.get_reason_code(),
    };
    UciNotification::SessionStatusNtf(evt_data)
}

fn session_update_controller_multicast_list_ntf(
    evt: SessionUpdateControllerMulticastListNtfPacket,
) -> UciNotification {
    let evt_data = SessionUpdateControllerMulticastListNtfBuilder {
        session_id: evt.get_session_id(),
        remaining_multicast_list_size: evt.get_remaining_multicast_list_size(),
        controlee_status: evt.get_controlee_status().to_vec(),
    };
    UciNotification::SessionUpdateControllerMulticastListNtf(evt_data)
}

fn range_data_ntf(evt: RangeDataNtfPacket) -> Result<UciNotification, UwbErr> {
    match evt.specialize() {
        RangeDataNtfChild::ShortMacRangeDataNtf(evt) => Ok(short_mac_range_data_ntf(evt)),
        RangeDataNtfChild::ExtendedMacRangeDataNtf(evt) => Ok(extended_mac_range_data_ntf(evt)),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn short_mac_range_data_ntf(evt: ShortMacRangeDataNtfPacket) -> UciNotification {
    let evt_data = ShortMacRangeDataNtfBuilder {
        sequence_number: evt.get_sequence_number(),
        session_id: evt.get_session_id(),
        current_ranging_interval: evt.get_current_ranging_interval(),
        ranging_measurement_type: evt.get_ranging_measurement_type(),
        two_way_ranging_measurements: evt.get_two_way_ranging_measurements().to_vec(),
    };
    UciNotification::ShortMacRangeDataNtf(evt_data)
}

fn extended_mac_range_data_ntf(evt: ExtendedMacRangeDataNtfPacket) -> UciNotification {
    let evt_data = ExtendedMacRangeDataNtfBuilder {
        sequence_number: evt.get_sequence_number(),
        session_id: evt.get_session_id(),
        current_ranging_interval: evt.get_current_ranging_interval(),
        ranging_measurement_type: evt.get_ranging_measurement_type(),
        two_way_ranging_measurements: evt.get_two_way_ranging_measurements().to_vec(),
    };
    UciNotification::ExtendedMacRangeDataNtf(evt_data)
}
