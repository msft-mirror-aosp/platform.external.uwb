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
pub enum UciMessage {
    Response(UciResponse),
    Notification(UciNotification),
}

#[derive(Debug)]
pub enum UciResponse {
    GetDeviceInfoRsp(GetDeviceInfoRspPacket),
    GetCapsInfoRsp(GetCapsInfoRspPacket),
    SetConfigRsp(SetConfigRspPacket),
    GetConfigRsp(GetConfigRspPacket),
    DeviceResetRsp(DeviceResetRspPacket),
    SessionInitRsp(SessionInitRspPacket),
    SessionDeinitRsp(SessionDeinitRspPacket),
    SessionGetAppConfigRsp(SessionGetAppConfigRspPacket),
    SessionSetAppConfigRsp(SessionSetAppConfigRspPacket),
    SessionGetStateRsp(SessionGetStateRspPacket),
    SessionGetCountRsp(SessionGetCountRspPacket),
    SessionUpdateControllerMulticastListRsp(SessionUpdateControllerMulticastListRspPacket),
    RangeStartRsp(RangeStartRspPacket),
    RangeStopRsp(RangeStopRspPacket),
    RangeGetRangingCountRsp(RangeGetRangingCountRspPacket),
    AndroidSetCountryCodeRsp(AndroidSetCountryCodeRspPacket),
    AndroidGetPowerStatsRsp(AndroidGetPowerStatsRspPacket),
}

#[derive(Debug)]
pub enum UciNotification {
    GenericError(GenericErrorPacket),
    DeviceStatusNtf(DeviceStatusNtfPacket),
    SessionStatusNtf(SessionStatusNtfPacket),
    SessionUpdateControllerMulticastListNtf(SessionUpdateControllerMulticastListNtfPacket),
    ShortMacTwoWayRangeDataNtf(ShortMacTwoWayRangeDataNtfPacket),
    ExtendedMacTwoWayRangeDataNtf(ExtendedMacTwoWayRangeDataNtfPacket),
}

pub fn uci_message(evt: UciPacketPacket) -> Result<UciMessage, UwbErr> {
    match evt.specialize() {
        UciPacketChild::UciResponse(evt) => Ok(UciMessage::Response(uci_response(evt).unwrap())),
        UciPacketChild::UciNotification(evt) => {
            Ok(UciMessage::Notification(uci_notification(evt).unwrap()))
        }
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

pub fn uci_response(evt: UciResponsePacket) -> Result<UciResponse, UwbErr> {
    match evt.specialize() {
        UciResponseChild::CoreResponse(evt) => core_response(evt),
        UciResponseChild::SessionResponse(evt) => session_response(evt),
        UciResponseChild::RangingResponse(evt) => ranging_response(evt),
        UciResponseChild::AndroidResponse(evt) => android_response(evt),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

pub fn uci_notification(evt: UciNotificationPacket) -> Result<UciNotification, UwbErr> {
    match evt.specialize() {
        UciNotificationChild::CoreNotification(evt) => core_notification(evt),
        UciNotificationChild::SessionNotification(evt) => session_notification(evt),
        UciNotificationChild::RangingNotification(evt) => ranging_notification(evt),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn core_response(evt: CoreResponsePacket) -> Result<UciResponse, UwbErr> {
    match evt.specialize() {
        CoreResponseChild::GetDeviceInfoRsp(evt) => Ok(UciResponse::GetDeviceInfoRsp(evt)),
        CoreResponseChild::GetCapsInfoRsp(evt) => Ok(UciResponse::GetCapsInfoRsp(evt)),
        CoreResponseChild::SetConfigRsp(evt) => Ok(UciResponse::SetConfigRsp(evt)),
        CoreResponseChild::GetConfigRsp(evt) => Ok(UciResponse::GetConfigRsp(evt)),
        CoreResponseChild::DeviceResetRsp(evt) => Ok(UciResponse::DeviceResetRsp(evt)),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn session_response(evt: SessionResponsePacket) -> Result<UciResponse, UwbErr> {
    match evt.specialize() {
        SessionResponseChild::SessionInitRsp(evt) => Ok(UciResponse::SessionInitRsp(evt)),
        SessionResponseChild::SessionDeinitRsp(evt) => Ok(UciResponse::SessionDeinitRsp(evt)),
        SessionResponseChild::SessionSetAppConfigRsp(evt) => {
            Ok(UciResponse::SessionSetAppConfigRsp(evt))
        }
        SessionResponseChild::SessionGetAppConfigRsp(evt) => {
            Ok(UciResponse::SessionGetAppConfigRsp(evt))
        }
        SessionResponseChild::SessionGetStateRsp(evt) => Ok(UciResponse::SessionGetStateRsp(evt)),
        SessionResponseChild::SessionGetCountRsp(evt) => Ok(UciResponse::SessionGetCountRsp(evt)),
        SessionResponseChild::SessionUpdateControllerMulticastListRsp(evt) => {
            Ok(UciResponse::SessionUpdateControllerMulticastListRsp(evt))
        }
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn ranging_response(evt: RangingResponsePacket) -> Result<UciResponse, UwbErr> {
    match evt.specialize() {
        RangingResponseChild::RangeStartRsp(evt) => Ok(UciResponse::RangeStartRsp(evt)),
        RangingResponseChild::RangeStopRsp(evt) => Ok(UciResponse::RangeStopRsp(evt)),
        RangingResponseChild::RangeGetRangingCountRsp(evt) => {
            Ok(UciResponse::RangeGetRangingCountRsp(evt))
        }
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn android_response(evt: AndroidResponsePacket) -> Result<UciResponse, UwbErr> {
    match evt.specialize() {
        AndroidResponseChild::AndroidSetCountryCodeRsp(evt) => {
            Ok(UciResponse::AndroidSetCountryCodeRsp(evt))
        }
        AndroidResponseChild::AndroidGetPowerStatsRsp(evt) => {
            Ok(UciResponse::AndroidGetPowerStatsRsp(evt))
        }
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn core_notification(evt: CoreNotificationPacket) -> Result<UciNotification, UwbErr> {
    match evt.specialize() {
        CoreNotificationChild::DeviceStatusNtf(evt) => Ok(UciNotification::DeviceStatusNtf(evt)),
        CoreNotificationChild::GenericError(evt) => Ok(UciNotification::GenericError(evt)),
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}

fn session_notification(evt: SessionNotificationPacket) -> Result<UciNotification, UwbErr> {
    match evt.specialize() {
        SessionNotificationChild::SessionStatusNtf(evt) => {
            Ok(UciNotification::SessionStatusNtf(evt))
        }
        SessionNotificationChild::SessionUpdateControllerMulticastListNtf(evt) => {
            Ok(UciNotification::SessionUpdateControllerMulticastListNtf(evt))
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

fn range_data_ntf(evt: RangeDataNtfPacket) -> Result<UciNotification, UwbErr> {
    match evt.specialize() {
        RangeDataNtfChild::ShortMacTwoWayRangeDataNtf(evt) => {
            Ok(UciNotification::ShortMacTwoWayRangeDataNtf(evt))
        }
        RangeDataNtfChild::ExtendedMacTwoWayRangeDataNtf(evt) => {
            Ok(UciNotification::ExtendedMacTwoWayRangeDataNtf(evt))
        }
        _ => Err(UwbErr::Specialize(evt.to_vec())),
    }
}
