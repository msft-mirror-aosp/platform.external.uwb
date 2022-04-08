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

use std::convert::{TryFrom, TryInto};

use num_traits::ToPrimitive;
use uwb_uci_packets::Packet;

use crate::uci::error::{StatusCode, UciError, UciResult};
use crate::uci::params::{
    ControleeStatus, DeviceState, ExtendedAddressTwoWayRangingMeasurement, RawVendorMessage,
    ReasonCode, SessionId, SessionState, ShortAddressTwoWayRangingMeasurement,
};

#[derive(Debug, Clone)]
pub(crate) enum UciNotification {
    CoreDeviceStatus(DeviceState),
    CoreGenericError(StatusCode),
    SessionStatus {
        session_id: SessionId,
        session_state: SessionState,
        reason_code: ReasonCode,
    },
    SessionUpdateControllerMulticastList {
        session_id: SessionId,
        remaining_multicast_list_size: usize,
        status_list: Vec<ControleeStatus>,
    },
    ShortMacTwoWayRangeData(Vec<ShortAddressTwoWayRangingMeasurement>),
    ExtendedMacTwoWayRangeData(Vec<ExtendedAddressTwoWayRangingMeasurement>),
    RawVendor(RawVendorMessage),
}

impl UciNotification {
    pub fn need_retry(&self) -> bool {
        matches!(self, Self::CoreGenericError(StatusCode::UciStatusCommandRetry))
    }
}

impl TryFrom<uwb_uci_packets::UciNotificationPacket> for UciNotification {
    type Error = UciError;
    fn try_from(evt: uwb_uci_packets::UciNotificationPacket) -> Result<Self, Self::Error> {
        use uwb_uci_packets::UciNotificationChild;
        match evt.specialize() {
            UciNotificationChild::CoreNotification(evt) => evt.try_into(),
            UciNotificationChild::SessionNotification(evt) => evt.try_into(),
            UciNotificationChild::RangingNotification(evt) => evt.try_into(),
            UciNotificationChild::AndroidNotification(evt) => evt.try_into(),
            UciNotificationChild::UciVendor_9_Notification(evt) => vendor_notification(evt.into()),
            UciNotificationChild::UciVendor_A_Notification(evt) => vendor_notification(evt.into()),
            UciNotificationChild::UciVendor_B_Notification(evt) => vendor_notification(evt.into()),
            UciNotificationChild::UciVendor_E_Notification(evt) => vendor_notification(evt.into()),
            UciNotificationChild::UciVendor_F_Notification(evt) => vendor_notification(evt.into()),
            _ => Err(UciError::Specialize(evt.to_vec())),
        }
    }
}

impl TryFrom<uwb_uci_packets::CoreNotificationPacket> for UciNotification {
    type Error = UciError;
    fn try_from(evt: uwb_uci_packets::CoreNotificationPacket) -> Result<Self, Self::Error> {
        use uwb_uci_packets::CoreNotificationChild;
        match evt.specialize() {
            CoreNotificationChild::DeviceStatusNtf(evt) => {
                Ok(UciNotification::CoreDeviceStatus(evt.get_device_state()))
            }
            CoreNotificationChild::GenericError(evt) => {
                Ok(UciNotification::CoreGenericError(evt.get_status()))
            }
            _ => Err(UciError::Specialize(evt.to_vec())),
        }
    }
}

impl TryFrom<uwb_uci_packets::SessionNotificationPacket> for UciNotification {
    type Error = UciError;
    fn try_from(evt: uwb_uci_packets::SessionNotificationPacket) -> Result<Self, Self::Error> {
        use uwb_uci_packets::SessionNotificationChild;
        match evt.specialize() {
            SessionNotificationChild::SessionStatusNtf(evt) => Ok(UciNotification::SessionStatus {
                session_id: evt.get_session_id(),
                session_state: evt.get_session_state(),
                reason_code: evt.get_reason_code(),
            }),
            SessionNotificationChild::SessionUpdateControllerMulticastListNtf(evt) => {
                Ok(UciNotification::SessionUpdateControllerMulticastList {
                    session_id: evt.get_session_id(),
                    remaining_multicast_list_size: evt.get_remaining_multicast_list_size() as usize,
                    status_list: evt.get_controlee_status().clone(),
                })
            }
            _ => Err(UciError::Specialize(evt.to_vec())),
        }
    }
}

impl TryFrom<uwb_uci_packets::RangingNotificationPacket> for UciNotification {
    type Error = UciError;
    fn try_from(evt: uwb_uci_packets::RangingNotificationPacket) -> Result<Self, Self::Error> {
        use uwb_uci_packets::RangingNotificationChild;
        match evt.specialize() {
            RangingNotificationChild::RangeDataNtf(evt) => evt.try_into(),
            _ => Err(UciError::Specialize(evt.to_vec())),
        }
    }
}

impl TryFrom<uwb_uci_packets::RangeDataNtfPacket> for UciNotification {
    type Error = UciError;
    fn try_from(evt: uwb_uci_packets::RangeDataNtfPacket) -> Result<Self, Self::Error> {
        use uwb_uci_packets::RangeDataNtfChild;
        match evt.specialize() {
            RangeDataNtfChild::ShortMacTwoWayRangeDataNtf(evt) => {
                Ok(UciNotification::ShortMacTwoWayRangeData(
                    evt.get_two_way_ranging_measurements().clone(),
                ))
            }
            RangeDataNtfChild::ExtendedMacTwoWayRangeDataNtf(evt) => {
                Ok(UciNotification::ExtendedMacTwoWayRangeData(
                    evt.get_two_way_ranging_measurements().clone(),
                ))
            }
            _ => Err(UciError::Specialize(evt.to_vec())),
        }
    }
}

impl TryFrom<uwb_uci_packets::AndroidNotificationPacket> for UciNotification {
    type Error = UciError;
    fn try_from(evt: uwb_uci_packets::AndroidNotificationPacket) -> Result<Self, Self::Error> {
        Err(UciError::Specialize(evt.to_vec()))
    }
}

fn vendor_notification(evt: uwb_uci_packets::UciNotificationPacket) -> UciResult<UciNotification> {
    Ok(UciNotification::RawVendor(RawVendorMessage {
        gid: evt
            .get_group_id()
            .to_u32()
            .ok_or_else(|| UciError::Specialize(evt.clone().to_vec()))?,
        oid: evt.get_opcode().to_u32().ok_or_else(|| UciError::Specialize(evt.clone().to_vec()))?,
        payload: get_vendor_uci_payload(evt)?,
    }))
}

fn get_vendor_uci_payload(evt: uwb_uci_packets::UciNotificationPacket) -> UciResult<Vec<u8>> {
    match evt.specialize() {
        uwb_uci_packets::UciNotificationChild::UciVendor_9_Notification(evt) => {
            match evt.specialize() {
                uwb_uci_packets::UciVendor_9_NotificationChild::Payload(payload) => {
                    Ok(payload.to_vec())
                }
                uwb_uci_packets::UciVendor_9_NotificationChild::None => Ok(Vec::new()),
            }
        }
        uwb_uci_packets::UciNotificationChild::UciVendor_A_Notification(evt) => {
            match evt.specialize() {
                uwb_uci_packets::UciVendor_A_NotificationChild::Payload(payload) => {
                    Ok(payload.to_vec())
                }
                uwb_uci_packets::UciVendor_A_NotificationChild::None => Ok(Vec::new()),
            }
        }
        uwb_uci_packets::UciNotificationChild::UciVendor_B_Notification(evt) => {
            match evt.specialize() {
                uwb_uci_packets::UciVendor_B_NotificationChild::Payload(payload) => {
                    Ok(payload.to_vec())
                }
                uwb_uci_packets::UciVendor_B_NotificationChild::None => Ok(Vec::new()),
            }
        }
        uwb_uci_packets::UciNotificationChild::UciVendor_E_Notification(evt) => {
            match evt.specialize() {
                uwb_uci_packets::UciVendor_E_NotificationChild::Payload(payload) => {
                    Ok(payload.to_vec())
                }
                uwb_uci_packets::UciVendor_E_NotificationChild::None => Ok(Vec::new()),
            }
        }
        uwb_uci_packets::UciNotificationChild::UciVendor_F_Notification(evt) => {
            match evt.specialize() {
                uwb_uci_packets::UciVendor_F_NotificationChild::Payload(payload) => {
                    Ok(payload.to_vec())
                }
                uwb_uci_packets::UciVendor_F_NotificationChild::None => Ok(Vec::new()),
            }
        }
        _ => Err(UciError::Specialize(evt.to_vec())),
    }
}
