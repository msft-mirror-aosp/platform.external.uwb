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

use log::{debug, error};
use num_traits::ToPrimitive;
use uwb_uci_packets::{parse_diagnostics_ntf, Packet};

use crate::error::{Error, Result};
use crate::params::uci_packets::{
    ControleeStatus, DeviceState, ExtendedAddressTwoWayRangingMeasurement, RangingMeasurementType,
    RawVendorMessage, ReasonCode, SessionId, SessionState, ShortAddressTwoWayRangingMeasurement,
    StatusCode,
};

/// enum of all UCI notifications with structured fields.
#[derive(Debug, Clone, PartialEq)]
pub enum UciNotification {
    /// CoreNotificationPacket equivalent.
    Core(CoreNotification),
    /// SessionNotificationPacket equivalent.
    Session(SessionNotification),
    /// UciVendor_X_Notification equivalent.
    Vendor(RawVendorMessage),
}

/// UCI CoreNotification.
#[derive(Debug, Clone, PartialEq)]
pub enum CoreNotification {
    /// DeviceStatusNtf equivalent.
    DeviceStatus(DeviceState),
    /// GenericErrorPacket equivalent.
    GenericError(StatusCode),
}

/// UCI SessionNotification.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionNotification {
    /// SessionStatusNtf equivalent.
    Status {
        /// SessionId : u32
        session_id: SessionId,
        /// uwb_uci_packets::SessionState.
        session_state: SessionState,
        /// uwb_uci_packets::Reasoncode.
        reason_code: ReasonCode,
    },
    /// SessionUpdateControllerMulticastListNtf equivalent.
    UpdateControllerMulticastList {
        /// SessionId : u32
        session_id: SessionId,
        /// count of controlees: u8
        remaining_multicast_list_size: usize,
        /// list of controlees.
        status_list: Vec<ControleeStatus>,
    },
    /// (Short/Extended)Mac()RangeDataNtf equivalent
    RangeData(SessionRangeData),
}

/// The session range data.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionRangeData {
    /// The sequence counter that starts with 0 when the session is started.
    pub sequence_number: u32,

    /// The identifier of the session.
    pub session_id: SessionId,

    /// The current ranging interval setting in the unit of ms.
    pub current_ranging_interval_ms: u32,

    /// The ranging measurement type.
    pub ranging_measurement_type: RangingMeasurementType,

    /// The ranging measurement data.
    pub ranging_measurements: RangingMeasurements,

    /// Indication that a RCR was sent/received in the current ranging round.
    pub rcr_indicator: u8,

    /// The raw data of the notification message.
    /// (b/243555651): It's not at FiRa specification, only used by vendor's extension.
    pub raw_ranging_data: Vec<u8>,
}

/// The ranging measurements.
#[derive(Debug, Clone, PartialEq)]
pub enum RangingMeasurements {
    /// The measurement with short address.
    Short(Vec<ShortAddressTwoWayRangingMeasurement>),

    /// The measurement with extended address.
    Extended(Vec<ExtendedAddressTwoWayRangingMeasurement>),
}

impl UciNotification {
    pub(crate) fn need_retry(&self) -> bool {
        matches!(
            self,
            Self::Core(CoreNotification::GenericError(StatusCode::UciStatusCommandRetry))
        )
    }
}

impl TryFrom<uwb_uci_packets::UciNotificationPacket> for UciNotification {
    type Error = Error;
    fn try_from(
        evt: uwb_uci_packets::UciNotificationPacket,
    ) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::UciNotificationChild;
        match evt.specialize() {
            UciNotificationChild::CoreNotification(evt) => Ok(Self::Core(evt.try_into()?)),
            UciNotificationChild::SessionNotification(evt) => Ok(Self::Session(evt.try_into()?)),
            UciNotificationChild::RangingNotification(evt) => Ok(Self::Session(evt.try_into()?)),
            UciNotificationChild::AndroidNotification(evt) => evt.try_into(),
            UciNotificationChild::UciVendor_9_Notification(evt) => vendor_notification(evt.into()),
            UciNotificationChild::UciVendor_A_Notification(evt) => vendor_notification(evt.into()),
            UciNotificationChild::UciVendor_B_Notification(evt) => vendor_notification(evt.into()),
            UciNotificationChild::UciVendor_E_Notification(evt) => vendor_notification(evt.into()),
            UciNotificationChild::UciVendor_F_Notification(evt) => vendor_notification(evt.into()),
            _ => {
                error!("Unknown UciNotificationPacket: {:?}", evt);
                Err(Error::Unknown)
            }
        }
    }
}

impl TryFrom<uwb_uci_packets::CoreNotificationPacket> for CoreNotification {
    type Error = Error;
    fn try_from(
        evt: uwb_uci_packets::CoreNotificationPacket,
    ) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::CoreNotificationChild;
        match evt.specialize() {
            CoreNotificationChild::DeviceStatusNtf(evt) => {
                Ok(Self::DeviceStatus(evt.get_device_state()))
            }
            CoreNotificationChild::GenericError(evt) => Ok(Self::GenericError(evt.get_status())),
            _ => {
                error!("Unknown CoreNotificationPacket: {:?}", evt);
                Err(Error::Unknown)
            }
        }
    }
}

impl TryFrom<uwb_uci_packets::SessionNotificationPacket> for SessionNotification {
    type Error = Error;
    fn try_from(
        evt: uwb_uci_packets::SessionNotificationPacket,
    ) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::SessionNotificationChild;
        match evt.specialize() {
            SessionNotificationChild::SessionStatusNtf(evt) => Ok(Self::Status {
                session_id: evt.get_session_id(),
                session_state: evt.get_session_state(),
                reason_code: evt.get_reason_code(),
            }),
            SessionNotificationChild::SessionUpdateControllerMulticastListNtf(evt) => {
                Ok(Self::UpdateControllerMulticastList {
                    session_id: evt.get_session_id(),
                    remaining_multicast_list_size: evt.get_remaining_multicast_list_size() as usize,
                    status_list: evt.get_controlee_status().clone(),
                })
            }
            _ => {
                error!("Unknown SessionNotificationPacket: {:?}", evt);
                Err(Error::Unknown)
            }
        }
    }
}

impl TryFrom<uwb_uci_packets::RangingNotificationPacket> for SessionNotification {
    type Error = Error;
    fn try_from(
        evt: uwb_uci_packets::RangingNotificationPacket,
    ) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::RangingNotificationChild;
        match evt.specialize() {
            RangingNotificationChild::RangeDataNtf(evt) => evt.try_into(),
            _ => {
                error!("Unknown RangingNotificationPacket: {:?}", evt);
                Err(Error::Unknown)
            }
        }
    }
}

impl TryFrom<uwb_uci_packets::RangeDataNtfPacket> for SessionNotification {
    type Error = Error;
    fn try_from(
        evt: uwb_uci_packets::RangeDataNtfPacket,
    ) -> std::result::Result<Self, Self::Error> {
        let raw_ranging_data = evt.clone().to_vec();
        use uwb_uci_packets::RangeDataNtfChild;
        let ranging_measurements = match evt.specialize() {
            RangeDataNtfChild::ShortMacTwoWayRangeDataNtf(evt) => {
                RangingMeasurements::Short(evt.get_two_way_ranging_measurements().clone())
            }
            RangeDataNtfChild::ExtendedMacTwoWayRangeDataNtf(evt) => {
                RangingMeasurements::Extended(evt.get_two_way_ranging_measurements().clone())
            }
            _ => {
                error!("Unknown RangeDataNtfPacket: {:?}", evt);
                return Err(Error::Unknown);
            }
        };
        Ok(Self::RangeData(SessionRangeData {
            sequence_number: evt.get_sequence_number(),
            session_id: evt.get_session_id(),
            current_ranging_interval_ms: evt.get_current_ranging_interval(),
            ranging_measurement_type: evt.get_ranging_measurement_type(),
            ranging_measurements,
            rcr_indicator: evt.get_rcr_indicator(),
            raw_ranging_data,
        }))
    }
}

impl TryFrom<uwb_uci_packets::AndroidNotificationPacket> for UciNotification {
    type Error = Error;
    fn try_from(
        evt: uwb_uci_packets::AndroidNotificationPacket,
    ) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::AndroidNotificationChild;

        // (b/241336806): Currently we don't process the diagnostic packet, just log it only.
        if let AndroidNotificationChild::AndroidRangeDiagnosticsNtf(ntf) = evt.specialize() {
            debug!("Received diagnostic packet: {:?}", parse_diagnostics_ntf(ntf));
        } else {
            error!("Received unknown AndroidNotificationPacket: {:?}", evt);
        }
        Err(Error::Unknown)
    }
}

fn vendor_notification(evt: uwb_uci_packets::UciNotificationPacket) -> Result<UciNotification> {
    Ok(UciNotification::Vendor(RawVendorMessage {
        gid: evt.get_group_id().to_u32().ok_or_else(|| {
            error!("Failed to get gid from packet: {:?}", evt);
            Error::Unknown
        })?,
        oid: evt.get_opcode().to_u32().ok_or_else(|| {
            error!("Failed to get opcode from packet: {:?}", evt);
            Error::Unknown
        })?,
        payload: get_vendor_uci_payload(evt)?,
    }))
}

fn get_vendor_uci_payload(evt: uwb_uci_packets::UciNotificationPacket) -> Result<Vec<u8>> {
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
        _ => {
            error!("Unknown UciVendor packet: {:?}", evt);
            Err(Error::Unknown)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ranging_measurements_trait() {
        let empty_short_ranging_measurements = RangingMeasurements::Short(vec![]);
        assert_eq!(empty_short_ranging_measurements, empty_short_ranging_measurements);
        let extended_ranging_measurements =
            RangingMeasurements::Extended(vec![ExtendedAddressTwoWayRangingMeasurement {
                mac_address: 0x1234_5678_90ab,
                status: StatusCode::UciStatusOk,
                nlos: 0,
                distance: 4,
                aoa_azimuth: 5,
                aoa_azimuth_fom: 6,
                aoa_elevation: 7,
                aoa_elevation_fom: 8,
                aoa_destination_azimuth: 9,
                aoa_destination_azimuth_fom: 10,
                aoa_destination_elevation: 11,
                aoa_destination_elevation_fom: 12,
                slot_index: 0,
                rssi: u8::MAX,
            }]);
        let extended_ranging_measurements_copy = extended_ranging_measurements.clone();
        assert_eq!(extended_ranging_measurements, extended_ranging_measurements_copy);
        let empty_extended_ranging_measurements = RangingMeasurements::Extended(vec![]);
        assert_eq!(empty_short_ranging_measurements, empty_short_ranging_measurements);
        //short and extended measurements are unequal even if both are empty:
        assert_ne!(empty_short_ranging_measurements, empty_extended_ranging_measurements);
    }
    #[test]
    fn test_core_notification_casting_from_generic_error() {
        let generic_error_packet = uwb_uci_packets::GenericErrorBuilder {
            status: uwb_uci_packets::StatusCode::UciStatusRejected,
        }
        .build();
        let core_notification =
            uwb_uci_packets::CoreNotificationPacket::try_from(generic_error_packet).unwrap();
        let core_notification = CoreNotification::try_from(core_notification).unwrap();
        let uci_notification_from_generic_error = UciNotification::Core(core_notification);
        assert_eq!(
            uci_notification_from_generic_error,
            UciNotification::Core(CoreNotification::GenericError(
                uwb_uci_packets::StatusCode::UciStatusRejected
            ))
        );
    }
    #[test]
    fn test_core_notification_casting_from_device_status_ntf() {
        let device_status_ntf_packet = uwb_uci_packets::DeviceStatusNtfBuilder {
            device_state: uwb_uci_packets::DeviceState::DeviceStateActive,
        }
        .build();
        let core_notification =
            uwb_uci_packets::CoreNotificationPacket::try_from(device_status_ntf_packet).unwrap();
        let uci_notification = CoreNotification::try_from(core_notification).unwrap();
        let uci_notification_from_device_status_ntf = UciNotification::Core(uci_notification);
        assert_eq!(
            uci_notification_from_device_status_ntf,
            UciNotification::Core(CoreNotification::DeviceStatus(
                uwb_uci_packets::DeviceState::DeviceStateActive
            ))
        );
    }
    #[test]
    fn test_session_notification_casting_from_extended_mac_two_way_range_data_ntf() {
        let extended_measurement = uwb_uci_packets::ExtendedAddressTwoWayRangingMeasurement {
            mac_address: 0x1234_5678_90ab,
            status: StatusCode::UciStatusOk,
            nlos: 0,
            distance: 4,
            aoa_azimuth: 5,
            aoa_azimuth_fom: 6,
            aoa_elevation: 7,
            aoa_elevation_fom: 8,
            aoa_destination_azimuth: 9,
            aoa_destination_azimuth_fom: 10,
            aoa_destination_elevation: 11,
            aoa_destination_elevation_fom: 12,
            slot_index: 0,
            rssi: u8::MAX,
        };
        let extended_two_way_range_data_ntf =
            uwb_uci_packets::ExtendedMacTwoWayRangeDataNtfBuilder {
                sequence_number: 0x10,
                session_id: 0x11,
                rcr_indicator: 0x12,
                current_ranging_interval: 0x13,
                two_way_ranging_measurements: vec![extended_measurement.clone()],
            }
            .build();
        let raw_ranging_data = extended_two_way_range_data_ntf.clone().to_vec();
        let range_notification =
            uwb_uci_packets::RangingNotificationPacket::try_from(extended_two_way_range_data_ntf)
                .unwrap();
        let session_notification = SessionNotification::try_from(range_notification).unwrap();
        let uci_notification_from_extended_two_way_range_data_ntf =
            UciNotification::Session(session_notification);
        assert_eq!(
            uci_notification_from_extended_two_way_range_data_ntf,
            UciNotification::Session(SessionNotification::RangeData(SessionRangeData {
                sequence_number: 0x10,
                session_id: 0x11,
                ranging_measurement_type: uwb_uci_packets::RangingMeasurementType::TwoWay,
                current_ranging_interval_ms: 0x13,
                ranging_measurements: RangingMeasurements::Extended(vec![extended_measurement]),
                rcr_indicator: 0x12,
                raw_ranging_data,
            }))
        );
    }

    #[test]
    fn test_session_notification_casting_from_short_mac_two_way_range_data_ntf() {
        let short_measurement = uwb_uci_packets::ShortAddressTwoWayRangingMeasurement {
            mac_address: 0x1234,
            status: StatusCode::UciStatusOk,
            nlos: 0,
            distance: 4,
            aoa_azimuth: 5,
            aoa_azimuth_fom: 6,
            aoa_elevation: 7,
            aoa_elevation_fom: 8,
            aoa_destination_azimuth: 9,
            aoa_destination_azimuth_fom: 10,
            aoa_destination_elevation: 11,
            aoa_destination_elevation_fom: 12,
            slot_index: 0,
            rssi: u8::MAX,
        };
        let short_two_way_range_data_ntf = uwb_uci_packets::ShortMacTwoWayRangeDataNtfBuilder {
            sequence_number: 0x10,
            session_id: 0x11,
            rcr_indicator: 0x12,
            current_ranging_interval: 0x13,
            two_way_ranging_measurements: vec![short_measurement.clone()],
        }
        .build();
        let raw_ranging_data = short_two_way_range_data_ntf.clone().to_vec();
        let range_notification =
            uwb_uci_packets::RangingNotificationPacket::try_from(short_two_way_range_data_ntf)
                .unwrap();
        let session_notification = SessionNotification::try_from(range_notification).unwrap();
        let uci_notification_from_short_two_way_range_data_ntf =
            UciNotification::Session(session_notification);
        assert_eq!(
            uci_notification_from_short_two_way_range_data_ntf,
            UciNotification::Session(SessionNotification::RangeData(SessionRangeData {
                sequence_number: 0x10,
                session_id: 0x11,
                ranging_measurement_type: uwb_uci_packets::RangingMeasurementType::TwoWay,
                current_ranging_interval_ms: 0x13,
                ranging_measurements: RangingMeasurements::Short(vec![short_measurement]),
                rcr_indicator: 0x12,
                raw_ranging_data,
            }))
        );
    }

    #[test]
    fn test_session_notification_casting_from_session_status_ntf() {
        let session_status_ntf = uwb_uci_packets::SessionStatusNtfBuilder {
            session_id: 0x20,
            session_state: uwb_uci_packets::SessionState::SessionStateActive,
            reason_code: uwb_uci_packets::ReasonCode::StateChangeWithSessionManagementCommands,
        }
        .build();
        let session_notification_packet =
            uwb_uci_packets::SessionNotificationPacket::try_from(session_status_ntf).unwrap();
        let session_notification =
            SessionNotification::try_from(session_notification_packet).unwrap();
        let uci_notification_from_session_status_ntf =
            UciNotification::Session(session_notification);
        assert_eq!(
            uci_notification_from_session_status_ntf,
            UciNotification::Session(SessionNotification::Status {
                session_id: 0x20,
                session_state: uwb_uci_packets::SessionState::SessionStateActive,
                reason_code: uwb_uci_packets::ReasonCode::StateChangeWithSessionManagementCommands,
            })
        );
    }

    #[test]
    fn test_session_notification_casting_from_session_update_controller_multicast_list_ntf_packet()
    {
        let controlee_status = uwb_uci_packets::ControleeStatus {
            mac_address: 0xc0a8,
            subsession_id: 0x30,
            status: uwb_uci_packets::MulticastUpdateStatusCode::StatusOkMulticastListUpdate,
        };
        let another_controlee_status = uwb_uci_packets::ControleeStatus {
            mac_address: 0xc0a9,
            subsession_id: 0x31,
            status: uwb_uci_packets::MulticastUpdateStatusCode::StatusErrorKeyFetchFail,
        };
        let session_update_controller_multicast_list_ntf =
            uwb_uci_packets::SessionUpdateControllerMulticastListNtfBuilder {
                session_id: 0x32,
                remaining_multicast_list_size: 0x2,
                controlee_status: vec![controlee_status.clone(), another_controlee_status.clone()],
            }
            .build();
        let session_notification_packet = uwb_uci_packets::SessionNotificationPacket::try_from(
            session_update_controller_multicast_list_ntf,
        )
        .unwrap();
        let session_notification =
            SessionNotification::try_from(session_notification_packet).unwrap();
        let uci_notification_from_session_update_controller_multicast_list_ntf =
            UciNotification::Session(session_notification);
        assert_eq!(
            uci_notification_from_session_update_controller_multicast_list_ntf,
            UciNotification::Session(SessionNotification::UpdateControllerMulticastList {
                session_id: 0x32,
                remaining_multicast_list_size: 0x2,
                status_list: vec![controlee_status, another_controlee_status],
            })
        );
    }

    #[test]
    #[allow(non_snake_case)] //override snake case for vendor_A
    fn test_vendor_notification_casting() {
        let vendor_9_empty_notification: uwb_uci_packets::UciNotificationPacket =
            uwb_uci_packets::UciVendor_9_NotificationBuilder { opcode: 0x40, payload: None }
                .build()
                .into();
        let vendor_A_nonempty_notification: uwb_uci_packets::UciNotificationPacket =
            uwb_uci_packets::UciVendor_A_NotificationBuilder {
                opcode: 0x41,
                payload: Some(bytes::Bytes::from_static(b"Placeholder notification.")),
            }
            .build()
            .into();
        let uci_notification_from_vendor_9 =
            UciNotification::try_from(vendor_9_empty_notification).unwrap();
        let uci_notification_from_vendor_A =
            UciNotification::try_from(vendor_A_nonempty_notification).unwrap();
        assert_eq!(
            uci_notification_from_vendor_9,
            UciNotification::Vendor(RawVendorMessage {
                gid: 0x9, // per enum GroupId in uci_packets.pdl
                oid: 0x40,
                payload: vec![],
            })
        );
        assert_eq!(
            uci_notification_from_vendor_A,
            UciNotification::Vendor(RawVendorMessage {
                gid: 0xa,
                oid: 0x41,
                payload: b"Placeholder notification.".to_owned().into(),
            })
        );
    }
}
