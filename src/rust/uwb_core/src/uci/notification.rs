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
use uwb_uci_packets::{parse_diagnostics_ntf, Packet, UCI_PACKET_HEADER_LEN};

use crate::error::{Error, Result};
use crate::params::fira_app_config_params::UwbAddress;
use crate::params::uci_packets::{
    ControleeStatus, CreditAvailability, DataRcvStatusCode, DataTransferNtfStatusCode, DeviceState,
    ExtendedAddressDlTdoaRangingMeasurement, ExtendedAddressOwrAoaRangingMeasurement,
    ExtendedAddressTwoWayRangingMeasurement, FiraComponent, RangingMeasurementType, RawUciMessage,
    SessionId, SessionState, ShortAddressDlTdoaRangingMeasurement,
    ShortAddressOwrAoaRangingMeasurement, ShortAddressTwoWayRangingMeasurement, StatusCode,
};

/// enum of all UCI notifications with structured fields.
#[derive(Debug, Clone, PartialEq)]
pub enum UciNotification {
    /// CoreNotification equivalent.
    Core(CoreNotification),
    /// SessionNotification equivalent.
    Session(SessionNotification),
    /// UciVendor_X_Notification equivalent.
    Vendor(RawUciMessage),
}

/// UCI CoreNotification.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        reason_code: u8,
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
    /// (Short/Extended)Mac()SessionInfoNtf equivalent
    SessionInfo(SessionRangeData),
    /// DataCreditNtf equivalent.
    DataCredit {
        /// SessionId : u32
        session_id: SessionId,
        /// Credit Availability (for sending Data packets on UWB Session)
        credit_availability: CreditAvailability,
    },
    /// DataTransferStatusNtf equivalent.
    DataTransferStatus {
        /// SessionId : u32
        session_id: SessionId,
        /// Sequence Number: u8
        uci_sequence_number: u8,
        /// Data Transfer Status Code
        status: DataTransferNtfStatusCode,
    },
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
    /// A Two-Way measurement with short address.
    ShortAddressTwoWay(Vec<ShortAddressTwoWayRangingMeasurement>),

    /// A Two-Way measurement with extended address.
    ExtendedAddressTwoWay(Vec<ExtendedAddressTwoWayRangingMeasurement>),

    /// Dl-TDoA measurement with short address.
    ShortAddressDltdoa(Vec<ShortAddressDlTdoaRangingMeasurement>),

    /// Dl-TDoA measurement with extended address.
    ExtendedAddressDltdoa(Vec<ExtendedAddressDlTdoaRangingMeasurement>),

    /// OWR for AoA measurement with short address.
    ShortAddressOwrAoa(ShortAddressOwrAoaRangingMeasurement),

    /// OWR for AoA measurement with extended address.
    ExtendedAddressOwrAoa(ExtendedAddressOwrAoaRangingMeasurement),
}

/// The DATA_RCV packet
#[derive(Debug, Clone)]
pub struct DataRcvNotification {
    /// The identifier of the session on which data transfer is happening.
    pub session_id: SessionId,

    /// The status of the data rx.
    pub status: DataRcvStatusCode,

    /// The sequence number of the data packet.
    pub uci_sequence_num: u32,

    /// MacAddress of the sender of the application data.
    pub source_address: UwbAddress,

    /// Identifier for the source FiraComponent.
    pub source_fira_component: FiraComponent,

    /// Identifier for the destination FiraComponent.
    pub dest_fira_component: FiraComponent,

    /// Application Payload Data
    pub payload: Vec<u8>,
}

impl TryFrom<uwb_uci_packets::UciDataPacket> for DataRcvNotification {
    type Error = Error;
    fn try_from(evt: uwb_uci_packets::UciDataPacket) -> std::result::Result<Self, Self::Error> {
        match evt.specialize() {
            uwb_uci_packets::UciDataPacketChild::UciDataRcv(evt) => Ok(DataRcvNotification {
                session_id: evt.get_session_id(),
                status: evt.get_status(),
                uci_sequence_num: evt.get_uci_sequence_number(),
                source_address: UwbAddress::Extended(evt.get_source_mac_address().to_le_bytes()),
                source_fira_component: evt.get_source_fira_component(),
                dest_fira_component: evt.get_dest_fira_component(),
                payload: evt.get_data().to_vec(),
            }),
            _ => {
                error!("Unknown UciData packet: {:?}", evt);
                Err(Error::Unknown)
            }
        }
    }
}

impl UciNotification {
    pub(crate) fn need_retry(&self) -> bool {
        matches!(
            self,
            Self::Core(CoreNotification::GenericError(StatusCode::UciStatusCommandRetry))
        )
    }
}

impl TryFrom<uwb_uci_packets::UciNotification> for UciNotification {
    type Error = Error;
    fn try_from(evt: uwb_uci_packets::UciNotification) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::UciNotificationChild;
        match evt.specialize() {
            UciNotificationChild::CoreNotification(evt) => Ok(Self::Core(evt.try_into()?)),
            UciNotificationChild::SessionConfigNotification(evt) => {
                Ok(Self::Session(evt.try_into()?))
            }
            UciNotificationChild::SessionControlNotification(evt) => {
                Ok(Self::Session(evt.try_into()?))
            }
            UciNotificationChild::AndroidNotification(evt) => evt.try_into(),
            UciNotificationChild::UciVendor_9_Notification(evt) => vendor_notification(evt.into()),
            UciNotificationChild::UciVendor_A_Notification(evt) => vendor_notification(evt.into()),
            UciNotificationChild::UciVendor_B_Notification(evt) => vendor_notification(evt.into()),
            UciNotificationChild::UciVendor_E_Notification(evt) => vendor_notification(evt.into()),
            UciNotificationChild::UciVendor_F_Notification(evt) => vendor_notification(evt.into()),
            _ => {
                error!("Unknown UciNotification: {:?}", evt);
                Err(Error::Unknown)
            }
        }
    }
}

impl TryFrom<uwb_uci_packets::CoreNotification> for CoreNotification {
    type Error = Error;
    fn try_from(evt: uwb_uci_packets::CoreNotification) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::CoreNotificationChild;
        match evt.specialize() {
            CoreNotificationChild::DeviceStatusNtf(evt) => {
                Ok(Self::DeviceStatus(evt.get_device_state()))
            }
            CoreNotificationChild::GenericError(evt) => Ok(Self::GenericError(evt.get_status())),
            _ => {
                error!("Unknown CoreNotification: {:?}", evt);
                Err(Error::Unknown)
            }
        }
    }
}

impl TryFrom<uwb_uci_packets::SessionConfigNotification> for SessionNotification {
    type Error = Error;
    fn try_from(
        evt: uwb_uci_packets::SessionConfigNotification,
    ) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::SessionConfigNotificationChild;
        match evt.specialize() {
            SessionConfigNotificationChild::SessionStatusNtf(evt) => Ok(Self::Status {
                session_id: evt.get_session_id(),
                session_state: evt.get_session_state(),
                reason_code: evt.get_reason_code(),
            }),
            SessionConfigNotificationChild::SessionUpdateControllerMulticastListNtf(evt) => {
                Ok(Self::UpdateControllerMulticastList {
                    session_id: evt.get_session_id(),
                    remaining_multicast_list_size: evt.get_remaining_multicast_list_size() as usize,
                    status_list: evt.get_controlee_status().clone(),
                })
            }
            _ => {
                error!("Unknown SessionConfigNotification: {:?}", evt);
                Err(Error::Unknown)
            }
        }
    }
}

impl TryFrom<uwb_uci_packets::SessionControlNotification> for SessionNotification {
    type Error = Error;
    fn try_from(
        evt: uwb_uci_packets::SessionControlNotification,
    ) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::SessionControlNotificationChild;
        match evt.specialize() {
            SessionControlNotificationChild::SessionInfoNtf(evt) => evt.try_into(),
            SessionControlNotificationChild::DataCreditNtf(evt) => Ok(Self::DataCredit {
                session_id: evt.get_session_id(),
                credit_availability: evt.get_credit_availability(),
            }),
            SessionControlNotificationChild::DataTransferStatusNtf(evt) => {
                Ok(Self::DataTransferStatus {
                    session_id: evt.get_session_id(),
                    uci_sequence_number: evt.get_uci_sequence_number(),
                    status: evt.get_status(),
                })
            }
            _ => {
                error!("Unknown SessionControlNotification: {:?}", evt);
                Err(Error::Unknown)
            }
        }
    }
}

impl TryFrom<uwb_uci_packets::SessionInfoNtf> for SessionNotification {
    type Error = Error;
    fn try_from(evt: uwb_uci_packets::SessionInfoNtf) -> std::result::Result<Self, Self::Error> {
        let raw_ranging_data = evt.clone().to_bytes()[UCI_PACKET_HEADER_LEN..].to_vec();
        use uwb_uci_packets::SessionInfoNtfChild;
        let ranging_measurements = match evt.specialize() {
            SessionInfoNtfChild::ShortMacTwoWaySessionInfoNtf(evt) => {
                RangingMeasurements::ShortAddressTwoWay(
                    evt.get_two_way_ranging_measurements().clone(),
                )
            }
            SessionInfoNtfChild::ExtendedMacTwoWaySessionInfoNtf(evt) => {
                RangingMeasurements::ExtendedAddressTwoWay(
                    evt.get_two_way_ranging_measurements().clone(),
                )
            }
            SessionInfoNtfChild::ShortMacOwrAoaSessionInfoNtf(evt) => {
                if evt.get_owr_aoa_ranging_measurements().clone().len() == 1 {
                    RangingMeasurements::ShortAddressOwrAoa(
                        evt.get_owr_aoa_ranging_measurements().clone().pop().unwrap(),
                    )
                } else {
                    error!("Wrong count of OwrAoA ranging measurements {:?}", evt);
                    return Err(Error::BadParameters);
                }
            }
            SessionInfoNtfChild::ExtendedMacOwrAoaSessionInfoNtf(evt) => {
                if evt.get_owr_aoa_ranging_measurements().clone().len() == 1 {
                    RangingMeasurements::ExtendedAddressOwrAoa(
                        evt.get_owr_aoa_ranging_measurements().clone().pop().unwrap(),
                    )
                } else {
                    error!("Wrong count of OwrAoA ranging measurements {:?}", evt);
                    return Err(Error::BadParameters);
                }
            }
            SessionInfoNtfChild::ShortMacDlTDoASessionInfoNtf(evt) => {
                match ShortAddressDlTdoaRangingMeasurement::parse(
                    evt.get_dl_tdoa_measurements(),
                    evt.get_no_of_ranging_measurements(),
                ) {
                    Some(v) => {
                        if v.len() == evt.get_no_of_ranging_measurements().into() {
                            RangingMeasurements::ShortAddressDltdoa(v)
                        } else {
                            error!("Wrong count of ranging measurements {:?}", evt);
                            return Err(Error::BadParameters);
                        }
                    }
                    None => return Err(Error::BadParameters),
                }
            }
            SessionInfoNtfChild::ExtendedMacDlTDoASessionInfoNtf(evt) => {
                match ExtendedAddressDlTdoaRangingMeasurement::parse(
                    evt.get_dl_tdoa_measurements(),
                    evt.get_no_of_ranging_measurements(),
                ) {
                    Some(v) => {
                        if v.len() == evt.get_no_of_ranging_measurements().into() {
                            RangingMeasurements::ExtendedAddressDltdoa(v)
                        } else {
                            error!("Wrong count of ranging measurements {:?}", evt);
                            return Err(Error::BadParameters);
                        }
                    }
                    None => return Err(Error::BadParameters),
                }
            }
            _ => {
                error!("Unknown SessionInfoNtf: {:?}", evt);
                return Err(Error::Unknown);
            }
        };
        Ok(Self::SessionInfo(SessionRangeData {
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

impl TryFrom<uwb_uci_packets::AndroidNotification> for UciNotification {
    type Error = Error;
    fn try_from(
        evt: uwb_uci_packets::AndroidNotification,
    ) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::AndroidNotificationChild;

        // (b/241336806): Currently we don't process the diagnostic packet, just log it only.
        if let AndroidNotificationChild::AndroidRangeDiagnosticsNtf(ntf) = evt.specialize() {
            debug!("Received diagnostic packet: {:?}", parse_diagnostics_ntf(ntf));
        } else {
            error!("Received unknown AndroidNotification: {:?}", evt);
        }
        Err(Error::Unknown)
    }
}

fn vendor_notification(evt: uwb_uci_packets::UciNotification) -> Result<UciNotification> {
    Ok(UciNotification::Vendor(RawUciMessage {
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

fn get_vendor_uci_payload(evt: uwb_uci_packets::UciNotification) -> Result<Vec<u8>> {
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
    use crate::params::uci_packets::OwrAoaStatusCode;

    #[test]
    fn test_ranging_measurements_trait() {
        let empty_short_ranging_measurements = RangingMeasurements::ShortAddressTwoWay(vec![]);
        assert_eq!(empty_short_ranging_measurements, empty_short_ranging_measurements);
        let extended_ranging_measurements = RangingMeasurements::ExtendedAddressTwoWay(vec![
            ExtendedAddressTwoWayRangingMeasurement {
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
            },
        ]);
        let extended_ranging_measurements_copy = extended_ranging_measurements.clone();
        assert_eq!(extended_ranging_measurements, extended_ranging_measurements_copy);
        let empty_extended_ranging_measurements =
            RangingMeasurements::ExtendedAddressTwoWay(vec![]);
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
            uwb_uci_packets::CoreNotification::try_from(generic_error_packet).unwrap();
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
            uwb_uci_packets::CoreNotification::try_from(device_status_ntf_packet).unwrap();
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
    fn test_session_notification_casting_from_extended_mac_two_way_session_info_ntf() {
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
        let extended_two_way_session_info_ntf =
            uwb_uci_packets::ExtendedMacTwoWaySessionInfoNtfBuilder {
                sequence_number: 0x10,
                session_id: 0x11,
                rcr_indicator: 0x12,
                current_ranging_interval: 0x13,
                two_way_ranging_measurements: vec![extended_measurement.clone()],
            }
            .build();
        let raw_ranging_data =
            extended_two_way_session_info_ntf.clone().to_bytes()[UCI_PACKET_HEADER_LEN..].to_vec();
        let range_notification =
            uwb_uci_packets::SessionInfoNtf::try_from(extended_two_way_session_info_ntf).unwrap();
        let session_notification = SessionNotification::try_from(range_notification).unwrap();
        let uci_notification_from_extended_two_way_session_info_ntf =
            UciNotification::Session(session_notification);
        assert_eq!(
            uci_notification_from_extended_two_way_session_info_ntf,
            UciNotification::Session(SessionNotification::SessionInfo(SessionRangeData {
                sequence_number: 0x10,
                session_id: 0x11,
                ranging_measurement_type: uwb_uci_packets::RangingMeasurementType::TwoWay,
                current_ranging_interval_ms: 0x13,
                ranging_measurements: RangingMeasurements::ExtendedAddressTwoWay(vec![
                    extended_measurement
                ]),
                rcr_indicator: 0x12,
                raw_ranging_data,
            }))
        );
    }

    #[test]
    fn test_session_notification_casting_from_short_mac_two_way_session_info_ntf() {
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
        let short_two_way_session_info_ntf = uwb_uci_packets::ShortMacTwoWaySessionInfoNtfBuilder {
            sequence_number: 0x10,
            session_id: 0x11,
            rcr_indicator: 0x12,
            current_ranging_interval: 0x13,
            two_way_ranging_measurements: vec![short_measurement.clone()],
        }
        .build();
        let raw_ranging_data =
            short_two_way_session_info_ntf.clone().to_bytes()[UCI_PACKET_HEADER_LEN..].to_vec();
        let range_notification =
            uwb_uci_packets::SessionInfoNtf::try_from(short_two_way_session_info_ntf).unwrap();
        let session_notification = SessionNotification::try_from(range_notification).unwrap();
        let uci_notification_from_short_two_way_session_info_ntf =
            UciNotification::Session(session_notification);
        assert_eq!(
            uci_notification_from_short_two_way_session_info_ntf,
            UciNotification::Session(SessionNotification::SessionInfo(SessionRangeData {
                sequence_number: 0x10,
                session_id: 0x11,
                ranging_measurement_type: uwb_uci_packets::RangingMeasurementType::TwoWay,
                current_ranging_interval_ms: 0x13,
                ranging_measurements: RangingMeasurements::ShortAddressTwoWay(vec![
                    short_measurement
                ]),
                rcr_indicator: 0x12,
                raw_ranging_data,
            }))
        );
    }

    #[test]
    fn test_session_notification_casting_from_extended_mac_owr_aoa_session_info_ntf() {
        let extended_measurement = uwb_uci_packets::ExtendedAddressOwrAoaRangingMeasurement {
            mac_address: 0x1234_5678_90ab,
            status: OwrAoaStatusCode::UciStatusSuccess,
            nlos: 0,
            frame_sequence_number: 1,
            block_index: 1,
            aoa_azimuth: 5,
            aoa_azimuth_fom: 6,
            aoa_elevation: 7,
            aoa_elevation_fom: 8,
        };
        let extended_owr_aoa_session_info_ntf =
            uwb_uci_packets::ExtendedMacOwrAoaSessionInfoNtfBuilder {
                sequence_number: 0x10,
                session_id: 0x11,
                rcr_indicator: 0x12,
                current_ranging_interval: 0x13,
                owr_aoa_ranging_measurements: vec![extended_measurement.clone()],
            }
            .build();
        let raw_ranging_data =
            extended_owr_aoa_session_info_ntf.clone().to_bytes()[UCI_PACKET_HEADER_LEN..].to_vec();
        let range_notification =
            uwb_uci_packets::SessionInfoNtf::try_from(extended_owr_aoa_session_info_ntf).unwrap();
        let session_notification = SessionNotification::try_from(range_notification).unwrap();
        let uci_notification_from_extended_owr_aoa_session_info_ntf =
            UciNotification::Session(session_notification);
        assert_eq!(
            uci_notification_from_extended_owr_aoa_session_info_ntf,
            UciNotification::Session(SessionNotification::SessionInfo(SessionRangeData {
                sequence_number: 0x10,
                session_id: 0x11,
                ranging_measurement_type: uwb_uci_packets::RangingMeasurementType::OwrAoa,
                current_ranging_interval_ms: 0x13,
                ranging_measurements: RangingMeasurements::ExtendedAddressOwrAoa(
                    extended_measurement
                ),
                rcr_indicator: 0x12,
                raw_ranging_data,
            }))
        );
    }

    #[test]
    fn test_session_notification_casting_from_short_mac_owr_aoa_session_info_ntf() {
        let short_measurement = uwb_uci_packets::ShortAddressOwrAoaRangingMeasurement {
            mac_address: 0x1234,
            status: OwrAoaStatusCode::UciStatusSuccess,
            nlos: 0,
            frame_sequence_number: 1,
            block_index: 1,
            aoa_azimuth: 5,
            aoa_azimuth_fom: 6,
            aoa_elevation: 7,
            aoa_elevation_fom: 8,
        };
        let short_owr_aoa_session_info_ntf = uwb_uci_packets::ShortMacOwrAoaSessionInfoNtfBuilder {
            sequence_number: 0x10,
            session_id: 0x11,
            rcr_indicator: 0x12,
            current_ranging_interval: 0x13,
            owr_aoa_ranging_measurements: vec![short_measurement.clone()],
        }
        .build();
        let raw_ranging_data =
            short_owr_aoa_session_info_ntf.clone().to_bytes()[UCI_PACKET_HEADER_LEN..].to_vec();
        let range_notification =
            uwb_uci_packets::SessionInfoNtf::try_from(short_owr_aoa_session_info_ntf).unwrap();
        let session_notification = SessionNotification::try_from(range_notification).unwrap();
        let uci_notification_from_short_owr_aoa_session_info_ntf =
            UciNotification::Session(session_notification);
        assert_eq!(
            uci_notification_from_short_owr_aoa_session_info_ntf,
            UciNotification::Session(SessionNotification::SessionInfo(SessionRangeData {
                sequence_number: 0x10,
                session_id: 0x11,
                ranging_measurement_type: uwb_uci_packets::RangingMeasurementType::OwrAoa,
                current_ranging_interval_ms: 0x13,
                ranging_measurements: RangingMeasurements::ShortAddressOwrAoa(short_measurement),
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
            reason_code: uwb_uci_packets::ReasonCode::StateChangeWithSessionManagementCommands
                .to_u8()
                .unwrap(),
        }
        .build();
        let session_notification_packet =
            uwb_uci_packets::SessionConfigNotification::try_from(session_status_ntf).unwrap();
        let session_notification =
            SessionNotification::try_from(session_notification_packet).unwrap();
        let uci_notification_from_session_status_ntf =
            UciNotification::Session(session_notification);
        assert_eq!(
            uci_notification_from_session_status_ntf,
            UciNotification::Session(SessionNotification::Status {
                session_id: 0x20,
                session_state: uwb_uci_packets::SessionState::SessionStateActive,
                reason_code: uwb_uci_packets::ReasonCode::StateChangeWithSessionManagementCommands
                    .to_u8()
                    .unwrap(),
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
        let session_notification_packet = uwb_uci_packets::SessionConfigNotification::try_from(
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
        let vendor_9_empty_notification: uwb_uci_packets::UciNotification =
            uwb_uci_packets::UciVendor_9_NotificationBuilder { opcode: 0x40, payload: None }
                .build()
                .into();
        let vendor_A_nonempty_notification: uwb_uci_packets::UciNotification =
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
            UciNotification::Vendor(RawUciMessage {
                gid: 0x9, // per enum GroupId in uci_packets.pdl
                oid: 0x40,
                payload: vec![],
            })
        );
        assert_eq!(
            uci_notification_from_vendor_A,
            UciNotification::Vendor(RawUciMessage {
                gid: 0xa,
                oid: 0x41,
                payload: b"Placeholder notification.".to_owned().into(),
            })
        );
    }
}
