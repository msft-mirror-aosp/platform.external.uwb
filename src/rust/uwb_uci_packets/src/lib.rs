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

#![allow(clippy::all)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused)]
#![allow(missing_docs)]

use log::error;
use std::cmp;

include!(concat!(env!("OUT_DIR"), "/uci_packets.rs"));

const MAX_PAYLOAD_LEN: usize = 255;
// TODO: Use a PDL struct to represent the headers and avoid hardcoding
// lengths below.
// Real UCI packet header len.
const UCI_PACKET_HAL_HEADER_LEN: usize = 4;
// Unfragmented UCI packet header len.
const UCI_PACKET_HEADER_LEN: usize = 7;

// Container for UCI packet header fields.
struct UciPacketHeader {
    message_type: MessageType,
    group_id: GroupId,
    opcode: u8,
}

// Ensure that the new packet fragment belong to the same packet.
fn is_same_packet(header: &UciPacketHeader, packet: &UciPacketHalPacket) -> bool {
    header.message_type == packet.get_message_type()
        && header.group_id == packet.get_group_id()
        && header.opcode == packet.get_opcode()
}

// Helper to convert from vector of |UciPacketHalPacket| to |UciPacketPacket|
impl TryFrom<Vec<UciPacketHalPacket>> for UciPacketPacket {
    type Error = Error;

    fn try_from(packets: Vec<UciPacketHalPacket>) -> Result<Self> {
        if packets.is_empty() {
            return Err(Error::InvalidPacketError);
        }
        // Store header info from the first packet.
        let header = UciPacketHeader {
            message_type: packets[0].get_message_type(),
            group_id: packets[0].get_group_id(),
            opcode: packets[0].get_opcode(),
        };

        let mut payload_buf = BytesMut::new();
        // Create the reassembled payload.
        for packet in packets {
            // Ensure that the new fragment is part of the same packet.
            if !is_same_packet(&header, &packet) {
                error!("Received unexpected fragment: {:?}", packet);
                return Err(Error::InvalidPacketError);
            }
            // get payload by stripping the header.
            payload_buf.extend_from_slice(&packet.to_bytes().slice(UCI_PACKET_HAL_HEADER_LEN..))
        }
        // Create assembled |UciPacketPacket| and convert to bytes again since we need to
        // reparse the packet after defragmentation to get the appropriate message.
        UciPacketPacket::parse(
            &UciPacketBuilder {
                message_type: header.message_type,
                group_id: header.group_id,
                opcode: header.opcode,
                payload: Some(payload_buf.into()),
            }
            .build()
            .to_bytes(),
        )
    }
}

// Helper to convert from |UciPacketPacket| to vector of |UciPacketHalPacket|s
impl From<UciPacketPacket> for Vec<UciPacketHalPacket> {
    fn from(packet: UciPacketPacket) -> Self {
        // Store header info.
        let header = UciPacketHeader {
            message_type: packet.get_message_type(),
            group_id: packet.get_group_id(),
            opcode: packet.get_opcode(),
        };
        let mut fragments: Vec<UciPacketHalPacket> = Vec::new();
        // get payload by stripping the header.
        let payload = packet.to_bytes().slice(UCI_PACKET_HEADER_LEN..);
        if payload.is_empty() {
            fragments.push(
                UciPacketHalBuilder {
                    message_type: header.message_type,
                    group_id: header.group_id,
                    opcode: header.opcode,
                    packet_boundary_flag: PacketBoundaryFlag::Complete,
                    payload: None,
                }
                .build(),
            );
        } else {
            let mut fragments_iter = payload.chunks(MAX_PAYLOAD_LEN).peekable();
            while let Some(fragment) = fragments_iter.next() {
                // Set the last fragment complete if this is last fragment.
                let pbf = if let Some(nxt_fragment) = fragments_iter.peek() {
                    PacketBoundaryFlag::NotComplete
                } else {
                    PacketBoundaryFlag::Complete
                };
                fragments.push(
                    UciPacketHalBuilder {
                        message_type: header.message_type,
                        group_id: header.group_id,
                        opcode: header.opcode,
                        packet_boundary_flag: pbf,
                        payload: Some(Bytes::from(fragment.to_owned())),
                    }
                    .build(),
                );
            }
        }
        fragments
    }
}

#[derive(Default, Debug)]
pub struct PacketDefrager {
    // Cache to store incoming fragmented packets in the middle of reassembly.
    // Will be empty if there is no reassembly in progress.
    fragment_cache: Vec<UciPacketHalPacket>,
}

impl PacketDefrager {
    pub fn defragment_packet(&mut self, msg: &[u8]) -> Option<UciPacketPacket> {
        match UciPacketHalPacket::parse(msg) {
            Ok(packet) => {
                let pbf = packet.get_packet_boundary_flag();
                // Add the incoming fragment to the packet cache.
                self.fragment_cache.push(packet);
                if pbf == PacketBoundaryFlag::NotComplete {
                    // Wait for remaining fragments.
                    return None;
                }
                // All fragments received, defragment the packet.
                match self.fragment_cache.drain(..).collect::<Vec<_>>().try_into() {
                    Ok(packet) => Some(packet),
                    Err(e) => {
                        error!("Failed to defragment packet: {:?}", e);
                        None
                    }
                }
            }
            Err(e) => {
                error!("Failed to parse packet: {:?}", e);
                None
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ParsedDiagnosticNtfPacket {
    session_id: u32,
    sequence_number: u32,
    frame_reports: Vec<ParsedFrameReport>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ParsedFrameReport {
    uwb_msg_id: u8,
    action: u8,
    antenna_set: u8,
    rssi: Vec<u8>,
    aoa: Vec<AoaMeasurement>,
    cir: Vec<CirValue>,
}

pub fn parse_diagnostics_ntf(
    evt: AndroidRangeDiagnosticsNtfPacket,
) -> Result<ParsedDiagnosticNtfPacket> {
    let session_id = evt.get_session_id();
    let sequence_number = evt.get_sequence_number();
    let mut parsed_frame_reports = Vec::new();
    for report in evt.get_frame_reports() {
        let mut rssi_vec = Vec::new();
        let mut aoa_vec = Vec::new();
        let mut cir_vec = Vec::new();
        for tlv in &report.frame_report_tlvs {
            match FrameReportTlvPacketPacket::parse(
                &[vec![tlv.t as u8, tlv.v.len() as u8, (tlv.v.len() >> 8) as u8], tlv.v.clone()]
                    .concat(),
            ) {
                Ok(pkt) => match pkt.specialize() {
                    FrameReportTlvPacketChild::Rssi(rssi) => {
                        rssi_vec.append(&mut rssi.get_rssi().clone())
                    }
                    FrameReportTlvPacketChild::Aoa(aoa) => {
                        aoa_vec.append(&mut aoa.get_aoa().clone())
                    }
                    FrameReportTlvPacketChild::Cir(cir) => {
                        cir_vec.append(&mut cir.get_cir_value().clone())
                    }
                    _ => return Err(Error::InvalidPacketError),
                },
                Err(e) => {
                    error!("Failed to parse the packet {:?}", e);
                    return Err(Error::InvalidPacketError);
                }
            }
        }
        parsed_frame_reports.push(ParsedFrameReport {
            uwb_msg_id: report.uwb_msg_id,
            action: report.action,
            antenna_set: report.antenna_set,
            rssi: rssi_vec,
            aoa: aoa_vec,
            cir: cir_vec,
        });
    }
    Ok(ParsedDiagnosticNtfPacket {
        session_id,
        sequence_number,
        frame_reports: parsed_frame_reports,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub enum ControleesV2 {
    NoSessionKey(Vec<Controlee_V2_0_0_Byte_Version>),
    ShortSessionKey(Vec<Controlee_V2_0_16_Byte_Version>),
    LongSessionKey(Vec<Controlee_V2_0_32_Byte_Version>),
}

// TODO(ziyiw): Replace these functions after making uwb_uci_packets::Controlee::write_to() public.
pub fn write_controlee(controlee: &Controlee) -> BytesMut {
    let mut buffer = BytesMut::new();
    let short_address = controlee.short_address;
    buffer.extend_from_slice(&short_address.to_le_bytes()[0..2]);
    let subsession_id = controlee.subsession_id;
    buffer.extend_from_slice(&subsession_id.to_le_bytes()[0..4]);
    buffer
}

pub fn write_controlee_2_0_0byte(controlee: &Controlee_V2_0_0_Byte_Version) -> BytesMut {
    let mut buffer = BytesMut::new();
    let short_address = controlee.short_address;
    buffer.extend_from_slice(&short_address.to_le_bytes()[0..2]);
    let subsession_id = controlee.subsession_id;
    buffer.extend_from_slice(&subsession_id.to_le_bytes()[0..4]);
    let message_control = controlee.message_control.to_u8().unwrap();
    buffer.extend_from_slice(&message_control.to_le_bytes()[0..1]);
    buffer
}

pub fn write_controlee_2_0_16byte(controlee: &Controlee_V2_0_16_Byte_Version) -> BytesMut {
    let mut buffer = BytesMut::new();
    let short_address = controlee.short_address;
    buffer.extend_from_slice(&short_address.to_le_bytes()[0..2]);
    let subsession_id = controlee.subsession_id;
    buffer.extend_from_slice(&subsession_id.to_le_bytes()[0..4]);
    let message_control = controlee.message_control.to_u8().unwrap();
    buffer.extend_from_slice(&message_control.to_le_bytes()[0..1]);
    buffer.extend_from_slice(&controlee.subsession_key);
    buffer
}

pub fn write_controlee_2_0_32byte(controlee: &Controlee_V2_0_32_Byte_Version) -> BytesMut {
    let mut buffer = BytesMut::new();
    let short_address = controlee.short_address;
    buffer.extend_from_slice(&short_address.to_le_bytes()[0..2]);
    let subsession_id = controlee.subsession_id;
    buffer.extend_from_slice(&subsession_id.to_le_bytes()[0..4]);
    let message_control = controlee.message_control.to_u8().unwrap();
    buffer.extend_from_slice(&message_control.to_le_bytes()[0..1]);
    buffer.extend_from_slice(&controlee.subsession_key);
    buffer
}

/// Generate the V1 SessionUpdateControllerMulticastListCmd packet.
///
/// Workaround for handling the non-compatible command.
/// Size check omitted and UCI spec compliancy is up to the caller of the method.
pub fn build_session_update_controller_multicast_list_cmd_v1(
    session_id: u32,
    action: UpdateMulticastListAction,
    controlees: Vec<Controlee>,
) -> SessionUpdateControllerMulticastListCmdPacket {
    let mut controlees_buf = BytesMut::new();
    controlees_buf.extend_from_slice(&(controlees.len() as u8).to_le_bytes());
    for controlee in controlees {
        controlees_buf.extend_from_slice(&write_controlee(&controlee));
    }
    SessionUpdateControllerMulticastListCmdBuilder {
        session_id,
        action,
        payload: Some(controlees_buf.freeze()),
    }
    .build()
}

/// Generate the V2 SessionUpdateControllerMulticastListCmd packet.
///
/// Workaround for handling the non-compatible command.
/// Size check omitted and UCI spec compliancy is up to the caller of the method.
pub fn build_session_update_controller_multicast_list_cmd_v2(
    session_id: u32,
    action: UpdateMulticastListAction,
    controlees: ControleesV2,
) -> SessionUpdateControllerMulticastListCmdPacket {
    let mut controlees_buf = BytesMut::new();
    match controlees {
        ControleesV2::NoSessionKey(controlee_v2) => {
            controlees_buf.extend_from_slice(&(controlee_v2.len() as u8).to_le_bytes());
            for controlee in controlee_v2 {
                controlees_buf.extend_from_slice(&write_controlee_2_0_0byte(&controlee));
            }
        }
        ControleesV2::ShortSessionKey(controlee_v2) => {
            controlees_buf.extend_from_slice(&(controlee_v2.len() as u8).to_le_bytes());
            for controlee in controlee_v2 {
                controlees_buf.extend_from_slice(&write_controlee_2_0_16byte(&controlee));
            }
        }
        ControleesV2::LongSessionKey(controlee_v2) => {
            controlees_buf.extend_from_slice(&(controlee_v2.len() as u8).to_le_bytes());
            for controlee in controlee_v2 {
                controlees_buf.extend_from_slice(&write_controlee_2_0_32byte(&controlee));
            }
        }
    }
    SessionUpdateControllerMulticastListCmdBuilder {
        session_id,
        action,
        payload: Some(controlees_buf.freeze()),
    }
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_diagnostics_ntf() {
        let rssi_vec = vec![0x01, 0x02, 0x03];
        let rssi = RssiBuilder { rssi: rssi_vec.clone() }.build();
        let aoa_1 = AoaMeasurement { tdoa: 1, pdoa: 2, aoa: 3, fom: 4, t: 1 };
        let aoa_2 = AoaMeasurement { tdoa: 5, pdoa: 6, aoa: 7, fom: 8, t: 2 };
        let aoa = AoaBuilder { aoa: vec![aoa_1.clone(), aoa_2.clone()] }.build();
        let cir_vec = vec![CirValue {
            first_path_index: 1,
            first_path_snr: 2,
            first_path_ns: 3,
            peak_path_index: 4,
            peak_path_snr: 5,
            peak_path_ns: 6,
            first_path_sample_offset: 7,
            samples_number: 2,
            sample_window: vec![0, 1, 2, 3],
        }];
        let cir = CirBuilder { cir_value: cir_vec.clone() }.build();
        let mut frame_reports = Vec::new();
        let tlvs = vec![
            FrameReportTlv { t: rssi.get_t(), v: rssi.get_rssi().to_vec() },
            FrameReportTlv { t: aoa.get_t(), v: aoa.to_vec()[3..].to_vec() },
            FrameReportTlv { t: cir.get_t(), v: cir.to_vec()[3..].to_vec() },
        ];
        let frame_report =
            FrameReport { uwb_msg_id: 1, action: 1, antenna_set: 1, frame_report_tlvs: tlvs };
        frame_reports.push(frame_report);
        let packet =
            AndroidRangeDiagnosticsNtfBuilder { session_id: 1, sequence_number: 1, frame_reports }
                .build();
        let mut parsed_packet = parse_diagnostics_ntf(packet).unwrap();
        let parsed_frame_report = parsed_packet.frame_reports.pop().unwrap();
        assert_eq!(rssi_vec, parsed_frame_report.rssi);
        assert_eq!(aoa_1, parsed_frame_report.aoa[0]);
        assert_eq!(aoa_2, parsed_frame_report.aoa[1]);
        assert_eq!(cir_vec, parsed_frame_report.cir);
    }

    #[test]
    fn test_write_controlee() {
        let controlee: Controlee = Controlee { short_address: 2, subsession_id: 3 };
        let bytes = write_controlee(&controlee);
        let parsed_controlee = Controlee::parse(&bytes).unwrap();
        assert_eq!(controlee, parsed_controlee);
    }

    #[test]
    fn test_build_multicast_update_v1_packet() {
        let controlee = Controlee { short_address: 0x1234, subsession_id: 0x1324_3546 };
        let packet: UciPacketPacket = build_session_update_controller_multicast_list_cmd_v1(
            0x1425_3647,
            UpdateMulticastListAction::AddControlee,
            vec![controlee; 1],
        )
        .into();
        let packet_fragments: Vec<UciPacketHalPacket> = packet.into();
        let uci_packet: Vec<u8> = packet_fragments[0].clone().into();
        assert_eq!(
            uci_packet,
            vec![
                0x21, 0x07, 0x00, 0x0c, // 2(packet info), RFU, payload length(12)
                0x47, 0x36, 0x25, 0x14, // 4(session id (LE))
                0x00, 0x01, 0x34, 0x12, // action, # controlee, 2(short address (LE))
                0x46, 0x35, 0x24, 0x13, // 4(subsession id (LE))
            ]
        );
    }
}
