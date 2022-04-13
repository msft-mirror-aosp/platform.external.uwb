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

use log::{error, warn};

use crate::uci::params::{AppConfigTlv, AppConfigTlvType};

/// The FiRa's application configuration parameters.
/// Ref: FiRa Consortium UWB Command Interface Generic Techinal Specification Version 1.1.0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiraAppConfigParams {
    // FiRa standard config.
    device_type: DeviceType,
    ranging_round_usage: RangingRoundUsage,
    sts_config: StsConfig,
    multi_node_mode: MultiNodeMode,
    channel_number: UwbChannel,
    device_mac_address: UwbAddress,
    dst_mac_address: Vec<UwbAddress>,
    slot_duration_rstu: u16,
    ranging_interval_ms: u32,
    mac_fcs_type: MacFcsType,
    ranging_round_control: RangingRoundControl,
    aoa_result_request: AoaResultRequest,
    range_data_ntf_config: RangeDataNtfConfig,
    range_data_ntf_proximity_near_cm: u16,
    range_data_ntf_proximity_far_cm: u16,
    device_role: RangingDeviceRole,
    rframe_config: RframeConfig,
    preamble_code_index: u8,
    sfd_id: u8,
    psdu_data_rate: PsduDataRate,
    preamble_duration: PreambleDuration,
    ranging_time_struct: RangingTimeStruct,
    slots_per_rr: u8,
    tx_adaptive_payload_power: TxAdaptivePayloadPower,
    responder_slot_index: u8,
    prf_mode: PrfMode,
    scheduled_mode: ScheduledMode,
    key_rotation: KeyRotation,
    key_rotation_rate: u8,
    session_priority: u8,
    mac_address_mode: MacAddressMode,
    vendor_id: [u8; 2],
    static_sts_iv: [u8; 6],
    number_of_sts_segments: u8,
    max_rr_retry: u16,
    uwb_initiation_time_ms: u32,
    hopping_mode: HoppingMode,
    block_stride_length: u8,
    result_report_config: ResultReportConfig,
    in_band_termination_attempt_count: u8,
    sub_session_id: Option<u32>,
    bprf_phr_data_rate: BprfPhrDataRate,
    max_number_of_measurements: u16,
    sts_length: StsLength,

    // Android-specific app config.
    number_of_range_measurements: Option<u8>,
    number_of_aoa_azimuth_measurements: Option<u8>,
    number_of_aoa_elevation_measurements: Option<u8>,
}

impl FiraAppConfigParams {
    /// validate if the params are valid.
    fn is_valid(&self) -> Option<()> {
        if self.device_type == DeviceType::Controlee {
            if self.ranging_round_control.ranging_result_report_message {
                warn!("The RRRM bit is ignored by a controlee");
            }
            if self.ranging_round_control.measurement_report_message {
                warn!("The MRM bit is ignored by a controlee");
            }
            if self.hopping_mode != HoppingMode::Disable {
                warn!("hopping_mode is ignored by a controlee");
            }
            if self.block_stride_length != 0 {
                warn!("block_stride_length is ignored by a controlee");
            }
        }
        if self.ranging_time_struct != RangingTimeStruct::BlockBasedScheduling
            && self.block_stride_length != 0
        {
            warn!(
                "block_stride_length is ignored when ranging_time_struct not BlockBasedScheduling"
            );
        }
        if self.prf_mode != PrfMode::Bprf && self.bprf_phr_data_rate != BprfPhrDataRate::Rate850k {
            warn!("BPRF_PHR_DATA_RATE is ignored when prf_mode not BPRF");
        }

        validate(
            (1..=8).contains(&self.dst_mac_address.len()),
            "The length of dst_mac_address should be between 1 to 8",
        )?;
        validate(
            (0..=15).contains(&self.key_rotation_rate),
            "key_rotation_rate should be between 0 to 15",
        )?;
        validate(
            (1..=100).contains(&self.session_priority),
            "session_priority should be between 1 to 100",
        )?;
        validate(
            (1..=10000).contains(&self.uwb_initiation_time_ms),
            "uwb_initiation_time_ms should be between 1 to 10000",
        )?;
        validate(
            (1..=10).contains(&self.in_band_termination_attempt_count),
            "in_band_termination_attempt_count should be between 1 to 10",
        )?;

        match self.mac_address_mode {
            MacAddressMode::MacAddress2Bytes | MacAddressMode::MacAddress8Bytes2BytesHeader => {
                validate(
                    matches!(self.device_mac_address, UwbAddress::Short(_)),
                    "device_mac_address should be short address",
                )?;
                validate(
                    self.dst_mac_address.iter().all(|addr| matches!(addr, UwbAddress::Short(_))),
                    "dst_mac_address should be short address",
                )?;
            }
            MacAddressMode::MacAddress8Bytes => {
                validate(
                    matches!(self.device_mac_address, UwbAddress::Extended(_)),
                    "device_mac_address should be extended address",
                )?;
                validate(
                    self.dst_mac_address.iter().all(|addr| matches!(addr, UwbAddress::Extended(_))),
                    "dst_mac_address should be extended address",
                )?;
            }
        }

        match self.prf_mode {
            PrfMode::Bprf => {
                validate(
                    (9..=12).contains(&self.preamble_code_index),
                    "preamble_code_index should be between 9 to 12 when BPRF",
                )?;
                validate([0, 2].contains(&self.sfd_id), "sfd_id should be 0 or 2 when BPRF")?;
                validate(
                    self.preamble_duration == PreambleDuration::T64Symbols,
                    "preamble_duration should be 64 symbols when BPRF",
                )?;
            }
            _ => {
                validate(
                    (25..=32).contains(&self.preamble_code_index),
                    "preamble_code_index should be between 25 to 32 when HPRF",
                )?;
                validate(
                    (1..=4).contains(&self.sfd_id),
                    "sfd_id should be between 1 to 4 when HPRF",
                )?;
            }
        }

        match self.rframe_config {
            RframeConfig::SP0 => {
                validate(
                    self.number_of_sts_segments == 0,
                    "number_of_sts_segments should be 0 when SP0",
                )?;
            }
            RframeConfig::SP1 | RframeConfig::SP3 => match self.prf_mode {
                PrfMode::Bprf => {
                    validate(
                        self.number_of_sts_segments == 1,
                        "number_of_sts_segments should be 1 when SP1/SP3 and BPRF",
                    )?;
                }
                _ => {
                    validate(
                        [1, 2, 3, 4].contains(&self.number_of_sts_segments),
                        "number_of_sts_segments should be between 1 to 4 when SP1/SP3 and HPRF",
                    )?;
                }
            },
        }

        match self.aoa_result_request {
            AoaResultRequest::ReqAoaResultsInterleaved => {
                validate(
                    self.number_of_range_measurements.is_some()
                        || self.number_of_aoa_azimuth_measurements.is_some()
                        || self.number_of_aoa_elevation_measurements.is_some(),
                    "At least one of the ratio params should be set for interleaving mode",
                );
            }
            _ => {
                validate(
                    self.number_of_range_measurements.is_none()
                        && self.number_of_aoa_azimuth_measurements.is_none()
                        && self.number_of_aoa_elevation_measurements.is_none(),
                    "All of the ratio params should not be set for non-interleaving mode",
                );
            }
        }

        Some(())
    }

    pub fn generate_tlvs(&self) -> Vec<AppConfigTlv> {
        debug_assert!(self.is_valid().is_some());

        let mut configs = vec![
            (AppConfigTlvType::DeviceType, u8_to_bytes(self.device_type as u8)),
            (AppConfigTlvType::RangingRoundUsage, u8_to_bytes(self.ranging_round_usage as u8)),
            (AppConfigTlvType::StsConfig, u8_to_bytes(self.sts_config as u8)),
            (AppConfigTlvType::MultiNodeMode, u8_to_bytes(self.multi_node_mode as u8)),
            (AppConfigTlvType::ChannelNumber, u8_to_bytes(self.channel_number as u8)),
            (AppConfigTlvType::NoOfControlee, u8_to_bytes(self.dst_mac_address.len() as u8)),
            (AppConfigTlvType::DeviceMacAddress, self.device_mac_address.clone().into()),
            (AppConfigTlvType::DstMacAddress, addresses_to_bytes(self.dst_mac_address.clone())),
            (AppConfigTlvType::SlotDuration, u16_to_bytes(self.slot_duration_rstu)),
            (AppConfigTlvType::RangingInterval, u32_to_bytes(self.ranging_interval_ms)),
            (AppConfigTlvType::MacFcsType, u8_to_bytes(self.mac_fcs_type as u8)),
            (
                AppConfigTlvType::RangingRoundControl,
                u8_to_bytes(self.ranging_round_control.as_u8()),
            ),
            (AppConfigTlvType::AoaResultReq, u8_to_bytes(self.aoa_result_request as u8)),
            (AppConfigTlvType::RngDataNtf, u8_to_bytes(self.range_data_ntf_config as u8)),
            (
                AppConfigTlvType::RngDataNtfProximityNear,
                u16_to_bytes(self.range_data_ntf_proximity_near_cm),
            ),
            (
                AppConfigTlvType::RngDataNtfProximityFar,
                u16_to_bytes(self.range_data_ntf_proximity_far_cm),
            ),
            (AppConfigTlvType::DeviceRole, u8_to_bytes(self.device_role as u8)),
            (AppConfigTlvType::RframeConfig, u8_to_bytes(self.rframe_config as u8)),
            (AppConfigTlvType::PreambleCodeIndex, u8_to_bytes(self.preamble_code_index)),
            (AppConfigTlvType::SfdId, u8_to_bytes(self.sfd_id)),
            (AppConfigTlvType::PsduDataRate, u8_to_bytes(self.psdu_data_rate as u8)),
            (AppConfigTlvType::PreambleDuration, u8_to_bytes(self.preamble_duration as u8)),
            (AppConfigTlvType::RangingTimeStruct, u8_to_bytes(self.ranging_time_struct as u8)),
            (AppConfigTlvType::SlotsPerRr, u8_to_bytes(self.slots_per_rr)),
            (
                AppConfigTlvType::TxAdaptivePayloadPower,
                u8_to_bytes(self.tx_adaptive_payload_power as u8),
            ),
            (AppConfigTlvType::ResponderSlotIndex, u8_to_bytes(self.responder_slot_index)),
            (AppConfigTlvType::PrfMode, u8_to_bytes(self.prf_mode as u8)),
            (AppConfigTlvType::ScheduledMode, u8_to_bytes(self.scheduled_mode as u8)),
            (AppConfigTlvType::KeyRotation, u8_to_bytes(self.key_rotation as u8)),
            (AppConfigTlvType::KeyRotationRate, u8_to_bytes(self.key_rotation_rate)),
            (AppConfigTlvType::SessionPriority, u8_to_bytes(self.session_priority)),
            (AppConfigTlvType::MacAddressMode, u8_to_bytes(self.mac_address_mode as u8)),
            (AppConfigTlvType::VendorId, self.vendor_id.to_vec()),
            (AppConfigTlvType::StaticStsIv, self.static_sts_iv.to_vec()),
            (AppConfigTlvType::NumberOfStsSegments, u8_to_bytes(self.number_of_sts_segments)),
            (AppConfigTlvType::MaxRrRetry, u16_to_bytes(self.max_rr_retry)),
            (AppConfigTlvType::UwbInitiationTime, u32_to_bytes(self.uwb_initiation_time_ms)),
            (AppConfigTlvType::HoppingMode, u8_to_bytes(self.hopping_mode as u8)),
            (AppConfigTlvType::BlockStrideLength, u8_to_bytes(self.block_stride_length)),
            (AppConfigTlvType::ResultReportConfig, u8_to_bytes(self.result_report_config.as_u8())),
            (
                AppConfigTlvType::InBandTerminationAttemptCount,
                u8_to_bytes(self.in_band_termination_attempt_count),
            ),
            (AppConfigTlvType::BprfPhrDataRate, u8_to_bytes(self.bprf_phr_data_rate as u8)),
            (
                AppConfigTlvType::MaxNumberOfMeasurements,
                u16_to_bytes(self.max_number_of_measurements),
            ),
            (AppConfigTlvType::StsLength, u8_to_bytes(self.sts_length as u8)),
        ];

        if let Some(value) = self.sub_session_id.as_ref() {
            configs.push((AppConfigTlvType::SubSessionId, u32_to_bytes(*value)));
        }
        if let Some(value) = self.number_of_range_measurements.as_ref() {
            configs.push((AppConfigTlvType::NbOfRangeMeasurements, u8_to_bytes(*value)));
        }
        if let Some(value) = self.number_of_aoa_azimuth_measurements.as_ref() {
            configs.push((AppConfigTlvType::NbOfAzimuthMeasurements, u8_to_bytes(*value)));
        }
        if let Some(value) = self.number_of_aoa_elevation_measurements.as_ref() {
            configs.push((AppConfigTlvType::NbOfElevationMeasurements, u8_to_bytes(*value)));
        }

        configs.into_iter().map(|(cfg_id, v)| AppConfigTlv { cfg_id, v }).collect()
    }
}

pub struct FiraAppConfigParamsBuilder {
    device_type: Option<DeviceType>,
    ranging_round_usage: RangingRoundUsage,
    sts_config: StsConfig,
    multi_node_mode: Option<MultiNodeMode>,
    channel_number: UwbChannel,
    device_mac_address: Option<UwbAddress>,
    dst_mac_address: Vec<UwbAddress>,
    slot_duration_rstu: u16,
    ranging_interval_ms: u32,
    mac_fcs_type: MacFcsType,
    ranging_round_control: RangingRoundControl,
    aoa_result_request: AoaResultRequest,
    range_data_ntf_config: RangeDataNtfConfig,
    range_data_ntf_proximity_near_cm: u16,
    range_data_ntf_proximity_far_cm: u16,
    device_role: Option<RangingDeviceRole>,
    rframe_config: RframeConfig,
    preamble_code_index: u8,
    sfd_id: u8,
    psdu_data_rate: PsduDataRate,
    preamble_duration: PreambleDuration,
    ranging_time_struct: RangingTimeStruct,
    slots_per_rr: u8,
    tx_adaptive_payload_power: TxAdaptivePayloadPower,
    responder_slot_index: u8,
    prf_mode: PrfMode,
    scheduled_mode: ScheduledMode,
    key_rotation: KeyRotation,
    key_rotation_rate: u8,
    session_priority: u8,
    mac_address_mode: MacAddressMode,
    vendor_id: Option<[u8; 2]>,
    static_sts_iv: Option<[u8; 6]>,
    number_of_sts_segments: u8,
    max_rr_retry: u16,
    uwb_initiation_time_ms: u32,
    hopping_mode: HoppingMode,
    block_stride_length: u8,
    result_report_config: ResultReportConfig,
    in_band_termination_attempt_count: u8,
    sub_session_id: Option<u32>,
    bprf_phr_data_rate: BprfPhrDataRate,
    max_number_of_measurements: u16,
    sts_length: StsLength,
    number_of_range_measurements: Option<u8>,
    number_of_aoa_azimuth_measurements: Option<u8>,
    number_of_aoa_elevation_measurements: Option<u8>,
}

impl FiraAppConfigParamsBuilder {
    /// Fill the default value of each field if exists, otherwise put None.
    pub fn new() -> Self {
        Self {
            device_type: None,
            ranging_round_usage: RangingRoundUsage::DsTwr,
            sts_config: StsConfig::Static,
            multi_node_mode: None,
            channel_number: UwbChannel::Channel9,
            device_mac_address: None,
            dst_mac_address: vec![],
            slot_duration_rstu: 2400,
            ranging_interval_ms: 200,
            mac_fcs_type: MacFcsType::Crc16,
            ranging_round_control: RangingRoundControl {
                ranging_result_report_message: true,
                control_message: true,
                measurement_report_message: false,
            },
            aoa_result_request: AoaResultRequest::ReqAoaResults,
            range_data_ntf_config: RangeDataNtfConfig::Enable,
            range_data_ntf_proximity_near_cm: 0,
            range_data_ntf_proximity_far_cm: 20000,
            device_role: None,
            rframe_config: RframeConfig::SP3,
            preamble_code_index: 10,
            sfd_id: 2,
            psdu_data_rate: PsduDataRate::Rate6m81,
            preamble_duration: PreambleDuration::T64Symbols,
            ranging_time_struct: RangingTimeStruct::BlockBasedScheduling,
            slots_per_rr: 25,
            tx_adaptive_payload_power: TxAdaptivePayloadPower::Disable,
            responder_slot_index: 1,
            prf_mode: PrfMode::Bprf,
            scheduled_mode: ScheduledMode::TimeScheduledRanging,
            key_rotation: KeyRotation::Disable,
            key_rotation_rate: 0,
            session_priority: 50,
            mac_address_mode: MacAddressMode::MacAddress2Bytes,
            vendor_id: None,
            static_sts_iv: None,
            number_of_sts_segments: 1,
            max_rr_retry: 0,
            uwb_initiation_time_ms: 0,
            hopping_mode: HoppingMode::Disable,
            block_stride_length: 0,
            result_report_config: ResultReportConfig {
                tof: true,
                aoa_azimuth: false,
                aoa_elevation: false,
                aoa_fom: false,
            },
            in_band_termination_attempt_count: 1,
            sub_session_id: None,
            bprf_phr_data_rate: BprfPhrDataRate::Rate850k,
            max_number_of_measurements: 0,
            sts_length: StsLength::Length64,
            number_of_range_measurements: None,
            number_of_aoa_azimuth_measurements: None,
            number_of_aoa_elevation_measurements: None,
        }
    }

    pub fn build(&self) -> Option<FiraAppConfigParams> {
        let params = FiraAppConfigParams {
            device_type: self.device_type?,
            ranging_round_usage: self.ranging_round_usage,
            sts_config: self.sts_config,
            multi_node_mode: self.multi_node_mode?,
            channel_number: self.channel_number,
            device_mac_address: self.device_mac_address.clone()?,
            dst_mac_address: self.dst_mac_address.clone(),
            slot_duration_rstu: self.slot_duration_rstu,
            ranging_interval_ms: self.ranging_interval_ms,
            mac_fcs_type: self.mac_fcs_type,
            ranging_round_control: self.ranging_round_control.clone(),
            aoa_result_request: self.aoa_result_request,
            range_data_ntf_config: self.range_data_ntf_config,
            range_data_ntf_proximity_near_cm: self.range_data_ntf_proximity_near_cm,
            range_data_ntf_proximity_far_cm: self.range_data_ntf_proximity_far_cm,
            device_role: self.device_role?,
            rframe_config: self.rframe_config,
            preamble_code_index: self.preamble_code_index,
            sfd_id: self.sfd_id,
            psdu_data_rate: self.psdu_data_rate,
            preamble_duration: self.preamble_duration,
            ranging_time_struct: self.ranging_time_struct,
            slots_per_rr: self.slots_per_rr,
            tx_adaptive_payload_power: self.tx_adaptive_payload_power,
            responder_slot_index: self.responder_slot_index,
            prf_mode: self.prf_mode,
            scheduled_mode: self.scheduled_mode,
            key_rotation: self.key_rotation,
            key_rotation_rate: self.key_rotation_rate,
            session_priority: self.session_priority,
            mac_address_mode: self.mac_address_mode,
            vendor_id: self.vendor_id?,
            static_sts_iv: self.static_sts_iv?,
            number_of_sts_segments: self.number_of_sts_segments,
            max_rr_retry: self.max_rr_retry,
            uwb_initiation_time_ms: self.uwb_initiation_time_ms,
            hopping_mode: self.hopping_mode,
            block_stride_length: self.block_stride_length,
            result_report_config: self.result_report_config.clone(),
            in_band_termination_attempt_count: self.in_band_termination_attempt_count,
            sub_session_id: self.sub_session_id,
            bprf_phr_data_rate: self.bprf_phr_data_rate,
            max_number_of_measurements: self.max_number_of_measurements,
            sts_length: self.sts_length,
            number_of_range_measurements: self.number_of_range_measurements,
            number_of_aoa_azimuth_measurements: self.number_of_aoa_azimuth_measurements,
            number_of_aoa_elevation_measurements: self.number_of_aoa_elevation_measurements,
        };

        params.is_valid()?;
        Some(params)
    }

    // Setter methods.
    // TODO(akahuang): Use macro for these setter methods.
    pub fn device_type(&mut self, value: DeviceType) -> &mut Self {
        self.device_type = Some(value);
        self
    }
    pub fn ranging_round_usage(&mut self, value: RangingRoundUsage) -> &mut Self {
        self.ranging_round_usage = value;
        self
    }
    pub fn sts_config(&mut self, value: StsConfig) -> &mut Self {
        self.sts_config = value;
        self
    }
    pub fn multi_node_mode(&mut self, value: MultiNodeMode) -> &mut Self {
        self.multi_node_mode = Some(value);
        self
    }
    pub fn channel_number(&mut self, value: UwbChannel) -> &mut Self {
        self.channel_number = value;
        self
    }
    pub fn device_mac_address(&mut self, value: UwbAddress) -> &mut Self {
        self.device_mac_address = Some(value);
        self
    }
    pub fn dst_mac_address(&mut self, value: Vec<UwbAddress>) -> &mut Self {
        self.dst_mac_address = value;
        self
    }
    pub fn slot_duration_rstu(&mut self, value: u16) -> &mut Self {
        self.slot_duration_rstu = value;
        self
    }
    pub fn ranging_interval_ms(&mut self, value: u32) -> &mut Self {
        self.ranging_interval_ms = value;
        self
    }
    pub fn mac_fcs_type(&mut self, value: MacFcsType) -> &mut Self {
        self.mac_fcs_type = value;
        self
    }
    pub fn ranging_round_control(&mut self, value: RangingRoundControl) -> &mut Self {
        self.ranging_round_control = value;
        self
    }
    pub fn aoa_result_request(&mut self, value: AoaResultRequest) -> &mut Self {
        self.aoa_result_request = value;
        self
    }
    pub fn range_data_ntf_config(&mut self, value: RangeDataNtfConfig) -> &mut Self {
        self.range_data_ntf_config = value;
        self
    }
    pub fn range_data_ntf_proximity_near_cm(&mut self, value: u16) -> &mut Self {
        self.range_data_ntf_proximity_near_cm = value;
        self
    }
    pub fn range_data_ntf_proximity_far_cm(&mut self, value: u16) -> &mut Self {
        self.range_data_ntf_proximity_far_cm = value;
        self
    }
    pub fn device_role(&mut self, value: RangingDeviceRole) -> &mut Self {
        self.device_role = Some(value);
        self
    }
    pub fn rframe_config(&mut self, value: RframeConfig) -> &mut Self {
        self.rframe_config = value;
        self
    }
    pub fn preamble_code_index(&mut self, value: u8) -> &mut Self {
        self.preamble_code_index = value;
        self
    }
    pub fn sfd_id(&mut self, value: u8) -> &mut Self {
        self.sfd_id = value;
        self
    }
    pub fn psdu_data_rate(&mut self, value: PsduDataRate) -> &mut Self {
        self.psdu_data_rate = value;
        self
    }
    pub fn preamble_duration(&mut self, value: PreambleDuration) -> &mut Self {
        self.preamble_duration = value;
        self
    }
    pub fn ranging_time_struct(&mut self, value: RangingTimeStruct) -> &mut Self {
        self.ranging_time_struct = value;
        self
    }
    pub fn slots_per_rr(&mut self, value: u8) -> &mut Self {
        self.slots_per_rr = value;
        self
    }
    pub fn tx_adaptive_payload_power(&mut self, value: TxAdaptivePayloadPower) -> &mut Self {
        self.tx_adaptive_payload_power = value;
        self
    }
    pub fn responder_slot_index(&mut self, value: u8) -> &mut Self {
        self.responder_slot_index = value;
        self
    }
    pub fn prf_mode(&mut self, value: PrfMode) -> &mut Self {
        self.prf_mode = value;
        self
    }
    pub fn scheduled_mode(&mut self, value: ScheduledMode) -> &mut Self {
        self.scheduled_mode = value;
        self
    }
    pub fn key_rotation(&mut self, value: KeyRotation) -> &mut Self {
        self.key_rotation = value;
        self
    }
    pub fn key_rotation_rate(&mut self, value: u8) -> &mut Self {
        self.key_rotation_rate = value;
        self
    }
    pub fn session_priority(&mut self, value: u8) -> &mut Self {
        self.session_priority = value;
        self
    }
    pub fn mac_address_mode(&mut self, value: MacAddressMode) -> &mut Self {
        self.mac_address_mode = value;
        self
    }
    pub fn vendor_id(&mut self, value: Option<[u8; 2]>) -> &mut Self {
        self.vendor_id = value;
        self
    }
    pub fn static_sts_iv(&mut self, value: Option<[u8; 6]>) -> &mut Self {
        self.static_sts_iv = value;
        self
    }
    pub fn number_of_sts_segments(&mut self, value: u8) -> &mut Self {
        self.number_of_sts_segments = value;
        self
    }
    pub fn max_rr_retry(&mut self, value: u16) -> &mut Self {
        self.max_rr_retry = value;
        self
    }
    pub fn uwb_initiation_time_ms(&mut self, value: u32) -> &mut Self {
        self.uwb_initiation_time_ms = value;
        self
    }
    pub fn hopping_mode(&mut self, value: HoppingMode) -> &mut Self {
        self.hopping_mode = value;
        self
    }
    pub fn block_stride_length(&mut self, value: u8) -> &mut Self {
        self.block_stride_length = value;
        self
    }
    pub fn result_report_config(&mut self, value: ResultReportConfig) -> &mut Self {
        self.result_report_config = value;
        self
    }
    pub fn in_band_termination_attempt_count(&mut self, value: u8) -> &mut Self {
        self.in_band_termination_attempt_count = value;
        self
    }
    pub fn sub_session_id(&mut self, value: u32) -> &mut Self {
        self.sub_session_id = Some(value);
        self
    }
    pub fn bprf_phr_data_rate(&mut self, value: BprfPhrDataRate) -> &mut Self {
        self.bprf_phr_data_rate = value;
        self
    }
    pub fn max_number_of_measurements(&mut self, value: u16) -> &mut Self {
        self.max_number_of_measurements = value;
        self
    }
    pub fn sts_length(&mut self, value: StsLength) -> &mut Self {
        self.sts_length = value;
        self
    }
    pub fn number_of_range_measurements(&mut self, value: u8) -> &mut Self {
        self.number_of_range_measurements = Some(value);
        self
    }
    pub fn number_of_aoa_azimuth_measurements(&mut self, value: u8) -> &mut Self {
        self.number_of_aoa_azimuth_measurements = Some(value);
        self
    }
    pub fn number_of_aoa_elevation_measurements(&mut self, value: u8) -> &mut Self {
        self.number_of_aoa_elevation_measurements = Some(value);
        self
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Controlee = 0,
    Controller = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangingRoundUsage {
    SsTwr = 1,
    DsTwr = 2,
    SsTwrNon = 3,
    DsTwrNon = 4,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StsConfig {
    Static = 0,
    Dynamic = 1,
    DynamicForControleeIndividualKey = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiNodeMode {
    Unicast = 0,
    OneToMany = 1,
    ManyToMany = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UwbChannel {
    Channel5 = 5,
    Channel6 = 6,
    Channel8 = 8,
    Channel9 = 9,
    Channel10 = 10,
    Channel12 = 12,
    Channel13 = 13,
    Channel14 = 14,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UwbAddress {
    Short([u8; 2]),
    Extended([u8; 8]),
}

impl From<UwbAddress> for Vec<u8> {
    fn from(item: UwbAddress) -> Self {
        match item {
            UwbAddress::Short(addr) => addr.to_vec(),
            UwbAddress::Extended(addr) => addr.to_vec(),
        }
    }
}

fn addresses_to_bytes(addresses: Vec<UwbAddress>) -> Vec<u8> {
    addresses.into_iter().flat_map(Into::<Vec<u8>>::into).collect()
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacFcsType {
    Crc16 = 0,
    Crc32 = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangingRoundControl {
    pub ranging_result_report_message: bool,
    pub control_message: bool,
    pub measurement_report_message: bool,
}

impl RangingRoundControl {
    const RANGING_RESULT_REPORT_MESSAGE_BIT_OFFSET: u8 = 0;
    const CONTROL_MESSAGE_BIT_OFFSET: u8 = 1;
    const MEASUREMENT_REPORT_MESSAGE_BIT_OFFSET: u8 = 7;

    fn as_u8(&self) -> u8 {
        let mut value = 0_u8;
        if self.ranging_result_report_message {
            value |= 1 << Self::RANGING_RESULT_REPORT_MESSAGE_BIT_OFFSET;
        }
        if self.control_message {
            value |= 1 << Self::CONTROL_MESSAGE_BIT_OFFSET;
        }
        if self.measurement_report_message {
            value |= 1 << Self::MEASUREMENT_REPORT_MESSAGE_BIT_OFFSET;
        }
        value
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AoaResultRequest {
    NoAoaReport = 0,
    ReqAoaResults = 1,
    ReqAoaResultsAzimuthOnly = 2,
    ReqAoaResultsElevationOnly = 3,
    ReqAoaResultsInterleaved = 0xF0,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeDataNtfConfig {
    Disable = 0,
    Enable = 1,
    EnableProximity = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangingDeviceRole {
    Responder = 0,
    Initiator = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RframeConfig {
    SP0 = 0,
    SP1 = 1,
    SP3 = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsduDataRate {
    Rate6m81 = 0,
    Rate7m80 = 1,
    Rate27m2 = 2,
    Rate31m2 = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreambleDuration {
    T32Symbols = 0,
    T64Symbols = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangingTimeStruct {
    IntervalBasedScheduling = 0,
    BlockBasedScheduling = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxAdaptivePayloadPower {
    Disable = 0,
    Enable = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfMode {
    Bprf = 0,
    HprfWith124_8MHz = 1,
    HprfWith249_6MHz = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledMode {
    TimeScheduledRanging = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRotation {
    Disable = 0,
    Enable = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAddressMode {
    MacAddress2Bytes = 0,
    MacAddress8Bytes2BytesHeader = 1,
    MacAddress8Bytes = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoppingMode {
    Disable = 0,
    FiraHoppingEnable = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultReportConfig {
    pub tof: bool,
    pub aoa_azimuth: bool,
    pub aoa_elevation: bool,
    pub aoa_fom: bool,
}

impl ResultReportConfig {
    const TOF_BIT_OFFSET: u8 = 0;
    const AOA_AZIMUTH_BIT_OFFSET: u8 = 1;
    const AOA_ELEVATION_BIT_OFFSET: u8 = 2;
    const AOA_FOM_BIT_OFFSET: u8 = 3;

    fn as_u8(&self) -> u8 {
        let mut value = 0_u8;
        if self.tof {
            value |= 1 << Self::TOF_BIT_OFFSET;
        }
        if self.aoa_azimuth {
            value |= 1 << Self::AOA_AZIMUTH_BIT_OFFSET;
        }
        if self.aoa_elevation {
            value |= 1 << Self::AOA_ELEVATION_BIT_OFFSET;
        }
        if self.aoa_fom {
            value |= 1 << Self::AOA_FOM_BIT_OFFSET;
        }

        value
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BprfPhrDataRate {
    Rate850k = 0,
    Rate6m81 = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StsLength {
    Length32 = 0,
    Length64 = 1,
    Length128 = 2,
}

fn u8_to_bytes(value: u8) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}
fn u16_to_bytes(value: u16) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}
fn u32_to_bytes(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn validate(value: bool, err_msg: &str) -> Option<()> {
    match value {
        true => Some(()),
        false => {
            error!("{}", err_msg);
            None
        }
    }
}
