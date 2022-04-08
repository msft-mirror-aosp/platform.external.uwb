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
    dst_mac_address: Vec<UwbAddress>, // 1 <= length of Vec <= 8
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
    preamble_code_index: u8, // BPRF: 9-12, HPRF: 25-32
    sfd_id: u8,              // from 0 to 4
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
    session_priority: u8, // 1-100
    mac_address_mode: MacAddressMode,
    vendor_id: [u8; 2],
    static_sts_iv: [u8; 6],
    number_of_sts_segments: u8,
    max_rr_retry: u16,
    uwb_initiation_time_ms: u32,
    hopping_mode: HoppingMode,
    block_stride_length: u8,
    result_report_config: ResultReportConfig,
    in_band_termination_attempt_count: u8, // from 1 to 10
    sub_session_id: Option<u32>,
    bprf_phr_data_rate: BprfPhrDataRate,
    max_number_of_measurements: u16,
    sts_length: StsLength,

    // Android-specific app config.
    number_of_range_measurements: Option<u8>,
    number_of_aoa_azimuth_measurements: Option<u8>,
    number_of_aoa_elevation_measurements: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Controlee = 0,
    Controller = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangingRoundUsage {
    SsTwr = 1,
    DsTwr = 2,
    SsTwrNon = 3,
    DsTwrNon = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StsConfig {
    Static = 0,
    Dynamic = 1,
    DynamicForControleeIndividualKey = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiNodeMode {
    Unicast = 0,
    OneToMany = 1,
    ManyToMany = 2,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AoaResultRequest {
    NoAoaReport = 0,
    ReqAoaResults = 1,
    ReqAoaResultsAzimuthOnly = 2,
    ReqAoaResultsElevationOnly = 3,
    ReqAoaResultsInterleaved = 0xF0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeDataNtfConfig {
    Disable = 0,
    Enable = 1,
    EnableProximity = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangingDeviceRole {
    Responder = 0,
    Initiator = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RframeConfig {
    SP0 = 0,
    SP1 = 1,
    SP3 = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsduDataRate {
    Rate6m81 = 0,
    Rate7m80 = 1,
    Rate27m2 = 2,
    Rate31m2 = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreambleDuration {
    T32Symbols = 0,
    T64Symbols = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangingTimeStruct {
    IntervalBasedScheduling = 0,
    BlockBasedScheduling = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxAdaptivePayloadPower {
    Disable = 0,
    Enable = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfMode {
    Bprf = 0,
    HprfWith124_8MHz = 1,
    HprfWith249_6MHz = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledMode {
    TimeScheduledRanging = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRotation {
    Disable = 0,
    Enable = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAddressMode {
    MacAddress2Bytes = 0,
    MacAddress8Bytes2BytesHeader = 1,
    MacAddress8Bytes = 2,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BprfPhrDataRate {
    Rate850k = 0,
    Rate6m81 = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StsLength {
    Length32 = 0,
    Length64 = 1,
    Length128 = 2,
}
