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

//! This module defines the parameters or responses of the UciManager's methods. Most of them are
//! re-exported from the uwb_uci_packets crate.

use std::collections::{hash_map::RandomState, HashMap};
use std::iter::FromIterator;

// Re-export enums and structs from uwb_uci_packets.
pub use uwb_uci_packets::{
    AppConfigStatus, AppConfigTlv, AppConfigTlvType, CapTlv, CapTlvType, Controlee,
    ControleeStatus, DeviceConfigId, DeviceConfigStatus, DeviceConfigTlv, DeviceState,
    ExtendedAddressTwoWayRangingMeasurement, MulticastUpdateStatusCode, PowerStats,
    RangingMeasurementType, ReasonCode, ResetConfig, SessionState, SessionType,
    ShortAddressTwoWayRangingMeasurement, StatusCode, UpdateMulticastListAction,
};

/// The type of the session identifier.
pub type SessionId = u32;
/// The type of the sub-session identifier.
pub type SubSessionId = u32;

/// Compare if two AppConfigTlv array are equal. Convert the array to HashMap before comparing
/// because the order of TLV elements doesn't matter.
#[allow(dead_code)]
pub fn app_config_tlvs_eq(a: &[AppConfigTlv], b: &[AppConfigTlv]) -> bool {
    app_config_tlvs_to_map(a) == app_config_tlvs_to_map(b)
}

fn app_config_tlvs_to_map(
    tlvs: &[AppConfigTlv],
) -> HashMap<AppConfigTlvType, &Vec<u8>, RandomState> {
    HashMap::from_iter(tlvs.iter().map(|config| (config.cfg_id, &config.v)))
}

/// Compare if two DeviceConfigTlv array are equal. Convert the array to HashMap before comparing
/// because the order of TLV elements doesn't matter.
#[allow(dead_code)]
pub fn device_config_tlvs_eq(a: &[DeviceConfigTlv], b: &[DeviceConfigTlv]) -> bool {
    device_config_tlvs_to_map(a) == device_config_tlvs_to_map(b)
}

fn device_config_tlvs_to_map(
    tlvs: &[DeviceConfigTlv],
) -> HashMap<DeviceConfigId, &Vec<u8>, RandomState> {
    HashMap::from_iter(tlvs.iter().map(|config| (config.cfg_id, &config.v)))
}

/// The response of the UciManager::core_set_config() method.
#[derive(Debug, Clone, PartialEq)]
pub struct CoreSetConfigResponse {
    /// The status code of the response.
    pub status: StatusCode,
    /// The status of each config TLV.
    pub config_status: Vec<DeviceConfigStatus>,
}

/// The response of the UciManager::session_set_app_config() method.
#[derive(Debug, Clone, PartialEq)]
pub struct SetAppConfigResponse {
    /// The status code of the response.
    pub status: StatusCode,
    /// The status of each config TLV.
    pub config_status: Vec<AppConfigStatus>,
}

/// The country code struct that contains 2 uppercase ASCII characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    /// Create a CountryCode instance.
    pub fn new(code: &[u8; 2]) -> Option<Self> {
        if !code[0].is_ascii_uppercase() || !code[1].is_ascii_uppercase() {
            None
        } else {
            Some(Self(*code))
        }
    }
}

impl From<CountryCode> for [u8; 2] {
    fn from(item: CountryCode) -> [u8; 2] {
        item.0
    }
}

/// The response of the UciManager::core_get_device_info() method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDeviceInfoResponse {
    /// The UCI version.
    pub uci_version: u16,
    /// The MAC version.
    pub mac_version: u16,
    /// The physical version.
    pub phy_version: u16,
    /// The UCI test version.
    pub uci_test_version: u16,
    /// The vendor spec info.
    pub vendor_spec_info: Vec<u8>,
}

/// The raw UCI message for the vendor commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawVendorMessage {
    /// The group id of the message.
    pub gid: u32,
    /// The opcode of the message.
    pub oid: u32,
    /// The payload of the message.
    pub payload: Vec<u8>,
}
