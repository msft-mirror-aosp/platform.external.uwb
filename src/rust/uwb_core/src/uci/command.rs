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

use bytes::Bytes;
use log::error;
use num_traits::FromPrimitive;

use crate::error::{Error, Result};
use crate::params::uci_packets::{
    AppConfigTlv, AppConfigTlvType, Controlee, CountryCode, DeviceConfigId, DeviceConfigTlv,
    ResetConfig, SessionId, SessionType, UpdateMulticastListAction,
};
use uwb_uci_packets::{
    build_session_update_controller_multicast_list_cmd_v1,
    build_session_update_controller_multicast_list_cmd_v2, ControleesV2,
};

/// The enum to represent the UCI commands. The definition of each field should follow UCI spec.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq)]
pub enum UciCommand {
    DeviceReset {
        reset_config: ResetConfig,
    },
    CoreGetDeviceInfo,
    CoreGetCapsInfo,
    CoreSetConfig {
        config_tlvs: Vec<DeviceConfigTlv>,
    },
    CoreGetConfig {
        cfg_id: Vec<DeviceConfigId>,
    },
    SessionInit {
        session_id: SessionId,
        session_type: SessionType,
    },
    SessionDeinit {
        session_id: SessionId,
    },
    SessionSetAppConfig {
        session_id: SessionId,
        config_tlvs: Vec<AppConfigTlv>,
    },
    SessionGetAppConfig {
        session_id: SessionId,
        app_cfg: Vec<AppConfigTlvType>,
    },
    SessionGetCount,
    SessionGetState {
        session_id: SessionId,
    },
    SessionUpdateControllerMulticastList {
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: Vec<Controlee>,
    },
    SessionUpdateControllerMulticastListV2 {
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: ControleesV2,
    },
    SessionUpdateActiveRoundsDtTag {
        session_id: u32,
        ranging_round_indexes: Vec<u8>,
    },
    RangeStart {
        session_id: SessionId,
    },
    RangeStop {
        session_id: SessionId,
    },
    RangeGetRangingCount {
        session_id: SessionId,
    },
    AndroidSetCountryCode {
        country_code: CountryCode,
    },
    AndroidGetPowerStats,
    RawVendorCmd {
        gid: u32,
        oid: u32,
        payload: Vec<u8>,
    },
}

impl TryFrom<UciCommand> for uwb_uci_packets::UciCommandPacket {
    type Error = Error;
    fn try_from(cmd: UciCommand) -> std::result::Result<Self, Self::Error> {
        let packet = match cmd {
            UciCommand::SessionInit { session_id, session_type } => {
                uwb_uci_packets::SessionInitCmdBuilder { session_id, session_type }.build().into()
            }
            UciCommand::SessionDeinit { session_id } => {
                uwb_uci_packets::SessionDeinitCmdBuilder { session_id }.build().into()
            }
            UciCommand::RangeStart { session_id } => {
                uwb_uci_packets::RangeStartCmdBuilder { session_id }.build().into()
            }
            UciCommand::RangeStop { session_id } => {
                uwb_uci_packets::RangeStopCmdBuilder { session_id }.build().into()
            }
            UciCommand::CoreGetDeviceInfo => {
                uwb_uci_packets::GetDeviceInfoCmdBuilder {}.build().into()
            }
            UciCommand::CoreGetCapsInfo => uwb_uci_packets::GetCapsInfoCmdBuilder {}.build().into(),
            UciCommand::SessionGetState { session_id } => {
                uwb_uci_packets::SessionGetStateCmdBuilder { session_id }.build().into()
            }
            UciCommand::SessionUpdateControllerMulticastList { session_id, action, controlees } => {
                build_session_update_controller_multicast_list_cmd_v1(
                    session_id, action, controlees,
                )
                .into()
            }
            UciCommand::SessionUpdateControllerMulticastListV2 {
                session_id,
                action,
                controlees,
            } => build_session_update_controller_multicast_list_cmd_v2(
                session_id, action, controlees,
            )
            .into(),
            UciCommand::CoreSetConfig { config_tlvs } => {
                uwb_uci_packets::SetConfigCmdBuilder { tlvs: config_tlvs }.build().into()
            }
            UciCommand::CoreGetConfig { cfg_id } => uwb_uci_packets::GetConfigCmdBuilder {
                cfg_id: cfg_id.into_iter().map(|item| item as u8).collect(),
            }
            .build()
            .into(),
            UciCommand::SessionSetAppConfig { session_id, config_tlvs } => {
                uwb_uci_packets::SessionSetAppConfigCmdBuilder {
                    session_id,
                    tlvs: config_tlvs.into_iter().map(|tlv| tlv.into_inner()).collect(),
                }
                .build()
                .into()
            }
            UciCommand::SessionGetAppConfig { session_id, app_cfg } => {
                uwb_uci_packets::SessionGetAppConfigCmdBuilder {
                    session_id,
                    app_cfg: app_cfg.into_iter().map(|item| item as u8).collect(),
                }
                .build()
                .into()
            }

            UciCommand::SessionUpdateActiveRoundsDtTag { session_id, ranging_round_indexes } => {
                uwb_uci_packets::SessionUpdateActiveRoundsDtTagCmdBuilder {
                    session_id,
                    ranging_round_indexes,
                }
                .build()
                .into()
            }

            UciCommand::AndroidGetPowerStats => {
                uwb_uci_packets::AndroidGetPowerStatsCmdBuilder {}.build().into()
            }
            UciCommand::RawVendorCmd { gid, oid, payload } => {
                build_uci_vendor_cmd_packet(gid, oid, payload)?
            }
            UciCommand::SessionGetCount => {
                uwb_uci_packets::SessionGetCountCmdBuilder {}.build().into()
            }
            UciCommand::AndroidSetCountryCode { country_code } => {
                uwb_uci_packets::AndroidSetCountryCodeCmdBuilder {
                    country_code: country_code.into(),
                }
                .build()
                .into()
            }
            UciCommand::DeviceReset { reset_config } => {
                uwb_uci_packets::DeviceResetCmdBuilder { reset_config }.build().into()
            }
            UciCommand::RangeGetRangingCount { session_id } => {
                uwb_uci_packets::RangeGetRangingCountCmdBuilder { session_id }.build().into()
            }
        };
        Ok(packet)
    }
}

fn build_uci_vendor_cmd_packet(
    gid: u32,
    oid: u32,
    payload: Vec<u8>,
) -> Result<uwb_uci_packets::UciCommandPacket> {
    use uwb_uci_packets::GroupId;
    let group_id = GroupId::from_u32(gid).ok_or_else(|| {
        error!("Invalid GroupId: {}", gid);
        Error::BadParameters
    })?;
    let payload = if payload.is_empty() { None } else { Some(Bytes::from(payload)) };
    let opcode = oid.try_into().map_err(|_| {
        error!("Invalid opcod: {}", oid);
        Error::BadParameters
    })?;
    let packet = match group_id {
        GroupId::VendorReserved9 => {
            uwb_uci_packets::UciVendor_9_CommandBuilder { opcode, payload }.build().into()
        }
        GroupId::VendorReservedA => {
            uwb_uci_packets::UciVendor_A_CommandBuilder { opcode, payload }.build().into()
        }
        GroupId::VendorReservedB => {
            uwb_uci_packets::UciVendor_B_CommandBuilder { opcode, payload }.build().into()
        }
        GroupId::VendorReservedE => {
            uwb_uci_packets::UciVendor_E_CommandBuilder { opcode, payload }.build().into()
        }
        GroupId::VendorReservedF => {
            uwb_uci_packets::UciVendor_F_CommandBuilder { opcode, payload }.build().into()
        }
        _ => {
            error!("Invalid vendor gid {:?}", gid);
            return Err(Error::BadParameters);
        }
    };
    Ok(packet)
}
