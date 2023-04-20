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

use std::convert::TryFrom;

use bytes::Bytes;
use log::error;

use crate::error::{Error, Result};
use crate::params::uci_packets::{
    AppConfigTlv, AppConfigTlvType, Controlees, CountryCode, DeviceConfigId, DeviceConfigTlv,
    ResetConfig, SessionId, SessionType, UpdateMulticastListAction,
};
use uwb_uci_packets::{build_session_update_controller_multicast_list_cmd, GroupId, MessageType};

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
        controlees: Controlees,
    },
    SessionUpdateActiveRoundsDtTag {
        session_id: u32,
        ranging_round_indexes: Vec<u8>,
    },
    SessionQueryMaxDataSize {
        session_id: SessionId,
    },
    SessionStart {
        session_id: SessionId,
    },
    SessionStop {
        session_id: SessionId,
    },
    SessionGetRangingCount {
        session_id: SessionId,
    },
    AndroidSetCountryCode {
        country_code: CountryCode,
    },
    AndroidGetPowerStats,
    RawUciCmd {
        mt: u32,
        gid: u32,
        oid: u32,
        payload: Vec<u8>,
    },
}

impl TryFrom<UciCommand> for uwb_uci_packets::UciControlPacket {
    type Error = Error;
    fn try_from(cmd: UciCommand) -> std::result::Result<Self, Self::Error> {
        let packet = match cmd {
            // UCI Session Config Commands
            UciCommand::SessionInit { session_id, session_type } => {
                uwb_uci_packets::SessionInitCmdBuilder { session_id, session_type }.build().into()
            }
            UciCommand::SessionDeinit { session_id } => {
                uwb_uci_packets::SessionDeinitCmdBuilder { session_id }.build().into()
            }
            UciCommand::CoreGetDeviceInfo => {
                uwb_uci_packets::GetDeviceInfoCmdBuilder {}.build().into()
            }
            UciCommand::CoreGetCapsInfo => uwb_uci_packets::GetCapsInfoCmdBuilder {}.build().into(),
            UciCommand::SessionGetState { session_id } => {
                uwb_uci_packets::SessionGetStateCmdBuilder { session_id }.build().into()
            }
            UciCommand::SessionUpdateControllerMulticastList { session_id, action, controlees } => {
                build_session_update_controller_multicast_list_cmd(session_id, action, controlees)
                    .map_err(|_| Error::BadParameters)?
                    .into()
            }
            UciCommand::CoreSetConfig { config_tlvs } => {
                uwb_uci_packets::SetConfigCmdBuilder { tlvs: config_tlvs }.build().into()
            }
            UciCommand::CoreGetConfig { cfg_id } => uwb_uci_packets::GetConfigCmdBuilder {
                cfg_id: cfg_id.into_iter().map(u8::from).collect(),
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
                    app_cfg: app_cfg.into_iter().map(u8::from).collect(),
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
            UciCommand::RawUciCmd { mt, gid, oid, payload } => {
                build_raw_uci_cmd_packet(mt, gid, oid, payload)?
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
            // UCI Session Control Commands
            UciCommand::SessionStart { session_id } => {
                uwb_uci_packets::SessionStartCmdBuilder { session_id }.build().into()
            }
            UciCommand::SessionStop { session_id } => {
                uwb_uci_packets::SessionStopCmdBuilder { session_id }.build().into()
            }
            UciCommand::SessionGetRangingCount { session_id } => {
                uwb_uci_packets::SessionGetRangingCountCmdBuilder { session_id }.build().into()
            }
            UciCommand::SessionQueryMaxDataSize { session_id } => {
                uwb_uci_packets::SessionQueryMaxDataSizeCmdBuilder { session_id }.build().into()
            }
        };
        Ok(packet)
    }
}

fn build_raw_uci_cmd_packet(
    mt: u32,
    gid: u32,
    oid: u32,
    payload: Vec<u8>,
) -> Result<uwb_uci_packets::UciControlPacket> {
    let group_id = u8::try_from(gid).or(Err(0)).and_then(GroupId::try_from).map_err(|_| {
        error!("Invalid GroupId: {}", gid);
        Error::BadParameters
    })?;
    let payload = if payload.is_empty() { None } else { Some(Bytes::from(payload)) };
    let opcode = u8::try_from(oid).map_err(|_| {
        error!("Invalid opcod: {}", oid);
        Error::BadParameters
    })?;
    let message_type =
        u8::try_from(mt).or(Err(0)).and_then(MessageType::try_from).map_err(|_| {
            error!("Invalid MessageType: {}", mt);
            Error::BadParameters
        })?;
    match uwb_uci_packets::build_uci_control_packet(message_type, group_id, opcode, payload) {
        Some(cmd) => Ok(cmd),
        None => Err(Error::BadParameters),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_raw_uci_cmd() {
        let payload = vec![0x01, 0x02];
        let cmd_packet = build_raw_uci_cmd_packet(1, 9, 0, payload.clone()).unwrap();
        assert_eq!(payload, cmd_packet.to_raw_payload());
    }

    #[test]
    fn test_convert_uci_cmd_to_packets() {
        let mut cmd = UciCommand::DeviceReset { reset_config: ResetConfig::UwbsReset };
        let mut packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(
            packet,
            uwb_uci_packets::DeviceResetCmdBuilder { reset_config: ResetConfig::UwbsReset }
                .build()
                .into()
        );

        cmd = UciCommand::CoreGetDeviceInfo {};
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(packet, uwb_uci_packets::GetDeviceInfoCmdBuilder {}.build().into());

        cmd = UciCommand::CoreGetCapsInfo {};
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(packet, uwb_uci_packets::GetCapsInfoCmdBuilder {}.build().into());

        let device_cfg_tlv = DeviceConfigTlv { cfg_id: DeviceConfigId::DeviceState, v: vec![0] };
        cmd = UciCommand::CoreSetConfig { config_tlvs: vec![device_cfg_tlv.clone()] };
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(
            packet,
            uwb_uci_packets::SetConfigCmdBuilder { tlvs: vec![device_cfg_tlv] }.build().into()
        );

        cmd = UciCommand::CoreGetConfig { cfg_id: vec![DeviceConfigId::DeviceState] };
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(packet, uwb_uci_packets::GetConfigCmdBuilder { cfg_id: vec![0] }.build().into());

        cmd = UciCommand::SessionInit {
            session_id: 1,
            session_type: SessionType::FiraRangingSession,
        };
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(
            packet,
            uwb_uci_packets::SessionInitCmdBuilder {
                session_id: 1,
                session_type: SessionType::FiraRangingSession
            }
            .build()
            .into()
        );

        cmd = UciCommand::SessionDeinit { session_id: 1 };
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(
            packet,
            uwb_uci_packets::SessionDeinitCmdBuilder { session_id: 1 }.build().into()
        );

        cmd = UciCommand::SessionSetAppConfig { session_id: 1, config_tlvs: vec![] };
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(
            packet,
            uwb_uci_packets::SessionSetAppConfigCmdBuilder { session_id: 1, tlvs: vec![] }
                .build()
                .into()
        );

        cmd = UciCommand::SessionGetAppConfig { session_id: 1, app_cfg: vec![] };
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(
            packet,
            uwb_uci_packets::SessionGetAppConfigCmdBuilder { session_id: 1, app_cfg: vec![] }
                .build()
                .into()
        );

        cmd = UciCommand::SessionGetCount {};
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(packet, uwb_uci_packets::SessionGetCountCmdBuilder {}.build().into());

        cmd = UciCommand::SessionGetState { session_id: 1 };
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(
            packet,
            uwb_uci_packets::SessionGetStateCmdBuilder { session_id: 1 }.build().into()
        );

        cmd = UciCommand::SessionUpdateControllerMulticastList {
            session_id: 1,
            action: UpdateMulticastListAction::AddControlee,
            controlees: Controlees::NoSessionKey(vec![]),
        };
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(
            packet,
            build_session_update_controller_multicast_list_cmd(
                1,
                UpdateMulticastListAction::AddControlee,
                Controlees::NoSessionKey(vec![])
            )
            .map_err(|_| Error::BadParameters)
            .unwrap()
            .into()
        );

        cmd = UciCommand::SessionUpdateActiveRoundsDtTag {
            session_id: 1,
            ranging_round_indexes: vec![0],
        };
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(
            packet,
            uwb_uci_packets::SessionUpdateActiveRoundsDtTagCmdBuilder {
                session_id: 1,
                ranging_round_indexes: vec![0]
            }
            .build()
            .into()
        );

        cmd = UciCommand::SessionQueryMaxDataSize { session_id: 1 };
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(
            packet,
            uwb_uci_packets::SessionQueryMaxDataSizeCmdBuilder { session_id: 1 }.build().into()
        );

        cmd = UciCommand::SessionStart { session_id: 1 };
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(
            packet,
            uwb_uci_packets::SessionStartCmdBuilder { session_id: 1 }.build().into()
        );

        cmd = UciCommand::SessionStop { session_id: 1 };
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(packet, uwb_uci_packets::SessionStopCmdBuilder { session_id: 1 }.build().into());

        cmd = UciCommand::SessionGetRangingCount { session_id: 1 };
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(
            packet,
            uwb_uci_packets::SessionGetRangingCountCmdBuilder { session_id: 1 }.build().into()
        );

        let country_code: [u8; 2] = [85, 83];
        cmd = UciCommand::AndroidSetCountryCode {
            country_code: CountryCode::new(&country_code).unwrap(),
        };
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd.clone()).unwrap();
        assert_eq!(
            packet,
            uwb_uci_packets::AndroidSetCountryCodeCmdBuilder { country_code }.build().into()
        );

        cmd = UciCommand::AndroidGetPowerStats {};
        packet = uwb_uci_packets::UciControlPacket::try_from(cmd).unwrap();
        assert_eq!(packet, uwb_uci_packets::AndroidGetPowerStatsCmdBuilder {}.build().into());
    }
}
