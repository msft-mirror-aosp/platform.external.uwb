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

use crate::error::{Error, Result};
use crate::params::uci_packets::{
    AppConfigTlv, CapTlv, CoreSetConfigResponse, DeviceConfigTlv, GetDeviceInfoResponse,
    PowerStats, RawUciMessage, SessionState, SessionUpdateActiveRoundsDtTagResponse,
    SetAppConfigResponse, StatusCode, UciControlPacketPacket,
};
use crate::uci::error::status_code_to_result;

#[derive(Debug)]
pub(super) enum UciResponse {
    SetLoggerMode,
    SetNotification,
    OpenHal,
    CloseHal,
    DeviceReset(Result<()>),
    CoreGetDeviceInfo(Result<GetDeviceInfoResponse>),
    CoreGetCapsInfo(Result<Vec<CapTlv>>),
    CoreSetConfig(CoreSetConfigResponse),
    CoreGetConfig(Result<Vec<DeviceConfigTlv>>),
    SessionInit(Result<()>),
    SessionDeinit(Result<()>),
    SessionSetAppConfig(SetAppConfigResponse),
    SessionGetAppConfig(Result<Vec<AppConfigTlv>>),
    SessionGetCount(Result<u8>),
    SessionGetState(Result<SessionState>),
    SessionUpdateControllerMulticastList(Result<()>),
    SessionUpdateActiveRoundsDtTag(Result<SessionUpdateActiveRoundsDtTagResponse>),
    RangeStart(Result<()>),
    RangeStop(Result<()>),
    RangeGetRangingCount(Result<usize>),
    AndroidSetCountryCode(Result<()>),
    AndroidGetPowerStats(Result<PowerStats>),
    RawUciCmd(Result<RawUciMessage>),
}

impl UciResponse {
    pub fn need_retry(&self) -> bool {
        match self {
            Self::SetNotification | Self::OpenHal | Self::CloseHal | Self::SetLoggerMode => false,
            Self::DeviceReset(result) => Self::matches_result_retry(result),
            Self::CoreGetDeviceInfo(result) => Self::matches_result_retry(result),
            Self::CoreGetCapsInfo(result) => Self::matches_result_retry(result),
            Self::CoreGetConfig(result) => Self::matches_result_retry(result),
            Self::SessionInit(result) => Self::matches_result_retry(result),
            Self::SessionDeinit(result) => Self::matches_result_retry(result),
            Self::SessionGetAppConfig(result) => Self::matches_result_retry(result),
            Self::SessionGetCount(result) => Self::matches_result_retry(result),
            Self::SessionGetState(result) => Self::matches_result_retry(result),
            Self::SessionUpdateControllerMulticastList(result) => {
                Self::matches_result_retry(result)
            }
            Self::SessionUpdateActiveRoundsDtTag(result) => Self::matches_result_retry(result),
            Self::RangeStart(result) => Self::matches_result_retry(result),
            Self::RangeStop(result) => Self::matches_result_retry(result),
            Self::RangeGetRangingCount(result) => Self::matches_result_retry(result),
            Self::AndroidSetCountryCode(result) => Self::matches_result_retry(result),
            Self::AndroidGetPowerStats(result) => Self::matches_result_retry(result),
            Self::RawUciCmd(result) => Self::matches_result_retry(result),

            Self::CoreSetConfig(resp) => Self::matches_status_retry(&resp.status),
            Self::SessionSetAppConfig(resp) => Self::matches_status_retry(&resp.status),
        }
    }

    fn matches_result_retry<T>(result: &Result<T>) -> bool {
        matches!(result, Err(Error::CommandRetry))
    }
    fn matches_status_retry(status: &StatusCode) -> bool {
        matches!(status, StatusCode::UciStatusCommandRetry)
    }
}

impl TryFrom<uwb_uci_packets::UciResponsePacket> for UciResponse {
    type Error = Error;
    fn try_from(evt: uwb_uci_packets::UciResponsePacket) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::UciResponseChild;
        match evt.specialize() {
            UciResponseChild::CoreResponse(evt) => evt.try_into(),
            UciResponseChild::SessionResponse(evt) => evt.try_into(),
            UciResponseChild::RangingResponse(evt) => evt.try_into(),
            UciResponseChild::AndroidResponse(evt) => evt.try_into(),
            UciResponseChild::UciVendor_9_Response(evt) => raw_response(evt.into()),
            UciResponseChild::UciVendor_A_Response(evt) => raw_response(evt.into()),
            UciResponseChild::UciVendor_B_Response(evt) => raw_response(evt.into()),
            UciResponseChild::UciVendor_E_Response(evt) => raw_response(evt.into()),
            UciResponseChild::UciVendor_F_Response(evt) => raw_response(evt.into()),
            _ => Err(Error::Unknown),
        }
    }
}

impl TryFrom<uwb_uci_packets::CoreResponsePacket> for UciResponse {
    type Error = Error;
    fn try_from(
        evt: uwb_uci_packets::CoreResponsePacket,
    ) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::CoreResponseChild;
        match evt.specialize() {
            CoreResponseChild::GetDeviceInfoRsp(evt) => Ok(UciResponse::CoreGetDeviceInfo(
                status_code_to_result(evt.get_status()).map(|_| GetDeviceInfoResponse {
                    uci_version: evt.get_uci_version(),
                    mac_version: evt.get_mac_version(),
                    phy_version: evt.get_phy_version(),
                    uci_test_version: evt.get_uci_test_version(),
                    vendor_spec_info: evt.get_vendor_spec_info().clone(),
                }),
            )),
            CoreResponseChild::GetCapsInfoRsp(evt) => Ok(UciResponse::CoreGetCapsInfo(
                status_code_to_result(evt.get_status()).map(|_| evt.get_tlvs().clone()),
            )),
            CoreResponseChild::DeviceResetRsp(evt) => {
                Ok(UciResponse::DeviceReset(status_code_to_result(evt.get_status())))
            }
            CoreResponseChild::SetConfigRsp(evt) => {
                Ok(UciResponse::CoreSetConfig(CoreSetConfigResponse {
                    status: evt.get_status(),
                    config_status: evt.get_cfg_status().clone(),
                }))
            }

            CoreResponseChild::GetConfigRsp(evt) => Ok(UciResponse::CoreGetConfig(
                status_code_to_result(evt.get_status()).map(|_| evt.get_tlvs().clone()),
            )),
            _ => Err(Error::Unknown),
        }
    }
}

impl TryFrom<uwb_uci_packets::SessionResponsePacket> for UciResponse {
    type Error = Error;
    fn try_from(
        evt: uwb_uci_packets::SessionResponsePacket,
    ) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::SessionResponseChild;
        match evt.specialize() {
            SessionResponseChild::SessionInitRsp(evt) => {
                Ok(UciResponse::SessionInit(status_code_to_result(evt.get_status())))
            }
            SessionResponseChild::SessionDeinitRsp(evt) => {
                Ok(UciResponse::SessionDeinit(status_code_to_result(evt.get_status())))
            }
            SessionResponseChild::SessionGetCountRsp(evt) => Ok(UciResponse::SessionGetCount(
                status_code_to_result(evt.get_status()).map(|_| evt.get_session_count()),
            )),
            SessionResponseChild::SessionGetStateRsp(evt) => Ok(UciResponse::SessionGetState(
                status_code_to_result(evt.get_status()).map(|_| evt.get_session_state()),
            )),
            SessionResponseChild::SessionUpdateControllerMulticastListRsp(evt) => {
                Ok(UciResponse::SessionUpdateControllerMulticastList(status_code_to_result(
                    evt.get_status(),
                )))
            }
            SessionResponseChild::SessionUpdateActiveRoundsDtTagRsp(evt) => {
                Ok(UciResponse::SessionUpdateActiveRoundsDtTag(Ok(
                    SessionUpdateActiveRoundsDtTagResponse {
                        status: evt.get_status(),
                        ranging_round_indexes: evt.get_ranging_round_indexes().to_vec(),
                    },
                )))
            }
            SessionResponseChild::SessionSetAppConfigRsp(evt) => {
                Ok(UciResponse::SessionSetAppConfig(SetAppConfigResponse {
                    status: evt.get_status(),
                    config_status: evt.get_cfg_status().clone(),
                }))
            }
            SessionResponseChild::SessionGetAppConfigRsp(evt) => {
                Ok(UciResponse::SessionGetAppConfig(
                    status_code_to_result(evt.get_status()).map(|_| {
                        evt.get_tlvs().clone().into_iter().map(|tlv| tlv.into()).collect()
                    }),
                ))
            }
            _ => Err(Error::Unknown),
        }
    }
}

impl TryFrom<uwb_uci_packets::RangingResponsePacket> for UciResponse {
    type Error = Error;
    fn try_from(
        evt: uwb_uci_packets::RangingResponsePacket,
    ) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::RangingResponseChild;
        match evt.specialize() {
            RangingResponseChild::RangeStartRsp(evt) => {
                Ok(UciResponse::RangeStart(status_code_to_result(evt.get_status())))
            }
            RangingResponseChild::RangeStopRsp(evt) => {
                Ok(UciResponse::RangeStop(status_code_to_result(evt.get_status())))
            }
            RangingResponseChild::RangeGetRangingCountRsp(evt) => {
                Ok(UciResponse::RangeGetRangingCount(
                    status_code_to_result(evt.get_status()).map(|_| evt.get_count() as usize),
                ))
            }
            _ => Err(Error::Unknown),
        }
    }
}

impl TryFrom<uwb_uci_packets::AndroidResponsePacket> for UciResponse {
    type Error = Error;
    fn try_from(
        evt: uwb_uci_packets::AndroidResponsePacket,
    ) -> std::result::Result<Self, Self::Error> {
        use uwb_uci_packets::AndroidResponseChild;
        match evt.specialize() {
            AndroidResponseChild::AndroidSetCountryCodeRsp(evt) => {
                Ok(UciResponse::AndroidSetCountryCode(status_code_to_result(evt.get_status())))
            }
            AndroidResponseChild::AndroidGetPowerStatsRsp(evt) => {
                Ok(UciResponse::AndroidGetPowerStats(
                    status_code_to_result(evt.get_stats().status).map(|_| evt.get_stats().clone()),
                ))
            }
            _ => Err(Error::Unknown),
        }
    }
}

fn raw_response(evt: uwb_uci_packets::UciResponsePacket) -> Result<UciResponse> {
    let gid = evt.get_group_id().to_u32().ok_or(Error::Unknown)?;
    let oid = evt.get_opcode().to_u32().ok_or(Error::Unknown)?;
    let packet: UciControlPacketPacket = evt.into();
    Ok(UciResponse::RawUciCmd(Ok(RawUciMessage { gid, oid, payload: packet.to_raw_payload() })))
}
