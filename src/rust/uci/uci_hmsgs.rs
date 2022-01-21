/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::uci::UwbErr;
use log::info;
use num_traits::cast::FromPrimitive;
use uwb_uci_packets::{
    AndroidSetCountryCodeCmdBuilder, AppConfigTlv, Controlee, CoreOpCode, DeviceConfigStatus,
    DeviceConfigTLV, DeviceResetCmdBuilder, GetCapsInfoCmdBuilder, GetDeviceInfoCmdBuilder,
    GetDeviceInfoCmdPacket, ResetConfig, SessionInitCmdBuilder, SessionSetAppConfigCmdBuilder,
    SessionType, SessionUpdateControllerMulticastListCmdBuilder, SetConfigCmdBuilder,
    SetConfigRspBuilder, StatusCode, UciCommandPacket,
};

fn uci_ucif_send_cmd() -> StatusCode {
    let resp = uwb_ucif_check_cmd_queue(GetDeviceInfoCmdBuilder {});
    StatusCode::UciStatusOk
}

pub fn build_session_init_cmd(session_id: u32, session_type: u8) -> SessionInitCmdBuilder {
    SessionInitCmdBuilder {
        session_id,
        session_type: SessionType::from_u8(session_type).expect("invalid session type"),
    }
}

pub fn build_set_country_code_cmd(code: &[u8]) -> AndroidSetCountryCodeCmdBuilder {
    AndroidSetCountryCodeCmdBuilder { country_code: code.try_into().expect("invalid country code") }
}

pub fn build_multicast_list_update_cmd(
    session_id: u32,
    action: u8,
    no_of_controlee: u8,
    address_list: &[u8],
    sub_session_id_list: &[i32],
) -> SessionUpdateControllerMulticastListCmdBuilder {
    let mut controlees = Vec::new();
    for i in 0..no_of_controlee {
        controlees.push(Controlee {
            short_address: address_list[i as usize] as u16,
            subsession_id: sub_session_id_list[i as usize] as u32,
        });
    }
    SessionUpdateControllerMulticastListCmdBuilder { session_id, action, controlees }
}

pub fn build_set_app_config_cmd(
    session_id: u32,
    no_of_params: u32,
    app_config_param_len: u32,
    mut app_configs: &[u8],
) -> Result<SessionSetAppConfigCmdBuilder, UwbErr> {
    let mut tlvs = Vec::new();
    for i in 0..no_of_params {
        let tlv = AppConfigTlv::parse(app_configs)?;
        app_configs = &app_configs[tlv.v.len() + 2..];
        tlvs.push(tlv);
    }
    Ok(SessionSetAppConfigCmdBuilder { session_id, tlvs })
}

fn build_caps_info_cmd() -> GetCapsInfoCmdBuilder {
    GetCapsInfoCmdBuilder {}
}

fn set_config_cmd(tlvs: Vec<DeviceConfigTLV>) -> SetConfigCmdBuilder {
    SetConfigCmdBuilder { tlvs }
}

fn build_device_reset_cmd(reset_config: ResetConfig) -> DeviceResetCmdBuilder {
    DeviceResetCmdBuilder { reset_config }
}

fn build_set_config_rsp(
    status: StatusCode,
    cfg_status: Vec<DeviceConfigStatus>,
) -> SetConfigRspBuilder {
    SetConfigRspBuilder { status, cfg_status }
}

fn uwb_ucif_check_cmd_queue(p_message: GetDeviceInfoCmdBuilder) -> StatusCode {
    // TODO : Hook to command queue
    return StatusCode::UciStatusOk;
}
