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
use bytes::Bytes;
use log::error;
use num_traits::FromPrimitive;
use uwb_uci_packets::{
    AndroidSetCountryCodeCmdBuilder, AppConfigTlv, Controlee, GroupId, SessionInitCmdBuilder,
    SessionSetAppConfigCmdBuilder, SessionType, SessionUpdateControllerMulticastListCmdBuilder,
    UciCommandPacket, UciVendor_9_CommandBuilder, UciVendor_A_CommandBuilder,
    UciVendor_B_CommandBuilder, UciVendor_C_CommandBuilder, UciVendor_F_CommandBuilder,
};

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
    address_list: &[i16],
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
    mut app_configs: &[u8],
) -> Result<SessionSetAppConfigCmdBuilder, UwbErr> {
    let mut tlvs = Vec::new();
    for _ in 0..no_of_params {
        let tlv = AppConfigTlv::parse(app_configs)?;
        app_configs = &app_configs[tlv.v.len() + 2..];
        tlvs.push(tlv);
    }
    Ok(SessionSetAppConfigCmdBuilder { session_id, tlvs })
}

pub fn build_uci_vendor_cmd_packet(
    gid: u32,
    oid: u32,
    payload: Vec<u8>,
) -> Result<UciCommandPacket, UwbErr> {
    use GroupId::*;
    let group_id: GroupId = GroupId::from_u32(gid).expect("invalid vendor gid");
    let payload = match payload.is_empty() {
        true => Some(Bytes::from(payload)),
        false => None,
    };
    let opcode: u8 = oid.try_into().expect("invalid vendor oid");
    let packet: UciCommandPacket = match group_id {
        VendorReserved9 => UciVendor_9_CommandBuilder { opcode, payload }.build().into(),
        VendorReservedA => UciVendor_A_CommandBuilder { opcode, payload }.build().into(),
        VendorReservedB => UciVendor_B_CommandBuilder { opcode, payload }.build().into(),
        VendorReservedC => UciVendor_C_CommandBuilder { opcode, payload }.build().into(),
        VendorReservedF => UciVendor_F_CommandBuilder { opcode, payload }.build().into(),
        _ => {
            error!("Invalid vendor gid {:?}", gid);
            return Err(UwbErr::InvalidArgs);
        }
    };
    Ok(packet)
}
