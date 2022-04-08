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

use std::collections::VecDeque;
use std::iter::zip;

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::uci::error::{UciError, UciResult};
use crate::uci::notification::UciNotification;
use crate::uci::params::{
    AppConfigTlv, AppConfigTlvType, CapTlv, Controlee, CoreSetConfigResponse, CountryCode,
    DeviceConfigId, DeviceConfigTlv, GetDeviceInfoResponse, PowerStats, RawVendorMessage,
    ResetConfig, SessionId, SessionState, SessionType, SetAppConfigResponse,
    UpdateMulticastListAction,
};
use crate::uci::uci_manager::UciManager;

use crate::uci::params::app_config_tlv_eq;
use crate::uci::params::device_config_tlv_eq;

#[derive(Default)]
pub(crate) struct MockUciManager {
    expected_calls: VecDeque<ExpectedCall>,
    notf_sender: Option<mpsc::UnboundedSender<UciNotification>>,
}

impl Drop for MockUciManager {
    fn drop(&mut self) {
        assert!(self.expected_calls.is_empty());
    }
}

impl MockUciManager {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn expect_open_hal(&mut self, notfs: Vec<UciNotification>, out: UciResult<()>) {
        self.expected_calls.push_back(ExpectedCall::OpenHal { notfs, out });
    }

    pub fn expect_close_hal(&mut self, out: UciResult<()>) {
        self.expected_calls.push_back(ExpectedCall::CloseHal { out });
    }

    pub fn expect_device_reset(&mut self, expected_reset_config: ResetConfig, out: UciResult<()>) {
        self.expected_calls.push_back(ExpectedCall::DeviceReset { expected_reset_config, out });
    }

    pub fn expect_core_get_device_info(&mut self, out: UciResult<GetDeviceInfoResponse>) {
        self.expected_calls.push_back(ExpectedCall::CoreGetDeviceInfo { out });
    }

    pub fn expect_core_get_caps_info(&mut self, out: UciResult<Vec<CapTlv>>) {
        self.expected_calls.push_back(ExpectedCall::CoreGetCapsInfo { out });
    }

    pub fn expect_core_set_config(
        &mut self,
        expected_config_tlvs: Vec<DeviceConfigTlv>,
        out: UciResult<CoreSetConfigResponse>,
    ) {
        self.expected_calls.push_back(ExpectedCall::CoreSetConfig { expected_config_tlvs, out });
    }

    pub fn expect_core_get_config(
        &mut self,
        expected_config_ids: Vec<DeviceConfigId>,
        out: UciResult<Vec<DeviceConfigTlv>>,
    ) {
        self.expected_calls.push_back(ExpectedCall::CoreGetConfig { expected_config_ids, out });
    }

    pub fn expect_session_init(
        &mut self,
        expected_session_id: SessionId,
        expected_session_type: SessionType,
        out: UciResult<()>,
    ) {
        self.expected_calls.push_back(ExpectedCall::SessionInit {
            expected_session_id,
            expected_session_type,
            out,
        });
    }

    pub fn expect_session_deinit(&mut self, expected_session_id: SessionId, out: UciResult<()>) {
        self.expected_calls.push_back(ExpectedCall::SessionDeinit { expected_session_id, out });
    }

    pub fn expect_session_set_app_config(
        &mut self,
        expected_session_id: SessionId,
        expected_config_tlvs: Vec<AppConfigTlv>,
        out: UciResult<SetAppConfigResponse>,
    ) {
        self.expected_calls.push_back(ExpectedCall::SessionSetAppConfig {
            expected_session_id,
            expected_config_tlvs,
            out,
        });
    }

    pub fn expect_session_get_app_config(
        &mut self,
        expected_session_id: SessionId,
        expected_config_ids: Vec<AppConfigTlvType>,
        out: UciResult<Vec<AppConfigTlv>>,
    ) {
        self.expected_calls.push_back(ExpectedCall::SessionGetAppConfig {
            expected_session_id,
            expected_config_ids,
            out,
        });
    }

    pub fn expect_session_get_count(&mut self, out: UciResult<usize>) {
        self.expected_calls.push_back(ExpectedCall::SessionGetCount { out });
    }

    pub fn expect_session_get_state(
        &mut self,
        expected_session_id: SessionId,
        out: UciResult<SessionState>,
    ) {
        self.expected_calls.push_back(ExpectedCall::SessionGetState { expected_session_id, out });
    }

    pub fn expect_session_update_controller_multicast_list(
        &mut self,
        expected_session_id: SessionId,
        expected_action: UpdateMulticastListAction,
        expected_controlees: Vec<Controlee>,
        out: UciResult<()>,
    ) {
        self.expected_calls.push_back(ExpectedCall::SessionUpdateControllerMulticastList {
            expected_session_id,
            expected_action,
            expected_controlees,
            out,
        });
    }

    pub fn expect_range_start(&mut self, expected_session_id: SessionId, out: UciResult<()>) {
        self.expected_calls.push_back(ExpectedCall::RangeStart { expected_session_id, out });
    }

    pub fn expect_range_stop(&mut self, expected_session_id: SessionId, out: UciResult<()>) {
        self.expected_calls.push_back(ExpectedCall::RangeStop { expected_session_id, out });
    }

    pub fn expect_range_get_ranging_count(
        &mut self,
        expected_session_id: SessionId,
        out: UciResult<usize>,
    ) {
        self.expected_calls
            .push_back(ExpectedCall::RangeGetRangingCount { expected_session_id, out });
    }

    pub fn expect_android_set_country_code(
        &mut self,
        expected_country_code: CountryCode,
        out: UciResult<()>,
    ) {
        self.expected_calls
            .push_back(ExpectedCall::AndroidSetCountryCode { expected_country_code, out });
    }

    pub fn expect_android_get_power_stats(&mut self, out: UciResult<PowerStats>) {
        self.expected_calls.push_back(ExpectedCall::AndroidGetPowerStats { out });
    }

    pub fn expect_raw_vendor_cmd(
        &mut self,
        expected_gid: u32,
        expected_oid: u32,
        expected_payload: Vec<u8>,
        out: UciResult<RawVendorMessage>,
    ) {
        self.expected_calls.push_back(ExpectedCall::RawVendorCmd {
            expected_gid,
            expected_oid,
            expected_payload,
            out,
        });
    }
}

#[async_trait]
impl UciManager for MockUciManager {
    async fn open_hal(
        &mut self,
        notf_sender: mpsc::UnboundedSender<UciNotification>,
    ) -> UciResult<()> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::OpenHal { notfs, out }) => {
                self.notf_sender = Some(notf_sender);
                for notf in notfs.into_iter() {
                    let _ = self.notf_sender.as_mut().unwrap().send(notf);
                }
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn close_hal(&mut self) -> UciResult<()> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::CloseHal { out }) => out,
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn device_reset(&mut self, reset_config: ResetConfig) -> UciResult<()> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::DeviceReset { expected_reset_config, out })
                if expected_reset_config == reset_config =>
            {
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn core_get_device_info(&mut self) -> UciResult<GetDeviceInfoResponse> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::CoreGetDeviceInfo { out }) => out,
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn core_get_caps_info(&mut self) -> UciResult<Vec<CapTlv>> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::CoreGetCapsInfo { out }) => out,
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn core_set_config(
        &mut self,
        config_tlvs: Vec<DeviceConfigTlv>,
    ) -> UciResult<CoreSetConfigResponse> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::CoreSetConfig { expected_config_tlvs, out })
                if zip(&expected_config_tlvs, &config_tlvs)
                    .all(|(a, b)| device_config_tlv_eq(a, b)) =>
            {
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn core_get_config(
        &mut self,
        config_ids: Vec<DeviceConfigId>,
    ) -> UciResult<Vec<DeviceConfigTlv>> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::CoreGetConfig { expected_config_ids, out })
                if expected_config_ids == config_ids =>
            {
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn session_init(
        &mut self,
        session_id: SessionId,
        session_type: SessionType,
    ) -> UciResult<()> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::SessionInit { expected_session_id, expected_session_type, out })
                if expected_session_id == session_id && expected_session_type == session_type =>
            {
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn session_deinit(&mut self, session_id: SessionId) -> UciResult<()> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::SessionDeinit { expected_session_id, out })
                if expected_session_id == session_id =>
            {
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn session_set_app_config(
        &mut self,
        session_id: SessionId,
        config_tlvs: Vec<AppConfigTlv>,
    ) -> UciResult<SetAppConfigResponse> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::SessionSetAppConfig {
                expected_session_id,
                expected_config_tlvs,
                out,
            }) if expected_session_id == session_id
                && zip(&expected_config_tlvs, &config_tlvs)
                    .all(|(a, b)| app_config_tlv_eq(a, b)) =>
            {
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn session_get_app_config(
        &mut self,
        session_id: SessionId,
        config_ids: Vec<AppConfigTlvType>,
    ) -> UciResult<Vec<AppConfigTlv>> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::SessionGetAppConfig {
                expected_session_id,
                expected_config_ids,
                out,
            }) if expected_session_id == session_id && expected_config_ids == config_ids => out,
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn session_get_count(&mut self) -> UciResult<usize> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::SessionGetCount { out }) => out,
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn session_get_state(&mut self, session_id: SessionId) -> UciResult<SessionState> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::SessionGetState { expected_session_id, out })
                if expected_session_id == session_id =>
            {
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn session_update_controller_multicast_list(
        &mut self,
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: Vec<Controlee>,
    ) -> UciResult<()> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::SessionUpdateControllerMulticastList {
                expected_session_id,
                expected_action,
                expected_controlees,
                out,
            }) if expected_session_id == session_id
                && expected_action == action
                && zip(&expected_controlees, &controlees).all(|(a, b)| {
                    a.short_address == b.short_address && a.subsession_id == b.subsession_id
                }) =>
            {
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn range_start(&mut self, session_id: SessionId) -> UciResult<()> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::RangeStart { expected_session_id, out })
                if expected_session_id == session_id =>
            {
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn range_stop(&mut self, session_id: SessionId) -> UciResult<()> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::RangeStop { expected_session_id, out })
                if expected_session_id == session_id =>
            {
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn range_get_ranging_count(&mut self, session_id: SessionId) -> UciResult<usize> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::RangeGetRangingCount { expected_session_id, out })
                if expected_session_id == session_id =>
            {
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn android_set_country_code(&mut self, country_code: CountryCode) -> UciResult<()> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::AndroidSetCountryCode { expected_country_code, out })
                if expected_country_code == country_code =>
            {
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn android_get_power_stats(&mut self) -> UciResult<PowerStats> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::AndroidGetPowerStats { out }) => out,
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }

    async fn raw_vendor_cmd(
        &mut self,
        gid: u32,
        oid: u32,
        payload: Vec<u8>,
    ) -> UciResult<RawVendorMessage> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::RawVendorCmd {
                expected_gid,
                expected_oid,
                expected_payload,
                out,
            }) if expected_gid == gid && expected_oid == oid && expected_payload == payload => out,
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::WrongState)
            }
            None => Err(UciError::WrongState),
        }
    }
}

enum ExpectedCall {
    OpenHal {
        notfs: Vec<UciNotification>,
        out: UciResult<()>,
    },
    CloseHal {
        out: UciResult<()>,
    },
    DeviceReset {
        expected_reset_config: ResetConfig,
        out: UciResult<()>,
    },
    CoreGetDeviceInfo {
        out: UciResult<GetDeviceInfoResponse>,
    },
    CoreGetCapsInfo {
        out: UciResult<Vec<CapTlv>>,
    },
    CoreSetConfig {
        expected_config_tlvs: Vec<DeviceConfigTlv>,
        out: UciResult<CoreSetConfigResponse>,
    },
    CoreGetConfig {
        expected_config_ids: Vec<DeviceConfigId>,
        out: UciResult<Vec<DeviceConfigTlv>>,
    },
    SessionInit {
        expected_session_id: SessionId,
        expected_session_type: SessionType,
        out: UciResult<()>,
    },
    SessionDeinit {
        expected_session_id: SessionId,
        out: UciResult<()>,
    },
    SessionSetAppConfig {
        expected_session_id: SessionId,
        expected_config_tlvs: Vec<AppConfigTlv>,
        out: UciResult<SetAppConfigResponse>,
    },
    SessionGetAppConfig {
        expected_session_id: SessionId,
        expected_config_ids: Vec<AppConfigTlvType>,
        out: UciResult<Vec<AppConfigTlv>>,
    },
    SessionGetCount {
        out: UciResult<usize>,
    },
    SessionGetState {
        expected_session_id: SessionId,
        out: UciResult<SessionState>,
    },
    SessionUpdateControllerMulticastList {
        expected_session_id: SessionId,
        expected_action: UpdateMulticastListAction,
        expected_controlees: Vec<Controlee>,
        out: UciResult<()>,
    },
    RangeStart {
        expected_session_id: SessionId,
        out: UciResult<()>,
    },
    RangeStop {
        expected_session_id: SessionId,
        out: UciResult<()>,
    },
    RangeGetRangingCount {
        expected_session_id: SessionId,
        out: UciResult<usize>,
    },
    AndroidSetCountryCode {
        expected_country_code: CountryCode,
        out: UciResult<()>,
    },
    AndroidGetPowerStats {
        out: UciResult<PowerStats>,
    },
    RawVendorCmd {
        expected_gid: u32,
        expected_oid: u32,
        expected_payload: Vec<u8>,
        out: UciResult<RawVendorMessage>,
    },
}
