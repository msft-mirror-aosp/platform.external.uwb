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

pub mod ccc_app_config_params;
pub mod fira_app_config_params;
mod utils;

use std::collections::HashMap;

use crate::session::params::ccc_app_config_params::CccAppConfigParams;
use crate::session::params::fira_app_config_params::FiraAppConfigParams;
use crate::uci::params::{AppConfigTlv, AppConfigTlvType, SessionState, SessionType};

type AppConfigTlvMap = HashMap<AppConfigTlvType, Vec<u8>>;

/// The parameters of the UWB session.
#[derive(Debug, Clone)]
pub enum AppConfigParams {
    Fira(FiraAppConfigParams),
    Ccc(CccAppConfigParams),
}

impl AppConfigParams {
    /// Generate the TLV list from the params.
    pub fn generate_tlvs(&self) -> Vec<AppConfigTlv> {
        Self::config_map_to_tlvs(self.generate_config_map())
    }

    /// Generate the updated TLV list from the difference between this and the previous params.
    pub fn generate_updated_tlvs(
        &self,
        prev_params: &Self,
        session_state: SessionState,
    ) -> Option<Vec<AppConfigTlv>> {
        Some(Self::config_map_to_tlvs(
            self.generate_updated_config_map(prev_params, session_state)?,
        ))
    }

    fn config_map_to_tlvs(config_map: AppConfigTlvMap) -> Vec<AppConfigTlv> {
        config_map.into_iter().map(|(cfg_id, v)| AppConfigTlv { cfg_id, v }).collect()
    }

    fn generate_config_map(&self) -> AppConfigTlvMap {
        match self {
            Self::Fira(params) => params.generate_config_map(),
            Self::Ccc(params) => params.generate_config_map(),
        }
    }

    fn generate_updated_config_map(
        &self,
        prev_params: &Self,
        session_state: SessionState,
    ) -> Option<AppConfigTlvMap> {
        let config_map = self.generate_config_map();
        let prev_config_map = prev_params.generate_config_map();

        match (self, prev_params) {
            (Self::Fira(_), Self::Fira(_)) => {
                let updated_config_map = Self::diff_config_map(config_map, prev_config_map);
                if FiraAppConfigParams::is_config_updatable(&updated_config_map, session_state) {
                    Some(updated_config_map)
                } else {
                    None
                }
            }
            (Self::Ccc(_), Self::Ccc(_)) => {
                let updated_config_map = Self::diff_config_map(config_map, prev_config_map);
                if CccAppConfigParams::is_config_updatable(&updated_config_map, session_state) {
                    Some(updated_config_map)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn is_type_matched(&self, session_type: SessionType) -> bool {
        match self {
            Self::Fira(_) => {
                session_type == SessionType::FiraDataTransfer
                    || session_type == SessionType::FiraRangingSession
            }
            Self::Ccc(_) => session_type == SessionType::Ccc,
        }
    }

    fn diff_config_map(
        config_map: AppConfigTlvMap,
        prev_config_map: AppConfigTlvMap,
    ) -> AppConfigTlvMap {
        // The key sets of both map should be the same.
        debug_assert!(
            config_map.len() == prev_config_map.len()
                && config_map.keys().all(|key| prev_config_map.contains_key(key))
        );

        let mut updated_config_map = HashMap::new();
        for (key, value) in config_map.into_iter() {
            if !matches!(prev_config_map.get(&key), Some(prev_value) if prev_value == &value) {
                updated_config_map.insert(key, value);
            }
        }
        updated_config_map
    }
}
