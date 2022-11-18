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

//! Trait definition for UciLogger.
use std::convert::TryFrom;

use uwb_uci_packets::{
    AppConfigTlv, AppConfigTlvType, SessionCommandChild, SessionGetAppConfigRspBuilder,
    SessionResponseChild, SessionSetAppConfigCmdBuilder, UciCommandChild, UciCommandPacket,
    UciPacketPacket, UciResponseChild, UciResponsePacket,
};

use crate::error::{Error, Result};
use crate::uci::UciCommand;

/// UCI Log mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UciLoggerMode {
    /// Log is disabled.
    Disabled,
    /// Logs all uci packets without filtering PII information.
    Unfiltered,
    /// Logs uci packets, with PII filtered.
    Filtered,
}

impl TryFrom<String> for UciLoggerMode {
    type Error = Error;
    /// Parse log mode from string.
    fn try_from(log_mode_string: String) -> Result<UciLoggerMode> {
        match log_mode_string.as_str() {
            "disabled" => Ok(UciLoggerMode::Disabled),
            "unfiltered" => Ok(UciLoggerMode::Unfiltered),
            "filtered" => Ok(UciLoggerMode::Filtered),
            _ => Err(Error::BadParameters),
        }
    }
}

/// Trait definition for the thread-safe uci logger
pub trait UciLogger: 'static + Send + Sync {
    /// Logs Uci Packet.
    fn log_uci_packet(&mut self, packet: UciPacketPacket);
    /// Logs hal open event.
    fn log_hal_open(&mut self, result: Result<()>);
    /// Logs hal close event.
    fn log_hal_close(&mut self, result: Result<()>);
}

fn filter_tlv(mut tlv: AppConfigTlv) -> AppConfigTlv {
    if tlv.cfg_id == AppConfigTlvType::VendorId || tlv.cfg_id == AppConfigTlvType::StaticStsIv {
        tlv.v = vec![0; tlv.v.len()];
    }
    tlv
}

fn filter_uci_command(cmd: UciCommandPacket) -> UciCommandPacket {
    match cmd.specialize() {
        UciCommandChild::SessionCommand(session_cmd) => match session_cmd.specialize() {
            SessionCommandChild::SessionSetAppConfigCmd(set_config_cmd) => {
                let session_id = set_config_cmd.get_session_id();
                let tlvs = set_config_cmd.get_tlvs().to_owned();
                let filtered_tlvs = tlvs.into_iter().map(filter_tlv).collect();
                SessionSetAppConfigCmdBuilder { session_id, tlvs: filtered_tlvs }.build().into()
            }
            _ => session_cmd.into(),
        },
        _ => cmd,
    }
}

fn filter_uci_response(rsp: UciResponsePacket) -> UciResponsePacket {
    match rsp.specialize() {
        UciResponseChild::SessionResponse(session_rsp) => match session_rsp.specialize() {
            SessionResponseChild::SessionGetAppConfigRsp(rsp) => {
                let status = rsp.get_status();
                let tlvs = rsp.get_tlvs().to_owned();
                let filtered_tlvs = tlvs.into_iter().map(filter_tlv).collect();
                SessionGetAppConfigRspBuilder { status, tlvs: filtered_tlvs }.build().into()
            }
            _ => session_rsp.into(),
        },
        _ => rsp,
    }
}

/// Wrapper struct that filters messages feeded to UciLogger.
pub(crate) struct UciLoggerWrapper<T: UciLogger> {
    mode: UciLoggerMode,
    logger: T,
}
impl<T: UciLogger> UciLoggerWrapper<T> {
    pub fn new(logger: T, mode: UciLoggerMode) -> Self {
        Self { mode, logger }
    }

    pub fn set_logger_mode(&mut self, mode: UciLoggerMode) {
        self.mode = mode;
    }

    /// Logs hal open event.
    pub fn log_hal_open(&mut self, result: &Result<()>) {
        if self.mode != UciLoggerMode::Disabled {
            self.logger.log_hal_open(result.clone());
        }
    }

    /// Logs hal close event.
    pub fn log_hal_close(&mut self, result: &Result<()>) {
        if self.mode != UciLoggerMode::Disabled {
            self.logger.log_hal_close(result.clone());
        }
    }

    pub fn log_uci_command(&mut self, cmd: &UciCommand) {
        match self.mode {
            UciLoggerMode::Disabled => (),
            UciLoggerMode::Unfiltered => {
                if let Ok(packet) = UciCommandPacket::try_from(cmd.clone()) {
                    self.logger.log_uci_packet(packet.into());
                };
            }
            UciLoggerMode::Filtered => {
                if let Ok(packet) = UciCommandPacket::try_from(cmd.clone()) {
                    self.logger.log_uci_packet(filter_uci_command(packet).into());
                };
            }
        }
    }

    pub fn log_uci_response_or_notification(&mut self, packet: &UciPacketPacket) {
        match self.mode {
            UciLoggerMode::Disabled => (),
            UciLoggerMode::Unfiltered => self.logger.log_uci_packet(packet.clone()),
            UciLoggerMode::Filtered => match packet.clone().specialize() {
                uwb_uci_packets::UciPacketChild::UciResponse(packet) => {
                    self.logger.log_uci_packet(filter_uci_response(packet).into())
                }
                uwb_uci_packets::UciPacketChild::UciNotification(packet) => {
                    self.logger.log_uci_packet(packet.into())
                }
                _ => (),
            },
        }
    }
}

/// A placeholder UciLogger implementation that does nothing.
#[derive(Default)]
pub struct NopUciLogger {}

impl UciLogger for NopUciLogger {
    fn log_uci_packet(&mut self, _packet: UciPacketPacket) {}

    fn log_hal_open(&mut self, _result: Result<()>) {}

    fn log_hal_close(&mut self, _result: Result<()>) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::TryInto;

    use tokio::sync::mpsc;

    use crate::params::uci_packets::StatusCode;
    use crate::uci::mock_uci_logger::{MockUciLogger, UciLogEvent};

    #[test]
    fn test_log_command_filter() -> Result<()> {
        let set_config_cmd = UciCommand::SessionSetAppConfig {
            session_id: 0x1,
            config_tlvs: vec![
                // Filtered to 0-filled of same length
                AppConfigTlv { cfg_id: AppConfigTlvType::VendorId, v: vec![0, 1, 2] }.into(),
                // Invariant after filter
                AppConfigTlv { cfg_id: AppConfigTlvType::AoaResultReq, v: vec![0, 1, 2, 3] }.into(),
            ],
        };
        let (log_sender, mut log_receiver) = mpsc::unbounded_channel::<UciLogEvent>();
        let mut logger =
            UciLoggerWrapper::new(MockUciLogger::new(log_sender), UciLoggerMode::Filtered);
        logger.log_uci_command(&set_config_cmd);
        assert_eq!(
            TryInto::<Vec<u8>>::try_into(log_receiver.blocking_recv().unwrap())?,
            vec!(
                0x21, 0x3, 0, 0x10, 0, 0, 0, 0x1, 0, 0, 0, 0x2, // other info
                0x27, 0x3, 0, 0, 0, // filtered vendor ID
                0xd, 0x4, 0, 0x1, 0x2, 0x3 // unfiltered tlv
            )
        );
        Ok(())
    }

    #[test]
    fn test_log_response_filter() -> Result<()> {
        let unfiltered_rsp: UciPacketPacket = SessionGetAppConfigRspBuilder {
            status: StatusCode::UciStatusOk,
            tlvs: vec![
                AppConfigTlv { cfg_id: AppConfigTlvType::StaticStsIv, v: vec![0, 1, 2] },
                AppConfigTlv { cfg_id: AppConfigTlvType::AoaResultReq, v: vec![0, 1, 2, 3] },
            ],
        }
        .build()
        .into();
        let (log_sender, mut log_receiver) = mpsc::unbounded_channel::<UciLogEvent>();
        let mut logger =
            UciLoggerWrapper::new(MockUciLogger::new(log_sender), UciLoggerMode::Filtered);
        logger.log_uci_response_or_notification(&unfiltered_rsp);
        assert_eq!(
            TryInto::<Vec<u8>>::try_into(log_receiver.blocking_recv().unwrap())?,
            vec!(
                0x41, 0x4, 0, 0xd, 0, 0, 0, 0, 0x2, // other info
                0x28, 0x3, 0, 0, 0, //filtered StaticStsIv
                0xd, 0x4, 0, 0x1, 0x2, 0x3 // unfiltered tlv
            )
        );
        Ok(())
    }
}
