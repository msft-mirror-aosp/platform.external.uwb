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
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use log::{error, info};
use std::time::SystemTime;
use tokio::fs::{create_dir, rename, File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use uwb_uci_packets::{
    AppConfigTlv, AppConfigTlvType, MessageType, Packet, SessionCommandChild,
    SessionGetAppConfigRspBuilder, SessionResponseChild, SessionSetAppConfigCmdBuilder,
    UciCommandChild, UciCommandPacket, UciNotificationPacket, UciPacketPacket, UciResponseChild,
    UciResponsePacket,
};

// micros since 0000-01-01
const UCI_EPOCH_DELTA: u64 = 0x00dcddb30f2f8000;
const MAX_FILE_SIZE: usize = 4096;
const PKT_LOG_HEADER_SIZE: usize = 25;
const VENDOR_ID: u64 = AppConfigTlvType::VendorId as u64;
const STATIC_STS_IV: u64 = AppConfigTlvType::StaticStsIv as u64;
const LOG_DIR: &str = "/data/misc/apexdata/com.android.uwb/log";
const FILE_NAME: &str = "uwb_uci.log";

#[derive(Clone, PartialEq, Eq)]
pub enum UciLogMode {
    Disabled,
    Filtered,
    Enabled,
}

#[derive(Clone)]
enum Type {
    Command = 1,
    Response,
    Notification,
}

#[derive(Clone)]
struct UciLogConfig {
    path: String,
    max_file_size: usize,
    mode: UciLogMode,
}

impl UciLogConfig {
    pub fn new(mode: UciLogMode) -> Self {
        Self { path: format!("{}/{}", LOG_DIR, FILE_NAME), max_file_size: MAX_FILE_SIZE, mode }
    }
}

#[async_trait]
pub trait UciLogger {
    async fn log_uci_command(&self, cmd: UciCommandPacket);
    async fn log_uci_response(&self, rsp: UciResponsePacket);
    async fn log_uci_notification(&self, ntf: UciNotificationPacket);
    async fn close_file(&self);
}

struct BufferedFile {
    file: Option<File>,
    size_count: usize,
    buffer: BytesMut,
}

impl BufferedFile {
    async fn open_next_file(&mut self, path: &str) -> Result<(), UwbErr> {
        info!("Open next file");
        self.close_file().await;
        if create_dir(LOG_DIR).await.is_err() {
            error!("Failed to create dir");
        }
        if rename(path, path.to_owned() + ".last").await.is_err() {
            error!("Failed to rename the file");
        }
        let mut file = File::create(path).await?;
        file.write_all(b"ucilogging").await?;
        if file.flush().await.is_err() {
            error!("Failed to flush");
        }
        self.file = Some(file);
        Ok(())
    }

    async fn close_file(&mut self) {
        if let Some(file) = &mut self.file {
            info!("UCI log file closing");
            if file.write_all(&self.buffer).await.is_err() {
                error!("Failed to write");
            }
            if file.flush().await.is_err() {
                error!("Failed to flush");
            }
            self.file = None;
            self.buffer.clear();
        }
        self.size_count = 0;
    }
}

pub struct UciLoggerImpl {
    config: UciLogConfig,
    buf_file: Mutex<BufferedFile>,
}

impl UciLoggerImpl {
    pub async fn new(mode: UciLogMode) -> Self {
        let config = UciLogConfig::new(mode);
        let file = match OpenOptions::new().append(true).open(&config.path).await.ok() {
            Some(f) => Some(f),
            None => {
                if create_dir(LOG_DIR).await.is_err() {
                    error!("Failed to create dir");
                }
                let new_file = match File::create(&config.path).await {
                    Ok(mut f) => {
                        if f.write_all(b"ucilogging").await.is_err() {
                            error!("failed to write");
                        }
                        if f.flush().await.is_err() {
                            error!("Failed to flush");
                        }
                        Some(f)
                    }
                    Err(e) => {
                        error!("Failed to create file {:?}", e);
                        None
                    }
                };
                new_file
            }
        };
        let buf_file = BufferedFile {
            size_count: match file {
                Some(ref f) => f.metadata().await.unwrap().len().try_into().unwrap(),
                None => 0,
            },
            file,
            buffer: BytesMut::new(),
        };
        let ret = Self { config, buf_file: Mutex::new(buf_file) };
        info!("UCI logger created");
        ret
    }

    async fn log_uci_packet(&self, packet: UciPacketPacket) {
        let mt = packet.get_message_type();
        let bytes = packet.to_vec();
        let mt_byte = match mt {
            MessageType::Command => Type::Command as u8,
            MessageType::Response => Type::Response as u8,
            MessageType::Notification => Type::Notification as u8,
        };
        let flags = match mt {
            MessageType::Command => 0b10,      // down direction
            MessageType::Response => 0b01,     // up direction
            MessageType::Notification => 0b01, // up direction
        };
        let timestamp = u64::try_from(
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_micros(),
        )
        .unwrap()
            + UCI_EPOCH_DELTA;

        let length = u32::try_from(bytes.len()).unwrap() + 1;

        // Check whether exceeded the size limit
        let mut buf_file = self.buf_file.lock().await;
        if buf_file.size_count + bytes.len() + PKT_LOG_HEADER_SIZE > self.config.max_file_size {
            match buf_file.open_next_file(&self.config.path).await {
                Ok(()) => info!("New file created"),
                Err(e) => error!("Open next file failed: {:?}", e),
            }
        }
        buf_file.buffer.put_u32(length); // original length
        buf_file.buffer.put_u32(length); // captured length
        buf_file.buffer.put_u32(flags); // flags
        buf_file.buffer.put_u32(0); // dropped packets
        buf_file.buffer.put_u64(timestamp); // timestamp
        buf_file.buffer.put_u8(mt_byte); // type
        buf_file.buffer.put_slice(&bytes); // full packet.
        buf_file.size_count += bytes.len() + PKT_LOG_HEADER_SIZE;
    }
}

#[async_trait]
impl UciLogger for UciLoggerImpl {
    async fn log_uci_command(&self, cmd: UciCommandPacket) {
        match self.config.mode {
            UciLogMode::Disabled => return,
            UciLogMode::Enabled => self.log_uci_packet(cmd.into()).await,
            UciLogMode::Filtered => {
                let filtered_cmd: UciCommandPacket = match cmd.specialize() {
                    UciCommandChild::SessionCommand(session_cmd) => {
                        match session_cmd.specialize() {
                            SessionCommandChild::SessionSetAppConfigCmd(set_config_cmd) => {
                                let session_id = set_config_cmd.get_session_id();
                                let tlvs = set_config_cmd.get_tlvs();
                                let mut filtered_tlvs = Vec::new();
                                for tlv in tlvs {
                                    if VENDOR_ID == tlv.cfg_id as u64
                                        || STATIC_STS_IV == tlv.cfg_id as u64
                                    {
                                        filtered_tlvs.push(AppConfigTlv {
                                            cfg_id: tlv.cfg_id,
                                            v: vec![0; tlv.v.len()],
                                        });
                                    } else {
                                        filtered_tlvs.push(tlv.clone());
                                    }
                                }
                                SessionSetAppConfigCmdBuilder { session_id, tlvs: filtered_tlvs }
                                    .build()
                                    .into()
                            }
                            _ => session_cmd.into(),
                        }
                    }
                    _ => cmd,
                };
                self.log_uci_packet(filtered_cmd.into()).await;
            }
        }
    }

    async fn log_uci_response(&self, rsp: UciResponsePacket) {
        match self.config.mode {
            UciLogMode::Disabled => return,
            UciLogMode::Enabled => self.log_uci_packet(rsp.into()).await,
            UciLogMode::Filtered => {
                let filtered_rsp: UciResponsePacket = match rsp.specialize() {
                    UciResponseChild::SessionResponse(session_rsp) => {
                        match session_rsp.specialize() {
                            SessionResponseChild::SessionGetAppConfigRsp(rsp) => {
                                let status = rsp.get_status();
                                let tlvs = rsp.get_tlvs();
                                let mut filtered_tlvs = Vec::new();
                                for tlv in tlvs {
                                    if VENDOR_ID == tlv.cfg_id as u64
                                        || STATIC_STS_IV == tlv.cfg_id as u64
                                    {
                                        filtered_tlvs.push(AppConfigTlv {
                                            cfg_id: tlv.cfg_id,
                                            v: vec![0; tlv.v.len()],
                                        });
                                    } else {
                                        filtered_tlvs.push(tlv.clone());
                                    }
                                }
                                SessionGetAppConfigRspBuilder { status, tlvs: filtered_tlvs }
                                    .build()
                                    .into()
                            }
                            _ => session_rsp.into(),
                        }
                    }
                    _ => rsp,
                };
                self.log_uci_packet(filtered_rsp.into()).await;
            }
        }
    }

    async fn log_uci_notification(&self, ntf: UciNotificationPacket) {
        if self.config.mode == UciLogMode::Disabled {
            return;
        }
        // No notifications to be filtered.
        self.log_uci_packet(ntf.into()).await;
    }

    async fn close_file(&self) {
        if self.config.mode == UciLogMode::Disabled {
            return;
        }
        self.buf_file.lock().await.close_file().await;
    }
}

#[cfg(test)]
pub struct MockUciLogger {}

#[cfg(test)]
impl MockUciLogger {
    pub fn new() -> Self {
        MockUciLogger {}
    }
}

#[cfg(test)]
impl Default for MockUciLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[async_trait]
impl UciLogger for MockUciLogger {
    async fn log_uci_command(&self, _cmd: UciCommandPacket) {}
    async fn log_uci_response(&self, _rsp: UciResponsePacket) {}
    async fn log_uci_notification(&self, _ntf: UciNotificationPacket) {}
    async fn close_file(&self) {}
}
