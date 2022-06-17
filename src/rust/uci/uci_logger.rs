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

extern crate libc;

#[cfg(test)]
use crate::uci::mock_uci_logger::{create_dir, remove_file, rename, Instant};
use crate::uci::UwbErr;
use async_trait::async_trait;
use log::{error, info};
use std::marker::Unpin;
use std::sync::Arc;
#[cfg(not(test))]
use std::time::Instant;
use std::time::SystemTime;
use tokio::fs::OpenOptions;
#[cfg(not(test))]
use tokio::fs::{create_dir, remove_file, rename};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::{task, time};
use uwb_uci_packets::{
    AppConfigTlv, AppConfigTlvType, Packet, SessionCommandChild, SessionGetAppConfigRspBuilder,
    SessionResponseChild, SessionSetAppConfigCmdBuilder, UciCommandChild, UciCommandPacket,
    UciNotificationPacket, UciPacketPacket, UciResponseChild, UciResponsePacket,
};

// micros since 0000-01-01
const UCI_LOG_LAST_FILE_STORE_TIME_SEC: u64 = 86400; // 24 hours
const MAX_FILE_SIZE: usize = 102400; // 100 kb
const MAX_BUFFER_SIZE: usize = 10240; // 10 kb
const VENDOR_ID: u64 = AppConfigTlvType::VendorId as u64;
const STATIC_STS_IV: u64 = AppConfigTlvType::StaticStsIv as u64;
const LOG_DIR: &str = "/data/misc/apexdata/com.android.uwb/log";
const FILE_NAME: &str = "uwb_uci.pcapng";

type SyncFile = Arc<Mutex<dyn AsyncWrite + Send + Sync + Unpin>>;
type SyncFactory = Arc<Mutex<dyn FileFactory + Send + Sync>>;

#[derive(Clone, PartialEq, Eq)]
pub enum UciLogMode {
    Disabled,
    Filtered,
    Enabled,
}

#[derive(Clone)]
pub struct UciLogConfig {
    path: String,
    mode: UciLogMode,
}

impl UciLogConfig {
    pub fn new(mode: UciLogMode) -> Self {
        Self { path: format!("{}/{}", LOG_DIR, FILE_NAME), mode }
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
    file: Option<SyncFile>,
    size_count: usize,
    buffer: Vec<u8>,
    deleter_handle: Option<task::JoinHandle<()>>,
}

impl BufferedFile {
    async fn open_next_file(&mut self, factory: SyncFactory, path: &str) -> Result<(), UwbErr> {
        info!("Open next file");
        self.close_file().await;
        if create_dir(LOG_DIR).await.is_err() {
            error!("Failed to create dir");
        }
        if rename(path, path.to_owned() + ".last").await.is_err() {
            error!("Failed to rename the file");
        }
        if let Some(deleter_handle) = self.deleter_handle.take() {
            deleter_handle.abort();
        }
        let last_file_path = path.to_owned() + ".last";
        self.deleter_handle = Some(task::spawn(async {
            time::sleep(time::Duration::from_secs(UCI_LOG_LAST_FILE_STORE_TIME_SEC)).await;
            if remove_file(last_file_path).await.is_err() {
                error!("Failed to remove file!");
            };
        }));
        let mut file = factory.lock().await.create_file_using_open_options(path).await?;
        write_pcapng_header(&mut file).await;
        self.file = Some(file);
        Ok(())
    }

    async fn close_file(&mut self) {
        if let Some(file) = &mut self.file {
            info!("UCI log file closing");
            write(file, &self.buffer).await;
            self.file = None;
            self.buffer.clear();
        }
        self.size_count = 0;
    }
}

pub struct UciLoggerImpl {
    config: UciLogConfig,
    buf_file: Mutex<BufferedFile>,
    file_factory: SyncFactory,
    start_time: Instant,
}

impl UciLoggerImpl {
    pub async fn new(mode: UciLogMode, file_factory: SyncFactory) -> Self {
        let config = UciLogConfig::new(mode);
        let mut factory = file_factory.lock().await;
        factory.set_config(config.clone()).await;
        let (file, size) = factory.new_file().await;
        let buf_file = BufferedFile {
            size_count: size,
            file,
            buffer: Vec::with_capacity(MAX_BUFFER_SIZE),
            deleter_handle: None,
        };
        let ret = Self {
            config,
            buf_file: Mutex::new(buf_file),
            file_factory: file_factory.clone(),
            start_time: Instant::now(),
        };
        info!("UCI logger created");
        ret
    }

    async fn log_uci_packet(&self, packet: UciPacketPacket) {
        const ENHANCED_BLOCK_SIZE: u32 = 32;
        let mut bytes = packet.to_vec();
        let packet_data_padding: usize = 4 - bytes.len() % 4;
        let block_total_length: u32 =
            bytes.len() as u32 + packet_data_padding as u32 + ENHANCED_BLOCK_SIZE;
        let timestamp = self.start_time.elapsed().as_micros() as u64;

        // Check whether the Enhanced Packet Block exceeds the size limit.
        let mut buf_file = self.buf_file.lock().await;
        if buf_file.size_count + block_total_length as usize > MAX_FILE_SIZE {
            match buf_file.open_next_file(self.file_factory.clone(), &self.config.path).await {
                Ok(()) => info!("Created new pcagng log file"),
                Err(e) => error!("Failed to open new pcapng log file: {:?}", e),
            }
        } else if buf_file.buffer.len() + block_total_length as usize > MAX_BUFFER_SIZE {
            if let BufferedFile { file: Some(ref mut file), ref mut buffer, .. } = *buf_file {
                write(file, buffer).await;
                buffer.clear();
            }
        }

        // Wrap the packet inside an Enhanced Packet Block.
        buf_file.buffer.extend_from_slice(&u32::to_le_bytes(0x00000006)); // Block Type
        buf_file.buffer.extend_from_slice(&u32::to_le_bytes(block_total_length));
        buf_file.buffer.extend_from_slice(&u32::to_le_bytes(0)); // Interface ID
        buf_file.buffer.extend_from_slice(&u32::to_le_bytes((timestamp >> 32) as u32)); // Timestamp (High)
        buf_file.buffer.extend_from_slice(&u32::to_le_bytes(timestamp as u32)); // Timestamp (Low)
        buf_file.buffer.extend_from_slice(&u32::to_le_bytes(bytes.len() as u32)); // Captured Packet Length
        buf_file.buffer.extend_from_slice(&u32::to_le_bytes(bytes.len() as u32)); // Original Packet Length
        buf_file.buffer.append(&mut bytes);
        buf_file.buffer.extend_from_slice(&vec![0; packet_data_padding]);
        buf_file.buffer.extend_from_slice(&u32::to_le_bytes(block_total_length));
    }
}

async fn write(file: &mut SyncFile, buffer: &[u8]) {
    let mut locked_file = file.lock().await;
    if locked_file.write_all(buffer).await.is_err() {
        error!("Failed to write");
    }
    if locked_file.flush().await.is_err() {
        error!("Failed to flush");
    }
}

async fn write_pcapng_header(file: &mut SyncFile) {
    let mut bytes = vec![];

    // PCAPng files must start with a Section Header Block.
    bytes.extend_from_slice(&u32::to_le_bytes(0x0A0D0D0A)); // Block Type
    bytes.extend_from_slice(&u32::to_le_bytes(28)); // Block Total Length
    bytes.extend_from_slice(&u32::to_le_bytes(0x1A2B3C4D)); // Byte-Order Magic
    bytes.extend_from_slice(&u16::to_le_bytes(1)); // Major Version
    bytes.extend_from_slice(&u16::to_le_bytes(0)); // Minor Version
    bytes.extend_from_slice(&u64::to_le_bytes(0xFFFFFFFFFFFFFFFF)); // Section Length (not specified)
    bytes.extend_from_slice(&u32::to_le_bytes(28)); // Block Total Length

    // Write the Interface Description Block used for all
    // UCI records.
    bytes.extend_from_slice(&u32::to_le_bytes(0x00000001)); // Block Type
    bytes.extend_from_slice(&u32::to_le_bytes(20)); // Block Total Length
    bytes.extend_from_slice(&u16::to_le_bytes(293)); // LinkType
    bytes.extend_from_slice(&u16::to_le_bytes(0)); // Reserved
    bytes.extend_from_slice(&u32::to_le_bytes(0)); // SnapLen (no limit)
    bytes.extend_from_slice(&u32::to_le_bytes(20)); // Block Total Length

    write(file, &bytes).await;
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

#[async_trait]
pub trait FileFactory {
    async fn new_file(&self) -> (Option<SyncFile>, usize);
    async fn create_file_using_open_options(&self, path: &str) -> Result<SyncFile, UwbErr>;
    async fn create_file_at_path(&self, path: &str) -> Option<SyncFile>;
    async fn set_config(&mut self, config: UciLogConfig);
}

#[derive(Default)]
pub struct RealFileFactory {
    config: Option<UciLogConfig>,
}

#[async_trait]
impl FileFactory for RealFileFactory {
    async fn new_file(&self) -> (Option<SyncFile>, usize) {
        match OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.config.as_ref().unwrap().path)
            .await
            .ok()
        {
            Some(f) => {
                let size = match f.metadata().await {
                    Ok(md) => {
                        let duration = match md.modified() {
                            Ok(modified_date) => {
                                match SystemTime::now().duration_since(modified_date) {
                                    Ok(duration) => duration.as_secs(),
                                    Err(e) => {
                                        error!("Failed to convert to duration {:?}", e);
                                        0
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to convert to duration {:?}", e);
                                0
                            }
                        };
                        if duration > UCI_LOG_LAST_FILE_STORE_TIME_SEC {
                            0
                        } else {
                            md.len().try_into().unwrap()
                        }
                    }
                    Err(e) => {
                        error!("Failed to get metadata {:?}", e);
                        0
                    }
                };
                match size {
                    0 => {
                        (self.create_file_at_path(&self.config.as_ref().unwrap().path).await, size)
                    }
                    _ => (Some(Arc::new(Mutex::new(f))), size),
                }
            }
            None => (self.create_file_at_path(&self.config.as_ref().unwrap().path).await, 0),
        }
    }

    async fn set_config(&mut self, config: UciLogConfig) {
        self.config = Some(config);
    }

    async fn create_file_using_open_options(&self, path: &str) -> Result<SyncFile, UwbErr> {
        Ok(Arc::new(Mutex::new(OpenOptions::new().write(true).create_new(true).open(path).await?)))
    }

    async fn create_file_at_path(&self, path: &str) -> Option<SyncFile> {
        if create_dir(LOG_DIR).await.is_err() {
            error!("Failed to create dir");
        }
        if remove_file(path).await.is_err() {
            error!("Failed to remove file!");
        }
        match self.create_file_using_open_options(path).await {
            Ok(mut f) => {
                write_pcapng_header(&mut f).await;
                Some(f)
            }
            Err(e) => {
                error!("Failed to create file {:?}", e);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use log::debug;
    use std::io::Error;
    use uwb_uci_packets::{
        AppConfigTlvType, DeviceState, DeviceStatusNtfBuilder, GetDeviceInfoCmdBuilder,
        GetDeviceInfoRspBuilder, StatusCode,
    };

    struct MockLogFile;

    impl MockLogFile {
        #[allow(dead_code)]
        async fn write_all(&mut self, _data: &[u8]) -> Result<(), UwbErr> {
            debug!("Write to fake file");
            Ok(())
        }
        #[allow(dead_code)]
        async fn flush(&self) -> Result<(), UwbErr> {
            debug!("Fake file flush success");
            Ok(())
        }
    }

    impl AsyncWrite for MockLogFile {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<Result<usize, Error>> {
            Poll::Ready(Ok(0))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }
    }

    struct MockFileFactory;

    #[async_trait]
    impl FileFactory for MockFileFactory {
        async fn new_file(&self) -> (Option<SyncFile>, usize) {
            (Some(Arc::new(Mutex::new(MockLogFile {}))), 0)
        }
        async fn set_config(&mut self, _config: UciLogConfig) {}
        async fn create_file_using_open_options(&self, _path: &str) -> Result<SyncFile, UwbErr> {
            Ok(Arc::new(Mutex::new(MockLogFile {})))
        }
        async fn create_file_at_path(&self, _path: &str) -> Option<SyncFile> {
            Some(Arc::new(Mutex::new(MockLogFile {})))
        }
    }

    #[tokio::test]
    async fn test_log_command() -> Result<(), UwbErr> {
        let logger =
            UciLoggerImpl::new(UciLogMode::Filtered, Arc::new(Mutex::new(MockFileFactory {})))
                .await;
        let cmd: UciCommandPacket = GetDeviceInfoCmdBuilder {}.build().into();
        logger.log_uci_command(cmd).await;
        let expected_buffer = [
            6, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0,
            32, 2, 0, 0, 0, 0, 0, 0, 40, 0, 0, 0,
        ];
        let buf_file = logger.buf_file.lock().await;
        assert_eq!(&buf_file.buffer, &expected_buffer);
        Ok(())
    }

    #[tokio::test]
    async fn test_log_response() -> Result<(), UwbErr> {
        let logger =
            UciLoggerImpl::new(UciLogMode::Filtered, Arc::new(Mutex::new(MockFileFactory {})))
                .await;
        let rsp = GetDeviceInfoRspBuilder {
            status: StatusCode::UciStatusOk,
            uci_version: 0,
            mac_version: 0,
            phy_version: 0,
            uci_test_version: 0,
            vendor_spec_info: vec![],
        }
        .build()
        .into();
        logger.log_uci_response(rsp).await;
        let expected_buffer = [
            6, 0, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 17, 0, 0, 0,
            64, 2, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 52, 0, 0, 0,
        ];
        let buf_file = logger.buf_file.lock().await;
        assert_eq!(&buf_file.buffer, &expected_buffer);
        Ok(())
    }

    #[tokio::test]
    async fn test_log_notification() -> Result<(), UwbErr> {
        let logger =
            UciLoggerImpl::new(UciLogMode::Filtered, Arc::new(Mutex::new(MockFileFactory {})))
                .await;
        let ntf =
            DeviceStatusNtfBuilder { device_state: DeviceState::DeviceStateReady }.build().into();
        logger.log_uci_notification(ntf).await;
        let expected_buffer = [
            6, 0, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0,
            96, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 44, 0, 0, 0,
        ];
        let buf_file = logger.buf_file.lock().await;
        assert_eq!(&buf_file.buffer, &expected_buffer);
        Ok(())
    }

    #[tokio::test]
    async fn test_disabled_log() -> Result<(), UwbErr> {
        let logger =
            UciLoggerImpl::new(UciLogMode::Disabled, Arc::new(Mutex::new(MockFileFactory {})))
                .await;
        let cmd: UciCommandPacket = GetDeviceInfoCmdBuilder {}.build().into();
        logger.log_uci_command(cmd).await;
        let buf_file = logger.buf_file.lock().await;
        assert!(buf_file.buffer.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_filter_log() -> Result<(), UwbErr> {
        let logger =
            UciLoggerImpl::new(UciLogMode::Filtered, Arc::new(Mutex::new(MockFileFactory {})))
                .await;
        let rsp = SessionGetAppConfigRspBuilder {
            status: StatusCode::UciStatusOk,
            tlvs: vec![AppConfigTlv { cfg_id: AppConfigTlvType::VendorId, v: vec![0x02, 0x02] }],
        }
        .build()
        .into();
        logger.log_uci_response(rsp).await;
        let expected_buffer = [
            6, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 13, 0, 0, 0,
            65, 4, 0, 6, 0, 0, 0, 0, 1, 39, 2, 0, 0, 0, 0, 0, 48, 0, 0, 0,
        ];
        let buf_file = logger.buf_file.lock().await;
        assert_eq!(&buf_file.buffer, &expected_buffer);
        Ok(())
    }
}
