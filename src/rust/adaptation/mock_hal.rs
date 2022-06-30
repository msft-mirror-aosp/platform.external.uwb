/*
 * Copyright (C) 2022 The Android Open Source Project
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

//! MockHal

use crate::uci::{uci_hrcv, HalCallback};
use android_hardware_uwb::aidl::android::hardware::uwb::{
    IUwbChip::IUwbChipAsync, IUwbClientCallback::IUwbClientCallback, UwbEvent::UwbEvent,
    UwbStatus::UwbStatus,
};
use android_hardware_uwb::binder::{Result as BinderResult, Strong};
use async_trait::async_trait;
use binder::{SpIBinder, StatusCode};
use log::info;
use std::collections::VecDeque;
use std::sync::Mutex as StdMutex;
use tokio::sync::mpsc;

#[cfg(any(test, fuzzing))]
enum ExpectedHalCall {
    Open {
        out: BinderResult<()>,
    },
    Close {
        out: BinderResult<()>,
    },
    CoreInit {
        out: BinderResult<()>,
    },
    SessionInit {
        expected_session_id: i32,
        out: BinderResult<()>,
    },
    SendUciMessage {
        expected_data: Vec<u8>,
        expected_rsp: Option<uci_hrcv::UciResponse>,
        out: BinderResult<i32>,
    },
}

#[cfg(any(test, fuzzing))]
pub struct MockHal {
    rsp_sender: Option<mpsc::UnboundedSender<HalCallback>>,
    expected_calls: StdMutex<VecDeque<ExpectedHalCall>>,
}

#[cfg(any(test, fuzzing))]
impl MockHal {
    pub fn new(rsp_sender: Option<mpsc::UnboundedSender<HalCallback>>) -> Self {
        logger::init(
            logger::Config::default().with_tag_on_device("uwb").with_min_level(log::Level::Debug),
        );
        info!("created mock hal.");
        Self { rsp_sender, expected_calls: StdMutex::new(VecDeque::new()) }
    }
    #[allow(dead_code)]
    pub fn expect_open(&self, out: BinderResult<()>) {
        self.expected_calls.lock().unwrap().push_back(ExpectedHalCall::Open { out });
    }
    #[allow(dead_code)]
    pub fn expect_close(&self, out: BinderResult<()>) {
        self.expected_calls.lock().unwrap().push_back(ExpectedHalCall::Close { out });
    }
    #[allow(dead_code)]
    pub fn expect_core_init(&self, out: BinderResult<()>) {
        self.expected_calls.lock().unwrap().push_back(ExpectedHalCall::CoreInit { out });
    }
    #[allow(dead_code)]
    pub fn expect_session_init(&self, expected_session_id: i32, out: BinderResult<()>) {
        self.expected_calls
            .lock()
            .unwrap()
            .push_back(ExpectedHalCall::SessionInit { expected_session_id, out });
    }
    pub fn expect_send_uci_message(
        &self,
        expected_data: Vec<u8>,
        expected_rsp: Option<uci_hrcv::UciResponse>,
        out: BinderResult<i32>,
    ) {
        self.expected_calls.lock().unwrap().push_back(ExpectedHalCall::SendUciMessage {
            expected_data,
            expected_rsp,
            out,
        });
    }
    pub fn clear_expected_calls(&self) {
        self.expected_calls.lock().unwrap().clear();
    }
}

#[cfg(any(test, fuzzing))]
impl Drop for MockHal {
    fn drop(&mut self) {
        assert!(self.expected_calls.lock().unwrap().is_empty());
    }
}

#[cfg(any(test, fuzzing))]
impl Default for MockHal {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(any(test, fuzzing))]
impl binder::Interface for MockHal {}

#[cfg(any(test, fuzzing))]
impl binder::FromIBinder for MockHal {
    fn try_from(_ibinder: SpIBinder) -> std::result::Result<Strong<Self>, binder::StatusCode> {
        Err(binder::StatusCode::OK)
    }
}

#[cfg(any(test, fuzzing))]
#[async_trait]
impl<P: binder::BinderAsyncPool> IUwbChipAsync<P> for MockHal {
    fn getName(&self) -> binder::BoxFuture<BinderResult<String>> {
        Box::pin(std::future::ready(Ok("default".into())))
    }

    fn open<'a>(
        &'a self,
        _cb: &'a binder::Strong<dyn IUwbClientCallback>,
    ) -> binder::BoxFuture<'a, BinderResult<()>> {
        let expected_out = {
            let mut expected_calls = self.expected_calls.lock().unwrap();
            match expected_calls.pop_front() {
                Some(ExpectedHalCall::Open { out }) => Some(out),
                Some(call) => {
                    expected_calls.push_front(call);
                    None
                }
                None => None,
            }
        };

        match expected_out {
            Some(out) => Box::pin(std::future::ready(out)),
            None => Box::pin(std::future::ready(Err(StatusCode::UNKNOWN_ERROR.into()))),
        }
    }

    fn close(&self) -> binder::BoxFuture<BinderResult<()>> {
        let expected_out = {
            let mut expected_calls = self.expected_calls.lock().unwrap();
            match expected_calls.pop_front() {
                Some(ExpectedHalCall::Close { out }) => {
                    if let Some(sender) = self.rsp_sender.as_ref() {
                        sender
                            .send(HalCallback::Event {
                                event: UwbEvent::CLOSE_CPLT,
                                event_status: UwbStatus::OK,
                            })
                            .unwrap();
                    }
                    Some(out)
                }
                Some(call) => {
                    expected_calls.push_front(call);
                    None
                }
                None => None,
            }
        };

        match expected_out {
            Some(out) => Box::pin(std::future::ready(out)),
            None => Box::pin(std::future::ready(Err(StatusCode::UNKNOWN_ERROR.into()))),
        }
    }

    fn coreInit(&self) -> binder::BoxFuture<BinderResult<()>> {
        let expected_out = {
            let mut expected_calls = self.expected_calls.lock().unwrap();
            match expected_calls.pop_front() {
                Some(ExpectedHalCall::CoreInit { out }) => Some(out),
                Some(call) => {
                    expected_calls.push_front(call);
                    None
                }
                None => None,
            }
        };

        match expected_out {
            Some(out) => Box::pin(std::future::ready(out)),
            None => Box::pin(std::future::ready(Err(StatusCode::UNKNOWN_ERROR.into()))),
        }
    }

    fn sessionInit(&self, session_id: i32) -> binder::BoxFuture<BinderResult<()>> {
        let expected_out = {
            let mut expected_calls = self.expected_calls.lock().unwrap();
            match expected_calls.pop_front() {
                Some(ExpectedHalCall::SessionInit { expected_session_id, out })
                    if expected_session_id == session_id =>
                {
                    Some(out)
                }
                Some(call) => {
                    expected_calls.push_front(call);
                    None
                }
                None => None,
            }
        };

        match expected_out {
            Some(out) => Box::pin(std::future::ready(out)),
            None => Box::pin(std::future::ready(Err(StatusCode::UNKNOWN_ERROR.into()))),
        }
    }

    fn getSupportedAndroidUciVersion(&self) -> binder::BoxFuture<BinderResult<i32>> {
        Box::pin(std::future::ready(Ok(0)))
    }

    fn sendUciMessage(&self, cmd: &[u8]) -> binder::BoxFuture<BinderResult<i32>> {
        let expected_out = {
            let mut expected_calls = self.expected_calls.lock().unwrap();
            match expected_calls.pop_front() {
                Some(ExpectedHalCall::SendUciMessage { expected_data, expected_rsp, out })
                    if expected_data == cmd =>
                {
                    if let (Some(rsp), Some(sender)) = (expected_rsp, self.rsp_sender.as_ref()) {
                        sender.send(HalCallback::UciRsp(rsp)).unwrap();
                    }
                    Some(out)
                }
                Some(call) => {
                    expected_calls.push_front(call);
                    None
                }
                None => None,
            }
        };
        match expected_out {
            Some(out) => Box::pin(std::future::ready(out)),
            None => Box::pin(std::future::ready(Err(StatusCode::UNKNOWN_ERROR.into()))),
        }
    }
}
