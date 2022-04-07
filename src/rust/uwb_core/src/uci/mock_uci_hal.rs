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

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::uci::error::{UciError, UciResult};
use crate::uci::params::SessionId;
use crate::uci::uci_hal::{RawUciMessage, UciHal};

/// The mock implementation of UciHal.
#[derive(Default)]
pub struct MockUciHal {
    msg_sender: Option<mpsc::UnboundedSender<RawUciMessage>>,
    expected_calls: VecDeque<ExpectedCall>,
}

impl Drop for MockUciHal {
    fn drop(&mut self) {
        assert!(self.expected_calls.is_empty());
    }
}

#[allow(dead_code)]
impl MockUciHal {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn expected_open(&mut self, msgs: Option<Vec<RawUciMessage>>, out: UciResult<()>) {
        self.expected_calls.push_back(ExpectedCall::Open { msgs, out });
    }

    pub fn expected_close(&mut self, out: UciResult<()>) {
        self.expected_calls.push_back(ExpectedCall::Close { out });
    }

    pub fn expected_send_command(
        &mut self,
        expected_cmd: RawUciMessage,
        msgs: Vec<RawUciMessage>,
        out: UciResult<()>,
    ) {
        self.expected_calls.push_back(ExpectedCall::SendCommand { expected_cmd, msgs, out });
    }

    pub fn expected_notify_session_initialized(
        &mut self,
        expected_session_id: SessionId,
        out: UciResult<()>,
    ) {
        self.expected_calls
            .push_back(ExpectedCall::NotifySessionInitialized { expected_session_id, out });
    }
}

#[async_trait]
impl UciHal for MockUciHal {
    async fn open(&mut self, msg_sender: mpsc::UnboundedSender<RawUciMessage>) -> UciResult<()> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::Open { msgs, out }) => {
                if let Some(msgs) = msgs {
                    for msg in msgs.into_iter() {
                        let _ = msg_sender.send(msg);
                    }
                }
                if out.is_ok() {
                    self.msg_sender.replace(msg_sender);
                }
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::MockUndefined)
            }
            None => Err(UciError::MockUndefined),
        }
    }

    async fn close(&mut self) -> UciResult<()> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::Close { out }) => {
                if out.is_ok() {
                    self.msg_sender = None;
                }
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::MockUndefined)
            }
            None => Err(UciError::MockUndefined),
        }
    }

    async fn send_command(&mut self, cmd: RawUciMessage) -> UciResult<()> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::SendCommand { expected_cmd, msgs, out }) if expected_cmd == cmd => {
                let msg_sender = self.msg_sender.as_mut().unwrap();
                for msg in msgs.into_iter() {
                    let _ = msg_sender.send(msg);
                }
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::MockUndefined)
            }
            None => Err(UciError::MockUndefined),
        }
    }

    async fn notify_session_initialized(&mut self, session_id: SessionId) -> UciResult<()> {
        match self.expected_calls.pop_front() {
            Some(ExpectedCall::NotifySessionInitialized { expected_session_id, out })
                if expected_session_id == session_id =>
            {
                out
            }
            Some(call) => {
                self.expected_calls.push_front(call);
                Err(UciError::MockUndefined)
            }
            None => Err(UciError::MockUndefined),
        }
    }
}

enum ExpectedCall {
    Open { msgs: Option<Vec<RawUciMessage>>, out: UciResult<()> },
    Close { out: UciResult<()> },
    SendCommand { expected_cmd: RawUciMessage, msgs: Vec<RawUciMessage>, out: UciResult<()> },
    NotifySessionInitialized { expected_session_id: SessionId, out: UciResult<()> },
}
