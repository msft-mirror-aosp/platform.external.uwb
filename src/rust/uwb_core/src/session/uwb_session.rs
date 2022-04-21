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

use std::time::Duration;

use log::{debug, error, warn};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;

use crate::session::error::{Error, Result};
use crate::session::params::AppConfigParams;
use crate::uci::error::StatusCode;
use crate::uci::params::{SessionId, SessionState, SessionType};
use crate::uci::uci_manager::UciManager;

pub(crate) struct UwbSession {
    cmd_sender: mpsc::UnboundedSender<(Command, oneshot::Sender<Result<()>>)>,
    state_sender: watch::Sender<SessionState>,
}

impl UwbSession {
    pub fn new<T: UciManager>(
        uci_manager: T,
        session_id: SessionId,
        session_type: SessionType,
    ) -> Self {
        let (cmd_sender, cmd_receiver) = mpsc::unbounded_channel();
        let (state_sender, mut state_receiver) = watch::channel(SessionState::SessionStateDeinit);
        // Mark the initial value of state as seen.
        let _ = state_receiver.borrow_and_update();

        let mut actor = UwbSessionActor::new(
            cmd_receiver,
            state_receiver,
            uci_manager,
            session_id,
            session_type,
        );
        tokio::spawn(async move { actor.run().await });

        Self { cmd_sender, state_sender }
    }

    pub fn initialize(
        &mut self,
        params: AppConfigParams,
        result_sender: oneshot::Sender<Result<()>>,
    ) {
        let _ = self.cmd_sender.send((Command::Initialize { params }, result_sender));
    }

    pub fn deinitialize(&mut self, result_sender: oneshot::Sender<Result<()>>) {
        let _ = self.cmd_sender.send((Command::Deinitialize, result_sender));
    }

    pub fn start_ranging(&mut self, result_sender: oneshot::Sender<Result<()>>) {
        let _ = self.cmd_sender.send((Command::StartRanging, result_sender));
    }

    pub fn stop_ranging(&mut self, result_sender: oneshot::Sender<Result<()>>) {
        let _ = self.cmd_sender.send((Command::StopRanging, result_sender));
    }

    pub fn set_state(&mut self, state: SessionState) {
        let _ = self.state_sender.send(state);
    }
}

struct UwbSessionActor<T: UciManager> {
    cmd_receiver: mpsc::UnboundedReceiver<(Command, oneshot::Sender<Result<()>>)>,
    state_receiver: watch::Receiver<SessionState>,
    uci_manager: T,
    session_id: SessionId,
    session_type: SessionType,
}

impl<T: UciManager> UwbSessionActor<T> {
    fn new(
        cmd_receiver: mpsc::UnboundedReceiver<(Command, oneshot::Sender<Result<()>>)>,
        state_receiver: watch::Receiver<SessionState>,
        uci_manager: T,
        session_id: SessionId,
        session_type: SessionType,
    ) -> Self {
        Self { cmd_receiver, state_receiver, uci_manager, session_id, session_type }
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                cmd = self.cmd_receiver.recv() => {
                    match cmd {
                        None => {
                            debug!("UwbSession is about to drop.");
                            break;
                        },
                        Some((cmd, result_sender)) => {
                            let result = match cmd {
                                Command::Initialize { params } => self.initialize(params).await,
                                Command::Deinitialize => self.deinitialize().await,
                                Command::StartRanging => self.start_ranging().await,
                                Command::StopRanging => self.stop_ranging().await,
                            };
                            let _ = result_sender.send(result);
                        }
                    }
                }
            }
        }
    }

    async fn initialize(&mut self, params: AppConfigParams) -> Result<()> {
        if let Err(e) = self.uci_manager.session_init(self.session_id, self.session_type).await {
            error!("Failed to initialize session: {:?}", e);
            return Err(Error::Uci);
        }
        self.wait_state(SessionState::SessionStateInit).await?;

        let tlvs = params.generate_tlvs();
        match self.uci_manager.session_set_app_config(self.session_id, tlvs).await {
            Ok(result) => {
                for config_status in result.config_status.iter() {
                    warn!(
                        "AppConfig {:?} is not applied: {:?}",
                        config_status.cfg_id, config_status.status
                    );
                }
                if result.status != StatusCode::UciStatusOk {
                    error!("Failed to set app_config. StatusCode: {:?}", result.status);
                    return Err(Error::Uci);
                }
            }
            Err(e) => {
                error!("Failed to set app_config: {:?}", e);
                return Err(Error::Uci);
            }
        }
        self.wait_state(SessionState::SessionStateIdle).await?;

        Ok(())
    }

    async fn deinitialize(&mut self) -> Result<()> {
        if let Err(e) = self.uci_manager.session_deinit(self.session_id).await {
            error!("Failed to deinit session: {:?}", e);
            return Err(Error::Uci);
        }
        Ok(())
    }

    async fn start_ranging(&mut self) -> Result<()> {
        let state = *self.state_receiver.borrow();
        match state {
            SessionState::SessionStateActive => {
                warn!("Session {} is already running", self.session_id);
                Ok(())
            }
            SessionState::SessionStateIdle => {
                if let Err(e) = self.uci_manager.range_start(self.session_id).await {
                    error!("Failed to start ranging: {:?}", e);
                    return Err(Error::Uci);
                }
                self.wait_state(SessionState::SessionStateActive).await?;

                Ok(())
            }
            _ => {
                error!("Session {} cannot start running at {:?}", self.session_id, state);
                Err(Error::WrongState(state))
            }
        }
    }

    async fn stop_ranging(&mut self) -> Result<()> {
        let state = *self.state_receiver.borrow();
        match state {
            SessionState::SessionStateIdle => {
                warn!("Session {} is already stopped", self.session_id);
                Ok(())
            }
            SessionState::SessionStateActive => {
                if let Err(e) = self.uci_manager.range_stop(self.session_id).await {
                    error!("Failed to start ranging: {:?}", e);
                    return Err(Error::Uci);
                }
                self.wait_state(SessionState::SessionStateIdle).await?;

                Ok(())
            }
            _ => {
                error!("Session {} cannot stop running at {:?}", self.session_id, state);
                Err(Error::WrongState(state))
            }
        }
    }

    async fn wait_state(&mut self, expected_state: SessionState) -> Result<()> {
        const WAIT_STATE_TIMEOUT_MS: u64 = 1000;
        match timeout(Duration::from_millis(WAIT_STATE_TIMEOUT_MS), self.state_receiver.changed())
            .await
        {
            Ok(result) => {
                if result.is_err() {
                    debug!("UwbSession is about to drop.");
                    return Err(Error::TokioFailure);
                }
            }
            Err(_) => {
                error!("Timeout waiting for the session status notification");
                return Err(Error::Timeout);
            }
        }

        let state = *self.state_receiver.borrow();
        if state != expected_state {
            error!(
                "Transit to wrong Session state {:?}. The expected state is {:?}",
                state, expected_state
            );
            return Err(Error::WrongState(state));
        }

        Ok(())
    }
}

enum Command {
    Initialize { params: AppConfigParams },
    Deinitialize,
    StartRanging,
    StopRanging,
}
