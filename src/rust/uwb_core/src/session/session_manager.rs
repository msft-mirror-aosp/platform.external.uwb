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

use std::collections::BTreeMap;

use log::{debug, error};
use tokio::sync::{mpsc, oneshot};

use crate::session::error::{SessionError, SessionResult};
use crate::uci::notification::UciNotification;
use crate::uci::params::{SessionId, SessionType};
use crate::uci::uci_manager::UciManager;

const MAX_SESSION_COUNT: usize = 5;

/// The SessionManager organizes the state machine of the existing UWB ranging sessions, sends
/// the session-related requests to the UciManager, and handles the session notifications from the
/// UciManager.
/// Using the actor model, SessionManager delegates the requests to SessionManagerActor.
pub(crate) struct SessionManager {
    cmd_sender: mpsc::UnboundedSender<(SessionCommand, oneshot::Sender<SessionResult<()>>)>,
}

impl SessionManager {
    pub fn new<T: UciManager>(
        uci_manager: T,
        uci_notf_receiver: mpsc::UnboundedReceiver<UciNotification>,
    ) -> Self {
        let (cmd_sender, cmd_receiver) = mpsc::unbounded_channel();
        let mut actor = SessionManagerActor::new(cmd_receiver, uci_manager, uci_notf_receiver);
        tokio::spawn(async move { actor.run().await });

        Self { cmd_sender }
    }

    async fn init_session(
        &mut self,
        session_id: SessionId,
        session_type: SessionType,
    ) -> SessionResult<()> {
        self.send_cmd(SessionCommand::InitSession { session_id, session_type }).await
    }

    async fn deinit_session(&mut self, session_id: SessionId) -> SessionResult<()> {
        self.send_cmd(SessionCommand::DeinitSession { session_id }).await
    }

    // Send the |cmd| to the SessionManagerActor.
    async fn send_cmd(&self, cmd: SessionCommand) -> SessionResult<()> {
        let (result_sender, result_receiver) = oneshot::channel();
        self.cmd_sender.send((cmd, result_sender)).map_err(|cmd| {
            error!("Failed to send cmd: {:?}", cmd.0);
            SessionError::TokioFailure
        })?;
        result_receiver.await.unwrap_or(Err(SessionError::TokioFailure))
    }
}

struct SessionManagerActor<T: UciManager> {
    // Receive the commands and the corresponding response senders from SessionManager.
    cmd_receiver: mpsc::UnboundedReceiver<(SessionCommand, oneshot::Sender<SessionResult<()>>)>,

    // The UciManager for delegating UCI requests.
    uci_manager: T,
    // Receive the notification from |uci_manager|.
    uci_notf_receiver: mpsc::UnboundedReceiver<UciNotification>,

    active_sessions: BTreeMap<SessionId, UwbSession>,
}

impl<T: UciManager> SessionManagerActor<T> {
    fn new(
        cmd_receiver: mpsc::UnboundedReceiver<(SessionCommand, oneshot::Sender<SessionResult<()>>)>,
        uci_manager: T,
        uci_notf_receiver: mpsc::UnboundedReceiver<UciNotification>,
    ) -> Self {
        Self { cmd_receiver, uci_manager, uci_notf_receiver, active_sessions: BTreeMap::new() }
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                cmd = self.cmd_receiver.recv() => {
                    match cmd {
                        None => {
                            debug!("SessionManager is about to drop.");
                            break;
                        },
                        Some((cmd, result_sender)) => {
                            let result = self.handle_cmd(cmd).await;
                            let _ = result_sender.send(result);
                        }
                    }
                }

                Some(uci_notf) = self.uci_notf_receiver.recv() => {
                    self.handle_uci_notification(uci_notf).await;
                }
            }
        }
    }

    async fn handle_cmd(&mut self, cmd: SessionCommand) -> SessionResult<()> {
        match cmd {
            SessionCommand::InitSession { session_id, session_type } => {
                if self.active_sessions.len() == MAX_SESSION_COUNT {
                    return Err(SessionError::MaxSessionsExceeded);
                }
                if self.active_sessions.contains_key(&session_id) {
                    return Err(SessionError::DuplicatedSessionId(session_id));
                }
                if let Err(e) = self.uci_manager.session_init(session_id, session_type).await {
                    error!("Failed to init session: {:?}", e);
                    return Err(SessionError::UciError);
                }

                self.active_sessions.insert(session_id, UwbSession {});
            }

            SessionCommand::DeinitSession { session_id } => {
                if self.active_sessions.remove(&session_id).is_none() {
                    return Err(SessionError::UnknownSessionId(session_id));
                }

                if let Err(e) = self.uci_manager.session_deinit(session_id).await {
                    error!("Failed to deinit session: {:?}", e);
                    return Err(SessionError::UciError);
                }
            }
        }
        Ok(())
    }

    async fn handle_uci_notification(&mut self, _notf: UciNotification) {}
}

// TODO(akahuang): store the necessary session parameters here.
struct UwbSession {}

#[derive(Debug)]
enum SessionCommand {
    InitSession { session_id: SessionId, session_type: SessionType },
    DeinitSession { session_id: SessionId },
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::uci::mock_uci_manager::MockUciManager;

    async fn setup_session_manager<F>(setup_uci_manager_fn: F) -> SessionManager
    where
        F: FnOnce(&mut MockUciManager),
    {
        let (notf_sender, notf_receiver) = mpsc::unbounded_channel();
        let mut uci_manager = MockUciManager::new();
        uci_manager.expect_open_hal(vec![], Ok(()));
        setup_uci_manager_fn(&mut uci_manager);
        let _ = uci_manager.open_hal(notf_sender).await;
        SessionManager::new(uci_manager, notf_receiver)
    }

    #[tokio::test]
    async fn test_init_session() {
        let session_id = 0x123;
        let session_type = SessionType::FiraRangingSession;

        let session_id_clone = session_id;
        let session_type_clone = session_type;
        let mut session_manager = setup_session_manager(move |uci_manager| {
            uci_manager.expect_session_init(session_id_clone, session_type_clone, Ok(()));
        })
        .await;

        let result = session_manager.init_session(session_id, session_type).await;
        assert_eq!(result, Ok(()));
        let result = session_manager.init_session(session_id, session_type).await;
        assert_eq!(result, Err(SessionError::DuplicatedSessionId(session_id)));
    }

    #[tokio::test]
    async fn test_deinit_session() {
        let session_id = 0x123;
        let session_type = SessionType::FiraRangingSession;

        let session_id_clone = session_id;
        let session_type_clone = session_type;
        let mut session_manager = setup_session_manager(move |uci_manager| {
            uci_manager.expect_session_init(session_id_clone, session_type_clone, Ok(()));
            uci_manager.expect_session_deinit(session_id_clone, Ok(()));
        })
        .await;

        let result = session_manager.deinit_session(session_id).await;
        assert_eq!(result, Err(SessionError::UnknownSessionId(session_id)));
        let result = session_manager.init_session(session_id, session_type).await;
        assert_eq!(result, Ok(()));
        let result = session_manager.deinit_session(session_id).await;
        assert_eq!(result, Ok(()));
        let result = session_manager.deinit_session(session_id).await;
        assert_eq!(result, Err(SessionError::UnknownSessionId(session_id)));
    }
}
