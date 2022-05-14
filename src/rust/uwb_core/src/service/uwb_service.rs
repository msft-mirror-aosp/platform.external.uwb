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

//! This module provides UwbService and its related components.

use log::{debug, error};
use tokio::sync::{mpsc, oneshot};

use crate::service::error::{Error, Result};
use crate::session::params::AppConfigParams;
use crate::session::session_manager::SessionManager;
use crate::uci::params::{Controlee, SessionId, SessionType, UpdateMulticastListAction};
use crate::uci::uci_hal::UciHal;
use crate::uci::uci_manager::{UciManager, UciManagerImpl};

#[cfg(test)]
use crate::uci::mock_uci_manager::MockUciManager;

/// The entry class (a.k.a top shim) of the core library. The class accepts requests from the
/// client, and delegates the requests to other components. It should provide the
/// backward-compatible interface for the client of the library.
pub struct UwbService {
    cmd_sender: mpsc::UnboundedSender<(Command, ResponseSender)>,
}

impl UwbService {
    /// Create a new UwbService instance.
    pub fn new<U: UciHal>(uci_hal: U) -> Self {
        let uci_manager = UciManagerImpl::new(uci_hal);
        let (cmd_sender, cmd_receiver) = mpsc::unbounded_channel();
        let mut actor = UwbServiceActor::new(cmd_receiver, uci_manager);
        tokio::spawn(async move { actor.run().await });

        Self { cmd_sender }
    }

    #[cfg(test)]
    fn new_for_testing(uci_manager: MockUciManager) -> Self {
        let (cmd_sender, cmd_receiver) = mpsc::unbounded_channel();
        // TODO(akahuang): Change to use MockSessionManager.
        let mut actor = UwbServiceActor::new(cmd_receiver, uci_manager);
        tokio::spawn(async move { actor.run().await });

        Self { cmd_sender }
    }

    /// Enable the UWB service.
    pub async fn enable(&mut self) -> Result<()> {
        self.send_cmd(Command::Enable).await?;
        Ok(())
    }

    /// Disable the UWB service.
    pub async fn disable(&mut self) -> Result<()> {
        self.send_cmd(Command::Disable).await?;
        Ok(())
    }

    /// Initialize a new ranging session with the given parameters.
    pub async fn init_session(
        &mut self,
        session_id: SessionId,
        session_type: SessionType,
        params: AppConfigParams,
    ) -> Result<()> {
        self.send_cmd(Command::InitSession { session_id, session_type, params }).await?;
        Ok(())
    }

    /// Destroy the session.
    pub async fn deinit_session(&mut self, session_id: SessionId) -> Result<()> {
        self.send_cmd(Command::DeinitSession { session_id }).await?;
        Ok(())
    }

    /// Start ranging of the session.
    pub async fn start_ranging(&mut self, session_id: SessionId) -> Result<AppConfigParams> {
        match self.send_cmd(Command::StartRanging { session_id }).await? {
            Response::AppConfigParams(params) => Ok(params),
            _ => panic!("start_ranging() should return AppConfigParams"),
        }
    }

    /// Stop ranging.
    pub async fn stop_ranging(&mut self, session_id: SessionId) -> Result<()> {
        self.send_cmd(Command::StopRanging { session_id }).await?;
        Ok(())
    }

    /// Reconfigure the parameters of the session.
    pub async fn reconfigure(
        &mut self,
        session_id: SessionId,
        params: AppConfigParams,
    ) -> Result<()> {
        self.send_cmd(Command::Reconfigure { session_id, params }).await?;
        Ok(())
    }

    /// Update the list of the controlees to the ongoing session.
    pub async fn update_controller_multicast_list(
        &mut self,
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: Vec<Controlee>,
    ) -> Result<()> {
        self.send_cmd(Command::UpdateControllerMulticastList { session_id, action, controlees })
            .await?;
        Ok(())
    }

    // Send the |cmd| to UwbServiceActor.
    async fn send_cmd(&self, cmd: Command) -> Result<Response> {
        let (result_sender, result_receiver) = oneshot::channel();
        self.cmd_sender.send((cmd, result_sender)).map_err(|cmd| {
            error!("Failed to send cmd: {:?}", cmd.0);
            Error::TokioFailure
        })?;
        result_receiver.await.unwrap_or(Err(Error::TokioFailure))
    }
}

struct UwbServiceActor<U: UciManager> {
    cmd_receiver: mpsc::UnboundedReceiver<(Command, ResponseSender)>,
    uci_manager: U,
    session_manager: Option<SessionManager>,
}

impl<U: UciManager> UwbServiceActor<U> {
    fn new(
        cmd_receiver: mpsc::UnboundedReceiver<(Command, ResponseSender)>,
        uci_manager: U,
    ) -> Self {
        Self { cmd_receiver, uci_manager, session_manager: None }
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                cmd = self.cmd_receiver.recv() => {
                    match cmd {
                        None => {
                            debug!("UwbService is about to drop.");
                            break;
                        },
                        Some((cmd, result_sender)) => {
                            let result = self.handle_cmd(cmd).await;
                            let _ = result_sender.send(result);
                        }
                    }
                }
            }
        }
    }

    async fn handle_cmd(&mut self, cmd: Command) -> Result<Response> {
        match cmd {
            Command::Enable => {
                if self.session_manager.is_some() {
                    debug!("The service is already enabled, skip.");
                    return Ok(Response::Null);
                }

                let (uci_notf_sender, uci_notf_receiver) = mpsc::unbounded_channel();
                self.uci_manager.set_session_notification_sender(uci_notf_sender).await;
                self.uci_manager.open_hal().await.map_err(|e| {
                    error!("Failed to open the UCI HAL: ${:?}", e);
                    Error::UciError
                })?;

                self.session_manager = Some(SessionManager::new(
                    self.uci_manager.clone(),
                    uci_notf_receiver,
                    // TODO(akahuang): handle the notification from SessionManager.
                    mpsc::unbounded_channel().0,
                ));
                Ok(Response::Null)
            }
            Command::Disable => {
                if self.session_manager.is_none() {
                    debug!("The service is already disabled, skip.");
                    return Ok(Response::Null);
                }

                self.session_manager = None;
                self.uci_manager.close_hal().await.map_err(|e| {
                    error!("Failed to open the UCI HAL: ${:?}", e);
                    Error::UciError
                })?;
                Ok(Response::Null)
            }
            Command::InitSession { session_id, session_type, params } => {
                if let Some(session_manager) = self.session_manager.as_mut() {
                    session_manager.init_session(session_id, session_type, params).await.map_err(
                        |e| {
                            error!("init_session failed: {:?}", e);
                            Error::SessionError
                        },
                    )?;
                    Ok(Response::Null)
                } else {
                    error!("The service is not enabled yet");
                    Err(Error::Reject)
                }
            }
            Command::DeinitSession { session_id } => {
                if let Some(session_manager) = self.session_manager.as_mut() {
                    session_manager.deinit_session(session_id).await.map_err(|e| {
                        error!("deinit_session failed: {:?}", e);
                        Error::SessionError
                    })?;
                    Ok(Response::Null)
                } else {
                    error!("The service is not enabled yet");
                    Err(Error::Reject)
                }
            }
            Command::StartRanging { session_id } => {
                if let Some(session_manager) = self.session_manager.as_mut() {
                    let params = session_manager.start_ranging(session_id).await.map_err(|e| {
                        error!("start_ranging failed: {:?}", e);
                        Error::SessionError
                    })?;
                    Ok(Response::AppConfigParams(params))
                } else {
                    error!("The service is not enabled yet");
                    Err(Error::Reject)
                }
            }
            Command::StopRanging { session_id } => {
                if let Some(session_manager) = self.session_manager.as_mut() {
                    session_manager.stop_ranging(session_id).await.map_err(|e| {
                        error!("stop_ranging failed: {:?}", e);
                        Error::SessionError
                    })?;
                    Ok(Response::Null)
                } else {
                    error!("The service is not enabled yet");
                    Err(Error::Reject)
                }
            }
            Command::Reconfigure { session_id, params } => {
                if let Some(session_manager) = self.session_manager.as_mut() {
                    session_manager.reconfigure(session_id, params).await.map_err(|e| {
                        error!("reconfigure failed: {:?}", e);
                        Error::SessionError
                    })?;
                    Ok(Response::Null)
                } else {
                    error!("The service is not enabled yet");
                    Err(Error::Reject)
                }
            }
            Command::UpdateControllerMulticastList { session_id, action, controlees } => {
                if let Some(session_manager) = self.session_manager.as_mut() {
                    session_manager
                        .update_controller_multicast_list(session_id, action, controlees)
                        .await
                        .map_err(|e| {
                            error!("update_controller_multicast_list failed: {:?}", e);
                            Error::SessionError
                        })?;
                    Ok(Response::Null)
                } else {
                    error!("The service is not enabled yet");
                    Err(Error::Reject)
                }
            }
        }
    }
}

#[derive(Debug)]
enum Command {
    Enable,
    Disable,
    InitSession {
        session_id: SessionId,
        session_type: SessionType,
        params: AppConfigParams,
    },
    DeinitSession {
        session_id: SessionId,
    },
    StartRanging {
        session_id: SessionId,
    },
    StopRanging {
        session_id: SessionId,
    },
    Reconfigure {
        session_id: SessionId,
        params: AppConfigParams,
    },
    UpdateControllerMulticastList {
        session_id: SessionId,
        action: UpdateMulticastListAction,
        controlees: Vec<Controlee>,
    },
}

#[derive(Debug)]
enum Response {
    Null,
    AppConfigParams(AppConfigParams),
}
type ResponseSender = oneshot::Sender<Result<Response>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::session_manager::test_utils::generate_params;

    #[tokio::test]
    async fn test_open_close_uci() {
        let mut uci_manager = MockUciManager::new();
        uci_manager.expect_open_hal(vec![], Ok(()));
        uci_manager.expect_close_hal(Ok(()));
        let mut service = UwbService::new_for_testing(uci_manager);

        let result = service.enable().await;
        assert!(result.is_ok());
        let result = service.disable().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_api_without_enabled() {
        let session_id = 0x123;
        let session_type = SessionType::FiraRangingSession;
        let params = generate_params();
        let action = UpdateMulticastListAction::AddControlee;
        let controlees = vec![Controlee { short_address: 0x13, subsession_id: 0x24 }];

        let uci_manager = MockUciManager::new();
        let mut service = UwbService::new_for_testing(uci_manager);

        let result = service.init_session(session_id, session_type, params.clone()).await;
        assert!(result.is_err());
        let result = service.deinit_session(session_id).await;
        assert!(result.is_err());
        let result = service.start_ranging(session_id).await;
        assert!(result.is_err());
        let result = service.stop_ranging(session_id).await;
        assert!(result.is_err());
        let result = service.reconfigure(session_id, params).await;
        assert!(result.is_err());
        let result = service.update_controller_multicast_list(session_id, action, controlees).await;
        assert!(result.is_err());
    }
}
