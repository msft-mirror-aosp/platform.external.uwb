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

mod uci_hmsgs;
mod uci_hrcv;

use anyhow::{bail, Result};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc;
use tokio::{select, task};

// TODO: Use real values for these enums.

// Commands sent from JNI.
#[derive(Debug)]
enum JNICommand {
    A,
    B,
    Exit,
}

// Responses from the HAL.
#[derive(Debug)]
enum HALResponse {
    A,
    B,
}

// Commands we send to the HAL.
#[derive(Debug)]
enum HALCommand {
    A,
    B,
}

struct Driver {
    cmd_receiver: mpsc::UnboundedReceiver<JNICommand>,
    rsp_receiver: mpsc::UnboundedReceiver<HALResponse>,
}

// Creates a future that handles messages from JNI and the HAL.
async fn drive(
    cmd_receiver: mpsc::UnboundedReceiver<JNICommand>,
    rsp_receiver: mpsc::UnboundedReceiver<HALResponse>,
) -> Result<()> {
    Driver::new(cmd_receiver, rsp_receiver).drive().await
}

impl Driver {
    fn new(
        cmd_receiver: mpsc::UnboundedReceiver<JNICommand>,
        rsp_receiver: mpsc::UnboundedReceiver<HALResponse>,
    ) -> Self {
        Self { cmd_receiver, rsp_receiver }
    }

    // Continually handles messages.
    async fn drive(mut self) -> Result<()> {
        loop {
            self.drive_once().await?
        }
    }

    // Handles a single message from JNI or the HAL.
    async fn drive_once(&mut self) -> Result<()> {
        // TODO: Handle messages for real instead of just logging them.
        select! {
            Some(cmd) = self.cmd_receiver.recv() => {
                match cmd {
                    JNICommand::A => log::error!("JNICommand::A"),
                    JNICommand::B => log::error!("JNICommand::B"),
                    JNICommand::Exit => bail!("Exit received"),
                }
            }
            Some(rsp) = self.rsp_receiver.recv() => {
                match rsp {
                    HALResponse::A => log::error!("HALResponse::A"),
                    HALResponse::B => log::error!("HALResponse::B"),
                }
            }
        }
        Ok(())
    }
}

// Controller for sending tasks for the native thread to handle.
struct Dispatcher {
    cmd_sender: mpsc::UnboundedSender<JNICommand>,
    rsp_sender: mpsc::UnboundedSender<HALResponse>,
    join_handle: task::JoinHandle<Result<()>>,
    runtime: Runtime,
}

impl Dispatcher {
    fn new() -> Result<Dispatcher> {
        let (cmd_sender, cmd_receiver) = mpsc::unbounded_channel::<JNICommand>();
        let (rsp_sender, rsp_receiver) = mpsc::unbounded_channel::<HALResponse>();
        // We create a new thread here both to avoid reusing the Java service thread and because
        // binder threads will call into this.
        let runtime =
            Builder::new_multi_thread().worker_threads(1).thread_name("uwb-uci-handler").build()?;
        let join_handle = runtime.spawn(drive(cmd_receiver, rsp_receiver));
        Ok(Dispatcher { cmd_sender, rsp_sender, join_handle, runtime })
    }

    fn send_jni_command(&self, cmd: JNICommand) -> Result<()> {
        self.cmd_sender.send(cmd)?;
        Ok(())
    }

    fn send_hal_response(&self, rsp: HALResponse) -> Result<()> {
        self.rsp_sender.send(rsp)?;
        Ok(())
    }

    fn exit(&mut self) -> Result<()> {
        self.send_jni_command(JNICommand::Exit)?;
        let _ = self.runtime.block_on(&mut self.join_handle);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver() -> Result<()> {
        // TODO: Remove this once we call it somewhere real.
        logger::init(
            logger::Config::default().with_tag_on_device("uwb").with_min_level(log::Level::Error),
        );
        let mut dispatcher = Dispatcher::new()?;
        dispatcher.send_jni_command(JNICommand::A)?;
        dispatcher.send_hal_response(HALResponse::A)?;
        dispatcher.send_jni_command(JNICommand::B)?;
        dispatcher.exit()?;
        assert!(dispatcher.send_hal_response(HALResponse::B).is_err());
        Ok(())
    }
}
