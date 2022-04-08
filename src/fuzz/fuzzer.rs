#![no_main]
#![allow(missing_docs)]

use libfuzzer_sys::{arbitrary::Arbitrary, fuzz_target};
use log::{error, info};
use num_traits::cast::FromPrimitive;
use std::sync::Arc;
use tokio::sync::mpsc;
use uwb_uci_packets::{SessionInitRspBuilder, StatusCode};
use uwb_uci_rust::adaptation::MockUwbAdaptation;
use uwb_uci_rust::error::UwbErr;
use uwb_uci_rust::event_manager::MockEventManager;
use uwb_uci_rust::uci::{
    uci_hmsgs, Dispatcher, DispatcherImpl, HalCallback, JNICommand, SyncUwbAdaptation,
};

fn create_dispatcher_with_mock_adaptation(msgs: Vec<JNICommand>) -> Result<DispatcherImpl, UwbErr> {
    let (rsp_sender, rsp_receiver) = mpsc::unbounded_channel::<HalCallback>();
    let mut mock_adaptation = Arc::new(MockUwbAdaptation::new(rsp_sender));
    let mut mock_event_manager = MockEventManager::new();
    for msg in &msgs {
        match msg {
            JNICommand::Enable => {
                mock_adaptation.expect_hal_open(Ok(()));
                mock_adaptation.expect_core_initialization(Ok(()));
            }
            JNICommand::Disable(_graceful) => {
                mock_adaptation.expect_hal_close(Ok(()));
            }
            _ => {
                let (cmd, rsp) = generate_fake_cmd_rsp(msg)?;
                mock_adaptation.expect_send_uci_message(cmd, Some(rsp), None, Ok(()));
            }
        }
    }
    DispatcherImpl::new_for_testing(
        mock_event_manager,
        mock_adaptation as SyncUwbAdaptation,
        rsp_receiver,
    )
}

fn generate_fake_cmd_rsp(msg: &JNICommand) -> Result<(Vec<u8>, Vec<u8>), UwbErr> {
    match msg {
        JNICommand::UciSessionInit(session_id, session_type) => Ok((
            uci_hmsgs::build_session_init_cmd(*session_id, *session_type)?.build().into(),
            SessionInitRspBuilder { status: StatusCode::UciStatusOk }.build().into(),
        )),
        _ => Err(UwbErr::Undefined),
    }
}

fn consume_command(msgs: Vec<JNICommand>) -> Result<(), UwbErr> {
    let mut mock_dispatcher = create_dispatcher_with_mock_adaptation(msgs.clone())?;
    for msg in msgs {
        match msg {
            JNICommand::Enable => {
                mock_dispatcher.send_jni_command(JNICommand::Enable)?;
            }
            _ => {
                mock_dispatcher.block_on_jni_command(msg)?;
            }
        }
    }
    mock_dispatcher.exit();
    Ok(())
}

fuzz_target!(|msgs: Vec<JNICommand>| {
    match consume_command(msgs) {
        Ok(()) => info!("fuzzing success"),
        Err(e) => error!("fuzzing failed: {:?}", e),
    };
});
