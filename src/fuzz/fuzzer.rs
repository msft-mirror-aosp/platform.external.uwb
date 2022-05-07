#![no_main]
#![allow(missing_docs)]

use android_hardware_uwb::aidl::android::hardware::uwb::{
    UwbEvent::UwbEvent, UwbStatus::UwbStatus,
};
use libfuzzer_sys::{arbitrary::Arbitrary, fuzz_target};
use log::{error, info};
use num_traits::cast::FromPrimitive;
use std::sync::Arc;
use tokio::sync::mpsc;
use uwb_uci_packets::{
    AndroidGetPowerStatsCmdBuilder, AndroidGetPowerStatsRspBuilder,
    AndroidSetCountryCodeCmdBuilder, AndroidSetCountryCodeRspBuilder, DeviceResetRspBuilder,
    DeviceState, DeviceStatusNtfBuilder, GenericErrorBuilder, GetCapsInfoCmdBuilder,
    GetCapsInfoRspBuilder, GetDeviceInfoCmdBuilder, GetDeviceInfoRspBuilder, PowerStats,
    RangeStartCmdBuilder, RangeStartRspBuilder, RangeStopCmdBuilder, RangeStopRspBuilder,
    ReasonCode, SessionDeinitCmdBuilder, SessionDeinitRspBuilder, SessionGetAppConfigCmdBuilder,
    SessionGetAppConfigRspBuilder, SessionGetCountCmdBuilder, SessionGetCountRspBuilder,
    SessionGetStateCmdBuilder, SessionGetStateRspBuilder, SessionInitCmdBuilder,
    SessionInitRspBuilder, SessionSetAppConfigRspBuilder, SessionState, SessionStatusNtfBuilder,
    SessionType, SessionUpdateControllerMulticastListRspBuilder, StatusCode, UciCommandPacket,
    UciPacketChild, UciPacketPacket, UciVendor_9_ResponseBuilder,
};
use uwb_uci_rust::adaptation::mock_adaptation::MockUwbAdaptation;
use uwb_uci_rust::error::UwbErr;
use uwb_uci_rust::event_manager::mock_event_manager::MockEventManager;
use uwb_uci_rust::uci::{
    uci_hmsgs, uci_hrcv, Dispatcher, DispatcherImpl, HalCallback, JNICommand, SyncUwbAdaptation,
};

#[derive(Debug, Clone, Arbitrary)]
enum UciNotification {
    GenericError { status: u8 },
    DeviceStatusNtf { device_state: u8 },
    SessionStatusNtf { session_id: u32, session_state: u8, reason_code: u8 },
}

#[derive(Debug, Clone, Arbitrary)]
enum Command {
    JNICmd(JNICommand),
    UciNtf(UciNotification),
}

fn create_dispatcher_with_mock_adaptation(
    msgs: Vec<Command>,
) -> Result<(DispatcherImpl, mpsc::UnboundedSender<HalCallback>), UwbErr> {
    let (rsp_sender, rsp_receiver) = mpsc::unbounded_channel::<HalCallback>();
    let mut mock_adaptation = Arc::new(MockUwbAdaptation::new(rsp_sender.clone()));
    let mut mock_event_manager = MockEventManager::new();
    for msg in &msgs {
        match msg {
            Command::JNICmd(cmd) => match cmd {
                JNICommand::Enable => {
                    mock_adaptation.expect_hal_open(Ok(()));
                    mock_adaptation.expect_core_initialization(Ok(()));
                }
                JNICommand::Disable(_graceful) => {
                    break;
                }
                _ => {
                    let (cmd, rsp) = match generate_fake_cmd_rsp(cmd) {
                        Ok((command, response)) => (command, response),
                        Err(e) => {
                            mock_adaptation.clear_expected_calls();
                            mock_event_manager.clear_expected_calls();
                            return Err(e);
                        }
                    };
                    mock_adaptation.expect_send_uci_message(cmd, Some(rsp), None, Ok(()))
                }
            },
            Command::UciNtf(ntf) => match ntf {
                UciNotification::GenericError { status } => {
                    if StatusCode::from_u8(*status).is_none() {
                        mock_adaptation.clear_expected_calls();
                        mock_event_manager.clear_expected_calls();
                        return Err(UwbErr::InvalidArgs);
                    }
                    mock_event_manager.expect_core_generic_error_notification_received(Ok(()))
                }
                UciNotification::DeviceStatusNtf { device_state } => {
                    if DeviceState::from_u8(*device_state).is_none() {
                        mock_adaptation.clear_expected_calls();
                        mock_event_manager.clear_expected_calls();
                        return Err(UwbErr::InvalidArgs);
                    }
                    mock_event_manager.expect_device_status_notification_received(Ok(()))
                }
                UciNotification::SessionStatusNtf {
                    session_id: _session_ids,
                    session_state,
                    reason_code,
                } => {
                    if SessionState::from_u8(*session_state).is_none()
                        || ReasonCode::from_u8(*reason_code).is_none()
                        || *session_state == 0
                    {
                        mock_adaptation.clear_expected_calls();
                        mock_event_manager.clear_expected_calls();
                        return Err(UwbErr::InvalidArgs);
                    }
                    mock_event_manager.expect_session_status_notification_received(Ok(()))
                }
            },
        }
    }
    mock_adaptation.expect_hal_close(Ok(()));
    Ok((
        DispatcherImpl::new_for_testing(
            mock_event_manager,
            mock_adaptation as SyncUwbAdaptation,
            rsp_receiver,
        )?,
        rsp_sender,
    ))
}

fn generate_fake_cmd_rsp(
    msg: &JNICommand,
) -> Result<(UciCommandPacket, uci_hrcv::UciResponse), UwbErr> {
    match msg {
        JNICommand::UciSessionInit(session_id, session_type) => Ok((
            uci_hmsgs::build_session_init_cmd(*session_id, *session_type)?.build().into(),
            uci_hrcv::UciResponse::SessionInitRsp(
                SessionInitRspBuilder { status: StatusCode::UciStatusOk }.build(),
            ),
        )),
        JNICommand::UciGetCapsInfo => Ok((
            GetCapsInfoCmdBuilder {}.build().into(),
            uci_hrcv::UciResponse::GetCapsInfoRsp(
                GetCapsInfoRspBuilder { status: StatusCode::UciStatusOk, tlvs: vec![] }.build(),
            ),
        )),
        JNICommand::UciGetDeviceInfo => Ok((
            GetDeviceInfoCmdBuilder {}.build().into(),
            uci_hrcv::UciResponse::GetDeviceInfoRsp(
                GetDeviceInfoRspBuilder {
                    status: StatusCode::UciStatusOk,
                    uci_version: 0,
                    mac_version: 0,
                    phy_version: 0,
                    uci_test_version: 0,
                    vendor_spec_info: vec![],
                }
                .build(),
            ),
        )),
        JNICommand::UciSessionDeinit(session_id) => Ok((
            SessionDeinitCmdBuilder { session_id: *session_id }.build().into(),
            uci_hrcv::UciResponse::SessionDeinitRsp(
                SessionDeinitRspBuilder { status: StatusCode::UciStatusOk }.build(),
            ),
        )),
        JNICommand::UciSessionGetCount => Ok((
            SessionGetCountCmdBuilder {}.build().into(),
            uci_hrcv::UciResponse::SessionGetCountRsp(
                SessionGetCountRspBuilder { status: StatusCode::UciStatusOk, session_count: 1 }
                    .build(),
            ),
        )),
        JNICommand::UciStartRange(session_id) => Ok((
            RangeStartCmdBuilder { session_id: *session_id }.build().into(),
            uci_hrcv::UciResponse::RangeStartRsp(
                RangeStartRspBuilder { status: StatusCode::UciStatusOk }.build(),
            ),
        )),
        JNICommand::UciStopRange(session_id) => Ok((
            RangeStopCmdBuilder { session_id: *session_id }.build().into(),
            uci_hrcv::UciResponse::RangeStopRsp(
                RangeStopRspBuilder { status: StatusCode::UciStatusOk }.build(),
            ),
        )),
        JNICommand::UciGetSessionState(session_id) => Ok((
            SessionGetStateCmdBuilder { session_id: *session_id }.build().into(),
            uci_hrcv::UciResponse::SessionGetStateRsp(
                SessionGetStateRspBuilder {
                    status: StatusCode::UciStatusOk,
                    session_state: SessionState::SessionStateInit,
                }
                .build(),
            ),
        )),
        JNICommand::UciSessionUpdateMulticastList {
            session_id,
            action,
            no_of_controlee,
            address_list,
            sub_session_id_list,
        } => Ok((
            uci_hmsgs::build_multicast_list_update_cmd(
                *session_id,
                *action,
                *no_of_controlee,
                address_list,
                sub_session_id_list,
            )?
            .build()
            .into(),
            uci_hrcv::UciResponse::SessionUpdateControllerMulticastListRsp(
                SessionUpdateControllerMulticastListRspBuilder { status: StatusCode::UciStatusOk }
                    .build(),
            ),
        )),
        JNICommand::UciSetCountryCode { code } => Ok((
            uci_hmsgs::build_set_country_code_cmd(&code)?.build().into(),
            uci_hrcv::UciResponse::AndroidSetCountryCodeRsp(
                AndroidSetCountryCodeRspBuilder { status: StatusCode::UciStatusOk }.build(),
            ),
        )),
        JNICommand::UciSetAppConfig {
            session_id,
            no_of_params,
            app_config_param_len,
            app_configs,
        } => Ok((
            uci_hmsgs::build_set_app_config_cmd(*session_id, *no_of_params, app_configs)?
                .build()
                .into(),
            uci_hrcv::UciResponse::SessionSetAppConfigRsp(
                SessionSetAppConfigRspBuilder {
                    status: StatusCode::UciStatusOk,
                    cfg_status: vec![],
                }
                .build(),
            ),
        )),
        JNICommand::UciGetAppConfig {
            session_id,
            no_of_params,
            app_config_param_len,
            app_configs,
        } => Ok((
            SessionGetAppConfigCmdBuilder {
                session_id: *session_id,
                app_cfg: app_configs.to_vec(),
            }
            .build()
            .into(),
            uci_hrcv::UciResponse::SessionGetAppConfigRsp(
                SessionGetAppConfigRspBuilder { status: StatusCode::UciStatusOk, tlvs: vec![] }
                    .build(),
            ),
        )),
        JNICommand::UciRawVendorCmd { gid, oid, payload } => Ok((
            uci_hmsgs::build_uci_vendor_cmd_packet(*gid, *oid, payload.to_vec())?.into(),
            uci_hrcv::UciResponse::RawVendorRsp(
                UciVendor_9_ResponseBuilder { opcode: 0, payload: None }.build().into(),
            ),
        )),
        JNICommand::UciDeviceReset { reset_config } => Ok((
            uci_hmsgs::build_device_reset_cmd(*reset_config)?.build().into(),
            uci_hrcv::UciResponse::DeviceResetRsp(
                DeviceResetRspBuilder { status: StatusCode::UciStatusOk }.build(),
            ),
        )),
        JNICommand::UciGetPowerStats => Ok((
            AndroidGetPowerStatsCmdBuilder {}.build().into(),
            uci_hrcv::UciResponse::AndroidGetPowerStatsRsp(
                AndroidGetPowerStatsRspBuilder {
                    stats: PowerStats {
                        status: StatusCode::UciStatusOk,
                        idle_time_ms: 0,
                        tx_time_ms: 0,
                        rx_time_ms: 0,
                        total_wake_count: 0,
                    },
                }
                .build(),
            ),
        )),
        _ => Err(UwbErr::Exit),
    }
}

fn consume_command(msgs: Vec<Command>) -> Result<(), UwbErr> {
    let (mut mock_dispatcher, mut rsp_sender) =
        create_dispatcher_with_mock_adaptation(msgs.clone())?;
    for msg in msgs {
        match msg {
            Command::JNICmd(cmd) => match cmd {
                JNICommand::Enable => {
                    mock_dispatcher.send_jni_command(JNICommand::Enable)?;
                }
                JNICommand::Disable(_graceful) => {
                    break;
                }
                _ => {
                    mock_dispatcher.block_on_jni_command(cmd)?;
                }
            },
            Command::UciNtf(ntf) => {
                let evt = match ntf {
                    UciNotification::GenericError { status } => {
                        uci_hrcv::UciNotification::GenericError(
                            GenericErrorBuilder {
                                status: StatusCode::from_u8(status).ok_or(UwbErr::InvalidArgs)?,
                            }
                            .build(),
                        )
                    }
                    UciNotification::DeviceStatusNtf { device_state } => {
                        uci_hrcv::UciNotification::DeviceStatusNtf(
                            DeviceStatusNtfBuilder {
                                device_state: DeviceState::from_u8(device_state)
                                    .ok_or(UwbErr::InvalidArgs)?,
                            }
                            .build(),
                        )
                    }
                    UciNotification::SessionStatusNtf {
                        session_id,
                        session_state,
                        reason_code,
                    } => uci_hrcv::UciNotification::SessionStatusNtf(
                        SessionStatusNtfBuilder {
                            session_id,
                            session_state: SessionState::from_u8(session_state)
                                .ok_or(UwbErr::InvalidArgs)?,
                            reason_code: ReasonCode::from_u8(reason_code)
                                .ok_or(UwbErr::InvalidArgs)?,
                        }
                        .build(),
                    ),
                };
                rsp_sender
                    .send(HalCallback::UciNtf(evt))
                    .unwrap_or_else(|e| error!("Error sending uci notification: {:?}", e));
            }
        }
    }
    mock_dispatcher.send_jni_command(JNICommand::Disable(true))?;
    mock_dispatcher.wait_for_exit()?;
    Ok(())
}

fuzz_target!(|msgs: Vec<Command>| {
    match consume_command(msgs) {
        Ok(()) => info!("fuzzing success"),
        Err(e) => error!("fuzzing failed: {:?}", e),
    };
});
