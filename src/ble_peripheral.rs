use tokio::sync::mpsc;

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use crate::data_structures::{BITCHAT_CHARACTERISTIC_UUID, BITCHAT_SERVICE_UUID};
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    use windows::core::{IInspectable, GUID};
    use windows::{
        Devices::Bluetooth::BluetoothError,
        Devices::Bluetooth::GenericAttributeProfile::*,
        Foundation::TypedEventHandler,
        Storage::Streams::{DataReader, DataWriter, IBuffer},
    };

    static OUTBOUND_TX: OnceLock<mpsc::UnboundedSender<Vec<u8>>> = OnceLock::new();

    fn peripheral_bridge_enabled() -> bool {
        match std::env::var("BITCHAT_BLE_PERIPHERAL") {
            Ok(value) => value.trim() == "1",
            Err(_) => false, // Default OFF to avoid degrading central scan stability on Win10.
        }
    }

    fn peripheral_bridge_verbose() -> bool {
        std::env::var("BITCHAT_BLE_PERIPHERAL_VERBOSE")
            .map(|value| value.trim() != "0")
            .unwrap_or(false)
    }

    fn bridge_device_name(nickname: &str) -> String {
        let base = nickname
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
            .take(18)
            .collect::<String>();
        if base.is_empty() {
            "bitchat-tui".to_string()
        } else {
            format!("bitchat-{}", base)
        }
    }

    fn create_buffer(data: &[u8]) -> windows::core::Result<IBuffer> {
        let writer = DataWriter::new()?;
        writer.WriteBytes(data)?;
        writer.DetachBuffer()
    }

    fn read_buffer_bytes(buffer: &IBuffer) -> windows::core::Result<Vec<u8>> {
        let reader = DataReader::FromBuffer(buffer)?;
        let size = reader.UnconsumedBufferLength()? as usize;
        let mut payload = vec![0u8; size];
        reader.ReadBytes(&mut payload)?;
        Ok(payload)
    }

    fn try_extract_session_device_id(session: &GattSession) -> Option<String> {
        session
            .DeviceId()
            .ok()
            .and_then(|device_id| device_id.Id().ok())
            .map(|id| id.to_string())
    }

    pub async fn start_bridge(
        ui_tx: mpsc::Sender<String>,
        nickname: String,
        inbound_tx: mpsc::Sender<Vec<u8>>,
    ) {
        if OUTBOUND_TX.get().is_some() {
            return;
        }

        if !peripheral_bridge_enabled() {
            crate::write_debug_log(
                "BLE peripheral bridge disabled. Set BITCHAT_BLE_PERIPHERAL=1 to enable.",
            );
            return;
        }

        let device_name = bridge_device_name(&nickname);
        let service_guid = GUID::from_u128(BITCHAT_SERVICE_UUID.as_u128());
        let characteristic_guid = GUID::from_u128(BITCHAT_CHARACTERISTIC_UUID.as_u128());

        let provider_result =
            match GattServiceProvider::CreateAsync(service_guid).and_then(|op| op.get()) {
                Ok(result) => result,
                Err(e) => {
                    let _ = ui_tx
                        .send(format!(
                            "system: BLE peripheral bridge failed to create service provider: {}",
                            e
                        ))
                        .await;
                    return;
                }
            };
        match provider_result.Error() {
            Ok(error) if error == BluetoothError::Success => {}
            Ok(error) => {
                let _ = ui_tx
                    .send(format!(
                        "system: BLE peripheral bridge create error: {:?}",
                        error
                    ))
                    .await;
                return;
            }
            Err(e) => {
                let _ = ui_tx
                    .send(format!(
                        "system: BLE peripheral bridge create error state unavailable: {}",
                        e
                    ))
                    .await;
                return;
            }
        }

        let service_provider = match provider_result.ServiceProvider() {
            Ok(provider) => provider,
            Err(e) => {
                let _ = ui_tx
                    .send(format!(
                        "system: BLE peripheral bridge failed to acquire service provider: {}",
                        e
                    ))
                    .await;
                return;
            }
        };
        let service = match service_provider.Service() {
            Ok(service) => service,
            Err(e) => {
                let _ = ui_tx
                    .send(format!(
                        "system: BLE peripheral bridge failed to access local service: {}",
                        e
                    ))
                    .await;
                return;
            }
        };

        let char_params = match GattLocalCharacteristicParameters::new() {
            Ok(params) => params,
            Err(e) => {
                let _ = ui_tx
                    .send(format!(
                        "system: BLE peripheral bridge failed to create characteristic parameters: {}",
                        e
                    ))
                    .await;
                return;
            }
        };
        let _ = char_params.SetCharacteristicProperties(
            GattCharacteristicProperties::Read
                | GattCharacteristicProperties::Notify
                | GattCharacteristicProperties::Write
                | GattCharacteristicProperties::WriteWithoutResponse,
        );
        let _ = char_params.SetReadProtectionLevel(GattProtectionLevel::Plain);
        let _ = char_params.SetWriteProtectionLevel(GattProtectionLevel::Plain);
        let _ =
            char_params.SetUserDescription(&windows::core::HSTRING::from("BitChat packet stream"));
        if let Ok(initial_value) = create_buffer(b"Ready") {
            let _ = char_params.SetStaticValue(&initial_value);
        }

        let char_result = match service
            .CreateCharacteristicAsync(characteristic_guid, &char_params)
            .and_then(|op| op.get())
        {
            Ok(result) => result,
            Err(e) => {
                let _ = ui_tx
                    .send(format!(
                        "system: BLE peripheral bridge failed to create characteristic: {}",
                        e
                    ))
                    .await;
                return;
            }
        };
        match char_result.Error() {
            Ok(error) if error == BluetoothError::Success => {}
            Ok(error) => {
                let _ = ui_tx
                    .send(format!(
                        "system: BLE peripheral bridge characteristic error: {:?}",
                        error
                    ))
                    .await;
                return;
            }
            Err(e) => {
                let _ = ui_tx
                    .send(format!(
                        "system: BLE peripheral bridge characteristic error state unavailable: {}",
                        e
                    ))
                    .await;
                return;
            }
        }
        let characteristic = match char_result.Characteristic() {
            Ok(characteristic) => characteristic,
            Err(e) => {
                let _ = ui_tx
                    .send(format!(
                        "system: BLE peripheral bridge failed to access characteristic: {}",
                        e
                    ))
                    .await;
                return;
            }
        };

        let subscribed_clients = std::sync::Arc::new(Mutex::new(HashSet::<String>::new()));

        let subscribers_for_event = std::sync::Arc::clone(&subscribed_clients);
        let ui_tx_subscribers = ui_tx.clone();
        let device_name_for_subscribers = device_name.clone();
        let _subscribed_token =
            match characteristic.SubscribedClientsChanged(&TypedEventHandler::new(
                move |sender: &Option<GattLocalCharacteristic>, _: &Option<IInspectable>| {
                    if let Some(sender) = sender {
                        let mut updated = HashSet::new();
                        if let Ok(clients) = sender.SubscribedClients() {
                            if let Ok(size) = clients.Size() {
                                for idx in 0..size {
                                    if let Ok(client) = clients.GetAt(idx) {
                                        if let Ok(session) = client.Session() {
                                            if let Some(device_id) =
                                                try_extract_session_device_id(&session)
                                            {
                                                updated.insert(device_id);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        let count = updated.len();
                        if let Ok(mut guard) = subscribers_for_event.lock() {
                            *guard = updated;
                        }
                        crate::write_debug_log(&format!(
                            "BLE peripheral subscribers={} ({})",
                            count, device_name_for_subscribers
                        ));
                    }
                    Ok(())
                },
            )) {
                Ok(token) => token,
                Err(e) => {
                    let _ = ui_tx
                        .send(format!(
                            "system: BLE peripheral bridge failed to bind subscriber callback: {}",
                            e
                        ))
                        .await;
                    return;
                }
            };

        let inbound_tx_write = inbound_tx.clone();
        let ui_tx_write = ui_tx.clone();
        let _write_token = match characteristic.WriteRequested(&TypedEventHandler::new(
            move |_: &Option<GattLocalCharacteristic>,
                  args: &Option<GattWriteRequestedEventArgs>| {
                if let Some(args) = args {
                    let deferral = args.GetDeferral().ok();
                    let write_request = match args.GetRequestAsync() {
                        Ok(op) => op.get(),
                        Err(e) => Err(e),
                    };
                    if let Ok(request) = write_request {
                        if let Ok(value) = request.Value() {
                            if let Ok(payload) = read_buffer_bytes(&value) {
                                let _ = inbound_tx_write.try_send(payload);
                            }
                        }
                        let _ = request.Respond();
                    } else {
                        let _ = ui_tx_write.try_send(
                            "system: BLE peripheral write request could not be resolved."
                                .to_string(),
                        );
                    }
                    if let Some(deferral) = deferral {
                        let _ = deferral.Complete();
                    }
                }
                Ok(())
            },
        )) {
            Ok(token) => token,
            Err(e) => {
                let _ = ui_tx
                    .send(format!(
                        "system: BLE peripheral bridge failed to bind write callback: {}",
                        e
                    ))
                    .await;
                return;
            }
        };

        let advertising_params = match GattServiceProviderAdvertisingParameters::new() {
            Ok(params) => params,
            Err(e) => {
                let _ = ui_tx
                    .send(format!(
                        "system: BLE peripheral bridge failed to create advertising parameters: {}",
                        e
                    ))
                    .await;
                return;
            }
        };
        let _ = advertising_params.SetIsConnectable(true);
        let _ = advertising_params.SetIsDiscoverable(true);
        match create_buffer(b"bc") {
            Ok(service_data) => {
                if let Err(e) = advertising_params.SetServiceData(&service_data) {
                    crate::write_debug_log(&format!(
                        "BLE peripheral bridge service data unavailable: {}",
                        e
                    ));
                }
            }
            Err(e) => {
                crate::write_debug_log(&format!(
                    "BLE peripheral bridge failed to create service data: {}",
                    e
                ));
            }
        }
        if let Err(e) = service_provider.StartAdvertisingWithParameters(&advertising_params) {
            let _ = ui_tx
                .send(format!(
                    "system: BLE peripheral bridge failed to start advertising: {}",
                    e
                ))
                .await;
            return;
        }

        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        if OUTBOUND_TX.set(tx).is_err() {
            return;
        }

        crate::write_debug_log(&format!(
            "BLE peripheral bridge active: name='{}' service={} characteristic={}",
            device_name, BITCHAT_SERVICE_UUID, BITCHAT_CHARACTERISTIC_UUID
        ));

        // Keep provider, characteristic and tokens alive in this task.
        let _provider_guard = service_provider;
        let characteristic_for_notify = characteristic.clone();
        let _subscribed_token_guard = _subscribed_token;
        let _write_token_guard = _write_token;

        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                if packet.is_empty() {
                    continue;
                }
                let should_send = subscribed_clients
                    .lock()
                    .ok()
                    .map(|set| !set.is_empty())
                    .unwrap_or(true);
                if !should_send {
                    continue;
                }

                if let Ok(buffer) = create_buffer(&packet) {
                    let _ = characteristic_for_notify
                        .NotifyValueAsync(&buffer)
                        .and_then(|op| op.get());
                }
            }
        });

        if peripheral_bridge_verbose() {
            let _ = ui_tx
                .send(format!(
                    "system: BLE peripheral bridge listener ready for writes on {}.",
                    device_name
                ))
                .await;
        }
    }

    pub fn queue_outbound_packet(packet: &[u8]) {
        if let Some(tx) = OUTBOUND_TX.get() {
            let _ = tx.send(packet.to_vec());
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_impl {
    use super::*;

    pub async fn start_bridge(
        _ui_tx: mpsc::Sender<String>,
        _nickname: String,
        _inbound_tx: mpsc::Sender<Vec<u8>>,
    ) {
    }

    pub fn queue_outbound_packet(_packet: &[u8]) {}
}

pub async fn start_ble_peripheral_bridge(
    ui_tx: mpsc::Sender<String>,
    nickname: String,
    inbound_tx: mpsc::Sender<Vec<u8>>,
) {
    windows_impl::start_bridge(ui_tx, nickname, inbound_tx).await;
}

pub fn queue_ble_peripheral_packet(packet: &[u8]) {
    windows_impl::queue_outbound_packet(packet);
}
