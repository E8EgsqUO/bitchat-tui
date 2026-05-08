use crate::data_structures::{DebugLevel, DeliveryTracker, MessageType, DEBUG_LEVEL};
use crate::encryption::EncryptionService;
use crate::fragmentation::{send_packet_with_fragmentation, should_fragment};
use crate::noise_session::NoiseSessionManager;
use crate::notification_handlers::write_noise_debug_log;
use crate::packet_creation::{
    create_bitchat_packet_for_signing_at, create_bitchat_packet_with_recipient,
    create_bitchat_packet_with_recipient_and_signature, create_bitchat_packet_with_signature_at,
    current_timestamp_ms,
};
use crate::payload_handling::{
    create_bitchat_message_payload_full, create_encrypted_channel_message_payload,
    create_private_noise_payload,
};
use crate::terminal_ux::{format_message_display, ChatContext};
use btleplug::api::{Peripheral, WriteType};
use btleplug::platform::Peripheral as PlatformPeripheral;
use chrono::Local;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use tokio::sync::mpsc;
use uuid::Uuid;

fn write_send_debug_log(message: &str) {
    if !crate::data_structures::file_logging_enabled() {
        return;
    }

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("send_debug.log")
    {
        let _ = writeln!(
            file,
            "[{}] {}",
            Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            message
        );
    }
}

// Handler for private DM messages using Noise protocol
pub async fn handle_private_dm_message(
    message: &str,
    target_peer_id: &str,
    noise_session_manager: &mut Option<NoiseSessionManager>,
    peripheral: &impl btleplug::api::Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    my_peer_id: &str,
    ui_tx: mpsc::Sender<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    write_noise_debug_log(&format!(
        "[DEBUG] Starting handle_private_dm_message to peer: {}",
        target_peer_id
    ));

    // Check if we have a noise session manager
    write_noise_debug_log("[DEBUG] Checking if noise session manager exists");
    let noise_manager = match noise_session_manager {
        Some(manager) => {
            write_noise_debug_log("[DEBUG] Noise session manager found");
            manager
        }
        None => {
            write_noise_debug_log("[DEBUG] No noise session manager available");
            return Err("No noise session manager available".into());
        }
    };

    // Check if we have an established session
    write_noise_debug_log(&format!(
        "[DEBUG] Checking if session is established for peer: {}",
        target_peer_id
    ));
    if !noise_manager.has_established_session(target_peer_id) {
        write_noise_debug_log(&format!(
            "[DEBUG] No established session for peer: {}, initiating handshake",
            target_peer_id
        ));

        // Initiate handshake
        write_noise_debug_log("[DEBUG] About to create session as initiator");
        match noise_manager.create_session(
            target_peer_id.to_string(),
            crate::noise_protocol::NoiseRole::Initiator,
        ) {
            Ok(_) => {
                write_noise_debug_log("[DEBUG] Session created successfully");

                // Store the message as pending
                write_noise_debug_log("[DEBUG] About to store message as pending");
                match noise_manager.store_pending_message(target_peer_id, message.to_string()) {
                    Ok(_) => {
                        write_noise_debug_log("[DEBUG] Message stored as pending successfully");

                        // Send handshake initiation
                        write_noise_debug_log("[DEBUG] About to initiate handshake");
                        match noise_manager.initiate_handshake(target_peer_id) {
                            Ok(handshake_data) => {
                                write_noise_debug_log(&format!(
                                    "[DEBUG] Handshake initiated, data length: {}",
                                    handshake_data.len()
                                ));

                                // Create and send the handshake packet
                                write_noise_debug_log("[DEBUG] About to create handshake packet");
                                let handshake_packet = create_bitchat_packet_with_recipient(
                                    my_peer_id,
                                    Some(target_peer_id),
                                    crate::data_structures::MessageType::NoiseHandshakeInit,
                                    handshake_data,
                                    None,
                                );

                                write_noise_debug_log("[DEBUG] About to send handshake packet");
                                match peripheral
                                    .write(
                                        cmd_char,
                                        &handshake_packet,
                                        btleplug::api::WriteType::WithoutResponse,
                                    )
                                    .await
                                {
                                    Ok(_) => {
                                        write_noise_debug_log(
                                            "[DEBUG] Handshake packet sent successfully",
                                        );
                                        let _ = ui_tx
                                            .send(format!(
                                                "[DM] Handshake initiated with {}\n> ",
                                                target_peer_id
                                            ))
                                            .await;
                                    }
                                    Err(e) => {
                                        write_noise_debug_log(&format!(
                                            "[DEBUG] Failed to send handshake packet: {:?}",
                                            e
                                        ));
                                        return Err(
                                            format!("Failed to send handshake: {}", e).into()
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                write_noise_debug_log(&format!(
                                    "[DEBUG] Failed to initiate handshake: {:?}",
                                    e
                                ));
                                return Err(format!("Failed to initiate handshake: {}", e).into());
                            }
                        }
                    }
                    Err(e) => {
                        write_noise_debug_log(&format!(
                            "[DEBUG] Failed to store pending message: {:?}",
                            e
                        ));
                        return Err(format!("Failed to store pending message: {}", e).into());
                    }
                }
            }
            Err(e) => {
                write_noise_debug_log(&format!("[DEBUG] Failed to create session: {:?}", e));
                return Err(format!("Failed to create session: {}", e).into());
            }
        }
    } else {
        write_noise_debug_log("[DEBUG] Session is established, sending encrypted message");

        // Send encrypted message
        write_noise_debug_log("[DEBUG] About to encrypt message");

        // Create iOS-compatible Noise private message payload.
        write_noise_debug_log(&format!(
            "[DEBUG] Creating private Noise payload for message: '{}'",
            message
        ));
        let message_id = Uuid::new_v4().to_string();
        let noise_payload = create_private_noise_payload(&message_id, message)
            .map_err(|e| format!("Failed to create private Noise payload: {}", e))?;
        write_noise_debug_log(&format!(
            "[DEBUG] Created private Noise payload, length: {}, message_id: {}",
            noise_payload.len(),
            message_id
        ));
        write_noise_debug_log(&format!(
            "[DEBUG] Payload bytes: {:?}",
            &noise_payload[..std::cmp::min(32, noise_payload.len())]
        ));

        write_noise_debug_log(&format!(
            "[DEBUG] About to encrypt message with Noise for peer: {}",
            target_peer_id
        ));
        match noise_manager.encrypt_message(target_peer_id, &noise_payload) {
            Ok(encrypted_data) => {
                write_noise_debug_log(&format!(
                    "[DEBUG] Message encrypted successfully, length: {}, first 16 bytes: {:?}",
                    encrypted_data.len(),
                    &encrypted_data[..std::cmp::min(16, encrypted_data.len())]
                ));

                // Create and send the encrypted message packet
                write_noise_debug_log(&format!(
                    "[DEBUG] About to create encrypted message packet for peer: {}",
                    target_peer_id
                ));
                let encrypted_packet = create_bitchat_packet_with_recipient(
                    my_peer_id,
                    Some(target_peer_id),
                    crate::data_structures::MessageType::NoiseEncrypted,
                    encrypted_data.clone(),
                    None,
                );

                write_noise_debug_log(&format!(
                    "[DEBUG] Created encrypted packet, length: {}, about to send via Bluetooth",
                    encrypted_packet.len()
                ));
                match peripheral
                    .write(
                        cmd_char,
                        &encrypted_packet,
                        btleplug::api::WriteType::WithoutResponse,
                    )
                    .await
                {
                    Ok(_) => {
                        write_noise_debug_log(&format!(
                            "[DEBUG] Encrypted message sent successfully to peer: {}",
                            target_peer_id
                        ));
                        let _ = ui_tx
                            .send(format!("[DM] Message sent to {}\n> ", target_peer_id))
                            .await;
                    }
                    Err(e) => {
                        write_noise_debug_log(&format!(
                            "[DEBUG] Failed to send encrypted message via Bluetooth: {:?}",
                            e
                        ));
                        return Err(format!("Failed to send encrypted message: {}", e).into());
                    }
                }
            }
            Err(e) => {
                write_noise_debug_log(&format!(
                    "[DEBUG] Failed to encrypt message with Noise: {:?}",
                    e
                ));
                return Err(format!("Failed to encrypt message: {}", e).into());
            }
        }
    }

    write_noise_debug_log("[DEBUG] Completed handle_private_dm_message");
    Ok(())
}

// Fallback handler using the old encryption method
async fn handle_private_dm_message_fallback(
    line: &str,
    nickname: &str,
    my_peer_id: &str,
    target_nickname: &str,
    target_peer_id: &str,
    delivery_tracker: &mut DeliveryTracker,
    encryption_service: &EncryptionService,
    peripheral: &PlatformPeripheral,
    cmd_char: &btleplug::api::Characteristic,
    chat_context: &ChatContext,
    ui_tx: mpsc::Sender<String>,
) {
    let (message_payload, message_id) =
        create_bitchat_message_payload_full(nickname, line, None, true, my_peer_id);
    delivery_tracker.track_message(message_id.clone(), line.to_string(), true);

    let block_sizes = [256, 512, 1024, 2048];
    let payload_size = message_payload.len();
    let target_size = block_sizes
        .iter()
        .find(|&&size| payload_size + 16 <= size)
        .copied()
        .unwrap_or(payload_size);
    let padding_needed = target_size - message_payload.len();
    let mut padded_payload = message_payload;

    if padding_needed > 0 && padding_needed <= 255 {
        for _ in 0..padding_needed {
            padded_payload.push(padding_needed as u8);
        }
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx
                .send(format!(
                    "[PRIVATE] Added {} bytes of PKCS#7 padding\n",
                    padding_needed
                ))
                .await;
        }
    } else if padding_needed == 0 && unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx
            .send("[PRIVATE] Message already at block size, no padding needed\n".to_string())
            .await;
    }

    match encryption_service.encrypt(&padded_payload, target_peer_id) {
        Ok(encrypted) => {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx
                    .send(format!(
                        "[PRIVATE] Encrypted payload: {} bytes\n",
                        encrypted.len()
                    ))
                    .await;
            }

            let signature = encryption_service.sign(&encrypted);
            let packet = create_bitchat_packet_with_recipient_and_signature(
                my_peer_id,
                target_peer_id,
                MessageType::Message,
                encrypted,
                Some(signature),
            );

            if send_packet_with_fragmentation(peripheral, cmd_char, packet, my_peer_id)
                .await
                .is_err()
            {
                let _ = ui_tx.send("\n\x1b[91mâŒ Failed to send private message\x1b[0m\n\x1b[90mThe message could not be delivered. Connection may have been lost.\x1b[0m\n".to_string()).await;
            } else {
                // Don't send any formatted message here - let the main loop handle it via the TUI
            }
        }
        Err(e) => {
            let _ = ui_tx
                .send(format!("[!] Failed to encrypt private message: {:?}\n", e))
                .await;
            let _ = ui_tx
                .send(format!(
                    "[!] Make sure you have received key exchange from {}\n",
                    target_nickname
                ))
                .await;
        }
    }
}

// Handler for private DM messages using Noise protocol
async fn handle_private_dm_message_via_noise(
    line: &str,
    nickname: &str,
    my_peer_id: &str,
    target_nickname: &str,
    target_peer_id: &str,
    delivery_tracker: &mut DeliveryTracker,
    noise_session_manager: &mut NoiseSessionManager,
    peripheral: &PlatformPeripheral,
    cmd_char: &btleplug::api::Characteristic,
    _chat_context: &ChatContext,
    ui_tx: mpsc::Sender<String>,
) {
    // Create the inner message
    let (message_payload, message_id) =
        create_bitchat_message_payload_full(nickname, line, None, true, my_peer_id);
    delivery_tracker.track_message(message_id.clone(), line.to_string(), true);

    // Create inner packet as Vec<u8> (raw binary data, no extra wrapping)
    let inner_data = create_bitchat_packet_with_recipient_and_signature(
        my_peer_id,
        target_peer_id,
        MessageType::Message,
        message_payload,
        None,
    );

    // Encrypt with Noise (raw handshake bytes, no extra wrapping)
    match noise_session_manager.encrypt(&inner_data, target_peer_id) {
        Ok(encrypted_data) => {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx
                    .send(format!(
                        "[NOISE] Successfully encrypted message, size: {}\n",
                        encrypted_data.len()
                    ))
                    .await;
            }

            // Send as Noise encrypted message (raw encrypted bytes, no extra wrapping)
            let outer_packet = create_bitchat_packet_with_recipient_and_signature(
                my_peer_id,
                target_peer_id,
                MessageType::NoiseEncrypted,
                encrypted_data,
                None,
            );

            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx
                    .send(format!(
                        "[NOISE] Sending encrypted private message {} to {}\n",
                        message_id, target_peer_id
                    ))
                    .await;
            }

            if send_packet_with_fragmentation(peripheral, cmd_char, outer_packet, my_peer_id)
                .await
                .is_err()
            {
                let _ = ui_tx.send("\n\x1b[91mâŒ Failed to send private message\x1b[0m\n\x1b[90mThe message could not be delivered. Connection may have been lost.\x1b[0m\n".to_string()).await;
            }
        }
        Err(e) => {
            let _ = ui_tx
                .send(format!("[!] Failed to encrypt private message: {:?}\n", e))
                .await;
            let _ = ui_tx
                .send(format!(
                    "[!] Make sure you have established a Noise session with {}\n",
                    target_nickname
                ))
                .await;
        }
    }
}

// Handler for regular public/channel messages
pub async fn handle_regular_message(
    line: &str,
    nickname: &str,
    my_peer_id: &str,
    _chat_context: &ChatContext,
    password_protected_channels: &HashSet<String>,
    channel_keys: &mut HashMap<String, [u8; 32]>,
    encryption_service: &EncryptionService,
    delivery_tracker: &mut DeliveryTracker,
    peripheral: &PlatformPeripheral,
    cmd_char: &btleplug::api::Characteristic,
    ui_tx: mpsc::Sender<String>,
    _app: &mut crate::tui::app::App,
) {
    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx
            .send(format!("{} > {}\n", _chat_context.format_prompt(), line))
            .await;
    }

    let current_channel = _chat_context
        .current_mode
        .get_channel()
        .map(|s| s.to_string());

    if let Some(ref channel) = current_channel {
        if password_protected_channels.contains(channel) && !channel_keys.contains_key(channel) {
            let _ = ui_tx
                .send(format!(
                    "âŒ Cannot send to password-protected channel {}. Join with password first.\n",
                    channel
                ))
                .await;
            return;
        }

        // Note: We can't easily verify if the user has the wrong password here without the original password
        // The warning about wrong passwords is handled in the join command when they try to rejoin
    }

    let (message_payload, message_id) = if current_channel.is_none() {
        (line.as_bytes().to_vec(), Uuid::new_v4().to_string())
    } else if let Some(ref channel) = current_channel {
        if let Some(channel_key) = channel_keys.get(channel) {
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx
                    .send(format!(
                        "[ENCRYPT] Encrypting message for channel {} ðŸ”’\n",
                        channel
                    ))
                    .await;
            }
            create_encrypted_channel_message_payload(
                nickname,
                line,
                channel,
                channel_key,
                encryption_service,
                my_peer_id,
            )
        } else {
            create_bitchat_message_payload_full(
                nickname,
                line,
                current_channel.as_deref(),
                false,
                my_peer_id,
            )
        }
    } else {
        unreachable!()
    };

    delivery_tracker.track_message(message_id.clone(), line.to_string(), false);

    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx
            .send(
                "[MESSAGE] ==================== SENDING USER MESSAGE ====================\n"
                    .to_string(),
            )
            .await;
        let _ = ui_tx
            .send(format!("[MESSAGE] Message content: '{}'\n", line))
            .await;
        let _ = ui_tx
            .send(format!(
                "[MESSAGE] Message payload size: {} bytes\n",
                message_payload.len()
            ))
            .await;
    }

    let message_timestamp = current_timestamp_ms();
    let message_signature_payload = create_bitchat_packet_for_signing_at(
        my_peer_id,
        None,
        MessageType::Message,
        &message_payload,
        message_timestamp,
    );
    let message_signature = encryption_service.sign(&message_signature_payload);
    let message_packet = create_bitchat_packet_with_signature_at(
        my_peer_id,
        MessageType::Message,
        message_payload.clone(),
        Some(message_signature),
        message_timestamp,
    );
    write_send_debug_log(&format!(
        "public message: content={:?}, peer_id={}, packet_len={}, type=0x{:02x}, ttl={}, flags=0x{:02x}, payload_len={}, packet_hex={}",
        line,
        my_peer_id,
        message_packet.len(),
        message_packet.get(1).copied().unwrap_or_default(),
        message_packet.get(2).copied().unwrap_or_default(),
        message_packet.get(11).copied().unwrap_or_default(),
        message_packet
            .get(12..14)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
            .unwrap_or_default(),
        hex::encode(&message_packet)
    ));

    // THIS BLOCK IS NOW CORRECT
    let send_result: Result<(), Box<dyn Error>> = if should_fragment(&message_packet) {
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx
                .send(format!(
                    "[MESSAGE] Complete packet ({} bytes) requires fragmentation\n",
                    message_packet.len()
                ))
                .await;
        }
        send_packet_with_fragmentation(peripheral, cmd_char, message_packet, my_peer_id).await
    } else {
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx
                .send(format!(
                    "[MESSAGE] Sending message as single packet ({} bytes)\n",
                    message_packet.len()
                ))
                .await;
        }
        let write_type = if cfg!(target_os = "windows") || message_packet.len() > 512 {
            WriteType::WithResponse
        } else {
            WriteType::WithoutResponse
        };
        let write_result = peripheral
            .write(cmd_char, &message_packet, write_type)
            .await;
        write_send_debug_log(&format!(
            "public message write result: write_type={:?}, result={:?}",
            write_type,
            write_result.as_ref().map(|_| ())
        ));
        write_result.map_err(Into::into)
    };

    if let Err(_) = send_result {
        let _ = ui_tx.send("\n\x1b[91mâŒ Message delivery failed\x1b[0m\n\x1b[90mConnection lost. Please restart BitChat to reconnect.\x1b[0m\n".to_string()).await;
        return;
    }

    if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
        let _ = ui_tx
            .send("[MESSAGE] âœ“ Successfully sent message packet\n".to_string())
            .await;
        let _ = ui_tx
            .send(
                "[MESSAGE] ==================== MESSAGE SEND COMPLETE ====================\n"
                    .to_string(),
            )
            .await;
    }

    let timestamp = Local::now();
    let display = format_message_display(
        timestamp,
        nickname,
        line,
        false,
        current_channel.is_some(),
        current_channel.as_deref(),
        None,
        nickname,
    );
    let _ = ui_tx.send(format!("\x1b[1A\r\x1b[K{}\n", display)).await;
}
