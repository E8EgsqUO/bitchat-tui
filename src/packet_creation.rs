use crate::data_structures::{MessageType, FLAG_HAS_RECIPIENT, FLAG_HAS_SIGNATURE};
use crate::debug_full_println;
use hex;
use std::time::SystemTime;

// Standard block sizes for padding (matching Swift)
const BLOCK_SIZES: [usize; 4] = [256, 512, 1024, 2048];
const DEFAULT_TTL: u8 = 7;

// Find optimal block size for data (matching Swift's MessagePadding.optimalBlockSize)
fn optimal_block_size_for_padding(data_size: usize) -> usize {
    // Account for encryption overhead (~16 bytes for AES-GCM tag)
    let total_size = data_size + 16;

    // Find smallest block that fits
    for &block_size in &BLOCK_SIZES {
        if total_size <= block_size {
            return block_size;
        }
    }

    // For very large messages, just use the original size
    // (will be fragmented anyway)
    data_size
}

// Add PKCS#7-style padding to reach target size (matching Swift's MessagePadding.pad)
fn pad_message_to_size(data: Vec<u8>, target_size: usize) -> Vec<u8> {
    if data.len() >= target_size {
        return data;
    }

    let padding_needed = target_size - data.len();

    // PKCS#7 only supports padding up to 255 bytes
    // If we need more padding than that, don't pad - return original data
    if padding_needed > 255 {
        return data;
    }

    let mut padded = data;
    padded.extend(std::iter::repeat(padding_needed as u8).take(padding_needed));
    padded
}

pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn id_bytes_from_str(id: &str) -> Vec<u8> {
    match hex::decode(id) {
        Ok(bytes) => {
            let mut padded = bytes;
            if padded.len() < 8 {
                padded.extend(vec![0; 8 - padded.len()]);
            } else if padded.len() > 8 {
                padded.truncate(8);
            }
            padded
        }
        Err(_) => {
            let mut bytes = id.as_bytes().to_vec();
            if bytes.len() < 8 {
                bytes.resize(8, 0);
            } else if bytes.len() > 8 {
                bytes.truncate(8);
            }
            bytes
        }
    }
}

fn encode_unpadded_packet(
    sender_id_str: &str,
    recipient_id_str: Option<&str>,
    msg_type: MessageType,
    payload: &[u8],
    signature: Option<&[u8]>,
    ttl: u8,
    timestamp_ms: u64,
) -> Vec<u8> {
    let mut data = Vec::new();

    data.push(1u8);
    data.push(msg_type as u8);
    data.push(ttl);

    data.extend_from_slice(&timestamp_ms.to_be_bytes());

    let mut flags: u8 = 0;
    if recipient_id_str.is_some() {
        flags |= FLAG_HAS_RECIPIENT;
    }
    if signature.is_some() {
        flags |= FLAG_HAS_SIGNATURE;
    }
    data.push(flags);

    data.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    data.extend_from_slice(&id_bytes_from_str(sender_id_str));

    if let Some(recipient) = recipient_id_str {
        data.extend_from_slice(&id_bytes_from_str(recipient));
    }

    data.extend_from_slice(payload);

    if let Some(sig) = signature {
        data.extend_from_slice(&sig[..std::cmp::min(sig.len(), 64)]);
    }

    data
}

fn encode_unpadded_packet_v2(
    sender_id_str: &str,
    recipient_id_str: Option<&str>,
    msg_type: MessageType,
    payload: &[u8],
    signature: Option<&[u8]>,
    ttl: u8,
    timestamp_ms: u64,
) -> Vec<u8> {
    let mut data = Vec::new();

    data.push(2u8);
    data.push(msg_type as u8);
    data.push(ttl);
    data.extend_from_slice(&timestamp_ms.to_be_bytes());

    let mut flags: u8 = 0;
    if recipient_id_str.is_some() {
        flags |= FLAG_HAS_RECIPIENT;
    }
    if signature.is_some() {
        flags |= FLAG_HAS_SIGNATURE;
    }
    data.push(flags);

    data.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    data.extend_from_slice(&id_bytes_from_str(sender_id_str));

    if let Some(recipient) = recipient_id_str {
        data.extend_from_slice(&id_bytes_from_str(recipient));
    }

    data.extend_from_slice(payload);

    if let Some(sig) = signature {
        data.extend_from_slice(&sig[..std::cmp::min(sig.len(), 64)]);
    }

    data
}

pub fn create_bitchat_packet_for_signing(
    sender_id_str: &str,
    recipient_id_str: Option<&str>,
    msg_type: MessageType,
    payload: &[u8],
) -> Vec<u8> {
    create_bitchat_packet_for_signing_at(
        sender_id_str,
        recipient_id_str,
        msg_type,
        payload,
        current_timestamp_ms(),
    )
}

pub fn create_bitchat_packet_for_signing_at(
    sender_id_str: &str,
    recipient_id_str: Option<&str>,
    msg_type: MessageType,
    payload: &[u8],
    timestamp_ms: u64,
) -> Vec<u8> {
    let data = encode_unpadded_packet(
        sender_id_str,
        recipient_id_str,
        msg_type,
        payload,
        None,
        0,
        timestamp_ms,
    );
    let optimal_size = optimal_block_size_for_padding(data.len());
    pad_message_to_size(data, optimal_size)
}

pub fn create_file_transfer_packet_for_signing_at(
    sender_id_str: &str,
    recipient_id_str: Option<&str>,
    payload: &[u8],
    timestamp_ms: u64,
) -> Vec<u8> {
    let data = encode_unpadded_packet_v2(
        sender_id_str,
        recipient_id_str,
        MessageType::FileTransfer,
        payload,
        None,
        0,
        timestamp_ms,
    );
    let optimal_size = optimal_block_size_for_padding(data.len());
    pad_message_to_size(data, optimal_size)
}

pub fn create_file_transfer_packet_with_recipient_at(
    sender_id_str: &str,
    recipient_id_str: Option<&str>,
    payload: Vec<u8>,
    signature: Option<Vec<u8>>,
    timestamp_ms: u64,
) -> Vec<u8> {
    let data = encode_unpadded_packet_v2(
        sender_id_str,
        recipient_id_str,
        MessageType::FileTransfer,
        &payload,
        signature.as_deref(),
        DEFAULT_TTL,
        timestamp_ms,
    );

    if cfg!(target_os = "windows") {
        return data;
    }

    let optimal_size = optimal_block_size_for_padding(data.len());
    pad_message_to_size(data, optimal_size)
}

pub fn create_bitchat_packet_with_recipient_at(
    sender_id_str: &str,
    recipient_id_str: Option<&str>,
    msg_type: MessageType,
    payload: Vec<u8>,
    signature: Option<Vec<u8>>,
    timestamp_ms: u64,
) -> Vec<u8> {
    let data = encode_unpadded_packet(
        sender_id_str,
        recipient_id_str,
        msg_type,
        &payload,
        signature.as_deref(),
        DEFAULT_TTL,
        timestamp_ms,
    );

    if cfg!(target_os = "windows") {
        return data;
    }

    let optimal_size = optimal_block_size_for_padding(data.len());
    pad_message_to_size(data, optimal_size)
}

pub fn create_bitchat_packet_with_signature_at(
    sender_id_str: &str,
    msg_type: MessageType,
    payload: Vec<u8>,
    signature: Option<Vec<u8>>,
    timestamp_ms: u64,
) -> Vec<u8> {
    create_bitchat_packet_with_recipient_at(
        sender_id_str,
        None,
        msg_type,
        payload,
        signature,
        timestamp_ms,
    )
}

pub fn create_announcement_payload(
    nickname: &str,
    noise_public_key: &[u8],
    signing_public_key: &[u8],
) -> Option<Vec<u8>> {
    let nickname_bytes = nickname.as_bytes();
    if nickname_bytes.len() > 255 || noise_public_key.len() > 255 || signing_public_key.len() > 255
    {
        return None;
    }

    let mut data = Vec::with_capacity(
        2 + nickname_bytes.len() + 2 + noise_public_key.len() + 2 + signing_public_key.len(),
    );

    data.push(0x01);
    data.push(nickname_bytes.len() as u8);
    data.extend_from_slice(nickname_bytes);

    data.push(0x02);
    data.push(noise_public_key.len() as u8);
    data.extend_from_slice(noise_public_key);

    data.push(0x03);
    data.push(signing_public_key.len() as u8);
    data.extend_from_slice(signing_public_key);

    Some(data)
}

pub fn create_bitchat_packet(
    sender_id_str: &str,
    msg_type: MessageType,
    payload: Vec<u8>,
) -> Vec<u8> {
    create_bitchat_packet_with_recipient(sender_id_str, None, msg_type, payload, None)
}

pub fn create_bitchat_packet_with_signature(
    sender_id_str: &str,
    msg_type: MessageType,
    payload: Vec<u8>,
    signature: Option<Vec<u8>>,
) -> Vec<u8> {
    create_bitchat_packet_with_recipient(sender_id_str, None, msg_type, payload, signature)
}

pub fn create_bitchat_packet_with_recipient_and_signature(
    sender_id_str: &str,
    recipient_id_str: &str,
    msg_type: MessageType,
    payload: Vec<u8>,
    signature: Option<Vec<u8>>,
) -> Vec<u8> {
    create_bitchat_packet_with_recipient(
        sender_id_str,
        Some(recipient_id_str),
        msg_type,
        payload,
        signature,
    )
}

pub fn create_bitchat_packet_with_recipient(
    sender_id_str: &str,
    recipient_id_str: Option<&str>,
    msg_type: MessageType,
    payload: Vec<u8>,
    signature: Option<Vec<u8>>,
) -> Vec<u8> {
    debug_full_println!("[PACKET] ==================== PACKET CREATION START ====================");
    debug_full_println!(
        "[PACKET] Creating packet: type={:?} (0x{:02X}), sender_id={}, payload_len={}",
        msg_type,
        msg_type as u8,
        sender_id_str,
        payload.len()
    );
    debug_full_println!("[PACKET] Recipient: {:?}", recipient_id_str);
    debug_full_println!(
        "[PACKET] Payload first 32 bytes: {:?}",
        &payload[..std::cmp::min(32, payload.len())]
    );

    // SWIFT BINARYPROTOCOL FORMAT:
    // Header (Fixed 14 bytes):
    // - Version: 1 byte
    // - Type: 1 byte
    // - TTL: 1 byte
    // - Timestamp: 8 bytes (UInt64)
    // - Flags: 1 byte (bit 0: hasRecipient, bit 1: hasSignature, bit 2: isCompressed)
    // - PayloadLength: 2 bytes (UInt16)
    // Variable sections:
    // - SenderID: 8 bytes (fixed)
    // - RecipientID: 8 bytes (if hasRecipient flag set)
    // - Payload: Variable length
    // - Signature: 64 bytes (if hasSignature flag set)

    let mut data = Vec::new();

    // 1. Version (1 byte)
    let version = 1u8;
    data.push(version);

    // 2. Type (1 byte)
    let msg_type_byte = msg_type as u8;
    data.push(msg_type_byte);

    // 3. TTL (1 byte) - current iOS uses TransportConfig.messageTTLDefault = 7
    let ttl = DEFAULT_TTL;
    data.push(ttl);

    // 4. Timestamp (8 bytes, big-endian)
    let timestamp_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    data.extend_from_slice(&timestamp_ms.to_be_bytes());

    // 5. Flags (1 byte)
    let mut flags: u8 = 0;
    let has_recipient = recipient_id_str.is_some();
    if has_recipient {
        flags |= FLAG_HAS_RECIPIENT;
    }
    if signature.is_some() {
        flags |= FLAG_HAS_SIGNATURE;
    }
    // No compression for now
    data.push(flags);

    // 6. Payload length (2 bytes, big-endian)
    let payload_length = payload.len() as u16;
    data.extend_from_slice(&payload_length.to_be_bytes());

    debug_full_println!(
        "[PACKET] Header: version={}, type=0x{:02X}, ttl={}, flags=0x{:02X}, payload_len={}",
        version,
        msg_type_byte,
        ttl,
        flags,
        payload_length
    );

    // 7. Sender ID (8 bytes) - Convert hex string to binary bytes
    let sender_id_bytes = match hex::decode(sender_id_str) {
        Ok(bytes) => {
            let mut padded = bytes;
            if padded.len() < 8 {
                padded.extend(vec![0; 8 - padded.len()]);
            } else if padded.len() > 8 {
                padded.truncate(8);
            }
            padded
        }
        Err(_) => {
            // Fallback: treat as ASCII and pad
            let mut sender_id_bytes = sender_id_str.as_bytes().to_vec();
            if sender_id_bytes.len() < 8 {
                sender_id_bytes.resize(8, 0);
            } else if sender_id_bytes.len() > 8 {
                sender_id_bytes.truncate(8);
            }
            sender_id_bytes
        }
    };
    data.extend_from_slice(&sender_id_bytes);
    debug_full_println!(
        "[PACKET] Sender ID: {} -> {} bytes: {}",
        sender_id_str,
        sender_id_bytes.len(),
        hex::encode(&sender_id_bytes)
    );

    // 8. Recipient ID (8 bytes) - only if hasRecipient flag is set
    if has_recipient {
        if let Some(recipient) = recipient_id_str {
            // Private message - use specific recipient
            let recipient_bytes = match hex::decode(recipient) {
                Ok(bytes) => {
                    let mut padded = bytes;
                    if padded.len() < 8 {
                        padded.extend(vec![0; 8 - padded.len()]);
                    } else if padded.len() > 8 {
                        padded.truncate(8);
                    }
                    padded
                }
                Err(_) => {
                    // Fallback: treat as ASCII and pad
                    let mut recipient_bytes = recipient.as_bytes().to_vec();
                    if recipient_bytes.len() < 8 {
                        recipient_bytes.resize(8, 0);
                    } else if recipient_bytes.len() > 8 {
                        recipient_bytes.truncate(8);
                    }
                    recipient_bytes
                }
            };
            data.extend_from_slice(&recipient_bytes);
            debug_full_println!(
                "[PACKET] Recipient ID (private): {} -> {} bytes: {}",
                recipient,
                recipient_bytes.len(),
                hex::encode(&recipient_bytes)
            );
        }
    } else {
        debug_full_println!("[PACKET] No recipient ID (fragment packet)");
    }

    // 9. Payload (variable)
    data.extend_from_slice(&payload);
    debug_full_println!("[PACKET] Payload: {} bytes", payload.len());

    // 10. Signature (64 bytes if present)
    if let Some(sig) = &signature {
        data.extend_from_slice(sig);
        debug_full_println!("[PACKET] Signature: {} bytes", sig.len());
    }

    debug_full_println!("[PACKET] Final packet size: {} bytes", data.len());
    debug_full_println!("[PACKET] Full packet hex: {}", hex::encode(&data));

    // Calculate offsets for structure breakdown
    let mut offset = 0;
    debug_full_println!("[PACKET] Packet structure breakdown:");
    debug_full_println!(
        "[PACKET]   - Version (1 byte): {}",
        hex::encode(&data[offset..offset + 1])
    );
    offset += 1;
    debug_full_println!(
        "[PACKET]   - Type (1 byte): {}",
        hex::encode(&data[offset..offset + 1])
    );
    offset += 1;
    debug_full_println!(
        "[PACKET]   - TTL (1 byte): {}",
        hex::encode(&data[offset..offset + 1])
    );
    offset += 1;
    debug_full_println!(
        "[PACKET]   - Timestamp (8 bytes): {}",
        hex::encode(&data[offset..offset + 8])
    );
    offset += 8;
    debug_full_println!(
        "[PACKET]   - Flags (1 byte): {}",
        hex::encode(&data[offset..offset + 1])
    );
    offset += 1;
    debug_full_println!(
        "[PACKET]   - PayloadLength (2 bytes): {}",
        hex::encode(&data[offset..offset + 2])
    );
    offset += 2;
    debug_full_println!(
        "[PACKET]   - Sender ID (8 bytes): {}",
        hex::encode(&data[offset..offset + 8])
    );
    offset += 8;

    if has_recipient {
        debug_full_println!(
            "[PACKET]   - Recipient ID (8 bytes): {}",
            hex::encode(&data[offset..offset + 8])
        );
        offset += 8;
    }

    debug_full_println!(
        "[PACKET]   - Payload ({} bytes): {}",
        payload.len(),
        hex::encode(&data[offset..std::cmp::min(offset + 32, data.len())])
    );
    offset += payload.len();

    if signature.is_some() {
        debug_full_println!(
            "[PACKET]   - Signature (64 bytes): {}",
            hex::encode(&data[offset..std::cmp::min(offset + 32, data.len())])
        );
        // offset += SIGNATURE_SIZE;  // Not needed as we're done parsing
    }

    debug_full_println!("[PACKET] ==================== PACKET CREATION END ====================");

    if cfg!(target_os = "windows") {
        return data;
    }

    // Apply padding to standard block sizes for traffic analysis resistance (matching Swift)
    let optimal_size = optimal_block_size_for_padding(data.len());
    pad_message_to_size(data, optimal_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_payload_uses_ttl_zero_and_deterministic_padding() {
        let payload = b"hi";
        let timestamp = 0x0102_0304_0506_0708;
        let data = create_bitchat_packet_for_signing_at(
            "0102030405060708",
            None,
            MessageType::Message,
            payload,
            timestamp,
        );

        assert_eq!(data.len(), 256);
        assert_eq!(&data[..3], &[1, MessageType::Message as u8, 0]);
        assert_eq!(&data[3..11], &timestamp.to_be_bytes());
        assert_eq!(data[11], 0);
        assert_eq!(&data[12..14], &(payload.len() as u16).to_be_bytes());
        assert_eq!(&data[14..22], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&data[22..24], payload);
        assert!(data[24..].iter().all(|byte| *byte == 232));
    }

    #[test]
    fn announcement_payload_uses_current_tlv_format() {
        let payload = create_announcement_payload("anon", &[1; 32], &[2; 32]).unwrap();

        assert_eq!(payload[0], 0x01);
        assert_eq!(payload[1], 4);
        assert_eq!(&payload[2..6], b"anon");
        assert_eq!(payload[6], 0x02);
        assert_eq!(payload[7], 32);
        assert_eq!(&payload[8..40], &[1; 32]);
        assert_eq!(payload[40], 0x03);
        assert_eq!(payload[41], 32);
        assert_eq!(&payload[42..74], &[2; 32]);
    }

    #[test]
    fn file_transfer_packet_uses_v2_four_byte_payload_length() {
        let payload = vec![7u8; 70_000];
        let timestamp = 0x0102_0304_0506_0708;
        let data = create_file_transfer_packet_with_recipient_at(
            "0102030405060708",
            Some("1112131415161718"),
            payload.clone(),
            None,
            timestamp,
        );

        assert_eq!(data[0], 2);
        assert_eq!(data[1], MessageType::FileTransfer as u8);
        assert_eq!(data[2], DEFAULT_TTL);
        assert_eq!(&data[3..11], &timestamp.to_be_bytes());
        assert_eq!(data[11], FLAG_HAS_RECIPIENT);
        assert_eq!(&data[12..16], &(payload.len() as u32).to_be_bytes());
        assert_eq!(&data[16..24], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&data[24..32], &[17, 18, 19, 20, 21, 22, 23, 24]);
        assert_eq!(&data[32..32 + payload.len()], payload.as_slice());
    }
}
