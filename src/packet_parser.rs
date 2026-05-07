use crate::compression::decompress_zlib;
use crate::data_structures::{
    BitchatPacket, MessageType, FLAG_HAS_RECIPIENT, FLAG_HAS_SIGNATURE, FLAG_IS_COMPRESSED,
};
use crate::debug_full_println;
use crate::encryption::EncryptionService;
use hex;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::fs::OpenOptions;
use std::io::Write;

// Debug logging function
fn write_packet_debug_log(message: &str) {
    if !crate::data_structures::file_logging_enabled() {
        return;
    }

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("packet_debug.log")
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let log_entry = format!("[{}] {}\n", timestamp, message);
        let _ = file.write_all(log_entry.as_bytes());
    }
}

// Remove PKCS#7 padding from data (matching Swift's MessagePadding.unpad)
fn unpad_message(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return data.to_vec();
    }

    // Last byte tells us how much padding to remove
    let padding_length = data[data.len() - 1] as usize;

    // Validate PKCS#7 padding. Signed, unpadded packets can naturally end with
    // a small byte value, so only strip when every tail byte matches.
    if padding_length == 0 || padding_length > data.len() || padding_length > 255 {
        return data.to_vec();
    }
    let padding_start = data.len() - padding_length;
    if !data[padding_start..]
        .iter()
        .all(|byte| *byte as usize == padding_length)
    {
        return data.to_vec();
    }

    // Remove padding
    data[..padding_start].to_vec()
}

pub fn parse_bitchat_packet(data: &[u8]) -> Result<BitchatPacket, &'static str> {
    write_packet_debug_log(&format!(
        "Starting packet parsing, data length: {}",
        data.len()
    ));

    // Match current iOS: decode the frame as-is first, then retry after
    // removing padding. Binary fragments can legitimately end with bytes that
    // look like PKCS#7 padding.
    match parse_bitchat_packet_core(data) {
        Ok(packet) => Ok(packet),
        Err(first_error) => {
            let unpadded_data = unpad_message(data);
            write_packet_debug_log(&format!(
                "After unpadding, data length: {}",
                unpadded_data.len()
            ));

            if unpadded_data.len() == data.len() {
                return Err(first_error);
            }

            parse_bitchat_packet_core(&unpadded_data)
        }
    }
}

fn parse_bitchat_packet_core(unpadded_data: &[u8]) -> Result<BitchatPacket, &'static str> {
    // Swift BinaryProtocol format:
    // Header (Fixed 14 bytes for v1, 16 bytes for v2):
    // - Version: 1 byte
    // - Type: 1 byte
    // - TTL: 1 byte
    // - Timestamp: 8 bytes (UInt64)
    // - Flags: 1 byte (bit 0: hasRecipient, bit 1: hasSignature, bit 2: isCompressed)
    // - PayloadLength: 2 bytes (UInt16)

    const V1_HEADER_SIZE: usize = 14;
    const V2_HEADER_SIZE: usize = 16;
    const SENDER_ID_SIZE: usize = 8;
    const RECIPIENT_ID_SIZE: usize = 8;
    const SIGNATURE_SIZE: usize = 64;

    if unpadded_data.len() < V1_HEADER_SIZE + SENDER_ID_SIZE {
        write_packet_debug_log(&format!(
            "Packet too small: {} bytes, need at least {}",
            unpadded_data.len(),
            V1_HEADER_SIZE + SENDER_ID_SIZE
        ));
        return Err("Packet too small.");
    }

    let mut offset = 0;

    // 1. Version (1 byte)
    let version = unpadded_data[offset];
    offset += 1;
    if !crate::data_structures::ProtocolVersion::is_supported(version) {
        return Err("Unsupported version.");
    }

    // 2. Type (1 byte)
    let msg_type_raw = unpadded_data[offset];
    offset += 1;
    let msg_type = match msg_type_raw {
        0x01 => MessageType::Announce,
        0x02 => MessageType::Message,
        0x03 => MessageType::Leave,
        0x04 => MessageType::Message,
        0x05 => MessageType::FragmentStart,
        0x06 => MessageType::FragmentContinue,
        0x07 => MessageType::FragmentEnd,
        0x08 => MessageType::ChannelAnnounce,
        0x09 => MessageType::ChannelRetention,
        0x0A => MessageType::DeliveryAck,
        0x0B => MessageType::DeliveryStatusRequest,
        0x0C => MessageType::ReadReceipt,
        0x0D => MessageType::KeyExchange,

        // Noise Protocol messages
        0x10 => MessageType::NoiseHandshakeInit,
        0x11 => MessageType::NoiseEncrypted,
        0x12 => MessageType::NoiseHandshakeResp,
        0x13 => MessageType::NoiseIdentityAnnounce,

        // Current iOS uses one fragment packet type (0x20); route it through
        // the existing fragment reassembly handler.
        0x20 => MessageType::FragmentStart,
        0x21 => MessageType::RequestSync,
        0x22 => MessageType::FileTransfer,
        0x23 => MessageType::ProtocolNack,
        0x24 => MessageType::SystemValidation,
        0x25 => MessageType::HandshakeRequest,
        0x26 => MessageType::ProtocolAck,

        _ => return Err("Unknown message type."),
    };

    // 3. TTL (1 byte)
    let ttl = unpadded_data[offset];
    offset += 1;

    // 4. Timestamp (8 bytes) - read it properly
    let timestamp_bytes: [u8; 8] = unpadded_data[offset..offset + 8].try_into().unwrap();
    let timestamp = u64::from_be_bytes(timestamp_bytes);
    offset += 8;

    // 5. Flags (1 byte)
    let flags = unpadded_data[offset];
    offset += 1;
    let has_recipient = (flags & FLAG_HAS_RECIPIENT) != 0;
    let has_signature = (flags & FLAG_HAS_SIGNATURE) != 0;
    let is_compressed = (flags & FLAG_IS_COMPRESSED) != 0;
    let has_route = version >= 2 && (flags & 0x08) != 0;

    // 6. Payload length (v1: 2 bytes, v2: 4 bytes, big-endian)
    let length_field_size = if version >= 2 { 4 } else { 2 };
    let header_size = if version >= 2 {
        V2_HEADER_SIZE
    } else {
        V1_HEADER_SIZE
    };
    if unpadded_data.len() < offset + length_field_size {
        return Err("Packet too small for payload length.");
    }
    let payload_len = if version >= 2 {
        let payload_len_bytes: [u8; 4] = unpadded_data[offset..offset + 4].try_into().unwrap();
        u32::from_be_bytes(payload_len_bytes) as usize
    } else {
        let payload_len_bytes: [u8; 2] = unpadded_data[offset..offset + 2].try_into().unwrap();
        u16::from_be_bytes(payload_len_bytes) as usize
    };
    offset += length_field_size;

    debug_assert_eq!(offset, header_size);

    // 7. Sender ID (8 bytes)
    if unpadded_data.len() < offset + SENDER_ID_SIZE {
        return Err("Packet data shorter than expected.");
    }
    let sender_id = unpadded_data[offset..offset + SENDER_ID_SIZE].to_vec();
    // Convert 8-byte binary data to hex string (matching Swift's hexEncodedString())
    let sender_id_str = hex::encode(&sender_id);

    // Debug logging for sender ID parsing
    write_packet_debug_log(&format!("Raw sender ID bytes: {:?}", sender_id));
    write_packet_debug_log(&format!("Sender ID as hex: '{}'", sender_id_str));

    offset += SENDER_ID_SIZE;

    // 8. Recipient ID (8 bytes if hasRecipient flag set)
    let (recipient_id, recipient_id_str) = if has_recipient {
        if unpadded_data.len() < offset + RECIPIENT_ID_SIZE {
            return Err("Packet too small for recipient.");
        }
        let recipient_id = unpadded_data[offset..offset + RECIPIENT_ID_SIZE].to_vec();
        // Convert 8-byte binary data to hex string (matching Swift's hexEncodedString())
        let recipient_id_str = hex::encode(&recipient_id);
        debug_full_println!("[PACKET] Recipient ID raw bytes: {:?}", recipient_id);
        debug_full_println!("[PACKET] Recipient ID as string: '{}'", recipient_id_str);
        offset += RECIPIENT_ID_SIZE;
        (Some(recipient_id), Some(recipient_id_str))
    } else {
        (None, None)
    };

    // 9. Route (v2 only, optional): one count byte followed by N 8-byte hops.
    if has_route {
        if unpadded_data.len() < offset + 1 {
            return Err("Packet too small for route count.");
        }
        let route_count = unpadded_data[offset] as usize;
        offset += 1;
        let route_len = route_count
            .checked_mul(SENDER_ID_SIZE)
            .ok_or("Route too large.")?;
        if unpadded_data.len() < offset + route_len {
            return Err("Packet too small for route.");
        }
        offset += route_len;
    }

    // 9. Payload
    if unpadded_data.len() < offset + payload_len {
        return Err("Packet data shorter than expected.");
    }
    let mut payload = unpadded_data[offset..offset + payload_len].to_vec();
    offset += payload_len;

    // 10. Signature (64 bytes if hasSignature flag set)
    let signature = if has_signature {
        if unpadded_data.len() < offset + SIGNATURE_SIZE {
            return Err("Packet too small for signature.");
        }
        let signature_data = unpadded_data[offset..offset + SIGNATURE_SIZE].to_vec();
        offset += SIGNATURE_SIZE;
        Some(signature_data)
    } else {
        None
    };

    // Decompress if needed
    if is_compressed {
        let original_size_field_len = if version >= 2 { 4 } else { 2 };
        if payload.len() < original_size_field_len {
            return Err("Compressed payload too short.");
        }

        let mut original_size = 0usize;
        for byte in &payload[..original_size_field_len] {
            original_size = (original_size << 8) | usize::from(*byte);
        }

        let compressed_payload = &payload[original_size_field_len..];
        if compressed_payload.is_empty() {
            return Err("Compressed payload missing data.");
        }

        match decompress_zlib(compressed_payload, original_size) {
            Ok(decompressed) => payload = decompressed,
            Err(_) => return Err("Failed to decompress payload"),
        }
    }

    Ok(BitchatPacket {
        version,
        msg_type,
        sender_id,
        sender_id_str,
        recipient_id,
        recipient_id_str,
        timestamp,
        payload,
        signature,
        ttl,
    })
}

pub fn generate_keys_and_payload(encryption_service: &EncryptionService) -> (Vec<u8>, String) {
    // Use the encryption service to get the combined public key data
    let payload = encryption_service.get_combined_public_key_data();

    // Generate fingerprint from identity key (last 32 bytes of the 96-byte payload)
    let identity_key_bytes = &payload[64..96];
    let mut hasher = Sha256::new();
    hasher.update(identity_key_bytes);
    let hash_result = hasher.finalize();
    let fingerprint = hex::encode(&hash_result[..8]);

    (payload, fingerprint)
}

#[cfg(test)]
mod tests {
    use super::parse_bitchat_packet;
    use crate::data_structures::{MessageType, FLAG_HAS_SIGNATURE, FLAG_IS_COMPRESSED};

    fn signed_message_packet(signature_last_byte: u8) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(1); // version
        data.push(MessageType::Message as u8);
        data.push(7); // ttl
        data.extend_from_slice(&0u64.to_be_bytes());
        data.push(FLAG_HAS_SIGNATURE);
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        data.push(b'x');
        data.extend_from_slice(&[0u8; 63]);
        data.push(signature_last_byte);
        data
    }

    #[test]
    fn signed_packet_tail_is_not_false_padding() {
        let data = signed_message_packet(3);

        let packet = parse_bitchat_packet(&data).expect("signed packet should parse");

        assert_eq!(packet.msg_type, MessageType::Message);
        assert_eq!(packet.payload, b"x");
        assert_eq!(packet.signature.unwrap().len(), 64);
    }

    #[test]
    fn valid_pkcs7_padding_does_not_break_parsing() {
        let mut data = signed_message_packet(4);
        data.extend_from_slice(&[4, 4, 4, 4]);

        let packet = parse_bitchat_packet(&data).expect("padded signed packet should parse");

        assert_eq!(packet.msg_type, MessageType::Message);
        assert_eq!(packet.payload, b"x");
        assert_eq!(packet.signature.unwrap().last(), Some(&4));
    }

    #[test]
    fn unpadded_binary_payload_tail_is_not_false_padding() {
        let mut data = Vec::new();
        data.push(1); // version
        data.push(MessageType::Message as u8);
        data.push(7); // ttl
        data.extend_from_slice(&0u64.to_be_bytes());
        data.push(0); // flags
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        data.push(1);

        let packet = parse_bitchat_packet(&data).expect("binary payload should parse");

        assert_eq!(packet.msg_type, MessageType::Message);
        assert_eq!(packet.payload, [1]);
    }

    #[test]
    fn v1_compressed_fragment_uses_zlib_with_two_byte_original_size() {
        let mut original_payload = Vec::new();
        original_payload.extend_from_slice(&[0x87, 0x0d, 0x1a, 0x82, 0x10, 0x49, 0x60, 0xdc]);
        original_payload.extend_from_slice(&0u16.to_be_bytes());
        original_payload.extend_from_slice(&1u16.to_be_bytes());
        original_payload.push(MessageType::FileTransfer as u8);
        original_payload.extend_from_slice(b"file-bytes");

        let compressed = miniz_oxide::deflate::compress_to_vec(&original_payload, 6);
        let mut payload = Vec::new();
        payload.extend_from_slice(&(original_payload.len() as u16).to_be_bytes());
        payload.extend_from_slice(&compressed);

        let mut data = Vec::new();
        data.push(1); // version
        data.push(0x20); // current iOS fragment packet type
        data.push(7); // ttl
        data.extend_from_slice(&0u64.to_be_bytes());
        data.push(FLAG_IS_COMPRESSED);
        data.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        data.extend_from_slice(&payload);

        let packet = parse_bitchat_packet(&data).expect("compressed fragment should parse");

        assert_eq!(packet.msg_type, MessageType::FragmentStart);
        assert_eq!(packet.payload, original_payload);
    }

    #[test]
    fn v2_file_transfer_packet_uses_four_byte_payload_length() {
        let payload = b"file".to_vec();
        let mut data = Vec::new();
        data.push(2); // version
        data.push(MessageType::FileTransfer as u8);
        data.push(7); // ttl
        data.extend_from_slice(&0u64.to_be_bytes());
        data.push(0); // flags
        data.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        data.extend_from_slice(&payload);

        let packet = parse_bitchat_packet(&data).expect("v2 file transfer packet should parse");

        assert_eq!(packet.version, 2);
        assert_eq!(packet.msg_type, MessageType::FileTransfer);
        assert_eq!(packet.payload, b"file");
    }
}
