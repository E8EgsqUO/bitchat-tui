use crate::data_structures::{DebugLevel, DeliveryTracker, MessageType, Peer, DEBUG_LEVEL};
use crate::encryption::EncryptionService;
use crate::fragmentation::send_packet_with_fragmentation_as;
use crate::noise_session::NoiseSessionManager;
use crate::packet_creation::{
    create_bitchat_packet, create_bitchat_packet_with_recipient,
    create_file_transfer_packet_for_signing_at, create_file_transfer_packet_with_recipient_at,
    current_timestamp_ms,
};
use crate::payload_handling::create_private_noise_payload;
use crate::persistence::{encrypt_password, save_state, AppState, EncryptedPassword};
use crate::terminal_ux::{ChatContext, ChatMode};
use btleplug::api::{Characteristic, Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
use chrono;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use uuid::Uuid;

async fn send_packet_to_mesh_targets(
    targets: &[(Peripheral, Characteristic)],
    packet: Vec<u8>,
    my_peer_id: &str,
    msg_type: MessageType,
) -> Result<(), Box<dyn std::error::Error>> {
    let peripheral_transport_ready = crate::ble_peripheral::ble_peripheral_transport_ready();
    if targets.is_empty() && !peripheral_transport_ready {
        return Err("No Bluetooth mesh links available".into());
    }

    let mut sent_any = false;
    let mut errors = Vec::new();
    for (idx, (peripheral, cmd_char)) in targets.iter().enumerate() {
        match send_packet_with_fragmentation_as(
            peripheral,
            cmd_char,
            packet.clone(),
            my_peer_id,
            msg_type,
        )
        .await
        {
            Ok(()) => sent_any = true,
            Err(e) => errors.push(format!("link {}: {}", idx + 1, e)),
        }
    }

    if peripheral_transport_ready {
        crate::ble_peripheral::queue_ble_peripheral_packet(&packet);
        // Peripheral transport means we have at least one notify subscriber.
        // Treat queueing as success even when central links fail.
        sent_any = true;
    }

    if sent_any {
        Ok(())
    } else {
        Err(format!("all mesh sends failed: {}", errors.join("; ")).into())
    }
}

fn is_mesh_write_failure(error_text: &str) -> bool {
    let lower = error_text.to_ascii_lowercase();
    error_text.contains("0x80000013")
        || error_text.contains("对象已关闭")
        || error_text.contains("0x80650003")
        || error_text.contains("无法写入属性")
        || (lower.contains("object") && lower.contains("closed"))
        || (lower.contains("write") && lower.contains("failed"))
}

const MAX_FILE_TRANSFER_BYTES: u64 = 1024 * 1024;

fn strip_display_suffix(target: &str) -> &str {
    let trimmed = target.trim();
    let Some((base, suffix)) = trimmed.rsplit_once('#') else {
        return trimmed;
    };
    if base.is_empty() || suffix.len() != 4 || !suffix.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return trimmed;
    }
    base
}

fn persistent_channels(chat_context: &ChatContext) -> Vec<String> {
    let mut channels: Vec<String> = chat_context
        .active_channels
        .iter()
        .filter_map(|channel| {
            let trimmed = channel.trim();
            if trimmed.is_empty() || trimmed == "#public" {
                return None;
            }
            Some(if trimmed.starts_with('#') {
                trimmed.to_string()
            } else {
                format!("#{}", trimmed)
            })
        })
        .collect();
    channels.sort();
    channels.dedup();
    channels
}

fn short_fingerprint(value: &str) -> String {
    value.chars().take(10).collect()
}

fn short_peer_id(value: &str) -> String {
    value.chars().take(8).collect()
}

fn normalize_block_target(value: &str) -> String {
    let mut trimmed = value
        .trim()
        .trim_start_matches('@')
        .trim_end_matches(':')
        .to_ascii_lowercase();
    if let Some((base, _)) = trimmed.split_once(" (") {
        trimmed = base.to_string();
    }
    if let Some((base, suffix)) = trimmed.rsplit_once('#') {
        if !base.is_empty() && suffix.len() == 4 && suffix.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            trimmed = base.to_string();
        }
    }
    trimmed
}

fn parse_name_with_optional_suffix(value: &str) -> (String, Option<String>) {
    let normalized = value
        .trim()
        .trim_start_matches('@')
        .trim_end_matches(':')
        .to_ascii_lowercase();
    if let Some(suffix) = normalized.strip_prefix('#') {
        if suffix.len() == 4 && suffix.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return ("".to_string(), Some(suffix.to_string()));
        }
    }
    if let Some((base, suffix)) = normalized.rsplit_once('#') {
        if !base.is_empty() && suffix.len() == 4 && suffix.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            return (normalize_block_target(base), Some(suffix.to_string()));
        }
    }
    (normalize_block_target(&normalized), None)
}

fn peer_suffix(peer_id: &str) -> String {
    let digest = Sha256::digest(peer_id.as_bytes());
    hex::encode(digest)[..4].to_string()
}

fn peer_display_token(nickname: &str, peer_id: &str) -> String {
    format!("{}#{}", nickname, peer_suffix(peer_id))
}

fn resolve_named_peers(
    peers: &HashMap<String, Peer>,
    target_name: &str,
) -> (Vec<(String, String)>, Vec<String>) {
    let (target_base, target_suffix) = parse_name_with_optional_suffix(target_name);
    if target_base.is_empty() && target_suffix.is_none() {
        return (Vec::new(), Vec::new());
    }
    let mut matches: Vec<(String, String)> = Vec::new();
    let mut labels: Vec<String> = Vec::new();

    for (peer_id, peer) in peers.iter() {
        let Some(nickname) = peer.nickname.as_ref() else {
            continue;
        };
        if !target_base.is_empty() && normalize_block_target(nickname) != target_base {
            continue;
        }
        let suffix = peer_suffix(peer_id);
        if let Some(target_suffix) = target_suffix.as_ref() {
            if &suffix != target_suffix {
                continue;
            }
        }
        matches.push((peer_id.clone(), nickname.clone()));
        labels.push(peer_display_token(nickname, peer_id));
    }

    labels.sort();
    labels.dedup();
    (matches, labels)
}

fn names_match(lhs: &str, rhs: &str) -> bool {
    let left = normalize_block_target(lhs);
    let right = normalize_block_target(rhs);
    !left.is_empty() && left == right
}

fn merge_manual_blocked_entries(blocked_entries: &mut Vec<String>, manual_entries: &[String]) {
    for entry in manual_entries {
        if blocked_entries
            .iter()
            .any(|existing| names_match(existing, entry))
        {
            continue;
        }
        if !entry.trim().is_empty() {
            blocked_entries.push(entry.trim().to_string());
        }
    }
    blocked_entries.sort();
}

fn add_manual_block_entry(app: &mut crate::tui::app::App, target_name: &str) {
    if app
        .blocked
        .iter()
        .any(|entry| names_match(entry, target_name))
    {
        return;
    }
    app.blocked
        .push(target_name.trim().trim_start_matches('@').to_string());
    app.blocked.sort();
}

fn remove_manual_block_entry(app: &mut crate::tui::app::App, target_name: &str) -> bool {
    let before = app.blocked.len();
    app.blocked.retain(|entry| !names_match(entry, target_name));
    before != app.blocked.len()
}

fn manual_block_entries(entries: &[String]) -> Vec<String> {
    let mut manual: Vec<String> = Vec::new();
    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() || trimmed.starts_with("fingerprint:") {
            continue;
        }
        if let Some((name, suffix_with_paren)) = trimmed.rsplit_once(" (") {
            if !name.trim().is_empty() && suffix_with_paren.ends_with(')') {
                let suffix = &suffix_with_paren[..suffix_with_paren.len() - 1];
                if suffix.len() == 10 && suffix.chars().all(|ch| ch.is_ascii_hexdigit()) {
                    continue;
                }
            }
        }
        if manual.iter().any(|existing| names_match(existing, trimmed)) {
            continue;
        }
        manual.push(trimmed.to_string());
    }
    manual.sort();
    manual
}

async fn collect_blocked_display_entries(
    blocked_peers: &HashSet<String>,
    peers: &Arc<Mutex<HashMap<String, Peer>>>,
    encryption_service: &EncryptionService,
) -> Vec<String> {
    let mut entries = Vec::new();
    let mut matched_fingerprints = HashSet::new();
    let peers_guard = peers.lock().await;

    for (peer_id, peer) in peers_guard.iter() {
        let Some(fingerprint) = encryption_service.get_peer_fingerprint(peer_id) else {
            continue;
        };
        if !blocked_peers.contains(&fingerprint) {
            continue;
        }
        matched_fingerprints.insert(fingerprint.clone());
        let label = if let Some(nickname) = &peer.nickname {
            format!("{} ({})", nickname, short_fingerprint(&fingerprint))
        } else {
            format!(
                "peer:{} ({})",
                short_peer_id(peer_id),
                short_fingerprint(&fingerprint)
            )
        };
        entries.push(label);
    }

    for fingerprint in blocked_peers.iter() {
        if !matched_fingerprints.contains(fingerprint) {
            entries.push(format!("fingerprint:{}", short_fingerprint(fingerprint)));
        }
    }

    entries.sort();
    entries
}

struct FileCommand<'a> {
    target_nickname: Option<&'a str>,
    path: &'a str,
}

pub(crate) struct GeohashFileOffer<'a> {
    pub(crate) target_nickname: Option<&'a str>,
    pub(crate) path: &'a str,
}

fn trim_path_quotes(path: &str) -> &str {
    let path = path.trim();
    if path.len() >= 2
        && ((path.starts_with('"') && path.ends_with('"'))
            || (path.starts_with('\'') && path.ends_with('\'')))
    {
        &path[1..path.len() - 1]
    } else {
        path
    }
}

fn parse_file_command(line: &str) -> Result<Option<FileCommand<'_>>, &'static str> {
    let Some(rest) = line.strip_prefix("/file") else {
        return Ok(None);
    };

    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
        return Ok(None);
    }

    let rest = rest.trim();
    if rest.is_empty() {
        return Err("Usage: /file [@user] <path>");
    }

    let mut parts = rest.splitn(2, char::is_whitespace);
    let first = parts.next().unwrap_or("");

    if let Some(target) = first.strip_prefix('@') {
        if target.is_empty() {
            return Err("Usage: /file [@user] <path>");
        }
        let Some(path) = parts.next().map(str::trim_start) else {
            return Err("Usage: /file [@user] <path>");
        };
        let path = trim_path_quotes(path);
        if path.is_empty() {
            return Err("Usage: /file [@user] <path>");
        }
        Ok(Some(FileCommand {
            target_nickname: Some(target),
            path,
        }))
    } else {
        let path = trim_path_quotes(rest);
        if path.is_empty() {
            return Err("Usage: /file [@user] <path>");
        }
        Ok(Some(FileCommand {
            target_nickname: None,
            path,
        }))
    }
}

pub(crate) fn parse_geohash_file_offer(
    line: &str,
) -> Result<Option<GeohashFileOffer<'_>>, &'static str> {
    let Some(rest) = line.strip_prefix("/file") else {
        return Ok(None);
    };

    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
        return Ok(None);
    }

    let rest = rest.trim();
    if rest.is_empty() {
        return Err("Usage: /file [@user] <path>");
    }

    let mut parts = rest.splitn(2, char::is_whitespace);
    let first = parts.next().unwrap_or("");
    if let Some(target) = first.strip_prefix('@') {
        if target.is_empty() {
            return Err("Usage: /file [@user] <path>");
        }
        let Some(path) = parts.next().map(str::trim_start) else {
            return Err("Usage: /file [@user] <path>");
        };
        let path = trim_path_quotes(path);
        if path.is_empty() {
            return Err("Usage: /file [@user] <path>");
        }
        return Ok(Some(GeohashFileOffer {
            target_nickname: Some(target),
            path,
        }));
    }

    let path = trim_path_quotes(rest);
    if path.is_empty() {
        return Err("Usage: /file [@user] <path>");
    }

    Ok(Some(GeohashFileOffer {
        target_nickname: None,
        path,
    }))
}

pub(crate) fn parse_receive_command(line: &str) -> Option<&str> {
    let Some(rest) = line.strip_prefix("/receive") else {
        return None;
    };
    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let rest = rest.trim();
    Some(rest)
}

pub(crate) fn extract_wormhole_code(text: &str) -> Option<String> {
    let code_re = Regex::new(r"\b[a-z0-9]{2,4}(?:-[a-z0-9]{2,4})+\b").ok()?;
    code_re.find(text).map(|m| m.as_str().to_string())
}

pub(crate) fn geohash_file_offer_message(code: &str, file_name: &str, file_size: u64) -> String {
    format!("__GEO_FILE_OFFER__:{}:{}:{}", code, file_name, file_size)
}

pub(crate) fn parse_geohash_file_offer_message(content: &str) -> Option<(String, String, u64)> {
    let parts: Vec<&str> = content.splitn(4, ':').collect();
    if parts.len() != 4 || parts[0] != "__GEO_FILE_OFFER__" {
        return None;
    }
    Some((
        parts[1].to_string(),
        parts[2].to_string(),
        parts[3].parse().ok()?,
    ))
}

fn push_tlv_u16(payload: &mut Vec<u8>, field_type: u8, value: &[u8]) -> Result<(), String> {
    if value.len() > u16::MAX as usize {
        return Err("File metadata is too large".to_string());
    }
    payload.push(field_type);
    payload.extend_from_slice(&(value.len() as u16).to_be_bytes());
    payload.extend_from_slice(value);
    Ok(())
}

fn push_tlv_u32(payload: &mut Vec<u8>, field_type: u8, value: &[u8]) -> Result<(), String> {
    if value.len() > u32::MAX as usize {
        return Err("File payload is too large".to_string());
    }
    payload.push(field_type);
    payload.extend_from_slice(&(value.len() as u32).to_be_bytes());
    payload.extend_from_slice(value);
    Ok(())
}

fn infer_mime_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }
}

fn create_file_transfer_payload(
    path: &Path,
    content: &[u8],
    channel: Option<&str>,
) -> Result<Vec<u8>, String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| "File path must include a valid file name".to_string())?;

    let mut payload = Vec::with_capacity(file_name.len() + content.len() + 64);
    push_tlv_u16(&mut payload, 0x01, file_name.as_bytes())?;

    payload.push(0x02);
    payload.extend_from_slice(&4u16.to_be_bytes());
    payload.extend_from_slice(&(content.len() as u32).to_be_bytes());

    push_tlv_u16(&mut payload, 0x03, infer_mime_type(path).as_bytes())?;
    push_tlv_u32(&mut payload, 0x04, content)?;

    if let Some(channel) = channel {
        push_tlv_u16(&mut payload, 0x05, channel.as_bytes())?;
    }

    Ok(payload)
}

pub(crate) fn format_file_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

pub async fn handle_name_command(
    line: &str,
    nickname: &mut String,
    app: &mut crate::tui::app::App,
    blocked_peers: &HashSet<String>,
    channel_creators: &HashMap<String, String>,
    chat_context: &ChatContext,
    password_protected_channels: &HashSet<String>,
    channel_key_commitments: &HashMap<String, String>,
    app_state: &AppState,
    create_app_state: &dyn Fn(
        &HashSet<String>,
        &[String],
        &HashMap<String, String>,
        &HashMap<String, String>,
        &Vec<String>,
        &HashSet<String>,
        &HashMap<String, String>,
        &HashMap<String, EncryptedPassword>,
        &str,
    ) -> AppState,
    ui_tx: mpsc::Sender<String>,
) -> bool {
    if line.starts_with("/name ") {
        let payload = line.trim_start_matches("/name ").trim();
        if payload.is_empty() {
            let _ = ui_tx.send("\x1b[93m⚠ Usage: /name <new_nickname>\x1b[0m\n\x1b[90mExample: /name Alice\x1b[0m\n".to_string()).await;
        } else {
            let mut parts = payload.split_whitespace();
            let first = parts.next().unwrap_or("");

            if first.starts_with('@') {
                let Some(alias) = parts.next() else {
                    let _ = ui_tx
                        .send("system: Usage: /name @user <custom_name>".to_string())
                        .await;
                    return true;
                };
                if parts.next().is_some() {
                    let _ = ui_tx
                        .send("system: Usage: /name @user <custom_name>".to_string())
                        .await;
                    return true;
                }
                if alias.len() > 20 {
                    let _ = ui_tx.send("\x1b[93m⚠ Nickname too long\x1b[0m\n\x1b[90mMaximum 20 characters allowed.\x1b[0m\n".to_string()).await;
                    return true;
                }
                if alias.contains(|c: char| !c.is_alphanumeric() && c != '-' && c != '_') {
                    let _ = ui_tx.send("\x1b[93m⚠ Invalid nickname\x1b[0m\n\x1b[90mNicknames can only contain letters, numbers, hyphens and underscores.\x1b[0m\n".to_string()).await;
                    return true;
                }
                if alias == "system" || alias == "all" {
                    let _ = ui_tx.send("\x1b[93m⚠ Reserved nickname\x1b[0m\n\x1b[90mThis nickname is reserved and cannot be used.\x1b[0m\n".to_string()).await;
                    return true;
                }
                let Some(channel) = app.current_geohash_context_channel() else {
                    let _ = ui_tx
                        .send("system: /name @user <custom_name> is only available in a Nostr geohash channel.".to_string())
                        .await;
                    return true;
                };
                let target = strip_display_suffix(first.trim_start_matches('@'));
                if target.is_empty() {
                    let _ = ui_tx
                        .send("system: Usage: /name @user <custom_name>".to_string())
                        .await;
                    return true;
                }
                if app.set_nostr_alias(&channel, target, alias).is_none() {
                    let _ = ui_tx
                        .send(format!(
                            "system: User '{}' not found in {} People list.",
                            target, channel
                        ))
                        .await;
                    return true;
                }

                let channels_vec = persistent_channels(chat_context);
                let blocked_names = manual_block_entries(&app.blocked);
                let state_to_save = create_app_state(
                    blocked_peers,
                    &blocked_names,
                    &app.nostr_aliases,
                    channel_creators,
                    &channels_vec,
                    password_protected_channels,
                    channel_key_commitments,
                    &app_state.encrypted_channel_passwords,
                    nickname,
                );
                if let Err(e) = save_state(&state_to_save) {
                    let _ = ui_tx
                        .send(format!("Warning: Could not save alias: {}\n", e))
                        .await;
                } else {
                    let _ = ui_tx
                        .send(format!("system: Renamed {} to {}", target, alias))
                        .await;
                }
            } else if payload.len() > 20 {
                let _ = ui_tx.send("\x1b[93m⚠ Nickname too long\x1b[0m\n\x1b[90mMaximum 20 characters allowed.\x1b[0m\n".to_string()).await;
            } else if payload.contains(|c: char| !c.is_alphanumeric() && c != '-' && c != '_') {
                let _ = ui_tx.send("\x1b[93m⚠ Invalid nickname\x1b[0m\n\x1b[90mNicknames can only contain letters, numbers, hyphens and underscores.\x1b[0m\n".to_string()).await;
            } else if payload == "system" || payload == "all" {
                let _ = ui_tx.send("\x1b[93m⚠ Reserved nickname\x1b[0m\n\x1b[90mThis nickname is reserved and cannot be used.\x1b[0m\n".to_string()).await;
            } else {
                *nickname = payload.to_string();
                // Don't send announcement or message here - let the main loop handle everything via the pending_nickname_update signal
                let channels_vec = persistent_channels(chat_context);
                let blocked_names = manual_block_entries(&app.blocked);
                let state_to_save = create_app_state(
                    blocked_peers,
                    &blocked_names,
                    &app.nostr_aliases,
                    channel_creators,
                    &channels_vec,
                    password_protected_channels,
                    channel_key_commitments,
                    &app_state.encrypted_channel_passwords,
                    nickname,
                );
                if let Err(e) = save_state(&state_to_save) {
                    let _ = ui_tx
                        .send(format!("Warning: Could not save nickname: {}\n", e))
                        .await;
                }
            }
        }
        return true;
    }
    false
}

pub async fn handle_join_command(
    line: &str,
    password_protected_channels: &HashSet<String>,
    channel_keys: &mut HashMap<String, [u8; 32]>,
    discovered_channels: &mut HashSet<String>,
    chat_context: &mut ChatContext,
    channel_key_commitments: &HashMap<String, String>,
    app_state: &mut AppState,
    create_app_state: &dyn Fn(
        &HashSet<String>,
        &[String],
        &HashMap<String, String>,
        &HashMap<String, String>,
        &Vec<String>,
        &HashSet<String>,
        &HashMap<String, String>,
        &HashMap<String, EncryptedPassword>,
        &str,
    ) -> AppState,
    nickname: &str,
    _peripheral: &Peripheral,
    _cmd_char: &btleplug::api::Characteristic,
    channel_creators: &HashMap<String, String>,
    blocked_peers: &HashSet<String>,
    ui_tx: mpsc::Sender<String>,
    app: &mut crate::tui::app::App,
) -> bool {
    if line.starts_with("/j ") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let mut channel_name = parts.get(1).unwrap_or(&"").to_string();

        if channel_name.is_empty() {
            let _ = ui_tx
                .send("\x1b[93m⚠ Usage: /j <channel> [password]\x1b[0m\n".to_string())
                .await;
            return true;
        }
        // If channel name does not start with #, add it automatically
        if !channel_name.starts_with('#') {
            channel_name = format!("#{}", channel_name);
        }

        if password_protected_channels.contains(&channel_name)
            && !channel_keys.contains_key(&channel_name)
        {
            if let Some(password) = parts.get(2) {
                let key = EncryptionService::derive_channel_key(password, &channel_name);
                if let Some(expected_commitment) = channel_key_commitments.get(&channel_name) {
                    let test_commitment = hex::encode(sha2::Sha256::digest(&key));
                    if &test_commitment != expected_commitment {
                        let _ = ui_tx
                            .send(format!("❌ Wrong password for channel {}.\n", channel_name))
                            .await;
                        return true;
                    }
                }
                channel_keys.insert(channel_name.clone(), key);
                if let Some(identity_key) = &app_state.identity_key {
                    if let Ok(encrypted) = encrypt_password(password, identity_key) {
                        app_state
                            .encrypted_channel_passwords
                            .insert(channel_name.clone(), encrypted);
                        // FIX: Convert HashSet to Vec before saving state
                        let channels_vec = persistent_channels(chat_context);
                        let blocked_names = manual_block_entries(&app.blocked);
                        let state_to_save = create_app_state(
                            blocked_peers,
                            &blocked_names,
                            &app.nostr_aliases,
                            channel_creators,
                            &channels_vec,
                            password_protected_channels,
                            channel_key_commitments,
                            &app_state.encrypted_channel_passwords,
                            nickname,
                        );
                        if let Err(e) = save_state(&state_to_save) {
                            let _ = ui_tx
                                .send(format!("Warning: Could not save state: {}\n", e))
                                .await;
                        }
                    }
                }
                chat_context.switch_to_channel_silent(&channel_name);
                let _ = ui_tx
                    .send(format!(
                        "\x1b[90m» Joined password-protected channel: {} 🔒\n",
                        channel_name
                    ))
                    .await;
            } else {
                let _ = ui_tx
                    .send(format!(
                        "❌ Channel {} is password-protected. Use: /j {} <password>\n",
                        channel_name, channel_name
                    ))
                    .await;
                return true;
            }
        } else if password_protected_channels.contains(&channel_name)
            && channel_keys.contains_key(&channel_name)
        {
            // User is already in a password-protected channel but we need to verify the password is correct
            if let Some(password) = parts.get(2) {
                let key = EncryptionService::derive_channel_key(password, &channel_name);
                if let Some(expected_commitment) = channel_key_commitments.get(&channel_name) {
                    let test_commitment = hex::encode(sha2::Sha256::digest(&key));
                    if &test_commitment != expected_commitment {
                        // User has wrong password - warn them
                        let warning_msg = format!("⚠️  WARNING: You entered channel {} with the wrong password. Your messages are encrypted and others cannot see them. Leave the channel with /leave and rejoin with the correct password.", channel_name);
                        let _ = ui_tx.send(format!("{}\n", warning_msg)).await;

                        // Add system message to TUI
                        let system_msg = format!("Wrong password detected for channel {}. Messages are encrypted and others cannot see them. Use /leave and rejoin with correct password.", channel_name);
                        app.add_log_message(format!("system: {}", system_msg));

                        return true;
                    }
                }
            }
            chat_context.switch_to_channel(&channel_name);
            let _ = ui_tx
                .send(format!(
                    "\x1b[90m» Switched to channel {}\x1b[0m\n",
                    channel_name
                ))
                .await;
        } else {
            chat_context.switch_to_channel(&channel_name);
            let _ = ui_tx
                .send(format!(
                    "\x1b[90m» Switched to channel {}\x1b[0m\n",
                    channel_name
                ))
                .await;
        }
        discovered_channels.insert(channel_name.clone());

        return true;
    }
    false
}

pub async fn handle_exit_command(
    line: &str,
    blocked_peers: &HashSet<String>,
    channel_creators: &HashMap<String, String>,
    chat_context: &ChatContext,
    password_protected_channels: &HashSet<String>,
    channel_key_commitments: &HashMap<String, String>,
    app_state: &AppState,
    create_app_state: &dyn Fn(
        &HashSet<String>,
        &[String],
        &HashMap<String, String>,
        &HashMap<String, String>,
        &Vec<String>,
        &HashSet<String>,
        &HashMap<String, String>,
        &HashMap<String, EncryptedPassword>,
        &str,
    ) -> AppState,
    nickname: &str,
    ui_tx: mpsc::Sender<String>,
    app: &mut crate::tui::app::App,
) -> bool {
    if line == "/exit" {
        let channels_vec = persistent_channels(chat_context);
        let blocked_names = manual_block_entries(&app.blocked);
        let state_to_save = create_app_state(
            blocked_peers,
            &blocked_names,
            &app.nostr_aliases,
            channel_creators,
            &channels_vec,
            password_protected_channels,
            channel_key_commitments,
            &app_state.encrypted_channel_passwords,
            nickname,
        );
        if let Err(e) = save_state(&state_to_save) {
            let _ = ui_tx
                .send(format!("Warning: Could not save state: {}\n", e))
                .await;
        }
        // Set the quit flag to exit the application
        app.should_quit = true;
        return true;
    }
    false
}

pub async fn handle_reply_command(
    line: &str,
    chat_context: &mut ChatContext,
    ui_tx: mpsc::Sender<String>,
) -> bool {
    if line == "/reply" {
        if let Some((peer_id, nickname)) = chat_context.last_private_sender.clone() {
            chat_context.enter_dm_mode(&nickname, &peer_id);
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx
                    .send(format!("{}\n", chat_context.get_status_line()))
                    .await;
            }
        } else {
            let _ = ui_tx
                .send("» No private messages received yet.\n".to_string())
                .await;
        }
        return true;
    }
    false
}

pub async fn handle_public_command(
    line: &str,
    chat_context: &mut ChatContext,
    ui_tx: mpsc::Sender<String>,
) -> bool {
    if line == "/public" {
        chat_context.switch_to_public();
        if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
            let _ = ui_tx
                .send(format!("{}\n", chat_context.get_status_line()))
                .await;
        }
        return true;
    }
    false
}

pub async fn handle_online_command(
    line: &str,
    peers: &Arc<Mutex<HashMap<String, Peer>>>,
    ui_tx: mpsc::Sender<String>,
) -> bool {
    if line == "/online" || line == "/w" {
        let peers_lock = peers.lock().await;
        if peers_lock.is_empty() {
            let _ = ui_tx
                .send("» No one else is online right now.\n".to_string())
                .await;
        } else {
            let mut online_list: Vec<String> = peers_lock
                .iter()
                .filter_map(|(_, peer)| peer.nickname.clone())
                .collect();
            online_list.sort();
            let _ = ui_tx
                .send(format!("» Online users: {}\n", online_list.join(", ")))
                .await;
        }
        return true;
    }
    false
}

pub async fn handle_channels_command(
    line: &str,
    chat_context: &ChatContext,
    channel_keys: &HashMap<String, [u8; 32]>,
    password_protected_channels: &HashSet<String>,
    ui_tx: mpsc::Sender<String>,
) -> bool {
    if line == "/channels" {
        let mut all_channels: HashSet<String> =
            chat_context.active_channels.iter().cloned().collect();
        all_channels.extend(channel_keys.keys().cloned());

        if all_channels.is_empty() {
            let _ = ui_tx
                .send(
                    "» No channels discovered yet. Channels appear as people use them.\n"
                        .to_string(),
                )
                .await;
        } else {
            let mut channel_list: Vec<String> = all_channels.into_iter().collect();
            channel_list.sort();

            let mut output = "» Discovered channels:\n".to_string();
            for channel in channel_list {
                let mut status = String::new();
                if chat_context.active_channels.contains(&channel) {
                    status.push_str(" ✓");
                }
                if password_protected_channels.contains(&channel) {
                    status.push_str(" 🔒");
                    if channel_keys.contains_key(&channel) {
                        status.push_str(" 🔑");
                    }
                }
                output.push_str(&format!("  {}{}\n", channel, status));
            }
            output.push_str("\n✓ = joined, 🔒 = password protected, 🔑 = authenticated\n");
            let _ = ui_tx.send(output).await;
        }
        return true;
    }
    false
}

pub async fn handle_dm_command(
    line: &str,
    chat_context: &mut ChatContext,
    peers: &Arc<Mutex<HashMap<String, Peer>>>,
    _nickname: &str,
    my_peer_id: &str,
    delivery_tracker: &mut DeliveryTracker,
    _encryption_service: &EncryptionService,
    fallback_peripheral: Option<&Peripheral>,
    fallback_cmd_char: Option<&btleplug::api::Characteristic>,
    mesh_targets: &[(Peripheral, Characteristic)],
    ui_tx: mpsc::Sender<String>,
    app: &mut crate::tui::app::App,
    _noise_session_manager: &mut NoiseSessionManager,
) -> bool {
    if line.starts_with("/dm ") {
        let rest = line.trim_start_matches("/dm").trim_start();
        if rest.is_empty() {
            let _ = ui_tx
                .send("\x1b[93m⚠ Usage: /dm <nickname> [message]\x1b[0m\n".to_string())
                .await;
            let _ = ui_tx
                .send("\x1b[90mExample: /dm Bob Hey there!\x1b[0m\n".to_string())
                .await;
            return true;
        }

        let target_end = rest
            .char_indices()
            .find_map(|(idx, ch)| ch.is_whitespace().then_some(idx))
            .unwrap_or(rest.len());
        let target_nickname = rest[..target_end].trim();
        let maybe_private_message = rest[target_end..].trim();
        let has_inline_message = !maybe_private_message.is_empty();

        let target_lookup = strip_display_suffix(target_nickname.trim_start_matches('@'));
        if target_lookup.is_empty() {
            let _ = ui_tx
                .send("\x1b[93m⚠ Usage: /dm <nickname> [message]\x1b[0m\n".to_string())
                .await;
            return true;
        }
        let normalized_target = target_lookup.to_ascii_lowercase();

        // Find peer ID for nickname
        let peer_id = if let Some(id) = app
            .mesh_people_peer_ids
            .iter()
            .find(|(name, _)| {
                strip_display_suffix(name.trim_start_matches('@'))
                    .eq_ignore_ascii_case(target_lookup)
            })
            .map(|(_, id)| id.clone())
        {
            Some(id)
        } else {
            peers
                .lock()
                .await
                .iter()
                .find(|(_, peer)| {
                    peer.nickname
                        .as_deref()
                        .map(|nick| {
                            strip_display_suffix(nick.trim_start_matches('@')).to_ascii_lowercase()
                                == normalized_target
                        })
                        .unwrap_or(false)
                })
                .map(|(id, _)| id.clone())
        };

        if let Some(target_peer_id) = peer_id {
            chat_context.enter_dm_mode(target_lookup, &target_peer_id);
            let owned_targets = if mesh_targets.is_empty() {
                fallback_peripheral
                    .zip(fallback_cmd_char)
                    .map(|(peripheral, cmd_char)| vec![(peripheral.clone(), cmd_char.clone())])
                    .unwrap_or_default()
            } else {
                mesh_targets.to_vec()
            };
            // If no message provided, enter DM mode
            if !has_inline_message {
                if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                    let _ = ui_tx
                        .send(format!("{}\n", chat_context.get_status_line()))
                        .await;
                }
                return true;
            }

            // Otherwise send the message directly
            let private_message = maybe_private_message;
            // Create private message
            if unsafe { DEBUG_LEVEL >= DebugLevel::Basic } {
                let _ = ui_tx
                    .send(format!(
                        "[PRIVATE] Sending encrypted message to {}\n",
                        target_lookup
                    ))
                    .await;
            }

            if !_noise_session_manager.has_established_session(&target_peer_id) {
                if !_noise_session_manager.has_session(&target_peer_id) {
                    let _ = _noise_session_manager.create_session(
                        target_peer_id.clone(),
                        crate::noise_protocol::NoiseRole::Initiator,
                    );
                }
                if let Err(e) = _noise_session_manager
                    .store_pending_message(&target_peer_id, private_message.to_string())
                {
                    let _ = ui_tx
                        .send(format!(
                            "\n\x1b[91m❌ Failed to queue private message: {}\x1b[0m\n",
                            e
                        ))
                        .await;
                    return true;
                }
                match _noise_session_manager.initiate_handshake(&target_peer_id) {
                    Ok(handshake_data) => {
                        let handshake_packet = create_bitchat_packet_with_recipient(
                            my_peer_id,
                            Some(&target_peer_id),
                            MessageType::NoiseHandshakeInit,
                            handshake_data,
                            None,
                        );
                        if let Err(e) = send_packet_to_mesh_targets(
                            &owned_targets,
                            handshake_packet,
                            my_peer_id,
                            MessageType::NoiseHandshakeInit,
                        )
                        .await
                        {
                            crate::notification_handlers::write_noise_debug_log(&format!(
                                "[DEBUG] Failed to start DM handshake: {}",
                                e
                            ));
                            if crate::tui::app::bitchat_debug_enabled() {
                                let _ = ui_tx
                                    .send(format!(
                                        "\n\x1b[91m❌ Failed to start DM handshake: {}\x1b[0m\n",
                                        e
                                    ))
                                    .await;
                            }
                            return true;
                        }

                        app.add_dm_message(target_lookup.to_string(), private_message.to_string());
                        app.add_transient_system_message(
                            format!(
                                "[{}|DM] <{}> {}",
                                chrono::Local::now().format("%H:%M"),
                                target_lookup,
                                private_message
                            ),
                            Duration::from_secs(1),
                        );
                        if crate::tui::app::bitchat_debug_enabled() {
                            let _ = ui_tx
                                .send(
                                    "\x1b[90mDM handshake started; message queued and will send when secure channel is ready.\x1b[0m\n"
                                        .to_string(),
                                )
                                .await;
                        }
                        return true;
                    }
                    Err(e) => {
                        crate::notification_handlers::write_noise_debug_log(&format!(
                            "[DEBUG] Failed to initiate DM handshake: {}",
                            e
                        ));
                        if crate::tui::app::bitchat_debug_enabled() {
                            let _ = ui_tx
                                .send(format!(
                                    "\n\x1b[91m❌ Failed to initiate DM handshake: {}\x1b[0m\n",
                                    e
                                ))
                                .await;
                        }
                        return true;
                    }
                }
            }

            let message_id = Uuid::new_v4().to_string();
            let noise_payload = match create_private_noise_payload(&message_id, private_message) {
                Ok(payload) => payload,
                Err(e) => {
                    let _ = ui_tx
                        .send(format!(
                            "\n\x1b[91m❌ Failed to build DM payload: {}\x1b[0m\n",
                            e
                        ))
                        .await;
                    return true;
                }
            };
            delivery_tracker.track_message(message_id.clone(), private_message.to_string(), true);

            let encrypted =
                match _noise_session_manager.encrypt_message(&target_peer_id, &noise_payload) {
                    Ok(encrypted) => encrypted,
                    Err(e) => {
                        let _ = ui_tx
                            .send(format!(
                                "\n\x1b[91m❌ Failed to encrypt private message: {}\x1b[0m\n",
                                e
                            ))
                            .await;
                        return true;
                    }
                };

            let packet = create_bitchat_packet_with_recipient(
                my_peer_id,
                Some(&target_peer_id),
                MessageType::NoiseEncrypted,
                encrypted,
                None,
            );

            if let Err(e) = send_packet_to_mesh_targets(
                &owned_targets,
                packet,
                my_peer_id,
                MessageType::NoiseEncrypted,
            )
            .await
            {
                let err_text = e.to_string();
                if is_mesh_write_failure(&err_text) {
                    app.trigger_connection_retry();
                }
                let _ = ui_tx
                    .send(format!(
                        "\n\x1b[91m❌ Failed to send private message: {}\x1b[0m\n",
                        err_text
                    ))
                    .await;
            } else {
                app.add_pending_mesh_dm_message(
                    target_lookup.to_string(),
                    private_message.to_string(),
                    message_id,
                );
                app.add_transient_system_message(
                    format!(
                        "[{}|DM] <{}> {}",
                        chrono::Local::now().format("%H:%M"),
                        target_lookup,
                        private_message
                    ),
                    Duration::from_secs(1),
                );
            }
            return true;
        } else {
            let _ = ui_tx
                .send(format!(
                    "\x1b[93m⚠ User '{}' not found\x1b[0m\n",
                    target_nickname
                ))
                .await;
            let _ = ui_tx
                .send(
                    "\x1b[90mThey may be offline or using a different nickname.\x1b[0m\n"
                        .to_string(),
                )
                .await;
            return true;
        }
    }
    false
}

pub async fn handle_file_command(
    line: &str,
    chat_context: &ChatContext,
    peers: &Arc<Mutex<HashMap<String, Peer>>>,
    password_protected_channels: &HashSet<String>,
    encryption_service: &EncryptionService,
    my_peer_id: &str,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    ui_tx: mpsc::Sender<String>,
    app: &mut crate::tui::app::App,
) -> bool {
    let command = match parse_file_command(line) {
        Ok(Some(command)) => command,
        Ok(None) => return false,
        Err(usage) => {
            app.add_log_message(format!("system: {}", usage));
            app.add_log_message("system: Example: /file @alice ./photo.png".to_string());
            return true;
        }
    };

    let path = Path::new(command.path);
    let metadata = match tokio::fs::metadata(path).await {
        Ok(metadata) => metadata,
        Err(e) => {
            app.add_log_message(format!(
                "system: Cannot read file '{}': {}",
                command.path, e
            ));
            return true;
        }
    };

    if !metadata.is_file() {
        app.add_log_message(format!("system: '{}' is not a regular file", command.path));
        return true;
    }

    let file_size = metadata.len();
    if file_size == 0 {
        app.add_log_message("system: Empty files are not supported yet".to_string());
        return true;
    }
    if file_size > MAX_FILE_TRANSFER_BYTES {
        app.add_log_message(format!(
            "system: File is too large: {}. Maximum is {}.",
            format_file_size(file_size),
            format_file_size(MAX_FILE_TRANSFER_BYTES)
        ));
        return true;
    }

    let content = match tokio::fs::read(path).await {
        Ok(content) => content,
        Err(e) => {
            app.add_log_message(format!("system: Failed to read '{}': {}", command.path, e));
            return true;
        }
    };

    let (recipient_peer_id, recipient_nickname) = if let Some(target_nickname) =
        command.target_nickname
    {
        let peer_id = {
            peers
                .lock()
                .await
                .iter()
                .find(|(_, peer)| peer.nickname.as_deref() == Some(target_nickname))
                .map(|(id, _)| id.clone())
        };

        match peer_id {
            Some(peer_id) => (Some(peer_id), Some(target_nickname.to_string())),
            None => {
                app.add_log_message(format!(
                    "system: User '{}' not found. They may be offline or using a different nickname.",
                    target_nickname
                ));
                return true;
            }
        }
    } else if let ChatMode::PrivateDM { nickname, peer_id } = &chat_context.current_mode {
        (Some(peer_id.clone()), Some(nickname.clone()))
    } else {
        (None, None)
    };

    let channel = if recipient_peer_id.is_none() {
        chat_context.current_mode.get_channel()
    } else {
        None
    };

    if let Some(channel) = channel {
        if crate::nostr_geo::is_geohash_channel(channel) {
            app.add_log_message(
                "system: /file is only available on the Bluetooth mesh, not in Nostr geohash channels."
                    .to_string(),
            );
            return true;
        }

        if password_protected_channels.contains(channel) {
            app.add_log_message(format!(
                "system: File transfer is not supported in password-protected channel {}.",
                channel
            ));
            return true;
        }
    }

    let payload = match create_file_transfer_payload(path, &content, channel) {
        Ok(payload) => payload,
        Err(e) => {
            app.add_log_message(format!("system: Failed to prepare file transfer: {}", e));
            return true;
        }
    };

    let timestamp = current_timestamp_ms();
    let signing_payload = create_file_transfer_packet_for_signing_at(
        my_peer_id,
        recipient_peer_id.as_deref(),
        &payload,
        timestamp,
    );
    let signature = encryption_service.sign(&signing_payload);
    let packet = create_file_transfer_packet_with_recipient_at(
        my_peer_id,
        recipient_peer_id.as_deref(),
        payload,
        Some(signature),
        timestamp,
    );

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(command.path);

    match send_packet_with_fragmentation_as(
        peripheral,
        cmd_char,
        packet,
        my_peer_id,
        MessageType::FileTransfer,
    )
    .await
    {
        Ok(()) => {
            let display = crate::tui::app::compact_file_message(file_name);
            if let Some(target_nickname) = recipient_nickname {
                app.add_dm_message(target_nickname.clone(), display);
                app.add_log_message(format!("system: Sent file to {}", target_nickname));
            } else {
                app.add_sent_message(display);
            }
        }
        Err(e) => {
            let _ = ui_tx
                .send(format!(
                    "\n\x1b[91m❌ File transfer failed\x1b[0m\n\x1b[90m{}\x1b[0m\n",
                    e
                ))
                .await;
        }
    }

    true
}

pub async fn handle_block_command(
    line: &str,
    blocked_peers: &mut HashSet<String>,
    _peers: &Arc<Mutex<HashMap<String, Peer>>>,
    _encryption_service: &EncryptionService,
    channel_creators: &HashMap<String, String>,
    chat_context: &ChatContext,
    password_protected_channels: &HashSet<String>,
    channel_key_commitments: &HashMap<String, String>,
    app_state: &AppState,
    create_app_state: &dyn Fn(
        &HashSet<String>,
        &[String],
        &HashMap<String, String>,
        &HashMap<String, String>,
        &Vec<String>,
        &HashSet<String>,
        &HashMap<String, String>,
        &HashMap<String, EncryptedPassword>,
        &str,
    ) -> AppState,
    nickname: &str,
    ui_tx: mpsc::Sender<String>,
    app: &mut crate::tui::app::App,
) -> bool {
    if line.starts_with("/block") {
        if app.current_geohash_context_channel().is_none() {
            let _ = ui_tx
                .send("system: /block is only available in Nostr geohash channels.".to_string())
                .await;
            return true;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();

        // Handle /block without arguments - show list of blocked users
        if parts.len() == 1 {
            let blocked_entries = manual_block_entries(&app.blocked);

            if blocked_entries.is_empty() {
                let _ = ui_tx
                    .send("system: No users are currently blocked.".to_string())
                    .await;
            } else {
                let blocked_list = blocked_entries.join(", ");
                let _ = ui_tx
                    .send(format!(
                        "system: Blocked users ({}): {}",
                        blocked_entries.len(),
                        blocked_list
                    ))
                    .await;
            }
            return true;
        }

        // Handle /block with username argument
        if parts.len() == 2 {
            let target_name = parts[1].trim_start_matches('@');
            let before_len = app.blocked.len();
            add_manual_block_entry(app, target_name);
            let added = app.blocked.len() > before_len;

            let channels_vec = persistent_channels(chat_context);
            let blocked_names = manual_block_entries(&app.blocked);
            let state_to_save = create_app_state(
                blocked_peers,
                &blocked_names,
                &app.nostr_aliases,
                channel_creators,
                &channels_vec,
                password_protected_channels,
                channel_key_commitments,
                &app_state.encrypted_channel_passwords,
                nickname,
            );
            if let Err(e) = save_state(&state_to_save) {
                let _ = ui_tx
                    .send(format!("Warning: Could not save state: {}\n", e))
                    .await;
            }

            app.update_blocked_list(manual_block_entries(&app.blocked));

            let msg = if added {
                format!("system: Blocked '{}' in this Nostr context.", target_name)
            } else {
                format!("system: User '{}' is already blocked.", target_name)
            };
            let _ = ui_tx.send(msg).await;
        }
        return true;
    }
    false
}

pub async fn handle_unblock_command(
    line: &str,
    blocked_peers: &mut HashSet<String>,
    _peers: &Arc<Mutex<HashMap<String, Peer>>>,
    _encryption_service: &EncryptionService,
    channel_creators: &HashMap<String, String>,
    chat_context: &ChatContext,
    password_protected_channels: &HashSet<String>,
    channel_key_commitments: &HashMap<String, String>,
    app_state: &AppState,
    create_app_state: &dyn Fn(
        &HashSet<String>,
        &[String],
        &HashMap<String, String>,
        &HashMap<String, String>,
        &Vec<String>,
        &HashSet<String>,
        &HashMap<String, String>,
        &HashMap<String, EncryptedPassword>,
        &str,
    ) -> AppState,
    nickname: &str,
    ui_tx: mpsc::Sender<String>,
    app: &mut crate::tui::app::App,
) -> bool {
    if line == "/unblock" {
        let _ = ui_tx
            .send("system: Usage: /unblock @user".to_string())
            .await;
        return true;
    }
    if line.starts_with("/unblock ") {
        if app.current_geohash_context_channel().is_none() {
            let _ = ui_tx
                .send("system: /unblock is only available in Nostr geohash channels.".to_string())
                .await;
            return true;
        }

        let target_name = line
            .trim_start_matches("/unblock ")
            .trim()
            .trim_start_matches('@');
        let removed_manual = remove_manual_block_entry(app, target_name);

        if removed_manual {
            let channels_vec = persistent_channels(chat_context);
            let blocked_names = manual_block_entries(&app.blocked);
            let state_to_save = create_app_state(
                blocked_peers,
                &blocked_names,
                &app.nostr_aliases,
                channel_creators,
                &channels_vec,
                password_protected_channels,
                channel_key_commitments,
                &app_state.encrypted_channel_passwords,
                nickname,
            );
            if let Err(e) = save_state(&state_to_save) {
                let _ = ui_tx
                    .send(format!("Warning: Could not save state: {}\n", e))
                    .await;
            }
            app.update_blocked_list(manual_block_entries(&app.blocked));
            let _ = ui_tx
                .send(format!("\n\x1b[92m✓ Unblocked {}\x1b[0m\n", target_name))
                .await;
        } else {
            app.add_log_message(format!("system: User '{}' is not blocked.", target_name));
        }
        return true;
    }
    false
}

pub async fn handle_clear_command(
    line: &str,
    _chat_context: &ChatContext,
    _ui_tx: mpsc::Sender<String>,
) -> bool {
    if line == "/clear" {
        // Don't send any output here - let the main loop handle it via the pending_clear_conversation signal
        return true;
    }
    false
}

pub async fn handle_leave_command(
    line: &str,
    chat_context: &mut ChatContext,
    channel_keys: &mut HashMap<String, [u8; 32]>,
    app_state: &mut AppState,
    my_peer_id: &str,
    peripheral: &Peripheral,
    cmd_char: &btleplug::api::Characteristic,
    ui_tx: mpsc::Sender<String>,
    app: &mut crate::tui::app::App,
) -> bool {
    if line == "/leave" {
        if let ChatMode::Channel(channel) = &chat_context.current_mode.clone() {
            let leave_payload = channel.as_bytes().to_vec();
            let mut leave_packet =
                create_bitchat_packet(my_peer_id, MessageType::Leave, leave_payload);
            if leave_packet.len() > 2 {
                leave_packet[2] = 3;
            } // Set TTL
            let _ = peripheral
                .write(cmd_char, &leave_packet, WriteType::WithoutResponse)
                .await;

            channel_keys.remove(channel);
            app_state.encrypted_channel_passwords.remove(channel);
            chat_context.remove_channel(channel);
            chat_context.switch_to_public();

            // Remove channel from TUI sidebar
            app.channels.retain(|c| c != channel);

            let _ = ui_tx
                .send(format!("\x1b[90m» Left channel {}\x1b[0m\n", channel))
                .await;
        } else {
            let _ = ui_tx
                .send("» You're not in a channel. Use /j #channel to join one.\n".to_string())
                .await;
        }
        return true;
    }
    false
}

pub async fn handle_fingerprint_command(
    line: &str,
    encryption_service: &EncryptionService,
    ui_tx: mpsc::Sender<String>,
) -> bool {
    if line == "/fingerprint" {
        let fingerprint = encryption_service.get_identity_fingerprint();
        let _ = ui_tx
            .send(format!(
                "\x1b[96m🔒 Your Identity Fingerprint:\x1b[0m\n\x1b[90m{}\x1b[0m\n",
                fingerprint
            ))
            .await;
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_geohash_file_offer_with_explicit_target() {
        let offer = parse_geohash_file_offer("/file @alice ./photo.png")
            .unwrap()
            .unwrap();

        assert_eq!(offer.target_nickname, Some("alice"));
        assert_eq!(offer.path, "./photo.png");
    }

    #[test]
    fn parses_geohash_file_offer_without_target_for_current_dm() {
        let offer = parse_geohash_file_offer("/file ./photo.png")
            .unwrap()
            .unwrap();

        assert_eq!(offer.target_nickname, None);
        assert_eq!(offer.path, "./photo.png");
    }

    #[test]
    fn creates_ios_compatible_image_file_transfer_payload() {
        let payload =
            create_file_transfer_payload(Path::new("photo.png"), b"pngdata", Some("#public"))
                .unwrap();

        let mut offset = 0usize;
        assert_eq!(payload[offset], 0x01);
        offset += 1;
        let name_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        assert_eq!(&payload[offset..offset + name_len], b"photo.png");
        offset += name_len;

        assert_eq!(payload[offset], 0x02);
        offset += 1;
        assert_eq!(
            u16::from_be_bytes([payload[offset], payload[offset + 1]]),
            4
        );
        offset += 2;
        assert_eq!(
            u32::from_be_bytes([
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3]
            ]),
            7
        );
        offset += 4;

        assert_eq!(payload[offset], 0x03);
        offset += 1;
        let mime_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        assert_eq!(&payload[offset..offset + mime_len], b"image/png");
        offset += mime_len;

        assert_eq!(payload[offset], 0x04);
        offset += 1;
        assert_eq!(
            u32::from_be_bytes([
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3]
            ]),
            7
        );
        offset += 4;
        assert_eq!(&payload[offset..offset + 7], b"pngdata");
    }
}
