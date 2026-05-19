use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter, WriteType};
use btleplug::platform::{Manager, Peripheral};
use ed25519_dalek::{Signature, VerifyingKey};

use futures::stream::StreamExt;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::{self, Duration};

use bloomfilter::Bloom;
mod tui;
use crossterm::event as crossterm_event;
use crossterm::event::Event as CrosstermEvent;
use crossterm::execute;
use crossterm::terminal::SetTitle;
use std::time::Duration as StdDuration;
use tui::app::App;
use tui::event;
use tui::tui as tui_mod;
use tui::ui;

const UI_EVENT_BUFFER_SIZE: usize = 4096;
const MAX_UI_MESSAGES_PER_TICK: usize = 512;

// Debug logging function
fn write_debug_log(message: &str) {
    if !crate::data_structures::file_logging_enabled() {
        return;
    }

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("debug.log")
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let log_entry = format!("[{}] {}\n", timestamp, message);
        let _ = std::io::Write::write_all(&mut file, log_entry.as_bytes());
    }
}

mod binary_encoding;
mod binary_protocol_utils;
mod command_handling;
mod compression;
mod data_structures;
mod encryption;
mod fragmentation;
mod message_handlers;
mod noise_protocol;
mod noise_session;
mod nostr_geo;
mod notification_handlers;
mod packet_creation;
mod packet_delivery;
mod packet_parser;
mod payload_handling;
mod persistence;
mod terminal_ux;
mod upload_share;
mod wormhole_transfer;

use crate::data_structures::{
    DebugLevel, DeliveryTracker, FragmentCollector, MessageType, Peer, BITCHAT_CHARACTERISTIC_UUID,
    BITCHAT_SERVICE_UUID, DEBUG_LEVEL,
};
use crate::noise_session::NoiseSessionManager;
use crate::notification_handlers::handle_handshake_request_message;
use command_handling::{
    geohash_file_offer_message, handle_block_command, handle_channels_command,
    handle_clear_command, handle_dm_command, handle_exit_command, handle_file_command,
    handle_fingerprint_command, handle_join_command, handle_leave_command, handle_name_command,
    handle_online_command, handle_public_command, handle_reply_command, handle_unblock_command,
    parse_geohash_file_offer, parse_receive_command,
};
use encryption::EncryptionService;
use message_handlers::{handle_private_dm_message, handle_regular_message};
use notification_handlers::{
    handle_announce_message, handle_channel_announce_message, handle_delivery_ack_message,
    handle_delivery_status_request_message, handle_file_transfer_packet, handle_fragment_packet,
    handle_key_exchange_message, handle_leave_message, handle_message_packet,
    handle_noise_encrypted_message, handle_noise_handshake_init, handle_noise_handshake_resp,
    handle_noise_identity_announce, handle_read_receipt_message,
};
use packet_creation::{
    create_announcement_payload, create_bitchat_packet_for_signing_at,
    create_bitchat_packet_with_signature_at, current_timestamp_ms,
};
use packet_parser::parse_bitchat_packet;
use persistence::{load_state, save_state, AppState, EncryptedPassword};
use terminal_ux::{ChatContext, ChatMode};
use uuid::Uuid;
use x25519_dalek::StaticSecret;

type AppStateFactory = Box<
    dyn Fn(
            &HashSet<String>,
            &[String],
            &HashMap<String, String>,
            &HashMap<String, String>,
            &Vec<String>,
            &HashSet<String>,
            &HashMap<String, String>,
            &HashMap<String, EncryptedPassword>,
            &str,
        ) -> AppState
        + Send
        + Sync,
>;

fn build_app_state_factory(
    verified_fingerprints_state: Arc<std::sync::Mutex<HashSet<String>>>,
    verified_labels_state: Arc<std::sync::Mutex<HashMap<String, String>>>,
    identity_key: Option<Vec<u8>>,
    noise_static_key: Option<Vec<u8>>,
) -> AppStateFactory {
    Box::new(
        move |blocked,
              blocked_names,
              nostr_aliases,
              creators,
              channels,
              protected,
              commitments,
              encrypted_passwords,
              current_nickname| {
            AppState {
                nickname: Some(current_nickname.to_string()),
                blocked_peers: blocked.clone(),
                blocked_names: blocked_names.to_vec(),
                nostr_aliases: nostr_aliases.clone(),
                verified_labels: verified_labels_state.lock().unwrap().clone(),
                channel_creators: creators.clone(),
                joined_channels: channels.clone(),
                password_protected_channels: protected.clone(),
                channel_key_commitments: commitments.clone(),
                favorites: verified_fingerprints_state.lock().unwrap().clone(),
                identity_key: identity_key.clone(),
                noise_static_key: noise_static_key.clone(),
                encrypted_channel_passwords: encrypted_passwords.clone(),
            }
        },
    )
}

fn collect_persisted_joined_channels(chat_context: &ChatContext) -> Vec<String> {
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

fn collect_manual_blocked_names(entries: &[String]) -> Vec<String> {
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
        if !manual
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(trimmed))
        {
            manual.push(trimmed.to_string());
        }
    }
    manual.sort();
    manual
}

fn short_fingerprint(value: &str) -> String {
    if value.len() <= 10 {
        value.to_string()
    } else {
        value[..10].to_string()
    }
}

fn is_hex_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn format_verified_entries(
    verified_fingerprints: &HashSet<String>,
    verified_labels: &HashMap<String, String>,
) -> Vec<String> {
    let mut fingerprints: Vec<String> = verified_fingerprints.iter().cloned().collect();
    fingerprints.sort();
    fingerprints
        .into_iter()
        .map(|fp| {
            if let Some(label) = verified_labels.get(&fp) {
                format!("{} ({})", label, short_fingerprint(&fp))
            } else {
                format!("fingerprint:{}", short_fingerprint(&fp))
            }
        })
        .collect()
}

fn parse_verify_like_command(line: &str, command: &str) -> Option<Vec<String>> {
    let rest = line.strip_prefix(command)?;
    if !rest.is_empty() && !rest.chars().next()?.is_whitespace() {
        return None;
    }
    Some(
        rest.split_whitespace()
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty())
            .collect(),
    )
}

fn persist_runtime_state(
    chat_context: &ChatContext,
    blocked_peers: &HashSet<String>,
    blocked_entries: &[String],
    nostr_aliases: &HashMap<String, String>,
    verified_labels: &HashMap<String, String>,
    verified_fingerprints: &HashSet<String>,
    channel_creators: &HashMap<String, String>,
    password_protected_channels: &HashSet<String>,
    channel_key_commitments: &HashMap<String, String>,
    app_state: &AppState,
    create_app_state: &AppStateFactory,
    nickname: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let channels_vec = collect_persisted_joined_channels(chat_context);
    let blocked_names = collect_manual_blocked_names(blocked_entries);
    let state_to_save = create_app_state(
        blocked_peers,
        &blocked_names,
        nostr_aliases,
        channel_creators,
        &channels_vec,
        password_protected_channels,
        channel_key_commitments,
        &app_state.encrypted_channel_passwords,
        nickname,
    );
    let mut state_to_save = state_to_save;
    state_to_save.favorites = verified_fingerprints.clone();
    state_to_save.verified_labels = verified_labels.clone();
    save_state(&state_to_save)
}

// This function now takes a UI channel sender to direct its output.
// It still reads from stdin directly but sends user input over its own channel.
async fn setup_bluetooth_connection(
    ui_tx: mpsc::Sender<String>,
) -> Result<Peripheral, Box<dyn std::error::Error + Send + Sync>> {
    let debug_enabled = crate::tui::app::bitchat_debug_enabled();
    let manager = Manager::new().await?;
    let adapters = manager.adapters().await?;
    let adapter = match adapters.into_iter().nth(0) {
        Some(adapter) => adapter,
        None => {
            let error_message = [
                "\n\x1b[91m❌ No Bluetooth adapter found\x1b[0m",
                "\x1b[90mPlease check:\x1b[0m",
                "\x1b[90m  • Your device has Bluetooth hardware\x1b[0m",
                "\x1b[90m  • Bluetooth is enabled in system settings\x1b[0m",
                "\x1b[90m  • You have permission to use Bluetooth\x1b[0m",
            ]
            .join("\n");
            ui_tx.send(error_message).await.map_err(|e| e.to_string())?;
            return Err("No Bluetooth adapter found.".into());
        }
    };

    adapter.start_scan(ScanFilter::default()).await?;

    if debug_enabled {
        ui_tx
            .send("\x1b[90m» Scanning for bitchat service...\x1b[0m\n".to_string())
            .await
            .map_err(|e| e.to_string())?;
    }

    // We can't use debug_println! here directly as it's not async-aware and prints directly.
    // Instead, we replicate its logic and send to the UI channel.
    if debug_enabled && unsafe { DEBUG_LEVEL } >= DebugLevel::Basic {
        ui_tx
            .send("[1] Scanning for bitchat service...\n".to_string())
            .await
            .map_err(|e| e.to_string())?;
    }

    let start_time = std::time::Instant::now();
    let timeout_duration = Duration::from_secs(15);

    let peripheral = loop {
        if let Some(p) = find_peripheral(&adapter).await? {
            if debug_enabled {
                ui_tx
                    .send("\x1b[90m» Found bitchat service! Connecting...\x1b[0m\n".to_string())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            if debug_enabled && unsafe { DEBUG_LEVEL } >= DebugLevel::Basic {
                ui_tx
                    .send("[1] Match Found! Connecting...\n".to_string())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            adapter.stop_scan().await?;
            break p;
        }

        // Check if we've exceeded the timeout
        if start_time.elapsed() >= timeout_duration {
            adapter.stop_scan().await?;
            if debug_enabled {
                let error_message = [
                    "\n\x1b[91m❌ No BitChat service found\x1b[0m",
                    "\x1b[90mScan timed out after 15 seconds.\x1b[0m",
                    "\x1b[90mPlease check:\x1b[0m",
                    "\x1b[90m  • Another device is running BitChat\x1b[0m",
                    "\x1b[90m  • Bluetooth is enabled on both devices\x1b[0m",
                    "\x1b[90m  • You're within Bluetooth range\x1b[0m",
                    "\x1b[90m  • The other device is advertising the BitChat service\x1b[0m",
                ]
                .join("\n");
                ui_tx.send(error_message).await.map_err(|e| e.to_string())?;
            }
            return Err("No BitChat service found within 30 seconds.".into());
        }

        time::sleep(Duration::from_secs(1)).await;
    };

    if let Err(e) = peripheral.connect().await {
        let error_message = format!("\n\x1b[91m❌ Connection failed\x1b[0m\n\x1b[90mReason: {}\x1b[0m\n\x1b[90mPlease check:\x1b[0m\n\x1b[90m  • Bluetooth is enabled\x1b[0m\n\x1b[90m  •  The other device is running BitChat\x1b[0m\n\x1b[90m •  You're within range\x1b[0m\n\n\x1b[90mTry running the command again.\x1b[0m\n", e);
        ui_tx.send(error_message).await.map_err(|e| e.to_string())?;
        return Err(format!("Connection failed: {}", e).into());
    }

    Ok(peripheral)
}

fn parse_dm_command(line: &str) -> Option<(String, Option<String>)> {
    let rest = line.strip_prefix("/dm")?;
    if !rest.is_empty() && !rest.chars().next()?.is_whitespace() {
        return None;
    }

    let rest = rest.trim_start();
    let target_end = rest
        .char_indices()
        .find_map(|(idx, ch)| ch.is_whitespace().then_some(idx))
        .unwrap_or(rest.len());
    let target = rest[..target_end].trim().trim_start_matches('@');
    if target.is_empty() {
        return None;
    }

    let message = rest[target_end..].trim();
    let message = (!message.is_empty()).then(|| message.to_owned());

    Some((target.to_string(), message))
}

fn parse_reply_command(line: &str) -> Option<Option<String>> {
    let rest = line.strip_prefix("/reply")?;
    if !rest.is_empty() && !rest.chars().next()?.is_whitespace() {
        return None;
    }

    let message = rest.trim();
    let message = (!message.is_empty()).then(|| message.to_owned());
    Some(message)
}

fn parse_go_command_target(line: &str) -> Result<Option<String>, &'static str> {
    let Some(rest) = line.strip_prefix("/g") else {
        return Err("not-g");
    };
    if !rest.is_empty() && !rest.chars().next().unwrap_or(' ').is_whitespace() {
        return Err("not-g");
    }
    let arg = rest.trim();
    if arg.is_empty() {
        return Ok(None);
    }
    if arg.split_whitespace().count() > 1 {
        return Err("usage");
    }
    let geohash = nostr_geo::normalize_geohash(arg).ok_or("usage")?;
    Ok(Some(format!("#{}", geohash)))
}

fn canonicalize_command_alias(raw_line: &str) -> String {
    if !raw_line.starts_with('/') {
        return raw_line.to_string();
    }

    let mut parts = raw_line.splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("");

    let canonical = match cmd {
        "/h" => "/help",
        "/p" => "/public",
        "/n" => "/name",
        "/c" => "/clear",
        "/l" => "/leave",
        "/d" => "/dm",
        "/f" => "/file",
        "/ch" => "/channels",
        "/b" => "/block",
        "/u" => "/unblock",
        "/s" => "/search",
        "/e" => "/export",
        "/up" => "/upload",
        _ => return raw_line.to_string(),
    };

    if rest.trim().is_empty() {
        canonical.to_string()
    } else {
        format!("{} {}", canonical, rest.trim_start())
    }
}

fn trim_wrapping_quotes(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}

fn parse_upload_path(line: &str) -> Result<Option<String>, &'static str> {
    let Some(rest) = line.strip_prefix("/upload") else {
        return Ok(None);
    };
    if !rest.is_empty() && !rest.chars().next().unwrap_or(' ').is_whitespace() {
        return Ok(None);
    }

    let arg = trim_wrapping_quotes(rest);
    if arg.is_empty() {
        return Err("Usage: /upload <path>");
    }
    Ok(Some(arg.to_string()))
}

#[derive(Debug, Clone)]
struct VerificationLinkPayload {
    version: i32,
    noise_key_hex: String,
    sign_key_hex: String,
    npub: Option<String>,
    nickname: String,
    ts: i64,
    nonce_b64: String,
}

fn parse_verifylink_command(line: &str) -> Result<Option<String>, &'static str> {
    let Some(rest) = line.strip_prefix("/verifylink") else {
        return Ok(None);
    };
    if !rest.is_empty() && !rest.chars().next().unwrap_or(' ').is_whitespace() {
        return Ok(None);
    }
    let value = rest.trim();
    if value.is_empty() {
        return Err("usage");
    }
    Ok(Some(value.to_string()))
}

fn build_verification_qr_canonical_bytes(payload: &VerificationLinkPayload) -> Vec<u8> {
    let mut out = Vec::new();
    fn append_field(out: &mut Vec<u8>, value: &str) {
        let bytes = value.as_bytes();
        let len = bytes.len().min(255);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }

    append_field(&mut out, "bitchat-verify-v1");
    append_field(&mut out, &payload.version.to_string());
    append_field(&mut out, &payload.noise_key_hex.to_ascii_lowercase());
    append_field(&mut out, &payload.sign_key_hex.to_ascii_lowercase());
    append_field(&mut out, payload.npub.as_deref().unwrap_or(""));
    append_field(&mut out, &payload.nickname);
    append_field(&mut out, &payload.ts.to_string());
    append_field(&mut out, &payload.nonce_b64);
    out
}

fn verification_link_noise_fingerprint(noise_key_hex: &str) -> Result<String, String> {
    let noise_key_bytes = hex::decode(noise_key_hex).map_err(|_| "invalid noise hex".to_string())?;
    if noise_key_bytes.len() != 32 {
        return Err("noise must be 32-byte hex".to_string());
    }

    let mut hasher = Sha256::new();
    hasher.update(&noise_key_bytes);
    let digest = hasher.finalize();
    Ok(hex::encode(digest))
}

fn verify_bitchat_verify_link(
    link: &str,
    max_age_secs: i64,
) -> Result<VerificationLinkPayload, String> {
    let url = url::Url::parse(link).map_err(|e| format!("invalid URL: {}", e))?;
    if !url.scheme().eq_ignore_ascii_case("bitchat") {
        return Err("invalid scheme".to_string());
    }
    if !matches!(url.host_str(), Some("verify")) {
        return Err("invalid host".to_string());
    }

    let mut query: HashMap<String, String> = HashMap::new();
    for (k, v) in url.query_pairs() {
        query.insert(k.to_string(), v.to_string());
    }
    let get_required = |name: &str| -> Result<String, String> {
        query
            .get(name)
            .cloned()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing field '{}'", name))
    };

    let version = get_required("v")?
        .parse::<i32>()
        .map_err(|_| "invalid v".to_string())?;
    if version != 1 {
        return Err(format!("unsupported v={}", version));
    }
    let noise_key_hex = get_required("noise")?.to_ascii_lowercase();
    let sign_key_hex = get_required("sign")?.to_ascii_lowercase();
    let nickname = get_required("nick")?;
    let ts = get_required("ts")?
        .parse::<i64>()
        .map_err(|_| "invalid ts".to_string())?;
    let nonce_b64 = get_required("nonce")?;
    let sig_hex = get_required("sig")?.to_ascii_lowercase();
    let npub = query.get("npub").cloned().filter(|value| !value.is_empty());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or_default();
    if now.saturating_sub(ts) > max_age_secs {
        return Err("verification link expired".to_string());
    }

    let noise_key_bytes = hex::decode(&noise_key_hex).map_err(|_| "invalid noise hex".to_string())?;
    if noise_key_bytes.len() != 32 {
        return Err("noise must be 32-byte hex".to_string());
    }

    let sign_key_bytes = hex::decode(&sign_key_hex).map_err(|_| "invalid sign hex".to_string())?;
    let sign_key_array: [u8; 32] = sign_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "sign must be 32-byte hex".to_string())?;
    let verifying_key =
        VerifyingKey::from_bytes(&sign_key_array).map_err(|_| "invalid signing key".to_string())?;

    let sig_bytes = hex::decode(&sig_hex).map_err(|_| "invalid sig hex".to_string())?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "sig must be 64-byte hex".to_string())?;
    let signature = Signature::from_bytes(&sig_array);

    let payload = VerificationLinkPayload {
        version,
        noise_key_hex,
        sign_key_hex,
        npub,
        nickname,
        ts,
        nonce_b64,
    };
    let canonical = build_verification_qr_canonical_bytes(&payload);
    verifying_key
        .verify_strict(&canonical, &signature)
        .map_err(|_| "signature verification failed".to_string())?;
    Ok(payload)
}

fn parse_channel_shortcut(line: &str) -> Option<usize> {
    let raw = line.strip_prefix('/')?;
    if raw.len() != 1 {
        return None;
    }
    let digit = raw.chars().next()?;
    if !('1'..='9').contains(&digit) {
        return None;
    }
    Some((digit as u8 - b'1') as usize)
}

fn search_query_from_line(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("/search")?;
    if !rest.is_empty() && !rest.chars().next().unwrap_or(' ').is_whitespace() {
        return None;
    }
    let query = rest.trim();
    if query.is_empty() {
        None
    } else {
        Some(query)
    }
}

fn export_path_from_line(line: &str) -> Option<std::path::PathBuf> {
    let rest = line.strip_prefix("/export")?;
    if !rest.is_empty() && !rest.chars().next().unwrap_or(' ').is_whitespace() {
        return None;
    }
    let arg = rest.trim();
    if arg.is_empty() {
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        Some(std::path::PathBuf::from(format!(
            "bitchat_export_{}.txt",
            timestamp
        )))
    } else {
        Some(std::path::PathBuf::from(arg))
    }
}

fn truncate_for_export(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max_chars.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn remote_image_fetch_proxy() -> Option<String> {
    [
        "BITCHAT_TUI_NOSTR_PROXY",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    .into_iter()
    .find_map(|name| {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn build_remote_image_client() -> Option<reqwest::Client> {
    let timeout_secs = env_u64("BITCHAT_REMOTE_IMAGE_TIMEOUT_SECS", 12);
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(timeout_secs));
    if let Some(proxy_url) = remote_image_fetch_proxy() {
        match reqwest::Proxy::all(&proxy_url) {
            Ok(proxy) => {
                builder = builder.proxy(proxy);
            }
            Err(e) => {
                write_debug_log(&format!(
                    "remote image fetch proxy is invalid ({}): {}",
                    proxy_url, e
                ));
            }
        }
    }
    builder.build().ok()
}

fn extract_first_http_url(content: &str) -> Option<String> {
    for token in content.split_whitespace() {
        let candidate = token.trim_matches(|ch: char| {
            matches!(ch, '"' | '\'' | '(' | ')' | '[' | ']' | '<' | '>' | ',' | ';')
        });
        if !(candidate.starts_with("http://") || candidate.starts_with("https://")) {
            continue;
        }
        if url::Url::parse(candidate).is_ok() {
            return Some(candidate.to_string());
        }
    }
    None
}

fn ext_from_content_type(content_type: &str) -> Option<&'static str> {
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match mime.as_str() {
        "image/jpeg" | "image/jpg" => Some("jpg"),
        "image/png" => Some("png"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        "image/bmp" => Some("bmp"),
        "image/avif" => Some("avif"),
        _ => None,
    }
}

fn ext_from_url(url: &url::Url) -> Option<String> {
    let path = url.path();
    let file_name = path.rsplit('/').next().unwrap_or_default();
    let ext = std::path::Path::new(file_name)
        .extension()
        .and_then(|value| value.to_str())?
        .to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "bmp" | "avif" => Some(ext),
        _ => None,
    }
}

fn sanitized_base_name(url: &url::Url) -> String {
    let path = url.path();
    let segment = path.rsplit('/').next().unwrap_or_default();
    let stem = std::path::Path::new(segment)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("image");
    let mut clean = stem
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    clean = clean.trim_matches('_').to_string();
    if clean.is_empty() {
        "image".to_string()
    } else {
        clean
    }
}

async fn download_remote_image_to_incoming(
    client: &reqwest::Client,
    url: &str,
) -> Result<std::path::PathBuf, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {}", e))?;
    let response = client
        .get(parsed.clone())
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e))?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }

    let max_bytes = env_u64("BITCHAT_REMOTE_IMAGE_MAX_BYTES", 20 * 1024 * 1024);
    if let Some(length) = response.content_length() {
        if length > max_bytes {
            return Err(format!(
                "image too large: {} bytes (limit {} bytes)",
                length, max_bytes
            ));
        }
    }

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let is_image = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .starts_with("image/");
    if !is_image {
        return Err(format!("non-image content-type: {}", content_type));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("failed reading body: {}", e))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "image too large after download: {} bytes (limit {} bytes)",
            bytes.len(),
            max_bytes
        ));
    }

    let ext = ext_from_content_type(&content_type)
        .map(|value| value.to_string())
        .or(ext_from_url(&parsed))
        .unwrap_or_else(|| "img".to_string());
    let file_name = format!(
        "{}_{}.{}",
        sanitized_base_name(&parsed),
        Uuid::new_v4(),
        ext
    );

    let destination = std::env::current_dir()
        .map_err(|e| format!("cannot resolve current dir: {}", e))?
        .join("received_files")
        .join("images")
        .join("incoming")
        .join(file_name);
    if let Some(parent) = destination.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("failed to create directory: {}", e))?;
    }
    tokio::fs::write(&destination, &bytes)
        .await
        .map_err(|e| format!("failed to write image: {}", e))?;
    Ok(destination)
}

fn split_optional_epoch_and_content(raw: &str) -> (Option<String>, String) {
    let Some((maybe_epoch, content)) = raw.split_once(':') else {
        return (None, raw.to_string());
    };
    if maybe_epoch.parse::<i64>().is_ok() {
        (Some(maybe_epoch.to_string()), content.to_string())
    } else {
        (None, raw.to_string())
    }
}

async fn localize_image_content_if_url(
    content: &str,
    client: &reqwest::Client,
) -> Option<String> {
    let trimmed = content.trim();
    if trimmed.starts_with("[image] ") {
        return None;
    }
    let url = extract_first_http_url(trimmed)?;
    let local_path = match download_remote_image_to_incoming(client, &url).await {
        Ok(path) => path,
        Err(e) => {
            write_debug_log(&format!("remote image auto-fetch skipped for {}: {}", url, e));
            return None;
        }
    };
    Some(format!("[image] {}", local_path.display()))
}

async fn maybe_localize_structured_remote_image_message(
    raw: &str,
    local_nickname: &str,
    client: Option<&reqwest::Client>,
) -> Option<String> {
    let client = client?;

    if let Some(payload) = raw.strip_prefix("__CHANNEL__:") {
        let (channel, rest) = payload.split_once(':')?;
        let (sender, rest) = rest.split_once(':')?;
        if sender == local_nickname {
            return None;
        }
        let is_geohash = nostr_geo::is_geohash_channel(channel);
        if is_geohash {
            let (third, rest) = rest.split_once(':')?;
            if nostr_geo::looks_like_dm_pubkey(third) || third.starts_with("npub") {
                let (timestamp, rest) = rest.split_once(':')?;
                let (epoch, content) = split_optional_epoch_and_content(rest);
                let localized = localize_image_content_if_url(&content, client).await?;
                return Some(if let Some(epoch) = epoch {
                    format!(
                        "__CHANNEL__:{}:{}:{}:{}:{}:{}",
                        channel, sender, third, timestamp, epoch, localized
                    )
                } else {
                    format!(
                        "__CHANNEL__:{}:{}:{}:{}:{}",
                        channel, sender, third, timestamp, localized
                    )
                });
            }

            let timestamp = third;
            let (epoch, content) = split_optional_epoch_and_content(rest);
            let localized = localize_image_content_if_url(&content, client).await?;
            return Some(if let Some(epoch) = epoch {
                format!(
                    "__CHANNEL__:{}:{}:{}:{}:{}",
                    channel, sender, timestamp, epoch, localized
                )
            } else {
                format!("__CHANNEL__:{}:{}:{}:{}", channel, sender, timestamp, localized)
            });
        }

        let (timestamp, rest) = rest.split_once(':')?;
        let (epoch, content) = split_optional_epoch_and_content(rest);
        let localized = localize_image_content_if_url(&content, client).await?;
        return Some(if let Some(epoch) = epoch {
            format!(
                "__CHANNEL__:{}:{}:{}:{}:{}",
                channel, sender, timestamp, epoch, localized
            )
        } else {
            format!("__CHANNEL__:{}:{}:{}:{}", channel, sender, timestamp, localized)
        });
    }

    if let Some(payload) = raw.strip_prefix("__GEO_DM__:") {
        let (channel, rest) = payload.split_once(':')?;
        let (sender, rest) = rest.split_once(':')?;
        if sender == local_nickname {
            return None;
        }
        let (sender_pubkey, rest) = rest.split_once(':')?;
        let (timestamp, rest) = rest.split_once(':')?;
        let (epoch_or_id, rest) = rest.split_once(':')?;
        if epoch_or_id.parse::<i64>().is_ok() {
            let (message_id, content) = rest.split_once(':')?;
            let localized = localize_image_content_if_url(content, client).await?;
            return Some(format!(
                "__GEO_DM__:{}:{}:{}:{}:{}:{}:{}",
                channel, sender, sender_pubkey, timestamp, epoch_or_id, message_id, localized
            ));
        }
        let message_id = epoch_or_id;
        let content = rest;
        let localized = localize_image_content_if_url(content, client).await?;
        return Some(format!(
            "__GEO_DM__:{}:{}:{}:{}:{}:{}",
            channel, sender, sender_pubkey, timestamp, message_id, localized
        ));
    }

    None
}

fn find_latest_geohash_with_messages(app: &App) -> Option<String> {
    app.channels
        .iter()
        .filter(|channel| nostr_geo::is_geohash_channel(channel))
        .filter_map(|channel| {
            let messages = app.channel_messages.get(channel)?;
            if messages.is_empty() {
                return None;
            }
            let last_epoch = messages
                .iter()
                .rev()
                .find_map(|message| message.timestamp_epoch)
                .unwrap_or(i64::MIN);
            Some((last_epoch, messages.len(), channel.clone()))
        })
        .max_by(|(epoch_a, len_a, _), (epoch_b, len_b, _)| {
            epoch_a.cmp(epoch_b).then_with(|| len_a.cmp(len_b))
        })
        .map(|(_, _, channel)| channel)
}

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

enum GeohashDmTargetError {
    UnknownName,
    UnknownPubkey,
}

fn resolve_geohash_dm_target(
    app: &App,
    channel: &str,
    target: &str,
) -> Result<(String, String), GeohashDmTargetError> {
    let target = strip_display_suffix(target);
    if let Some(pubkey) = app.geohash_person_pubkey(channel, target) {
        return Ok((target.to_string(), pubkey));
    }

    let mut alias_matches: Vec<(String, String)> = app
        .nostr_aliases
        .iter()
        .filter_map(|(pubkey, alias)| {
            alias
                .eq_ignore_ascii_case(target)
                .then(|| (alias.clone(), pubkey.clone()))
        })
        .collect();
    if !alias_matches.is_empty() {
        alias_matches.sort_by(|a, b| a.1.cmp(&b.1));
        return Ok(alias_matches.remove(0));
    }

    if let Some(pubkey) = nostr_geo::normalize_dm_pubkey(target) {
        if let Some(label) = app.geohash_person_for_pubkey(channel, &pubkey) {
            return Ok((label, pubkey));
        }
        if let Some(alias) = app.nostr_aliases.get(&pubkey) {
            return Ok((alias.clone(), pubkey));
        }
        return Err(GeohashDmTargetError::UnknownPubkey);
    }

    Err(GeohashDmTargetError::UnknownName)
}

fn queue_geohash_dm_send(
    app: &mut App,
    nostr_geo_client: nostr_geo::NostrGeoClient,
    ui_tx: mpsc::Sender<String>,
    channel: String,
    target_label: String,
    recipient_pubkey: String,
    message: String,
    my_peer_id: String,
    sender_nickname: String,
) {
    queue_geohash_dm_send_with_display(
        app,
        nostr_geo_client,
        ui_tx,
        channel,
        target_label,
        recipient_pubkey,
        message,
        None,
        my_peer_id,
        sender_nickname,
    );
}

fn queue_geohash_dm_send_with_display(
    app: &mut App,
    nostr_geo_client: nostr_geo::NostrGeoClient,
    ui_tx: mpsc::Sender<String>,
    channel: String,
    target_label: String,
    recipient_pubkey: String,
    message: String,
    display_message: Option<String>,
    my_peer_id: String,
    sender_nickname: String,
) {
    let message_id = Uuid::new_v4().to_string();
    let display = display_message.unwrap_or_else(|| message.clone());
    app.add_pending_geohash_dm_message(display, message_id.clone());
    write_debug_log(&format!(
        "Queued geohash DM: channel={}, target={}, recipient={}, message={}",
        channel,
        sanitize_status_field(&target_label),
        App::short_pubkey(&recipient_pubkey),
        App::short_pubkey(&message_id)
    ));

    tokio::spawn(async move {
        let status = match nostr_geo_client
            .send_private_message(
                &channel,
                &recipient_pubkey,
                &message,
                &my_peer_id,
                &sender_nickname,
                &message_id,
            )
            .await
        {
            Ok(()) => format!("__GEO_DM_STATUS__:{}:sent", message_id),
            Err(e) => format!(
                "__GEO_DM_STATUS__:{}:failed:{}",
                message_id,
                sanitize_status_field(&format!("{}: {}", target_label, e))
            ),
        };
        let _ = ui_tx.send(status).await;
    });
}

fn sanitize_status_field(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

// Keep regular messages below the BLE fragmentation path when possible.
// This improves iOS interop for long multi-line mesh messages.
const OUTGOING_MESSAGE_SOFT_LIMIT_BYTES: usize = 320;

fn push_utf8_slices_with_limit(text: &str, limit_bytes: usize, out: &mut Vec<String>) {
    if text.is_empty() {
        return;
    }
    if text.len() <= limit_bytes {
        out.push(text.to_string());
        return;
    }

    let mut current = String::new();
    let mut current_len = 0usize;
    for ch in text.chars() {
        let ch_len = ch.len_utf8();
        if current_len + ch_len > limit_bytes && !current.is_empty() {
            out.push(std::mem::take(&mut current));
            current_len = 0;
        }
        current.push(ch);
        current_len += ch_len;
    }
    if !current.is_empty() {
        out.push(current);
    }
}

fn split_outgoing_message_chunks(message: &str) -> Vec<String> {
    if message.is_empty() {
        return Vec::new();
    }

    if message.len() <= OUTGOING_MESSAGE_SOFT_LIMIT_BYTES {
        return vec![message.to_string()];
    }

    let mut chunks: Vec<String> = Vec::new();
    let mut current = String::new();

    for raw_line in message.split('\n') {
        let line = raw_line.trim_end_matches('\r');

        if line.len() > OUTGOING_MESSAGE_SOFT_LIMIT_BYTES {
            if !current.is_empty() {
                chunks.push(std::mem::take(&mut current));
            }
            push_utf8_slices_with_limit(line, OUTGOING_MESSAGE_SOFT_LIMIT_BYTES, &mut chunks);
            continue;
        }

        if current.is_empty() {
            current.push_str(line);
            continue;
        }

        let candidate_len = current.len() + 1 + line.len();
        if candidate_len <= OUTGOING_MESSAGE_SOFT_LIMIT_BYTES {
            current.push('\n');
            current.push_str(line);
        } else {
            chunks.push(std::mem::take(&mut current));
            current.push_str(line);
        }
    }

    if !current.is_empty() {
        chunks.push(current);
    }

    if chunks.is_empty() {
        vec![message.to_string()]
    } else {
        chunks
    }
}

fn build_terminal_title(app: &App) -> String {
    let unread_total: usize = app.unread_counts.values().copied().sum();
    let current = if let Some(person_idx) = app.sidebar_state.people_selected {
        app.visible_person_at(person_idx)
            .map(|name| format!("DM {}", name))
            .or_else(|| {
                app.current_conv
                    .as_ref()
                    .and_then(|(dm, _)| dm.as_ref().map(|dm_target| format!("DM {}", dm_target)))
            })
            .unwrap_or_else(|| "DM".to_string())
    } else {
        app.current_conv
            .as_ref()
            .and_then(|(_, channel)| channel.clone())
            .unwrap_or_else(|| "#public".to_string())
    };
    if unread_total > 0 {
        format!("🔔 ({}) bitchat-tui - {}", unread_total, current)
    } else {
        format!("bitchat-tui - {}", current)
    }
}

fn sync_terminal_title(last_title: &mut String, app: &App) {
    let next_title = build_terminal_title(app);
    if *last_title == next_title {
        return;
    }
    let _ = execute!(std::io::stdout(), SetTitle(next_title.clone()));
    *last_title = next_title;
}

fn is_pass_command(line: &str) -> bool {
    line == "/pass" || line.starts_with("/pass ")
}

fn mesh_only_command_in_geohash(line: &str) -> Option<&'static str> {
    let command = line.split_whitespace().next().unwrap_or("");
    match command {
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Channel for user input from the TUI input box
    let (input_tx, mut input_rx) = mpsc::channel::<String>(10);
    // Channel for all UI output. All parts of the application will send strings here.
    let (ui_tx, mut ui_rx) = mpsc::channel::<String>(UI_EVENT_BUFFER_SIZE);

    // Load saved state to get the nickname before initializing TUI
    let saved_state = load_state();
    let saved_nickname = saved_state
        .nickname
        .clone()
        .unwrap_or_else(|| "anonymous".to_string());
    let saved_nickname_clone = saved_nickname.clone();
    let nostr_identity_seed = saved_state
        .identity_key
        .clone()
        .or_else(|| saved_state.noise_static_key.clone())
        .unwrap_or_default();

    // Initialize the TUI with the saved nickname
    let mut terminal = tui_mod::init().expect("Failed to initialize TUI");
    let mut app = App::new_with_nickname(saved_nickname);
    let mut last_terminal_title = String::new();
    app.update_blocked_list(saved_state.blocked_names.clone());
    app.update_verified_identities({
        let mut entries = Vec::new();
        for fp in &saved_state.favorites {
            let short = if fp.len() > 10 { &fp[..10] } else { fp.as_str() };
            if let Some(label) = saved_state.verified_labels.get(fp) {
                entries.push(format!("{} ({})", label, short));
            } else {
                entries.push(format!("fingerprint:{}", short));
            }
        }
        entries
    });
    app.nostr_aliases = saved_state.nostr_aliases.clone();
    let nostr_geo_client =
        nostr_geo::NostrGeoClient::new(ui_tx.clone(), nostr_identity_seed.clone());

    // Spawn Bluetooth connection setup in the background
    let ui_tx_clone = ui_tx.clone();
    let mut bt_handle = Some(tokio::spawn(async move {
        match setup_bluetooth_connection(ui_tx_clone.clone()).await {
            Ok(peripheral) => {
                let _ = ui_tx_clone.send("__CONNECTED__".to_string()).await;
                Ok(peripheral)
            }
            Err(e) => {
                let _ = ui_tx_clone.send(format!("__ERROR__{}", e)).await;
                Err(e)
            }
        }
    }));

    // State for after connection
    let mut peripheral: Option<Peripheral> = None;
    let mut notification_stream = None;
    let mut _characteristics = None;
    let mut cmd_char = None;
    let mut post_connect_initialized = false;
    let encryption = Arc::new(EncryptionService::new());
    let my_peer_id = encryption.derive_peer_id();
    let mut app_state: Option<persistence::AppState> = Some(saved_state.clone());
    let mut nickname = saved_nickname_clone.clone();
    let mut encryption_service = Some(encryption);
    let peers: Option<Arc<Mutex<HashMap<String, Peer>>>> =
        Some(Arc::new(Mutex::new(HashMap::new())));
    let mut bloom: Option<Bloom<String>> = Some(Bloom::new_for_fp_rate(500, 0.01));
    let mut fragment_collector: Option<FragmentCollector> = Some(FragmentCollector::new());
    let mut delivery_tracker: Option<DeliveryTracker> = Some(DeliveryTracker::new());
    let mut chat_context: Option<ChatContext> = Some(ChatContext::new());
    let mut channel_keys: Option<HashMap<String, [u8; 32]>> = Some(HashMap::new());
    let mut _chat_messages: Option<HashMap<String, Vec<String>>> = None;
    let mut blocked_peers: Option<HashSet<String>> = Some(saved_state.blocked_peers.clone());
    let mut channel_creators: Option<HashMap<String, String>> =
        Some(saved_state.channel_creators.clone());
    let mut password_protected_channels: Option<HashSet<String>> =
        Some(saved_state.password_protected_channels.clone());
    let mut channel_key_commitments: Option<HashMap<String, String>> =
        Some(saved_state.channel_key_commitments.clone());
    let mut discovered_channels: Option<HashSet<String>> = Some(HashSet::new());
    let mut favorites: Option<HashSet<String>> = Some(saved_state.favorites.clone());
    let mut verified_labels: Option<HashMap<String, String>> =
        Some(saved_state.verified_labels.clone());
    let verified_fingerprints_state =
        Arc::new(std::sync::Mutex::new(saved_state.favorites.clone()));
    let verified_labels_state =
        Arc::new(std::sync::Mutex::new(saved_state.verified_labels.clone()));
    let mut _identity_key: Option<Vec<u8>> = saved_state.identity_key.clone();
    let create_app_state: Option<AppStateFactory> = Some(build_app_state_factory(
        verified_fingerprints_state.clone(),
        verified_labels_state.clone(),
        _identity_key.clone(),
        app_state
            .as_ref()
            .and_then(|state| state.noise_static_key.clone()),
    ));
    let mut noise_session_manager: Option<NoiseSessionManager> = None;

    let mut restored_channels: Vec<String> = Vec::new();
    let mut seen_restored_channels: HashSet<String> = HashSet::new();
    for raw_channel in &saved_state.joined_channels {
        let trimmed = raw_channel.trim();
        if trimmed.is_empty() || trimmed == "#public" {
            continue;
        }
        let normalized = if trimmed.starts_with('#') {
            trimmed.to_string()
        } else {
            format!("#{}", trimmed)
        };
        if seen_restored_channels.insert(normalized.clone()) {
            restored_channels.push(normalized);
        }
    }

    if let Some(state) = app_state.as_mut() {
        if state.joined_channels != restored_channels {
            state.joined_channels = restored_channels.clone();
            let _ = save_state(state);
        }
    }

    let mut pending_saved_geohash_joins: VecDeque<String> = VecDeque::new();
    for channel in &restored_channels {
        if !app.channels.contains(channel) {
            app.channels.push(channel.clone());
        }
        app.channel_messages.entry(channel.clone()).or_default();
        discovered_channels
            .as_mut()
            .unwrap()
            .insert(channel.clone());
        chat_context.as_mut().unwrap().add_channel(channel);

        if nostr_geo::is_geohash_channel(channel) {
            pending_saved_geohash_joins.push_back(channel.clone());
        }
    }
    let mut active_saved_geohash_join: Option<tokio::task::JoinHandle<()>> = None;
    let remote_image_client = build_remote_image_client();

    let mut last_tick = std::time::Instant::now();
    let tick_rate = StdDuration::from_millis(100);
    'mainloop: loop {
        if let Some(handle) = active_saved_geohash_join.as_ref() {
            if handle.is_finished() {
                let handle = active_saved_geohash_join.take().unwrap();
                let _ = handle.await;
            }
        }
        if active_saved_geohash_join.is_none() {
            if let Some(channel) = pending_saved_geohash_joins.pop_front() {
                let client = nostr_geo_client.clone();
                let nickname_for_join = nickname.clone();
                let ui_tx_for_join = ui_tx.clone();
                active_saved_geohash_join = Some(tokio::spawn(async move {
                    if let Err(e) = client.join_channel(&channel, &nickname_for_join).await {
                        let _ = ui_tx_for_join
                            .send(format!(
                                "system: Failed to auto-join saved geohash channel {}: {}",
                                channel, e
                            ))
                            .await;
                    }
                }));
            }
        }

        // 1. Handle UI messages
        for _ in 0..MAX_UI_MESSAGES_PER_TICK {
            let Ok(msg) = ui_rx.try_recv() else {
                break;
            };

            if msg == "__CONNECTED__" {
                app.transition_to_connected();
                // Await the bt_handle to get the peripheral
                if peripheral.is_none() {
                    if let Ok(Ok(periph)) = bt_handle.take().unwrap().await {
                        peripheral = Some(periph);
                    }
                }
            } else if msg.starts_with("__ERROR__") {
                let err = msg.trim_start_matches("__ERROR__").to_string();
                app.connected = false;
                app.mesh_status = "Offline".to_string();
                app.add_log_message(format!(
                    "system: Bluetooth mesh unavailable: {}. Nostr geohash channels remain available, for example /j #ws.",
                    err
                ));
            } else if matches!(app.phase, tui::app::TuiPhase::Connecting) {
                app.add_popup_message(msg);
            } else {
                let rewritten = maybe_localize_structured_remote_image_message(
                    &msg,
                    &nickname,
                    remote_image_client.as_ref(),
                )
                .await;
                app.add_log_message(rewritten.unwrap_or(msg));
            }
        }

        // Post-connection initialization (only once)
        if !post_connect_initialized && matches!(app.phase, tui::app::TuiPhase::Connected) {
            if let Some(current_peripheral) = peripheral.as_ref().cloned() {
                // Discover services, get characteristics, subscribe, etc.
                if let Err(e) = current_peripheral.discover_services().await {
                    app.connected = false;
                    app.mesh_status = "Offline".to_string();
                    app.add_log_message(format!(
                        "system: Bluetooth mesh unavailable: service discovery failed: {}. Nostr geohash channels remain available, for example /j #ws.",
                        e
                    ));
                    let _ = current_peripheral.disconnect().await;
                    peripheral = None;
                    notification_stream = None;
                    _characteristics = None;
                    cmd_char = None;
                    post_connect_initialized = true;
                    continue;
                }

                let chars = current_peripheral.characteristics();
                let Some(cmd) = chars
                    .iter()
                    .find(|c| c.uuid == BITCHAT_CHARACTERISTIC_UUID)
                    .cloned()
                else {
                    let available = chars
                        .iter()
                        .map(|c| c.uuid.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    app.connected = false;
                    app.mesh_status = "Offline".to_string();
                    app.add_log_message(format!(
                        "system: Bluetooth mesh unavailable: required bitchat characteristic {} was not found. Available characteristics: {}. Nostr geohash channels remain available, for example /j #ws.",
                        BITCHAT_CHARACTERISTIC_UUID,
                        if available.is_empty() { "none" } else { &available }
                    ));
                    let _ = current_peripheral.disconnect().await;
                    peripheral = None;
                    notification_stream = None;
                    _characteristics = None;
                    cmd_char = None;
                    post_connect_initialized = true;
                    continue;
                };

                if let Err(e) = current_peripheral.subscribe(&cmd).await {
                    app.connected = false;
                    app.mesh_status = "Offline".to_string();
                    app.add_log_message(format!(
                        "system: Bluetooth mesh unavailable: failed to subscribe to bitchat characteristic: {}. Nostr geohash channels remain available, for example /j #ws.",
                        e
                    ));
                    let _ = current_peripheral.disconnect().await;
                    peripheral = None;
                    notification_stream = None;
                    _characteristics = None;
                    cmd_char = None;
                    post_connect_initialized = true;
                    continue;
                }

                let notifications = match current_peripheral.notifications().await {
                    Ok(notifications) => notifications,
                    Err(e) => {
                        app.connected = false;
                        app.mesh_status = "Offline".to_string();
                        app.add_log_message(format!(
                            "system: Bluetooth mesh unavailable: failed to open notifications: {}. Nostr geohash channels remain available, for example /j #ws.",
                            e
                        ));
                        let _ = current_peripheral.disconnect().await;
                        peripheral = None;
                        notification_stream = None;
                        _characteristics = None;
                        cmd_char = None;
                        post_connect_initialized = true;
                        continue;
                    }
                };

                notification_stream = Some(notifications);
                _characteristics = Some(chars);
                cmd_char = Some(cmd.clone());
                // Announce the existing mesh identity once Bluetooth is available.
                let encryption = encryption_service.as_ref().unwrap();
                let announce_payload = create_announcement_payload(
                    &nickname,
                    &encryption.get_static_public_key_data(),
                    &encryption.get_signing_public_key_data(),
                )
                .unwrap_or_else(|| nickname.as_bytes().to_vec());
                let announce_timestamp = current_timestamp_ms();
                let announce_signature_payload = create_bitchat_packet_for_signing_at(
                    &my_peer_id,
                    None,
                    MessageType::Announce,
                    &announce_payload,
                    announce_timestamp,
                );
                let announce_signature = encryption.sign(&announce_signature_payload);
                let announce_packet = create_bitchat_packet_with_signature_at(
                    &my_peer_id,
                    MessageType::Announce,
                    announce_payload,
                    Some(announce_signature),
                    announce_timestamp,
                );
                let announce_write_type = if cfg!(target_os = "windows") {
                    WriteType::WithResponse
                } else {
                    WriteType::WithoutResponse
                };
                let _ = current_peripheral
                    .write(&cmd, &announce_packet, announce_write_type)
                    .await;
                _chat_messages = Some(HashMap::new());
                post_connect_initialized = true;

                // Initialize TUI blocked list with current blocked users
                if let (Some(blocked_peers), Some(peers), Some(encryption_service)) = (
                    blocked_peers.as_ref(),
                    peers.as_ref(),
                    encryption_service.as_ref(),
                ) {
                    let mut blocked_nicknames: Vec<String> = peers
                        .lock()
                        .await
                        .iter()
                        .filter_map(|(peer_id, peer)| {
                            if let Some(fp) = encryption_service.get_peer_fingerprint(peer_id) {
                                if blocked_peers.contains(&fp) {
                                    peer.nickname.clone()
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .collect();
                    blocked_nicknames.extend(app.blocked.iter().cloned());
                    blocked_nicknames.sort();
                    blocked_nicknames.dedup();
                    app.update_blocked_list(blocked_nicknames);
                }
                // Initialize Noise session manager
                let static_secret =
                    if let Some(noise_key_bytes) = &app_state.as_ref().unwrap().noise_static_key {
                        let key_array: [u8; 32] = noise_key_bytes.as_slice().try_into().unwrap();
                        StaticSecret::from(key_array)
                    } else {
                        StaticSecret::random_from_rng(&mut rand::thread_rng())
                    };

                let mut temp_noise_session_manager = NoiseSessionManager::new(static_secret);

                // Set up session callbacks (matching Swift implementation)
                temp_noise_session_manager.set_on_session_established(
                    |peer_id, remote_static_key| {
                        debug_full_println!(
                            "[NOISE] Session established with {} (remote key: {:?})",
                            peer_id,
                            &remote_static_key.to_bytes()[..8]
                        );
                    },
                );

                temp_noise_session_manager.set_on_session_failed(|peer_id, error| {
                    debug_full_println!("[NOISE] Session failed with {}: {:?}", peer_id, error);
                });

                // Set up peer authentication callback (matching Swift implementation)
                temp_noise_session_manager.set_on_peer_authenticated(|peer_id, fingerprint| {
                    debug_full_println!(
                        "[NOISE] Peer authenticated: {} (fingerprint: {})",
                        peer_id,
                        &fingerprint[..16]
                    );
                    // TODO: Update UI encryption status here
                });

                // Set up handshake required callback (matching Swift implementation)
                temp_noise_session_manager.set_on_handshake_required(|peer_id| {
                    debug_full_println!("[NOISE] Handshake required for peer: {}", peer_id);
                    // TODO: Update UI encryption status here
                });

                if let Some(known_verified) = favorites.as_ref() {
                    temp_noise_session_manager.load_verified_fingerprints(known_verified.clone());
                }

                noise_session_manager = Some(temp_noise_session_manager);

                // Set the noise session manager in the encryption service
                if let Some(encryption_service) = &mut encryption_service {
                    // We can't clone NoiseSessionManager, so we'll set it up later
                    // The encryption service will be updated when needed
                }
            }
        }

        // 2. Handle Bluetooth notifications (async)
        if let (Some(notification_stream), true) =
            (notification_stream.as_mut(), post_connect_initialized)
        {
            for _ in 0..64 {
                let notification = match tokio::time::timeout(
                    std::time::Duration::from_millis(1),
                    notification_stream.next(),
                )
                .await
                {
                    Ok(Some(notification)) => notification,
                    Ok(None) | Err(_) => break,
                };
                let mut peers_lock = peers.as_ref().unwrap().lock().await;
                let ui_tx = ui_tx.clone();

                // Process notification
                write_debug_log(&format!("Processing notification from characteristic"));
                write_debug_log(&format!(
                    "Raw notification data: {} bytes",
                    notification.value.len()
                ));

                // Log the raw bytes for debugging
                write_debug_log(&format!("Raw bytes: {:?}", notification.value));

                match parse_bitchat_packet(&notification.value) {
                    Ok(packet) => {
                        if packet.sender_id_str == my_peer_id {
                            continue;
                        }

                        write_debug_log(&format!("Successfully parsed packet: type={:?}, sender_id='{}', recipient_id='{:?}'", 
                            packet.msg_type, packet.sender_id_str, packet.recipient_id_str));

                        // Handle different packet types
                        match packet.msg_type {
                            MessageType::Announce => {
                                write_debug_log("Processing Announce packet");
                                handle_announce_message(&packet, &mut peers_lock, ui_tx.clone())
                                    .await;
                            }
                            MessageType::Message => {
                                write_debug_log("Processing Message packet");
                                handle_message_packet(
                                    &packet,
                                    &notification.value,
                                    &mut peers_lock,
                                    bloom.as_mut().unwrap(),
                                    discovered_channels.as_mut().unwrap(),
                                    password_protected_channels.as_mut().unwrap(),
                                    channel_keys.as_mut().unwrap(),
                                    chat_context.as_mut().unwrap(),
                                    delivery_tracker.as_mut().unwrap(),
                                    encryption_service.as_ref().unwrap(),
                                    noise_session_manager.as_mut().unwrap(),
                                    peripheral.as_ref().unwrap(),
                                    cmd_char.as_ref().unwrap(),
                                    &nickname,
                                    &my_peer_id,
                                    blocked_peers.as_ref().unwrap(),
                                    ui_tx.clone(),
                                )
                                .await;
                            }
                            MessageType::FragmentStart
                            | MessageType::FragmentContinue
                            | MessageType::FragmentEnd => {
                                write_debug_log("Processing Fragment packet");
                                handle_fragment_packet(
                                    &packet,
                                    &notification.value,
                                    fragment_collector.as_mut().unwrap(),
                                    &mut peers_lock,
                                    bloom.as_mut().unwrap(),
                                    discovered_channels.as_mut().unwrap(),
                                    password_protected_channels.as_mut().unwrap(),
                                    chat_context.as_mut().unwrap(),
                                    encryption_service.as_ref().unwrap(),
                                    peripheral.as_ref().unwrap(),
                                    cmd_char.as_ref().unwrap(),
                                    &nickname,
                                    &my_peer_id,
                                    blocked_peers.as_ref().unwrap(),
                                    ui_tx.clone(),
                                )
                                .await;
                            }
                            MessageType::KeyExchange => {
                                write_debug_log("Processing KeyExchange packet");
                                handle_key_exchange_message(
                                    &packet,
                                    &mut peers_lock,
                                    encryption_service.as_ref().unwrap(),
                                    peripheral.as_ref().unwrap(),
                                    cmd_char.as_ref().unwrap(),
                                    &my_peer_id,
                                    ui_tx.clone(),
                                )
                                .await;
                            }
                            MessageType::Leave => {
                                write_debug_log("Processing Leave packet");
                                handle_leave_message(
                                    &packet,
                                    &mut peers_lock,
                                    chat_context.as_ref().unwrap(),
                                    ui_tx.clone(),
                                )
                                .await;
                            }
                            MessageType::ChannelAnnounce => {
                                write_debug_log("Processing ChannelAnnounce packet");
                                // Get the channel name from the packet payload
                                let payload_str = String::from_utf8_lossy(&packet.payload);
                                let parts: Vec<&str> = payload_str.split('|').collect();
                                if parts.len() >= 3 {
                                    let channel_name = parts[0].to_string();
                                    // Don't add #public as a regular channel
                                    if channel_name != "#public"
                                        && !app.channels.contains(&channel_name)
                                    {
                                        app.channels.push(channel_name.clone());
                                    }
                                }
                                handle_channel_announce_message(
                                    &packet,
                                    channel_creators.as_mut().unwrap(),
                                    password_protected_channels.as_mut().unwrap(),
                                    channel_keys.as_mut().unwrap(),
                                    channel_key_commitments.as_mut().unwrap(),
                                    chat_context.as_mut().unwrap(),
                                    blocked_peers.as_ref().unwrap(),
                                    &collect_manual_blocked_names(&app.blocked),
                                    &app.nostr_aliases,
                                    &app_state.as_ref().unwrap().encrypted_channel_passwords,
                                    &nickname,
                                    create_app_state.as_ref().unwrap().as_ref(),
                                    ui_tx.clone(),
                                )
                                .await;
                            }
                            MessageType::DeliveryAck => {
                                write_debug_log("Processing DeliveryAck packet");
                                handle_delivery_ack_message(
                                    &packet,
                                    &notification.value,
                                    encryption_service.as_ref().unwrap(),
                                    delivery_tracker.as_mut().unwrap(),
                                    peripheral.as_ref().unwrap(),
                                    cmd_char.as_ref().unwrap(),
                                    &my_peer_id,
                                    ui_tx.clone(),
                                )
                                .await;
                            }
                            MessageType::DeliveryStatusRequest => {
                                write_debug_log("Processing DeliveryStatusRequest packet");
                                handle_delivery_status_request_message(&packet, ui_tx.clone())
                                    .await;
                            }
                            MessageType::ReadReceipt => {
                                write_debug_log("Processing ReadReceipt packet");
                                handle_read_receipt_message(&packet, ui_tx.clone()).await;
                            }
                            MessageType::NoiseHandshakeInit => {
                                write_debug_log("Processing NoiseHandshakeInit packet");
                                handle_noise_handshake_init(
                                    &packet,
                                    noise_session_manager.as_mut().unwrap(),
                                    peripheral.as_ref().unwrap(),
                                    cmd_char.as_ref().unwrap(),
                                    &my_peer_id,
                                    ui_tx.clone(),
                                )
                                .await;
                            }
                            MessageType::NoiseHandshakeResp => {
                                write_debug_log("Processing NoiseHandshakeResp packet");
                                handle_noise_handshake_resp(
                                    &packet,
                                    noise_session_manager.as_mut().unwrap(),
                                    peripheral.as_ref().unwrap(),
                                    cmd_char.as_ref().unwrap(),
                                    &my_peer_id,
                                    ui_tx.clone(),
                                )
                                .await;
                            }
                            MessageType::NoiseEncrypted => {
                                write_debug_log(&format!(
                                    "Processing NoiseEncrypted packet from peer: {}",
                                    packet.sender_id_str
                                ));
                                write_debug_log(&format!(
                                    "Packet payload length: {}",
                                    packet.payload.len()
                                ));
                                write_debug_log(&format!(
                                    "Packet first 16 bytes: {:?}",
                                    &packet.payload[..std::cmp::min(16, packet.payload.len())]
                                ));
                                handle_noise_encrypted_message(
                                    &packet,
                                    noise_session_manager.as_mut().unwrap(),
                                    &mut peers_lock,
                                    bloom.as_mut().unwrap(),
                                    discovered_channels.as_mut().unwrap(),
                                    password_protected_channels.as_mut().unwrap(),
                                    channel_keys.as_mut().unwrap(),
                                    chat_context.as_mut().unwrap(),
                                    delivery_tracker.as_mut().unwrap(),
                                    encryption_service.as_ref().unwrap(),
                                    peripheral.as_ref().unwrap(),
                                    cmd_char.as_ref().unwrap(),
                                    &nickname,
                                    &my_peer_id,
                                    blocked_peers.as_ref().unwrap(),
                                    ui_tx.clone(),
                                )
                                .await;
                            }
                            MessageType::NoiseIdentityAnnounce => {
                                write_debug_log(&format!(
                                    "Processing NoiseIdentityAnnounce from peer: {}",
                                    packet.sender_id_str
                                ));
                                handle_noise_identity_announce(
                                    &packet,
                                    &mut peers_lock,
                                    noise_session_manager.as_mut().unwrap(),
                                    ui_tx.clone(),
                                )
                                .await;
                            }
                            MessageType::HandshakeRequest => {
                                write_debug_log("Processing HandshakeRequest packet");
                                handle_handshake_request_message(
                                    &packet,
                                    noise_session_manager.as_mut().unwrap(),
                                    peripheral.as_ref().unwrap(),
                                    cmd_char.as_ref().unwrap(),
                                    &my_peer_id,
                                    ui_tx.clone(),
                                )
                                .await;
                            }
                            MessageType::FileTransfer => {
                                write_debug_log("Processing FileTransfer packet");
                                handle_file_transfer_packet(
                                    &packet,
                                    &mut peers_lock,
                                    bloom.as_mut().unwrap(),
                                    &my_peer_id,
                                    ui_tx.clone(),
                                )
                                .await;
                            }
                            MessageType::RequestSync => {
                                write_debug_log("Ignoring RequestSync packet");
                            }
                            _ => {
                                write_debug_log(&format!(
                                    "Ignoring unknown packet type: {:?}",
                                    packet.msg_type
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        write_debug_log(&format!("Failed to parse packet: {}", e));
                    }
                }
            }
        }

        // 3. Handle input events
        if crossterm_event::poll(tick_rate.saturating_sub(last_tick.elapsed())).unwrap_or(false) {
            match crossterm_event::read().unwrap() {
                CrosstermEvent::Key(key_event) => {
                    event::handle_key_event(&mut app, key_event, &input_tx);
                }
                CrosstermEvent::Paste(pasted) => {
                    event::handle_paste_event(&mut app, &pasted);
                }
                CrosstermEvent::Mouse(mouse_event) => {
                    event::handle_mouse_event(&mut app, mouse_event);
                }
                _ => {}
            }
        }
        // 4. Handle pending channel switches
        if let Some(channel_name) = app.pending_channel_switch.take() {
            // Update backend chat_context to switch to the selected channel
            if channel_name == "#public" {
                chat_context.as_mut().unwrap().switch_to_public();
            } else {
                chat_context
                    .as_mut()
                    .unwrap()
                    .switch_to_channel(&channel_name);
            }
        }

        // 4.5. Handle pending DM switches
        if let Some((target_nickname, _)) = app.pending_dm_switch.take() {
            // Find the peer ID for the nickname and switch to DM mode
            let peer_id = {
                let peers = peers.as_ref().unwrap().lock().await;
                peers
                    .iter()
                    .find(|(_, peer)| peer.nickname.as_deref() == Some(&target_nickname))
                    .map(|(id, _)| id.clone())
            };

            if let Some(target_peer_id) = peer_id {
                chat_context
                    .as_mut()
                    .unwrap()
                    .enter_dm_mode(&target_nickname, &target_peer_id);
            }
        }

        // 4.6. Handle pending nickname updates
        if let Some(new_nickname) = app.pending_nickname_update.take() {
            // Update backend nickname
            nickname = new_nickname.clone();
            // Update app state if it exists
            if let Some(state) = app_state.as_mut() {
                state.nickname = Some(new_nickname.clone());
            }
            // Update TUI nickname immediately
            app.nickname = new_nickname.clone();

            // Announce the new nickname to other peers
            if let (Some(peripheral), Some(cmd_char), Some(encryption)) = (
                peripheral.as_ref(),
                cmd_char.as_ref(),
                encryption_service.as_ref(),
            ) {
                let announce_payload = create_announcement_payload(
                    &new_nickname,
                    &encryption.get_static_public_key_data(),
                    &encryption.get_signing_public_key_data(),
                )
                .unwrap_or_else(|| new_nickname.as_bytes().to_vec());
                let announce_timestamp = current_timestamp_ms();
                let announce_signature_payload = create_bitchat_packet_for_signing_at(
                    &my_peer_id,
                    None,
                    crate::data_structures::MessageType::Announce,
                    &announce_payload,
                    announce_timestamp,
                );
                let announce_signature = encryption.sign(&announce_signature_payload);
                let announce_packet = create_bitchat_packet_with_signature_at(
                    &my_peer_id,
                    crate::data_structures::MessageType::Announce,
                    announce_payload,
                    Some(announce_signature),
                    announce_timestamp,
                );
                let announce_write_type = if cfg!(target_os = "windows") {
                    btleplug::api::WriteType::WithResponse
                } else {
                    btleplug::api::WriteType::WithoutResponse
                };
                if peripheral
                    .write(cmd_char, &announce_packet, announce_write_type)
                    .await
                    .is_err()
                {
                    let error_msg = "Failed to announce new nickname";
                    app.add_log_message(format!("system: {}", error_msg));
                }
            }

            // Save the updated state
            if let (
                Some(chat_context),
                Some(blocked_peers),
                Some(channel_creators),
                Some(password_protected_channels),
                Some(channel_key_commitments),
                Some(app_state),
                Some(create_app_state),
                Some(favorites),
                Some(verified_labels),
            ) = (
                chat_context.as_ref(),
                blocked_peers.as_ref(),
                channel_creators.as_ref(),
                password_protected_channels.as_ref(),
                channel_key_commitments.as_ref(),
                app_state.as_ref(),
                create_app_state.as_ref(),
                favorites.as_ref(),
                verified_labels.as_ref(),
            ) {
                if let Err(e) = persist_runtime_state(
                    chat_context,
                    blocked_peers,
                    &app.blocked,
                    &app.nostr_aliases,
                    verified_labels,
                    favorites,
                    channel_creators,
                    password_protected_channels,
                    channel_key_commitments,
                    app_state,
                    create_app_state,
                    &new_nickname,
                ) {
                    let error_msg = format!("Warning: Could not save nickname: {}", e);
                    app.add_log_message(format!("system: {}", error_msg));
                }
            }

            // Send system message to confirm nickname change
            let system_msg = format!("Nickname changed to: {}", new_nickname);
            app.add_log_message(format!("system: {}", system_msg));
        }

        // 4.7. Handle pending conversation clear
        if app.pending_clear_conversation {
            app.pending_clear_conversation = false;
            app.clear_current_conversation();
            // Send confirmation message
            let context_msg = match &chat_context.as_ref().unwrap().current_mode {
                ChatMode::Public => "Cleared public chat".to_string(),
                ChatMode::Channel(channel) => format!("Cleared channel {}", channel),
                ChatMode::PrivateDM { nickname, .. } => format!("Cleared DM with {}", nickname),
            };
            app.add_log_message(format!("system: {}", context_msg));
        }

        // 4.7. Handle pending connection retry
        if app.pending_connection_retry {
            app.pending_connection_retry = false;

            // Reset only Bluetooth connection state; Nostr/UI chat state remains usable.
            peripheral = None;
            notification_stream = None;
            _characteristics = None;
            cmd_char = None;
            post_connect_initialized = false;
            noise_session_manager = None;

            if let Some(handle) = bt_handle.take() {
                handle.abort();
            }

            // Spawn new Bluetooth connection setup
            let ui_tx_clone = ui_tx.clone();
            bt_handle = Some(tokio::spawn(async move {
                match setup_bluetooth_connection(ui_tx_clone.clone()).await {
                    Ok(peripheral) => {
                        let _ = ui_tx_clone.send("__CONNECTED__".to_string()).await;
                        Ok(peripheral)
                    }
                    Err(e) => {
                        let _ = ui_tx_clone.send(format!("__ERROR__{}", e)).await;
                        Err(e)
                    }
                }
            }));
        }

        // 5. Handle input from the input box (from input_rx)
        while let Ok(raw_line) = input_rx.try_recv() {
            let ui_tx = ui_tx.clone();
            let mut line = canonicalize_command_alias(&raw_line);

            match parse_upload_path(&line) {
                Ok(Some(path)) => {
                    app.add_log_message(format!(
                        "system: Uploading {} ...",
                        crate::tui::app::compact_file_message(&path)
                    ));
                    let upload_path = std::path::Path::new(&path);
                    match upload_share::upload_file(upload_path, &nostr_identity_seed).await {
                        Ok(result) => {
                            app.add_log_message(format!(
                                "system: Uploaded {} ({} bytes)",
                                crate::tui::app::compact_file_message(&result.file_name),
                                result.file_size
                            ));
                            line = format!("{} {}", result.file_name, result.url);
                            let is_mesh_dm = app.current_geohash_dm().is_none()
                                && app
                                    .current_conv
                                    .as_ref()
                                    .and_then(|(dm, _)| dm.as_ref())
                                    .is_some();
                            if app.current_geohash_dm().is_none() && !is_mesh_dm {
                                app.add_sent_message(line.clone());
                            }
                        }
                        Err(e) => {
                            app.add_log_message(format!("system: Upload failed: {}", e));
                            continue;
                        }
                    }
                }
                Ok(None) => {}
                Err(usage) => {
                    app.add_log_message(format!("system: {}", usage));
                    continue;
                }
            }
            // Handle /exit immediately to avoid panics during connecting phase
            if line == "/exit" {
                if let (
                    Some(chat_context),
                    Some(blocked_peers),
                    Some(channel_creators),
                    Some(password_protected_channels),
                    Some(channel_key_commitments),
                    Some(app_state),
                    Some(create_app_state),
                    Some(favorites),
                    Some(verified_labels),
                ) = (
                    chat_context.as_ref(),
                    blocked_peers.as_ref(),
                    channel_creators.as_ref(),
                    password_protected_channels.as_ref(),
                    channel_key_commitments.as_ref(),
                    app_state.as_ref(),
                    create_app_state.as_ref(),
                    favorites.as_ref(),
                    verified_labels.as_ref(),
                ) {
                    if let Err(e) = persist_runtime_state(
                        chat_context,
                        blocked_peers,
                        &app.blocked,
                        &app.nostr_aliases,
                        verified_labels,
                        favorites,
                        channel_creators,
                        password_protected_channels,
                        channel_key_commitments,
                        app_state,
                        create_app_state,
                        &nickname,
                    ) {
                        app.add_log_message(format!(
                            "system: Warning: Could not save state: {}",
                            e
                        ));
                    }
                }
                app.should_quit = true;
                break 'mainloop;
            }
            if line == "/help" {
                let help_text = terminal_ux::get_help_text();
                let lines: Vec<&str> = help_text.split('\n').collect();
                for line in lines {
                    let formatted_line = line.trim_end();
                    if !formatted_line.trim().is_empty() {
                        app.add_log_message(format!("system: {}", formatted_line));
                    }
                }
                // `/help` is a local self command output; don't mark it as unseen/new messages.
                app.unseen_divider_message_index = None;
                app.unseen_divider_line_index = None;
                continue;
            }

            if let Some(args) = parse_verify_like_command(&line, "/verified") {
                if !args.is_empty() {
                    app.add_log_message("system: Usage: /verified".to_string());
                    continue;
                }
                let favorites_ref = favorites.as_ref().unwrap();
                let labels_ref = verified_labels.as_ref().unwrap();
                if favorites_ref.is_empty() {
                    app.add_log_message("system: No verified mesh identities yet.".to_string());
                    continue;
                }
                app.add_log_message(format!(
                    "system: Verified mesh identities: {}",
                    favorites_ref.len()
                ));
                for entry in format_verified_entries(favorites_ref, labels_ref) {
                    app.add_log_message(format!("system:   {}", entry));
                }
                continue;
            }

            if let Some(args) = parse_verify_like_command(&line, "/verify") {
                if args.is_empty() {
                    app.add_log_message(
                        "system: Usage: /verify <@user|fingerprint|prefix> [label]".to_string(),
                    );
                    continue;
                }
                let target_raw = args[0].trim().trim_start_matches('@');
                if target_raw.is_empty() {
                    app.add_log_message(
                        "system: Usage: /verify <@user|fingerprint|prefix> [label]".to_string(),
                    );
                    continue;
                }
                let label_override = if args.len() > 1 {
                    Some(args[1..].join(" ").trim().to_string())
                } else {
                    None
                }
                .filter(|value| !value.is_empty());

                let token = target_raw.to_ascii_lowercase();
                let mut resolved_fp: Option<String> = None;
                let mut resolved_label: Option<String> = None;
                let mut prefix_candidates: Vec<String> = Vec::new();

                if is_hex_fingerprint(&token) {
                    resolved_fp = Some(token.clone());
                } else if token.len() >= 6 && token.chars().all(|ch| ch.is_ascii_hexdigit()) {
                    for fp in favorites.as_ref().unwrap().iter() {
                        if fp.starts_with(&token) {
                            prefix_candidates.push(fp.clone());
                        }
                    }
                    let peers_guard = peers.as_ref().unwrap().lock().await;
                    for (peer_id, peer) in peers_guard.iter() {
                        if let Some(fp) = encryption_service
                            .as_ref()
                            .unwrap()
                            .get_peer_fingerprint(peer_id)
                        {
                            if fp.starts_with(&token) && !prefix_candidates.iter().any(|e| e == &fp)
                            {
                                prefix_candidates.push(fp);
                            }
                        }
                    }
                    if prefix_candidates.len() == 1 {
                        resolved_fp = prefix_candidates.first().cloned();
                    } else if prefix_candidates.len() > 1 {
                        app.add_log_message(format!(
                            "system: Fingerprint prefix '{}' matches {} entries; use a longer prefix or full fingerprint.",
                            token,
                            prefix_candidates.len()
                        ));
                        continue;
                    }
                }

                if resolved_fp.is_none() {
                    let peers_guard = peers.as_ref().unwrap().lock().await;
                    let mut matched: Vec<(String, String)> = peers_guard
                        .iter()
                        .filter_map(|(peer_id, peer)| {
                            let nick = peer.nickname.as_ref()?;
                            if !nick.eq_ignore_ascii_case(target_raw) {
                                return None;
                            }
                            let fp = encryption_service
                                .as_ref()
                                .unwrap()
                                .get_peer_fingerprint(peer_id)?;
                            Some((fp, nick.clone()))
                        })
                        .collect();
                    matched.sort_by(|a, b| a.0.cmp(&b.0));
                    matched.dedup_by(|a, b| a.0 == b.0);
                    if matched.len() == 1 {
                        resolved_fp = Some(matched[0].0.clone());
                        resolved_label = Some(matched[0].1.clone());
                    } else if matched.len() > 1 {
                        app.add_log_message(format!(
                            "system: User '{}' matched multiple peers; use fingerprint instead.",
                            target_raw
                        ));
                        continue;
                    }
                }

                let Some(fingerprint) = resolved_fp else {
                    app.add_log_message(format!(
                        "system: Could not resolve '{}'. Use /online then /verify @user, or /verify <fingerprint>.",
                        target_raw
                    ));
                    continue;
                };

                favorites
                    .as_mut()
                    .unwrap()
                    .insert(fingerprint.to_ascii_lowercase());
                let chosen_label = label_override.or(resolved_label);
                if let Some(label) = chosen_label {
                    verified_labels
                        .as_mut()
                        .unwrap()
                        .insert(fingerprint.clone(), label);
                }
                {
                    let mut favorites_guard = verified_fingerprints_state.lock().unwrap();
                    *favorites_guard = favorites.as_ref().unwrap().clone();
                }
                {
                    let mut labels_guard = verified_labels_state.lock().unwrap();
                    *labels_guard = verified_labels.as_ref().unwrap().clone();
                }

                if let Some(noise_manager) = noise_session_manager.as_mut() {
                    noise_manager.verify_fingerprint(&fingerprint);
                }

                if let Some(state) = app_state.as_mut() {
                    state.favorites = favorites.as_ref().unwrap().clone();
                    state.verified_labels = verified_labels.as_ref().unwrap().clone();
                    let _ = save_state(state);
                }

                app.update_verified_identities(format_verified_entries(
                    favorites.as_ref().unwrap(),
                    verified_labels.as_ref().unwrap(),
                ));

                if let Err(e) = persist_runtime_state(
                    chat_context.as_ref().unwrap(),
                    blocked_peers.as_ref().unwrap(),
                    &app.blocked,
                    &app.nostr_aliases,
                    verified_labels.as_ref().unwrap(),
                    favorites.as_ref().unwrap(),
                    channel_creators.as_ref().unwrap(),
                    password_protected_channels.as_ref().unwrap(),
                    channel_key_commitments.as_ref().unwrap(),
                    app_state.as_ref().unwrap(),
                    create_app_state.as_ref().unwrap(),
                    &nickname,
                ) {
                    app.add_log_message(format!("system: Warning: Could not save state: {}", e));
                }

                app.add_log_message(format!(
                    "system: Verified mesh identity {}.",
                    short_fingerprint(&fingerprint)
                ));
                continue;
            }

            match parse_verifylink_command(&line) {
                Ok(Some(link)) => {
                    const IOS_VERIFY_LINK_MAX_AGE_SECS: i64 = 300;
                    let payload =
                        match verify_bitchat_verify_link(&link, IOS_VERIFY_LINK_MAX_AGE_SECS) {
                            Ok(payload) => payload,
                            Err(err) => {
                                app.add_log_message(format!(
                                    "system: Invalid verify link: {}",
                                    err
                                ));
                                continue;
                            }
                        };

                    let fingerprint = match verification_link_noise_fingerprint(&payload.noise_key_hex)
                    {
                        Ok(fp) => fp,
                        Err(err) => {
                            app.add_log_message(format!(
                                "system: Invalid verify link: {}",
                                err
                            ));
                            continue;
                        }
                    };

                    let label = payload.nickname.trim().to_string();
                    favorites
                        .as_mut()
                        .unwrap()
                        .insert(fingerprint.to_ascii_lowercase());
                    if !label.is_empty() {
                        verified_labels
                            .as_mut()
                            .unwrap()
                            .insert(fingerprint.clone(), label.clone());
                    }

                    {
                        let mut favorites_guard = verified_fingerprints_state.lock().unwrap();
                        *favorites_guard = favorites.as_ref().unwrap().clone();
                    }
                    {
                        let mut labels_guard = verified_labels_state.lock().unwrap();
                        *labels_guard = verified_labels.as_ref().unwrap().clone();
                    }

                    if let Some(noise_manager) = noise_session_manager.as_mut() {
                        noise_manager.verify_fingerprint(&fingerprint);
                    }

                    if let Some(state) = app_state.as_mut() {
                        state.favorites = favorites.as_ref().unwrap().clone();
                        state.verified_labels = verified_labels.as_ref().unwrap().clone();
                        let _ = save_state(state);
                    }

                    app.update_verified_identities(format_verified_entries(
                        favorites.as_ref().unwrap(),
                        verified_labels.as_ref().unwrap(),
                    ));

                    if let Err(e) = persist_runtime_state(
                        chat_context.as_ref().unwrap(),
                        blocked_peers.as_ref().unwrap(),
                        &app.blocked,
                        &app.nostr_aliases,
                        verified_labels.as_ref().unwrap(),
                        favorites.as_ref().unwrap(),
                        channel_creators.as_ref().unwrap(),
                        password_protected_channels.as_ref().unwrap(),
                        channel_key_commitments.as_ref().unwrap(),
                        app_state.as_ref().unwrap(),
                        create_app_state.as_ref().unwrap(),
                        &nickname,
                    ) {
                        app.add_log_message(format!("system: Warning: Could not save state: {}", e));
                    }

                    let mut verified_msg = format!(
                        "system: Verified {} via /verifylink (fingerprint {}).",
                        if label.is_empty() {
                            "identity".to_string()
                        } else {
                            label.clone()
                        },
                        short_fingerprint(&fingerprint)
                    );
                    if let Some(npub) = payload.npub.as_deref() {
                        verified_msg.push_str(&format!(" npub={}.", npub));
                    }
                    app.add_log_message(verified_msg);
                    continue;
                }
                Ok(None) => {}
                Err("usage") => {
                    app.add_log_message("system: Usage: /verifylink <bitchat://verify?...>".to_string());
                    continue;
                }
                Err(_) => {}
            }

            if let Some(args) = parse_verify_like_command(&line, "/unverify") {
                if args.is_empty() {
                    app.add_log_message(
                        "system: Usage: /unverify <@user|fingerprint|prefix>".to_string(),
                    );
                    continue;
                }
                let token = args[0].trim().trim_start_matches('@').to_ascii_lowercase();
                let mut target_fp: Option<String> = None;

                if is_hex_fingerprint(&token) {
                    target_fp = Some(token.clone());
                } else if token.len() >= 6 && token.chars().all(|ch| ch.is_ascii_hexdigit()) {
                    let mut matches: Vec<String> = favorites
                        .as_ref()
                        .unwrap()
                        .iter()
                        .filter(|fp| fp.starts_with(&token))
                        .cloned()
                        .collect();
                    matches.sort();
                    matches.dedup();
                    if matches.len() == 1 {
                        target_fp = matches.first().cloned();
                    } else if matches.len() > 1 {
                        app.add_log_message(format!(
                            "system: Fingerprint prefix '{}' matches {} entries; use a longer prefix.",
                            token,
                            matches.len()
                        ));
                        continue;
                    }
                }

                if target_fp.is_none() {
                    let peers_guard = peers.as_ref().unwrap().lock().await;
                    let mut matches: Vec<String> = peers_guard
                        .iter()
                        .filter_map(|(peer_id, peer)| {
                            let nick = peer.nickname.as_ref()?;
                            if !nick.eq_ignore_ascii_case(&token) {
                                return None;
                            }
                            encryption_service
                                .as_ref()
                                .unwrap()
                                .get_peer_fingerprint(peer_id)
                        })
                        .collect();
                    matches.sort();
                    matches.dedup();
                    if matches.len() == 1 {
                        target_fp = matches.first().cloned();
                    }
                }

                let Some(fingerprint) = target_fp else {
                    app.add_log_message(format!(
                        "system: Could not resolve '{}'. Use /verified to list stored entries.",
                        token
                    ));
                    continue;
                };

                let removed = favorites.as_mut().unwrap().remove(&fingerprint);
                verified_labels.as_mut().unwrap().remove(&fingerprint);
                if !removed {
                    app.add_log_message(format!(
                        "system: Fingerprint {} is not in verified list.",
                        short_fingerprint(&fingerprint)
                    ));
                    continue;
                }
                {
                    let mut favorites_guard = verified_fingerprints_state.lock().unwrap();
                    *favorites_guard = favorites.as_ref().unwrap().clone();
                }
                {
                    let mut labels_guard = verified_labels_state.lock().unwrap();
                    *labels_guard = verified_labels.as_ref().unwrap().clone();
                }

                if let Some(noise_manager) = noise_session_manager.as_mut() {
                    noise_manager.load_verified_fingerprints(favorites.as_ref().unwrap().clone());
                }

                if let Some(state) = app_state.as_mut() {
                    state.favorites = favorites.as_ref().unwrap().clone();
                    state.verified_labels = verified_labels.as_ref().unwrap().clone();
                    let _ = save_state(state);
                }

                app.update_verified_identities(format_verified_entries(
                    favorites.as_ref().unwrap(),
                    verified_labels.as_ref().unwrap(),
                ));

                if let Err(e) = persist_runtime_state(
                    chat_context.as_ref().unwrap(),
                    blocked_peers.as_ref().unwrap(),
                    &app.blocked,
                    &app.nostr_aliases,
                    verified_labels.as_ref().unwrap(),
                    favorites.as_ref().unwrap(),
                    channel_creators.as_ref().unwrap(),
                    password_protected_channels.as_ref().unwrap(),
                    channel_key_commitments.as_ref().unwrap(),
                    app_state.as_ref().unwrap(),
                    create_app_state.as_ref().unwrap(),
                    &nickname,
                ) {
                    app.add_log_message(format!("system: Warning: Could not save state: {}", e));
                }

                app.add_log_message(format!(
                    "system: Removed verified mesh identity {}.",
                    short_fingerprint(&fingerprint)
                ));
                continue;
            }

            if let Some(mut channel_index) = parse_channel_shortcut(&line) {
                if app.channels.is_empty() {
                    app.add_log_message("system: No channels available yet.".to_string());
                    continue;
                }
                if channel_index >= app.channels.len() {
                    channel_index = app.channels.len().saturating_sub(1);
                }
                let target_channel = app.channels[channel_index].clone();
                chat_context
                    .as_mut()
                    .unwrap()
                    .switch_to_channel(&target_channel);
                app.switch_to_channel(target_channel.clone());

                if nostr_geo::is_geohash_channel(&target_channel) {
                    if let Err(e) = nostr_geo_client
                        .join_channel(&target_channel, &nickname)
                        .await
                    {
                        app.add_log_message(format!(
                            "system: Failed to join Nostr geohash channel {}: {}",
                            target_channel, e
                        ));
                    }
                }
                continue;
            }

            if line == "/g" || line.starts_with("/g ") {
                let target_channel = match parse_go_command_target(&line) {
                    Ok(Some(channel)) => channel,
                    Ok(None) => match find_latest_geohash_with_messages(&app) {
                        Some(channel) => channel,
                        None => {
                            app.add_log_message(
                                "system: No geohash channel has messages yet. Use /g <area> (e.g. /g ws)."
                                    .to_string(),
                            );
                            continue;
                        }
                    },
                    Err("usage") => {
                        app.add_log_message(
                            "system: Usage: /g <area>. Examples: /g ws, /g dh. Use /g with no args to jump to a geohash channel that already has messages."
                                .to_string(),
                        );
                        continue;
                    }
                    Err(_) => continue,
                };

                if !app.channels.contains(&target_channel) {
                    app.join_channel(target_channel.clone());
                    discovered_channels
                        .as_mut()
                        .unwrap()
                        .insert(target_channel.clone());
                }
                chat_context
                    .as_mut()
                    .unwrap()
                    .switch_to_channel(&target_channel);

                if let Err(e) = nostr_geo_client
                    .join_channel(&target_channel, &nickname)
                    .await
                {
                    app.add_log_message(format!(
                        "system: Failed to join Nostr geohash channel {}: {}",
                        target_channel, e
                    ));
                }
                app.switch_to_channel(target_channel.clone());

                if let Err(e) = persist_runtime_state(
                    chat_context.as_ref().unwrap(),
                    blocked_peers.as_ref().unwrap(),
                    &app.blocked,
                    &app.nostr_aliases,
                    verified_labels.as_ref().unwrap(),
                    favorites.as_ref().unwrap(),
                    channel_creators.as_ref().unwrap(),
                    password_protected_channels.as_ref().unwrap(),
                    channel_key_commitments.as_ref().unwrap(),
                    app_state.as_ref().unwrap(),
                    create_app_state.as_ref().unwrap(),
                    &nickname,
                ) {
                    app.add_log_message(format!("system: Warning: Could not save state: {}", e));
                }
                continue;
            }

            if line.starts_with("/j ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let mut channel_name = parts.get(1).unwrap_or(&"").to_string();
                if !channel_name.is_empty() && !channel_name.starts_with('#') {
                    channel_name = format!("#{}", channel_name);
                }

                if !channel_name.is_empty() {
                    let is_geohash_channel = nostr_geo::is_geohash_channel(&channel_name);
                    let has_password_arg = parts.len() > 2;

                    if is_geohash_channel && !has_password_arg {
                        app.join_channel(channel_name.clone());
                        app.add_log_message(format!(
                            "system: Joined geohash channel {} over Nostr",
                            channel_name
                        ));
                        chat_context
                            .as_mut()
                            .unwrap()
                            .switch_to_channel(&channel_name);
                        discovered_channels
                            .as_mut()
                            .unwrap()
                            .insert(channel_name.clone());
                        if let Err(e) = nostr_geo_client
                            .join_channel(&channel_name, &nickname)
                            .await
                        {
                            app.add_log_message(format!(
                                "system: Failed to join Nostr geohash channel {}: {}",
                                channel_name, e
                            ));
                        }
                        app.switch_to_channel(channel_name.clone());
                        if let Err(e) = persist_runtime_state(
                            chat_context.as_ref().unwrap(),
                            blocked_peers.as_ref().unwrap(),
                            &app.blocked,
                            &app.nostr_aliases,
                            verified_labels.as_ref().unwrap(),
                            favorites.as_ref().unwrap(),
                            channel_creators.as_ref().unwrap(),
                            password_protected_channels.as_ref().unwrap(),
                            channel_key_commitments.as_ref().unwrap(),
                            app_state.as_ref().unwrap(),
                            create_app_state.as_ref().unwrap(),
                            &nickname,
                        ) {
                            app.add_log_message(format!(
                                "system: Warning: Could not save state: {}",
                                e
                            ));
                        }
                        continue;
                    }

                    if !app.connected {
                        app.add_log_message(format!(
                            "system: Bluetooth mesh is offline, so channel {} is unavailable. Use a geohash channel such as /j #ws for Nostr.",
                            channel_name
                        ));
                        continue;
                    }

                    // Update TUI state
                    app.join_channel(channel_name.clone());

                    // Check if this is a password-protected channel
                    let is_password_protected = password_protected_channels
                        .as_ref()
                        .unwrap()
                        .contains(&channel_name);
                    let has_password = channel_keys.as_ref().unwrap().contains_key(&channel_name);

                    // Send appropriate system message to TUI
                    let system_msg = if is_geohash_channel && !has_password_arg {
                        format!("Joined geohash channel {} over Nostr", channel_name)
                    } else if is_password_protected && has_password {
                        format!("Joined password-protected channel {}", channel_name)
                    } else {
                        format!("Joined channel {}", channel_name)
                    };
                    app.add_log_message(format!("system: {}", system_msg));

                    // Handle backend join logic
                    if handle_join_command(
                        &line,
                        password_protected_channels.as_ref().unwrap(),
                        channel_keys.as_mut().unwrap(),
                        discovered_channels.as_mut().unwrap(),
                        chat_context.as_mut().unwrap(),
                        channel_key_commitments.as_mut().unwrap(),
                        app_state.as_mut().unwrap(),
                        create_app_state.as_ref().unwrap().as_ref(),
                        &nickname,
                        peripheral.as_ref().unwrap(),
                        cmd_char.as_ref().unwrap(),
                        channel_creators.as_ref().unwrap(),
                        blocked_peers.as_ref().unwrap(),
                        ui_tx.clone(),
                        &mut app,
                    )
                    .await
                    {
                        // Explicitly switch UI to the joined channel after successful join
                        app.switch_to_channel(channel_name.clone());
                        if let Err(e) = persist_runtime_state(
                            chat_context.as_ref().unwrap(),
                            blocked_peers.as_ref().unwrap(),
                            &app.blocked,
                            &app.nostr_aliases,
                            verified_labels.as_ref().unwrap(),
                            favorites.as_ref().unwrap(),
                            channel_creators.as_ref().unwrap(),
                            password_protected_channels.as_ref().unwrap(),
                            channel_key_commitments.as_ref().unwrap(),
                            app_state.as_ref().unwrap(),
                            create_app_state.as_ref().unwrap(),
                            &nickname,
                        ) {
                            app.add_log_message(format!(
                                "system: Warning: Could not save state: {}",
                                e
                            ));
                        }
                        continue;
                    }
                } else {
                    let _ = ui_tx
                        .send("\x1b[93m⚠ Usage: /j #<channel>\x1b[0m\n".to_string())
                        .await;
                    continue;
                }
            }

            if line == "/clear" {
                app.pending_clear_conversation = true;
                continue;
            }

            if line == "/status" {
                let peer_count = peers.as_ref().unwrap().lock().await.len();
                let channel_count = chat_context
                    .as_ref()
                    .unwrap()
                    .active_channels
                    .iter()
                    .filter(|channel| !nostr_geo::is_geohash_channel(channel))
                    .count();
                let geohash_count = app
                    .channels
                    .iter()
                    .filter(|channel| nostr_geo::is_geohash_channel(channel))
                    .count();
                let dm_count = chat_context.as_ref().unwrap().active_dms.len();

                let status_lines = vec![
                    "━━━ Connection Status ━━━".to_string(),
                    "▶ Mesh".to_string(),
                    format!("  Status: {}", app.mesh_status),
                    format!("  Connected peers: {}", peer_count),
                    format!("  Active mesh channels: {}", channel_count),
                    "▶ Nostr".to_string(),
                    format!("  Geohash channels this session: {}", geohash_count),
                    "▶ Your Info".to_string(),
                    format!("  Active DMs: {}", dm_count),
                    format!("  Nickname: {}", nickname),
                    format!("  ID: {}", my_peer_id),
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string(),
                ];

                for line in status_lines {
                    app.add_log_message(format!("system: {}", line));
                }
                continue;
            }

            if line == "/search" {
                app.add_log_message("system: Usage: /search <keyword>".to_string());
                continue;
            }
            if let Some(query) = search_query_from_line(&line) {
                let (messages, dm_target, channel_name) = app.get_current_messages();
                let query_lower = query.to_ascii_lowercase();
                let mut hit_count = 0usize;
                let mut preview_count = 0usize;
                let mut previews: Vec<String> = Vec::new();
                let conv_name = if let Some(dm) = dm_target {
                    format!("DM {}", app.display_dm_target(&dm))
                } else if let Some(ch) = channel_name {
                    format!("channel {}", ch)
                } else {
                    "current conversation".to_string()
                };

                for msg in messages.iter() {
                    if !msg.content.to_ascii_lowercase().contains(&query_lower)
                        && !msg.sender.to_ascii_lowercase().contains(&query_lower)
                    {
                        continue;
                    }
                    hit_count += 1;
                    if preview_count < 20 {
                        preview_count += 1;
                        previews.push(format!(
                            "[{}] {}: {}",
                            msg.timestamp,
                            msg.sender,
                            truncate_for_export(&msg.content, 120)
                        ));
                    }
                }

                if hit_count == 0 {
                    app.add_log_message(format!(
                        "system: No matches for '{}' in {}.",
                        query, conv_name
                    ));
                } else {
                    app.add_log_message(format!(
                        "system: Found {} match(es) for '{}' in {}{}.",
                        hit_count,
                        query,
                        conv_name,
                        if hit_count > preview_count {
                            " (showing first 20)"
                        } else {
                            ""
                        }
                    ));
                    for line in previews {
                        app.add_log_message(format!("system: {}", line));
                    }
                }
                continue;
            }

            if line == "/export" || line.starts_with("/export ") {
                if let Some(path) = export_path_from_line(&line) {
                    let (messages, dm_target, channel_name) = app.get_current_messages();
                    let conv_name = if let Some(dm) = dm_target {
                        format!("DM {}", app.display_dm_target(&dm))
                    } else if let Some(ch) = channel_name {
                        format!("channel {}", ch)
                    } else {
                        "current conversation".to_string()
                    };
                    let mut content = String::new();
                    content.push_str("# BitChat Export\n");
                    content.push_str(&format!(
                        "Generated: {}\n",
                        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
                    ));
                    content.push_str(&format!("Conversation: {}\n\n", conv_name));
                    for msg in messages.iter() {
                        content.push_str(&format!(
                            "[{}] {}: {}\n",
                            msg.timestamp, msg.sender, msg.content
                        ));
                    }
                    if let Some(parent) = path.parent() {
                        if !parent.as_os_str().is_empty() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                    }
                    match std::fs::write(&path, content) {
                        Ok(_) => {
                            app.add_log_message(format!(
                                "system: Exported {} message(s) to {}",
                                messages.len(),
                                path.display()
                            ));
                        }
                        Err(e) => {
                            app.add_log_message(format!("system: Export failed: {}", e));
                        }
                    }
                    continue;
                }
            }

            if line == "/r" || line == "/retry" {
                app.trigger_connection_retry();
                app.add_log_message("system: Restarting Bluetooth mesh scan...".to_string());
                continue;
            }

            if line == "/leave" {
                let selected_channel = app
                    .current_geohash_dm()
                    .map(|(channel, _, _)| channel)
                    .unwrap_or_else(|| app.get_selected_channel_name());
                if nostr_geo::is_geohash_channel(&selected_channel) {
                    if let Err(e) = nostr_geo_client.leave_channel(&selected_channel).await {
                        app.add_log_message(format!(
                            "system: Failed to leave Nostr geohash channel {}: {}",
                            selected_channel, e
                        ));
                    } else {
                        if let Some(chat_context) = chat_context.as_mut() {
                            chat_context.remove_channel(&selected_channel);
                            chat_context.switch_to_public();
                        }
                        app.leave_geohash_channel(&selected_channel);
                        app.add_log_message(format!(
                            "system: Left geohash channel {}",
                            selected_channel
                        ));
                        if let Err(e) = persist_runtime_state(
                            chat_context.as_ref().unwrap(),
                            blocked_peers.as_ref().unwrap(),
                            &app.blocked,
                            &app.nostr_aliases,
                            verified_labels.as_ref().unwrap(),
                            favorites.as_ref().unwrap(),
                            channel_creators.as_ref().unwrap(),
                            password_protected_channels.as_ref().unwrap(),
                            channel_key_commitments.as_ref().unwrap(),
                            app_state.as_ref().unwrap(),
                            create_app_state.as_ref().unwrap(),
                            &nickname,
                        ) {
                            app.add_log_message(format!(
                                "system: Warning: Could not save state: {}",
                                e
                            ));
                        }
                    }
                    continue;
                }
            }

            let nickname_before = nickname.clone();
            if handle_name_command(
                &line,
                &mut nickname,
                &mut app,
                blocked_peers.as_ref().unwrap(),
                channel_creators.as_ref().unwrap(),
                chat_context.as_mut().unwrap(),
                password_protected_channels.as_ref().unwrap(),
                channel_key_commitments.as_ref().unwrap(),
                app_state.as_ref().unwrap(),
                create_app_state.as_ref().unwrap().as_ref(),
                ui_tx.clone(),
            )
            .await
            {
                if nickname != nickname_before {
                    app.pending_nickname_update = Some(nickname.clone());
                }
                continue;
            }

            if line == "/public" {
                chat_context.as_mut().unwrap().switch_to_public();
                app.switch_to_public();
                continue;
            }

            if is_pass_command(&line) {
                app.add_log_message(
                    "system: /pass has been removed. Use normal mesh channels or Nostr geohash channels without this command."
                        .to_string(),
                );
                continue;
            }

            if let Some(geohash_channel) = app.current_geohash_context_channel() {
                if line == "/online" || line == "/w" {
                    let active_count = app.geohash_active_count(&geohash_channel);
                    let mut people: Vec<String> = app
                        .geohash_people_with_pubkeys(&geohash_channel)
                        .into_iter()
                        .map(|(name, pubkey)| {
                            if let Some(pubkey) = pubkey {
                                format!("{} ({})", name, App::short_pubkey(&pubkey))
                            } else {
                                name
                            }
                        })
                        .collect();
                    people.sort();
                    if people.is_empty() {
                        app.add_log_message(format!(
                            "system: {} active in {}; no named people seen yet.",
                            active_count, geohash_channel
                        ));
                    } else {
                        app.add_log_message(format!(
                            "system: {} active in {}; people seen: {}",
                            active_count,
                            geohash_channel,
                            people.join(", ")
                        ));
                    }
                    continue;
                }

                if line == "/channels" {
                    let mut mesh_channels: Vec<String> = chat_context
                        .as_ref()
                        .unwrap()
                        .active_channels
                        .iter()
                        .filter(|channel| !nostr_geo::is_geohash_channel(channel))
                        .cloned()
                        .collect();
                    let mut geohash_channels: Vec<String> = app
                        .channels
                        .iter()
                        .filter(|channel| nostr_geo::is_geohash_channel(channel))
                        .cloned()
                        .collect();
                    mesh_channels.sort();
                    geohash_channels.sort();
                    let mesh_text = if mesh_channels.is_empty() {
                        "none".to_string()
                    } else {
                        mesh_channels.join(", ")
                    };
                    let geohash_text = if geohash_channels.is_empty() {
                        "none".to_string()
                    } else {
                        geohash_channels.join(", ")
                    };
                    app.add_log_message(format!("system: Mesh channels: {}", mesh_text));
                    app.add_log_message(format!("system: Geohash channels: {}", geohash_text));
                    continue;
                }

                if line.starts_with("/dm") {
                    let Some((target_nickname, maybe_message)) = parse_dm_command(&line) else {
                        app.add_log_message("system: Usage: /dm <name> [message]".to_string());
                        continue;
                    };

                    let (target_label, recipient_pubkey) = match resolve_geohash_dm_target(
                        &app,
                        &geohash_channel,
                        &target_nickname,
                    ) {
                        Ok(target) => target,
                        Err(GeohashDmTargetError::UnknownPubkey) => {
                            app.add_log_message(format!(
                                    "system: Pubkey '{}' has not been seen in {}. Geohash DMs use per-channel Nostr keys; send to a name from /w, or to a full key that is already in People.",
                                    target_nickname, geohash_channel
                                ));
                            continue;
                        }
                        Err(GeohashDmTargetError::UnknownName) => {
                            app.add_log_message(format!(
                                "system: User '{}' has not been seen in {} with a Nostr key yet.",
                                target_nickname, geohash_channel
                            ));
                            continue;
                        }
                    };

                    app.add_geohash_person(
                        &geohash_channel,
                        &target_label,
                        Some(&recipient_pubkey),
                    );
                    app.switch_to_geohash_dm(target_label.clone());

                    if let Some(message) = maybe_message {
                        queue_geohash_dm_send(
                            &mut app,
                            nostr_geo_client.clone(),
                            ui_tx.clone(),
                            geohash_channel.clone(),
                            target_label,
                            recipient_pubkey,
                            message,
                            my_peer_id.clone(),
                            nickname.clone(),
                        );
                    }
                    continue;
                }

                if let Some(maybe_message) = parse_reply_command(&line) {
                    if let Some((_, target_label, recipient_pubkey)) = app.current_geohash_dm() {
                        app.switch_to_geohash_dm(target_label.clone());
                        if let Some(message) = maybe_message {
                            queue_geohash_dm_send(
                                &mut app,
                                nostr_geo_client.clone(),
                                ui_tx.clone(),
                                geohash_channel.clone(),
                                target_label,
                                recipient_pubkey,
                                message,
                                my_peer_id.clone(),
                                nickname.clone(),
                            );
                        }
                        continue;
                    }

                    if let Some(message) = maybe_message {
                        let reply_message = if message.trim_start().starts_with('@') {
                            message
                        } else if let Some(target) =
                            app.last_geohash_mention_sender(&geohash_channel)
                        {
                            format!("@{} {}", target, message)
                        } else {
                            message
                        };
                        app.add_sent_message(reply_message.clone());
                        let nostr_geo_client = nostr_geo_client.clone();
                        let ui_tx = ui_tx.clone();
                        let channel = geohash_channel.clone();
                        let nickname = nickname.clone();
                        tokio::spawn(async move {
                            if let Err(e) = nostr_geo_client
                                .send_message(&channel, &reply_message, &nickname)
                                .await
                            {
                                let _ = ui_tx
                                    .send(format!(
                                        "system: Failed to send geohash message on {}: {}",
                                        channel, e
                                    ))
                                    .await;
                            }
                        });
                    } else {
                        app.add_log_message(
                            "system: In geohash public chat, /reply does not switch to DM. Use /dm <name> [message] for direct messages."
                                .to_string(),
                        );
                    }
                    continue;
                }

                if let Some(command) = mesh_only_command_in_geohash(&line) {
                    app.add_log_message(format!(
                        "system: {} is only available on the Bluetooth mesh. It is not supported in Nostr geohash channels.",
                        command
                    ));
                    continue;
                }

                match parse_geohash_file_offer(&line) {
                    Ok(Some(offer)) => {
                        let (target_label, recipient_pubkey) = if let Some(target_nickname) =
                            offer.target_nickname
                        {
                            match resolve_geohash_dm_target(&app, &geohash_channel, target_nickname)
                            {
                                Ok(target) => target,
                                Err(GeohashDmTargetError::UnknownPubkey) => {
                                    app.add_log_message(format!(
                                                "system: Pubkey '{}' has not been seen in {}. Geohash file offers must target a name from /w, or a full key that is already in People.",
                                                target_nickname, geohash_channel
                                            ));
                                    continue;
                                }
                                Err(GeohashDmTargetError::UnknownName) => {
                                    app.add_log_message(format!(
                                            "system: User '{}' has not been seen in {} with a Nostr key yet.",
                                            target_nickname, geohash_channel
                                        ));
                                    continue;
                                }
                            }
                        } else if let Some((_, target_nickname, recipient_pubkey)) =
                            app.current_geohash_dm()
                        {
                            (target_nickname, recipient_pubkey)
                        } else {
                            app.add_log_message(format!(
                                    "system: Usage in {}: /file @user <path>. In a geohash DM, use /file <path>.",
                                    geohash_channel
                                ));
                            continue;
                        };

                        let file_path = std::path::Path::new(offer.path);
                        let metadata = match tokio::fs::metadata(file_path).await {
                            Ok(metadata) => metadata,
                            Err(e) => {
                                app.add_log_message(format!(
                                    "system: Cannot read file '{}': {}",
                                    offer.path, e
                                ));
                                continue;
                            }
                        };

                        if !metadata.is_file() {
                            app.add_log_message(format!(
                                "system: '{}' is not a regular file",
                                offer.path
                            ));
                            continue;
                        }

                        let file_size = metadata.len();
                        let file_name = file_path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or(offer.path)
                            .to_string();
                        let transfer = match wormhole_transfer::prepare_send(
                            file_path,
                            file_name.clone(),
                            file_size,
                        )
                        .await
                        {
                            Ok(transfer) => transfer,
                            Err(e) => {
                                app.add_log_message(format!("system: {}", e));
                                continue;
                            }
                        };

                        let offer_msg = geohash_file_offer_message(
                            &transfer.code,
                            &transfer.file_name,
                            transfer.file_size,
                        );
                        queue_geohash_dm_send_with_display(
                            &mut app,
                            nostr_geo_client.clone(),
                            ui_tx.clone(),
                            geohash_channel.clone(),
                            target_label.clone(),
                            recipient_pubkey.clone(),
                            offer_msg,
                            Some(crate::tui::app::compact_file_message(&file_name)),
                            my_peer_id.clone(),
                            nickname.clone(),
                        );

                        let transfer_ui_tx = ui_tx.clone();
                        let code_for_log = transfer.code.clone();
                        let sent_file_name = file_name.clone();
                        tokio::spawn(async move {
                            if let Err(e) = wormhole_transfer::send_file(transfer).await {
                                let _ = transfer_ui_tx
                                    .send(format!(
                                        "system: File transfer failed: {}",
                                        sanitize_status_field(&e.to_string())
                                    ))
                                    .await;
                            } else if crate::tui::app::bitchat_debug_enabled() {
                                let _ = ui_tx
                                    .send(format!(
                                        "system: Wormhole send complete: {} ({})",
                                        sent_file_name, code_for_log
                                    ))
                                    .await;
                            }
                        });
                        continue;
                    }
                    Ok(None) => {}
                    Err(usage) => {
                        if line.starts_with("/file") {
                            app.add_log_message(format!("system: {}", usage));
                            continue;
                        }
                    }
                }
            }

            if parse_receive_command(&line).is_some() {
                if let Some((channel, _target_nickname, recipient_pubkey)) =
                    app.current_geohash_dm()
                {
                    let conversation_key = App::geohash_dm_pubkey_key(&channel, &recipient_pubkey);
                    let Some(offer) = app.take_pending_wormhole_offer(&conversation_key) else {
                        app.add_log_message(
                            "system: No pending file offer in this conversation.".to_string(),
                        );
                        continue;
                    };
                    app.add_log_message(format!(
                        "system: Receiving {}",
                        crate::tui::app::compact_file_message(&offer.file_name)
                    ));
                    let receive_ui_tx = ui_tx.clone();
                    let code_for_log = offer.code.clone();
                    let receive_file_name = offer.file_name.clone();
                    tokio::spawn(async move {
                        match wormhole_transfer::receive_file(&offer.code).await {
                            Ok(path) => {
                                let _ = receive_ui_tx
                                    .send(format!(
                                        "system: Saved {} to {}",
                                        receive_file_name,
                                        path.display()
                                    ))
                                    .await;
                            }
                            Err(e) => {
                                let _ = receive_ui_tx
                                    .send(format!(
                                        "system: Receive failed ({}): {}",
                                        code_for_log,
                                        sanitize_status_field(&e.to_string())
                                    ))
                                    .await;
                            }
                        }
                    });
                    continue;
                } else {
                    app.add_log_message(
                        "system: /receive is only available in geohash DMs.".to_string(),
                    );
                    continue;
                }
            }

            if !app.connected && !line.starts_with('/') {
                if let Some((channel, target_nickname, recipient_pubkey)) = app.current_geohash_dm()
                {
                    queue_geohash_dm_send(
                        &mut app,
                        nostr_geo_client.clone(),
                        ui_tx.clone(),
                        channel,
                        target_nickname,
                        recipient_pubkey,
                        line.clone(),
                        my_peer_id.clone(),
                        nickname.clone(),
                    );
                    continue;
                }

                let current_ui_channel = if app.sidebar_state.people_selected.is_some()
                    && !app.current_people_are_geohash()
                {
                    None
                } else {
                    Some(app.get_selected_channel_name())
                };

                if let Some(channel) = current_ui_channel {
                    if nostr_geo::is_geohash_channel(&channel)
                        && !password_protected_channels
                            .as_ref()
                            .unwrap()
                            .contains(&channel)
                    {
                        chat_context.as_mut().unwrap().switch_to_channel(&channel);
                        let nostr_geo_client = nostr_geo_client.clone();
                        let ui_tx = ui_tx.clone();
                        let channel = channel.clone();
                        let message = line.clone();
                        let nickname = nickname.clone();
                        tokio::spawn(async move {
                            if let Err(e) = nostr_geo_client
                                .send_message(&channel, &message, &nickname)
                                .await
                            {
                                let _ = ui_tx
                                    .send(format!(
                                        "system: Failed to send geohash message on {}: {}",
                                        channel, e
                                    ))
                                    .await;
                            }
                        });
                        continue;
                    }
                }

                app.add_log_message("system: Bluetooth mesh is offline. Join a Nostr geohash channel such as /j #ws, or wait for mesh discovery to finish.".to_string());
                continue;
            }

            // Check if we're connected before handling commands that require connection
            if !app.connected
                && !line.starts_with("/help")
                && !line.starts_with("/j ")
                && line != "/public"
                && !line.starts_with("/block")
                && !line.starts_with("/unblock")
            {
                app.add_log_message("system: Bluetooth mesh is still offline. Nostr geohash channels are available with /j #ws.".to_string());
                continue;
            }

            if handle_exit_command(
                &line,
                blocked_peers.as_ref().unwrap(),
                channel_creators.as_ref().unwrap(),
                chat_context.as_ref().unwrap(),
                password_protected_channels.as_ref().unwrap(),
                channel_key_commitments.as_ref().unwrap(),
                app_state.as_ref().unwrap(),
                create_app_state.as_ref().unwrap().as_ref(),
                &nickname,
                ui_tx.clone(),
                &mut app,
            )
            .await
            {
                break;
            }
            if handle_reply_command(&line, chat_context.as_mut().unwrap(), ui_tx.clone()).await {
                // Update TUI to reflect DM mode if we entered DM mode
                if let ChatMode::PrivateDM {
                    nickname: target_nickname,
                    ..
                } = &chat_context.as_ref().unwrap().current_mode
                {
                    app.switch_to_dm(target_nickname.clone());
                }
                continue;
            }
            if handle_public_command(&line, chat_context.as_mut().unwrap(), ui_tx.clone()).await {
                // Update TUI to reflect public chat mode
                app.switch_to_public();
                continue;
            }
            if handle_online_command(&line, peers.as_ref().unwrap(), ui_tx.clone()).await {
                continue;
            }
            if handle_channels_command(
                &line,
                chat_context.as_ref().unwrap(),
                channel_keys.as_ref().unwrap(),
                password_protected_channels.as_ref().unwrap(),
                ui_tx.clone(),
            )
            .await
            {
                continue;
            }
            if handle_block_command(
                &line,
                blocked_peers.as_mut().unwrap(),
                peers.as_ref().unwrap(),
                encryption_service.as_ref().unwrap(),
                channel_creators.as_ref().unwrap(),
                chat_context.as_mut().unwrap(),
                password_protected_channels.as_ref().unwrap(),
                channel_key_commitments.as_ref().unwrap(),
                app_state.as_ref().unwrap(),
                create_app_state.as_ref().unwrap().as_ref(),
                &nickname,
                ui_tx.clone(),
                &mut app,
            )
            .await
            {
                continue;
            }
            if handle_unblock_command(
                &line,
                blocked_peers.as_mut().unwrap(),
                peers.as_ref().unwrap(),
                encryption_service.as_ref().unwrap(),
                channel_creators.as_ref().unwrap(),
                chat_context.as_mut().unwrap(),
                password_protected_channels.as_ref().unwrap(),
                channel_key_commitments.as_ref().unwrap(),
                app_state.as_ref().unwrap(),
                create_app_state.as_ref().unwrap().as_ref(),
                &nickname,
                ui_tx.clone(),
                &mut app,
            )
            .await
            {
                continue;
            }
            if handle_dm_command(
                &line,
                chat_context.as_mut().unwrap(),
                peers.as_ref().unwrap(),
                &nickname,
                &my_peer_id,
                delivery_tracker.as_mut().unwrap(),
                encryption_service.as_ref().unwrap(),
                peripheral.as_ref().unwrap(),
                cmd_char.as_ref().unwrap(),
                ui_tx.clone(),
                &mut app,
                noise_session_manager.as_mut().unwrap(),
            )
            .await
            {
                // Update TUI to reflect DM mode if we entered DM mode
                if let ChatMode::PrivateDM {
                    nickname: target_nickname,
                    ..
                } = &chat_context.as_ref().unwrap().current_mode
                {
                    app.switch_to_dm(target_nickname.clone());
                }
                continue;
            }
            if handle_file_command(
                &line,
                chat_context.as_ref().unwrap(),
                peers.as_ref().unwrap(),
                password_protected_channels.as_ref().unwrap(),
                encryption_service.as_ref().unwrap(),
                &my_peer_id,
                peripheral.as_ref().unwrap(),
                cmd_char.as_ref().unwrap(),
                ui_tx.clone(),
                &mut app,
            )
            .await
            {
                continue;
            }
            if handle_clear_command(&line, chat_context.as_mut().unwrap(), ui_tx.clone()).await {
                app.pending_clear_conversation = true;
                continue;
            }
            if line == "/status" {
                let peer_count = peers.as_ref().unwrap().lock().await.len();
                let channel_count = chat_context.as_ref().unwrap().active_channels.len();
                let dm_count = chat_context.as_ref().unwrap().active_dms.len();

                let status_lines = vec![
                    "━━━ Connection Status ━━━".to_string(),
                    "▶ Network".to_string(),
                    format!("  Connected peers: {}", peer_count),
                    format!("  Active channels: {}", channel_count),
                    format!("  Active DMs: {}", dm_count),
                    "▶ Your Info".to_string(),
                    format!("  Nickname: {}", nickname),
                    format!("  ID: {}", my_peer_id),
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string(),
                ];

                for line in status_lines {
                    app.add_log_message(format!("system: {}", line));
                }
                continue;
            }
            if handle_leave_command(
                &line,
                chat_context.as_mut().unwrap(),
                channel_keys.as_mut().unwrap(),
                app_state.as_mut().unwrap(),
                &my_peer_id,
                peripheral.as_ref().unwrap(),
                cmd_char.as_ref().unwrap(),
                ui_tx.clone(),
                &mut app,
            )
            .await
            {
                // Update TUI to reflect public chat mode (since leaving a channel switches to public)
                app.switch_to_public();
                if let Err(e) = persist_runtime_state(
                    chat_context.as_ref().unwrap(),
                    blocked_peers.as_ref().unwrap(),
                    &app.blocked,
                    &app.nostr_aliases,
                    verified_labels.as_ref().unwrap(),
                    favorites.as_ref().unwrap(),
                    channel_creators.as_ref().unwrap(),
                    password_protected_channels.as_ref().unwrap(),
                    channel_key_commitments.as_ref().unwrap(),
                    app_state.as_ref().unwrap(),
                    create_app_state.as_ref().unwrap(),
                    &nickname,
                ) {
                    app.add_log_message(format!("system: Warning: Could not save state: {}", e));
                }
                continue;
            }
            if handle_fingerprint_command(
                &line,
                encryption_service.as_ref().unwrap(),
                ui_tx.clone(),
            )
            .await
            {
                continue;
            }
            if line.starts_with("/") {
                let unknown_cmd = line.split_whitespace().next().unwrap_or("");
                let unknown_cmd_msg = format!("⚠  Unknown command: {}", unknown_cmd);
                app.add_log_message(format!("system: {}", unknown_cmd_msg));
                app.add_log_message("system: Type /help to see available commands.".to_string());
                continue;
            }

            if let Some((channel, target_nickname, recipient_pubkey)) = app.current_geohash_dm() {
                let outgoing_chunks = split_outgoing_message_chunks(&line);
                let chunk_total = outgoing_chunks.len();
                for (idx, chunk) in outgoing_chunks.into_iter().enumerate() {
                    queue_geohash_dm_send(
                        &mut app,
                        nostr_geo_client.clone(),
                        ui_tx.clone(),
                        channel.clone(),
                        target_nickname.clone(),
                        recipient_pubkey.clone(),
                        chunk,
                        my_peer_id.clone(),
                        nickname.clone(),
                    );
                    if chunk_total > 1 && idx + 1 < chunk_total {
                        time::sleep(Duration::from_millis(40)).await;
                    }
                }
                continue;
            }

            let current_ui_channel = if app.sidebar_state.people_selected.is_some()
                && !app.current_people_are_geohash()
            {
                None
            } else {
                Some(app.get_selected_channel_name())
            };

            if let Some(channel) = current_ui_channel {
                if nostr_geo::is_geohash_channel(&channel)
                    && !password_protected_channels
                        .as_ref()
                        .unwrap()
                        .contains(&channel)
                {
                    chat_context.as_mut().unwrap().switch_to_channel(&channel);
                    let nostr_geo_client = nostr_geo_client.clone();
                    let ui_tx = ui_tx.clone();
                    let channel = channel.clone();
                    let messages = split_outgoing_message_chunks(&line);
                    let nickname = nickname.clone();
                    tokio::spawn(async move {
                        let chunk_total = messages.len();
                        for (idx, message) in messages.into_iter().enumerate() {
                            if let Err(e) = nostr_geo_client
                                .send_message(&channel, &message, &nickname)
                                .await
                            {
                                let _ = ui_tx
                                    .send(format!(
                                        "system: Failed to send geohash message on {}: {}",
                                        channel, e
                                    ))
                                    .await;
                            }
                            if chunk_total > 1 && idx + 1 < chunk_total {
                                time::sleep(Duration::from_millis(40)).await;
                            }
                        }
                    });
                    continue;
                }
            }

            if let ChatMode::Channel(channel) = &chat_context.as_ref().unwrap().current_mode {
                if nostr_geo::is_geohash_channel(channel)
                    && !password_protected_channels
                        .as_ref()
                        .unwrap()
                        .contains(channel)
                {
                    let nostr_geo_client = nostr_geo_client.clone();
                    let ui_tx = ui_tx.clone();
                    let channel = channel.clone();
                    let messages = split_outgoing_message_chunks(&line);
                    let nickname = nickname.clone();
                    tokio::spawn(async move {
                        let chunk_total = messages.len();
                        for (idx, message) in messages.into_iter().enumerate() {
                            if let Err(e) = nostr_geo_client
                                .send_message(&channel, &message, &nickname)
                                .await
                            {
                                let _ = ui_tx
                                    .send(format!(
                                        "system: Failed to send geohash message on {}: {}",
                                        channel, e
                                    ))
                                    .await;
                            }
                            if chunk_total > 1 && idx + 1 < chunk_total {
                                time::sleep(Duration::from_millis(40)).await;
                            }
                        }
                    });
                    continue;
                }
            }

            // Check if we're connected before handling Bluetooth mesh messages
            if !app.connected {
                app.add_log_message("system: Bluetooth mesh is offline. Join a Nostr geohash channel such as /j #ws, or wait for mesh discovery to finish.".to_string());
                continue;
            }

            if let ChatMode::PrivateDM {
                nickname: target_nickname,
                peer_id: target_peer_id,
            } = &chat_context.as_ref().unwrap().current_mode
            {
                match handle_private_dm_message(
                    &line,
                    target_peer_id,
                    &mut noise_session_manager,
                    peripheral.as_ref().unwrap(),
                    cmd_char.as_ref().unwrap(),
                    &my_peer_id,
                    ui_tx.clone(),
                )
                .await
                {
                    Ok(Some(message_id)) => {
                        app.add_pending_mesh_dm_message(
                            target_nickname.clone(),
                            line.clone(),
                            message_id,
                        );
                    }
                    Ok(None) => {
                        app.add_dm_message(target_nickname.clone(), line.clone());
                    }
                    Err(e) => {
                        app.add_log_message(format!("system: Failed to send DM: {}", e));
                    }
                }
                continue;
            }
            let outgoing_chunks = split_outgoing_message_chunks(&line);

            let chunk_total = outgoing_chunks.len();
            for (idx, chunk) in outgoing_chunks.into_iter().enumerate() {
                handle_regular_message(
                    &chunk,
                    &nickname,
                    &my_peer_id,
                    chat_context.as_ref().unwrap(),
                    password_protected_channels.as_ref().unwrap(),
                    channel_keys.as_mut().unwrap(),
                    encryption_service.as_ref().unwrap(),
                    delivery_tracker.as_mut().unwrap(),
                    peripheral.as_ref().unwrap(),
                    cmd_char.as_ref().unwrap(),
                    ui_tx.clone(),
                    &mut app,
                )
                .await;

                if chunk_total > 1 && idx + 1 < chunk_total {
                    time::sleep(Duration::from_millis(40)).await;
                }
            }
        }
        // 6. Render the UI
        app.prune_expired_transient_messages();
        sync_terminal_title(&mut last_terminal_title, &app);
        terminal.draw(|f| ui::render(&mut app, f)).unwrap();
        // 7. Exit if requested
        if app.should_quit {
            break 'mainloop;
        }
        last_tick = std::time::Instant::now();
    }

    let _ = execute!(std::io::stdout(), SetTitle("bitchat-tui"));

    // Always persist state on shutdown so state.json mtime reflects the latest exit.
    if let (
        Some(chat_context),
        Some(blocked_peers),
        Some(channel_creators),
        Some(password_protected_channels),
        Some(channel_key_commitments),
        Some(app_state),
        Some(create_app_state),
        Some(favorites),
        Some(verified_labels),
    ) = (
        chat_context.as_ref(),
        blocked_peers.as_ref(),
        channel_creators.as_ref(),
        password_protected_channels.as_ref(),
        channel_key_commitments.as_ref(),
        app_state.as_ref(),
        create_app_state.as_ref(),
        favorites.as_ref(),
        verified_labels.as_ref(),
    ) {
        let _ = persist_runtime_state(
            chat_context,
            blocked_peers,
            &app.blocked,
            &app.nostr_aliases,
            verified_labels,
            favorites,
            channel_creators,
            password_protected_channels,
            channel_key_commitments,
            app_state,
            create_app_state,
            &nickname,
        );
    }

    // Restore the terminal
    tui_mod::restore().expect("Failed to restore terminal");
    Ok(())
}

async fn find_peripheral(
    adapter: &btleplug::platform::Adapter,
) -> Result<Option<Peripheral>, btleplug::Error> {
    for p in adapter.peripherals().await? {
        if let Ok(Some(properties)) = p.properties().await {
            if properties.services.contains(&BITCHAT_SERVICE_UUID) {
                return Ok(Some(p));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_values() {
        assert_eq!(MessageType::Announce as u8, 0x01);
        assert_eq!(MessageType::Message as u8, 0x02);
        assert_eq!(MessageType::Leave as u8, 0x03);
        assert_eq!(MessageType::NoiseHandshakeInit as u8, 0x10);
        assert_eq!(MessageType::NoiseEncrypted as u8, 0x11);
        assert_eq!(MessageType::FragmentStart as u8, 0x05);
    }

    #[test]
    fn test_protocol_constants() {
        assert_eq!(crate::data_structures::FLAG_HAS_RECIPIENT, 0x01);
        assert_eq!(crate::data_structures::FLAG_HAS_SIGNATURE, 0x02);
        assert_eq!(crate::data_structures::FLAG_IS_COMPRESSED, 0x04);
        assert_eq!(crate::data_structures::SIGNATURE_SIZE, 64);
        assert_eq!(crate::data_structures::BROADCAST_RECIPIENT, [0xFF; 8]);
    }

    #[test]
    fn parses_dm_command_for_geohash_handling() {
        assert_eq!(
            parse_dm_command("/dm anon7301 hello there"),
            Some(("anon7301".to_string(), Some("hello there".to_string())))
        );
        assert_eq!(
            parse_dm_command("/dm @anon7301"),
            Some(("anon7301".to_string(), None))
        );
        assert_eq!(
            parse_dm_command("/dm   npub1abc\twith tabs"),
            Some(("npub1abc".to_string(), Some("with tabs".to_string())))
        );
        assert_eq!(
            parse_dm_command("/dm @alice#ffe6 hey"),
            Some(("alice#ffe6".to_string(), Some("hey".to_string())))
        );
        assert_eq!(parse_dm_command("/dm"), None);
    }

    #[test]
    fn parses_go_command_target() {
        assert_eq!(parse_go_command_target("/g"), Ok(None));
        assert_eq!(
            parse_go_command_target("/g ws"),
            Ok(Some("#ws".to_string()))
        );
        assert_eq!(
            parse_go_command_target("/g #dh"),
            Ok(Some("#dh".to_string()))
        );
        assert_eq!(parse_go_command_target("/g   bad!"), Err("usage"));
    }

    #[test]
    fn picks_latest_geohash_with_messages() {
        let mut app = App::new_with_nickname("me".to_string());
        app.join_channel("#ws".to_string());
        app.join_channel("#dh".to_string());

        app.add_log_message("__CHANNEL__:#ws:alice:1200:first".to_string());
        app.add_log_message("__CHANNEL__:#dh:bob:1201:second".to_string());

        assert_eq!(
            find_latest_geohash_with_messages(&app),
            Some("#dh".to_string())
        );
    }

    #[test]
    fn detects_mesh_only_commands_inside_geohash() {
        assert_eq!(
            mesh_only_command_in_geohash("/file @alice ./photo.png"),
            None
        );
        assert_eq!(mesh_only_command_in_geohash("/block @alice"), None);
        assert_eq!(mesh_only_command_in_geohash("/online"), None);
    }

    #[test]
    fn geohash_dm_pubkey_targets_must_be_seen_in_channel() {
        let mut app = App::new_with_nickname("me".to_string());
        let known_pubkey = "4ccaa3888b3b303d28bd9ae6aa2278530232b404abccffa83d9aa815ed2ca4e2";
        let unknown_pubkey = "f5688e82b33eae5112cd6ec58eca77da3091974f84579129e0d13141e4403c9e";

        app.join_channel("#ws".to_string());
        app.add_log_message(format!("__GEO_PERSON__:#ws:alice:{}", known_pubkey));

        assert_eq!(
            resolve_geohash_dm_target(&app, "#ws", "alice").ok(),
            Some(("alice".to_string(), known_pubkey.to_string()))
        );
        assert_eq!(
            resolve_geohash_dm_target(&app, "#ws", known_pubkey).ok(),
            Some(("alice".to_string(), known_pubkey.to_string()))
        );
        assert!(matches!(
            resolve_geohash_dm_target(&app, "#ws", unknown_pubkey),
            Err(GeohashDmTargetError::UnknownPubkey)
        ));
    }

    #[test]
    fn geohash_dm_alias_can_resolve_offline_user_from_saved_aliases() {
        let mut app = App::new_with_nickname("me".to_string());
        let offline_pubkey = "f5688e82b33eae5112cd6ec58eca77da3091974f84579129e0d13141e4403c9e";
        app.join_channel("#ws".to_string());
        app.nostr_aliases
            .insert(offline_pubkey.to_string(), "xiaojie".to_string());

        assert_eq!(
            resolve_geohash_dm_target(&app, "#ws", "xiaojie").ok(),
            Some(("xiaojie".to_string(), offline_pubkey.to_string()))
        );
    }

    #[test]
    fn parses_receive_command_without_arguments() {
        assert_eq!(parse_receive_command("/receive"), Some(""));
        assert_eq!(parse_receive_command("/receive   "), Some(""));
        assert_eq!(
            parse_receive_command("/receive wormhole-code"),
            Some("wormhole-code")
        );
    }

    #[test]
    fn parses_upload_path_with_optional_quotes() {
        assert_eq!(
            parse_upload_path("/upload ./test.png"),
            Ok(Some("./test.png".to_string()))
        );
        assert_eq!(
            parse_upload_path("/upload \"./folder/my pic.png\""),
            Ok(Some("./folder/my pic.png".to_string()))
        );
        assert_eq!(parse_upload_path("/upload"), Err("Usage: /upload <path>"));
        assert_eq!(parse_upload_path("/upload-now"), Ok(None));
    }

    #[test]
    fn parses_verifylink_command_and_usage() {
        assert_eq!(
            parse_verifylink_command("/verifylink bitchat://verify?v=1"),
            Ok(Some("bitchat://verify?v=1".to_string()))
        );
        assert_eq!(parse_verifylink_command("/verifylink"), Err("usage"));
        assert_eq!(parse_verifylink_command("/verifylink-now"), Ok(None));
    }

    #[test]
    fn verifies_ios_style_verify_link_signature() {
        use ed25519_dalek::Signer;

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let sign_pub_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let noise_hex = "11".repeat(32);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let payload = VerificationLinkPayload {
            version: 1,
            noise_key_hex: noise_hex.clone(),
            sign_key_hex: sign_pub_hex.clone(),
            npub: Some("npub1example".to_string()),
            nickname: "alice".to_string(),
            ts,
            nonce_b64: "abcd1234".to_string(),
        };
        let canonical = build_verification_qr_canonical_bytes(&payload);
        let sig = signing_key.sign(&canonical);
        let sig_hex = hex::encode(sig.to_bytes());

        let link = format!(
            "bitchat://verify?v=1&noise={}&sign={}&nick=alice&ts={}&nonce=abcd1234&sig={}&npub=npub1example",
            noise_hex, sign_pub_hex, ts, sig_hex
        );
        let verified = verify_bitchat_verify_link(&link, 300).expect("verify link should pass");
        assert_eq!(verified.nickname, "alice");
        assert_eq!(verified.noise_key_hex, noise_hex);
    }
}
