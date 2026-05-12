use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use bech32::{FromBase32, Variant};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key as XChaChaKey, XChaCha20Poly1305, XNonce};
use chrono::{Local, TimeZone};
use futures_util::future::join_all;
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use hmac::{Hmac, Mac as HmacMac};
use rand::{Rng, RngCore};
use secp256k1::{
    Keypair, Message as SecpMessage, PublicKey as SecpPublicKey, Scalar, Secp256k1, SecretKey,
    XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use std::time::{Duration as StdDuration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::handshake::client::Response as WsResponse;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{
    client_async_tls_with_config, connect_async, MaybeTlsStream, WebSocketStream,
};
use uuid::Uuid;

const GEO_RELAY_CSV_URL: &str =
    "https://raw.githubusercontent.com/permissionlesstech/georelays/main/nostr_relays.csv";
const GEOHASH_ALPHABET: &str = "0123456789bcdefghjkmnpqrstuvwxyz";
const SUBSCRIBE_SINCE_SECONDS: i64 = 300;
const DM_SUBSCRIBE_MAX_SECONDS: i64 = 15 * 60;
const DM_SUBSCRIBE_FALLBACK_SECONDS: i64 = 10 * 60;
const RECONNECT_DELAY_SECONDS: u64 = 10;
const CONNECT_TIMEOUT_SECONDS: u64 = 8;
const PUBLISH_TIMEOUT_SECONDS: u64 = 8;
pub const PRESENCE_ACTIVE_WINDOW_SECONDS: i64 = 300;
const GEOHASH_CHAT_KIND: i64 = 20000;
const GEOHASH_PRESENCE_KIND: i64 = 20001;
const GEOHASH_DM_KIND: i64 = 1059;
const PRESENCE_HEARTBEAT_MIN_SECONDS: u64 = 40;
const PRESENCE_HEARTBEAT_MAX_SECONDS: u64 = 80;
const NIP44_MIN_PLAINTEXT_SIZE: usize = 1;
const NIP44_MAX_PLAINTEXT_SIZE: usize = 65_535;
const EMBEDDED_PRIVATE_PAYLOAD_UNSUPPORTED_TYPE: &str =
    "Embedded private payload has unsupported type";
const GEOHASH_DM_STATUS_DELIVERED: &str = "delivered";
const GEOHASH_DM_STATUS_READ: &str = "read";

const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://offchain.pub",
    "wss://nostr21.com",
];

const PROFILE_METADATA_RELAYS: &[&str] = &[
    "wss://purplepag.es",
    "wss://relay.nostr.band",
    "wss://relay.primal.net",
];

const EMBEDDED_WS_RELAYS: &[&str] = &[
    "wss://nostr-relay.zeabur.app",
    "wss://relay.henryxplace.eu.org:9988",
    "wss://nostr.ps1829.com",
    "wss://relay.mulatta.io",
    "wss://ms.chinacounty.com",
    "wss://relay.notoshi.win",
    "wss://relay.ru.ac.th",
    "wss://relay02.lnfi.network",
    "wss://relay01.lnfi.network",
    "wss://yabu.me",
    "wss://relay.homeinhk.xyz",
    "wss://nostr.middling.mydns.jp",
    "wss://relay-arg.zombi.cloudrodion.com",
    "wss://nostr-01.yakihonne.com",
    "wss://relay.islandbitcoin.com",
];

const EMBEDDED_GEO_RELAYS: &[(&str, f64, f64)] = &[
    ("nostr-relay.zeabur.app", 22.3193, 114.1694),
    ("relay.henryxplace.eu.org:9988", 22.3193, 114.1694),
    ("nostr.ps1829.com", 22.3193, 114.1694),
    ("relay.mulatta.io", 22.3193, 114.1694),
    ("ms.chinacounty.com", 22.3193, 114.1694),
    ("relay.homeinhk.xyz", 22.3193, 114.1694),
    ("nostr-01.yakihonne.com", 22.3193, 114.1694),
    ("relay02.lnfi.network", 1.3521, 103.8198),
    ("relay01.lnfi.network", 1.3521, 103.8198),
    ("relay.notoshi.win", 13.7563, 100.5018),
    ("relay.ru.ac.th", 13.7563, 100.5018),
    ("yabu.me", 35.6762, 139.6503),
    ("nostr.middling.mydns.jp", 35.6762, 139.6503),
    ("relay.islandbitcoin.com", 35.6762, 139.6503),
    ("relay-arg.zombi.cloudrodion.com", -34.6037, -58.3816),
];

#[derive(Clone)]
pub struct NostrGeoClient {
    inner: Arc<NostrGeoInner>,
}

struct NostrGeoInner {
    ui_tx: mpsc::Sender<String>,
    identity_seed: Vec<u8>,
    seen_event_ids: Mutex<HashSet<String>>,
    joined_geohashes: Mutex<HashSet<String>>,
    relays_by_geohash: Mutex<HashMap<String, Vec<String>>>,
    people_by_pubkey: Mutex<HashMap<String, String>>,
    metadata_lookup_pubkeys: Mutex<HashSet<String>>,
    publish_lock: Mutex<()>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NostrEvent {
    id: String,
    pubkey: String,
    created_at: i64,
    kind: i64,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Nip17Event {
    id: String,
    pubkey: String,
    created_at: i64,
    kind: i64,
    tags: Vec<Vec<String>>,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sig: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NostrProfileMetadata {
    display_name: Option<String>,
    name: Option<String>,
    username: Option<String>,
    nip05: Option<String>,
}

#[derive(Clone)]
struct RelayEntry {
    host: String,
    lat: f64,
    lon: f64,
}

pub fn is_geohash_channel(channel: &str) -> bool {
    normalize_geohash(channel).is_some()
}

pub fn geohash_broadcasts_presence(channel: &str) -> bool {
    normalize_geohash(channel)
        .map(|geohash| matches!(geohash.len(), 2 | 4 | 5))
        .unwrap_or(false)
}

pub fn normalize_geohash(channel: &str) -> Option<String> {
    let geohash = channel.trim().trim_start_matches('#').to_ascii_lowercase();
    if !matches!(geohash.len(), 2 | 4 | 5 | 6 | 7 | 8) {
        return None;
    }
    if geohash.chars().all(|ch| GEOHASH_ALPHABET.contains(ch)) {
        Some(geohash)
    } else {
        None
    }
}

impl NostrGeoClient {
    pub fn new(ui_tx: mpsc::Sender<String>, identity_seed: Vec<u8>) -> Self {
        Self {
            inner: Arc::new(NostrGeoInner {
                ui_tx,
                identity_seed,
                seen_event_ids: Mutex::new(HashSet::new()),
                joined_geohashes: Mutex::new(HashSet::new()),
                relays_by_geohash: Mutex::new(HashMap::new()),
                people_by_pubkey: Mutex::new(HashMap::new()),
                metadata_lookup_pubkeys: Mutex::new(HashSet::new()),
                publish_lock: Mutex::new(()),
            }),
        }
    }

    pub async fn join_channel(&self, channel: &str, nickname: &str) -> Result<(), String> {
        let geohash =
            normalize_geohash(channel).ok_or_else(|| "Invalid geohash channel".to_string())?;

        let mut joined = self.inner.joined_geohashes.lock().await;
        if joined.contains(&geohash) {
            return Ok(());
        }
        joined.insert(geohash.clone());
        drop(joined);

        let relays = resolve_relays(&geohash).await;
        let dm_relays = dm_relays();
        let subscribe_relays = merge_relays(&relays, &dm_relays);
        write_nostr_debug_log(&format!(
            "joined geohash #{} public_relays={} dm_relays={}",
            geohash,
            relays.join(","),
            dm_relays.join(",")
        ));
        self.inner
            .relays_by_geohash
            .lock()
            .await
            .insert(geohash.clone(), relays.clone());

        let local_secret = derive_secret_key(&self.inner.identity_seed, &geohash)?;
        let pubkey = xonly_pubkey_from_secret(&local_secret);
        write_nostr_debug_log(&format!(
            "geohash identity: geohash=#{}, local_pubkey={}",
            geohash,
            &pubkey[..pubkey.len().min(8)]
        ));
        for relay in subscribe_relays {
            let inner = self.inner.clone();
            let channel = format!("#{}", geohash);
            let geohash = geohash.clone();
            let pubkey = pubkey.clone();
            let local_secret = local_secret.clone();
            tokio::spawn(async move {
                subscribe_loop(inner, relay, channel, geohash, pubkey, local_secret).await;
            });
        }

        if geohash_broadcasts_presence(&geohash) {
            let inner = self.inner.clone();
            let geohash = geohash.clone();
            tokio::spawn(async move {
                presence_heartbeat_loop(inner, geohash).await;
            });
        }

        let _ = self
            .inner
            .ui_tx
            .send(format!(
                "system: Joined geohash channel #{} over Nostr ({} relays) as {}\n",
                geohash,
                relays.len(),
                sanitize_display_field(nickname)
            ))
            .await;
        Ok(())
    }

    pub async fn send_message(
        &self,
        channel: &str,
        content: &str,
        nickname: &str,
    ) -> Result<(), String> {
        let geohash =
            normalize_geohash(channel).ok_or_else(|| "Invalid geohash channel".to_string())?;
        self.join_channel(channel, nickname).await?;

        let event = create_geohash_event(&self.inner.identity_seed, &geohash, content, nickname)?;
        let event_id = event.id.clone();
        let event_pubkey = event.pubkey.clone();
        let event_created_at = event.created_at;
        self.inner
            .seen_event_ids
            .lock()
            .await
            .insert(event_id.clone());

        let relays = self
            .inner
            .relays_by_geohash
            .lock()
            .await
            .get(&geohash)
            .cloned()
            .unwrap_or_else(default_relays);

        let _publish_guard = self.inner.publish_lock.lock().await;
        let publish_results = join_all(relays.into_iter().map(|relay| {
            let event = event.clone();
            async move {
                let result = publish_event(&relay, &event).await;
                (relay, result)
            }
        }))
        .await;

        let mut sent_count = 0usize;
        let total_count = publish_results.len();
        let mut accepted_relays = Vec::new();
        for (relay, result) in publish_results {
            match result {
                Ok(()) => {
                    sent_count += 1;
                    accepted_relays.push(relay);
                }
                Err(e) => write_nostr_debug_log(&format!(
                    "publish failed: relay={}, event={}, error={}",
                    relay, event_id, e
                )),
            }
        }
        write_nostr_debug_log(&format!(
            "publish result: geohash=#{}, event={}, sent={}, total={}, accepted={}",
            geohash,
            event_id,
            sent_count,
            total_count,
            accepted_relays.join(",")
        ));

        if sent_count == 0 {
            Err("Failed to publish geohash message to any Nostr relay".to_string())
        } else {
            send_presence_update(
                &self.inner,
                &format!("#{}", geohash),
                &event_pubkey,
                event_created_at,
            )
            .await;
            Ok(())
        }
    }

    pub async fn send_private_message(
        &self,
        channel: &str,
        recipient_pubkey: &str,
        content: &str,
        sender_peer_id: &str,
        sender_nickname: &str,
        message_id: &str,
    ) -> Result<(), String> {
        let geohash =
            normalize_geohash(channel).ok_or_else(|| "Invalid geohash channel".to_string())?;
        if !is_valid_xonly_pubkey(recipient_pubkey) {
            return Err("Invalid geohash DM recipient pubkey".to_string());
        }

        let event = create_private_message_event(
            &self.inner.identity_seed,
            &geohash,
            recipient_pubkey,
            content,
            sender_peer_id,
            sender_nickname,
            message_id,
        )?;
        self.publish_private_event(&geohash, recipient_pubkey, event)
            .await
    }

    async fn publish_private_event(
        &self,
        geohash: &str,
        recipient_pubkey: &str,
        event: NostrEvent,
    ) -> Result<(), String> {
        let event_id = event.id.clone();
        let sender_pubkey = derive_secret_key(&self.inner.identity_seed, geohash)
            .map(|secret| xonly_pubkey_from_secret(&secret))
            .unwrap_or_else(|_| event.pubkey.clone());

        let public_relays = self
            .inner
            .relays_by_geohash
            .lock()
            .await
            .get(geohash)
            .cloned()
            .unwrap_or_else(default_relays);
        let dm_relays = dm_relays();
        let dm_relay_set: HashSet<String> = dm_relays.iter().cloned().collect();
        let relays = merge_relays(&public_relays, &dm_relays);

        let _publish_guard = self.inner.publish_lock.lock().await;
        write_nostr_debug_log(&format!(
            "dm publish start: geohash=#{}, sender={}, recipient={}, event={}, public_relays={}, dm_relays={}, relays={}",
            geohash,
            short_log_pubkey(&sender_pubkey),
            short_log_pubkey(recipient_pubkey),
            event_id,
            public_relays.len(),
            dm_relays.len(),
            relays.join(",")
        ));

        let publish_results = join_all(relays.into_iter().map(|relay| {
            let event = event.clone();
            async move {
                let result = publish_event(&relay, &event).await;
                (relay, result)
            }
        }))
        .await;

        let mut sent_count = 0usize;
        let mut dm_sent_count = 0usize;
        let total_count = publish_results.len();
        let mut accepted_relays = Vec::new();
        for (relay, result) in publish_results {
            match result {
                Ok(()) => {
                    sent_count += 1;
                    if dm_relay_set.contains(&relay) {
                        dm_sent_count += 1;
                    }
                    accepted_relays.push(relay);
                }
                Err(e) => write_nostr_debug_log(&format!(
                    "dm publish failed: relay={}, event={}, error={}",
                    relay, event_id, e
                )),
            }
        }
        write_nostr_debug_log(&format!(
            "dm publish result: geohash=#{}, event={}, sent={}, dm_sent={}, total={}, accepted={}",
            geohash,
            event_id,
            sent_count,
            dm_sent_count,
            total_count,
            accepted_relays.join(",")
        ));

        if dm_sent_count == 0 {
            Err(
                "Failed to publish geohash DM to any default DM relay; iOS only listens on those relays"
                    .to_string(),
            )
        } else if sent_count == 0 {
            Err("Failed to publish geohash DM to any Nostr relay".to_string())
        } else {
            Ok(())
        }
    }

    pub async fn leave_channel(&self, channel: &str) -> Result<(), String> {
        let geohash =
            normalize_geohash(channel).ok_or_else(|| "Invalid geohash channel".to_string())?;
        self.inner.joined_geohashes.lock().await.remove(&geohash);
        self.inner.relays_by_geohash.lock().await.remove(&geohash);
        write_nostr_debug_log(&format!("left geohash #{}", geohash));
        Ok(())
    }
}

async fn subscribe_loop(
    inner: Arc<NostrGeoInner>,
    relay: String,
    channel: String,
    geohash: String,
    local_pubkey: String,
    local_secret: SecretKey,
) {
    loop {
        if !is_joined(&inner, &geohash).await {
            break;
        }
        if let Err(e) = subscribe_once(
            inner.clone(),
            &relay,
            &channel,
            &geohash,
            &local_pubkey,
            &local_secret,
        )
        .await
        {
            write_nostr_debug_log(&format!(
                "subscribe error: relay={}, geohash={}, error={}",
                relay, geohash, e
            ));
        }
        if !is_joined(&inner, &geohash).await {
            break;
        }
        tokio::time::sleep(Duration::from_secs(RECONNECT_DELAY_SECONDS)).await;
    }
}

async fn is_joined(inner: &Arc<NostrGeoInner>, geohash: &str) -> bool {
    inner.joined_geohashes.lock().await.contains(geohash)
}

async fn presence_heartbeat_loop(inner: Arc<NostrGeoInner>, geohash: String) {
    loop {
        if !is_joined(&inner, &geohash).await {
            break;
        }

        if let Err(e) = broadcast_geohash_presence(&inner, &geohash).await {
            write_nostr_debug_log(&format!(
                "presence publish failed: geohash=#{}, error={}",
                geohash, e
            ));
        }

        let delay = random_presence_heartbeat_delay();
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }
}

async fn broadcast_geohash_presence(
    inner: &Arc<NostrGeoInner>,
    geohash: &str,
) -> Result<(), String> {
    let event = create_geohash_presence_event(&inner.identity_seed, geohash)?;
    let event_id = event.id.clone();
    let event_pubkey = event.pubkey.clone();
    let event_created_at = event.created_at;
    inner.seen_event_ids.lock().await.insert(event_id.clone());

    let relays = inner
        .relays_by_geohash
        .lock()
        .await
        .get(geohash)
        .cloned()
        .unwrap_or_else(default_relays);

    let _publish_guard = inner.publish_lock.lock().await;
    let publish_results = join_all(relays.into_iter().map(|relay| {
        let event = event.clone();
        async move {
            let result = publish_event(&relay, &event).await;
            (relay, result)
        }
    }))
    .await;

    let mut sent_count = 0usize;
    let total_count = publish_results.len();
    let mut accepted_relays = Vec::new();
    for (relay, result) in publish_results {
        match result {
            Ok(()) => {
                sent_count += 1;
                accepted_relays.push(relay);
            }
            Err(e) => write_nostr_debug_log(&format!(
                "presence publish failed: relay={}, event={}, error={}",
                relay, event_id, e
            )),
        }
    }
    write_nostr_debug_log(&format!(
        "presence publish result: geohash=#{}, event={}, sent={}, total={}, accepted={}",
        geohash,
        event_id,
        sent_count,
        total_count,
        accepted_relays.join(",")
    ));

    if sent_count == 0 {
        Err("Failed to publish geohash presence to any Nostr relay".to_string())
    } else {
        send_presence_update(
            inner,
            &format!("#{}", geohash),
            &event_pubkey,
            event_created_at,
        )
        .await;
        Ok(())
    }
}

fn random_presence_heartbeat_delay() -> u64 {
    rand::thread_rng().gen_range(PRESENCE_HEARTBEAT_MIN_SECONDS..=PRESENCE_HEARTBEAT_MAX_SECONDS)
}

async fn subscribe_once(
    inner: Arc<NostrGeoInner>,
    relay: &str,
    channel: &str,
    geohash: &str,
    local_pubkey: &str,
    local_secret: &SecretKey,
) -> Result<(), String> {
    let (ws_stream, _) = timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECONDS),
        connect_relay(relay),
    )
    .await
    .map_err(|_| format!("connect timeout after {}s", CONNECT_TIMEOUT_SECONDS))??;
    let (mut write, mut read) = ws_stream.split();
    let sub_id = format!("bitchat-tui-{}-{}", geohash, Uuid::new_v4());
    let now = Local::now().timestamp();
    let public_since = now.saturating_sub(SUBSCRIBE_SINCE_SECONDS);
    let dm_since = now.saturating_sub(compute_dm_subscribe_window_seconds());
    let req = json!([
        "REQ",
        sub_id,
        {
            "kinds": [GEOHASH_CHAT_KIND, GEOHASH_PRESENCE_KIND],
            "#g": [geohash],
            "since": public_since
        },
        {
            "kinds": [GEOHASH_DM_KIND],
            "#p": [local_pubkey],
            "since": dm_since,
            "limit": 100
        }
    ]);

    write
        .send(WsMessage::Text(req.to_string()))
        .await
        .map_err(|e| e.to_string())?;
    write_nostr_debug_log(&format!(
        "subscribe connected: relay={}, geohash=#{}, local_pubkey={}, public_since={}, dm_since={}",
        relay,
        geohash,
        short_log_pubkey(local_pubkey),
        public_since,
        dm_since
    ));

    loop {
        if !is_joined(&inner, geohash).await {
            break;
        }
        let message = match timeout(Duration::from_secs(2), read.next()).await {
            Ok(Some(message)) => message.map_err(|e| e.to_string())?,
            Ok(None) => break,
            Err(_) => continue,
        };
        if let WsMessage::Text(text) = message {
            handle_relay_text(&inner, channel, geohash, local_pubkey, local_secret, &text).await;
        }
    }

    Ok(())
}

fn compute_dm_subscribe_window_seconds() -> i64 {
    let path = crate::persistence::get_state_file_path();
    let Ok(metadata) = std::fs::metadata(path) else {
        return DM_SUBSCRIBE_FALLBACK_SECONDS;
    };
    let Ok(modified) = metadata.modified() else {
        return DM_SUBSCRIBE_FALLBACK_SECONDS;
    };
    let now = SystemTime::now();
    let elapsed = now
        .duration_since(modified)
        .unwrap_or_else(|_| StdDuration::from_secs(DM_SUBSCRIBE_FALLBACK_SECONDS as u64))
        .as_secs() as i64;
    elapsed.clamp(1, DM_SUBSCRIBE_MAX_SECONDS)
}

async fn handle_relay_text(
    inner: &Arc<NostrGeoInner>,
    channel: &str,
    geohash: &str,
    local_pubkey: &str,
    local_secret: &SecretKey,
    text: &str,
) {
    let parsed: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => return,
    };
    let arr = match parsed.as_array() {
        Some(arr) if arr.len() >= 3 => arr,
        _ => return,
    };
    if arr.first().and_then(Value::as_str) != Some("EVENT") {
        return;
    }

    let event: NostrEvent = match serde_json::from_value(arr[2].clone()) {
        Ok(event) => event,
        Err(_) => return,
    };
    if event.kind == GEOHASH_DM_KIND {
        handle_private_relay_event(inner, channel, local_pubkey, local_secret, &event).await;
        return;
    }

    if !matches!(event.kind, GEOHASH_CHAT_KIND | GEOHASH_PRESENCE_KIND)
        || event.pubkey == local_pubkey
        || !event_has_geohash(&event, geohash)
    {
        return;
    }

    let mut seen = inner.seen_event_ids.lock().await;
    if !seen.insert(event.id.clone()) {
        return;
    }
    drop(seen);

    if event.kind == GEOHASH_PRESENCE_KIND {
        if event.content.is_empty() {
            send_presence_update(inner, channel, &event.pubkey, event.created_at).await;
            write_nostr_debug_log(&format!(
                "received presence: geohash=#{}, sender={}, event={}",
                geohash,
                &event.pubkey[..event.pubkey.len().min(8)],
                event.id
            ));
        }
        return;
    }

    let tagged_sender = event
        .tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some("n") && tag.len() >= 2)
        .and_then(|tag| tag.get(1))
        .map(|nick| sanitize_display_field(nick));
    let sender = if let Some(name) = tagged_sender
        .as_ref()
        .filter(|name| !is_pubkey_placeholder_name(name))
    {
        name.clone()
    } else if let Some(name) = known_person_name(inner, &event.pubkey).await {
        name
    } else {
        tagged_sender
            .unwrap_or_else(|| format!("npub{}", event.pubkey.chars().take(8).collect::<String>()))
    };

    update_known_person(inner, channel, &event.pubkey, &sender).await;
    if is_pubkey_placeholder_name(&sender) {
        schedule_metadata_lookup(inner.clone(), channel.to_string(), event.pubkey.clone()).await;
    }

    let timestamp = Local
        .timestamp_opt(event.created_at, 0)
        .single()
        .unwrap_or_else(Local::now);
    let structured = format!(
        "__CHANNEL__:{}:{}:{}:{}:{}",
        channel,
        sender,
        event.pubkey,
        timestamp.format("%H%M"),
        event.content
    );
    write_nostr_debug_log(&format!(
        "received event: geohash=#{}, sender={}, pubkey={}, event={}",
        geohash,
        sender,
        short_log_pubkey(&event.pubkey),
        event.id
    ));
    send_presence_update(inner, channel, &event.pubkey, event.created_at).await;
    let _ = inner.ui_tx.send(structured).await;
}

async fn send_presence_update(
    inner: &Arc<NostrGeoInner>,
    channel: &str,
    pubkey: &str,
    timestamp: i64,
) {
    let _ = inner
        .ui_tx
        .send(format!(
            "__GEO_PRESENCE__:{}:{}:{}",
            channel, pubkey, timestamp
        ))
        .await;
}

async fn known_person_name(inner: &Arc<NostrGeoInner>, pubkey: &str) -> Option<String> {
    inner.people_by_pubkey.lock().await.get(pubkey).cloned()
}

fn is_pubkey_placeholder_name(name: &str) -> bool {
    name.starts_with("npub") || looks_like_dm_pubkey(name)
}

async fn update_known_person(inner: &Arc<NostrGeoInner>, channel: &str, pubkey: &str, name: &str) {
    let name = sanitize_display_field(name);
    if !is_pubkey_placeholder_name(&name) {
        inner
            .people_by_pubkey
            .lock()
            .await
            .insert(pubkey.to_string(), name.clone());
    }

    let _ = inner
        .ui_tx
        .send(format!("__GEO_PERSON__:{}:{}:{}", channel, name, pubkey))
        .await;
}

async fn schedule_metadata_lookup(inner: Arc<NostrGeoInner>, channel: String, pubkey: String) {
    let lookup_key = format!("{}:{}", channel, pubkey);
    let mut lookups = inner.metadata_lookup_pubkeys.lock().await;
    if !lookups.insert(lookup_key.clone()) {
        return;
    }
    drop(lookups);

    let relays = profile_lookup_relays(&inner, &channel).await;
    tokio::spawn(async move {
        write_nostr_debug_log(&format!(
            "profile metadata lookup start: pubkey={}, relays={}",
            &pubkey[..pubkey.len().min(8)],
            relays.join(",")
        ));
        match lookup_profile_name(&pubkey, relays).await {
            Ok(Some(name)) => {
                write_nostr_debug_log(&format!(
                    "resolved profile metadata: pubkey={}, name={}",
                    &pubkey[..pubkey.len().min(8)],
                    name
                ));
                update_known_person(&inner, &channel, &pubkey, &name).await;
            }
            Ok(None) => {
                inner
                    .metadata_lookup_pubkeys
                    .lock()
                    .await
                    .remove(&lookup_key);
                write_nostr_debug_log(&format!(
                    "profile metadata not found: pubkey={}",
                    &pubkey[..pubkey.len().min(8)]
                ));
            }
            Err(e) => {
                inner
                    .metadata_lookup_pubkeys
                    .lock()
                    .await
                    .remove(&lookup_key);
                write_nostr_debug_log(&format!(
                    "profile metadata lookup failed: pubkey={}, error={}",
                    &pubkey[..pubkey.len().min(8)],
                    e
                ));
            }
        }
    });
}

async fn profile_lookup_relays(inner: &Arc<NostrGeoInner>, channel: &str) -> Vec<String> {
    let geohash_relays = if let Some(geohash) = normalize_geohash(channel) {
        inner
            .relays_by_geohash
            .lock()
            .await
            .get(&geohash)
            .cloned()
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let profile_relays = metadata_relays();
    let dm_relays = dm_relays();
    merge_relays(&geohash_relays, &merge_relays(&profile_relays, &dm_relays))
}

async fn handle_private_relay_event(
    inner: &Arc<NostrGeoInner>,
    channel: &str,
    local_pubkey: &str,
    local_secret: &SecretKey,
    event: &NostrEvent,
) {
    write_nostr_debug_log(&format!(
        "received geohash dm candidate: channel={}, event={}, gift_pubkey={}, local={}, p_tags={}",
        channel,
        event.id,
        short_log_pubkey(&event.pubkey),
        short_log_pubkey(local_pubkey),
        event
            .tags
            .iter()
            .filter(|tag| tag.first().map(String::as_str) == Some("p"))
            .filter_map(|tag| tag.get(1))
            .map(|value| short_log_pubkey(value))
            .collect::<Vec<_>>()
            .join(",")
    ));

    if event.pubkey == local_pubkey || !event_has_tag_value(event, "p", local_pubkey) {
        write_nostr_debug_log(&format!(
            "ignored geohash dm candidate: event={}, reason=not addressed to local key",
            event.id
        ));
        return;
    }

    let mut seen = inner.seen_event_ids.lock().await;
    if !seen.insert(event.id.clone()) {
        return;
    }
    drop(seen);

    let decoded =
        match decrypt_private_message(event, local_secret).and_then(decode_bitchat_dm_content) {
            Ok(decoded) => decoded,
            Err(e) => {
                write_nostr_debug_log(&format!(
                    "failed to decrypt geohash dm: event={}, error={}",
                    event.id, e
                ));
                return;
            }
        };

    let sender_pubkey = decoded.sender_pubkey.clone();
    write_nostr_debug_log(&format!(
        "decrypted geohash dm: channel={}, sender={}, event={}",
        channel,
        short_log_pubkey(&sender_pubkey),
        event.id
    ));
    match decoded.kind {
        DecodedPrivateMessageKind::Text {
            content,
            message_id,
        } => {
            handle_private_text_event(
                inner,
                channel,
                event,
                sender_pubkey,
                decoded.timestamp,
                decoded.sender_nickname,
                message_id,
                content,
            )
            .await;
        }
        DecodedPrivateMessageKind::Delivered { message_id } => {
            emit_private_status_update(
                inner,
                channel,
                &sender_pubkey,
                &message_id,
                GEOHASH_DM_STATUS_DELIVERED,
            )
            .await;
        }
        DecodedPrivateMessageKind::Read { message_id } => {
            emit_private_status_update(
                inner,
                channel,
                &sender_pubkey,
                &message_id,
                GEOHASH_DM_STATUS_READ,
            )
            .await;
        }
    }
}

async fn handle_private_text_event(
    inner: &Arc<NostrGeoInner>,
    channel: &str,
    event: &NostrEvent,
    sender_pubkey: String,
    timestamp: i64,
    sender_nickname: Option<String>,
    message_id: String,
    content: String,
) {
    let sender = if let Some(nickname) = sender_nickname {
        update_known_person(inner, channel, &sender_pubkey, &nickname).await;
        nickname
    } else if let Some(name) = known_person_name(inner, &sender_pubkey).await {
        name
    } else {
        let fallback = format!("npub{}", sender_pubkey.chars().take(8).collect::<String>());
        update_known_person(inner, channel, &sender_pubkey, &fallback).await;
        schedule_metadata_lookup(inner.clone(), channel.to_string(), sender_pubkey.clone()).await;
        fallback
    };

    let timestamp = Local
        .timestamp_opt(timestamp, 0)
        .single()
        .unwrap_or_else(Local::now);
    let structured = format!(
        "__GEO_DM__:{}:{}:{}:{}:{}:{}",
        channel,
        sender,
        sender_pubkey,
        timestamp.format("%H%M"),
        sanitize_display_field(&message_id),
        content
    );
    write_nostr_debug_log(&format!(
        "received geohash dm: channel={}, sender={}, message={}, event={}",
        channel,
        sender,
        short_log_pubkey(&message_id),
        event.id
    ));
    let _ = inner.ui_tx.send(structured).await;
}

async fn emit_private_status_update(
    inner: &Arc<NostrGeoInner>,
    channel: &str,
    sender_pubkey: &str,
    message_id: &str,
    status: &str,
) {
    write_nostr_debug_log(&format!(
        "received geohash dm {}: channel={}, sender={}, message={}",
        status,
        channel,
        short_log_pubkey(sender_pubkey),
        short_log_pubkey(message_id)
    ));
    let _ = inner
        .ui_tx
        .send(format!(
            "__GEO_DM_STATUS__:{}:{}",
            sanitize_display_field(message_id),
            status
        ))
        .await;
}

fn event_has_geohash(event: &NostrEvent, geohash: &str) -> bool {
    event_has_tag_value(event, "g", geohash)
}

fn event_has_tag_value(event: &NostrEvent, tag_name: &str, value: &str) -> bool {
    event.tags.iter().any(|tag| {
        tag.first().map(String::as_str) == Some(tag_name)
            && tag.get(1).map(String::as_str) == Some(value)
    })
}

fn event_tag_value(event: &Nip17Event, tag_name: &str) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        if tag.first().map(String::as_str) == Some(tag_name) {
            tag.get(1).cloned()
        } else {
            None
        }
    })
}

async fn lookup_profile_name(pubkey: &str, relays: Vec<String>) -> Result<Option<String>, String> {
    let results = join_all(relays.into_iter().map(|relay| {
        let pubkey = pubkey.to_string();
        async move { lookup_profile_name_once(&relay, &pubkey).await }
    }))
    .await;

    let mut last_error = None;
    for result in results {
        match result {
            Ok(Some(name)) => return Ok(Some(name)),
            Ok(None) => {}
            Err(e) => last_error = Some(e),
        }
    }

    if let Some(error) = last_error {
        Err(error)
    } else {
        Ok(None)
    }
}

async fn lookup_profile_name_once(relay: &str, pubkey: &str) -> Result<Option<String>, String> {
    let (mut ws_stream, _) = connect_relay(relay).await?;
    let sub_id = format!("bitchat-tui-profile-{}", Uuid::new_v4());
    let req = json!([
        "REQ",
        sub_id,
        {
            "kinds": [0],
            "authors": [pubkey],
            "limit": 1
        }
    ]);
    ws_stream
        .send(WsMessage::Text(req.to_string()))
        .await
        .map_err(|e| e.to_string())?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let message = match tokio::time::timeout(remaining, ws_stream.next()).await {
            Ok(Some(Ok(message))) => message,
            Ok(Some(Err(e))) => return Err(e.to_string()),
            Ok(None) | Err(_) => break,
        };

        let WsMessage::Text(text) = message else {
            continue;
        };
        let parsed: Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let Some(arr) = parsed.as_array() else {
            continue;
        };
        match arr.first().and_then(Value::as_str) {
            Some("EVENT") if arr.len() >= 3 => {
                let event: NostrEvent = match serde_json::from_value(arr[2].clone()) {
                    Ok(event) => event,
                    Err(_) => continue,
                };
                if event.kind == 0 && event.pubkey == pubkey {
                    let _ = ws_stream
                        .send(WsMessage::Text(json!(["CLOSE", sub_id]).to_string()))
                        .await;
                    let _ = ws_stream.close(None).await;
                    return Ok(profile_name_from_metadata(&event.content));
                }
            }
            Some("EOSE") => break,
            _ => {}
        }
    }

    let _ = ws_stream
        .send(WsMessage::Text(json!(["CLOSE", sub_id]).to_string()))
        .await;
    let _ = ws_stream.close(None).await;
    Ok(None)
}

fn profile_name_from_metadata(content: &str) -> Option<String> {
    let metadata: NostrProfileMetadata = serde_json::from_str(content).ok()?;
    [
        metadata.display_name,
        metadata.name,
        metadata.username,
        metadata.nip05,
    ]
    .into_iter()
    .flatten()
    .map(|name| sanitize_display_field(&name))
    .find(|name| !name.trim().is_empty() && !is_pubkey_placeholder_name(name))
}

async fn publish_event(relay: &str, event: &NostrEvent) -> Result<(), String> {
    tokio::time::timeout(
        Duration::from_secs(PUBLISH_TIMEOUT_SECONDS),
        publish_event_once(relay, event),
    )
    .await
    .map_err(|_| format!("publish timeout after {}s", PUBLISH_TIMEOUT_SECONDS))?
}

async fn publish_event_once(relay: &str, event: &NostrEvent) -> Result<(), String> {
    let (mut ws_stream, _) = connect_relay(relay).await?;
    let msg = json!(["EVENT", event]).to_string();
    ws_stream
        .send(WsMessage::Text(msg))
        .await
        .map_err(|e| e.to_string())?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let message = match tokio::time::timeout(remaining, ws_stream.next()).await {
            Ok(Some(Ok(message))) => message,
            Ok(Some(Err(e))) => return Err(e.to_string()),
            Ok(None) | Err(_) => break,
        };
        if let WsMessage::Text(text) = message {
            if let Some(result) = parse_publish_ack(&text, &event.id) {
                let _ = ws_stream.close(None).await;
                return result;
            }
        }
    }
    let _ = ws_stream.close(None).await;
    Err("publish ack timeout after 2s".to_string())
}

async fn connect_relay(
    relay: &str,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, WsResponse), String> {
    if let Some(proxy) = nostr_proxy() {
        let socket = connect_proxy_tunnel(&proxy, relay).await?;
        client_async_tls_with_config(relay, socket, None, None)
            .await
            .map_err(|e| format!("proxy websocket handshake failed via {}: {}", proxy, e))
    } else {
        connect_async(relay).await.map_err(|e| e.to_string())
    }
}

fn nostr_proxy() -> Option<String> {
    [
        "BITCHAT_TUI_NOSTR_PROXY",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    .iter()
    .find_map(|name| std::env::var(name).ok())
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty())
}

async fn connect_proxy_tunnel(proxy: &str, relay: &str) -> Result<TcpStream, String> {
    let proxy = parse_proxy(proxy)?;
    let target = parse_ws_target(relay)?;
    match proxy.scheme {
        ProxyScheme::Http => connect_http_proxy(&proxy, &target).await,
        ProxyScheme::Socks5 => connect_socks5_proxy(&proxy, &target).await,
    }
}

#[derive(Debug, Clone, Copy)]
enum ProxyScheme {
    Http,
    Socks5,
}

#[derive(Debug, Clone)]
struct ProxyConfig {
    scheme: ProxyScheme,
    host: String,
    port: u16,
}

#[derive(Debug, Clone)]
struct WsTarget {
    host: String,
    port: u16,
}

impl ProxyConfig {
    fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl WsTarget {
    fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn parse_proxy(value: &str) -> Result<ProxyConfig, String> {
    let value = value.trim().trim_end_matches('/');
    let (scheme, rest, default_port) = if let Some(rest) = value.strip_prefix("http://") {
        (ProxyScheme::Http, rest, 8080)
    } else if value.starts_with("https://") {
        return Err("HTTPS proxies are not supported; use http:// or socks5://".to_string());
    } else if let Some(rest) = value.strip_prefix("socks5h://") {
        (ProxyScheme::Socks5, rest, 1080)
    } else if let Some(rest) = value.strip_prefix("socks5://") {
        (ProxyScheme::Socks5, rest, 1080)
    } else {
        (ProxyScheme::Http, value, 8080)
    };
    let rest = rest.rsplit('@').next().unwrap_or(rest);
    let (host, port) = split_host_port(rest, default_port)?;
    Ok(ProxyConfig { scheme, host, port })
}

fn parse_ws_target(relay: &str) -> Result<WsTarget, String> {
    let (rest, default_port) = if let Some(rest) = relay.strip_prefix("wss://") {
        (rest, 443)
    } else if let Some(rest) = relay.strip_prefix("ws://") {
        (rest, 80)
    } else {
        return Err(format!("Unsupported relay URL: {}", relay));
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = split_host_port(authority, default_port)?;
    Ok(WsTarget { host, port })
}

fn split_host_port(authority: &str, default_port: u16) -> Result<(String, u16), String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err("Missing host".to_string());
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return Err(format!("Invalid bracketed host: {}", authority));
        };
        let port = after
            .strip_prefix(':')
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Ok((host.to_string(), port));
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return Ok((host.to_string(), port));
        }
    }
    Ok((authority.to_string(), default_port))
}

async fn connect_http_proxy(proxy: &ProxyConfig, target: &WsTarget) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(proxy.address())
        .await
        .map_err(|e| format!("proxy connect failed: {}", e))?;
    let authority = target.authority();
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: bitchat-tui\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("proxy CONNECT write failed: {}", e))?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    while response.len() < 8192 {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("proxy CONNECT read failed: {}", e))?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..n]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&response);
    let status = text.lines().next().unwrap_or_default();
    if status.contains(" 200 ") {
        Ok(stream)
    } else {
        Err(format!("proxy CONNECT rejected: {}", status))
    }
}

async fn connect_socks5_proxy(proxy: &ProxyConfig, target: &WsTarget) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(proxy.address())
        .await
        .map_err(|e| format!("SOCKS5 proxy connect failed: {}", e))?;
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| format!("SOCKS5 greeting write failed: {}", e))?;
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(|e| format!("SOCKS5 greeting read failed: {}", e))?;
    if greeting != [0x05, 0x00] {
        return Err("SOCKS5 proxy requires unsupported authentication".to_string());
    }

    let host = target.host.as_bytes();
    if host.len() > u8::MAX as usize {
        return Err("SOCKS5 target hostname is too long".to_string());
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&target.port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|e| format!("SOCKS5 CONNECT write failed: {}", e))?;

    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| format!("SOCKS5 CONNECT read failed: {}", e))?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(format!("SOCKS5 CONNECT rejected with code {}", header[1]));
    }
    match header[3] {
        0x01 => read_socks5_tail(&mut stream, 4).await?,
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|e| format!("SOCKS5 domain tail read failed: {}", e))?;
            read_socks5_tail(&mut stream, len[0] as usize).await?;
        }
        0x04 => read_socks5_tail(&mut stream, 16).await?,
        _ => return Err("SOCKS5 proxy returned invalid address type".to_string()),
    }
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .map_err(|e| format!("SOCKS5 port tail read failed: {}", e))?;
    Ok(stream)
}

async fn read_socks5_tail(stream: &mut TcpStream, len: usize) -> Result<(), String> {
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("SOCKS5 address tail read failed: {}", e))?;
    Ok(())
}

fn parse_publish_ack(text: &str, event_id: &str) -> Option<Result<(), String>> {
    let parsed: Value = serde_json::from_str(text).ok()?;
    let arr = parsed.as_array()?;
    if arr.first().and_then(Value::as_str) != Some("OK") {
        return None;
    }
    if arr.get(1).and_then(Value::as_str) != Some(event_id) {
        return None;
    }
    let accepted = arr.get(2).and_then(Value::as_bool).unwrap_or(false);
    if accepted {
        Some(Ok(()))
    } else {
        let reason = arr
            .get(3)
            .and_then(Value::as_str)
            .unwrap_or("relay rejected event");
        Some(Err(reason.to_string()))
    }
}

fn create_geohash_event(
    identity_seed: &[u8],
    geohash: &str,
    content: &str,
    nickname: &str,
) -> Result<NostrEvent, String> {
    let secp = Secp256k1::new();
    let secret_key = derive_secret_key(identity_seed, geohash)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    let pubkey = hex::encode(xonly.serialize());
    let created_at = Local::now().timestamp();
    let tags = vec![
        vec!["g".to_string(), geohash.to_string()],
        vec!["n".to_string(), sanitize_display_field(nickname)],
    ];
    let kind = GEOHASH_CHAT_KIND;
    let event_id = calculate_event_id(&pubkey, created_at, kind, &tags, content)?;
    let digest = hex::decode(&event_id).map_err(|e| e.to_string())?;
    let message = SecpMessage::from_digest_slice(&digest).map_err(|e| e.to_string())?;
    let sig = secp.sign_schnorr_no_aux_rand(&message, &keypair);

    Ok(NostrEvent {
        id: event_id,
        pubkey,
        created_at,
        kind,
        tags,
        content: content.to_string(),
        sig: sig.to_string(),
    })
}

fn create_geohash_presence_event(
    identity_seed: &[u8],
    geohash: &str,
) -> Result<NostrEvent, String> {
    let secp = Secp256k1::new();
    let secret_key = derive_secret_key(identity_seed, geohash)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    let pubkey = hex::encode(xonly.serialize());
    let created_at = Local::now().timestamp();
    let tags = vec![vec!["g".to_string(), geohash.to_string()]];
    let content = "";
    let kind = GEOHASH_PRESENCE_KIND;
    let event_id = calculate_event_id(&pubkey, created_at, kind, &tags, content)?;
    let digest = hex::decode(&event_id).map_err(|e| e.to_string())?;
    let message = SecpMessage::from_digest_slice(&digest).map_err(|e| e.to_string())?;
    let sig = secp.sign_schnorr_no_aux_rand(&message, &keypair);

    Ok(NostrEvent {
        id: event_id,
        pubkey,
        created_at,
        kind,
        tags,
        content: content.to_string(),
        sig: sig.to_string(),
    })
}

fn create_private_message_event(
    identity_seed: &[u8],
    geohash: &str,
    recipient_pubkey: &str,
    content: &str,
    sender_peer_id: &str,
    sender_nickname: &str,
    message_id: &str,
) -> Result<NostrEvent, String> {
    let local_secret = derive_secret_key(identity_seed, geohash)?;
    let local_pubkey = xonly_pubkey_from_secret(&local_secret);
    let embedded = create_embedded_bitchat_dm(content, sender_peer_id, message_id)?;

    create_private_event_from_embedded(local_pubkey, recipient_pubkey, embedded, sender_nickname)
}

fn create_private_event_from_embedded(
    local_pubkey: String,
    recipient_pubkey: &str,
    embedded: String,
    sender_nickname: &str,
) -> Result<NostrEvent, String> {
    let rumor = Nip17Event {
        id: String::new(),
        pubkey: local_pubkey.clone(),
        created_at: Local::now().timestamp(),
        kind: 14,
        tags: vec![vec![
            "bitchat-nick".to_string(),
            sanitize_display_field(sender_nickname),
        ]],
        content: embedded,
        sig: None,
    };

    // Match iOS NostrProtocol.createPrivateMessage: the rumor carries the
    // geohash identity, while seal and gift-wrap use fresh ephemeral keys.
    let seal_key = random_secret_key();
    let seal_pubkey = xonly_pubkey_from_secret(&seal_key);
    let seal_json = serde_json::to_string(&rumor).map_err(|e| e.to_string())?;
    let encrypted_seal = legacy_nip44_encrypt(&seal_json, recipient_pubkey, &seal_key)?;
    let seal = sign_nip17_event(
        Nip17Event {
            id: String::new(),
            pubkey: seal_pubkey,
            created_at: randomized_timestamp(),
            kind: 13,
            tags: Vec::new(),
            content: encrypted_seal,
            sig: None,
        },
        &seal_key,
    )?;

    let wrap_key = random_secret_key();
    let seal_json = serde_json::to_string(&seal).map_err(|e| e.to_string())?;
    let encrypted_wrap = legacy_nip44_encrypt(&seal_json, recipient_pubkey, &wrap_key)?;
    let gift_wrap = sign_nip17_event(
        Nip17Event {
            id: String::new(),
            pubkey: xonly_pubkey_from_secret(&wrap_key),
            created_at: randomized_timestamp(),
            kind: GEOHASH_DM_KIND,
            tags: vec![vec!["p".to_string(), recipient_pubkey.to_string()]],
            content: encrypted_wrap,
            sig: None,
        },
        &wrap_key,
    )?;

    nip17_to_nostr_event(gift_wrap)
}

fn decrypt_private_message(
    gift_wrap: &NostrEvent,
    local_secret: &SecretKey,
) -> Result<(String, String, i64, Option<String>), String> {
    let seal_json = nip44_decrypt(&gift_wrap.content, &gift_wrap.pubkey, local_secret)?;
    let seal: Nip17Event = serde_json::from_str(&seal_json).map_err(|e| e.to_string())?;
    let rumor_json = nip44_decrypt(&seal.content, &seal.pubkey, local_secret)?;
    let rumor: Nip17Event = serde_json::from_str(&rumor_json).map_err(|e| e.to_string())?;
    let sender_nickname = event_tag_value(&rumor, "bitchat-nick")
        .map(|value| sanitize_display_field(&value))
        .filter(|value| !value.starts_with("npub"));
    Ok((
        rumor.content,
        rumor.pubkey,
        rumor.created_at,
        sender_nickname,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedPrivateMessage {
    kind: DecodedPrivateMessageKind,
    sender_pubkey: String,
    timestamp: i64,
    sender_nickname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DecodedPrivateMessageKind {
    Text { message_id: String, content: String },
    Delivered { message_id: String },
    Read { message_id: String },
}

fn decode_bitchat_dm_content(
    decoded: (String, String, i64, Option<String>),
) -> Result<DecodedPrivateMessage, String> {
    let (content, sender_pubkey, timestamp, sender_nickname) = decoded;
    let Some(encoded) = content.strip_prefix("bitchat1:") else {
        return Ok(DecodedPrivateMessage {
            kind: DecodedPrivateMessageKind::Text {
                message_id: Uuid::new_v4().to_string(),
                content,
            },
            sender_pubkey,
            timestamp,
            sender_nickname,
        });
    };

    let packet_bytes = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|e| e.to_string())?;
    let packet =
        crate::packet_parser::parse_bitchat_packet(&packet_bytes).map_err(|e| e.to_string())?;
    write_nostr_debug_log(&format!(
        "decoded embedded geohash dm packet: version={}, type={:?}, payload_type={}",
        packet.version,
        packet.msg_type,
        packet
            .payload
            .first()
            .map(|payload_type| format!("0x{:02x}", payload_type))
            .unwrap_or_else(|| "none".to_string())
    ));
    if packet.msg_type != crate::data_structures::MessageType::NoiseEncrypted {
        return Err("Embedded BitChat packet is not a private message".to_string());
    }
    let Some((&payload_type, private_payload)) = packet.payload.split_first() else {
        return Err("Embedded private payload is empty".to_string());
    };
    let kind_result = match payload_type {
        crate::payload_handling::NOISE_PAYLOAD_PRIVATE_MESSAGE => {
            crate::payload_handling::parse_private_noise_payload(private_payload)
                .map(
                    |(message_id, private_content)| DecodedPrivateMessageKind::Text {
                        message_id,
                        content: private_content,
                    },
                )
                .map_err(|e| e.to_string())
        }
        crate::payload_handling::NOISE_PAYLOAD_DELIVERED => {
            crate::payload_handling::parse_private_noise_ack_payload(private_payload)
                .map(|message_id| DecodedPrivateMessageKind::Delivered { message_id })
                .map_err(|e| e.to_string())
        }
        crate::payload_handling::NOISE_PAYLOAD_READ_RECEIPT => {
            crate::payload_handling::parse_private_noise_ack_payload(private_payload)
                .map(|message_id| DecodedPrivateMessageKind::Read { message_id })
                .map_err(|e| e.to_string())
        }
        _ => Err(format!(
            "{} 0x{:02x}",
            EMBEDDED_PRIVATE_PAYLOAD_UNSUPPORTED_TYPE, payload_type
        )),
    };
    let kind = kind_result.map_err(|e| {
        write_nostr_debug_log(&format!(
            "failed to decode embedded geohash dm payload: payload_type=0x{:02x}, payload_len={}, error={}",
            payload_type,
            private_payload.len(),
            e
        ));
        e
    })?;
    Ok(DecodedPrivateMessage {
        kind,
        sender_pubkey,
        timestamp,
        sender_nickname,
    })
}

fn create_embedded_bitchat_dm(
    content: &str,
    sender_peer_id: &str,
    message_id: &str,
) -> Result<String, String> {
    let payload = crate::payload_handling::create_private_noise_payload(&message_id, content)
        .map_err(|e| e.to_string())?;
    create_embedded_bitchat_noise_packet(sender_peer_id, payload)
}

fn create_embedded_bitchat_noise_packet(
    sender_peer_id: &str,
    payload: Vec<u8>,
) -> Result<String, String> {
    let packet = crate::packet_creation::create_bitchat_packet_with_recipient_at(
        sender_peer_id,
        None,
        crate::data_structures::MessageType::NoiseEncrypted,
        payload,
        None,
        crate::packet_creation::current_timestamp_ms(),
    );
    Ok(format!("bitchat1:{}", URL_SAFE_NO_PAD.encode(packet)))
}

fn sign_nip17_event(event: Nip17Event, secret_key: &SecretKey) -> Result<Nip17Event, String> {
    let secp = Secp256k1::new();
    let event_id = calculate_event_id(
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    )?;
    let digest = hex::decode(&event_id).map_err(|e| e.to_string())?;
    let message = SecpMessage::from_digest_slice(&digest).map_err(|e| e.to_string())?;
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let sig = secp.sign_schnorr_no_aux_rand(&message, &keypair);

    Ok(Nip17Event {
        id: event_id,
        sig: Some(sig.to_string()),
        ..event
    })
}

fn nip17_to_nostr_event(event: Nip17Event) -> Result<NostrEvent, String> {
    Ok(NostrEvent {
        id: event.id,
        pubkey: event.pubkey,
        created_at: event.created_at,
        kind: event.kind,
        tags: event.tags,
        content: event.content,
        sig: event
            .sig
            .ok_or_else(|| "Missing Nostr event signature".to_string())?,
    })
}

fn nip44_encrypt(
    plaintext: &str,
    recipient_pubkey: &str,
    sender_key: &SecretKey,
) -> Result<String, String> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    nip44_encrypt_with_nonce(plaintext, recipient_pubkey, sender_key, &nonce)
}

fn legacy_nip44_encrypt(
    plaintext: &str,
    recipient_pubkey: &str,
    sender_key: &SecretKey,
) -> Result<String, String> {
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    legacy_nip44_encrypt_with_nonce(plaintext, recipient_pubkey, sender_key, &nonce)
}

fn legacy_nip44_encrypt_with_nonce(
    plaintext: &str,
    recipient_pubkey: &str,
    sender_key: &SecretKey,
    nonce: &[u8; 24],
) -> Result<String, String> {
    let public_key = public_key_from_xonly(recipient_pubkey, 0x02)?;
    let shared_secret = derive_shared_secret_compressed(sender_key, &public_key)?;
    let key = legacy_derive_nip44_key(&shared_secret)?;
    let cipher = XChaCha20Poly1305::new(XChaChaKey::from_slice(&key));
    let encrypted = cipher
        .encrypt(XNonce::from_slice(nonce), plaintext.as_bytes())
        .map_err(|_| "NIP-44 legacy encryption failed".to_string())?;

    let mut combined = Vec::with_capacity(nonce.len() + encrypted.len());
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(&encrypted);
    Ok(format!("v2:{}", URL_SAFE_NO_PAD.encode(combined)))
}

fn nip44_encrypt_with_nonce(
    plaintext: &str,
    recipient_pubkey: &str,
    sender_key: &SecretKey,
    nonce: &[u8; 32],
) -> Result<String, String> {
    let public_key = public_key_from_xonly(recipient_pubkey, 0x02)?;
    let conversation_key = derive_nip44_conversation_key(sender_key, &public_key)?;
    nip44_encrypt_payload(plaintext, &conversation_key, nonce)
}

fn nip44_decrypt(
    ciphertext: &str,
    sender_pubkey: &str,
    recipient_key: &SecretKey,
) -> Result<String, String> {
    if ciphertext.starts_with("v2:") {
        return legacy_nip44_decrypt(ciphertext, sender_pubkey, recipient_key);
    }

    let mut last_error = "NIP-44 decryption failed".to_string();
    for prefix in [0x02u8, 0x03u8] {
        match public_key_from_xonly(sender_pubkey, prefix)
            .and_then(|public_key| derive_nip44_conversation_key(recipient_key, &public_key))
            .and_then(|conversation_key| nip44_decrypt_payload(ciphertext, &conversation_key))
        {
            Ok(plaintext) => return Ok(plaintext),
            Err(e) => last_error = e,
        }
    }

    Err(last_error)
}

fn nip44_encrypt_payload(
    plaintext: &str,
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<String, String> {
    let (chacha_key, chacha_nonce, hmac_key) = derive_nip44_message_keys(conversation_key, nonce)?;
    let mut ciphertext = pad_nip44_plaintext(plaintext.as_bytes())?;
    let mut cipher = ChaCha20::new_from_slices(&chacha_key, &chacha_nonce)
        .map_err(|_| "NIP-44 ChaCha20 initialization failed".to_string())?;
    cipher.apply_keystream(&mut ciphertext);
    let mac = nip44_hmac(&hmac_key, &ciphertext, nonce)?;

    let mut payload = Vec::with_capacity(1 + nonce.len() + ciphertext.len() + mac.len());
    payload.push(0x02);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&mac);
    Ok(STANDARD.encode(payload))
}

fn nip44_decrypt_payload(payload: &str, conversation_key: &[u8; 32]) -> Result<String, String> {
    if payload.is_empty() || payload.starts_with('#') {
        return Err("Unsupported NIP-44 ciphertext version".to_string());
    }
    if !(132..=87_472).contains(&payload.len()) {
        return Err("Invalid NIP-44 payload size".to_string());
    }

    let data = STANDARD.decode(payload).map_err(|e| e.to_string())?;
    if !(99..=65_603).contains(&data.len()) {
        return Err("Invalid NIP-44 data size".to_string());
    }
    if data.first() != Some(&0x02) {
        return Err("Unsupported NIP-44 ciphertext version".to_string());
    }

    let nonce: [u8; 32] = data[1..33]
        .try_into()
        .map_err(|_| "Invalid NIP-44 nonce length".to_string())?;
    let ciphertext = &data[33..data.len() - 32];
    let expected_mac = &data[data.len() - 32..];
    let (chacha_key, chacha_nonce, hmac_key) = derive_nip44_message_keys(conversation_key, &nonce)?;
    verify_nip44_hmac(&hmac_key, ciphertext, &nonce, expected_mac)?;

    let mut plaintext = ciphertext.to_vec();
    let mut cipher = ChaCha20::new_from_slices(&chacha_key, &chacha_nonce)
        .map_err(|_| "NIP-44 ChaCha20 initialization failed".to_string())?;
    cipher.apply_keystream(&mut plaintext);
    unpad_nip44_plaintext(&plaintext)
}

fn legacy_nip44_decrypt(
    ciphertext: &str,
    sender_pubkey: &str,
    recipient_key: &SecretKey,
) -> Result<String, String> {
    let encoded = ciphertext
        .strip_prefix("v2:")
        .ok_or_else(|| "Unsupported NIP-44 ciphertext version".to_string())?;
    let combined = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|e| e.to_string())?;
    if combined.len() <= 40 {
        return Err("NIP-44 ciphertext too short".to_string());
    }
    let (nonce, encrypted) = combined.split_at(24);

    for prefix in [0x02u8, 0x03u8] {
        if let Ok(public_key) = public_key_from_xonly(sender_pubkey, prefix) {
            if let Ok(shared_secret) = derive_shared_secret_compressed(recipient_key, &public_key) {
                if let Ok(key) = legacy_derive_nip44_key(&shared_secret) {
                    let cipher = XChaCha20Poly1305::new(XChaChaKey::from_slice(&key));
                    if let Ok(plaintext) = cipher.decrypt(XNonce::from_slice(nonce), encrypted) {
                        return String::from_utf8(plaintext).map_err(|e| e.to_string());
                    }
                }
            }
        }
    }

    Err("NIP-44 decryption failed".to_string())
}

fn derive_nip44_conversation_key(
    secret_key: &SecretKey,
    public_key: &SecpPublicKey,
) -> Result<[u8; 32], String> {
    let shared_x = derive_shared_secret_xonly(secret_key, public_key)?;
    let (prk, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), &shared_x);
    let mut conversation_key = [0u8; 32];
    conversation_key.copy_from_slice(&prk);
    Ok(conversation_key)
}

fn derive_shared_secret_xonly(
    secret_key: &SecretKey,
    public_key: &SecpPublicKey,
) -> Result<[u8; 32], String> {
    let secp = Secp256k1::new();
    let scalar = Scalar::from_be_bytes(secret_key.secret_bytes())
        .map_err(|_| "Invalid secp256k1 scalar while deriving Nostr shared secret".to_string())?;
    let shared_point = public_key
        .clone()
        .mul_tweak(&secp, &scalar)
        .map_err(|e| e.to_string())?;
    let serialized = shared_point.serialize();
    let mut shared_x = [0u8; 32];
    shared_x.copy_from_slice(&serialized[1..33]);
    Ok(shared_x)
}

fn derive_shared_secret_compressed(
    secret_key: &SecretKey,
    public_key: &SecpPublicKey,
) -> Result<Vec<u8>, String> {
    let secp = Secp256k1::new();
    let scalar = Scalar::from_be_bytes(secret_key.secret_bytes())
        .map_err(|_| "Invalid secp256k1 scalar while deriving Nostr shared secret".to_string())?;
    let shared_point = public_key
        .clone()
        .mul_tweak(&secp, &scalar)
        .map_err(|e| e.to_string())?;
    Ok(shared_point.serialize().to_vec())
}

fn legacy_derive_nip44_key(shared_secret: &[u8]) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"nip44-v2", &mut key)
        .map_err(|_| "NIP-44 HKDF expansion failed".to_string())?;
    Ok(key)
}

fn derive_nip44_message_keys(
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<([u8; 32], [u8; 12], [u8; 32]), String> {
    let hk =
        Hkdf::<Sha256>::from_prk(conversation_key).map_err(|_| "Invalid NIP-44 PRK".to_string())?;
    let mut output = [0u8; 76];
    hk.expand(nonce, &mut output)
        .map_err(|_| "NIP-44 message key expansion failed".to_string())?;

    let mut chacha_key = [0u8; 32];
    let mut chacha_nonce = [0u8; 12];
    let mut hmac_key = [0u8; 32];
    chacha_key.copy_from_slice(&output[0..32]);
    chacha_nonce.copy_from_slice(&output[32..44]);
    hmac_key.copy_from_slice(&output[44..76]);
    Ok((chacha_key, chacha_nonce, hmac_key))
}

fn nip44_hmac(
    hmac_key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 32],
) -> Result<[u8; 32], String> {
    let mut mac = <Hmac<Sha256> as HmacMac>::new_from_slice(hmac_key).map_err(|e| e.to_string())?;
    HmacMac::update(&mut mac, nonce);
    HmacMac::update(&mut mac, ciphertext);
    let bytes = mac.finalize().into_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

fn verify_nip44_hmac(
    hmac_key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 32],
    expected_mac: &[u8],
) -> Result<(), String> {
    let mut mac = <Hmac<Sha256> as HmacMac>::new_from_slice(hmac_key).map_err(|e| e.to_string())?;
    HmacMac::update(&mut mac, nonce);
    HmacMac::update(&mut mac, ciphertext);
    mac.verify_slice(expected_mac)
        .map_err(|_| "Invalid NIP-44 MAC".to_string())
}

fn pad_nip44_plaintext(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let unpadded_len = plaintext.len();
    if !(NIP44_MIN_PLAINTEXT_SIZE..=NIP44_MAX_PLAINTEXT_SIZE).contains(&unpadded_len) {
        return Err("Invalid NIP-44 plaintext length".to_string());
    }

    let padded_len = calc_nip44_padded_len(unpadded_len);
    let mut padded = Vec::with_capacity(2 + padded_len);
    padded.extend_from_slice(&(unpadded_len as u16).to_be_bytes());
    padded.extend_from_slice(plaintext);
    padded.resize(2 + padded_len, 0);
    Ok(padded)
}

fn unpad_nip44_plaintext(padded: &[u8]) -> Result<String, String> {
    if padded.len() < 2 {
        return Err("Invalid NIP-44 padding".to_string());
    }
    let unpadded_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if unpadded_len == 0
        || unpadded_len > NIP44_MAX_PLAINTEXT_SIZE
        || padded.len() != 2 + calc_nip44_padded_len(unpadded_len)
        || padded.len() < 2 + unpadded_len
    {
        return Err("Invalid NIP-44 padding".to_string());
    }
    String::from_utf8(padded[2..2 + unpadded_len].to_vec()).map_err(|e| e.to_string())
}

fn calc_nip44_padded_len(unpadded_len: usize) -> usize {
    if unpadded_len <= 32 {
        return 32;
    }

    let log2_next = usize::BITS as usize - (unpadded_len - 1).leading_zeros() as usize;
    let next_power = 1usize << log2_next;
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * (((unpadded_len - 1) / chunk) + 1)
}

fn public_key_from_xonly(pubkey: &str, prefix: u8) -> Result<SecpPublicKey, String> {
    let xonly = hex::decode(pubkey).map_err(|e| e.to_string())?;
    if xonly.len() != 32 {
        return Err("Invalid x-only public key length".to_string());
    }
    let mut compressed = Vec::with_capacity(33);
    compressed.push(prefix);
    compressed.extend_from_slice(&xonly);
    SecpPublicKey::from_slice(&compressed).map_err(|e| e.to_string())
}

fn is_valid_xonly_pubkey(pubkey: &str) -> bool {
    public_key_from_xonly(pubkey, 0x02).is_ok() || public_key_from_xonly(pubkey, 0x03).is_ok()
}

fn clean_dm_pubkey_input(input: &str) -> &str {
    let mut input = input.trim().trim_matches(|c| {
        matches!(
            c,
            '<' | '>'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '"'
                | '\''
                | '`'
                | '.'
                | ','
                | ';'
                | ':'
                | '!'
                | '?'
                | '。'
                | '，'
                | '；'
                | '：'
                | '！'
                | '？'
        )
    });
    input = input.trim_start_matches('@');
    if input
        .get(..6)
        .map(|prefix| prefix.eq_ignore_ascii_case("nostr:"))
        .unwrap_or(false)
    {
        input = &input[6..];
    }
    input.trim()
}

pub fn looks_like_dm_pubkey(input: &str) -> bool {
    let input = clean_dm_pubkey_input(input);
    (input.len() == 64 && input.chars().all(|c| c.is_ascii_hexdigit()))
        || input
            .get(..5)
            .map(|prefix| prefix.eq_ignore_ascii_case("npub1"))
            .unwrap_or(false)
}

pub fn normalize_dm_pubkey(input: &str) -> Option<String> {
    let input = clean_dm_pubkey_input(input);
    if input.len() == 64 && input.chars().all(|c| c.is_ascii_hexdigit()) {
        let pubkey = input.to_ascii_lowercase();
        return is_valid_xonly_pubkey(&pubkey).then_some(pubkey);
    }

    let (hrp, data, variant) = bech32::decode(input).ok()?;
    if variant != Variant::Bech32 || !hrp.eq_ignore_ascii_case("npub") {
        return None;
    }
    let bytes = Vec::<u8>::from_base32(&data).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let pubkey = hex::encode(bytes);
    is_valid_xonly_pubkey(&pubkey).then_some(pubkey)
}

fn xonly_pubkey_from_secret(secret_key: &SecretKey) -> String {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    hex::encode(xonly.serialize())
}

fn random_secret_key() -> SecretKey {
    SecretKey::new(&mut rand::thread_rng())
}

fn randomized_timestamp() -> i64 {
    let offset = rand::thread_rng().gen_range(0i64..=900i64);
    Local::now().timestamp().saturating_sub(offset)
}

fn calculate_event_id(
    pubkey: &str,
    created_at: i64,
    kind: i64,
    tags: &[Vec<String>],
    content: &str,
) -> Result<String, String> {
    let serialized = serde_json::to_vec(&json!([0, pubkey, created_at, kind, tags, content]))
        .map_err(|e| e.to_string())?;
    let digest = Sha256::digest(&serialized);
    Ok(hex::encode(digest))
}

fn derive_secret_key(identity_seed: &[u8], geohash: &str) -> Result<SecretKey, String> {
    if identity_seed.is_empty() {
        return Err("Missing persistent identity seed for Nostr geohash channel".to_string());
    }

    for counter in 0u32..1000 {
        let mut hasher = Sha256::new();
        hasher.update(b"bitchat-tui-nostr-geohash-v1");
        hasher.update(identity_seed);
        hasher.update(geohash.as_bytes());
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();
        if let Ok(secret) = SecretKey::from_slice(&digest) {
            return Ok(secret);
        }
    }

    Err("Failed to derive Nostr geohash identity".to_string())
}

async fn resolve_relays(geohash: &str) -> Vec<String> {
    if let Ok(value) = std::env::var("BITCHAT_TUI_NOSTR_RELAYS") {
        let relays: Vec<String> = value
            .split(',')
            .filter_map(|relay| normalize_relay_url(relay.trim()))
            .collect();
        if !relays.is_empty() {
            return relays;
        }
    }

    match fetch_geo_relays().await {
        Ok(entries) => closest_relays(&entries, geohash, relay_count_for_geohash(geohash)),
        Err(e) => {
            write_nostr_debug_log(&format!("relay CSV fetch failed: {}", e));
            fallback_geo_relays(geohash)
        }
    }
}

fn relay_count_for_geohash(geohash: &str) -> usize {
    match geohash.len() {
        2 => 15,
        4 => 10,
        _ => 5,
    }
}

async fn fetch_geo_relays() -> Result<Vec<RelayEntry>, String> {
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| e.to_string())?
        .get(GEO_RELAY_CSV_URL)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let text = response.text().await.map_err(|e| e.to_string())?;
    let entries = parse_relay_csv(&text);
    if entries.is_empty() {
        Err("empty relay CSV".to_string())
    } else {
        Ok(entries)
    }
}

fn parse_relay_csv(text: &str) -> Vec<RelayEntry> {
    text.lines()
        .enumerate()
        .filter_map(|(idx, raw)| {
            let line = raw.trim();
            if line.is_empty() || (idx == 0 && line.to_ascii_lowercase().contains("relay url")) {
                return None;
            }
            let parts: Vec<&str> = line.split(',').map(str::trim).collect();
            if parts.len() < 3 {
                return None;
            }
            let host = parts[0]
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_start_matches("wss://")
                .trim_start_matches("ws://")
                .trim_end_matches('/')
                .to_string();
            let lat = parts[1].parse::<f64>().ok()?;
            let lon = parts[2].parse::<f64>().ok()?;
            Some(RelayEntry { host, lat, lon })
        })
        .collect()
}

fn closest_relays(entries: &[RelayEntry], geohash: &str, count: usize) -> Vec<String> {
    let (lat, lon) = match decode_geohash_center(geohash) {
        Some(center) => center,
        None => return default_relays(),
    };
    let mut ranked: Vec<(f64, &RelayEntry)> = entries
        .iter()
        .map(|entry| (haversine_km(lat, lon, entry.lat, entry.lon), entry))
        .collect();
    ranked.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    ranked
        .into_iter()
        .take(count)
        .map(|(_, entry)| format!("wss://{}", entry.host))
        .collect()
}

fn fallback_geo_relays(geohash: &str) -> Vec<String> {
    if geohash == "ws" {
        let relays = EMBEDDED_WS_RELAYS
            .iter()
            .filter_map(|relay| normalize_relay_url(relay))
            .collect::<Vec<_>>();
        write_nostr_debug_log(&format!(
            "using embedded #ws georelay fallback: relays={}",
            relays.join(",")
        ));
        return relays;
    }

    let entries = embedded_geo_relays();
    let relays = closest_relays(&entries, geohash, relay_count_for_geohash(geohash));
    if relays.is_empty() {
        default_relays()
    } else {
        write_nostr_debug_log(&format!(
            "using embedded georelay fallback: geohash=#{}, relays={}",
            geohash,
            relays.join(",")
        ));
        relays
    }
}

fn embedded_geo_relays() -> Vec<RelayEntry> {
    EMBEDDED_GEO_RELAYS
        .iter()
        .map(|(host, lat, lon)| RelayEntry {
            host: (*host).to_string(),
            lat: *lat,
            lon: *lon,
        })
        .collect()
}

fn decode_geohash_center(geohash: &str) -> Option<(f64, f64)> {
    let mut lat = [-90.0f64, 90.0f64];
    let mut lon = [-180.0f64, 180.0f64];
    let mut even = true;

    for ch in geohash.chars() {
        let mut bits = GEOHASH_ALPHABET.find(ch)? as u8;
        for mask in [16, 8, 4, 2, 1] {
            if even {
                refine_interval(&mut lon, bits & mask != 0);
            } else {
                refine_interval(&mut lat, bits & mask != 0);
            }
            even = !even;
            bits &= !mask;
        }
    }

    Some(((lat[0] + lat[1]) / 2.0, (lon[0] + lon[1]) / 2.0))
}

fn refine_interval(interval: &mut [f64; 2], upper: bool) {
    let mid = (interval[0] + interval[1]) / 2.0;
    if upper {
        interval[0] = mid;
    } else {
        interval[1] = mid;
    }
}

fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let radius_km = 6371.0;
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    let lat1 = lat1.to_radians();
    let lat2 = lat2.to_radians();
    let a = (d_lat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (d_lon / 2.0).sin().powi(2);
    radius_km * 2.0 * a.sqrt().atan2((1.0 - a).sqrt())
}

fn default_relays() -> Vec<String> {
    DEFAULT_RELAYS
        .iter()
        .map(|relay| relay.to_string())
        .collect()
}

fn dm_relays() -> Vec<String> {
    if let Ok(value) = std::env::var("BITCHAT_TUI_NOSTR_DM_RELAYS") {
        let relays: Vec<String> = value
            .split(',')
            .filter_map(|relay| normalize_relay_url(relay.trim()))
            .collect();
        if !relays.is_empty() {
            return relays;
        }
    }

    let relays = default_relays();
    write_nostr_debug_log(&format!(
        "using default dm relays: relays={}",
        relays.join(",")
    ));
    relays
}

fn metadata_relays() -> Vec<String> {
    let default_metadata_relays: Vec<String> = PROFILE_METADATA_RELAYS
        .iter()
        .filter_map(|relay| normalize_relay_url(relay))
        .collect();
    let base_relays = merge_relays(&default_metadata_relays, &default_relays());

    if let Ok(value) = std::env::var("BITCHAT_TUI_NOSTR_METADATA_RELAYS") {
        let relays: Vec<String> = value
            .split(',')
            .filter_map(|relay| normalize_relay_url(relay.trim()))
            .collect();
        if !relays.is_empty() {
            return merge_relays(&relays, &base_relays);
        }
    }

    base_relays
}

fn merge_relays(primary: &[String], secondary: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    primary
        .iter()
        .chain(secondary.iter())
        .filter(|relay| seen.insert((*relay).clone()))
        .cloned()
        .collect()
}

fn normalize_relay_url(relay: &str) -> Option<String> {
    if relay.is_empty() {
        None
    } else if relay.starts_with("wss://") || relay.starts_with("ws://") {
        Some(relay.trim_end_matches('/').to_string())
    } else {
        Some(format!("wss://{}", relay.trim_end_matches('/')))
    }
}

fn sanitize_display_field(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| match ch {
            ':' | '\n' | '\r' => '_',
            _ => ch,
        })
        .collect::<String>();
    if sanitized.trim().is_empty() {
        "anonymous".to_string()
    } else {
        sanitized
    }
}

fn short_log_pubkey(pubkey: &str) -> String {
    let char_count = pubkey.chars().count();
    if char_count <= 18 {
        return pubkey.to_string();
    }

    let prefix: String = pubkey.chars().take(10).collect();
    let mut suffix_chars: Vec<char> = pubkey.chars().rev().take(6).collect();
    suffix_chars.reverse();
    format!(
        "{}...{}",
        prefix,
        suffix_chars.into_iter().collect::<String>()
    )
}

fn write_nostr_debug_log(message: &str) {
    if !crate::data_structures::file_logging_enabled() {
        return;
    }

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("nostr_debug.log")
    {
        let _ = writeln!(
            file,
            "[{}] {}",
            Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            message
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_geohash_channels() {
        assert_eq!(normalize_geohash("#ws").as_deref(), Some("ws"));
        assert_eq!(normalize_geohash("dr5ru62").as_deref(), Some("dr5ru62"));
        assert!(normalize_geohash("dr5").is_none());
        assert!(normalize_geohash("#general").is_none());
        assert!(normalize_geohash("#a").is_none());
    }

    #[test]
    fn decodes_geohash_center() {
        let (lat, lon) = decode_geohash_center("ws").unwrap();
        assert!((-1.5..=45.0).contains(&lat));
        assert!((90.0..=135.0).contains(&lon));
    }

    #[test]
    fn widens_short_geohash_relay_sets() {
        assert_eq!(relay_count_for_geohash("ws"), 15);
        assert_eq!(relay_count_for_geohash("dr5r"), 10);
        assert_eq!(relay_count_for_geohash("dr5ru"), 5);
    }

    #[test]
    fn uses_embedded_ws_relay_fallback() {
        let relays = fallback_geo_relays("ws");
        assert_eq!(relays.len(), 15);
        assert!(relays.iter().all(|relay| relay.starts_with("wss://")));
        assert!(relays
            .iter()
            .any(|relay| relay.contains("relay.homeinhk.xyz")));
    }

    #[test]
    fn creates_signed_geohash_event() {
        let seed = vec![7u8; 32];
        let event = create_geohash_event(&seed, "ws", "hello", "alice").unwrap();
        assert_eq!(event.kind, GEOHASH_CHAT_KIND);
        assert!(event_has_geohash(&event, "ws"));
        assert_eq!(event.pubkey.len(), 64);
        assert_eq!(event.sig.len(), 128);
    }

    #[test]
    fn creates_signed_geohash_presence_event() {
        let seed = vec![7u8; 32];
        let event = create_geohash_presence_event(&seed, "ws").unwrap();
        assert_eq!(event.kind, GEOHASH_PRESENCE_KIND);
        assert!(event_has_geohash(&event, "ws"));
        assert!(event.content.is_empty());
        assert_eq!(event.pubkey.len(), 64);
        assert_eq!(event.sig.len(), 128);
    }

    #[test]
    fn parses_profile_metadata_display_name() {
        assert_eq!(
            profile_name_from_metadata(r#"{"display_name":"g8.bot","name":"fallback"}"#).as_deref(),
            Some("g8.bot")
        );
        assert_eq!(
            profile_name_from_metadata(r#"{"name":"bot_name"}"#).as_deref(),
            Some("bot_name")
        );
        assert_eq!(profile_name_from_metadata(r#"{"name":"npub1234"}"#), None);
    }

    #[test]
    fn only_broadcasts_presence_for_coarse_geohashes() {
        assert!(geohash_broadcasts_presence("#ws"));
        assert!(geohash_broadcasts_presence("#dr5r"));
        assert!(geohash_broadcasts_presence("#dr5ru"));
        assert!(!geohash_broadcasts_presence("#dr5ru6"));
        assert!(!geohash_broadcasts_presence("#dr5ru62"));
    }

    #[test]
    fn parses_nostr_proxy_urls() {
        let http = parse_proxy("http://127.0.0.1:7890").unwrap();
        assert!(matches!(http.scheme, ProxyScheme::Http));
        assert_eq!(http.host, "127.0.0.1");
        assert_eq!(http.port, 7890);

        let socks = parse_proxy("socks5://localhost:1080").unwrap();
        assert!(matches!(socks.scheme, ProxyScheme::Socks5));
        assert_eq!(socks.host, "localhost");
        assert_eq!(socks.port, 1080);
    }

    #[test]
    fn parses_websocket_targets() {
        let target = parse_ws_target("wss://relay.damus.io").unwrap();
        assert_eq!(target.host, "relay.damus.io");
        assert_eq!(target.port, 443);

        let target = parse_ws_target("ws://localhost:8080/path").unwrap();
        assert_eq!(target.host, "localhost");
        assert_eq!(target.port, 8080);
    }

    #[test]
    fn normalizes_hex_dm_pubkeys() {
        let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let hex_pubkey = xonly_pubkey_from_secret(&secret_key);
        assert_eq!(normalize_dm_pubkey(&hex_pubkey), Some(hex_pubkey));
    }

    #[test]
    fn normalizes_npub_dm_pubkeys() {
        use bech32::ToBase32;

        let secret_key = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let hex_pubkey = xonly_pubkey_from_secret(&secret_key);
        let bytes = hex::decode(&hex_pubkey).unwrap();
        let npub = bech32::encode("npub", bytes.to_base32(), Variant::Bech32).unwrap();

        assert_eq!(normalize_dm_pubkey(&npub), Some(hex_pubkey.clone()));
        assert_eq!(
            normalize_dm_pubkey(&format!("nostr:{}", npub)),
            Some(hex_pubkey)
        );
    }

    #[test]
    fn normalizes_real_dm_pubkeys_from_reports() {
        assert_eq!(
            normalize_dm_pubkey("npub1745gaq4n86h9zykddmzcajnhmgcfr960s3tez20q6yc5rezq8j0qrpctyq")
                .as_deref(),
            Some("f5688e82b33eae5112cd6ec58eca77da3091974f84579129e0d13141e4403c9e")
        );
        assert_eq!(
            normalize_dm_pubkey("npub1fn928zyt8vcr629antn25gnc2vpr9dqy40x0l2pan25ptmfv5n3qdvtshx")
                .as_deref(),
            Some("4ccaa3888b3b303d28bd9ae6aa2278530232b404abccffa83d9aa815ed2ca4e2")
        );
        assert_eq!(
            normalize_dm_pubkey(
                "npub1fn928zyt8vcr629antn25gnc2vpr9dqy40x0l2pan25ptmfv5n3qdvtshx。"
            )
            .as_deref(),
            Some("4ccaa3888b3b303d28bd9ae6aa2278530232b404abccffa83d9aa815ed2ca4e2")
        );
    }

    #[test]
    fn normalize_dm_pubkey_rejects_invalid_npub() {
        assert!(normalize_dm_pubkey("npub1invalid").is_none());
    }

    #[test]
    fn nip44_matches_v2_test_vector() {
        let sender_secret = SecretKey::from_slice(
            &hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
        )
        .unwrap();
        let recipient_secret = SecretKey::from_slice(
            &hex::decode("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap(),
        )
        .unwrap();
        let recipient_pubkey = xonly_pubkey_from_secret(&recipient_secret);
        let recipient_public_key = public_key_from_xonly(&recipient_pubkey, 0x02).unwrap();
        let conversation_key =
            derive_nip44_conversation_key(&sender_secret, &recipient_public_key).unwrap();
        assert_eq!(
            hex::encode(conversation_key),
            "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"
        );

        let mut nonce = [0u8; 32];
        nonce[31] = 1;
        let payload =
            nip44_encrypt_with_nonce("a", &recipient_pubkey, &sender_secret, &nonce).unwrap();
        assert_eq!(
            payload,
            "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"
        );

        let sender_pubkey = xonly_pubkey_from_secret(&sender_secret);
        let plaintext = nip44_decrypt(&payload, &sender_pubkey, &recipient_secret).unwrap();
        assert_eq!(plaintext, "a");

        let random_payload = nip44_encrypt("hello", &recipient_pubkey, &sender_secret).unwrap();
        let random_plaintext =
            nip44_decrypt(&random_payload, &sender_pubkey, &recipient_secret).unwrap();
        assert_eq!(random_plaintext, "hello");
    }

    #[test]
    fn legacy_nip44_encrypts_and_decrypts_v2_payload() {
        let sender_secret = SecretKey::from_slice(
            &hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
        )
        .unwrap();
        let recipient_secret = SecretKey::from_slice(
            &hex::decode("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap(),
        )
        .unwrap();
        let recipient_pubkey = xonly_pubkey_from_secret(&recipient_secret);
        let sender_pubkey = xonly_pubkey_from_secret(&sender_secret);
        let nonce = [3u8; 24];

        let payload =
            legacy_nip44_encrypt_with_nonce("hello", &recipient_pubkey, &sender_secret, &nonce)
                .unwrap();

        assert!(payload.starts_with("v2:"));
        assert_eq!(
            nip44_decrypt(&payload, &sender_pubkey, &recipient_secret).unwrap(),
            "hello"
        );
    }

    #[test]
    fn creates_and_decrypts_geohash_dm_event() {
        let sender_seed = vec![7u8; 32];
        let recipient_seed = vec![9u8; 32];
        let recipient_secret = derive_secret_key(&recipient_seed, "ws").unwrap();
        let recipient_pubkey = xonly_pubkey_from_secret(&recipient_secret);

        let event = create_private_message_event(
            &sender_seed,
            "ws",
            &recipient_pubkey,
            "private hello",
            "0102030405060708",
            "c666",
            "msg-1",
        )
        .unwrap();

        assert_eq!(event.kind, GEOHASH_DM_KIND);
        assert!(event.content.starts_with("v2:"));
        assert!(event_has_tag_value(&event, "p", &recipient_pubkey));
        assert_eq!(event.sig.len(), 128);

        let sender_pubkey =
            xonly_pubkey_from_secret(&derive_secret_key(&sender_seed, "ws").unwrap());
        let seal_json = nip44_decrypt(&event.content, &event.pubkey, &recipient_secret).unwrap();
        let seal: Nip17Event = serde_json::from_str(&seal_json).unwrap();
        assert_ne!(seal.pubkey, sender_pubkey);
        let rumor_json = nip44_decrypt(&seal.content, &seal.pubkey, &recipient_secret).unwrap();
        let rumor: Nip17Event = serde_json::from_str(&rumor_json).unwrap();
        assert_eq!(rumor.pubkey, sender_pubkey);

        let decoded = decrypt_private_message(&event, &recipient_secret)
            .and_then(decode_bitchat_dm_content)
            .unwrap();
        assert_eq!(
            decoded.kind,
            DecodedPrivateMessageKind::Text {
                message_id: "msg-1".to_string(),
                content: "private hello".to_string()
            }
        );
        assert_eq!(decoded.sender_nickname.as_deref(), Some("c666"));
        assert_eq!(decoded.sender_pubkey, sender_pubkey);
    }
}
