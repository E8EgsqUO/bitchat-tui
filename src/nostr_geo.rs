use chrono::{Local, TimeZone};
use futures_util::future::join_all;
use futures_util::{SinkExt, StreamExt};
use secp256k1::{Keypair, Message as SecpMessage, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use uuid::Uuid;

const GEO_RELAY_CSV_URL: &str =
    "https://raw.githubusercontent.com/permissionlesstech/georelays/main/nostr_relays.csv";
const GEOHASH_ALPHABET: &str = "0123456789bcdefghjkmnpqrstuvwxyz";
const SUBSCRIBE_SINCE_SECONDS: i64 = 300;
const RECONNECT_DELAY_SECONDS: u64 = 10;
const PUBLISH_TIMEOUT_SECONDS: u64 = 8;

const DEFAULT_RELAYS: &[&str] = &[
    "wss://bitchat.nostr1.com",
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://relay.wellorder.net",
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

#[derive(Clone)]
struct RelayEntry {
    host: String,
    lat: f64,
    lon: f64,
}

pub fn is_geohash_channel(channel: &str) -> bool {
    normalize_geohash(channel).is_some()
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
        write_nostr_debug_log(&format!(
            "joined geohash #{} relays={}",
            geohash,
            relays.join(",")
        ));
        self.inner
            .relays_by_geohash
            .lock()
            .await
            .insert(geohash.clone(), relays.clone());

        let pubkey = derive_xonly_pubkey(&self.inner.identity_seed, &geohash)?;
        for relay in relays.clone() {
            let inner = self.inner.clone();
            let channel = format!("#{}", geohash);
            let geohash = geohash.clone();
            let pubkey = pubkey.clone();
            tokio::spawn(async move {
                subscribe_loop(inner, relay, channel, geohash, pubkey).await;
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
        for (relay, result) in publish_results {
            match result {
                Ok(()) => sent_count += 1,
                Err(e) => write_nostr_debug_log(&format!(
                    "publish failed: relay={}, event={}, error={}",
                    relay, event_id, e
                )),
            }
        }
        write_nostr_debug_log(&format!(
            "publish result: geohash=#{}, event={}, sent={}, total={}",
            geohash, event_id, sent_count, total_count
        ));

        if sent_count == 0 {
            Err("Failed to publish geohash message to any Nostr relay".to_string())
        } else {
            Ok(())
        }
    }
}

async fn subscribe_loop(
    inner: Arc<NostrGeoInner>,
    relay: String,
    channel: String,
    geohash: String,
    local_pubkey: String,
) {
    loop {
        if let Err(e) =
            subscribe_once(inner.clone(), &relay, &channel, &geohash, &local_pubkey).await
        {
            write_nostr_debug_log(&format!(
                "subscribe error: relay={}, geohash={}, error={}",
                relay, geohash, e
            ));
        }
        tokio::time::sleep(Duration::from_secs(RECONNECT_DELAY_SECONDS)).await;
    }
}

async fn subscribe_once(
    inner: Arc<NostrGeoInner>,
    relay: &str,
    channel: &str,
    geohash: &str,
    local_pubkey: &str,
) -> Result<(), String> {
    let (ws_stream, _) = connect_async(relay).await.map_err(|e| e.to_string())?;
    let (mut write, mut read) = ws_stream.split();
    let sub_id = format!("bitchat-tui-{}-{}", geohash, Uuid::new_v4());
    let since = Local::now()
        .timestamp()
        .saturating_sub(SUBSCRIBE_SINCE_SECONDS);
    let req = json!([
        "REQ",
        sub_id,
        {
            "kinds": [20000],
            "#g": [geohash],
            "since": since
        }
    ]);

    write
        .send(WsMessage::Text(req.to_string()))
        .await
        .map_err(|e| e.to_string())?;
    write_nostr_debug_log(&format!(
        "subscribe connected: relay={}, geohash=#{}, since={}",
        relay, geohash, since
    ));

    while let Some(message) = read.next().await {
        let message = message.map_err(|e| e.to_string())?;
        if let WsMessage::Text(text) = message {
            handle_relay_text(&inner, channel, geohash, local_pubkey, &text).await;
        }
    }

    Ok(())
}

async fn handle_relay_text(
    inner: &Arc<NostrGeoInner>,
    channel: &str,
    geohash: &str,
    local_pubkey: &str,
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
    if event.kind != 20000 || event.pubkey == local_pubkey || !event_has_geohash(&event, geohash) {
        return;
    }

    let mut seen = inner.seen_event_ids.lock().await;
    if !seen.insert(event.id.clone()) {
        return;
    }
    drop(seen);

    let sender = event
        .tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some("n") && tag.len() >= 2)
        .and_then(|tag| tag.get(1))
        .map(|nick| sanitize_display_field(nick))
        .unwrap_or_else(|| format!("npub{}", event.pubkey.chars().take(8).collect::<String>()));

    let timestamp = Local
        .timestamp_opt(event.created_at, 0)
        .single()
        .unwrap_or_else(Local::now);
    let structured = format!(
        "__CHANNEL__:{}:{}:{}:{}",
        channel,
        sender,
        timestamp.format("%H%M"),
        event.content
    );
    write_nostr_debug_log(&format!(
        "received event: geohash=#{}, sender={}, event={}",
        geohash, sender, event.id
    ));
    let _ = inner.ui_tx.send(structured).await;
}

fn event_has_geohash(event: &NostrEvent, geohash: &str) -> bool {
    event.tags.iter().any(|tag| {
        tag.first().map(String::as_str) == Some("g")
            && tag.get(1).map(String::as_str) == Some(geohash)
    })
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
    let (mut ws_stream, _) = connect_async(relay).await.map_err(|e| e.to_string())?;
    let msg = json!(["EVENT", event]).to_string();
    ws_stream
        .send(WsMessage::Text(msg))
        .await
        .map_err(|e| e.to_string())?;
    let _ = tokio::time::timeout(Duration::from_secs(2), ws_stream.next()).await;
    let _ = ws_stream.close(None).await;
    Ok(())
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
    let kind = 20000;
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

fn derive_xonly_pubkey(identity_seed: &[u8], geohash: &str) -> Result<String, String> {
    let secp = Secp256k1::new();
    let secret_key = derive_secret_key(identity_seed, geohash)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    Ok(hex::encode(xonly.serialize()))
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
        assert_eq!(event.kind, 20000);
        assert!(event_has_geohash(&event, "ws"));
        assert_eq!(event.pubkey.len(), 64);
        assert_eq!(event.sig.len(), 128);
    }
}
