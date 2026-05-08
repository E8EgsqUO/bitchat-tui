use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key as XChaChaKey, XChaCha20Poly1305, XNonce};
use chrono::{Local, TimeZone};
use futures_util::future::join_all;
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
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
const RECONNECT_DELAY_SECONDS: u64 = 10;
const CONNECT_TIMEOUT_SECONDS: u64 = 8;
const PUBLISH_TIMEOUT_SECONDS: u64 = 8;

const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://offchain.pub",
    "wss://nostr21.com",
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
                people_by_pubkey: Mutex::new(HashMap::new()),
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

    pub async fn send_private_message(
        &self,
        channel: &str,
        recipient_pubkey: &str,
        content: &str,
        sender_peer_id: &str,
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
        )?;
        let event_id = event.id.clone();

        let relays = dm_relays();
        write_nostr_debug_log(&format!(
            "dm publish start: geohash=#{}, recipient={}, relays={}",
            geohash,
            &recipient_pubkey[..recipient_pubkey.len().min(8)],
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
        let total_count = publish_results.len();
        for (relay, result) in publish_results {
            match result {
                Ok(()) => sent_count += 1,
                Err(e) => write_nostr_debug_log(&format!(
                    "dm publish failed: relay={}, event={}, error={}",
                    relay, event_id, e
                )),
            }
        }
        write_nostr_debug_log(&format!(
            "dm publish result: geohash=#{}, event={}, sent={}, total={}",
            geohash, event_id, sent_count, total_count
        ));

        if sent_count == 0 {
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
        },
        {
            "kinds": [1059],
            "#p": [local_pubkey],
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
    if event.kind == 1059 {
        handle_private_relay_event(inner, channel, local_pubkey, local_secret, &event).await;
        return;
    }

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

    inner
        .people_by_pubkey
        .lock()
        .await
        .insert(event.pubkey.clone(), sender.clone());

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
    let _ = inner
        .ui_tx
        .send(format!(
            "__GEO_PERSON__:{}:{}:{}",
            channel, sender, event.pubkey
        ))
        .await;
    let _ = inner.ui_tx.send(structured).await;
}

async fn handle_private_relay_event(
    inner: &Arc<NostrGeoInner>,
    channel: &str,
    local_pubkey: &str,
    local_secret: &SecretKey,
    event: &NostrEvent,
) {
    if event.pubkey == local_pubkey || !event_has_tag_value(event, "p", local_pubkey) {
        return;
    }

    let mut seen = inner.seen_event_ids.lock().await;
    if !seen.insert(event.id.clone()) {
        return;
    }
    drop(seen);

    let (content, sender_pubkey, timestamp) =
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

    let sender = inner
        .people_by_pubkey
        .lock()
        .await
        .get(&sender_pubkey)
        .cloned()
        .unwrap_or_else(|| format!("npub{}", sender_pubkey.chars().take(8).collect::<String>()));

    let timestamp = Local
        .timestamp_opt(timestamp, 0)
        .single()
        .unwrap_or_else(Local::now);
    let structured = format!(
        "__GEO_DM__:{}:{}:{}:{}:{}",
        channel,
        sender,
        sender_pubkey,
        timestamp.format("%H%M"),
        content
    );
    write_nostr_debug_log(&format!(
        "received geohash dm: channel={}, sender={}, event={}",
        channel, sender, event.id
    ));
    let _ = inner.ui_tx.send(structured).await;
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
    Ok(())
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

fn create_private_message_event(
    identity_seed: &[u8],
    geohash: &str,
    recipient_pubkey: &str,
    content: &str,
    sender_peer_id: &str,
) -> Result<NostrEvent, String> {
    let local_secret = derive_secret_key(identity_seed, geohash)?;
    let local_pubkey = xonly_pubkey_from_secret(&local_secret);
    let embedded = create_embedded_bitchat_dm(content, sender_peer_id)?;

    let rumor = Nip17Event {
        id: String::new(),
        pubkey: local_pubkey,
        created_at: Local::now().timestamp(),
        kind: 14,
        tags: Vec::new(),
        content: embedded,
        sig: None,
    };

    let seal_key = random_secret_key();
    let seal_json = serde_json::to_string(&rumor).map_err(|e| e.to_string())?;
    let encrypted_seal = nip44_encrypt(&seal_json, recipient_pubkey, &seal_key)?;
    let seal = sign_nip17_event(
        Nip17Event {
            id: String::new(),
            pubkey: xonly_pubkey_from_secret(&seal_key),
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
    let encrypted_wrap = nip44_encrypt(&seal_json, recipient_pubkey, &wrap_key)?;
    let gift_wrap = sign_nip17_event(
        Nip17Event {
            id: String::new(),
            pubkey: xonly_pubkey_from_secret(&wrap_key),
            created_at: randomized_timestamp(),
            kind: 1059,
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
) -> Result<(String, String, i64), String> {
    let seal_json = nip44_decrypt(&gift_wrap.content, &gift_wrap.pubkey, local_secret)?;
    let seal: Nip17Event = serde_json::from_str(&seal_json).map_err(|e| e.to_string())?;
    let rumor_json = nip44_decrypt(&seal.content, &seal.pubkey, local_secret)?;
    let rumor: Nip17Event = serde_json::from_str(&rumor_json).map_err(|e| e.to_string())?;
    Ok((rumor.content, rumor.pubkey, rumor.created_at))
}

fn decode_bitchat_dm_content(
    decoded: (String, String, i64),
) -> Result<(String, String, i64), String> {
    let (content, sender_pubkey, timestamp) = decoded;
    let Some(encoded) = content.strip_prefix("bitchat1:") else {
        return Ok((content, sender_pubkey, timestamp));
    };

    let packet_bytes = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|e| e.to_string())?;
    let packet =
        crate::packet_parser::parse_bitchat_packet(&packet_bytes).map_err(|e| e.to_string())?;
    if packet.msg_type != crate::data_structures::MessageType::NoiseEncrypted {
        return Err("Embedded BitChat packet is not a private message".to_string());
    }
    let Some((&payload_type, private_payload)) = packet.payload.split_first() else {
        return Err("Embedded private payload is empty".to_string());
    };
    if payload_type != crate::payload_handling::NOISE_PAYLOAD_PRIVATE_MESSAGE {
        return Err("Embedded private payload has unsupported type".to_string());
    }
    let (_, private_content) =
        crate::payload_handling::parse_private_noise_payload(private_payload)
            .map_err(|e| e.to_string())?;
    Ok((private_content, sender_pubkey, timestamp))
}

fn create_embedded_bitchat_dm(content: &str, sender_peer_id: &str) -> Result<String, String> {
    let message_id = Uuid::new_v4().to_string();
    let payload = crate::payload_handling::create_private_noise_payload(&message_id, content)
        .map_err(|e| e.to_string())?;
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
    let public_key = public_key_from_xonly(recipient_pubkey, 0x02)?;
    let shared_secret = derive_shared_secret_compressed(sender_key, &public_key)?;
    let key = derive_nip44_key(&shared_secret)?;

    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(XChaChaKey::from_slice(&key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|_| "NIP-44 encryption failed".to_string())?;

    let mut combined = Vec::with_capacity(nonce.len() + ciphertext.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);
    Ok(format!("v2:{}", URL_SAFE_NO_PAD.encode(combined)))
}

fn nip44_decrypt(
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
                if let Ok(key) = derive_nip44_key(&shared_secret) {
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

fn derive_nip44_key(shared_secret: &[u8]) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"nip44-v2", &mut key)
        .map_err(|_| "NIP-44 HKDF expansion failed".to_string())?;
    Ok(key)
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
    let offset = rand::thread_rng().gen_range(-900i64..=900i64);
    Local::now().timestamp().saturating_add(offset)
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
    default_relays()
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
        )
        .unwrap();

        assert_eq!(event.kind, 1059);
        assert!(event_has_tag_value(&event, "p", &recipient_pubkey));
        assert_eq!(event.sig.len(), 128);

        let (content, sender_pubkey, _) = decrypt_private_message(&event, &recipient_secret)
            .and_then(decode_bitchat_dm_content)
            .unwrap();
        assert_eq!(content, "private hello");
        assert_eq!(
            sender_pubkey,
            xonly_pubkey_from_secret(&derive_secret_key(&sender_seed, "ws").unwrap())
        );
    }
}
