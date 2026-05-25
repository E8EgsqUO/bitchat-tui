use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use secp256k1::{Keypair, Message as SecpMessage, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;

const DEFAULT_UPLOAD_PROVIDER: &str = "blossom";
const BLOSSOM_NOSTR_BUILD_UPLOAD: &str = "https://blossom.nostr.build/upload";
const NOSTR_MEDIA_UPLOAD: &str = "https://nostrmedia.com/upload";
const CATBOX_UPLOAD: &str = "https://catbox.moe/user/api.php";
const ZEROX0_UPLOAD: &str = "https://0x0.st";
const DEFAULT_UPLOAD_FIELD: &str = "file";
const DEFAULT_UPLOAD_TIMEOUT_SECS: u64 = 45;
const DEFAULT_UPLOAD_MAX_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) struct UploadResult {
    pub(crate) url: String,
    pub(crate) file_name: String,
    pub(crate) file_size: u64,
}

#[derive(Clone, Copy, Debug)]
enum UploadMethod {
    RawPut,
    MultipartPost,
}

#[derive(Clone, Copy, Debug)]
enum AuthMode {
    None,
    Blossom24242,
}

#[derive(Clone, Debug)]
struct UploadTarget {
    name: &'static str,
    endpoint: String,
    method: UploadMethod,
    file_field: String,
    extra_fields: Vec<(String, String)>,
    auth_mode: AuthMode,
}

#[derive(Serialize)]
struct NostrAuthEvent {
    id: String,
    pubkey: String,
    created_at: i64,
    kind: i64,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

pub(crate) async fn upload_file(
    path: &Path,
    nostr_identity_seed: &[u8],
) -> Result<UploadResult, String> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|e| format!("cannot read '{}': {}", path.display(), e))?;
    if !metadata.is_file() {
        return Err(format!("'{}' is not a regular file", path.display()));
    }

    let file_size = metadata.len();
    if file_size == 0 {
        return Err("empty files cannot be uploaded".to_string());
    }
    let max_bytes = env_u64("BITCHAT_UPLOAD_MAX_BYTES", DEFAULT_UPLOAD_MAX_BYTES);
    if file_size > max_bytes {
        return Err(format!(
            "file is too large: {} bytes (limit {} bytes, set BITCHAT_UPLOAD_MAX_BYTES to change)",
            file_size, max_bytes
        ));
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("upload.bin")
        .to_string();
    let mime_type = infer_mime_type(path);
    if !is_media_mime_type(mime_type) {
        return Err(format!(
            "only media files are supported by /upload (images/audio/video). got MIME '{}' for '{}'",
            mime_type,
            file_name
        ));
    }
    let file_bytes = tokio::fs::read(path)
        .await
        .map_err(|e| format!("failed to read '{}': {}", path.display(), e))?;
    let timeout = Duration::from_secs(env_u64(
        "BITCHAT_UPLOAD_TIMEOUT_SECS",
        DEFAULT_UPLOAD_TIMEOUT_SECS,
    ));

    let targets = upload_targets();
    let mut errors = Vec::new();
    for target in targets {
        match upload_to_target(
            &target,
            timeout,
            &file_name,
            path,
            &file_bytes,
            nostr_identity_seed,
        )
        .await
        {
            Ok(url) => {
                return Ok(UploadResult {
                    url,
                    file_name,
                    file_size,
                })
            }
            Err(err) => {
                errors.push(format!("{}: {}", target.name, err));
            }
        }
    }

    Err(errors.join(" | "))
}

async fn upload_to_target(
    target: &UploadTarget,
    timeout: Duration,
    file_name: &str,
    path: &Path,
    file_bytes: &[u8],
    nostr_identity_seed: &[u8],
) -> Result<String, String> {
    let mime_type = infer_mime_type(path);
    let sha256_hex = hex::encode(Sha256::digest(file_bytes));
    let boundary = format!(
        "bitchat-tui-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );

    let client = build_upload_client(timeout)?;

    let mut request = match target.method {
        UploadMethod::RawPut => client.put(&target.endpoint).body(file_bytes.to_vec()),
        UploadMethod::MultipartPost => {
            let body = build_multipart_body(
                &boundary,
                &target.file_field,
                file_name,
                mime_type,
                file_bytes,
                &target.extra_fields,
            );
            client
                .post(&target.endpoint)
                .header(
                    reqwest::header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={}", boundary),
                )
                .body(body)
        }
    };

    if let AuthMode::Blossom24242 = target.auth_mode {
        let auth = build_blossom_authorization(
            nostr_identity_seed,
            &sha256_hex,
            target.endpoint.as_str(),
        )?;
        request = request.header(reqwest::header::AUTHORIZATION, auth);
        request = request.header("X-SHA-256", sha256_hex.clone());
    }

    if let UploadMethod::RawPut = target.method {
        request = request.header(reqwest::header::CONTENT_TYPE, mime_type);
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("request failed: {} ({:?})", e, e))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("failed to read response body: {}", e))?;

    if !status.is_success() {
        if matches!(target.method, UploadMethod::RawPut)
            && status == reqwest::StatusCode::BAD_REQUEST
        {
            if let Some(expected_type) = parse_expected_content_type(&body) {
                if !expected_type.eq_ignore_ascii_case(mime_type) {
                    let retry_request = client
                        .put(&target.endpoint)
                        .header(reqwest::header::CONTENT_TYPE, expected_type.as_str())
                        .header("X-SHA-256", sha256_hex.clone())
                        .header(
                            reqwest::header::AUTHORIZATION,
                            build_blossom_authorization(
                                nostr_identity_seed,
                                &sha256_hex,
                                target.endpoint.as_str(),
                            )?,
                        )
                        .body(file_bytes.to_vec());
                    let retry_response = retry_request
                        .send()
                        .await
                        .map_err(|e| format!("retry request failed: {} ({:?})", e, e))?;
                    let retry_status = retry_response.status();
                    let retry_body = retry_response
                        .text()
                        .await
                        .map_err(|e| format!("failed to read retry response body: {}", e))?;
                    if retry_status.is_success() {
                        return extract_url_from_response(&retry_body).ok_or_else(|| {
                            format!(
                                "{} -> response did not contain a URL: {}",
                                target.endpoint,
                                retry_body.trim()
                            )
                        });
                    }
                }
            }
        }
        let snippet = body.lines().next().unwrap_or("").trim();
        return Err(if snippet.is_empty() {
            format!("{} -> HTTP {}", target.endpoint, status)
        } else {
            format!("{} -> HTTP {}: {}", target.endpoint, status, snippet)
        });
    }

    extract_url_from_response(&body).ok_or_else(|| {
        format!(
            "{} -> response did not contain a URL: {}",
            target.endpoint,
            body.trim()
        )
    })
}

fn is_media_mime_type(mime: &str) -> bool {
    mime.starts_with("image/") || mime.starts_with("audio/") || mime.starts_with("video/")
}

fn build_upload_client(timeout: Duration) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Some(proxy_url) = upload_proxy() {
        let proxy = reqwest::Proxy::all(&proxy_url)
            .map_err(|e| format!("invalid upload proxy '{}': {}", proxy_url, e))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| format!("failed to build upload client: {}", e))
}

fn upload_proxy() -> Option<String> {
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

fn build_multipart_body(
    boundary: &str,
    field_name: &str,
    file_name: &str,
    mime_type: &str,
    file_bytes: &[u8],
    extra_fields: &[(String, String)],
) -> Vec<u8> {
    let sanitized_field = field_name.replace('"', "");
    let sanitized_name = file_name.replace('"', "_");
    let mut body = Vec::with_capacity(file_bytes.len() + 1024);
    for (key, value) in extra_fields {
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{}\"\r\n\r\n",
                key.replace('"', "")
            )
            .as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
            sanitized_field, sanitized_name
        )
        .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {}\r\n\r\n", mime_type).as_bytes());
    body.extend_from_slice(file_bytes);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    body
}

fn extract_url_from_response(body: &str) -> Option<String> {
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
            return Some(trimmed.to_string());
        }
    }

    let json: Value = serde_json::from_str(body).ok()?;
    if let Some(url) = json.as_str() {
        if url.starts_with("https://") || url.starts_with("http://") {
            return Some(url.to_string());
        }
    }
    if let Some(url) = json.get("url").and_then(Value::as_str) {
        if url.starts_with("https://") || url.starts_with("http://") {
            return Some(url.to_string());
        }
    }
    if let Some(url) = json
        .get("data")
        .and_then(|v| v.get("url"))
        .and_then(Value::as_str)
    {
        if url.starts_with("https://") || url.starts_with("http://") {
            return Some(url.to_string());
        }
    }
    if let Some(tags) = json.get("tags").and_then(Value::as_array) {
        for tag in tags {
            let Some(arr) = tag.as_array() else {
                continue;
            };
            if arr.len() < 2 {
                continue;
            }
            if arr.first().and_then(Value::as_str) != Some("url") {
                continue;
            }
            let Some(url) = arr.get(1).and_then(Value::as_str) else {
                continue;
            };
            if url.starts_with("https://") || url.starts_with("http://") {
                return Some(url.to_string());
            }
        }
    }
    None
}

fn build_blossom_authorization(
    identity_seed: &[u8],
    sha256_hex: &str,
    endpoint: &str,
) -> Result<String, String> {
    let event = create_blossom_auth_event(identity_seed, sha256_hex, endpoint)?;
    let json = serde_json::to_vec(&event).map_err(|e| e.to_string())?;
    let encoded = URL_SAFE_NO_PAD.encode(json);
    Ok(format!("Nostr {}", encoded))
}

fn create_blossom_auth_event(
    identity_seed: &[u8],
    sha256_hex: &str,
    endpoint: &str,
) -> Result<NostrAuthEvent, String> {
    let secret_key = derive_upload_secret_key(identity_seed)?;
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    let pubkey = hex::encode(xonly.serialize());
    let created_at = chrono::Utc::now().timestamp();
    let expires = created_at + 600;
    let mut tags = vec![
        vec!["t".to_string(), "upload".to_string()],
        vec!["x".to_string(), sha256_hex.to_string()],
        vec!["expiration".to_string(), expires.to_string()],
    ];
    if let Some(domain) = endpoint_domain(endpoint) {
        tags.push(vec!["server".to_string(), domain]);
    }
    let content = "Uploading blob with SHA-256 hash".to_string();
    let kind = 24242i64;
    let id = calculate_event_id(&pubkey, created_at, kind, &tags, &content)?;
    let digest = hex::decode(&id).map_err(|e| e.to_string())?;
    let msg = SecpMessage::from_digest_slice(&digest).map_err(|e| e.to_string())?;
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair).to_string();

    Ok(NostrAuthEvent {
        id,
        pubkey,
        created_at,
        kind,
        tags,
        content,
        sig,
    })
}

fn endpoint_domain(endpoint: &str) -> Option<String> {
    let parsed = url::Url::parse(endpoint).ok()?;
    parsed.host_str().map(|host| host.to_ascii_lowercase())
}

fn parse_expected_content_type(body: &str) -> Option<String> {
    let marker = "expected ";
    let pos = body.find(marker)?;
    let rest = &body[pos + marker.len()..];
    let ctype = rest
        .split(|ch: char| ch.is_whitespace() || ch == '"' || ch == '\'' || ch == ',' || ch == ';')
        .find(|token| token.contains('/'))?;
    Some(ctype.trim().to_string())
}

fn calculate_event_id(
    pubkey: &str,
    created_at: i64,
    kind: i64,
    tags: &[Vec<String>],
    content: &str,
) -> Result<String, String> {
    let serialized = serde_json::to_vec(&serde_json::json!([
        0, pubkey, created_at, kind, tags, content
    ]))
    .map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(&serialized)))
}

fn derive_upload_secret_key(identity_seed: &[u8]) -> Result<SecretKey, String> {
    if identity_seed.is_empty() {
        return Err("Missing persistent Nostr identity seed for upload auth".to_string());
    }

    for counter in 0u32..1000 {
        let mut hasher = Sha256::new();
        hasher.update(b"bitchat-tui-nostr-upload-v1");
        hasher.update(identity_seed);
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();
        if let Ok(secret) = SecretKey::from_slice(&digest) {
            return Ok(secret);
        }
    }

    Err("Failed to derive Nostr upload identity".to_string())
}

fn upload_targets() -> Vec<UploadTarget> {
    let custom_endpoint = std::env::var("BITCHAT_UPLOAD_ENDPOINT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    if let Some(endpoint) = custom_endpoint {
        let file_field = std::env::var("BITCHAT_UPLOAD_FIELD")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_UPLOAD_FIELD.to_string());
        return vec![UploadTarget {
            name: "custom",
            endpoint,
            method: UploadMethod::MultipartPost,
            file_field,
            extra_fields: Vec::new(),
            auth_mode: AuthMode::None,
        }];
    }

    let provider = std::env::var("BITCHAT_UPLOAD_PROVIDER")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_UPLOAD_PROVIDER.to_string());

    match provider.as_str() {
        "blossom" | "blossom_nostr_build" | "nostr.build" => vec![blossom_nostr_build_target()],
        "nostrmedia" | "nostr_media" => vec![nostrmedia_target()],
        "catbox" => vec![catbox_target()],
        "0x0" | "0x0st" | "zero" | "zerox0" => vec![zerox0_target()],
        "auto" => vec![
            blossom_nostr_build_target(),
            nostrmedia_target(),
            catbox_target(),
            zerox0_target(),
        ],
        _ => vec![blossom_nostr_build_target()],
    }
}

fn blossom_nostr_build_target() -> UploadTarget {
    UploadTarget {
        name: "blossom.nostr.build",
        endpoint: BLOSSOM_NOSTR_BUILD_UPLOAD.to_string(),
        method: UploadMethod::RawPut,
        file_field: DEFAULT_UPLOAD_FIELD.to_string(),
        extra_fields: Vec::new(),
        auth_mode: AuthMode::Blossom24242,
    }
}

fn nostrmedia_target() -> UploadTarget {
    UploadTarget {
        name: "nostrmedia.com",
        endpoint: NOSTR_MEDIA_UPLOAD.to_string(),
        method: UploadMethod::MultipartPost,
        file_field: "file".to_string(),
        extra_fields: Vec::new(),
        auth_mode: AuthMode::Blossom24242,
    }
}

fn catbox_target() -> UploadTarget {
    let mut extra_fields = vec![("reqtype".to_string(), "fileupload".to_string())];
    if let Ok(userhash) = std::env::var("BITCHAT_UPLOAD_USERHASH") {
        let trimmed = userhash.trim();
        if !trimmed.is_empty() {
            extra_fields.push(("userhash".to_string(), trimmed.to_string()));
        }
    }
    UploadTarget {
        name: "catbox.moe",
        endpoint: CATBOX_UPLOAD.to_string(),
        method: UploadMethod::MultipartPost,
        file_field: "fileToUpload".to_string(),
        extra_fields,
        auth_mode: AuthMode::None,
    }
}

fn zerox0_target() -> UploadTarget {
    UploadTarget {
        name: "0x0.st",
        endpoint: ZEROX0_UPLOAD.to_string(),
        method: UploadMethod::MultipartPost,
        file_field: DEFAULT_UPLOAD_FIELD.to_string(),
        extra_fields: Vec::new(),
        auth_mode: AuthMode::None,
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
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
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "pdf" => "application/pdf",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
