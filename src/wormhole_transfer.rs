use magic_wormhole::{AppID, Code, MailboxConnection, Wormhole, transfer, transit};
use std::path::{Path, PathBuf};
use tokio::fs::{self, OpenOptions};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

const BITCHAT_TUI_WORMHOLE_APP_ID: &str = "bitchat-tui/geohash-file-transfer";
const WORMHOLE_CODE_WORDS: usize = 2;

pub struct OutgoingTransfer {
    pub code: String,
    pub file_name: String,
    pub file_size: u64,
    path: PathBuf,
    mailbox: MailboxConnection<transfer::AppVersion>,
}

pub async fn prepare_send(
    path: impl AsRef<Path>,
    file_name: String,
    file_size: u64,
) -> Result<OutgoingTransfer, String> {
    let mailbox = MailboxConnection::create(app_config(), WORMHOLE_CODE_WORDS)
        .await
        .map_err(|e| format!("failed to create wormhole mailbox: {}", e))?;
    let code = mailbox.code().to_string();

    Ok(OutgoingTransfer {
        code,
        file_name,
        file_size,
        path: path.as_ref().to_path_buf(),
        mailbox,
    })
}

pub async fn send_file(offer: OutgoingTransfer) -> Result<(), String> {
    let wormhole = Wormhole::connect(offer.mailbox)
        .await
        .map_err(|e| format!("failed to connect wormhole sender: {}", e))?;
    let mut file = tokio::fs::File::open(&offer.path)
        .await
        .map_err(|e| format!("failed to open '{}': {}", offer.path.display(), e))?
        .compat();

    transfer::send_file(
        wormhole,
        default_relay_hints()?,
        &mut file,
        offer.file_name,
        offer.file_size,
        transit::Abilities::ALL,
        |_info| {},
        |_sent, _total| {},
        std::future::pending::<()>(),
    )
    .await
    .map_err(|e| format!("wormhole send failed: {}", e))
}

pub async fn receive_file(code: &str) -> Result<PathBuf, String> {
    let code: Code = code
        .parse()
        .map_err(|e| format!("invalid wormhole code '{}': {}", code, e))?;
    let mailbox = MailboxConnection::connect(app_config(), code, false)
        .await
        .map_err(|e| format!("failed to connect wormhole mailbox: {}", e))?;
    let wormhole = Wormhole::connect(mailbox)
        .await
        .map_err(|e| format!("failed to connect wormhole receiver: {}", e))?;

    let request = transfer::request_file(
        wormhole,
        default_relay_hints()?,
        transit::Abilities::ALL,
        std::future::pending::<()>(),
    )
    .await
    .map_err(|e| format!("failed to request wormhole file: {}", e))?
    .ok_or_else(|| "wormhole receive was cancelled".to_string())?;

    let destination = allocate_destination_path(&request.file_name()).await?;
    let mut output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&destination)
        .await
        .map_err(|e| format!("failed to create '{}': {}", destination.display(), e))?
        .compat_write();

    request
        .accept(
            |_info| {},
            |_received, _total| {},
            &mut output,
            std::future::pending::<()>(),
        )
        .await
        .map_err(|e| format!("wormhole receive failed: {}", e))?;

    Ok(destination)
}

fn app_config() -> magic_wormhole::AppConfig<transfer::AppVersion> {
    transfer::APP_CONFIG.id(AppID::new(BITCHAT_TUI_WORMHOLE_APP_ID))
}

fn default_relay_hints() -> Result<Vec<transit::RelayHint>, String> {
    let relay = transit::RelayHint::from_urls(
        None,
        [transit::DEFAULT_RELAY_SERVER
            .parse()
            .map_err(|e| format!("invalid default wormhole relay URL: {}", e))?],
    )
    .map_err(|e| format!("invalid default wormhole relay hint: {}", e))?;
    Ok(vec![relay])
}

async fn allocate_destination_path(preferred_name: &str) -> Result<PathBuf, String> {
    let base_dir = std::env::current_dir()
        .map_err(|e| format!("failed to determine working directory: {}", e))?
        .join("received_files")
        .join("files")
        .join("incoming");
    fs::create_dir_all(&base_dir)
        .await
        .map_err(|e| format!("failed to create '{}': {}", base_dir.display(), e))?;

    let file_name = sanitize_file_name(preferred_name);
    Ok(unique_path(&base_dir, &file_name))
}

fn sanitize_file_name(preferred_name: &str) -> String {
    let fallback = format!(
        "file_{}",
        chrono::Local::now().format("%Y%m%d_%H%M%S")
    );
    let base_name = Path::new(preferred_name)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&fallback);

    let mut cleaned = base_name
        .chars()
        .map(|ch| {
            if ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
            {
                '_'
            } else {
                ch
            }
        })
        .collect::<String>()
        .trim_matches(['.', ' '])
        .to_string();

    if cleaned.is_empty() {
        cleaned = fallback;
    }

    cleaned
}

fn unique_path(directory: &Path, file_name: &str) -> PathBuf {
    let mut candidate = directory.join(file_name);
    if !candidate.exists() {
        return candidate;
    }

    let stem = Path::new(file_name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let extension = Path::new(file_name).extension().and_then(|e| e.to_str());

    for index in 1..100 {
        let next_name = match extension {
            Some(ext) if !ext.is_empty() => format!("{} ({}).{}", stem, index, ext),
            _ => format!("{} ({})", stem, index),
        };
        candidate = directory.join(next_name);
        if !candidate.exists() {
            return candidate;
        }
    }

    directory.join(format!("{}_{}.dat", stem, uuid::Uuid::new_v4()))
}
