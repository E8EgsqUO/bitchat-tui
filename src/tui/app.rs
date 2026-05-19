// src/tui/app.rs

use chrono::{Local, TimeZone};
use regex::Regex;
use ratatui_image::{
    picker::{Picker, ProtocolType},
    protocol::StatefulProtocol,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::Instant;
use tui_input::Input;
use unicode_width::UnicodeWidthChar;

const GEOHASH_ACTIVE_WINDOW_SECONDS: i64 = crate::nostr_geo::PRESENCE_ACTIVE_WINDOW_SECONDS;
const COMPACT_FILE_NAME_MAX_CHARS: usize = 52;

pub fn bitchat_debug_enabled() -> bool {
    let Ok(raw) = std::env::var("BITCHAT_DEBUG") else {
        return false;
    };
    let normalized = raw.trim().to_ascii_lowercase();
    !(normalized.is_empty()
        || normalized == "0"
        || normalized == "false"
        || normalized == "off"
        || normalized == "no")
}

pub fn compact_file_message(file_name: &str) -> String {
    format!(
        "📎 {}",
        compact_file_name(file_name, COMPACT_FILE_NAME_MAX_CHARS)
    )
}

fn compact_file_name(file_name: &str, max_chars: usize) -> String {
    let char_count = file_name.chars().count();
    if char_count <= max_chars {
        return file_name.to_string();
    }

    if max_chars <= 3 {
        return "...".to_string();
    }

    let front_len = max_chars - 3;
    let mut truncated: String = file_name.chars().take(front_len).collect();
    truncated.push_str("...");
    truncated
}

#[derive(Debug, Clone)]
pub struct Message {
    pub sender: String,
    pub sender_pubkey: Option<String>,
    pub timestamp: String,
    pub timestamp_epoch: Option<i64>,
    pub content: String,
    pub is_self: bool,
    pub status: MessageStatus,
    pub local_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageStatus {
    None,
    Sending,
    Delivered,
    Read,
    Failed,
}

#[derive(Debug, Clone)]
pub struct PendingWormholeOffer {
    pub sender: String,
    pub code: String,
    pub file_name: String,
    pub file_size_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SidebarSection {
    Channels,
    People,
    Blocked,
    Settings,
}

pub struct SidebarMenuState {
    pub expanded: [bool; 5], // Public, Channels, People, Blocked, Settings
    pub public_selected: Option<bool>,
    pub channel_selected: Option<usize>,
    pub people_selected: Option<usize>,
    pub blocked_selected: Option<usize>,
}

impl SidebarMenuState {
    pub fn new() -> Self {
        Self {
            expanded: [true, true, true, true, true], // All sections expanded by default
            public_selected: Some(true),              // Default to public selected
            channel_selected: None, // No channel selected by default since public is selected
            people_selected: None,
            blocked_selected: None,
        }
    }

    pub fn toggle_expand(&mut self, section_index: usize) {
        if section_index < self.expanded.len() {
            self.expanded[section_index] = !self.expanded[section_index];
        }
    }
}

#[allow(dead_code)]
pub enum TuiPhase {
    Connecting,
    Connected,
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusArea {
    Sidebar,
    MainPanel,
    InputBox,
}

pub struct App {
    // UI state
    pub input: Input,
    pub phase: TuiPhase,
    pub should_quit: bool,
    pub focus_area: FocusArea,
    pub sidebar_flat_selected: usize,
    pub msg_scroll: usize,
    pub message_viewport_height: usize, // ADDED: To store the height of the message panel
    pub message_rendered_line_count: usize,
    pub unseen_divider_message_index: Option<usize>,
    pub unseen_divider_line_index: Option<usize>,

    // Data state for rendering
    pub nickname: String,
    #[allow(dead_code)]
    pub network_name: String,
    pub connected: bool,
    pub mesh_status: String,
    pub channels: Vec<String>,
    pub people: Vec<String>,
    pub mesh_people_peer_ids: HashMap<String, String>,
    pub geohash_people: HashMap<String, Vec<String>>,
    pub geohash_people_pubkeys: HashMap<String, HashMap<String, String>>,
    pub geohash_last_dm_sender: HashMap<String, String>,
    pub geohash_last_mention_sender: HashMap<String, String>,
    pub nostr_aliases: HashMap<String, String>,
    pub geohash_presence: HashMap<String, HashMap<String, i64>>,
    pub blocked: Vec<String>,

    // Message storage
    pub channel_messages: HashMap<String, Vec<Message>>,
    pub dm_messages: HashMap<String, Vec<Message>>,

    // Navigation and Popups
    pub sidebar_state: SidebarMenuState,
    pub popup_messages: Vec<String>,

    // To track current conversation for message routing and scroll reset
    pub current_conv: Option<(Option<String>, Option<String>)>, // (DM target, Channel name)

    // To signal when backend channel switch is needed
    pub pending_channel_switch: Option<String>,
    // To signal when backend DM switch is needed
    pub pending_dm_switch: Option<(String, String)>, // (nickname, peer_id)
    // To signal when backend nickname update is needed
    pub pending_nickname_update: Option<String>,
    // To signal when backend should retry connection
    pub pending_connection_retry: bool,
    // To signal when conversation should be cleared
    pub pending_clear_conversation: bool,
    pub pending_wormhole_offers: HashMap<String, PendingWormholeOffer>,

    // Unread message tracking
    pub unread_counts: HashMap<String, usize>, // Channel/DM name -> unread count
    pub last_read_messages: HashMap<String, usize>, // Channel/DM name -> last read message count

    // Popup state
    pub popup_active: bool,
    pub popup_input: Input,
    pub popup_title: String,
    pub messages_area_rect: Option<(u16, u16, u16, u16)>,
    pub message_first_visible_index: usize,
    pub message_line_copy_targets: Vec<Option<MessageLineCopyTarget>>,
    pub last_message_click: Option<MessageClickState>,
    pub copy_highlight: Option<CopyHighlightState>,
    pub image_preview: Option<ImagePreviewState>,
    pub image_preview_area_rect: Option<(u16, u16, u16, u16)>,
    pub image_picker: Picker,
    pub paste_keyburst_active: bool,
    pub last_input_char_event_at: Option<Instant>,
    pub input_char_burst_count: u16,
    pub transient_message_expirations: HashMap<String, Instant>,
    pub transient_message_seq: u64,
}

pub enum ImagePreviewRenderState {
    Ready(Box<dyn StatefulProtocol>),
    Failed(String),
}

pub struct ImagePreviewState {
    pub source_path: PathBuf,
    pub render_state: ImagePreviewRenderState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageLineCopyTarget {
    Message(usize),
    SenderLabel(String),
}

#[derive(Debug, Clone)]
pub struct MessageClickState {
    pub row: u16,
    pub kind: u8,
    pub target: MessageLineCopyTarget,
    pub conversation_key: String,
    pub clicked_at: Instant,
}

#[derive(Debug, Clone)]
pub struct CopyHighlightState {
    pub target: MessageLineCopyTarget,
    pub expires_at: Instant,
}

impl App {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::new_with_nickname("anonymous".to_string())
    }

    pub fn new_with_nickname(nickname: String) -> Self {
        let channels = Vec::new();
        let mut channel_messages = HashMap::new();
        channel_messages.insert("#public".to_string(), Vec::new());

        let mut app = Self {
            input: Input::default(),
            phase: TuiPhase::Connected,
            should_quit: false,
            focus_area: FocusArea::InputBox,
            sidebar_flat_selected: 0,
            msg_scroll: 0,
            message_viewport_height: 10, // ADDED: Default value
            message_rendered_line_count: 0,
            unseen_divider_message_index: None,
            unseen_divider_line_index: None,
            nickname,
            network_name: "BitChat Mesh".to_string(),
            connected: false,
            mesh_status: "Scanning".to_string(),
            channels,
            people: Vec::new(),
            mesh_people_peer_ids: HashMap::new(),
            geohash_people: HashMap::new(),
            geohash_people_pubkeys: HashMap::new(),
            geohash_last_dm_sender: HashMap::new(),
            geohash_last_mention_sender: HashMap::new(),
            nostr_aliases: HashMap::new(),
            geohash_presence: HashMap::new(),
            blocked: Vec::new(),
            channel_messages,
            dm_messages: HashMap::new(),
            sidebar_state: SidebarMenuState::new(),
            popup_messages: Vec::new(),
            current_conv: Some((None, Some("#public".to_string()))),
            pending_channel_switch: None,
            pending_dm_switch: None,
            pending_nickname_update: None,
            pending_connection_retry: false,
            pending_clear_conversation: false,
            pending_wormhole_offers: HashMap::new(),
            unread_counts: HashMap::new(),
            last_read_messages: HashMap::new(),
            popup_active: false,
            popup_input: Input::default(),
            popup_title: String::new(),
            messages_area_rect: None,
            message_first_visible_index: 0,
            message_line_copy_targets: Vec::new(),
            last_message_click: None,
            copy_highlight: None,
            image_preview: None,
            image_preview_area_rect: None,
            image_picker: build_image_picker(),
            paste_keyburst_active: false,
            last_input_char_event_at: None,
            input_char_burst_count: 0,
            transient_message_expirations: HashMap::new(),
            transient_message_seq: 0,
        };

        app.update_current_conversation();
        app
    }

    pub fn image_preview_is_open(&self) -> bool {
        self.image_preview.is_some()
    }

    pub fn close_image_preview(&mut self) {
        self.image_preview = None;
        self.image_preview_area_rect = None;
    }

    pub fn set_image_preview_area(&mut self, area: Option<(u16, u16, u16, u16)>) {
        self.image_preview_area_rect = area;
    }

    pub fn image_preview_contains_position(&self, row: u16, column: u16) -> bool {
        let Some((x, y, width, height)) = self.image_preview_area_rect else {
            return false;
        };
        if width == 0 || height == 0 {
            return false;
        }
        column >= x
            && column < x.saturating_add(width)
            && row >= y
            && row < y.saturating_add(height)
    }

    pub fn open_image_preview_for_message(&mut self, index: usize) -> Result<(), String> {
        let message_content = {
            let (messages, _, _) = self.get_current_messages();
            let Some(message) = messages.get(index) else {
                return Err("message not found".to_string());
            };
            message.content.clone()
        };
        let Some(path) = extract_preview_image_path(&message_content) else {
            return Err("selected message does not contain a local image path".to_string());
        };
        if !path.exists() {
            return Err(format!("image file not found: {}", path.display()));
        }
        let img = image::ImageReader::open(&path)
            .map_err(|e| format!("failed to open {}: {}", path.display(), e))?
            .decode()
            .map_err(|e| format!("failed to decode {}: {}", path.display(), e))?;
        let state = self.image_picker.new_resize_protocol(img);
        self.image_preview = Some(ImagePreviewState {
            source_path: path,
            render_state: ImagePreviewRenderState::Ready(state),
        });
        self.image_preview_area_rect = None;
        Ok(())
    }

    pub fn get_selected_channel_name(&self) -> String {
        if self.sidebar_state.public_selected.unwrap_or(false) {
            return "#public".to_string();
        }

        if let Some(idx) = self.sidebar_state.channel_selected {
            if let Some(ch_name) = self.channels.get(idx) {
                return ch_name.clone();
            }
        }
        "#public".to_string()
    }

    pub fn current_people_are_geohash(&self) -> bool {
        crate::nostr_geo::is_geohash_channel(&self.get_selected_channel_name())
    }

    pub fn visible_people(&self) -> Vec<String> {
        let channel = self.get_selected_channel_name();
        if crate::nostr_geo::is_geohash_channel(&channel) {
            self.geohash_people
                .get(&channel)
                .cloned()
                .unwrap_or_default()
        } else {
            self.people.clone()
        }
    }

    pub fn visible_people_count(&self) -> usize {
        self.visible_people().len()
    }

    pub fn geohash_active_count(&self, channel: &str) -> usize {
        self.geohash_active_count_at(channel, chrono::Local::now().timestamp())
    }

    fn geohash_active_count_at(&self, channel: &str, now: i64) -> usize {
        self.geohash_presence
            .get(channel)
            .map(|presence| {
                presence
                    .values()
                    .filter(|last_seen| {
                        now.saturating_sub(**last_seen) <= GEOHASH_ACTIVE_WINDOW_SECONDS
                    })
                    .count()
            })
            .unwrap_or_default()
    }

    pub fn visible_person_at(&self, idx: usize) -> Option<String> {
        self.visible_people().get(idx).cloned()
    }

    pub fn geohash_dm_key(channel: &str, target: &str) -> String {
        format!("geo:{}:{}", channel, target)
    }

    pub fn geohash_dm_pubkey_key(channel: &str, pubkey: &str) -> String {
        Self::geohash_dm_key(channel, pubkey)
    }

    pub fn parse_geohash_dm_key(key: &str) -> Option<(String, String)> {
        let rest = key.strip_prefix("geo:")?;
        let (channel, target) = rest.split_once(':')?;
        Some((channel.to_string(), target.to_string()))
    }

    fn resolve_geohash_target_pubkey(&self, channel: &str, target: &str) -> Option<String> {
        self.geohash_person_pubkey(channel, target)
            .or_else(|| crate::nostr_geo::normalize_dm_pubkey(target))
    }

    fn stable_suffix_from_id(stable_id: &str) -> String {
        let digest = Sha256::digest(stable_id.as_bytes());
        hex::encode(digest)[..4].to_ascii_lowercase()
    }

    fn label_with_suffix(name: Option<&str>, stable_id: &str) -> String {
        let suffix = Self::stable_suffix_from_id(stable_id);
        let base = name
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("anon");
        format!("{base}#{suffix}")
    }

    fn is_pubkey_placeholder(name: &str) -> bool {
        crate::nostr_geo::is_pubkey_placeholder_name(name)
    }

    pub fn geohash_person_name_by_pubkey(&self, channel: &str, pubkey: &str) -> Option<String> {
        if let Some(alias) = self.nostr_aliases.get(pubkey) {
            return Some(alias.clone());
        }
        let mut pubkey_name = None;
        for (name, known_pubkey) in self.geohash_people_pubkeys.get(channel)? {
            if known_pubkey != pubkey {
                continue;
            }
            if !Self::is_pubkey_placeholder(name) {
                return Some(name.clone());
            }
            pubkey_name.get_or_insert_with(|| name.clone());
        }
        pubkey_name
    }

    fn geohash_pubkey_display_name(&self, channel: &str, pubkey: &str) -> String {
        let name = self
            .geohash_person_name_by_pubkey(channel, pubkey)
            .filter(|value| !Self::is_pubkey_placeholder(value));
        Self::label_with_suffix(name.as_deref(), pubkey)
    }

    fn geohash_display_name(&self, channel: &str, target: &str) -> String {
        let Some(pubkey) = self.resolve_geohash_target_pubkey(channel, target) else {
            return Self::label_with_suffix(Some(target), target);
        };
        self.geohash_pubkey_display_name(channel, &pubkey)
    }

    pub fn display_geohash_sender(&self, channel: &str, message: &Message) -> String {
        if let Some(pubkey) = &message.sender_pubkey {
            return self.geohash_pubkey_display_name(channel, pubkey);
        }

        self.geohash_display_name(channel, &message.sender)
    }

    pub fn display_dm_target(&self, target: &str) -> String {
        if let Some((channel, nickname)) = Self::parse_geohash_dm_key(target) {
            return format!(
                "{} in {}",
                self.geohash_display_name(&channel, &nickname),
                channel
            );
        }

        target.to_string()
    }

    pub fn short_pubkey(pubkey: &str) -> String {
        let short = pubkey.trim();
        let char_count = short.chars().count();
        if char_count <= 18 {
            short.to_string()
        } else {
            let prefix: String = short.chars().take(10).collect();
            let mut suffix_chars: Vec<char> = short.chars().rev().take(6).collect();
            suffix_chars.reverse();
            let suffix: String = suffix_chars.into_iter().collect();
            format!("{}...{}", prefix, suffix)
        }
    }

    pub fn display_visible_person(&self, person: &str) -> String {
        if self.current_people_are_geohash() {
            let channel = self.get_selected_channel_name();
            if let Some(pubkey) = self.resolve_geohash_target_pubkey(&channel, person) {
                return self.geohash_pubkey_display_name(&channel, &pubkey);
            }
            if crate::nostr_geo::looks_like_dm_pubkey(person) {
                return Self::label_with_suffix(None, person);
            }
            return person.to_string();
        }
        person.to_string()
    }

    pub fn current_geohash_dm(&self) -> Option<(String, String, String)> {
        let (dm_target, _) = self.current_conv.clone().unwrap_or((None, None));
        let target_key = dm_target?;
        let (channel, nickname) = Self::parse_geohash_dm_key(&target_key)?;
        let pubkey = self.resolve_geohash_target_pubkey(&channel, &nickname)?;
        Some((channel, nickname, pubkey))
    }

    pub fn current_geohash_context_channel(&self) -> Option<String> {
        if let Some((channel, _, _)) = self.current_geohash_dm() {
            return Some(channel);
        }

        let channel = self.get_selected_channel_name();
        if crate::nostr_geo::is_geohash_channel(&channel) {
            Some(channel)
        } else {
            None
        }
    }

    pub fn geohash_people_for_channel(&self, channel: &str) -> Vec<String> {
        self.geohash_people
            .get(channel)
            .cloned()
            .unwrap_or_default()
    }

    pub fn geohash_person_pubkey(&self, channel: &str, nickname: &str) -> Option<String> {
        self.geohash_people_pubkeys
            .get(channel)?
            .get(nickname)
            .cloned()
    }

    pub fn geohash_person_for_pubkey(&self, channel: &str, pubkey: &str) -> Option<String> {
        self.geohash_people_pubkeys
            .get(channel)?
            .iter()
            .find_map(|(name, known_pubkey)| (known_pubkey == pubkey).then(|| name.clone()))
    }

    pub fn geohash_people_with_pubkeys(&self, channel: &str) -> Vec<(String, Option<String>)> {
        let pubkeys = self.geohash_people_pubkeys.get(channel);
        self.geohash_people_for_channel(channel)
            .into_iter()
            .map(|person| {
                let pubkey = pubkeys.and_then(|items| items.get(&person)).cloned();
                (person, pubkey)
            })
            .collect()
    }

    pub fn last_geohash_dm_sender(&self, channel: &str) -> Option<(String, String)> {
        let pubkey = self.geohash_last_dm_sender.get(channel)?.clone();
        let label = self
            .geohash_person_for_pubkey(channel, &pubkey)
            .unwrap_or_else(|| pubkey.clone());
        Some((label, pubkey))
    }

    pub fn last_geohash_mention_sender(&self, channel: &str) -> Option<String> {
        let sender = self.geohash_last_mention_sender.get(channel)?.clone();
        if crate::nostr_geo::looks_like_dm_pubkey(&sender) {
            return Some(
                self.geohash_person_for_pubkey(channel, &sender)
                    .unwrap_or(sender),
            );
        }
        Some(sender)
    }

    fn geohash_dm_thread_key(&self, channel: &str, target: &str) -> String {
        self.resolve_geohash_target_pubkey(channel, target)
            .map(|pubkey| Self::geohash_dm_pubkey_key(channel, &pubkey))
            .unwrap_or_else(|| Self::geohash_dm_key(channel, target))
    }

    fn geohash_person_index_by_pubkey(&self, channel: &str, pubkey: &str) -> Option<usize> {
        self.geohash_people.get(channel)?.iter().position(|person| {
            self.resolve_geohash_target_pubkey(channel, person)
                .as_deref()
                == Some(pubkey)
        })
    }

    pub(crate) fn add_geohash_person(&mut self, channel: &str, sender: &str, pubkey: Option<&str>) {
        if sender == self.nickname || sender == "system" || sender.trim().is_empty() {
            return;
        }

        let Some(pubkey) = pubkey.filter(|value| !value.trim().is_empty()) else {
            return;
        };

        let people_pubkeys = self
            .geohash_people_pubkeys
            .entry(channel.to_string())
            .or_default();
        let people = self.geohash_people.entry(channel.to_string()).or_default();

        if let Some(existing_name) = people_pubkeys
            .iter()
            .find_map(|(name, known_pubkey)| (known_pubkey == pubkey).then(|| name.clone()))
        {
            let alias = self.nostr_aliases.get(pubkey).cloned();
            let existing_is_pubkey = Self::is_pubkey_placeholder(&existing_name);
            let sender_is_pubkey = Self::is_pubkey_placeholder(sender);
            let preferred_name = if let Some(alias) = alias {
                alias
            } else if existing_is_pubkey && !sender_is_pubkey {
                sender.to_string()
            } else {
                existing_name.clone()
            };

            if preferred_name != existing_name {
                people_pubkeys.remove(&existing_name);
                if let Some(idx) = people.iter().position(|person| person == &existing_name) {
                    people[idx] = preferred_name.clone();
                }
            }

            if !people.iter().any(|person| person == &preferred_name) {
                people.push(preferred_name.clone());
            }
            people_pubkeys.insert(preferred_name, pubkey.to_string());
            people.sort();
            return;
        }

        let target = if let Some(alias) = self.nostr_aliases.get(pubkey) {
            alias.to_string()
        } else if Self::is_pubkey_placeholder(sender) {
            pubkey.to_string()
        } else {
            sender.to_string()
        };

        people_pubkeys.insert(target.clone(), pubkey.to_string());
        if !people.iter().any(|person| person == &target) {
            people.push(target);
            people.sort();
        }
    }

    fn note_geohash_presence(&mut self, channel: &str, pubkey: &str, timestamp: i64) {
        if pubkey.trim().is_empty() {
            return;
        }

        let presence = self
            .geohash_presence
            .entry(channel.to_string())
            .or_default();
        let entry = presence.entry(pubkey.to_string()).or_insert(timestamp);
        if timestamp > *entry {
            *entry = timestamp;
        }
    }

    fn add_mesh_person(&mut self, name: &str, peer_id: Option<&str>) {
        let name = name.trim().trim_start_matches('@');
        if name.is_empty() || name == self.nickname || name == "system" {
            return;
        }
        if name.len() > 20
            || !name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return;
        }
        if !self.people.iter().any(|person| person == name) {
            self.people.push(name.to_string());
            self.people.sort();
        }
        if let Some(peer_id) = peer_id.filter(|value| !value.trim().is_empty()) {
            self.mesh_people_peer_ids
                .insert(name.to_string(), peer_id.to_string());
        }
    }

    pub fn update_current_conversation(&mut self) {
        if let Some(user_idx) = self.sidebar_state.people_selected {
            if !self.current_people_are_geohash() {
                if let Some(user) = self.people.get(user_idx) {
                    self.current_conv = Some((Some(user.clone()), None));
                    return;
                }
            } else if self.visible_person_at(user_idx).is_some() {
                let channel = self.get_selected_channel_name();
                if let Some(user) = self.visible_person_at(user_idx) {
                    let target_key = self.geohash_dm_thread_key(&channel, &user);
                    self.current_conv = Some((Some(target_key), Some(channel)));
                    return;
                }
            }
        }

        if self.sidebar_state.public_selected.unwrap_or(false) {
            self.current_conv = Some((None, Some("#public".to_string())));
            return;
        }

        if let Some(channel_idx) = self.sidebar_state.channel_selected {
            if let Some(channel) = self.channels.get(channel_idx) {
                self.current_conv = Some((None, Some(channel.clone())));
                return;
            }
        }

        self.current_conv = Some((None, Some("#public".to_string())));
    }

    pub fn get_current_messages(&self) -> (&[Message], Option<String>, Option<String>) {
        if let Some(user_idx) = self.sidebar_state.people_selected {
            if !self.current_people_are_geohash() {
                if let Some(user) = self.people.get(user_idx) {
                    let messages = self
                        .dm_messages
                        .get(user)
                        .map(|v| v.as_slice())
                        .unwrap_or(&[]);
                    return (messages, Some(user.clone()), None);
                }
            } else if let Some(user) = self.visible_person_at(user_idx) {
                let channel = self.get_selected_channel_name();
                let target_key = self.geohash_dm_thread_key(&channel, &user);
                let messages = self
                    .dm_messages
                    .get(&target_key)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                return (messages, Some(target_key), None);
            }
        }

        let ch = self.get_selected_channel_name();
        let messages = self
            .channel_messages
            .get(&ch)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        (messages, None, Some(ch))
    }

    fn parse_display_and_epoch(
        timestamp_hhmm: &str,
        timestamp_epoch_raw: Option<&str>,
    ) -> (String, Option<i64>) {
        let display = if timestamp_hhmm.len() == 4 {
            format!("{}:{}", &timestamp_hhmm[0..2], &timestamp_hhmm[2..4])
        } else {
            timestamp_hhmm.to_string()
        };
        let epoch = timestamp_epoch_raw.and_then(|raw| raw.parse::<i64>().ok());
        (display, epoch)
    }

    fn split_optional_epoch_and_content(rest: &str) -> (Option<&str>, String) {
        let Some((maybe_epoch, content)) = rest.split_once(':') else {
            return (None, rest.to_string());
        };
        if maybe_epoch.parse::<i64>().is_ok() {
            (Some(maybe_epoch), content.to_string())
        } else {
            (None, rest.to_string())
        }
    }

    fn looks_like_nostr_pubkey_field(value: &str) -> bool {
        crate::nostr_geo::looks_like_dm_pubkey(value) || value.starts_with("npub")
    }

    pub fn format_timestamp_for_display(
        &self,
        message: &Message,
        previous: Option<&Message>,
    ) -> String {
        let Some(current_epoch) = message.timestamp_epoch else {
            return message.timestamp.clone();
        };
        let Some(current_dt) = Local.timestamp_opt(current_epoch, 0).single() else {
            return message.timestamp.clone();
        };

        let previous_same_day = previous
            .and_then(|m| m.timestamp_epoch)
            .and_then(|epoch| Local.timestamp_opt(epoch, 0).single())
            .map(|prev_dt| prev_dt.date_naive() == current_dt.date_naive())
            .unwrap_or(true);

        if previous_same_day {
            current_dt.format("%H:%M").to_string()
        } else {
            current_dt.format("%m-%d %H:%M").to_string()
        }
    }

    pub fn add_log_message(&mut self, raw_message: String) {
        let cleaned_message =
            String::from_utf8(strip_ansi_escapes::strip(&raw_message)).unwrap_or_default();
        let trimmed = cleaned_message.trim();
        let debug_enabled = Self::debug_logs_enabled();

        if trimmed.is_empty() || trimmed.starts_with('>') || trimmed.starts_with("Â»") {
            return;
        }

        if !debug_enabled && Self::should_suppress_noisy_line(trimmed) {
            return;
        }

        if let Some(payload) = trimmed.strip_prefix("__DM__:") {
            let Some((sender_raw, rest)) = payload.split_once(':') else {
                return;
            };
            let Some((timestamp_raw, rest)) = rest.split_once(':') else {
                return;
            };
            let sender = sender_raw.to_string();
            if self.is_sender_blocked(&sender) {
                return;
            }
            let (epoch_raw, content) = Self::split_optional_epoch_and_content(rest);
            let (timestamp, timestamp_epoch) = Self::parse_display_and_epoch(timestamp_raw, epoch_raw);

            let sender_clone = sender.clone();
            let msg = Message {
                sender,
                sender_pubkey: None,
                timestamp,
                timestamp_epoch,
                content,
                is_self: false,
                status: MessageStatus::None,
                local_id: None,
            };

            self.dm_messages
                .entry(sender_clone.clone())
                .or_default()
                .push(msg);

            let dm_key = format!("dm:{}", sender_clone);
            let (_, current_dm_target, _) = self.get_current_messages();
            if current_dm_target.as_ref() != Some(&sender_clone) {
                self.add_unread_message(dm_key);
            }

            self.follow_or_mark_new_message();
            return;
        }

        if trimmed.starts_with("__DM_STATUS__:") {
            let parts: Vec<&str> = trimmed.splitn(4, ':').collect();
            if parts.len() >= 3 {
                let local_id = parts[1];
                let status = match parts[2] {
                    "sent" => Some(MessageStatus::Delivered),
                    "delivered" => Some(MessageStatus::Delivered),
                    "read" => Some(MessageStatus::Read),
                    "failed" => Some(MessageStatus::Failed),
                    _ => None,
                };
                if let Some(status) = status {
                    self.update_dm_message_status(local_id, status);
                }
                return;
            }
        }

        if trimmed.starts_with("__GEO_PERSON__:") {
            let parts: Vec<&str> = trimmed.splitn(4, ':').collect();
            if parts.len() >= 4 {
                let channel = parts[1].to_string();
                let sender = parts[2].to_string();
                let pubkey = parts[3].to_string();
                if !self.channels.contains(&channel) {
                    self.channels.push(channel.clone());
                }
                self.note_geohash_presence(&channel, &pubkey, chrono::Local::now().timestamp());
                self.add_geohash_person(&channel, &sender, Some(&pubkey));
                self.geohash_last_dm_sender
                    .insert(channel.clone(), pubkey.clone());
                return;
            }
        }

        if trimmed.starts_with("__GEO_PRESENCE__:") {
            let parts: Vec<&str> = trimmed.splitn(4, ':').collect();
            if parts.len() >= 4 {
                let channel = parts[1].to_string();
                let pubkey = parts[2].to_string();
                if let Ok(timestamp) = parts[3].parse::<i64>() {
                    if !self.channels.contains(&channel) {
                        self.channels.push(channel.clone());
                    }
                    self.note_geohash_presence(&channel, &pubkey, timestamp);
                }
                return;
            }
        }

        if trimmed.starts_with("__GEO_DM_STATUS__:") {
            let parts: Vec<&str> = trimmed.splitn(4, ':').collect();
            if parts.len() >= 3 {
                let local_id = parts[1];
                let status = match parts[2] {
                    "sent" => Some(MessageStatus::Delivered),
                    "delivered" => Some(MessageStatus::Delivered),
                    "read" => Some(MessageStatus::Read),
                    "failed" => Some(MessageStatus::Failed),
                    _ => None,
                };
                if let Some(status) = status {
                    self.update_dm_message_status(local_id, status);
                }
                if status == Some(MessageStatus::Failed) && parts.len() >= 4 && !parts[3].is_empty()
                {
                    self.add_log_message(format!(
                        "system: Failed to send geohash DM: {}",
                        parts[3]
                    ));
                }
                return;
            }
        }

        if trimmed.starts_with("__GEO_DM__:") {
            let parts: Vec<&str> = trimmed.splitn(8, ':').collect();
            if parts.len() >= 7 {
                let channel = parts[1].to_string();
                let sender = parts[2].to_string();
                if self.is_sender_blocked(&sender) {
                    return;
                }
                let pubkey = parts[3].to_string();
                let timestamp_raw = parts[4];
                let (timestamp, timestamp_epoch) = if parts.len() >= 8 {
                    Self::parse_display_and_epoch(timestamp_raw, parts.get(5).copied())
                } else {
                    Self::parse_display_and_epoch(timestamp_raw, None)
                };
                let message_id = if parts.len() >= 8 {
                    parts[6].to_string()
                } else {
                    parts[5].to_string()
                };
                let content = if parts.len() >= 8 {
                    parts[7].to_string()
                } else {
                    parts[6].to_string()
                };

                if !self.channels.contains(&channel) {
                    self.channels.push(channel.clone());
                }
                self.note_geohash_presence(&channel, &pubkey, chrono::Local::now().timestamp());
                self.add_geohash_person(&channel, &sender, Some(&pubkey));
                self.geohash_last_dm_sender
                    .insert(channel.clone(), pubkey.clone());

                let target_key = Self::geohash_dm_pubkey_key(&channel, &pubkey);
                if let Some((code, file_name, file_size_bytes)) =
                    crate::command_handling::parse_geohash_file_offer_message(&content)
                {
                    self.pending_wormhole_offers.insert(
                        target_key.clone(),
                        PendingWormholeOffer {
                            sender: sender.clone(),
                            code,
                            file_name: file_name.clone(),
                            file_size_bytes,
                        },
                    );
                    let content = compact_file_message(&file_name);
                    let msg = Message {
                        sender,
                        sender_pubkey: Some(pubkey.clone()),
                        timestamp,
                        timestamp_epoch,
                        content,
                        is_self: false,
                        status: MessageStatus::None,
                        local_id: Some(message_id),
                    };
                    self.dm_messages
                        .entry(target_key.clone())
                        .or_default()
                        .push(msg);
                    if self.current_conv.as_ref().and_then(|(dm, _)| dm.as_ref())
                        != Some(&target_key)
                    {
                        self.add_unread_message(format!("dm:{}", target_key));
                    }
                    self.follow_or_mark_new_message();
                    return;
                }

                let msg = Message {
                    sender,
                    sender_pubkey: Some(pubkey),
                    timestamp,
                    timestamp_epoch,
                    content,
                    is_self: false,
                    status: MessageStatus::None,
                    local_id: Some(message_id),
                };

                self.dm_messages
                    .entry(target_key.clone())
                    .or_default()
                    .push(msg);

                if self.current_conv.as_ref().and_then(|(dm, _)| dm.as_ref()) != Some(&target_key) {
                    self.add_unread_message(format!("dm:{}", target_key));
                }

                self.follow_or_mark_new_message();
                return;
            }

            let parts: Vec<&str> = trimmed.splitn(7, ':').collect();
            if parts.len() >= 6 {
                let channel = parts[1].to_string();
                let sender = parts[2].to_string();
                if self.is_sender_blocked(&sender) {
                    return;
                }
                let pubkey = parts[3].to_string();
                let timestamp_raw = parts[4];
                let (timestamp, timestamp_epoch) = if parts.len() >= 7 {
                    Self::parse_display_and_epoch(timestamp_raw, parts.get(5).copied())
                } else {
                    Self::parse_display_and_epoch(timestamp_raw, None)
                };
                let content = if parts.len() >= 7 {
                    parts[6].to_string()
                } else {
                    parts[5].to_string()
                };

                if !self.channels.contains(&channel) {
                    self.channels.push(channel.clone());
                }
                self.note_geohash_presence(&channel, &pubkey, chrono::Local::now().timestamp());
                self.add_geohash_person(&channel, &sender, Some(&pubkey));

                let target_key = Self::geohash_dm_pubkey_key(&channel, &pubkey);
                let msg = Message {
                    sender,
                    sender_pubkey: Some(pubkey),
                    timestamp,
                    timestamp_epoch,
                    content,
                    is_self: false,
                    status: MessageStatus::None,
                    local_id: None,
                };

                self.dm_messages
                    .entry(target_key.clone())
                    .or_default()
                    .push(msg);

                if self.current_conv.as_ref().and_then(|(dm, _)| dm.as_ref()) != Some(&target_key) {
                    self.add_unread_message(format!("dm:{}", target_key));
                }

                self.follow_or_mark_new_message();
                return;
            }
        }

        if let Some(payload) = trimmed.strip_prefix("__CHANNEL__:") {
            let Some((channel_raw, rest)) = payload.split_once(':') else {
                return;
            };
            let Some((sender_raw, rest)) = rest.split_once(':') else {
                return;
            };
            let channel = channel_raw.to_string();
            let sender = sender_raw.to_string();
            if self.is_sender_blocked(&sender) {
                return;
            }
            let is_geohash = crate::nostr_geo::is_geohash_channel(&channel);

            let (sender_pubkey, timestamp_raw, remainder) = if is_geohash {
                let Some((third, after_third)) = rest.split_once(':') else {
                    return;
                };
                if Self::looks_like_nostr_pubkey_field(third) {
                    let Some((timestamp_raw, remainder)) = after_third.split_once(':') else {
                        return;
                    };
                    (Some(third.to_string()), timestamp_raw, remainder)
                } else {
                    (None, third, after_third)
                }
            } else {
                let Some((timestamp_raw, remainder)) = rest.split_once(':') else {
                    return;
                };
                (None, timestamp_raw, remainder)
            };

            let (epoch_raw, content) = Self::split_optional_epoch_and_content(remainder);
            let (timestamp, timestamp_epoch) = Self::parse_display_and_epoch(timestamp_raw, epoch_raw);

            if is_geohash {
                if !self.channels.contains(&channel) {
                    self.channels.push(channel.clone());
                }
                self.add_geohash_person(&channel, &sender, sender_pubkey.as_deref());
                if sender != self.nickname && self.message_mentions_self(&content) {
                    let sender_key = sender_pubkey.clone().unwrap_or_else(|| sender.clone());
                    self.geohash_last_mention_sender
                        .insert(channel.clone(), sender_key);
                }
            }

            let msg = Message {
                sender,
                sender_pubkey,
                timestamp,
                timestamp_epoch,
                content,
                is_self: false,
                status: MessageStatus::None,
                local_id: None,
            };

            self.channel_messages
                .entry(channel.clone())
                .or_default()
                .push(msg);

            let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
            let in_dm = dm_target.is_some();
            if channel == "#public" {
                // If not currently viewing public (i.e., in DM or in another channel), add unread
                if !self.sidebar_state.public_selected.unwrap_or(false) {
                    self.add_unread_message("#public".to_string());
                }
            } else {
                // For other channels, only add unread if not currently viewing that channel
                if channel_name.as_deref() != Some(&channel) || in_dm {
                    self.add_unread_message(channel);
                }
            }

            self.follow_or_mark_new_message();
            return;
        }

        if let Some(payload) = trimmed.strip_prefix("__PEER_CONNECTED__:") {
            let mut parts = payload.splitn(2, ':');
            let name = parts.next().unwrap_or_default();
            let peer_id = parts.next();
            self.add_mesh_person(name, peer_id);
            return;
        }

        if let Some(captures) = Regex::new(r"\[(\d{2}:\d{2})\] <(\w+)> (.*)")
            .unwrap()
            .captures(trimmed)
        {
            let timestamp = captures.get(1).unwrap().as_str().to_string();
            let sender = captures.get(2).unwrap().as_str().to_string();
            let content = captures.get(3).unwrap().as_str().to_string();

            if sender == self.nickname {
                return;
            }

            let msg = Message {
                sender,
                sender_pubkey: None,
                timestamp,
                timestamp_epoch: None,
                content,
                is_self: false,
                status: MessageStatus::None,
                local_id: None,
            };
            let current_channel = self.get_selected_channel_name();
            self.channel_messages
                .entry(current_channel)
                .or_default()
                .push(msg);
            self.follow_or_mark_new_message();
            return;
        }

        if let Some(content) = trimmed.strip_prefix("system:") {
            let lines: Vec<&str> = content.split('\n').collect();

            for line in lines {
                let line_no_trailing = line.trim_end();
                if line_no_trailing.trim().is_empty() {
                    continue;
                }
                let Some(content) =
                    Self::filter_system_message_line(line_no_trailing, debug_enabled)
                else {
                    continue;
                };
                let msg = Message {
                    sender: "system".to_string(),
                    sender_pubkey: None,
                    timestamp: chrono::Local::now().format("%H:%M").to_string(),
                    timestamp_epoch: Some(chrono::Local::now().timestamp()),
                    content,
                    is_self: false,
                    status: MessageStatus::None,
                    local_id: None,
                };

                // Check if we're in a DM conversation or channel conversation
                let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
                if let Some(target) = dm_target {
                    // We're in a DM, add to DM messages
                    self.dm_messages.entry(target).or_default().push(msg);
                } else if let Some(channel) = channel_name {
                    // We're in a channel, add to channel messages
                    self.channel_messages.entry(channel).or_default().push(msg);
                } else {
                    // Fallback to current channel (shouldn't happen but just in case)
                    let current_channel = self.get_selected_channel_name();
                    self.channel_messages
                        .entry(current_channel.clone())
                        .or_default()
                        .push(msg);
                }
            }
            self.follow_or_mark_new_message();
            return;
        }

        if trimmed.contains(&self.nickname) {
            return;
        }

        let lines: Vec<&str> = trimmed.split('\n').collect();
        let current_channel = self.get_selected_channel_name();

        for line in lines {
            let trimmed_line = line.trim();
            if !trimmed_line.is_empty() {
                let msg = Message {
                    sender: "system".to_string(),
                    sender_pubkey: None,
                    timestamp: chrono::Local::now().format("%H:%M").to_string(),
                    timestamp_epoch: Some(chrono::Local::now().timestamp()),
                    content: trimmed_line.to_string(),
                    is_self: false,
                    status: MessageStatus::None,
                    local_id: None,
                };
                self.channel_messages
                    .entry(current_channel.clone())
                    .or_default()
                    .push(msg);
            }
        }
        self.follow_or_mark_new_message();
    }

    pub fn add_sent_message(&mut self, text: String) {
        let timestamp = chrono::Local::now().format("%H:%M").to_string();
        let msg = Message {
            sender: self.nickname.clone(),
            sender_pubkey: None,
            timestamp,
            timestamp_epoch: Some(chrono::Local::now().timestamp()),
            content: text,
            is_self: true,
            status: MessageStatus::None,
            local_id: None,
        };

        let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
        if let Some(target) = dm_target {
            self.dm_messages.entry(target).or_default().push(msg);
        } else if let Some(channel) = channel_name {
            self.channel_messages.entry(channel).or_default().push(msg);
        }
        self.follow_or_mark_new_message();
    }

    fn normalized_block_name(value: &str) -> String {
        let mut trimmed = value.trim().trim_start_matches('@').to_ascii_lowercase();
        if let Some((base, suffix)) = trimmed.rsplit_once('#') {
            if !base.is_empty()
                && suffix.len() == 4
                && suffix.chars().all(|ch| ch.is_ascii_hexdigit())
            {
                trimmed = base.to_string();
            }
        }
        trimmed
    }

    fn is_sender_blocked(&self, sender: &str) -> bool {
        let sender_norm = Self::normalized_block_name(sender);
        if sender_norm.is_empty() {
            return false;
        }
        self.blocked
            .iter()
            .map(|entry| Self::normalized_block_name(entry))
            .any(|entry| !entry.is_empty() && entry == sender_norm)
    }

    fn strip_display_suffix(value: &str) -> &str {
        let trimmed = value.trim();
        let Some((base, suffix)) = trimmed.rsplit_once('#') else {
            return trimmed;
        };
        if base.is_empty() || suffix.len() != 4 || !suffix.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            return trimmed;
        }
        base
    }

    fn message_mentions_self(&self, content: &str) -> bool {
        let my_name = Self::strip_display_suffix(self.nickname.trim().trim_start_matches('@'))
            .to_ascii_lowercase();
        if my_name.is_empty() {
            return false;
        }

        content.split_whitespace().any(|token| {
            let mention = token.trim_start_matches(|ch: char| ch != '@');
            let Some(raw_target) = mention.strip_prefix('@') else {
                return false;
            };
            let target = raw_target.trim_matches(|ch: char| {
                !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '#')
            });
            if target.is_empty() {
                return false;
            }
            let target_base = Self::strip_display_suffix(target).to_ascii_lowercase();
            !target_base.is_empty() && target_base == my_name
        })
    }

    pub fn add_pending_geohash_dm_message(&mut self, text: String, local_id: String) {
        let timestamp = chrono::Local::now().format("%H:%M").to_string();
        let msg = Message {
            sender: self.nickname.clone(),
            sender_pubkey: None,
            timestamp,
            timestamp_epoch: Some(chrono::Local::now().timestamp()),
            content: text,
            is_self: true,
            status: MessageStatus::Sending,
            local_id: Some(local_id),
        };

        let (dm_target, _) = self.current_conv.clone().unwrap_or((None, None));
        if let Some(target) = dm_target {
            self.dm_messages.entry(target).or_default().push(msg);
        }
        self.follow_or_mark_new_message();
    }

    pub fn current_conversation_key(&self) -> String {
        let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
        if let Some(target) = dm_target {
            format!("dm:{}", target)
        } else if let Some(channel) = channel_name {
            channel
        } else {
            self.get_selected_channel_name()
        }
    }

    pub fn visible_copy_target_at_position(
        &self,
        row: u16,
        column: u16,
    ) -> Option<MessageLineCopyTarget> {
        let (x, y, width, height) = self.messages_area_rect?;
        if width < 2 || height < 2 {
            return None;
        }
        if column <= x || column >= x.saturating_add(width).saturating_sub(1) {
            return None;
        }
        if row <= y || row >= y.saturating_add(height).saturating_sub(1) {
            return None;
        }

        let inner_row = row.saturating_sub(y + 1) as usize;
        let rendered_row = self.message_first_visible_index.saturating_add(inner_row);
        self.message_line_copy_targets
            .get(rendered_row)
            .cloned()
            .flatten()
    }

    pub fn current_message_text_for_copy(&self, index: usize) -> Option<String> {
        let (messages, _, _) = self.get_current_messages();
        let msg = messages.get(index)?;
        let text = msg.content.trim();
        if text.is_empty() {
            None
        } else {
            Some(text.to_string())
        }
    }

    pub fn copy_text_for_target(&self, target: &MessageLineCopyTarget) -> Option<String> {
        match target {
            MessageLineCopyTarget::Message(index) => self.current_message_text_for_copy(*index),
            MessageLineCopyTarget::SenderLabel(name) => {
                let trimmed = name.trim().trim_end_matches(':').trim_end();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
        }
    }

    pub fn show_copy_highlight(&mut self, target: MessageLineCopyTarget, duration: Duration) {
        self.copy_highlight = Some(CopyHighlightState {
            target,
            expires_at: Instant::now() + duration,
        });
    }

    pub fn should_highlight_copy_target(&self, target: &MessageLineCopyTarget) -> bool {
        let Some(active) = self.copy_highlight.as_ref() else {
            return false;
        };
        if Instant::now() >= active.expires_at {
            return false;
        }
        &active.target == target
    }

    pub fn add_pending_mesh_dm_message(&mut self, target: String, text: String, local_id: String) {
        let timestamp = chrono::Local::now().format("%H:%M").to_string();
        let msg = Message {
            sender: self.nickname.clone(),
            sender_pubkey: None,
            timestamp,
            timestamp_epoch: Some(chrono::Local::now().timestamp()),
            content: text,
            is_self: true,
            status: MessageStatus::Sending,
            local_id: Some(local_id),
        };

        self.dm_messages.entry(target).or_default().push(msg);
        self.follow_or_mark_new_message();
    }

    pub fn add_transient_system_message(&mut self, content: String, duration: Duration) {
        let local_id = format!("transient:{}", self.transient_message_seq);
        self.transient_message_seq = self.transient_message_seq.saturating_add(1);
        self.transient_message_expirations
            .insert(local_id.clone(), Instant::now() + duration);

        let msg = Message {
            sender: "system".to_string(),
            sender_pubkey: None,
            timestamp: chrono::Local::now().format("%H:%M").to_string(),
            timestamp_epoch: Some(chrono::Local::now().timestamp()),
            content,
            is_self: false,
            status: MessageStatus::None,
            local_id: Some(local_id),
        };

        let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
        if let Some(target) = dm_target {
            self.dm_messages.entry(target).or_default().push(msg);
        } else if let Some(channel) = channel_name {
            self.channel_messages.entry(channel).or_default().push(msg);
        } else {
            let current_channel = self.get_selected_channel_name();
            self.channel_messages.entry(current_channel).or_default().push(msg);
        }
        self.follow_or_mark_new_message();
    }

    pub fn prune_expired_transient_messages(&mut self) {
        if self.transient_message_expirations.is_empty() {
            return;
        }

        let now = Instant::now();
        let mut expired_ids: Vec<String> = self
            .transient_message_expirations
            .iter()
            .filter_map(|(id, expires_at)| (now >= *expires_at).then_some(id.clone()))
            .collect();
        if expired_ids.is_empty() {
            return;
        }

        expired_ids.sort();
        expired_ids.dedup();
        for id in &expired_ids {
            self.transient_message_expirations.remove(id);
        }

        self.channel_messages.values_mut().for_each(|messages| {
            messages.retain(|message| {
                !message
                    .local_id
                    .as_ref()
                    .is_some_and(|id| expired_ids.binary_search(id).is_ok())
            });
        });

        self.dm_messages.values_mut().for_each(|messages| {
            messages.retain(|message| {
                !message
                    .local_id
                    .as_ref()
                    .is_some_and(|id| expired_ids.binary_search(id).is_ok())
            });
        });
    }

    pub fn update_dm_message_status(&mut self, local_id: &str, status: MessageStatus) -> bool {
        for messages in self.dm_messages.values_mut() {
            if let Some(message) = messages
                .iter_mut()
                .find(|message| message.local_id.as_deref() == Some(local_id))
            {
                if !Self::should_apply_dm_status(message.status, status) {
                    return true;
                }
                message.status = status;
                return true;
            }
        }
        false
    }

    fn should_apply_dm_status(current: MessageStatus, next: MessageStatus) -> bool {
        match current {
            MessageStatus::Read => matches!(next, MessageStatus::Read),
            MessageStatus::Delivered => {
                matches!(next, MessageStatus::Delivered | MessageStatus::Read)
            }
            MessageStatus::Failed => {
                matches!(
                    next,
                    MessageStatus::Failed | MessageStatus::Delivered | MessageStatus::Read
                )
            }
            MessageStatus::None => !matches!(next, MessageStatus::Sending),
            MessageStatus::Sending => true,
        }
    }

    fn debug_logs_enabled() -> bool {
        bitchat_debug_enabled()
    }

    fn should_suppress_noisy_line(line: &str) -> bool {
        line.contains("Scanning for bitchat service")
            || line.contains("Restarting Bluetooth mesh scan...")
            || line.starts_with("[DM] ")
            || line.contains("No BitChat service found")
            || line.contains("Another device is running BitChat")
            || line.starts_with("Scan timed out after")
            || line.starts_with("Bluetooth mesh unavailable:")
            || line
                == "Bluetooth mesh is offline. Join a Nostr geohash channel such as /j #ws, or wait for mesh discovery to finish."
            || line == "Bluetooth mesh is still offline. Nostr geohash channels are available with /j #ws."
    }

    fn filter_system_message_line(line: &str, debug_enabled: bool) -> Option<String> {
        if debug_enabled {
            return Some(line.to_string());
        }

        if Self::should_suppress_noisy_line(line) {
            return None;
        }

        if line.contains("iOS only listens on those relays") {
            if line.contains("Failed to send geohash DM") {
                return Some(
                    "Failed to send geohash DM. Check relay/network and retry.".to_string(),
                );
            }
            if line.contains("Failed to send geohash message") {
                return Some(
                    "Failed to send geohash message. Check relay/network and retry.".to_string(),
                );
            }
            return Some("Relay publish failed. Check relay/network and retry.".to_string());
        }

        Some(line.to_string())
    }

    pub fn add_dm_message(&mut self, target_nickname: String, content: String) {
        let timestamp = chrono::Local::now().format("%H:%M").to_string();
        let msg = Message {
            sender: self.nickname.clone(),
            sender_pubkey: None,
            timestamp,
            timestamp_epoch: Some(chrono::Local::now().timestamp()),
            content,
            is_self: true,
            status: MessageStatus::None,
            local_id: None,
        };
        self.dm_messages
            .entry(target_nickname)
            .or_default()
            .push(msg);
        self.follow_or_mark_new_message();
    }

    pub fn take_pending_wormhole_offer(
        &mut self,
        conversation_key: &str,
    ) -> Option<PendingWormholeOffer> {
        self.pending_wormhole_offers.remove(conversation_key)
    }

    pub fn scroll_to_bottom_current_conversation(&mut self) {
        self.msg_scroll = 0;
        self.unseen_divider_message_index = None;
        self.unseen_divider_line_index = None;
    }

    pub fn is_viewing_bottom(&self) -> bool {
        self.msg_scroll == 0
    }

    pub fn note_user_scrolled(&mut self) {
        if self.is_viewing_bottom() {
            self.unseen_divider_message_index = None;
            self.unseen_divider_line_index = None;
        }
    }

    pub fn follow_or_mark_new_message(&mut self) {
        if self.is_viewing_bottom() {
            self.scroll_to_bottom_current_conversation();
            return;
        }

        if self.unseen_divider_message_index.is_none() {
            let (messages, _, _) = self.get_current_messages();
            self.unseen_divider_message_index = Some(messages.len().saturating_sub(1));
            self.unseen_divider_line_index = None;
        }
    }

    pub fn jump_to_unseen_or_bottom(&mut self) {
        if let Some(line_idx) = self.unseen_divider_line_index {
            let viewport = self.message_viewport_height.max(1);
            let target_end = line_idx.saturating_add(viewport);
            self.msg_scroll = self.message_rendered_line_count.saturating_sub(target_end);
            self.unseen_divider_message_index = None;
            self.unseen_divider_line_index = None;
            return;
        }
        self.scroll_to_bottom_current_conversation();
    }

    pub fn transition_to_connected(&mut self) {
        self.phase = TuiPhase::Connected;
        self.connected = true;
        self.mesh_status = "Connected".to_string();
        let mut final_messages = self
            .popup_messages
            .drain(..)
            .map(|content| Message {
                sender: "system".to_string(),
                sender_pubkey: None,
                timestamp: chrono::Local::now().format("%H:%M").to_string(),
                timestamp_epoch: Some(chrono::Local::now().timestamp()),
                content,
                is_self: false,
                status: MessageStatus::None,
                local_id: None,
            })
            .collect();
        self.channel_messages
            .entry("#public".to_string())
            .or_default()
            .append(&mut final_messages);
    }

    pub fn transition_to_error(&mut self, error: String) {
        let cleaned_error =
            String::from_utf8(strip_ansi_escapes::strip(&error)).unwrap_or_default();
        self.phase = TuiPhase::Error(cleaned_error);
        self.connected = false;
        self.mesh_status = "Offline".to_string();
    }

    pub fn add_popup_message(&mut self, message: String) {
        let cleaned_message =
            String::from_utf8(strip_ansi_escapes::strip(&message)).unwrap_or_default();
        let trimmed = cleaned_message.trim().to_string();
        if !trimmed.is_empty() {
            self.popup_messages.push(trimmed);
        }
    }

    pub fn join_channel(&mut self, channel_name: String) {
        if channel_name == "#public" {
            return;
        }
        if !self.channels.contains(&channel_name) {
            self.channels.push(channel_name.clone());
        }
        self.sidebar_state.public_selected = None;
        if let Some(channel_idx) = self.channels.iter().position(|c| c == &channel_name) {
            self.sidebar_state.channel_selected = Some(channel_idx);
            self.update_current_conversation();
            self.update_sidebar_flat_selection();
            self.mark_current_conversation_as_read();
            self.pending_channel_switch = Some(channel_name.clone());
        }
        self.channel_messages.entry(channel_name).or_default();
    }

    pub fn switch_to_channel(&mut self, channel_name: String) {
        if let Some(channel_idx) = self.channels.iter().position(|c| c == &channel_name) {
            // Clear other selections when switching to a channel
            self.sidebar_state.public_selected = None;
            self.sidebar_state.people_selected = None;
            self.sidebar_state.channel_selected = Some(channel_idx);
            self.update_current_conversation();
            self.update_sidebar_flat_selection();
            self.mark_current_conversation_as_read();
            self.scroll_to_bottom_current_conversation();
            self.pending_channel_switch = Some(channel_name);
        }
    }

    pub fn switch_to_public(&mut self) {
        self.sidebar_state.public_selected = Some(true);
        self.sidebar_state.channel_selected = None;
        self.sidebar_state.people_selected = None;
        self.update_current_conversation();
        self.update_sidebar_flat_selection();
        self.mark_current_conversation_as_read();
        self.scroll_to_bottom_current_conversation();
        self.pending_channel_switch = Some("#public".to_string());
    }

    pub fn switch_to_dm(&mut self, target_nickname: String) {
        self.sidebar_state.public_selected = None;
        self.sidebar_state.channel_selected = None;
        if let Some(person_idx) = self.people.iter().position(|p| p == &target_nickname) {
            self.sidebar_state.people_selected = Some(person_idx);
            self.update_current_conversation();
            self.update_sidebar_flat_selection();
            self.mark_current_conversation_as_read();
            self.scroll_to_bottom_current_conversation();
            self.pending_dm_switch = Some((target_nickname, String::new()));
        }
    }

    pub fn switch_to_geohash_dm(&mut self, target_nickname: String) {
        let channel = self.get_selected_channel_name();
        if !crate::nostr_geo::is_geohash_channel(&channel) {
            return;
        }

        let Some(channel_idx) = self.channels.iter().position(|c| c == &channel) else {
            return;
        };
        let Some(canonical_target) = self.resolve_geohash_target_pubkey(&channel, &target_nickname)
        else {
            return;
        };
        self.add_geohash_person(&channel, &target_nickname, Some(&canonical_target));
        let Some(person_idx) = self.geohash_person_index_by_pubkey(&channel, &canonical_target)
        else {
            return;
        };

        self.sidebar_state.public_selected = None;
        self.sidebar_state.channel_selected = Some(channel_idx);
        self.sidebar_state.people_selected = Some(person_idx);
        self.current_conv = Some((
            Some(Self::geohash_dm_key(&channel, &canonical_target)),
            Some(channel),
        ));
        self.update_sidebar_flat_selection();
        self.mark_current_conversation_as_read();
        self.scroll_to_bottom_current_conversation();
    }

    pub fn leave_geohash_channel(&mut self, channel: &str) {
        self.channels.retain(|c| c != channel);
        self.geohash_people.remove(channel);
        self.geohash_people_pubkeys.remove(channel);
        self.geohash_last_dm_sender.remove(channel);
        self.geohash_last_mention_sender.remove(channel);
        self.geohash_presence.remove(channel);
        self.channel_messages.remove(channel);
        self.dm_messages.retain(|key, _| {
            Self::parse_geohash_dm_key(key)
                .map(|(dm_channel, _)| dm_channel != channel)
                .unwrap_or(true)
        });
        // Drop unread/read-state entries tied to this geohash channel and its DMs.
        self.unread_counts.retain(|key, _| {
            if key == channel {
                return false;
            }
            if let Some(dm_key) = key.strip_prefix("dm:") {
                return Self::parse_geohash_dm_key(dm_key)
                    .map(|(dm_channel, _)| dm_channel != channel)
                    .unwrap_or(true);
            }
            true
        });
        self.last_read_messages.retain(|key, _| {
            if key == channel {
                return false;
            }
            if let Some(dm_key) = key.strip_prefix("dm:") {
                return Self::parse_geohash_dm_key(dm_key)
                    .map(|(dm_channel, _)| dm_channel != channel)
                    .unwrap_or(true);
            }
            true
        });
        self.switch_to_public();
    }

    pub fn mark_current_conversation_as_read(&mut self) {
        let (messages, dm_target, channel_name) = self.get_current_messages();
        let conversation_key = if let Some(target) = dm_target.as_ref() {
            format!("dm:{}", target)
        } else if let Some(channel) = channel_name {
            channel
        } else {
            return;
        };
        let message_count = messages.len();
        self.last_read_messages
            .insert(conversation_key.clone(), message_count);
        self.unread_counts.remove(&conversation_key);

        // Geohash DM targets can appear under alias/name/pubkey forms.
        // Clear unread counters for keys that resolve to the same DM thread.
        if let Some(current_dm_target) = dm_target.as_deref() {
            let keys_to_remove: Vec<String> = self
                .unread_counts
                .keys()
                .filter_map(|key| {
                    let Some(other_dm_target) = key.strip_prefix("dm:") else {
                        return None;
                    };
                    if self.dm_targets_equivalent(current_dm_target, other_dm_target) {
                        Some(key.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for key in keys_to_remove {
                self.unread_counts.remove(&key);
            }
        }
    }

    fn normalize_mesh_dm_target(value: &str) -> String {
        value
            .trim()
            .trim_start_matches('@')
            .to_ascii_lowercase()
    }

    fn canonical_geohash_dm_target(&self, channel: &str, target: &str) -> String {
        self.resolve_geohash_target_pubkey(channel, target)
            .unwrap_or_else(|| target.trim().to_ascii_lowercase())
    }

    fn dm_targets_equivalent(&self, left: &str, right: &str) -> bool {
        if left == right {
            return true;
        }

        match (Self::parse_geohash_dm_key(left), Self::parse_geohash_dm_key(right)) {
            (Some((left_channel, left_target)), Some((right_channel, right_target))) => {
                if left_channel != right_channel {
                    return false;
                }
                self.canonical_geohash_dm_target(&left_channel, &left_target)
                    == self.canonical_geohash_dm_target(&right_channel, &right_target)
            }
            (None, None) => {
                Self::normalize_mesh_dm_target(left) == Self::normalize_mesh_dm_target(right)
            }
            _ => false,
        }
    }

    pub fn add_unread_message(&mut self, conversation_key: String) {
        let (_, dm_target, channel_name) = self.get_current_messages();
        let current_key = if let Some(target) = dm_target {
            format!("dm:{}", target)
        } else if let Some(channel) = channel_name {
            channel
        } else {
            return;
        };
        if current_key == conversation_key {
            return;
        }
        *self.unread_counts.entry(conversation_key).or_insert(0) += 1;
    }

    pub fn get_unread_count(&self, conversation_key: &str) -> usize {
        self.unread_counts
            .get(conversation_key)
            .copied()
            .unwrap_or(0)
    }

    pub fn get_visible_person_unread_count(&self, person: &str) -> usize {
        if self.current_people_are_geohash() {
            let key = self.geohash_dm_thread_key(&self.get_selected_channel_name(), person);
            self.get_unread_count(&format!("dm:{}", key))
        } else {
            self.get_unread_count(&format!("dm:{}", person))
        }
    }

    pub fn get_section_unread_count(&self, section: usize) -> usize {
        match section {
            0 => {
                if self.get_unread_count("#public") > 0 {
                    1
                } else {
                    0
                }
            }
            1 => self
                .channels
                .iter()
                .map(|ch| self.get_unread_count(ch))
                .sum(),
            2 => {
                if self.current_people_are_geohash() {
                    self.visible_people()
                        .iter()
                        .map(|person| self.get_visible_person_unread_count(person))
                        .sum()
                } else {
                    self.people
                        .iter()
                        .map(|person| self.get_visible_person_unread_count(person))
                        .sum()
                }
            }
            _ => 0,
        }
    }

    pub fn open_nickname_popup(&mut self) {
        self.popup_active = true;
        self.popup_title = "Edit Nickname".to_string();
        self.popup_input = Input::default();
        self.focus_area = FocusArea::InputBox;
    }

    pub fn close_popup(&mut self) {
        self.popup_active = false;
        self.popup_input = Input::default();
        self.popup_title = String::new();
        self.focus_area = FocusArea::Sidebar;
    }

    pub fn update_nickname(&mut self, new_nickname: String) {
        self.nickname = new_nickname.clone();
        self.pending_nickname_update = Some(new_nickname);
    }

    pub fn set_nostr_alias(&mut self, channel: &str, target: &str, alias: &str) -> Option<String> {
        let pubkey = self.resolve_geohash_target_pubkey(channel, target)?;
        self.nostr_aliases.insert(pubkey.clone(), alias.to_string());
        self.add_geohash_person(channel, alias, Some(&pubkey));
        Some(pubkey)
    }

    pub fn trigger_connection_retry(&mut self) {
        self.pending_connection_retry = true;
        self.phase = TuiPhase::Connected;
        self.connected = false;
        self.mesh_status = "Scanning".to_string();
        self.popup_messages.clear();
    }

    pub fn clear_current_conversation(&mut self) {
        // Check if we're in a DM conversation
        let (dm_target, channel_name) = self.current_conv.clone().unwrap_or((None, None));
        if let Some(target) = dm_target {
            // We're in a DM, clear DM messages
            if let Some(messages) = self.dm_messages.get_mut(&target) {
                messages.clear();
            }
        } else if let Some(channel) = channel_name {
            // We're in a channel, clear channel messages
            if let Some(messages) = self.channel_messages.get_mut(&channel) {
                messages.clear();
            }
        } else {
            // Fallback to current channel (shouldn't happen but just in case)
            let current_channel = self.get_selected_channel_name();
            if let Some(messages) = self.channel_messages.get_mut(&current_channel) {
                messages.clear();
            }
        }
        self.scroll_to_bottom_current_conversation();
    }

    pub fn update_blocked_list(&mut self, blocked_nicknames: Vec<String>) {
        self.blocked = blocked_nicknames;
    }

    pub fn update_sidebar_flat_selection(&mut self) {
        let mut flat_idx = 0;
        for section in 0..5 {
            flat_idx += 1;
            if self.sidebar_state.expanded[section] {
                let count = match section {
                    0 => 1,
                    1 => self.channels.len(),
                    2 => self.visible_people_count(),
                    3 => self.blocked.len(),
                    4 => 2,
                    _ => 0,
                };
                let is_current_section = match section {
                    0 => self.sidebar_state.public_selected.unwrap_or(false),
                    1 => self.sidebar_state.channel_selected.is_some(),
                    2 => self.sidebar_state.people_selected.is_some(),
                    _ => false,
                };
                if is_current_section {
                    let item_idx = match section {
                        0 => 0,
                        1 => self.sidebar_state.channel_selected.unwrap_or(0),
                        2 => self.sidebar_state.people_selected.unwrap_or(0),
                        _ => 0,
                    };
                    self.sidebar_flat_selected = flat_idx + item_idx;
                    return;
                }
                flat_idx += count;
            }
        }
    }

    pub fn get_input_box_height(&self, available_width: usize) -> usize {
        let input_text = self.input.value();
        if input_text.is_empty() {
            return 3; // Minimum height
        }

        // Calculate how many lines the input text would need
        let mut lines_needed = 1;
        let mut current_line_width = 0usize;
        let max_line_width = available_width.saturating_sub(2).max(1); // Account for borders

        for ch in input_text.chars() {
            if ch == '\n' {
                lines_needed += 1;
                current_line_width = 0;
            } else {
                let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0);
                if current_line_width > 0 && current_line_width + ch_width > max_line_width {
                    lines_needed += 1;
                    current_line_width = 0;
                }
                current_line_width += ch_width;
                if current_line_width >= max_line_width {
                    lines_needed += 1;
                    current_line_width = 0;
                }
            }
        }

        // Ensure minimum height and reasonable maximum
        std::cmp::max(3, std::cmp::min(lines_needed + 2, 10)) // +2 for borders, max 10 lines
    }
}

fn build_image_picker() -> Picker {
    let mut picker = Picker::new((8, 16));
    let guessed = picker.guess_protocol();
    picker.protocol_type = select_image_protocol_override(guessed);
    picker
}

fn select_image_protocol_override(default: ProtocolType) -> ProtocolType {
    if let Ok(raw) = std::env::var("BITCHAT_IMAGE_PROTOCOL") {
        let value = raw.trim().to_ascii_lowercase();
        let forced = match value.as_str() {
            "kitty" => Some(ProtocolType::Kitty),
            "sixel" => Some(ProtocolType::Sixel),
            "iterm2" | "iterm" => Some(ProtocolType::Iterm2),
            "halfblocks" | "halfblock" => Some(ProtocolType::Halfblocks),
            "auto" | "" => None,
            _ => None,
        };
        if let Some(protocol) = forced {
            return protocol;
        }
    }

    // WezTerm supports Kitty graphics; prefer it over iTerm2 protocol for better
    // image quality and positioning behavior in our TUI preview.
    if let Ok(term_program) = std::env::var("TERM_PROGRAM") {
        if term_program.trim().eq_ignore_ascii_case("wezterm") {
            return ProtocolType::Kitty;
        }
    }

    // If TERM already looks like kitty, force Kitty protocol.
    if let Ok(term) = std::env::var("TERM") {
        if term.to_ascii_lowercase().contains("kitty") {
            return ProtocolType::Kitty;
        }
    }

    default
}

fn extract_preview_image_path(content: &str) -> Option<PathBuf> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(path) = trimmed.strip_prefix("[image] ") {
        let candidate = PathBuf::from(path.trim());
        if looks_like_supported_image_path(&candidate) {
            return Some(candidate);
        }
    }

    let candidate = PathBuf::from(trimmed);
    if looks_like_supported_image_path(&candidate) {
        return Some(candidate);
    }

    None
}

fn looks_like_supported_image_path(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());
    matches!(
        ext.as_deref(),
        Some("png") | Some("jpg") | Some("jpeg") | Some("gif") | Some("webp")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_unread_geohash_dm_for_visible_people() {
        let mut app = App::new_with_nickname("me".to_string());

        app.join_channel("#ws".to_string());
        app.add_log_message("__GEO_DM__:#ws:anon7301:pubkey:1201:first".to_string());
        app.add_log_message("__GEO_DM__:#ws:anon7301:pubkey:1202:second".to_string());

        assert_eq!(app.get_visible_person_unread_count("anon7301"), 2);
        assert_eq!(app.get_section_unread_count(2), 2);

        app.switch_to_geohash_dm("anon7301".to_string());

        assert_eq!(app.get_visible_person_unread_count("anon7301"), 0);
        assert_eq!(app.get_section_unread_count(2), 0);
    }

    #[test]
    fn keeps_scroll_position_and_marks_unseen_when_not_at_bottom() {
        let mut app = App::new_with_nickname("me".to_string());
        app.add_log_message("__CHANNEL__:#public:alice:1200:first".to_string());
        app.add_log_message("__CHANNEL__:#public:alice:1201:second".to_string());

        app.msg_scroll = 1;
        app.note_user_scrolled();
        app.add_log_message("__CHANNEL__:#public:alice:1202:third".to_string());

        assert_eq!(app.msg_scroll, 1);
        assert_eq!(app.unseen_divider_message_index, Some(2));
    }

    #[test]
    fn clears_unseen_marker_when_back_to_bottom() {
        let mut app = App::new_with_nickname("me".to_string());
        app.add_log_message("__CHANNEL__:#public:alice:1200:first".to_string());
        app.add_log_message("__CHANNEL__:#public:alice:1201:second".to_string());

        app.msg_scroll = 1;
        app.note_user_scrolled();
        app.add_log_message("__CHANNEL__:#public:alice:1202:third".to_string());
        assert!(app.unseen_divider_message_index.is_some());

        app.msg_scroll = 0;
        app.note_user_scrolled();
        assert_eq!(app.unseen_divider_message_index, None);
    }

    #[test]
    fn end_prefers_unseen_marker_then_clears_it() {
        let mut app = App::new_with_nickname("me".to_string());
        app.message_viewport_height = 5;
        app.message_rendered_line_count = 20;
        app.msg_scroll = 4;
        app.unseen_divider_message_index = Some(10);
        app.unseen_divider_line_index = Some(12);

        app.jump_to_unseen_or_bottom();

        assert_eq!(app.msg_scroll, 3);
        assert_eq!(app.unseen_divider_message_index, None);
        assert_eq!(app.unseen_divider_line_index, None);
    }

    #[test]
    fn geohash_dm_prefers_canonical_pubkey_thread_keys() {
        let mut app = App::new_with_nickname("me".to_string());
        let pubkey = "4ccaa3888b3b303d28bd9ae6aa2278530232b404abccffa83d9aa815ed2ca4e2";

        app.join_channel("#ws".to_string());
        app.add_log_message(format!("__GEO_PERSON__:#ws:alice:{}", pubkey));
        app.switch_to_geohash_dm("alice".to_string());
        app.add_sent_message("hello".to_string());

        let key = App::geohash_dm_pubkey_key("#ws", pubkey);
        assert!(app.dm_messages.contains_key(&key));
        assert_eq!(app.dm_messages.get(&key).unwrap().len(), 1);
    }

    #[test]
    fn geohash_dm_npub_uses_pubkey_thread_and_short_display() {
        let mut app = App::new_with_nickname("me".to_string());
        let npub = "npub1n7wu4ycqsglag2kmfjdzuvyumktaf79ra5t8km3a9t25rpjgud3qj4plrk";
        let pubkey = crate::nostr_geo::normalize_dm_pubkey(npub).unwrap();

        app.join_channel("#ws".to_string());
        app.add_log_message(format!("__GEO_PERSON__:#ws:bob:{}", pubkey));
        app.switch_to_geohash_dm(npub.to_string());
        app.add_sent_message("hello".to_string());

        let key = App::geohash_dm_pubkey_key("#ws", &pubkey);
        assert!(app.dm_messages.contains_key(&key));
        assert_eq!(
            app.current_geohash_dm(),
            Some(("#ws".to_string(), pubkey.clone(), pubkey))
        );
        assert_eq!(app.sidebar_state.people_selected, Some(0));
    }

    #[test]
    fn geohash_dm_unknown_pubkey_is_shortened_until_name_seen() {
        let mut app = App::new_with_nickname("me".to_string());
        let npub = "npub1n7wu4ycqsglag2kmfjdzuvyumktaf79ra5t8km3a9t25rpjgud3qj4plrk";
        let pubkey = crate::nostr_geo::normalize_dm_pubkey(npub).unwrap();

        app.join_channel("#ws".to_string());
        app.switch_to_geohash_dm(npub.to_string());

        let key = App::geohash_dm_pubkey_key("#ws", &pubkey);
        let expected_suffix = App::stable_suffix_from_id(&pubkey);
        assert_eq!(
            app.display_dm_target(&key),
            format!("anon#{} in #ws", expected_suffix)
        );
        assert_eq!(
            app.display_visible_person(&pubkey),
            format!("anon#{}", expected_suffix)
        );

        app.add_log_message(format!("__GEO_PERSON__:#ws:bob:{}", pubkey));

        assert_eq!(
            app.display_dm_target(&key),
            format!("bob#{} in #ws", expected_suffix)
        );
        assert_eq!(
            app.display_visible_person("bob"),
            format!("bob#{}", expected_suffix)
        );
    }

    #[test]
    fn geohash_profile_metadata_replaces_npub_placeholder() {
        let mut app = App::new_with_nickname("me".to_string());
        let pubkey = "b4600ed4d0f359a1b7e6c64fa62c1f0db7b5c52780cf3fe79931f8a6f13bb661";

        app.join_channel("#ws".to_string());
        app.add_log_message(format!("__CHANNEL__:#ws:npub9fdca93:{}:1201:hello", pubkey));

        let expected_suffix = App::stable_suffix_from_id(pubkey);
        assert_eq!(
            app.display_visible_person(pubkey),
            format!("anon#{}", expected_suffix)
        );

        app.add_log_message(format!("__GEO_PERSON__:#ws:g8.bot:{}", pubkey));

        assert_eq!(
            app.display_visible_person("g8.bot"),
            format!("g8.bot#{}", expected_suffix)
        );
        let msg = app.channel_messages.get("#ws").unwrap().first().unwrap();
        assert_eq!(
            app.display_geohash_sender("#ws", msg),
            format!("g8.bot#{}", expected_suffix)
        );
    }

    #[test]
    fn geohash_profile_metadata_replaces_anon_placeholder_from_dm() {
        let mut app = App::new_with_nickname("me".to_string());
        let pubkey = "b4600ed4d0f359a1b7e6c64fa62c1f0db7b5c52780cf3fe79931f8a6f13bb661";
        let key = App::geohash_dm_pubkey_key("#ws", pubkey);
        let expected_suffix = App::stable_suffix_from_id(pubkey);

        app.join_channel("#ws".to_string());
        app.add_log_message(format!(
            "__GEO_DM__:#ws:anon7301:{}:1201:msg-1:hello",
            pubkey
        ));

        assert_eq!(
            app.display_dm_target(&key),
            format!("anon#{} in #ws", expected_suffix)
        );

        app.add_log_message(format!("__GEO_PERSON__:#ws:g8.bot:{}", pubkey));

        assert_eq!(
            app.display_dm_target(&key),
            format!("g8.bot#{} in #ws", expected_suffix)
        );
    }

    #[test]
    fn pending_geohash_dm_status_updates_in_current_thread() {
        let mut app = App::new_with_nickname("me".to_string());
        let pubkey = "4ccaa3888b3b303d28bd9ae6aa2278530232b404abccffa83d9aa815ed2ca4e2";

        app.join_channel("#ws".to_string());
        app.add_log_message(format!("__GEO_PERSON__:#ws:alice:{}", pubkey));
        app.switch_to_geohash_dm("alice".to_string());
        app.add_pending_geohash_dm_message("hello".to_string(), "local-1".to_string());

        let key = App::geohash_dm_pubkey_key("#ws", pubkey);
        let msg = app.dm_messages.get(&key).unwrap().first().unwrap();
        assert_eq!(msg.status, MessageStatus::Sending);

        app.add_log_message("__GEO_DM_STATUS__:local-1:sent".to_string());
        let msg = app.dm_messages.get(&key).unwrap().first().unwrap();
        assert_eq!(msg.status, MessageStatus::Delivered);

        app.add_log_message("__GEO_DM_STATUS__:local-1:delivered".to_string());
        let msg = app.dm_messages.get(&key).unwrap().first().unwrap();
        assert_eq!(msg.status, MessageStatus::Delivered);

        app.add_log_message("__GEO_DM_STATUS__:local-1:read".to_string());
        let msg = app.dm_messages.get(&key).unwrap().first().unwrap();
        assert_eq!(msg.status, MessageStatus::Read);

        app.add_log_message("__GEO_DM_STATUS__:local-1:sent".to_string());
        let msg = app.dm_messages.get(&key).unwrap().first().unwrap();
        assert_eq!(msg.status, MessageStatus::Read);

        app.add_log_message("__GEO_DM_STATUS__:local-1:delivered".to_string());
        let msg = app.dm_messages.get(&key).unwrap().first().unwrap();
        assert_eq!(msg.status, MessageStatus::Read);
    }

    #[test]
    fn dm_status_does_not_downgrade_delivered_to_sent() {
        let mut app = App::new_with_nickname("me".to_string());
        let pubkey = "4ccaa3888b3b303d28bd9ae6aa2278530232b404abccffa83d9aa815ed2ca4e2";

        app.join_channel("#ws".to_string());
        app.add_log_message(format!("__GEO_PERSON__:#ws:alice:{}", pubkey));
        app.switch_to_geohash_dm("alice".to_string());
        app.add_pending_geohash_dm_message("hello".to_string(), "local-1".to_string());

        let key = App::geohash_dm_pubkey_key("#ws", pubkey);
        app.add_log_message("__GEO_DM_STATUS__:local-1:delivered".to_string());
        app.add_log_message("__GEO_DM_STATUS__:local-1:sent".to_string());

        let msg = app.dm_messages.get(&key).unwrap().first().unwrap();
        assert_eq!(msg.status, MessageStatus::Delivered);
    }

    #[test]
    fn geohash_profile_name_keeps_pubkey_dm_thread_stable() {
        let mut app = App::new_with_nickname("me".to_string());
        let pubkey = "4ccaa3888b3b303d28bd9ae6aa2278530232b404abccffa83d9aa815ed2ca4e2";

        app.join_channel("#ws".to_string());
        app.add_log_message(format!("__GEO_PERSON__:#ws:{}:{}", pubkey, pubkey));
        app.switch_to_geohash_dm(pubkey.to_string());
        app.add_pending_geohash_dm_message("before".to_string(), "local-1".to_string());
        app.add_log_message(format!("__GEO_PERSON__:#ws:g8.bot:{}", pubkey));
        app.switch_to_geohash_dm("g8.bot".to_string());
        app.add_pending_geohash_dm_message("after".to_string(), "local-2".to_string());

        let key = App::geohash_dm_pubkey_key("#ws", pubkey);
        let messages = app.dm_messages.get(&key).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(
            app.current_geohash_dm(),
            Some(("#ws".to_string(), pubkey.to_string(), pubkey.to_string()))
        );
        let expected_suffix = App::stable_suffix_from_id(pubkey);
        assert_eq!(
            app.display_dm_target(&key),
            format!("g8.bot#{} in #ws", expected_suffix)
        );
    }

    #[test]
    fn geohash_presence_counts_active_pubkeys_without_adding_people() {
        let mut app = App::new_with_nickname("me".to_string());
        let now = chrono::Local::now().timestamp();

        app.join_channel("#ws".to_string());
        app.add_log_message(format!(
            "__GEO_PRESENCE__:#ws:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:{}",
            now
        ));
        app.add_log_message(format!(
            "__GEO_PRESENCE__:#ws:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:{}",
            now - crate::nostr_geo::PRESENCE_ACTIVE_WINDOW_SECONDS - 1
        ));

        assert_eq!(app.geohash_active_count_at("#ws", now), 1);
        assert!(app.geohash_people_for_channel("#ws").is_empty());
    }

    #[test]
    fn counts_unread_mesh_dm_for_visible_people() {
        let mut app = App::new_with_nickname("me".to_string());
        app.people.push("anon7301".to_string());
        app.mesh_people_peer_ids
            .insert("anon7301".to_string(), "peer7301".to_string());

        app.add_log_message("__DM__:anon7301:1201:hello".to_string());

        assert_eq!(app.get_visible_person_unread_count("anon7301"), 1);
        assert_eq!(app.display_visible_person("anon7301"), "anon7301");

        app.switch_to_dm("anon7301".to_string());

        assert_eq!(app.get_visible_person_unread_count("anon7301"), 0);
    }

    #[test]
    fn mesh_channel_message_keeps_windows_drive_path_content() {
        let mut app = App::new_with_nickname("me".to_string());
        app.add_log_message(
            "__CHANNEL__:#public:alice:1201:1716000000:[image] X:\\received_files\\images\\incoming\\test.png"
                .to_string(),
        );

        let messages = app.channel_messages.get("#public").unwrap();
        assert_eq!(
            messages.last().unwrap().content,
            "[image] X:\\received_files\\images\\incoming\\test.png"
        );
    }

    #[test]
    fn legacy_dm_without_epoch_keeps_colon_content() {
        let mut app = App::new_with_nickname("me".to_string());
        app.add_log_message("__DM__:anon7301:1201:[image] X:\\a.png".to_string());

        let messages = app.dm_messages.get("anon7301").unwrap();
        assert_eq!(messages.last().unwrap().content, "[image] X:\\a.png");
    }

    #[test]
    fn structured_peer_connected_updates_people() {
        let mut app = App::new_with_nickname("me".to_string());

        app.add_log_message("__PEER_CONNECTED__:anon7301:peer7301".to_string());

        assert_eq!(app.people, vec!["anon7301".to_string()]);
        assert!(app.mesh_people_peer_ids.contains_key("anon7301"));
    }

    #[test]
    fn not_connected_text_does_not_create_person() {
        let mut app = App::new_with_nickname("me".to_string());

        app.add_log_message("system: Bluetooth mesh unavailable: Not connected".to_string());
        app.add_log_message("Not connected".to_string());

        assert!(app.people.is_empty());
    }

    #[test]
    fn transient_system_message_expires_and_is_pruned() {
        let mut app = App::new_with_nickname("me".to_string());

        app.add_transient_system_message(
            "[12:34|DM] <bb> hi".to_string(),
            std::time::Duration::from_millis(0),
        );
        assert_eq!(
            app.channel_messages
                .get("#public")
                .map(|messages| messages.len())
                .unwrap_or(0),
            1
        );

        app.prune_expired_transient_messages();
        assert_eq!(
            app.channel_messages
                .get("#public")
                .map(|messages| messages.len())
                .unwrap_or(0),
            0
        );
    }
}
