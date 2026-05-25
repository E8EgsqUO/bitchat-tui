// src/tui/event.rs

use base64::Engine as _;
use crossterm::event::{
    Event as CrosstermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton,
    MouseEvent, MouseEventKind,
};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tui_input::backend::crossterm::EventHandler;
use tui_input::InputRequest;

use crate::tui::app::{App, FocusArea, MessageLineCopyTarget};
use crate::tui::widgets::sidebar::sidebar_visible_items;

const MAX_GLOBAL_HISTORY_SCROLL_STEP: usize = 8;
const DOUBLE_CLICK_WINDOW: Duration = Duration::from_millis(350);
const COPY_HIGHLIGHT_DURATION: Duration = Duration::from_millis(1000);
const PASTE_BURST_CHAR_WINDOW: Duration = Duration::from_millis(45);
const PASTE_BURST_ENTER_WINDOW: Duration = Duration::from_millis(120);
const PASTE_FAST_ENTER_WINDOW: Duration = Duration::from_millis(45);
const PASTE_BURST_MIN_CHARS: u16 = 5;

pub fn handle_key_event(app: &mut App, key_event: KeyEvent, input_tx: &mpsc::Sender<String>) {
    if key_event.kind != KeyEventKind::Press {
        return;
    }
    if key_event.code == KeyCode::Char('c') && key_event.modifiers == KeyModifiers::CONTROL {
        app.should_quit = true;
        return;
    }
    if matches!(app.phase, crate::tui::app::TuiPhase::Error(_))
        && key_event.code == KeyCode::Char('r')
    {
        app.trigger_connection_retry();
        return;
    }
    if app.image_preview_is_open() {
        if key_event.code == KeyCode::Esc {
            app.close_image_preview();
        }
        return;
    }
    if app.popup_active {
        handle_popup_events(app, key_event, input_tx);
        return;
    }
    if handle_global_message_scroll(app, key_event) {
        return;
    }
    if key_event.code == KeyCode::Tab {
        app.focus_area = match app.focus_area {
            FocusArea::Sidebar | FocusArea::MainPanel => FocusArea::InputBox,
            FocusArea::InputBox => FocusArea::Sidebar,
        };
        return;
    }
    match app.focus_area {
        FocusArea::Sidebar => handle_sidebar_events(app, key_event),
        FocusArea::MainPanel => handle_main_panel_events(app, key_event),
        FocusArea::InputBox => handle_input_events(app, key_event, input_tx),
    }
}

pub fn handle_paste_event(app: &mut App, pasted: &str) {
    if app.popup_active {
        insert_text_into_input(&mut app.popup_input, pasted);
        return;
    }

    if app.input.value().trim().is_empty() {
        if let Some(paths) = detect_dragged_file_paths(pasted) {
            let command = build_file_share_command_from_paths(app, &paths);
            app.focus_area = FocusArea::InputBox;
            app.input.reset();
            let _ = insert_text_into_input(&mut app.input, &command);
            if paths.len() > 1 {
                let action = file_share_action_name(app);
                app.add_log_message(format!(
                    "system: Detected {} files from drag-and-drop. Prepared {} for the first one. Send it, then drag the next file.",
                    paths.len(),
                    action
                ));
            }
            app.paste_keyburst_active = false;
            app.last_input_char_event_at = None;
            app.input_char_burst_count = 0;
            return;
        }
    }

    app.focus_area = FocusArea::InputBox;
    let _ = insert_text_into_input(&mut app.input, pasted);
    app.paste_keyburst_active = false;
    app.last_input_char_event_at = None;
    app.input_char_burst_count = 0;
}

fn detect_dragged_file_paths(pasted: &str) -> Option<Vec<String>> {
    let trimmed = pasted.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut paths: Vec<String> = Vec::new();
    for raw in trimmed.lines() {
        let candidate = raw.trim();
        if candidate.is_empty() {
            continue;
        }
        let unquoted = strip_wrapping_quotes(candidate);
        if looks_like_upload_file_reference(unquoted) {
            paths.push(unquoted.to_string());
        } else {
            return None;
        }
    }

    if paths.is_empty() {
        None
    } else {
        Some(paths)
    }
}

fn looks_like_windows_file_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return true;
    }
    value.starts_with("\\\\")
}

fn looks_like_filename_token(value: &str) -> bool {
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return false;
    }
    let has_ext = value
        .rsplit_once('.')
        .map(|(base, ext)| {
            !base.is_empty() && ext.chars().all(|ch| ch.is_ascii_alphanumeric()) && !ext.is_empty()
        })
        .unwrap_or(false);
    has_ext
}

fn looks_like_upload_file_reference(value: &str) -> bool {
    if Path::new(value).is_file() {
        return true;
    }

    if value.chars().any(char::is_whitespace) {
        return false;
    }

    looks_like_windows_file_path(value)
        || value.contains('/')
        || value.contains('\\')
        || looks_like_filename_token(value)
}

fn strip_wrapping_quotes(value: &str) -> &str {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn quote_for_upload_command(path: &str) -> String {
    if path.chars().any(char::is_whitespace) {
        format!("\"{}\"", path.replace('"', "\\\""))
    } else {
        path.to_string()
    }
}

fn file_share_command_prefix(app: &App) -> &'static str {
    if app.current_geohash_context_channel().is_some() {
        "/upload"
    } else {
        "/file"
    }
}

fn file_share_action_name(app: &App) -> &'static str {
    if app.current_geohash_context_channel().is_some() {
        "upload"
    } else {
        "Bluetooth file transfer"
    }
}

fn build_file_share_command_from_paths(app: &App, paths: &[String]) -> String {
    let first = paths.first().map(String::as_str).unwrap_or("");
    format!(
        "{} {}",
        file_share_command_prefix(app),
        quote_for_upload_command(first)
    )
}

fn file_share_command_from_freeform_input(app: &App, value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with('/') || trimmed.contains('\n') {
        return None;
    }
    let unquoted = strip_wrapping_quotes(trimmed);
    // Do not reinterpret links/deep-links as local upload paths.
    if unquoted.contains("://") {
        return None;
    }
    if !looks_like_upload_file_reference(unquoted) {
        return None;
    }
    Some(format!(
        "{} {}",
        file_share_command_prefix(app),
        quote_for_upload_command(unquoted)
    ))
}

pub fn handle_mouse_event(app: &mut App, mouse_event: MouseEvent) {
    if app.image_preview_is_open() {
        if matches!(mouse_event.kind, MouseEventKind::Up(MouseButton::Left))
            && app.image_preview_contains_position(mouse_event.row, mouse_event.column)
        {
            app.close_image_preview();
        }
        return;
    }
    if app.popup_active {
        return;
    }
    if !matches!(mouse_event.kind, MouseEventKind::Up(MouseButton::Left)) {
        return;
    }

    let Some(target) = app.visible_copy_target_at_position(mouse_event.row, mouse_event.column)
    else {
        return;
    };
    let conversation_key = app.current_conversation_key();
    let now = Instant::now();
    let click_kind = 1;

    let is_double_click = app
        .last_message_click
        .as_ref()
        .map(|last| {
            last.kind == click_kind
                && last.target == target
                && last.row == mouse_event.row
                && last.conversation_key == conversation_key
                && now.duration_since(last.clicked_at) <= DOUBLE_CLICK_WINDOW
        })
        .unwrap_or(false);

    if is_double_click {
        app.last_message_click = None;
        if let Some(text) = app.copy_text_for_target(&target) {
            if let Err(err) = copy_message_text(&text) {
                app.add_log_message(format!("system: Failed to copy message: {}", err));
            } else {
                app.show_copy_highlight(target, COPY_HIGHLIGHT_DURATION);
            }
        }
        return;
    }

    if let MessageLineCopyTarget::Message(index) = target.clone() {
        if app.open_image_preview_for_message(index).is_ok() {
            app.last_message_click = None;
            return;
        }
    }

    app.last_message_click = Some(crate::tui::app::MessageClickState {
        row: mouse_event.row,
        kind: click_kind,
        target,
        conversation_key,
        clicked_at: now,
    });
}

fn copy_message_text(text: &str) -> Result<(), String> {
    match arboard::Clipboard::new().and_then(|mut clipboard| clipboard.set_text(text.to_string())) {
        Ok(_) => Ok(()),
        Err(arboard_error) => copy_via_osc52(text).map_err(|osc_error| {
            format!("{} (OSC52 fallback failed: {})", arboard_error, osc_error)
        }),
    }
}

fn copy_via_osc52(text: &str) -> Result<(), String> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    let sequence = if std::env::var_os("TMUX").is_some() {
        format!("\x1bPtmux;\x1b\x1b]52;c;{}\x07\x1b\\", encoded)
    } else {
        format!("\x1b]52;c;{}\x07", encoded)
    };

    let mut stdout = std::io::stdout();
    stdout
        .write_all(sequence.as_bytes())
        .map_err(|e| format!("stdout write error: {}", e))?;
    stdout
        .flush()
        .map_err(|e| format!("stdout flush error: {}", e))?;
    Ok(())
}

fn insert_text_into_input(input: &mut tui_input::Input, text: &str) -> bool {
    let mut changed = false;
    for ch in text.chars() {
        match ch {
            '\r' => {}
            _ => {
                let _ = input.handle(InputRequest::InsertChar(ch));
                changed = true;
            }
        }
    }
    changed
}

fn handle_global_message_scroll(app: &mut App, key_event: KeyEvent) -> bool {
    let total_lines = app.message_rendered_line_count;
    let messages_height = app.message_viewport_height;
    let max_scroll = total_lines.saturating_sub(messages_height);
    let scroll_step = global_history_scroll_step(messages_height);

    match key_event.code {
        KeyCode::PageUp => {
            app.msg_scroll = (app.msg_scroll + scroll_step).min(max_scroll);
            app.note_user_scrolled();
            true
        }
        KeyCode::PageDown => {
            app.msg_scroll = app.msg_scroll.saturating_sub(scroll_step);
            app.note_user_scrolled();
            true
        }
        KeyCode::Home => {
            app.msg_scroll = max_scroll;
            app.note_user_scrolled();
            true
        }
        KeyCode::End => {
            app.jump_to_unseen_or_bottom();
            true
        }
        _ => false,
    }
}

fn global_history_scroll_step(messages_height: usize) -> usize {
    (messages_height / 2)
        .max(1)
        .min(MAX_GLOBAL_HISTORY_SCROLL_STEP)
}

fn handle_sidebar_events(app: &mut App, key_event: KeyEvent) {
    let visible_items = sidebar_visible_items(app);
    let current_selection = app.sidebar_flat_selected;
    match key_event.code {
        KeyCode::Tab => app.focus_area = FocusArea::InputBox,
        KeyCode::Down => {
            if !visible_items.is_empty() {
                app.sidebar_flat_selected = (current_selection + 1) % visible_items.len();
            }
        }
        KeyCode::Up => {
            if !visible_items.is_empty() {
                app.sidebar_flat_selected = if current_selection == 0 {
                    visible_items.len() - 1
                } else {
                    current_selection - 1
                };
            }
        }
        KeyCode::Enter => {
            if let Some(&(section_idx, child_opt)) = visible_items.get(app.sidebar_flat_selected) {
                if let Some(child_idx) = child_opt {
                    match section_idx {
                        0 => {
                            app.sidebar_state.public_selected = Some(true);
                            app.switch_to_public();
                        }
                        1 => {
                            if let Some(channel_name) = app.channels.get(child_idx) {
                                app.switch_to_channel(channel_name.clone());
                            }
                        }
                        2 => {
                            if app.current_people_are_geohash() {
                                if let Some(person_name) = app.visible_person_at(child_idx) {
                                    app.switch_to_geohash_dm(person_name);
                                }
                            } else if let Some(person_name) = app.visible_person_at(child_idx) {
                                app.switch_to_dm(person_name.clone());
                            }
                        }
                        3 => app.sidebar_state.blocked_selected = Some(child_idx),
                        4 => {
                            if child_idx == 0 {
                                app.open_nickname_popup();
                            }
                        }
                        _ => {}
                    }
                    if section_idx != 1 {
                        app.update_current_conversation();
                    }
                } else {
                    app.sidebar_state.toggle_expand(section_idx);
                }
            }
        }
        _ => {}
    }
}

fn handle_main_panel_events(app: &mut App, key_event: KeyEvent) {
    let total_lines = app.message_rendered_line_count;
    let messages_height = app.message_viewport_height;
    let max_scroll = total_lines.saturating_sub(messages_height);

    match key_event.code {
        KeyCode::Tab => app.focus_area = FocusArea::InputBox,
        KeyCode::Up => {
            app.msg_scroll = (app.msg_scroll + 1).min(max_scroll);
            app.note_user_scrolled();
        }
        KeyCode::Down => {
            app.msg_scroll = app.msg_scroll.saturating_sub(1);
            app.note_user_scrolled();
        }
        KeyCode::Home => {
            app.msg_scroll = max_scroll;
            app.note_user_scrolled();
        }
        KeyCode::End => {
            app.scroll_to_bottom_current_conversation();
        }
        _ => {}
    }
}

fn handle_popup_events(app: &mut App, key_event: KeyEvent, _input_tx: &mpsc::Sender<String>) {
    match key_event.code {
        KeyCode::Enter => {
            let new_nickname = app.popup_input.value().to_string();
            if !new_nickname.is_empty() {
                app.update_nickname(new_nickname);
                app.close_popup();
            }
        }
        KeyCode::Esc => app.close_popup(),
        _ => {
            // FIX: Ignore the return value of handle_event
            let _ = app
                .popup_input
                .handle_event(&CrosstermEvent::Key(key_event));
        }
    }
}

fn handle_input_events(app: &mut App, key_event: KeyEvent, input_tx: &mpsc::Sender<String>) {
    match key_event.code {
        KeyCode::Char(ch)
            if ch.eq_ignore_ascii_case(&'a')
                && key_event.modifiers.contains(KeyModifiers::CONTROL) =>
        {
            let _ = app.input.handle(InputRequest::GoToStart);
        }
        KeyCode::Char(ch)
            if ch.eq_ignore_ascii_case(&'e')
                && key_event.modifiers.contains(KeyModifiers::CONTROL) =>
        {
            let _ = app.input.handle(InputRequest::GoToEnd);
        }
        KeyCode::Char(ch)
            if ch.eq_ignore_ascii_case(&'u')
                && key_event.modifiers.contains(KeyModifiers::CONTROL) =>
        {
            app.input.reset();
            app.paste_keyburst_active = false;
            app.last_input_char_event_at = None;
            app.input_char_burst_count = 0;
        }
        KeyCode::Char(ch)
            if ch.eq_ignore_ascii_case(&'v')
                && key_event.modifiers.contains(KeyModifiers::CONTROL) =>
        {
            match arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
                Ok(text) => {
                    let _ = insert_text_into_input(&mut app.input, &text);
                }
                Err(err) => {
                    app.add_log_message(format!("system: Clipboard paste failed: {}", err));
                }
            }
            app.paste_keyburst_active = false;
            app.last_input_char_event_at = None;
            app.input_char_burst_count = 0;
        }
        KeyCode::Insert if key_event.modifiers.contains(KeyModifiers::SHIFT) => {
            match arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
                Ok(text) => {
                    let _ = insert_text_into_input(&mut app.input, &text);
                }
                Err(err) => {
                    app.add_log_message(format!("system: Clipboard paste failed: {}", err));
                }
            }
            app.paste_keyburst_active = false;
            app.last_input_char_event_at = None;
            app.input_char_burst_count = 0;
        }
        KeyCode::Enter => {
            let now = Instant::now();
            let burst_enter = app.paste_keyburst_active
                && app
                    .last_input_char_event_at
                    .map(|last| now.duration_since(last) <= PASTE_BURST_ENTER_WINDOW)
                    .unwrap_or(false);
            let fast_enter_after_char = app
                .last_input_char_event_at
                .map(|last| now.duration_since(last) <= PASTE_FAST_ENTER_WINDOW)
                .unwrap_or(false);
            if burst_enter || fast_enter_after_char {
                let _ = app.input.handle(InputRequest::InsertChar('\n'));
                return;
            }

            if key_event.modifiers.contains(KeyModifiers::SHIFT) {
                let _ = app.input.handle(InputRequest::InsertChar('\n'));
                return;
            }

            let input_str = app.input.value().to_string();
            let outgoing = file_share_command_from_freeform_input(app, &input_str)
                .unwrap_or(input_str.clone());
            if !input_str.is_empty() {
                if input_tx.try_send(outgoing.clone()).is_ok() {
                    let is_mesh_dm = app.current_geohash_dm().is_none()
                        && app
                            .current_conv
                            .as_ref()
                            .and_then(|(dm, _)| dm.as_ref())
                            .is_some();
                    if !outgoing.starts_with('/')
                        && app.current_geohash_dm().is_none()
                        && !is_mesh_dm
                    {
                        app.add_sent_message(outgoing);
                    }
                    app.input.reset();
                    app.paste_keyburst_active = false;
                    app.last_input_char_event_at = None;
                    app.input_char_burst_count = 0;
                }
            }
        }
        KeyCode::Esc => {}
        _ => {
            let before = app.input.value().to_string();
            let _ = app.input.handle_event(&CrosstermEvent::Key(key_event));
            let changed = app.input.value() != before;
            let plain_char = matches!(key_event.code, KeyCode::Char(_))
                && !key_event.modifiers.contains(KeyModifiers::CONTROL)
                && !key_event.modifiers.contains(KeyModifiers::ALT);

            if changed && plain_char {
                let now = Instant::now();
                let in_burst = app
                    .last_input_char_event_at
                    .map(|last| now.duration_since(last) <= PASTE_BURST_CHAR_WINDOW)
                    .unwrap_or(false);
                app.input_char_burst_count = if in_burst {
                    app.input_char_burst_count.saturating_add(1)
                } else {
                    1
                };
                app.last_input_char_event_at = Some(now);
                app.paste_keyburst_active = app.input_char_burst_count >= PASTE_BURST_MIN_CHARS;
            } else if changed {
                app.paste_keyburst_active = false;
                app.last_input_char_event_at = None;
                app.input_char_burst_count = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::MessageLineCopyTarget;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn mouse_down_left(row: u16, column: u16) -> MouseEvent {
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn mouse_up_left(row: u16, column: u16) -> MouseEvent {
        MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn release_char(ch: char) -> KeyEvent {
        KeyEvent::new_with_kind(KeyCode::Char(ch), KeyModifiers::NONE, KeyEventKind::Release)
    }

    #[test]
    fn page_scroll_is_global_and_incremental() {
        let (input_tx, _input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        app.focus_area = FocusArea::InputBox;
        app.message_rendered_line_count = 100;
        app.message_viewport_height = 20;

        handle_key_event(&mut app, key(KeyCode::PageUp), &input_tx);
        assert_eq!(app.msg_scroll, MAX_GLOBAL_HISTORY_SCROLL_STEP);

        handle_key_event(&mut app, key(KeyCode::PageUp), &input_tx);
        assert_eq!(app.msg_scroll, MAX_GLOBAL_HISTORY_SCROLL_STEP * 2);

        handle_key_event(&mut app, key(KeyCode::PageDown), &input_tx);
        assert_eq!(app.msg_scroll, MAX_GLOBAL_HISTORY_SCROLL_STEP);
    }

    #[test]
    fn pasted_emoji_is_sent_on_enter() {
        let (input_tx, mut input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        app.focus_area = FocusArea::InputBox;

        handle_paste_event(&mut app, "🙂");
        assert_eq!(app.input.value(), "🙂");

        handle_key_event(&mut app, key(KeyCode::Enter), &input_tx);

        assert_eq!(input_rx.try_recv().unwrap(), "🙂");
        assert_eq!(app.input.value(), "");
        let public_messages = app.channel_messages.get("#public").unwrap();
        assert_eq!(public_messages.last().unwrap().content, "🙂");
    }

    #[test]
    fn shift_enter_inserts_newline_and_enter_sends() {
        let (input_tx, mut input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        app.focus_area = FocusArea::InputBox;

        handle_paste_event(&mut app, "line1\nline2");
        assert_eq!(app.input.value(), "line1\nline2");

        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT),
            &input_tx,
        );
        assert_eq!(app.input.value(), "line1\nline2\n");
        assert!(input_rx.try_recv().is_err());

        handle_key_event(&mut app, key(KeyCode::Enter), &input_tx);

        assert_eq!(input_rx.try_recv().unwrap(), "line1\nline2\n");
        assert_eq!(app.input.value(), "");
    }

    #[test]
    fn single_line_paste_still_sends_with_single_enter() {
        let (input_tx, mut input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        app.focus_area = FocusArea::InputBox;

        handle_paste_event(&mut app, "line1 line2");
        assert_eq!(app.input.value(), "line1 line2");

        handle_key_event(&mut app, key(KeyCode::Enter), &input_tx);
        assert_eq!(input_rx.try_recv().unwrap(), "line1 line2");
        assert_eq!(app.input.value(), "");
    }

    #[test]
    fn enter_converts_windows_path_like_input_to_mesh_file_command() {
        let (input_tx, mut input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        app.focus_area = FocusArea::InputBox;
        handle_paste_event(&mut app, "D:\\test.png");

        handle_key_event(&mut app, key(KeyCode::Enter), &input_tx);

        assert_eq!(input_rx.try_recv().unwrap(), "/file D:\\test.png");
    }

    #[test]
    fn enter_converts_filename_token_to_mesh_file_command() {
        let (input_tx, mut input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        app.focus_area = FocusArea::InputBox;
        handle_paste_event(&mut app, "photo.jpg");

        handle_key_event(&mut app, key(KeyCode::Enter), &input_tx);

        assert_eq!(input_rx.try_recv().unwrap(), "/file photo.jpg");
    }

    #[test]
    fn enter_converts_path_to_upload_command_in_geohash() {
        let (input_tx, mut input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        app.focus_area = FocusArea::InputBox;
        app.join_channel("#ws".to_string());
        app.update_current_conversation();
        handle_paste_event(&mut app, "photo.jpg");

        handle_key_event(&mut app, key(KeyCode::Enter), &input_tx);

        assert_eq!(input_rx.try_recv().unwrap(), "/upload photo.jpg");
    }

    #[test]
    fn mixed_text_with_path_fragment_is_not_converted_to_upload() {
        let (input_tx, mut input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        app.focus_area = FocusArea::InputBox;
        handle_paste_event(&mut app, "test D:\\t.png");

        handle_key_event(&mut app, key(KeyCode::Enter), &input_tx);

        assert_eq!(input_rx.try_recv().unwrap(), "test D:\\t.png");
    }

    #[test]
    fn deep_link_is_not_converted_to_upload_command() {
        let (input_tx, mut input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        app.focus_area = FocusArea::InputBox;
        handle_paste_event(
            &mut app,
            "bitchat://verify?v=1&noise=abc&sign=def&nick=me&ts=1&nonce=x&sig=y",
        );

        handle_key_event(&mut app, key(KeyCode::Enter), &input_tx);

        assert_eq!(
            input_rx.try_recv().unwrap(),
            "bitchat://verify?v=1&noise=abc&sign=def&nick=me&ts=1&nonce=x&sig=y"
        );
    }

    #[test]
    fn enter_sends_immediately() {
        let (input_tx, mut input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        app.focus_area = FocusArea::InputBox;
        handle_paste_event(&mut app, "hello");

        handle_key_event(&mut app, key(KeyCode::Enter), &input_tx);
        assert_eq!(input_rx.try_recv().unwrap(), "hello");
        assert_eq!(app.input.value(), "");
    }

    #[test]
    fn geohash_dm_input_is_not_echoed_by_event_layer() {
        let (input_tx, mut input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        let pubkey = "4ccaa3888b3b303d28bd9ae6aa2278530232b404abccffa83d9aa815ed2ca4e2";
        let dm_key = App::geohash_dm_pubkey_key("#ws", pubkey);
        app.focus_area = FocusArea::InputBox;
        app.join_channel("#ws".to_string());
        app.add_log_message(format!("__GEO_PERSON__:#ws:alice:{}", pubkey));
        app.switch_to_geohash_dm("alice".to_string());

        handle_paste_event(&mut app, "hello");
        handle_key_event(&mut app, key(KeyCode::Enter), &input_tx);

        assert_eq!(input_rx.try_recv().unwrap(), "hello");
        assert_eq!(app.input.value(), "");
        assert!(app
            .dm_messages
            .get(&dm_key)
            .map(Vec::is_empty)
            .unwrap_or(true));
    }

    #[test]
    fn ctrl_u_clears_input_for_fast_reset() {
        let (input_tx, _input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        app.focus_area = FocusArea::InputBox;
        handle_paste_event(&mut app, "to be cleared");
        assert_eq!(app.input.value(), "to be cleared");

        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
            &input_tx,
        );
        assert_eq!(app.input.value(), "");
    }

    #[test]
    fn ctrl_a_and_ctrl_e_move_cursor_start_and_end() {
        let (input_tx, _input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        app.focus_area = FocusArea::InputBox;
        handle_paste_event(&mut app, "abc");

        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL),
            &input_tx,
        );
        handle_key_event(&mut app, key(KeyCode::Char('X')), &input_tx);
        assert_eq!(app.input.value(), "Xabc");

        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL),
            &input_tx,
        );
        handle_key_event(&mut app, key(KeyCode::Char('Y')), &input_tx);
        assert_eq!(app.input.value(), "XabcY");
    }

    #[test]
    fn ime_composition_key_releases_are_ignored() {
        let (input_tx, _input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());

        handle_key_event(&mut app, release_char('v'), &input_tx);
        handle_key_event(&mut app, release_char('b'), &input_tx);
        handle_key_event(&mut app, key(KeyCode::Char('好')), &input_tx);

        assert_eq!(app.input.value(), "好");
    }

    #[test]
    fn escape_does_not_clear_input_text() {
        let (input_tx, _input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());

        handle_paste_event(&mut app, "🙂");
        handle_key_event(&mut app, key(KeyCode::Esc), &input_tx);

        assert_eq!(app.input.value(), "🙂");
    }

    #[test]
    fn error_retry_key_takes_priority_over_text_input() {
        let (input_tx, _input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        app.phase = crate::tui::app::TuiPhase::Error("failed".to_string());

        handle_key_event(&mut app, key(KeyCode::Char('r')), &input_tx);

        assert!(app.pending_connection_retry);
        assert_eq!(app.input.value(), "");
    }

    #[test]
    fn drag_and_drop_file_path_prefills_mesh_file_command() {
        let mut app = App::new_with_nickname("me".to_string());
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(format!("bitchat_upload_{}.txt", std::process::id()));
        std::fs::write(&path, "ok").expect("write temp file");
        let pasted = path.to_string_lossy().to_string();

        handle_paste_event(&mut app, &pasted);

        assert_eq!(
            app.input.value(),
            format!("/file {}", quote_for_upload_command(&pasted))
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn single_click_records_last_message_click() {
        let mut app = App::new_with_nickname("me".to_string());
        app.messages_area_rect = Some((0, 0, 40, 8));
        app.message_first_visible_index = 0;
        app.message_line_copy_targets = vec![Some(MessageLineCopyTarget::Message(0))];
        app.add_sent_message("hello".to_string());

        handle_mouse_event(&mut app, mouse_down_left(1, 5));

        assert!(app.last_message_click.is_some());
    }

    #[test]
    fn single_mouse_up_click_is_tracked_for_double_click_compatibility() {
        let mut app = App::new_with_nickname("me".to_string());
        app.messages_area_rect = Some((0, 0, 40, 8));
        app.message_first_visible_index = 0;
        app.message_line_copy_targets = vec![Some(MessageLineCopyTarget::Message(0))];
        app.add_sent_message("hello".to_string());

        handle_mouse_event(&mut app, mouse_up_left(1, 5));

        assert!(app.last_message_click.is_some());
    }

    #[test]
    fn single_click_image_message_opens_preview_and_escape_closes() {
        let (input_tx, _input_rx) = mpsc::channel(1);
        let mut app = App::new_with_nickname("me".to_string());
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(format!(
            "bitchat_preview_{}_{}.png",
            std::process::id(),
            chrono::Local::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
        ));
        let image = image::RgbaImage::from_pixel(2, 2, image::Rgba([0, 255, 0, 255]));
        image.save(&path).expect("save png");
        app.add_sent_message(format!("[image] {}", path.to_string_lossy()));
        app.messages_area_rect = Some((0, 0, 80, 12));
        app.message_first_visible_index = 0;
        app.message_line_copy_targets = vec![Some(MessageLineCopyTarget::Message(0))];

        handle_mouse_event(&mut app, mouse_down_left(1, 5));
        assert!(app.image_preview_is_open());

        handle_key_event(&mut app, key(KeyCode::Esc), &input_tx);
        assert!(!app.image_preview_is_open());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn click_in_preview_area_closes_preview() {
        let mut app = App::new_with_nickname("me".to_string());
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(format!(
            "bitchat_preview_{}_{}_2.png",
            std::process::id(),
            chrono::Local::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
        ));
        let image = image::RgbaImage::from_pixel(2, 2, image::Rgba([0, 0, 255, 255]));
        image.save(&path).expect("save png");
        app.add_sent_message(format!("[image] {}", path.to_string_lossy()));

        assert!(app.open_image_preview_for_message(0).is_ok());
        app.set_image_preview_area(Some((10, 5, 30, 10)));
        handle_mouse_event(&mut app, mouse_down_left(8, 20));

        assert!(!app.image_preview_is_open());
        let _ = std::fs::remove_file(path);
    }
}
