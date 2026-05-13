// src/tui/event.rs

use base64::Engine as _;
use crossterm::event::{
    Event as CrosstermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton,
    MouseEvent, MouseEventKind,
};
use std::io::Write;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tui_input::backend::crossterm::EventHandler;
use tui_input::InputRequest;

use crate::tui::app::{App, FocusArea, MessageLineCopyTarget};
use crate::tui::widgets::sidebar::sidebar_visible_items;

const MAX_GLOBAL_HISTORY_SCROLL_STEP: usize = 8;
const DOUBLE_CLICK_WINDOW: Duration = Duration::from_millis(350);
const COPY_HIGHLIGHT_DURATION: Duration = Duration::from_millis(1000);

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

    app.focus_area = FocusArea::InputBox;
    insert_text_into_input(&mut app.input, pasted);
}

pub fn handle_mouse_event(app: &mut App, mouse_event: MouseEvent) {
    if app.popup_active {
        return;
    }
    if !matches!(
        mouse_event.kind,
        MouseEventKind::Down(MouseButton::Left) | MouseEventKind::Up(MouseButton::Left)
    ) {
        return;
    }

    let Some(target) = app.visible_copy_target_at_position(mouse_event.row, mouse_event.column)
    else {
        return;
    };
    let conversation_key = app.current_conversation_key();
    let now = Instant::now();
    let click_kind = match mouse_event.kind {
        MouseEventKind::Down(MouseButton::Left) => 0,
        MouseEventKind::Up(MouseButton::Left) => 1,
        _ => 2,
    };

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

fn insert_text_into_input(input: &mut tui_input::Input, text: &str) {
    for ch in text.chars() {
        match ch {
            '\r' => {}
            _ => {
                let _ = input.handle(InputRequest::InsertChar(ch));
            }
        }
    }
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
        KeyCode::Enter => {
            let input_str = app.input.value().to_string();
            if !input_str.is_empty() {
                if input_tx.try_send(input_str.clone()).is_ok() {
                    let is_mesh_dm = app.current_geohash_dm().is_none()
                        && app
                            .current_conv
                            .as_ref()
                            .and_then(|(dm, _)| dm.as_ref())
                            .is_some();
                    if !input_str.starts_with('/')
                        && app.current_geohash_dm().is_none()
                        && !is_mesh_dm
                    {
                        app.add_sent_message(input_str);
                    }
                    app.input.reset();
                }
            }
        }
        KeyCode::Esc => {}
        _ => {
            // FIX: Ignore the return value of handle_event
            let _ = app.input.handle_event(&CrosstermEvent::Key(key_event));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
