// src/tui/widgets/main_panel.rs

use ratatui::{
    prelude::{Constraint, Direction, Frame, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
    },
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::tui::app::{App, FocusArea, Message, MessageStatus};

const TIME_DIVIDER_GAP_MINUTES: i32 = 15;
const OTHER_MESSAGE_INDENT: usize = 4;
const DM_OTHER_INDENT: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum MessageRole {
    System,
    SelfUser,
    Other,
}

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Message history
        ])
        .split(area);

    let header_area = chunks[0];
    let messages_area = chunks[1];

    // Update the viewport height before borrowing `app` for messages
    app.message_viewport_height = messages_area.height.saturating_sub(2) as usize;

    // Get the current conversation messages
    let (messages, dm_target, channel_name) = app.get_current_messages();

    // --- Header Rendering ---
    let header_text = if let Some(ref user) = dm_target {
        format!("Direct Message with {}", app.display_dm_target(user))
    } else if let Some(ref channel) = channel_name {
        if channel == "#public" {
            "Public Chat".to_string()
        } else if crate::nostr_geo::is_geohash_channel(&channel) {
            let active_count = app.geohash_active_count(&channel);
            if active_count > 0 {
                format!("Channel: {} ({} active)", channel, active_count)
            } else {
                format!("Channel: {}", channel)
            }
        } else {
            format!("Channel: {}", channel)
        }
    } else {
        if app.get_selected_channel_name() == "#public" {
            "Public Chat".to_string()
        } else if crate::nostr_geo::is_geohash_channel(&app.get_selected_channel_name()) {
            let channel = app.get_selected_channel_name();
            let active_count = app.geohash_active_count(&channel);
            if active_count > 0 {
                format!("Channel: {} ({} active)", channel, active_count)
            } else {
                format!("Channel: {}", channel)
            }
        } else {
            format!("Channel: {}", app.get_selected_channel_name())
        }
    };
    let header = Paragraph::new(header_text)
        .block(Block::default().borders(Borders::ALL).title("Conversation"))
        .style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(header, header_area);

    // --- Message Panel Rendering ---
    let messages_height = app.message_viewport_height;
    let all_msg_items = render_message_lines(
        app,
        messages,
        messages_area.width,
        dm_target.as_deref(),
        channel_name.as_deref(),
    );
    let total_lines = all_msg_items.len();
    app.message_rendered_line_count = total_lines;

    let max_scroll = total_lines.saturating_sub(messages_height);
    app.msg_scroll = app.msg_scroll.min(max_scroll);
    let end = total_lines.saturating_sub(app.msg_scroll);
    let start = end.saturating_sub(messages_height);
    let msg_items = all_msg_items.into_iter().skip(start).take(end - start);

    let border_style = if app.focus_area == FocusArea::MainPanel {
        Style::default().fg(Color::Green)
    } else {
        Style::default()
    };

    let list = List::new(msg_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Messages")
                .border_style(border_style),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(list, messages_area);

    // --- Scrollbar Rendering ---
    // Fix: Use scroll positions as content length, and invert app.msg_scroll for correct direction
    let (scrollbar_content_length, scrollbar_viewport_length, scrollbar_position) =
        if total_lines > messages_height {
            let content_length = max_scroll + 1;
            let position = max_scroll.saturating_sub(app.msg_scroll);
            // Set viewport length to a reasonable fraction of the content length for consistent thumb size
            let viewport_length = std::cmp::max(1, content_length / 10);
            (content_length, viewport_length, position)
        } else {
            (1, 1, 0)
        };

    let mut scrollbar_state = ScrollbarState::default()
        .content_length(scrollbar_content_length)
        .viewport_content_length(scrollbar_viewport_length)
        .position(scrollbar_position);

    // Render the scrollbar only if scrolling is actually possible (prevents unnecessary rendering)
    if total_lines > messages_height {
        f.render_stateful_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼")),
            messages_area, // Use full area to allow scrollbar to extend to bottom
            &mut scrollbar_state,
        );
    }
}

fn render_message_lines(
    app: &App,
    messages: &[Message],
    area_width: u16,
    dm_target: Option<&str>,
    channel_name: Option<&str>,
) -> Vec<ListItem<'static>> {
    let available_width = area_width.saturating_sub(2) as usize;
    let geohash_channel = channel_name
        .filter(|channel| crate::nostr_geo::is_geohash_channel(channel))
        .map(ToString::to_string)
        .or_else(|| app.current_geohash_context_channel());
    let is_dm = dm_target.is_some();
    let last_self_idx = messages.iter().rposition(|msg| msg.is_self);

    let mut items = Vec::new();
    for (idx, msg) in messages.iter().enumerate() {
        let prev = idx
            .checked_sub(1)
            .and_then(|prev_idx| messages.get(prev_idx));
        let group_starts_here = is_group_start(app, messages, idx, geohash_channel.as_deref());
        if should_insert_time_divider(prev, msg) {
            items.push(centered_item(
                msg.timestamp.clone(),
                available_width,
                Style::default().fg(Color::Gray),
            ));
        }

        let role = message_role(msg);
        let sender_display = resolved_sender(app, msg, geohash_channel.as_deref());
        let show_sender_label = !is_dm && role == MessageRole::Other && group_starts_here;
        let content_indent = if role == MessageRole::Other {
            if is_dm {
                DM_OTHER_INDENT
            } else {
                OTHER_MESSAGE_INDENT
            }
        } else {
            0
        };
        if show_sender_label {
            if idx > 0 {
                items.push(empty_line_item());
            }
            items.push(render_aligned_message_line(
                format!("{}:", sender_display),
                role,
                available_width,
                None,
                0,
                true,
                false,
            ));
        }
        let body = format_message_body(msg, role);
        let reserve_trailing_slot = is_dm && role != MessageRole::System;
        let show_status = if role == MessageRole::SelfUser && Some(idx) == last_self_idx {
            message_status_marker(msg.status)
        } else {
            None
        };
        let status_reserve = if reserve_trailing_slot { 2 } else { 0 };
        let wrap_width = available_width
            .saturating_sub(status_reserve)
            .saturating_sub(content_indent)
            .max(1);
        let wrapped_lines = wrap_display_width(&body, wrap_width);
        let last_line_idx = wrapped_lines.len().saturating_sub(1);

        for (line_idx, wrapped) in wrapped_lines.into_iter().enumerate() {
            let status = if line_idx == last_line_idx {
                show_status
            } else {
                None
            };
            items.push(render_aligned_message_line(
                wrapped,
                role,
                available_width,
                status,
                content_indent,
                false,
                reserve_trailing_slot && line_idx == last_line_idx,
            ));
        }

        if role == MessageRole::SelfUser
            && is_group_end(app, messages, idx, geohash_channel.as_deref())
        {
            items.push(separator_item(role, available_width));
        }
    }

    items
}

fn message_status_marker(status: MessageStatus) -> Option<(&'static str, Style)> {
    match status {
        MessageStatus::None | MessageStatus::Sending => None,
        MessageStatus::Delivered => Some(("✓", Style::default().fg(Color::Green))),
        MessageStatus::Read => Some(("✓", Style::default().fg(Color::LightBlue))),
        MessageStatus::Failed => Some((
            "!",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
    }
}

fn render_aligned_message_line(
    line: String,
    role: MessageRole,
    available_width: usize,
    status: Option<(&'static str, Style)>,
    content_indent: usize,
    is_sender_label: bool,
    reserve_status_slot: bool,
) -> ListItem<'static> {
    let base_style = match role {
        MessageRole::System => Style::default().fg(Color::Gray),
        MessageRole::SelfUser => Style::default().fg(Color::LightGreen),
        MessageRole::Other => {
            if is_sender_label {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            }
        }
    };
    let line_width = UnicodeWidthStr::width(line.as_str());

    match role {
        _ if reserve_status_slot => {
            let total_width = line_width.saturating_add(2);
            let leading = match role {
                MessageRole::SelfUser => available_width.saturating_sub(total_width),
                MessageRole::Other => content_indent,
                MessageRole::System => available_width.saturating_sub(total_width) / 2,
            };
            let mut spans = vec![Span::raw(" ".repeat(leading))];
            spans.extend(content_spans_with_file_icon(line, base_style));
            spans.push(Span::raw(" "));
            if role == MessageRole::SelfUser {
                if let Some((marker, marker_style)) = status {
                    spans.push(Span::styled(marker, marker_style));
                } else {
                    spans.push(Span::raw(" "));
                }
            } else {
                spans.push(Span::raw(" "));
            }
            ListItem::new(Line::from(spans))
        }
        _ => {
            let leading = match role {
                MessageRole::System => available_width.saturating_sub(line_width) / 2,
                MessageRole::SelfUser => available_width.saturating_sub(line_width),
                MessageRole::Other => content_indent,
            };
            let mut spans = vec![Span::raw(" ".repeat(leading))];
            spans.extend(content_spans_with_file_icon(line, base_style));
            ListItem::new(Line::from(spans))
        }
    }
}

fn content_spans_with_file_icon(line: String, base_style: Style) -> Vec<Span<'static>> {
    let Some((icon_idx, _)) = line.char_indices().find(|(_, ch)| *ch == '📎') else {
        return vec![Span::styled(line, base_style)];
    };

    let icon_end = icon_idx + '📎'.len_utf8();
    let before = &line[..icon_idx];
    let after = &line[icon_end..];
    let mut spans = Vec::new();
    if !before.is_empty() {
        spans.push(Span::styled(before.to_string(), base_style));
    }
    spans.push(Span::styled("📎", Style::default().fg(Color::Yellow)));
    if !after.is_empty() {
        spans.push(Span::styled(after.to_string(), base_style));
    }
    spans
}

fn centered_item(text: String, available_width: usize, style: Style) -> ListItem<'static> {
    let text_width = UnicodeWidthStr::width(text.as_str());
    let leading = available_width.saturating_sub(text_width) / 2;
    ListItem::new(Line::from(vec![
        Span::raw(" ".repeat(leading)),
        Span::styled(text, style),
    ]))
}

fn separator_item(role: MessageRole, available_width: usize) -> ListItem<'static> {
    let line_width = (available_width / 3).max(8).min(available_width);
    let leading = match role {
        MessageRole::Other => 0,
        MessageRole::SelfUser => available_width.saturating_sub(line_width),
        MessageRole::System => available_width.saturating_sub(line_width) / 2,
    };
    let separator = "-".repeat(line_width);
    ListItem::new(Line::from(vec![
        Span::raw(" ".repeat(leading)),
        Span::styled(
            separator,
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::DIM),
        ),
    ]))
}

fn empty_line_item() -> ListItem<'static> {
    ListItem::new(Line::from(Span::raw(String::new())))
}

fn format_message_body(msg: &Message, role: MessageRole) -> String {
    match role {
        MessageRole::System | MessageRole::SelfUser | MessageRole::Other => msg.content.clone(),
    }
}

fn resolved_sender(app: &App, msg: &Message, geohash_channel: Option<&str>) -> String {
    if let Some(pubkey) = &msg.sender_pubkey {
        if let Some(channel) = geohash_channel {
            return app
                .geohash_person_name_by_pubkey(channel, pubkey)
                .unwrap_or_else(|| App::short_pubkey(pubkey));
        }
        return App::short_pubkey(pubkey);
    }
    msg.sender.clone()
}

fn message_role(message: &Message) -> MessageRole {
    if message.sender == "system" {
        MessageRole::System
    } else if message.is_self {
        MessageRole::SelfUser
    } else {
        MessageRole::Other
    }
}

fn message_group_key(app: &App, message: &Message, geohash_channel: Option<&str>) -> String {
    match message_role(message) {
        MessageRole::System => "system".to_string(),
        MessageRole::SelfUser => "self".to_string(),
        MessageRole::Other => {
            if let Some(pubkey) = &message.sender_pubkey {
                if let Some(channel) = geohash_channel {
                    if let Some(name) = app.geohash_person_name_by_pubkey(channel, pubkey) {
                        return format!("other:{name}:{pubkey}");
                    }
                }
                return format!("other:{pubkey}");
            }
            format!("other:{}", message.sender)
        }
    }
}

fn is_group_end(
    app: &App,
    messages: &[Message],
    index: usize,
    geohash_channel: Option<&str>,
) -> bool {
    let Some(current) = messages.get(index) else {
        return false;
    };
    let Some(next) = messages.get(index + 1) else {
        return true;
    };
    message_group_key(app, current, geohash_channel)
        != message_group_key(app, next, geohash_channel)
}

fn is_group_start(
    app: &App,
    messages: &[Message],
    index: usize,
    geohash_channel: Option<&str>,
) -> bool {
    let Some(current) = messages.get(index) else {
        return false;
    };
    let Some(previous) = index.checked_sub(1).and_then(|prev| messages.get(prev)) else {
        return true;
    };
    message_group_key(app, current, geohash_channel)
        != message_group_key(app, previous, geohash_channel)
}

fn should_insert_time_divider(previous: Option<&Message>, current: &Message) -> bool {
    let Some(previous) = previous else {
        return true;
    };
    let Some(prev_minutes) = parse_timestamp_minutes(&previous.timestamp) else {
        return true;
    };
    let Some(curr_minutes) = parse_timestamp_minutes(&current.timestamp) else {
        return true;
    };

    let mut delta = curr_minutes - prev_minutes;
    if delta < 0 {
        delta += 24 * 60;
    }
    delta > TIME_DIVIDER_GAP_MINUTES
}

fn parse_timestamp_minutes(value: &str) -> Option<i32> {
    let (hour, minute) = value.split_once(':')?;
    let hour = hour.parse::<i32>().ok()?;
    let minute = minute.parse::<i32>().ok()?;
    if !(0..24).contains(&hour) || !(0..60).contains(&minute) {
        return None;
    }
    Some(hour * 60 + minute)
}

fn wrap_display_width(text: &str, max_width: usize) -> Vec<String> {
    if text.is_empty() {
        return vec![String::new()];
    }

    let max_width = max_width.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut line_width = 0usize;
    let mut last_break = None;

    for ch in text.chars() {
        if ch == '\n' {
            lines.push(line.trim_end().to_string());
            line.clear();
            line_width = 0;
            last_break = None;
            continue;
        }

        let ch_width = ch.width().unwrap_or(0);
        if !line.is_empty() && line_width + ch_width > max_width {
            if let Some(break_idx) = last_break {
                let remainder = line[break_idx..].trim_start().to_string();
                line.truncate(break_idx);
                lines.push(line.trim_end().to_string());
                line = remainder;
                line_width = UnicodeWidthStr::width(line.as_str());
                last_break = last_whitespace_boundary(&line);
            } else {
                lines.push(line);
                line = String::new();
                line_width = 0;
                last_break = None;
            }
        }

        line.push(ch);
        line_width += ch_width;
        if ch.is_whitespace() {
            last_break = Some(line.len());
        }
    }

    lines.push(line.trim_end().to_string());
    lines
}

fn last_whitespace_boundary(value: &str) -> Option<usize> {
    value
        .char_indices()
        .filter_map(|(idx, ch)| ch.is_whitespace().then_some(idx + ch.len_utf8()))
        .last()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_wide_characters_by_display_width() {
        assert_eq!(wrap_display_width("你好世界", 4), vec!["你好", "世界"]);
    }

    #[test]
    fn inserts_time_divider_for_first_message_and_large_gap() {
        let first = Message {
            sender: "alice".to_string(),
            sender_pubkey: None,
            timestamp: "10:00".to_string(),
            content: "hello".to_string(),
            is_self: false,
            status: MessageStatus::None,
            local_id: None,
        };
        let second = Message {
            timestamp: "10:10".to_string(),
            ..first.clone()
        };
        let third = Message {
            timestamp: "10:31".to_string(),
            ..first.clone()
        };

        assert!(should_insert_time_divider(None, &first));
        assert!(!should_insert_time_divider(Some(&first), &second));
        assert!(should_insert_time_divider(Some(&second), &third));
    }

    #[test]
    fn detects_group_end_only_when_sender_changes() {
        let app = App::new_with_nickname("me".to_string());
        let messages = vec![
            Message {
                sender: "alice".to_string(),
                sender_pubkey: None,
                timestamp: "10:00".to_string(),
                content: "a".to_string(),
                is_self: false,
                status: MessageStatus::None,
                local_id: None,
            },
            Message {
                sender: "alice".to_string(),
                sender_pubkey: None,
                timestamp: "10:01".to_string(),
                content: "b".to_string(),
                is_self: false,
                status: MessageStatus::None,
                local_id: None,
            },
            Message {
                sender: "me".to_string(),
                sender_pubkey: None,
                timestamp: "10:02".to_string(),
                content: "c".to_string(),
                is_self: true,
                status: MessageStatus::None,
                local_id: None,
            },
        ];

        assert!(!is_group_end(&app, &messages, 0, None));
        assert!(is_group_end(&app, &messages, 1, None));
        assert!(is_group_end(&app, &messages, 2, None));
    }
}
