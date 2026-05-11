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
    let header_text = if let Some(user) = dm_target {
        format!("Direct Message with {}", app.display_dm_target(&user))
    } else if let Some(channel) = channel_name {
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
    let all_msg_items = render_message_lines(app, messages, messages_area.width);
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
) -> Vec<ListItem<'static>> {
    messages
        .iter()
        .flat_map(|msg| message_to_list_items(app, msg, area_width))
        .collect()
}

fn message_to_list_items(app: &App, msg: &Message, area_width: u16) -> Vec<ListItem<'static>> {
    let color = if msg.sender == "system" {
        Color::White
    } else if msg.is_self {
        Color::Cyan
    } else {
        Color::LightGreen
    };

    let timestamp = format!("[{}]", msg.timestamp);
    let sender_text = if let Some(pubkey) = &msg.sender_pubkey {
        if let Some(channel) = app.current_geohash_context_channel() {
            app.geohash_person_name_by_pubkey(&channel, pubkey)
                .unwrap_or_else(|| App::short_pubkey(pubkey))
        } else {
            App::short_pubkey(pubkey)
        }
    } else {
        msg.sender.clone()
    };
    let sender = format!("{}:", sender_text);
    let timestamp_width = UnicodeWidthStr::width(timestamp.as_str());
    let sender_width = UnicodeWidthStr::width(sender.as_str());
    let prefix_width = timestamp_width + 1 + sender_width + 1;
    let available_width = area_width.saturating_sub(2) as usize;
    let status_marker = message_status_marker(msg.status);
    let status_reserve = status_marker
        .as_ref()
        .map(|(text, _)| UnicodeWidthStr::width(*text) + 1)
        .unwrap_or_default();
    let content_width = available_width
        .saturating_sub(prefix_width + status_reserve)
        .max(1);
    let continuation_indent = " ".repeat(prefix_width.min(available_width.saturating_sub(1)));

    let wrapped_lines = wrap_display_width(&msg.content, content_width);
    let last_idx = wrapped_lines.len().saturating_sub(1);
    wrapped_lines
        .into_iter()
        .enumerate()
        .map(|(idx, line_content)| {
            let is_last_line = idx == last_idx;
            if idx == 0 {
                let mut spans = vec![
                    Span::styled(timestamp.clone(), Style::default().fg(Color::DarkGray)),
                    Span::raw(" "),
                    Span::styled(
                        sender.clone(),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" "),
                    Span::raw(line_content),
                ];
                append_status_marker(
                    &mut spans,
                    status_marker,
                    is_last_line,
                    available_width,
                    prefix_width,
                );
                ListItem::new(Line::from(spans))
            } else {
                let indent_width = UnicodeWidthStr::width(continuation_indent.as_str());
                let mut spans = vec![
                    Span::raw(continuation_indent.clone()),
                    Span::raw(line_content),
                ];
                append_status_marker(
                    &mut spans,
                    status_marker,
                    is_last_line,
                    available_width,
                    indent_width,
                );
                ListItem::new(Line::from(spans))
            }
        })
        .collect()
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

fn append_status_marker(
    spans: &mut Vec<Span<'static>>,
    marker: Option<(&'static str, Style)>,
    is_last_line: bool,
    available_width: usize,
    prefix_width: usize,
) {
    let Some((text, style)) = marker else {
        return;
    };
    if !is_last_line {
        return;
    }

    let marker_width = UnicodeWidthStr::width(text);
    let content_width = spans
        .last()
        .map(|span| UnicodeWidthStr::width(span.content.as_ref()))
        .unwrap_or_default();
    let current_width = prefix_width + content_width;
    let padding_width = available_width.saturating_sub(current_width + marker_width);
    if padding_width > 0 {
        spans.push(Span::raw(" ".repeat(padding_width)));
    }
    spans.push(Span::styled(text, style));
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
    fn wraps_long_messages_into_visual_lines() {
        let app = App::new_with_nickname("me".to_string());
        let message = Message {
            sender: "bot".to_string(),
            sender_pubkey: None,
            timestamp: "12:00".to_string(),
            content: "one two three four five six seven".to_string(),
            is_self: false,
            status: MessageStatus::None,
            local_id: None,
        };

        assert!(message_to_list_items(&app, &message, 24).len() > 1);
    }

    #[test]
    fn wraps_wide_characters_by_display_width() {
        assert_eq!(wrap_display_width("你好世界", 4), vec!["你好", "世界"]);
    }
}
