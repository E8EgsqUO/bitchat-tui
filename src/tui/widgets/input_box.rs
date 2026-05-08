// src/tui/widgets/input_box.rs

use ratatui::{
    prelude::{Frame, Rect},
    style::Style,
    widgets::{Block, Borders, Paragraph},
};
use unicode_width::UnicodeWidthChar;

use crate::tui::app::{App, FocusArea};

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    let border_style = if app.focus_area == FocusArea::InputBox {
        Style::default().fg(ratatui::style::Color::Green)
    } else {
        Style::default().fg(ratatui::style::Color::White)
    };

    // Create wrapped text for the input
    let input_text = app.input.value();
    let available_width = (area.width.saturating_sub(2) as usize).max(1); // Account for borders

    // Split text into lines based on available width
    let lines = wrap_text(&input_text, available_width);

    let input = Paragraph::new(lines)
        .style(Style::default().fg(ratatui::style::Color::Yellow))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Type a message")
                .border_style(border_style),
        );

    f.render_widget(input, area);

    // Calculate cursor position for multi-line input
    let cursor_pos = app.input.cursor();
    let (cursor_line, cursor_col) =
        calculate_cursor_position(&input_text, cursor_pos, available_width);

    f.set_cursor(
        area.x + cursor_col as u16 + 1,
        area.y + cursor_line as u16 + 1,
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WrappedSegment {
    start: usize,
    end: usize,
    width: usize,
    text: String,
}

fn wrap_text(text: &str, max_width: usize) -> Vec<ratatui::text::Line<'static>> {
    wrap_segments(text, max_width)
        .into_iter()
        .map(|segment| ratatui::text::Line::from(segment.text))
        .collect()
}

fn wrap_segments(text: &str, max_width: usize) -> Vec<WrappedSegment> {
    let max_width = max_width.max(1);
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
        return vec![WrappedSegment {
            start: 0,
            end: 0,
            width: 0,
            text: String::new(),
        }];
    }

    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut current = String::new();
    let mut width = 0usize;
    let mut idx = 0usize;

    while idx < chars.len() {
        let ch = chars[idx];
        if ch == '\n' {
            lines.push(WrappedSegment {
                start,
                end: idx,
                width,
                text: std::mem::take(&mut current),
            });
            idx += 1;
            start = idx;
            width = 0;
            continue;
        }

        let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if width > 0 && width + ch_width > max_width {
            lines.push(WrappedSegment {
                start,
                end: idx,
                width,
                text: std::mem::take(&mut current),
            });
            start = idx;
            width = 0;
            continue;
        }

        current.push(ch);
        width += ch_width;
        idx += 1;
    }

    lines.push(WrappedSegment {
        start,
        end: chars.len(),
        width,
        text: current,
    });

    if width >= max_width {
        lines.push(WrappedSegment {
            start: chars.len(),
            end: chars.len(),
            width: 0,
            text: String::new(),
        });
    }

    lines
}

fn calculate_cursor_position(text: &str, cursor_chars: usize, max_width: usize) -> (usize, usize) {
    let chars: Vec<char> = text.chars().collect();
    let cursor_chars = cursor_chars.min(chars.len());
    let segments = wrap_segments(text, max_width);

    for (line_idx, segment) in segments.iter().enumerate() {
        if cursor_chars >= segment.start && cursor_chars <= segment.end {
            if cursor_chars == segment.end
                && segment.width >= max_width.max(1)
                && line_idx + 1 < segments.len()
            {
                return (line_idx + 1, 0);
            }

            let col = chars[segment.start..cursor_chars]
                .iter()
                .map(|ch| UnicodeWidthChar::width(*ch).unwrap_or(0))
                .sum::<usize>();
            return (line_idx, col);
        }
    }

    let last_idx = segments.len().saturating_sub(1);
    let last_width = segments.last().map(|segment| segment.width).unwrap_or(0);
    (last_idx, last_width)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_uses_display_width_for_wide_chars() {
        assert_eq!(calculate_cursor_position("你好啊", 3, 20), (0, 6));
    }

    #[test]
    fn cursor_wraps_at_display_width() {
        assert_eq!(calculate_cursor_position("你好吗", 2, 4), (1, 0));
        assert_eq!(calculate_cursor_position("你好吗", 3, 4), (1, 2));
    }
}
