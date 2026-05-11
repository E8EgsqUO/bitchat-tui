// src/tui/widgets/sidebar.rs

use ratatui::{
    prelude::{Frame, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
};

use crate::tui::app::{App, FocusArea};

// Helper to calculate what items are visible for navigation
pub fn sidebar_visible_items(app: &App) -> Vec<(usize, Option<usize>)> {
    let mut items = Vec::new();
    for section in 0..5 {
        // Now 5 sections: Public, Channels, People, Blocked, Settings
        items.push((section, None)); // Section header
        if app.sidebar_state.expanded[section] {
            let count = match section {
                0 => 1, // Public: always 1 item
                1 => app.channels.len(),
                2 => app.visible_people_count(),
                3 => app.blocked.len(),
                4 => 2, // Settings: Nickname, Network
                _ => 0,
            };
            for idx in 0..count {
                items.push((section, Some(idx)));
            }
        }
    }
    items
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let mut items: Vec<ListItem> = Vec::new();
    let section_titles = ["Public", "Channels", "People", "Blocked", "Settings"];
    let icons = ["🌐", "#", "@", "🚫", "⚙"];

    let _visible_items = sidebar_visible_items(app);
    let mut flat_idx = 0;

    for (i, section_title) in section_titles.iter().enumerate() {
        let section_label = if i == 2 && app.current_people_are_geohash() {
            let channel = app.get_selected_channel_name();
            let active_count = app.geohash_active_count(&channel);
            if active_count > 0 {
                format!("People ({} active)", active_count)
            } else {
                "People (seen)".to_string()
            }
        } else {
            (*section_title).to_string()
        };
        let is_selected = app.sidebar_flat_selected == flat_idx;
        let mut style = if is_selected && app.focus_area == FocusArea::Sidebar {
            Style::default().bg(Color::Blue).fg(Color::White)
        } else {
            Style::default()
        };

        let arrow = if app.sidebar_state.expanded[i] {
            "▼"
        } else {
            "▶"
        };

        // Add unread indicator for sections that can have unread messages
        let unread_count = app.get_section_unread_count(i);
        let unread_indicator = if unread_count > 0 {
            Span::styled(" ●", Style::default().fg(Color::Rgb(255, 165, 0))) // Orange circle
        } else {
            Span::raw("")
        };

        let section_line = Line::from(vec![
            Span::styled(
                format!("{} {}", icons[i], section_label),
                Style::default().bold(),
            ),
            unread_indicator,
            Span::raw(format!(" {}", arrow)),
        ]);
        items.push(ListItem::new(section_line).style(style));
        flat_idx += 1;

        if app.sidebar_state.expanded[i] {
            let list: Vec<(String, String, Color, bool)> = match i {
                0 => vec![(
                    "Public Chat".to_string(),
                    "#public".to_string(),
                    Color::Yellow,
                    app.sidebar_state.public_selected.unwrap_or(false),
                )], // Public section
                1 => app
                    .channels
                    .iter()
                    .enumerate()
                    .map(|(idx, s)| {
                        (
                            s.clone(),
                            s.clone(),
                            Color::Cyan,
                            app.sidebar_state.channel_selected == Some(idx),
                        )
                    })
                    .collect(),
                2 => app
                    .visible_people()
                    .iter()
                    .enumerate()
                    .map(|(idx, s)| {
                        (
                            app.display_visible_person(s),
                            s.clone(),
                            Color::Green,
                            app.sidebar_state.people_selected == Some(idx),
                        )
                    })
                    .collect(),
                3 => app
                    .blocked
                    .iter()
                    .map(|s| (s.clone(), s.clone(), Color::Red, false))
                    .collect(),
                _ => vec![],
            };

            for (item_str, item_key, color, is_active_conv) in list {
                let is_selected = app.sidebar_flat_selected == flat_idx;

                // Add unread count for individual items
                let unread_count = match i {
                    0 => app.get_unread_count(&item_key), // Public
                    1 => app.get_unread_count(&item_key), // Channels
                    2 => app.get_visible_person_unread_count(&item_key),
                    _ => 0,
                };

                let unread_indicator = if unread_count > 0 {
                    Span::styled(
                        format!(" ({})", unread_count),
                        Style::default().fg(Color::Rgb(255, 165, 0)),
                    )
                } else {
                    Span::raw("")
                };

                // Create the line with proper styling for active conversation
                let mut spans = vec![Span::raw("  ")];

                if is_selected && app.focus_area == FocusArea::Sidebar {
                    // Cursor selection: blue background, white text
                    spans.push(Span::styled(
                        item_str.clone(),
                        Style::default().bg(Color::Blue).fg(Color::White),
                    ));
                } else if is_active_conv {
                    // Active conversation: green background, white text (only for the item text)
                    spans.push(Span::styled(
                        item_str.clone(),
                        Style::default().bg(Color::Green).fg(Color::White),
                    ));
                } else {
                    // Normal item: colored text
                    spans.push(Span::styled(item_str.clone(), Style::default().fg(color)));
                }

                spans.push(unread_indicator);

                items.push(ListItem::new(Line::from(spans)));
                flat_idx += 1;
            }

            if i == 4 {
                // Settings
                // Nickname
                let is_selected = app.sidebar_flat_selected == flat_idx;
                style = if is_selected && app.focus_area == FocusArea::Sidebar {
                    Style::default().bg(Color::Blue).fg(Color::White)
                } else {
                    Style::default()
                };
                items.push(ListItem::new(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(format!("Nick: {}", app.nickname), style),
                ])));
                flat_idx += 1;
                // Status
                let is_selected = app.sidebar_flat_selected == flat_idx;
                style = if is_selected && app.focus_area == FocusArea::Sidebar {
                    Style::default().bg(Color::Blue).fg(Color::White)
                } else {
                    Style::default()
                };
                items.push(ListItem::new(Line::from(vec![
                    Span::raw("  "),
                    Span::styled("Mesh: ", style),
                    Span::styled(
                        app.mesh_status.as_str(),
                        if app.connected {
                            Style::default().fg(Color::Green)
                        } else if app.mesh_status == "Scanning" {
                            Style::default().fg(Color::Yellow)
                        } else {
                            Style::default().fg(Color::Red)
                        },
                    ),
                ])));
                flat_idx += 1;
            }
        }
    }

    let border_style = if app.focus_area == FocusArea::Sidebar {
        Style::default().fg(Color::Green)
    } else {
        Style::default()
    };
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Navigation")
            .border_style(border_style),
    );
    f.render_widget(list, area);
}
