// src/tui/ui.rs

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    prelude::Frame,
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use ratatui_image::{FilterType, Resize, StatefulImage};

use crate::tui::{
    app::{App, ImagePreviewRenderState, TuiPhase},
    widgets,
};

pub fn render(app: &mut App, f: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(0),     // Main panel takes remaining space
            Constraint::Length(30), // Sidebar has a fixed width
        ])
        .split(f.size());

    let main_panel_area = chunks[0];
    let sidebar_area = chunks[1];

    // Calculate dynamic input box height
    let input_box_height = app.get_input_box_height(main_panel_area.width as usize) as u16;

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),                   // Message history
            Constraint::Length(input_box_height), // Input box (dynamic height)
            Constraint::Length(1),                // Help bar
        ])
        .split(main_panel_area);

    // Render the main message panel
    widgets::main_panel::render(f, app, main_chunks[0]);

    // Render the input box
    widgets::input_box::render(f, app, main_chunks[1]);

    // Render the help bar
    widgets::help_bar::render(f, app, main_chunks[2]);

    // Render the sidebar
    widgets::sidebar::render(f, app, sidebar_area);

    render_image_preview_overlay(f, app);

    // Render popups if needed (covers everything)
    if app.popup_active {
        widgets::popup::render(f, app, f.size());
    } else {
        match &app.phase {
            TuiPhase::Connecting | TuiPhase::Error(_) => {
                widgets::popup::render(f, app, f.size());
            }
            TuiPhase::Connected => {}
        }
    }
}

fn render_image_preview_overlay(f: &mut Frame, app: &mut App) {
    if app.image_preview.is_none() {
        app.set_image_preview_area(None);
        return;
    }

    let area = centered_rect(f.size(), 92, 82);
    app.set_image_preview_area(Some((area.x, area.y, area.width, area.height)));
    f.render_widget(Clear, area);
    let Some(preview) = app.image_preview.as_mut() else {
        return;
    };

    let title = preview
        .source_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("Image Preview");
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::Gray));
    let inner = block.inner(area);
    f.render_widget(block, area);

    match &mut preview.render_state {
        ImagePreviewRenderState::Ready(state) => {
            if inner.width > 2 && inner.height > 2 {
                let image = StatefulImage::new(None).resize(Resize::Fit(Some(FilterType::Lanczos3)));
                f.render_stateful_widget(image, inner, state);
            }
        }
        ImagePreviewRenderState::Failed(err) => {
            let text = vec![
                Line::styled(
                    "Failed to open image",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::raw(err.as_str()),
                Line::raw(""),
                Line::styled(
                    "Click image or press Esc to close",
                    Style::default().fg(Color::DarkGray),
                ),
            ];
            let p = Paragraph::new(text).wrap(Wrap { trim: false });
            f.render_widget(p, inner);
        }
    }
}

fn centered_rect(area: Rect, width_percent: u16, height_percent: u16) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - height_percent) / 2),
            Constraint::Percentage(height_percent),
            Constraint::Percentage((100 - height_percent) / 2),
        ])
        .split(area);
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - width_percent) / 2),
            Constraint::Percentage(width_percent),
            Constraint::Percentage((100 - width_percent) / 2),
        ])
        .split(vertical[1]);
    horizontal[1]
}
