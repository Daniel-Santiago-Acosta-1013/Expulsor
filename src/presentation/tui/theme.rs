//! Definición de colores y estilos coherentes con una TUI de aspecto profesional.

use ratatui::style::{Color, Modifier, Style};

/// Colección de estilos reutilizables para los distintos widgets de la interfaz.
#[derive(Clone)]
pub struct Theme {
    pub normal: Style,
    pub emphasis: Style,
    pub warning: Style,
    pub error: Style,
    pub table_header: Style,
    pub selection: Style,
    pub blocked_row: Style,
    pub error_row: Style,
    pub dimmed: Style,
}

impl Theme {
    /// Crea la paleta base de la aplicación.
    pub fn default() -> Self {
        Self {
            normal: Style::default().fg(Color::Gray),
            emphasis: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            warning: Style::default().fg(Color::Yellow),
            error: Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            table_header: Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            selection: Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            blocked_row: Style::default().fg(Color::LightRed),
            error_row: Style::default().fg(Color::Yellow),
            dimmed: Style::default().fg(Color::DarkGray),
        }
    }
}
