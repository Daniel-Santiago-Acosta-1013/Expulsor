//! Implementación de la interfaz de usuario de terminal.

pub mod components;
pub mod theme;

use crate::app::commands::CommandDispatcher;
use crate::app::state::AppState;
use crate::domain::actions::AppAction;
use crate::domain::device::{DeviceRecord, DeviceStatus};
use crate::domain::logs::LogLevel;
use crate::domain::settings::ScanKind;
use crate::presentation::tui::theme::Theme;
use crate::utils::shutdown::ShutdownSignal;
use anyhow::Result;
use chrono::Utc;
use crossterm::cursor::Show;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, Clear as TerminalClear, ClearType, EnterAlternateScreen,
    LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Terminal;
use std::cmp::{max, min};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Interfaz de texto que imita el estilo de herramientas como k9s pero enfocada en control de red.
pub struct Tui {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    state: Arc<Mutex<AppState>>,
    dispatcher: CommandDispatcher,
    shutdown: ShutdownSignal,
    ui: UiState,
    theme: Theme,
    spinner: Spinner,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FocusPane {
    Devices,
    Logs,
}

#[derive(Clone)]
struct UiState {
    selected_index: usize,
    focus: FocusPane,
    log_scroll: u16,
}

impl UiState {
    fn new() -> Self {
        Self {
            selected_index: 0,
            focus: FocusPane::Devices,
            log_scroll: 0,
        }
    }
}

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

struct Spinner {
    index: usize,
    last_tick: Instant,
    interval: Duration,
}

impl Default for Spinner {
    fn default() -> Self {
        Self {
            index: 0,
            last_tick: Instant::now(),
            interval: Duration::from_millis(100),
        }
    }
}

impl Spinner {
    fn frame(&mut self) -> &'static str {
        let now = Instant::now();
        if now.duration_since(self.last_tick) >= self.interval {
            self.index = (self.index + 1) % SPINNER_FRAMES.len();
            self.last_tick = now;
        }
        SPINNER_FRAMES[self.index]
    }

    fn reset(&mut self) {
        self.index = 0;
        self.last_tick = Instant::now();
    }
}

impl Tui {
    /// Construye la TUI configurando el backend de terminal requerido.
    pub fn new(
        state: Arc<Mutex<AppState>>,
        dispatcher: CommandDispatcher,
        shutdown: ShutdownSignal,
    ) -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, TerminalClear(ClearType::All))?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        Ok(Self {
            terminal,
            state,
            dispatcher,
            shutdown,
            ui: UiState::new(),
            theme: Theme::default(),
            spinner: Spinner::default(),
        })
    }

    /// Ejecuta el bucle principal de dibujo y gestión de eventos.
    pub async fn run(&mut self) -> Result<()> {
        while !self.shutdown.is_triggered() {
            let snapshot = {
                let guard = self.state.lock().await;
                guard.clone()
            };
            self.sync_selection(&snapshot);
            self.render(&snapshot)?;

            if event::poll(std::time::Duration::from_millis(90))? {
                if let Event::Key(key) = event::read()? {
                    if key.code == KeyCode::Char('q') && key.modifiers.is_empty() {
                        break;
                    }
                    self.handle_key(key, &snapshot).await?;
                }
            }
        }

        self.shutdown.trigger();
        disable_raw_mode()?;
        Ok(())
    }

    fn sync_selection(&mut self, snapshot: &AppState) {
        if snapshot.devices.is_empty() {
            self.ui.selected_index = 0;
        } else {
            self.ui.selected_index = min(self.ui.selected_index, snapshot.devices.len() - 1);
        }
    }

    async fn handle_key(&mut self, key: event::KeyEvent, snapshot: &AppState) -> Result<()> {
        match (self.ui.focus, key.code, key.modifiers) {
            (FocusPane::Devices, KeyCode::Up, _) => self.move_selection(snapshot, -1),
            (FocusPane::Devices, KeyCode::Down, _) => self.move_selection(snapshot, 1),
            (FocusPane::Devices, KeyCode::PageUp, _) => self.move_selection(snapshot, -5),
            (FocusPane::Devices, KeyCode::PageDown, _) => self.move_selection(snapshot, 5),
            (FocusPane::Devices, KeyCode::Char('b'), _) => {
                self.trigger_block(snapshot, true).await?
            }
            (FocusPane::Devices, KeyCode::Char('u'), _) => {
                self.trigger_block(snapshot, false).await?
            }
            (FocusPane::Devices, KeyCode::Enter, _) => self.trigger_scan_device(snapshot).await?,
            (FocusPane::Devices, KeyCode::Char('a'), _) => {
                self.dispatcher
                    .submit(AppAction::ToggleAggressiveMode)
                    .await?;
            }
            (FocusPane::Logs, KeyCode::Up, _) => {
                self.ui.log_scroll = self.ui.log_scroll.saturating_sub(1);
            }
            (FocusPane::Logs, KeyCode::Down, _) => {
                self.ui.log_scroll = self.ui.log_scroll.saturating_add(1);
            }
            (_, KeyCode::Tab, _) => self.toggle_focus(),
            (_, KeyCode::Char('r'), modifiers)
                if modifiers.contains(KeyModifiers::CONTROL)
                    || modifiers.contains(KeyModifiers::SUPER) =>
            {
                self.dispatcher
                    .submit(AppAction::ScanNetwork {
                        mode: ScanKind::Deep,
                    })
                    .await?;
            }
            (_, KeyCode::Char('r'), modifiers) if modifiers.is_empty() => {
                self.dispatcher
                    .submit(AppAction::ScanNetwork {
                        mode: ScanKind::Quick,
                    })
                    .await?;
            }
            (_, KeyCode::Char('R'), KeyModifiers::SHIFT) => {
                self.dispatcher
                    .submit(AppAction::ScanNetwork {
                        mode: ScanKind::Deep,
                    })
                    .await?;
            }
            _ => {}
        }
        Ok(())
    }

    fn toggle_focus(&mut self) {
        self.ui.focus = match self.ui.focus {
            FocusPane::Devices => FocusPane::Logs,
            FocusPane::Logs => FocusPane::Devices,
        };
    }

    fn move_selection(&mut self, snapshot: &AppState, delta: isize) {
        if snapshot.devices.is_empty() {
            self.ui.selected_index = 0;
            return;
        }
        let len = snapshot.devices.len() as isize;
        let current = self.ui.selected_index as isize;
        let next = max(0, min(len - 1, current + delta));
        self.ui.selected_index = next as usize;
    }

    async fn trigger_scan_device(&self, snapshot: &AppState) -> Result<()> {
        if let Some(device) = self.current_device(snapshot) {
            self.dispatcher
                .submit(AppAction::ScanDevice {
                    identity: device.identity.clone(),
                })
                .await?;
        }
        Ok(())
    }

    async fn trigger_block(&self, snapshot: &AppState, block: bool) -> Result<()> {
        if let Some(device) = self.current_device(snapshot) {
            let action = if block {
                AppAction::BlockDevice {
                    identity: device.identity.clone(),
                }
            } else {
                AppAction::UnblockDevice {
                    identity: device.identity.clone(),
                }
            };
            self.dispatcher.submit(action).await?;
        }
        Ok(())
    }

    fn current_device<'a>(&self, snapshot: &'a AppState) -> Option<&'a DeviceRecord> {
        snapshot.devices.get(self.ui.selected_index)
    }

    fn render(&mut self, snapshot: &AppState) -> Result<()> {
        let ui_snapshot = self.ui.clone();
        let theme = self.theme.clone();
        let mut log_scroll = ui_snapshot.log_scroll;
        let selected_index = ui_snapshot.selected_index;
        let focus = ui_snapshot.focus;
        let spinner_frame = if snapshot.ongoing_scan.is_some() {
            Some(self.spinner.frame())
        } else {
            self.spinner.reset();
            None
        };

        self.terminal.draw(|frame| {
            let size = frame.size();
            frame.render_widget(Clear, size);

            let vertical = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(0), Constraint::Length(2)])
                .split(size);

            let body = vertical[0];
            let status_area = vertical[1];

            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                .split(body);

            draw_devices(frame, columns[0], snapshot, selected_index, focus, &theme);
            log_scroll = draw_right_panel(
                frame,
                columns[1],
                snapshot,
                focus,
                log_scroll,
                &theme,
                selected_index,
            );
            draw_status_bar(frame, status_area, snapshot, &theme, spinner_frame);
        })?;

        self.ui.log_scroll = log_scroll;
        Ok(())
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen, Show);
    }
}

fn draw_devices(
    frame: &mut ratatui::terminal::Frame<'_>,
    area: Rect,
    snapshot: &AppState,
    selected_index: usize,
    focus: FocusPane,
    theme: &Theme,
) {
    let headers = ["IP", "MAC", "Hostname", "Fabricante", "Estado", "Bloqueo"]
        .into_iter()
        .map(|cell| Span::styled(cell, theme.table_header))
        .collect::<Vec<_>>();

    let rows = snapshot.devices.iter().map(|device| {
        let status = match device.status {
            DeviceStatus::Active => "Activo",
            DeviceStatus::Inactive => "Inactivo",
            DeviceStatus::Error => "Error",
        };
        let blocked = if device.blocked { "Restringido" } else { "--" };
        let hostname = device
            .hostname
            .as_deref()
            .filter(|v| !v.is_empty())
            .unwrap_or("Desconocido");
        let vendor = device
            .vendor
            .as_deref()
            .filter(|v| !v.is_empty())
            .unwrap_or("Desconocido");
        let mac = device.identity.mac.as_deref().unwrap_or("--");
        let mut row = Row::new(vec![
            device.identity.ip.to_string(),
            mac.to_string(),
            hostname.to_string(),
            vendor.to_string(),
            status.to_string(),
            blocked.to_string(),
        ]);

        if device.blocked {
            row = row.style(theme.blocked_row);
        } else if matches!(device.status, DeviceStatus::Error) {
            row = row.style(theme.error_row);
        }
        row
    });

    let mut table_state = TableState::default();
    if !snapshot.devices.is_empty() {
        table_state.select(Some(selected_index));
    }

    let title_style = if focus == FocusPane::Devices {
        theme.emphasis
    } else {
        theme.normal
    };

    let widths = [
        Constraint::Length(16),
        Constraint::Length(18),
        Constraint::Length(24),
        Constraint::Length(20),
        Constraint::Length(10),
        Constraint::Length(12),
    ];
    let table = Table::new(rows, widths)
        .header(Row::new(headers))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled("Dispositivos", title_style)),
        )
        .highlight_style(theme.selection)
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(table, area, &mut table_state);
}

fn draw_right_panel(
    frame: &mut ratatui::terminal::Frame<'_>,
    area: Rect,
    snapshot: &AppState,
    focus: FocusPane,
    mut log_scroll: u16,
    theme: &Theme,
    selected_index: usize,
) -> u16 {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    draw_details(frame, vertical[0], snapshot, theme, selected_index);
    draw_logs(frame, vertical[1], snapshot, focus, &mut log_scroll, theme);
    log_scroll
}

fn draw_details(
    frame: &mut ratatui::terminal::Frame<'_>,
    area: Rect,
    snapshot: &AppState,
    theme: &Theme,
    selected_index: usize,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled("Detalles", theme.normal));

    let text = snapshot
        .devices
        .get(selected_index)
        .map(build_device_details)
        .unwrap_or_else(|| Text::raw("No hay dispositivos detectados aún."));

    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn draw_logs(
    frame: &mut ratatui::terminal::Frame<'_>,
    area: Rect,
    snapshot: &AppState,
    focus: FocusPane,
    log_scroll: &mut u16,
    theme: &Theme,
) {
    let title_style = if focus == FocusPane::Logs {
        theme.emphasis
    } else {
        theme.normal
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled("Eventos", title_style));

    let lines: Vec<Line> = snapshot
        .logs
        .iter()
        .rev()
        .map(|entry| {
            let level_style = match entry.level {
                LogLevel::Info => theme.normal,
                LogLevel::Warn => theme.warning,
                LogLevel::Error => theme.error,
            };
            let timestamp = entry.timestamp.format("%H:%M:%S");
            Line::from(vec![
                Span::styled(format!("[{}] ", timestamp), theme.dimmed),
                Span::styled(format!("{:?}", entry.level), level_style),
                Span::raw("  "),
                Span::styled(&entry.message, theme.normal),
            ])
        })
        .collect();

    if area.height > 0 {
        let total_lines = snapshot.logs.len() as u16;
        let max_allowed = total_lines.saturating_sub(area.height);
        if *log_scroll > max_allowed {
            *log_scroll = max_allowed;
        }
    } else {
        *log_scroll = 0;
    }

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: true })
        .scroll((*log_scroll, 0));

    frame.render_widget(paragraph, area);
}

fn draw_status_bar(
    frame: &mut ratatui::terminal::Frame<'_>,
    area: Rect,
    snapshot: &AppState,
    theme: &Theme,
    spinner_frame: Option<&'static str>,
) {
    let hints = vec![
        Span::styled("[Q] Salir", theme.dimmed),
        Span::raw("  "),
        Span::styled("[R] Escaneo rápido", theme.dimmed),
        Span::raw("  "),
        Span::styled("[Ctrl/Cmd+R] Escaneo profundo", theme.dimmed),
        Span::raw("  "),
        Span::styled("[Enter] Detalle", theme.dimmed),
        Span::raw("  "),
        Span::styled("[B/U] Bloquear", theme.dimmed),
        Span::raw("  "),
        Span::styled("[Tab] Panel", theme.dimmed),
        Span::raw("  "),
        Span::styled("[A] Modo agresivo", theme.dimmed),
    ];

    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    let help = Paragraph::new(Line::from(hints)).wrap(Wrap { trim: true });
    frame.render_widget(help, layout[0]);

    let subtitle_line = if let Some(status) = &snapshot.ongoing_scan {
        let spinner = spinner_frame.unwrap_or("⠋");
        let elapsed = Utc::now()
            .signed_duration_since(status.started_at)
            .num_seconds()
            .max(0);
        let minutes = elapsed / 60;
        let seconds = elapsed % 60;
        let mode = match status.mode {
            ScanKind::Quick => "rápido",
            ScanKind::Deep => "profundo",
        };
        let text = format!(
            "{} Escaneo {}… {:02}:{:02}",
            spinner, mode, minutes, seconds
        );
        Line::from(Span::styled(text, theme.emphasis))
    } else {
        let text = snapshot
            .last_refresh
            .map(|ts| format!("Actualizado: {}", ts.format("%H:%M:%S")))
            .unwrap_or_else(|| "Sin escaneos previos".to_string());
        Line::from(Span::styled(text, theme.dimmed))
    };

    let subtitle = Paragraph::new(subtitle_line).alignment(Alignment::Right);
    frame.render_widget(subtitle, layout[1]);
}

fn build_device_details(device: &DeviceRecord) -> Text<'static> {
    let mut lines = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(
            "Dirección IP: ",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(device.identity.ip.to_string()),
    ]));
    if let Some(mac) = &device.identity.mac {
        lines.push(Line::from(vec![
            Span::styled("MAC: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(mac.clone()),
        ]));
    }
    if let Some(hostname) = &device.hostname {
        lines.push(Line::from(vec![
            Span::styled("Hostname: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(hostname.clone()),
        ]));
    }
    if let Some(vendor) = &device.vendor {
        lines.push(Line::from(vec![
            Span::styled(
                "Fabricante: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(vendor.clone()),
        ]));
    }
    if let Some(model) = &device.model {
        lines.push(Line::from(vec![
            Span::styled("Modelo: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(model.clone()),
        ]));
    }
    if let Some(os) = &device.operating_system {
        lines.push(Line::from(vec![
            Span::styled(
                "Sistema Operativo: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(os.clone()),
        ]));
    }
    lines.push(Line::from(""));

    if !device.open_ports.is_empty() {
        let ports: Vec<String> = device.open_ports.iter().map(|p| p.to_string()).collect();
        lines.push(Line::from(vec![
            Span::styled(
                "Puertos abiertos: ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(ports.join(", ")),
        ]));
    }

    if !device.service_details.is_empty() {
        lines.push(Line::from(Span::styled(
            "Servicios detectados:",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for (port, detail) in &device.service_details {
            let descriptor = format!(
                "{} {} {}",
                detail.name.as_deref().unwrap_or("Servicio"),
                detail.product.as_deref().unwrap_or(""),
                detail.version.as_deref().unwrap_or("")
            )
            .trim()
            .to_string();
            lines.push(Line::from(Span::raw(format!(
                "  • {} -> {}",
                port, descriptor
            ))));
        }
    }

    if let Some(http) = &device.http_signature {
        lines.push(Line::from(Span::styled(
            "HTTP:",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::raw(http.clone())));
    }

    Text::from(lines)
}
