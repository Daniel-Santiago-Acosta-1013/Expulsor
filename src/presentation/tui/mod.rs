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
use std::collections::HashMap;
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
    scan_spinner: Spinner,
    loader_spinner: Spinner,
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
    pending_blocks: HashMap<String, Instant>,
}

impl UiState {
    fn new() -> Self {
        Self {
            selected_index: 0,
            focus: FocusPane::Devices,
            log_scroll: 0,
            pending_blocks: HashMap::new(),
        }
    }

    fn register_pending_block(&mut self, ip: &str) {
        self.pending_blocks.insert(ip.to_string(), Instant::now());
    }

    fn clear_pending_block(&mut self, ip: &str) {
        self.pending_blocks.remove(ip);
    }

    fn cleanup_pending_blocks(&mut self, snapshot: &AppState) {
        self.pending_blocks.retain(|ip, started| {
            if let Some(device) = snapshot
                .devices
                .iter()
                .find(|d| d.identity.ip.to_string() == *ip)
            {
                if matches!(device.status, DeviceStatus::Error) {
                    return false;
                }
                if device.blocked && matches!(device.block_verified, Some(true)) {
                    return false;
                }
                if !device.blocked {
                    // Permite un margen para que la verificación inicial actualice el estado.
                    return started.elapsed() < Duration::from_secs(10);
                }
                true
            } else {
                // Si el dispositivo ya no existe, limpiamos tras un pequeño margen.
                started.elapsed() < Duration::from_secs(5)
            }
        });
    }
}

const SPINNER_FRAMES: &[&str] = &["|", "/", "-", "\\"];

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
            scan_spinner: Spinner::default(),
            loader_spinner: Spinner::default(),
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

    async fn trigger_block(&mut self, snapshot: &AppState, block: bool) -> Result<()> {
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
            let ip = device.identity.ip.to_string();
            if block {
                self.ui.register_pending_block(&ip);
            } else {
                self.ui.clear_pending_block(&ip);
            }
            self.dispatcher.submit(action).await?;
        }
        Ok(())
    }

    fn current_device<'a>(&self, snapshot: &'a AppState) -> Option<&'a DeviceRecord> {
        snapshot.devices.get(self.ui.selected_index)
    }

    fn render(&mut self, snapshot: &AppState) -> Result<()> {
        self.ui.cleanup_pending_blocks(snapshot);
        let ui_snapshot = self.ui.clone();
        let theme = self.theme.clone();
        let mut log_scroll = ui_snapshot.log_scroll;
        let selected_index = ui_snapshot.selected_index;
        let focus = ui_snapshot.focus;
        let spinner_frame = if snapshot.ongoing_scan.is_some() {
            Some(self.scan_spinner.frame())
        } else {
            self.scan_spinner.reset();
            None
        };
        let loader_frame = if !ui_snapshot.pending_blocks.is_empty() {
            Some(self.loader_spinner.frame())
        } else {
            self.loader_spinner.reset();
            None
        };

        self.terminal.draw(|frame| {
            let size = frame.size();
            frame.render_widget(Clear, size);

            let vertical = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(5),
                    Constraint::Min(0),
                    Constraint::Length(2),
                ])
                .split(size);

            let header_area = vertical[0];
            let body = vertical[1];
            let status_area = vertical[2];

            draw_header(frame, header_area, snapshot, &theme, spinner_frame);
            log_scroll = draw_main_content(
                frame,
                body,
                snapshot,
                selected_index,
                focus,
                &theme,
                log_scroll,
                &ui_snapshot.pending_blocks,
                loader_frame,
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
    pending_blocks: &HashMap<String, Instant>,
    loader_frame: Option<&str>,
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
        let ip_str = device.identity.ip.to_string();
        let is_pending = pending_blocks.contains_key(&ip_str);
        let blocked_label = if is_pending {
            loader_frame
                .map(|frame| format!("{} Bloqueando", frame))
                .unwrap_or_else(|| "Bloqueando".to_string())
        } else if device.blocked {
            match device.block_verified {
                Some(true) => "Restringido".to_string(),
                Some(false) => "Sin confirmar".to_string(),
                None => "Pendiente".to_string(),
            }
        } else if matches!(device.status, DeviceStatus::Error) {
            "Error".to_string()
        } else {
            "--".to_string()
        };
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
            blocked_label.clone(),
        ]);

        if device.blocked || is_pending {
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
        .highlight_symbol(">> ");

    frame.render_stateful_widget(table, area, &mut table_state);
}

fn draw_main_content(
    frame: &mut ratatui::terminal::Frame<'_>,
    area: Rect,
    snapshot: &AppState,
    selected_index: usize,
    focus: FocusPane,
    theme: &Theme,
    mut log_scroll: u16,
    pending_blocks: &HashMap<String, Instant>,
    loader_frame: Option<&str>,
) -> u16 {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    let upper = vertical[0];
    let logs_area = vertical[1];

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(upper);

    draw_devices(
        frame,
        columns[0],
        snapshot,
        selected_index,
        focus,
        theme,
        pending_blocks,
        loader_frame,
    );

    draw_details(
        frame,
        columns[1],
        snapshot,
        theme,
        selected_index,
        pending_blocks,
        loader_frame,
    );
    draw_logs(frame, logs_area, snapshot, focus, &mut log_scroll, theme);
    log_scroll
}

fn draw_details(
    frame: &mut ratatui::terminal::Frame<'_>,
    area: Rect,
    snapshot: &AppState,
    theme: &Theme,
    selected_index: usize,
    pending_blocks: &HashMap<String, Instant>,
    loader_frame: Option<&str>,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled("Detalles", theme.normal));

    let text = snapshot
        .devices
        .get(selected_index)
        .map(|device| build_device_details(device, pending_blocks, loader_frame))
        .unwrap_or_else(|| Text::raw("No hay dispositivos detectados aun."));

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
        Span::styled("[R] Escaneo rapido", theme.dimmed),
        Span::raw("  "),
        Span::styled("[Ctrl/Cmd+R] Escaneo profundo", theme.dimmed),
        Span::raw("  "),
        Span::styled("[Enter] Detalle", theme.dimmed),
        Span::raw("  "),
        Span::styled("[B] Restringir", theme.dimmed),
        Span::raw("  "),
        Span::styled("[U] Restaurar", theme.dimmed),
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
        let spinner = spinner_frame.unwrap_or("|");
        let elapsed = Utc::now()
            .signed_duration_since(status.started_at)
            .num_seconds()
            .max(0);
        let minutes = elapsed / 60;
        let seconds = elapsed % 60;
        let mode = match status.mode {
            ScanKind::Quick => "rapido",
            ScanKind::Deep => "profundo",
        };
        let text = format!(
            "{} Escaneo {}... {:02}:{:02}",
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

fn draw_header(
    frame: &mut ratatui::terminal::Frame<'_>,
    area: Rect,
    snapshot: &AppState,
    theme: &Theme,
    spinner_frame: Option<&'static str>,
) {
    let total = snapshot.devices.len();
    let active = snapshot
        .devices
        .iter()
        .filter(|device| {
            matches!(device.status, DeviceStatus::Active)
                && !matches!(device.block_verified, Some(true))
        })
        .count();
    let blocked_verified = snapshot
        .devices
        .iter()
        .filter(|d| matches!(d.block_verified, Some(true)))
        .count();
    let blocked_pending = snapshot
        .devices
        .iter()
        .filter(|d| d.blocked && !matches!(d.block_verified, Some(true)))
        .count();
    let blocked_value = if blocked_pending > 0 {
        format!("{} (+{} sin confirmar)", blocked_verified, blocked_pending)
    } else {
        blocked_verified.to_string()
    };

    let spinner = spinner_frame.unwrap_or("-");
    let scan_text = if let Some(status) = &snapshot.ongoing_scan {
        let mode = match status.mode {
            ScanKind::Quick => "Rapido",
            ScanKind::Deep => "Profundo",
        };
        format!("{} Escaneo {} en curso", spinner, mode)
    } else {
        "[PAUSE] Escaner inactivo".to_string()
    };

    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    draw_stat_card(
        frame,
        cards[0],
        "[DEV] Monitoreados",
        total.to_string(),
        theme,
    );
    draw_stat_card(frame, cards[1], "[ON] Activos", active.to_string(), theme);
    draw_stat_card(frame, cards[2], "[LOCK] Restringidos", blocked_value, theme);
    draw_stat_card(frame, cards[3], "[SCAN] Estado", scan_text, theme);
}

fn draw_stat_card(
    frame: &mut ratatui::terminal::Frame<'_>,
    area: Rect,
    title: &str,
    value: String,
    theme: &Theme,
) {
    let lines = vec![
        Line::from(Span::styled(title, theme.dimmed)),
        Line::from(Span::styled(value, theme.emphasis)),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.dimmed);

    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(block),
        area,
    );
}

fn build_device_details(
    device: &DeviceRecord,
    pending_blocks: &HashMap<String, Instant>,
    loader_frame: Option<&str>,
) -> Text<'static> {
    let mut lines = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("[IP] ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(device.identity.ip.to_string()),
    ]));

    let status_label = match device.status {
        DeviceStatus::Active => "Activo",
        DeviceStatus::Inactive => "Inactivo",
        DeviceStatus::Error => "Error",
    };
    lines.push(Line::from(vec![
        Span::styled("[ESTADO] ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(status_label.to_string()),
    ]));

    if let Some(reason) = &device.status_reason {
        if !reason.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("[DETALLE] ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(reason.clone()),
            ]));
        }
    }

    let ip_str = device.identity.ip.to_string();
    let pending = pending_blocks.contains_key(&ip_str);
    let block_label = if pending {
        loader_frame
            .map(|frame| format!("{} Bloqueando", frame))
            .unwrap_or_else(|| "Bloqueando".to_string())
    } else if device.blocked {
        match device.block_verified {
            Some(true) => "Restringido".to_string(),
            Some(false) => "Sin confirmar".to_string(),
            None => "Pendiente".to_string(),
        }
    } else {
        "Permitido".to_string()
    };
    lines.push(Line::from(vec![
        Span::styled("[BLOQUEO] ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(block_label.clone()),
    ]));

    if pending {
        lines.push(Line::from(vec![
            Span::styled("[AVISO] ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("Reintentando verificación de bloqueo"),
        ]));
    } else if matches!(device.block_verified, Some(false)) {
        lines.push(Line::from(vec![
            Span::styled("[AVISO] ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("Última verificación del bloqueo falló"),
        ]));
    }

    if let Some(mac) = &device.identity.mac {
        lines.push(Line::from(vec![
            Span::styled("[MAC] ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(mac.clone()),
        ]));
    }
    if let Some(hostname) = &device.hostname {
        lines.push(Line::from(vec![
            Span::styled("[HOST] ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(hostname.clone()),
        ]));
    }
    if let Some(vendor) = &device.vendor {
        lines.push(Line::from(vec![
            Span::styled("[VENDOR] ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(vendor.clone()),
        ]));
    }
    if let Some(model) = &device.model {
        lines.push(Line::from(vec![
            Span::styled("[MODEL] ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(model.clone()),
        ]));
    }
    if let Some(os) = &device.operating_system {
        lines.push(Line::from(vec![
            Span::styled("[OS] ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(os.clone()),
        ]));
    }
    lines.push(Line::from(""));

    if !device.open_ports.is_empty() {
        let ports: Vec<String> = device.open_ports.iter().map(|p| p.to_string()).collect();
        lines.push(Line::from(vec![
            Span::styled("[PORTS] ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(ports.join(", ")),
        ]));
    }

    if !device.service_details.is_empty() {
        lines.push(Line::from(Span::styled(
            "[SERVICES]",
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
                "  - {} -> {}",
                port, descriptor
            ))));
        }
    }

    if let Some(http) = &device.http_signature {
        lines.push(Line::from(Span::styled(
            "[HTTP]",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::raw(http.clone())));
    }

    Text::from(lines)
}
