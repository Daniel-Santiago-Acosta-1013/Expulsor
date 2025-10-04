//! Registro de servicios de infraestructura disponibles para la capa de aplicación.

use crate::app::state::AppState;
use crate::domain::actions::AppAction;
use crate::domain::capabilities::{BlockStrategy, CapabilityReport};
use crate::domain::device::DeviceIdentity;
use crate::domain::logs::{LogEntry, LogLevel};
use crate::domain::settings::{ScanKind, Settings};
use crate::infrastructure::network::arp::ArpSpoofer;
use crate::infrastructure::network::capabilities;
use crate::infrastructure::network::fingerprint::Fingerprinter;
use crate::infrastructure::network::scanner::NetworkScanner;
use crate::infrastructure::persistence::device_db::DeviceDatabase;
use crate::utils::shutdown::ShutdownSignal;
use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc::Receiver, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use tracing::{error, info};

/// Contenedor principal de servicios como el escáner, fingerprinter y spoofer.
pub struct ServiceRegistry {
    _db: Arc<DeviceDatabase>,
    scanner: NetworkScanner,
    spoofer: ArpSpoofer,
    pending_verifications: Arc<Mutex<HashSet<String>>>,
}

impl ServiceRegistry {
    /// Crea un registro con los servicios inicializados.
    pub fn new() -> Result<Self> {
        let _db = Arc::new(DeviceDatabase::new()?);
        let fingerprinter = Fingerprinter::new(_db.clone())?;
        let scanner = NetworkScanner::new(_db.clone(), fingerprinter.clone())?;
        let spoofer = ArpSpoofer::new(Settings::default())?;

        Ok(Self {
            _db,
            scanner,
            spoofer,
            pending_verifications: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    /// Lanza la tarea encargada de consumir comandos y delegar en los servicios.
    pub fn spawn_executor(
        registry: Arc<Self>,
        state: Arc<Mutex<AppState>>,
        mut receiver: Receiver<AppAction>,
        shutdown: ShutdownSignal,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(action) = receiver.recv().await {
                if let Err(err) = registry.handle_action(action, state.clone()).await {
                    error!(?err, "Error procesando acción");
                }
            }
            shutdown.trigger();
        })
    }

    async fn handle_action(&self, action: AppAction, state: Arc<Mutex<AppState>>) -> Result<()> {
        match action {
            AppAction::ScanNetwork { mode } => {
                self.handle_scan(mode, state).await?;
            }
            AppAction::ScanDevice { identity } => {
                let record = self.scanner.scan_device(&identity).await?;
                let mut guard = state.lock().await;
                guard.upsert_device(record);
                guard.push_log(LogEntry::new(
                    LogLevel::Info,
                    format!("Escaneo detallado completado para {}", identity.ip),
                ));
            }
            AppAction::BlockDevice { identity } => match self.spoofer.block(&identity).await {
                Ok(report) => {
                    let mut guard = state.lock().await;
                    for message in report.logs {
                        guard.push_log(LogEntry::new(LogLevel::Info, format!("{}", message)));
                    }
                    guard.set_block_state(&identity, true, Some(report.verified));
                    let needs_retry = !report.verified;
                    if needs_retry {
                        guard.push_log(LogEntry::new(
                            LogLevel::Warn,
                            format!("No se pudo confirmar la restricción para {}", identity.ip),
                        ));
                    }
                    guard.push_log(LogEntry::new(
                        LogLevel::Warn,
                        format!("Acceso restringido para {}", identity.ip),
                    ));
                    drop(guard);
                    if needs_retry {
                        self.ensure_verification_retry(identity.clone(), state.clone())
                            .await;
                    }
                }
                Err(err) => {
                    error!(?err, %identity.ip, "No se pudo bloquear dispositivo");
                    let mut guard = state.lock().await;
                    let message = format!("Fallo al restringir {}: {}", identity.ip, err);
                    guard.push_log(LogEntry::new(LogLevel::Error, message.clone()));
                    let reason = message.lines().next().unwrap_or_default().to_string();
                    guard.mark_device_error(&identity, reason);
                }
            },
            AppAction::UnblockDevice { identity } => match self.spoofer.unblock(&identity).await {
                Ok(report) => {
                    let mut guard = state.lock().await;
                    for message in report.logs {
                        guard.push_log(LogEntry::new(LogLevel::Info, format!("{}", message)));
                    }
                    guard.set_block_state(&identity, false, None);
                    guard.push_log(LogEntry::new(
                        LogLevel::Info,
                        format!("Acceso restaurado para {}", identity.ip),
                    ));
                    drop(guard);
                    let mut pending = self.pending_verifications.lock().await;
                    pending.remove(&identity.ip.to_string());
                }
                Err(err) => {
                    error!(?err, %identity.ip, "No se pudo desbloquear dispositivo");
                    let mut guard = state.lock().await;
                    guard.push_log(LogEntry::new(
                        LogLevel::Error,
                        format!("Fallo al restaurar acceso {}: {}", identity.ip, err),
                    ));
                }
            },
            AppAction::ToggleAggressiveMode => {
                let mut guard = state.lock().await;
                if guard.settings.external_block_command.is_some() {
                    guard.push_log(LogEntry::new(
                        LogLevel::Info,
                        "El comando externo de bloqueo está activo; el modo agresivo permanece deshabilitado",
                    ));
                    return Ok(());
                }
                guard.settings.aggressive_mode = !guard.settings.aggressive_mode;
                let message = if guard.settings.aggressive_mode {
                    "Modo agresivo activado"
                } else {
                    "Modo agresivo desactivado"
                };
                guard.push_log(LogEntry::new(LogLevel::Info, message));
                let settings = guard.settings.clone();
                drop(guard);
                self.spoofer.update_settings(settings).await;
            }
        }
        Ok(())
    }

    async fn handle_scan(&self, mode: ScanKind, state: Arc<Mutex<AppState>>) -> Result<()> {
        {
            let mut guard = state.lock().await;
            guard.set_scan_in_progress(mode);
        }

        let scan_result = match mode {
            ScanKind::Quick => self.scanner.quick_scan().await,
            ScanKind::Deep => self.scanner.deep_scan().await,
        };

        let map = match scan_result {
            Ok(map) => map,
            Err(err) => {
                {
                    let mut guard = state.lock().await;
                    guard.clear_scan_in_progress();
                    guard.push_log(LogEntry::new(
                        LogLevel::Error,
                        format!("Escaneo {:?} falló: {}", mode, err),
                    ));
                }
                return Err(err);
            }
        };

        let capability_report = capabilities::evaluate().await;

        let mut guard = state.lock().await;
        guard.update_devices(map.values().cloned().collect());
        guard.clear_scan_in_progress();
        guard.set_network_capabilities(capability_report.clone());
        for note in &capability_report.diagnostics {
            guard.push_log(LogEntry::new(LogLevel::Info, note.clone()));
        }
        let strategy_log = format!(
            "Estrategia sugerida: {}",
            capability_report.recommended.label()
        );
        guard.push_log(LogEntry::new(LogLevel::Info, strategy_log));
        let adjustment_note = apply_strategy_to_settings(&mut guard.settings, &capability_report);
        guard.push_log(LogEntry::new(
            LogLevel::Info,
            format!("Escaneo {:?} completado ({} dispositivos)", mode, map.len()),
        ));
        let settings = guard.settings.clone();
        drop(guard);
        if let Some(note) = adjustment_note {
            let mut guard = state.lock().await;
            guard.push_log(LogEntry::new(LogLevel::Info, note));
        }
        self.spoofer.update_settings(settings).await;
        info!("Escaneo {:?} finalizado", mode);
        Ok(())
    }

    /// Inicializa tareas de largo aliento como escaneos periódicos.
    pub async fn spawn_background_tasks(
        &self,
        _state: Arc<Mutex<AppState>>,
        _shutdown: ShutdownSignal,
    ) -> Result<Vec<JoinHandle<()>>> {
        Ok(Vec::new())
    }

    async fn ensure_verification_retry(
        &self,
        identity: DeviceIdentity,
        state: Arc<Mutex<AppState>>,
    ) {
        let ip = identity.ip.to_string();
        {
            let mut guard = self.pending_verifications.lock().await;
            if guard.contains(&ip) {
                return;
            }
            guard.insert(ip.clone());
        }

        let spoofer = self.spoofer.clone();
        let pending = self.pending_verifications.clone();

        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(5)).await;

                let (still_blocked, settings_snapshot) = {
                    let state_guard = state.lock().await;
                    let blocked = state_guard
                        .devices
                        .iter()
                        .any(|device| device.identity.ip == identity.ip && device.blocked);
                    (blocked, state_guard.settings.clone())
                };

                if !settings_snapshot.block_mode && !settings_snapshot.poison_enabled {
                    let mut guard = pending.lock().await;
                    guard.remove(&ip);
                    break;
                }

                if !still_blocked {
                    let mut guard = pending.lock().await;
                    guard.remove(&ip);
                    break;
                }

                match spoofer.reverify(&identity).await {
                    Ok((success, mut logs)) => {
                        let mut state_guard = state.lock().await;
                        state_guard.push_log(LogEntry::new(
                            LogLevel::Info,
                            format!("Reintentando verificación para {}", identity.ip),
                        ));
                        for message in logs.drain(..) {
                            state_guard.push_log(LogEntry::new(LogLevel::Info, message));
                        }
                        state_guard.set_block_state(&identity, true, Some(success));
                        if success {
                            state_guard.push_log(LogEntry::new(
                                LogLevel::Info,
                                format!("Restricción confirmada para {}", identity.ip),
                            ));
                        } else {
                            state_guard.push_log(LogEntry::new(
                                LogLevel::Warn,
                                format!(
                                    "El dispositivo {} sigue respondiendo; se volverá a intentar",
                                    identity.ip
                                ),
                            ));
                        }
                        let should_break = success;
                        drop(state_guard);
                        if should_break {
                            let mut guard = pending.lock().await;
                            guard.remove(&ip);
                            break;
                        }
                    }
                    Err(err) => {
                        let mut state_guard = state.lock().await;
                        state_guard.push_log(LogEntry::new(
                            LogLevel::Error,
                            format!(
                                "No se pudo reintentar la verificación de {}: {}",
                                identity.ip, err
                            ),
                        ));
                        state_guard.set_block_state(&identity, true, Some(false));
                        drop(state_guard);

                        let mut guard = pending.lock().await;
                        guard.remove(&ip);
                        break;
                    }
                }
            }
        });
    }
}

fn apply_strategy_to_settings(
    settings: &mut Settings,
    report: &CapabilityReport,
) -> Option<String> {
    if settings.external_block_command.is_some() {
        settings.block_mode = false;
        settings.poison_enabled = false;
        settings.aggressive_mode = false;
        return Some("Se utilizará el comando externo configurado para bloquear".to_string());
    }
    match report.recommended {
        BlockStrategy::Unsupported => {
            settings.block_mode = false;
            settings.poison_enabled = false;
            settings.aggressive_mode = false;
            settings.packet_interval_secs = 1.0;
            Some("Sin capacidades: se desactiva bloqueo automático".to_string())
        }
        BlockStrategy::FirewallOnly => {
            settings.block_mode = true;
            settings.poison_enabled = false;
            settings.aggressive_mode = false;
            settings.packet_interval_secs = 1.0;
            Some("Se utilizará únicamente firewall (sin ARP)".to_string())
        }
        BlockStrategy::BalancedArp => {
            settings.block_mode = true;
            settings.poison_enabled = true;
            settings.aggressive_mode = false;
            settings.packet_interval_secs = settings.packet_interval_secs.max(0.75);
            Some("ARP moderado activado".to_string())
        }
        BlockStrategy::AggressiveArp => {
            settings.block_mode = true;
            settings.poison_enabled = true;
            settings.aggressive_mode = true;
            settings.packet_interval_secs = settings.packet_interval_secs.min(0.5);
            Some("ARP agresivo habilitado".to_string())
        }
    }
}
