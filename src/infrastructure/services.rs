//! Registro de servicios de infraestructura disponibles para la capa de aplicación.

use crate::app::state::AppState;
use crate::domain::actions::AppAction;
use crate::domain::logs::{LogEntry, LogLevel};
use crate::domain::settings::{ScanKind, Settings};
use crate::infrastructure::network::arp::ArpSpoofer;
use crate::infrastructure::network::fingerprint::Fingerprinter;
use crate::infrastructure::network::scanner::NetworkScanner;
use crate::infrastructure::persistence::device_db::DeviceDatabase;
use crate::utils::shutdown::ShutdownSignal;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{mpsc::Receiver, Mutex};
use tokio::task::JoinHandle;
use tracing::{error, info};

/// Contenedor principal de servicios como el escáner, fingerprinter y spoofer.
pub struct ServiceRegistry {
    _db: Arc<DeviceDatabase>,
    scanner: NetworkScanner,
    spoofer: ArpSpoofer,
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
                    guard.set_block_state(&identity, true);
                    guard.push_log(LogEntry::new(
                        LogLevel::Warn,
                        format!("Acceso restringido para {}", identity.ip),
                    ));
                }
                Err(err) => {
                    error!(?err, %identity.ip, "No se pudo bloquear dispositivo");
                    let mut guard = state.lock().await;
                    guard.push_log(LogEntry::new(
                        LogLevel::Error,
                        format!("Fallo al restringir {}: {}", identity.ip, err),
                    ));
                }
            },
            AppAction::UnblockDevice { identity } => match self.spoofer.unblock(&identity).await {
                Ok(report) => {
                    let mut guard = state.lock().await;
                    for message in report.logs {
                        guard.push_log(LogEntry::new(LogLevel::Info, format!("{}", message)));
                    }
                    guard.set_block_state(&identity, false);
                    guard.push_log(LogEntry::new(
                        LogLevel::Info,
                        format!("Acceso restaurado para {}", identity.ip),
                    ));
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

        let mut guard = state.lock().await;
        guard.update_devices(map.values().cloned().collect());
        guard.clear_scan_in_progress();
        guard.push_log(LogEntry::new(
            LogLevel::Info,
            format!("Escaneo {:?} completado ({} dispositivos)", mode, map.len()),
        ));
        drop(guard);
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
}
