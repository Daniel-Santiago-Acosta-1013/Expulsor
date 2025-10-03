//! Envío y gestión de reglas de bloqueo basadas en ARP/firewall.

use crate::domain::device::DeviceIdentity;
use crate::domain::settings::Settings;
use crate::infrastructure::system::{firewall, ip_forwarding};
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Información de un objetivo actualmente bloqueado.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TargetStatus {
    pub identity: DeviceIdentity,
    pub started_at: DateTime<Utc>,
    pub active: bool,
    pub aggressive: bool,
    pub block_mode: bool,
}

/// Administrador de táctica de bloqueo basada en ARP/firewall.
#[derive(Clone)]
pub struct ArpSpoofer {
    targets: Arc<Mutex<HashMap<String, TargetStatus>>>,
    ip_forward_state: Arc<Mutex<Option<String>>>,
    settings: Arc<Mutex<Settings>>,
}

impl ArpSpoofer {
    /// Crea un spoofer configurado con la puerta de enlace y la interfaz local.
    pub fn new(settings: Settings) -> Result<Self> {
        Ok(Self {
            targets: Arc::new(Mutex::new(HashMap::new())),
            ip_forward_state: Arc::new(Mutex::new(None)),
            settings: Arc::new(Mutex::new(settings)),
        })
    }

    /// Configura ajustes runtime provenientes del diálogo de agresividad.
    pub async fn update_settings(&self, settings: Settings) {
        let mut guard = self.settings.lock().await;
        *guard = settings;
    }

    /// Inicia el bloqueo del dispositivo indicado.
    pub async fn block(&self, identity: &DeviceIdentity) -> Result<()> {
        let settings = self.settings.lock().await.clone();
        if settings.block_mode {
            firewall::add_rule(&identity.ip.to_string()).await?;
        }

        if settings.block_mode {
            let mut state_guard = self.ip_forward_state.lock().await;
            if state_guard.is_none() {
                *state_guard = ip_forwarding::enable().await?;
            }
        }

        let mut guard = self.targets.lock().await;
        guard.insert(
            identity.ip.to_string(),
            TargetStatus {
                identity: identity.clone(),
                started_at: Utc::now(),
                active: true,
                aggressive: settings.aggressive_mode,
                block_mode: settings.block_mode,
            },
        );

        Ok(())
    }

    /// Detiene el bloqueo actual del dispositivo indicado.
    pub async fn unblock(&self, identity: &DeviceIdentity) -> Result<()> {
        firewall::remove_rule(&identity.ip.to_string()).await?;
        let mut guard = self.targets.lock().await;
        guard.remove(&identity.ip.to_string());

        if guard.is_empty() {
            let mut state_guard = self.ip_forward_state.lock().await;
            if let Some(previous) = state_guard.take() {
                ip_forwarding::restore(Some(previous)).await?;
            }
        }

        Ok(())
    }

    /// Recupera un resumen de los objetivos bloqueados.
    #[allow(dead_code)]
    pub async fn get_targets(&self) -> HashMap<String, TargetStatus> {
        self.targets.lock().await.clone()
    }
}
