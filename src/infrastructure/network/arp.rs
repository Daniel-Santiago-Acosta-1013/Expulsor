//! Envío y gestión de reglas de bloqueo basadas en ARP/firewall.

use crate::domain::device::DeviceIdentity;
use crate::domain::settings::Settings;
use crate::infrastructure::system::firewall::{FirewallDriver, SystemFirewall};
use crate::infrastructure::system::ip_forwarding;
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
    firewall: Arc<dyn FirewallDriver>,
    firewall_ready: Arc<Mutex<bool>>,
}

#[derive(Debug, Default, Clone)]
pub struct BlockOutcome {
    pub logs: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct UnblockOutcome {
    pub logs: Vec<String>,
}

impl ArpSpoofer {
    /// Crea un spoofer configurado con la puerta de enlace y la interfaz local.
    pub fn new(settings: Settings) -> Result<Self> {
        Self::with_firewall(settings, Arc::new(SystemFirewall::default()))
    }

    /// Permite inyectar un controlador de firewall personalizado (útil en pruebas).
    pub fn with_firewall(settings: Settings, firewall: Arc<dyn FirewallDriver>) -> Result<Self> {
        Ok(Self {
            targets: Arc::new(Mutex::new(HashMap::new())),
            ip_forward_state: Arc::new(Mutex::new(None)),
            settings: Arc::new(Mutex::new(settings)),
            firewall,
            firewall_ready: Arc::new(Mutex::new(false)),
        })
    }

    /// Configura ajustes runtime provenientes del diálogo de agresividad.
    pub async fn update_settings(&self, settings: Settings) {
        let mut guard = self.settings.lock().await;
        *guard = settings;
    }

    /// Inicia el bloqueo del dispositivo indicado.
    pub async fn block(&self, identity: &DeviceIdentity) -> Result<BlockOutcome> {
        let settings = self.settings.lock().await.clone();
        let mut logs = Vec::new();
        logs.push(format!("Preparando cortafuegos para {}", identity.ip));
        self.ensure_firewall_ready().await?;
        logs.push("Cortafuegos listo".to_string());

        if settings.block_mode {
            logs.push(format!(
                "Agregando {} a la lista de bloqueo expulsor_blocklist",
                identity.ip
            ));
            self.firewall.block(&identity.ip.to_string()).await?;
            logs.push("Regla de bloqueo aplicada".to_string());
        } else {
            logs.push("block_mode desactivado: no se aplicó regla de firewall".to_string());
        }

        if settings.block_mode {
            let mut state_guard = self.ip_forward_state.lock().await;
            if state_guard.is_none() {
                let previous = ip_forwarding::enable().await?;
                logs.push("Reenvio IP habilitado temporalmente".to_string());
                *state_guard = previous;
            } else {
                logs.push("Reenvio IP ya activo".to_string());
            }
        } else {
            logs.push("block_mode desactivado: reenvio IP sin cambios".to_string());
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

        Ok(BlockOutcome { logs })
    }

    /// Detiene el bloqueo actual del dispositivo indicado.
    pub async fn unblock(&self, identity: &DeviceIdentity) -> Result<UnblockOutcome> {
        let mut logs = Vec::new();
        logs.push(format!("Quitando {} de la lista de expulsión", identity.ip));
        self.firewall.unblock(&identity.ip.to_string()).await?;
        logs.push("Regla de bloqueo retirada".to_string());
        let mut guard = self.targets.lock().await;
        guard.remove(&identity.ip.to_string());

        if guard.is_empty() {
            let mut state_guard = self.ip_forward_state.lock().await;
            if let Some(previous) = state_guard.take() {
                ip_forwarding::restore(Some(previous)).await?;
                logs.push("Estado de reenvio IP restaurado".to_string());
            } else {
                logs.push("No hubo cambios en reenvio IP".to_string());
            }
        }

        Ok(UnblockOutcome { logs })
    }

    /// Recupera un resumen de los objetivos bloqueados.
    #[allow(dead_code)]
    pub async fn get_targets(&self) -> HashMap<String, TargetStatus> {
        self.targets.lock().await.clone()
    }

    async fn ensure_firewall_ready(&self) -> Result<()> {
        let mut guard = self.firewall_ready.lock().await;
        if !*guard {
            self.firewall.ensure_ready().await?;
            *guard = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::BoxFuture;
    use std::collections::HashSet;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockFirewall {
        blocked: Mutex<HashSet<String>>,
        ensure_calls: Mutex<u32>,
        block_calls: Mutex<u32>,
        unblock_calls: Mutex<u32>,
    }

    impl MockFirewall {
        fn is_blocked(&self, ip: &str) -> bool {
            self.blocked.lock().unwrap().contains(ip)
        }

        fn ensure_calls(&self) -> u32 {
            *self.ensure_calls.lock().unwrap()
        }

        fn block_calls(&self) -> u32 {
            *self.block_calls.lock().unwrap()
        }

        fn unblock_calls(&self) -> u32 {
            *self.unblock_calls.lock().unwrap()
        }
    }

    impl FirewallDriver for MockFirewall {
        fn ensure_ready(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async move {
                *self.ensure_calls.lock().unwrap() += 1;
                Ok(())
            })
        }

        fn block(&self, ip: &str) -> BoxFuture<'_, Result<()>> {
            let ip = ip.to_string();
            Box::pin(async move {
                *self.block_calls.lock().unwrap() += 1;
                self.blocked.lock().unwrap().insert(ip);
                Ok(())
            })
        }

        fn unblock(&self, ip: &str) -> BoxFuture<'_, Result<()>> {
            let ip = ip.to_string();
            Box::pin(async move {
                *self.unblock_calls.lock().unwrap() += 1;
                self.blocked.lock().unwrap().remove(&ip);
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn block_registers_target_and_updates_firewall() {
        let firewall = Arc::new(MockFirewall::default());
        let spoofer = ArpSpoofer::with_firewall(Settings::default(), firewall.clone()).unwrap();
        let identity = DeviceIdentity::from_strings("192.168.0.9", Some("AA:BB:CC:DD:EE:FF"))
            .expect("identidad válida");

        let outcome = spoofer.block(&identity).await.expect("bloqueo exitoso");

        let targets = spoofer.get_targets().await;
        assert!(targets.contains_key("192.168.0.9"));
        assert!(firewall.is_blocked("192.168.0.9"));
        assert_eq!(firewall.ensure_calls(), 1);
        assert_eq!(firewall.block_calls(), 1);
        assert!(outcome
            .logs
            .iter()
            .any(|msg| msg.contains("Regla de bloqueo aplicada")));
    }

    #[tokio::test]
    async fn block_skips_firewall_when_block_mode_disabled() {
        let firewall = Arc::new(MockFirewall::default());
        let mut settings = Settings::default();
        settings.block_mode = false;
        let spoofer = ArpSpoofer::with_firewall(settings, firewall.clone()).unwrap();
        let identity = DeviceIdentity::from_strings("192.168.0.10", None).unwrap();

        let outcome = spoofer.block(&identity).await.unwrap();

        assert_eq!(firewall.block_calls(), 0);
        assert!(spoofer.get_targets().await.contains_key("192.168.0.10"));
        assert!(outcome
            .logs
            .iter()
            .any(|msg| msg.contains("block_mode desactivado")));
    }

    #[tokio::test]
    async fn unblock_releases_firewall_and_clears_target() {
        let firewall = Arc::new(MockFirewall::default());
        let spoofer = ArpSpoofer::with_firewall(Settings::default(), firewall.clone()).unwrap();
        let identity = DeviceIdentity::from_strings("192.168.0.11", None).unwrap();

        spoofer.block(&identity).await.unwrap();
        let report = spoofer.unblock(&identity).await.unwrap();

        assert_eq!(firewall.unblock_calls(), 1);
        assert!(!firewall.is_blocked("192.168.0.11"));
        assert!(spoofer.get_targets().await.is_empty());
        assert!(report
            .logs
            .iter()
            .any(|msg| msg.contains("Regla de bloqueo retirada")));
    }
}
