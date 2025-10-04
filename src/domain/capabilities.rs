//! Reportes sobre las capacidades de bloqueo detectadas en la red actual.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Estrategias recomendadas para limitar el tráfico de un dispositivo.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockStrategy {
    /// Solo firewall; no se espera que el envenenamiento ARP funcione.
    FirewallOnly,
    /// Firewall combinado con ARP moderado (intervalos más largos, sin modo agresivo).
    BalancedArp,
    /// Envenenamiento ARP agresivo más firewall.
    AggressiveArp,
    /// No se dispone de capacidades suficientes para bloquear desde este equipo.
    Unsupported,
}

impl BlockStrategy {
    pub fn label(self) -> &'static str {
        match self {
            BlockStrategy::FirewallOnly => "Solo firewall",
            BlockStrategy::BalancedArp => "ARP moderado",
            BlockStrategy::AggressiveArp => "ARP agresivo",
            BlockStrategy::Unsupported => "Sin soporte",
        }
    }
}

impl Default for BlockStrategy {
    fn default() -> Self {
        BlockStrategy::FirewallOnly
    }
}

/// Diagnóstico sobre las capacidades actuales del router/interfaz para expulsar dispositivos.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CapabilityReport {
    pub interface_name: String,
    pub interface_kind: String,
    pub gateway_ip: Option<Ipv4Addr>,
    pub supports_firewall: bool,
    pub supports_datalink: bool,
    pub recommended: BlockStrategy,
    pub diagnostics: Vec<String>,
}

impl CapabilityReport {
    pub fn summary(&self) -> String {
        format!(
            "{} | pf:{} | datalink:{}",
            self.recommended.label(),
            if self.supports_firewall { "ok" } else { "no" },
            if self.supports_datalink { "ok" } else { "no" }
        )
    }
}
