//! Configuraciones de usuario y parámetros de operación.

use serde::{Deserialize, Serialize};

/// Ritmos de escaneo disponibles.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ScanKind {
    Quick,
    Deep,
}

impl Default for ScanKind {
    fn default() -> Self {
        Self::Quick
    }
}

/// Preferencias de aplicación configurables por el usuario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub aggressive_mode: bool,
    pub block_mode: bool,
    pub packet_interval_secs: f64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            aggressive_mode: true,
            block_mode: true,
            packet_interval_secs: 0.5,
        }
    }
}
