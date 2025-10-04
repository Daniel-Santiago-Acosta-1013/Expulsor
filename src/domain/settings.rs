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
    pub poison_enabled: bool,
    pub packet_interval_secs: f64,
    pub external_block_command: Option<String>,
    pub external_unblock_command: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Settings {
    pub fn from_env() -> Self {
        let external_block_command = std::env::var("EXPULSOR_BLOCK_CMD").ok();
        let external_unblock_command = std::env::var("EXPULSOR_UNBLOCK_CMD").ok();

        let mut settings = Self {
            aggressive_mode: true,
            block_mode: true,
            poison_enabled: true,
            packet_interval_secs: 0.5,
            external_block_command,
            external_unblock_command,
        };

        if settings.external_block_command.is_some() {
            settings.block_mode = false;
            settings.poison_enabled = false;
            settings.aggressive_mode = false;
        }

        settings
    }
}
