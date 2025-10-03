//! Enumeraciones de acciones que pueden ser solicitadas por la interfaz.

use crate::domain::device::DeviceIdentity;
use crate::domain::settings::ScanKind;

/// Acciones de alto nivel que ejecutan operaciones potencialmente costosas.
#[derive(Debug, Clone)]
pub enum AppAction {
    /// Ejecuta un escaneo de red completo o rápido según el modo indicado.
    ScanNetwork { mode: ScanKind },
    /// Inicia un fingerprint detallado para un único dispositivo identificado por IP.
    ScanDevice { identity: DeviceIdentity },
    /// Solicita bloquear tráfico para el dispositivo indicado.
    BlockDevice { identity: DeviceIdentity },
    /// Solicita restaurar el tráfico del dispositivo indicado.
    UnblockDevice { identity: DeviceIdentity },
    /// Alterna configuraciones avanzadas como el modo agresivo del spoofer.
    ToggleAggressiveMode,
}
