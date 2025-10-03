//! Tipos relacionados con el registro histórico de eventos.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Niveles de severidad empleados en los mensajes del registro.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

/// Representa una línea del registro mostrado en la TUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub level: LogLevel,
    pub timestamp: DateTime<Utc>,
    pub message: String,
}

impl LogEntry {
    /// Construye un registro con la hora actual.
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            level,
            timestamp: Utc::now(),
            message: message.into(),
        }
    }
}
