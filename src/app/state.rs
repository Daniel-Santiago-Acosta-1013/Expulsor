//! Representa el estado compartido de la aplicación accesible desde la TUI y los servicios.

use crate::domain::device::{DeviceIdentity, DeviceRecord};
use crate::domain::logs::LogEntry;
use crate::domain::settings::Settings;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::VecDeque;

/// Número máximo de entradas del registro de eventos que se conservan en memoria.
const MAX_LOG_ENTRIES: usize = 512;

/// Estado observable de la aplicación.
#[derive(Debug, Clone)]
pub struct AppState {
    pub devices: Vec<DeviceRecord>,
    pub logs: VecDeque<LogEntry>,
    pub settings: Settings,
    pub last_refresh: Option<DateTime<Utc>>,
}

impl AppState {
    /// Carga el estado inicial desde la persistencia si está disponible.
    pub async fn load() -> Result<Self> {
        Ok(Self {
            devices: Vec::new(),
            logs: VecDeque::with_capacity(MAX_LOG_ENTRIES),
            settings: Settings::default(),
            last_refresh: None,
        })
    }

    /// Añade una entrada al registro, descartando las más antiguas cuando sea necesario.
    pub fn push_log(&mut self, entry: LogEntry) {
        if self.logs.len() == MAX_LOG_ENTRIES {
            self.logs.pop_front();
        }
        self.logs.push_back(entry);
    }

    /// Actualiza la colección de dispositivos detectados.
    pub fn update_devices(&mut self, devices: Vec<DeviceRecord>) {
        self.devices = devices;
        self.last_refresh = Some(Utc::now());
    }

    /// Inserta o actualiza la información de un dispositivo individual.
    pub fn upsert_device(&mut self, record: DeviceRecord) {
        if let Some(existing) = self
            .devices
            .iter_mut()
            .find(|entry| entry.identity.ip == record.identity.ip)
        {
            *existing = record;
        } else {
            self.devices.push(record);
        }
        self.last_refresh = Some(Utc::now());
    }

    /// Marca el estado de bloqueo de un dispositivo existente.
    pub fn set_block_state(&mut self, identity: &DeviceIdentity, blocked: bool) {
        if let Some(device) = self
            .devices
            .iter_mut()
            .find(|entry| entry.identity.ip == identity.ip)
        {
            device.blocked = blocked;
        }
    }
}
