//! Persistencia de información histórica de dispositivos y bases de datos auxiliares.

use crate::domain::device::{DeviceIdentity, DeviceRecord, ServiceDetail};
use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use futures::executor;
use indexmap::IndexMap;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Ruta relativa dentro del directorio del usuario donde se guardan las bases de datos.
const DEFAULT_DB_DIR: &str = ".expulsor/device_db";
const DB_FILE_NAME: &str = "device_fingerprints.db";
const VENDOR_CACHE_FILE: &str = "mac_vendor_cache.json";

/// Representa la base de datos persistente y los catálogos auxiliares.
pub struct DeviceDatabase {
    db_path: PathBuf,
    vendor_cache_path: PathBuf,
    vendor_map: Arc<RwLock<HashMap<String, VendorRecord>>>,
    fallback_map: HashMap<String, VendorRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VendorRecord {
    short: String,
    details: String,
}

impl DeviceDatabase {
    /// Inicializa la base de datos y las tablas requeridas.
    pub fn new() -> Result<Self> {
        let base_dir = dirs::home_dir()
            .map(|dir| dir.join(DEFAULT_DB_DIR))
            .context("No se pudo determinar el directorio HOME del usuario")?;
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir)
                .with_context(|| format!("No se pudo crear el directorio {:?}", base_dir))?;
        }

        let db_path = base_dir.join(DB_FILE_NAME);
        let vendor_cache_path = base_dir.join(VENDOR_CACHE_FILE);

        let mut database = Self {
            db_path,
            vendor_cache_path,
            vendor_map: Arc::new(RwLock::new(HashMap::new())),
            fallback_map: HashMap::new(),
        };

        database.bootstrap_sqlite()?;
        database.load_vendor_data()?;

        Ok(database)
    }

    /// Recupera el fabricante asociado a la dirección MAC indicada.
    pub async fn get_vendor_info(&self, mac: &str) -> (String, String) {
        let prefix = match Self::normalize_mac_prefix(mac) {
            Some(value) => value,
            None => return ("Desconocido".into(), "".into()),
        };

        if let Some(record) = self.vendor_map.read().await.get(&prefix) {
            return (record.short.clone(), record.details.clone());
        }

        if let Some(record) = self.fallback_map.get(&prefix) {
            self.vendor_map
                .write()
                .await
                .insert(prefix.clone(), record.clone());
            let _ = self.persist_vendor_cache().await;
            return (record.short.clone(), record.details.clone());
        }

        ("Desconocido".into(), "".into())
    }

    /// Guarda un registro identificado para consultas futuras.
    pub async fn save_record(&self, record: &DeviceRecord) -> Result<()> {
        let conn = Self::connect(&self.db_path)?;
        let open_ports = serde_json::to_string(&record.open_ports)?;
        let service_details = serde_json::to_string(&record.service_details)?;
        let identity = &record.identity;

        let blocked_flag = matches!(record.block_verified, Some(true));

        conn.execute(
            r#"
            INSERT INTO identified_devices (
                ip, mac, hostname, vendor, vendor_details, device_type, model,
                os, open_ports, service_details, last_seen, blocked
            ) VALUES (
                :ip, :mac, :hostname, :vendor, :vendor_details, :device_type,
                :model, :os, :open_ports, :service_details, :last_seen, :blocked
            )
            ON CONFLICT(ip) DO UPDATE SET
                mac = excluded.mac,
                hostname = excluded.hostname,
                vendor = excluded.vendor,
                vendor_details = excluded.vendor_details,
                device_type = excluded.device_type,
                model = excluded.model,
                os = excluded.os,
                open_ports = excluded.open_ports,
                service_details = excluded.service_details,
                last_seen = excluded.last_seen,
                blocked = excluded.blocked
            "#,
            rusqlite::named_params! {
                ":ip": identity.ip.to_string(),
                ":mac": identity.mac.clone().unwrap_or_default(),
                ":hostname": record.hostname.clone().unwrap_or_default(),
                ":vendor": record.vendor.clone().unwrap_or_default(),
                ":vendor_details": record.vendor_details.clone().unwrap_or_default(),
                ":device_type": record.device_type.clone().unwrap_or_default(),
                ":model": record.model.clone().unwrap_or_default(),
                ":os": record.operating_system.clone().unwrap_or_default(),
                ":open_ports": open_ports,
                ":service_details": service_details,
                ":last_seen": record.last_seen.timestamp(),
                ":blocked": if blocked_flag { 1 } else { 0 },
            },
        )?;

        Ok(())
    }

    /// Recupera un dispositivo previamente almacenado.
    pub async fn get_known_device(&self, ip: &IpAddr) -> Result<Option<DeviceRecord>> {
        let conn = Self::connect(&self.db_path)?;
        let mut stmt = conn.prepare(
            r#"SELECT ip, mac, hostname, vendor, vendor_details, device_type,
                model, os, open_ports, service_details, last_seen, blocked
            FROM identified_devices WHERE ip = ?1"#,
        )?;

        let result = stmt
            .query_row(params![ip.to_string()], |row| {
                let ip_str: String = row.get(0)?;
                let mac: String = row.get(1)?;
                let hostname: String = row.get(2)?;
                let vendor: String = row.get(3)?;
                let vendor_details: String = row.get(4)?;
                let device_type: String = row.get(5)?;
                let model: String = row.get(6)?;
                let os: String = row.get(7)?;
                let open_ports: String = row.get(8)?;
                let service_details: String = row.get(9)?;
                let last_seen: i64 = row.get(10)?;
                let blocked: i64 = row.get(11)?;

                let identity = DeviceIdentity::from_strings(
                    &ip_str,
                    if mac.is_empty() { None } else { Some(&mac) },
                )
                .ok_or_else(|| rusqlite::Error::InvalidQuery)?;
                let open_ports_vec: Vec<u16> =
                    serde_json::from_str(&open_ports).unwrap_or_default();
                let service_map: IndexMap<u16, ServiceDetail> =
                    serde_json::from_str(&service_details).unwrap_or_default();
                let last_seen_time: DateTime<Utc> = Utc
                    .timestamp_opt(last_seen, 0)
                    .single()
                    .unwrap_or_else(Utc::now);

                let mut record = DeviceRecord::new(identity);
                if !hostname.is_empty() {
                    record.hostname = Some(hostname);
                }
                if !vendor.is_empty() {
                    record.vendor = Some(vendor);
                }
                if !vendor_details.is_empty() {
                    record.vendor_details = Some(vendor_details);
                }
                if !device_type.is_empty() {
                    record.device_type = Some(device_type);
                }
                if !model.is_empty() {
                    record.model = Some(model);
                }
                if !os.is_empty() {
                    record.operating_system = Some(os);
                }
                record.open_ports = open_ports_vec;
                record.service_details = service_map;
                record.last_seen = last_seen_time;
                record.blocked = blocked != 0;
                if record.blocked {
                    record.block_verified = Some(true);
                }

                Ok(record)
            })
            .optional()?;

        Ok(result)
    }

    /// Exporta los datos de proveedores cacheados a disco.
    async fn persist_vendor_cache(&self) -> Result<()> {
        let guard = self.vendor_map.read().await;
        let json = serde_json::to_string_pretty(&*guard)?;
        tokio::fs::write(&self.vendor_cache_path, json).await?;
        Ok(())
    }

    fn connect(path: &Path) -> Result<Connection> {
        let conn = Connection::open(path)
            .with_context(|| format!("No se pudo abrir la base de datos {:?}", path))?;
        conn.pragma_update(None, "journal_mode", &"WAL")?;
        conn.pragma_update(None, "synchronous", &"NORMAL")?;
        Ok(conn)
    }

    fn bootstrap_sqlite(&mut self) -> Result<()> {
        let conn = Self::connect(&self.db_path)?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS device_signatures (
                id INTEGER PRIMARY KEY,
                mac_prefix TEXT,
                port_signature TEXT,
                banner_signature TEXT,
                http_signature TEXT,
                mdns_signature TEXT,
                device_type TEXT,
                vendor TEXT,
                model TEXT,
                os TEXT,
                created_at INTEGER,
                updated_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS identified_devices (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                hostname TEXT,
                vendor TEXT,
                vendor_details TEXT,
                device_type TEXT,
                model TEXT,
                os TEXT,
                open_ports TEXT,
                service_details TEXT,
                last_seen INTEGER,
                blocked INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_identified_mac ON identified_devices(mac);
            "#,
        )?;
        Ok(())
    }

    fn load_vendor_data(&mut self) -> Result<()> {
        if let Ok(contents) = fs::read_to_string(&self.vendor_cache_path) {
            let map: HashMap<String, VendorRecord> =
                serde_json::from_str(&contents).unwrap_or_default();
            let mut guard = executor::block_on(self.vendor_map.write());
            *guard = map;
        }

        let fallback_json = include_str!("../../../assets/mac_vendor_fallback.json");
        let fallback_map: HashMap<String, String> =
            serde_json::from_str(fallback_json).unwrap_or_default();
        self.fallback_map = fallback_map
            .into_iter()
            .map(|(prefix, name)| {
                let record = VendorRecord {
                    short: name.clone(),
                    details: name,
                };
                (prefix, record)
            })
            .collect();

        Ok(())
    }

    fn normalize_mac_prefix(mac: &str) -> Option<String> {
        let clean: String = mac
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .flat_map(|c| c.to_lowercase())
            .collect();
        if clean.len() < 6 {
            return None;
        }
        let prefix = &clean[..6];
        Some(format!(
            "{}:{}:{}",
            &prefix[0..2],
            &prefix[2..4],
            &prefix[4..6]
        ))
    }
}
