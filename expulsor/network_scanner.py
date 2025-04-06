"""
Módulo de escaneo de red mejorado para Expulsor
"""

import socket
import threading
import time
import concurrent.futures
import logging
from typing import Dict, List, Optional, Callable

import netifaces
import nmap
from scapy.all import ARP, Ether, srp, conf

from .device_identification.fingerprinter import DeviceFingerprinter

# Configurar logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Desactivar mensajes verbose de scapy
conf.verb = 0


class DeviceInfo:
    """Clase para almacenar información de dispositivos detectados"""
    def __init__(self, ip: str, mac: str):
        self.ip = ip
        self.mac = mac
        self.hostname = ""
        self.vendor = ""
        self.vendor_details = ""  # Información detallada del fabricante
        self.device_type = ""     # Tipo de dispositivo (smartphone, TV, etc.)
        self.model = ""           # Modelo específico del dispositivo
        self.os = ""
        self.open_ports = []
        self.service_details = {}  # Detalles de servicios detectados
        self.last_seen = time.time()
        self.status = "activo"
        self.blocked = False
        self.detailed_scan_time = None  # Timestamp del último escaneo detallado
    
    def to_dict(self) -> Dict:
        """Convierte la información del dispositivo a un diccionario"""
        return {
            'ip': self.ip,
            'mac': self.mac,
            'hostname': self.hostname,
            'vendor': self.vendor,
            'vendor_details': self.vendor_details,
            'device_type': self.device_type,
            'model': self.model,
            'os': self.os,
            'open_ports': self.open_ports,
            'service_details': self.service_details,
            'last_seen': self.last_seen,
            'status': self.status,
            'blocked': self.blocked,
            'detailed_scan_time': self.detailed_scan_time
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'DeviceInfo':
        """Crea una instancia de DeviceInfo desde un diccionario"""
        device = cls(data['ip'], data['mac'])
        device.hostname = data.get('hostname', '')
        device.vendor = data.get('vendor', '')
        device.vendor_details = data.get('vendor_details', '')
        device.device_type = data.get('device_type', '')
        device.model = data.get('model', '')
        device.os = data.get('os', '')
        device.open_ports = data.get('open_ports', [])
        device.service_details = data.get('service_details', {})
        device.last_seen = data.get('last_seen', time.time())
        device.status = data.get('status', 'activo')
        device.blocked = data.get('blocked', False)
        device.detailed_scan_time = data.get('detailed_scan_time', None)
        return device

    def update_from_dict(self, data: Dict) -> None:
        """Actualiza los campos del dispositivo desde un diccionario"""
        # Solo actualizar campos que están presentes en el diccionario
        for key, value in data.items():
            if hasattr(self, key) and value is not None:  # Solo actualizar si el valor no es None
                setattr(self, key, value)
        
        # Siempre actualizar last_seen
        self.last_seen = time.time()
        self.status = "activo"

class NetworkScanner:
    """Escáner de red optimizado para detectar dispositivos y recopilar información"""
    
    def __init__(self, max_workers: int = 20, scan_timeout: int = 3, aggressive_scan: bool = False):
        """
        Inicializa el escáner de red
        
        Args:
            max_workers: Número máximo de trabajadores para escaneos paralelos
            scan_timeout: Tiempo de espera para operaciones de escaneo (en segundos)
            aggressive_scan: Si se debe realizar un escaneo más agresivo (más lento pero más detallado)
        """
        self.devices = {}  # Diccionario de dispositivos: {ip: DeviceInfo}
        self.scanning = False
        self.scanner_thread = None
        self.on_device_found = None  # Callback cuando se encuentra un dispositivo
        self.on_scan_complete = None  # Callback cuando se completa el escaneo
        
        # Parámetros de escaneo
        self.max_workers = max_workers
        self.scan_timeout = scan_timeout
        self.aggressive_scan = aggressive_scan
        
        # Inicializar componentes de red
        self.interfaces = self._get_interfaces()
        self.gateway_ip = self._get_default_gateway()
        self.gateway_mac = self._get_mac_address(self.gateway_ip) if self.gateway_ip else None
        self.local_ip = self._get_local_ip()
        self.local_mac = self._get_local_mac()
        
        # Inicializar fingerprinter
        self.fingerprinter = DeviceFingerprinter(
            max_workers=max_workers,
            timeout=scan_timeout,
            aggressive_scan=aggressive_scan
        )
        
        # Inicializar escáner nmap
        self.nm = nmap.PortScanner()
    
    def _get_interfaces(self) -> Dict[str, Dict]:
        """Obtiene información de todas las interfaces de red"""
        interfaces = {}
        try:
            for iface in netifaces.interfaces():
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addresses:
                    for addr in addresses[netifaces.AF_INET]:
                        # Guardar IP, máscara, MAC si está disponible
                        iface_info = {
                            'ip': addr.get('addr'),
                            'netmask': addr.get('netmask'),
                            'mac': None
                        }
                        
                        # Intentar obtener MAC
                        if netifaces.AF_LINK in addresses:
                            iface_info['mac'] = addresses[netifaces.AF_LINK][0].get('addr')
                        
                        interfaces[iface] = iface_info
        except Exception as e:
            logger.error(f"Error al obtener interfaces: {e}")
        
        return interfaces
    
    def _get_default_gateway(self) -> Optional[str]:
        """Obtiene la dirección IP de la puerta de enlace por defecto"""
        try:
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                return gateways['default'][netifaces.AF_INET][0]
        except Exception as e:
            logger.error(f"Error al obtener la puerta de enlace: {e}")
        return None
    
    def _get_local_ip(self) -> Optional[str]:
        """Obtiene la dirección IP local"""
        try:
            if self.gateway_ip:
                iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addresses:
                    return addresses[netifaces.AF_INET][0]['addr']
        except Exception as e:
            logger.error(f"Error al obtener la IP local: {e}")
        return None
    
    def _get_local_mac(self) -> Optional[str]:
        """Obtiene la dirección MAC local"""
        try:
            if self.local_ip:
                for iface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            if addr['addr'] == self.local_ip and netifaces.AF_LINK in addrs:
                                return addrs[netifaces.AF_LINK][0]['addr'].lower()
        except Exception as e:
            logger.error(f"Error al obtener la MAC local: {e}")
        return None
    
    def _get_mac_address(self, ip: str) -> Optional[str]:
        """Obtiene la dirección MAC de un dispositivo dada su IP"""
        if not ip:
            return None
            
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            answered, _ = srp(packet, timeout=2, verbose=0, retry=3)
            
            if answered:
                return answered[0][1].hwsrc.lower()
        except Exception as e:
            logger.debug(f"Error al obtener la MAC de {ip}: {e}")
        return None
    
    def _get_network_range(self) -> str:
        """Determina el rango de red a escanear basado en la IP local y la máscara"""
        if not self.local_ip:
            logger.error("No se pudo determinar la IP local")
            return "192.168.1.0/24"  # Rango por defecto
        
        try:
            # Obtener la interfaz activa
            active_iface = None
            for iface, info in self.interfaces.items():
                if info.get('ip') == self.local_ip:
                    active_iface = iface
                    break
            
            if active_iface and 'netmask' in self.interfaces[active_iface]:
                # Calcular rango de red basado en IP y máscara
                ip = self.local_ip
                netmask = self.interfaces[active_iface]['netmask']
                
                # Convertir IP y máscara a integers para operar
                ip_parts = [int(part) for part in ip.split('.')]
                mask_parts = [int(part) for part in netmask.split('.')]
                
                # Calcular dirección de red
                network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
                network = '.'.join(str(part) for part in network_parts)
                
                # Calcular prefijo de red (CIDR)
                mask_binary = ''.join([bin(part)[2:].zfill(8) for part in mask_parts])
                prefix_len = mask_binary.count('1')
                
                return f"{network}/{prefix_len}"
            else:
                # Si no podemos determinar la máscara, usamos /24
                ip_parts = self.local_ip.split('.')
                return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                
        except Exception as e:
            logger.error(f"Error al determinar el rango de red: {e}")
            ip_parts = self.local_ip.split('.')
            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    
    def _discover_hosts_arpscan(self, network_range: str) -> List[Dict]:
        """
        Descubre dispositivos en la red usando ARP scan (rápido)
        
        Args:
            network_range: Rango de red en formato CIDR (e.g., "192.168.1.0/24")
            
        Returns:
            List[Dict]: Lista de dispositivos detectados (ip, mac)
        """
        devices = []
        try:
            # Crear paquete ARP para el escaneo
            arp_request = ARP(pdst=network_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            
            # Enviar paquetes y capturar respuestas
            logger.info(f"Iniciando ARP scan en {network_range}")
            answered, _ = srp(packet, timeout=3, verbose=0)
            
            # Procesar respuestas
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc.lower()
                devices.append({'ip': ip, 'mac': mac})
                logger.debug(f"Dispositivo encontrado via ARP: {ip} ({mac})")
        
        except Exception as e:
            logger.error(f"Error durante el ARP scan: {e}")
        
        return devices
    
    def _discover_hosts_pingscan(self, network_range: str) -> List[Dict]:
        """
        Descubre dispositivos en la red usando ping scan (nmap)
        
        Args:
            network_range: Rango de red en formato CIDR (e.g., "192.168.1.0/24")
            
        Returns:
            List[Dict]: Lista de dispositivos detectados (ip)
        """
        devices = []
        try:
            # Usar nmap para escaneo ping
            logger.info(f"Iniciando ping scan en {network_range}")
            result = self.nm.scan(hosts=network_range, arguments="-sn -T4 --min-rate=1000")
            
            # Extraer hosts encontrados
            for host in result['scan']:
                # Solo añadir si el estado es 'up'
                if 'status' in result['scan'][host] and result['scan'][host]['status']['state'] == 'up':
                    # Intentar obtener mac si está disponible
                    mac = None
                    if 'addresses' in result['scan'][host] and 'mac' in result['scan'][host]['addresses']:
                        mac = result['scan'][host]['addresses']['mac'].lower()
                    
                    devices.append({'ip': host, 'mac': mac})
                    logger.debug(f"Dispositivo encontrado via ping: {host}" + (f" ({mac})" if mac else ""))
        
        except Exception as e:
            logger.error(f"Error durante el ping scan: {e}")
        
        return devices
    
    def _merge_device_lists(self, arp_devices: List[Dict], ping_devices: List[Dict]) -> List[Dict]:
        """
        Combina las listas de dispositivos detectados por ARP y ping
        
        Args:
            arp_devices: Lista de dispositivos detectados por ARP
            ping_devices: Lista de dispositivos detectados por ping
            
        Returns:
            List[Dict]: Lista combinada de dispositivos
        """
        # Crear diccionario de dispositivos ARP para búsqueda rápida
        arp_dict = {device['ip']: device for device in arp_devices}
        
        # Lista final de dispositivos
        merged_devices = list(arp_devices)  # Empezar con todos los dispositivos ARP
        
        # Añadir dispositivos ping que no están en ARP
        for ping_device in ping_devices:
            if ping_device['ip'] not in arp_dict:
                merged_devices.append(ping_device)
            elif not arp_dict[ping_device['ip']]['mac'] and ping_device['mac']:
                # Si tenemos MAC en ping pero no en ARP, actualizar
                arp_dict[ping_device['ip']]['mac'] = ping_device['mac']
        
        return merged_devices
    
    def _batch_process_devices(self, devices: List[Dict], quick_scan: bool) -> None:
        """
        Procesa dispositivos en lotes para mejor rendimiento
        
        Args:
            devices: Lista de dispositivos a procesar
            quick_scan: Si es un escaneo rápido o completo
        """
        # Si no hay dispositivos o callbacks, salir
        if not devices or not self.on_device_found:
            return
        
        # Procesar dispositivos que ya conocemos primero
        known_devices = []
        for device_info in devices:
            ip = device_info['ip']
            if ip in self.devices:
                # Actualizar timestamp y estado
                self.devices[ip].last_seen = time.time()
                self.devices[ip].status = "activo"
                
                # Actualizar MAC si no lo teníamos
                if not self.devices[ip].mac and 'mac' in device_info and device_info['mac']:
                    self.devices[ip].mac = device_info['mac']
                
                # Notificar actualización
                self.on_device_found(self.devices[ip])
                
                # Añadir a la lista de dispositivos conocidos
                known_devices.append(ip)
        
        # Filtrar dispositivos que necesitan fingerprinting
        devices_to_fingerprint = [d for d in devices if d['ip'] not in known_devices]
        
        if not devices_to_fingerprint:
            logger.info("No hay nuevos dispositivos para fingerprinting")
            return
        
        # Nivel de detalle del fingerprinting según el tipo de escaneo
        if quick_scan:
            # Escaneo rápido: solo información básica
            logger.info(f"Realizando fingerprinting básico para {len(devices_to_fingerprint)} dispositivos")
            
            def process_device(device_info):
                try:
                    ip = device_info['ip']
                    mac = device_info['mac']
                    
                    # Si no tenemos MAC, intentar obtenerla
                    if not mac:
                        mac = self._get_mac_address(ip)
                        device_info['mac'] = mac
                    
                    # Crear objeto DeviceInfo básico
                    device = DeviceInfo(ip, mac if mac else "")
                    
                    # Obtener vendor si tenemos MAC
                    if mac:
                        vendor_short, vendor_details = self.fingerprinter.device_db.get_vendor_info(mac)
                        if vendor_short != "Desconocido":
                            device.vendor = vendor_short
                            device.vendor_details = vendor_details
                    
                    # Estimar tipo de dispositivo rápidamente
                    device_type = self.fingerprinter.estimate_device_type(ip, mac)
                    if device_type != "Desconocido":
                        device.device_type = device_type
                    
                    # Obtener hostname básico
                    try:
                        hostname = socket.getfqdn(ip)
                        if hostname != ip:  # A veces getfqdn devuelve la IP si no hay nombre
                            device.hostname = hostname
                    except:
                        pass
                    
                    # Guardar el dispositivo
                    self.devices[ip] = device
                    
                    # Notificar
                    self.on_device_found(device)
                    
                except Exception as e:
                    logger.error(f"Error procesando dispositivo {device_info['ip']}: {e}")
            
            # Procesar dispositivos en paralelo
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                executor.map(process_device, devices_to_fingerprint)
        
        else:
            # Escaneo completo: fingerprinting detallado
            logger.info(f"Realizando fingerprinting detallado para {len(devices_to_fingerprint)} dispositivos")
            
            # Función de callback para cada dispositivo completado
            def on_device_fingerprinted(device_data):
                try:
                    ip = device_data['ip']
                    
                    # Crear o actualizar objeto DeviceInfo
                    if ip in self.devices:
                        device = self.devices[ip]
                        device.update_from_dict(device_data)
                    else:
                        device = DeviceInfo(ip, device_data.get('mac', ''))
                        device.update_from_dict(device_data)
                        self.devices[ip] = device
                    
                    # Notificar
                    self.on_device_found(device)
                    
                except Exception as e:
                    logger.error(f"Error procesando resultado de fingerprint para {device_data.get('ip', 'unknown')}: {e}")
            
            # Realizar fingerprinting en lote
            self.fingerprinter.fingerprint_devices_batch(
                devices_to_fingerprint,
                on_device_done=on_device_fingerprinted
            )
    
    def _scan_thread(self, quick_scan: bool = True):
        """Método interno para ejecutar el escaneo en un hilo separado"""
        try:
            if not self.gateway_ip or not self.local_ip:
                logger.error("No se pudo determinar la puerta de enlace o la IP local")
                self.scanning = False
                if self.on_scan_complete:
                    self.on_scan_complete(False, "No se pudo determinar la puerta de enlace o la IP local")
                return
            
            # Determinar el rango de red a escanear
            network_range = self._get_network_range()
            logger.info(f"Escaneando red {network_range}, modo {'rápido' if quick_scan else 'completo'}")
            
            # Descubrir hosts usando diferentes métodos
            arp_devices = self._discover_hosts_arpscan(network_range)
            ping_devices = self._discover_hosts_pingscan(network_range)
            
            # Combinar resultados
            all_devices = self._merge_device_lists(arp_devices, ping_devices)
            logger.info(f"Total de dispositivos detectados: {len(all_devices)}")
            
            # Procesar dispositivos en lotes
            self._batch_process_devices(all_devices, quick_scan)
            
            # Marcar dispositivos que no respondieron como inactivos
            current_time = time.time()
            for ip, device in list(self.devices.items()):
                if device.last_seen < current_time - 300:  # Más de 5 minutos sin responder
                    device.status = "inactivo"
                    # Notificar actualización
                    if self.on_device_found:
                        self.on_device_found(device)
            
            # Escaneo completado
            logger.info("Escaneo de red completado")
            
        except Exception as e:
            logger.error(f"Error durante el escaneo de red: {e}")
            if self.on_scan_complete:
                self.on_scan_complete(False, f"Error: {e}")
        
        finally:
            self.scanning = False
            if self.on_scan_complete:
                self.on_scan_complete(True, "Escaneo completado correctamente")
    
    def scan_network(self, on_device_found: Callable = None, on_scan_complete: Callable = None, quick_scan: bool = True):
        """
        Inicia un escaneo de la red
        
        Args:
            on_device_found: Callback llamado cuando se encuentra un dispositivo
            on_scan_complete: Callback llamado cuando se completa el escaneo
            quick_scan: Si es True, realiza un escaneo rápido sin información detallada
        """
        if self.scanning:
            logger.warning("Ya hay un escaneo en curso")
            return
        
        self.on_device_found = on_device_found
        self.on_scan_complete = on_scan_complete
        self.scanning = True
        
        # Iniciar el escaneo en un hilo separado
        self.scanner_thread = threading.Thread(
            target=self._scan_thread, 
            args=(quick_scan,),
            daemon=True
        )
        self.scanner_thread.start()
    
    def stop_scan(self):
        """Detiene el escaneo en curso"""
        self.scanning = False
        if self.scanner_thread and self.scanner_thread.is_alive():
            self.scanner_thread.join(timeout=1)
            logger.info("Escaneo detenido")
    
    def get_all_devices(self) -> List[DeviceInfo]:
        """Retorna la lista de todos los dispositivos detectados"""
        return list(self.devices.values())
    
    def get_device(self, ip: str) -> Optional[DeviceInfo]:
        """Obtiene información de un dispositivo específico por su IP"""
        return self.devices.get(ip)
    
    def scan_specific_device(self, ip: str, callback: Callable = None):
        """
        Escanea un dispositivo específico para obtener información detallada
        
        Args:
            ip: Dirección IP del dispositivo
            callback: Función llamada cuando se completa el escaneo (opcional)
        """
        if not ip:
            return
        
        if self.scanning:
            logger.warning("Ya hay un escaneo en curso")
            return
        
        # Función para realizar el escaneo en un hilo separado
        def scan_thread():
            try:
                logger.info(f"Iniciando escaneo detallado para {ip}")
                
                # Obtener MAC si no la tenemos
                mac = None
                if ip in self.devices and self.devices[ip].mac:
                    mac = self.devices[ip].mac
                else:
                    mac = self._get_mac_address(ip)
                
                # Obtener información básica si ya tenemos el dispositivo
                basic_info = None
                if ip in self.devices:
                    basic_info = self.devices[ip].to_dict()
                
                # Realizar fingerprinting detallado con el parámetro detailed_scan=True
                device_data = self.fingerprinter.fingerprint_device(ip, mac, basic_info, detailed_scan=True)
                
                # Crear o actualizar objeto DeviceInfo
                if ip in self.devices:
                    device = self.devices[ip]
                    device.update_from_dict(device_data)
                else:
                    device = DeviceInfo(ip, device_data.get('mac', ''))
                    device.update_from_dict(device_data)
                    self.devices[ip] = device
                
                # Actualizar campos especiales como service_details y detailed_scan_time
                if 'service_details' in device_data:
                    device.service_details = device_data['service_details']
                
                if 'detailed_scan_time' in device_data:
                    device.detailed_scan_time = device_data['detailed_scan_time']
                
                logger.info(f"Escaneo detallado completado para {ip}")
                
                # Llamar al callback si está definido
                if callback:
                    callback(device)
                
            except Exception as e:
                logger.error(f"Error al escanear dispositivo específico {ip}: {e}")
                if callback:
                    # Si hay error, intentar devolver un objeto básico
                    if ip in self.devices:
                        callback(self.devices[ip])
                    else:
                        device = DeviceInfo(ip, "")
                        device.status = "error"
                        callback(device)
            
            finally:
                self.scanning = False
        
        # Iniciar el escaneo en un hilo separado
        self.scanning = True
        thread = threading.Thread(target=scan_thread, daemon=True)
        thread.start()

    def set_max_workers(self, max_workers: int):
        """Configura el número máximo de trabajadores para escaneos paralelos"""
        self.max_workers = max_workers
        self.fingerprinter = DeviceFingerprinter(
            max_workers=max_workers,
            timeout=self.scan_timeout,
            aggressive_scan=self.aggressive_scan
        )
    
    def set_scan_timeout(self, timeout: int):
        """Configura el tiempo de espera para operaciones de escaneo"""
        self.scan_timeout = timeout
        self.fingerprinter = DeviceFingerprinter(
            max_workers=self.max_workers,
            timeout=timeout,
            aggressive_scan=self.aggressive_scan
        )
    
    def set_aggressive_scan(self, aggressive: bool):
        """Configura si se debe realizar un escaneo más agresivo"""
        self.aggressive_scan = aggressive
        self.fingerprinter = DeviceFingerprinter(
            max_workers=self.max_workers,
            timeout=self.scan_timeout,
            aggressive_scan=aggressive
        )