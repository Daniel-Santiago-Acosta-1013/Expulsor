"""
Módulo de escaneo de red para Expulsor
"""

import socket
import threading
import time
import re
import json
import os
from typing import Dict, List, Optional, Callable
from pathlib import Path

import netifaces
import nmap
import requests
from scapy.all import ARP, Ether, srp

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
        self.last_seen = time.time()
        self.status = "activo"
        self.blocked = False
    
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
            'last_seen': self.last_seen,
            'status': self.status,
            'blocked': self.blocked
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
        device.last_seen = data.get('last_seen', time.time())
        device.status = data.get('status', 'activo')
        device.blocked = data.get('blocked', False)
        return device


class NetworkScanner:
    """Escáner de red para detectar dispositivos y recopilar información"""
    
    # Definiciones para ayudar a identificar dispositivos
    DEVICE_SIGNATURES = {
        # Basado en puertos abiertos
        'ports': {
            (80, 443, 8080): ['Router', 'Gateway', 'Access Point'],
            (554, 1935): ['IP Camera', 'Security Camera'],
            (1883, 8883): ['IoT Device', 'Smart Home Hub'],
            (8009,): ['Chromecast', 'Smart TV'],
            (548, 5009, 5353): ['Apple Device'],
            (62078,): ['iPhone', 'iPad'],
            (5353, 7000): ['Apple TV'],
            (8008, 8009): ['Smart TV', 'Streaming Device'],
            (8080, 8443, 9080): ['IP Camera', 'NVR', 'DVR'],
            (9100,): ['Printer'],
            (23, 2323): ['IoT Device', 'Smart Appliance'],
        },
        # Basado en patrones de nombre de host
        'hostname': {
            r'.*iphone.*': 'iPhone',
            r'.*ipad.*': 'iPad',
            r'.*macbook.*': 'MacBook',
            r'.*android.*': 'Android Device',
            r'.*phone.*': 'Smartphone',
            r'.*tv.*': 'Smart TV',
            r'.*roku.*': 'Roku Device',
            r'.*chromecast.*': 'Chromecast',
            r'.*echo.*': 'Amazon Echo',
            r'.*alexa.*': 'Amazon Alexa',
            r'.*nest.*': 'Nest Device',
            r'.*camera.*': 'IP Camera',
            r'.*printer.*': 'Printer',
            r'.*xbox.*': 'Xbox',
            r'.*playstation.*': 'PlayStation',
            r'.*nintendo.*': 'Nintendo Switch',
            r'.*laptop.*': 'Laptop',
            r'.*pc.*': 'Desktop PC',
            r'.*router.*': 'Router',
            r'.*hub.*': 'Smart Hub',
            r'.*watch.*': 'Smart Watch',
            r'.*refrigerator.*': 'Smart Refrigerator',
            r'.*doorbell.*': 'Smart Doorbell',
        },
        # Basado en prefijos MAC de fabricantes específicos
        'mac_prefixes': {
            'Apple': ['iPhone', 'iPad', 'Mac', 'Apple Device'],
            'Samsung': ['Samsung Phone', 'Samsung TV', 'Samsung Device'],
            'Google': ['Google Device', 'Chromecast', 'Nest'],
            'Amazon': ['Amazon Device', 'Echo', 'Alexa', 'Fire TV'],
            'Sony': ['PlayStation', 'Sony TV', 'Sony Device'],
            'Microsoft': ['Xbox', 'Surface', 'Microsoft Device'],
            'LG Electronics': ['LG TV', 'LG Smartphone', 'LG Appliance'],
            'Xiaomi': ['Xiaomi Phone', 'Xiaomi Device'],
            'Huawei': ['Huawei Phone', 'Huawei Device'],
            'TP-Link': ['Router', 'Access Point', 'TP-Link Device'],
            'Netgear': ['Router', 'Access Point', 'Netgear Device'],
            'Cisco': ['Router', 'Switch', 'Enterprise Network Device'],
            'D-Link': ['Router', 'IP Camera', 'D-Link Device'],
            'Roku': ['Roku Device', 'Streaming Device'],
            'Nintendo': ['Nintendo Switch', 'Gaming Console'],
            'Sonos': ['Sonos Speaker', 'Audio Device'],
            'Philips': ['Philips Hue', 'Smart Lighting', 'Philips TV'],
            'Bose': ['Bose Speaker', 'Audio Device'],
            'Ring': ['Ring Doorbell', 'Security Camera'],
            'Ubiquiti': ['Access Point', 'Network Device'],
            'Asus': ['Router', 'Laptop', 'Asus Device'],
            'Linksys': ['Router', 'Network Device'],
            'Dell': ['Laptop', 'Desktop PC', 'Dell Device'],
            'HP': ['Printer', 'Laptop', 'HP Device'],
            'Epson': ['Printer', 'Epson Device'],
            'Canon': ['Printer', 'Canon Device'],
            'Brother': ['Printer', 'Brother Device'],
            'Lenovo': ['Laptop', 'Lenovo Device'],
            'Intel': ['Desktop PC', 'Intel Device'],
            'Honeywell': ['Smart Thermostat', 'Security System'],
            'Fitbit': ['Fitness Tracker', 'Smart Watch'],
            'Garmin': ['GPS Device', 'Smart Watch'],
        }
    }
    
    def __init__(self):
        """Inicializa el escáner de red"""
        self.devices = {}  # Diccionario de dispositivos: {ip: DeviceInfo}
        self.gateway_ip = self._get_default_gateway()
        self.gateway_mac = self._get_mac_address(self.gateway_ip) if self.gateway_ip else None
        self.local_ip = self._get_local_ip()
        self.local_mac = self._get_local_mac()
        self.scanning = False
        self.scanner_thread = None
        self.on_device_found = None  # Callback cuando se encuentra un dispositivo
        self.on_scan_complete = None  # Callback cuando se completa el escaneo
        self.nm = nmap.PortScanner()  # Scanner de nmap para información adicional
        
        # Inicializar la caché de MACs
        self.mac_vendor_cache = {}
        self._load_mac_vendor_cache()
        
        # Descargar base de datos de OUI si no existe
        self.oui_db_path = Path(os.path.expanduser("~/.expulsor/oui_database.json"))
        if not self.oui_db_path.exists():
            self._download_oui_database()
    
    def _get_default_gateway(self) -> Optional[str]:
        """Obtiene la dirección IP de la puerta de enlace por defecto"""
        try:
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                return gateways['default'][netifaces.AF_INET][0]
        except Exception as e:
            print(f"Error al obtener la puerta de enlace: {e}")
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
            print(f"Error al obtener la IP local: {e}")
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
                                return addrs[netifaces.AF_LINK][0]['addr']
        except Exception as e:
            print(f"Error al obtener la MAC local: {e}")
        return None
    
    def _get_mac_address(self, ip: str) -> Optional[str]:
        """Obtiene la dirección MAC de un dispositivo dada su IP"""
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            answered, _ = srp(packet, timeout=2, verbose=0)
            
            if answered:
                return answered[0][1].hwsrc
        except Exception as e:
            print(f"Error al obtener la MAC de {ip}: {e}")
        return None
    
    def _get_hostname(self, ip: str) -> str:
        """Obtiene el nombre de host de un dispositivo dada su IP"""
        try:
            return socket.getfqdn(ip)
        except:
            return ""
    
    def _download_oui_database(self):
        """Descarga la base de datos de OUI desde el registro IEEE"""
        try:
            # Asegurar que el directorio existe
            self.oui_db_path.parent.mkdir(parents=True, exist_ok=True)
            
            # URL de la base de datos de OUI de IEEE
            url = "https://standards-oui.ieee.org/oui/oui.csv"
            response = requests.get(url)
            
            if response.status_code == 200:
                # Procesar el CSV y convertirlo a un diccionario
                lines = response.text.splitlines()
                oui_dict = {}
                
                for line in lines[1:]:  # Saltamos la cabecera
                    parts = line.split(',')
                    if len(parts) >= 3:
                        mac_prefix = parts[1].strip('"').replace('-', ':').lower()
                        company = parts[2].strip('"')
                        if mac_prefix and company:
                            oui_dict[mac_prefix] = company
                
                # Guardar en un archivo JSON
                with open(self.oui_db_path, 'w') as f:
                    json.dump(oui_dict, f)
                
                print(f"Base de datos OUI descargada: {len(oui_dict)} registros")
            else:
                print(f"Error al descargar la base de datos OUI: {response.status_code}")
                
                # Crear un diccionario vacío si falla la descarga
                with open(self.oui_db_path, 'w') as f:
                    json.dump({}, f)
        
        except Exception as e:
            print(f"Error al descargar la base de datos OUI: {e}")
            # Crear un diccionario vacío si falla la descarga
            with open(self.oui_db_path, 'w') as f:
                json.dump({}, f)
    
    def _load_mac_vendor_cache(self):
        """Carga la caché de fabricantes MAC desde un archivo"""
        cache_path = Path(os.path.expanduser("~/.expulsor/mac_vendor_cache.json"))
        try:
            if cache_path.exists():
                with open(cache_path, 'r') as f:
                    self.mac_vendor_cache = json.load(f)
        except Exception as e:
            print(f"Error al cargar la caché de fabricantes MAC: {e}")
            self.mac_vendor_cache = {}
    
    def _save_mac_vendor_cache(self):
        """Guarda la caché de fabricantes MAC en un archivo"""
        cache_path = Path(os.path.expanduser("~/.expulsor/mac_vendor_cache.json"))
        try:
            # Asegurar que el directorio existe
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(cache_path, 'w') as f:
                json.dump(self.mac_vendor_cache, f)
        except Exception as e:
            print(f"Error al guardar la caché de fabricantes MAC: {e}")
    
    def _get_vendor_info(self, mac: str) -> tuple:
        """
        Obtiene información detallada del fabricante a partir de la dirección MAC
        
        Returns:
            tuple: (vendor_short, vendor_details)
        """
        try:
            # Normalizar la dirección MAC
            mac = mac.lower()
            
            # Verificar si ya está en caché
            if mac in self.mac_vendor_cache:
                return self.mac_vendor_cache[mac]
            
            # Extraer el prefijo OUI (primeros 6 caracteres sin los ':')
            mac_prefix = mac.replace(':', '')[:6]
            
            # Convertir a formato XX:XX:XX para búsqueda en la base de datos
            lookup_prefix = ':'.join([mac_prefix[i:i+2] for i in range(0, 6, 2)]).lower()
            
            # Intentar obtener el fabricante de la base de datos local
            vendor_info = "Desconocido"
            vendor_details = "Desconocido"
            
            if self.oui_db_path.exists():
                try:
                    with open(self.oui_db_path, 'r') as f:
                        oui_db = json.load(f)
                    
                    # Buscar en la base de datos
                    for prefix, company in oui_db.items():
                        if lookup_prefix.startswith(prefix.lower()):
                            vendor_info = company
                            vendor_details = company
                            break
                except Exception as e:
                    print(f"Error al consultar la base de datos OUI: {e}")
            
            # Si no encontramos nada, intentar con la API de macvendors.com
            if vendor_info == "Desconocido":
                try:
                    url = f"https://api.macvendors.com/{mac}"
                    response = requests.get(url, timeout=2)
                    
                    if response.status_code == 200:
                        vendor_info = response.text.strip()
                        vendor_details = vendor_info
                except Exception as e:
                    print(f"Error al consultar la API de macvendors.com: {e}")
            
            # Extraer nombre corto del fabricante (primera palabra o dos)
            short_vendor = vendor_info.split()[0]
            if len(vendor_info.split()) > 1 and len(vendor_info.split()[0]) <= 3:
                short_vendor = ' '.join(vendor_info.split()[:2])
            
            # Guardar en caché
            self.mac_vendor_cache[mac] = (short_vendor, vendor_details)
            self._save_mac_vendor_cache()
            
            return short_vendor, vendor_details
        
        except Exception as e:
            print(f"Error al obtener información del fabricante para {mac}: {e}")
            return "Desconocido", "Desconocido"
    
    def _identify_device_type(self, device: DeviceInfo) -> str:
        """Identifica el tipo de dispositivo basado en diferentes heurísticas"""
        if not device:
            return "Desconocido"
        
        # Lista de posibles tipos de dispositivo basados en diferentes fuentes
        possible_types = []
        
        # 1. Identificar por puertos abiertos
        if device.open_ports:
            for port_pattern, device_types in self.DEVICE_SIGNATURES['ports'].items():
                if all(port in device.open_ports for port in port_pattern):
                    possible_types.extend(device_types)
        
        # 2. Identificar por nombre de host
        if device.hostname:
            hostname_lower = device.hostname.lower()
            for pattern, device_type in self.DEVICE_SIGNATURES['hostname'].items():
                if re.match(pattern, hostname_lower):
                    possible_types.append(device_type)
        
        # 3. Identificar por fabricante
        if device.vendor:
            vendor_lower = device.vendor.lower()
            for vendor, device_types in self.DEVICE_SIGNATURES['mac_prefixes'].items():
                if vendor.lower() in vendor_lower:
                    possible_types.extend(device_types)
        
        # 4. Inferir por sistema operativo
        if device.os:
            os_lower = device.os.lower()
            if "windows" in os_lower:
                possible_types.append("Desktop PC")
                possible_types.append("Laptop")
            elif "linux" in os_lower:
                possible_types.append("Server")
                possible_types.append("Desktop PC")
                possible_types.append("IoT Device")
            elif "android" in os_lower:
                possible_types.append("Android Device")
                possible_types.append("Smartphone")
                possible_types.append("Tablet")
            elif "ios" in os_lower or "iphone" in os_lower:
                possible_types.append("iPhone")
                possible_types.append("iPad")
            elif "mac" in os_lower:
                possible_types.append("Mac")
                possible_types.append("MacBook")
        
        # Contar ocurrencias y seleccionar el tipo más probable
        if possible_types:
            from collections import Counter
            count = Counter(possible_types)
            return count.most_common(1)[0][0]
        
        return "Desconocido"
    
    def _identify_device_model(self, device: DeviceInfo) -> str:
        """Identifica el modelo específico del dispositivo usando fingerprinting avanzado"""
        if not device or not device.ip:
            return "Desconocido"
        
        # Para dispositivos especiales, usar información conocida
        if device.ip == self.gateway_ip:
            return "Router/Gateway"
        
        if device.ip == self.local_ip:
            return "Este dispositivo"
        
        # Intentar identificar usando nmap con scripts de identificación avanzados
        try:
            # Solo si tenemos un tipo de dispositivo identificado, usamos scripts específicos
            if device.device_type != "Desconocido":
                # Usar scripts de nmap específicos según el tipo de dispositivo
                script_args = ""
                
                if "Router" in device.device_type or "Access Point" in device.device_type:
                    script_args = "--script=snmp-info,http-title,http-headers"
                elif "Smart TV" in device.device_type or "Streaming" in device.device_type:
                    script_args = "--script=upnp-info,broadcast-upnp-info"
                elif "Camera" in device.device_type:
                    script_args = "--script=rtsp-methods,http-title"
                elif "Printer" in device.device_type:
                    script_args = "--script=snmp-info"
                elif "Phone" in device.device_type or "Smartphone" in device.device_type:
                    script_args = "--script=broadcast-dhcp-discover"
                
                if script_args:
                    result = self.nm.scan(device.ip, arguments=f"-F -T4 {script_args}")
                    
                    # Analizar resultados para inferir el modelo
                    if 'scan' in result and device.ip in result['scan']:
                        scan_data = result['scan'][device.ip]
                        
                        # Extraer información de los scripts de nmap
                        if 'hostscript' in scan_data:
                            for script in scan_data['hostscript']:
                                if 'output' in script:
                                    # Buscar patrones conocidos en la salida
                                    model_patterns = [
                                        r"(?:model|Model|MODEL)[:\s]+([A-Za-z0-9\-_\.]+)",
                                        r"(?:device|Device|DEVICE)[:\s]+([A-Za-z0-9\-_\.]+)",
                                        r"(?:product|Product|PRODUCT)[:\s]+([A-Za-z0-9\-_\.]+)"
                                    ]
                                    
                                    for pattern in model_patterns:
                                        match = re.search(pattern, script['output'])
                                        if match:
                                            return match.group(1)
            
            # Análisis basado en puertos y servicios detectados
            if device.open_ports:
                services = []
                
                # Intentar obtener información de servicios para los puertos abiertos
                for port in device.open_ports:
                    try:
                        service_scan = self.nm.scan(device.ip, str(port))
                        if 'scan' in service_scan and device.ip in service_scan['scan']:
                            if 'tcp' in service_scan['scan'][device.ip] and port in service_scan['scan'][device.ip]['tcp']:
                                service_info = service_scan['scan'][device.ip]['tcp'][port]
                                if 'product' in service_info and service_info['product']:
                                    services.append(f"{service_info['product']}")
                                    if 'version' in service_info and service_info['version']:
                                        return f"{service_info['product']} {service_info['version']}"
                    except:
                        continue
                
                if services:
                    return services[0]
        
        except Exception as e:
            print(f"Error al identificar el modelo del dispositivo {device.ip}: {e}")
        
        # Si no se pudo identificar un modelo específico
        if device.device_type != "Desconocido":
            return f"{device.device_type} genérico"
        
        return "Desconocido"
    
    def _scan_ports(self, ip: str) -> List[int]:
        """Escanea los puertos abiertos en una IP específica"""
        try:
            result = self.nm.scan(ip, arguments='-F -T4')
            if ip in result['scan'] and 'tcp' in result['scan'][ip]:
                return [port for port, data in result['scan'][ip]['tcp'].items() 
                        if data['state'] == 'open']
        except Exception as e:
            print(f"Error al escanear puertos de {ip}: {e}")
        return []
    
    def _get_os_info(self, ip: str) -> str:
        """Obtiene información del sistema operativo"""
        try:
            result = self.nm.scan(ip, arguments='-O')
            if ip in result['scan'] and 'osmatch' in result['scan'][ip]:
                if result['scan'][ip]['osmatch']:
                    return result['scan'][ip]['osmatch'][0]['name']
        except:
            pass
        return "Desconocido"
    
    def _collect_device_info(self, ip: str, mac: str) -> DeviceInfo:
        """Recopila información detallada sobre un dispositivo"""
        device = DeviceInfo(ip, mac)
        device.hostname = self._get_hostname(ip)
        
        # Obtener información del fabricante (versión corta y detallada)
        vendor_short, vendor_details = self._get_vendor_info(mac)
        device.vendor = vendor_short
        device.vendor_details = vendor_details
        
        # Escaneo avanzado (podría ser lento, considerar hacerlo bajo demanda)
        if ip != self.local_ip and ip != self.gateway_ip:
            device.open_ports = self._scan_ports(ip)
            device.os = self._get_os_info(ip)
            
            # Identificar tipo de dispositivo y modelo
            device.device_type = self._identify_device_type(device)
            device.model = self._identify_device_model(device)
        elif ip == self.gateway_ip:
            device.hostname = "Puerta de enlace"
            device.device_type = "Router/Gateway"
            device.model = "Router Principal"
        elif ip == self.local_ip:
            device.hostname = "Este dispositivo"
            device.device_type = "Este dispositivo"
            device.model = "Cliente Expulsor"
        
        return device
    
    def scan_network(self, on_device_found: Callable = None, on_scan_complete: Callable = None, quick_scan: bool = True):
        """
        Inicia un escaneo de la red
        
        Args:
            on_device_found: Callback llamado cuando se encuentra un dispositivo
            on_scan_complete: Callback llamado cuando se completa el escaneo
            quick_scan: Si es True, realiza un escaneo rápido sin información detallada
        """
        if self.scanning:
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
    
    def _scan_thread(self, quick_scan: bool = True):
        """Método interno para ejecutar el escaneo en un hilo separado"""
        try:
            if not self.gateway_ip or not self.local_ip:
                print("No se pudo determinar la puerta de enlace o la IP local")
                self.scanning = False
                if self.on_scan_complete:
                    self.on_scan_complete(False, "No se pudo determinar la puerta de enlace o la IP local")
                return
            
            # Determinar la red a escanear
            ip_parts = self.local_ip.split('.')
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            # Crear paquete ARP para el escaneo
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            
            # Enviar paquetes y capturar respuestas
            answered, _ = srp(packet, timeout=3, verbose=0)
            
            # Procesar respuestas
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                
                # Si el dispositivo ya está en la lista, actualizar timestamp
                if ip in self.devices:
                    self.devices[ip].last_seen = time.time()
                    self.devices[ip].status = "activo"
                else:
                    # Recolectar información básica primero
                    device = DeviceInfo(ip, mac)
                    self.devices[ip] = device
                    
                    # Notificar que se encontró un dispositivo
                    if self.on_device_found:
                        self.on_device_found(device)
                    
                    # Si no es un escaneo rápido, recopilar información detallada
                    if not quick_scan:
                        detailed_device = self._collect_device_info(ip, mac)
                        self.devices[ip] = detailed_device
                        
                        # Notificar la actualización
                        if self.on_device_found:
                            self.on_device_found(detailed_device)
            
            # Marcar dispositivos que no respondieron como inactivos
            for ip, device in list(self.devices.items()):
                if device.last_seen < time.time() - 60:  # Más de 1 minuto sin responder
                    device.status = "inactivo"
            
            # Recopilar información adicional para los dispositivos que solo tienen información básica
            if not quick_scan:
                for ip, device in list(self.devices.items()):
                    if not device.hostname and device.status == "activo":
                        detailed_device = self._collect_device_info(ip, device.mac)
                        self.devices[ip] = detailed_device
                        
                        # Notificar la actualización
                        if self.on_device_found:
                            self.on_device_found(detailed_device)
        
        except Exception as e:
            print(f"Error durante el escaneo de red: {e}")
            if self.on_scan_complete:
                self.on_scan_complete(False, f"Error: {e}")
        
        finally:
            self.scanning = False
            if self.on_scan_complete:
                self.on_scan_complete(True, "Escaneo completado correctamente")
    
    def stop_scan(self):
        """Detiene el escaneo en curso"""
        self.scanning = False
        if self.scanner_thread and self.scanner_thread.is_alive():
            self.scanner_thread.join(timeout=1)
    
    def get_all_devices(self) -> List[DeviceInfo]:
        """Retorna la lista de todos los dispositivos detectados"""
        return list(self.devices.values())
    
    def get_device(self, ip: str) -> Optional[DeviceInfo]:
        """Obtiene información de un dispositivo específico por su IP"""
        return self.devices.get(ip)