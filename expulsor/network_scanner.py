"""
Módulo de escaneo de red para Expulsor
"""

import socket
import threading
import time
from typing import Dict, List, Optional, Callable

import netifaces
import nmap
from scapy.all import ARP, Ether, srp

class DeviceInfo:
    """Clase para almacenar información de dispositivos detectados"""
    def __init__(self, ip: str, mac: str):
        self.ip = ip
        self.mac = mac
        self.hostname = ""
        self.vendor = ""
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
        device.os = data.get('os', '')
        device.open_ports = data.get('open_ports', [])
        device.last_seen = data.get('last_seen', time.time())
        device.status = data.get('status', 'activo')
        device.blocked = data.get('blocked', False)
        return device


class NetworkScanner:
    """Escáner de red para detectar dispositivos y recopilar información"""
    
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
    
    def _get_vendor_info(self, mac: str) -> str:
        """Obtiene información del fabricante a partir de la dirección MAC"""
        try:
            # Simplificado - en una implementación real podríamos usar una base de datos de OUIs
            return "Desconocido"
        except:
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
        device.vendor = self._get_vendor_info(mac)
        
        # Escaneo avanzado (podría ser lento, considerar hacerlo bajo demanda)
        if ip != self.local_ip and ip != self.gateway_ip:
            device.open_ports = self._scan_ports(ip)
            device.os = self._get_os_info(ip)
        elif ip == self.gateway_ip:
            device.hostname = "Puerta de enlace"
        elif ip == self.local_ip:
            device.hostname = "Este dispositivo"
        
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