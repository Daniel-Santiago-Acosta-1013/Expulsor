"""
Módulo para el fingerprinting avanzado de dispositivos de red
"""

import concurrent.futures
import re
import socket
import time
import logging
from typing import Dict, List, Optional, Tuple, Callable

import nmap
import requests
from scapy.all import ARP, Ether, srp, conf

from .device_db import DeviceDatabase
from .signature_matcher import SignatureMatcher

# Configurar logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Desactivar advertencias de Scapy
conf.verb = 0


class DeviceFingerprinter:
    """
    Clase principal para el fingerprinting avanzado de dispositivos
    Integra múltiples técnicas para identificar dispositivos con alta precisión
    """
    
    def __init__(self, max_workers: int = 10, timeout: int = 3, aggressive_scan: bool = False):
        """
        Inicializa el fingerprinter
        
        Args:
            max_workers: Número máximo de trabajadores para tareas paralelas
            timeout: Tiempo de espera para operaciones de red (en segundos)
            aggressive_scan: Si se deben utilizar técnicas de escaneo agresivas
        """
        self.max_workers = max_workers
        self.timeout = timeout
        self.aggressive_scan = aggressive_scan
        
        # Inicializar componentes
        self.nm = nmap.PortScanner()
        self.device_db = DeviceDatabase()
        self.signature_matcher = SignatureMatcher()
        
        # Listas de puertos comunes para escanear
        self.common_ports = [80, 443, 22, 23, 21, 25, 53, 111, 139, 445, 3389, 8080, 8443, 1883]
        self.iot_ports = [80, 443, 22, 23, 1883, 5683, 8883, 8080, 8088, 8888, 9999, 5000, 5001]
        self.media_ports = [80, 443, 554, 1900, 5000, 5001, 5353, 7000, 8000, 8008, 8009, 8080, 8443, 9080]
        
        # Lista de puertos a escanear según el tipo de escaneo
        if aggressive_scan:
            # Escaneo agresivo: más puertos
            self.scan_ports = list(set(self.common_ports + self.iot_ports + self.media_ports))
        else:
            # Escaneo normal: menos puertos para mejor rendimiento
            self.scan_ports = self.common_ports

        # Convertir a formato de nmap
        self.nmap_ports = ",".join([str(port) for port in self.scan_ports])
        
        # Configurar HTTP headers para requests
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def _scan_ports_extensive(self, ip: str) -> Tuple[List[int], Dict]:
        """
        Escanea un rango más amplio de puertos en un dispositivo para escaneos detallados
        
        Args:
            ip: Dirección IP del dispositivo
            
        Returns:
            Tuple[List[int], Dict]: Lista de puertos abiertos y diccionario de servicios
        """
        try:
            # Usar nmap para escanear un rango más amplio de puertos
            # Incluye los 1000 puertos más comunes y detección de versiones
            result = self.nm.scan(
                hosts=ip, 
                arguments="-p 1-1000 -sV -T4 --max-retries=2 --host-timeout=60s"
            )
            
            # Extraer puertos abiertos y servicios
            open_ports = []
            service_details = {}
            
            if ip in result['scan'] and 'tcp' in result['scan'][ip]:
                for port, data in result['scan'][ip]['tcp'].items():
                    if data['state'] == 'open':
                        port_num = int(port)
                        open_ports.append(port_num)
                        
                        # Extraer información de servicio
                        service_name = data.get('name', '')
                        product = data.get('product', '')
                        version = data.get('version', '')
                        extrainfo = data.get('extrainfo', '')
                        
                        service_details[port_num] = {
                            'name': service_name,
                            'product': product,
                            'version': version,
                            'extrainfo': extrainfo
                        }
            
            return open_ports, service_details
        except Exception as e:
            logger.debug(f"Error escaneando puertos extensivamente para {ip}: {e}")
        
        return [], {}
    

    def _get_service_name(self, port: int) -> Optional[str]:
        """
        Determina el nombre del servicio basado en el puerto
        
        Args:
            port: Número de puerto
            
        Returns:
            Optional[str]: Nombre del servicio o None si no se reconoce
        """
        common_services = {
            21: 'ftp', 
            22: 'ssh', 
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            111: 'rpcbind',
            135: 'msrpc',
            139: 'netbios-ssn',
            143: 'imap',
            443: 'https',
            445: 'microsoft-ds',
            993: 'imaps',
            995: 'pop3s',
            1883: 'mqtt',
            3306: 'mysql',
            3389: 'ms-wbt-server',
            5432: 'postgresql',
            8080: 'http-proxy',
            8443: 'https-alt'
        }
        
        return common_services.get(port, None)

    def fingerprint_device(self, ip: str, mac: str = None, basic_info: Dict = None, detailed_scan: bool = False) -> Dict:
        """
        Realiza un fingerprinting completo de un dispositivo
        
        Args:
            ip: Dirección IP del dispositivo
            mac: Dirección MAC del dispositivo (opcional)
            basic_info: Información básica ya conocida del dispositivo (opcional)
            detailed_scan: Si es True, realiza un escaneo más detallado y agresivo (para escaneos individuales)
            
        Returns:
            Dict: Información completa del dispositivo
        """
        # Si no tenemos MAC, obtenerla
        if not mac:
            mac = self._get_mac_address(ip)
        
        # Inicializar datos del dispositivo
        device_data = {
            'ip': ip,
            'mac': mac,
            'hostname': '',
            'vendor': '',
            'vendor_details': '',
            'device_type': '',
            'model': '',
            'os': '',
            'open_ports': [],
            'last_seen': time.time(),
            'status': 'activo',
            'blocked': False
        }
        
        # Actualizar con información básica si se proporciona
        if basic_info:
            device_data.update(basic_info)
        
        # Buscar en la base de datos si ya conocemos este dispositivo
        known_device = self.device_db.get_known_device(ip=ip)
        # Para escaneos detallados, siempre realizar un nuevo escaneo completo
        if known_device and not detailed_scan:
            # Si encontramos el dispositivo en la base de datos y es reciente,
            # usar esos datos y evitar un nuevo escaneo
            last_seen_diff = time.time() - known_device.get('last_seen', 0)
            if last_seen_diff < 3600:  # 1 hora
                logger.info(f"Dispositivo {ip} encontrado en caché (hace {int(last_seen_diff/60)} minutos)")
                return known_device
            else:
                # Si los datos son antiguos, hacer un nuevo escaneo pero preservar algunos campos
                for field in ['vendor', 'vendor_details', 'device_type', 'model', 'os']:
                    if field in known_device and known_device[field]:
                        device_data[field] = known_device[field]
        
        # Ajustar tiempos de espera para escaneos detallados
        effective_timeout = self.timeout * 3 if detailed_scan else self.timeout
        
        # Realizar fingerprinting utilizando múltiples técnicas en paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Iniciar tareas en paralelo
            hostname_future = executor.submit(self._get_hostname, ip)
            vendor_future = executor.submit(self._get_vendor_info, mac)
            
            # Para escaneos detallados, usar un método diferente con más puertos
            if detailed_scan:
                ports_scan_future = executor.submit(self._scan_ports_extensive, ip)
            else:
                ports_scan_future = executor.submit(self._scan_ports, ip)
            
            os_scan_future = executor.submit(self._get_os_info, ip, detailed_scan)
            http_scan_future = executor.submit(self._get_http_info, ip)
            
            # Recopilar resultados a medida que estén disponibles
            try:
                hostname = hostname_future.result(timeout=effective_timeout)
                if hostname:
                    device_data['hostname'] = hostname
            except (concurrent.futures.TimeoutError, Exception) as e:
                logger.debug(f"Error obteniendo hostname para {ip}: {e}")
            
            try:
                vendor_short, vendor_details = vendor_future.result(timeout=effective_timeout)
                if vendor_short != "Desconocido":
                    device_data['vendor'] = vendor_short
                    device_data['vendor_details'] = vendor_details
            except (concurrent.futures.TimeoutError, Exception) as e:
                logger.debug(f"Error obteniendo información de fabricante para {mac}: {e}")
            
            try:
                if detailed_scan:
                    open_ports, service_details = ports_scan_future.result(timeout=effective_timeout * 2)
                    if open_ports:
                        device_data['open_ports'] = open_ports
                    if service_details:
                        device_data['service_details'] = service_details
                else:
                    open_ports = ports_scan_future.result(timeout=effective_timeout * 2)
                    if open_ports:
                        device_data['open_ports'] = open_ports
            except (concurrent.futures.TimeoutError, Exception) as e:
                logger.debug(f"Error escaneando puertos para {ip}: {e}")
            
            try:
                os_info = os_scan_future.result(timeout=effective_timeout * 2)
                if os_info and os_info != "Desconocido":
                    device_data['os'] = os_info
            except (concurrent.futures.TimeoutError, Exception) as e:
                logger.debug(f"Error obteniendo información de OS para {ip}: {e}")
            
            try:
                http_info = http_scan_future.result(timeout=effective_timeout)
                if http_info:
                    device_data['http_signature'] = http_info
            except (concurrent.futures.TimeoutError, Exception) as e:
                logger.debug(f"Error obteniendo información HTTP para {ip}: {e}")
        
        # Solo para escaneos detallados, añadir escaneos adicionales de servicios
        if detailed_scan and 'open_ports' in device_data and device_data['open_ports'] and not 'service_details' in device_data:
            # Si no obtuvimos detalles de servicio del escaneo de puertos, intentar obtenerlos ahora
            service_details = {}
            for port in device_data['open_ports']:
                service_name = self._get_service_name(port)
                if service_name:
                    service_info = self._scan_service_specific(ip, port, service_name)
                    if service_info:
                        service_details[port] = {
                            'name': service_name,
                            'info': service_info
                        }
            
            if service_details:
                device_data['service_details'] = service_details
        
        # Buscar información adicional basada en el fabricante y MAC
        if mac:
            device_by_mac = self.device_db.get_device_by_mac_prefix(mac)
            if device_by_mac:
                if not device_data['vendor'] and 'vendor' in device_by_mac:
                    device_data['vendor'] = device_by_mac['vendor']
                
                if not device_data['device_type'] and 'device_type' in device_by_mac:
                    device_data['device_type'] = device_by_mac['device_type']
                    
                if not device_data['model'] and 'model' in device_by_mac:
                    device_data['model'] = device_by_mac['model']
        
        # Usar el matcher de firmas para identificar el dispositivo
        device_data = self.signature_matcher.identify_device(device_data)
        
        # Para escaneos detallados, intentar escanear puertos adicionales basados en el tipo de dispositivo
        if detailed_scan and 'open_ports' in device_data and device_data['open_ports']:
            additional_ports = self.scan_additional_ports(ip, device_data['open_ports'])
            device_data['open_ports'] = additional_ports
        
        # Guardar la información del dispositivo en la base de datos
        self.device_db.save_device_identification(device_data)
        
        # Añadir timestamp para indicar cuándo se realizó este escaneo detallado
        if detailed_scan:
            device_data['detailed_scan_time'] = time.time()
        
        return device_data
    
    def fingerprint_devices_batch(self, devices_info: List[Dict], 
                                  on_device_done: Optional[Callable[[Dict], None]] = None) -> List[Dict]:
        """
        Realiza fingerprinting en lote para múltiples dispositivos
        
        Args:
            devices_info: Lista de diccionarios con información básica (ip, mac)
            on_device_done: Callback llamado cuando se completa un dispositivo (opcional)
            
        Returns:
            List[Dict]: Lista de información de dispositivos
        """
        results = []
        
        # Fingerprinting en paralelo con limitación de concurrencia
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Enviar todas las tareas
            future_to_device = {
                executor.submit(self.fingerprint_device, device['ip'], device.get('mac'), device): device
                for device in devices_info
            }
            
            # Procesar resultados a medida que estén disponibles
            for future in concurrent.futures.as_completed(future_to_device):
                device_info = future_to_device[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Llamar al callback si está definido
                    if on_device_done:
                        on_device_done(result)
                        
                except Exception as e:
                    logger.error(f"Error en fingerprint para {device_info['ip']}: {e}")
                    # Incluir información básica al menos
                    results.append(device_info)
                    
                    if on_device_done:
                        on_device_done(device_info)
        
        return results
    
    def estimate_device_type(self, ip: str, mac: str = None, open_ports: List[int] = None) -> str:
        """
        Estima rápidamente el tipo de dispositivo sin hacer un fingerprinting completo
        
        Args:
            ip: Dirección IP del dispositivo
            mac: Dirección MAC (opcional)
            open_ports: Lista de puertos abiertos conocidos (opcional)
            
        Returns:
            str: Tipo de dispositivo estimado
        """
        device_data = {'ip': ip}
        
        if mac:
            device_data['mac'] = mac
            # Intentar identificar por MAC vendor
            vendor_short, _ = self.device_db.get_vendor_info(mac)
            if vendor_short != "Desconocido":
                device_data['vendor'] = vendor_short
            
            # Buscar en base de datos de dispositivos MAC
            device_by_mac = self.device_db.get_device_by_mac_prefix(mac)
            if device_by_mac and 'device_type' in device_by_mac:
                return device_by_mac['device_type']
        
        # Si tenemos puertos abiertos, usar para estimar
        if open_ports:
            device_data['open_ports'] = open_ports
            device_types = self.signature_matcher.match_device_type(device_data)
            if device_types and device_types[0][0] != "Desconocido":
                return device_types[0][0]
        
        return "Desconocido"
    
    def _get_mac_address(self, ip: str) -> Optional[str]:
        """Obtiene la dirección MAC de un dispositivo dada su IP"""
        try:
            # Usar ARP para obtener la MAC
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            
            # Enviar paquete y esperar respuesta
            response = srp(packet, timeout=self.timeout, verbose=0, retry=2)
            
            # Extraer MAC de la respuesta
            if response and response[0]:
                return response[0][0][1].hwsrc
        except Exception as e:
            logger.debug(f"Error al obtener MAC para {ip}: {e}")
        
        return None
    
    def _get_hostname(self, ip: str) -> str:
        """Obtiene el nombre de host de un dispositivo"""
        try:
            # Intentar resolver mediante DNS inverso
            hostname = socket.getfqdn(ip)
            if hostname != ip:  # A veces getfqdn devuelve la IP si no hay nombre
                return hostname
            
            # Intentar además con gethostbyaddr
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                return hostname
            except:
                pass
            
            # Si llegamos aquí, no pudimos resolver el nombre
            return ""
        except Exception as e:
            logger.debug(f"Error al obtener hostname para {ip}: {e}")
            return ""
    
    def _get_vendor_info(self, mac: str) -> Tuple[str, str]:
        """Obtiene información del fabricante a partir de la dirección MAC"""
        if not mac:
            return ("Desconocido", "Desconocido")
        
        try:
            # Usar la base de datos para consultar el fabricante
            return self.device_db.get_vendor_info(mac)
        except Exception as e:
            logger.debug(f"Error al obtener información de fabricante para {mac}: {e}")
            return ("Desconocido", "Desconocido")
    
    def _scan_ports(self, ip: str) -> List[int]:
        """Escanea los puertos abiertos en un dispositivo"""
        try:
            # Usar nmap para escanear puertos
            result = self.nm.scan(
                hosts=ip, 
                arguments=f"-p {self.nmap_ports} -T4 --min-rate=1000 --max-retries=1 --host-timeout={self.timeout * 1000}"
            )
            
            # Extraer puertos abiertos
            if ip in result['scan'] and 'tcp' in result['scan'][ip]:
                return [
                    port for port, data in result['scan'][ip]['tcp'].items() 
                    if data['state'] == 'open'
                ]
        except Exception as e:
            logger.debug(f"Error escaneando puertos para {ip}: {e}")
        
        return []
    
    def _get_os_info(self, ip: str, detailed: bool = False) -> str:
        """
        Obtiene información del sistema operativo
        
        Args:
            ip: Dirección IP del dispositivo
            detailed: Si es True, realiza un escaneo más detallado
        
        Returns:
            str: Nombre del sistema operativo o "Desconocido"
        """
        try:
            # Usar nmap para detección de OS
            # Nota: esto requiere privilegios de administrador/root
            arguments = "-O"
            
            if detailed:
                # Configuración más exhaustiva para escaneos detallados
                arguments += " --osscan-guess --max-os-tries=3"
            else:
                arguments += " --osscan-limit --max-os-tries=1"
                
            arguments += f" --host-timeout={self.timeout * (3 if detailed else 1.5) * 1000}ms"
            
            result = self.nm.scan(
                hosts=ip, 
                arguments=arguments
            )
            
            # Extraer información de OS si está disponible
            if (ip in result['scan'] and 
                'osmatch' in result['scan'][ip] and 
                result['scan'][ip]['osmatch']):
                
                # Obtener el mejor match
                os_match = result['scan'][ip]['osmatch'][0]
                os_name = os_match['name']
                accuracy = os_match.get('accuracy', '')
                
                if detailed and accuracy:
                    os_name = f"{os_name} (Precisión: {accuracy}%)"
                
                # Limpiar la cadena de OS para hacerla más legible
                # Eliminar información de versión muy específica
                os_name = re.sub(r'Microsoft Windows .* or ', 'Microsoft Windows ', os_name)
                os_name = re.sub(r' \(build .*\)', '', os_name)
                os_name = re.sub(r' SP\d+', '', os_name)
                
                return os_name
        except Exception as e:
            logger.debug(f"Error al obtener información de OS para {ip}: {e}")
        
        return "Desconocido"

    def _get_http_info(self, ip: str) -> Optional[str]:
        """Obtiene información de servicios HTTP/HTTPS para fingerprinting"""
        http_info = []
        
        # Probar conexiones HTTP y HTTPS
        for protocol, port in [('http', 80), ('https', 443), ('http', 8080)]:
            try:
                url = f"{protocol}://{ip}:{port}"
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    timeout=self.timeout,
                    verify=False  # Ignorar certificados SSL inválidos
                )
                
                # Extraer headers importantes para fingerprinting
                important_headers = ['Server', 'X-Powered-By', 'Set-Cookie']
                header_info = []
                
                for header in important_headers:
                    if header in response.headers:
                        header_info.append(f"{header}: {response.headers[header]}")
                
                # Extraer título e información del body
                title = None
                title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                if title_match:
                    title = title_match.group(1)
                
                # Recopilar información
                if title:
                    http_info.append(f"Title: {title}")
                if header_info:
                    http_info.append(", ".join(header_info))
                
                # Si obtuvimos información, no necesitamos probar más puertos
                if http_info:
                    break
                    
            except requests.exceptions.RequestException:
                # Ignorar errores de conexión
                pass
        
        # Devolver información recopilada
        if http_info:
            return "; ".join(http_info)
        else:
            return None
    
    def _scan_service_specific(self, ip: str, port: int, service_name: str) -> Optional[str]:
        """
        Escanea un servicio específico para obtener información detallada
        
        Args:
            ip: Dirección IP del dispositivo
            port: Puerto del servicio
            service_name: Nombre del servicio (ssh, http, rtsp, etc.)
            
        Returns:
            Optional[str]: Información del servicio o None si no se pudo obtener
        """
        try:
            # Usar nmap para escaneo de servicio avanzado con scripts
            script_args = ""
            
            # Seleccionar script según el servicio
            if service_name == 'ssh':
                script_args = "--script=ssh-auth-methods,ssh-hostkey,ssh-server-info"
            elif service_name in ['http', 'https']:
                script_args = "--script=http-title,http-server-header,http-generator"
            elif service_name == 'rtsp':
                script_args = "--script=rtsp-methods"
            elif service_name == 'upnp':
                script_args = "--script=upnp-info"
            elif service_name == 'snmp':
                script_args = "--script=snmp-info"
            elif service_name == 'mdns':
                script_args = "--script=dns-service-discovery"
            else:
                # Para otros servicios, usar banner grabbing genérico
                script_args = "--script=banner"
            
            # Solo realizar el escaneo si tenemos scripts apropiados
            if script_args:
                result = self.nm.scan(
                    hosts=ip, 
                    ports=str(port), 
                    arguments=f"-sV {script_args} --host-timeout={self.timeout * 1000}"
                )
                
                # Extraer información de scripts
                if (ip in result['scan'] and 
                    'tcp' in result['scan'][ip] and 
                    port in result['scan'][ip]['tcp'] and
                    'script' in result['scan'][ip]['tcp'][port]):
                    
                    script_output = []
                    for script_name, output in result['scan'][ip]['tcp'][port]['script'].items():
                        script_output.append(f"{script_name}: {output}")
                    
                    return "; ".join(script_output)
        except Exception as e:
            logger.debug(f"Error en escaneo de servicio {service_name}:{port} para {ip}: {e}")
        
        return None
    
    def _get_device_model_from_banners(self, ip: str, ports: List[int]) -> Optional[str]:
        """
        Intenta obtener el modelo del dispositivo a partir de banners de servicios
        
        Args:
            ip: Dirección IP del dispositivo
            ports: Lista de puertos abiertos
            
        Returns:
            Optional[str]: Modelo del dispositivo o None si no se pudo determinar
        """
        # Patrones para extraer información de modelo
        model_patterns = [
            r'model[=:"\s]+([A-Za-z0-9\-\_\.\+\s]+?)[\s,">]',
            r'product[=:"\s]+([A-Za-z0-9\-\_\.\+\s]+?)[\s,">]',
            r'device[=:"\s]+([A-Za-z0-9\-\_\.\+\s]+?)[\s,">]'
        ]
        
        try:
            # Intentar obtener banners de servicios comunes
            for port in ports:
                # Determinar el servicio basado en el puerto
                service = ""
                if port == 22:
                    service = "ssh"
                elif port == 80 or port == 8080:
                    service = "http"
                elif port == 443 or port == 8443:
                    service = "https"
                elif port == 554:
                    service = "rtsp"
                elif port == 161:
                    service = "snmp"
                elif port == 1900:
                    service = "upnp"
                elif port == 5353:
                    service = "mdns"
                else:
                    continue  # Saltar puertos sin servicio conocido
                
                # Escanear el servicio
                banner = self._scan_service_specific(ip, port, service)
                
                if banner:
                    # Buscar patrones de modelo en el banner
                    for pattern in model_patterns:
                        match = re.search(pattern, banner, re.IGNORECASE)
                        if match:
                            return match.group(1).strip()
        except Exception as e:
            logger.debug(f"Error al obtener modelo desde banners para {ip}: {e}")
        
        return None
    
    def scan_additional_ports(self, ip: str, initial_ports: List[int]) -> List[int]:
        """
        Escanea puertos adicionales basados en el tipo de dispositivo detectado
        
        Args:
            ip: Dirección IP del dispositivo
            initial_ports: Puertos ya detectados como abiertos
            
        Returns:
            List[int]: Lista completa de puertos abiertos
        """
        try:
            # Estimar tipo de dispositivo basado en puertos iniciales
            device_type = self.estimate_device_type(ip, open_ports=initial_ports)
            
            # Determinar puertos adicionales según el tipo de dispositivo
            additional_ports = []
            
            if device_type in ["Router", "Gateway", "Access Point"]:
                additional_ports = [22, 23, 53, 67, 68, 80, 443, 1900, 5000, 8080, 8443]
            elif device_type in ["IP Camera", "Security Camera", "NVR", "DVR"]:
                additional_ports = [80, 443, 554, 8000, 8080, 8443, 9000, 9090, 37777]
            elif device_type in ["Smart TV", "Media Device", "Streaming Device"]:
                additional_ports = [80, 443, 554, 1900, 5000, 7000, 8008, 8009, 8060, 9080]
            elif device_type in ["IoT Device", "Smart Home Hub"]:
                additional_ports = [80, 443, 1883, 5683, 8080, 8888, 9999]
            elif device_type in ["Printer", "Scanner", "Network Printer"]:
                additional_ports = [80, 443, 515, 631, 9100]
            elif "Server" in device_type:
                additional_ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432]
            elif "Windows" in device_type:
                additional_ports = [135, 139, 445, 3389, 5985]
                
            # Si no hay puertos adicionales o si ya escaneamos muchos puertos, salir
            if not additional_ports or len(initial_ports) > 10:
                return initial_ports
                
            # Filtrar puertos que ya conocemos
            ports_to_scan = [p for p in additional_ports if p not in initial_ports]
            
            if not ports_to_scan:
                return initial_ports
                
            # Convertir a formato de nmap
            port_str = ",".join([str(port) for port in ports_to_scan])
            
            # Escaneo rápido de los puertos adicionales
            result = self.nm.scan(
                hosts=ip, 
                arguments=f"-p {port_str} -T4 --min-rate=1000 --max-retries=1 --host-timeout={self.timeout * 1000}"
            )
            
            # Extraer puertos abiertos adicionales
            additional_open_ports = []
            if ip in result['scan'] and 'tcp' in result['scan'][ip]:
                additional_open_ports = [
                    port for port, data in result['scan'][ip]['tcp'].items() 
                    if data['state'] == 'open'
                ]
            
            # Combinar con los puertos iniciales
            return sorted(list(set(initial_ports + additional_open_ports)))
            
        except Exception as e:
            logger.debug(f"Error al escanear puertos adicionales para {ip}: {e}")
            return initial_ports