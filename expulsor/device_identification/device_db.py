"""
Base de datos mejorada para identificación de dispositivos
"""

import os
import json
import time
import urllib.request
import re
import sqlite3
from pathlib import Path
from typing import Dict, Optional, Tuple


class DeviceDatabase:
    """Gestiona las bases de datos locales para identificación de dispositivos"""
    
    # Las URLs para descargar las diferentes bases de datos
    DB_URLS = {
        'oui': "https://standards-oui.ieee.org/oui/oui.csv",
        'mac_vendors': "https://www.wireshark.org/download/automated/data/manuf",
        'nmap_fingerprints': "https://svn.nmap.org/nmap/nmap-os-db",
    }
    
    def __init__(self, cache_dir: Optional[str] = None):
        """
        Inicializa la base de datos de dispositivos
        
        Args:
            cache_dir: Directorio para almacenar las bases de datos locales (opcional)
        """
        # Configurar directorio de caché
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path(os.path.expanduser("~/.expulsor/device_db"))
        
        # Crear directorio si no existe
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Inicializar las diferentes bases de datos
        self.oui_db = {}
        self.mac_vendors_db = {}
        self.device_models_db = {}
        self.fingerprints_db = {}
        
        # Inicializar base de datos SQLite para fingerprinting avanzado
        self.db_path = self.cache_dir / "device_fingerprints.db"
        self._init_sqlite_db()
        
        # Cargar bases de datos existentes o descargarlas si es necesario
        self._load_or_download_dbs()
    
    def _init_sqlite_db(self):
        """Inicializa la base de datos SQLite para fingerprinting avanzado"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Tabla de firmas de dispositivos
            cursor.execute('''
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
            )
            ''')
            
            # Tabla de dispositivos identificados previamente
            cursor.execute('''
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
                last_seen INTEGER,
                confidence REAL,
                fingerprint_id INTEGER,
                FOREIGN KEY (fingerprint_id) REFERENCES device_signatures (id)
            )
            ''')
            
            # Índices para búsqueda rápida
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_mac_prefix ON device_signatures (mac_prefix)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_mac ON identified_devices (mac)')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error inicializando la base de datos SQLite: {e}")
    
    def _load_or_download_dbs(self):
        """Carga las bases de datos locales o las descarga si no existen o están desactualizadas"""
        # Comprobar y cargar/descargar cada base de datos
        self._load_or_download_oui_db()
        self._load_or_download_mac_vendors_db()
        self._load_or_download_fingerprints_db()
        self._load_device_models_db()
    
    def _load_or_download_oui_db(self):
        """Carga o descarga la base de datos OUI de IEEE"""
        oui_path = self.cache_dir / "oui_database.json"
        
        # Comprobar si la base de datos existe y no está desactualizada
        if oui_path.exists():
            # Si la base de datos tiene más de 30 días, la actualizamos
            if time.time() - oui_path.stat().st_mtime > 30 * 24 * 60 * 60:
                self._download_oui_database()
            else:
                # Cargar la base de datos existente
                try:
                    with open(oui_path, 'r') as f:
                        self.oui_db = json.load(f)
                except Exception as e:
                    print(f"Error cargando la base de datos OUI: {e}")
                    self._download_oui_database()
        else:
            # Descargar si no existe
            self._download_oui_database()
    
    def _download_oui_database(self):
        """Descarga la base de datos OUI desde el registro IEEE"""
        try:
            oui_path = self.cache_dir / "oui_database.json"
            url = self.DB_URLS['oui']
            
            print(f"Descargando base de datos OUI desde {url}...")
            response = urllib.request.urlopen(url, timeout=10)
            
            if response.getcode() == 200:
                # Procesar el CSV y convertirlo a un diccionario
                content = response.read().decode('utf-8')
                lines = content.splitlines()
                oui_dict = {}
                
                for line in lines[1:]:  # Saltamos la cabecera
                    parts = line.split(',')
                    if len(parts) >= 3:
                        mac_prefix = parts[1].strip('"').replace('-', ':').lower()
                        company = parts[2].strip('"')
                        if mac_prefix and company:
                            oui_dict[mac_prefix] = company
                
                # Guardar en un archivo JSON
                with open(oui_path, 'w') as f:
                    json.dump(oui_dict, f)
                
                self.oui_db = oui_dict
                print(f"Base de datos OUI descargada: {len(oui_dict)} registros")
            else:
                print(f"Error al descargar la base de datos OUI: {response.getcode()}")
                
                # Crear un diccionario vacío si falla la descarga
                self.oui_db = {}
                with open(oui_path, 'w') as f:
                    json.dump({}, f)
        
        except Exception as e:
            print(f"Error al descargar la base de datos OUI: {e}")
            # Crear un diccionario vacío si falla la descarga
            self.oui_db = {}
            with open(oui_path, 'w') as f:
                json.dump({}, f)
    
    def _load_or_download_mac_vendors_db(self):
        """Carga o descarga una base de datos alternativa de fabricantes MAC"""
        vendors_path = self.cache_dir / "mac_vendors.json"
        cache_path = self.cache_dir / "mac_vendor_cache.json"
        
        # Cargar la caché existente si existe
        if cache_path.exists():
            try:
                with open(cache_path, 'r') as f:
                    self.mac_vendors_db = json.load(f)
            except Exception as e:
                print(f"Error cargando la caché de fabricantes MAC: {e}")
                self.mac_vendors_db = {}
        
        # Comprobar si la base de datos principal existe y no está desactualizada
        if vendors_path.exists():
            # Si la base de datos tiene más de 60 días, la actualizamos
            if time.time() - vendors_path.stat().st_mtime > 60 * 24 * 60 * 60:
                self._download_mac_vendors()
            else:
                # Cargar la base de datos existente
                try:
                    with open(vendors_path, 'r') as f:
                        main_db = json.load(f)
                        # Combinar con la caché
                        self.mac_vendors_db.update(main_db)
                except Exception as e:
                    print(f"Error cargando la base de datos de fabricantes MAC: {e}")
        else:
            # Descargar si no existe
            self._download_mac_vendors()
    
    def _download_mac_vendors(self):
        """Descarga una base de datos de fabricantes MAC desde Wireshark"""
        try:
            vendors_path = self.cache_dir / "mac_vendors.json"
            url = self.DB_URLS['mac_vendors']
            
            print(f"Descargando base de datos de fabricantes MAC desde {url}...")
            
            # Este enfoque de descarga es más resistente a errores
            try:
                headers = {'User-Agent': 'Expulsor/1.0 (Network Security Tool)'}
                req = urllib.request.Request(url, headers=headers)
                response = urllib.request.urlopen(req, timeout=15)
                
                if response.getcode() == 200:
                    content = response.read().decode('utf-8', errors='ignore')
                    vendors_dict = {}
                    
                    # Procesar el formato de la base de datos de Wireshark
                    for line in content.splitlines():
                        if line and not line.startswith('#'):
                            parts = line.split('#')[0].strip().split('\t')
                            if len(parts) >= 2:
                                mac_prefix = parts[0].replace(':', '').lower()
                                # Convertir a formato XX:XX:XX si tiene la longitud adecuada
                                if len(mac_prefix) >= 6:
                                    formatted_prefix = ':'.join([mac_prefix[i:i+2] for i in range(0, 6, 2)]).lower()
                                    company = parts[1].strip()
                                    vendors_dict[formatted_prefix] = company
                    
                    # Guardar en un archivo JSON
                    with open(vendors_path, 'w') as f:
                        json.dump(vendors_dict, f)
                    
                    # Actualizar el diccionario en memoria
                    self.mac_vendors_db.update(vendors_dict)
                    print(f"Base de datos de fabricantes MAC descargada: {len(vendors_dict)} registros")
                else:
                    print(f"Error al descargar la base de datos de fabricantes MAC: {response.getcode()}")
                    # Intentar un método alternativo de descarga
                    self._download_alternate_mac_db()
            except Exception as e:
                print(f"Error en la descarga primaria: {e}")
                # Intentar un método alternativo de descarga
                self._download_alternate_mac_db()
        
        except Exception as e:
            print(f"Error general al descargar la base de datos de fabricantes MAC: {e}")
            self._download_alternate_mac_db()
    
    def _download_alternate_mac_db(self):
        """Descarga una fuente alternativa de información de fabricantes MAC"""
        try:
            # Usar la base de datos de IEEE OUI como respaldo
            alt_url = self.DB_URLS['oui']
            
            print(f"Intentando descarga alternativa desde {alt_url}...")
            response = urllib.request.urlopen(alt_url, timeout=15)
            
            if response.getcode() == 200:
                content = response.read().decode('utf-8')
                vendors_dict = {}
                
                # Procesar el CSV de IEEE OUI
                lines = content.splitlines()
                for line in lines[1:]:  # Saltamos la cabecera
                    parts = line.split(',')
                    if len(parts) >= 3:
                        mac_prefix = parts[1].strip('"').replace('-', ':').lower()
                        company = parts[2].strip('"')
                        if mac_prefix and company:
                            vendors_dict[mac_prefix] = company
                
                # Guardar en un archivo JSON
                vendors_path = self.cache_dir / "mac_vendors.json"
                with open(vendors_path, 'w') as f:
                    json.dump(vendors_dict, f)
                
                # Actualizar el diccionario en memoria
                self.mac_vendors_db.update(vendors_dict)
                print(f"Base de datos alternativa de fabricantes MAC descargada: {len(vendors_dict)} registros")
                return
        except Exception as e:
            print(f"Error al descargar la base de datos alternativa de fabricantes MAC: {e}")
        
        # Si llegamos aquí, ambos métodos fallaron. Usar una base de datos mínima incorporada
        try:
            print("Usando base de datos de fabricantes incorporada como último recurso...")
            min_vendors = {
                "00:00:0c": "Cisco Systems",
                "00:1a:11": "Google, Inc.",
                "00:04:96": "Extreme Networks",
                "b8:27:eb": "Raspberry Pi Foundation",
                "00:0c:29": "VMware, Inc.",
                "18:fe:34": "Apple, Inc.",
                "d4:3d:7e": "Apple, Inc.",
                "28:cf:da": "Apple, Inc.",
                "00:50:56": "VMware, Inc.",
                "00:1d:7e": "Cisco-Linksys, LLC",
                "00:25:9c": "Cisco-Linksys, LLC",
                "cc:16:7e": "Cisco Systems",
                "e8:40:f2": "Pegatron Corporation",
                "00:15:5d": "Microsoft Corporation",
                "00:17:fa": "Microsoft Corporation",
                "00:08:74": "Dell Inc.",
                "a4:ba:db": "Dell Inc.",
                "00:13:a9": "Sony Corporation",
                "00:26:b0": "Apple, Inc.",
                "78:dd:08": "Hon Hai Precision Ind. Co.,Ltd.",
                "00:11:32": "Synology Incorporated",
                "00:11:33": "QNAP Systems, Inc.",
                "10:7b:ef": "Zyxel Communications Corp.",
                "00:90:4c": "Epson",
                "00:68:eb": "HP Inc.",
                "00:18:fe": "Hewlett Packard",
                "24:be:05": "Hewlett Packard",
            }
            
            # Guardar esta pequeña base de datos
            vendors_path = self.cache_dir / "mac_vendors.json"
            with open(vendors_path, 'w') as f:
                json.dump(min_vendors, f)
            
            # Actualizar el diccionario en memoria
            self.mac_vendors_db.update(min_vendors)
            print(f"Base de datos mínima incorporada cargada: {len(min_vendors)} registros")
        except Exception as e:
            print(f"Error al cargar la base de datos mínima incorporada: {e}")
            # En este punto, simplemente tendremos un diccionario vacío
            self.mac_vendors_db = {}
    
    def _load_or_download_fingerprints_db(self):
        """Carga o descarga la base de datos de fingerprints de Nmap"""
        fingerprints_path = self.cache_dir / "nmap_fingerprints.txt"
        parsed_path = self.cache_dir / "parsed_fingerprints.json"
        
        # Si existe la versión parseada, la cargamos
        if parsed_path.exists():
            try:
                with open(parsed_path, 'r') as f:
                    self.fingerprints_db = json.load(f)
                return
            except Exception as e:
                print(f"Error cargando la base de datos de fingerprints: {e}")
        
        # Comprobar si la base de datos existe y no está desactualizada
        if fingerprints_path.exists():
            # Si la base de datos tiene más de 90 días, la actualizamos
            if time.time() - fingerprints_path.stat().st_mtime > 90 * 24 * 60 * 60:
                self._download_fingerprints_db()
            else:
                # Parsear la base de datos existente
                self._parse_fingerprints_db(fingerprints_path, parsed_path)
        else:
            # Descargar si no existe
            self._download_fingerprints_db()
    
    def _download_fingerprints_db(self):
        """Descarga la base de datos de fingerprints de Nmap"""
        try:
            fingerprints_path = self.cache_dir / "nmap_fingerprints.txt"
            parsed_path = self.cache_dir / "parsed_fingerprints.json"
            url = self.DB_URLS['nmap_fingerprints']
            
            print(f"Descargando base de datos de fingerprints desde {url}...")
            
            # Intentar la descarga
            try:
                headers = {'User-Agent': 'Expulsor/1.0 (Network Security Tool)'}
                req = urllib.request.Request(url, headers=headers)
                response = urllib.request.urlopen(req, timeout=15)
                
                if response.getcode() == 200:
                    content = response.read().decode('utf-8', errors='ignore')
                    
                    # Guardar el archivo original
                    with open(fingerprints_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    # Parsear la base de datos
                    self._parse_fingerprints_db(fingerprints_path, parsed_path)
                    print("Base de datos de fingerprints descargada y parseada correctamente")
                else:
                    print(f"Error al descargar la base de datos de fingerprints: {response.getcode()}")
            except Exception as e:
                print(f"Error en la descarga de fingerprints: {e}")
                # Intentar cargar una versión existente si está disponible
                if fingerprints_path.exists():
                    self._parse_fingerprints_db(fingerprints_path, parsed_path)
        except Exception as e:
            print(f"Error general al descargar la base de datos de fingerprints: {e}")
            # Intentar cargar una versión existente si está disponible
            if fingerprints_path.exists():
                self._parse_fingerprints_db(fingerprints_path, parsed_path)
    
    def _parse_fingerprints_db(self, fingerprints_path: Path, parsed_path: Path):
        """Parsea la base de datos de fingerprints de Nmap"""
        try:
            # Estructura para guardar los fingerprints parseados
            parsed_db = {
                'os_fingerprints': [],
                'service_fingerprints': [],
                'device_signatures': []
            }
            
            # Leer el archivo de fingerprints
            with open(fingerprints_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parsear fingerprints de OS
            # Esto es una versión simplificada, el parsing real sería más complejo
            os_pattern = r'Fingerprint\s+([^\n]+)\n((?:.+\n)+?)(?=Fingerprint|\Z)'
            for match in re.finditer(os_pattern, content):
                os_name = match.group(1).strip()
                fingerprint_data = match.group(2).strip()
                
                # Extraer información de dispositivos cuando está disponible
                device_info = {
                    'os': os_name,
                    'device_type': '',
                    'vendor': '',
                    'model': ''
                }
                
                # Buscar información de clase de dispositivo
                class_match = re.search(r'Class\s+([^\n]+)', fingerprint_data)
                if class_match:
                    classes = class_match.group(1).strip()
                    if 'router' in classes.lower():
                        device_info['device_type'] = 'Router'
                    elif 'switch' in classes.lower():
                        device_info['device_type'] = 'Switch'
                    elif 'printer' in classes.lower():
                        device_info['device_type'] = 'Printer'
                    elif 'firewall' in classes.lower():
                        device_info['device_type'] = 'Firewall'
                    elif 'wap' in classes.lower() or 'access point' in classes.lower():
                        device_info['device_type'] = 'Access Point'
                    elif 'phone' in classes.lower():
                        device_info['device_type'] = 'Phone'
                    elif 'game' in classes.lower():
                        device_info['device_type'] = 'Gaming Console'
                
                # Buscar información de fabricante
                vendor_matches = re.findall(r'\b(Apple|Cisco|HP|Samsung|Sony|Dell|Lenovo|Asus|Huawei|TP-Link|D-Link|Netgear|Microsoft|Nintendo|Ubiquiti)\b', os_name, re.IGNORECASE)
                if vendor_matches:
                    device_info['vendor'] = vendor_matches[0]
                
                # Añadir a la base de datos parseada
                parsed_db['os_fingerprints'].append({
                    'name': os_name,
                    'fingerprint': fingerprint_data,
                    'device_info': device_info
                })
            
            # Guardar la versión parseada
            with open(parsed_path, 'w') as f:
                json.dump(parsed_db, f)
            
            # Actualizar la base de datos en memoria
            self.fingerprints_db = parsed_db
            print(f"Base de datos de fingerprints parseada: {len(parsed_db['os_fingerprints'])} registros de OS")
        except Exception as e:
            print(f"Error al parsear la base de datos de fingerprints: {e}")
            self.fingerprints_db = {'os_fingerprints': [], 'service_fingerprints': [], 'device_signatures': []}
    
    def _load_device_models_db(self):
        """Carga base de datos interna de modelos de dispositivos"""
        models_path = self.cache_dir / "device_models.json"
        
        # Si la base de datos existe, la cargamos
        if models_path.exists():
            try:
                with open(models_path, 'r') as f:
                    self.device_models_db = json.load(f)
            except Exception as e:
                print(f"Error cargando la base de datos de modelos de dispositivos: {e}")
                self._init_device_models_db(models_path)
        else:
            # Inicializar base de datos interna
            self._init_device_models_db(models_path)
    
    def _init_device_models_db(self, models_path: Path):
        """Inicializa la base de datos interna de modelos de dispositivos"""
        # Base de datos mejorada de dispositivos por MAC
        models_db = {
            # Apple devices
            "a8:66:7f": {"vendor": "Apple", "device_type": "iPhone", "model": "iPhone 14"},
            "a8:bb:cf": {"vendor": "Apple", "device_type": "iPhone", "model": "iPhone 13"},
            "f0:18:98": {"vendor": "Apple", "device_type": "iPhone", "model": "iPhone 12"},
            "8c:85:90": {"vendor": "Apple", "device_type": "iPhone", "model": "iPhone 11"},
            "3c:22:fb": {"vendor": "Apple", "device_type": "MacBook", "model": "MacBook Pro"},
            "a4:83:e7": {"vendor": "Apple", "device_type": "MacBook", "model": "MacBook Air"},
            "a8:5c:2c": {"vendor": "Apple", "device_type": "iPad", "model": "iPad Pro"},
            "00:cd:fe": {"vendor": "Apple", "device_type": "Apple TV", "model": "Apple TV 4K"},
            "90:6c:ac": {"vendor": "Apple", "device_type": "Apple TV", "model": "Apple TV HD"},
            
            # Samsung devices
            "b0:72:bf": {"vendor": "Samsung", "device_type": "Smart TV", "model": "Samsung Smart TV"},
            "94:63:d1": {"vendor": "Samsung", "device_type": "Smartphone", "model": "Galaxy S22"},
            "bc:d1:d3": {"vendor": "Samsung", "device_type": "Smartphone", "model": "Galaxy S21"},
            "e8:c7:94": {"vendor": "Samsung", "device_type": "Smartphone", "model": "Galaxy S20"},
            "98:0c:82": {"vendor": "Samsung", "device_type": "Smartphone", "model": "Galaxy Note"},
            
            # Google devices
            "54:60:09": {"vendor": "Google", "device_type": "Chromecast", "model": "Chromecast Ultra"},
            "6c:ad:f8": {"vendor": "Google", "device_type": "Chromecast", "model": "Chromecast"},
            "f4:f5:d8": {"vendor": "Google", "device_type": "Nest", "model": "Nest Hub"},
            "20:df:b9": {"vendor": "Google", "device_type": "Nest", "model": "Nest Thermostat"},
            
            # Amazon devices
            "68:37:e9": {"vendor": "Amazon", "device_type": "Echo", "model": "Echo Dot"},
            "fc:65:de": {"vendor": "Amazon", "device_type": "Echo", "model": "Echo Show"},
            "b0:fc:0d": {"vendor": "Amazon", "device_type": "Fire TV", "model": "Fire TV Stick"},
            
            # Sony devices
            "7c:6d:62": {"vendor": "Sony", "device_type": "PlayStation", "model": "PlayStation 5"},
            "00:1d:0d": {"vendor": "Sony", "device_type": "PlayStation", "model": "PlayStation 4"},
            "bc:60:a7": {"vendor": "Sony", "device_type": "Smart TV", "model": "Sony Bravia TV"},
            
            # Microsoft devices
            "c8:e1:7d": {"vendor": "Microsoft", "device_type": "Xbox", "model": "Xbox Series X"},
            "58:82:a8": {"vendor": "Microsoft", "device_type": "Xbox", "model": "Xbox One"},
            "bc:83:85": {"vendor": "Microsoft", "device_type": "Surface", "model": "Surface Pro"},
            
            # Routers and networking
            "e8:de:27": {"vendor": "TP-Link", "device_type": "Router", "model": "Archer C7"},
            "d8:0d:17": {"vendor": "TP-Link", "device_type": "Router", "model": "Archer A7"},
            "24:a4:3c": {"vendor": "Ubiquiti", "device_type": "Access Point", "model": "UniFi AP"},
            "fc:ec:da": {"vendor": "Ubiquiti", "device_type": "Access Point", "model": "UniFi AP AC"},
            "04:18:d6": {"vendor": "Ubiquiti", "device_type": "Router", "model": "EdgeRouter"},
            "b0:b9:8a": {"vendor": "Netgear", "device_type": "Router", "model": "Nighthawk"},
            "8c:3b:ad": {"vendor": "Netgear", "device_type": "Router", "model": "Orbi"},
            "10:7b:ef": {"vendor": "Netgear", "device_type": "Switch", "model": "Smart Switch"},
            "14:91:82": {"vendor": "D-Link", "device_type": "Router", "model": "DIR Series"},
            "00:50:99": {"vendor": "3Com", "device_type": "Switch", "model": "3Com Switch"},
            "00:1e:c9": {"vendor": "Dell", "device_type": "Switch", "model": "PowerConnect"},
            
            # IoT and smart home
            "24:fd:52": {"vendor": "Philips", "device_type": "Smart Lighting", "model": "Hue Bridge"},
            "ec:b5:fa": {"vendor": "Philips", "device_type": "Smart Lighting", "model": "Hue Light"},
            "d0:52:a8": {"vendor": "Sonos", "device_type": "Speaker", "model": "Sonos One"},
            "00:04:20": {"vendor": "Sonos", "device_type": "Speaker", "model": "Sonos Play"},
            "00:57:d2": {"vendor": "Ring", "device_type": "Doorbell", "model": "Ring Doorbell"},
            "60:ee:a8": {"vendor": "Xiaomi", "device_type": "IoT Gateway", "model": "Mi Smart Home"},
            
            # Printers
            "68:b5:99": {"vendor": "HP", "device_type": "Printer", "model": "LaserJet Pro"},
            "00:17:a4": {"vendor": "HP", "device_type": "Printer", "model": "OfficeJet Pro"},
            "30:85:a9": {"vendor": "Brother", "device_type": "Printer", "model": "Brother Laser"},
            "a4:17:31": {"vendor": "Canon", "device_type": "Printer", "model": "PIXMA"},
            "00:26:ab": {"vendor": "Epson", "device_type": "Printer", "model": "EcoTank"},
            
            # PCs and laptops
            "24:ee:9a": {"vendor": "Dell", "device_type": "PC", "model": "OptiPlex"},
            "b8:ca:3a": {"vendor": "Dell", "device_type": "Laptop", "model": "XPS"},
            "f8:bc:12": {"vendor": "Dell", "device_type": "Laptop", "model": "Latitude"},
            "04:7b:cb": {"vendor": "Lenovo", "device_type": "Laptop", "model": "ThinkPad"},
            "50:7b:9d": {"vendor": "Lenovo", "device_type": "PC", "model": "ThinkCentre"},
            "e0:d5:5e": {"vendor": "Lenovo", "device_type": "Laptop", "model": "Legion"},
            "70:5a:b6": {"vendor": "ASUS", "device_type": "Laptop", "model": "ZenBook"},
            "38:d5:47": {"vendor": "ASUS", "device_type": "Laptop", "model": "ROG"},
            
            # Smart TVs
            "c8:d3:ff": {"vendor": "LG", "device_type": "Smart TV", "model": "LG WebOS TV"},
            "a4:ab:65": {"vendor": "Vizio", "device_type": "Smart TV", "model": "Vizio SmartCast"},
            "08:70:45": {"vendor": "TCL", "device_type": "Smart TV", "model": "TCL Roku TV"},
            "00:23:7d": {"vendor": "Roku", "device_type": "Streaming Device", "model": "Roku Ultra"},
            
            # IP Cameras
            "b2:8b:af": {"vendor": "Hikvision", "device_type": "IP Camera", "model": "Hikvision Camera"},
            "c4:11:e0": {"vendor": "Dahua", "device_type": "IP Camera", "model": "Dahua Camera"},
            "00:09:07": {"vendor": "Axis", "device_type": "IP Camera", "model": "Axis Network Camera"},
            "78:97:c3": {"vendor": "Reolink", "device_type": "IP Camera", "model": "Reolink Camera"}
        }
        
        # Guardar la base de datos
        try:
            with open(models_path, 'w') as f:
                json.dump(models_db, f)
            
            self.device_models_db = models_db
            print(f"Base de datos de modelos de dispositivos inicializada: {len(models_db)} registros")
        except Exception as e:
            print(f"Error al inicializar la base de datos de modelos de dispositivos: {e}")
            self.device_models_db = {}
    
    def save_vendor_to_cache(self, mac: str, vendor_info: Tuple[str, str]):
        """
        Guarda la información de un fabricante en la caché
        
        Args:
            mac: Dirección MAC completa
            vendor_info: Tupla (vendor_short, vendor_details)
        """
        try:
            cache_path = self.cache_dir / "mac_vendor_cache.json"
            
            # Cargar la caché existente
            cache_data = {}
            if cache_path.exists():
                try:
                    with open(cache_path, 'r') as f:
                        cache_data = json.load(f)
                except:
                    cache_data = {}
            
            # Añadir el nuevo registro
            cache_data[mac.lower()] = vendor_info
            
            # Guardar la caché actualizada
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f)
                
            # Actualizar la caché en memoria
            self.mac_vendors_db[mac.lower()] = vendor_info
        except Exception as e:
            print(f"Error al guardar información de fabricante en caché: {e}")
    
    def save_device_identification(self, device_data: Dict):
        """
        Guarda la información de identificación de un dispositivo en la base de datos SQLite
        
        Args:
            device_data: Diccionario con la información del dispositivo
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Convertir open_ports a string para almacenamiento
            if 'open_ports' in device_data and isinstance(device_data['open_ports'], list):
                open_ports = ','.join(str(port) for port in device_data['open_ports'])
            else:
                open_ports = ''
            
            # Verificar si el dispositivo ya existe
            cursor.execute(
                'SELECT ip FROM identified_devices WHERE ip = ?',
                (device_data.get('ip', ''),)
            )
            exists = cursor.fetchone()
            
            if exists:
                # Actualizar registro existente
                cursor.execute('''
                UPDATE identified_devices
                SET mac = ?, hostname = ?, vendor = ?, vendor_details = ?,
                    device_type = ?, model = ?, os = ?, open_ports = ?,
                    last_seen = ?, confidence = ?
                WHERE ip = ?
                ''', (
                    device_data.get('mac', ''),
                    device_data.get('hostname', ''),
                    device_data.get('vendor', ''),
                    device_data.get('vendor_details', ''),
                    device_data.get('device_type', ''),
                    device_data.get('model', ''),
                    device_data.get('os', ''),
                    open_ports,
                    int(time.time()),
                    device_data.get('confidence', 0.0),
                    device_data.get('ip', '')
                ))
            else:
                # Insertar nuevo registro
                cursor.execute('''
                INSERT INTO identified_devices (
                    ip, mac, hostname, vendor, vendor_details, 
                    device_type, model, os, open_ports, last_seen, confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device_data.get('ip', ''),
                    device_data.get('mac', ''),
                    device_data.get('hostname', ''),
                    device_data.get('vendor', ''),
                    device_data.get('vendor_details', ''),
                    device_data.get('device_type', ''),
                    device_data.get('model', ''),
                    device_data.get('os', ''),
                    open_ports,
                    int(time.time()),
                    device_data.get('confidence', 0.0)
                ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error al guardar información de dispositivo en la base de datos: {e}")
    
    def get_known_device(self, ip: str = None, mac: str = None) -> Optional[Dict]:
        """
        Obtiene información de un dispositivo previamente identificado
        
        Args:
            ip: Dirección IP del dispositivo (opcional)
            mac: Dirección MAC del dispositivo (opcional)
            
        Returns:
            Dict or None: Información del dispositivo si existe, None en caso contrario
        """
        if not ip and not mac:
            return None
        
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            if ip:
                cursor.execute(
                    'SELECT * FROM identified_devices WHERE ip = ?',
                    (ip,)
                )
            else:
                cursor.execute(
                    'SELECT * FROM identified_devices WHERE mac = ?',
                    (mac.lower(),)
                )
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                # Convertir a diccionario
                columns = [col[0] for col in cursor.description]
                device_data = dict(zip(columns, row))
                
                # Convertir open_ports de string a lista
                if 'open_ports' in device_data and device_data['open_ports']:
                    device_data['open_ports'] = [int(port) for port in device_data['open_ports'].split(',') if port]
                else:
                    device_data['open_ports'] = []
                
                return device_data
                
            return None
        except Exception as e:
            print(f"Error al obtener información de dispositivo conocido: {e}")
            return None
    
    def get_device_by_mac_prefix(self, mac: str) -> Optional[Dict]:
        """
        Busca información del dispositivo basada en el prefijo MAC
        
        Args:
            mac: Dirección MAC completa o prefijo
        
        Returns:
            Dict or None: Información del dispositivo si se encuentra, None en caso contrario
        """
        if not mac:
            return None
        
        # Normalizar MAC
        mac = mac.lower().replace('-', ':')
        
        # Primer intento: buscar coincidencia exacta en la base de datos de modelos
        # Verificar diferentes longitudes de prefijo, desde más específico a más general
        prefixes = [
            mac[:8],  # XX:XX:XX
            mac[:5],  # XX:XX
            mac[:2]   # XX
        ]
        
        for prefix in prefixes:
            if prefix in self.device_models_db:
                return self.device_models_db[prefix]
        
        # Segundo intento: buscar un prefijo en la base de datos de modelos
        for db_prefix, info in self.device_models_db.items():
            if mac.startswith(db_prefix):
                return info
        
        # Si no encontramos nada, retornar None
        return None
    
    def get_vendor_info(self, mac: str) -> Tuple[str, str]:
        """
        Obtiene información del fabricante a partir de la dirección MAC
        
        Args:
            mac: Dirección MAC completa
            
        Returns:
            Tuple[str, str]: (vendor_short, vendor_details)
        """
        if not mac:
            return ("Desconocido", "Desconocido")
        
        # Normalizar MAC
        mac = mac.lower().replace('-', ':')
        
        # Verificar si ya está en caché
        if mac in self.mac_vendors_db:
            if isinstance(self.mac_vendors_db[mac], tuple):
                return self.mac_vendors_db[mac]
            else:
                vendor_info = self.mac_vendors_db[mac]
                return (vendor_info, vendor_info)
        
        # Extraer prefijo OUI (primeros 6 caracteres)
        prefix = mac[:8]  # Formato XX:XX:XX
        
        # Buscar en la base de datos OUI
        vendor_info = "Desconocido"
        vendor_details = "Desconocido"
        
        # Buscar en la base de datos OUI
        for db_prefix, company in self.oui_db.items():
            if prefix.startswith(db_prefix.lower()):
                vendor_info = company
                vendor_details = company
                break
        
        # Si no encontramos nada, intentar con la otra base de datos
        if vendor_info == "Desconocido":
            for db_prefix, company in self.mac_vendors_db.items():
                if isinstance(company, tuple):
                    # Si es una tupla, usar el primer elemento (vendor_short)
                    company_name = company[0]
                else:
                    # Si es una cadena, usarla directamente
                    company_name = company
                
                if prefix.startswith(db_prefix.lower()):
                    vendor_info = company_name
                    vendor_details = company_name
                    break
        
        # Extraer nombre corto del fabricante (primera palabra o dos)
        short_vendor = vendor_info.split()[0]
        if len(vendor_info.split()) > 1 and len(vendor_info.split()[0]) <= 3:
            short_vendor = ' '.join(vendor_info.split()[:2])
        
        # Guardar en caché
        vendor_tuple = (short_vendor, vendor_details)
        self.save_vendor_to_cache(mac, vendor_tuple)
        
        return vendor_tuple