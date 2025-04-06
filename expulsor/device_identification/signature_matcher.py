"""
Módulo para hacer coincidir firmas de dispositivos
"""

import re
from typing import Dict, List, Tuple
from collections import Counter

class SignatureMatcher:
    """
    Clase para hacer coincidir características de dispositivos con firmas conocidas
    y determinar su tipo, fabricante y modelo
    """
    
    # Firmas y patrones mejorados para la identificación de dispositivos
    DEVICE_SIGNATURES = {
        # Basado en patrones de puertos abiertos
        'ports': {
            (80, 443): ['Router', 'Gateway', 'Access Point', 'Embedded Device'],
            (80, 443, 8080): ['Router', 'Gateway', 'Access Point'],
            (80, 443, 8443): ['Router', 'Smart Hub', 'NVR'],
            (80, 23): ['Router', 'Embedded Device', 'IoT Device'],
            (80, 23, 21): ['Router', 'NAS', 'Embedded Server'],
            (554, 80): ['IP Camera', 'Security Camera', 'NVR'],
            (554, 80, 443): ['IP Camera', 'Security Camera', 'NVR'],
            (554, 1935): ['IP Camera', 'Security Camera', 'Streaming Device'],
            (1883,): ['IoT Device', 'Smart Home Hub', 'MQTT Broker'],
            (1883, 8883): ['IoT Device', 'Smart Home Hub', 'MQTT Broker'],
            (8009,): ['Chromecast', 'Smart TV', 'Streaming Device'],
            (8008, 8009): ['Chromecast', 'Smart TV', 'Google Device'],
            (548, 5009): ['Apple Device', 'Mac', 'Time Capsule'],
            (548, 5009, 5353): ['Apple Device', 'Mac', 'Time Capsule'],
            (62078,): ['iPhone', 'iPad', 'Apple Mobile Device'],
            (5353,): ['mDNS Device', 'IoT Device', 'Networked Device'],
            (5353, 7000): ['Apple TV', 'AirPlay Device'],
            (5000, 5353): ['Sonos Speaker', 'Smart Speaker', 'Audio Device'],
            (8080, 8443, 9080): ['IP Camera', 'NVR', 'DVR', 'Surveillance System'],
            (9100,): ['Printer', 'Network Printer'],
            (9100, 515): ['Printer', 'Network Printer'],
            (22, 80, 443): ['Linux Device', 'Server', 'NAS'],
            (22, 80, 443, 3306): ['Web Server', 'LAMP Server'],
            (3389,): ['Windows Remote Desktop', 'Windows Server'],
            (3389, 445): ['Windows Server', 'Windows Device'],
            (445,): ['Windows Device', 'Windows File Sharing'],
            (139, 445): ['Windows Device', 'Windows File Sharing'],
            (53,): ['DNS Server', 'Domain Controller'],
            (53, 88, 389): ['Domain Controller', 'Active Directory Server'],
            (5060, 5061): ['VoIP Device', 'SIP Phone', 'IP Phone'],
            (1900,): ['UPNP Device', 'Smart Device', 'IoT Device'],
            (1900, 5000): ['Smart TV', 'Media Device', 'DLNA Device'],
            (2323,): ['Telnet Device', 'IoT Device', 'Embedded Device'],
            (502,): ['Modbus Device', 'Industrial Control', 'PLC'],
            (20, 21): ['FTP Server', 'NAS', 'Storage Device'],
            (67, 68): ['DHCP Server', 'Router', 'Network Infrastructure'],
            (123,): ['NTP Server', 'Network Infrastructure', 'Time Server'],
            (161, 162): ['SNMP Device', 'Network Infrastructure', 'Managed Device'],
            (5060,): ['VoIP Device', 'SIP Server', 'IP Phone'],
            (25,): ['Mail Server', 'SMTP Server'],
            (110, 143): ['Mail Server', 'POP3/IMAP Server'],
            (3306,): ['MySQL Server', 'Database Server'],
            (1433,): ['SQL Server', 'Database Server'],
            (5432,): ['PostgreSQL Server', 'Database Server'],
            (27017,): ['MongoDB Server', 'Database Server'],
            (6379,): ['Redis Server', 'Cache Server'],
            (11211,): ['Memcached Server', 'Cache Server'],
            (9090, 9443): ['Management Interface', 'Admin Console'],
            (8086,): ['InfluxDB', 'Time Series Database'],
            (8088, 8090): ['Web Interface', 'Admin Panel'],
            (8123,): ['Home Assistant', 'Smart Home Hub'],
            (8123, 1883): ['Home Assistant', 'Smart Home System'],
            (1880,): ['Node-RED', 'IoT Platform'],
            (1880, 1883): ['IoT Platform', 'Automation System'],
            (1521,): ['Oracle DB', 'Database Server'],
            (5984,): ['CouchDB', 'Database Server'],
            (9200, 9300): ['Elasticsearch', 'Search Engine'],
            (9000, 9200): ['Elasticsearch Stack', 'Data Platform'],
            (2181,): ['ZooKeeper', 'Distributed System'],
            (2375, 2376): ['Docker', 'Container Platform'],
            (6443,): ['Kubernetes', 'Container Orchestration'],
            (4369,): ['RabbitMQ', 'Message Broker'],
            (5672,): ['AMQP Broker', 'Message Queue'],
            (3000,): ['Development Server', 'Web Application'],
            (8000,): ['Web Server', 'Development Server'],
            (8080,): ['Web Server', 'Proxy', 'Web Interface'],
            (8800, 8880): ['Control Panel', 'Management Interface'],
            (10000,): ['Webmin', 'Admin Interface'],
            (10000, 20000): ['Virtual Server', 'Management Tools'],
            (8291, 8728): ['MikroTik Router', 'MikroTik API'],
            (49152, 52000): ['UPnP Device', 'NAT-PMP Device'],
            (5357, 3702): ['WSD Device', 'Microsoft Network Discovery'],
            (5222, 5269): ['XMPP Server', 'Chat Server'],
            (5280,): ['XMPP Web', 'Chat Web Interface'],
            (6660, 6669): ['IRC Server', 'Chat Server'],
            (7777,): ['Game Server', 'Gaming Service'],
            (27015, 27020): ['Steam Game Server', 'Game Service'],
            (3074,): ['Xbox Live', 'Gaming Console'],
            (3478, 3479): ['PlayStation Network', 'Gaming Console'],
            (3478, 5004): ['VoIP NAT Traversal', 'Video Conferencing'],
            (5938,): ['TeamViewer', 'Remote Access'],
            (1194,): ['OpenVPN', 'VPN Service'],
            (500, 4500): ['IPsec VPN', 'VPN Service'],
        },
        
        # Basado en patrones de nombre de host mejorados
        'hostname': {
            r'.*iphone.*': 'iPhone',
            r'.*ipad.*': 'iPad',
            r'.*macbook.*': 'MacBook',
            r'.*mac.*mini.*': 'Mac Mini',
            r'.*imac.*': 'iMac',
            r'.*mbp.*': 'MacBook Pro',
            r'.*mba.*': 'MacBook Air',
            r'.*android.*': 'Android Device',
            r'.*galaxy.*': 'Samsung Galaxy',
            r'.*pixel.*': 'Google Pixel',
            r'.*oneplus.*': 'OnePlus Phone',
            r'.*xiaomi.*': 'Xiaomi Phone',
            r'.*redmi.*': 'Xiaomi Redmi',
            r'.*huawei.*': 'Huawei Phone',
            r'.*honor.*': 'Honor Phone',
            r'.*phone.*': 'Smartphone',
            r'.*mobile.*': 'Mobile Device',
            r'.*tablet.*': 'Tablet',
            r'.*pad.*': 'Tablet',
            r'.*surface.*': 'Microsoft Surface',
            r'.*tv.*': 'Smart TV',
            r'.*roku.*': 'Roku Device',
            r'.*firetv.*': 'Amazon Fire TV',
            r'.*fire-tv.*': 'Amazon Fire TV',
            r'.*chromecast.*': 'Chromecast',
            r'.*appletv.*': 'Apple TV',
            r'.*apple-tv.*': 'Apple TV',
            r'.*shield.*': 'NVIDIA Shield',
            r'.*echo.*': 'Amazon Echo',
            r'.*alexa.*': 'Amazon Alexa',
            r'.*homepod.*': 'Apple HomePod',
            r'.*nest.*': 'Nest Device',
            r'.*hue.*': 'Philips Hue',
            r'.*ring.*': 'Ring Device',
            r'.*cam.*': 'Camera',
            r'.*camera.*': 'IP Camera',
            r'.*doorbell.*': 'Smart Doorbell',
            r'.*printer.*': 'Printer',
            r'.*mfp.*': 'Multi-Function Printer',
            r'.*scanner.*': 'Scanner',
            r'.*xbox.*': 'Xbox',
            r'.*playstation.*': 'PlayStation',
            r'.*ps4.*': 'PlayStation 4',
            r'.*ps5.*': 'PlayStation 5',
            r'.*nintendo.*': 'Nintendo',
            r'.*switch.*': 'Nintendo Switch',
            r'.*laptop.*': 'Laptop',
            r'.*notebook.*': 'Laptop',
            r'.*desktop.*': 'Desktop PC',
            r'.*pc.*': 'Desktop PC',
            r'.*thinkpad.*': 'Lenovo ThinkPad',
            r'.*thinkcentre.*': 'Lenovo ThinkCentre',
            r'.*precision.*': 'Dell Precision',
            r'.*optiplex.*': 'Dell OptiPlex',
            r'.*latitude.*': 'Dell Latitude',
            r'.*xps.*': 'Dell XPS',
            r'.*inspiron.*': 'Dell Inspiron',
            r'.*hp.*elitebook.*': 'HP EliteBook',
            r'.*hp.*probook.*': 'HP ProBook',
            r'.*hp.*envy.*': 'HP Envy',
            r'.*hp.*pavilion.*': 'HP Pavilion',
            r'.*spectre.*': 'HP Spectre',
            r'.*zenbook.*': 'ASUS ZenBook',
            r'.*vivobook.*': 'ASUS VivoBook',
            r'.*router.*': 'Router',
            r'.*gateway.*': 'Gateway',
            r'.*modem.*': 'Modem',
            r'.*ap.*': 'Access Point',
            r'.*access-point.*': 'Access Point',
            r'.*hub.*': 'Smart Hub',
            r'.*bridge.*': 'Network Bridge',
            r'.*nas.*': 'NAS',
            r'.*storage.*': 'Storage Device',
            r'.*synology.*': 'Synology NAS',
            r'.*qnap.*': 'QNAP NAS',
            r'.*wd.*my.*cloud.*': 'WD My Cloud',
            r'.*diskstation.*': 'Synology DiskStation',
            r'.*server.*': 'Server',
            r'.*vmware.*': 'VMware Server',
            r'.*esxi.*': 'VMware ESXi',
            r'.*proxmox.*': 'Proxmox Server',
            r'.*unraid.*': 'Unraid Server',
            r'.*raspberry.*': 'Raspberry Pi',
            r'.*pi.*': 'Raspberry Pi',
            r'.*arduino.*': 'Arduino',
            r'.*esp.*': 'ESP Device',
            r'.*watch.*': 'Smart Watch',
            r'.*applew.*': 'Apple Watch',
            r'.*fitbit.*': 'Fitbit',
            r'.*garmin.*': 'Garmin Watch',
            r'.*refrigerator.*': 'Smart Refrigerator',
            r'.*fridge.*': 'Smart Refrigerator',
            r'.*oven.*': 'Smart Oven',
            r'.*microwave.*': 'Smart Microwave',
            r'.*cooker.*': 'Smart Cooker',
            r'.*washer.*': 'Smart Washer',
            r'.*dryer.*': 'Smart Dryer',
            r'.*dishwasher.*': 'Smart Dishwasher',
            r'.*thermostat.*': 'Smart Thermostat',
            r'.*air.*purifier.*': 'Air Purifier',
            r'.*vacuum.*': 'Robot Vacuum',
            r'.*roomba.*': 'iRobot Roomba',
            r'.*speaker.*': 'Smart Speaker',
            r'.*soundbar.*': 'Soundbar',
            r'.*amplifier.*': 'Amplifier',
            r'.*receiver.*': 'AV Receiver',
            r'.*sonos.*': 'Sonos Speaker',
            r'.*bose.*': 'Bose Speaker',
            r'.*denon.*': 'Denon Device',
            r'.*onkyo.*': 'Onkyo Device',
            r'.*yamaha.*': 'Yamaha Device',
            r'.*lock.*': 'Smart Lock',
            r'.*light.*': 'Smart Light',
            r'.*bulb.*': 'Smart Bulb',
            r'.*strip.*': 'LED Strip',
            r'.*fan.*': 'Smart Fan',
            r'.*curtain.*': 'Smart Curtain',
            r'.*blind.*': 'Smart Blind',
            r'.*shutter.*': 'Smart Shutter',
            r'.*siren.*': 'Smart Siren',
            r'.*sensor.*': 'Sensor',
            r'.*motion.*': 'Motion Sensor',
            r'.*contact.*': 'Contact Sensor',
            r'.*smoke.*': 'Smoke Detector',
            r'.*co.*detector.*': 'CO Detector',
            r'.*water.*leak.*': 'Water Leak Sensor',
            r'.*temp.*': 'Temperature Sensor',
            r'.*humidity.*': 'Humidity Sensor',
            r'.*presence.*': 'Presence Sensor',
            r'.*switch.*': 'Smart Switch',
            r'.*plug.*': 'Smart Plug',
            r'.*outlet.*': 'Smart Outlet',
            r'.*wall.*socket.*': 'Wall Socket',
        },
        
        # Basado en respuestas HTTP (User-Agent, Server, etc.)
        'http_signature': {
            r'.*mikrotik.*': 'Mikrotik Router',
            r'.*ubiquiti.*': 'Ubiquiti Device',
            r'.*unifi.*': 'Ubiquiti UniFi',
            r'.*edgeos.*': 'Ubiquiti EdgeOS',
            r'.*edge.*os.*': 'Ubiquiti EdgeOS',
            r'.*synology.*': 'Synology NAS',
            r'.*diskstation.*': 'Synology DiskStation',
            r'.*qnap.*': 'QNAP NAS',
            r'.*asus.*rt.*': 'Asus Router',
            r'.*dd-wrt.*': 'DD-WRT Router',
            r'.*openwrt.*': 'OpenWRT Router',
            r'.*tomato.*': 'Tomato Router',
            r'.*merlin.*': 'Asuswrt-Merlin Router',
            r'.*linksys.*': 'Linksys Router',
            r'.*cisco.*': 'Cisco Device',
            r'.*tp-link.*': 'TP-Link Device',
            r'.*tplink.*': 'TP-Link Device',
            r'.*netgear.*': 'Netgear Device',
            r'.*d-link.*': 'D-Link Device',
            r'.*dlink.*': 'D-Link Device',
            r'.*hikvision.*': 'Hikvision Camera',
            r'.*dahua.*': 'Dahua Camera',
            r'.*axis.*': 'Axis Camera',
            r'.*foscam.*': 'Foscam Camera',
            r'.*reolink.*': 'Reolink Camera',
            r'.*amcrest.*': 'Amcrest Camera',
            r'.*wyze.*': 'Wyze Camera',
            r'.*arlo.*': 'Arlo Camera',
            r'.*ring.*': 'Ring Device',
            r'.*doorbell.*': 'Smart Doorbell',
            r'.*philips.*hue.*': 'Philips Hue',
            r'.*hue.*bridge.*': 'Philips Hue Bridge',
            r'.*lifx.*': 'LIFX Light',
            r'.*wemo.*': 'Belkin WeMo',
            r'.*sonos.*': 'Sonos Speaker',
            r'.*bose.*': 'Bose Device',
            r'.*denon.*': 'Denon Device',
            r'.*yamaha.*': 'Yamaha Device',
            r'.*samsung.*tv.*': 'Samsung TV',
            r'.*lg.*webos.*': 'LG WebOS TV',
            r'.*vizio.*': 'Vizio TV',
            r'.*roku.*': 'Roku Device',
            r'.*chromecast.*': 'Google Chromecast',
            r'.*apple.*tv.*': 'Apple TV',
            r'.*fire.*tv.*': 'Amazon Fire TV',
            r'.*nvidia.*shield.*': 'NVIDIA Shield',
            r'.*playstation.*': 'PlayStation',
            r'.*xbox.*': 'Xbox',
            r'.*nintendo.*': 'Nintendo Device',
            r'.*hp.*': 'HP Printer',
            r'.*canon.*': 'Canon Printer',
            r'.*epson.*': 'Epson Printer',
            r'.*brother.*': 'Brother Printer',
            r'.*lexmark.*': 'Lexmark Printer',
            r'.*xerox.*': 'Xerox Printer',
            r'.*ricoh.*': 'Ricoh Printer',
            r'.*kyocera.*': 'Kyocera Printer',
            r'.*nest.*': 'Nest Device',
            r'.*thermostat.*': 'Smart Thermostat',
            r'.*ecobee.*': 'Ecobee Thermostat',
            r'.*honeywell.*': 'Honeywell Device',
            r'.*smartthings.*': 'SmartThings Hub',
            r'.*hubitat.*': 'Hubitat Hub',
            r'.*vera.*': 'Vera Hub',
            r'.*homeseer.*': 'HomeSeer Hub',
            r'.*home.*assistant.*': 'Home Assistant',
            r'.*homekit.*': 'Apple HomeKit',
            r'.*broadlink.*': 'BroadLink Device',
            r'.*tasmota.*': 'Tasmota Device',
            r'.*esphome.*': 'ESPHome Device',
            r'.*shelly.*': 'Shelly Device',
            r'.*tuya.*': 'Tuya Device',
            r'.*smart.*life.*': 'Smart Life Device',
            r'.*kasa.*': 'TP-Link Kasa',
            r'.*govee.*': 'Govee Device',
            r'.*meross.*': 'Meross Device',
            r'.*wyze.*': 'Wyze Device',
            r'.*eufy.*': 'Eufy Device',
        },
        
        # Signaturas SNMP para identificación de dispositivos
        'snmp_signature': {
            r'.*cisco.*ios.*': 'Cisco IOS',
            r'.*router.*': 'Router',
            r'.*switch.*': 'Network Switch',
            r'.*firewall.*': 'Firewall',
            r'.*printer.*': 'Printer',
            r'.*storage.*': 'Storage Device',
            r'.*camera.*': 'IP Camera',
            r'.*ups.*': 'UPS',
            r'.*server.*': 'Server',
            r'.*workstation.*': 'Workstation',
            r'.*terminal.*': 'Terminal',
            r'.*access.*point.*': 'Access Point',
            r'.*bridge.*': 'Network Bridge',
            r'.*gateway.*': 'Gateway',
            r'.*modem.*': 'Modem',
            r'.*pbx.*': 'PBX System',
            r'.*voip.*': 'VoIP Device',
            r'.*ip.*phone.*': 'IP Phone',
            r'.*load.*balancer.*': 'Load Balancer',
            r'.*appliance.*': 'Network Appliance',
            r'.*controller.*': 'Controller',
            r'.*hub.*': 'Hub',
            r'.*repeater.*': 'Repeater',
            r'.*nas.*': 'NAS',
            r'.*san.*': 'SAN',
            r'.*media.*converter.*': 'Media Converter',
            r'.*kvm.*': 'KVM Switch',
            r'.*pdu.*': 'PDU',
        },
        
        # Signaturas específicas de servicio
        'service_signature': {
            'ssh': {
                r'.*openssh.*': 'OpenSSH Server',
                r'.*dropbear.*': 'Dropbear SSH',
                r'.*cisco.*': 'Cisco Device',
                r'.*mikrotik.*': 'Mikrotik Router',
                r'.*ubiquiti.*': 'Ubiquiti Device',
                r'.*synology.*': 'Synology NAS',
                r'.*qnap.*': 'QNAP NAS',
                r'.*asustor.*': 'Asustor NAS',
                r'.*freenas.*': 'FreeNAS Server',
                r'.*truenas.*': 'TrueNAS Server',
                r'.*openwrt.*': 'OpenWRT Router',
                r'.*debian.*': 'Debian Linux',
                r'.*ubuntu.*': 'Ubuntu Linux',
                r'.*centos.*': 'CentOS Linux',
                r'.*fedora.*': 'Fedora Linux',
                r'.*redhat.*': 'Red Hat Linux',
                r'.*raspbian.*': 'Raspberry Pi',
            },
            'http': {
                r'.*apache.*': 'Apache Web Server',
                r'.*nginx.*': 'Nginx Web Server',
                r'.*iis.*': 'Microsoft IIS',
                r'.*lighttpd.*': 'Lighttpd Web Server',
                r'.*node\.js.*': 'Node.js Server',
                r'.*tomcat.*': 'Apache Tomcat',
                r'.*weblogic.*': 'Oracle WebLogic',
                r'.*websphere.*': 'IBM WebSphere',
                r'.*jetty.*': 'Jetty Web Server',
                r'.*cherokee.*': 'Cherokee Web Server',
                r'.*caddy.*': 'Caddy Web Server',
                r'.*traefik.*': 'Traefik Proxy',
                r'.*synology.*': 'Synology NAS',
                r'.*qnap.*': 'QNAP NAS',
                r'.*mikrotik.*': 'Mikrotik Router',
                r'.*ubiquiti.*': 'Ubiquiti Device',
                r'.*sonicwall.*': 'SonicWall Firewall',
                r'.*pfsense.*': 'pfSense Firewall',
                r'.*opnsense.*': 'OPNsense Firewall',
                r'.*fortinet.*': 'Fortinet Device',
                r'.*juniper.*': 'Juniper Device',
                r'.*cloudflare.*': 'Cloudflare',
                r'.*akamai.*': 'Akamai',
                r'.*fastly.*': 'Fastly',
                r'.*aws.*': 'AWS Service',
                r'.*azure.*': 'Azure Service',
                r'.*gcp.*': 'Google Cloud',
                r'.*wordpress.*': 'WordPress Site',
                r'.*joomla.*': 'Joomla Site',
                r'.*drupal.*': 'Drupal Site',
                r'.*magento.*': 'Magento Site',
                r'.*shopify.*': 'Shopify Site',
                r'.*woocommerce.*': 'WooCommerce Site',
                r'.*prestashop.*': 'PrestaShop Site',
                r'.*confluence.*': 'Atlassian Confluence',
                r'.*jira.*': 'Atlassian Jira',
                r'.*gitlab.*': 'GitLab',
                r'.*github.*': 'GitHub',
                r'.*jenkins.*': 'Jenkins',
                r'.*grafana.*': 'Grafana',
                r'.*prometheus.*': 'Prometheus',
                r'.*kibana.*': 'Kibana',
                r'.*elasticsearch.*': 'Elasticsearch',
                r'.*influxdb.*': 'InfluxDB',
                r'.*plesk.*': 'Plesk Control Panel',
                r'.*cpanel.*': 'cPanel Control Panel',
                r'.*webmin.*': 'Webmin Control Panel',
                r'.*directadmin.*': 'DirectAdmin Control Panel',
            },
            'rtsp': {
                r'.*hikvision.*': 'Hikvision Camera',
                r'.*dahua.*': 'Dahua Camera',
                r'.*axis.*': 'Axis Camera',
                r'.*foscam.*': 'Foscam Camera',
                r'.*reolink.*': 'Reolink Camera',
                r'.*amcrest.*': 'Amcrest Camera',
                r'.*wyze.*': 'Wyze Camera',
                r'.*arlo.*': 'Arlo Camera',
                r'.*uniview.*': 'Uniview Camera',
                r'.*lorex.*': 'Lorex Camera',
                r'.*swann.*': 'Swann Camera',
                r'.*vivotek.*': 'Vivotek Camera',
                r'.*geovision.*': 'GeoVision Camera',
                r'.*tvt.*': 'TVT Camera',
                r'.*qvis.*': 'QVIS Camera',
                r'.*bosch.*': 'Bosch Camera',
                r'.*hanwha.*': 'Hanwha Camera',
                r'.*wisenet.*': 'Wisenet Camera',
                r'.*ezviz.*': 'EZVIZ Camera',
                r'.*annke.*': 'ANNKE Camera',
                r'.*zosi.*': 'ZOSI Camera',
                r'.*sannce.*': 'SANNCE Camera',
                r'.*tplink.*': 'TP-Link Camera',
                r'.*yi.*': 'Yi Camera',
                r'.*honeywell.*': 'Honeywell Camera',
                r'.*merkury.*': 'Merkury Camera',
                r'.*zmodo.*': 'Zmodo Camera',
                r'.*sercomm.*': 'Sercomm Camera',
                r'.*nvr.*': 'NVR System',
                r'.*dvr.*': 'DVR System',
            },
            'upnp': {
                r'.*router.*': 'UPnP Router',
                r'.*nas.*': 'UPnP NAS',
                r'.*media.*server.*': 'Media Server',
                r'.*tv.*': 'Smart TV',
                r'.*gateway.*': 'Internet Gateway',
                r'.*igd.*': 'Internet Gateway Device',
                r'.*playstation.*': 'PlayStation',
                r'.*xbox.*': 'Xbox',
                r'.*wmp.*': 'Windows Media Player',
                r'.*dlna.*': 'DLNA Device',
                r'.*philips.*': 'Philips Device',
                r'.*samsung.*': 'Samsung Device',
                r'.*sony.*': 'Sony Device',
                r'.*lg.*': 'LG Device',
                r'.*panasonic.*': 'Panasonic Device',
                r'.*pioneer.*': 'Pioneer Device',
                r'.*denon.*': 'Denon Device',
                r'.*onkyo.*': 'Onkyo Device',
                r'.*yamaha.*': 'Yamaha Device',
                r'.*marantz.*': 'Marantz Device',
                r'.*bose.*': 'Bose Device',
                r'.*sonos.*': 'Sonos Speaker',
                r'.*heos.*': 'HEOS Speaker',
                r'.*chromecast.*': 'Chromecast',
                r'.*roku.*': 'Roku Device',
                r'.*kodi.*': 'Kodi Media Center',
                r'.*plex.*': 'Plex Media Server',
                r'.*emby.*': 'Emby Media Server',
                r'.*jellyfin.*': 'Jellyfin Media Server',
                r'.*universal.*media.*server.*': 'Universal Media Server',
                r'.*serviio.*': 'Serviio Media Server',
                r'.*twonky.*': 'Twonky Media Server',
                r'.*western.*digital.*': 'Western Digital Device',
                r'.*wd.*': 'Western Digital Device',
                r'.*seagate.*': 'Seagate Device',
                r'.*buffalo.*': 'Buffalo Device',
                r'.*toshiba.*': 'Toshiba Device',
                r'.*lacie.*': 'LaCie Device',
                r'.*netgear.*': 'Netgear Device',
                r'.*synology.*': 'Synology Device',
                r'.*qnap.*': 'QNAP Device',
            },
            'mdns': {
                r'.*airplay.*': 'AirPlay Device',
                r'.*apple.*tv.*': 'Apple TV',
                r'.*homekit.*': 'HomeKit Device',
                r'.*chromecast.*': 'Chromecast',
                r'.*google.*home.*': 'Google Home',
                r'.*google.*nest.*': 'Google Nest',
                r'.*sonos.*': 'Sonos Speaker',
                r'.*bose.*': 'Bose Speaker',
                r'.*yamaha.*': 'Yamaha Device',
                r'.*denon.*': 'Denon Device',
                r'.*heos.*': 'HEOS Speaker',
                r'.*marantz.*': 'Marantz Device',
                r'.*onkyo.*': 'Onkyo Device',
                r'.*pioneer.*': 'Pioneer Device',
                r'.*philips.*hue.*': 'Philips Hue',
                r'.*lifx.*': 'LIFX Light',
                r'.*wemo.*': 'Belkin WeMo',
                r'.*lutron.*': 'Lutron Device',
                r'.*apple.*device.*': 'Apple Device',
                r'.*iphone.*': 'iPhone',
                r'.*ipad.*': 'iPad',
                r'.*ipod.*': 'iPod',
                r'.*macbook.*': 'MacBook',
                r'.*imac.*': 'iMac',
                r'.*mac.*mini.*': 'Mac Mini',
                r'.*mac.*pro.*': 'Mac Pro',
                r'.*time.*capsule.*': 'Time Capsule',
                r'.*airport.*': 'AirPort Base Station',
                r'.*printer.*': 'Network Printer',
                r'.*scanner.*': 'Network Scanner',
                r'.*canon.*': 'Canon Device',
                r'.*hp.*': 'HP Device',
                r'.*epson.*': 'Epson Device',
                r'.*brother.*': 'Brother Device',
                r'.*lexmark.*': 'Lexmark Device',
                r'.*ricoh.*': 'Ricoh Device',
                r'.*synology.*': 'Synology NAS',
                r'.*qnap.*': 'QNAP NAS',
                r'.*raspberry.*pi.*': 'Raspberry Pi',
                r'.*home.*assistant.*': 'Home Assistant',
                r'.*homebridge.*': 'Homebridge',
                r'.*esphome.*': 'ESPHome Device',
                r'.*tasmota.*': 'Tasmota Device',
                r'.*shelly.*': 'Shelly Device',
            },
        }
    }
    
    def __init__(self):
        """Inicializa el matcher de firmas"""
        pass
    
    def match_device_type(self, device_data: Dict) -> List[Tuple[str, float]]:
        """
        Identifica posibles tipos de dispositivo basados en la información disponible
        
        Args:
            device_data: Diccionario con información del dispositivo (ports, hostname, etc.)
            
        Returns:
            List[Tuple[str, float]]: Lista de posibles tipos con puntuación de confianza
        """
        possible_types = []
        
        # 1. Identificar por puertos abiertos
        if 'open_ports' in device_data and device_data['open_ports']:
            open_ports = set(device_data['open_ports'])
            
            # Comparar con firmas de puertos
            for port_pattern, device_types in self.DEVICE_SIGNATURES['ports'].items():
                port_pattern_set = set(port_pattern)
                
                # Calcular coincidencia
                if port_pattern_set.issubset(open_ports):
                    # Coincidencia perfecta - todos los puertos están presentes
                    confidence = 0.9
                    
                    # Ajustar confianza según el número total de puertos abiertos
                    # Una coincidencia perfecta con menos puertos adicionales abiertos es mejor
                    extra_ports = len(open_ports) - len(port_pattern_set)
                    if extra_ports > 0:
                        confidence -= min(0.4, extra_ports * 0.05)
                    
                    for device_type in device_types:
                        possible_types.append((device_type, confidence))
                elif len(port_pattern_set.intersection(open_ports)) >= min(2, len(port_pattern_set)):
                    # Coincidencia parcial - al menos 2 puertos o todos si hay menos de 2
                    match_ratio = len(port_pattern_set.intersection(open_ports)) / len(port_pattern_set)
                    confidence = 0.5 * match_ratio
                    
                    for device_type in device_types:
                        possible_types.append((device_type, confidence))
        
        # 2. Identificar por nombre de host
        if 'hostname' in device_data and device_data['hostname']:
            hostname = device_data['hostname'].lower()
            
            for pattern, device_type in self.DEVICE_SIGNATURES['hostname'].items():
                if re.search(pattern, hostname, re.IGNORECASE):
                    # La confianza es mayor para coincidencias más específicas
                    # Patrones más largos y más específicos tienen mayor confianza
                    specificity = min(0.3, len(pattern) / 100)  # Máximo 0.3 bonus por especificidad
                    confidence = 0.7 + specificity
                    
                    possible_types.append((device_type, confidence))
        
        # 3. Identificar por firma HTTP si está disponible
        if 'http_signature' in device_data and device_data['http_signature']:
            http_sig = device_data['http_signature'].lower()
            
            for pattern, device_type in self.DEVICE_SIGNATURES['http_signature'].items():
                if re.search(pattern, http_sig, re.IGNORECASE):
                    # Las firmas HTTP son bastante confiables
                    confidence = 0.85
                    possible_types.append((device_type, confidence))
        
        # 4. Identificar por firma SNMP si está disponible
        if 'snmp_signature' in device_data and device_data['snmp_signature']:
            snmp_sig = device_data['snmp_signature'].lower()
            
            for pattern, device_type in self.DEVICE_SIGNATURES['snmp_signature'].items():
                if re.search(pattern, snmp_sig, re.IGNORECASE):
                    # Las firmas SNMP son muy confiables
                    confidence = 0.9
                    possible_types.append((device_type, confidence))
        
        # 5. Identificar por firmas de servicio si están disponibles
        for service_type, signatures in self.DEVICE_SIGNATURES['service_signature'].items():
            service_key = f'{service_type}_signature'
            if service_key in device_data and device_data[service_key]:
                service_sig = device_data[service_key].lower()
                
                for pattern, device_type in signatures.items():
                    if re.search(pattern, service_sig, re.IGNORECASE):
                        # Las firmas de servicio son bastante confiables
                        confidence = 0.8
                        possible_types.append((device_type, confidence))
        
        # 6. Inferir por OS
        if 'os' in device_data and device_data['os']:
            os_lower = device_data['os'].lower()
            
            if "windows" in os_lower:
                if "server" in os_lower:
                    possible_types.append(("Windows Server", 0.85))
                else:
                    possible_types.append(("Windows PC", 0.8))
                    possible_types.append(("Desktop PC", 0.7))
                    
            elif "linux" in os_lower:
                if "debian" in os_lower or "ubuntu" in os_lower:
                    possible_types.append(("Debian/Ubuntu Server", 0.8))
                elif "centos" in os_lower or "redhat" in os_lower or "fedora" in os_lower:
                    possible_types.append(("Red Hat Linux Server", 0.8))
                elif "raspberry" in os_lower or "raspbian" in os_lower:
                    possible_types.append(("Raspberry Pi", 0.85))
                else:
                    possible_types.append(("Linux Server", 0.75))
                    
            elif "freebsd" in os_lower or "openbsd" in os_lower or "netbsd" in os_lower:
                possible_types.append(("BSD Server", 0.8))
                
            elif "android" in os_lower:
                possible_types.append(("Android Device", 0.85))
                possible_types.append(("Smartphone", 0.75))
                possible_types.append(("Tablet", 0.65))
                
            elif "ios" in os_lower or "iphone" in os_lower:
                possible_types.append(("iPhone", 0.85))
                
            elif "ipad" in os_lower:
                possible_types.append(("iPad", 0.85))
                
            elif "mac" in os_lower or "osx" in os_lower or "macos" in os_lower:
                possible_types.append(("Mac", 0.8))
                
            elif "router" in os_lower or "routeros" in os_lower:
                possible_types.append(("Router", 0.85))
                
            elif "printer" in os_lower:
                possible_types.append(("Printer", 0.85))
                
            elif "camera" in os_lower:
                possible_types.append(("IP Camera", 0.85))
                
            elif "nas" in os_lower:
                possible_types.append(("NAS", 0.85))
                
            elif "tv" in os_lower or "smart tv" in os_lower:
                possible_types.append(("Smart TV", 0.85))
        
        # 7. Si el dispositivo está basado en fabricante conocido
        if 'vendor' in device_data and device_data['vendor']:
            vendor = device_data['vendor'].lower()
            
            vendor_map = {
                'apple': [("Apple Device", 0.7)],
                'samsung': [("Samsung Device", 0.7)],
                'google': [("Google Device", 0.7)],
                'amazon': [("Amazon Device", 0.7)],
                'microsoft': [("Microsoft Device", 0.7)],
                'sony': [("Sony Device", 0.7)],
                'lg': [("LG Device", 0.7)],
                'asus': [("ASUS Device", 0.7)],
                'dell': [("Dell Device", 0.7)],
                'hp': [("HP Device", 0.7), ("Printer", 0.6)],
                'lenovo': [("Lenovo Device", 0.7)],
                'acer': [("Acer Device", 0.7)],
                'toshiba': [("Toshiba Device", 0.7)],
                'huawei': [("Huawei Device", 0.7)],
                'xiaomi': [("Xiaomi Device", 0.7)],
                'vivo': [("Vivo Phone", 0.7)],
                'oppo': [("OPPO Phone", 0.7)],
                'oneplus': [("OnePlus Phone", 0.7)],
                'realme': [("Realme Phone", 0.7)],
                'motorola': [("Motorola Phone", 0.7)],
                'nokia': [("Nokia Device", 0.7)],
                'cisco': [("Cisco Device", 0.7), ("Network Infrastructure", 0.6)],
                'netgear': [("Netgear Device", 0.7), ("Router", 0.6)],
                'tp-link': [("TP-Link Device", 0.7), ("Router", 0.6)],
                'd-link': [("D-Link Device", 0.7), ("Router", 0.6)],
                'zyxel': [("ZyXEL Device", 0.7), ("Router", 0.6)],
                'mikrotik': [("MikroTik Router", 0.8)],
                'ubiquiti': [("Ubiquiti Device", 0.8), ("Access Point", 0.7)],
                'linksys': [("Linksys Router", 0.8)],
                'belkin': [("Belkin Device", 0.7)],
                'synology': [("Synology NAS", 0.8)],
                'qnap': [("QNAP NAS", 0.8)],
                'western digital': [("Western Digital Device", 0.7), ("Storage Device", 0.6)],
                'wd': [("Western Digital Device", 0.7), ("Storage Device", 0.6)],
                'seagate': [("Seagate Device", 0.7), ("Storage Device", 0.6)],
                'hikvision': [("Hikvision Camera", 0.8)],
                'dahua': [("Dahua Camera", 0.8)],
                'axis': [("Axis Camera", 0.8)],
                'canon': [("Canon Device", 0.7), ("Printer", 0.6)],
                'epson': [("Epson Device", 0.7), ("Printer", 0.6)],
                'brother': [("Brother Device", 0.7), ("Printer", 0.6)],
                'honeywell': [("Honeywell Device", 0.7)],
                'nest': [("Nest Device", 0.8)],
                'ecobee': [("Ecobee Thermostat", 0.8)],
                'philips': [("Philips Device", 0.7)],
                'hue': [("Philips Hue", 0.8)],
                'sonos': [("Sonos Speaker", 0.8)],
                'bose': [("Bose Device", 0.8)],
                'yamaha': [("Yamaha Device", 0.7)],
                'denon': [("Denon Device", 0.7)],
                'marantz': [("Marantz Device", 0.7)],
                'onkyo': [("Onkyo Device", 0.7)],
                'pioneer': [("Pioneer Device", 0.7)],
                'roku': [("Roku Device", 0.8)],
                'nintendo': [("Nintendo Device", 0.8)],
                'playstation': [("PlayStation", 0.8)],
                'xbox': [("Xbox", 0.8)],
                'fitbit': [("Fitbit Device", 0.8)],
                'garmin': [("Garmin Device", 0.8)],
                'ring': [("Ring Device", 0.8)],
                'arlo': [("Arlo Camera", 0.8)],
                'logitech': [("Logitech Device", 0.7)],
                'intel': [("Intel Device", 0.7)],
                'amd': [("AMD Device", 0.7)],
                'nvidia': [("NVIDIA Device", 0.7)],
                'broadcom': [("Broadcom Device", 0.7)],
                'qualcomm': [("Qualcomm Device", 0.7)],
                'raspberry pi': [("Raspberry Pi", 0.8)],
                'arduino': [("Arduino", 0.8)],
                'espressif': [("ESP Device", 0.8)],
            }
            
            for vendor_key, type_entries in vendor_map.items():
                if vendor_key in vendor:
                    possible_types.extend(type_entries)
        
        # Consolidar los resultados y obtener los más probables
        return self._consolidate_device_types(possible_types)
    
    def _consolidate_device_types(self, possible_types: List[Tuple[str, float]]) -> List[Tuple[str, float]]:
        """
        Consolida y clasifica tipos de dispositivos identificados por confianza
        
        Args:
            possible_types: Lista de tuplas (tipo_dispositivo, confianza)
            
        Returns:
            List[Tuple[str, float]]: Lista ordenada de tipos de dispositivo por confianza
        """
        if not possible_types:
            return [("Desconocido", 0.0)]
        
        # Agrupar por tipo de dispositivo y sumar confianza
        type_scores = {}
        type_counts = Counter([t[0] for t in possible_types])
        
        for device_type, confidence in possible_types:
            if device_type not in type_scores:
                type_scores[device_type] = 0.0
            
            # Añadir confianza, dando más peso a tipos que aparecen varias veces
            count_weight = min(1.5, 1.0 + (type_counts[device_type] - 1) * 0.1)
            type_scores[device_type] += confidence * count_weight
        
        # Normalizar puntajes y ordenar por confianza
        max_score = max(type_scores.values()) if type_scores else 1.0
        normalized_scores = [(t, min(0.95, s / max_score)) for t, s in type_scores.items()]
        
        return sorted(normalized_scores, key=lambda x: x[1], reverse=True)
    
    def match_vendor_model(self, device_data: Dict) -> Tuple[str, str, float]:
        """
        Identifica el fabricante y el modelo del dispositivo basado en la información disponible
        
        Args:
            device_data: Diccionario con información del dispositivo
            
        Returns:
            Tuple[str, str, float]: (vendor, model, confidence)
        """
        vendor = device_data.get('vendor', "Desconocido")
        vendor_details = device_data.get('vendor_details', "")
        potential_models = []
        
        # 1. Extraer modelo de OS si está disponible
        if 'os' in device_data and device_data['os']:
            os_str = device_data['os']
            
            # Patrones para extraer información de modelo del OS
            model_patterns = [
                # Patrón general "Vendor Model Version"
                r'([A-Za-z0-9\-\_\.\+]+)\s+([A-Za-z0-9\-\_\.\+]+)\s+([0-9\.]+)',
                # Patrón para dispositivos Cisco
                r'Cisco\s+([A-Za-z0-9\-\_\.]+)',
                # Patrón para dispositivos Ubiquiti
                r'Ubiquiti\s+([A-Za-z0-9\-\_\.]+)',
                # Patrón para MikroTik RouterOS
                r'RouterOS\s+([0-9\.]+)',
                # Patrón para Windows con versión
                r'Windows\s+([A-Za-z0-9\-\_\.]+)',
                # Patrón para dispositivos móviles
                r'([A-Za-z0-9\-\_\.]+)\s+([A-Za-z0-9\-\_\.]+)\s+([A-Za-z0-9\-\_\.]+)',
            ]
            
            for pattern in model_patterns:
                match = re.search(pattern, os_str)
                if match:
                    if len(match.groups()) >= 3:
                        # Intento de extraer vendor/model/version
                        vendor_match = match.group(1)
                        model_match = match.group(2)
                        version_match = match.group(3)
                        potential_models.append((f"{model_match} {version_match}", 0.7))
                    elif len(match.groups()) >= 1:
                        # Al menos tenemos un componente
                        model_match = match.group(1)
                        potential_models.append((model_match, 0.6))
                    break
        
        # 2. Buscar modelo en banners de servicio si están disponibles
        service_signatures = [
            'http_signature', 'ssh_signature', 'rtsp_signature', 
            'snmp_signature', 'upnp_signature', 'mdns_signature'
        ]
        
        for sig_key in service_signatures:
            if sig_key in device_data and device_data[sig_key]:
                sig_value = device_data[sig_key]
                
                # Patrones para extraer modelo de banners
                banner_model_patterns = [
                    r'model[=:"\s]+([A-Za-z0-9\-\_\.\+\s]+?)[\s,">]',
                    r'product[=:"\s]+([A-Za-z0-9\-\_\.\+\s]+?)[\s,">]',
                    r'version[=:"\s]+([A-Za-z0-9\-\_\.\+\s]+?)[\s,">]',
                    r'([A-Za-z0-9\-\_\.]+)[-_\s]([A-Za-z0-9\-\_\.]+)[-_\s]([0-9\.]+)',
                ]
                
                for pattern in banner_model_patterns:
                    match = re.search(pattern, sig_value, re.IGNORECASE)
                    if match:
                        model_match = match.group(1).strip()
                        if len(model_match) > 2:  # Evitar coincidencias muy cortas
                            potential_models.append((model_match, 0.75))
        
        # 3. Crear modelo basado en tipo de dispositivo y fabricante si no tenemos otro modelo
        if 'device_type' in device_data and device_data['device_type'] and device_data['device_type'] != "Desconocido":
            device_type = device_data['device_type']
            
            if vendor != "Desconocido":
                # Construir un modelo genérico basado en el fabricante y el tipo
                generic_model = f"{vendor} {device_type}"
                potential_models.append((generic_model, 0.4))
            else:
                # Usar solo el tipo de dispositivo como modelo genérico
                potential_models.append((device_type, 0.3))
        
        # Seleccionar el modelo con mayor confianza
        if potential_models:
            potential_models.sort(key=lambda x: x[1], reverse=True)
            best_model, confidence = potential_models[0]
            return vendor, best_model, confidence
        
        return vendor, "Desconocido", 0.0
    
    def match_os(self, device_data: Dict) -> Tuple[str, float]:
        """
        Identifica el sistema operativo basado en la información disponible
        
        Args:
            device_data: Diccionario con información del dispositivo
            
        Returns:
            Tuple[str, float]: (os, confidence)
        """
        # Si ya tenemos OS definido, usarlo
        if 'os' in device_data and device_data['os'] and device_data['os'] != "Desconocido":
            return device_data['os'], 0.9
        
        # Intentar inferir OS basado en otra información
        potential_os = []
        
        # 1. Inferir OS por tipo de dispositivo
        if 'device_type' in device_data and device_data['device_type']:
            device_type = device_data['device_type']
            
            os_by_type = {
                'Router': [("RouterOS", 0.5), ("OpenWRT", 0.4), ("DD-WRT", 0.4), ("Embedded Linux", 0.3)],
                'Access Point': [("Embedded Linux", 0.5), ("Proprietary Firmware", 0.4)],
                'Switch': [("Embedded OS", 0.5), ("Proprietary Firmware", 0.4)],
                'IP Camera': [("Embedded Linux", 0.5), ("Proprietary Firmware", 0.4)],
                'Printer': [("Printer Firmware", 0.6), ("Embedded OS", 0.4)],
                'Smart TV': [("WebOS", 0.3), ("Tizen", 0.3), ("Android TV", 0.3), ("Roku OS", 0.3)],
                'Streaming Device': [("Android TV", 0.4), ("Roku OS", 0.4), ("tvOS", 0.4), ("Fire OS", 0.4)],
                'iPhone': [("iOS", 0.9)],
                'iPad': [("iPadOS", 0.9)],
                'Mac': [("macOS", 0.9)],
                'MacBook': [("macOS", 0.9)],
                'Android Device': [("Android", 0.9)],
                'Smartphone': [("Android", 0.7), ("iOS", 0.3)],
                'Windows PC': [("Windows", 0.9)],
                'Desktop PC': [("Windows", 0.6), ("Linux", 0.3), ("macOS", 0.1)],
                'Laptop': [("Windows", 0.6), ("macOS", 0.3), ("Linux", 0.1)],
                'Linux Server': [("Linux", 0.9)],
                'Windows Server': [("Windows Server", 0.9)],
                'NAS': [("Embedded Linux", 0.7), ("Proprietary NAS OS", 0.3)],
                'IoT Device': [("Embedded Linux", 0.6), ("RTOS", 0.3), ("Proprietary Firmware", 0.1)],
                'Smart Home Hub': [("Embedded Linux", 0.7), ("Proprietary Firmware", 0.3)],
                'Gaming Console': [("Proprietary Console OS", 0.9)],
                'PlayStation': [("PlayStation OS", 0.9)],
                'Xbox': [("Xbox OS", 0.9)],
                'Nintendo Switch': [("Nintendo Switch OS", 0.9)],
                'VoIP Phone': [("Embedded VoIP Firmware", 0.9)],
                'Smart Speaker': [("Proprietary Firmware", 0.9)],
                'Smart Display': [("Android", 0.5), ("Proprietary Firmware", 0.5)],
                'Network Appliance': [("Proprietary Firmware", 0.9)],
                'UPS': [("Embedded Firmware", 0.9)],
                'Smart Lock': [("Embedded Firmware", 0.9)],
                'Smart Thermostat': [("Embedded Firmware", 0.9)],
                'Network Storage': [("NAS OS", 0.9)],
                'DVR': [("Embedded DVR Firmware", 0.9)],
                'NVR': [("Embedded NVR Firmware", 0.9)],
                'Raspberry Pi': [("Raspbian", 0.7), ("Raspberry Pi OS", 0.7), ("Linux", 0.5)],
            }
            
            if device_type in os_by_type:
                potential_os.extend(os_by_type[device_type])
        
        # 2. Inferir OS por fabricante
        if 'vendor' in device_data and device_data['vendor']:
            vendor = device_data['vendor']
            
            os_by_vendor = {
                'Apple': [("iOS", 0.5), ("macOS", 0.5), ("tvOS", 0.3), ("watchOS", 0.3)],
                'Microsoft': [("Windows", 0.8), ("Windows Server", 0.6)],
                'Cisco': [("Cisco IOS", 0.8), ("Cisco IOS XE", 0.7), ("Cisco IOS XR", 0.6)],
                'Ubiquiti': [("EdgeOS", 0.7), ("UniFi OS", 0.7), ("AirOS", 0.6)],
                'MikroTik': [("RouterOS", 0.9)],
                'QNAP': [("QTS", 0.9)],
                'Synology': [("DSM", 0.9)],
                'Western Digital': [("My Cloud OS", 0.8)],
                'Samsung': [("Android", 0.6), ("Tizen", 0.6)],
                'Sony': [("Android", 0.5), ("PlayStation OS", 0.5)],
                'LG': [("WebOS", 0.7), ("Android", 0.5)],
                'Google': [("Android", 0.8), ("Chrome OS", 0.6)],
                'Amazon': [("Fire OS", 0.8), ("Embedded Linux", 0.6)],
                'Netgear': [("Netgear OS", 0.8)],
                'TP-Link': [("TP-Link OS", 0.8)],
                'D-Link': [("D-Link OS", 0.8)],
                'Linksys': [("Linksys OS", 0.8)],
                'Asus': [("ASUSWRT", 0.7), ("Android", 0.5), ("Windows", 0.5)],
                'Hikvision': [("Hikvision OS", 0.8)],
                'Dahua': [("Dahua OS", 0.8)],
                'Axis': [("AXIS OS", 0.8)],
                'HP': [("HP Firmware", 0.7), ("Windows", 0.5)],
                'Dell': [("Windows", 0.7), ("Linux", 0.3)],
                'Lenovo': [("Windows", 0.7), ("Linux", 0.3)],
                'Intel': [("Windows", 0.6), ("Linux", 0.4)],
                'Huawei': [("Android", 0.7), ("HarmonyOS", 0.6)],
                'Xiaomi': [("Android", 0.8), ("MIUI", 0.7)],
                'Raspberry Pi': [("Raspberry Pi OS", 0.8), ("Raspbian", 0.7)],
                'Arduino': [("Arduino Firmware", 0.9)],
                'Espressif': [("ESP Firmware", 0.9), ("RTOS", 0.7)],
            }
            
            if vendor in os_by_vendor:
                potential_os.extend(os_by_vendor[vendor])
        
        # 3. Inferir por información de puerto y servicio
        if 'open_ports' in device_data and device_data['open_ports']:
            open_ports = set(device_data['open_ports'])
            
            os_by_ports = {
                frozenset([80, 443, 22, 3306]): [("Linux Web Server", 0.7)],
                frozenset([80, 443, 3389]): [("Windows Web Server", 0.7)],
                frozenset([445, 139, 135]): [("Windows", 0.8)],
                frozenset([22, 111, 2049]): [("Linux NFS Server", 0.7)],
                frozenset([3389, 445, 139]): [("Windows Server", 0.8)],
                frozenset([8080, 8443, 8009]): [("Java Application Server", 0.7)],
                frozenset([80, 443, 8080, 8443]): [("Web Server", 0.6)],
                frozenset([5060, 5061]): [("VoIP System", 0.7)],
                frozenset([9100, 515, 631]): [("Printer OS", 0.8)],
                frozenset([554, 80, 443]): [("IP Camera OS", 0.8)],
                frozenset([1883, 8883]): [("IoT Platform", 0.7)],
                frozenset([2323, 23]): [("Embedded Device OS", 0.7)],
                frozenset([8009, 8008]): [("Chromecast OS", 0.8)],
                frozenset([548, 88, 5009]): [("macOS", 0.8)],
                frozenset([5000, 5353]): [("Audio Device OS", 0.7)],
            }
            
            for port_set, os_entries in os_by_ports.items():
                if len(port_set.intersection(open_ports)) == len(port_set):
                    potential_os.extend(os_entries)
        
        # Seleccionar el OS con mayor confianza
        if potential_os:
            potential_os.sort(key=lambda x: x[1], reverse=True)
            best_os, confidence = potential_os[0]
            return best_os, confidence
        
        return "Desconocido", 0.0
    
    def identify_device(self, device_data: Dict) -> Dict:
        """
        Identifica un dispositivo basado en toda la información disponible
        
        Args:
            device_data: Diccionario con información del dispositivo
            
        Returns:
            Dict: Diccionario con la información del dispositivo actualizada
        """
        # Hacer una copia para no modificar el original
        result = device_data.copy()
        
        # 1. Identificar tipo de dispositivo
        device_types = self.match_device_type(device_data)
        if device_types and device_types[0][0] != "Desconocido":
            result['device_type'] = device_types[0][0]
            result['device_type_confidence'] = device_types[0][1]
            # Guardar tipos alternativos para referencia
            result['alternative_types'] = device_types[1:5] if len(device_types) > 1 else []
        
        # 2. Identificar fabricante y modelo
        vendor, model, model_confidence = self.match_vendor_model(result)
        if vendor != "Desconocido":
            result['vendor'] = vendor
        if model != "Desconocido":
            result['model'] = model
            result['model_confidence'] = model_confidence
        
        # 3. Identificar sistema operativo
        os_name, os_confidence = self.match_os(result)
        if os_name != "Desconocido":
            result['os'] = os_name
            result['os_confidence'] = os_confidence
        
        # 4. Calcular confianza general
        confidences = [
            result.get('device_type_confidence', 0.0),
            result.get('model_confidence', 0.0),
            result.get('os_confidence', 0.0)
        ]
        
        valid_confidences = [c for c in confidences if c > 0.0]
        if valid_confidences:
            result['confidence'] = sum(valid_confidences) / len(valid_confidences)
        else:
            result['confidence'] = 0.0
        
        return result