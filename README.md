# Expulsor - Herramienta Avanzada de Control de Red

Expulsor es una herramienta de seguridad de red que permite escanear, monitorear y controlar dispositivos dentro de una red local. El proyecto combina las capacidades avanzadas de manipulación de paquetes de Scapy con una interfaz gráfica moderna desarrollada con PyQt6.

## Características

- **Interfaz Gráfica Moderna**: Diseño intuitivo y responsive con PyQt6 para una mejor experiencia de usuario.
- **Escaneo Avanzado de Red**: Detecta todos los dispositivos en la red local con información detallada.
- **Información Detallada de Dispositivos**: Muestra IP, MAC, fabricante, nombre del host y más.
- **Control de Acceso**: Capacidad para restringir el acceso a internet de dispositivos específicos mediante técnicas de ARP Spoofing.
- **Monitoreo en Tiempo Real**: Visualización del estado de los dispositivos en la red.
- **Gestión de Dependencias**: Utiliza Poetry para un manejo eficiente de dependencias y entorno virtual.

## Instalación

### Prerequisitos
- Python 3.8+
- Poetry

### Pasos de Instalación

1. Clona el repositorio:
```bash
git clone git@github.com:Daniel-Santiago-Acosta-1013/Expulsor.git
cd expulsor
```

2. Instala las dependencias usando Poetry:
```bash
poetry install
```

3. Inicia la aplicación:
```bash
poetry run expulsor
```

## Uso

1. Al iniciar la aplicación, se mostrará la ventana principal.
2. Haz clic en "Escanear Red" para detectar todos los dispositivos conectados.
3. Selecciona cualquier dispositivo de la lista para ver información detallada.
4. Para restringir el acceso a internet de un dispositivo, selecciónalo y haz clic en "Bloquear Acceso".
5. Para restaurar el acceso, haz clic en "Restaurar Acceso".

## Consideraciones Éticas y Legales

Esta herramienta está diseñada con propósitos educativos y de seguridad para redes propias. El uso indebido de esta herramienta puede violar leyes de privacidad y seguridad informática. Solo debe utilizarse:

- En redes donde tienes permiso explícito para realizar pruebas
- Para proteger tu propia red de dispositivos no autorizados
- Con fines educativos en entornos controlados

El autor no se hace responsable del mal uso que se pueda dar a esta herramienta.

## Tecnologías Utilizadas

- **Scapy**: Para la manipulación de paquetes y comunicación de red
- **PyQt6**: Para la interfaz gráfica de usuario
- **Poetry**: Para la gestión de dependencias y entorno virtual
- **netifaces**: Para obtener información de las interfaces de red
- **python-nmap**: Para escaneo avanzado de puertos y servicios