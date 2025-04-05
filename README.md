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
- Nmap (requerido para escaneo de puertos y detección de servicios)
- Privilegios de administrador/root (requerido para ARP spoofing y manipulación de paquetes)

### Instalación de Nmap

Nmap es una herramienta esencial para Expulsor ya que permite realizar escaneo avanzado de puertos y detección de servicios. A continuación se detallan las instrucciones para instalar Nmap en diferentes sistemas operativos:

#### Linux
En distribuciones basadas en Debian/Ubuntu:
```bash
sudo apt update
sudo apt install nmap
```

En distribuciones basadas en Red Hat/Fedora:
```bash
sudo dnf install nmap
```

En distribuciones basadas en Arch:
```bash
sudo pacman -S nmap
```

#### macOS
Usando Homebrew:
```bash
brew install nmap
```

O usando MacPorts:
```bash
sudo port install nmap
```

#### Windows
1. Descargar el instalador desde la [página oficial de Nmap](https://nmap.org/download.html)
2. Ejecutar el instalador y seguir las instrucciones en pantalla
3. Asegurarse de que la opción para instalar Npcap esté seleccionada durante la instalación

Para verificar que Nmap está correctamente instalado, ejecute en una terminal:
```bash
nmap --version
```

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

3. Inicia la aplicación (con privilegios de administrador/root):
```bash
sudo poetry run expulsor
```

**Nota**: Expulsor requiere privilegios de administrador/root para funcionar correctamente debido a las operaciones de bajo nivel que realiza (ARP spoofing, escaneo de puertos, etc.). Asegúrate de ejecutar la aplicación con permisos elevados.

## Uso

1. Al iniciar la aplicación, se mostrará la ventana principal.
2. Haz clic en "Escanear Red" para detectar todos los dispositivos conectados.
3. Selecciona cualquier dispositivo de la lista para ver información detallada.
4. Para restringir el acceso a internet de un dispositivo, selecciónalo y haz clic en "Bloquear Acceso".
5. Para restaurar el acceso, haz clic en "Restaurar Acceso".
6. Puedes configurar los modos de bloqueo (bloqueo real o solo monitorización) en el menú "Herramientas > Configurar Bloqueo".

## Consideraciones Éticas y Legales

Esta herramienta está diseñada con propósitos educativos y de seguridad para redes propias. El uso indebido de esta herramienta puede violar leyes de privacidad y seguridad informática. Solo debe utilizarse:

- En redes donde tienes permiso explícito para realizar pruebas
- Para proteger tu propia red de dispositivos no autorizados
- Con fines educativos en entornos controlados

El autor no se hace responsable del mal uso que se pueda dar a esta herramienta.

## Resolución de Problemas

### Problemas con el Bloqueo de Dispositivos
Si los dispositivos continúan teniendo acceso a internet después de intentar bloquearlos:

1. Verifica que estés ejecutando Expulsor con privilegios de administrador/root
2. Asegúrate de que el "Modo de Bloqueo" esté activado en "Herramientas > Configurar Bloqueo"
3. Comprueba que el reenvío de IP esté correctamente deshabilitado durante el bloqueo
4. En algunos routers o dispositivos con protección avanzada, es posible que el ARP spoofing no sea efectivo

### Problemas con el Escaneo de Red
Si el escaneo de red no detecta todos los dispositivos o no muestra información detallada:

1. Verifica que Nmap esté correctamente instalado ejecutando `nmap --version` en una terminal
2. Asegúrate de que la aplicación tenga los permisos necesarios para realizar escaneos

## Tecnologías Utilizadas

- **Scapy**: Para la manipulación de paquetes y comunicación de red
- **PyQt6**: Para la interfaz gráfica de usuario
- **Nmap**: Herramienta fundamental para el escaneo avanzado de puertos, detección de servicios y fingerprinting de sistemas operativos
- **netifaces**: Para obtener información de las interfaces de red
- **Poetry**: Para la gestión de dependencias y entorno virtual

## Contribución

Las contribuciones son bienvenidas. Si deseas mejorar Expulsor, por favor sigue estos pasos:

1. Haz fork del repositorio
2. Crea una rama para tu funcionalidad (`git checkout -b feature/nueva-funcionalidad`)
3. Realiza tus cambios y haz commit (`git commit -am 'Añade nueva funcionalidad'`)
4. Haz push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crea un Pull Request