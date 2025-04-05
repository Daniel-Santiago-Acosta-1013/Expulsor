# Guía de Empaquetado para Expulsor

Este documento explica cómo empaquetar Expulsor para distribución en diferentes sistemas operativos (Windows y macOS).

## Prerrequisitos

### Para todas las plataformas
- Python 3.8 o superior
- Poetry (para gestión de dependencias)
- PyInstaller (Windows) o py2app (macOS) para empaquetado

### Para Windows
- NSIS (Nullsoft Scriptable Install System)
  - Descargar e instalar desde: https://nsis.sourceforge.io/Download
  - Asegurarse de que NSIS esté en el PATH

### Para macOS
- py2app: `pip install py2app`
- dmgbuild: `pip install dmgbuild`
- XCode Command Line Tools: `xcode-select --install`

## Creación de iconos

### Para Windows (icon.ico)
1. Crear una imagen de 256x256 píxeles
2. Convertirla a formato ICO usando herramientas como:
   - https://convertico.com/
   - https://icoconvert.com/

### Para macOS (icon.icns)
1. Crear imágenes en diferentes tamaños (16x16, 32x32, 64x64, 128x128, 256x256, 512x512, 1024x1024)
2. Usar iconutil para convertir a formato icns:
   ```bash
   mkdir MyIcon.iconset
   sips -z 16 16 original.png --out MyIcon.iconset/icon_16x16.png
   sips -z 32 32 original.png --out MyIcon.iconset/icon_16x16@2x.png
   # Repetir para otros tamaños
   iconutil -c icns MyIcon.iconset
   ```

## Empaquetado para Windows

1. Asegurarse de que NSIS está instalado y en el PATH
2. Colocar el icono en `resources/icon.ico` (opcional)
3. Ejecutar el script de empaquetado:
   ```bash
   python build_windows.py
   ```
4. El instalador se generará como `Expulsor-1.0.0-Setup.exe` en el directorio raíz

### Características del instalador de Windows
- Detecta si Nmap está instalado
- Descarga e instala Nmap automáticamente si es necesario
- Crea accesos directos en el escritorio y menú inicio
- Incluye desinstalador

## Empaquetado para macOS

1. Asegurarse de que py2app y dmgbuild están instalados
2. Colocar el icono en `resources/icon.icns` (opcional)
3. Ejecutar el script de empaquetado:
   ```bash
   python build_macos.py
   ```
4. El archivo DMG se generará como `Expulsor-1.0.0.dmg` en el directorio raíz

### Características del instalador de macOS
- La primera vez que se ejecuta, verifica si Nmap está instalado
- Si Nmap no está instalado, ofrece instalarlo automáticamente
- Intenta instalar primero usando Homebrew
- Si Homebrew no está disponible, descarga e instala el paquete oficial

## Personalización

### Para cambiar la versión
Modificar la variable `APP_VERSION` en los scripts `build_windows.py` y `build_macos.py`.

### Para cambiar el nombre de la aplicación
Modificar la variable `APP_NAME` en los scripts `build_windows.py` y `build_macos.py`.

## Notas importantes

1. **Permisos en macOS**: Debido a las políticas de seguridad de macOS, es posible que se muestre una advertencia al abrir la aplicación por primera vez. El usuario deberá aprobar la ejecución en Preferencias del Sistema > Seguridad y Privacidad.

2. **Firma de código**: Estos scripts no incluyen firma de código. Para distribución comercial, se debería considerar firmar la aplicación con un certificado de desarrollador.

3. **Instalación de Nmap**: Ambos instaladores intentarán detectar e instalar Nmap si no está presente. Sin embargo, puede que requieran privilegios de administrador para hacerlo.

4. **Tamaño del paquete**: La aplicación empaquetada puede ser grande (>100MB) debido a la inclusión de todas las dependencias de Python.