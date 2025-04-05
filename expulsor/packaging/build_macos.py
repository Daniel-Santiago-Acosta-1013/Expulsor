"""
Script para empaquetar Expulsor en macOS
Crea un archivo .dmg que incluye la aplicación con soporte para Nmap
"""

import os
import sys
import shutil
import plistlib
import subprocess
from pathlib import Path

# Configuración
APP_NAME = "Expulsor"
APP_VERSION = "1.0.0"
BUNDLE_IDENTIFIER = "com.securitytools.expulsor"


def check_requirements():
    """Verifica que estén instalados todos los requisitos para compilar"""
    try:
        # Verificar que py2app esté instalado
        subprocess.run(['pip', 'show', 'py2app'], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE, 
                      check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        print("ERROR: py2app no está instalado. Instálelo con 'pip install py2app'")
        return False
    
    try:
        # Verificar que dmgbuild esté instalado
        subprocess.run(['pip', 'show', 'dmgbuild'], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE, 
                      check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        print("ERROR: dmgbuild no está instalado. Instálelo con 'pip install dmgbuild'")
        return False
    
    try:
        # Verificar que Poetry esté instalado
        subprocess.run(['poetry', '--version'], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE, 
                      check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        print("ERROR: Poetry no está instalado. Instálelo según las instrucciones en https://python-poetry.org/docs/#installation")
        return False
    
    return True


def create_setup_py():
    """Crea un archivo setup.py para py2app"""
    project_dir = Path(__file__).parent.resolve()
    setup_py_path = project_dir / "setup.py"
    
    # Contenido del archivo setup.py
    setup_content = f"""
import sys
from setuptools import setup

APP = ['{project_dir / "expulsor" / "main.py"}']
DATA_FILES = []
OPTIONS = {{
    'argv_emulation': True,
    'plist': {{
        'CFBundleName': '{APP_NAME}',
        'CFBundleDisplayName': '{APP_NAME}',
        'CFBundleGetInfoString': '{APP_NAME} {APP_VERSION}',
        'CFBundleIdentifier': '{BUNDLE_IDENTIFIER}',
        'CFBundleVersion': '{APP_VERSION}',
        'CFBundleShortVersionString': '{APP_VERSION}',
        'NSHumanReadableCopyright': '© 2025 Santiago Acosta',
        'NSPrincipalClass': 'NSApplication',
        'NSHighResolutionCapable': True,
        'LSRequiresNativeExecution': True,
        'LSMinimumSystemVersion': '10.14',
        'LSEnvironment': {{
            'PATH': '/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin',
        }},
    }},
    'packages': ['PyQt6', 'scapy', 'netifaces', 'nmap'],
    'includes': ['PyQt6.QtCore', 'PyQt6.QtWidgets', 'PyQt6.QtGui'],
    'excludes': ['tkinter'],
    'iconfile': '{project_dir / "resources" / "icon.icns"}' if os.path.exists('{project_dir / "resources" / "icon.icns"}') else None,
}}

setup(
    name='{APP_NAME}',
    app=APP,
    data_files=DATA_FILES,
    options={{'py2app': OPTIONS}},
    setup_requires=['py2app'],
)
"""
    
    with open(setup_py_path, 'w') as f:
        f.write(setup_content)
    
    return setup_py_path


def create_nmap_installer_script():
    """Crea un script que verifica e instala Nmap durante el primer lanzamiento"""
    project_dir = Path(__file__).parent.resolve()
    script_dir = project_dir / "resources"
    script_dir.mkdir(exist_ok=True)
    
    install_script_path = script_dir / "install_nmap.sh"
    
    script_content = """#!/bin/bash

# Script de instalación de Nmap para Expulsor
# Este script se ejecuta automáticamente en el primer lanzamiento

# Función para verificar si Nmap está instalado
check_nmap() {
    if command -v nmap >/dev/null 2>&1; then
        echo "✅ Nmap está instalado correctamente."
        return 0
    else
        return 1
    fi
}

# Función para instalar Nmap usando Homebrew
install_nmap_brew() {
    echo "🔄 Instalando Nmap usando Homebrew..."
    
    # Verificar si Homebrew está instalado
    if ! command -v brew >/dev/null 2>&1; then
        echo "❌ Homebrew no está instalado. Intentando instalación manual..."
        return 1
    fi
    
    brew install nmap
    
    if [ $? -eq 0 ]; then
        echo "✅ Nmap instalado correctamente con Homebrew."
        return 0
    else
        echo "❌ Error al instalar Nmap con Homebrew."
        return 1
    fi
}

# Función para instalar Nmap manualmente
install_nmap_manual() {
    echo "🔄 Instalando Nmap manualmente..."
    
    # Crear directorio temporal
    TMP_DIR=$(mktemp -d)
    DMG_PATH="$TMP_DIR/nmap.dmg"
    
    # Descargar DMG de Nmap
    echo "📥 Descargando Nmap..."
    curl -L -o "$DMG_PATH" "https://nmap.org/dist/nmap-7.94.dmg"
    
    if [ $? -ne 0 ]; then
        echo "❌ Error al descargar Nmap."
        rm -rf "$TMP_DIR"
        return 1
    fi
    
    # Montar DMG
    echo "📂 Montando imagen DMG..."
    hdiutil attach "$DMG_PATH" -nobrowse
    
    if [ $? -ne 0 ]; then
        echo "❌ Error al montar la imagen DMG."
        rm -rf "$TMP_DIR"
        return 1
    fi
    
    # Buscar el instalador PKG
    PKG_PATH=$(find /Volumes/Nmap -name "*.pkg" -depth 1 | head -n 1)
    
    if [ -z "$PKG_PATH" ]; then
        echo "❌ No se encontró el instalador PKG."
        hdiutil detach "/Volumes/Nmap" -force
        rm -rf "$TMP_DIR"
        return 1
    fi
    
    # Instalar el paquete
    echo "🔄 Instalando Nmap. Se solicitará su contraseña de administrador..."
    sudo installer -pkg "$PKG_PATH" -target /
    
    if [ $? -ne 0 ]; then
        echo "❌ Error al instalar Nmap."
        hdiutil detach "/Volumes/Nmap" -force
        rm -rf "$TMP_DIR"
        return 1
    fi
    
    # Desmontar y limpiar
    hdiutil detach "/Volumes/Nmap" -force
    rm -rf "$TMP_DIR"
    
    echo "✅ Nmap instalado correctamente de forma manual."
    return 0
}

# Función principal
main() {
    echo "🔍 Verificando Nmap..."
    
    # Verificar si Nmap ya está instalado
    if check_nmap; then
        exit 0
    fi
    
    # Mostrar mensaje al usuario
    osascript -e 'display dialog "Nmap es necesario para el funcionamiento completo de Expulsor pero no está instalado. ¿Desea instalarlo ahora?" buttons {"Sí", "No"} default button "Sí" with title "Nmap Requerido" with icon caution'
    
    if [ $? -ne 0 ]; then
        osascript -e 'display dialog "Expulsor tendrá funcionalidad limitada sin Nmap. Se recomienda instalarlo manualmente." buttons {"OK"} default button "OK" with title "Funcionalidad Limitada" with icon caution'
        exit 1
    fi
    
    # Intentar instalar con Homebrew primero
    install_nmap_brew
    
    # Si falló, intentar instalación manual
    if ! check_nmap; then
        install_nmap_manual
    fi
    
    # Verificar de nuevo
    if check_nmap; then
        osascript -e 'display dialog "Nmap se ha instalado correctamente." buttons {"OK"} default button "OK" with title "Instalación Completada" with icon note'
        exit 0
    else
        osascript -e 'display dialog "No se pudo instalar Nmap automáticamente. Por favor, instálelo manualmente desde https://nmap.org/download.html" buttons {"OK"} default button "OK" with title "Error de Instalación" with icon stop'
        exit 1
    fi
}

# Ejecutar función principal
main
"""
    
    with open(install_script_path, 'w') as f:
        f.write(script_content)
    
    # Hacerlo ejecutable
    os.chmod(install_script_path, 0o755)
    
    return install_script_path


def create_launcher_script():
    """Crea un script launcher para verificar e instalar Nmap antes de iniciar la aplicación"""
    project_dir = Path(__file__).parent.resolve()
    script_dir = project_dir / "resources"
    script_dir.mkdir(exist_ok=True)
    
    launcher_path = script_dir / "launcher.sh"
    
    script_content = """#!/bin/bash

# Ruta al script de instalación de Nmap
INSTALL_SCRIPT="$PWD/Resources/install_nmap.sh"

# Ruta al archivo de verificación
NMAP_CHECK_FILE="$HOME/.expulsor/nmap_installed"

# Verificar si ya se ejecutó el instalador
if [ ! -f "$NMAP_CHECK_FILE" ]; then
    # Crear directorio si no existe
    mkdir -p "$HOME/.expulsor"
    
    # Ejecutar el script de instalación
    "$INSTALL_SCRIPT"
    
    # Marcar como ejecutado
    touch "$NMAP_CHECK_FILE"
fi

# Iniciar la aplicación principal
exec "$PWD/MacOS/Expulsor"
"""
    
    with open(launcher_path, 'w') as f:
        f.write(script_content)
    
    # Hacerlo ejecutable
    os.chmod(launcher_path, 0o755)
    
    return launcher_path


def modify_app_for_nmap_check(app_path):
    """Modifica la aplicación para incluir verificación de Nmap"""
    print("Modificando aplicación para incluir instalador de Nmap...")
    
    install_script = create_nmap_installer_script()
    launcher_script = create_launcher_script()
    
    # Copiar scripts al bundle
    resources_dir = Path(app_path) / "Contents" / "Resources"
    shutil.copy(install_script, resources_dir)
    
    # Crear directorio MacOS original (como respaldo)
    original_macos_dir = Path(app_path) / "Contents" / "MacOS.original"
    macos_dir = Path(app_path) / "Contents" / "MacOS"
    
    # Mover el binario original
    os.rename(macos_dir, original_macos_dir)
    os.mkdir(macos_dir)
    
    # Copiar el binario original a su ubicación
    for file in original_macos_dir.iterdir():
        if file.is_file():
            shutil.copy(file, macos_dir / file.name)
    
    # Copiar el script de lanzamiento
    shutil.copy(launcher_script, macos_dir / "Expulsor")
    
    # Asegurar permisos
    os.chmod(macos_dir / "Expulsor", 0o755)
    
    # Actualizar Info.plist para usar el launcher
    info_plist_path = Path(app_path) / "Contents" / "Info.plist"
    with open(info_plist_path, 'rb') as f:
        info_plist = plistlib.load(f)
    
    # Asegurar que se use el launcher como ejecutable principal
    info_plist['CFBundleExecutable'] = "Expulsor"
    
    with open(info_plist_path, 'wb') as f:
        plistlib.dump(info_plist, f)
    
    print(f"Aplicación modificada exitosamente en {app_path}")


def build_with_py2app():
    """Construye la aplicación con py2app"""
    print("Empaquetando Expulsor con py2app...")
    
    # Obtener directorio raíz del proyecto
    project_dir = Path(__file__).parent.resolve()
    
    # Crear setup.py
    setup_py = create_setup_py()
    
    # Instalar dependencias con Poetry
    subprocess.run(['poetry', 'install'], 
                  stdout=subprocess.PIPE, 
                  stderr=subprocess.PIPE,
                  cwd=project_dir,
                  check=True)
    
    # Activar entorno virtual de Poetry
    poetry_env = subprocess.run(['poetry', 'env', 'info', '--path'], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE,
                               cwd=project_dir,
                               text=True,
                               check=True).stdout.strip()
    
    # Ejecutar py2app
    env = os.environ.copy()
    env['PATH'] = f"{os.path.join(poetry_env, 'bin')}:{env['PATH']}"
    
    # Limpiar directorio build anterior si existe
    dist_dir = project_dir / "dist"
    build_dir = project_dir / "build"
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    if build_dir.exists():
        shutil.rmtree(build_dir)
    
    result = subprocess.run(
        ['python', 'setup.py', 'py2app'],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=project_dir
    )
    
    if result.returncode != 0:
        print("Error al compilar con py2app:")
        print(result.stderr)
        return None
    
    # Verificar que la aplicación se creó correctamente
    app_path = dist_dir / f"{APP_NAME}.app"
    if not app_path.exists():
        print(f"Error: No se encontró la aplicación en {app_path}")
        return None
    
    print(f"Aplicación creada en: {app_path}")
    
    # Modificar la aplicación para incluir la verificación de Nmap
    modify_app_for_nmap_check(app_path)
    
    return app_path


def create_dmg(app_path):
    """Crea un archivo DMG con la aplicación"""
    print("Creando archivo DMG...")
    
    # Directorio del proyecto
    project_dir = Path(__file__).parent.resolve()
    
    # Nombre del archivo DMG
    dmg_name = f"{APP_NAME}-{APP_VERSION}.dmg"
    dmg_path = project_dir / dmg_name
    
    # Crear script para dmgbuild
    dmg_settings = f"""
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import biplist
import os.path

#
# Configuración del archivo DMG
#

# Volumen / Nombre del archivo
volume_name = '{APP_NAME}'
format = 'UDBZ'
size = None

# Archivos a incluir
files = [ '{app_path}' ]

# Algunas configuraciones para el dmg
icon_locations = {{
    '{APP_NAME}.app': (140, 120),
    'Applications': (500, 120)
}}

background = 'builtin-arrow'

show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False

# Mostrar ventana de tamaño personalizado
window_rect = ((100, 100), (640, 280))

# Agregar un symlink a /Applications
symlinks = {{ 'Applications': '/Applications' }}

# Badge para el icono
badge_icon = None
"""
    
    # Escribir configuración a un archivo temporal
    dmg_settings_path = project_dir / "dmg_settings.py"
    with open(dmg_settings_path, 'w') as f:
        f.write(dmg_settings)
    
    # Crear DMG
    result = subprocess.run(
        ['dmgbuild', '-s', 'dmg_settings.py', APP_NAME, dmg_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=project_dir
    )
    
    # Limpiar archivo de configuración
    dmg_settings_path.unlink()
    
    if result.returncode != 0:
        print("Error al crear el DMG:")
        print(result.stderr)
        return None
    
    print(f"DMG creado en: {dmg_path}")
    return dmg_path


def main():
    """Función principal"""
    print(f"=== Empaquetando {APP_NAME} v{APP_VERSION} para macOS ===")
    
    # Verificar requisitos
    if not check_requirements():
        sys.exit(1)
    
    # Construir con py2app
    app_path = build_with_py2app()
    if not app_path:
        sys.exit(1)
    
    # Crear DMG
    dmg_path = create_dmg(app_path)
    if not dmg_path:
        sys.exit(1)
    
    print(f"=== ¡{APP_NAME} v{APP_VERSION} empaquetado exitosamente! ===")
    print(f"Archivo DMG: {dmg_path}")


if __name__ == "__main__":
    main()