"""
Script para empaquetar Expulsor en Windows
Crea un instalador que incluye la aplicación y Nmap
"""

import os
import sys
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path


# Configuración
APP_NAME = "Expulsor"
APP_VERSION = "1.0.0"
NMAP_URL = "https://nmap.org/dist/nmap-7.94-setup.exe"
NSIS_TEMPLATE = r"""
; Instalador de Expulsor
; Creado con NSIS

!include "MUI2.nsh"
!include "LogicLib.nsh"

; Configuración general
Name "${APP_NAME}"
OutFile "${INSTALLER_NAME}"
InstallDir "$PROGRAMFILES\${APP_NAME}"
InstallDirRegKey HKCU "Software\${APP_NAME}" ""
RequestExecutionLevel admin

; Páginas del instalador
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${LICENSE_FILE}"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Páginas de desinstalación
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Idiomas
!insertmacro MUI_LANGUAGE "Spanish"

; Secciones
Section "${APP_NAME}" SecApp
  SectionIn RO
  SetOutPath "$INSTDIR"
  
  ; Archivos de la aplicación
  File /r "${DIST_DIR}\*.*"
  
  ; Crear accesos directos
  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\${EXE_NAME}"
  CreateShortcut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${EXE_NAME}"
  
  ; Registrar desinstalador
  WriteRegStr HKCU "Software\${APP_NAME}" "" $INSTDIR
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "DisplayVersion" "${APP_VERSION}"
SectionEnd

Section "Nmap (Requerido)" SecNmap
  SectionIn RO
  SetOutPath "$TEMP"
  
  ; Descargar e instalar Nmap si no está instalado
  IfFileExists "$PROGRAMFILES\Nmap\nmap.exe" NmapInstalled
    File "${NMAP_INSTALLER}"
    DetailPrint "Instalando Nmap..."
    ExecWait '"$TEMP\${NMAP_INSTALLER_NAME}" /S'
    Delete "$TEMP\${NMAP_INSTALLER_NAME}"
  NmapInstalled:
    DetailPrint "Nmap ya está instalado o se ha instalado correctamente."
SectionEnd

; Desinstalador
Section "Uninstall"
  ; Eliminar archivos de la aplicación
  RMDir /r "$INSTDIR"
  
  ; Eliminar accesos directos
  Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
  Delete "$DESKTOP\${APP_NAME}.lnk"
  RMDir "$SMPROGRAMS\${APP_NAME}"
  
  ; Eliminar registros
  DeleteRegKey HKCU "Software\${APP_NAME}"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"
  
  ; No desinstalamos Nmap porque puede ser usado por otros programas
SectionEnd
"""


def check_requirements():
    """Verifica que estén instalados todos los requisitos para compilar"""
    try:
        # Verificar que PyInstaller esté instalado
        subprocess.run(['pyinstaller', '--version'], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE, 
                      check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        print("ERROR: PyInstaller no está instalado. Instálelo con 'pip install pyinstaller'")
        return False
    
    # Verificar que NSIS esté instalado (Windows)
    try:
        subprocess.run(['makensis', '/VERSION'], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE, 
                      check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        print("ERROR: NSIS no está instalado o no está en el PATH.")
        print("Descargue e instale NSIS desde https://nsis.sourceforge.io/Download")
        return False
    
    return True


def download_nmap_installer():
    """Descarga el instalador de Nmap"""
    temp_dir = tempfile.gettempdir()
    nmap_installer_path = os.path.join(temp_dir, "nmap_setup.exe")
    
    if not os.path.exists(nmap_installer_path):
        print(f"Descargando instalador de Nmap desde {NMAP_URL}...")
        try:
            urllib.request.urlretrieve(NMAP_URL, nmap_installer_path)
        except Exception as e:
            print(f"Error al descargar Nmap: {e}")
            return None
    
    return nmap_installer_path


def create_license_file():
    """Crea un archivo de licencia temporal para el instalador"""
    license_content = """Acuerdo de Licencia para Expulsor

Copyright (c) 2025 Santiago Acosta

Este software se proporciona 'tal cual', sin garantía de ningún tipo. 
En ningún caso el autor será responsable de cualquier daño derivado del uso de este software.

El uso de esta herramienta para atacar redes sin autorización es ilegal.
Solo debe utilizarse en redes propias o con permiso explícito.

Nmap y otras herramientas incluidas tienen sus propias licencias.
Nmap está disponible bajo la licencia Nmap (https://nmap.org/book/man-legal.html).
"""
    
    temp_dir = tempfile.gettempdir()
    license_path = os.path.join(temp_dir, "license.txt")
    
    with open(license_path, 'w', encoding='utf-8') as f:
        f.write(license_content)
    
    return license_path


def build_with_pyinstaller():
    """Construye la aplicación con PyInstaller"""
    print("Empaquetando Expulsor con PyInstaller...")
    
    # Obtener directorio raíz del proyecto
    project_dir = Path(__file__).parent.resolve()
    
    # Crear especificación para PyInstaller
    spec_content = f"""# -*- mode: python -*-

block_cipher = None

a = Analysis(
    ['{project_dir / "expulsor" / "main.py"}'],
    pathex=['{project_dir}'],
    binaries=[],
    datas=[],
    hiddenimports=['scapy.layers.all', 'PyQt6', 'netifaces'],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='{APP_NAME}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    runtime_tmpdir=None,
    console=False,
    icon='{project_dir / "resources" / "icon.ico"}' if os.path.exists('{project_dir / "resources" / "icon.ico"}') else None
)
"""
    
    # Escribir el archivo spec para PyInstaller
    spec_path = os.path.join(project_dir, f"{APP_NAME.lower()}.spec")
    with open(spec_path, 'w') as f:
        f.write(spec_content)
    
    # Ejecutar PyInstaller
    build_dir = os.path.join(project_dir, "build")
    dist_dir = os.path.join(project_dir, "dist")
    
    # Limpiar directorios de compilación anteriores
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir)
    if os.path.exists(dist_dir):
        shutil.rmtree(dist_dir)
    
    # Compilar con PyInstaller
    result = subprocess.run(
        ['pyinstaller', spec_path, '--clean', '--distpath', dist_dir, '--workpath', build_dir],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    if result.returncode != 0:
        print("Error al compilar con PyInstaller:")
        print(result.stderr)
        return None
    
    print(f"Aplicación empaquetada en: {dist_dir}/{APP_NAME}")
    return dist_dir


def create_installer(dist_dir, nmap_installer):
    """Crea el instalador con NSIS"""
    print("Creando instalador con NSIS...")
    
    # Directorio del proyecto
    project_dir = Path(__file__).parent.resolve()
    
    # Obtener nombre del archivo exe generado por PyInstaller
    exe_name = f"{APP_NAME}.exe"
    
    # Nombre del instalador final
    installer_name = f"{APP_NAME}-{APP_VERSION}-Setup.exe"
    
    # Crear archivo de licencia
    license_file = create_license_file()
    
    # Crear script NSIS
    nsis_script = NSIS_TEMPLATE.replace("${APP_NAME}", APP_NAME)
    nsis_script = nsis_script.replace("${APP_VERSION}", APP_VERSION)
    nsis_script = nsis_script.replace("${INSTALLER_NAME}", installer_name)
    nsis_script = nsis_script.replace("${DIST_DIR}", str(dist_dir).replace("\\", "\\\\"))
    nsis_script = nsis_script.replace("${EXE_NAME}", exe_name)
    nsis_script = nsis_script.replace("${LICENSE_FILE}", license_file.replace("\\", "\\\\"))
    nsis_script = nsis_script.replace("${NMAP_INSTALLER}", nmap_installer.replace("\\", "\\\\"))
    nsis_script = nsis_script.replace("${NMAP_INSTALLER_NAME}", os.path.basename(nmap_installer))
    
    # Escribir script NSIS a un archivo temporal
    nsis_path = os.path.join(tempfile.gettempdir(), "expulsor_installer.nsi")
    with open(nsis_path, 'w') as f:
        f.write(nsis_script)
    
    # Ejecutar NSIS para crear el instalador
    result = subprocess.run(
        ['makensis', nsis_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    if result.returncode != 0:
        print("Error al crear el instalador con NSIS:")
        print(result.stderr)
        return None
    
    # Mover instalador al directorio raíz del proyecto
    installer_path = os.path.join(os.path.dirname(nsis_path), installer_name)
    final_path = os.path.join(project_dir, installer_name)
    
    if os.path.exists(installer_path):
        shutil.move(installer_path, final_path)
        print(f"Instalador creado en: {final_path}")
        return final_path
    else:
        print(f"Error: No se encontró el instalador generado en {installer_path}")
        return None


def main():
    """Función principal"""
    print(f"=== Empaquetando {APP_NAME} v{APP_VERSION} para Windows ===")
    
    # Verificar requisitos
    if not check_requirements():
        sys.exit(1)
    
    # Descargar instalador de Nmap
    nmap_installer = download_nmap_installer()
    if not nmap_installer:
        sys.exit(1)
    
    # Construir con PyInstaller
    dist_dir = build_with_pyinstaller()
    if not dist_dir:
        sys.exit(1)
    
    # Crear instalador
    installer_path = create_installer(dist_dir, nmap_installer)
    if not installer_path:
        sys.exit(1)
    
    print(f"=== ¡{APP_NAME} v{APP_VERSION} empaquetado exitosamente! ===")
    print(f"Instalador: {installer_path}")


if __name__ == "__main__":
    main()