"""
Punto de entrada principal para la aplicación Expulsor
"""

import os
import sys
import argparse
import platform
import subprocess
import tempfile
import time
import shutil
import urllib.request

from PyQt6.QtWidgets import QApplication, QMessageBox


def check_permissions():
    """Verifica si el programa tiene los permisos necesarios para funcionar"""
    
    # En Linux y macOS, verificar si se está ejecutando como root/sudo
    if platform.system() in ('Linux', 'Darwin'):
        if os.geteuid() != 0:
            print("⚠️  ADVERTENCIA: Esta aplicación requiere privilegios de administrador para funcionar correctamente.")
            print("    Por favor, ejecuta el programa con 'sudo' o como usuario root.")
            return False
    # En Windows, verificar si se está ejecutando como administrador
    elif platform.system() == 'Windows':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("⚠️  ADVERTENCIA: Esta aplicación requiere privilegios de administrador para funcionar correctamente.")
                print("    Por favor, ejecuta el programa como administrador.")
                return False
        except:
            print("⚠️  No se pudo verificar los privilegios de administrador. Algunas funciones podrían no estar disponibles.")
    
    return True


def check_nmap_installed():
    """Verifica si Nmap está instalado en el sistema"""
    try:
        # Intentar ejecutar nmap --version para verificar si está instalado
        result = subprocess.run(['nmap', '--version'], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE, 
                               text=True,
                               check=False)
        
        # Si el comando se ejecutó con éxito, Nmap está instalado
        if result.returncode == 0 and 'Nmap version' in result.stdout:
            print(f"✓ Nmap detectado: {result.stdout.splitlines()[0]}")
            return True
        else:
            print("✗ Nmap no está instalado o no está disponible en el PATH")
            return False
    except FileNotFoundError:
        print("✗ Nmap no está instalado o no está disponible en el PATH")
        return False


def detect_linux_distribution():
    """Detecta la distribución Linux para seleccionar el método de instalación apropiado"""
    if not os.path.exists('/etc/os-release'):
        return 'unknown'
    
    try:
        with open('/etc/os-release', 'r') as f:
            os_release = f.read()
        
        if 'debian' in os_release.lower() or 'ubuntu' in os_release.lower():
            return 'debian'
        elif 'fedora' in os_release.lower() or 'rhel' in os_release.lower() or 'centos' in os_release.lower():
            return 'fedora'
        elif 'arch' in os_release.lower() or 'manjaro' in os_release.lower():
            return 'arch'
        else:
            return 'unknown'
    except:
        return 'unknown'


def install_nmap_linux():
    """Instala Nmap en sistemas Linux"""
    distribution = detect_linux_distribution()
    
    if distribution == 'debian':
        cmd = ['apt', 'update', '-y']
        subprocess.run(cmd, check=True)
        cmd = ['apt', 'install', '-y', 'nmap']
    elif distribution == 'fedora':
        cmd = ['dnf', 'install', '-y', 'nmap']
    elif distribution == 'arch':
        cmd = ['pacman', '-S', '--noconfirm', 'nmap']
    else:
        # Si no podemos identificar la distribución, mostrar mensaje
        print("No se pudo determinar la distribución Linux. Por favor, instala Nmap manualmente.")
        return False
    
    try:
        print(f"Instalando Nmap mediante {' '.join(cmd)}...")
        result = subprocess.run(cmd, 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE, 
                               text=True,
                               check=False)
        
        if result.returncode == 0:
            print("Nmap se ha instalado correctamente.")
            return True
        else:
            print(f"Error al instalar Nmap: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error durante la instalación de Nmap: {str(e)}")
        return False


def check_brew_installed():
    """Verifica si Homebrew está instalado en macOS"""
    try:
        # Primero verificamos si brew está en el PATH
        result = subprocess.run(['which', 'brew'], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE, 
                               text=True,
                               check=False)
        
        if result.returncode == 0 and result.stdout.strip():
            return True
        
        # Si no está en el PATH, verificamos ubicaciones comunes
        brew_paths = [
            '/usr/local/bin/brew',
            '/opt/homebrew/bin/brew',
            '/home/linuxbrew/.linuxbrew/bin/brew'
        ]
        
        for path in brew_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return True
        
        return False
    except:
        return False


def get_brew_path():
    """Obtiene la ruta completa al ejecutable de Homebrew"""
    try:
        # Primero verificamos si brew está en el PATH
        result = subprocess.run(['which', 'brew'], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE, 
                               text=True,
                               check=False)
        
        if result.returncode == 0:
            return result.stdout.strip()
        
        # Si no está en el PATH, verificamos ubicaciones comunes
        brew_paths = [
            '/usr/local/bin/brew',
            '/opt/homebrew/bin/brew',
            '/home/linuxbrew/.linuxbrew/bin/brew'
        ]
        
        for path in brew_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path
        
        return None
    except:
        return None


def install_nmap_macos():
    """Instala Nmap en sistemas macOS"""
    # Verificar si ya tenemos Homebrew
    brew_installed = check_brew_installed()
    
    if brew_installed:
        brew_path = get_brew_path()
        if not brew_path:
            print("Homebrew encontrado pero no se pudo determinar su ruta. Intentando con 'brew'...")
            brew_path = 'brew'
        
        print(f"Instalando Nmap mediante Homebrew ({brew_path})...")
        
        try:
            # Verificar si estamos ejecutando como sudo
            is_sudo = 'SUDO_USER' in os.environ
            
            if is_sudo:
                # Cuando se ejecuta con sudo, necesitamos usar un enfoque diferente para Homebrew
                sudo_user = os.environ.get('SUDO_USER')
                print(f"Ejecutando como sudo para el usuario {sudo_user}")
                
                # Usar el usuario real, no root, para brew
                cmd = ['su', sudo_user, '-c', f"{brew_path} install nmap"]
                result = subprocess.run(cmd, 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE, 
                                       text=True,
                                       check=False)
            else:
                # Ejecución normal sin sudo
                cmd = [brew_path, 'install', 'nmap']
                result = subprocess.run(cmd, 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE, 
                                       text=True,
                                       check=False)
            
            if result.returncode == 0:
                print("Nmap se ha instalado correctamente mediante Homebrew.")
                return True
            else:
                print(f"Error al instalar Nmap con Homebrew: {result.stderr}")
                # Intento alternativo con instalación manual
                return _install_nmap_macos_manual()
        except Exception as e:
            print(f"Error durante la instalación de Nmap con Homebrew: {str(e)}")
            # Intento alternativo con instalación manual
            return _install_nmap_macos_manual()
    else:
        # Si Homebrew no está instalado, intentar instalación manual
        return _install_nmap_macos_manual()


def _install_nmap_macos_manual():
    """Descarga e instala Nmap manualmente en macOS"""
    try:
        # URL del instalador de Nmap para macOS
        nmap_url = "https://nmap.org/dist/nmap-7.94.dmg"
        
        # Crear un directorio temporal para la descarga
        temp_dir = tempfile.mkdtemp()
        dmg_path = os.path.join(temp_dir, "nmap.dmg")
        
        print("Intentando instalación manual de Nmap...")
        print(f"Descargando {nmap_url}...")
        
        # Descargar el DMG
        try:
            urllib.request.urlretrieve(nmap_url, dmg_path)
        except Exception as e:
            print(f"Error al descargar el instalador de Nmap: {str(e)}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return False
        
        print("Descarga completada. Montando imagen DMG...")
        
        # Montar el DMG
        mount_point = "/Volumes/Nmap"
        mount_cmd = ["hdiutil", "attach", dmg_path]
        result = subprocess.run(mount_cmd, 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE, 
                               text=True,
                               check=False)
        
        if result.returncode != 0:
            print(f"Error al montar la imagen DMG: {result.stderr}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return False
        
        print("Imagen montada. Instalando Nmap...")
        
        # Buscar el instalador .pkg
        pkg_path = None
        for root, dirs, files in os.walk(mount_point):
            for file in files:
                if file.endswith(".pkg") and "nmap" in file.lower():
                    pkg_path = os.path.join(root, file)
                    break
            if pkg_path:
                break
        
        if not pkg_path:
            print("No se encontró el instalador .pkg en la imagen DMG")
            subprocess.run(["hdiutil", "detach", mount_point, "-force"], check=False)
            shutil.rmtree(temp_dir, ignore_errors=True)
            return False
        
        # Instalar el paquete
        install_cmd = ["installer", "-pkg", pkg_path, "-target", "/"]
        result = subprocess.run(install_cmd, 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE, 
                               text=True,
                               check=True)
        
        # Desmontar la imagen
        subprocess.run(["hdiutil", "detach", mount_point, "-force"], check=False)
        
        # Limpiar
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        # Verificar la instalación
        if check_nmap_installed():
            print("Nmap se ha instalado correctamente de forma manual.")
            return True
        else:
            print("La instalación manual de Nmap parece haber fallado.")
            
            # Dar instrucciones detalladas al usuario
            print("\nPor favor, siga estos pasos para instalar Nmap manualmente:")
            print("1. Descargue Nmap desde https://nmap.org/download.html#macosx")
            print("2. Abra el archivo DMG descargado")
            print("3. Ejecute el instalador PKG y siga las instrucciones")
            print("4. Reinicie la aplicación después de la instalación")
            
            return False
        
    except Exception as e:
        print(f"Error durante la instalación manual de Nmap: {str(e)}")
        return False


def install_nmap_windows():
    """Instala Nmap en sistemas Windows"""
    try:
        # URL del instalador de Nmap
        nmap_url = "https://nmap.org/dist/nmap-7.94-setup.exe"
        
        # Informar al usuario
        print("Descargando el instalador de Nmap...")
        
        # Crear un directorio temporal para la descarga
        temp_dir = tempfile.mkdtemp()
        installer_path = os.path.join(temp_dir, "nmap_setup.exe")
        
        # Descargar el instalador
        try:
            urllib.request.urlretrieve(nmap_url, installer_path)
        except Exception as e:
            print(f"Error al descargar el instalador de Nmap: {str(e)}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return False
        
        # Ejecutar el instalador
        print("Ejecutando el instalador de Nmap. Por favor, siga las instrucciones en pantalla.")
        
        # Ejecutar el instalador y esperar a que termine
        result = subprocess.run([installer_path, '/S'], 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE,
                               shell=True,  # Usar shell para evitar problemas de permisos
                               check=False)
        
        # Limpiar archivos temporales
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        # Verificar si la instalación fue exitosa
        # Para Windows, esperamos un momento y luego verificamos si nmap está instalado
        time.sleep(5)  # Dar tiempo a que termine la instalación
        
        if check_nmap_installed():
            print("Nmap se ha instalado correctamente.")
            return True
        else:
            print("La instalación automática de Nmap ha fallado. Por favor, siga estos pasos:")
            print("1. Descargue el instalador de Nmap desde https://nmap.org/download.html")
            print("2. Ejecute el instalador con privilegios de administrador")
            print("3. Asegúrese de marcar la opción para instalar Npcap durante la instalación")
            print("4. Reinicie la aplicación después de instalar Nmap")
            return False
            
    except Exception as e:
        print(f"Error durante la instalación de Nmap: {str(e)}")
        return False


def setup_nmap():
    """Verifica e instala Nmap si es necesario"""
    if check_nmap_installed():
        return True
    
    # Si no está instalado, preguntar al usuario si desea instalarlo
    print("Nmap es necesario para el funcionamiento completo de Expulsor.")
    reply = input("¿Desea intentar instalar Nmap ahora? (s/n): ").lower()
    if reply not in ('s', 'si', 'sí', 'y', 'yes'):
        print("Expulsor tendrá funcionalidad limitada sin Nmap. Se recomienda instalarlo manualmente.")
        return False
    
    # Instalar según el sistema operativo
    system = platform.system()
    if system == 'Linux':
        return install_nmap_linux()
    elif system == 'Darwin':  # macOS
        return install_nmap_macos()
    elif system == 'Windows':
        return install_nmap_windows()
    else:
        print(f"Sistema operativo no soportado: {system}")
        return False


def setup_nmap_gui(app):
    """Verifica e instala Nmap si es necesario (versión GUI)"""
    if check_nmap_installed():
        return True
    
    # Si no está instalado, preguntar al usuario si desea instalarlo
    reply = QMessageBox.question(
        None, 
        "Nmap Requerido",
        "Nmap es necesario para el funcionamiento de Expulsor pero no está instalado. "
        "¿Desea instalar Nmap ahora?",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
    )
    
    if reply != QMessageBox.StandardButton.Yes:
        QMessageBox.warning(
            None,
            "Funcionalidad Limitada",
            "Expulsor tendrá funcionalidad limitada sin Nmap. Se recomienda instalarlo manualmente."
        )
        return False
    
    # Instalar según el sistema operativo
    system = platform.system()
    install_success = False
    error_message = ""
    
    try:
        if system == 'Linux':
            install_success = install_nmap_linux()
            if not install_success:
                error_message = "No se pudo instalar Nmap automáticamente en Linux."
        elif system == 'Darwin':  # macOS
            install_success = install_nmap_macos()
            if not install_success:
                error_message = "No se pudo instalar Nmap automáticamente en macOS."
        elif system == 'Windows':
            install_success = install_nmap_windows()
            if not install_success:
                error_message = "No se pudo instalar Nmap automáticamente en Windows."
        else:
            error_message = f"Sistema operativo no soportado: {system}"
    except Exception as e:
        install_success = False
        error_message = f"Error durante la instalación: {str(e)}"
    
    if install_success:
        QMessageBox.information(
            None,
            "Instalación Completada",
            "Nmap se ha instalado correctamente."
        )
        return True
    else:
        QMessageBox.warning(
            None,
            "Error de Instalación",
            f"{error_message}\n\nPor favor, instale Nmap manualmente desde https://nmap.org/download.html"
        )
        return False


def create_qt_app():
    """Crea y devuelve una instancia de QApplication"""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    app.setApplicationName("Expulsor")
    app.setStyle('Fusion')
    return app


def main():
    """Función principal de la aplicación"""
    # Configurar el parseador de argumentos
    parser = argparse.ArgumentParser(description='Expulsor - Herramienta de gestión y control de red')
    parser.add_argument('--no-check-admin', action='store_true', help='Omitir verificación de privilegios de administrador')
    parser.add_argument('--no-gui', action='store_true', help='Iniciar en modo consola (sin interfaz gráfica)')
    parser.add_argument('--skip-nmap-check', action='store_true', help='Omitir verificación e instalación de Nmap')
    args = parser.parse_args()
    
    # Verificar permisos
    if not args.no_check_admin:
        if not check_permissions():
            print("Continuando sin privilegios. Algunas funciones podrían no estar disponibles.")
    
    # Verificar e instalar Nmap si es necesario
    if not args.skip_nmap_check:
        # Verificamos la disponibilidad de Nmap
        if not check_nmap_installed():
            if args.no_gui:
                # Modo consola
                if not setup_nmap():
                    print("ADVERTENCIA: Algunas funcionalidades de escaneo de red estarán limitadas sin Nmap.")
            else:
                # En modo GUI, necesitamos inicializar QApplication primero para mostrar diálogos
                # Pero solo creamos la aplicación sin entrar al bucle de eventos
                app = create_qt_app()
                if not setup_nmap_gui(app):
                    print("ADVERTENCIA: Algunas funcionalidades de escaneo de red estarán limitadas sin Nmap.")
    
    # Si estamos en modo consola, salir aquí después de la verificación
    if args.no_gui:
        print("Expulsor no está configurado para funcionar en modo consola. Por favor, inicie la aplicación en modo GUI.")
        return
    
    # Evitar el escalado automático de alto DPI en Windows
    if platform.system() == 'Windows':
        os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    
    # Asegurarnos de que tengamos una aplicación Qt
    app = create_qt_app()
    
    # Importar MainWindow aquí para evitar que se intente crear un widget antes de QApplication
    from .ui.main_window import MainWindow
    
    # Crear y mostrar la ventana principal
    window = MainWindow()
    window.show()
    
    # Ejecutar el bucle de eventos de Qt
    sys.exit(app.exec())


if __name__ == "__main__":
    main()