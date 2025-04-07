"""
Punto de entrada principal para la aplicación Expulsor
"""

import os
import sys
import argparse
import platform
import subprocess

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

def setup_nmap():
    """Verifica si Nmap está instalado y notifica al usuario si no lo está"""
    if check_nmap_installed():
        return True
    
    # Si no está instalado, informar al usuario que debe instalarlo manualmente
    print("Nmap es necesario para el funcionamiento completo de Expulsor.")
    print("Por favor, instale Nmap manualmente desde https://nmap.org/download.html")
    print("Después de instalar Nmap, reinicie la aplicación.")
    print("Expulsor tendrá funcionalidad limitada sin Nmap.")
    
    return False

def setup_nmap_gui(app):
    """Verifica si Nmap está instalado y notifica al usuario mediante GUI si no lo está"""
    if check_nmap_installed():
        return True
    
    # Si no está instalado, mostrar mensaje de advertencia en GUI
    QMessageBox.warning(
        None,
        "Nmap Requerido",
        "Nmap es necesario para el funcionamiento completo de Expulsor, pero no está instalado.\n\n"
        "Por favor, instale Nmap manualmente desde https://nmap.org/download.html\n"
        "Después de instalar Nmap, reinicie la aplicación.\n\n"
        "Expulsor tendrá funcionalidad limitada sin Nmap."
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
    parser.add_argument('--skip-nmap-check', action='store_true', help='Omitir verificación de Nmap')
    args = parser.parse_args()
    
    # Verificar permisos
    if not args.no_check_admin:
        if not check_permissions():
            print("Continuando sin privilegios. Algunas funciones podrían no estar disponibles.")
    
    # Verificar Nmap si es necesario
    if not args.skip_nmap_check:
        # Verificamos la disponibilidad de Nmap
        if not check_nmap_installed():
            if args.no_gui:
                # Modo consola
                setup_nmap()
                print("ADVERTENCIA: Algunas funcionalidades de escaneo de red estarán limitadas sin Nmap.")
            else:
                # En modo GUI, necesitamos inicializar QApplication primero para mostrar diálogos
                # Pero solo creamos la aplicación sin entrar al bucle de eventos
                app = create_qt_app()
                setup_nmap_gui(app)
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