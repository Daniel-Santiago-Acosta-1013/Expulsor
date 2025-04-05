"""
Punto de entrada principal para la aplicación Expulsor
"""

import os
import sys
import argparse
import platform

from PyQt6.QtWidgets import QApplication

from .ui.main_window import MainWindow


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


def main():
    """Función principal de la aplicación"""
    
    # Configurar el parseador de argumentos
    parser = argparse.ArgumentParser(description='Expulsor - Herramienta de gestión y control de red')
    parser.add_argument('--no-check-admin', action='store_true', help='Omitir verificación de privilegios de administrador')
    args = parser.parse_args()
    
    # Verificar permisos
    if not args.no_check_admin:
        if not check_permissions():
            print("Continuando sin privilegios. Algunas funciones podrían no estar disponibles.")
    
    # Evitar el escalado automático de alto DPI en Windows
    if platform.system() == 'Windows':
        os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    
    # Iniciar aplicación Qt
    app = QApplication(sys.argv)
    app.setApplicationName("Expulsor")
    
    # Establecer estilo (opcional)
    app.setStyle('Fusion')
    
    # Crear y mostrar la ventana principal
    window = MainWindow()
    window.show()
    
    # Ejecutar el bucle de eventos de Qt
    sys.exit(app.exec())


if __name__ == "__main__":
    main()