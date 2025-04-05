"""
Ventana principal de la aplicación Expulsor
"""

import time

from PyQt6.QtCore import Qt, QTimer, pyqtSlot, pyqtSignal, QObject
from PyQt6.QtWidgets import (QHBoxLayout, QMainWindow, 
                            QMessageBox, QPushButton, QSplitter, QTabWidget, 
                            QTableView, QTextEdit, QVBoxLayout, QWidget)

from ..network_scanner import DeviceInfo, NetworkScanner
from ..arp_spoofer import ARPSpoofer
from .device_model import DeviceTableModel


class SpooferSignals(QObject):
    """Clase de señales para comunicación segura entre hilos"""
    status_update = pyqtSignal(str, str, bool)

class MainWindow(QMainWindow):
    """Ventana principal de la aplicación Expulsor"""
    
    def __init__(self):
        super().__init__()
        
        # Inicializar componentes internos
        self.scanner = NetworkScanner()
        self.spoofer = None  # Se inicializará después de obtener la puerta de enlace
        self.device_model = DeviceTableModel()
        self.selected_device = None
        
        # Inicializar señales para comunicación segura entre hilos
        self.spoofer_signals = SpooferSignals()
        self.spoofer_signals.status_update.connect(self._on_spoofer_status_safe)
        
        # Configurar la ventana
        self.setWindowTitle("Expulsor - Control de Red")
        self.setMinimumSize(1000, 600)
        
        # Inicializar la interfaz gráfica
        self._init_ui()
        
        # Inicializar temporizador para actualizaciones
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._update_status)
        self.timer.start(10000)  # Actualizar cada 10 segundos
        
        # Inicializar el spoofer una vez que tengamos la información de red
        if self.scanner.gateway_ip and self.scanner.gateway_mac and self.scanner.local_mac:
            self.spoofer = ARPSpoofer(
                self.scanner.gateway_ip,
                self.scanner.gateway_mac,
                self.scanner.local_mac
            )
            self.spoofer.set_status_callback(self._emit_spoofer_status)
            self.log(f"Información de red obtenida: Gateway {self.scanner.gateway_ip} ({self.scanner.gateway_mac})")
        else:
            self.log("⚠️ No se pudo obtener información de red. Algunas funciones no estarán disponibles.", error=True)
    
    def _init_ui(self):
        """Inicializa la interfaz de usuario"""
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        main_layout = QVBoxLayout(central_widget)
        
        # Splitter horizontal principal
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(self.main_splitter)
        
        # Panel izquierdo: Tabla de dispositivos
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # Botones de control
        control_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("Escanear Red")
        self.scan_button.clicked.connect(self._on_scan_clicked)
        control_layout.addWidget(self.scan_button)
        
        self.block_button = QPushButton("Bloquear Acceso")
        self.block_button.clicked.connect(self._on_block_clicked)
        self.block_button.setEnabled(False)
        control_layout.addWidget(self.block_button)
        
        self.unblock_button = QPushButton("Restaurar Acceso")
        self.unblock_button.clicked.connect(self._on_unblock_clicked)
        self.unblock_button.setEnabled(False)
        control_layout.addWidget(self.unblock_button)
        
        left_layout.addLayout(control_layout)
        
        # Tabla de dispositivos
        self.device_table = QTableView()
        self.device_table.setModel(self.device_model)
        self.device_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.device_table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.device_table.clicked.connect(self._on_device_selected)
        self.device_table.doubleClicked.connect(self._on_device_details)
        
        # Ajustar ancho de columnas
        header = self.device_table.horizontalHeader()
        header.setStretchLastSection(True)
        
        left_layout.addWidget(self.device_table)
        
        # Panel derecho: Paneles de detalles y log
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Tabbed widget para detalles y log
        self.tab_widget = QTabWidget()
        
        # Pestaña de detalles
        self.details_widget = QWidget()
        details_layout = QVBoxLayout(self.details_widget)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        
        # Pestaña de log
        self.log_widget = QWidget()
        log_layout = QVBoxLayout(self.log_widget)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        
        # Añadir pestañas
        self.tab_widget.addTab(self.details_widget, "Detalles")
        self.tab_widget.addTab(self.log_widget, "Log")
        
        right_layout.addWidget(self.tab_widget)
        
        # Añadir widgets al splitter
        self.main_splitter.addWidget(left_widget)
        self.main_splitter.addWidget(right_widget)
        self.main_splitter.setSizes([500, 500])  # Tamaño inicial
        
        # Barra de estado
        self.statusBar().showMessage("Listo")
        
        # Log inicial
        self.log("Aplicación iniciada")
        self.log(f"IP local: {self.scanner.local_ip} | MAC: {self.scanner.local_mac}")
        self.log(f"Gateway: {self.scanner.gateway_ip} | MAC: {self.scanner.gateway_mac}")
    
    def log(self, message: str, error: bool = False):
        """Añade un mensaje al log"""
        timestamp = time.strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {'❌ ' if error else ''}{message}"
        self.log_text.append(formatted)
        
        # Auto-scroll
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
        # Mostrar en barra de estado brevemente
        self.statusBar().showMessage(message, 5000)
    
    def _update_status(self):
        """Actualiza el estado de los dispositivos periódicamente"""
        if not self.scanner.scanning and self.device_model.rowCount() > 0:
            self.scanner.scan_network(
                on_device_found=self._on_device_updated,
                on_scan_complete=self._on_scan_complete,
                quick_scan=True
            )
    
    def _update_device_details(self, device: DeviceInfo):
        """Actualiza la visualización de detalles de un dispositivo"""
        if not device:
            self.details_text.clear()
            return
        
        # Formato HTML para mejor presentación
        details = f"""
        <h2>Detalles del Dispositivo</h2>
        <p><b>IP:</b> {device.ip}</p>
        <p><b>MAC:</b> {device.mac}</p>
        <p><b>Hostname:</b> {device.hostname or "Desconocido"}</p>
        <p><b>Fabricante:</b> {device.vendor or "Desconocido"}</p>
        <p><b>Sistema Operativo:</b> {device.os or "Desconocido"}</p>
        <p><b>Estado:</b> {device.status}</p>
        <p><b>Bloqueado:</b> {"Sí" if device.blocked else "No"}</p>
        <p><b>Última actividad:</b> {time.strftime('%H:%M:%S', time.localtime(device.last_seen))}</p>
        """
        
        # Información de puertos si está disponible
        if device.open_ports:
            details += "<h3>Puertos Abiertos</h3><ul>"
            for port in device.open_ports:
                details += f"<li>{port}</li>"
            details += "</ul>"
        else:
            details += "<p><i>No hay información de puertos disponible</i></p>"
        
        self.details_text.setHtml(details)
    
    def _on_device_selected(self, index):
        """Manejador para cuando se selecciona un dispositivo en la tabla"""
        row = index.row()
        device = self.device_model.get_device_at_row(row)
        if device:
            self.selected_device = device
            self._update_device_details(device)
            
            # Habilitar/deshabilitar botones según estado
            is_local = device.ip == self.scanner.local_ip
            is_gateway = device.ip == self.scanner.gateway_ip
            is_blocked = device.blocked
            
            # No permitir bloquear la puerta de enlace o a nosotros mismos
            self.block_button.setEnabled(not (is_local or is_gateway) and not is_blocked and self.spoofer is not None)
            self.unblock_button.setEnabled(is_blocked and self.spoofer is not None)
    
    def _on_device_details(self, index):
        """Manejador para cuando se hace doble clic en un dispositivo"""
        # Cambiar a la pestaña de detalles
        self.tab_widget.setCurrentIndex(0)
    
    def _on_scan_clicked(self):
        """Manejador para el botón de escaneo"""
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Escaneando...")
        self.log("Iniciando escaneo de red completo...")
        
        # Iniciar escaneo
        self.scanner.scan_network(
            on_device_found=self._on_device_found,
            on_scan_complete=self._on_scan_complete,
            quick_scan=False
        )
    
    def _on_device_found(self, device: DeviceInfo):
        """Callback cuando se encuentra un dispositivo durante el escaneo"""
        # Marcar si es local o gateway
        if device.ip == self.scanner.local_ip:
            device.hostname = "Este dispositivo"
        elif device.ip == self.scanner.gateway_ip:
            device.hostname = "Puerta de enlace"
        
        # Marcar si está bloqueado
        if self.spoofer and self.spoofer.is_spoofing(device.ip):
            device.blocked = True
        
        # Actualizar modelo
        self.device_model.update_device(device)
        
        # Log
        if not device.hostname:
            hostname_txt = ""
        else:
            hostname_txt = f" ({device.hostname})"
            
        self.log(f"Dispositivo encontrado: {device.ip}{hostname_txt}")
    
    def _on_device_updated(self, device: DeviceInfo):
        """Callback cuando se actualiza un dispositivo durante un escaneo rápido"""
        # Preservar el estado de bloqueo
        existing_device = self.device_model.get_device_by_ip(device.ip)
        if existing_device:
            device.blocked = existing_device.blocked
        
        # Actualizar modelo
        self.device_model.update_device(device)
        
        # Actualizar detalles si es el dispositivo seleccionado
        if self.selected_device and device.ip == self.selected_device.ip:
            self.selected_device = device
            self._update_device_details(device)
    
    def _on_scan_complete(self, success: bool, message: str):
        """Callback cuando se completa el escaneo"""
        self.scan_button.setEnabled(True)
        self.scan_button.setText("Escanear Red")
        
        if success:
            self.log(f"Escaneo completado: {len(self.scanner.get_all_devices())} dispositivos encontrados")
        else:
            self.log(f"Error en el escaneo: {message}", error=True)
    
    def _on_block_clicked(self):
        """Manejador para el botón de bloqueo"""
        if not self.selected_device or not self.spoofer:
            return
        
        # Confirmar con el usuario
        reply = QMessageBox.question(self, "Confirmar Bloqueo", 
                                    f"¿Deseas bloquear el acceso a internet para {self.selected_device.ip}?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            # Iniciar spoofing
            success = self.spoofer.start_spoofing(self.selected_device.ip)
            
            if success:
                self.log(f"Iniciando bloqueo para {self.selected_device.ip}")
                self.selected_device.blocked = True
                self.device_model.update_device(self.selected_device)
                self._update_device_details(self.selected_device)
                
                # Actualizar botones
                self.block_button.setEnabled(False)
                self.unblock_button.setEnabled(True)
            else:
                self.log(f"No se pudo iniciar el bloqueo para {self.selected_device.ip}", error=True)
    
    def _on_unblock_clicked(self):
        """Manejador para el botón de desbloqueo"""
        if not self.selected_device or not self.spoofer:
            return
        
        # Detener el spoofing
        success = self.spoofer.stop_spoofing(self.selected_device.ip)
        
        if success:
            self.log(f"Restaurando acceso para {self.selected_device.ip}")
            self.selected_device.blocked = False
            self.device_model.update_device(self.selected_device)
            self._update_device_details(self.selected_device)
            
            # Actualizar botones
            self.block_button.setEnabled(True)
            self.unblock_button.setEnabled(False)
        else:
            self.log(f"No se pudo restaurar el acceso para {self.selected_device.ip}", error=True)
    
    def _emit_spoofer_status(self, ip: str, message: str, success: bool):
        """Emite la señal desde el hilo secundario al hilo principal"""
        self.spoofer_signals.status_update.emit(ip, message, success)
    
    @pyqtSlot(str, str, bool)
    def _on_spoofer_status_safe(self, ip: str, message: str, success: bool):
        """Callback para mensajes de estado del spoofer (seguro para hilos)"""
        self.log(f"[ARP Spoofer] {ip}: {message}", not success)
        
        # Actualizar UI si es necesario
        device = self.device_model.get_device_by_ip(ip)
        if device:
            device.blocked = self.spoofer.is_spoofing(ip)
            self.device_model.update_device(device)
            
            if self.selected_device and self.selected_device.ip == ip:
                self.selected_device = device
                self._update_device_details(device)
                self.block_button.setEnabled(not device.blocked)
                self.unblock_button.setEnabled(device.blocked)
    
    def closeEvent(self, event):
        """Manejador para el cierre de la ventana"""
        # Detener todos los ataques en curso
        if self.spoofer:
            self.spoofer.stop_all()
        
        # Detener escáner si está en curso
        if self.scanner.scanning:
            self.scanner.stop_scan()
        
        # Detener timer
        self.timer.stop()
        
        # Continuar con el cierre
        super().closeEvent(event)