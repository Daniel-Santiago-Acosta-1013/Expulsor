"""
Ventana principal de la aplicación Expulsor
"""

import time
import platform

from PyQt6.QtCore import Qt, QTimer, pyqtSlot, pyqtSignal, QObject
from PyQt6.QtGui import QAction, QCursor
from PyQt6.QtWidgets import (QHBoxLayout, QLabel, QMainWindow, 
                            QMessageBox, QPushButton, QSplitter, QTabWidget, 
                            QTableView, QTextEdit, QVBoxLayout, QWidget,
                            QCheckBox, QDoubleSpinBox, QMenu,
                            QDialog, QGridLayout, QToolButton)

from ..network_scanner import DeviceInfo, NetworkScanner
from ..arp_spoofer import ARPSpoofer
from .device_model import DeviceTableModel
from PyQt6.QtCore import QMetaObject


class SpooferSignals(QObject):
    """Clase de señales para comunicación segura entre hilos para el ARP Spoofer"""
    status_update = pyqtSignal(str, str, bool)


class ScannerSignals(QObject):
    """Clase de señales para comunicación segura entre hilos para el Network Scanner"""
    device_found = pyqtSignal(object)
    device_updated = pyqtSignal(object)
    scan_complete = pyqtSignal(bool, str)


class AgressiveModeDialog(QDialog):
    """Diálogo para configurar el modo agresivo"""
    
    def __init__(self, parent=None, current_rate=0.5, aggressive_enabled=True, block_enabled=True):
        super().__init__(parent)
        self.setWindowTitle("Configuración del Modo Agresivo")
        self.setMinimumWidth(400)
        
        # Valores iniciales
        self.packet_rate = current_rate
        self.aggressive_mode = aggressive_enabled
        self.block_mode = block_enabled
        
        # Layout principal
        layout = QGridLayout(self)
        
        # Modo agresivo
        self.aggressive_checkbox = QCheckBox("Activar modo agresivo", self)
        self.aggressive_checkbox.setChecked(aggressive_enabled)
        self.aggressive_checkbox.setToolTip("Activa técnicas adicionales para un bloqueo más efectivo")
        layout.addWidget(self.aggressive_checkbox, 0, 0, 1, 2)
        
        # Modo de bloqueo
        self.block_checkbox = QCheckBox("Bloquear tráfico (desactivar reenvío de IP)", self)
        self.block_checkbox.setChecked(block_enabled)
        self.block_checkbox.setToolTip("Si está activado, bloquea realmente el tráfico. Si está desactivado, solo monitoriza")
        layout.addWidget(self.block_checkbox, 1, 0, 1, 2)
        
        # Frecuencia de paquetes
        layout.addWidget(QLabel("Frecuencia de paquetes (segundos):"), 2, 0)
        self.rate_spinner = QDoubleSpinBox(self)
        self.rate_spinner.setRange(0.1, 5.0)
        self.rate_spinner.setSingleStep(0.1)
        self.rate_spinner.setValue(current_rate)
        self.rate_spinner.setToolTip("Intervalo entre envíos de paquetes ARP. Valores más bajos son más agresivos")
        layout.addWidget(self.rate_spinner, 2, 1)
        
        # Botones
        self.ok_button = QPushButton("Aceptar", self)
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Cancelar", self)
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout, 3, 0, 1, 2)
    
    def get_settings(self):
        """Retorna la configuración seleccionada"""
        return {
            'aggressive_mode': self.aggressive_checkbox.isChecked(),
            'block_mode': self.block_checkbox.isChecked(),
            'packet_rate': self.rate_spinner.value()
        }

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
        
        # Inicializar señales para el escáner de red
        self.scanner_signals = ScannerSignals()
        self.scanner_signals.device_found.connect(self._on_device_found_safe)
        self.scanner_signals.device_updated.connect(self._on_device_updated_safe)
        self.scanner_signals.scan_complete.connect(self._on_scan_complete_safe)
        
        # Configurar la ventana
        self.setWindowTitle("Expulsor - Control de Red")
        self.setMinimumSize(1000, 600)
        
        # Inicializar la interfaz gráfica
        self._init_ui()
        self._create_menu()
        
        # Inicializar temporizador para actualizaciones
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._update_status)
        self.timer.start(10000)  # Actualizar cada 10 segundos
        
        # Temporizador para actualizar información de bloqueo
        self.block_timer = QTimer(self)
        self.block_timer.timeout.connect(self._update_block_info)
        self.block_timer.start(2000)  # Actualizar cada 2 segundos
        
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
    
    def _create_menu(self):
        """Crea el menú de la aplicación"""
        menu_bar = self.menuBar()
        
        # Menú Archivo
        file_menu = menu_bar.addMenu("Archivo")
        
        exit_action = QAction("Salir", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Menú Herramientas
        tools_menu = menu_bar.addMenu("Herramientas")
        
        # Submenú de escaneo
        scan_menu = tools_menu.addMenu("Escanear Red")
        
        # Opciones de escaneo
        scan_quick_action = QAction("Escaneo Rápido", self)
        scan_quick_action.triggered.connect(self._on_quick_scan_clicked)
        scan_menu.addAction(scan_quick_action)
        
        scan_deep_action = QAction("Escaneo Profundo", self)
        scan_deep_action.triggered.connect(self._on_deep_scan_clicked)
        scan_menu.addAction(scan_deep_action)
        
        # Configuración de bloqueo
        block_config_action = QAction("Configurar Bloqueo", self)
        block_config_action.triggered.connect(self._show_aggressive_config)
        tools_menu.addAction(block_config_action)
        
        # Menú Ayuda
        help_menu = menu_bar.addMenu("Ayuda")
        
        about_action = QAction("Acerca de", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
    
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
        
        # Botón de escaneo con menú desplegable
        self.scan_button = QToolButton()
        self.scan_button.setText("Escanear")
        self.scan_button.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        
        # Crear menú de opciones de escaneo
        scan_menu = QMenu()
        
        # Acción para escaneo rápido
        scan_quick_action = QAction("Escaneo Rápido", self)
        scan_quick_action.setToolTip("Realiza un escaneo básico para detectar dispositivos rápidamente")
        scan_quick_action.triggered.connect(self._on_quick_scan_clicked)
        scan_menu.addAction(scan_quick_action)
        
        # Acción para escaneo profundo
        scan_deep_action = QAction("Escaneo Profundo", self)
        scan_deep_action.setToolTip("Realiza un escaneo detallado de todos los dispositivos")
        scan_deep_action.triggered.connect(self._on_deep_scan_clicked)
        scan_menu.addAction(scan_deep_action)
        
        # Configurar el menú en el botón
        self.scan_button.setMenu(scan_menu)
        self.scan_button.setDefaultAction(scan_quick_action)
        self.scan_button.clicked.connect(self._on_quick_scan_clicked)  # Acción por defecto
        
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
        # Añadir menú contextual para escaneo individual
        self.device_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.device_table.customContextMenuRequested.connect(self._show_device_context_menu)
        
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
        
        # Pestaña de estado de bloqueo
        self.block_widget = QWidget()
        block_layout = QVBoxLayout(self.block_widget)
        
        self.block_text = QTextEdit()
        self.block_text.setReadOnly(True)
        block_layout.addWidget(self.block_text)
        
        # Añadir pestañas
        self.tab_widget.addTab(self.details_widget, "Detalles")
        self.tab_widget.addTab(self.log_widget, "Log")
        self.tab_widget.addTab(self.block_widget, "Estado de Bloqueo")
        
        right_layout.addWidget(self.tab_widget)
        
        # Añadir widgets al splitter
        self.main_splitter.addWidget(left_widget)
        self.main_splitter.addWidget(right_widget)
        self.main_splitter.setSizes([500, 500])  # Tamaño inicial
        
        # Barra de estado
        self.statusBar().showMessage("Listo")
        
        # Log inicial
        self.log("Aplicación iniciada")
        self.log(f"Sistema: {platform.system()} {platform.release()}")
        self.log(f"IP local: {self.scanner.local_ip} | MAC: {self.scanner.local_mac}")
        self.log(f"Gateway: {self.scanner.gateway_ip} | MAC: {self.scanner.gateway_mac}")
    
    def _show_device_context_menu(self, pos):
        """Muestra el menú contextual para un dispositivo"""
        # Obtener el índice bajo el cursor
        index = self.device_table.indexAt(pos)
        if not index.isValid():
            return
            
        # Obtener el dispositivo
        device = self.device_model.get_device_at_row(index.row())
        if not device:
            return
            
        # Crear menú contextual
        context_menu = QMenu(self)
        
        # Opción para escanear el dispositivo individualmente
        scan_action = QAction("Escanear este dispositivo (detallado)", self)
        scan_action.triggered.connect(lambda: self._scan_specific_device(device.ip))
        
        # Determinar el estado del escaneo detallado
        if hasattr(device, 'detailed_scan_time') and device.detailed_scan_time:
            last_scan_time = time.strftime('%H:%M:%S', time.localtime(device.detailed_scan_time))
            scan_action.setText(f"Escanear este dispositivo (último: {last_scan_time})")
        
        context_menu.addAction(scan_action)
        
        # Añadir opciones para bloquear/desbloquear
        if device.blocked:
            unblock_action = QAction("Restaurar acceso", self)
            unblock_action.triggered.connect(lambda: self._unblock_device(device))
            context_menu.addAction(unblock_action)
        else:
            block_action = QAction("Bloquear acceso", self)
            block_action.triggered.connect(lambda: self._block_device(device))
            # Deshabilitar para gateway y local
            if device.ip == self.scanner.gateway_ip or device.ip == self.scanner.local_ip:
                block_action.setEnabled(False)
            context_menu.addAction(block_action)
        
        # Mostrar el menú contextual
        context_menu.exec(QCursor.pos())

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
                self._emit_device_updated,
                self._emit_scan_complete,
                quick_scan=True
            )
    
    def _update_block_info(self):
        """Actualiza la información de los dispositivos bloqueados"""
        if not self.spoofer:
            return
            
        targets = self.spoofer.get_all_targets()
        if not targets:
            self.block_text.setText("<h2>No hay dispositivos bloqueados actualmente</h2>")
            return
            
        # Mostrar información
        html = "<h2>Dispositivos con acceso restringido</h2>"
        html += "<table width='100%' border='1' cellpadding='4' style='border-collapse: collapse;'>"
        html += "<tr><th>IP</th><th>MAC</th><th>Tiempo activo</th><th>Estado</th><th>Modo</th></tr>"
        
        for ip, info in targets.items():
            device = self.device_model.get_device_by_ip(ip)
            hostname = device.hostname if device else "Desconocido"
            duration = info.get('duration', 0)
            
            # Formatear duración
            minutes, seconds = divmod(int(duration), 60)
            hours, minutes = divmod(minutes, 60)
            duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            
            # Fila con color según estado
            bg_color = "#ffdddd" if info.get('active', False) else "#dddddd"
            html += f"<tr style='background-color: {bg_color};'>"
            html += f"<td>{ip} ({hostname})</td>"
            html += f"<td>{info.get('mac', 'Desconocido')}</td>"
            html += f"<td>{duration_str}</td>"
            html += f"<td>{'Activo' if info.get('active', False) else 'Inactivo'}</td>"
            html += f"<td>{'Bloqueo' if info.get('block_mode', False) else 'Monitorización'}</td>"
            html += "</tr>"
            
        html += "</table>"
        
        # Añadir información sobre configuración
        html += "<h3>Configuración actual</h3>"
        html += f"<p><b>Modo agresivo:</b> {'Activado' if self.spoofer.aggressive_mode else 'Desactivado'}</p>"
        html += f"<p><b>Modo de bloqueo:</b> {'Activado (bloqueo real)' if self.spoofer.block_mode else 'Desactivado (solo monitorización)'}</p>"
        html += f"<p><b>Frecuencia de paquetes:</b> {self.spoofer.packet_rate} segundos</p>"
        
        self.block_text.setHtml(html)

    def _update_device_details(self, device: DeviceInfo):
        """Actualiza la visualización de detalles de un dispositivo"""
        if not device:
            self.details_text.clear()
            return
        
        # Formato HTML para mejor presentación
        details = f"""
        <h2>Detalles del Dispositivo</h2>
        <table width="100%" cellpadding="3">
            <tr><td width="30%"><b>IP:</b></td><td>{device.ip}</td></tr>
            <tr><td><b>MAC:</b></td><td>{device.mac}</td></tr>
            <tr><td><b>Hostname:</b></td><td>{device.hostname or "Desconocido"}</td></tr>
        </table>
        
        <h3>Información de Fabricante</h3>
        <table width="100%" cellpadding="3">
            <tr><td width="30%"><b>Fabricante:</b></td><td>{device.vendor or "Desconocido"}</td></tr>
            <tr><td><b>Detalles de fabricante:</b></td><td>{device.vendor_details or "Desconocido"}</td></tr>
        </table>
        
        <h3>Identificación del Dispositivo</h3>
        <table width="100%" cellpadding="3">
            <tr><td width="30%"><b>Tipo de dispositivo:</b></td><td>{device.device_type or "Desconocido"}</td></tr>
            <tr><td><b>Modelo específico:</b></td><td>{device.model or "Desconocido"}</td></tr>
            <tr><td><b>Sistema Operativo:</b></td><td>{device.os or "Desconocido"}</td></tr>
        </table>
        
        <h3>Estado</h3>
        <table width="100%" cellpadding="3">
            <tr><td width="30%"><b>Estado actual:</b></td><td>{device.status}</td></tr>
            <tr><td><b>Bloqueado:</b></td><td>{"Sí" if device.blocked else "No"}</td></tr>
            <tr><td><b>Última actividad:</b></td><td>{time.strftime('%d/%m/%Y %H:%M:%S', time.localtime(device.last_seen))}</td></tr>
        """
        
        # Si se ha realizado un escaneo detallado, mostrar cuándo
        if hasattr(device, 'detailed_scan_time') and device.detailed_scan_time:
            scan_time = time.strftime('%d/%m/%Y %H:%M:%S', time.localtime(device.detailed_scan_time))
            details += f"<tr><td><b>Último escaneo detallado:</b></td><td>{scan_time}</td></tr>"
        
        details += "</table>"
        
        # Información de puertos si está disponible
        if device.open_ports:
            details += "<h3>Puertos Abiertos y Servicios</h3>"
            
            # Si tenemos información detallada de servicios, mostrarla en una tabla
            if hasattr(device, 'service_details') and device.service_details:
                details += """
                <table width="100%" border="1" cellpadding="3" cellspacing="0" style="border-collapse: collapse;">
                    <tr style="background-color: #e0e0e0;">
                        <th width="15%">Puerto</th>
                        <th width="20%">Servicio</th>
                        <th>Detalles</th>
                    </tr>
                """
                
                for port in sorted(device.open_ports):
                    port_str = str(port)
                    service_name = "Desconocido"
                    service_details = ""
                    
                    if port in device.service_details:
                        service_info = device.service_details[port]
                        
                        if isinstance(service_info, dict):
                            if 'name' in service_info:
                                service_name = service_info['name']
                            elif 'info' in service_info and 'name' in service_info:
                                service_name = service_info['name']
                            
                            # Compilar detalles del servicio
                            details_parts = []
                            
                            # Si tenemos product, version, extrainfo
                            if 'product' in service_info and service_info['product']:
                                details_parts.append(service_info['product'])
                                
                            if 'version' in service_info and service_info['version']:
                                details_parts.append(f"v{service_info['version']}")
                                
                            if 'extrainfo' in service_info and service_info['extrainfo']:
                                details_parts.append(service_info['extrainfo'])
                                
                            # Si tenemos info general
                            if 'info' in service_info and service_info['info']:
                                details_parts.append(service_info['info'])
                                
                            service_details = " ".join(details_parts)
                    
                    # Alternar colores de fila
                    row_color = "#f8f8f8" if port % 2 == 0 else "#ffffff"
                    details += f"""
                    <tr style="background-color: {row_color};">
                        <td align="center">{port_str}</td>
                        <td>{service_name}</td>
                        <td>{service_details}</td>
                    </tr>
                    """
                
                details += "</table>"
                
                details += """
                <p><small><i>Consejo: Realiza un escaneo específico de este dispositivo para obtener información detallada 
                de servicios. Haz clic derecho sobre el dispositivo en la tabla y selecciona "Escanear este dispositivo".</i></small></p>
                """
            else:
                # Si no tenemos información detallada, mostrar lista simple
                details += "<ul>"
                for port in sorted(device.open_ports):
                    details += f"<li>Puerto {port}</li>"
                details += "</ul>"
                
                details += """
                <p><i>Para obtener información detallada de servicios, realiza un escaneo específico de este dispositivo.
                Haz clic derecho sobre el dispositivo en la tabla y selecciona "Escanear este dispositivo".</i></p>
                """
        else:
            details += "<p><i>No hay información de puertos disponible</i></p>"
        
        # Si está bloqueado, mostrar información adicional
        if device.blocked and self.spoofer:
            targets = self.spoofer.get_all_targets()
            if device.ip in targets:
                info = targets[device.ip]
                duration = info.get('duration', 0)
                minutes, seconds = divmod(int(duration), 60)
                hours, minutes = divmod(minutes, 60)
                
                details += f"""
                <h3>Información de Bloqueo</h3>
                <table width="100%" cellpadding="3">
                    <tr><td width="30%"><b>Tiempo de bloqueo:</b></td><td>{hours:02d}:{minutes:02d}:{seconds:02d}</td></tr>
                    <tr><td><b>Estado:</b></td><td>{'Activo' if info.get('active', False) else 'Inactivo'}</td></tr>
                </table>
                """
        
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
    
    def _on_quick_scan_clicked(self):
        """Manejador para el botón de escaneo rápido"""
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Escaneando...")
        self.log("Iniciando escaneo rápido de red...")
        
        # Iniciar escaneo rápido
        self.scanner.scan_network(
            self._emit_device_found,
            self._emit_scan_complete,
            quick_scan=True
        )
    
    def _on_deep_scan_clicked(self):
        """Manejador para el botón de escaneo profundo"""
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Escaneando...")
        self.log("Iniciando escaneo profundo de red...")
        
        # Iniciar escaneo profundo
        self.scanner.scan_network(
            self._emit_device_found,
            self._emit_scan_complete,
            quick_scan=False
        )

    def _scan_specific_device(self, ip):
        """Escanea un dispositivo específico"""
        if not ip or self.scanner.scanning:
            # Mostrar mensaje de error si ya hay un escaneo en curso
            if self.scanner.scanning:
                self.log(f"Ya hay un escaneo en curso. Por favor, espere.", error=True)
                QMessageBox.warning(
                    self,
                    "Escaneo en curso",
                    "Ya hay un escaneo en curso. Por favor, espere a que finalice."
                )
            return
        
        self.log(f"Iniciando escaneo detallado del dispositivo {ip}...")
        
        # Cambiar a la pestaña de detalles
        self.tab_widget.setCurrentIndex(0)
        
        # Deshabilitar el botón de escaneo
        self.scan_button.setEnabled(False)
        
        # Crear un mensaje de espera y mostrarlo en la barra de estado
        self.statusBar().showMessage(f"Escaneando dispositivo {ip} (puede tardar hasta un minuto)...")
        
        # Mostrar información preliminar de que el escaneo está en curso
        if self.selected_device and self.selected_device.ip == ip:
            current_html = self.details_text.toHtml()
            self.details_text.setHtml(
                current_html + 
                "<div style='margin-top: 20px; padding: 10px; background-color: #f0f7ff; border-left: 4px solid #0078d7;'>" +
                "<b>⏳ Escaneo detallado en curso...</b><br>" +
                "Este proceso puede tardar hasta un minuto mientras se recopila información completa del dispositivo." +
                "</div>"
            )
        
        # Crear un temporizador para mostrar que el escaneo sigue en progreso
        progress_timer = QTimer(self)
        progress_dots = 0
        
        def update_progress():
            nonlocal progress_dots
            progress_dots = (progress_dots + 1) % 4
            dots = "." * progress_dots
            self.statusBar().showMessage(f"Escaneando dispositivo {ip} (puede tardar hasta un minuto){dots}")
        
        # Iniciar el temporizador
        progress_timer.timeout.connect(update_progress)
        progress_timer.start(500)  # Actualizar cada 500ms
        
        # Función de callback para cuando se complete el escaneo
        # IMPORTANTE: Esta función se llamará desde un hilo secundario,
        # por lo que debemos asegurar que solo emita señales seguras
        def on_device_scanned(device):
            # Emitir la señal para procesar de forma segura en el hilo principal
            self.scanner_signals.device_updated.emit(device)
            
            # Es seguro detener el temporizador desde el hilo principal usando un QueuedConnection
            QMetaObject.invokeMethod(progress_timer, "stop", Qt.ConnectionType.QueuedConnection)
        
        # Iniciar el escaneo específico
        self.scanner.scan_specific_device(ip, on_device_scanned)
        
        # Configurar un temporizador de seguridad para evitar que la interfaz quede bloqueada
        safety_timer = QTimer(self)
        safety_timer.setSingleShot(True)
        
        def safety_timeout():
            if self.scanner.scanning:
                # Si después de 2 minutos sigue escaneando, forzar el término
                self.scanner.scanning = False
                progress_timer.stop()
                self.scan_button.setEnabled(True)
                self.statusBar().showMessage("El escaneo ha excedido el tiempo límite", 5000)
                self.log(f"⚠️ El escaneo de {ip} ha excedido el tiempo límite. Posible problema de conexión.", error=True)
        
        safety_timer.timeout.connect(safety_timeout)
        safety_timer.start(120000)  # 2 minutos de timeout

    # Métodos emisores de señales (desde hilos secundarios)
    def _emit_device_found(self, device: DeviceInfo):
        """Emite la señal device_found desde un hilo secundario"""
        self.scanner_signals.device_found.emit(device)
    
    def _emit_device_updated(self, device: DeviceInfo):
        """Emite la señal device_updated desde un hilo secundario"""
        self.scanner_signals.device_updated.emit(device)
    
    def _emit_scan_complete(self, success: bool, message: str):
        """Emite la señal scan_complete desde un hilo secundario"""
        self.scanner_signals.scan_complete.emit(success, message)
    
    # Slots para recibir señales (en el hilo principal)
    @pyqtSlot(object)
    def _on_device_found_safe(self, device: DeviceInfo):
        """Slot seguro para manejar la señal device_found"""
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
    
    @pyqtSlot(object)
    def _on_device_updated_safe(self, device: DeviceInfo):
        """Slot seguro para manejar la señal device_updated"""
        # Preservar el estado de bloqueo
        existing_device = self.device_model.get_device_by_ip(device.ip)
        if existing_device:
            device.blocked = existing_device.blocked
        
        # Actualizar si está bloqueado según el spoofer
        if self.spoofer and self.spoofer.is_spoofing(device.ip):
            device.blocked = True
        
        # Actualizar modelo
        self.device_model.update_device(device)
        
        # Actualizar detalles si es el dispositivo seleccionado
        if self.selected_device and device.ip == self.selected_device.ip:
            self.selected_device = device
            self._update_device_details(device)
    
    @pyqtSlot(bool, str)
    def _on_scan_complete_safe(self, success: bool, message: str):
        """Slot seguro para manejar la señal scan_complete"""
        self.scan_button.setEnabled(True)
        self.scan_button.setText("Escanear")
        
        if success:
            self.log(f"Escaneo completado: {len(self.scanner.get_all_devices())} dispositivos encontrados")
        else:
            self.log(f"Error en el escaneo: {message}", error=True)
    
    def _show_aggressive_config(self):
        """Muestra el diálogo de configuración de modo agresivo"""
        if not self.spoofer:
            QMessageBox.warning(self, "Error", "El módulo de spoofing no está inicializado")
            return
            
        dialog = AgressiveModeDialog(
            self, 
            current_rate=self.spoofer.packet_rate,
            aggressive_enabled=self.spoofer.aggressive_mode,
            block_enabled=self.spoofer.block_mode
        )
        
        if dialog.exec():
            settings = dialog.get_settings()
            self.spoofer.set_aggressive_mode(settings['aggressive_mode'])
            self.spoofer.set_block_mode(settings['block_mode'])
            self.spoofer.set_packet_rate(settings['packet_rate'])
            
            self.log(f"Configuración actualizada: Modo agresivo = {settings['aggressive_mode']}, " +
                    f"Modo bloqueo = {settings['block_mode']}, " +
                    f"Frecuencia = {settings['packet_rate']} segundos")

    def _block_device(self, device):
        """Bloquea un dispositivo específico"""
        if not device or not self.spoofer:
            return
        
        # Confirmar con el usuario
        reply = QMessageBox.question(self, "Confirmar Bloqueo", 
                                    f"¿Deseas bloquear el acceso a internet para {device.ip}?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            # Cambiar a la pestaña de estado de bloqueo
            self.tab_widget.setCurrentIndex(2)
            
            # Iniciar spoofing
            success = self.spoofer.start_spoofing(device.ip)
            
            if success:
                self.log(f"Iniciando bloqueo para {device.ip}")
                device.blocked = True
                self.device_model.update_device(device)
                
                # Actualizar detalles si es el dispositivo seleccionado
                if self.selected_device and device.ip == self.selected_device.ip:
                    self.selected_device = device
                    self._update_device_details(device)
                    self.block_button.setEnabled(False)
                    self.unblock_button.setEnabled(True)
            else:
                self.log(f"No se pudo iniciar el bloqueo para {device.ip}", error=True)
    
    def _unblock_device(self, device):
        """Desbloquea un dispositivo específico"""
        if not device or not self.spoofer:
            return
        
        # Detener el spoofing
        success = self.spoofer.stop_spoofing(device.ip)
        
        if success:
            self.log(f"Restaurando acceso para {device.ip}")
            device.blocked = False
            self.device_model.update_device(device)
            
            # Actualizar detalles si es el dispositivo seleccionado
            if self.selected_device and device.ip == self.selected_device.ip:
                self.selected_device = device
                self._update_device_details(device)
                self.block_button.setEnabled(True)
                self.unblock_button.setEnabled(False)
        else:
            self.log(f"No se pudo restaurar el acceso para {device.ip}", error=True)
    
    def _on_block_clicked(self):
        """Manejador para el botón de bloqueo"""
        if self.selected_device:
            self._block_device(self.selected_device)
    
    def _on_unblock_clicked(self):
        """Manejador para el botón de desbloqueo"""
        if self.selected_device:
            self._unblock_device(self.selected_device)
    
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
    
    def _show_about(self):
        """Muestra el diálogo de Acerca de"""
        about_text = """
        <h1>Expulsor</h1>
        <p>Versión 1.0.0</p>
        <p>Herramienta avanzada de gestión y control de red con capacidades de escaneo y restricción de dispositivos.</p>
        <p>Desarrollado como una mejora de PinguExit, con técnicas avanzadas de ARP Spoofing.</p>
        <p><b>Nota:</b> Esta herramienta debe utilizarse únicamente en entornos controlados y con fines educativos.</p>
        """
        
        QMessageBox.about(self, "Acerca de Expulsor", about_text)
    
    def closeEvent(self, event):
        """Manejador para el cierre de la ventana"""
        # Detener todos los ataques en curso
        if self.spoofer:
            self.log("Deteniendo todos los bloqueos activos...")
            self.spoofer.stop_all()
        
        # Detener escáner si está en curso
        if self.scanner.scanning:
            self.scanner.stop_scan()
        
        # Detener timers
        self.timer.stop()
        self.block_timer.stop()
        
        # Continuar con el cierre
        super().closeEvent(event)