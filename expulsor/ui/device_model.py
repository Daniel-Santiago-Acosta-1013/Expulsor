"""
Modelo de datos para dispositivos de red en la interfaz gráfica
"""

from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex, QVariant
from PyQt6.QtGui import QColor


class DeviceTableModel(QAbstractTableModel):
    """Modelo para mostrar dispositivos en una tabla"""
    
    HEADERS = ['IP', 'MAC', 'Hostname', 'Fabricante', 'Estado', 'Bloqueado']
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.devices = []
    
    def rowCount(self, parent=QModelIndex()):
        """Retorna el número de filas"""
        return len(self.devices)
    
    def columnCount(self, parent=QModelIndex()):
        """Retorna el número de columnas"""
        return len(self.HEADERS)
    
    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        """Retorna los datos para mostrar en la tabla"""
        if not index.isValid() or not (0 <= index.row() < len(self.devices)):
            return QVariant()
        
        device = self.devices[index.row()]
        column = index.column()
        
        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return device.ip
            elif column == 1:
                return device.mac
            elif column == 2:
                return device.hostname or "Desconocido"
            elif column == 3:
                return device.vendor or "Desconocido"
            elif column == 4:
                return device.status
            elif column == 5:
                return "Sí" if device.blocked else "No"
        
        elif role == Qt.ItemDataRole.BackgroundRole:
            # Colorear según el estado
            if device.blocked:
                return QColor(255, 200, 200)  # Rojo claro para bloqueados
            elif device.status == "inactivo":
                return QColor(230, 230, 230)  # Gris para inactivos
            elif device.ip == device.gateway_ip:
                return QColor(220, 240, 255)  # Azul claro para la puerta de enlace
            elif device.ip == device.local_ip:
                return QColor(220, 255, 220)  # Verde claro para este dispositivo
        
        elif role == Qt.ItemDataRole.TextAlignmentRole:
            return Qt.AlignmentFlag.AlignCenter
        
        return QVariant()
    
    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        """Retorna los datos de cabecera"""
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.HEADERS[section]
        return QVariant()
    
    def update_devices(self, devices):
        """Actualiza la lista de dispositivos"""
        self.beginResetModel()
        self.devices = devices
        self.endResetModel()
    
    def update_device(self, updated_device):
        """Actualiza un dispositivo específico"""
        for i, device in enumerate(self.devices):
            if device.ip == updated_device.ip:
                self.devices[i] = updated_device
                self.dataChanged.emit(
                    self.index(i, 0),
                    self.index(i, self.columnCount() - 1)
                )
                break
        else:
            # Si no se encontró, añadirlo
            self.beginInsertRows(QModelIndex(), len(self.devices), len(self.devices))
            self.devices.append(updated_device)
            self.endInsertRows()
    
    def get_device_at_row(self, row):
        """Retorna el dispositivo en una fila específica"""
        if 0 <= row < len(self.devices):
            return self.devices[row]
        return None
    
    def get_device_by_ip(self, ip):
        """Busca un dispositivo por su IP"""
        for device in self.devices:
            if device.ip == ip:
                return device
        return None