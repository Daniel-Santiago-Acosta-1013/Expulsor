# Expulsor - Terminal Network Control Tool

Expulsor es ahora una aplicación escrita íntegramente en Rust con una interfaz TUI enfocada en operación rápida desde terminal. Permite descubrir dispositivos dentro de la red local, ejecutar fingerprinting avanzado con Nmap y restringir su tráfico desde una terminal, sin necesidad de argumentos de línea de comandos ni GUI.

## Características principales

- **TUI profesional**: interfaz fluida basada en `ratatui` con foco únicamente en teclado, resaltados dinámicos y paneles de detalles, eventos y estado.
- **Escaneo híbrido**: combinaciones de Nmap en modo rápido (`-sn`) o profundo (`-sV -O`) para obtener puertos abiertos, servicios y sistema operativo estimado.
- **Fingerprinting enriquecido**: coincidencia contra firmas descargadas, resolución DNS inversa, análisis de banners HTTP y caché local persistida en `~/.expulsor/device_db`.
- **Control de acceso**: bloqueo y restauración de dispositivos mediante reglas de firewall e inhibición del reenvío IP, replicando el flujo operativo original basado en ARP.
- **Arquitectura modular**: servicios de red, persistencia, sistema y presentación separados en capas para facilitar extensiones futuras.

## Requisitos

- Rust 1.74 o superior (se recomienda `rustup` para gestionar toolchains).
- [Nmap](https://nmap.org/download.html) instalado y disponible en el `PATH`.
- Permisos elevados para operaciones de bloqueo (`sudo`, ejecutarse como administrador, etc.).

### Instalación de Nmap (resumen)
- **Linux (Debian/Ubuntu)**: `sudo apt install nmap`
- **macOS (Homebrew)**: `brew install nmap`
- **Windows**: instalar Nmap + Npcap desde la página oficial y añadirlos al `PATH`.

## Compilación y ejecución

```bash
git clone https://github.com/Daniel-Santiago-Acosta-1013/Expulsor.git
cd Expulsor
cargo build --release
sudo ./target/release/expulsor
```

> Usa `sudo` o permisos equivalentes para permitir que las operaciones de bloqueo y escaneo profundo funcionen correctamente.

## Controles en la TUI

| Tecla                   | Acción                                                  |
|------------------------|---------------------------------------------------------|
| `r`                    | Escaneo rápido (ping/ARP + refresco incremental)        |
| `Shift + R`            | Escaneo profundo (fingerprinting completo)              |
| `Enter`                | Fingerprint detallado del dispositivo seleccionado      |
| `b` / `u`              | Bloquear / restaurar el dispositivo actual              |
| `a`                    | Alternar el modo agresivo de bloqueo                    |
| `Tab`                  | Cambiar el panel activo (dispositivos / eventos)        |
| `↑` / `↓`              | Navegar por la tabla o hacer scroll en el panel activo  |
| `q`                    | Salir de la aplicación                                  |

La columna "Bloqueo" indica el estado del dispositivo (`Restringido` / `--`). El panel de eventos muestra en tiempo real los logs generados por los servicios.

## Notas de operación

- El primer escaneo rápido se lanza automáticamente al iniciar la aplicación.
- Los fingerprints completos se almacenan en `~/.expulsor/device_db/device_fingerprints.db` para reutilizar datos recientes.
- En macOS se utiliza `pfctl`, en Linux `iptables` y en Windows `netsh advfirewall` para aplicar restricciones.
- Se recomienda ejecutar con la pantalla a un mínimo de 110×30 caracteres para una visualización óptima.

## Consideraciones éticas y legales

Expulsor está pensado para monitorizar y proteger redes propias o entornos de laboratorio. El uso en redes de terceros sin consentimiento puede infringir leyes de privacidad y telecomunicaciones. Utiliza la herramienta de forma responsable y únicamente donde tengas autorización expresa.

## Contribuir

1. Haz un fork del repositorio.
2. Crea una rama (`git checkout -b feature/mi-mejora`).
3. Implementa la mejora o corrección (`cargo fmt && cargo clippy` antes de abrir el PR).
4. Envía un Pull Request describiendo claramente los cambios.

¡Gracias por probar la nueva versión en Rust de Expulsor!
