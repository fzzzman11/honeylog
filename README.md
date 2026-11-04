<div align="center">

<img src="assets/banner.gif" width="100%" alt="Shadow-HoneyLog banner" />

<h1>🍯 Shadow-HoneyLog</h1>

<b>Honeypot SSH de alta interacción y generación de inteligencia de amenazas en tiempo real</b>

<br><br>

<img src="https://img.shields.io/badge/Bash-4.4%2B-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white" alt="Bash" />
<img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Debian%20%7C%20Parrot-1793D1?style=for-the-badge&logo=linux&logoColor=white" alt="Platform" />
<img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License" />
<img src="https://img.shields.io/badge/Security-Defensive%20Monitoring-red?style=for-the-badge" alt="Security" />
<img src="https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge" alt="Version" />

<br><br>

<a href="#descripción-técnica">Descripción</a> ·
<a href="#arquitectura">Arquitectura</a> ·
<a href="#instalación">Instalación</a> ·
<a href="#guía-de-uso">Uso</a> ·
<a href="#ejemplo-de-reporte-forense">Reporte</a>

</div>

---

> [!WARNING]
> **Uso exclusivamente autorizado.** Shadow-HoneyLog debe ejecutarse únicamente sobre sistemas propios o sobre los que exista una autorización escrita explícita. La exposición de servicios SSH a Internet sin el debido aislamiento puede derivar en accesos no autorizados, uso del host como pivote o responsabilidades legales. El autor no se hace responsable del mal uso de esta herramienta.

---

## Descripción técnica

**Shadow-HoneyLog** es un sensor defensivo escrito en Bash puro que convierte una instancia controlada de OpenSSH en un honeypot de alta interacción. En lugar de emular un servidor SSH, utiliza el demonio `sshd` real como superficie de interacción y consume sus eventos de autenticación para:

- Detectar intentos de acceso SSH fallidos en tiempo real.
- Extraer la IP de origen, el usuario probado y el puerto de origen.
- Persistir la evidencia en un formato estable y fácil de parsear.
- Generar un reporte forense con rankings de IPs atacantes y credenciales/usuarios más probados.

El script no abre puertos ni implementa cifrado: la interacción la provee `sshd`; Shadow-HoneyLog actúa como la capa de **recolección, normalización y análisis**. Esta separación mantiene el sensor simple, auditable y portable.

### Características

- Monitoreo en tiempo real de `/var/log/auth.log` o `journalctl` (fallback automático).
- Soporte para logs de `sshd` y `sshd-session` (OpenSSH moderno).
- Detección de `Failed password`, `Failed publickey` y `Failed keyboard-interactive`.
- Extracción de IPv4, IPv6 y puerto de origen.
- Persistencia en `logs/captured_attacks.log` con timestamp ISO 8601.
- Reporte con totales, ventana temporal, IPs únicas, usuarios únicos y rankings.
- Detección de tráfico proveniente de loopback para advertir sobre túneles inversos.
- Control de privilegios de root y verificación de dependencias.
- Colores ANSI con desactivación automática cuando la salida no es una TTY.
- Sin dependencias externas más allá de las utilidades base de GNU/Linux.

---

## Arquitectura

```text
                    +----------------------+
                    |      Atacante        |
                    +----------+-----------+
                               |
                     TCP/22 o puerto efímero
                               |
              +----------------v-----------------+
              |   LAN / Serveo / VPS público     |
              +----------------+-----------------+
                               |
                    Conexión al honeypot
                               |
                    +----------v-----------+
                    |   sshd real (OpenSSH) |  <-- Interacción real
                    +----------+-----------+
                               |
                     /var/log/auth.log
                     o journalctl -t sshd
                               |
                    +----------v-----------+
                    |  honeylog.sh start   |  <-- Sensor y parser
                    +----------+-----------+
                               |
                    logs/captured_attacks.log
                               |
                    +----------v-----------+
                    |  honeylog.sh report  |  <-- Threat intelligence
                    +----------------------+
```

| Componente | Responsabilidad |
|---|---|
| `sshd` | Expone la superficie SSH y registra los eventos de autenticación. |
| `honeylog.sh start` | Lee el log en tiempo real, filtra intentos fallidos y persiste la evidencia. |
| `logs/captured_attacks.log` | Fuente de verdad local para el análisis forense. |
| `honeylog.sh report` | Agrega, cuenta y presenta los indicadores de amenaza. |

---

## Requisitos

- Linux basado en Debian: Debian, Ubuntu, Kali Linux, Parrot OS.
- Bash 4.4 o superior.
- OpenSSH Server instalado y en ejecución (`ssh.service` o `sshd.service`).
- Privilegios de root para el modo `start` (lectura de logs del sistema).
- Utilidades base: `awk`, `sed`, `grep`, `tail`, `sort`, `uniq`, `head`, `date`.
- Opcional: `journalctl` si el sistema no conserva `/var/log/auth.log`.

Verificación rápida:

```bash
bash --version | head -n 1
systemctl status ssh --no-pager
command -v awk sed grep tail journalctl
```

---

## Instalación

```bash
git clone https://github.com/fzzzman11/honeylog.git
cd honeylog
chmod +x honeylog.sh
```

El directorio `logs/` se crea automáticamente en el primer arranque. Si el script se ejecuta con `sudo`, la carpeta se transfiere al usuario que invocó `sudo` para permitir reportes sin privilegios elevados.

---

## Guía de uso

### 1. Monitoreo local en LAN

Inicia el sensor con privilegios de root:

```bash
sudo ./honeylog.sh start
```

Desde otra máquina de la misma LAN, simula un intento fallido contra el honeypot:

```bash
ssh usuario_falso@192.168.1.50
# Introduce una contraseña incorrecta
```

Salida esperada en el sensor:

```text
[+] Entorno inicializado correctamente en /home/analista/honeylog/logs
[*] Fuente de eventos: /var/log/auth.log
[*] Evidencia persistente: /home/analista/honeylog/logs/captured_attacks.log
[!] Presiona Ctrl+C para interrumpir la vigilancia.

[!] INTRUSIÓN DETECTADA | IP: 192.168.1.77 | Usuario: usuario_falso | Puerto: 51422 | 2026-11-04 02:22:59
```

Detén la vigilancia con `Ctrl+C`.

### 2. Generación del reporte

En otra terminal, o después de detener el sensor:

```bash
./honeylog.sh report
```

Si el archivo de evidencia pertenece a `root` y no puede leerse, ejecuta:

```bash
sudo ./honeylog.sh report
```

Para ampliar los rankings:

```bash
TOP_N=10 ./honeylog.sh report
```

### 3. Exposición externa con Serveo

El comando debe ejecutarse **en el host del honeypot**, no en la máquina atacante. Serveo crea un puerto TCP público efímero en su infraestructura y lo reenvía a `localhost:22` a través de un túnel SSH inverso.

Terminal 1 — sensor:

```bash
sudo ./honeylog.sh start
```

Terminal 2 — túnel:

```bash
ssh -R 0:localhost:22 serveo.net
```

La salida de Serveo indicará el puerto público asignado:

```text
Forwarding TCP connections from serveo.net:43127
```

Prueba desde una red externa:

```bash
ssh -p 43127 usuario_falso@serveo.net
# Introduce una contraseña incorrecta
```

Para solicitar un puerto remoto fijo (si está disponible):

```bash
ssh -R 2222:localhost:22 serveo.net
```

Para mantener el túnel estable:

```bash
ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -R 0:localhost:22 serveo.net
```

O con `autossh`:

```bash
autossh -M 0 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" \
  -R 0:localhost:22 serveo.net
```

> [!NOTE]
> Serveo es un servicio de terceros y gratuito. Su disponibilidad, límites y política de retención no están garantizados. Para un laboratorio reproducible o una exposición prolongada, utiliza un VPS propio, una red de laboratorio aislada o un túnel corporativo con registro de conexiones.

---

## Nota técnica: comportamiento de sockets en túneles TCP

Esta diferencia es crítica al interpretar el reporte.

### Conexión directa a un VPS o a un host en LAN

Cuando un atacante se conecta directamente al puerto 22 del honeypot, `sshd` acepta un socket cuyo extremo remoto es la IP real del atacante. El kernel mantiene la tupla:

```text
(IP_atacante:puerto_efímero) -> (IP_honeypot:22)
```

Por lo tanto, `/var/log/auth.log` registra la IP pública (VPS) o privada (LAN) del atacante.

### Conexión a través de un túnel inverso (Serveo)

Con `ssh -R 0:localhost:22 serveo.net`, el flujo es distinto:

1. El atacante conecta a `serveo.net:PUERTO_PUBLICO`.
2. El borde de Serveo acepta esa conexión TCP.
3. Serveo transporta los bytes por el canal SSH ya establecido entre el cliente y Serveo.
4. El cliente SSH del honeypot abre una **nueva conexión local** hacia `127.0.0.1:22` (o `::1`).
5. `sshd` acepta esa conexión local y registra como origen `127.0.0.1`.

La IP original del atacante es metadato de la conexión en el borde de Serveo; nunca viaja como información de red hasta el backend. Por eso el reporte mostrará `127.0.0.1` y no la IP pública del atacante. El puerto de origen registrado también es efímero y local, no el puerto público asignado por Serveo.

| Escenario | Origen observado por `sshd` | ¿IP real del atacante? |
|---|---|---|
| LAN directa | `192.168.x.y` | Sí |
| VPS con IP pública | IP pública del atacante | Sí |
| Túnel inverso Serveo | `127.0.0.1` / `::1` | No |
| NAT o balanceador L4 sin metadatos | IP del relay | No |

### Cómo atribuir la IP real

- **Exposición directa:** usa un VPS con IP pública y mapea el puerto 22 o un puerto alternativo. Es la opción más simple para obtener la IP real.
- **Relay con registro:** si usas HAProxy, Nginx Stream u otro proxy TCP, conserva sus logs como fuente autoritativa de la IP de origen y correlaciona por fecha, puerto y usuario.
- **PROXY protocol:** permite propagar la IP original, pero OpenSSH estándar no interpreta PROXY protocol de forma nativa. Requiere un `sshd` parcheado o una pasarela SSH que lo soporte; no ocurre con Serveo.
- **No confíes en loopback:** un origen `127.0.0.1` puede ser un túnel legítimo del laboratorio o un proxy local comprometido. Correlaciona con los logs del túnel y con el puerto público asignado.

---

## Formato de la evidencia

Cada evento se agrega a `logs/captured_attacks.log` con el siguiente formato:

```text
[2026-11-04 02:22:59] IP: 203.0.113.42 | User: root | Port: 51422
```

| Campo | Descripción |
|---|---|
| `timestamp` | Fecha y hora local del sensor en formato ISO 8601. |
| `IP` | IP de origen observada por `sshd` (`desconocida` si no fue posible extraerla). |
| `User` | Usuario probado (`desconocido` si no fue posible extraerlo). |
| `Port` | Puerto TCP de origen observado por `sshd` (`N/A` si no está presente). |

El reporte es compatible con registros antiguos que no incluyen el campo `Port`.

---

## Ejemplo de reporte forense

```text
==================================================================
           REPORTE FORENSE DE INTELIGENCIA DE AMENAZAS
==================================================================

[+] Resumen de actividad
    Intentos registrados:        1284
    IPs únicas:                  87
    Usuarios únicos:             143
    Primera detección:           2026-11-01 03:12:44
    Última detección:            2026-11-04 02:22:59

[+] Top 5 direcciones IP más agresivas:
    INTENTOS   DIRECCIÓN IP
    --------   ------------
          412   203.0.113.42
          189   198.51.100.17
           96   192.0.2.88
           71   198.51.100.23
           54   203.0.113.9

[+] Top 5 usuarios más probados:
    INTENTOS   USUARIO
    --------   -------
          318   root
          204   admin
          151   ubuntu
           88   test
           63   oracle

==================================================================
```

Ejemplo con tráfico proveniente de un túnel:

```text
[!] Se detectó tráfico desde loopback (127.0.0.1/::1).
[!] Probablemente proviene de un túnel inverso (Serveo): la IP real del atacante no es visible en auth.log.
[!] Consulta la nota de arquitectura de sockets en el README.
```

---

## Estructura del repositorio

```text
honeylog/
├── honeylog.sh              # Sensor, parser y generador de reportes
├── README.md                # Documentación técnica
├── LICENSE                  # Licencia MIT
├── .gitignore               # Exclusión de logs y archivos temporales
├── assets/
│   └── banner.gif           # Banner animado del README
└── logs/                    # Generado en tiempo de ejecución (ignorado por Git)
    └── captured_attacks.log
```

---

## Seguridad y hardening

- Despliega el honeypot en una **VM, contenedor o red aislada**, nunca en el mismo host que tus servicios críticos.
- No reutilices credenciales reales, claves SSH privadas ni datos sensibles dentro del honeypot.
- Ejecuta una instancia dedicada de `sshd` en un puerto alternativo o en una interfaz de laboratorio.
- No debilites la configuración SSH de producción. El honeypot debe tener su propio archivo de configuración y su propio servicio.
- Restringe la salida de red del honeypot para evitar que sea utilizado como pivote.
- Aplica límites de recursos y de concurrencia (`MaxStartups`, `LoginGraceTime`, `MaxAuthTries`).
- Considera `fail2ban` solo si tu objetivo es bloquear; para investigación suele ser preferible observar y limitar la tasa sin cortar la evidencia.
- Rota y protege los logs. Para cadena de custodia, complementa con `tcpdump`, hashes periódicos o almacenamiento append-only.
- Revisa las obligaciones legales y de privacidad aplicables al tratamiento de direcciones IP y nombres de usuario.

---

## Limitaciones

- Es un sensor pasivo: no bloquea ni modifica el tráfico.
- Depende del formato de los logs de OpenSSH y de la configuración de `sshd`.
- Solo analiza autenticaciones fallidas por contraseña, clave pública o keyboard-interactive.
- No realiza geolocalización ni enriquecimiento con fuentes externas.
- La rotación de logs puede omitir eventos si el sensor no está activo.
- En túneles TCP inversos no es posible atribuir la IP real del atacante sin metadatos adicionales.

---

## Roadmap

- Exportación de reportes en JSON y CSV.
- Enriquecimiento opcional con GeoIP y ASN.
- Persistencia en SQLite para consultas históricas.
- Unidad `systemd` para ejecución como servicio.
- Normalización de IPv6 y deduplicación configurable.
- Integración con SIEM mediante syslog o webhook.

---

## Licencia

Este proyecto se distribuye bajo la **Licencia MIT**. Consulta [LICENSE](LICENSE) para más detalles.

---

## Autor

**Shadow-HoneyLog** fue desarrollado como proyecto de laboratorio y portafolio de ciberseguridad ofensiva/defensiva.

- GitHub: [@fzzzman11](https://github.com/fzzzman11)
- Reportes de seguridad: abre un security advisory o contacta al mantenedor.

Si este proyecto te resulta útil, considera darle una estrella en GitHub.
