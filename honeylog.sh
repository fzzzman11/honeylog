#!/usr/bin/env bash
# ==============================================================================
#  Shadow-HoneyLog
#  SSH honeypot sensor and threat intelligence report generator
#
#  Repository : https://github.com/<TU_USUARIO>/Shadow-HoneyLog
#  License    : MIT
#  Platform   : Linux (Debian, Ubuntu, Kali, Parrot OS)
# ==============================================================================

set -uo pipefail
export LC_ALL=C

VERSION="1.0.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs"
ATTACK_LOG="${LOG_DIR}/captured_attacks.log"
TOP_N="${TOP_N:-5}"

if [[ -t 1 ]]; then
    RED=$'\e[0;31m'
    GREEN=$'\e[0;32m'
    YELLOW=$'\e[1;33m'
    BLUE=$'\e[0;34m'
    PURPLE=$'\e[0;35m'
    CYAN=$'\e[0;36m'
    NC=$'\e[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    PURPLE=''
    CYAN=''
    NC=''
fi

info()    { printf '%s\n' "${CYAN}[*] $*${NC}"; }
success() { printf '%s\n' "${GREEN}[+] $*${NC}"; }
warn()    { printf '%s\n' "${YELLOW}[!] $*${NC}"; }
error()   { printf '%s\n' "${RED}[x] $*${NC}" >&2; }

banner() {
    printf '%s\n' "${PURPLE}"
    printf '%s\n' \
        '  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗' \
        '  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║' \
        '  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║' \
        '  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║' \
        '  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝' \
        '  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ '
    printf '%s\n' "${NC}"
    printf '%s\n' "${CYAN}==================================================================${NC}"
    printf '%s\n' "${CYAN}       SHADOW-HONEYLOG v${VERSION} | SSH TRAP & THREAT INTEL${NC}"
    printf '%s\n' "${CYAN}==================================================================${NC}"
}

usage() {
    banner
    printf '\n%s\n' "${BLUE}Modo de uso:${NC}"
    printf '  %s\n' "${GREEN}sudo ./honeylog.sh start${NC}    Inicia la vigilancia SSH en tiempo real"
    printf '  %s\n' "${GREEN}./honeylog.sh report${NC}         Genera el reporte forense"
    printf '  %s\n' "${GREEN}./honeylog.sh --help${NC}         Muestra esta ayuda"
    printf '  %s\n' "${GREEN}./honeylog.sh --version${NC}      Muestra la versión"
    printf '\n%s\n' "${BLUE}Variables de entorno:${NC}"
    printf '  %s\n' "TOP_N=10 ./honeylog.sh report    Cambia el tamaño de los rankings (default: 5)"
    printf '\n'
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "Este comando requiere privilegios de root. Ejecuta: sudo $0 start"
        exit 1
    fi
}

check_dependencies() {
    local cmd missing=()
    for cmd in awk sed grep tail sort uniq head date; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done

    if (( ${#missing[@]} > 0 )); then
        error "Faltan dependencias obligatorias: ${missing[*]}"
        exit 1
    fi
}

init_environment() {
    if ! mkdir -p "$LOG_DIR"; then
        error "No se pudo crear el directorio de logs: $LOG_DIR"
        exit 1
    fi

    if ! touch "$ATTACK_LOG"; then
        error "No se pudo crear el archivo de evidencia: $ATTACK_LOG"
        exit 1
    fi

    chmod 750 "$LOG_DIR" 2>/dev/null || true
    chmod 640 "$ATTACK_LOG" 2>/dev/null || true

    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        chown -R "${SUDO_USER}:" "$LOG_DIR" 2>/dev/null || true
    fi
}

detect_auth_source() {
    local candidate
    for candidate in /var/log/auth.log /var/log/secure; do
        if [[ -r "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done

    if command -v journalctl >/dev/null 2>&1; then
        printf 'journalctl'
        return 0
    fi

    return 1
}

process_line() {
    local line="$1"
    local timestamp src_ip username port

    if [[ "$line" != *"Failed password"* && \
          "$line" != *"Failed publickey"* && \
          "$line" != *"Failed keyboard-interactive"* ]]; then
        return 0
    fi

    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    src_ip="$(sed -nE 's/.* from ([^ ]+) port [0-9]+.*/\1/p' <<< "$line" | head -n 1)"
    if [[ -z "$src_ip" ]]; then
        src_ip="$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "$line" | tail -n 1 || true)"
    fi
    [[ -z "$src_ip" ]] && src_ip="desconocida"

    username="$(sed -nE 's/.* for (invalid user )?([^ ]+) from .*/\2/p' <<< "$line" | head -n 1)"
    [[ -z "$username" ]] && username="desconocido"

    port="$(sed -nE 's/.* port ([0-9]+).*/\1/p' <<< "$line" | head -n 1)"
    [[ -z "$port" ]] && port="N/A"

    printf '%s\n' "${RED}[!] INTRUSIÓN DETECTADA${NC} | IP: ${CYAN}${src_ip}${NC} | Usuario: ${YELLOW}${username}${NC} | Puerto: ${port} | ${timestamp}"
    printf '[%s] IP: %s | User: %s | Port: %s\n' "$timestamp" "$src_ip" "$username" "$port" >> "$ATTACK_LOG"
    return 0
}

monitor_ssh_attacks() {
    local log_source

    if ! log_source="$(detect_auth_source)"; then
        error "No se encontró auth.log, secure ni journalctl. Verifica el servicio SSH."
        exit 1
    fi

    printf '\n'
    success "Entorno inicializado correctamente en $LOG_DIR"
    info "Fuente de eventos: $log_source"
    info "Evidencia persistente: $ATTACK_LOG"
    warn "Presiona Ctrl+C para interrumpir la vigilancia."
    printf '\n'

    trap 'printf "\n"; warn "Vigilancia detenida por el operador."; exit 0' INT TERM

    if [[ "$log_source" == "journalctl" ]]; then
        journalctl -f -n 0 --no-pager -t sshd -t sshd-session 2>/dev/null | \
            while IFS= read -r line; do
                process_line "$line"
            done
    else
        tail -n 0 -F -- "$log_source" 2>/dev/null | \
            while IFS= read -r line; do
                process_line "$line"
            done
    fi
}

extract_ips() {
    awk -F'IP: ' '
        NF > 1 {
            split($2, fields, " \\| ")
            ip = fields[1]
            gsub(/^[ \t]+|[ \t]+$/, "", ip)
            if (ip != "" && ip != "desconocida") print ip
        }
    ' "$ATTACK_LOG"
}

extract_users() {
    awk -F'User: ' '
        NF > 1 {
            split($2, fields, " \\| ")
            user = fields[1]
            gsub(/^[ \t]+|[ \t]+$/, "", user)
            if (user != "" && user != "desconocido") print user
        }
    ' "$ATTACK_LOG"
}

print_ranking() {
    local title="$1"
    local header="$2"
    local ranking="$3"

    printf '\n%s\n' "${GREEN}[+] ${title}${NC}"

    if [[ -z "$ranking" ]]; then
        printf '    (sin datos)\n'
        return 0
    fi

    printf '    %9s   %s\n' "INTENTOS" "$header"
    printf '    %9s   %s\n' "--------" "------------"
    while read -r count value; do
        printf '    %9s   %s\n' "$count" "$value"
    done <<< "$ranking"
}

generate_report() {
    local total unique_ips unique_users first_seen last_seen
    local ip_ranking user_ranking

    printf '\n%s\n' "${CYAN}==================================================================${NC}"
    printf '%s\n' "${PURPLE}           REPORTE FORENSE DE INTELIGENCIA DE AMENAZAS${NC}"
    printf '%s\n\n' "${CYAN}==================================================================${NC}"

    if [[ ! -e "$ATTACK_LOG" ]]; then
        warn "No existe $ATTACK_LOG. Inicia el monitoreo primero: sudo ./honeylog.sh start"
        return 0
    fi

    if [[ ! -r "$ATTACK_LOG" ]]; then
        error "Sin permisos de lectura sobre $ATTACK_LOG. Ejecuta el reporte con sudo."
        return 1
    fi

    if [[ ! -s "$ATTACK_LOG" ]]; then
        warn "El registro está vacío. Ningún atacante ha caído en la trampa todavía."
        return 0
    fi

    total="$(grep -cE '^\[[^]]+\] IP:' "$ATTACK_LOG" || true)"
    unique_ips="$(extract_ips | sort -u | wc -l | tr -d ' ')"
    unique_users="$(extract_users | sort -u | wc -l | tr -d ' ')"
    first_seen="$(head -n 1 "$ATTACK_LOG" | sed -nE 's/^\[([^]]+)\].*/\1/p')"
    last_seen="$(tail -n 1 "$ATTACK_LOG" | sed -nE 's/^\[([^]]+)\].*/\1/p')"
    first_seen="${first_seen:-N/A}"
    last_seen="${last_seen:-N/A}"

    printf '%s\n' "${GREEN}[+] Resumen de actividad${NC}"
    printf '    %-28s %s\n' "Intentos registrados:" "$total"
    printf '    %-28s %s\n' "IPs únicas:" "$unique_ips"
    printf '    %-28s %s\n' "Usuarios únicos:" "$unique_users"
    printf '    %-28s %s\n' "Primera detección:" "$first_seen"
    printf '    %-28s %s\n' "Última detección:" "$last_seen"

    ip_ranking="$(extract_ips | sort | uniq -c | sort -rn | head -n "$TOP_N")"
    user_ranking="$(extract_users | sort | uniq -c | sort -rn | head -n "$TOP_N")"

    print_ranking "Top ${TOP_N} direcciones IP más agresivas:" "DIRECCIÓN IP" "$ip_ranking"
    print_ranking "Top ${TOP_N} usuarios más probados:" "USUARIO" "$user_ranking"

    if extract_ips | grep -qxE '127\.0\.0\.1|::1'; then
        printf '\n'
        warn "Se detectó tráfico desde loopback (127.0.0.1/::1)."
        warn "Probablemente proviene de un túnel inverso (Serveo): la IP real del atacante no es visible en auth.log."
        warn "Consulta la nota de arquitectura de sockets en el README."
    fi

    printf '\n%s\n' "${CYAN}==================================================================${NC}"
}

case "${1:-}" in
    start)
        check_root
        check_dependencies
        banner
        init_environment
        monitor_ssh_attacks
        ;;
    report)
        check_dependencies
        banner
        generate_report
        ;;
    help|-h|--help)
        usage
        ;;
    version|-v|--version)
        printf 'Shadow-HoneyLog v%s\n' "$VERSION"
        ;;
    *)
        usage
        if [[ -n "${1:-}" ]]; then
            printf '\n'
            error "Opción no válida: $1"
        fi
        exit 1
        ;;
esac
