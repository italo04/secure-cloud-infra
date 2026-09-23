#!/usr/bin/env bash
# ==============================================================================
# Script: harden_linux.sh
# Descripción: Automatización de bastionado (Hardening) a nivel de sistema operativo
#              alineado con el CIS Linux Benchmark y el CIS AWS Foundations Benchmark.
# Autor: Lead Cloud Security & DevSecOps Engineer (github.com/italo04/secure-cloud-infra)
# ==============================================================================

set -euo pipefail

# Constantes y Colores
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date -u +"%Y-%m-%dT%H:%M:%SZ") - $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date -u +"%Y-%m-%dT%H:%M:%SZ") - $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date -u +"%Y-%m-%dT%H:%M:%SZ") - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date -u +"%Y-%m-%dT%H:%M:%SZ") - $1" >&2
}

# 1. Verificación de Privilegios de Superusuario
if [[ $EUID -ne 0 ]]; then
    log_error "Este script debe ejecutarse con privilegios de root (sudo)."
    exit 1
fi

log_info "Iniciando proceso de bastionado de sistema operativo bajo CIS Benchmarks..."

# 2. Hardening del Servicio SSH (OpenSSH)
# CIS Benchmark: Deshabilitar Root, Deshabilitar Contraseñas, Forzar Llaves Públicas, Timeout estricto
log_info "1/5 Aplicando bastionado a OpenSSH..."

SSH_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSH_HARDENING_CONF="${SSH_DROPIN_DIR}/99-cis-hardening.conf"

mkdir -p "${SSH_DROPIN_DIR}"

cat <<'EOF' > "${SSH_HARDENING_CONF}"
# CIS Linux Benchmark - Hardened SSH Configuration
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
LogLevel VERBOSE
UsePAM yes
EOF

chmod 0600 "${SSH_HARDENING_CONF}"
chown root:root "${SSH_HARDENING_CONF}"

# Asegurar compatibilidad en sshd_config base
if grep -q "^Include /etc/ssh/sshd_config.d/\*.conf" /etc/ssh/sshd_config; then
    log_info "Directiva Include activa en /etc/ssh/sshd_config."
else
    # Insertar al inicio de sshd_config si no existe la directiva include
    sed -i '1s|^|Include /etc/ssh/sshd_config.d/*.conf\n|' /etc/ssh/sshd_config
fi

# Validar sintaxis antes de reiniciar sshd
if sshd -t; then
    systemctl reload sshd || systemctl reload ssh || log_warn "No se pudo recargar el servicio ssh (puede requerir reinicio)."
    log_success "Configuración SSH endurecida y verificada correctamente."
else
    log_error "Error en la validación sintáctica de OpenSSH. Revise ${SSH_HARDENING_CONF}."
    exit 1
fi

# 3. Hardening a Nivel de Kernel (sysctl)
# CIS Benchmark: Deshabilitar ICMP redirects, deshabilitar IP forwarding, habilitar TCP syncookies, ASLR
log_info "2/5 Aplicando parámetros de seguridad al kernel Linux (sysctl)..."

SYSCTL_CONF="/etc/sysctl.d/99-security-hardening.conf"

cat <<'EOF' > "${SYSCTL_CONF}"
# CIS Benchmark - Network & Memory Security Parameters

# Deshabilitar reenvío de paquetes (Este host no actúa como router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Deshabilitar aceptación y envío de redirecciones ICMP (Prevención de ataques MitM)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Deshabilitar enrutamiento de origen (Source Routing)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Habilitar protección SYN Flood (TCP SYN Cookies)
net.ipv4.tcp_syncookies = 1

# Habilitar Reverse Path Filtering (Mitigación de IP Spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Registrar paquetes con direcciones sospechosas o imposibles (Martian packets)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignorar paquetes broadcast ICMP echo (Prevención Smurf Attacks)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Habilitar Address Space Layout Randomization (ASLR)
kernel.randomize_va_space = 2

# Protección de enlaces simbólicos y enlaces duros
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Deshabilitar volcado de memoria para binarios con SUID
fs.suid_dumpable = 0
EOF

chmod 0644 "${SYSCTL_CONF}"
sysctl --system >/dev/null 2>&1 || sysctl -p "${SYSCTL_CONF}" >/dev/null 2>&1
log_success "Parámetros sysctl aplicados al kernel."

# 4. Configuración del Firewall a Nivel de Kernel (iptables)
# CIS Benchmark: Política por defecto DROP, permitir loopback, permitir conexiones establecidas y puerto SSH
log_info "3/5 Configurando cortafuegos de kernel mediante iptables..."

# Asegurar herramientas de iptables y persistencia instaladas
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq iptables iptables-persistent netfilter-persistent >/dev/null 2>&1 || true

# Limpieza inicial de reglas existentes
iptables -F
iptables -X
iptables -t nat -F || true
iptables -t nat -X || true
iptables -t mangle -F || true
iptables -t mangle -X || true

# Políticas por defecto: Denegación implícita
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Permitir tráfico local en interfaz de loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Descartar paquetes inválidos de inmediato
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Permitir conexiones establecidas y relacionadas (Stateful Inspection)
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Permitir tráfico SSH explícito
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# Guardar reglas persistentes
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
netfilter-persistent save >/dev/null 2>&1 || true
log_success "Reglas de iptables configuradas (Default DROP) y persistidas."

# 5. Seguridad en Auditoría y Permisos Estrictos de Archivos de Logs
log_info "4/5 Configurando permisos estrictos de registros de auditoría (/var/log/auth.log)..."

# Asegurar archivo /var/log/auth.log con permisos restrictivos
if [[ ! -f /var/log/auth.log ]]; then
    touch /var/log/auth.log
fi
chmod 0640 /var/log/auth.log
chown root:adm /var/log/auth.log

# Crear archivo de auditoría del sistema de detección de intrusiones
readonly THREAT_LOG="/var/log/threat_detection.log"
touch "${THREAT_LOG}"
chmod 0640 "${THREAT_LOG}"
chown root:adm "${THREAT_LOG}"

# Configurar permisos estrictos en directorio de logs
chmod 0750 /var/log

log_success "Permisos de registros asegurados (auth.log y threat_detection.log)."

# 6. Deshabilitar Servicios y Módulos de Red Inseguros
log_info "5/5 Deshabilitando protocolos obsoletos y servicios innecesarios..."

MODPROBE_BLACKLIST="/etc/modprobe.d/cis-blacklist.conf"
cat <<'EOF' > "${MODPROBE_BLACKLIST}"
# Deshabilitar protocolos de red legacy / inseguros
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

chmod 0644 "${MODPROBE_BLACKLIST}"

log_success "Bastionado del sistema operativo completado satisfactoriamente bajo CIS Benchmarks."
exit 0
