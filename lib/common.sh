#!/usr/bin/env bash
# lib/common.sh — utilitários compartilhados por todos os módulos do vps-sec.
# Carregado via `source`. Não executar diretamente.

# ── Caminhos canônicos ──────────────────────────────────────────────────────
: "${VPS_SEC_PREFIX:=/opt/vps-sec}"
: "${VPS_SEC_CONFIG:=/etc/vps-sec/config}"
: "${VPS_SEC_STATE:=/var/lib/vps-sec}"
: "${VPS_SEC_LOG_DIR:=/var/log/vps-sec}"
: "${VPS_SEC_BACKUP_DIR:=/var/backups/vps-sec}"

VPS_SEC_LIB="${VPS_SEC_PREFIX}/lib"
VPS_SEC_MODULES="${VPS_SEC_PREFIX}/modules"

# ── Cores (só em TTY) ───────────────────────────────────────────────────────
if [[ -t 2 ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_MAGENTA=$'\033[35m'; C_CYAN=$'\033[36m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''
  C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_MAGENTA=''; C_CYAN=''
fi

# ── Logging (sempre para stderr, para não poluir stdout de --json) ──────────
log()   { printf '%s[vps-sec]%s %s\n'      "$C_DIM"    "$C_RESET" "$*" >&2; }
info()  { printf '%s[info]%s %s\n'         "$C_BLUE"   "$C_RESET" "$*" >&2; }
warn()  { printf '%s[aviso]%s %s\n'        "$C_YELLOW" "$C_RESET" "$*" >&2; }
error() { printf '%s[erro]%s %s\n'         "$C_RED"    "$C_RESET" "$*" >&2; }
ok()    { printf '%s[ok]%s %s\n'           "$C_GREEN"  "$C_RESET" "$*" >&2; }
die()   { error "$*"; exit 1; }

# Log persistente para o monitor/daemon (append em arquivo, com timestamp UTC).
log_file() {
  local msg="$1" file="${2:-$VPS_SEC_LOG_DIR/vps-sec.log}"
  mkdir -p "$(dirname "$file")" 2>/dev/null || true
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$msg" >>"$file" 2>/dev/null || true
}

# ── Guards de ambiente ──────────────────────────────────────────────────────
require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    die "Este comando precisa de root. Rode: sudo vps-sec ${VPS_SEC_SUBCMD:-$*}"
  fi
}

require_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "Dependência ausente: '$c'. Instale com: apt-get install -y $c"
  done
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# ── Detecção de sistema (executada uma vez, exporta variáveis) ──────────────
# Popula: OS_ID, OS_VERSION_ID, OS_PRETTY, SSH_UNIT, SSH_SYSLOG_IDS, HAS_DOCKER,
#         HAS_UFW, HAS_FAIL2BAN
detect_system() {
  OS_ID="unknown"; OS_VERSION_ID=""; OS_PRETTY="unknown"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION_ID="${VERSION_ID:-}"
    OS_PRETTY="${PRETTY_NAME:-$OS_ID $OS_VERSION_ID}"
  fi

  # Unit do SSH: Ubuntu usa 'ssh', algumas distros usam 'sshd'.
  if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
    SSH_UNIT="ssh"
  elif systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
    SSH_UNIT="sshd"
  else
    SSH_UNIT="ssh"
  fi

  # Identifiers do journald para o SSH: OpenSSH >= 9.6 (Ubuntu 24.04) usa
  # 'sshd-session' para as sessões; 22.04 usa só 'sshd'. Monitoramos ambos.
  SSH_SYSLOG_IDS=("sshd" "sshd-session")

  HAS_DOCKER=0; has_cmd docker && HAS_DOCKER=1
  HAS_UFW=0;    has_cmd ufw && HAS_UFW=1
  HAS_FAIL2BAN=0; has_cmd fail2ban-client && HAS_FAIL2BAN=1

  PRIMARY_IP="$(detect_primary_ip)"

  export OS_ID OS_VERSION_ID OS_PRETTY SSH_UNIT HAS_DOCKER HAS_UFW HAS_FAIL2BAN PRIMARY_IP
}

# IP primário do host (o de saída da rota default — numa VPS típica é o IP
# público). Local e instantâneo, sem depender de serviço externo. Se a VPS
# estiver atrás de NAT, defina NODE_NAME manualmente no config.
detect_primary_ip() {
  local ip=""
  if has_cmd ip; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1)"
  fi
  [[ -z "$ip" ]] && ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  printf '%s' "$ip"
}

# Docker está presente E o daemon responde?
docker_alive() {
  [[ "${HAS_DOCKER:-0}" == "1" ]] && docker info >/dev/null 2>&1
}

# ── Config ──────────────────────────────────────────────────────────────────
# Defaults. Sobrescritos pelo /etc/vps-sec/config se existir e for seguro.
config_defaults() {
  WEBHOOK_URL=""
  NODE_NAME=""
  ALERT_MIN_SEVERITY="low"
  DIGEST_ENABLED="yes"
  SSH_ALERT_ON_SUCCESS="yes"
  FAIL_BURST_THRESHOLD=10
  FAIL_BURST_WINDOW=60
  ALERT_COOLDOWN=900
  GLOBAL_ALERT_CAP_HOUR=30
  SCAN_INTERVAL=60
  INTEGRITY_WATCHLIST="/etc/ssh/sshd_config /etc/ssh/sshd_config.d /etc/sudoers /etc/sudoers.d /etc/passwd /etc/shadow /etc/docker/daemon.json /root/.ssh/authorized_keys /etc/crontab /etc/cron.d"
  # Saúde de containers (monitor) e consciência de backup (audit).
  CONTAINER_HEALTH_ENABLED="yes"
  RESTART_LOOP_DELTA=3
  BACKUP_WATCH=""
  BACKUP_DEFAULT_MAX_AGE_DAYS=2
}

# Carrega config validando dono/permissão ANTES de dar source (evita que um
# arquivo controlado por não-root injete comandos executados como root).
load_config() {
  config_defaults
  local cfg="${1:-$VPS_SEC_CONFIG}"

  if [[ -f "$cfg" ]]; then
    # Precisa ser dono root e não ter escrita para grupo/outros.
    local owner perms
    owner="$(stat -c '%u' "$cfg" 2>/dev/null || echo -1)"
    perms="$(stat -c '%a' "$cfg" 2>/dev/null || echo 777)"
    if [[ "$owner" != "0" ]]; then
      die "Config $cfg não pertence a root (uid=$owner). Recusando carregar por segurança."
    fi
    # Bloqueia se grupo/other tiverem qualquer bit de escrita (dígitos 2 e 3).
    if [[ "${perms: -2:1}" =~ [2367] || "${perms: -1:1}" =~ [2367] ]]; then
      die "Config $cfg tem permissões inseguras ($perms). Corrija: chmod 600 $cfg"
    fi
    # shellcheck disable=SC1090
    . "$cfg"
    CONFIG_LOADED=1
  else
    CONFIG_LOADED=0
  fi

  # A resolução abaixo roda SEMPRE (mesmo sem arquivo de config), para que
  # NODE_NAME/PRIMARY_IP fiquem corretos em qualquer fluxo.

  # IP primário do host (para o campo host_ip e como fallback do nome).
  [[ -z "${PRIMARY_IP:-}" ]] && PRIMARY_IP="$(detect_primary_ip)"

  # NODE_NAME: se o usuário não definiu um nome amigável no config, usa o IP
  # (mais identificável que o hostname padrão do provedor, ex.: "srv1359...").
  # Cai para o hostname curto só se não houver IP detectável.
  if [[ -z "${NODE_NAME:-}" ]]; then
    if [[ -n "$PRIMARY_IP" ]]; then
      NODE_NAME="$PRIMARY_IP"
    else
      NODE_NAME="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)"
    fi
  fi
  export WEBHOOK_URL NODE_NAME PRIMARY_IP ALERT_MIN_SEVERITY DIGEST_ENABLED \
         SSH_ALERT_ON_SUCCESS FAIL_BURST_THRESHOLD FAIL_BURST_WINDOW \
         ALERT_COOLDOWN GLOBAL_ALERT_CAP_HOUR SCAN_INTERVAL INTEGRITY_WATCHLIST \
         CONTAINER_HEALTH_ENABLED RESTART_LOOP_DELTA BACKUP_WATCH \
         BACKUP_DEFAULT_MAX_AGE_DAYS
}

# ── Severidade ──────────────────────────────────────────────────────────────
# Ordem numérica para comparação de thresholds.
severity_rank() {
  case "$1" in
    critical) echo 4 ;;
    high)     echo 3 ;;
    medium)   echo 2 ;;
    low)      echo 1 ;;
    info)     echo 0 ;;
    *)        echo 0 ;;
  esac
}

# ── Utilidades ──────────────────────────────────────────────────────────────
now_utc()      { date -u +%Y-%m-%dT%H:%M:%SZ; }
now_ts()       { date -u +%Y%m%dT%H%M%SZ; }
epoch()        { date +%s; }
short_sha1()   { printf '%s' "$1" | sha1sum | cut -c1-16; }

# Cria os diretórios de estado com permissões corretas (idempotente).
ensure_dirs() {
  install -d -m 700 "$VPS_SEC_STATE" "$VPS_SEC_STATE/baseline" \
    "$VPS_SEC_STATE/spool" "$VPS_SEC_STATE/dedup" 2>/dev/null || true
  install -d -m 750 "$VPS_SEC_LOG_DIR" 2>/dev/null || true
  install -d -m 700 "$VPS_SEC_BACKUP_DIR" 2>/dev/null || true
}
