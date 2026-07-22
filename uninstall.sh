#!/usr/bin/env bash
# uninstall.sh — remove o vps-sec. Não reverte hardening já aplicado.
set -euo pipefail

PREFIX="/opt/vps-sec"
CONFIG_DIR="/etc/vps-sec"
BIN_LINK="/usr/local/bin/vps-sec"
SYSTEMD_DIR="/etc/systemd/system"
STATE="/var/lib/vps-sec"
LOGS="/var/log/vps-sec"
BACKUPS="/var/backups/vps-sec"

msg() { printf '\033[36m[uninstall]\033[0m %s\n' "$*"; }
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Rode como root." >&2; exit 1; }

PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1

msg "Parando e desabilitando serviços..."
for u in vps-sec-monitor.service vps-sec-audit.timer vps-sec-digest.timer \
         vps-sec-update.timer vps-sec-audit.service vps-sec-digest.service \
         vps-sec-update.service; do
  systemctl disable --now "$u" >/dev/null 2>&1 || true
done
systemctl stop vps-sec-ssh-rollback.timer >/dev/null 2>&1 || true

msg "Removendo units e binário..."
rm -f "$SYSTEMD_DIR"/vps-sec-*.service "$SYSTEMD_DIR"/vps-sec-*.timer
systemctl daemon-reload
rm -f "$BIN_LINK"
rm -rf "$PREFIX"

if [[ "$PURGE" == "1" ]]; then
  msg "Purge: removendo config, estado e logs (backups preservados)..."
  rm -rf "$CONFIG_DIR" "$STATE" "$LOGS"
  msg "Backups de hardening mantidos em $BACKUPS (remova manualmente se desejar)."
else
  msg "Config, estado, logs e backups preservados."
  msg "Para remover tudo: $0 --purge"
  msg "NOTA: correções de hardening aplicadas NÃO são revertidas."
  msg "      Reverta antes com: vps-sec rollback last  (se ainda instalado)."
fi

msg "vps-sec removido."
