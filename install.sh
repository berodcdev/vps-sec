#!/usr/bin/env bash
# install.sh — instalador one-line do vps-sec (idempotente; re-rodar = upgrade).
#
# Uso:
#   curl -fsSL <url>/install.sh | sudo bash -s -- --webhook-url "https://..."
# ou, a partir do repositório:
#   sudo ./install.sh --webhook-url "https://..."
set -euo pipefail

# ── Origem do código (troque aqui, ou use as env vars, ao criar seu repo) ───
# Se nomear o repositório diferente de "vps-sec", ajuste aqui ou use --repo.
GITHUB_REPO="${VPS_SEC_REPO:-berodcdev/vps-sec}"
GITHUB_BRANCH="${VPS_SEC_BRANCH:-main}"

PREFIX="/opt/vps-sec"
CONFIG_DIR="/etc/vps-sec"
CONFIG="$CONFIG_DIR/config"
BIN_LINK="/usr/local/bin/vps-sec"
SYSTEMD_DIR="/etc/systemd/system"
# URL de tarball explícita (opcional). Se vazio, deriva de GITHUB_REPO/BRANCH.
REPO_TARBALL="${VPS_SEC_TARBALL:-}"

WEBHOOK_URL=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --webhook-url) WEBHOOK_URL="$2"; shift ;;
    --webhook-url=*) WEBHOOK_URL="${1#*=}" ;;
    --repo) GITHUB_REPO="$2"; shift ;;
    --repo=*) GITHUB_REPO="${1#*=}" ;;
    --branch) GITHUB_BRANCH="$2"; shift ;;
    --branch=*) GITHUB_BRANCH="${1#*=}" ;;
    *) echo "opção desconhecida: $1" >&2 ;;
  esac
  shift
done

msg()  { printf '\033[36m[install]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[erro]\033[0m %s\n' "$*" >&2; exit 1; }

# ── 1. Guards ───────────────────────────────────────────────────────────────
[[ ${EUID:-$(id -u)} -eq 0 ]] || die "Rode como root (sudo)."
command -v systemctl >/dev/null || die "systemd é obrigatório."
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04) : ;;
    ubuntu:*) msg "Aviso: testado em Ubuntu 22.04/24.04; ${VERSION_ID} pode variar." ;;
    debian:*) msg "Aviso: Debian detectado — deve funcionar, não testado a fundo." ;;
    *) die "SO não suportado: ${PRETTY_NAME:-desconhecido}. Requer Ubuntu/Debian." ;;
  esac
else
  die "Não foi possível identificar o SO (/etc/os-release ausente)."
fi

# ── 2. Dependências duras ───────────────────────────────────────────────────
msg "Instalando dependências (jq, curl)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1 || msg "aviso: apt-get update falhou (seguindo)"
apt-get install -y -qq jq curl >/dev/null 2>&1 || die "falha ao instalar jq/curl"

# ── 3. Código → /opt/vps-sec ────────────────────────────────────────────────
# Detecta a origem: (a) tarball explícito; (b) diretório local do repo (quando
# o script está ao lado de bin/vps-sec); (c) via pipe `curl | bash` → baixa do
# GitHub derivando a URL de GITHUB_REPO/GITHUB_BRANCH.
SRC_DIR=""
SCRIPT_SELF="${BASH_SOURCE[0]:-}"
LOCAL_DIR=""
if [[ -n "$SCRIPT_SELF" && -f "$SCRIPT_SELF" ]]; then
  LOCAL_DIR="$(cd "$(dirname "$SCRIPT_SELF")" && pwd)"
fi

if [[ -n "$REPO_TARBALL" ]]; then
  msg "Baixando tarball: $REPO_TARBALL"
  TMP="$(mktemp -d)"
  curl -fsSL "$REPO_TARBALL" | tar -xz -C "$TMP" --strip-components=1 || die "falha ao baixar/extrair tarball"
  SRC_DIR="$TMP"
elif [[ -n "$LOCAL_DIR" && -f "$LOCAL_DIR/bin/vps-sec" ]]; then
  msg "Instalando a partir do repositório local: $LOCAL_DIR"
  SRC_DIR="$LOCAL_DIR"
else
  # Modo one-line (curl | bash): baixa o tarball do GitHub.
  case "$GITHUB_REPO" in
    SEU-USUARIO/*) die "Configure o repositório: use --repo usuario/repo ou VPS_SEC_REPO=usuario/repo" ;;
  esac
  local_tarball="https://github.com/$GITHUB_REPO/archive/refs/heads/$GITHUB_BRANCH.tar.gz"
  msg "Baixando do GitHub: $GITHUB_REPO@$GITHUB_BRANCH"
  TMP="$(mktemp -d)"
  curl -fsSL "$local_tarball" | tar -xz -C "$TMP" --strip-components=1 \
    || die "falha ao baixar de $local_tarball (repo/branch corretos? é público?)"
  SRC_DIR="$TMP"
fi
[[ -f "$SRC_DIR/bin/vps-sec" ]] || die "código-fonte não encontrado em $SRC_DIR"

msg "Instalando em $PREFIX ..."
mkdir -p "$PREFIX"
if command -v rsync >/dev/null; then
  rsync -a --delete \
    --exclude '.git' --exclude '*.md' \
    "$SRC_DIR"/{bin,lib,modules,systemd,etc,VERSION,install.sh,uninstall.sh} "$PREFIX"/ 2>/dev/null || \
  rsync -a --exclude '.git' "$SRC_DIR"/ "$PREFIX"/
else
  cp -a "$SRC_DIR"/{bin,lib,modules,systemd,etc,VERSION,install.sh,uninstall.sh} "$PREFIX"/
fi
chown -R root:root "$PREFIX"
chmod -R 755 "$PREFIX"
chmod 755 "$PREFIX/bin/vps-sec" "$PREFIX/install.sh" "$PREFIX/uninstall.sh"
ln -sf "$PREFIX/bin/vps-sec" "$BIN_LINK"

# Grava a origem para o 'vps-sec self-update' saber de onde re-baixar.
{
  echo "GITHUB_REPO=\"$GITHUB_REPO\""
  echo "GITHUB_BRANCH=\"$GITHUB_BRANCH\""
} >"$PREFIX/.source"
chmod 644 "$PREFIX/.source"

# ── 4. Config ───────────────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR"; chmod 755 "$CONFIG_DIR"
if [[ -f "$CONFIG" ]]; then
  msg "Config existente preservada: $CONFIG"
  # Se passaram --webhook-url, atualiza só essa chave.
  if [[ -n "$WEBHOOK_URL" ]]; then
    sed -i "s|^WEBHOOK_URL=.*|WEBHOOK_URL=\"$WEBHOOK_URL\"|" "$CONFIG"
    msg "WEBHOOK_URL atualizada."
  fi
else
  cp "$PREFIX/etc/config.example" "$CONFIG"
  if [[ -n "$WEBHOOK_URL" ]]; then
    sed -i "s|^WEBHOOK_URL=.*|WEBHOOK_URL=\"$WEBHOOK_URL\"|" "$CONFIG"
  elif [[ -t 0 ]]; then
    read -r -p "URL do webhook do n8n (enter p/ configurar depois): " w
    [[ -n "$w" ]] && sed -i "s|^WEBHOOK_URL=.*|WEBHOOK_URL=\"$w\"|" "$CONFIG"
  fi
fi
chown root:root "$CONFIG"; chmod 600 "$CONFIG"

# ── 5. Units systemd ────────────────────────────────────────────────────────
msg "Instalando serviços systemd..."
cp "$PREFIX"/systemd/*.service "$PREFIX"/systemd/*.timer "$SYSTEMD_DIR"/
systemctl daemon-reload
systemctl enable --now vps-sec-monitor.service >/dev/null 2>&1 || msg "aviso: monitor não iniciou"
systemctl enable --now vps-sec-audit.timer >/dev/null 2>&1 || true
systemctl enable --now vps-sec-digest.timer >/dev/null 2>&1 || true

# ── 6. Baselines + teste + primeira auditoria ──────────────────────────────
msg "Criando baselines iniciais..."
"$BIN_LINK" baseline update >/dev/null 2>&1 || msg "aviso: falha ao criar baseline"

if grep -q '^WEBHOOK_URL="http' "$CONFIG"; then
  msg "Testando webhook..."
  "$BIN_LINK" test-webhook || msg "aviso: teste de webhook falhou — verifique a URL"
else
  msg "WEBHOOK_URL não configurada — configure em $CONFIG e rode: vps-sec test-webhook"
fi

echo
msg "Auditoria inicial:"
"$BIN_LINK" audit || true

echo
cat <<EOF
────────────────────────────────────────────────────────
 vps-sec instalado com sucesso.

 Comandos úteis:
   vps-sec audit                # auditar agora
   vps-sec harden --dry-run     # ver o que seria corrigido
   vps-sec harden --yes         # aplicar correções seguras
   vps-sec monitor status       # estado do monitor
   vps-sec test-webhook         # testar alerta no n8n

 Config:   $CONFIG (chmod 600)
 Logs:     /var/log/vps-sec/
 Monitor:  systemctl status vps-sec-monitor
────────────────────────────────────────────────────────
EOF
