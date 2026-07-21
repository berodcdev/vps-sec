#!/usr/bin/env bash
# modules/harden/fixes.sh — aplicação guiada de correções de segurança.
# Depende de common.sh, backup.sh (já sourced) e jq.
#
# Classificação:
#   SAFE  — reversível, não derruba acesso; pode aplicar com --yes.
#   RISKY — pode trancar o acesso (SSH/UFW); exige confirmação digitando
#           CONFIRMO e nunca é aplicado só com --yes.

SSH_DROPIN="/etc/ssh/sshd_config.d/99-vps-sec.conf"
SYSCTL_DROPIN="/etc/sysctl.d/99-vps-sec.conf"

# Tabela: check_id → "classe:função:descrição"
_fix_table() {
  cat <<'EOF'
SVC-001|SAFE|fix_fail2ban|Instala e habilita fail2ban com jail sshd
SVC-002|SAFE|fix_unattended|Habilita atualizações automáticas de segurança
SYS-001|SAFE|fix_sysctl|Aplica parâmetros de kernel endurecidos
SSH-005|SAFE|fix_ssh_dropin|Endurece SSH (drop-in): sem senha vazia, MaxAuthTries, etc.
SSH-006|SAFE|fix_ssh_dropin|Endurece SSH (drop-in): MaxAuthTries/LoginGraceTime
SSH-007|SAFE|fix_ssh_dropin|Endurece SSH (drop-in): desabilita X11Forwarding
SSH-009|SAFE|fix_ssh_key_perms|Corrige permissões dos authorized_keys
FS-003|SAFE|fix_shadow_perms|Corrige permissões de /etc/shadow
DKR-004|SAFE|fix_docker_sock|Corrige permissões do docker.sock
DKR-005|SAFE|fix_daemon_json|Adiciona limites de log ao daemon.json
USR-001|SAFE|fix_lock_empty|Trava contas com senha vazia
SSH-001|RISKY|fix_ssh_root|Desabilita login de root por SSH
SSH-003|RISKY|fix_ssh_password|Desabilita autenticação por senha no SSH
FW-001|RISKY|fix_ufw_enable|Habilita o UFW (liberando a porta SSH antes)
FW-002|RISKY|fix_ufw_default|Define política default de entrada como deny
EOF
}

harden_main() {
  require_cmd jq
  local dry=0 assume_yes=0 allow_risky=0 only=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)     dry=1 ;;
      --yes)         assume_yes=1 ;;
      --allow-risky) allow_risky=1 ;;
      --only)        only="$2"; shift ;;
      --confirm-ssh) harden_confirm_ssh; return $? ;;
      *) warn "harden: opção ignorada '$1'" ;;
    esac
    shift
  done

  # Descobre o que está falhando rodando o audit em JSON.
  log "Rodando auditoria para identificar correções aplicáveis..."
  # shellcheck source=/dev/null
  . "$VPS_SEC_MODULES/audit/run.sh"
  local audit_json
  audit_json="$( _harden_capture_audit )"

  local failed_ids
  failed_ids="$(jq -r '.findings[] | select(.status=="FAIL" or .status=="WARN") | .id' <<<"$audit_json" 2>/dev/null | sort -u)"

  # Filtro --only.
  if [[ -n "$only" ]]; then
    only="${only//,/ }"
  fi

  backup_start_session
  local applied=() skipped=() refused=()

  local id class fn desc
  while IFS='|' read -r id class fn desc; do
    [[ -z "$id" ]] && continue
    # Só oferece se o check falhou (ou está na lista --only explícita).
    if [[ -n "$only" ]]; then
      grep -qw "$id" <<<"$only" || continue
    else
      grep -qxF "$id" <<<"$failed_ids" || continue
    fi

    if [[ "$class" == "RISKY" ]]; then
      if [[ "$allow_risky" != "1" && -z "$only" ]]; then
        skipped+=("$id (RISKY — use --allow-risky)")
        continue
      fi
      if [[ "$dry" == "1" ]]; then
        echo "[dry-run] RISKY $id: $desc"; applied+=("$id (dry)"); continue
      fi
      if _harden_confirm_risky "$id" "$desc"; then
        if "$fn"; then applied+=("$id"); else refused+=("$id (erro)"); fi
      else
        refused+=("$id (recusado)")
      fi
    else
      # SAFE
      if [[ "$dry" == "1" ]]; then
        echo "[dry-run] SAFE $id: $desc"; applied+=("$id (dry)"); continue
      fi
      if [[ "$assume_yes" == "1" ]] || _harden_confirm_safe "$id" "$desc"; then
        if "$fn"; then applied+=("$id"); else refused+=("$id (erro)"); fi
      else
        skipped+=("$id (pulado)")
      fi
    fi
  done < <(_fix_table)

  # Atualiza baseline de integridade (mudanças nossas não devem auto-alertar).
  if [[ "$dry" != "1" && -f "$VPS_SEC_PREFIX/lib/baseline.sh" ]]; then
    # shellcheck source=/dev/null
    . "$VPS_SEC_PREFIX/lib/baseline.sh"
    baseline_refresh_integrity 2>/dev/null || true
  fi

  _harden_report applied skipped refused "$dry"
}

# Captura o JSON do audit sem que o exit code (2 p/ crítico) mate o harden.
_harden_capture_audit() {
  ( audit_main --json --quiet ) || true
}

# ── Confirmações ────────────────────────────────────────────────────────────
_harden_confirm_safe() {
  local id="$1" desc="$2"
  [[ -t 0 ]] || return 1
  printf '%sAplicar [%s]%s %s? [s/N] ' "$C_CYAN" "$id" "$C_RESET" "$desc" >&2
  local ans; read -r ans; [[ "$ans" =~ ^[sSyY] ]]
}

_harden_confirm_risky() {
  local id="$1" desc="$2"
  [[ -t 0 ]] || { warn "[$id] RISKY requer terminal interativo — pulando"; return 1; }
  printf '\n%s⚠ MUDANÇA ARRISCADA [%s]%s\n  %s\n' "$C_RED$C_BOLD" "$id" "$C_RESET" "$desc" >&2
  printf '  Isto pode afetar seu acesso ao servidor. Digite %sCONFIRMO%s para prosseguir: ' \
    "$C_BOLD" "$C_RESET" >&2
  local ans; read -r ans; [[ "$ans" == "CONFIRMO" ]]
}

# ── Fixes SAFE ──────────────────────────────────────────────────────────────
fix_fail2ban() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban >/dev/null 2>&1 || return 1
  backup_file /etc/fail2ban/jail.d/vps-sec.conf
  cat >/etc/fail2ban/jail.d/vps-sec.conf <<'EOF'
[sshd]
enabled = true
bantime = 1h
findtime = 10m
maxretry = 5
EOF
  systemctl enable --now fail2ban >/dev/null 2>&1
  backup_record_cmd "instalou e habilitou fail2ban (jail sshd)"
  ok "fail2ban configurado"
}

fix_unattended() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades >/dev/null 2>&1 || return 1
  backup_file /etc/apt/apt.conf.d/20auto-upgrades
  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  backup_record_cmd "habilitou unattended-upgrades"
  ok "atualizações automáticas de segurança habilitadas"
}

fix_sysctl() {
  backup_file "$SYSCTL_DROPIN"
  cat >"$SYSCTL_DROPIN" <<'EOF'
# vps-sec — endurecimento de rede/kernel (não altera ip_forward por causa do Docker)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.kptr_restrict = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
EOF
  sysctl -p "$SYSCTL_DROPIN" >/dev/null 2>&1
  backup_record_cmd "aplicou sysctl endurecido"
  ok "parâmetros de kernel aplicados"
}

fix_ssh_dropin() {
  backup_file "$SSH_DROPIN"
  install -d -m 755 /etc/ssh/sshd_config.d
  # Merge idempotente: reescreve o bloco básico do drop-in preservando linhas RISKY já presentes.
  {
    echo "# vps-sec — endurecimento leve do SSH (seguro)"
    echo "PermitEmptyPasswords no"
    echo "MaxAuthTries 3"
    echo "LoginGraceTime 30"
    echo "X11Forwarding no"
    # Preserva diretivas RISKY já aplicadas por nós (root/senha), se existirem.
    grep -E '^(PermitRootLogin|PasswordAuthentication|Port) ' "$SSH_DROPIN" 2>/dev/null || true
  } >"$SSH_DROPIN.tmp"
  mv "$SSH_DROPIN.tmp" "$SSH_DROPIN"
  if sshd -t 2>/dev/null; then
    systemctl reload "${SSH_UNIT:-ssh}" 2>/dev/null || true
    backup_record_cmd "endureceu SSH via drop-in (leve)"
    ok "SSH endurecido (mudanças seguras, sessão preservada)"
  else
    error "sshd -t falhou — revertendo drop-in"
    cp -a "$BACKUP_SESSION_DIR/files$SSH_DROPIN" "$SSH_DROPIN" 2>/dev/null || rm -f "$SSH_DROPIN"
    return 1
  fi
}

fix_ssh_key_perms() {
  local user uid home ak
  while IFS=: read -r user _ uid _ _ home _; do
    [[ "$uid" -ge 1000 || "$user" == "root" ]] || continue
    ak="$home/.ssh/authorized_keys"
    [[ -f "$ak" ]] || continue
    chmod 600 "$ak" 2>/dev/null
    chmod 700 "$home/.ssh" 2>/dev/null
    chown "$user" "$ak" "$home/.ssh" 2>/dev/null || true
  done </etc/passwd
  backup_record_cmd "corrigiu permissões de authorized_keys"
  ok "permissões de authorized_keys corrigidas"
}

fix_shadow_perms() {
  backup_file /etc/shadow
  chown root:shadow /etc/shadow 2>/dev/null || chown root:root /etc/shadow
  chmod 640 /etc/shadow
  backup_record_cmd "corrigiu permissões de /etc/shadow"
  ok "/etc/shadow com permissão 640"
}

fix_docker_sock() {
  [[ -S /var/run/docker.sock ]] || return 0
  chmod 660 /var/run/docker.sock
  chown root:docker /var/run/docker.sock 2>/dev/null || true
  backup_record_cmd "corrigiu permissões do docker.sock"
  ok "docker.sock com permissão 660 root:docker"
}

fix_daemon_json() {
  local dj=/etc/docker/daemon.json
  install -d -m 755 /etc/docker
  backup_file "$dj"
  local base='{}'; [[ -f "$dj" ]] && base="$(cat "$dj")"
  echo "$base" | jq '. + {"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"},"live-restore":true}' \
    >"$dj.tmp" 2>/dev/null || { error "daemon.json inválido — abortando"; rm -f "$dj.tmp"; return 1; }
  mv "$dj.tmp" "$dj"
  warn "daemon.json atualizado — requer 'systemctl restart docker' (reinicia containers sem live-restore)"
  backup_record_cmd "adicionou limites de log ao daemon.json (restart do docker pendente)"
  ok "daemon.json atualizado (aplique com: systemctl restart docker)"
}

fix_lock_empty() {
  local user
  while IFS=: read -r user pass _; do
    [[ -z "$pass" ]] && { passwd -l "$user" >/dev/null 2>&1 && log "conta travada: $user"; }
  done </etc/shadow
  backup_record_cmd "travou contas com senha vazia"
  ok "contas com senha vazia travadas"
}

# ── Fixes RISKY (com anti-lockout) ──────────────────────────────────────────
fix_ssh_root()     { _ssh_risky_change "PermitRootLogin" "prohibit-password" "PermitRootLogin=prohibit-password"; }
fix_ssh_password() { _ssh_risky_change "PasswordAuthentication" "no" "PasswordAuthentication=no"; }

# Aplica uma diretiva RISKY no drop-in do SSH com proteção anti-lockout:
# backup → sshd -t → agenda rollback em 5min → reload → instrui a testar.
_ssh_risky_change() {
  local directive="$1" value="$2" label="$3"
  backup_file "$SSH_DROPIN"
  install -d -m 755 /etc/ssh/sshd_config.d
  touch "$SSH_DROPIN"
  # Remove a diretiva antiga e adiciona a nova.
  grep -vE "^${directive} " "$SSH_DROPIN" >"$SSH_DROPIN.tmp" 2>/dev/null || true
  echo "$directive $value" >>"$SSH_DROPIN.tmp"
  mv "$SSH_DROPIN.tmp" "$SSH_DROPIN"

  if ! sshd -t 2>/dev/null; then
    error "sshd -t falhou — revertendo"
    _rollback_apply "$BACKUP_SESSION_DIR"
    return 1
  fi

  # Garante que a porta SSH esteja liberada no UFW (evita lockout combinado).
  _ensure_ssh_port_allowed

  # Agenda rollback automático em 5 min (cancelável por --confirm-ssh).
  echo "$BACKUP_SESSION_DIR" >"$VPS_SEC_STATE/ssh-harden-pending"
  systemd-run --unit=vps-sec-ssh-rollback --on-active=5min \
    "$VPS_SEC_PREFIX/bin/vps-sec" _rollback-pending >/dev/null 2>&1 || \
    warn "não foi possível agendar rollback automático (systemd-run indisponível)"

  systemctl reload "${SSH_UNIT:-ssh}" 2>/dev/null || true
  backup_record_cmd "aplicou $label (aguardando confirmação)"

  printf '\n%s╔══════════════════════════════════════════════════════════════╗%s\n' "$C_YELLOW$C_BOLD" "$C_RESET" >&2
  printf '%s║  MUDANÇA DE SSH APLICADA — TESTE ANTES DE CONFIRMAR           ║%s\n' "$C_YELLOW$C_BOLD" "$C_RESET" >&2
  printf '%s╚══════════════════════════════════════════════════════════════╝%s\n' "$C_YELLOW$C_BOLD" "$C_RESET" >&2
  echo "  Aplicado: $label" >&2
  echo "  1. NÃO feche esta sessão." >&2
  echo "  2. Abra um NOVO terminal e conecte via SSH." >&2
  echo "  3. Se conseguir, rode:  vps-sec harden --confirm-ssh" >&2
  echo "  Sem confirmação em 5 minutos, a mudança é revertida automaticamente." >&2
  ok "$label aplicado (reversão automática armada)"
}

_ensure_ssh_port_allowed() {
  [[ "${HAS_UFW:-0}" == "1" ]] || return 0
  local port
  port="$(sshd -T 2>/dev/null | awk 'tolower($1)=="port"{print $2; exit}')"
  [[ -z "$port" ]] && port="22"
  # Porta da conexão atual, se disponível.
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    local cur; cur="$(awk '{print $4}' <<<"$SSH_CONNECTION")"
    [[ -n "$cur" ]] && ufw allow "$cur/tcp" >/dev/null 2>&1 || true
  fi
  ufw allow "$port/tcp" >/dev/null 2>&1 || true
  log "porta SSH $port liberada no UFW"
}

fix_ufw_enable() {
  [[ "${HAS_UFW:-0}" == "1" ]] || { DEBIAN_FRONTEND=noninteractive apt-get install -y ufw >/dev/null 2>&1; HAS_UFW=1; }
  _ensure_ssh_port_allowed
  ufw --force enable >/dev/null 2>&1
  touch "$VPS_SEC_STATE/baseline/ufw-was-active" 2>/dev/null || true
  backup_record_cmd "habilitou o UFW (porta SSH liberada)"
  ok "UFW habilitado (porta SSH garantida)"
}

fix_ufw_default() {
  ufw default deny incoming >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1
  backup_record_cmd "definiu default deny incoming / allow outgoing"
  ok "política default do UFW: deny incoming"
}

# ── Confirmação de SSH (cancela o rollback pendente) ────────────────────────
harden_confirm_ssh() {
  local pending="$VPS_SEC_STATE/ssh-harden-pending"
  if [[ ! -f "$pending" ]]; then
    warn "Nenhuma mudança de SSH pendente de confirmação."
    return 0
  fi
  systemctl stop vps-sec-ssh-rollback.timer 2>/dev/null || true
  systemctl reset-failed vps-sec-ssh-rollback.service 2>/dev/null || true
  rm -f "$pending"
  ok "Mudança de SSH confirmada. Reversão automática cancelada."
}

# ── Relatório final + alerta ────────────────────────────────────────────────
_harden_report() {
  local -n _ap="$1" _sk="$2" _rf="$3"; local dry="$4"
  echo >&2
  printf '%s── Resumo do harden%s ──%s\n' "$C_BOLD" "$([[ "$dry" == 1 ]] && echo ' (dry-run)')" "$C_RESET" >&2
  printf '  aplicados: %d   pulados: %d   recusados/erro: %d\n' \
    "${#_ap[@]}" "${#_sk[@]}" "${#_rf[@]}" >&2
  [[ ${#_ap[@]} -gt 0 ]] && printf '  %s✓%s %s\n' "$C_GREEN" "$C_RESET" "${_ap[*]}" >&2
  [[ ${#_sk[@]} -gt 0 ]] && printf '  %s•%s %s\n' "$C_DIM" "$C_RESET" "${_sk[*]}" >&2
  [[ ${#_rf[@]} -gt 0 ]] && printf '  %s✗%s %s\n' "$C_RED" "$C_RESET" "${_rf[*]}" >&2

  if [[ "$dry" != "1" && ${#_ap[@]} -gt 0 && -f "$VPS_SEC_PREFIX/lib/alert.sh" ]]; then
    # shellcheck source=/dev/null
    . "$VPS_SEC_PREFIX/lib/alert.sh"
    local details; details="$(jq -n --arg a "${_ap[*]}" \
      '{applied:($a|split(" ")|map(select(length>0)))}')"
    alert_send "harden_applied" "info" "$details" "" "harden_applied" 2>/dev/null || true
  fi
}
