#!/usr/bin/env bash
# modules/audit/50-services.sh — fail2ban, updates automáticos, patches pendentes.

audit_services() {
  # SVC-001: fail2ban presente, com jail sshd, e a jail REALMENTE lendo o log.
  case "$(f2b_state)" in
    active)
      # "Ativo" não basta. No Ubuntu 24.04 não há rsyslog, então /var/log/auth.log
      # não existe: com backend=file a jail sobe, reporta-se ativa e nunca bane
      # nada. Detectar essa falha silenciosa é o ponto deste check.
      local backend="" logfiles=""
      backend="$(fail2ban-client get sshd logencoding >/dev/null 2>&1 && \
                 grep -rhiE '^\s*backend\s*=' /etc/fail2ban/jail.d/ /etc/fail2ban/jail.local 2>/dev/null \
                 | head -1 | sed 's/.*=[[:space:]]*//')"
      logfiles="$(fail2ban-client get sshd logpath 2>/dev/null | grep -oE '/[^ ,]+' || true)"
      if [[ "$backend" == "systemd" ]]; then
        report_pass "SVC-001" "high" "fail2ban ativo, jail sshd lendo o journald"
      elif [[ -n "$logfiles" ]] && [[ ! -r "${logfiles%% *}" ]]; then
        report_fail "SVC-001" "high" "fail2ban ativo mas a jail sshd não lê nada" \
          "logpath=${logfiles%% *} não existe (Ubuntu 24.04 não instala rsyslog). Nenhum IP é bloqueado." \
          "SVC-001"
      else
        report_pass "SVC-001" "high" "fail2ban ativo com jail sshd"
      fi
      ;;
    active-nojail)
      report_fail "SVC-001" "high" "fail2ban ativo mas sem jail sshd" \
        "O serviço roda, porém nada protege o SSH" "SVC-001"
      ;;
    inactive)
      report_fail "SVC-001" "high" "fail2ban instalado mas parado" \
        "Sem bloqueio automático de brute force SSH" "SVC-001"
      ;;
    *)
      report_fail "SVC-001" "high" "fail2ban ausente" \
        "Sem bloqueio automático de brute force SSH" "SVC-001"
      ;;
  esac

  # SVC-002: unattended-upgrades habilitado.
  local auto=/etc/apt/apt.conf.d/20auto-upgrades
  if [[ -f "$auto" ]] && grep -qE 'Unattended-Upgrade"?\s+"1"' "$auto" 2>/dev/null; then
    report_pass "SVC-002" "medium" "Atualizações automáticas de segurança ativas"
  else
    report_fail "SVC-002" "medium" "unattended-upgrades não configurado" \
      "Patches de segurança não são aplicados automaticamente" "SVC-002"
  fi

  # SVC-003: pacotes de segurança pendentes.
  if has_cmd apt-get; then
    local sec_pending
    sec_pending="$(apt-get -s -o Debug::NoLocking=true dist-upgrade 2>/dev/null \
      | grep -c '^Inst.*-security\| Security' || true)"
    sec_pending="${sec_pending:-0}"
    if [[ "$sec_pending" -gt 0 ]]; then
      report_fail "SVC-003" "high" "$sec_pending atualização(ões) de segurança pendente(s)" \
        "Rode: apt-get update && apt-get upgrade" "SVC-003"
    else
      report_pass "SVC-003" "high" "Nenhuma atualização de segurança pendente"
    fi
  fi

  # SVC-004: reboot pendente.
  if [[ -f /var/run/reboot-required ]]; then
    report_warn "SVC-004" "high" "Reboot pendente" \
      "$(cat /var/run/reboot-required 2>/dev/null | head -1)" "SVC-004"
  else
    report_pass "SVC-004" "high" "Sem reboot pendente"
  fi

  # SVC-005: serviços legados/inseguros habilitados.
  local legacy=""
  local svc
  for svc in telnet.socket rsh.socket rlogin.socket vsftpd xinetd; do
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
      legacy+="$svc "
    fi
  done
  if [[ -n "$legacy" ]]; then
    report_warn "SVC-005" "low" "Serviço(s) legado(s) habilitado(s)" "$legacy"
  else
    report_pass "SVC-005" "low" "Nenhum serviço legado inseguro habilitado"
  fi
}
