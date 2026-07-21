#!/usr/bin/env bash
# modules/audit/90-rootkit.sh — indicadores leves de comprometimento.
# Não substitui rkhunter/chkrootkit; são sinais rápidos e sem dependências.

audit_rootkit() {
  # RK-002: /etc/ld.so.preload não-vazio (técnica clássica de hooking).
  if [[ -s /etc/ld.so.preload ]]; then
    report_fail "RK-002" "high" "/etc/ld.so.preload não está vazio" \
      "Conteúdo: $(tr '\n' ' ' </etc/ld.so.preload 2>/dev/null)"
  else
    report_pass "RK-002" "high" "/etc/ld.so.preload vazio/ausente"
  fi

  # RK-003: processos rodando com binário deletado (fora de padrões de upgrade).
  local deleted=""
  local procdir pid exe
  for procdir in /proc/[0-9]*; do
    pid="${procdir#/proc/}"
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    if [[ "$exe" == *"(deleted)"* ]]; then
      # Ignora libs recém-atualizadas comuns.
      case "$exe" in
        *"/memfd:"*|*"/dev/zero"*) continue ;;
      esac
      local comm; comm="$(cat "/proc/$pid/comm" 2>/dev/null || echo '?')"
      deleted+="$comm(pid $pid) "
    fi
  done
  if [[ -n "$deleted" ]]; then
    report_warn "RK-003" "medium" "Processo(s) com binário deletado" \
      "Comum após upgrade (reinicie o serviço); investigue se persistir: $deleted"
  else
    report_pass "RK-003" "medium" "Nenhum processo com binário deletado"
  fi

  # RK-005: authorized_keys em contas de sistema (persistência de atacante).
  local syskeys=""
  local user uid home
  while IFS=: read -r user _ uid _ _ home _; do
    [[ "$uid" -lt 1000 && "$uid" -ne 0 ]] || continue
    [[ -n "$home" && -f "$home/.ssh/authorized_keys" && -s "$home/.ssh/authorized_keys" ]] \
      && syskeys+="$user "
  done </etc/passwd
  if [[ -n "$syskeys" ]]; then
    report_fail "RK-005" "critical" "Conta de sistema com authorized_keys" \
      "Possível backdoor: $syskeys"
  else
    report_pass "RK-005" "critical" "Nenhuma chave SSH em contas de sistema"
  fi

  # RK-004: entradas suspeitas em rc.local.
  if [[ -s /etc/rc.local ]] && grep -qvE '^\s*(#|exit|$)' /etc/rc.local 2>/dev/null; then
    local rc; rc="$(grep -vE '^\s*(#|exit 0|$)' /etc/rc.local 2>/dev/null | tr '\n' ';' | head -c 200)"
    report_warn "RK-004" "medium" "/etc/rc.local contém comandos" \
      "Revise: $rc"
  fi
}
