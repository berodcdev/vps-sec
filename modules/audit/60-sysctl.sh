#!/usr/bin/env bash
# modules/audit/60-sysctl.sh — parâmetros de kernel de rede/segurança.
# NÃO sugere net.ipv4.ip_forward=0 quando há Docker (Docker exige forward=1).

audit_sysctl() {
  # chave => valor esperado
  local -a keys=(
    "net.ipv4.conf.all.rp_filter=1"
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv4.tcp_syncookies=1"
    "net.ipv4.icmp_echo_ignore_broadcasts=1"
    "kernel.kptr_restrict=1"
    "fs.protected_symlinks=1"
    "fs.protected_hardlinks=1"
  )

  local bad=""
  local kv key want have
  for kv in "${keys[@]}"; do
    key="${kv%%=*}"; want="${kv#*=}"
    have="$(sysctl -n "$key" 2>/dev/null || echo NA)"
    [[ "$have" == "NA" ]] && continue
    # kptr_restrict: aceita >=1.
    if [[ "$key" == "kernel.kptr_restrict" ]]; then
      [[ "$have" -ge 1 ]] 2>/dev/null && continue
    fi
    [[ "$have" == "$want" ]] || bad+="$key(=$have, esperado $want) "
  done

  if [[ -n "$bad" ]]; then
    report_fail "SYS-001" "medium" "Parâmetros de kernel abaixo do recomendado" \
      "$bad" "SYS-001"
  else
    report_pass "SYS-001" "medium" "Parâmetros de kernel de rede endurecidos"
  fi
}
