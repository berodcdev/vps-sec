#!/usr/bin/env bash
# modules/audit/95-authlog.sh — análise das últimas 24h de logs de auth (journald).

audit_authlog() {
  if ! has_cmd journalctl; then
    report_skip "LOG-000" "journalctl ausente — análise de logs indisponível"
    return 0
  fi

  local logs
  logs="$(journalctl _COMM=sshd --since "24 hours ago" -o cat 2>/dev/null || true)"
  if [[ -z "$logs" ]]; then
    logs="$(journalctl -t sshd -t sshd-session --since "24 hours ago" -o cat 2>/dev/null || true)"
  fi
  if [[ -z "$logs" ]]; then
    report_info "LOG-000" "Sem logs de SSH nas últimas 24h"
    return 0
  fi

  # LOG-001: falhas de autenticação por IP.
  local fails
  fails="$(grep -cE 'Failed password|Invalid user|authentication failure' <<<"$logs" || true)"
  fails="${fails:-0}"
  local top_ips
  top_ips="$(grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' <<<"$logs" \
             | awk '{print $2}' | sort | uniq -c | sort -rn | head -5 \
             | awk '{printf "%s(%s) ", $2, $1}')"

  if [[ "$fails" -gt 500 ]]; then
    local sev="high"
    [[ "${HAS_FAIL2BAN:-0}" == "1" ]] && sev="medium"
    report_fail "LOG-001" "$sev" "$fails falhas de autenticação SSH em 24h" \
      "Top IPs: ${top_ips:-nenhum}" "SVC-001"
  elif [[ "$fails" -gt 0 ]]; then
    report_info "LOG-001" "$fails falhas de autenticação SSH em 24h" \
      "Top IPs: ${top_ips:-nenhum}"
  else
    report_pass "LOG-001" "medium" "Sem falhas de autenticação SSH nas últimas 24h"
  fi

  # LOG-002: logins bem-sucedidos (informativo, útil no relatório).
  local ok_logins
  ok_logins="$(grep -E 'Accepted (password|publickey)' <<<"$logs" \
               | grep -oE 'for [^ ]+ from [0-9.]+' | sort | uniq -c | sort -rn \
               | head -5 | tr '\n' ';')"
  [[ -n "$ok_logins" ]] && report_info "LOG-002" "Logins SSH aceitos (24h)" "$ok_logins"

  # LOG-003: volume de "Invalid user" (scanning ativo).
  local invalid
  invalid="$(grep -cE 'Invalid user' <<<"$logs" || true)"
  invalid="${invalid:-0}"
  if [[ "$invalid" -gt 100 ]]; then
    report_warn "LOG-003" "medium" "$invalid tentativas com usuário inexistente (24h)" \
      "Scanning ativo — considere mudar porta e usar fail2ban"
  fi
}
