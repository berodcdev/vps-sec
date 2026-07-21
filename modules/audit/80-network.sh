#!/usr/bin/env bash
# modules/audit/80-network.sh — portas escutando e serviços expostos.

_ADMIN_PORTS_NET="3306 5432 6379 27017 9200 5984 11211 2375 15672 5601 9090"

audit_network() {
  if ! has_cmd ss; then
    report_skip "NET-000" "comando 'ss' ausente — inventário de portas indisponível"
    return 0
  fi

  # NET-001: inventário (informativo).
  local listening
  listening="$(ss -tulnH 2>/dev/null | awk '{print $1, $5}' | sort -u | tr '\n' ';')"
  report_info "NET-001" "Portas em escuta" "$listening"

  # NET-002: serviços sensíveis escutando em 0.0.0.0/:: (fora de containers).
  # Docker publica via docker-proxy; aqui focamos em processos do host.
  local exposed=""
  local local_addr port
  while read -r _ local_addr; do
    # local_addr ex.: 0.0.0.0:5432 ou [::]:6379
    port="${local_addr##*:}"
    if [[ "$local_addr" == 0.0.0.0:* || "$local_addr" == "[::]:"* ]]; then
      if grep -qw "$port" <<<"$_ADMIN_PORTS_NET"; then
        exposed+="$port "
      fi
    fi
  done < <(ss -tulnH 2>/dev/null | awk '{print $1, $5}')

  if [[ -n "$exposed" ]]; then
    report_fail "NET-002" "high" "Serviço sensível escutando em todas as interfaces" \
      "Portas expostas ao mundo: $exposed — prefira bind em 127.0.0.1" "NET-002"
  else
    report_pass "NET-002" "high" "Nenhum serviço sensível exposto em 0.0.0.0"
  fi
}
