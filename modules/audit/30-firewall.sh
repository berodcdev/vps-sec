#!/usr/bin/env bash
# modules/audit/30-firewall.sh — firewall (UFW / nftables / iptables).

# Portas de administração/serviços que não deveriam estar abertas ao mundo.
_ADMIN_PORTS="3306 5432 6379 27017 9200 5984 11211 2375 2376 8080 3000 9000 8443 15672"

audit_firewall() {
  if [[ "${HAS_UFW:-0}" == "1" ]]; then
    local status; status="$(ufw status verbose 2>/dev/null)"
    if grep -qi 'Status: active' <<<"$status"; then
      report_pass "FW-001" "critical" "UFW ativo"

      # FW-002: política default de entrada.
      if grep -qiE 'Default:.*deny \(incoming\)|deny \(incoming\)' <<<"$status"; then
        report_pass "FW-002" "high" "UFW nega conexões de entrada por padrão"
      else
        report_fail "FW-002" "high" "UFW não nega entrada por padrão" \
          "Default incoming deveria ser 'deny'" "FW-002"
      fi

      # FW-003: portas de admin liberadas para Anywhere.
      local exposed=""
      local p
      for p in $_ADMIN_PORTS; do
        if grep -qE "^${p}[/ ].*(ALLOW).*(Anywhere)" <<<"$status"; then
          exposed+="$p "
        fi
      done
      if [[ -n "$exposed" ]]; then
        report_fail "FW-003" "medium" "Porta(s) sensível liberada para qualquer origem" \
          "UFW permite de Anywhere: $exposed" "FW-003"
      else
        report_pass "FW-003" "medium" "Nenhuma porta sensível aberta a Anywhere no UFW"
      fi
    else
      report_fail "FW-001" "critical" "UFW instalado mas INATIVO" \
        "Sem firewall ativo — habilite com cuidado (vps-sec harden --only FW-001)" "FW-001"
    fi
  else
    # Sem UFW: checa se há política restritiva em nftables/iptables.
    local has_rules=0
    if has_cmd nft && nft list ruleset 2>/dev/null | grep -qE 'policy drop|drop$'; then
      has_rules=1
    elif has_cmd iptables && iptables -S 2>/dev/null | grep -qE '^-P INPUT DROP'; then
      has_rules=1
    fi
    if [[ "$has_rules" == "1" ]]; then
      report_pass "FW-001" "critical" "Firewall via nftables/iptables com política restritiva"
    else
      report_fail "FW-001" "critical" "Nenhum firewall ativo detectado" \
        "UFW ausente e sem política DROP em iptables/nftables" "FW-001"
    fi
  fi
}
