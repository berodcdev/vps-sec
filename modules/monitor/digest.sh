#!/usr/bin/env bash
# modules/monitor/digest.sh — resumo diário enviado ao webhook.
# Também funciona como heartbeat: se um host para de mandar digest, o n8n sabe.

digest_main() {
  require_cmd jq
  # Aceita --now (ou nada); ambos geram e enviam o digest agora.
  _digest_build_and_send
}

_digest_build_and_send() {
  local since="24 hours ago"

  # Último score do audit.
  local score="null" grade="null"
  local latest="$VPS_SEC_LOG_DIR/audit-latest.json"
  if [[ -f "$latest" ]]; then
    score="$(jq -r '.score // "null"' "$latest" 2>/dev/null)"
    grade="$(jq -r '.grade // "null"' "$latest" 2>/dev/null)"
  fi

  # Contagem de eventos do monitor.log nas últimas 24h (por tipo).
  local events_json="{}"
  if [[ -f "$VPS_SEC_LOG_DIR/monitor.log" ]]; then
    local cutoff; cutoff="$(date -u -d "$since" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT00:00:00Z)"
    events_json="$(awk -v c="$cutoff" '$1 >= c {print $2}' "$VPS_SEC_LOG_DIR/monitor.log" 2>/dev/null \
      | sort | uniq -c \
      | jq -R -s 'split("\n") | map(select(length>0) | ltrimstr(" ") | capture("(?<n>[0-9]+) +(?<k>.+)")) | map({(.k): (.n|tonumber)}) | add // {}' 2>/dev/null || echo "{}")"
  fi

  # Top IPs atacantes (24h).
  local top_ips="[]"
  if has_cmd journalctl; then
    top_ips="$(journalctl _COMM=sshd --since "$since" -o cat 2>/dev/null \
      | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' \
      | sort | uniq -c | sort -rn | head -5 \
      | jq -R -s 'split("\n") | map(select(length>0) | ltrimstr(" ") | capture("(?<count>[0-9]+) +(?<ip>.+)")) | map({ip:.ip, count:(.count|tonumber)})' 2>/dev/null || echo "[]")"
  fi

  # Updates de segurança pendentes.
  local sec_pending=0
  if has_cmd apt-get; then
    sec_pending="$(apt-get -s -o Debug::NoLocking=true dist-upgrade 2>/dev/null \
      | grep -c '^Inst.*-security' || echo 0)"
  fi

  # Tamanho do spool.
  local spool; spool="$(find "$VPS_SEC_STATE/spool" -type f -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"

  local details
  details="$(jq -n \
    --argjson score "${score:-null}" --arg grade "${grade:-null}" \
    --argjson events "$events_json" --argjson top_ips "$top_ips" \
    --argjson sec "${sec_pending:-0}" --argjson spool "${spool:-0}" \
    '{audit_score:$score, audit_grade:$grade, events_24h:$events,
      top_attacker_ips:$top_ips, security_updates_pending:$sec,
      spooled_alerts:$spool}')"

  # Digest ignora dedup/severidade (é heartbeat) → usa _alert_emit direto.
  _alert_emit "digest" "info" "$details" "" "digest:$(date -u +%Y%m%d)"
  ok "Digest enviado."
}
