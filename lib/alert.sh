#!/usr/bin/env bash
# lib/alert.sh — envio de alertas ao webhook do n8n, com retry, spool,
# dedup/cooldown e cap global anti-flood. Carregado via `source`.
# Depende de common.sh (já sourced), jq e curl.

_alert_version() { cat "$VPS_SEC_PREFIX/VERSION" 2>/dev/null || echo "0.0.0"; }

# ── Núcleo do envio HTTP ────────────────────────────────────────────────────
# _alert_post <payload_json> → 0 se 2xx, 1 caso contrário.
# A URL vai via --config no stdin (nunca no argv → invisível em `ps`).
_alert_post() {
  local payload="$1"
  [[ -z "${WEBHOOK_URL:-}" ]] && return 1

  local code
  code="$(printf 'url = "%s"\n' "$WEBHOOK_URL" | curl -sS -o /dev/null \
            -w '%{http_code}' --max-time 10 \
            -H 'Content-Type: application/json' \
            -X POST --data-binary "$payload" \
            --config - 2>/dev/null || echo 000)"

  case "$code" in
    2*) return 0 ;;
    4*) log_file "alerta rejeitado pelo webhook (HTTP $code) — descartado" \
          "$VPS_SEC_LOG_DIR/monitor.log"; return 2 ;;  # 2 = não re-tentar
    *)  return 1 ;;                                     # 5xx/timeout → re-tentar
  esac
}

# Envia com 3 tentativas e backoff; em falha total, faz spool.
# _alert_deliver <payload_json> <event_id>
_alert_deliver() {
  local payload="$1" event_id="$2"
  local -a delays=(0 5 25)
  local i rc
  for i in "${delays[@]}"; do
    (( i > 0 )) && sleep "$i"
    _alert_post "$payload"; rc=$?
    [[ $rc -eq 0 ]] && return 0
    [[ $rc -eq 2 ]] && return 1   # 4xx: não adianta repetir
  done
  # Falhou tudo → spool.
  _alert_spool_write "$payload" "$event_id"
  return 1
}

# ── Spool (fila em disco quando o webhook está fora) ────────────────────────
_alert_spool_write() {
  local payload="$1" event_id="$2"
  install -d -m 700 "$VPS_SEC_STATE/spool" 2>/dev/null || return 1
  local f; f="$VPS_SEC_STATE/spool/$(epoch)-${event_id}.json"
  printf '%s\n' "$payload" >"$f" 2>/dev/null || return 1
  # Cap de 500 arquivos: remove os mais antigos.
  local count
  count="$(find "$VPS_SEC_STATE/spool" -type f -name '*.json' 2>/dev/null | wc -l)"
  if [[ "${count:-0}" -gt 500 ]]; then
    find "$VPS_SEC_STATE/spool" -type f -name '*.json' -printf '%T@ %p\n' 2>/dev/null \
      | sort -n | head -n $(( count - 500 )) | awk '{print $2}' \
      | xargs -r rm -f
  fi
  log_file "alerta em spool ($event_id) — webhook indisponível" "$VPS_SEC_LOG_DIR/monitor.log"
}

# Tenta reenviar tudo que está no spool (chamado antes de novos envios e no digest).
alert_flush_spool() {
  [[ -z "${WEBHOOK_URL:-}" ]] && return 0
  local f payload
  for f in "$VPS_SEC_STATE"/spool/*.json; do
    [[ -f "$f" ]] || continue
    payload="$(cat "$f" 2>/dev/null)" || continue
    if _alert_post "$payload"; then
      rm -f "$f"
    else
      # Ainda fora do ar: para de tentar para não travar.
      return 1
    fi
  done
  return 0
}

# ── Dedup / cooldown / cap global (com flock) ───────────────────────────────
# Retorna 0 se DEVE enviar, 1 se deve suprimir. Também gerencia o contador
# suprimido por chave (para o digest).
# _alert_should_send <event_type> <dedup_key>
_alert_should_send() {
  local event_type="$1" key="$2"
  install -d -m 700 "$VPS_SEC_STATE/dedup" 2>/dev/null || return 0
  local lock="$VPS_SEC_STATE/dedup/.lock"
  exec 9>"$lock"
  flock 9 2>/dev/null || true

  local now; now="$(epoch)"
  local cooldown="${ALERT_COOLDOWN:-900}"

  # Cap global por hora.
  local capfile="$VPS_SEC_STATE/dedup/.global"
  local win_start=0 win_count=0
  if [[ -f "$capfile" ]]; then
    read -r win_start win_count <"$capfile" 2>/dev/null || true
  fi
  if (( now - win_start >= 3600 )); then
    win_start="$now"; win_count=0
  fi
  win_count=$((win_count+1))
  printf '%s %s\n' "$win_start" "$win_count" >"$capfile"

  local cap="${GLOBAL_ALERT_CAP_HOUR:-30}"
  if (( win_count == cap + 1 )); then
    ALERT_STORM_TRIGGERED=1   # sinaliza para quem chamou emitir alert_storm
  fi
  if (( win_count > cap )); then
    flock -u 9 2>/dev/null || true
    return 1
  fi

  # Dedup por chave.
  local kf; kf="$VPS_SEC_STATE/dedup/$(short_sha1 "$event_type|$key")"
  local last=0 suppressed=0
  if [[ -f "$kf" ]]; then
    read -r last suppressed <"$kf" 2>/dev/null || true
  fi
  if (( now - last < cooldown )); then
    suppressed=$((suppressed+1))
    printf '%s %s\n' "$last" "$suppressed" >"$kf"
    flock -u 9 2>/dev/null || true
    return 1
  fi
  # Passou o cooldown → envia e zera o contador de suprimidos.
  ALERT_SUPPRESSED_SINCE_LAST="$suppressed"
  printf '%s 0\n' "$now" >"$kf"
  flock -u 9 2>/dev/null || true
  return 0
}

# ── API pública ─────────────────────────────────────────────────────────────
# alert_send <event_type> <severity> <details_json> [suggested_action] [dedup_key]
# details_json deve ser um objeto JSON válido (use jq -n para montar).
alert_send() {
  local event_type="$1" severity="$2" details_json="${3:-{\}}"
  local action="${4:-}" dedup_key="${5:-$event_type}"

  # Filtro por severidade mínima.
  local min="${ALERT_MIN_SEVERITY:-low}"
  if (( $(severity_rank "$severity") < $(severity_rank "$min") )); then
    return 0
  fi

  ALERT_SUPPRESSED_SINCE_LAST=0
  ALERT_STORM_TRIGGERED=0
  if ! _alert_should_send "$event_type" "$dedup_key"; then
    # Se acabou de estourar o cap, emite um único alert_storm.
    if [[ "${ALERT_STORM_TRIGGERED:-0}" == "1" ]]; then
      _alert_emit "alert_storm" "high" \
        "$(jq -n --argjson cap "${GLOBAL_ALERT_CAP_HOUR:-30}" \
           '{message:"Limite de alertas por hora atingido; novos alertas suprimidos até a próxima janela", cap_per_hour:$cap}')" \
        "Verifique o host — possível incidente em andamento" "alert_storm"
    fi
    return 0
  fi

  _alert_emit "$event_type" "$severity" "$details_json" "$action" "$dedup_key"
}

# Monta o payload final e entrega (sem passar pelo dedup — uso interno).
_alert_emit() {
  local event_type="$1" severity="$2" details_json="$3"
  local action="${4:-}" dedup_key="${5:-$event_type}"

  local ts host ver event_id
  ts="$(now_utc)"; host="${NODE_NAME:-$(hostname)}"; ver="$(_alert_version)"
  event_id="$(short_sha1 "$host|$event_type|$dedup_key|$ts")"

  local payload
  payload="$(jq -n \
    --argjson sv 1 \
    --arg et "$event_type" --arg sev "$severity" --arg host "$host" \
    --arg ts "$ts" --arg ver "$ver" --arg eid "$event_id" \
    --argjson details "$details_json" \
    --arg action "$action" \
    --argjson supp "${ALERT_SUPPRESSED_SINCE_LAST:-0}" \
    '{schema_version:$sv, event_type:$et, severity:$sev, hostname:$host,
      timestamp:$ts, agent_version:$ver, event_id:$eid,
      details:$details,
      suggested_action:(if $action=="" then null else $action end),
      suppressed_since_last:$supp}')"

  # Reenvia spool primeiro (best-effort), depois entrega este.
  alert_flush_spool >/dev/null 2>&1 || true
  _alert_deliver "$payload" "$event_id"
}

# ── test-webhook ─────────────────────────────────────────────────────────────
alert_test() {
  require_cmd jq curl
  if [[ -z "${WEBHOOK_URL:-}" ]]; then
    die "WEBHOOK_URL não configurada em $VPS_SEC_CONFIG"
  fi
  log "Enviando evento de teste para o webhook..."
  local details
  details="$(jq -n --arg h "${NODE_NAME:-$(hostname)}" \
    '{message:"Evento de teste do vps-sec", host:$h}')"
  local payload ts host ver
  ts="$(now_utc)"; host="${NODE_NAME:-$(hostname)}"; ver="$(_alert_version)"
  payload="$(jq -n --argjson sv 1 --arg et "test" --arg sev "info" \
    --arg host "$host" --arg ts "$ts" --arg ver "$ver" \
    --arg eid "$(short_sha1 "$host|test|$ts")" --argjson details "$details" \
    '{schema_version:$sv, event_type:$et, severity:$sev, hostname:$host,
      timestamp:$ts, agent_version:$ver, event_id:$eid, details:$details,
      suggested_action:null, suppressed_since_last:0}')"

  local code
  code="$(printf 'url = "%s"\n' "$WEBHOOK_URL" | curl -sS -o /dev/null \
            -w '%{http_code}' --max-time 10 -H 'Content-Type: application/json' \
            -X POST --data-binary "$payload" --config - 2>/dev/null || echo 000)"
  if [[ "$code" == 2* ]]; then
    ok "Webhook respondeu HTTP $code — alerta de teste entregue."
  else
    die "Webhook respondeu HTTP $code — verifique a URL e a conectividade."
  fi
}
