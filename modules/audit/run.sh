#!/usr/bin/env bash
# modules/audit/run.sh — orquestra os módulos de audit e gera as saídas.
# Depende de common.sh (já sourced) + report.sh + jq. Carregado via `source`.

# shellcheck source=/dev/null
. "$VPS_SEC_PREFIX/lib/report.sh"

# Lista ordenada de módulos (ordem lexicográfica dos arquivos).
_audit_modules() {
  find "$VPS_SEC_MODULES/audit" -maxdepth 1 -name '[0-9]*.sh' 2>/dev/null | sort
}

audit_main() {
  require_cmd jq

  local as_json=0 quiet=0 only=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --json)  as_json=1 ;;
      --quiet) quiet=1 ;;
      --only)  only="$2"; shift ;;
      *) warn "audit: opção ignorada '$1'" ;;
    esac
    shift
  done

  report_init

  # Roda cada módulo. Cada arquivo define uma função audit_<slug>.
  local mod fn
  for mod in $(_audit_modules); do
    # shellcheck source=/dev/null
    . "$mod"
    fn="audit_$(basename "$mod" .sh | sed 's/^[0-9]*-//; s/-/_/g')"
    if declare -F "$fn" >/dev/null; then
      "$fn" || warn "módulo $fn retornou erro (continuando)"
    fi
  done

  # Persiste as saídas (se rodando como root com dirs disponíveis).
  ensure_dirs 2>/dev/null || true
  local ts json_out txt_out
  ts="$(now_ts)"
  json_out="$VPS_SEC_LOG_DIR/audit-$ts.json"
  txt_out="$VPS_SEC_LOG_DIR/audit-$ts.txt"

  local json; json="$(report_render_json)"
  if [[ -d "$VPS_SEC_LOG_DIR" ]]; then
    printf '%s\n' "$json" >"$json_out" 2>/dev/null || true
    # Render texto sem cor no arquivo.
    ( C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' \
      C_BLUE='' C_MAGENTA='' C_CYAN=''; report_render_text ) \
      >"$txt_out" 2>/dev/null || true
    ln -sf "audit-$ts.json" "$VPS_SEC_LOG_DIR/audit-latest.json" 2>/dev/null || true
  fi

  # Alerta findings críticos/altos NOVOS (diff contra o audit anterior),
  # se o alerting estiver disponível e configurado.
  _audit_alert_new_findings "$json" 2>/dev/null || true

  # Saída para o usuário.
  if [[ "$as_json" == "1" ]]; then
    printf '%s\n' "$json"
  elif [[ "$quiet" != "1" ]]; then
    report_render_text
  fi

  exit "$(report_exit_code)"
}

# Compara os findings críticos/altos com o penúltimo audit e alerta os novos.
_audit_alert_new_findings() {
  local current_json="$1"
  [[ -z "${WEBHOOK_URL:-}" ]] && return 0
  [[ -f "$VPS_SEC_PREFIX/lib/alert.sh" ]] || return 0

  # IDs críticos/altos do anterior (o symlink ainda aponta pro que acabamos de
  # escrever nesta run? Não: escrevemos o novo e o symlink já foi trocado.
  # Guardamos o snapshot anterior separado.)
  local prev="$VPS_SEC_STATE/audit-prev-ids.txt"
  local cur_ids
  cur_ids="$(jq -r '.findings[] | select(.status=="FAIL") |
             select(.severity=="critical" or .severity=="high") | .id' \
             <<<"$current_json" 2>/dev/null | sort -u)"

  local prev_ids=""
  [[ -f "$prev" ]] && prev_ids="$(sort -u "$prev")"

  # shellcheck source=/dev/null
  . "$VPS_SEC_PREFIX/lib/alert.sh"

  local id
  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    if ! grep -qxF "$id" <<<"$prev_ids"; then
      # Finding novo → alerta.
      local sev title detail action
      sev="$(jq -r --arg id "$id" '.findings[] | select(.id==$id) | .severity' <<<"$current_json")"
      title="$(jq -r --arg id "$id" '.findings[] | select(.id==$id) | .title' <<<"$current_json")"
      detail="$(jq -r --arg id "$id" '.findings[] | select(.id==$id) | .detail' <<<"$current_json")"
      action="$(jq -r --arg id "$id" '.findings[] | select(.id==$id) | .suggested_action // ""' <<<"$current_json")"
      local details_json
      details_json="$(jq -n --arg id "$id" --arg t "$title" --arg d "$detail" \
                      '{check_id:$id, title:$t, detail:$d}')"
      alert_send "audit_finding" "$sev" "$details_json" "$action" "audit:$id"
    fi
  done <<<"$cur_ids"

  # Atualiza o snapshot para a próxima run.
  printf '%s\n' "$cur_ids" >"$prev" 2>/dev/null || true
}
