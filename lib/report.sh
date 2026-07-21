#!/usr/bin/env bash
# lib/report.sh — acumulador de findings do audit, scoring e render (texto/JSON).
# Carregado via `source`. Depende de common.sh e de `jq`.

# Cada finding é uma linha TSV em $REPORT_FINDINGS_FILE (tmp), com campos:
#   id \t severity \t status \t title \t detail \t fix_id
# Usar arquivo (e não array) permite que submódulos rodem em subshells/pipes.

report_init() {
  REPORT_FINDINGS_FILE="$(mktemp -t vps-sec-findings.XXXXXX)"
  # shellcheck disable=SC2064
  trap "rm -f '$REPORT_FINDINGS_FILE'" EXIT
  : >"$REPORT_FINDINGS_FILE"
}

# report_add ID SEVERITY STATUS TITLE DETAIL [FIX_ID]
# SEVERITY: critical|high|medium|low|info
# STATUS:   PASS|FAIL|WARN|INFO|SKIPPED
report_add() {
  local id="$1" sev="$2" status="$3" title="$4" detail="${5:-}" fix="${6:--}"
  # Sanitiza tabs/newlines no conteúdo textual (input pode vir de logs).
  title="${title//$'\t'/ }"; title="${title//$'\n'/ }"
  detail="${detail//$'\t'/ }"; detail="${detail//$'\n'/ }"
  # Campos vazios viram "-": com IFS=tab (whitespace), o `read` colapsaria
  # campos vazios e deslocaria as colunas na leitura. "-" = "sem valor".
  [[ -z "$detail" ]] && detail="-"
  [[ -z "$title" ]] && title="-"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$id" "$sev" "$status" "$title" "$detail" "$fix" >>"$REPORT_FINDINGS_FILE"
}

# Atalhos semânticos.
report_pass() { report_add "$1" "$2" "PASS" "$3" "${4:-}" "-"; }
report_fail() { report_add "$1" "$2" "FAIL" "$3" "${4:-}" "${5:--}"; }
report_warn() { report_add "$1" "$2" "WARN" "$3" "${4:-}" "${5:--}"; }
report_info() { report_add "$1" "info" "INFO" "$2" "${3:-}" "-"; }
report_skip() { report_add "$1" "info" "SKIPPED" "$2" "${3:-}" "-"; }

# ── Scoring ─────────────────────────────────────────────────────────────────
# Só contam FAIL. Pesos: critical=25 high=10 medium=4 low=1.
_severity_weight() {
  case "$1" in
    critical) echo 25 ;; high) echo 10 ;; medium) echo 4 ;; low) echo 1 ;; *) echo 0 ;;
  esac
}

_grade_for() {
  local s="$1"
  if   (( s >= 90 )); then echo A
  elif (( s >= 80 )); then echo B
  elif (( s >= 65 )); then echo C
  elif (( s >= 50 )); then echo D
  else echo F; fi
}

# Calcula score e popula contadores globais a partir do arquivo de findings.
# Popula: REPORT_SCORE REPORT_GRADE e REPORT_CNT_<sev>/REPORT_CNT_PASS/etc.
report_compute() {
  local id sev status rest penalty=0
  REPORT_CNT_critical=0 REPORT_CNT_high=0 REPORT_CNT_medium=0 REPORT_CNT_low=0
  REPORT_CNT_pass=0 REPORT_CNT_warn=0 REPORT_CNT_info=0 REPORT_CNT_skipped=0
  while IFS=$'\t' read -r id sev status rest; do
    [[ -z "$id" ]] && continue
    # Nota: usa VAR=$((VAR+1)) e não ((VAR++)) — este último retorna código 1
    # quando a variável vale 0, o que sob `set -e` mataria o script.
    case "$status" in
      PASS)    REPORT_CNT_pass=$((REPORT_CNT_pass+1)) ;;
      WARN)    REPORT_CNT_warn=$((REPORT_CNT_warn+1)) ;;
      INFO)    REPORT_CNT_info=$((REPORT_CNT_info+1)) ;;
      SKIPPED) REPORT_CNT_skipped=$((REPORT_CNT_skipped+1)) ;;
      FAIL)
        penalty=$(( penalty + $(_severity_weight "$sev") ))
        case "$sev" in
          critical) REPORT_CNT_critical=$((REPORT_CNT_critical+1)) ;;
          high)     REPORT_CNT_high=$((REPORT_CNT_high+1)) ;;
          medium)   REPORT_CNT_medium=$((REPORT_CNT_medium+1)) ;;
          low)      REPORT_CNT_low=$((REPORT_CNT_low+1)) ;;
        esac
        ;;
    esac
  done <"$REPORT_FINDINGS_FILE"

  REPORT_SCORE=$(( 100 - penalty ))
  (( REPORT_SCORE < 0 )) && REPORT_SCORE=0
  REPORT_GRADE="$(_grade_for "$REPORT_SCORE")"
}

_sev_color() {
  case "$1" in
    critical) printf '%s' "$C_RED$C_BOLD" ;;
    high)     printf '%s' "$C_RED" ;;
    medium)   printf '%s' "$C_YELLOW" ;;
    low)      printf '%s' "$C_CYAN" ;;
    *)        printf '%s' "$C_DIM" ;;
  esac
}

# ── Render humano (para TTY / arquivo .txt) ─────────────────────────────────
report_render_text() {
  report_compute
  local id sev status title detail fix
  {
    printf '\n%s══ Relatório de auditoria vps-sec ══%s\n' "$C_BOLD" "$C_RESET"
    printf '%sHost:%s %s    %sData:%s %s\n\n' \
      "$C_DIM" "$C_RESET" "${NODE_NAME:-$(hostname)}" \
      "$C_DIM" "$C_RESET" "$(now_utc)"

    # Só falhas e avisos na listagem principal (PASS/INFO poluem).
    printf '%s%-10s %-9s %-9s %s%s\n' "$C_BOLD" "ID" "SEVERIDADE" "STATUS" "TÍTULO" "$C_RESET"
    printf '%s\n' "────────────────────────────────────────────────────────────────────"
    while IFS=$'\t' read -r id sev status title detail fix; do
      [[ -z "$id" ]] && continue
      [[ "$status" == "PASS" || "$status" == "SKIPPED" ]] && continue
      local col; col="$(_sev_color "$sev")"
      printf '%s%-10s %-9s %-9s %s%s\n' "$col" "$id" "$sev" "$status" "$title" "$C_RESET"
      [[ -n "$detail" && "$detail" != "-" ]] && printf '           %s└─ %s%s\n' "$C_DIM" "$detail" "$C_RESET"
      [[ "$fix" != "-" ]] && printf '           %s   corrigir: vps-sec harden --only %s%s\n' "$C_DIM" "$id" "$C_RESET"
    done <"$REPORT_FINDINGS_FILE"

    printf '\n%s── Resumo ──%s\n' "$C_BOLD" "$C_RESET"
    printf '  crítico: %d   alto: %d   médio: %d   baixo: %d   ok: %d   skip: %d\n' \
      "$REPORT_CNT_critical" "$REPORT_CNT_high" "$REPORT_CNT_medium" \
      "$REPORT_CNT_low" "$REPORT_CNT_pass" "$REPORT_CNT_skipped"
    local gcol="$C_GREEN"
    case "$REPORT_GRADE" in C) gcol="$C_YELLOW";; D|F) gcol="$C_RED";; esac
    printf '  %sScore: %d/100 (%s)%s\n\n' "$gcol$C_BOLD" "$REPORT_SCORE" "$REPORT_GRADE" "$C_RESET"
  }
}

# ── Render JSON (via jq, seguro contra injeção) ─────────────────────────────
report_render_json() {
  report_compute
  local version; version="$(cat "$VPS_SEC_PREFIX/VERSION" 2>/dev/null || echo "0.1.0")"

  # Monta o array de findings linha a linha com jq --arg (dados como dados).
  local findings_json="[]"
  local id sev status title detail fix
  while IFS=$'\t' read -r id sev status title detail fix; do
    [[ -z "$id" ]] && continue
    local action=""
    [[ "$fix" != "-" ]] && action="vps-sec harden --only $id"
    findings_json="$(jq -c \
      --arg id "$id" --arg sev "$sev" --arg status "$status" \
      --arg title "$title" --arg detail "$detail" --arg fix "$fix" \
      --arg action "$action" \
      '. + [{id:$id, severity:$sev, status:$status, title:$title,
             detail:(if $detail=="-" then null else $detail end),
             fix_id:(if $fix=="-" then null else $fix end),
             suggested_action:(if $action=="" then null else $action end)}]' \
      <<<"$findings_json")"
  done <"$REPORT_FINDINGS_FILE"

  jq -n \
    --arg tool "vps-sec" --arg version "$version" \
    --arg hostname "${NODE_NAME:-$(hostname)}" --arg ts "$(now_utc)" \
    --argjson score "$REPORT_SCORE" --arg grade "$REPORT_GRADE" \
    --argjson crit "$REPORT_CNT_critical" --argjson high "$REPORT_CNT_high" \
    --argjson med "$REPORT_CNT_medium" --argjson low "$REPORT_CNT_low" \
    --argjson pass "$REPORT_CNT_pass" --argjson skip "$REPORT_CNT_skipped" \
    --argjson findings "$findings_json" \
    '{tool:$tool, version:$version, hostname:$hostname, timestamp:$ts,
      score:$score, grade:$grade,
      summary:{critical:$crit, high:$high, medium:$med, low:$low,
               pass:$pass, skipped:$skip},
      findings:$findings}'
}

# Exit code do audit: 0 limpo, 1 há findings, 2 há critical.
report_exit_code() {
  report_compute
  if (( REPORT_CNT_critical > 0 )); then echo 2
  elif (( REPORT_CNT_high + REPORT_CNT_medium + REPORT_CNT_low > 0 )); then echo 1
  else echo 0; fi
}
