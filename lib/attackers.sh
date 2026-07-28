#!/usr/bin/env bash
# lib/attackers.sh — histórico permanente de IPs que tentaram força bruta.
# Carregado via `source`. Depende de common.sh.
#
# Diferente de burst-offenders.tsv (janela de 24h, estado de trabalho do
# journal-watch para detectar login-após-burst), este arquivo é o REGISTRO
# HISTÓRICO: sobrevive a restart, acumula por meses e alimenta o digest e o
# comando `vps-sec attackers`.
#
# Formato TSV: ip \t first_seen \t last_seen \t total_fails \t times_banned
# GOTCHA: nunca deixe um campo do meio vazio — `IFS=$'\t' read` colapsa campos
# vazios porque tab é whitespace-class, e as colunas se deslocam.

_ATTACKERS="${VPS_SEC_STATE:-/var/lib/vps-sec}/attackers.tsv"

# attackers_record <ip> <fails> <last_seen_epoch> [banned:0|1]
# Soma as tentativas ao total do IP, preservando o first_seen.
attackers_record() {
  local ip="$1" fails="${2:-0}" ts="${3:-$(epoch)}" banned="${4:-0}"
  [[ -z "$ip" ]] && return 0
  install -d -m 700 "$(dirname "$_ATTACKERS")" 2>/dev/null || true
  touch "$_ATTACKERS" 2>/dev/null || return 0

  awk -F'\t' -v OFS='\t' -v ip="$ip" -v f="$fails" -v ts="$ts" -v b="$banned" '
    $1 == ip {
      found = 1
      first = ($2 < ts && $2 > 0) ? $2 : ts
      print $1, first, (ts > $3 ? ts : $3), $4 + f, $5 + b
      next
    }
    NF >= 5 { print }
    END { if (!found) print ip, ts, ts, f, b }
  ' "$_ATTACKERS" >"$_ATTACKERS.tmp" 2>/dev/null && mv "$_ATTACKERS.tmp" "$_ATTACKERS"
}

# Marca que um IP já conhecido foi banido (incrementa o contador).
attackers_mark_banned() {
  local ip="$1"
  [[ -z "$ip" ]] && return 0
  [[ -f "$_ATTACKERS" ]] || return 0
  awk -F'\t' -v OFS='\t' -v ip="$ip" '
    $1 == ip && NF >= 5 { print $1, $2, $3, $4, $5 + 1; next }
    NF >= 5 { print }
  ' "$_ATTACKERS" >"$_ATTACKERS.tmp" 2>/dev/null && mv "$_ATTACKERS.tmp" "$_ATTACKERS"
}

# Remove registros cujo last_seen passou da retenção (default 365 dias).
attackers_prune() {
  [[ -f "$_ATTACKERS" ]] || return 0
  local days="${ATTACKERS_RETENTION_DAYS:-365}"
  local cutoff=$(( $(epoch) - days * 86400 ))
  awk -F'\t' -v c="$cutoff" 'NF >= 5 && $3 >= c' "$_ATTACKERS" \
    >"$_ATTACKERS.tmp" 2>/dev/null && mv "$_ATTACKERS.tmp" "$_ATTACKERS"
}

# Top N por total de tentativas, como array JSON (para o digest/payloads).
attackers_top_json() {
  local n="${1:-10}"
  [[ -f "$_ATTACKERS" ]] || { echo '[]'; return; }
  sort -t$'\t' -k4 -rn "$_ATTACKERS" 2>/dev/null | head -n "$n" \
    | jq -R -s --argjson lim "$n" '
        split("\n") | map(select(length>0) | split("\t")
        | select(length >= 5)
        | {ip:.[0], first_seen:(.[1]|tonumber), last_seen:(.[2]|tonumber),
           failed_attempts:(.[3]|tonumber), times_banned:(.[4]|tonumber)})
        | .[0:$lim]' 2>/dev/null || echo '[]'
}

attackers_count() {
  [[ -f "$_ATTACKERS" ]] || { echo 0; return; }
  # `grep -c` já imprime 0 quando não casa nada, mas sai com código 1 — um
  # `|| echo 0` aqui imprimiria o zero DUAS vezes. Conta com wc.
  local n; n="$(grep -c . "$_ATTACKERS" 2>/dev/null)" || n=0
  printf '%s' "${n:-0}"
}

# ── Subcomando `vps-sec attackers` ──────────────────────────────────────────
attackers_main() {
  local json=0 top=20
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --json)  json=1 ;;
      --top)   top="${2:-20}"; shift ;;
      --all)   top=100000 ;;
      --prune) attackers_prune; ok "Histórico podado (retenção: ${ATTACKERS_RETENTION_DAYS:-365} dias)."; return 0 ;;
      *) warn "attackers: opção ignorada '$1'" ;;
    esac
    shift
  done

  if (( json )); then
    attackers_top_json "$top"
    return 0
  fi

  if [[ ! -s "$_ATTACKERS" ]]; then
    echo "Nenhum IP atacante registrado ainda." >&2
    return 0
  fi

  local total; total="$(attackers_count)"
  printf '\n  %-16s %8s %7s  %-17s %-17s\n' "IP" "TENTAT." "BANIDO" "PRIMEIRA VEZ" "ÚLTIMA VEZ"
  printf '  %s\n' "──────────────────────────────────────────────────────────────────────────"
  local ip first last fails banned
  while IFS=$'\t' read -r ip first last fails banned; do
    [[ -z "$ip" ]] && continue
    printf '  %-16s %8s %7s  %-17s %-17s\n' \
      "$ip" "$fails" "${banned:-0}x" "$(fmt_local "$first")" "$(fmt_local "$last")"
  done < <(sort -t$'\t' -k4 -rn "$_ATTACKERS" 2>/dev/null | head -n "$top")
  printf '\n  %s IP(s) no histórico · retenção %s dias · %s\n\n' \
    "$total" "${ATTACKERS_RETENTION_DAYS:-365}" "$_ATTACKERS"
}
