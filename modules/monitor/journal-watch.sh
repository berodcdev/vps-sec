#!/usr/bin/env bash
# modules/monitor/journal-watch.sh — segue o journald em tempo real e detecta
# eventos de autenticação/segurança. Carregado via `source` pelo run.sh.
#
# SEGURANÇA: linhas de log são input adversarial (o atacante controla o
# username tentado no SSH). NUNCA usar eval; todo parse via jq -r/regex e
# valores tratados só como dados (jq --arg nos payloads).

# ── Estado da agregação de brute force (memória do processo) ────────────────
# Um host com a 22 exposta é varrido por botnets sem parar: dezenas de IPs
# distintos por hora cruzam o threshold. Alertar um por IP era uma torneira
# aberta — e pior, enchia o cap global e fazia alertas reais serem descartados.
# Agora as falhas são acumuladas e resumidas em UM alerta por janela.
declare -A _burst_count      # ip -> falhas na janela em tempo real
declare -A _burst_backlog    # ip -> falhas vindas do backlog do journal
declare -A _burst_seen       # ip -> epoch da última falha (p/ login-após-burst)
declare -A _burst_hist       # ip -> falhas acumuladas em janelas já fechadas
_burst_win_start=0
_burst_total=0
_burst_bl_total=0
_burst_bl_from=0
_burst_bl_to=0
_line_is_realtime=1

monitor_journal_loop() {
  local ids=() id
  for id in "${SSH_SYSLOG_IDS[@]}" sudo useradd userdel usermod groupadd; do
    ids+=(-t "$id")
  done

  _offenders_load

  # -o short-unix prefixa o epoch do evento: a janela do burst passa a ser
  # medida pelo TEMPO DO LOG, não pelo relógio de parede. GOTCHA que causou
  # enxurrada: ao reiniciar, o journalctl reprocessa o backlog desde o cursor
  # em rajada; com wall-clock, milhares de linhas antigas caíam todas "no mesmo
  # minuto" e cada IP com histórico disparava um burst na hora.
  # --cursor-file sobrevive a restart sem perder/duplicar. Se o journalctl
  # morrer (rotação extrema), o Restart do systemd reergue o serviço.
  # O read tem timeout para o agregador fechar a janela mesmo sem linhas novas.
  local line rc tick=30
  while :; do
    if IFS= read -r -t "$tick" line; then
      _handle_log_line "$line"
      (( _line_is_realtime )) && _burst_flush_backlog
    else
      rc=$?
      (( rc > 128 )) || break        # <=128 é EOF/erro: sai e o systemd reergue
      _burst_flush_backlog           # o replay acabou (nada mais chegando)
    fi
    _burst_flush_window
  done < <(journalctl -f -o short-unix --cursor-file="$VPS_SEC_STATE/monitor.cursor" \
             "${ids[@]}" 2>/dev/null)
}

# Extrai o epoch do prefixo do `-o short-unix`. Linha sem prefixo (teste manual,
# formato inesperado) cai para o relógio de parede.
_line_epoch() {
  local line="$1"
  if [[ "$line" =~ ^([0-9]{9,})(\.[0-9]+)?[[:space:]] ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  else
    epoch
  fi
}

_handle_log_line() {
  local line="$1"
  local ev_ts; ev_ts="$(_line_epoch "$line")"
  local now; now="$(epoch)"
  local grace="${BURST_REPLAY_GRACE:-600}"
  # Evento mais velho que a folga = backlog reprocessado, não atividade "agora".
  if (( now - ev_ts > grace )); then _line_is_realtime=0; else _line_is_realtime=1; fi

  # ── Login SSH bem-sucedido ────────────────────────────────────────────────
  if [[ "$line" =~ Accepted\ (password|publickey)\ for\ ([^ ]+)\ from\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
    local method="${BASH_REMATCH[1]}" user="${BASH_REMATCH[2]}" ip="${BASH_REMATCH[3]}"
    [[ "${SSH_ALERT_ON_SUCCESS:-yes}" == "yes" ]] || return 0

    # Sucesso vindo de um IP que estava tentando força bruta é O evento que
    # importa: possível comprometimento. Vai como crítico e SEM passar por
    # filtro/dedup/cap — nunca pode ser engolido pelo anti-flood.
    local fails; fails="$(_offender_fails "$ip")"
    if (( fails >= ${FAIL_BURST_THRESHOLD:-10} )); then
      local d; d="$(jq -n --arg u "$user" --arg ip "$ip" --arg m "$method" \
        --argjson f "$fails" \
        '{user:$u, ip:$ip, method:$m, prior_failed_attempts:$f}')"
      _alert_emit "ssh_login_after_burst" "critical" "$d" \
        "Autenticação BEM-SUCEDIDA de um IP que estava em força bruta. Trate como comprometimento: revogue a sessão, rotacione credenciais e audite o host" \
        "login_after_burst:$user@$ip"
      log_file "ssh_login_after_burst user=$user ip=$ip fails=$fails" \
        "$VPS_SEC_LOG_DIR/monitor.log"
      return 0
    fi

    # Piso 'low' (não 'info') para não ser descartado pelo filtro padrão
    # ALERT_MIN_SEVERITY=low. Root/IP novo elevam para 'high'.
    local sev="low" note="Login SSH bem-sucedido"
    if [[ "$user" == "root" ]]; then sev="high"; note="Login SSH de ROOT"; fi
    if ! _ip_known "$ip"; then
      sev="high"
      note="$note (IP novo, fora do histórico)"
    fi
    local details
    details="$(jq -n --arg u "$user" --arg ip "$ip" --arg m "$method" \
      '{user:$u, ip:$ip, method:$m}')"
    alert_send "ssh_login_success" "$sev" "$details" \
      "Se não reconhece este acesso, rotacione chaves/senhas e revise o host" \
      "login:$user@$ip"
    log_file "ssh_login_success user=$user ip=$ip method=$method sev=$sev" \
      "$VPS_SEC_LOG_DIR/monitor.log"
    return 0
  fi

  # ── Falha de autenticação no sudo ─────────────────────────────────────────
  # ORDEM IMPORTA: tem que vir ANTES do bloco de falha de SSH. O PAM do sudo
  # loga "pam_unix(sudo:auth): authentication failure", que casa com o regex de
  # falha de SSH abaixo; como a linha não tem IP, o bloco dava `return` e o
  # sudo_auth_failure nunca era emitido.
  if [[ "$line" =~ sudo:.*authentication\ failure ]]; then
    local suser=""
    [[ "$line" =~ user=([^ ]+) ]] && suser="${BASH_REMATCH[1]}"
    local details; details="$(jq -n --arg u "$suser" '{user:$u}')"
    alert_send "sudo_auth_failure" "medium" "$details" \
      "Falha de autenticação no sudo" "sudo_fail:$suser"
    log_file "sudo_auth_failure user=$suser" "$VPS_SEC_LOG_DIR/monitor.log"
    return 0
  fi

  # ── Falha de auth SSH → agregação de brute force ─────────────────────────
  if [[ "$line" =~ (Failed\ password|Invalid\ user|authentication\ failure) ]]; then
    local ip=""
    if [[ "$line" =~ from\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      ip="${BASH_REMATCH[1]}"
    fi
    [[ -z "$ip" ]] && return 0
    _register_failed_auth "$ip" "$ev_ts"
    return 0
  fi

  # ── Novo usuário criado ──────────────────────────────────────────────────
  if [[ "$line" =~ new\ user:\ name=([^,]+) ]]; then
    local newuser="${BASH_REMATCH[1]}"
    local details; details="$(jq -n --arg u "$newuser" '{user:$u}')"
    alert_send "new_user" "high" "$details" \
      "Se você não criou este usuário, investigue imediatamente" "new_user:$newuser"
    log_file "new_user name=$newuser" "$VPS_SEC_LOG_DIR/monitor.log"
    return 0
  fi

  # ── Usuário removido ─────────────────────────────────────────────────────
  # userdel loga: "delete user 'nome'".
  if [[ "$line" =~ delete\ user\ \'([^\']+)\' ]]; then
    local deluser="${BASH_REMATCH[1]}"
    local details; details="$(jq -n --arg u "$deluser" '{user:$u}')"
    alert_send "user_deleted" "high" "$details" \
      "Se você não removeu este usuário, investigue (possível cobertura de rastros)" \
      "user_deleted:$deluser"
    log_file "user_deleted name=$deluser" "$VPS_SEC_LOG_DIR/monitor.log"
    return 0
  fi

}

# Contabiliza a falha no balde certo (tempo real x backlog). Não alerta aqui:
# quem alerta é o flush da janela.
_register_failed_auth() {
  local ip="$1" ev_ts="$2"
  _burst_seen["$ip"]="$ev_ts"
  if (( _line_is_realtime )); then
    (( _burst_win_start == 0 )) && _burst_win_start="$ev_ts"
    _burst_count["$ip"]=$(( ${_burst_count[$ip]:-0} + 1 ))
    _burst_total=$(( _burst_total + 1 ))
  else
    _burst_backlog["$ip"]=$(( ${_burst_backlog[$ip]:-0} + 1 ))
    _burst_bl_total=$(( _burst_bl_total + 1 ))
    (( _burst_bl_from == 0 || ev_ts < _burst_bl_from )) && _burst_bl_from="$ev_ts"
    (( ev_ts > _burst_bl_to )) && _burst_bl_to="$ev_ts"
  fi
}

# Fecha a janela em tempo real quando ela expira.
_burst_flush_window() {
  (( _burst_total > 0 && _burst_win_start > 0 )) || return 0
  local now; now="$(epoch)"
  local win="${BURST_AGGREGATE_WINDOW:-3600}"
  (( now - _burst_win_start >= win )) || return 0
  local ip pairs=""
  for ip in "${!_burst_count[@]}"; do pairs+="$ip ${_burst_count[$ip]}"$'\n'; done
  _burst_emit "window" "$_burst_win_start" "$now" "$_burst_total" "$pairs"
  # GOTCHA: acumular no histórico ANTES de zerar a janela. Sem isto o IP deixa
  # de ser "ofensor" no instante em que a janela fecha — justo quando um login
  # bem-sucedido dele seria o sinal mais importante do sistema.
  for ip in "${!_burst_count[@]}"; do
    _burst_hist["$ip"]=$(( ${_burst_hist[$ip]:-0} + ${_burst_count[$ip]} ))
  done
  _burst_count=(); _burst_total=0; _burst_win_start=0
  _offenders_save
}

# Resume TODO o backlog reprocessado num único alerta, marcado como tal.
_burst_flush_backlog() {
  (( _burst_bl_total > 0 )) || return 0
  local ip pairs=""
  for ip in "${!_burst_backlog[@]}"; do pairs+="$ip ${_burst_backlog[$ip]}"$'\n'; done
  _burst_emit "backlog" "$_burst_bl_from" "$_burst_bl_to" "$_burst_bl_total" "$pairs"
  for ip in "${!_burst_backlog[@]}"; do
    _burst_hist["$ip"]=$(( ${_burst_hist[$ip]:-0} + ${_burst_backlog[$ip]} ))
  done
  _burst_backlog=(); _burst_bl_total=0; _burst_bl_from=0; _burst_bl_to=0
  _offenders_save
}

# _burst_emit <kind> <from_ts> <to_ts> <total> <pairs>
# pairs = "ip count" por linha. Recebido por argumento, não por pipe: um pipe
# rodaria a função em subshell e qualquer estado que ela tocasse se perderia.
# Só alerta se algum IP cruzou o threshold; ruído de duas tentativas perdidas
# não vira notificação.
_burst_emit() {
  local kind="$1" from="$2" to="$3" total="$4" pairs="$5"
  local thr="${FAIL_BURST_THRESHOLD:-10}"
  [[ -z "$pairs" ]] && return 0

  # `grep -c` sai com 1 quando não casa nada; sem o `|| true` isso derruba o
  # monitor inteiro (o dispatcher roda com set -e).
  local distinct offenders top
  distinct="$(printf '%s\n' "$pairs" | grep -c . || true)"
  offenders="$(printf '%s\n' "$pairs" | awk -v t="$thr" '$2+0 >= t+0' | grep -c . || true)"
  (( offenders > 0 )) || return 0
  top="$(printf '%s\n' "$pairs" | grep . | sort -k2 -rn | head -5 \
    | jq -R -s 'split("\n") | map(select(length>0) | split(" ")
                | {ip:.[0], failed_attempts:(.[1]|tonumber)})' 2>/dev/null || echo '[]')"
  [[ -z "$top" ]] && top='[]'

  # Escalonamento: volume muito acima do que este host costuma ver na janela.
  local sev="high" baseline; baseline="$(_burst_baseline)"
  if (( baseline > 0 && total >= baseline * 3 && total >= thr * 10 )); then
    sev="critical"
  fi
  _burst_baseline_record "$total"

  local action="Ruído de varredura é esperado num host com SSH exposto. Confirme que o fail2ban está ativo e que a autenticação por senha está desabilitada."
  (( offenders >= 20 )) && action="Volume alto de origens distintas. Confirme fail2ban ativo, desabilite PasswordAuthentication e considere restringir a porta 22 por firewall/VPN."

  local details
  details="$(jq -n --arg k "$kind" --argjson t "$total" --argjson d "$distinct" \
    --argjson o "$offenders" --argjson w "${BURST_AGGREGATE_WINDOW:-3600}" \
    --argjson top "$top" --arg from "$(_iso "$from")" --arg to "$(_iso "$to")" \
    '{failed_attempts:$t, distinct_ips:$d, ips_over_threshold:$o,
      window_seconds:$w, period_start:$from, period_end:$to,
      top_ips:$top, source:$k}')"

  # Backlog e janela são chaves de dedup distintas: o resumo do replay não pode
  # engolir o alerta da atividade em tempo real que vem logo depois.
  alert_send "ssh_auth_burst" "$sev" "$details" "$action" "burst:$kind"
  log_file "ssh_auth_burst source=$kind total=$total ips=$distinct offenders=$offenders sev=$sev" \
    "$VPS_SEC_LOG_DIR/monitor.log"
}

_iso() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf 'null'; }

# ── Linha de base do volume por janela (para escalonar severidade) ──────────
_BURST_HIST="${VPS_SEC_STATE:-/var/lib/vps-sec}/burst-history.txt"

# Mediana aproximada (média) das últimas janelas registradas; 0 se não há
# histórico suficiente para afirmar o que é "normal" neste host.
_burst_baseline() {
  [[ -f "$_BURST_HIST" ]] || { echo 0; return; }
  awk 'NF{s+=$1; n++} END{ if (n>=3) printf "%d", s/n; else print 0 }' "$_BURST_HIST" 2>/dev/null || echo 0
}

_burst_baseline_record() {
  printf '%s\n' "$1" >>"$_BURST_HIST" 2>/dev/null || return 0
  # Mantém só as últimas 24 janelas.
  tail -n 24 "$_BURST_HIST" >"$_BURST_HIST.tmp" 2>/dev/null && mv "$_BURST_HIST.tmp" "$_BURST_HIST"
}

# ── Ofensores recentes (para detectar login bem-sucedido após brute force) ──
_OFFENDERS="${VPS_SEC_STATE:-/var/lib/vps-sec}/burst-offenders.tsv"

# Persiste ip<TAB>ultimo_ts<TAB>falhas, podando o que passou de 24h. Sobrevive
# a restart do monitor — o login pode vir depois de o serviço reiniciar.
_offenders_save() {
  local cutoff=$(( $(epoch) - 86400 )) ip
  {
    for ip in "${!_burst_seen[@]}"; do
      local n=$(( ${_burst_count[$ip]:-0} + ${_burst_backlog[$ip]:-0} + ${_burst_hist[$ip]:-0} ))
      (( ${_burst_seen[$ip]} >= cutoff )) && printf '%s\t%s\t%s\n' "$ip" "${_burst_seen[$ip]}" "$n"
    done
  } >"$_OFFENDERS.tmp" 2>/dev/null && mv "$_OFFENDERS.tmp" "$_OFFENDERS" 2>/dev/null || true
}

_offenders_load() {
  [[ -f "$_OFFENDERS" ]] || return 0
  local cutoff=$(( $(epoch) - 86400 )) ip ts n
  while IFS=$'\t' read -r ip ts n; do
    [[ -z "$ip" ]] && continue
    (( ts >= cutoff )) || continue
    _burst_seen["$ip"]="$ts"
    _burst_hist["$ip"]="$n"
  done <"$_OFFENDERS"
}

# Quantas falhas este IP acumulou nas últimas 24h.
_offender_fails() {
  local ip="$1"
  printf '%s' $(( ${_burst_count[$ip]:-0} + ${_burst_backlog[$ip]:-0} + ${_burst_hist[$ip]:-0} ))
}

# IP já apareceu em logins bem-sucedidos anteriores (baseline)?
_ip_known() {
  local ip="$1" f="$VPS_SEC_STATE/baseline/ips.txt"
  [[ -f "$f" ]] || return 1
  grep -qxF "$ip" "$f"
}
