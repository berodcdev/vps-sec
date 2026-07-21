#!/usr/bin/env bash
# modules/monitor/journal-watch.sh — segue o journald em tempo real e detecta
# eventos de autenticação/segurança. Carregado via `source` pelo run.sh.
#
# SEGURANÇA: linhas de log são input adversarial (o atacante controla o
# username tentado no SSH). NUNCA usar eval; todo parse via jq -r/regex e
# valores tratados só como dados (jq --arg nos payloads).

# Estado de agregação de brute force por IP (em memória do processo).
declare -A _burst_count _burst_start _burst_alerted

monitor_journal_loop() {
  local ids=() id
  for id in "${SSH_SYSLOG_IDS[@]}" sudo useradd usermod groupadd; do
    ids+=(-t "$id")
  done

  # -f segue; --cursor-file sobrevive a restart sem perder/duplicar; -o cat dá a
  # mensagem crua. Se o journalctl morrer (rotação extrema), o Restart do
  # systemd reergue o serviço e o cursor retoma de onde parou.
  journalctl -f -o cat --cursor-file="$VPS_SEC_STATE/monitor.cursor" \
    "${ids[@]}" 2>/dev/null | while IFS= read -r line; do
      _handle_log_line "$line"
    done
}

_handle_log_line() {
  local line="$1"

  # ── Login SSH bem-sucedido ────────────────────────────────────────────────
  if [[ "$line" =~ Accepted\ (password|publickey)\ for\ ([^ ]+)\ from\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
    local method="${BASH_REMATCH[1]}" user="${BASH_REMATCH[2]}" ip="${BASH_REMATCH[3]}"
    [[ "${SSH_ALERT_ON_SUCCESS:-yes}" == "yes" ]] || return 0
    local sev="info" note="Login SSH bem-sucedido"
    # Root ou IP fora do baseline → eleva severidade.
    if [[ "$user" == "root" ]]; then sev="high"; note="Login SSH de ROOT"; fi
    if ! _ip_known "$ip"; then
      [[ "$sev" == "info" ]] && sev="high"
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

  # ── Falha de auth SSH → agregação de brute force ─────────────────────────
  if [[ "$line" =~ (Failed\ password|Invalid\ user|authentication\ failure) ]]; then
    local ip=""
    if [[ "$line" =~ from\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
      ip="${BASH_REMATCH[1]}"
    fi
    [[ -z "$ip" ]] && return 0
    _register_failed_auth "$ip"
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

  # ── Falha de autenticação no sudo ─────────────────────────────────────────
  if [[ "$line" =~ sudo:.*authentication\ failure ]]; then
    local suser=""
    [[ "$line" =~ user=([^ ]+) ]] && suser="${BASH_REMATCH[1]}"
    local details; details="$(jq -n --arg u "$suser" '{user:$u}')"
    alert_send "sudo_auth_failure" "medium" "$details" \
      "Falha de autenticação no sudo" "sudo_fail:$suser"
    log_file "sudo_auth_failure user=$suser" "$VPS_SEC_LOG_DIR/monitor.log"
    return 0
  fi
}

# Registra falha e dispara alerta agregado ao cruzar o threshold na janela.
_register_failed_auth() {
  local ip="$1" now; now="$(epoch)"
  local win="${FAIL_BURST_WINDOW:-60}" thr="${FAIL_BURST_THRESHOLD:-10}"

  local start="${_burst_start[$ip]:-0}"
  if (( now - start > win )); then
    # Nova janela.
    _burst_start[$ip]="$now"
    _burst_count[$ip]=1
    _burst_alerted[$ip]=0
  else
    _burst_count[$ip]=$(( ${_burst_count[$ip]:-0} + 1 ))
  fi

  if (( ${_burst_count[$ip]} >= thr )) && (( ${_burst_alerted[$ip]:-0} == 0 )); then
    _burst_alerted[$ip]=1
    local details
    details="$(jq -n --arg ip "$ip" --argjson c "${_burst_count[$ip]}" \
      --argjson w "$win" \
      '{ip:$ip, failed_attempts:$c, window_seconds:$w}')"
    alert_send "ssh_auth_burst" "high" "$details" \
      "Possível brute force. Confirme fail2ban ativo e considere bloquear o IP" \
      "burst:$ip"
    log_file "ssh_auth_burst ip=$ip count=${_burst_count[$ip]}" \
      "$VPS_SEC_LOG_DIR/monitor.log"
  fi
}

# IP já apareceu em logins bem-sucedidos anteriores (baseline)?
_ip_known() {
  local ip="$1" f="$VPS_SEC_STATE/baseline/ips.txt"
  [[ -f "$f" ]] || return 1
  grep -qxF "$ip" "$f"
}
