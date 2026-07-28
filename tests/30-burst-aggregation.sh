#!/usr/bin/env bash
# Suíte do journal-watch: agregação de brute force, replay de backlog e
# login-após-burst. Precisa de bash 5 (arrays associativos).
set -uo pipefail
# VPS_SEC_TEST_HEADER — rodar via tests/run.sh (que provê SRC e TESTROOT).
: "${SRC:?defina SRC=<raiz do repo> ou rode via tests/run.sh}"
: "${TESTROOT:?defina TESTROOT=<dir temporário> ou rode via tests/run.sh}"
export VPS_SEC_PREFIX="$SRC"
export VPS_SEC_STATE="${TESTROOT:?}/state" VPS_SEC_LOG_DIR="${TESTROOT}/log"
mkdir -p "$VPS_SEC_STATE/baseline" "$VPS_SEC_STATE/dedup" "$VPS_SEC_LOG_DIR"
. "$SRC/lib/common.sh"; config_defaults
SSH_SYSLOG_IDS=("sshd" "sshd-session")
. "$SRC/lib/alert.sh"; . "$SRC/lib/baseline.sh"; . "$SRC/lib/attackers.sh"
. "$SRC/modules/monitor/journal-watch.sh"
# Esta suíte isola a agregação: fail2ban saudável, para que a severidade reflita
# só o volume. A correlação com o fail2ban é coberta na t4.
f2b_state(){ echo active; }
f2b_banned_ips(){ printf ''; }

fail=0
chk(){ [[ "$2" == "$3" ]] && echo "  ok  $1" || { echo "  FAIL $1: esperado '$3', obtido '$2'"; fail=1; }; }

# Relógio controlado + captura de alertas.
FAKE_NOW=1000000000
epoch(){ printf '%s' "$FAKE_NOW"; }
SENT=""
# details vai compactado: jq -n produz JSON multilinha e inflaria a contagem.
alert_send(){ SENT+="send|$1|$2|$(printf '%s' "$3" | jq -c . 2>/dev/null)"$'\n'; }
_alert_emit(){ SENT+="emit|$1|$2|$(printf '%s' "$3" | jq -c . 2>/dev/null)"$'\n'; }
n_events(){ printf '%s' "$SENT" | grep -c . ; }
field(){ printf '%s' "$SENT" | awk -F'|' -v n="$1" 'NR==1{print $n}'; }
det(){ printf '%s' "$SENT" | awk -F'|' 'NR==1{for(i=4;i<=NF;i++)printf "%s",$i}' | jq -r "$1"; }

# Linha no formato do `journalctl -o short-unix`.
mkline(){ printf '%s.123456 host sshd[42]: %s\n' "$1" "$2"; }

echo "== _line_epoch =="
chk "extrai epoch"        "$(_line_epoch "$(mkline 1700000000 'oi')")" "1700000000"
chk "sem prefixo → agora" "$(_line_epoch 'Failed password for x from 1.2.3.4')" "$FAKE_NOW"

echo "== REPLAY: backlog não vira ataque em andamento =="
# 30 falhas de um IP + 15 de outro, todas de 3h atrás, chegando em rajada.
old=$(( FAKE_NOW - 10800 ))
SENT=""
for i in $(seq 1 30); do _handle_log_line "$(mkline $((old+i)) 'Failed password for root from 68.183.196.28 port 1 ssh2')"; done
for i in $(seq 1 15); do _handle_log_line "$(mkline $((old+i)) 'Invalid user admin from 45.9.9.9 port 1 ssh2')"; done
chk "durante o replay: SILÊNCIO" "$(n_events)" "0"
_burst_flush_backlog
chk "fim do replay: 1 alerta só" "$(n_events)" "1"
chk "tipo" "$(field 2)" "ssh_auth_burst"
chk "marcado como backlog" "$(det .source)" "backlog"
chk "total consolidado"    "$(det .failed_attempts)" "45"
chk "ips distintos"        "$(det .distinct_ips)" "2"
chk "ips sobre o threshold" "$(det .ips_over_threshold)" "2"
chk "top ip"               "$(det '.top_ips[0].ip')" "68.183.196.28"
chk "flush é idempotente"  "$(_burst_flush_backlog; n_events)" "1"

echo "== ruído abaixo do threshold não alerta =="
SENT=""
for i in 1 2 3; do _handle_log_line "$(mkline $((old+i)) 'Failed password for root from 1.1.1.1 port 1 ssh2')"; done
_burst_flush_backlog
chk "3 falhas = sem alerta" "$(n_events)" "0"

echo "== TEMPO REAL: agrega na janela, não por IP =="
SENT=""; _burst_count=(); _burst_total=0; _burst_win_start=0
for i in $(seq 1 25); do
  FAKE_NOW=$((1000000000+i)); _handle_log_line "$(mkline $FAKE_NOW 'Failed password for root from 203.0.113.9 port 1 ssh2')"
done
for i in $(seq 1 12); do
  FAKE_NOW=$((1000000030+i)); _handle_log_line "$(mkline $FAKE_NOW 'Failed password for root from 198.51.100.7 port 1 ssh2')"
done
chk "dentro da janela: SILÊNCIO" "$(n_events)" "0"
_burst_flush_window
chk "janela aberta não fecha cedo" "$(n_events)" "0"
FAKE_NOW=$((1000000000+3601))      # janela expirou
_burst_flush_window
chk "1 alerta ao fechar a janela" "$(n_events)" "1"
chk "source=window" "$(det .source)" "window"
chk "total" "$(det .failed_attempts)" "37"
chk "2 ofensores" "$(det .ips_over_threshold)" "2"

echo "== ssh_login_after_burst (crítico, sem dedup) =="
SENT=""
FAKE_NOW=1000005000
_handle_log_line "$(mkline $FAKE_NOW 'Accepted password for root from 203.0.113.9 port 2 ssh2')"
chk "1 evento" "$(n_events)" "1"
chk "emitido direto (bypassa filtro/dedup)" "$(field 1)" "emit"
chk "tipo" "$(field 2)" "ssh_login_after_burst"
chk "severidade" "$(field 3)" "critical"
chk "conta as falhas anteriores" "$(det .prior_failed_attempts)" "25"
chk "usuário" "$(det .user)" "root"

echo "== login normal segue o caminho antigo =="
SENT=""
_handle_log_line "$(mkline $FAKE_NOW 'Accepted publickey for deploy from 8.8.4.4 port 2 ssh2')"
chk "via alert_send" "$(field 1)" "send"
chk "tipo" "$(field 2)" "ssh_login_success"
chk "high (IP fora do baseline)" "$(field 3)" "high"

echo "== ofensores persistem entre restarts do monitor =="
_offenders_save
chk "arquivo gravado" "$([[ -s "$VPS_SEC_STATE/burst-offenders.tsv" ]] && echo sim)" "sim"
_burst_seen=(); _burst_hist=(); _burst_count=(); _burst_backlog=()
_offenders_load
chk "recarregou o ofensor" "$(_offender_fails 203.0.113.9)" "25"
SENT=""; _handle_log_line "$(mkline $FAKE_NOW 'Accepted password for root from 203.0.113.9 port 2 ssh2')"
chk "detecta após restart" "$(field 2)" "ssh_login_after_burst"

echo "== poda de ofensores com mais de 24h =="
FAKE_NOW=$((FAKE_NOW + 172800))
_offenders_save; _burst_seen=(); _burst_hist=(); _offenders_load
chk "ofensor antigo esquecido" "$(_offender_fails 203.0.113.9)" "0"

echo "== escalonamento por volume acima do padrão do host =="
rm -f "$VPS_SEC_STATE/burst-history.txt"
for v in 40 45 50; do printf '%s\n' "$v" >>"$VPS_SEC_STATE/burst-history.txt"; done
SENT=""; _burst_emit window 1 2 300 '9.9.9.9 300\n' 
chk "3x acima da média → critical" "$(field 3)" "critical"
SENT=""; _burst_emit window 1 2 50 '9.9.9.9 50\n' 
chk "volume normal → high" "$(field 3)" "high"

echo "== outros eventos não regrediram =="
SENT=""; _handle_log_line "$(mkline $FAKE_NOW 'new user: name=hacker, UID=1001')"
chk "new_user" "$(field 2)" "new_user"
SENT=""; _handle_log_line "$(mkline $FAKE_NOW "delete user 'antigo'")"
chk "user_deleted" "$(field 2)" "user_deleted"
SENT=""; _handle_log_line "$(mkline $FAKE_NOW 'sudo: pam_unix(sudo:auth): authentication failure; user=deploy')"
chk "sudo_auth_failure" "$(field 2)" "sudo_auth_failure"

echo; [[ $fail -eq 0 ]] && echo "TODOS OS TESTES PASSARAM" || echo "HOUVE FALHAS"; exit $fail
