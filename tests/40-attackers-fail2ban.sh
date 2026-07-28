#!/usr/bin/env bash
# Suíte: period_local, histórico de atacantes, correlação com fail2ban.
set -uo pipefail
# VPS_SEC_TEST_HEADER — rodar via tests/run.sh (que provê SRC e TESTROOT).
: "${SRC:?defina SRC=<raiz do repo> ou rode via tests/run.sh}"
: "${TESTROOT:?defina TESTROOT=<dir temporário> ou rode via tests/run.sh}"
export VPS_SEC_PREFIX="$SRC"
export VPS_SEC_STATE="${TESTROOT:?}/state" VPS_SEC_LOG_DIR="${TESTROOT}/log"
mkdir -p "$VPS_SEC_STATE/baseline" "$VPS_SEC_STATE/dedup" "$VPS_SEC_LOG_DIR"
. "$SRC/lib/common.sh"; config_defaults
SSH_SYSLOG_IDS=("sshd")
. "$SRC/lib/alert.sh"; . "$SRC/lib/baseline.sh"; . "$SRC/lib/attackers.sh"
. "$SRC/modules/monitor/journal-watch.sh"

fail=0
chk(){ [[ "$2" == "$3" ]] && echo "  ok  $1" || { echo "  FAIL $1: esperado '$3', obtido '$2'"; fail=1; }; }

FAKE_NOW=1785000000
epoch(){ printf '%s' "$FAKE_NOW"; }
SENT=""
LAST_DETAILS=""
alert_send(){ SENT+="send|$1|$2|$4"$'\n'; LAST_DETAILS="$3"; }
_alert_emit(){ SENT+="emit|$1|$2|$4"$'\n'; LAST_DETAILS="$3"; }
field(){ printf '%s' "$SENT" | awk -F'|' -v n="$1" 'NR==1{print $n}'; }
det(){ printf '%s' "$LAST_DETAILS" | jq -r "$1"; }

echo "== fmt_local / fmt_period (America/Sao_Paulo = UTC-3) =="
# 2026-07-28T20:32:28Z  →  17:32 em Brasília
chk "fmt_local"            "$(fmt_local 1785270748)" "28/07/2026 17:32"
chk "formato customizado"  "$(fmt_local 1785270748 %d/%m/%Y)" "28/07/2026"
chk "mesmo dia: hora só no fim" \
  "$(fmt_period 1785270748 1785274362)" "28/07/2026 17:32 → 18:32 (Brasília)"
# cruzando a meia-noite: 2026-07-29T02:30Z = 23:30 do dia 28 em Brasília
chk "cruza meia-noite repete a data" \
  "$(fmt_period 1785292140 1785299340)" "28/07/2026 23:29 → 29/07/2026 01:29 (Brasília)"
chk "timezone configurável" \
  "$(REPORT_TIMEZONE=UTC REPORT_TZ_LABEL=UTC fmt_local 1785270748)" "28/07/2026 20:32"
chk "epoch inválido → vazio" "$(fmt_local 'abc')" ""

echo "== histórico de atacantes =="
rm -f "$VPS_SEC_STATE/attackers.tsv"
attackers_record "1.2.3.4" 10 1785000000 0
attackers_record "5.6.7.8" 30 1785000100 1
attackers_record "1.2.3.4" 15 1785005000 1     # reincidente: soma e move o last_seen
chk "2 IPs no histórico" "$(attackers_count)" "2"
chk "total somado"    "$(attackers_top_json 10 | jq -r '.[]|select(.ip=="1.2.3.4")|.failed_attempts')" "25"
chk "first_seen preservado" "$(attackers_top_json 10 | jq -r '.[]|select(.ip=="1.2.3.4")|.first_seen')" "1785000000"
chk "last_seen atualizado"  "$(attackers_top_json 10 | jq -r '.[]|select(.ip=="1.2.3.4")|.last_seen')" "1785005000"
chk "bans acumulados"       "$(attackers_top_json 10 | jq -r '.[]|select(.ip=="1.2.3.4")|.times_banned')" "1"
chk "ordenado por tentativas" "$(attackers_top_json 10 | jq -r '.[0].ip')" "5.6.7.8"
attackers_mark_banned "1.2.3.4"
chk "mark_banned incrementa" "$(attackers_top_json 10 | jq -r '.[]|select(.ip=="1.2.3.4")|.times_banned')" "2"
chk "--top limita" "$(attackers_top_json 1 | jq 'length')" "1"

echo "== poda por retenção =="
ATTACKERS_RETENTION_DAYS=1; FAKE_NOW=$((1785005000 + 172800))   # +2 dias
attackers_prune
chk "tudo além da retenção sai" "$(attackers_count)" "0"
ATTACKERS_RETENTION_DAYS=365; FAKE_NOW=1785000000

echo "== relatório em texto não quebra =="
attackers_record "9.9.9.9" 42 1785270748 3
out="$(attackers_main 2>&1)"
chk "mostra o IP"        "$(grep -c '9.9.9.9' <<<"$out")" "1"
chk "mostra tentativas"  "$(grep -c '42' <<<"$out")" "1"
chk "data legível"       "$(grep -c '28/07/2026' <<<"$out")" "1"
chk "json é válido"      "$(attackers_main --json | jq -r '.[0].ip')" "9.9.9.9"

echo "== correlação com fail2ban no burst =="
rm -f "$VPS_SEC_STATE/attackers.tsv" "$VPS_SEC_STATE/burst-history.txt"
# (a) sem fail2ban no host
f2b_state(){ echo absent; }; f2b_banned_ips(){ printf ''; }
SENT=""; _burst_emit window 1785270748 1785274362 18 $'89.252.135.113 18\n'
chk "severidade sobe sem fail2ban" "$(field 3)" "critical"
chk "status no payload"            "$(det .fail2ban.status)" "absent"
chk "ação afirma, não pergunta"    "$(printf '%s' "$SENT" | grep -c 'não há fail2ban')" "1"
chk "period_local presente"        "$(det .period_local)" "28/07/2026 17:32 → 18:32 (Brasília)"
chk "ISO preservado"               "$(det .period_start)" "2026-07-28T20:32:28Z"
chk "atacante foi para o histórico" "$(attackers_top_json 5 | jq -r '.[0].ip')" "89.252.135.113"
chk "com as tentativas"             "$(attackers_top_json 5 | jq -r '.[0].failed_attempts')" "18"

# (b) fail2ban ativo e banindo o IP da janela
rm -f "$VPS_SEC_STATE/attackers.tsv"
f2b_state(){ echo active; }; f2b_banned_ips(){ printf '89.252.135.113\n203.0.113.1\n'; }
SENT=""; _burst_emit window 1785270748 1785274362 18 $'89.252.135.113 18\n'
chk "severidade normal com fail2ban" "$(field 3)" "high"
chk "banidos agora"                  "$(det .fail2ban.currently_banned)" "2"
chk "banidos desta janela"           "$(det .fail2ban.banned_from_this_window)" "1"
chk "ação informa que está ativo"    "$(printf '%s' "$SENT" | grep -c 'está ativo e bloqueando')" "1"
chk "ban registrado no histórico"    "$(attackers_top_json 5 | jq -r '.[0].times_banned')" "1"

# (c) jail caída é tão grave quanto não ter
f2b_state(){ echo active-nojail; }; f2b_banned_ips(){ printf ''; }
SENT=""; _burst_emit window 1785270748 1785274362 18 $'1.1.1.1 18\n'
chk "jail caída → critical" "$(field 3)" "critical"
chk "explica a jail"        "$(printf '%s' "$SENT" | grep -c 'jail sshd NÃO está ativa')" "1"

echo; [[ $fail -eq 0 ]] && echo "TODOS OS TESTES PASSARAM" || echo "HOUVE FALHAS"; exit $fail
