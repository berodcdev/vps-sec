#!/usr/bin/env bash
set -uo pipefail
# VPS_SEC_TEST_HEADER — rodar via tests/run.sh (que provê SRC e TESTROOT).
: "${SRC:?defina SRC=<raiz do repo> ou rode via tests/run.sh}"
: "${TESTROOT:?defina TESTROOT=<dir temporário> ou rode via tests/run.sh}"
export VPS_SEC_PREFIX="$SRC"
export VPS_SEC_STATE="${TESTROOT:?}/state" VPS_SEC_LOG_DIR="${TESTROOT}/log"
mkdir -p "$VPS_SEC_STATE/baseline" "$VPS_SEC_STATE/dedup" "$VPS_SEC_LOG_DIR"
. "$SRC/lib/common.sh"; config_defaults
. "$SRC/lib/alert.sh"; . "$SRC/lib/baseline.sh"
. "$VPS_SEC_MODULES/monitor/state-scan.sh"
fail=0
chk(){ [[ "$2" == "$3" ]] && echo "  ok  $1" || { echo "  FAIL $1: esperado '$3', obtido '$2'"; fail=1; }; }
SENT=""; alert_send(){ SENT+="$1|$2|$5"$'\n'; }
docker_alive(){ return 0; }
CB="$VPS_SEC_STATE/baseline/containers.txt"
one_round(){ _scan_containers; _scan_container_state; _absorb_containers; }
# _scan_container_state parte (B): sem docker real, o inspect não roda — ok, testamos (A).
docker(){ return 1; }

echo "== deploy de container novo =="
printf 'prod/postgres\nprod/redis\n' >"$CB"
container_snapshot(){ printf 'prod/postgres\tpg:16\t\nprod/redis\tredis:7\t\nprod/signal-api\tbbernhard/signal-cli-rest-api:latest\t0.0.0.0:8080->8080/tcp\n'; }
container_ids(){ container_snapshot | cut -f1 | sort -u; }
SENT=""; one_round
chk "1 alerta de container novo" "$(printf '%s' "$SENT" | grep -c .)" "1"
chk "severidade alta (publica em 0.0.0.0)" "$(printf '%s' "$SENT" | awk -F'|' '{print $2}')" "high"
SENT=""; one_round; one_round; one_round
chk "rodadas seguintes = SILÊNCIO" "$(printf '%s' "$SENT" | grep -c .)" "0"
chk "baseline absorveu" "$(tr '\n' ',' <"$CB")" "prod/postgres,prod/redis,prod/signal-api,"

echo "== container caiu =="
container_snapshot(){ printf 'prod/postgres\tpg:16\t\nprod/signal-api\tx\t\n'; }
SENT=""; one_round
chk "1 alerta container_down" "$(printf '%s' "$SENT" | grep -c 'container_down')" "1"
SENT=""; one_round; one_round
chk "não repete" "$(printf '%s' "$SENT" | grep -c .)" "0"
chk "baseline removeu o caído" "$(tr '\n' ',' <"$CB")" "prod/postgres,prod/signal-api,"

echo "== guard: docker ps vazio não zera o baseline =="
container_snapshot(){ printf ''; }
SENT=""; one_round
chk "vazio: sem alerta de down" "$(printf '%s' "$SENT" | grep -c .)" "0"
chk "vazio: baseline intacto" "$(tr '\n' ',' <"$CB")" "prod/postgres,prod/signal-api,"

echo; [[ $fail -eq 0 ]] && echo "TODOS OS TESTES PASSARAM" || echo "HOUVE FALHAS"; exit $fail
