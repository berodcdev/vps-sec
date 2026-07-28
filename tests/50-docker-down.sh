#!/usr/bin/env bash
# Suíte: queda do daemon do Docker e queda total dos containers.
set -uo pipefail
# VPS_SEC_TEST_HEADER — rodar via tests/run.sh (que provê SRC e TESTROOT).
: "${SRC:?defina SRC=<raiz do repo> ou rode via tests/run.sh}"
: "${TESTROOT:?defina TESTROOT=<dir temporário> ou rode via tests/run.sh}"
export VPS_SEC_PREFIX="$SRC"
export VPS_SEC_STATE="${TESTROOT:?}/state" VPS_SEC_LOG_DIR="${TESTROOT}/log"
mkdir -p "$VPS_SEC_STATE/baseline" "$VPS_SEC_STATE/dedup" "$VPS_SEC_LOG_DIR"
. "$SRC/lib/common.sh"; config_defaults; HAS_DOCKER=1
. "$SRC/lib/alert.sh"; . "$SRC/lib/baseline.sh"; . "$SRC/lib/attackers.sh"
. "$SRC/modules/monitor/state-scan.sh"
fail=0
chk(){ [[ "$2" == "$3" ]] && echo "  ok  $1" || { echo "  FAIL $1: esperado '$3', obtido '$2'"; fail=1; }; }
SENT=""; LAST=""
alert_send(){ SENT+="$1|$2|$5"$'\n'; LAST="$3"; }
n_ev(){ printf '%s' "$SENT" | grep -c . ; }
det(){ printf '%s' "$LAST" | jq -r "$1"; }
CB="$VPS_SEC_STATE/baseline/containers.txt"
reset(){ printf 'prod/postgres\nprod/redis\nprod/n8n\n' >"$CB"
         rm -f "$VPS_SEC_STATE"/*-rounds "$VPS_SEC_STATE"/dedup/*; SENT=""; }

echo "== daemon do Docker morto =="
reset
docker_alive(){ return 1; }
_scan_docker_daemon; chk "rodada 1: silêncio"  "$(n_ev)" "0"
_scan_docker_daemon; chk "rodada 2: silêncio"  "$(n_ev)" "0"
_scan_docker_daemon; chk "rodada 3: ALERTA"    "$(n_ev)" "1"
chk "tipo"        "$(printf '%s' "$SENT" | cut -d'|' -f1 | head -1)" "docker_daemon_down"
chk "severidade"  "$(printf '%s' "$SENT" | cut -d'|' -f2 | head -1)" "critical"
chk "conta as checagens" "$(det .failed_checks)" "3"
chk "estima o tempo fora" "$(det .seconds_down)" "180"
# O dedup real vive em alert_send (cooldown 900s), que aqui está mockado; o que
# importa validar é que a CHAVE é estável, para o cooldown poder agrupar.
SENT=""; _scan_docker_daemon; _scan_docker_daemon
chk "chave de dedup estável" "$(printf '%s' "$SENT" | cut -d'|' -f3 | sort -u | tr -d '\n')" "docker_daemon_down"

echo "== daemon volta: contador zera =="
docker_alive(){ return 0; }
_scan_docker_daemon
chk "contador zerado" "$([[ -f "$VPS_SEC_STATE/docker-daemon-rounds" ]] && echo sim || echo nao)" "nao"
chk "recuperação logada" "$(grep -c docker_daemon_recovered "$VPS_SEC_LOG_DIR/monitor.log")" "1"
docker_alive(){ return 1; }; SENT=""
_scan_docker_daemon; _scan_docker_daemon
chk "nova queda recomeça a contagem" "$(n_ev)" "0"

echo "== restart normal do Docker não alarma =="
reset
docker_alive(){ return 1; }; _scan_docker_daemon
docker_alive(){ return 0; }; _scan_docker_daemon
docker_alive(){ return 1; }; _scan_docker_daemon
chk "1 rodada fora, volta, 1 fora = silêncio" "$(n_ev)" "0"

echo "== todos os containers sumiram (daemon vivo) =="
reset
docker_alive(){ return 0; }
container_snapshot(){ printf ''; }
container_ids(){ printf ''; }
docker(){ return 1; }
_scan_container_state; chk "rodada 1: silêncio" "$(n_ev)" "0"
_scan_container_state; chk "rodada 2: silêncio" "$(n_ev)" "0"
_scan_container_state; chk "rodada 3: ALERTA"   "$(n_ev)" "1"
chk "tipo"       "$(printf '%s' "$SENT" | cut -d'|' -f1 | head -1)" "containers_all_down"
chk "severidade" "$(printf '%s' "$SENT" | cut -d'|' -f2 | head -1)" "critical"
chk "1 alerta agregado, não 3" "$(n_ev)" "1"
chk "conta os serviços" "$(det .expected_services)" "3"
chk "lista os serviços"  "$(det '.services|join(",")')" "prod/n8n,prod/postgres,prod/redis"
chk "baseline preservado (volta não vira 'novos')" "$(tr '\n' ',' <"$CB")" "prod/postgres,prod/redis,prod/n8n,"

echo "== containers voltam: contador zera =="
container_snapshot(){ printf 'prod/postgres\tpg\t\nprod/redis\tredis\t\nprod/n8n\tn8n\t\n'; }
container_ids(){ container_snapshot | cut -f1 | sort -u; }
SENT=""; _scan_container_state
chk "sem alerta na volta" "$(n_ev)" "0"
chk "contador zerado" "$([[ -f "$VPS_SEC_STATE/containers-empty-rounds" ]] && echo sim || echo nao)" "nao"

echo "== queda parcial ainda alerta por serviço (não regrediu) =="
reset
container_snapshot(){ printf 'prod/postgres\tpg\t\n'; }
container_ids(){ container_snapshot | cut -f1 | sort -u; }
_scan_container_state
chk "2 container_down individuais" "$(printf '%s' "$SENT" | grep -c '^container_down|')" "2"
chk "nenhum agregado" "$(printf '%s' "$SENT" | grep -c containers_all_down)" "0"

echo; [[ $fail -eq 0 ]] && echo "TODOS OS TESTES PASSARAM" || echo "HOUVE FALHAS"; exit $fail
