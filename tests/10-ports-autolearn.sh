#!/usr/bin/env bash
set -uo pipefail
# VPS_SEC_TEST_HEADER — rodar via tests/run.sh (que provê SRC e TESTROOT).
: "${SRC:?defina SRC=<raiz do repo> ou rode via tests/run.sh}"
: "${TESTROOT:?defina TESTROOT=<dir temporário> ou rode via tests/run.sh}"
: "${SRC:=/opt/vps-sec}"
export VPS_SEC_PREFIX="$SRC"
export VPS_SEC_STATE="${TESTROOT:?}/state" VPS_SEC_LOG_DIR="${TESTROOT}/log"
mkdir -p "$VPS_SEC_STATE/baseline" "$VPS_SEC_STATE/dedup" "$VPS_SEC_LOG_DIR"
. "$SRC/lib/common.sh"
config_defaults
. "$SRC/lib/alert.sh"
. "$SRC/lib/baseline.sh"

fail=0
chk() { if [[ "$2" == "$3" ]]; then echo "  ok  $1"; else echo "  FAIL $1: esperado '$3', obtido '$2'"; fail=1; fi; }

echo "== port_normalize =="
chk "dual-stack v4" "$(port_normalize tcp 0.0.0.0:8080)" "tcp *:8080"
chk "dual-stack v6" "$(port_normalize tcp '[::]:8080')"  "tcp *:8080"
chk "udp any v4"    "$(port_normalize udp 0.0.0.0:41641)" "udp *:41641"
chk "udp any v6"    "$(port_normalize udp '[::]:41641')"  "udp *:41641"
chk "loopback v4"   "$(port_normalize tcp 127.0.0.1:6379)" "tcp localhost:6379"
chk "loopback v6"   "$(port_normalize tcp '[::1]:6379')"   "tcp localhost:6379"
chk "loopback .53"  "$(port_normalize udp 127.0.0.53:53)"  "udp localhost:53"
chk "tailscale"     "$(port_normalize tcp 100.95.141.39:58354)" "tcp 100.95.141.39:58354"
chk "v4-mapped"     "$(port_normalize tcp '[::ffff:10.0.0.5]:443')" "tcp 10.0.0.5:443"
chk "star"          "$(port_normalize udp '*:111')" "udp *:111"
chk "link-local"    "$(port_normalize udp '[fe80::1%eth0]:546')" "udp fe80::1%eth0:546"

echo "== port_scope / severidade =="
for pair in "*|public|high" "localhost|loopback|info" \
            "100.95.141.39|private|medium" "100.64.0.1|private|medium" \
            "100.127.255.254|private|medium" "100.128.0.1|public|high" \
            "100.63.255.1|public|high" "172.17.0.1|private|medium" \
            "172.32.0.1|public|high" "10.0.0.5|private|medium" \
            "192.168.1.10|private|medium" "203.0.113.7|public|high" \
            "fd00::1|private|medium" "fe80::1%eth0|private|medium"; do
  addr="${pair%%|*}"; rest="${pair#*|}"; exp_scope="${rest%%|*}"; exp_sev="${rest##*|}"
  s="$(port_scope "$addr")"
  chk "scope $addr" "$s" "$exp_scope"
  chk "sev   $addr" "$(port_scope_severity "$s")" "$exp_sev"
done

echo "== auto-learn de portas (o bug do spam) =="
. "$VPS_SEC_MODULES/monitor/state-scan.sh"
SENT=""
alert_send() { SENT+="$1|$2|$5"$'\n'; }
BL="$VPS_SEC_STATE/baseline/ports.txt"
PEND="$VPS_SEC_STATE/ports-pending.txt"
reset_ports(){ printf 'tcp *:22\n' >"$BL"; rm -f "$PEND" "$VPS_SEC_STATE"/dedup/*; }

# Baseline conhecido, e o "ss" passa a ver 3 portas novas do tailscale/docker.
reset_ports
baseline_collect_ports() { printf 'tcp *:22\nudp *:41641\ntcp 100.95.141.39:58354\ntcp *:8080\n'; }

SENT=""; _scan_ports
chk "1a varredura: nada ainda (confirmacao pendente)" "$(printf '%s' "$SENT" | grep -c .)" "0"
SENT=""; _scan_ports
echo "--- 2a varredura (confirmadas: 3 alertas, 1 por porta apesar do dual-stack) ---"
printf '%s' "$SENT" | sed 's/^/    /'
chk "confirmadas alertam" "$(printf '%s' "$SENT" | grep -c .)" "3"
chk "severidade tailscale" "$(printf '%s' "$SENT" | awk -F'|' '/58354/{print $2}')" "medium"
chk "severidade 8080"      "$(printf '%s' "$SENT" | awk -F'|' '/:8080/{print $2}')" "high"

SENT=""; _scan_ports; _scan_ports; _scan_ports
chk "rodadas seguintes = SILENCIO" "$(printf '%s' "$SENT" | grep -c .)" "0"
chk "baseline absorveu" "$(sort "$BL" | tr '\n' ',')" "tcp *:22,tcp *:8080,tcp 100.95.141.39:58354,udp *:41641,"

echo "== socket UDP efemero NAO gera alerta (o caso do udp *:54819) =="
reset_ports
# Cada varredura ve um socket UDP de saida diferente, que some na seguinte.
SENT=""
for p in 54819 41022 60333 33871 58120; do
  baseline_collect_ports() { printf 'tcp *:22\nudp *:%s\n' "$1"; }
  baseline_collect_ports() { printf 'tcp *:22\nudp *:'"$p"'\n'; }
  _scan_ports
done
chk "5 sockets efemeros = 0 alertas" "$(printf '%s' "$SENT" | grep -c .)" "0"
chk "baseline nao acumulou lixo" "$(sort "$BL" | tr '\n' ',')" "tcp *:22,"

echo "== listener real no meio do ruido efemero ainda e detectado =="
reset_ports
SENT=""
baseline_collect_ports() { printf 'tcp *:22\nudp *:11111\ntcp *:9000\n'; }; _scan_ports
baseline_collect_ports() { printf 'tcp *:22\nudp *:22222\ntcp *:9000\n'; }; _scan_ports
chk "so a porta persistente alerta" "$(printf '%s' "$SENT" | grep -c .)" "1"
chk "e a certa" "$(printf '%s' "$SENT" | awk -F'|' '{print $3}')" "port:tcp *:9000"
chk "efemeras fora do baseline" "$(sort "$BL" | tr '\n' ',')" "tcp *:22,tcp *:9000,"

echo "== auto-learn OFF mantém o comportamento antigo =="
reset_ports
baseline_collect_ports() { printf 'tcp *:22\nudp *:41641\ntcp 100.95.141.39:58354\ntcp *:8080\n'; }
MONITOR_AUTOLEARN=no; SENT=""; _scan_ports; _scan_ports
chk "off: alerta ao confirmar" "$(printf '%s' "$SENT" | grep -c .)" "3"
chk "off: baseline intacto" "$(cat "$BL")" "tcp *:22"
MONITOR_AUTOLEARN=yes

echo "== guard: ss vazio não zera o baseline =="
printf 'tcp *:22\ntcp *:8080\n' >"$BL"; rm -f "$PEND"
baseline_collect_ports() { printf ''; }
SENT=""; _scan_ports
chk "vazio: sem alerta" "$(printf '%s' "$SENT" | grep -c .)" "0"
chk "vazio: baseline intacto" "$(cat "$BL" | tr '\n' ',')" "tcp *:22,tcp *:8080,"

echo "== conversão de formato do baseline (self-update) =="
printf 'tcp 0.0.0.0:22\ntcp [::]:22\ntcp 127.0.0.1:6379\n' >"$BL"
rm -f "$VPS_SEC_STATE/baseline/.ports-format"
baseline_ensure_ports_format
chk "convertido+dedup" "$(cat "$BL" | tr '\n' ',')" "tcp *:22,tcp localhost:6379,"
chk "carimbo" "$(cat "$VPS_SEC_STATE/baseline/.ports-format")" "2"
# Idempotente: segunda chamada não mexe.
baseline_ensure_ports_format
chk "conversão idempotente" "$(cat "$BL" | tr '\n' ',')" "tcp *:22,tcp localhost:6379,"

echo "== integridade: dedup por hash, 1 alerta por alteração =="
IBL="$VPS_SEC_STATE/baseline/integrity.sha256"
printf 'aaa  /etc/ssh/sshd_config\n' >"$IBL"
baseline_collect_integrity() { printf '%s  /etc/ssh/sshd_config\n' "$H"; }
H=bbb; SENT=""; _scan_integrity; _scan_integrity; _scan_integrity
chk "1 alerta na 1ª alteração" "$(printf '%s' "$SENT" | grep -c .)" "1"
chk "chave inclui o hash" "$(printf '%s' "$SENT" | awk -F'|' '{print $3}')" "integrity:/etc/ssh/sshd_config:bbb"
H=ccc; SENT=""; _scan_integrity
chk "nova alteração realerta" "$(printf '%s' "$SENT" | grep -c .)" "1"

echo
[[ $fail -eq 0 ]] && echo "TODOS OS TESTES PASSARAM" || echo "HOUVE FALHAS"
exit $fail
