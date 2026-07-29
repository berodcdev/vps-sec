#!/usr/bin/env bash
# Suíte: o audit de filesystem olha o HOST, não o interior das imagens.
set -uo pipefail
# VPS_SEC_TEST_HEADER — rodar via tests/run.sh (que provê SRC e TESTROOT).
: "${SRC:?defina SRC=<raiz do repo> ou rode via tests/run.sh}"
: "${TESTROOT:?defina TESTROOT=<dir temporário> ou rode via tests/run.sh}"

fail=0
chk(){ [[ "$2" == "$3" ]] && echo "  ok  $1" || { echo "  FAIL $1: esperado '$3', obtido '$2'"; fail=1; }; }

export VPS_SEC_PREFIX="$SRC"
export VPS_SEC_STATE="$TESTROOT/state" VPS_SEC_LOG_DIR="$TESTROOT/log"
mkdir -p "$VPS_SEC_STATE" "$VPS_SEC_LOG_DIR"

# Camadas de imagem: exatamente o que poluía o relatório num host com Docker.
LAYER=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/111/fs
mkdir -p "$LAYER/tmp" "$LAYER/usr/bin"
touch "$LAYER/tmp/uv-setuptools-deadbeef.lock"; chmod 0666 "$LAYER/tmp/uv-setuptools-deadbeef.lock"
touch "$LAYER/usr/bin/passwd"; chmod 4755 "$LAYER/usr/bin/passwd"
mkdir -p /snap/core/1/usr/bin
touch /snap/core/1/usr/bin/snap-confine; chmod 4755 /snap/core/1/usr/bin/snap-confine

# E um problema DE VERDADE no host, que precisa continuar sendo visto.
mkdir -p /etc/vps-sec-test
touch /etc/vps-sec-test/mundo-escreve.conf; chmod 0666 /etc/vps-sec-test/mundo-escreve.conf
cp /bin/true /usr/local/bin/backdoor-suid 2>/dev/null; chmod 4755 /usr/local/bin/backdoor-suid

. "$SRC/lib/common.sh"; config_defaults
. "$SRC/lib/report.sh"
report_init
. "$SRC/modules/audit/70-filesystem.sh"
audit_filesystem

f="$REPORT_FINDINGS_FILE"
detail_of(){ awk -F'\t' -v id="$1" '$1==id {print $5}' "$f"; }
status_of(){ awk -F'\t' -v id="$1" '$1==id {print $3}' "$f"; }

echo "== FS-001: world-writable =="
chk "reporta o arquivo real do host" \
  "$(detail_of FS-001 | grep -c '/etc/vps-sec-test/mundo-escreve.conf')" "1"
chk "IGNORA camada de container" \
  "$(detail_of FS-001 | grep -c 'io.containerd')" "0"
chk "status FAIL"  "$(status_of FS-001)" "FAIL"

echo "== FS-002: SUID =="
chk "reporta o SUID plantado no host" \
  "$(detail_of FS-002 | grep -c '/usr/local/bin/backdoor-suid')" "1"
chk "IGNORA SUID dentro de imagem" \
  "$(detail_of FS-002 | grep -c 'io.containerd')" "0"
chk "IGNORA SUID de snap" \
  "$(detail_of FS-002 | grep -c '/snap/')" "0"
chk "não acusa polkit do 24.04 (está na whitelist)" \
  "$(detail_of FS-002 | grep -c 'polkit-agent-helper-1')" "0"

echo "== contagem não mente =="
# O `head -20` antigo truncava a LISTA e a CONTAGEM juntas: "20 arquivos"
# podia significar 400. Hoje a contagem é do total real.
for i in $(seq 1 25); do
  touch "/etc/vps-sec-test/ww-$i.conf"; chmod 0666 "/etc/vps-sec-test/ww-$i.conf"
done
report_init; audit_filesystem; f="$REPORT_FINDINGS_FILE"
title_of(){ awk -F'\t' -v id="$1" '$1==id {print $4}' "$f"; }
n="$(title_of FS-001 | grep -oE '^[0-9]+')"
chk "conta mais de 20"        "$([[ "${n:-0}" -gt 20 ]] && echo sim || echo nao)" "sim"
chk "avisa que truncou a lista" "$(detail_of FS-001 | grep -c 'mostrando 20 de')" "1"

rm -rf /etc/vps-sec-test /usr/local/bin/backdoor-suid
echo; [[ $fail -eq 0 ]] && echo "TODOS OS TESTES PASSARAM" || echo "HOUVE FALHAS"; exit $fail
