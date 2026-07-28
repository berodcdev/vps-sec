#!/usr/bin/env bash
# tests/run.sh — roda todas as suítes num container ubuntu:24.04.
#
# As suítes precisam de bash 5 (arrays associativos, `read -t`) e de utilitários
# GNU (date -d, sort -t, awk). O bash 3.2 do macOS NÃO serve — por isso o
# container é o alvo, não uma conveniência.
#
#   ./tests/run.sh              # tudo: shellcheck + suítes + audit end-to-end
#   ./tests/run.sh 30           # só as suítes cujo nome começa com "30"
#   VPS_SEC_TEST_IMAGE=ubuntu:22.04 ./tests/run.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${VPS_SEC_TEST_IMAGE:-ubuntu:24.04}"
FILTER="${1:-}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

# ── shellcheck roda no host (não precisa de container) ──────────────────────
if command -v shellcheck >/dev/null 2>&1; then
  bold "── shellcheck ──"
  ok_sc=1
  # Código de produção: as exclusões do projeto (ruído do source dinâmico e de
  # variáveis compartilhadas entre arquivos).
  shellcheck -x -e SC1090,SC1091,SC2034,SC2155 \
    "$REPO"/bin/vps-sec "$REPO"/install.sh "$REPO"/uninstall.sh \
    "$REPO"/lib/*.sh "$REPO"/modules/*/*.sh || ok_sc=0
  # Suítes: além dessas, ignora o que é inerente a um harness — mocks que
  # "nunca são invocados" (substituem funções reais e são chamados
  # indiretamente) e o A && B || C dos assertivos.
  shellcheck -x -e SC1090,SC1091,SC2034,SC2155,SC2015,SC2059,SC2120,SC2317,SC2329 \
    "$REPO"/tests/*.sh || ok_sc=0
  if [[ $ok_sc -eq 1 ]]; then green "shellcheck OK"; else red "shellcheck FALHOU"; exit 1; fi
else
  echo "(shellcheck não instalado no host — pulando)"
fi

command -v docker >/dev/null 2>&1 || { red "docker é necessário para as suítes"; exit 1; }
docker info >/dev/null 2>&1 || { red "o daemon do Docker não responde"; exit 1; }

bold "── suítes em $IMAGE ──"
docker run --rm -v "$REPO":/src:ro -e "FILTER=$FILTER" "$IMAGE" bash -c '
  set -uo pipefail
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq jq iproute2 tzdata >/dev/null 2>&1
  cp -r /src /work && export SRC=/work
  rc=0
  for t in /work/tests/[0-9]*.sh; do
    name="$(basename "$t")"
    [[ -n "${FILTER:-}" && "$name" != "$FILTER"* ]] && continue
    export TESTROOT="/tmp/$name"; mkdir -p "$TESTROOT"
    printf "\n\033[1m▸ %s\033[0m\n" "$name"
    if bash "$t"; then :; else rc=1; fi
  done

  exit $rc'
rc=$?

echo
if [[ $rc -eq 0 ]]; then green "TUDO PASSOU"; else red "HOUVE FALHAS"; fi
exit $rc
