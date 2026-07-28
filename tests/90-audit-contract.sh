#!/usr/bin/env bash
# Contratos do audit que já quebraram no passado. Roda o audit de verdade.
set -uo pipefail
# VPS_SEC_TEST_HEADER — rodar via tests/run.sh (que provê SRC e TESTROOT).
: "${SRC:?defina SRC=<raiz do repo> ou rode via tests/run.sh}"
: "${TESTROOT:?defina TESTROOT=<dir temporário> ou rode via tests/run.sh}"

fail=0
chk(){ [[ "$2" == "$3" ]] && echo "  ok  $1" || { echo "  FAIL $1: esperado '$3', obtido '$2'"; fail=1; }; }

export VPS_SEC_PREFIX="$SRC"
export VPS_SEC_STATE="$TESTROOT/state" VPS_SEC_LOG_DIR="$TESTROOT/log"
mkdir -p "$VPS_SEC_STATE" "$VPS_SEC_LOG_DIR"

echo "== o audit produz relatório e score =="
# REGRESSÃO HISTÓRICA: `((VAR++))` retorna 1 quando VAR é 0 e, sob `set -e`,
# matava o script sem imprimir nada — o audit saía mudo.
txt="$("$SRC/bin/vps-sec" audit 2>&1)"; code=$?
chk "imprime a tabela"   "$(grep -c '── Resumo ──' <<<"$txt")" "1"
chk "imprime o score"    "$(grep -cE 'Score: [0-9]+/100' <<<"$txt")" "1"
chk "exit 2 com crítico" "$code" "2"

json="$("$SRC/bin/vps-sec" audit --json --quiet 2>/dev/null)"
chk "JSON é válido" "$(jq -e 'has("findings")' <<<"$json" 2>/dev/null)" "true"
chk "score é número" "$(jq -r '.score|type' <<<"$json")" "number"

echo "== findings advisory não sugerem harden inexistente =="
# App-stack e backup moram em compose/stacks fora do controle da ferramenta.
# Se carregarem fix_id, o relatório imprime "corrigir: vps-sec harden --only X"
# para um X que não existe em _fix_table — instrução que não faz nada.
advisory_re='^(RDS|PG|TRF|N8N|PTR|BKP)-'
bad="$(jq -r --arg re "$advisory_re" \
  '[.findings[] | select(.id | test($re)) | select(.fix_id != null) | .id] | join(",")' \
  <<<"$json" 2>/dev/null)"
chk "nenhum advisory com fix_id" "$bad" ""

echo "== todo fix_id emitido existe mesmo na tabela do harden =="
# Um fix_id órfão manda o usuário rodar um comando que não corrige nada.
known="$(sed -n 's/^\([A-Z0-9-]*\)|.*/\1/p' "$SRC/modules/harden/fixes.sh" | sort -u)"
orphans=""
while IFS= read -r fid; do
  [[ -z "$fid" || "$fid" == "null" ]] && continue
  grep -qxF "$fid" <<<"$known" || orphans+="$fid "
done < <(jq -r '.findings[].fix_id // empty' <<<"$json" | sort -u)
chk "nenhum fix_id órfão" "${orphans% }" ""

echo "== IDs de finding são únicos =="
dupes="$(jq -r '.findings[].id' <<<"$json" | sort | uniq -d | tr '\n' ' ')"
chk "sem IDs duplicados" "${dupes% }" ""

echo "== o audit interno do harden não tem efeito colateral =="
# harden roda audit para descobrir o que corrigir; isso não pode consumir o
# snapshot de IDs nem disparar alertas.
rm -f "$VPS_SEC_STATE/audit-prev-ids.txt"
VPS_SEC_AUDIT_NO_ALERT=1 "$SRC/bin/vps-sec" audit --json --quiet >/dev/null 2>&1
chk "snapshot não foi escrito" \
  "$([[ -f "$VPS_SEC_STATE/audit-prev-ids.txt" ]] && echo sim || echo nao)" "nao"
# Sem a flag, o snapshot é gravado mesmo sem WEBHOOK_URL (senão, ao configurar
# o webhook depois, todos os findings antigos chegariam como novos de uma vez).
WEBHOOK_URL="" "$SRC/bin/vps-sec" audit --json --quiet >/dev/null 2>&1
chk "snapshot gravado mesmo sem webhook" \
  "$([[ -f "$VPS_SEC_STATE/audit-prev-ids.txt" ]] && echo sim || echo nao)" "sim"

echo; [[ $fail -eq 0 ]] && echo "TODOS OS TESTES PASSARAM" || echo "HOUVE FALHAS"; exit $fail
