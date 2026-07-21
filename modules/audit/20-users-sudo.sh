#!/usr/bin/env bash
# modules/audit/20-users-sudo.sh — contas, senhas e sudo.

audit_users_sudo() {
  # USR-001: contas com senha vazia em /etc/shadow (campo 2 vazio).
  local empty=""
  if [[ -r /etc/shadow ]]; then
    empty="$(awk -F: '($2=="") {print $1}' /etc/shadow | tr '\n' ' ')"
  fi
  if [[ -n "${empty// /}" ]]; then
    report_fail "USR-001" "critical" "Conta(s) com senha vazia" \
      "Usuários sem senha: $empty" "USR-001"
  else
    report_pass "USR-001" "critical" "Nenhuma conta com senha vazia"
  fi

  # USR-002: UID 0 além de root.
  local uid0; uid0="$(awk -F: '($3==0 && $1!="root") {print $1}' /etc/passwd | tr '\n' ' ')"
  if [[ -n "${uid0// /}" ]]; then
    report_fail "USR-002" "critical" "UID 0 duplicado" \
      "Contas com privilégio de root: $uid0" "USR-002"
  else
    report_pass "USR-002" "critical" "Apenas root possui UID 0"
  fi

  # USR-005: sintaxe do sudoers e permissões dos drop-ins.
  if has_cmd visudo; then
    if visudo -c >/dev/null 2>&1; then
      report_pass "USR-005" "medium" "sudoers com sintaxe válida"
    else
      report_fail "USR-005" "critical" "sudoers com sintaxe inválida" \
        "visudo -c falhou — sudo pode estar quebrado"
    fi
  fi
  local bad_perm=""
  local f
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    local p o; p="$(stat -c '%a' "$f" 2>/dev/null)"; o="$(stat -c '%u' "$f" 2>/dev/null)"
    if [[ "$o" != "0" || "${p: -1}" =~ [2367] || "${p: -2:1}" =~ [2367] ]]; then
      bad_perm+="$f($p) "
    fi
  done
  if [[ -n "$bad_perm" ]]; then
    report_fail "USR-005b" "medium" "Arquivo sudoers com permissão/dono inseguro" \
      "$bad_perm" "USR-005"
  fi

  # USR-004: entradas NOPASSWD:ALL (comum em cloud-init → WARN, não penaliza forte).
  local nopass=""
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    if grep -qE 'NOPASSWD:\s*ALL' "$f" 2>/dev/null; then
      nopass+="$(basename "$f") "
    fi
  done
  if [[ -n "$nopass" ]]; then
    report_warn "USR-004" "medium" "Regra sudo NOPASSWD:ALL presente" \
      "Em: $nopass — revise se é intencional (comum no usuário de cloud)" "USR-004"
  else
    report_pass "USR-004" "medium" "Sem NOPASSWD:ALL amplo"
  fi

  # USR-006: contas de sistema (UID<1000) com shell interativo.
  local sysshell=""
  while IFS=: read -r user _ uid _ _ _ shell; do
    [[ "$uid" -lt 1000 && "$uid" -ne 0 ]] || continue
    case "$shell" in
      */bash|*/sh|*/zsh|*/ksh) sysshell+="$user " ;;
    esac
  done </etc/passwd
  if [[ -n "$sysshell" ]]; then
    report_warn "USR-006" "medium" "Conta(s) de sistema com shell interativo" \
      "Considere shell nologin: $sysshell" "USR-006"
  else
    report_pass "USR-006" "medium" "Contas de sistema sem shell interativo"
  fi
}
