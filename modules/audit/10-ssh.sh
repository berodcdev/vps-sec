#!/usr/bin/env bash
# modules/audit/10-ssh.sh — checks de configuração do SSH.
# Usa `sshd -T` (config efetiva) em vez de fazer parse manual do arquivo.

audit_ssh() {
  local cfg
  if ! cfg="$(sshd -T 2>/dev/null)"; then
    # sshd -T pode falhar se não houver Match/host keys; tenta com -C.
    cfg="$(sshd -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null || true)"
  fi
  if [[ -z "$cfg" ]]; then
    report_skip "SSH-000" "SSH não avaliável (sshd -T falhou ou sshd ausente)"
    return 0
  fi

  # Helper: valor efetivo de uma diretiva (lowercase key).
  _sshv() { awk -v k="$1" 'tolower($1)==k {print tolower($2); exit}' <<<"$cfg"; }

  # SSH-001: PermitRootLogin
  local prl; prl="$(_sshv permitrootlogin)"
  if [[ "$prl" == "yes" ]]; then
    report_fail "SSH-001" "critical" "Login de root por SSH habilitado" \
      "PermitRootLogin=$prl — root deve ser 'no' ou 'prohibit-password'" "SSH-001"
  else
    report_pass "SSH-001" "critical" "PermitRootLogin restrito ($prl)"
  fi

  # SSH-005: PermitEmptyPasswords
  local pep; pep="$(_sshv permitemptypasswords)"
  if [[ "$pep" == "yes" ]]; then
    report_fail "SSH-005" "high" "SSH permite senhas vazias" \
      "PermitEmptyPasswords=yes" "SSH-005"
  else
    report_pass "SSH-005" "high" "Senhas vazias bloqueadas no SSH"
  fi

  # SSH-003: PasswordAuthentication
  local pa; pa="$(_sshv passwordauthentication)"
  if [[ "$pa" == "yes" ]]; then
    report_fail "SSH-003" "high" "Autenticação por senha habilitada no SSH" \
      "PasswordAuthentication=yes — prefira apenas chaves públicas" "SSH-003"
  else
    report_pass "SSH-003" "high" "Autenticação por senha desabilitada"
  fi

  # SSH-004: porta default 22 (informativo)
  local port; port="$(_sshv port)"
  if [[ "$port" == "22" ]]; then
    report_warn "SSH-004" "low" "SSH na porta padrão 22" \
      "Mudar a porta reduz ruído de scanners (opcional)" "SSH-004"
  else
    report_pass "SSH-004" "low" "SSH em porta não-padrão ($port)"
  fi

  # SSH-006: MaxAuthTries / LoginGraceTime
  local mat; mat="$(_sshv maxauthtries)"
  if [[ -n "$mat" && "$mat" -gt 4 ]] 2>/dev/null; then
    report_fail "SSH-006" "medium" "MaxAuthTries alto ($mat)" \
      "Recomendado <= 3 para dificultar brute force" "SSH-006"
  else
    report_pass "SSH-006" "medium" "MaxAuthTries adequado ($mat)"
  fi

  # SSH-007: X11Forwarding
  local x11; x11="$(_sshv x11forwarding)"
  if [[ "$x11" == "yes" ]]; then
    report_warn "SSH-007" "low" "X11Forwarding habilitado" \
      "Raramente necessário em servidor" "SSH-007"
  else
    report_pass "SSH-007" "low" "X11Forwarding desabilitado"
  fi

  # SSH-008: AllowUsers/AllowGroups (sem lista = qualquer usuário válido pode logar)
  if grep -qiE '^(allowusers|allowgroups)' <<<"$cfg"; then
    report_pass "SSH-008" "low" "Acesso SSH restrito por AllowUsers/AllowGroups"
  else
    report_warn "SSH-008" "low" "Sem AllowUsers/AllowGroups" \
      "Qualquer conta com shell pode tentar logar via SSH"
  fi

  # SSH-009: permissões dos authorized_keys de todos os usuários com home
  local bad_keys=""
  local home user
  while IFS=: read -r user _ uid _ _ home _; do
    [[ "$uid" -ge 1000 || "$user" == "root" ]] || continue
    local ak="$home/.ssh/authorized_keys"
    [[ -f "$ak" ]] || continue
    local p; p="$(stat -c '%a' "$ak" 2>/dev/null)"
    # Deve ser <= 600 (sem bits de grupo/other).
    if [[ "${p: -1}" != "0" || "${p: -2:1}" != "0" ]]; then
      bad_keys+="$ak($p) "
    fi
  done </etc/passwd
  if [[ -n "$bad_keys" ]]; then
    report_fail "SSH-009" "high" "authorized_keys com permissão insegura" \
      "Arquivos legíveis/graváveis por outros: $bad_keys" "SSH-009"
  else
    report_pass "SSH-009" "high" "Permissões de authorized_keys corretas"
  fi
}
