#!/usr/bin/env bash
# modules/audit/70-filesystem.sh — permissões, world-writable, SUID.

# Whitelist de binários SUID/SGID padrão do Ubuntu (diferenças viram WARN).
_SUID_WHITELIST='/usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/chsh /usr/bin/chfn /usr/bin/newgrp /usr/bin/gpasswd /usr/bin/mount /usr/bin/umount /usr/bin/fusermount3 /usr/bin/fusermount /usr/lib/openssh/ssh-keysign /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/policykit-1/polkit-agent-helper-1 /usr/libexec/polkit-agent-helper-1 /usr/bin/pkexec /usr/bin/crontab /usr/bin/wall /usr/bin/write /usr/bin/expiry /usr/bin/chage /usr/sbin/pppd /usr/bin/at /usr/bin/ssh-agent /usr/bin/dotlockfile /usr/bin/mail-lock /usr/bin/mail-unlock /usr/bin/mail-touchlock'

audit_filesystem() {
  # FS-003: /etc/shadow e /etc/passwd.
  local sp; sp="$(stat -c '%a' /etc/shadow 2>/dev/null)"
  if [[ -n "$sp" && "${sp: -1}" == "0" && "${sp: -2:1}" -le 4 ]]; then
    report_pass "FS-003" "high" "/etc/shadow com permissão adequada ($sp)"
  else
    report_fail "FS-003" "high" "/etc/shadow com permissão insegura ($sp)" \
      "Deveria ser 640 root:shadow ou mais restrito" "FS-003"
  fi

  # FS-001: arquivos world-writable fora de dirs temporários (com timeout).
  local ww
  ww="$(timeout 45 find / -xdev -type f -perm -0002 \
        ! -path '/tmp/*' ! -path '/var/tmp/*' ! -path '/dev/shm/*' \
        ! -path '/proc/*' ! -path '/sys/*' ! -path '/run/*' \
        ! -path '/var/lib/docker/*' 2>/dev/null | head -20)"
  if [[ -n "$ww" ]]; then
    local n; n="$(wc -l <<<"$ww" | tr -d ' ')"
    report_fail "FS-001" "high" "$n arquivo(s) graváveis por qualquer usuário" \
      "$(tr '\n' ' ' <<<"$ww")" "FS-001"
  else
    report_pass "FS-001" "high" "Sem arquivos world-writable fora de áreas temporárias"
  fi

  # FS-002: SUID/SGID fora da whitelist.
  local suid_extra=""
  local f
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    grep -qwF "$f" <<<"$_SUID_WHITELIST" || suid_extra+="$f "
  done < <(timeout 45 find / -xdev -type f -perm -4000 \
           ! -path '/proc/*' ! -path '/var/lib/docker/*' 2>/dev/null)
  if [[ -n "$suid_extra" ]]; then
    report_warn "FS-002" "medium" "Binário(s) SUID fora do padrão" \
      "Revise: $suid_extra" "FS-002"
  else
    report_pass "FS-002" "medium" "Binários SUID conforme padrão do sistema"
  fi
}
