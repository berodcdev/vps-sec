#!/usr/bin/env bash
# modules/audit/70-filesystem.sh — permissões, world-writable, SUID.

# Whitelist de binários SUID/SGID padrão do Ubuntu (diferenças viram WARN).
# polkit-1 é o caminho do 24.04; policykit-1 é o do 22.04 — ambos válidos.
_SUID_WHITELIST='/usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/chsh /usr/bin/chfn /usr/bin/newgrp /usr/bin/gpasswd /usr/bin/mount /usr/bin/umount /usr/bin/fusermount3 /usr/bin/fusermount /usr/lib/openssh/ssh-keysign /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/policykit-1/polkit-agent-helper-1 /usr/lib/polkit-1/polkit-agent-helper-1 /usr/libexec/polkit-agent-helper-1 /usr/bin/pkexec /usr/bin/crontab /usr/bin/wall /usr/bin/write /usr/bin/expiry /usr/bin/chage /usr/sbin/pppd /usr/bin/at /usr/bin/ssh-agent /usr/bin/dotlockfile /usr/bin/mail-lock /usr/bin/mail-unlock /usr/bin/mail-touchlock'

# Diretórios que contêm SISTEMAS DE ARQUIVOS DE OUTRAS MÁQUINAS: camadas de
# imagem, rootfs de container, snaps. Varrê-los é ruído puro — um
# `/usr/bin/passwd` SUID dentro de uma imagem Debian é normal, e um `.lock`
# world-writable no cache do pip de uma imagem não diz nada sobre o host.
#
# GOTCHA que inutilizou os dois checks: só `/var/lib/docker` era excluído, mas
# o Docker moderno guarda as camadas em `/var/lib/containerd`. Num host com
# algumas dezenas de imagens, FS-001 (que tem `head -20`) enchia com locks de
# container e um arquivo world-writable REAL do host nunca apareceria.
#
# Usa -prune (não `! -path`): -prune impede o find de DESCER na árvore, em vez
# de percorrer milhares de camadas e descartar depois — a diferença decide se o
# `timeout 45` é suficiente.
_fs_prune_args() {
  local d
  local -a out=()
  for d in /var/lib/docker /var/lib/containerd /var/lib/containers \
           /var/lib/rancher /var/lib/kubelet /var/lib/lxd /var/lib/lxc \
           /var/lib/machines /snap /var/snap /proc /sys /dev /run \
           /tmp /var/tmp /dev/shm; do
    out+=(-path "$d" -prune -o)
  done
  printf '%s\n' "${out[@]}"
}

audit_filesystem() {
  # FS-003: /etc/shadow e /etc/passwd.
  local sp; sp="$(stat -c '%a' /etc/shadow 2>/dev/null)"
  if [[ -n "$sp" && "${sp: -1}" == "0" && "${sp: -2:1}" -le 4 ]]; then
    report_pass "FS-003" "high" "/etc/shadow com permissão adequada ($sp)"
  else
    report_fail "FS-003" "high" "/etc/shadow com permissão insegura ($sp)" \
      "Deveria ser 640 root:shadow ou mais restrito" "FS-003"
  fi

  local -a prune
  mapfile -t prune < <(_fs_prune_args)

  # FS-001: arquivos world-writable do HOST (não de camadas de container).
  local ww total
  ww="$(timeout 45 find / -xdev "${prune[@]}" \
        -type f -perm -0002 -print 2>/dev/null)"
  total="$(grep -c . <<<"$ww" || true)"
  if [[ "${total:-0}" -gt 0 ]]; then
    # Trunca a LISTA exibida, mas reporta o total real — antes, o `head -20`
    # truncava a contagem também e "20 arquivos" podia significar 400.
    local shown; shown="$(head -20 <<<"$ww" | tr '\n' ' ')"
    local suffix=""; [[ "$total" -gt 20 ]] && suffix="(mostrando 20 de $total) "
    report_fail "FS-001" "high" "$total arquivo(s) graváveis por qualquer usuário" \
      "${suffix}${shown}" "FS-001"
  else
    report_pass "FS-001" "high" "Sem arquivos world-writable fora de áreas temporárias"
  fi

  # FS-002: SUID/SGID do HOST fora da whitelist.
  local suid_extra="" n_extra=0
  local f
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    grep -qwF "$f" <<<"$_SUID_WHITELIST" && continue
    n_extra=$((n_extra+1))
    [[ "$n_extra" -le 20 ]] && suid_extra+="$f "
  done < <(timeout 45 find / -xdev "${prune[@]}" \
           -type f -perm -4000 -print 2>/dev/null)
  if [[ "$n_extra" -gt 0 ]]; then
    local sfx=""; [[ "$n_extra" -gt 20 ]] && sfx="(mostrando 20 de $n_extra) "
    report_warn "FS-002" "medium" "$n_extra binário(s) SUID fora do padrão" \
      "Revise: ${sfx}${suid_extra}" "FS-002"
  else
    report_pass "FS-002" "medium" "Binários SUID conforme padrão do sistema"
  fi
}
