#!/usr/bin/env bash
# lib/backup.sh — backup, manifest e rollback para o módulo harden.
# Carregado via `source`. Depende de common.sh e jq.

# Inicia um novo conjunto de backup para uma sessão de harden.
# Popula BACKUP_SESSION_DIR e cria o manifest vazio.
backup_start_session() {
  ensure_dirs
  BACKUP_SESSION_DIR="$VPS_SEC_BACKUP_DIR/$(now_ts)"
  install -d -m 700 "$BACKUP_SESSION_DIR"
  BACKUP_MANIFEST="$BACKUP_SESSION_DIR/manifest.json"
  jq -n --arg ts "$(now_utc)" --arg host "${NODE_NAME:-$(hostname)}" \
    '{timestamp:$ts, hostname:$host, files:[], commands:[]}' \
    >"$BACKUP_MANIFEST"
  _backup_retention
}

# Faz backup de um arquivo, espelhando o caminho absoluto dentro da sessão.
# backup_file <path>
backup_file() {
  local path="$1"
  [[ -n "${BACKUP_SESSION_DIR:-}" ]] || die "backup: sessão não iniciada"
  local dest="$BACKUP_SESSION_DIR/files$path"
  install -d -m 700 "$(dirname "$dest")"
  local sha="ausente"
  if [[ -f "$path" ]]; then
    cp -a "$path" "$dest"
    sha="$(sha256sum "$path" | awk '{print $1}')"
  else
    # Marca que o arquivo não existia (rollback = remover).
    : >"$dest.ABSENT"
  fi
  # Registra no manifest.
  local tmp; tmp="$(mktemp)"
  jq --arg p "$path" --arg s "$sha" \
    '.files += [{path:$p, sha256_before:$s}]' "$BACKUP_MANIFEST" >"$tmp" \
    && mv "$tmp" "$BACKUP_MANIFEST"
}

# Registra um comando aplicado (para o relatório/rollback informativo).
backup_record_cmd() {
  local desc="$1"
  [[ -n "${BACKUP_MANIFEST:-}" ]] || return 0
  local tmp; tmp="$(mktemp)"
  jq --arg c "$desc" '.commands += [$c]' "$BACKUP_MANIFEST" >"$tmp" \
    && mv "$tmp" "$BACKUP_MANIFEST"
}

# Retenção: mantém os 20 backups mais recentes.
_backup_retention() {
  local dirs; mapfile -t dirs < <(find "$VPS_SEC_BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort)
  local excess=$(( ${#dirs[@]} - 20 ))
  local i
  for (( i=0; i<excess; i++ )); do
    rm -rf "${dirs[$i]}"
  done
}

# ── Rollback ────────────────────────────────────────────────────────────────
rollback_main() {
  local target="${1:-last}"
  case "$target" in
    --list|list)
      echo "Backups disponíveis:"
      find "$VPS_SEC_BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d 2>/dev/null \
        | sort -r | while read -r d; do
          local ts; ts="$(jq -r '.timestamp' "$d/manifest.json" 2>/dev/null || echo '?')"
          local n; n="$(jq -r '.files | length' "$d/manifest.json" 2>/dev/null || echo 0)"
          printf '  %s  (%s arquivos)  %s\n' "$(basename "$d")" "$n" "$ts"
        done
      return 0
      ;;
    last)
      target="$(find "$VPS_SEC_BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort | tail -1)"
      [[ -n "$target" ]] || die "Nenhum backup encontrado"
      ;;
    *)
      target="$VPS_SEC_BACKUP_DIR/$target"
      ;;
  esac
  _rollback_apply "$target"
}

_rollback_apply() {
  local dir="$1"
  [[ -d "$dir" && -f "$dir/manifest.json" ]] || die "Backup inválido: $dir"
  warn "Restaurando backup: $(basename "$dir")"

  local path
  while IFS= read -r path; do
    local src="$dir/files$path"
    if [[ -f "$src.ABSENT" ]]; then
      rm -f "$path" && log "removido (não existia antes): $path"
    elif [[ -f "$src" ]]; then
      install -d "$(dirname "$path")"
      cp -a "$src" "$path" && log "restaurado: $path"
    fi
  done < <(jq -r '.files[].path' "$dir/manifest.json")

  # Validações pós-restauro.
  if has_cmd sshd && ! sshd -t 2>/dev/null; then
    error "sshd -t falhou após rollback — verifique manualmente!"
  fi
  if has_cmd visudo && ! visudo -c >/dev/null 2>&1; then
    error "visudo -c falhou após rollback — verifique manualmente!"
  fi

  # Recarrega serviços afetados (best-effort).
  systemctl reload "${SSH_UNIT:-ssh}" 2>/dev/null || true
  ok "Rollback concluído a partir de $(basename "$dir")."
}

# ── Rollback automático de SSH (chamado pelo timer transiente) ─────────────
# Restaura o último backup marcado como "pendente de confirmação" e alerta.
rollback_pending_ssh() {
  local pending="$VPS_SEC_STATE/ssh-harden-pending"
  [[ -f "$pending" ]] || { log "sem harden de SSH pendente — nada a reverter"; return 0; }
  local dir; dir="$(cat "$pending")"
  warn "Confirmação de SSH não recebida em tempo — revertendo automaticamente"
  _rollback_apply "$dir"
  rm -f "$pending"

  if [[ -f "$VPS_SEC_PREFIX/lib/alert.sh" ]]; then
    # shellcheck source=/dev/null
    . "$VPS_SEC_PREFIX/lib/alert.sh"
    alert_send "harden_rollback" "high" \
      "$(jq -n --arg d "$(basename "$dir")" '{backup:$d, reason:"Confirmação de SSH não recebida em 5 min"}')" \
      "A mudança de SSH foi revertida para não trancar o acesso" \
      "harden_rollback" 2>/dev/null || true
  fi
}
