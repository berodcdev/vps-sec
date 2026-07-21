#!/usr/bin/env bash
# modules/audit/55-backup.sh — consciência de backup dos dados críticos.
# Advisory (report-only): a ferramenta não sabe COMO você faz backup, só
# verifica se os caminhos vigiados estão frescos e alerta se há dados sem vigilância.

audit_backup() {
  # ── BKP-001: caminhos vigiados estão frescos? ──
  if [[ -n "${BACKUP_WATCH:-}" ]]; then
    local item path maxdays newest age now; now="$(epoch)"
    for item in $BACKUP_WATCH; do
      path="${item%:*}"; maxdays="${item##*:}"
      [[ "$maxdays" =~ ^[0-9]+$ ]] || { path="$item"; maxdays="${BACKUP_DEFAULT_MAX_AGE_DAYS:-2}"; }
      # Arquivo mais novo abaixo do caminho (glob expandido pelo shell).
      # shellcheck disable=SC2086
      newest="$(find $path -type f -printf '%T@\n' 2>/dev/null | sort -rn | head -1)"
      newest="${newest%.*}"
      if [[ -z "$newest" ]]; then
        report_fail "BKP-001" "high" "Backup ausente: $path" \
          "Nenhum arquivo encontrado no caminho vigiado"
      else
        age=$(( (now - newest) / 86400 ))
        if (( age > maxdays )); then
          report_fail "BKP-001" "high" "Backup desatualizado: $path" \
            "Arquivo mais recente tem ${age}d (limite ${maxdays}d)"
        else
          report_pass "BKP-001" "high" "Backup recente: $path (${age}d, limite ${maxdays}d)"
        fi
      fi
    done
  fi

  # ── BKP-002: tem dados persistentes mas não vigia backup? ──
  if [[ -z "${BACKUP_WATCH:-}" ]] && docker_alive; then
    local has_data="" cid vols cname
    while read -r cid; do
      [[ -z "$cid" ]] && continue
      vols="$(docker inspect -f '{{range .Mounts}}{{.Destination}}{{"\n"}}{{end}}' "$cid" 2>/dev/null)"
      if grep -qE '^/var/lib/postgresql/data$|^/home/node/\.n8n$|^/data$|^/var/lib/mysql$|^/bitnami' <<<"$vols"; then
        cname="$(docker inspect -f '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##')"
        has_data+="$cname "
      fi
    done < <(docker ps -q 2>/dev/null)
    if [[ -n "$has_data" ]]; then
      report_warn "BKP-002" "medium" "Dados persistentes sem vigilância de backup" \
        "Volumes de dados detectados ($has_data) mas BACKUP_WATCH está vazio. Configure BACKUP_WATCH em /etc/vps-sec/config"
    else
      report_pass "BKP-002" "medium" "Nenhum volume de dados crítico sem vigilância detectado"
    fi
  fi
}
