#!/usr/bin/env bash
# modules/monitor/state-scan.sh — varredura periódica de estado (loop 2).
# Compara o estado atual contra os baselines e alerta divergências.
# Carregado via `source` pelo run.sh. Depende de baseline.sh e alert.sh.

monitor_scan_loop() {
  local interval="${SCAN_INTERVAL:-60}"
  while :; do
    _scan_ports           || true
    _scan_containers      || true
    _scan_container_state || true
    _scan_ufw             || true
    _scan_integrity       || true
    sleep "$interval"
  done
}

# Nova porta em escuta (não presente no baseline).
_scan_ports() {
  local base="$VPS_SEC_STATE/baseline/ports.txt"
  [[ -f "$base" ]] || return 0
  local current; current="$(baseline_collect_ports)"
  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if ! grep -qxF "$line" "$base"; then
      local proc; proc="$(ss -tulnpH 2>/dev/null | grep -F "${line##* }" | grep -oE 'users:\(\("[^"]+"' | head -1 | sed 's/users:((//; s/"//g')"
      local details; details="$(jq -n --arg l "$line" --arg p "${proc:-?}" \
        '{listener:$l, process:$p}')"
      alert_send "new_listening_port" "high" "$details" \
        "Nova porta em escuta. Se não é esperado, investigue o processo" \
        "port:$line"
      log_file "new_listening_port $line proc=${proc:-?}" "$VPS_SEC_LOG_DIR/monitor.log"
    fi
  done <<<"$current"
}

# Novo container (não presente no baseline).
_scan_containers() {
  docker_alive || return 0
  local base="$VPS_SEC_STATE/baseline/containers.txt"
  [[ -f "$base" ]] || return 0
  # Identidade estável = serviço do compose (ou nome). Não dispara em deploy que
  # apenas recria o container (nome muda, serviço não).
  local id image ports
  while IFS=$'\t' read -r id image ports; do
    [[ -z "$id" ]] && continue
    if ! grep -qxF "$id" "$base"; then
      local sev="medium"
      [[ "$ports" == *"0.0.0.0:"* || "$ports" == *":::"* ]] && sev="high"
      local details; details="$(jq -n --arg i "$image" --arg n "$id" --arg p "$ports" \
        '{image:$i, service:$n, ports:$p}')"
      alert_send "new_docker_container" "$sev" "$details" \
        "Novo container/serviço detectado. Confirme se foi um deploy legítimo" \
        "container:$id"
      log_file "new_docker_container id=$id image=$image" "$VPS_SEC_LOG_DIR/monitor.log"
    fi
  done < <(container_snapshot)
}

# UFW foi desativado (só alerta se o baseline indicava ativo).
_scan_ufw() {
  [[ "${HAS_UFW:-0}" == "1" ]] || return 0
  local flag="$VPS_SEC_STATE/baseline/ufw-was-active"
  if ufw status 2>/dev/null | grep -qi 'Status: active'; then
    touch "$flag" 2>/dev/null || true
    return 0
  fi
  # Inativo agora: se antes estava ativo, alerta.
  if [[ -f "$flag" ]]; then
    alert_send "ufw_disabled" "critical" \
      "$(jq -n '{message:"UFW foi desativado"}')" \
      "Reative o firewall: ufw enable (garanta a regra da porta SSH antes)" \
      "ufw_disabled"
    log_file "ufw_disabled" "$VPS_SEC_LOG_DIR/monitor.log"
    rm -f "$flag"   # evita re-alertar a cada scan até reativar
  fi
}

# Integridade dos arquivos críticos (sha256 vs baseline).
_scan_integrity() {
  local base="$VPS_SEC_STATE/baseline/integrity.sha256"
  [[ -f "$base" ]] || return 0
  local current; current="$(baseline_collect_integrity)"
  # Diferença por linha (hash + caminho).
  local changed
  changed="$(comm -13 <(sort "$base") <(sort <<<"$current") 2>/dev/null | awk '{print $2}')"
  local file
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    local details; details="$(jq -n --arg f "$file" '{file:$f}')"
    alert_send "file_integrity" "high" "$details" \
      "Arquivo crítico alterado. Se não foi você, pode ser comprometimento" \
      "integrity:$file"
    log_file "file_integrity changed=$file" "$VPS_SEC_LOG_DIR/monitor.log"
  done <<<"$changed"
}

# Saúde dos containers: caiu, unhealthy, restart loop. Uma coleta em lote.
_scan_container_state() {
  [[ "${CONTAINER_HEALTH_ENABLED:-yes}" == "yes" ]] || return 0
  docker_alive || return 0

  # ── (A) container_down: serviço do baseline não está mais rodando ──
  # Compara por identidade estável (serviço do compose), não pelo nome efêmero
  # do container — assim um deploy que recria o container não vira "caiu".
  local base="$VPS_SEC_STATE/baseline/containers.txt"
  if [[ -f "$base" ]]; then
    local expected current down n
    expected="$(grep -v '^[[:space:]]*$' "$base" | sort -u)"
    current="$(container_ids)"
    down="$(comm -23 <(printf '%s\n' "$expected") <(printf '%s\n' "$current") 2>/dev/null)"
    while IFS= read -r n; do
      [[ -z "$n" ]] && continue
      alert_send "container_down" "high" \
        "$(jq -n --arg n "$n" '{service:$n, message:"Serviço do baseline não está mais em execução"}')" \
        "Serviço esperado parou/sumiu. Reinicie ou, se foi intencional, rode: vps-sec baseline update --containers" \
        "container_down:$n"
      log_file "container_down id=$n" "$VPS_SEC_LOG_DIR/monitor.log"
    done <<<"$down"
  fi

  # ── (B)+(C) unhealthy e restart loop: um inspect em lote ──
  local ids; ids="$(docker ps -q 2>/dev/null)"; [[ -z "$ids" ]] && return 0
  local statefile="$VPS_SEC_STATE/restart-counts.txt"
  local now; now="$(epoch)"
  local newstate="" name rc restarting health prev_rc delta
  # shellcheck disable=SC2086
  while read -r name rc restarting health; do
    [[ -z "$name" ]] && continue
    name="${name#/}"

    # (B) unhealthy — ignora none/starting/healthy.
    if [[ "$health" == "unhealthy" ]]; then
      alert_send "container_unhealthy" "high" \
        "$(jq -n --arg n "$name" '{container:$n, health:"unhealthy"}')" \
        "Healthcheck falhando. Verifique 'docker logs $name'" \
        "container_unhealthy:$name"
      log_file "container_unhealthy name=$name" "$VPS_SEC_LOG_DIR/monitor.log"
    fi

    # (C) restart loop — Restarting=true ou RestartCount crescendo rápido.
    prev_rc="$(awk -v n="$name" '$1==n {print $2}' "$statefile" 2>/dev/null)"
    prev_rc="${prev_rc:-$rc}"
    delta=$(( rc - prev_rc ))
    if [[ "$restarting" == "true" ]] || (( delta >= ${RESTART_LOOP_DELTA:-3} )); then
      alert_send "container_restart_loop" "high" \
        "$(jq -n --arg n "$name" --argjson rc "$rc" --argjson d "$delta" \
           '{container:$n, restart_count:$rc, delta_since_last_scan:$d}')" \
        "Container em loop de reinício. Veja 'docker logs $name' e a saúde das dependências" \
        "container_restart_loop:$name"
      log_file "container_restart_loop name=$name rc=$rc delta=$delta" "$VPS_SEC_LOG_DIR/monitor.log"
    fi
    newstate+="$name $rc $now"$'\n'
  done < <(docker inspect -f \
        '{{.Name}} {{.RestartCount}} {{.State.Restarting}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
        $ids 2>/dev/null)

  printf '%s' "$newstate" >"$statefile" 2>/dev/null || true
}
