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
    _absorb_containers    || true
    _scan_ufw             || true
    _scan_integrity       || true
    sleep "$interval"
  done
}

# Auto-learn ligado? Quando ligado, uma novidade gera UM alerta e em seguida é
# absorvida no baseline — em vez de reaparecer como "nova" em toda varredura e
# ser realertada a cada ALERT_COOLDOWN, indefinidamente, até alguém rodar
# `vps-sec baseline update` na mão. Desligue (no) para o comportamento antigo,
# em que a divergência insiste até ser confirmada manualmente.
_autolearn() { [[ "${MONITOR_AUTOLEARN:-yes}" == "yes" ]]; }

# Descobre o processo dono de uma porta (busca pelo número, já que o endereço
# no baseline está canonizado e não casa literalmente com a saída do `ss`).
_port_process() {
  local port="$1"
  ss -tulnpH 2>/dev/null \
    | awk -v p=":$port" '$5 ~ p"$" {print; exit}' \
    | grep -oE 'users:\(\("[^"]+"' | head -1 | sed 's/users:((//; s/"//g'
}

# Linhas não vazias, ordenadas e sem repetição — formato que o `comm` exige.
_sorted_lines() { printf '%s\n' "$1" | grep . | sort -u || true; }

# Nova porta em escuta (não presente no baseline).
#
# GOTCHA: `ss -uln` lista sockets UDP NÃO CONECTADOS — e como UDP não tem estado
# de conexão, um socket de SAÍDA (consulta DNS, NTP, STUN do Tailscale) aparece
# exatamente como um listener, com porta efêmera aleatória e vida de segundos.
# Alertar na primeira aparição gerava um evento novo por socket, eternamente
# ("udp *:54819", process "?" porque o socket já sumiu). Por isso a porta só
# vira alerta depois de sobreviver a DUAS varreduras consecutivas: o que é
# efêmero desaparece nesse intervalo, o que é listener de verdade permanece.
# Custo: até um SCAN_INTERVAL de atraso no alerta de uma porta legítima.
_scan_ports() {
  local base="$VPS_SEC_STATE/baseline/ports.txt"
  [[ -f "$base" ]] || return 0
  local current; current="$(baseline_collect_ports)"
  # Guard: coleta vazia = `ss` falhou/ausente. Não é "todas as portas fecharam",
  # e nunca deve sobrescrever o baseline com nada.
  [[ -z "$current" ]] && return 0

  local pendfile="$VPS_SEC_STATE/ports-pending.txt"
  local prev_pending=""; [[ -f "$pendfile" ]] && prev_pending="$(cat "$pendfile" 2>/dev/null)"

  local cur_s base_s; cur_s="$(_sorted_lines "$current")"; base_s="$(_sorted_lines "$(cat "$base")")"
  # Divergentes do baseline nesta rodada.
  local fresh; fresh="$(comm -23 <(printf '%s\n' "$cur_s") <(printf '%s\n' "$base_s") 2>/dev/null)"
  # Confirmadas = divergentes que também estavam pendentes na rodada anterior.
  local confirmed
  confirmed="$(comm -12 <(_sorted_lines "$fresh") <(_sorted_lines "$prev_pending") 2>/dev/null)"
  # As de agora ficam pendentes para a próxima rodada.
  printf '%s\n' "$fresh" >"$pendfile" 2>/dev/null || true

  local line
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    # Severidade pelo escopo real de exposição: 0.0.0.0/:: é alto; um bind na
    # rede do Tailscale/Docker é médio; loopback é info (filtrado no default).
    local addr_port="${line#* }" port addr scope sev proc
    port="${addr_port##*:}"; addr="${addr_port%:*}"
    scope="$(port_scope "$addr")"
    sev="$(port_scope_severity "$scope")"
    proc="$(_port_process "$port")"
    local details; details="$(jq -n --arg l "$line" --arg p "${proc:-?}" --arg s "$scope" \
      '{listener:$l, process:$p, scope:$s}')"
    alert_send "new_listening_port" "$sev" "$details" \
      "Nova porta em escuta. Se não é esperado, investigue o processo" \
      "port:$line"
    log_file "new_listening_port $line scope=$scope proc=${proc:-?}" "$VPS_SEC_LOG_DIR/monitor.log"
  done <<<"$confirmed"

  # Absorve: mantém as conhecidas que ainda existem e acrescenta as confirmadas.
  # As pendentes (vistas só uma vez) NÃO entram — senão seriam adotadas sem
  # nunca terem sido alertadas, e um listener real que subiu agora passaria batido.
  if _autolearn; then
    local keep newbase
    keep="$(comm -12 <(printf '%s\n' "$cur_s") <(printf '%s\n' "$base_s") 2>/dev/null)"
    newbase="$(_sorted_lines "$keep
$confirmed")"
    if [[ "$newbase" != "$base_s" ]]; then
      printf '%s\n' "$newbase" >"$base"
      _baseline_stamp_ports_format
      log_file "autolearn_ports baseline de portas sincronizado" "$VPS_SEC_LOG_DIR/monitor.log"
    fi
  fi
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

# Absorve o estado atual dos containers no baseline. Roda DEPOIS de
# _scan_containers (novos) e _scan_container_state (caídos) — se rodasse antes,
# apagaria justamente a diferença que esses dois precisam ver.
_absorb_containers() {
  _autolearn || return 0
  docker_alive || return 0
  local base="$VPS_SEC_STATE/baseline/containers.txt"
  [[ -f "$base" ]] || return 0
  local expected current
  expected="$(grep -v '^[[:space:]]*$' "$base" | sort -u)"
  current="$(container_ids)"
  # Mesmo guard do container_down: snapshot vazio com baseline populado é quase
  # sempre um `docker ps` transitório — não zera o baseline por causa disso.
  [[ -n "$expected" && -z "$current" ]] && return 0
  [[ "$current" == "$expected" ]] && return 0
  if [[ -n "$current" ]]; then printf '%s\n' "$current" >"$base"; else : >"$base"; fi
  _baseline_stamp_containers_format
  log_file "autolearn_containers baseline de containers sincronizado" "$VPS_SEC_LOG_DIR/monitor.log"
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
# A chave de dedup inclui o HASH: cada conteúdo novo gera o seu alerta, e o
# mesmo conteúdo não volta a alertar. Sem isso, um arquivo alterado uma vez
# realertava a cada ALERT_COOLDOWN para sempre.
_scan_integrity() {
  local base="$VPS_SEC_STATE/baseline/integrity.sha256"
  [[ -f "$base" ]] || return 0
  local current; current="$(baseline_collect_integrity)"
  [[ -z "$current" ]] && return 0
  # Diferença por linha (hash + caminho).
  local changed
  changed="$(comm -13 <(sort "$base") <(sort <<<"$current") 2>/dev/null)"
  local line hash file
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    hash="${line%% *}"; file="${line##* }"
    local details; details="$(jq -n --arg f "$file" --arg h "${hash:0:16}" \
      '{file:$f, sha256_prefix:$h}')"
    alert_send "file_integrity" "high" "$details" \
      "Arquivo crítico alterado. Se não foi você, pode ser comprometimento" \
      "integrity:$file:$hash"
    log_file "file_integrity changed=$file" "$VPS_SEC_LOG_DIR/monitor.log"
  done <<<"$changed"

  # Absorve o novo estado: o alerta de CADA alteração já foi entregue, e manter
  # o hash antigo só produziria repetição. Uma alteração posterior tem hash
  # diferente e volta a alertar.
  if _autolearn && [[ -n "$changed" ]]; then
    printf '%s\n' "$current" >"$base"
    log_file "autolearn_integrity baseline de integridade sincronizado" "$VPS_SEC_LOG_DIR/monitor.log"
  fi
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
    # Guard: se o baseline espera serviços mas o snapshot atual veio VAZIO, é
    # quase certo um `docker ps` transitório (daemon reiniciando, transição de
    # restart) — não a queda simultânea de todos os serviços. Sem este guard,
    # o comm marcaria TODO o baseline como container_down de uma só vez. Pula a
    # rodada; o próximo scan (SCAN_INTERVAL) reavalia com o docker já estável.
    if [[ -n "$expected" && -z "$current" ]]; then
      log_file "container_down: snapshot vazio (docker ps sem resultado) — checagem pulada nesta rodada" \
        "$VPS_SEC_LOG_DIR/monitor.log"
      return 0
    fi
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
