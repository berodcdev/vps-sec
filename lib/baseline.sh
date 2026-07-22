#!/usr/bin/env bash
# lib/baseline.sh — snapshots de estado (portas, containers, IPs, integridade).
# O monitor compara o estado atual contra estes baselines para detectar mudanças.

_BL_DIR="$VPS_SEC_STATE/baseline"

# Versão do FORMATO do baseline de containers (a identidade estável gravada em
# containers.txt). Suba este número sempre que mudar o formato da identidade —
# o monitor detecta a divergência no startup e regenera sozinho, evitando o
# spam de container_down/new_docker_container que uma mudança de formato causa
# num host que ainda tem o baseline no formato antigo.
#   1 = "imagem|nome|ports"
#   2 = identidade estável: compose (proj/svc) → swarm (stack_svc) → nome
BASELINE_CONTAINERS_FORMAT="2"

# ── Coletores de estado (produzem a "foto" atual em stdout) ─────────────────

# Portas em escuta: "proto local_addr" ordenado (sem PID, que muda a cada restart).
baseline_collect_ports() {
  has_cmd ss || return 0
  ss -tulnH 2>/dev/null | awk '{print $1, $5}' | sort -u
}

# Snapshot dos containers com IDENTIDADE ESTÁVEL. A identidade tem que sobreviver
# a um deploy que recria o container. Em ordem de preferência:
#   1) Compose  → "projeto/serviço"  (label com.docker.compose.service)
#   2) Swarm    → "stack_serviço"    (label com.docker.swarm.service.name)
#   3) fallback → nome do container
# GOTCHA: no Swarm o nome do container é "<serviço>.<slot>.<taskid>" e o <taskid>
# MUDA a cada reagendamento da task. Cair direto no nome (sem checar a label do
# Swarm) fazia toda reprogramação virar container_down + new_docker_container em
# loop. A label com.docker.swarm.service.name NÃO tem o sufixo de task → estável.
# Formato por linha (TSV): identidade \t imagem \t ports
container_snapshot() {
  docker_alive || return 0
  docker ps --format '{{.Names}}|{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.service"}}|{{.Label "com.docker.swarm.service.name"}}|{{.Image}}|{{.Ports}}' 2>/dev/null \
    | while IFS='|' read -r name proj svc swarmsvc image ports; do
        local id
        if [[ -n "$svc" ]]; then       id="${proj:+$proj/}$svc"
        elif [[ -n "$swarmsvc" ]]; then id="$swarmsvc"
        else                           id="$name"; fi
        printf '%s\t%s\t%s\n' "$id" "$image" "$ports"
      done | sort -u
}

# Só as identidades estáveis (uma por linha) — base do diff novo/caído.
container_ids() { container_snapshot | cut -f1 | grep -v '^[[:space:]]*$' | sort -u; }

# Baseline de containers = conjunto de identidades conhecidas.
baseline_collect_containers() { container_ids; }

# IPs que já logaram com sucesso via SSH (para distinguir login "novo").
baseline_collect_ips() {
  has_cmd journalctl || return 0
  journalctl _COMM=sshd --since "30 days ago" -o cat 2>/dev/null \
    | grep -oE 'Accepted (password|publickey) for .* from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u
}

# Hashes de integridade da watchlist.
baseline_collect_integrity() {
  local target
  for target in ${INTEGRITY_WATCHLIST:-}; do
    if [[ -f "$target" ]]; then
      sha256sum "$target" 2>/dev/null
    elif [[ -d "$target" ]]; then
      find "$target" -type f -exec sha256sum {} \; 2>/dev/null
    fi
  done | sort -k2
}

# ── Atualização dos baselines ───────────────────────────────────────────────
# baseline_update [--ports|--containers|--integrity|--ips]  (sem flag = todos)
baseline_update() {
  ensure_dirs
  local what="${1:-all}"
  case "$what" in
    all)
      baseline_collect_ports      >"$_BL_DIR/ports.txt"
      baseline_collect_containers >"$_BL_DIR/containers.txt"
      _baseline_stamp_containers_format
      baseline_collect_ips        >"$_BL_DIR/ips.txt"
      baseline_collect_integrity  >"$_BL_DIR/integrity.sha256"
      ;;
    --ports)      baseline_collect_ports      >"$_BL_DIR/ports.txt" ;;
    --containers) baseline_collect_containers >"$_BL_DIR/containers.txt"; _baseline_stamp_containers_format ;;
    --ips)        baseline_collect_ips        >"$_BL_DIR/ips.txt" ;;
    --integrity)  baseline_collect_integrity  >"$_BL_DIR/integrity.sha256" ;;
    *) die "baseline: alvo desconhecido '$what'" ;;
  esac
}

# Carimba a versão de formato do baseline de containers recém-escrito.
_baseline_stamp_containers_format() {
  printf '%s\n' "$BASELINE_CONTAINERS_FORMAT" >"$_BL_DIR/.containers-format" 2>/dev/null || true
}

# Auto-cura: se o baseline de containers foi escrito por uma versão anterior do
# formato (ou não tem carimbo), regenera-o no formato atual e loga. Chamado no
# startup do monitor — assim uma atualização de código que muda o formato não
# gera enxurrada de container_down/new_docker_container contra um baseline velho.
# No-op se o Docker não estiver disponível (não dá pra regenerar com segurança).
baseline_ensure_containers_format() {
  local f="$_BL_DIR/containers.txt" mk="$_BL_DIR/.containers-format"
  [[ -f "$f" ]] || return 0
  local cur=""; [[ -f "$mk" ]] && cur="$(cat "$mk" 2>/dev/null)"
  [[ "$cur" == "$BASELINE_CONTAINERS_FORMAT" ]] && return 0
  docker_alive || return 0
  ensure_dirs
  baseline_collect_containers >"$f" 2>/dev/null || return 0
  _baseline_stamp_containers_format
  log_file "baseline de containers regenerado (formato ${cur:-desconhecido} → $BASELINE_CONTAINERS_FORMAT)" \
    "$VPS_SEC_LOG_DIR/monitor.log" 2>/dev/null || true
}

# Atualiza só a integridade de um arquivo (usado pelo harden após mudar algo,
# para não gerar auto-alerta de integridade).
baseline_refresh_integrity() {
  ensure_dirs
  baseline_collect_integrity >"$_BL_DIR/integrity.sha256"
}

# Entrypoint do subcomando `vps-sec baseline`.
baseline_main() {
  local sub="${1:-}"; shift || true
  case "$sub" in
    update)
      ensure_dirs
      if [[ $# -eq 0 ]]; then
        baseline_update all
        ok "Baselines atualizados (portas, containers, IPs, integridade)."
      else
        local flag
        for flag in "$@"; do baseline_update "$flag"; done
        ok "Baseline(s) atualizado(s): $*"
      fi
      ;;
    ""|help|-h|--help)
      echo "Uso: vps-sec baseline update [--ports|--containers|--integrity|--ips]" >&2
      ;;
    *) die "baseline: subcomando desconhecido '$sub'" ;;
  esac
}
