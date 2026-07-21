#!/usr/bin/env bash
# lib/baseline.sh — snapshots de estado (portas, containers, IPs, integridade).
# O monitor compara o estado atual contra estes baselines para detectar mudanças.

_BL_DIR="$VPS_SEC_STATE/baseline"

# ── Coletores de estado (produzem a "foto" atual em stdout) ─────────────────

# Portas em escuta: "proto local_addr" ordenado (sem PID, que muda a cada restart).
baseline_collect_ports() {
  has_cmd ss || return 0
  ss -tulnH 2>/dev/null | awk '{print $1, $5}' | sort -u
}

# Snapshot dos containers com IDENTIDADE ESTÁVEL. A identidade é o serviço do
# compose ("projeto/serviço") — que NÃO muda quando o container é recriado num
# deploy — caindo para o nome do container quando não é gerenciado por compose.
# Formato por linha (TSV): identidade \t imagem \t ports
container_snapshot() {
  docker_alive || return 0
  docker ps --format '{{.Names}}|{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.service"}}|{{.Image}}|{{.Ports}}' 2>/dev/null \
    | while IFS='|' read -r name proj svc image ports; do
        local id
        if [[ -n "$svc" ]]; then id="${proj:+$proj/}$svc"; else id="$name"; fi
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
      baseline_collect_ips        >"$_BL_DIR/ips.txt"
      baseline_collect_integrity  >"$_BL_DIR/integrity.sha256"
      ;;
    --ports)      baseline_collect_ports      >"$_BL_DIR/ports.txt" ;;
    --containers) baseline_collect_containers >"$_BL_DIR/containers.txt" ;;
    --ips)        baseline_collect_ips        >"$_BL_DIR/ips.txt" ;;
    --integrity)  baseline_collect_integrity  >"$_BL_DIR/integrity.sha256" ;;
    *) die "baseline: alvo desconhecido '$what'" ;;
  esac
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
