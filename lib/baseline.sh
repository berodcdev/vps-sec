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

# Versão do FORMATO do baseline de PORTAS. Mesma lógica do de containers: subir
# este número faz o monitor regenerar o ports.txt no startup, evitando que uma
# mudança de formato transforme o baseline inteiro em "portas novas".
#   1 = saída crua do ss ("tcp 0.0.0.0:22")
#   2 = endereço canonizado (any → "*", loopback → "localhost", IPv4-mapped)
BASELINE_PORTS_FORMAT="2"

# ── Coletores de estado (produzem a "foto" atual em stdout) ─────────────────

# Canoniza um listener do `ss` numa chave estável: "<proto> <addr>:<porta>".
# GOTCHA: um socket dual-stack aparece DUAS vezes no `ss` ("0.0.0.0:8080" e
# "[::]:8080") — sem canonizar, um único serviço vira dois alertas de porta
# nova. Aqui ambos colapsam em "*:8080"; 127.0.0.1 e ::1 viram "localhost".
port_normalize() {
  local proto="$1" ap="$2"
  local port="${ap##*:}" addr="${ap%:*}"
  addr="${addr#\[}"; addr="${addr%\]}"
  # IPv4-mapped (::ffff:1.2.3.4) → trata como o IPv4 que ele é.
  [[ "$addr" == ::ffff:*.*.*.* ]] && addr="${addr#::ffff:}"
  case "$addr" in
    ''|'*'|'0.0.0.0'|'::')  addr='*' ;;
    '::1'|127.*)            addr='localhost' ;;
  esac
  printf '%s %s:%s\n' "$proto" "$addr" "$port"
}

# Classifica a exposição de um endereço já canonizado: public|private|loopback.
# "private" cobre RFC1918, link-local e a faixa CGNAT 100.64.0.0/10 usada pelo
# Tailscale — rede interna/autenticada não tem o mesmo risco que 0.0.0.0.
port_scope() {
  case "$1" in
    localhost)                              echo loopback ;;
    '*')                                    echo public ;;
    10.*|192.168.*|169.254.*)               echo private ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*)  echo private ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*) echo private ;;
    fc*|fd*|fe80*|::1)                      echo private ;;
    *)                                      echo public ;;
  esac
}

# Severidade de uma porta nova conforme o escopo de exposição.
port_scope_severity() {
  case "$1" in
    public)   echo high ;;
    private)  echo medium ;;
    *)        echo info ;;
  esac
}

# Portas em escuta: "<proto> <addr>:<porta>" canonizado e ordenado (sem PID,
# que muda a cada restart do processo).
baseline_collect_ports() {
  has_cmd ss || return 0
  local proto ap
  ss -tulnH 2>/dev/null | awk '{print $1, $5}' | while read -r proto ap; do
    [[ -z "$proto" || -z "$ap" ]] && continue
    port_normalize "$proto" "$ap"
  done | sort -u
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
      _baseline_stamp_ports_format
      baseline_collect_containers >"$_BL_DIR/containers.txt"
      _baseline_stamp_containers_format
      baseline_collect_ips        >"$_BL_DIR/ips.txt"
      baseline_collect_integrity  >"$_BL_DIR/integrity.sha256"
      ;;
    --ports)      baseline_collect_ports      >"$_BL_DIR/ports.txt"; _baseline_stamp_ports_format ;;
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

# Idem para o baseline de portas.
_baseline_stamp_ports_format() {
  printf '%s\n' "$BASELINE_PORTS_FORMAT" >"$_BL_DIR/.ports-format" 2>/dev/null || true
}

# Auto-cura do baseline de portas: se foi escrito num formato anterior (ou não
# tem carimbo), regenera no formato atual. Sem isto, o self-update que introduz
# a canonização faria TODA porta conhecida parecer nova de uma vez.
baseline_ensure_ports_format() {
  local f="$_BL_DIR/ports.txt" mk="$_BL_DIR/.ports-format"
  [[ -f "$f" ]] || return 0
  local cur=""; [[ -f "$mk" ]] && cur="$(cat "$mk" 2>/dev/null)"
  [[ "$cur" == "$BASELINE_PORTS_FORMAT" ]] && return 0
  # Reescreve o baseline EXISTENTE aplicando a canonização (não recoleta): assim
  # uma porta que já era conhecida continua conhecida, e uma que subiu desde a
  # última atualização do baseline ainda gera o seu alerta.
  local proto ap out=""
  while read -r proto ap; do
    [[ -z "$proto" || -z "$ap" ]] && continue
    out+="$(port_normalize "$proto" "$ap")"$'\n'
  done <"$f"
  printf '%s' "$out" | sort -u >"$f.tmp" 2>/dev/null && mv "$f.tmp" "$f"
  _baseline_stamp_ports_format
  log_file "baseline de portas convertido (formato ${cur:-desconhecido} → $BASELINE_PORTS_FORMAT)" \
    "$VPS_SEC_LOG_DIR/monitor.log" 2>/dev/null || true
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
