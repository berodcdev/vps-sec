#!/usr/bin/env bash
# modules/audit/40-docker.sh — checks específicos de Docker.
# Só roda se o daemon Docker estiver ativo.

# Imagens/containers que legitimamente precisam do docker.sock (painéis/proxies).
_SOCK_EXCEPTIONS='coolify|portainer|traefik|watchtower|dockge|easypanel|autoheal|docker-socket-proxy'

audit_docker() {
  if ! docker_alive; then
    report_skip "DKR-000" "Docker não instalado ou daemon inacessível"
    return 0
  fi

  # DKR-001: portas publicadas em 0.0.0.0/:: que bypassam o UFW.
  # Docker insere regras direto na chain DOCKER, ignorando o UFW. Se há UFW
  # ativo mas a porta está publicada em todas as interfaces, o tráfego passa.
  local ufw_active=0
  [[ "${HAS_UFW:-0}" == "1" ]] && ufw status 2>/dev/null | grep -qi 'Status: active' && ufw_active=1

  local exposed=""
  local line
  while IFS= read -r line; do
    # Ex.: "0.0.0.0:5678->5678/tcp, :::5678->5678/tcp"
    [[ "$line" == *"0.0.0.0:"* || "$line" == *":::"* ]] || continue
    exposed+="$line "
  done < <(docker ps --format '{{.Names}}: {{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0:|:::')

  if [[ -n "$exposed" ]]; then
    if [[ "$ufw_active" == "1" ]]; then
      report_fail "DKR-001" "critical" "Container publica porta em 0.0.0.0 bypassando o UFW" \
        "Docker ignora o UFW. Exposto: ${exposed}— publique em 127.0.0.1 atrás de proxy ou use DOCKER-USER" "DKR-001"
    else
      report_warn "DKR-001" "high" "Containers publicam portas em todas as interfaces" \
        "Sem UFW ativo para filtrar: ${exposed}"
    fi
  else
    report_pass "DKR-001" "critical" "Nenhum container publicando em 0.0.0.0 sem controle"
  fi

  # DKR-002: containers privileged.
  local priv=""
  local cid name
  while read -r cid; do
    [[ -z "$cid" ]] && continue
    if [[ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null)" == "true" ]]; then
      name="$(docker inspect -f '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##')"
      priv+="$name "
    fi
  done < <(docker ps -q 2>/dev/null)
  if [[ -n "$priv" ]]; then
    report_fail "DKR-002" "critical" "Container(s) em modo --privileged" \
      "Privileged = acesso total ao host: $priv" "DKR-002"
  else
    report_pass "DKR-002" "critical" "Nenhum container privileged"
  fi

  # DKR-003: docker.sock montado dentro de containers.
  local sockmounts=""
  while read -r cid; do
    [[ -z "$cid" ]] && continue
    if docker inspect -f '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' "$cid" 2>/dev/null \
         | grep -q '/var/run/docker.sock'; then
      name="$(docker inspect -f '{{.Config.Image}}' "$cid" 2>/dev/null)"
      local cname; cname="$(docker inspect -f '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##')"
      if grep -qiE "$_SOCK_EXCEPTIONS" <<<"$name $cname"; then
        report_warn "DKR-003" "medium" "docker.sock montado (painel/proxy conhecido: $cname)" \
          "Esperado para $cname, mas equivale a root no host — mantenha atualizado"
      else
        sockmounts+="$cname "
      fi
    fi
  done < <(docker ps -q 2>/dev/null)
  if [[ -n "$sockmounts" ]]; then
    report_fail "DKR-003b" "high" "docker.sock montado em container não reconhecido" \
      "Equivale a root no host: $sockmounts" "DKR-003"
  fi

  # DKR-004: permissões do socket e usuários no grupo docker.
  if [[ -S /var/run/docker.sock ]]; then
    local sp; sp="$(stat -c '%a' /var/run/docker.sock 2>/dev/null)"
    if [[ "${sp: -1}" =~ [2367] ]]; then
      report_fail "DKR-004" "high" "docker.sock gravável por 'other'" \
        "Permissão $sp — qualquer usuário local vira root" "DKR-004"
    else
      report_pass "DKR-004" "high" "Permissões do docker.sock adequadas ($sp)"
    fi
  fi
  local dockergrp; dockergrp="$(getent group docker | cut -d: -f4)"
  if [[ -n "$dockergrp" ]]; then
    report_info "DKR-004b" "Usuários no grupo docker (= root efetivo)" "$dockergrp"
  fi

  # DKR-005/006: daemon.json.
  local dj=/etc/docker/daemon.json
  if [[ -f "$dj" ]]; then
    if jq -e '."log-opts"' "$dj" >/dev/null 2>&1; then
      report_pass "DKR-005" "medium" "daemon.json com limites de log configurados"
    else
      report_warn "DKR-005" "medium" "daemon.json sem log-opts (rotação de logs)" \
        "Logs de container podem encher o disco" "DKR-005"
    fi
    # DKR-006: exposição TCP do daemon.
    if jq -e '.hosts[]? | select(test("2375"))' "$dj" >/dev/null 2>&1; then
      report_fail "DKR-006" "critical" "Docker daemon exposto em TCP 2375 (sem TLS)" \
        "API Docker sem autenticação = root remoto" "DKR-006"
    fi
  else
    report_warn "DKR-005" "medium" "daemon.json ausente" \
      "Sem limites de log nem ajustes de segurança" "DKR-005"
  fi

  # DKR-008: capabilities perigosas adicionadas.
  local capadd=""
  while read -r cid; do
    [[ -z "$cid" ]] && continue
    local caps; caps="$(docker inspect -f '{{range .HostConfig.CapAdd}}{{.}} {{end}}' "$cid" 2>/dev/null)"
    if grep -qiE 'SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|ALL' <<<"$caps"; then
      cname="$(docker inspect -f '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##')"
      capadd+="$cname($caps) "
    fi
  done < <(docker ps -q 2>/dev/null)
  if [[ -n "$capadd" ]]; then
    report_warn "DKR-008" "high" "Container com capabilities perigosas" \
      "$capadd" "DKR-008"
  fi
}
