#!/usr/bin/env bash
# modules/audit/45-appstack.sh — checks de segurança por aplicação.
# Detecta serviços do stack (Redis, Postgres, Traefik, n8n, Portainer) e roda
# checks direcionados. Todos ADVISORY (report-only, sem FIX_ID) — as correções
# moram em docker-compose/stacks gerenciadas fora da ferramenta.
#
# SIGILO: nenhum valor de senha/chave entra em título/detalhe — só
# presença/ausência/fraqueza.

# ── Helpers ─────────────────────────────────────────────────────────────────

# Bindings de host para uma porta interna. Ecoa "porta/proto HostIp:HostPort".
_app_port_binding() { # <cid> <port>
  docker inspect -f \
    '{{range $p,$b := .HostConfig.PortBindings}}{{range $b}}{{$p}} {{.HostIp}}:{{.HostPort}}{{"\n"}}{{end}}{{end}}' \
    "$1" 2>/dev/null | grep -E "^$2/"
}

# Classifica os bindings recebidos por stdin: public | local | none.
_app_binding_scope() {
  local bind; bind="$(cat)"
  if [[ -z "$bind" ]]; then echo none
  elif grep -qE ' 0\.0\.0\.0:| :::|^\S+ :[0-9]' <<<"$bind"; then echo public
  elif grep -qE ' 127\.0\.0\.1:| \[?::1\]?:' <<<"$bind"; then echo local
  else echo public; fi   # HostIp vazio no PortBindings = todas interfaces
}

# Env do container, uma var por linha (nunca ecoado inteiro em finding).
_app_env() { docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$1" 2>/dev/null; }

# Args + Cmd + Labels concatenados (Traefik pode configurar por qualquer um).
_app_argsline() {
  { docker inspect -f '{{range .Args}}{{println .}}{{end}}' "$1" 2>/dev/null
    docker inspect -f '{{range .Config.Cmd}}{{println .}}{{end}}' "$1" 2>/dev/null
    docker inspect -f '{{range $k,$v := .Config.Labels}}{{$k}}={{$v}}{{"\n"}}{{end}}' "$1" 2>/dev/null; }
}

# Imagem sem tag/digest sugere :latest?
_app_is_latest() { # <image>
  local img="$1"
  [[ "$img" == *"@sha256:"* ]] && return 1          # pinado por digest = ok
  [[ "$img" == *":latest" || "$img" != *:* ]]       # :latest ou sem tag
}

# ── Dispatcher ──────────────────────────────────────────────────────────────
audit_appstack() {
  if ! docker_alive; then
    report_skip "APP-000" "Docker inacessível — checks de aplicação pulados"
    return 0
  fi

  local cid meta img name hay
  while read -r cid; do
    [[ -z "$cid" ]] && continue
    meta="$(docker inspect -f '{{.Config.Image}}|{{.Name}}' "$cid" 2>/dev/null)"
    img="${meta%%|*}"; name="${meta##*|}"; name="${name#/}"
    hay="$img $name"
    if   grep -qiE '(^|/)redis|redis:'          <<<"$hay"; then _app_redis     "$cid" "$name" "$img"
    elif grep -qiE 'postgres|postgis|timescale' <<<"$hay"; then _app_postgres  "$cid" "$name" "$img"
    elif grep -qiE 'traefik'                    <<<"$hay"; then _app_traefik   "$cid" "$name" "$img"
    elif grep -qiE '(^|/)n8n'                   <<<"$hay"; then _app_n8n       "$cid" "$name" "$img"
    elif grep -qiE 'portainer'                  <<<"$hay"; then _app_portainer "$cid" "$name" "$img"
    fi
  done < <(docker ps -q 2>/dev/null)
}

# ── Redis ───────────────────────────────────────────────────────────────────
_app_redis() {
  local cid="$1" name="$2"
  local scope; scope="$(_app_port_binding "$cid" 6379 | _app_binding_scope)"

  # RDS-001: senha.
  local out has_pass="unknown"
  out="$(docker exec "$cid" redis-cli CONFIG GET requirepass 2>&1)"
  if grep -qiE 'NOAUTH|authentication' <<<"$out"; then
    has_pass="yes"
  elif grep -qiE 'executable file not found|no such file|OCI runtime' <<<"$out"; then
    # redis-cli ausente (distroless/bitnami) → fallback args/env.
    local args; args="$(_app_argsline "$cid"; _app_env "$cid")"
    if grep -qiE 'requirepass|REDIS_PASSWORD=.|REDIS_ARGS=.*requirepass' <<<"$args"; then
      has_pass="yes"
    else
      has_pass="unknown"
    fi
  else
    # Saída normal: "requirepass" + valor (vazio = sem senha).
    local val; val="$(sed -n '2p' <<<"$out")"
    [[ -n "$val" ]] && has_pass="yes" || has_pass="no"
  fi

  case "$has_pass" in
    no)
      local sev="high"; [[ "$scope" == "public" ]] && sev="critical"
      report_fail "RDS-001" "$sev" "Redis sem senha ($name)" \
        "requirepass não definido${scope:+ (porta 6379 $scope)}. Defina REDIS_PASSWORD/--requirepass e mantenha na rede interna"
      ;;
    yes) report_pass "RDS-001" "high" "Redis com autenticação ($name)" ;;
    *)   report_info "RDS-001" "Auth do Redis indeterminada ($name)" \
           "redis-cli ausente e sem indício em args/env — verifique manualmente" ;;
  esac

  # RDS-002: exposição da porta.
  case "$scope" in
    public) report_fail "RDS-002" "critical" "Redis 6379 exposto fora do host ($name)" \
              "Remova o publish de 6379; acesse via rede interna do Docker" ;;
    local)  report_warn "RDS-002" "low" "Redis 6379 publicado em localhost ($name)" \
              "Aceitável, mas prefira só a rede interna do Docker" ;;
    none)   report_pass "RDS-002" "high" "Redis não publica porta no host ($name)" ;;
  esac

  # RDS-003: protected-mode (só relevante se sem senha).
  if [[ "$has_pass" == "no" ]]; then
    local pm; pm="$(docker exec "$cid" redis-cli CONFIG GET protected-mode 2>/dev/null | sed -n '2p')"
    [[ "$pm" == "no" ]] && report_warn "RDS-003" "medium" "Redis com protected-mode off e sem senha ($name)" \
      "Sem senha e sem protected-mode — altamente exposto a abuso"
  fi
}

# ── Postgres ────────────────────────────────────────────────────────────────
_app_postgres() {
  local cid="$1" name="$2" img="$3"
  local env; env="$(_app_env "$cid")"
  local scope; scope="$(_app_port_binding "$cid" 5432 | _app_binding_scope)"

  # PG-001: trust auth.
  if grep -qE '^POSTGRES_HOST_AUTH_METHOD=trust$' <<<"$env"; then
    local sev="high"; [[ "$scope" == "public" ]] && sev="critical"
    report_fail "PG-001" "$sev" "Postgres com autenticação 'trust' ($name)" \
      "POSTGRES_HOST_AUTH_METHOD=trust aceita conexões sem senha. Use senha/scram"
  else
    report_pass "PG-001" "high" "Postgres não usa auth 'trust' ($name)"
  fi

  # PG-002: senha padrão/fraca (sem imprimir o valor).
  if grep -qE '^POSTGRES_PASSWORD_FILE=' <<<"$env"; then
    report_pass "PG-002" "high" "Postgres usa senha via secret file ($name)"
  else
    local val; val="$(grep -E '^POSTGRES_PASSWORD=' <<<"$env" | cut -d= -f2-)"
    if grep -qE '^POSTGRES_HOST_AUTH_METHOD=trust$' <<<"$env"; then
      : # já coberto por PG-001
    elif [[ -z "$val" ]] || printf '%s\n' postgres password admin root 123456 changeme \
           | grep -qxiF "$val"; then
      report_warn "PG-002" "high" "Postgres com senha fraca/padrão ($name)" \
        "POSTGRES_PASSWORD é vazio ou trivial. Troque por segredo forte ou POSTGRES_PASSWORD_FILE"
    else
      report_pass "PG-002" "high" "Postgres com senha não-trivial ($name)"
    fi
  fi

  # PG-003: exposição da porta.
  case "$scope" in
    public) report_fail "PG-003" "critical" "Postgres 5432 exposto fora do host ($name)" \
              "Remova o publish de 5432; acesse via rede interna do Docker" ;;
    local)  report_warn "PG-003" "low" "Postgres 5432 publicado em localhost ($name)" ;;
    none)   report_pass "PG-003" "critical" "Postgres não publica porta no host ($name)" ;;
  esac

  # PG-004: imagem :latest.
  _app_is_latest "$img" && report_warn "PG-004" "low" "Postgres em imagem :latest ($name)" \
    "Fixe uma versão major (ex.: postgres:16) para upgrades previsíveis"
}

# ── Traefik ─────────────────────────────────────────────────────────────────
_app_traefik() {
  local cid="$1" name="$2"
  local args; args="$(_app_argsline "$cid")"
  local scope8080; scope8080="$(_app_port_binding "$cid" 8080 | _app_binding_scope)"

  # TRF-001: api.insecure.
  if grep -qiE 'api\.insecure=true|--api\.insecure( |$)|\.insecure=true' <<<"$args"; then
    report_fail "TRF-001" "high" "Traefik com dashboard inseguro ($name)" \
      "api.insecure=true expõe o dashboard sem autenticação. Desative e use router autenticado"
  elif [[ "$scope8080" == "public" ]]; then
    report_warn "TRF-001" "medium" "Traefik 8080 exposto; api.insecure não confirmável ($name)" \
      "Config pode estar em traefik.yml (não inspecionável). Verifique api.insecure"
  else
    report_pass "TRF-001" "high" "Traefik sem api.insecure detectado ($name)"
  fi

  # TRF-002: dashboard/8080 publicado.
  case "$scope8080" in
    public) report_warn "TRF-002" "high" "Traefik 8080 (dashboard) publicado ($name)" \
              "Não publique 8080; acesse o dashboard via router com auth" ;;
    local)  report_warn "TRF-002" "low" "Traefik 8080 publicado em localhost ($name)" ;;
  esac

  # TRF-003: exposedByDefault (default do Traefik é true).
  if grep -qiE 'exposedbydefault=false' <<<"$args"; then
    report_pass "TRF-003" "medium" "Traefik exposedByDefault=false ($name)"
  else
    report_warn "TRF-003" "medium" "Traefik expõe todos os containers por padrão ($name)" \
      "Defina --providers.docker.exposedByDefault=false e habilite via label traefik.enable=true"
  fi

  # TRF-004: docker.sock read-write.
  local sock; sock="$(docker inspect -f '{{range .Mounts}}{{.Source}} {{.RW}}{{"\n"}}{{end}}' "$cid" 2>/dev/null | grep 'docker.sock')"
  if [[ -n "$sock" ]]; then
    if grep -q 'true$' <<<"$sock"; then
      report_warn "TRF-004" "medium" "Traefik monta docker.sock read-write ($name)" \
        "Monte como :ro ou use um docker-socket-proxy com escopo mínimo"
    else
      report_pass "TRF-004" "medium" "Traefik monta docker.sock read-only ($name)"
    fi
  fi
}

# ── n8n ─────────────────────────────────────────────────────────────────────
_app_n8n() {
  local cid="$1" name="$2"
  local env; env="$(_app_env "$cid")"

  # N8N-001: encryption key fixa.
  if grep -qE '^N8N_ENCRYPTION_KEY=.' <<<"$env"; then
    report_pass "N8N-001" "medium" "n8n com N8N_ENCRYPTION_KEY fixo ($name)"
  else
    report_warn "N8N-001" "medium" "n8n sem N8N_ENCRYPTION_KEY no env ($name)" \
      "n8n gera uma chave volátil; fixe N8N_ENCRYPTION_KEY e faça backup dela (senão perde credenciais em recreate)"
  fi

  # N8N-002: autenticação.
  if grep -qiE '^N8N_BASIC_AUTH_ACTIVE=true' <<<"$env"; then
    report_pass "N8N-002" "medium" "n8n com basic auth ativo ($name)"
  else
    report_warn "N8N-002" "medium" "n8n sem basic auth explícito ($name)" \
      "Confirme que há login (basic auth OU conta de owner). Atrás do Traefik ainda exige auth de app"
  fi

  # N8N-003: cookie/protocolo.
  if grep -qiE '^N8N_SECURE_COOKIE=false' <<<"$env"; then
    report_warn "N8N-003" "medium" "n8n com N8N_SECURE_COOKIE=false ($name)" \
      "Cookie sem flag Secure. Mantenha N8N_SECURE_COOKIE=true atrás de HTTPS"
  elif grep -qiE '^N8N_PROTOCOL=http$' <<<"$env"; then
    report_info "N8N-003" "n8n com N8N_PROTOCOL=http ($name)" \
      "Normal atrás do Traefik; confirme N8N_HOST/WEBHOOK_URL com o https público"
  fi
}

# ── Portainer ───────────────────────────────────────────────────────────────
_app_portainer() {
  local cid="$1" name="$2"
  local s9000 s9443
  s9000="$(_app_port_binding "$cid" 9000 | _app_binding_scope)"
  s9443="$(_app_port_binding "$cid" 9443 | _app_binding_scope)"
  if [[ "$s9000" == "public" ]]; then
    report_warn "PTR-001" "high" "Portainer HTTP (9000) exposto direto ($name)" \
      "Coloque o Portainer atrás do Traefik com TLS; remova o publish de 9000"
  elif [[ "$s9443" == "public" ]]; then
    report_warn "PTR-001" "low" "Portainer HTTPS (9443) publicado direto ($name)" \
      "Funciona, mas prefira rotear via Traefik para centralizar TLS/acesso"
  else
    report_pass "PTR-001" "medium" "Portainer não publica porta direto no host ($name)"
  fi
}
