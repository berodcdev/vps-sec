# vps-sec

Toolkit de segurança para VPS Ubuntu (22.04/24.04), em Bash puro + `jq` + `curl` + systemd.
Faz **auditoria**, **hardening guiado** e **monitoramento em tempo real** com alertas
enviados para um webhook do n8n.

Três pilares:

- **audit** — somente leitura; ~40 checks de configuração com score e relatório (texto + JSON).
- **harden** — aplica correções sob comando, com backup e rollback; mudanças arriscadas
  (SSH/UFW) exigem confirmação e têm proteção anti-lockout.
- **monitor** — daemon que segue o `journald` e varre o estado do host, alertando
  logins SSH, brute force, novos usuários/portas/containers, UFW desativado e alteração
  de arquivos críticos.

---

## Instalação

One-line (repositório público no GitHub) — troque `berodcdev/vps-sec`:

```bash
curl -fsSL https://raw.githubusercontent.com/berodcdev/vps-sec/main/install.sh \
  | sudo bash -s -- --webhook-url "https://SEU-N8N/webhook/SEU-ID"
```

A URL do webhook é sempre fornecida no momento da instalação (nunca fica no código).
Se você omitir `--webhook-url` e rodar num terminal interativo, o instalador pergunta.

O `install.sh` detecta que roda via pipe e baixa o tarball do próprio repositório.
Você pode fixar o repo/branch por flag (`--repo usuario/repo --branch main`) ou por
variável de ambiente (`VPS_SEC_REPO`, `VPS_SEC_BRANCH`).

A partir de um clone local (para desenvolvimento):

```bash
git clone https://github.com/berodcdev/vps-sec.git
sudo ./vps-sec/install.sh --webhook-url "https://..."
```

O instalador é idempotente (re-rodar = upgrade). Ele instala em `/opt/vps-sec`, cria
`/etc/vps-sec/config` (chmod 600), habilita os serviços systemd, cria os baselines,
testa o webhook e roda a primeira auditoria.

Para atualizar depois: `sudo vps-sec self-update` (rebaixa a última versão do
repositório e reinstala, preservando sua config).

Requisitos: Ubuntu/Debian com systemd. Dependências (`jq`, `curl`) são instaladas
automaticamente. **Nada de firewall é instalado ou alterado na instalação** — UFW e
fail2ban são apenas reportados pelo audit e aplicados via `harden`.

---

## Uso

```bash
vps-sec audit                 # auditar agora (exit: 0 limpo · 1 findings · 2 crítico)
vps-sec audit --json          # saída JSON (para automação)

vps-sec harden --dry-run      # ver o que seria corrigido
vps-sec harden --yes          # aplicar só as correções SEGURAS, sem perguntar
vps-sec harden --allow-risky  # habilita perguntar as correções ARRISCADAS
vps-sec harden --only SSH-001 # aplicar o fix de um check específico
vps-sec harden --confirm-ssh  # confirmar mudança de SSH (cancela o rollback automático)

vps-sec rollback --list       # listar backups
vps-sec rollback last         # reverter o último harden

vps-sec monitor status        # estado do monitor
vps-sec monitor log           # últimos eventos
vps-sec baseline update       # atualizar os baselines (após mudanças legítimas)
vps-sec test-webhook          # enviar evento de teste ao n8n
vps-sec digest --now          # gerar/enviar o resumo diário
```

---

## Correções (harden)

**SAFE** (aplicáveis com `--yes`, reversíveis, não derrubam acesso):
fail2ban + jail sshd · unattended-upgrades · sysctl endurecido · permissões de
`authorized_keys`/`shadow`/`docker.sock` · limites de log no `daemon.json` ·
endurecimento leve do SSH (drop-in) · travar contas sem senha.

**RISKY** (exigem digitar `CONFIRMO`, nunca aplicadas só com `--yes`):
`PermitRootLogin no` · `PasswordAuthentication no` · `ufw enable` · política default do UFW.

### Proteção anti-lockout (SSH)

Ao mudar SSH, o vps-sec: faz backup → grava num drop-in `sshd_config.d/99-vps-sec.conf`
→ valida com `sshd -t` → **agenda um rollback automático em 5 minutos** → faz `reload`
(não derruba a sessão atual) → e instrui você a testar em um **novo terminal**.
Se você conseguir logar, rode `vps-sec harden --confirm-ssh` para cancelar o rollback.
Se não confirmar em 5 minutos, a mudança é revertida sozinha e um alerta
`harden_rollback` é enviado. Antes de `ufw enable`, a porta do SSH é sempre liberada.

---

## Docker × UFW (importante)

O Docker insere regras direto no iptables e **ignora o UFW** por padrão. Uma porta
publicada em `0.0.0.0` fica exposta mesmo com UFW "ativo". O audit detecta isso
(`DKR-001`). A correção estrutural recomendada é publicar serviços internos em
`127.0.0.1:porta` atrás de um reverse proxy. O vps-sec **não** usa `"iptables": false`
nem scripts de terceiros (causas comuns de "o Docker parou depois do hardening").

---

## Checks de aplicação (app-stack)

Além da infra, o audit inspeciona os serviços do stack via `docker inspect`/`exec`
(sem precisar das suas credenciais) e reporta riscos comuns — tudo **advisory**
(sem correção automática, pois moram em compose/stacks gerenciadas fora da ferramenta):

- **Redis** (`RDS-*`): sem senha (crítico se a porta 6379 estiver exposta), 6379
  publicada no host, protected-mode off.
- **Postgres** (`PG-*`): `POSTGRES_HOST_AUTH_METHOD=trust`, senha padrão/fraca,
  5432 publicada no host, imagem `:latest`. Senhas nunca são impressas.
- **Traefik** (`TRF-*`): `api.insecure=true` (dashboard sem auth), 8080 exposto,
  `exposedByDefault` não desligado, docker.sock montado read-write (prefira `:ro`).
- **n8n** (`N8N-*`): `N8N_ENCRYPTION_KEY` não fixado, sem autenticação,
  `N8N_SECURE_COOKIE=false`.
- **Portainer** (`PTR-*`): 9000 (HTTP) publicado direto em vez de atrás do Traefik.

## Consciência de backup

Configure `BACKUP_WATCH` no config com os caminhos dos seus backups e a idade máxima
aceitável (`caminho:dias`). O audit alerta (`BKP-001`) se um backup está velho ou
ausente. Se você tem volumes de dados (Postgres/n8n) mas não configurou `BACKUP_WATCH`,
o audit avisa (`BKP-002`).

```bash
BACKUP_WATCH="/var/backups/pg:2 /var/backups/n8n:2"
```

## Saúde de containers

O monitor detecta e alerta no n8n quando um container do baseline **cai**
(`container_down`), fica **unhealthy** (`container_unhealthy`) ou entra em **loop de
reinício** (`container_restart_loop`) — útil para saber na hora se o Postgres ou o n8n
parou. Após parar/remover um container de propósito, rode
`vps-sec baseline update --containers` para o monitor não alertar `container_down`.

## Monitoramento e alertas

O serviço `vps-sec-monitor` roda dois loops:

1. **journald em tempo real** (`journalctl -f --cursor-file`, sobrevive a rotação e
   restart): login SSH, brute force (agregado por IP), novo usuário, falha de sudo.
2. **state-scan** (a cada 60s): nova porta em escuta, novo container, UFW desativado,
   integridade (sha256) de arquivos críticos.

**Anti-flood**: alertas repetidos da mesma chave são deduplicados por cooldown
(15 min) e há um teto global por hora — ao estourar, um único `alert_storm` é enviado.
Brute force nunca vira enxurrada: já é agregado em um alerta com a contagem.

Se o webhook estiver fora do ar, os alertas vão para um **spool** em disco e são
reenviados depois. O **digest diário** (08:00) também serve de **heartbeat**: se um host
parar de enviá-lo, o n8n pode alertar que o host/agente caiu.

### Payload enviado ao webhook

```json
{
  "schema_version": 1,
  "event_type": "ssh_login_success",
  "severity": "info",
  "hostname": "vps-n8n-01",
  "timestamp": "2026-07-21T15:04:05Z",
  "agent_version": "0.1.0",
  "event_id": "abc123...",
  "details": { "user": "deploy", "ip": "203.0.113.7", "method": "publickey" },
  "suggested_action": "Se não reconhece este acesso, rotacione chaves e revise o host",
  "suppressed_since_last": 0
}
```

`event_type` possíveis: `ssh_login_success`, `ssh_auth_burst`, `new_user`,
`sudo_auth_failure`, `file_integrity`, `new_listening_port`, `new_docker_container`,
`container_down`, `container_unhealthy`, `container_restart_loop`,
`ufw_disabled`, `audit_finding`, `harden_applied`, `harden_rollback`, `alert_storm`,
`digest`, `agent_start`, `test`.

Os findings de aplicação (`RDS-*`, `PG-*`, `TRF-*`, `N8N-*`, `PTR-*`) e de backup
(`BKP-*`) não têm event_type próprio: quando são `critical`/`high`, viajam dentro de
`audit_finding.details.check_id`.

### Sugestão de workflow no n8n

1. **Webhook** (POST) → recebe o JSON.
2. **Switch** por `event_type` (ou **IF** por `severity`).
3. Roteie: `critical`/`high` → notificação imediata (Telegram/Discord/email);
   `digest` → uma mensagem-resumo por host; demais → log/planilha.
4. **Heartbeat**: um workflow com **Schedule** diário que verifica se cada host
   enviou o `digest` nas últimas ~26h; se faltar, alerta "host silencioso".

---

## Arquivos no sistema

| Caminho | Conteúdo |
|---|---|
| `/opt/vps-sec/` | código |
| `/etc/vps-sec/config` | configuração (chmod 600, root) |
| `/var/lib/vps-sec/` | baselines, spool de alertas, dedup, cursor do journal |
| `/var/log/vps-sec/` | relatórios de audit, log do monitor |
| `/var/backups/vps-sec/<ts>/` | backups do harden (retenção: 20) |

---

## Desinstalação

```bash
sudo vps-sec uninstall            # remove código e serviços; preserva config/logs/backups
sudo /opt/vps-sec/uninstall.sh --purge   # remove tudo (mantém só os backups)
```

O hardening já aplicado **não** é revertido pela desinstalação. Reverta antes com
`vps-sec rollback last` se necessário.

---

## Segurança do próprio agente

- Config lida como root só se pertencer a root e não for gravável por outros.
- URL do webhook enviada via stdin do `curl` (invisível em `ps`), nunca logada.
- Linhas de log são tratadas como dados (sem `eval`); payloads montados com `jq --arg`.
- Serviço systemd com `NoNewPrivileges`, `ProtectHome`, `PrivateTmp`.
