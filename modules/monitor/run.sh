#!/usr/bin/env bash
# modules/monitor/run.sh — daemon de monitoramento (dois loops num só serviço).
# `monitor run` é o ExecStart do systemd. Carregado via `source`.

monitor_main() {
  local sub="${1:-status}"; shift || true
  case "$sub" in
    run)    monitor_run ;;
    status) monitor_status ;;
    log)    tail -n "${1:-100}" "$VPS_SEC_LOG_DIR/monitor.log" 2>/dev/null \
              || echo "(sem log ainda)" ;;
    start)  systemctl start vps-sec-monitor.service && ok "monitor iniciado" ;;
    stop)   systemctl stop vps-sec-monitor.service && ok "monitor parado" ;;
    *) die "monitor: subcomando desconhecido '$sub' (use: run|status|log|start|stop)" ;;
  esac
}

monitor_status() {
  echo "── vps-sec monitor ──"
  if systemctl is-active --quiet vps-sec-monitor.service 2>/dev/null; then
    ok "serviço: ativo"
    systemctl status vps-sec-monitor.service --no-pager -n 0 2>/dev/null \
      | grep -E 'Active:|Main PID:' || true
  else
    warn "serviço: inativo"
  fi
  local spool; spool="$(find "$VPS_SEC_STATE/spool" -type f -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"
  echo "alertas em spool: ${spool:-0}"
  if [[ -f "$VPS_SEC_LOG_DIR/monitor.log" ]]; then
    echo "últimos eventos:"
    tail -n 8 "$VPS_SEC_LOG_DIR/monitor.log" 2>/dev/null | sed 's/^/  /'
  fi
}

# Loop principal: dispara o state-scan em background e segue no journal-watch
# em foreground (que é o processo "vivo" do serviço).
monitor_run() {
  require_cmd jq
  ensure_dirs
  # shellcheck source=/dev/null
  . "$VPS_SEC_MODULES/monitor/state-scan.sh"
  # shellcheck source=/dev/null
  . "$VPS_SEC_MODULES/monitor/journal-watch.sh"

  log_file "monitor iniciado (pid $$)" "$VPS_SEC_LOG_DIR/monitor.log"
  alert_send "agent_start" "info" \
    "$(jq -n --arg v "$(cat "$VPS_SEC_PREFIX/VERSION" 2>/dev/null)" '{message:"Monitor vps-sec iniciado", version:$v}')" \
    "" "agent_start" 2>/dev/null || true

  # Encerramento limpo mata o filho do scan.
  _scan_pid=""
  trap '[[ -n "$_scan_pid" ]] && kill "$_scan_pid" 2>/dev/null; log_file "monitor encerrado" "$VPS_SEC_LOG_DIR/monitor.log"; exit 0' TERM INT

  # Loop 2 (state-scan) em background.
  ( monitor_scan_loop ) &
  _scan_pid=$!

  # Loop 1 (journal-watch) em foreground — mantém o serviço vivo.
  monitor_journal_loop
}
