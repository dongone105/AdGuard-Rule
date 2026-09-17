#!/usr/bin/env bash
#
# 重启本地 SmartDNS 进程，用于长时间 DNS 校验任务中定期刷新守护进程状态，
# 防止其在几万个域名的长跑场景里状态退化（连接数/内存/缓存内部状态等）。
#
# 参考 217heidai/adblockfilters-modified 的 __restart_smartdns，思路一致：
# 处理满一批域名后，先 SIGTERM 优雅关闭旧进程（给它机会把 cache-persist 缓存落盘），
# 拿不到响应再 SIGKILL 兜底，然后用同一份二进制/配置重新拉起，等它在 5053 端口重新应答。
#
# 由 Java 侧 DnsRuleFilter 通过 application.yml 的
#   application.dns.restart-command: ${SMARTDNS_PATH:/tmp/smartdns}/restart-smartdns.sh
# 以 `sh -c "$restartCommand"` 的方式调用，同步等待本脚本退出。
#
# 依赖以下由 CI workflow（.github/workflows/auto-update.yml 的 Setup SmartDNS 步骤）
# 提前准备在 $SMARTDNS_PATH 下的文件：
#   smartdns        - 可执行文件
#   smartdns.conf   - 配置文件（从 config/smartdns.conf 拷贝而来）
#   smartdns.pid    - 当前正在运行的进程 pid（本脚本会读取并覆盖写入新 pid）
#
# 退出码：0 = 重启后已就绪；非 0 = 重启失败或超时未就绪。
# 调用方（DnsRuleFilter）只把非 0 当作警告记录，不会中断本轮 DNS 校验。

set -uo pipefail

SMARTDNS_PATH="${SMARTDNS_PATH:-/tmp/smartdns}"
BIN="$SMARTDNS_PATH/smartdns"
CONF="$SMARTDNS_PATH/smartdns.conf"
PIDFILE="$SMARTDNS_PATH/smartdns.pid"
LOGFILE="$SMARTDNS_PATH/smartdns.log"
PORT=5053
STOP_WAIT_SECONDS=10
READY_WAIT_SECONDS=60

log() {
  echo "[restart-smartdns] $*"
}

if [ ! -x "$BIN" ]; then
  log "找不到可执行文件 $BIN，跳过重启"
  exit 1
fi
if [ ! -f "$CONF" ]; then
  log "找不到配置文件 $CONF，跳过重启"
  exit 1
fi

# 1. 优雅停掉旧进程（若还活着），给它机会把 cache-persist 缓存落盘
if [ -f "$PIDFILE" ]; then
  OLD_PID="$(cat "$PIDFILE" 2>/dev/null || true)"
  if [ -n "${OLD_PID:-}" ] && kill -0 "$OLD_PID" 2>/dev/null; then
    log "停止旧进程 (pid=$OLD_PID)"
    kill -TERM "$OLD_PID" 2>/dev/null || true
    for _ in $(seq 1 "$STOP_WAIT_SECONDS"); do
      kill -0 "$OLD_PID" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$OLD_PID" 2>/dev/null; then
      log "旧进程 ${STOP_WAIT_SECONDS}s 内未退出，强制 kill"
      kill -KILL "$OLD_PID" 2>/dev/null || true
    fi
  fi
fi

# 2. 用同一份二进制/配置重新拉起
nohup "$BIN" -f -x -c "$CONF" >> "$LOGFILE" 2>&1 &
NEW_PID=$!
echo "$NEW_PID" > "$PIDFILE"
log "已拉起新进程 (pid=$NEW_PID)"

# 3. 等待重新在 5053 端口应答
for i in $(seq 1 "$READY_WAIT_SECONDS"); do
  if dig @127.0.0.1 -p "$PORT" example.com A +time=2 +tries=1 +short > /dev/null 2>&1; then
    log "重启完成，已就绪 (pid=$NEW_PID)"
    exit 0
  fi
  sleep 1
done

log "重启后 ${READY_WAIT_SECONDS}s 内仍未就绪，dump 最近日志："
tail -n 50 "$LOGFILE" 2>/dev/null || true
exit 1
