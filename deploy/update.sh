#!/usr/bin/env bash
# 一键更新脚本：拉取最新代码 → 安装依赖 → 重启 worker
#
# 用法:
#   bash deploy/update.sh              # 使用 supervisord
#   bash deploy/update.sh systemd      # 使用 systemd
set -euo pipefail

cd "$(dirname "$0")/.."
MODE="${1:-supervisor}"

echo "==> Pulling latest code …"
git pull --ff-only

echo "==> Installing dependencies …"
conda run -n skill pip install -e ".[worker]" --quiet

echo "==> Restarting workers …"
if [ "$MODE" = "systemd" ]; then
    sudo systemctl restart scan-worker
    sleep 2
    sudo systemctl status scan-worker --no-pager
else
    supervisorctl -c deploy/supervisord.conf restart scan-worker
    sleep 2
    supervisorctl -c deploy/supervisord.conf status
fi

echo "==> Update complete"
