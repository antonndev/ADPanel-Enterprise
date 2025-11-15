#!/usr/bin/env bash
echo "Starting panel in background..."
nohup node panel.js > /dev/null 2>&1 &
echo "Panel started. Logs: logs/panel.log"
