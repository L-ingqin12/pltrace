#!/bin/bash
# 快速启动 pltrace 的便捷脚本
# Usage: ./run_pltrace.sh [command] [args...]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
exec python3 -m pltrace.main "$@"
