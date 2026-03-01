#!/bin/bash
# Trojan launcher - sets library path before executing
# Required libraries path for Debian/Ubuntu x86_64

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export LD_LIBRARY_PATH="/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH"

exec "$SCRIPT_DIR/build/trojan" "$@"
