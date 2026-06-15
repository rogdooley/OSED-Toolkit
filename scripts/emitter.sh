#!/usr/bin/env bash
cd "$(dirname "${BASH_SOURCE[0]}")/../Exploits/windows_x86/Tools"
exec python3 -m emitter.build "$@"
