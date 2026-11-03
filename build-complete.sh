#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
exec python3 "$ROOT/scripts/build_complete.py" "$@"
