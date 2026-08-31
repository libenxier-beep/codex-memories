#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
python_command=${PYTHON:-python3}

exec "$python_command" "$script_dir/scripts/codex_memories.py" install "$@"
