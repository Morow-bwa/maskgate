#!/usr/bin/env sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"

if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install --upgrade 'pip>=26.2.1'
.venv/bin/python -m pip install -e '.[dev,media]'

cd playground-react
if command -v pnpm >/dev/null 2>&1; then
  pnpm install --frozen-lockfile
  pnpm build
elif command -v corepack >/dev/null 2>&1; then
  corepack pnpm install --frozen-lockfile
  corepack pnpm build
else
  echo 'Node.js 22 with pnpm or corepack is required.' >&2
  exit 1
fi

echo 'MaskGate dependencies and Playground are ready.'
