#!/bin/sh
# Пересобрать оба lockfile с хешами (нужен pip-tools, см. requirements-dev.in).
# Запускать после изменения pyproject.toml/requirements*.in; CI-джоб `lock` проверяет,
# что lock не разошёлся с .in и не потерял хеши.
set -eu
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"
"$PYTHON" -m piptools compile --quiet --generate-hashes \
    --output-file=requirements.lock requirements.in
"$PYTHON" -m piptools compile --quiet --generate-hashes \
    --output-file=requirements-dev.lock requirements-dev.in
"$PYTHON" scripts/check_lock.py \
    requirements.in requirements.lock requirements-dev.in requirements-dev.lock
