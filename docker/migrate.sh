#!/bin/sh
# One-shot set-up job (the `migrate` service). Runs with the OWNER connection and is the only container that has it.
#   1. Week 4 schema, 2. Week 5 job queue schema, 3. the two least-privilege login roles. Safe to run again: every step is idempotent.
# Passwords come from the environment; nothing is echoed. Exit code is non-zero on the first failure (set -e).
set -eu
python -m week4.db.migrate apply
python -m week5.db.migrate apply
python -m week4.db.admin create-api-login
python -m week5.db.admin create-worker-login
python -m week5.db.migrate verify
echo "migrate: done"
