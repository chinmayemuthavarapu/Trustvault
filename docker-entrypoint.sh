#!/bin/sh
set -e
# Seed demo accounts and documents the first time (only if the database has no users).
if [ "${TV_SEED_ON_START:-0}" = "1" ]; then
  python -m scripts.seed
fi
# ONE process: the rate limiter is in memory and SQLite has one writer.
# Threads give concurrency; BEGIN IMMEDIATE serialises writes and audit appends.
exec gunicorn wsgi:app --bind "0.0.0.0:${PORT:-8000}" --workers 1 --threads 8 \
  --timeout 60 --limit-request-line 4094 --access-logfile -
