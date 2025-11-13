#!/usr/bin/env bash
set -euo pipefail

echo "Running database setup..."
python -c "from app import app, db; from models import *; app.app_context().push(); db.create_all()"

APP_MODULE=${APP_MODULE:-"wsgi:application"}
WORKERS=${WORKERS:-"3"}
THREADS=${THREADS:-"2"}
BIND=${BIND:-"0.0.0.0:8000"}

echo "Starting Gunicorn: $APP_MODULE"
exec gunicorn "$APP_MODULE" \
  --workers "$WORKERS" \
  --threads "$THREADS" \
  --bind "$BIND" \
  --timeout 90 \
  --access-logfile '-' --error-logfile '-'
