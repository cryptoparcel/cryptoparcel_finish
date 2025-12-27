#!/usr/bin/env bash
set -e

echo "Starting Cryptoparcel..."

# Render provides the port number in the $PORT variable
PORT=${PORT:-10000}

echo "Using port: $PORT"

echo "Starting Gunicorn..."
exec gunicorn wsgi:application \
    --bind 0.0.0.0:$PORT \
    --workers 3 \
    --threads 2 \
    --timeout 120 \
    --log-level info \
    --access-logfile '-' \
    --error-logfile '-'
