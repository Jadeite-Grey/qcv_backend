#!/bin/bash
set -e
python3 manage.py collectstatic --noinput
python3 manage.py migrate
python3 manage.py bootstrap_admin
exec gunicorn qcv_backend.wsgi:application --bind 0.0.0.0:8000
