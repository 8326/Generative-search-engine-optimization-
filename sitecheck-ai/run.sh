#!/usr/bin/env bash
cd "$(dirname "$0")/backend"
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt
(sleep 2; (xdg-open http://localhost:8000 || open http://localhost:8000) >/dev/null 2>&1) &
uvicorn main:app --port 8000
