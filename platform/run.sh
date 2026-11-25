#!/bin/sh
# Run the AstraTravel demo platform on http://localhost:8000
# (uses the venv in this directory; run `python3 -m venv venv &&
#  venv/bin/pip install -r requirements.txt` first if it does not exist)
cd "$(dirname "$0")"
exec ./venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
