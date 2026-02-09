#!/usr/bin/env bash

# systemctl stop mercedes.service
source venv/bin/activate
uvicorn MERCEDES:app --host 0.0.0.0 --port 9000 --reload
