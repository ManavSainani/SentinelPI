# Run from the repo root.
PY ?= .venv/bin/python

.PHONY: setup dev-backend dev-frontend test lint build run

setup:            ## Create venv, install backend + frontend deps
	python3 -m venv .venv
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -e "backend[dev]"
	cd frontend && npm install

dev-backend:      ## API on 127.0.0.1:8787
	$(PY) -m sentinelpi.main

dev-frontend:     ## Vite dev server on :5173 (proxies /api)
	cd frontend && npm run dev

test:             ## Backend tests
	cd backend && ../$(PY) -m pytest -q

lint:             ## Ruff + ESLint + typecheck
	cd backend && ../$(PY) -m ruff check . && ../$(PY) -m ruff format --check .
	cd frontend && npm run lint && npm run typecheck

build:            ## Build frontend (do this on the Mac)
	cd frontend && npm run build

run: build        ## Build UI, then serve everything from FastAPI
	$(PY) -m sentinelpi.main
