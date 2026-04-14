PYTHON := ../.venv/bin/python

.PHONY: proto test lint run-services run-gateway gen-rsa

proto:
	$(PYTHON) scripts/generate_protos.py

test:
	$(PYTHON) -m pytest tests

lint:
	$(PYTHON) -m ruff check src tests

run-services:
	$(PYTHON) -m ntgram.main_services --service all

run-gateway:
	$(PYTHON) -m ntgram.main_gateway

gen-rsa:
	$(PYTHON) scripts/generate_rsa_keys.py
