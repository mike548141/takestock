# takestock: the whole gate. The guard runs first and needs only the standard
# library; lint, type checks and tests run from the project virtualenv.
PY ?= python3
VENV ?= .venv
VPY := $(VENV)/bin/python

.PHONY: check guard lint types test venv hooks

check: guard lint types test

guard:
	$(PY) tools/guard.py

lint:
	$(VPY) -m ruff check src tests tools

types:
	$(VPY) -m mypy src

test:
	$(VPY) -m pytest -q

# Once per clone: a virtualenv with the package installed in editable mode.
venv:
	$(PY) -m venv $(VENV)
	$(VPY) -m pip install -e '.[dev]'

# Once per clone: run the guard on every commit and every commit message.
hooks:
	git config core.hooksPath .githooks
