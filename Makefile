# takestock: the whole gate. Standard library only, so no virtualenv is needed yet.
PY ?= python3

.PHONY: check guard test hooks

check: guard test

guard:
	$(PY) tools/guard.py

test:
	$(PY) -m unittest discover -s tests -v

# Once per clone: run the guard on every commit and every commit message.
hooks:
	git config core.hooksPath .githooks
