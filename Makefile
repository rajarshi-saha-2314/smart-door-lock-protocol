# Thin wrapper around tasks.py so `make <target>` and `python tasks.py <target>` behave identically.
PY ?= python
DOOR ?= CSE-101

.PHONY: setup run-as run-dl demo attacks test lint proverif bench clean

setup:
	$(PY) tasks.py setup

run-as:
	$(PY) tasks.py run-as

run-dl:
	$(PY) tasks.py run-dl $(DOOR)

demo:
	$(PY) tasks.py demo

attacks:
	$(PY) tasks.py attacks

test:
	$(PY) tasks.py test

lint:
	$(PY) tasks.py lint

proverif:
	$(PY) tasks.py proverif

bench:
	$(PY) tasks.py bench

clean:
	$(PY) tasks.py clean
