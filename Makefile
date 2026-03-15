# rttp Makefile
#
# All targets delegate to makefile.py for cross-platform compatibility.
# Prerequisites: python3 + pip install rich
#
# Quick-install rich:  pip install rich

PY := python

.PHONY: all full build test doctest lint fmt fmt-check check clean doc doc-build \
        audit deny coverage run watch watch-test bacon ci help

all: help

help:
	@$(PY) makefile.py help

full:
	@$(PY) makefile.py full

build:
	@$(PY) makefile.py build

test:
	@$(PY) makefile.py test

doctest:
	@$(PY) makefile.py doctest

lint:
	@$(PY) makefile.py lint

fmt:
	@$(PY) makefile.py fmt

fmt-check:
	@$(PY) makefile.py fmt-check

check:
	@$(PY) makefile.py check

clean:
	@$(PY) makefile.py clean

doc:
	@$(PY) makefile.py doc

doc-build:
	@$(PY) makefile.py doc-build

audit:
	@$(PY) makefile.py audit

deny:
	@$(PY) makefile.py deny

coverage:
	@$(PY) makefile.py coverage

run:
	@$(PY) makefile.py run

watch:
	@$(PY) makefile.py watch

watch-test:
	@$(PY) makefile.py watch-test

bacon:
	@$(PY) makefile.py bacon

ci:
	@$(PY) makefile.py ci
