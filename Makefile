.PHONY: keys decrypt web build

PYTHON ?= .venv/bin/python3

build:
	cc -O2 -o bin/find_all_keys_macos c_src/find_all_keys_macos.c -framework Foundation
	codesign -s - bin/find_all_keys_macos

keys:
	sudo ./bin/find_all_keys_macos

decrypt:
	$(PYTHON) main.py decrypt

web:
	$(PYTHON) main.py
