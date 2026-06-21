.PHONY: help install dev test clean

help:
	@echo "install  - install the package (pip install -e .)"
	@echo "dev      - install with dev extras (pytest)"
	@echo "test     - run the test suite"
	@echo "clean    - remove caches and build artifacts"

install:
	python -m pip install -e .

dev:
	python -m pip install -e ".[dev]"

test:
	python -m pytest

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
