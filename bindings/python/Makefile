# QUAC 100 Python SDK - Makefile
# Build automation for development and deployment

.PHONY: help install install-dev test lint format typecheck docs clean build publish

PYTHON ?= python3
PIP ?= pip

# Default target
help:
	@echo "QUAC 100 Python SDK - Build Targets"
	@echo ""
	@echo "Development:"
	@echo "  install        Install package in development mode"
	@echo "  install-dev    Install with development dependencies"
	@echo "  test           Run test suite"
	@echo "  lint           Run linting checks"
	@echo "  format         Format code with black"
	@echo "  typecheck      Run mypy type checking"
	@echo ""
	@echo "Documentation:"
	@echo "  docs           Build Sphinx documentation"
	@echo ""
	@echo "Build & Publish:"
	@echo "  clean          Remove build artifacts"
	@echo "  build          Build distribution packages"
	@echo "  publish-test   Upload to TestPyPI"
	@echo "  publish        Upload to PyPI"
	@echo ""
	@echo "Examples:"
	@echo "  run-basic      Run basic example"
	@echo "  run-kem        Run KEM example"
	@echo "  run-sign       Run signature example"
	@echo "  run-hash       Run hash example"
	@echo "  run-random     Run random example"

# Installation
install:
	$(PIP) install -e .

install-dev:
	$(PIP) install -e ".[dev]"
	$(PIP) install -r requirements-dev.txt

# Testing
test:
	$(PYTHON) -m pytest tests/ -v

test-cov:
	$(PYTHON) -m pytest tests/ -v --cov=quantacore --cov-report=html --cov-report=term

test-quick:
	$(PYTHON) -m pytest tests/ -v -x --tb=short

# Code Quality
lint:
	$(PYTHON) -m flake8 quantacore/ tests/
	$(PYTHON) -m isort --check-only quantacore/ tests/

format:
	$(PYTHON) -m black quantacore/ tests/ examples/
	$(PYTHON) -m isort quantacore/ tests/ examples/

typecheck:
	$(PYTHON) -m mypy quantacore/

# Documentation
docs:
	cd docs && make html

docs-serve:
	cd docs/_build/html && $(PYTHON) -m http.server 8000

# Clean
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf docs/_build/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete

# Build
build: clean
	$(PYTHON) -m build

# Publishing
publish-test: build
	$(PYTHON) -m twine upload --repository testpypi dist/*

publish: build
	$(PYTHON) -m twine upload dist/*

# Version check
check-version:
	$(PYTHON) -c "import quantacore; print(f'Version: {quantacore.__version__}')"

# Run examples
run-basic:
	$(PYTHON) examples/basic_example.py

run-kem:
	$(PYTHON) examples/kem_example.py

run-sign:
	$(PYTHON) examples/sign_example.py

run-hash:
	$(PYTHON) examples/hash_example.py

run-random:
	$(PYTHON) examples/random_example.py

run-all-examples: run-basic run-kem run-sign run-hash run-random

# Pre-commit setup
pre-commit-install:
	pre-commit install

pre-commit-run:
	pre-commit run --all-files

# Development environment setup
dev-setup: install-dev pre-commit-install
	@echo "Development environment ready!"

# Full CI check
ci: lint typecheck test
	@echo "All CI checks passed!"