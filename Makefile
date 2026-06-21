.PHONY: help install install-dev lint format type-check test test-cov clean

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	pip install -r requirements.txt

install-dev: install ## Install development dependencies
	pip install -r requirements-dev.txt
	pre-commit install

lint: ## Run linter (ruff)
	ruff check .

format: ## Format code (ruff)
	ruff format .
	ruff check --fix .

type-check: ## Run type checker (mypy)
	mypy aegis.py

test: ## Run tests
	pytest tests/

test-cov: ## Run tests with coverage report
	pytest tests/ --cov=. --cov-report=term-missing --cov-report=html

clean: ## Remove build artifacts and caches
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache
	rm -rf dist build *.egg-info htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
