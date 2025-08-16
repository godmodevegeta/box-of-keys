.PHONY: help setup install test lint format clean dev docker-up docker-down migrate

help: ## Show this help message
	@echo "KeyHaven Pro - Development Commands"
	@echo "=================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Set up development environment
	@./scripts/setup.sh

install: ## Install Python dependencies
	pip install -r requirements.txt

test: ## Run tests
	pytest -v --cov=app --cov-report=term-missing

lint: ## Run linting
	flake8 app tests
	isort --check-only app tests

format: ## Format code
	black app tests
	isort app tests

clean: ## Clean up temporary files
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache
	rm -rf .coverage

dev: ## Start development server
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

docker-up: ## Start Docker services
	docker-compose up -d

docker-down: ## Stop Docker services
	docker-compose down

docker-logs: ## View Docker logs
	docker-compose logs -f

migrate: ## Run database migrations
	alembic upgrade head

migration: ## Create new migration
	@read -p "Enter migration message: " msg; \
	alembic revision --autogenerate -m "$$msg"

init-db: ## Initialize database
	python scripts/init_db.py