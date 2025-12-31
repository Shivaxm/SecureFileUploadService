.PHONY: install format lint test up down migrate revision reset worker logs

install:
	pip install -r requirements.txt

format:
	black app tests

lint:
	ruff check app tests

test:
	pytest -q

reset:
	docker compose down -v

worker:
	python -m app.workers.rq_worker

up:
	docker compose up --build

down:
	docker compose down -v

logs:
	docker compose logs -f

migrate:
	docker compose run --rm -e PYTHONPATH=/app api alembic upgrade head

revision:
	alembic revision -m "auto" --autogenerate

