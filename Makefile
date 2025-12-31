.PHONY: install format lint test up down migrate revision

install:
\tpip install -r requirements.txt

format:
\tblack app tests

lint:
\truff check app tests

test:
\tpytest -q

worker:
\tpython -m app.workers.rq_worker

up:
\tdocker compose up --build

down:
\tdocker compose down -v

logs:
\tdocker compose logs -f

migrate:
\talembic upgrade head

revision:
\talembic revision -m "auto" --autogenerate

