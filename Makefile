.PHONY: install format lint test up down migrate revision

install:
\tpip install -r requirements.txt

format:
\tblack app tests

lint:
\truff check app tests

test:
\tpytest -q

up:
\tdocker compose up --build

down:
\tdocker compose down -v

migrate:
\talembic upgrade head

revision:
\talembic revision -m "auto" --autogenerate

