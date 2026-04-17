.PHONY: install test lint type bench run docker clean

install:
	pip install -e ".[dev,bench]"

test:
	pytest --cov=pwscore --cov-report=term-missing

lint:
	ruff check .
	ruff format --check .

fmt:
	ruff format .
	ruff check --fix .

type:
	mypy src/

bench:
	python benchmarks/benchmark.py

run:
	uvicorn pwscore.api:app --host 0.0.0.0 --port 8000 --reload

docker:
	docker build -t pwscore:dev -f docker/Dockerfile .

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
