.PHONY: sync lint format typecheck test selfcheck demo latency scenarios bench-smoke pilot check

sync:
	uv sync --locked

lint:
	uv run ruff check src tests research

format:
	uv run ruff format --check src tests research

typecheck:
	uv run mypy

test:
	uv run pytest

selfcheck:
	uv run ananke selfcheck --offline

demo:
	uv run ananke demo-gateway --offline --seed 42

latency:
	uv run python research/experiments/gateway_latency.py --rules 1000 --requests 1000

scenarios:
	uv run ananke bench verify-scenarios --root scenarios

bench-smoke:
	uv run ananke bench run --config research/experiments/smoke.json --offline

pilot:
	uv run ananke bench run --config research/experiments/pilot-dev.json --offline

check: lint format typecheck test selfcheck demo scenarios bench-smoke
