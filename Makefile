# SPDX-License-Identifier: Apache-2.0
#
# Nanda Town developer Makefile.
#
# The single most important target here is `ci-local`. It runs the EXACT
# sequence of commands that .github/workflows/ci.yml executes, in the same
# order, and hard-fails on the first red command. Run it before every push.
.DEFAULT_GOAL := help
.PHONY: help ci-local ci-dashboard hooks test-fast clean
help: ## List available targets.
	@echo "Nanda Town developer targets:"
	@echo ""
	@echo "  make ci-local      Run the full Python CI sequence locally."
	@echo "  make ci-dashboard  Run nest-dashboard typecheck, lint, and build."
	@echo "  make test-fast     Run pytest excluding slow tests."
	@echo "  make clean         Remove build artifacts and coverage output."
	@echo "  make hooks         Install pre-commit hooks."
	@echo ""
	@echo "  make help          Show this message."
ci-local: ## Run the exact Python CI command sequence; hard-fail on the first red command.
	@echo ">>> [1/9] uv sync --frozen"
	uv sync --frozen
	@echo ">>> [2/9] uv run ruff check ."
	uv run ruff check .
	@echo ">>> [3/9] uv run ruff format --check ."
	uv run ruff format --check .
	@echo ">>> [4/9] uv run python scripts/generate_hackathon_types.py --check"
	uv run python scripts/generate_hackathon_types.py --check
	@echo ">>> [5/9] uv run python scripts/check_hackathon_data.py"
	uv run python scripts/check_hackathon_data.py
	@echo ">>> [6/9] uv run pyright"
	uv run pyright
	@echo ">>> [7/9] uv run pip-audit"
	uv run pip-audit
	@echo ">>> [8/9] uv run bandit -r packages/ -c pyproject.toml"
	uv run bandit -r packages/ -c pyproject.toml
	@echo ">>> [9/9] uv run pytest -v -m \"not slow\""
	uv run pytest -v -m "not slow"
	@echo ""
	@echo "ci-local: all Python checks passed. Safe to push."
test-fast: ## Run fast tests only (exclude @pytest.mark.slow).
	uv run pytest -v -m "not slow"
clean: ## Remove dist/, coverage, and trace artifacts.
	uv run python -c "import pathlib, shutil; [shutil.rmtree(p, ignore_errors=True) for p in ('dist','htmlcov','.pytest_cache','traces')]; pathlib.Path('.coverage').unlink(missing_ok=True)"
ci-dashboard: ## Run nest-dashboard frontend CI (typecheck, lint, build).
	cd apps/nest-dashboard && npm ci && npm run ci
hooks: ## Install pre-commit hooks defined in .pre-commit-config.yaml.
	uv run --with pre-commit pre-commit install
	@echo "pre-commit hooks installed. Hooks will run automatically on 'git commit'."
