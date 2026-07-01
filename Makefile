# SPDX-License-Identifier: Apache-2.0
#
# Nanda Town developer Makefile.
#
# The single most important target here is `ci-local`. It runs the EXACT
# sequence of commands that .github/workflows/ci.yml executes, in the same
# order, and hard-fails on the first red command. Run it before every push.

.DEFAULT_GOAL := help

.PHONY: help ci-local hooks

help: ## List available targets.
	@echo "Nanda Town developer targets:"
	@echo ""
	@echo "  make ci-local   Run the full CI sequence locally (sync, ruff check,"
	@echo "                  ruff format --check, pyright, pytest). Hard-fails on"
	@echo "                  the first red command. Run this before every push."
	@echo ""
	@echo "  make hooks      Install pre-commit hooks (ruff-format, ruff-check,"
	@echo "                  pyright) so violations are caught at commit time."
	@echo ""
	@echo "  make help       Show this message."

ci-local: ## Run the exact CI command sequence; hard-fail on the first red command.
	@echo ">>> [1/5] uv sync"
	uv sync
	@echo ">>> [2/5] uv run ruff check ."
	uv run ruff check .
	@echo ">>> [3/5] uv run ruff format --check ."
	uv run ruff format --check .
	@echo ">>> [4/5] uv run pyright"
	uv run pyright
	@echo ">>> [5/5] uv run pytest -v"
	uv run pytest -v
	@echo ""
	@echo "ci-local: all 5 checks passed. Safe to push."

hooks: ## Install pre-commit hooks defined in .pre-commit-config.yaml.
	uv run --with pre-commit pre-commit install
	@echo "pre-commit hooks installed. Hooks will run automatically on 'git commit'."

