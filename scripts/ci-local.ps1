# SPDX-License-Identifier: Apache-2.0
# Nanda Town local CI for Windows (mirrors Makefile ci-local / .github/workflows/ci.yml).
# Usage: .\scripts\ci-local.ps1
# Hard-fails on the first red command.

$ErrorActionPreference = "Stop"

function Step([string]$Label, [scriptblock]$Action) {
    Write-Host ">>> $Label"
    & $Action
    if ($LASTEXITCODE -ne 0) {
        Write-Error "ci-local failed at: $Label (exit $LASTEXITCODE)"
        exit $LASTEXITCODE
    }
}

Step "[1/5] uv sync" { uv sync }
Step "[2/5] uv run ruff check ." { uv run ruff check . }
Step "[3/5] uv run ruff format --check ." { uv run ruff format --check . }
Step "[4/5] uv run pyright" { uv run pyright }
Step "[5/5] uv run pytest -v" { uv run pytest -v }

Write-Host ""
Write-Host "ci-local: all 5 checks passed. Safe to push."
