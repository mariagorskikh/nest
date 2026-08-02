#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Run Agent Heist scenario with a random seed based on current time.

SEED=${1:-$(date +%s | tail -c 6)}
echo "Running Agent Heist with seed: $SEED"

nest run scenarios/agent_heist/agent_heist.yaml \
    --seed "$SEED" \
    -o reports/agent_heist.jsonl

# Generate HTML report
nest report reports/agent_heist.jsonl --output reports/agent_heist.html

echo ""
echo "Reports generated:"
echo "  - reports/agent_heist.html"
echo "  - reports/agent_heist.jsonl"
