#!/usr/bin/env bash
# StreamPay — Live API Demo
# Just run: ./streampay/demo.sh

set -e
BASE="https://steamplay.onrender.com"
SEPARATOR="=============================================="

bold()  { printf "\033[1m%s\033[0m\n" "$1"; }
green() { printf "\033[32m%s\033[0m\n" "$1"; }

clear
bold "$SEPARATOR"
bold "  StreamPay — Metered Streaming Payments for AI Agents"
bold "  NandaHack 2026 · stripe-engineer"
bold "$SEPARATOR"

echo ""
bold "1. Health check"
curl -s "$BASE/health" | python3 -m json.tool
echo ""

bold "2. Alice opens a stream to pay Bob for compute rental"
echo "   (rate: 2 credits/tick, max: 20 credits)"
curl -s -X POST "$BASE/streams" \
  -H "Content-Type: application/json" \
  -d '{"stream_id":"demo","payer":"alice","payee":"bob","rate_per_tick":2,"max_total":20}' \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'   Opened!  Debited: {d[\"total_debited\"]}, Remaining: {d[\"remaining\"]}, Open: {d[\"is_open\"]}')
"
echo ""

bold "3. Alice drains tick by tick while Bob computes"
for t in 1 2 3; do
  echo "   Tick $t:"
  curl -s -X POST "$BASE/streams/demo/tick" \
    -H "Content-Type: application/json" \
    -d "{\"tick\":$t}" \
    | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'     Debited: {d[\"total_debited\"]}, Remaining: {d[\"remaining\"]}')
"
done
echo ""

bold "4. Task done — Alice closes the stream"
curl -s -X POST "$BASE/streams/demo/close" \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)
r = d['receipt']
print(f'   Closed!  Paid: {r[\"amount\"]} credits, Status: {r[\"status\"]}')
"
echo ""

bold "5. Receipt — verifiable proof of payment"
curl -s "$BASE/streams/demo/receipt" | python3 -m json.tool
echo ""

green "$SEPARATOR"
green "  9 endpoints · idempotent · deployed on Render"
green "  GitHub: github.com/stanleyoz/nandatown"
green "  Skills: nandatown.projectnanda.org/skills"
green "  API:    steamplay.onrender.com"
green "$SEPARATOR"