#!/usr/bin/env python3
"""A bring-your-own-agent seller, in plain standard-library Python.

Proof that the town contract is runtime-neutral: no nandatown import,
no third-party dependency. It joins a run, claims quote requests under
a lease, applies each exactly once, responds, and acknowledges.

Run it through the town:

    nandatown test-agent --role seller --cmd "python examples/byoa_seller.py"

or start it yourself with TOWN_URL, RUN_ID, NAME, TOKEN in the
environment (nandatown test-agent --wait prints them).

It joins with the run's join token. Under --identity the town pins each
role to a portable identity and hands out TOWN_GRANT instead; joining
then needs an Ed25519 session proof (see nandatown.client
join_with_grant), which plain standard-library Python cannot produce, so
this example is for token runs only.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

TOWN = os.environ["TOWN_URL"]
RUN = os.environ["RUN_ID"]
NAME = os.environ["NAME"]
TOKEN = os.environ["TOKEN"]
DEADLINE = time.time() + float(os.environ.get("DEADLINE", "45"))

session = None
processed = {}


def call(method, path, body=None, retry=True):
    url = f"{TOWN}/runs/{RUN}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if session:
        req.add_header("X-Town-Session", session)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 204:
                return None
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        if exc.code == 503 and retry:
            time.sleep(0.2)
            return call(method, path, body, retry=False)
        raise


def main():
    global session
    joined = call("POST", "/join", {"name": NAME, "token": TOKEN})
    session = joined["session"]

    while time.time() < DEADLINE:
        call("GET", "/inbox/notify?wait=0.4")
        claim = call("POST", "/inbox/claim")
        if claim is None:
            continue
        mid = claim["message_id"]
        if claim["kind"] != "quote_request":
            call("POST", "/inbox/ack",
                 {"message_id": mid, "fence": claim["fence"],
                  "status": "rejected", "note": {"reason": "unknown kind"}})
            continue
        if mid in processed:
            call("POST", "/messages", processed[mid])
            call("POST", "/inbox/ack",
                 {"message_id": mid, "fence": claim["fence"],
                  "status": "processed", "note": {"duplicate": True}})
            continue
        body = claim["body"]
        total = body["quantity"] * body["unit_price_cents"]
        reply = {"message_id": "r-" + mid.removeprefix("q-"),
                 "to": claim["from"], "kind": "quote_response",
                 "body": {"request_id": mid, "total_cents": total}}
        call("POST", "/messages", reply)
        processed[mid] = reply
        call("POST", "/inbox/ack",
             {"message_id": mid, "fence": claim["fence"],
              "status": "processed",
              "note": {"applied": True, "total_cents": total,
                       "runtime": "byoa-stdlib"}})
    return 0


if __name__ == "__main__":
    sys.exit(main())
