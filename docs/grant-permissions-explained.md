# The town can now say no — and prove it said no

*A plain-language explainer for the `fix/enforce-grant-permissions` branch.*

## The one-sentence version

When an agent joins a test run with an ID badge that says what it is allowed
to do, the town now actually reads the badge. Before, it only checked that
the badge was real and then let the agent do anything.

## Background: how a run works

In a Track run, agents (a buyer and a seller) connect to a small server called
the **coordinator** and exchange work through a mailbox with four verbs:

| verb | HTTP route | meaning |
|---|---|---|
| `join` | `POST /runs/{run}/join` | enter the run, get a session |
| `send` | `POST /runs/{run}/messages` | put work in someone's inbox |
| `claim` | `POST /runs/{run}/inbox/claim` | take one piece of work under a lease |
| `ack` | `POST /runs/{run}/inbox/ack` | say what you did with it |

Every run ends in an **evidence bundle**: the list of things agents *tried*
(`intents.jsonl`), the list of things that *happened* (`events.jsonl`), and a
verdict computed from those events alone.

## The badge

With `nandatown run --identity`, an agent does not join with a plain token.
Its owner's long-lived key signs a short-lived **Run Grant** — a visitor badge
that says *"this agent, this run, allowed to: join, claim, send, ack."*

```python
# identity_portable.py — what the owner's key signs
grant = {
    "agent_id": "did:town:9f31…",
    "run_id": "run-3e19d8b4d545",
    "session_public": "…",          # a throwaway key just for this run
    "permissions": ["ack", "claim", "join", "send"],
    "issued_at": 1787950000.0,
    "expires_at": 1787953600.0,     # one hour later
}
```

The coordinator verifies the signature chain: the grant was signed by the
owner's key that was pinned when the run was created, it names this run, it
has not expired, and the joiner holds the session key inside it.

## The bug

After verifying all of that, the coordinator never looked at the
`permissions` list. The function to do it already existed:

```python
# coordinator.py, before this branch
def require_permission(run_id: str, name: str, permission: str):
    permissions = session_permissions.get((run_id, name))
    if permissions is not None and permission not in permissions:
        db.record_event(run_id, observer="town",
                        kind="grant_permission_denied", subject=name, ...)
        raise HTTPException(status_code=403, ...)
```

…but nothing called it:

```
$ grep -rn "require_permission" src/
src/nandatown/coordinator.py:78:    def require_permission(run_id: str, name: str, permission: str):
```

One definition, zero callers. A badge that said "claim and ack only" still let
the agent send. The README described a security feature that did not exist.

### Why it matters beyond the bug

The whole point of the town is to produce evidence about agent behaviour. The
team's "Test the Path" proposal says one of the key things to prove is
*"the agent did something it was told not to."* If the town never refuses
anything, there is no such thing as a refused action — and no evidence bundle
could ever contain one.

## What the branch does

### 1. Reads the badge on every action

`send`, `claim`, and `ack` now check the grant **after** recording the intent
and **before** doing anything else. The order is deliberate: the attempt is
evidence, so it is written down first; the refusal comes next; and nothing
downstream (no fault injection, no database write) runs on a refused action.

```python
# coordinator.py
@app.post("/runs/{run_id}/messages", status_code=202)
def send(run_id: str, body: SendBody, name: str = Depends(participant)):
    now = time.time()
    db.record_intent(run_id, actor=name, action="send",
                     payload=body.model_dump(), at=now)
    require_permission(run_id, name, "send", now)   # <- new
    state = fault_state(run_id)
    ...
```

A refusal is recorded as a town-observed event, then rejected:

```python
def deny(run_id: str, name: str, permission: str, now: float) -> None:
    """A refused action is evidence: record it, then refuse."""
    db.record_event(run_id, observer="town",
                    kind="grant_permission_denied", subject=name,
                    at=now, detail={"permission": permission})
    raise HTTPException(
        status_code=403,
        detail={"error": "grant_permission_denied",
                "permission": permission})
```

So a bundle can now contain this pair — *tried to send, was told no*:

```jsonc
// intents.jsonl
{"actor": "buyer", "action": "send", "payload": {"message_id": "q-1", ...}}
// events.jsonl
{"observer": "town", "kind": "grant_permission_denied",
 "subject": "buyer", "detail": {"permission": "send"}}
```

`join` is checked too, before any session is created. `GET /participants` and
`GET /inbox/notify` are deliberately left open: there is no such permission in
the vocabulary, and gating them would break every existing grant.

### 2. Does not forget on restart

The permissions used to live in a Python dict inside the server process.
Sessions live in SQLite. Restart the coordinator and the session was still
valid but the restriction was gone. Now the permissions are written in the
**same transaction** as the session:

```python
# db.py
def authenticate(self, run_id, name, token, now=0.0,
                 permissions=None, grant_issued_at=None):
    """... A grant's permissions are written in the same transaction, so
    a session never exists without the restrictions its grant named;
    None means a token join, which carries no grant."""
    permissions_json = (None if permissions is None
                        else json.dumps(sorted(permissions)))
    with self._conn() as conn:
        ...
        conn.execute(
            "UPDATE participants SET session=?, joined_at=?,"
            " permissions_json=?, grant_issued_at=?"
            " WHERE run_id=? AND name=?",
            (session, now, permissions_json, grant_issued_at, run_id, name))
```

Two small but important distinctions in that column:

| `permissions_json` | meaning |
|---|---|
| `NULL` | joined with a plain token — no grant, no restrictions |
| `'[]'` | joined with a grant that allows **nothing** |

The pinned identities got the same treatment (a `run_identities` table
instead of a dict), and older databases are upgraded in place:

```python
_PARTICIPANT_COLUMNS_ADDED = (("permissions_json", "TEXT"),
                              ("grant_issued_at", "REAL"))

@classmethod
def _migrate(cls, conn) -> None:
    columns = {row["name"] for row in
               conn.execute("PRAGMA table_info(participants)")}
    for column, declared in cls._PARTICIPANT_COLUMNS_ADDED:
        if column not in columns:
            conn.execute(f"ALTER TABLE participants ADD COLUMN {column} {declared}")
```

### 3. Closes the side doors

Three ways to slip past the badge, all now shut.

**Side door A — join with the plain token instead.** The runner used to hand
every agent both a token and a grant. An agent that simply ignored the grant
got an unrestricted session. Now a role that is pinned to an identity can only
join through its grant:

```python
def require_grant_for_pinned_role(run_id, name, token, now) -> None:
    if db.pinned_identity(run_id, name) is None:
        return                                     # unpinned: tokens are fine
    if token != db.join_token(run_id, name):
        raise HTTPException(status_code=403, detail="join rejected")
    db.record_event(run_id, observer="town", kind="grant_required",
                    subject=name, at=now, detail={"attempted": "token join"})
    raise HTTPException(status_code=403, detail={"error": "grant_required", ...})
```

(The `token != join_token` check matters: only the holder of the real token
leaves a mark in the evidence. Anyone who merely knows a run id cannot spam
events into an attested bundle.)

**Side door B — a badge with a broken permissions field.** A signed grant
whose `permissions` was `null` used to pass all the checks and produce a
fully unrestricted session; a string like `"acknowledged"` would have
matched `ack` by substring. The field is now validated before it is trusted:

```python
# identity_portable.py, inside verify_grant()
permissions = grant.get("permissions")
if not isinstance(permissions, list) \
        or not all(isinstance(p, str) for p in permissions):
    raise IdentityError("grant permissions must be a list of names")
```

And `make_grant(permissions=[])` now means *nothing*, not *everything*
(it used `permissions or DEFAULT_PERMISSIONS`, so an empty list fell through
to the full set).

**Side door C — replay an older, more generous badge.** If the owner issues a
wide grant, then a narrow one to rein the agent in, the agent could re-join
with the old wide grant (still signed, still unexpired) and be unrestricted
again. Now the grant's `issued_at` is recorded and an older grant never
replaces a newer one:

```python
def _not_older(issued_at, recorded) -> bool:
    """May a grant issued at issued_at replace the one recorded?"""
    if issued_at is None or recorded is None:
        return True
    return issued_at >= recorded
```

### 4. Keeps the runner in step

Two things in `runner.py` had to follow:

- When a role is played by an **external** agent, the credentials handed out
  now include `TOWN_GRANT` for pinned roles (previously only `TOKEN`, which
  the town now refuses).
- If an agent tries to token-join a pinned role, the run stops immediately
  with a runner-attributed event instead of waiting out the timeout:

```python
def _grant_refused(events) -> str | None:
    """The first role that tried to join a pinned identity with a bare
    token, or None. Such a harness can never join, so waiting is pointless."""
    for e in events:
        if e["kind"] == "grant_required":
            return e["subject"]
    return None
```

```
$ nandatown run quote-clean --identity --agent seller=cmd:"python examples/byoa_seller.py"
Verdict:   INCOMPLETE          # in ~1 second, with harness_refused_grant in the events
```

(The standard-library example agent joins with a token on purpose — a grant
join needs an Ed25519 signature, which plain Python cannot produce. The
example now says so in its docstring.)

### 5. Says so in the report

```
Events recorded: 14. Intents recorded: 6. Refused by grant permissions: 1.
```

## How we know it works

**Tests** — `tests/test_grant_permissions.py`, 23 of them. Each one pins a
specific claim. For example, a denial must not have side effects:

```python
def test_denied_send_leaves_drop_wakeup_fault_armed(town):
    ...
    seller = _join_with_grant(client, keystore, run_id, "seller",
                              permissions=["join", "claim", "ack"])   # no send

    assert _send(client, run_id, seller, to="buyer").status_code == 403
    assert _send(client, run_id, buyer).status_code == 202

    assert "notify_suppressed" in _kinds(client, run_id), \
        "the one-shot fault must fire on the first accepted send"
```

And restrictions must outlive the server process:

```python
def test_restrictions_and_pins_survive_a_coordinator_restart(tmp_path):
    with TestClient(build_app(db_path, admin_token="secret")) as first:
        ... join with a grant lacking "send" ...
        assert _send(first, run_id, buyer).status_code == 403

    with TestClient(build_app(db_path, admin_token="secret")) as restarted:
        assert _send(restarted, run_id, buyer, message_id="q-2").status_code == 403
```

Full suite: **181 passed**.

**Real runs** — the shipped participants always carry the full grant, so
nothing legitimate should change. These all still pass, including the one
where the seller crashes mid-task and re-joins through its grant:

```
nandatown run quote-clean --identity
nandatown run quote-crash-restart --identity
nandatown run quote-llm --identity
```

**Reviews** — three independent review passes. Each found something real
(the restart problem, the `null` bypass, the token side door), and each
finding was fixed before moving on.

## Try it yourself

There is no command-line flag yet to *make* a restricted grant, so this is
the by-hand version:

```python
from fastapi.testclient import TestClient
from nandatown.coordinator import build_app
from nandatown.identity_portable import Keystore, session_proof

client = TestClient(build_app("town.db", admin_token="secret"))
ks = Keystore("keys")
buyer = ks.new_identity("buyer")

# 1. create a run with the buyer's identity pinned
run = client.post("/runs", json={"profile": PROFILE, "identities": {
    "buyer": {"agent_id": buyer["agent_id"],
              "controller_public": buyer["controller_public"]}}},
    headers={"X-Town-Admin": "secret"}).json()

# 2. a badge that may join and claim, but not send
g = ks.make_grant("buyer", run["run_id"], permissions=["join", "claim"])
proof = session_proof(g["session_private"], run["run_id"], "buyer")
session = client.post(f"/runs/{run['run_id']}/join", json={
    "name": "buyer", "grant": g["grant"],
    "grant_signature": g["grant_signature"], "session_proof": proof,
}).json()["session"]

# 3. try to send anyway
r = client.post(f"/runs/{run['run_id']}/messages",
                json={"message_id": "q-1", "to": "seller",
                      "kind": "quote_request", "body": {}},
                headers={"X-Town-Session": session})
print(r.status_code, r.json())
# 403 {'detail': {'error': 'grant_permission_denied', 'permission': 'send'}}
```

## What is still open

- No `--permissions` flag on `nandatown identity grant` or the runner — today
  every shipped grant is the full set.
- Grants expire but cannot be revoked early.
- Spawned participants still receive a `TOKEN` even when pinned (harmless — the
  town refuses it — but a dead credential).

## If you remember one thing

**The town can now say no, and prove it said no.**

---

# Questions a first reader asked

## 1. What is the "ID badge"?

It is a nickname for the **Run Grant**: a small JSON document, signed by the
agent owner's long-lived key, that the agent presents when it joins a run.

```jsonc
{
  "agent_id": "did:town:9f31…",               // who this is
  "run_id": "run-3e19d8b4d545",               // which run it is valid for
  "session_public": "8a4c…",                  // a throwaway key, just for this run
  "permissions": ["ack", "claim", "join"],    // what it may do
  "issued_at": 1787950000.0,
  "expires_at": 1787953600.0                  // one hour later
}
```

Office-visitor analogy: security (the owner's key) issues a badge for one day
(one run), printed with the floors you may enter (permissions), and it only
works when *you* swipe it (the session key proves you hold it). The owner's
real key never leaves the owner; only the disposable session key goes to the
agent process.

## 2. Why does an agent need one?

Because of *who* the agent process is. Without a grant there are only two
options, and both are bad:

- **A plain token.** Anyone holding the token *is* the agent. There is no
  identity behind it, so the evidence cannot say whose agent did what, and a
  stolen token is a stolen role.
- **The owner's real key in the agent's environment.** That process might be
  a subprocess on a laptop, an LLM harness calling a hosted model, or someone
  else's code entirely. Put the long-lived key there and it leaks.

The grant threads the needle: the owner authorizes **one disposable key, for
one run, with a named scope**, and the coordinator checks that chain against
the owner's public key it pinned when the run was created. The bundle gets an
attributable identity (`portable_identity: Passed`) without the key that
matters ever being exposed.

## 3. Why must the coordinator read the permissions list?

Because it is the **only place enforcement can happen**. Every action an agent
takes (send, claim, ack) is an HTTP call to the coordinator. The agent itself
is untrusted: it might be a third-party bring-your-own-agent process, or a
model that got confused. Asking it to respect its own badge is pointless. The
badge is a *claim by the owner*; only the coordinator can turn that claim into
an actual "no."

Same analogy: a badge printed with "floors 1–3" means nothing if there is no
reader on the door to floor 4.

## 4. An example of the bug

You are running a seller agent you did not write (an imported PR, or a
model-driven participant). You want it to answer quotes but **never
initiate** anything, so you issue it a badge with `["join", "claim", "ack"]`
and no `send`.

**Before this branch:**

```
POST /runs/run-1/join      body: {grant with permissions ["join","claim","ack"], signature…}
→ 200  {"session": "ses-8b3d…"}        signature verified; permissions stored… and ignored

POST /runs/run-1/messages  X-Town-Session: ses-8b3d…
                           body: {"to": "buyer", "kind": "quote_request", …}
→ 202  accepted                        ← should have been refused
```

`require_permission()` existed in `coordinator.py` (the code that would have
said no) but nothing called it, so the stored list was never consulted. The
README sentence *"authorizes one disposable session key for one run with
named permissions"* was true about the run and false about the permissions.

**After:**

```
POST /runs/run-1/messages  X-Town-Session: ses-8b3d…
→ 403  {"error": "grant_permission_denied", "permission": "send"}
```

## 5. An example of a refused action as evidence

Picture an **auditor agent**. It is allowed to receive copies of quotes and
acknowledge them, but it must never place an order, so its badge is
`["join", "claim", "ack"]`. Now suppose a prompt-injected message, or context
truncation mid-run, makes the model "forget" its role and try to order two
widgets.

**Before the branch**, the bundle would show the auditor sending a
`quote_request` and the seller fulfilling it. Nothing in the evidence says
that was forbidden: the grant's permissions were recorded at join, but no
action was ever judged against them. You could not prove the agent
misbehaved, and worse, the town let the misbehaviour succeed.

**After the branch**, `intents.jsonl` and `events.jsonl` contain this pair:

```jsonc
// intents.jsonl — what the agent tried
{"actor": "auditor", "action": "send",
 "payload": {"message_id": "q-7", "to": "seller", "kind": "quote_request",
             "body": {"sku": "widget", "quantity": 2}}}

// events.jsonl — what the town did about it
{"event_id": "ev-19", "observer": "town", "kind": "grant_permission_denied",
 "subject": "auditor", "detail": {"permission": "send"}}
```

There is **no** `message_accepted` event, the seller's inbox stays empty, and
the report ends with `Refused by grant permissions: 1`.

That pair is the paper's sentence made concrete:

| the evidence | what it proves |
|---|---|
| the `send` intent | the agent did something it was told not to |
| the `grant_permission_denied` event | the town refused it |
| no `message_accepted` afterwards | the refusal held |

A scenario validator can now assert "every executed action was authorized",
which was impossible before, because there was no such thing as a denied
action to look for.
