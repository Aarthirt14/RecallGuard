# RecallGuard

Origin-bound memory controls for AI agents. Preserve where a memory came from, keep its restrictions through summaries, and decide whether it may influence the current action.

**Status: milestones 1–2 — security core, LangGraph procurement workflow, and simulated payment gate.** This is a research foundation, not a production prompt-injection defense. No benchmark accuracy or novelty claims are made.

## What works

- Immutable source registration, restricted to a reviewer credential.
- Memory records with content hashes, source origins, parent links, authority ceilings, taint labels, lifecycle status, and decision reasons.
- Derived memories inherit the lowest parent authority and the union of parent taints.
- Agent credentials cannot create trusted roots, register sources, issue approvals, revoke memories, or read raw management endpoints.
- Rule-based instruction quarantine and rejection of some obvious credential assignments.
- Conflict detection for explicitly supplied entity/attribute/value claims.
- Retrieval checks lifecycle, all ancestors, conflicts, and exact action/target approvals before returning context.
- Time-limited, audited grants bound to one memory and its content hash. Grants never transfer to descendants.
- Conservative descendant revocation, including invalidation of existing grants at retrieval time.
- Atomic Neo4j persistence and an explicitly ephemeral in-memory development store.
- Authenticated FastAPI API, OpenAPI explorer, poisoning example, security tests, and CI.
- LangGraph observation, payment-planning, and execution workflows with persisted session-labelled traces.
- Source summaries with adapter-bound lineage; an offline summarizer and an optional LangChain chat-model adapter.
- Reviewer-registered suppliers and immutable invoices, exact-payment review, fresh execution-time permission checks, and idempotent simulated receipts.

## Run the procurement workflow

After installing the package below, run:

```bash
python examples/procurement.py
```

It demonstrates a cross-session poisoned account being blocked, an approval invalidated by later source revocation, a valid approved simulated payment, and a retry that creates no duplicate payment. It invokes real LangGraph nodes. The default summarizer is deterministic; no LLM or paid API call is made. See [the procurement API walkthrough](docs/procurement.md).

## Run the example first

Requires Python 3.12+.

```bash
python -m venv .venv
# Linux / macOS / WSL
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
python examples/poisoning.py
python -m pytest -q
```

The example stores an external account claim, summarizes it, and creates a new service instance over the same store to represent a later session. The claim remains available for informational questions, but cannot enter payment context. An explicit review permits one exact memory for one target. Revoking the source memory then blocks that approval and its descendants. No real payment or external tool call occurs.

Expected output:

```json
{
  "external_claim_usable_for_information": 2,
  "summary_authority": 1,
  "unapproved_payment_context": 0,
  "explicitly_approved_context": 1,
  "revoked_memories": 2,
  "payment_context_after_revocation": 0,
  "real_payments_executed": 0
}
```

## Start the persistent API

Install Docker with Compose, then:

```bash
python scripts/init_env.py
docker compose up --build
```

Open [API explorer](http://localhost:8000/docs), [health](http://localhost:8000/health), and [Neo4j Browser](http://localhost:7474). The generated `.env` contains distinct agent and reviewer keys and the database password. It is excluded from Git and Docker build context. Keep it private. Compose loads it automatically. This setup binds host ports to loopback.

In `/docs`, click **Authorize** and paste a key from your local `.env`. Use the reviewer key to register sources and review records, and the agent key to test ingestion and retrieval. The reviewer key must never be handed to the agent or included in model context.

To stop services without deleting data:

```bash
docker compose down
```

The named volume retains memories and audit events. `docker compose down -v` removes that data.

### API without Docker

For an explicitly ephemeral API, after generating `.env`:

```bash
# Bash / WSL. Run from the repository root.
set -a
source .env
set +a
export RECALLGUARD_BACKEND=memory
python -m uvicorn recallguard.api:create_app --factory --host 127.0.0.1 --port 8000
```

PowerShell equivalent:

```powershell
Get-Content .env | ForEach-Object {
    $name, $value = $_ -split '=', 2
    [Environment]::SetEnvironmentVariable($name, $value, 'Process')
}
$env:RECALLGUARD_BACKEND = 'memory'
python -m uvicorn recallguard.api:create_app --factory --host 127.0.0.1 --port 8000
```

For a separately running Neo4j, set `RECALLGUARD_BACKEND=neo4j`, `NEO4J_URI`, and `NEO4J_PASSWORD`. A database connection failure fails startup; it never silently falls back to ephemeral storage.

## Try the API

All protected requests use `X-API-Key`.

| Endpoint | Credential | Purpose |
|---|---|---|
| `POST /sources` | Reviewer | Register immutable source identity |
| `POST /memories` | Agent or reviewer | Ingest a root or derive a memory |
| `POST /retrieve` | Agent or reviewer | Retrieve context for a declared action |
| `POST /grants` | Reviewer | Approve a specific memory/action/target until expiry |
| `POST /memories/{id}/revoke` | Reviewer | Revoke a root and every descendant |
| `GET /memories`, `/graph`, `/audit` | Reviewer | Inspect the security state |

1. Register a source using the reviewer key:

```json
{"id":"supplier-web","kind":"web","locator":"https://supplier.example"}
```

2. Write an external claim using the agent key:

```json
{"content":"ABC bank account is 991872.","source_id":"supplier-web"}
```

3. Query its informational context:

```json
{"query":"ABC account","action":"inform"}
```

4. Query its payment context; expect an empty `allowed` list and `scoped_approval_required`:

```json
{"query":"ABC account","action":"payment","target":"supplier:ABC"}
```

A derived write supplies `parent_ids` instead of `source_id`. A grant supplies `memory_id`, `action`, exact `target`, a review `reason`, and an ISO 8601 `expires_at` with timezone in the next 24 hours. Restricted memories cannot receive grants. The API has no automatic quarantine release.

## Security boundary

**A memory grant permits influence; it does not approve a transaction.** The procurement simulator now adds a separate reviewer approval for an exact invoice, amount, currency, account, and evidence record. Its tool gate rechecks both approvals, memory ancestry, conflicts, cancellation, and prior execution inside the same transaction as the simulated ledger write. No real transfer is made.

The general-purpose memory API still depends on callers reporting the action and full lineage. The bundled observation adapter binds summary parents itself, and the simulator fixes the tool action to payment and derives its arguments from stored records. Asking for informational context cannot bypass the simulator's execution gate. Other agents and external tools need equivalent integration; real tool execution, network source authentication, and universal lineage capture are not implemented. Reviewer identity, adapter code, and database access are trusted. The Python engine is an internal library; the HTTP API is the credential boundary.

Numeric authority describes the origin ceiling, not factual correctness or executable permission. Approval grants are separate, scoped records and never rewrite origin or remove taint. Higher authority is not sufficient for consequential retrieval.

The current store is single-workspace. Neo4j operations serialize on a workspace lock, load its records, evaluate policy, and atomically commit changed records plus events. This prioritizes correctness for a small research dataset; it needs pagination, bounded resource usage, indexed candidate retrieval, and more granular transactions before scaling.

## Limitations and next milestones

- Retrieval is lexical token overlap, **not embeddings or semantic search**.
- Instruction detection uses English patterns; it misses obfuscation and multilingual payloads and may quarantine harmless imperative text. No detector accuracy is claimed.
- Credential detection is a limited pattern check, not comprehensive secret scanning.
- Conflict keys come from the caller; there is no semantic extraction or independent corroboration. Both conflicting claims are quarantined. This is fail-closed but creates an availability tradeoff.
- Revocation disables all descendants, even if they have other parents. Claim-level repair and independent-support verification are future work. Revocation is not physical deletion: records remain available to reviewers for auditing.
- Content hashes bind approvals; they are not signatures and do not protect against a database administrator modifying records. Audit events have no public mutation API, but are not tamper-proof.
- Memory grants permit influence until expiry; they are reusable and not transaction approval tokens. Simulator transaction approvals are separate and single-execution per invoice.
- The LangGraph workflow is a fixed procurement workflow, not an open-ended autonomous planner. The optional chat-model adapter is dependency-injected; no hosted provider is configured or evaluated.
- Session IDs label runs; they are not identity or tenant boundaries. Business records persist in Neo4j, while graph invocations have no checkpoint/replay service. A crashed observation can leave a root without a summary; repeating observation may create duplicate informational records. Payment retries remain idempotent.
- No embeddings, Next.js dashboard, MPBench adapter, LLM-filter baseline, or published evaluation results yet.

Next: add semantic retrieval, a security dashboard, and reproducible benchmark comparisons. Verify benchmark availability and licenses before importing datasets. Extending the simulated gate to a real payment provider requires a separate durable outbox and provider idempotency design; a database transaction cannot atomically commit an external bank transfer.

See [architecture and threat model](docs/architecture.md) for the invariants and acceptance cases.

## Tests

```bash
python -m ruff check .
python -m ruff format --check .
python -m pytest -q
```

The Neo4j integration tests are skipped unless `NEO4J_TEST_URI` and `NEO4J_TEST_PASSWORD` are set. They use random namespaces and clean up only those namespaces. They cover core persistence and the agent/review/payment lifecycle across reconnects, including concurrent execution and revoked evidence. GitHub Actions provisions Neo4j and runs them alongside the unit and API tests and both examples.

Implementation references: [FastAPI security](https://fastapi.tiangolo.com/reference/security/), [FastAPI tests](https://fastapi.tiangolo.com/tutorial/testing/), [Neo4j managed transactions](https://neo4j.com/docs/python-manual/current/transactions/).
