# Conflict retirement and replacement

A reviewer can recover from an explicit structured-claim conflict without restoring quarantined records. The reviewer independently checks one of the existing values, retires the full affected group, and creates a new assertion from a separately registered source. This is a human decision recorded by the system, not automatic factual adjudication.

## Dashboard workflow

1. Check the selected value outside RecallGuard. Use an official record, an independently arranged callback, or an in-person check. Register the evidence source through `POST /sources` first.
2. Inspect a non-revoked conflicting memory and choose **Resolve using this claim**. The selected entity, attribute and value are fixed; to choose another value, inspect that memory instead.
3. Inspect the affected records. All records for the same case-insensitive entity/attribute key, including matching-value duplicates and historical revoked records, are included. Their descendants are retired too, including descendants shared with unrelated parents. Unrelated parents themselves are untouched.
4. Select separate evidence, enter its document/page/callback reference and checking method, provide a reason, and confirm the check. The form previews the replacement text and every affected record. Retirement cannot be undone.
5. Inspect the replacement. It is available to lexical informational retrieval, marked as an unverified claim. In semantic workspaces, use **Embedding coverage** to backfill its embedding. No model runs inside the resolution transaction.
6. For consequential use, perform and record a separate current claim verification using another eligible source, then issue a new scoped grant. Payments require a new proposal and a new approval as well.

A conflict-resolution attestation does not substitute for claim verification. Its purpose is to record why old evidence was retired and where the new assertion came from. The separate verification requirement prevents resolution alone from granting action access.

## API

`GET /review` exposes `conflict_resolution_options[memory_id]`:

- `conflicting_memory_ids`: all historical/current records sharing the selected claim key.
- `retired_memory_ids`: complete retirement impact, including descendants.
- `replacement_content`: server-generated text containing only the selected structured claim.
- `evidence_sources`: eligible registered source IDs and their request fingerprints.

Submit with reviewer credentials:

```json
POST /conflict-resolutions
{
  "selected_memory_id": "memory-id-from-review",
  "evidence_source_id": "registered-independent-source",
  "expected_fingerprint": "64-character-fingerprint-from-review",
  "evidence_reference": "record:2026-09-28/page-3",
  "method": "official_record",
  "independently_checked": true,
  "reason": "Selected value confirmed against independent evidence"
}
```

A successful request returns 201 with the resolution ID, exact selected claim, reviewer, timestamp, retired IDs and replacement memory ID. These fields are server-owned; clients cannot submit an arbitrary claim, content, replacement ID, retirement list or reviewer identity. Methods are `official_record`, `callback`, or `in_person`. Reference and reason each require 5–2000 characters.

A fingerprint binds the selected record, the full affected records, the evidence source and the resolution policy. A newly added claim or descendant, changed record, or policy update invalidates the request with 409. Replaying a completed request also returns 409: the selected memory is now revoked. On a network interruption, refresh and inspect `conflict_resolutions` before retrying.

## Guarantees within the declared model

- Retirement, replacement, resolution history and audit events share one transaction. Failure rolls back everything; simultaneous submissions create only one replacement.
- Old content, hashes, structured claims, conflict links, origins, authority and taints remain intact. Lifecycle status becomes revoked and retirement reasons are added. No old record is promoted.
- The replacement is a new source-root assertion with a fresh ID and a server-generated rendering of the selected claim. Its authority and taints come from its new source type under the ordinary ingestion policy. Its text and claim pass current screening. It receives no inherited verification, grant, embedding or payment approval.
- Resolution history links the old records to the replacement for audit and evidence-source exclusions. These are not derivation edges: old lifecycle restrictions do not propagate into the independently sourced assertion. Revoking the replacement itself still revokes its descendants normally.
- Evidence cannot reuse a declared origin from the affected records, their ancestors, or prior resolution history. Simple locator aliases are rejected using case-folding and trailing-slash removal. These exclusions also apply to subsequent verification of the replacement and its descendants, including successive resolutions of different claim keys.
- Existing grants and pending payments still refer to their old memory and verification IDs. They cannot authorize the replacement. Completed simulated receipts remain historical and idempotent.
- New conflicting evidence quarantines the replacement normally. There is no permanent allowlist or automatic suppression of a rejected value.

## Limits and compatibility

Only explicitly supplied structured conflicts can be resolved. This does not discover semantic contradictions, prove the truth of a claim, authenticate a source, or detect undisclosed mirrors/collusion. The reviewer must do the independent check. A caller that conceals lineage and the shared reviewer credential remain limitations. Availability remains conservative: all descendants are retired even if they have other independent parents; individual claim/support repair is still future work.

References are recorded strings, not retrieved or archived documents. Resolution history is permanent; if replacement evidence becomes unreliable, revoke that replacement through the existing memory endpoint. There is no restore action for retired records.

v0.9 adds a persisted `conflict_resolutions` record kind. Use the same application version for every process sharing a workspace; old versions do not understand the new history or its evidence exclusions. Downgrade needs a compatible migration or backup. Engine and verification-policy changes invalidate previous claim verifications and informational reviews: perform fresh checks and reissue dependent grants and pending proposals. No old evidence is automatically approved.

Run `python examples/conflict_resolution.py` for a synthetic walkthrough. Unit/API tests cover scope, rollback, source reuse, stale requests, concurrent submissions, inherited exclusions, late conflicts and payment isolation. Neo4j CI checks persistence across reconnects. Dashboard tests exercise the real API with jsdom; rendered layout, native focus, mobile behavior and accessibility remain unverified.
