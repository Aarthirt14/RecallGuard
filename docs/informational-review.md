# Informational review

A legitimate security handbook can quote an attack and still trigger screening. A reviewer can now permit that exact record in informational retrieval for a limited time. This is a human decision about context, not automatic fact verification or a detector accuracy improvement.

## Scope

| Property | Behavior |
|---|---|
| Eligible record | A directly sourced record restricted only by instruction screening, including legacy instruction quarantine |
| Unreviewable restrictions | Revocation, conflicts, credentials, restricted/unknown taints or reasons, and all derived records |
| Permitted use | Retrieval with `action=inform`, in lexical or semantic mode |
| Identity binding | Exact record including claims, provenance, lifecycle metadata, and the deployed screening/review/engine source fingerprints |
| Duration | A timezone-aware expiry within the next 24 hours |
| Withdrawal | Reviewer-only; stops future exceptional admission and preserves history |
| Unchanged controls | Stored quarantine, authority, taints, lineage, summary-input restrictions, and all consequential-action gates |

Approval is tied to one memory ID. An identical copy is not approved. Neither existing nor newly created descendants inherit the exception; a reviewed parent still fails the normal derivation restrictions. An informational review cannot issue an action grant or create a payment proposal. Existing payment approvals cannot use it to override their evidence restrictions.

The reviewer is trusted to decide whether the text is appropriate. Mistaken approval can expose an actual injection to informational consumers. Do not approve text simply to increase test scores. Separate factual verification and consequential-action approval are still required.

## Dashboard

Open a memory in `/dashboard`. The **Informational review** section shows eligibility, prior reviews, and the effective exception at the snapshot time. Choose **Review for informational use**, inspect the original text and any structured claim, choose an expiry, enter a reason, and confirm. The server checks the submitted fingerprint against current state inside the same transaction that records the review and audit event.

**Withdraw informational review** ends that exception. Refresh before deliberately issuing another one. A delayed request from before approval or withdrawal cannot recreate the exception because review history changes the request fingerprint. Only one effective review can be issued concurrently for the same record.

The retrieval lab labels admitted records as **reviewed exception** when this permission was used. A record can remain `quarantined` while being admitted informationally through that explicit exception. Action-grant controls remain disabled.

## API

All review mutations require the reviewer `X-API-Key`; agent credentials receive 403.

1. Read `GET /review`. Find the memory, inspect its content/claim/provenance, and read `context_review_options[memory_id]`. The option includes `blockers`, `fingerprint`, and `effective_review_id`.
2. Submit `POST /context-reviews` with:

```json
{
  "memory_id": "COPY_MEMORY_ID",
  "expected_fingerprint": "COPY_64_CHARACTER_REVIEW_FINGERPRINT",
  "reason": "Verified this is a benign training quotation",
  "expires_at": "REPLACE_WITH_FUTURE_TIMEZONE_AWARE_TIMESTAMP"
}
```

The placeholders must be replaced. Changed state/policy, an ineligible record, or an existing effective review returns 409. Invalid expiry returns 422. Approval is not automatically retried against a fresh fingerprint.

3. `POST /retrieve` with `action=inform` returns the usual allowed and blocked records plus `context_reviews`, a mapping from admitted memory ID to the exact review ID used. The same mapping is recorded in the retrieval audit event. Returned permission metadata describes the admission decision; it is not a reusable authorization token.
4. Submit `POST /context-reviews/{review_id}/withdraw` with a `reason`. Retries are idempotent and preserve the first withdrawal reason and timestamp. Revoking the underlying memory through its existing endpoint also blocks informational use immediately.

`GET /review` exposes conservative `memory_restrictions` for normal/action eligibility separately from `information_restrictions`. Full review history remains reviewer-only. The service still uses a shared reviewer identity; individual reviewer accounts are not implemented.

Run the isolated example:

```bash
python examples/context_review.py
```

It demonstrates default blocking, an explicit reviewer exception, continued payment denial, and blocking after withdrawal. It does not populate a running API or call a model.

## Persistence and upgrades

Reviews and withdrawals persist as typed records in Neo4j and commit atomically with their audit events. Existing workspaces start with no reviews. Source changes to screening, review eligibility, or the engine invalidate prior reviews after the service is restarted; this intentionally also includes nonfunctional edits to those files. There is no automatic renewal or approval migration.

Deploy the same code to all processes sharing a workspace. Once new review records exist, older releases cannot read that record kind: rollback needs a compatible application or an appropriate backup/migration plan. Do not point an older server at the upgraded workspace.

Expiration, withdrawal and revocation affect later admission decisions. They cannot retract text already returned to a caller. A reviewed record remains untrusted source material, and arbitrary downstream tools still require their own authorization boundary.
