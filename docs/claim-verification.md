# Independent claim verification

RecallGuard records a reviewer's completed check of a structured claim against a separately registered evidence source. This is an enforceable evidence requirement for consequential use, not an automatic fact-checker. The reviewer must actually perform the check outside the app.

## Permissions

| Record | Purpose |
|---|---|
| Claim verification | Binds one memory and its exact claim to a reviewer, evidence source, reference, method, and expiry |
| Action grant | Permits that memory to influence one action and target; binds to its current verification |
| Payment approval | Approves exact invoice/payment terms, including the verification selected for the proposal |
| Informational review | Only permits an eligible overblocked record in informational retrieval; cannot create claim verification or authorize tools |

Grant creation returns 409 if a memory has a structured claim but no current verification. Consequential retrieval also validates the grant's exact verification each time. A copy or summary does not inherit verification: review the exact record that will be granted action scope. All normal lifecycle, ancestry, screening and conflict checks still apply.

Unverified claims may remain available for informational use. Retrieval marks them in `unverified_claim_ids`; checked records appear in `claim_verifications` as memory-ID-to-verification-ID mappings. The dashboard labels the distinction. Neither field is a reusable permission token.

## Record a check

1. Independently check the claim using an official record, a callback through independently obtained contact details, or an in-person check. Retain an appropriate document/page/log reference.
2. Register that evidence source with the existing reviewer-only `POST /sources` endpoint. Its identity and locator must differ from every declared origin of the target memory. The app also rejects simple locator aliases after case-folding and removing trailing slashes.
3. Open the memory in the dashboard and choose **Record independent verification**. Select the source and method, enter the reference, reason and expiry, then confirm the independent check. The form shows the exact structured claim, source details and current request fingerprint.
4. Issue a separate action grant. For procurement, create a payment proposal and approve its exact terms separately.

A different source ID or URL does not establish real independence. Mirror sites, forwarded messages, related organizations and compromised contact details can appear separate. The reviewer must judge independence and factual support; the app only enforces the declared source separation and permission bindings. It never fetches a URL, contacts a supplier or invokes a model to certify the claim.

## API

Read `GET /review` with reviewer credentials. `claim_verification_options[memory_id]` includes the current verification ID and eligible evidence sources with their request fingerprints. Ineligible/restricted claims have no eligible candidates. Agents cannot access this reviewer projection.

Submit `POST /claim-verifications`:

```json
{
  "memory_id": "COPY_MEMORY_ID",
  "evidence_source_id": "COPY_SEPARATE_SOURCE_ID",
  "expected_fingerprint": "COPY_64_CHARACTER_SOURCE_OPTION_FINGERPRINT",
  "evidence_reference": "callback-log:case-001",
  "method": "callback",
  "independently_checked": true,
  "reason": "Account confirmed using independently obtained contact details",
  "expires_at": "REPLACE_WITH_FUTURE_TIMEZONE_AWARE_TIMESTAMP"
}
```

Replace all placeholders. `method` is `official_record`, `callback`, or `in_person`; expiry must be in the next 24 hours. The server derives the claim from the stored memory and rejects caller-supplied verification ownership or claim fields. Issuance and its audit event share a store transaction. Stale fingerprints and ineligible records return 409; invalid input/expiry returns 422.

The fingerprint covers the target record, selected evidence source, policy source files and prior verification decisions. Concurrent duplicate issuance creates only one current verification. A delayed request cannot recreate withdrawn evidence; deliberate re-verification needs a fresh snapshot. Existing APIs require a reviewer key; agents cannot issue or withdraw verification.

## Withdrawal and expiry

Use **Withdraw claim verification** or `POST /claim-verifications/{id}/withdraw` with a reason. Withdrawal is idempotent and preserves the first actor, reason and timestamp. Expiry, withdrawal, revoked/conflicted ancestry, record/source changes, or a bound policy update invalidate the verification at use time.

Existing grants retain their original verification ID. Re-verifying the same claim does not repair those grants: issue a new grant after the new check. Payment terms retain the original verification ID too, so a previously approved proposal cannot silently switch evidence. Create and approve new payment terms. The new proposal fingerprint changes even when the account and amount remain the same.

These restrictions affect future actions. Already executed simulated receipts remain historical, and retries return the same receipt without another effect.

## Storage and upgrade behavior

Verification, withdrawal and audit records persist atomically in Neo4j. No existing grants or pending payments are automatically given evidence. On upgrading to v0.8:

- Existing structured-claim grants without a verification ID stop authorizing consequential use.
- Existing pending payment proposals need to be recreated with verification and approved again.
- Changes to the engine also invalidate older informational-review fingerprints, as documented in that workflow.
- Older application versions cannot read the new record kind/fields; downgrade requires compatible migration or an appropriate backup. Use the same application version for every process sharing the workspace.

Evidence references are recorded strings, not stored copies or cryptographic proofs of an external document. External content drift is not automatically monitored. Withdraw verification when evidence becomes unreliable. The current shared reviewer credential does not identify an individual human or implement two-person approval.

## Limits and tests

Only explicit structured claims trigger this requirement. Arbitrary prose is not semantically extracted or validated. The bundled payment adapter requires an exact structured account claim and derives its action arguments from stored records; other tool adapters need equivalent checks. A caller lying about lineage, a dishonest reviewer, a compromised evidence source, and real-world bank account authentication remain outside this mechanism.

Tests cover source/locator reuse, inherited origins, missing verification, exact grant bindings, expiry, withdrawal, replay protection, duplicate issuance, informational-review separation, stale payment approval, API roles, dashboard confirmation, and Neo4j reconnection. `examples/procurement.py` models explicit synthetic verification; it does not perform a real independent check or payment.
