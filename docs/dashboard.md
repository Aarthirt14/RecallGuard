# Reviewer dashboard

The dashboard is included in the Python package and served by FastAPI at `/dashboard` (the root URL redirects there). It uses plain HTML, CSS, and JavaScript, with no separate frontend server or production Node dependency.

## Open the workspace

Start the API using the existing [setup instructions](../README.md), then open [the dashboard](http://localhost:8000/dashboard). Enter the **reviewer** key from your local `.env`. Agent keys cannot access reviewer records or review actions. The dashboard starts empty when the backend has no records; it never inserts sample business data.

The key is held only in the tab's JavaScript memory, cleared from the input after submission, and sent in the existing `X-API-Key` header. It is not written to cookies, localStorage, sessionStorage, or URLs. Disconnect, refresh, and page navigation clear the session. Back/forward cache restoration also clears it. Access rejection clears loaded records. Treat the browser, its extensions, and the host serving the JavaScript as trusted. Use HTTPS if you expose the API beyond local development; the existing Compose setup binds host ports to loopback.

The existing development examples use their own in-memory stores. Running them does not populate a separately running API. Use the API or procurement workflow against your running service to create records.

## What reviewers can do

| View | Function |
|---|---|
| Overview | Count stored memories, restricted records, revocations, and pending proposals; inspect recent activity and embedding coverage |
| Memories | Search and filter records, inspect full text and content hashes, follow direct parent/descendant links, inspect registered origins and conflicts |
| Memory review | Issue an exact memory/action/target grant with expiry and review reason; revoke a memory and all descendants |
| Payment review | Inspect immutable payment terms and evidence, approve the displayed fingerprint, renew an approval, or cancel a proposal |
| Retrieval lab | Test lexical or configured semantic retrieval for an action and target; inspect allowed context and blocked IDs/reasons |
| Audit log | Search the latest 200 events and expand their full subject IDs and decision details |
| Embedding coverage | Backfill up to 32 missing embeddings per click when a model is configured |

A grant permits one memory to influence an action. It does not approve a payment. Payment approval has its own confirmation form, exact terms, fingerprint, and expiry. The dashboard never calls the execution endpoint. All transactions remain simulated. Raw integer minor units and currency are shown during review; the secondary display amount uses the browser's currency formatting convention.

Review forms require an explicit checkbox and a reason. Revocation and cancellation have no restore action. Revocation retains the records for audit and includes descendants added after the displayed snapshot. Quarantined and conflicted records cannot receive grants. There is no quarantine-release or conflict-resolution feature in this milestone.

## Security boundary

`GET /review` requires reviewer credentials and returns a consistent projection of one store transaction. It includes current lifecycle and ancestry restrictions, payment evidence blockers, grants, sources, invoices, and audit history. It exposes coverage counts and model identity without returning embedding vectors. The server remains the authority: mutations use the existing authenticated endpoints and recheck live state. The UI does not implement a substitute authorization policy.

Stored text, source locators, reasons, and audit payloads are rendered as text, not HTML or clickable external source links. Dashboard responses use a restrictive Content Security Policy, anti-framing headers, `nosniff`, and no referrer. API and dashboard responses use `Cache-Control: no-store`. There are no analytics or external scripts/fonts. API-key authentication rather than ambient cookies avoids cookie-based cross-site request forgery; do not add permissive CORS or expose reviewer credentials to untrusted origins.

This is a snapshot interface. Refresh to see changes made in another session. Counts and displayed approvals can become stale; all grants, approvals, and revocations still pass server-side checks. Network interruptions explicitly warn that a submitted action may already have completed. Refresh before retrying. The server still uses a shared reviewer credential, not individual reviewer accounts, MFA, or tenant isolation.

## Verification and limits

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
npm ci
npm run format:check
npm test
```

Node 22+ is needed for development checks only. The DOM integration suite starts a fresh local FastAPI service with isolated synthetic data for each test. It checks reviewer access, malicious text rendering, filters and pagination, explicit review confirmation, exact grants, descendant revocation, payment approval/cancellation, stale evidence rejection, retrieval, embedding backfill, audit details, and disconnected-session race handling.

These tests use jsdom and the real API. They do not render CSS or prove native dialog focus behavior, mobile layout, or screen-reader accessibility. A manual browser check is still needed for those aspects. The cloud browser in the implementation workspace could not reach localhost, so rendered-browser verification was not completed there.

Memory pagination and filtering happen in the browser after loading the snapshot. The API still loads a whole small workspace, and the dashboard audit list is capped at 200 events. This is not a scalable operations console. Indexed retrieval, server pagination, individual reviewer identities, conflict resolution, and benchmark evaluation remain separate work.
