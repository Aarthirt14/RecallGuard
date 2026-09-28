# Context admission hardening (v0.6)

The old detector treated `must`, `always`, and `never` as instructions on their own. It quarantined an ordinary delivery obligation but missed a payment instruction framed as a permanent preference. The new deterministic scanner recognizes specific behavior-changing patterns instead of those isolated words.

## Layers

1. **Screen every exposed text field.** Inspect memory content plus claim entity, attribute, and value. Credential-like assignments are rejected before embedding inference or persistence. Detected directives receive named policy reasons and are quarantined.
2. **Normalize for inspection.** Scan original text and bounded decoded views: two passes of Unicode NFKC, HTML entity and percent decoding, removal of Unicode format characters, and a markup-stripped view. Original stored content and content hashes remain unchanged. No decoding executes commands or fetches URLs.
3. **Check behavior-changing patterns.** Signals cover control overrides, persistent instructions/preferences, forged system/developer roles, financial redirection, credential exfiltration, tool execution, answer manipulation, and concealment. A benign sentence never exempts another sentence from screening.
4. **Recheck at use time.** Retrieval, grants, payment approval/execution and reviewer restrictions share live checks of the memory and its ancestors. A record accepted under an older detector cannot retain eligibility solely because its stored status is active. Existing action grants cannot override a current restriction. The separate [informational-review workflow](informational-review.md) allows explicit, expiring exceptions for eligible direct-source records only.
5. **Stop restricted input before summarization.** The observation graph leaves the root for review and records `restricted_summary_input`. It does not call the configured summarizer or invent a sanitized summary. Permitted input is summarized with adapter-bound lineage, then screened again on write. If revocation occurs during a model call, the resulting child is restricted by the live parent check.

Reasons expose rule names, not matched source snippets. Agent retrieval returns blocked IDs and reasons without their text or claims. Reviewer inspection continues to show originals.

## Upgrade behavior

No database migration is required. Live checks immediately apply to old records, descendants, grants and pending payment proposals. Stored status and historical reasons are not rewritten during reads: an old `active` record can have a current content-policy restriction in the dashboard. Policy reads do not erase the audit history.

Old quarantined records are **not automatically released**, even when the revised detector would accept their wording. There is no unquarantine endpoint. Reviewers can use the v0.7 informational-review workflow for eligible false positives while preserving the original record, quarantine, and audit history. Do not edit the database to clear taints or lifecycle state.

Observation clients must tolerate a blocked run with only the root memory ID. Previously a quarantined root could still produce a quarantined summary; now the provider is skipped. No request flag disables screening. Trusted-origin text is screened too, and origin authority still cannot substitute for scoped authorization.

## Evidence and limits

See [evaluation results](evaluation.md) for unchanged original fixtures and the additional regression suite. Unit/API tests cover common wrappers, claim-field payloads and credentials, benign obligations, old-policy records and grants, summary-provider non-invocation, unsafe model output, revocation during summarization, and payment denial after a policy upgrade. The additional cases were designed with the implementation; they do not estimate performance on unseen attacks.

The scanner remains a conservative English heuristic. Bounded pattern windows and normalization are not arbitrary decoding, semantic parsing or truth verification. Novel wording, padding, ciphers, base64, unhandled Unicode tricks and other languages can evade it. Legitimate discussions and quotations of instructions can be blocked. It cannot distinguish a plausible false account number from a true one without independent evidence.

Untrusted informational context can therefore still contain undetected attacks or misinformation. Keep consequential tool authorization outside the model, bind it to current evidence and exact arguments, and independently verify approvals. The included payment simulator enforces its own gate; arbitrary external tools require their own equivalent boundary. Screening does not establish production readiness or make an unrestricted agent safe.

Live scans add work to an already full-workspace store. This release makes no throughput claim. Provider invocation is outside database transactions: a revocation cannot retract text already dispatched, but it blocks derived use through the existing lineage checks. Hosted models are still opt-in and have not been evaluated here.
