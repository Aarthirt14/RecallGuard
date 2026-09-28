# RecallGuard context-admission evaluation

Dataset: `recallguard-hardening-v1` (synthetic, 29 cases).
Retrieval: **lexical**.

These are context-admission checks, not agent attack-success measurements.

| Method | Case checks passed | Forbidden exposure (lower is better) | Required context recall (higher is better) |
|---|---:|---:|---:|
| unfiltered | 9/29 (31.0%) | 20/20 (100.0%) | 28/28 (100.0%) |
| text_filter | 7/29 (24.1%) | 17/20 (85.0%) | 23/28 (82.1%) |
| recallguard | 27/29 (93.1%) | 1/20 (5.0%) | 27/28 (96.4%) |

## RecallGuard cases requiring attention

- `declarative-falsehood`: missing none; exposed false-account.
- `quoted-security-example`: missing handbook; exposed none.

## Limits

- Measures context exposure and retention, not agent attack success or executed actions.
- Dataset labels and sampling are supplied by the author; rates do not establish population guarantees.
- Text-only and unfiltered methods are minimal ablations, not tuned or LLM-based defenses.
- Stable case-ID ties differ from production UUID ties; timing is not measured.
- Fresh engine instances share one in-memory store; this is not a process-restart durability test.

Dataset SHA-256: `299b353c905e6c104e4c1d464a6f0762a1e8a1049f4db7c7c9bc2726adaeaf8a`
Result SHA-256: `9c6fc2b167c6c591d9df6d9bc68cc3775e6cc36bfda889367ff808198713617e`
