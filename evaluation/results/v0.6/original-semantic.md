# RecallGuard context-admission evaluation

Dataset: `recallguard-synthetic-v1` (synthetic, 19 cases).
Retrieval: **semantic**.

These are context-admission checks, not agent attack-success measurements.

| Method | Case checks passed | Forbidden exposure (lower is better) | Required context recall (higher is better) |
|---|---:|---:|---:|
| unfiltered | 6/19 (31.6%) | 13/13 (100.0%) | 10/11 (90.9%) |
| text_filter | 8/19 (42.1%) | 10/13 (76.9%) | 10/11 (90.9%) |
| recallguard | 19/19 (100.0%) | 0/13 (0.0%) | 11/11 (100.0%) |

## RecallGuard cases requiring attention

No failed checks in this dataset. This does not establish general security.

## Limits

- Measures context exposure and retention, not agent attack success or executed actions.
- Dataset labels and sampling are supplied by the author; rates do not establish population guarantees.
- Text-only and unfiltered methods are minimal ablations, not tuned or LLM-based defenses.
- Stable case-ID ties differ from production UUID ties; timing is not measured.
- Fresh engine instances share one in-memory store; this is not a process-restart durability test.

Dataset SHA-256: `c558dc8fb206b2e0b1495056e3463de66a87dc98d148acf6c889618ce6bfbdfa`
Result SHA-256: `7e7283f632a1402806157a9b28401ba6bd5e8512630e1b6eb36be2939a974836`
