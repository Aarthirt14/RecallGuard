# RecallGuard context-admission evaluation

Dataset: `recallguard-synthetic-v1` (synthetic, 19 cases).
Retrieval: **semantic**.

These are context-admission checks, not agent attack-success measurements.

| Method | Case checks passed | Forbidden exposure (lower is better) | Required context recall (higher is better) |
|---|---:|---:|---:|
| unfiltered | 6/19 (31.6%) | 13/13 (100.0%) | 10/11 (90.9%) |
| text_filter | 8/19 (42.1%) | 10/13 (76.9%) | 10/11 (90.9%) |
| recallguard | 17/19 (89.5%) | 1/13 (7.7%) | 10/11 (90.9%) |

## RecallGuard cases requiring attention

- `benign-imperative`: missing delivery; exposed none.
- `informational-instruction-gap`: missing none; exposed preference.

## Limits

- Measures context exposure and retention, not agent attack success or executed actions.
- Dataset labels and sampling are supplied by the author; rates do not establish population guarantees.
- Text-only and unfiltered methods are minimal ablations, not tuned or LLM-based defenses.
- Stable case-ID ties differ from production UUID ties; timing is not measured.
- Fresh engine instances share one in-memory store; this is not a process-restart durability test.

Dataset SHA-256: `c558dc8fb206b2e0b1495056e3463de66a87dc98d148acf6c889618ce6bfbdfa`
Result SHA-256: `dcbf3b7a32951d56df717291f2b075566d91f5ff0d099317a283bd538fda9c5b`
