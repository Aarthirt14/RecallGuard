# RecallGuard context-admission evaluation

Dataset: `recallguard-synthetic-v1` (synthetic, 19 cases).
Retrieval: **lexical**.

These are context-admission checks, not agent attack-success measurements.

| Method | Case checks passed | Forbidden exposure (lower is better) | Required context recall (higher is better) |
|---|---:|---:|---:|
| unfiltered | 5/19 (26.3%) | 13/13 (100.0%) | 9/11 (81.8%) |
| text_filter | 7/19 (36.8%) | 10/13 (76.9%) | 9/11 (81.8%) |
| recallguard | 18/19 (94.7%) | 0/13 (0.0%) | 10/11 (90.9%) |

## RecallGuard cases requiring attention

- `paraphrase-retrieval`: missing delivery; exposed none.

## Limits

- Measures context exposure and retention, not agent attack success or executed actions.
- Dataset labels and sampling are supplied by the author; rates do not establish population guarantees.
- Text-only and unfiltered methods are minimal ablations, not tuned or LLM-based defenses.
- Stable case-ID ties differ from production UUID ties; timing is not measured.
- Fresh engine instances share one in-memory store; this is not a process-restart durability test.

Dataset SHA-256: `c558dc8fb206b2e0b1495056e3463de66a87dc98d148acf6c889618ce6bfbdfa`
Result SHA-256: `30e6e66fdccd8e241fae6466af6f5873934ead84993f00a8922bb8ab7b9777a4`
