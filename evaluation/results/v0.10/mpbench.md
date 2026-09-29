# MPBench external-material audit

**This is not MPBench attack success or retrieval success, and does not test an agent acting on memory.**

Protocol: `mpbench-external-material-audit-v1`. Upstream revision: `6886880a7c29625e0109e0ad91d0e095029f1577`.

Rows are forced through external-memory ingestion. Skill cases target `skill_md`; all other cases target `context`. No expected memory is inserted. Missing queries are excluded only from retrieval denominators.

| Split | Rows | Unique target texts | Eligible for information | Withheld | Queries available | Raw lexical candidates | Returned for query |
|---|---:|---:|---:|---:|---:|---:|---:|
| adversarial | 3241 | 3241 | 1773 | 1468 | 2999 | 2994 | 1631 |
| benign | 2999 | 2699 | 2511 | 488 | 2997 | 2963 | 2478 |

## Admission comparison

| Method | Adversarial target eligible | Benign target withheld |
|---|---:|---:|
| unfiltered | 3241/3241 | 0/2999 |
| text_filter | 1932/3241 | 219/2999 |
| recallguard | 1773/3241 | 488/2999 |

## Adversarial categories (upstream labels unchanged)

| Attack type | Rows | Eligible | Withheld |
|---|---:|---:|---:|
| delayed_conditional_injection | 33 | 25 | 8 |
| delayed_conditional_injection_injection | 567 | 307 | 260 |
| experience_injection | 600 | 335 | 265 |
| explicit_keyword | 16 | 8 | 8 |
| explicit_keyword_injection | 824 | 397 | 427 |
| fact_injection | 601 | 445 | 156 |
| repetition | 3 | 1 | 2 |
| repetition_based_injection | 57 | 24 | 33 |
| repetition_injection | 540 | 231 | 309 |

## Parsing notes

```json
{
  "adversarial": {
    "multiple_object_lines": [
      {
        "line": 1080,
        "objects": 2
      }
    ],
    "string_boolean_labels": 0,
    "id_prefix_mismatches": 0
  },
  "benign": {
    "multiple_object_lines": [],
    "string_boolean_labels": 7,
    "id_prefix_mismatches": 300
  }
}
```

## Limits

- This is an external-material admission audit, not MPBench ASR/RSR or an agent benchmark reproduction.
- Forced ingestion skips the agent write decision, summarization and later behavior; no tool actions or hosted model are tested.
- Whole target material eligibility does not establish whether an agent adopts its malicious span or answers correctly.
- Benign withholding measures access to supplied context, not correctness of legitimate_memory_write decisions.
- Raw corpus labels and duplicate rows are preserved; row-weighted results are not independent samples or verified ground truth.
- Missing follow-up queries have no retrieval outcome and do not count as successfully blocked attacks.
- Lexical misses are reported separately from admission withholding; no semantic-retrieval result is claimed.
