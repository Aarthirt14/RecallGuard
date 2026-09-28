# Reproducible context-admission evaluation

RecallGuard now includes an offline runner that compares three methods on the same data and retrieval scores:

| Method | Behavior |
|---|---|
| `unfiltered` | Return matching records without lifecycle, text, lineage, or grant checks |
| `text_filter` | Frozen v0.5 raw-content instruction/credential patterns; do not scan claim fields, propagate parent restrictions, or enforce grants |
| `recallguard` | Replay writes, grants, and revocations through the real policy engine, then retrieve through a fresh engine instance over the same store |

The first two methods are deliberately minimal ablations. They are not tuned defenses or an LLM-filter baseline. Every run uses new, isolated in-memory stores. There is no database connection, hosted LLM, payment, message, shell payload, or external tool execution. Source locators are data and are never fetched.

## Run

```bash
python -m pip install -e '.[dev]'
python -m recallguard.evaluation \
  --output evaluation-output/lexical.json \
  --markdown evaluation-output/lexical.md
```

The installed `recallguard-eval` command is equivalent. Omit `--output` to print JSON to stdout. A valid evaluation returns exit code 0 even when cases reveal weaknesses; input, setup, or provider failure returns a nonzero code. Invalid runs are not counted as successful defenses.

For semantic retrieval:

```bash
python -m pip install -e '.[dev,semantic]'
python -m recallguard.evaluation --mode semantic \
  --model-cache .model-cache \
  --output evaluation-output/semantic.json \
  --markdown evaluation-output/semantic.md
```

Use `--offline` after provisioning the model cache, or supply `--model-path`. The model is the same local MiniLM adapter used by the API. The first online run downloads assets; inference stays local. Semantic scores depend on the fingerprinted model and runtime versions. Thresholds come from each case's `query.min_score` (default 0.25).

The root-level JSON and Markdown [reference results](../evaluation/results/) preserve v0.5 outcomes. Updated results are in [v0.6](../evaluation/results/v0.6/); the original 19-case dataset is unchanged. They are examples of the runner's output, not a published security benchmark. Write new versioned reports after code or fixture changes; source and data hashes identify the exact run inputs.

## What is measured

The 19 original, handwritten scenarios (with explicit verification setup in v2) cover exact grants, scope mismatches, inherited quarantine, revocation, late conflicts, authority ceilings, credential rejection, filtering before top-k, benign information, and known limitations. Each case supplies required memory IDs and forbidden memory IDs independently of the policy being tested. Both sets can be present; unlabelled distractors are allowed but can consume retrieval slots.

- **Case checks passed:** cases returning every required ID and no forbidden ID, divided by all cases.
- **Forbidden context exposure:** cases returning at least one forbidden ID, divided by cases with at least one forbidden ID. Lower is better. This does not measure an agent acting on that text.
- **Required context recall:** total required IDs returned, divided by total required IDs. Higher is better. This is a micro-average over annotated records and includes retrieval misses and filter omissions.
- **Required candidate retention:** returned required IDs divided by required IDs that passed the raw retrieval threshold. This separates lexical/semantic misses from later filtering and top-k losses, but is not a pure detector false-positive rate.
- **Forbidden candidate coverage:** cases with at least one forbidden raw-corpus candidate, divided by cases with forbidden IDs. This is computed before policy and top-k, so a retrieval miss cannot masquerade as evidence that a detector caught an attack.

Every fraction includes its numerator and denominator. A zero denominator gives `null`, not a fabricated zero or 100%. Reports include per-case admitted IDs, missed required IDs, exposed forbidden IDs, raw candidate scores, policy reasons, expected write rejections, and summaries by category.

There are no confidence intervals: the small convenience sample is neither randomly drawn nor representative, and related scenarios are not independent trials. Its rates describe these fixtures only. No claim of general attack prevention, novelty, or comparison to state-of-the-art defenses follows from them.

## Reproducibility and fairness

Each method sees the same raw corpus and query. Baselines retain raw writes even when RecallGuard rejects them, because rejecting a write is part of the defense being measured. A text-only method treats derived text independently, making missing lineage controls visible.

All methods use the same lexical scores or cached, validated semantic vectors. The evaluator requests all eligible results from the bounded case (at most 64 records), then applies the case's top-k after policy filtering with deterministic case-ID tie breaking. Production retrieval uses UUID tie breaking, so this is a membership comparison, not an exact production ranking trace. No latency or memory-usage claim is made; caching and store overhead would make such a comparison misleading.

Reports include a canonical normalized dataset hash, engine, screening, informational-review, claim-verification, and runner source hashes, package version, retrieval mode, model identity, and a result hash. Random runtime IDs and timestamps are excluded. The result hash is computed over the report before adding the hash itself. Repeated lexical runs with the same software and dataset produce identical JSON bytes; semantic reproducibility also depends on model/runtime identity and numerical behavior.

A fresh RecallGuard instance represents another session over the same in-memory store. This is not a process-restart or Neo4j durability test; the separate integration suite covers persistent storage.

## Add cases

The packaged [cases-v2.json](../src/recallguard/evaluation/cases-v2.json) is the current format reference and CLI default. The original [cases.json](../src/recallguard/evaluation/cases.json) is preserved for historical comparison. `--dataset PATH` accepts a strict JSON object with:

- `schema_version: 2` (version 1 remains accepted for scenarios without verification operations), a dataset ID, `kind` (`synthetic` or `adapted`), and an honest provenance statement.
- A list of cases with unique IDs, a category (`security`, `utility`, or `limitation`), source registrations, ordered operations, a retrieval query, and outcome labels.
- Operations: `write` with `MemoryInput` and a stable alias; `verify_claim` with an earlier alias, separately registered evidence source ID, and evidence reference; `grant` for an earlier alias, action, and target; or `revoke` for an earlier alias. Parent references must point to earlier writes. Trusted roots require a fixture reviewer actor.
- Optional `expected_error` on a write for an intentional 403/404/409/422 denial. Unexpected errors abort the run; an expected denial that does not happen also aborts it.

Each case is capped at 64 memories and 128 operations; datasets at 500 cases and 4 MiB. Duplicate IDs, unknown references, contradictory labels, and impossible required-result counts are rejected. The selected retrieval mode applies to the entire run. Case query limits and thresholds are included in the dataset fingerprint.

Reports omit source text and queries. Case aliases and policy reasons remain visible, so avoid sensitive identifiers when adapting private data. Validation errors do not echo input values. JSON writes are atomic, and the CLI refuses to overwrite the input dataset or use one path for both output formats.

## Findings in the reference suite

The v0.6 results below use the unchanged original dataset and labels. Both original failures involving “must deliver” and a preference-like instruction are fixed by the v0.6 policy.

| Suite | v0.5 lexical | v0.5 semantic | v0.6 lexical | v0.6 semantic |
|---|---:|---:|---:|---:|
| Original 19 cases | 16/19 | 17/19 | 18/19 | 19/19 |
| Additional 29 hardening cases | Not run | Not run | 27/29 | 27/29 |

The remaining original lexical failure is the paraphrased delivery question. Both v0.6 modes expose zero forbidden records across the original suite's 13 forbidden-labelled cases. This is an in-sample regression result, not a general security rate.

The additional [hardening.json](../src/recallguard/evaluation/hardening.json) dataset covers persistent preferences, role spoofing, overrides, financial redirection, exfiltration, tool commands, answer manipulation, concealment, encoded wrappers, malicious claim fields, and benign obligations/descriptions. These cases were developed alongside the rules and are **not held out**. An explicit Orion query marker and semantic threshold -1 force candidate coverage: this suite tests admission, not retrieval quality. Its 19 security cases all preserve a useful neighboring record while withholding the payload; all eight utility cases pass.

Two intentional limitation cases fail in both modes: a declarative false account claim is admitted informationally, and a benign security-handbook quotation is overblocked. Thus expanded-suite forbidden exposure is 1/20, and required-context recall is 27/28. The false claim still requires independent scoped approval before payment influence. There is no blanket safe-context guarantee.

Version 0.7 adds an explicit human informational-review workflow, tested separately through the engine, API, dashboard, and Neo4j persistence checks. Neither dataset automatically creates reviews, and their default admission outcomes remain unchanged. A manual exception is not counted as a detector improvement. The v0.6 reports remain historical artifacts.

Version 0.8 requires evidence-bound grants for structured claims. Its default dataset is `recallguard-synthetic-v2`: all memory content, queries, and required/forbidden labels match v1, but two grant scenarios now include explicit synthetic `verify_claim` operations against a newly registered separate source. This changes setup and the dataset hash; v2 is not the identical v1 protocol. No evidence is silently inserted by the runner. Running the preserved v1 grant scenarios against v0.8 aborts at the missing verification, instead of counting setup rejection as a defense success. Schema v1 cases without those grants, including `hardening.json`, still run.

The local v0.8 v2 run passes 18/19 lexical and 19/19 semantic cases; the 29-case hardening lexical run remains 27/29. These are synthetic workflow checks with declared reviewer verification, not real factual-validation results. CI generates full reports for the installed version.

Run the additional cases with:

```bash
python -m recallguard.evaluation \
  --dataset src/recallguard/evaluation/hardening.json \
  --output evaluation-output/hardening-lexical.json
```

Add `--mode semantic --offline --model-cache PATH` for semantic mode. CI publishes both datasets' reports. The text-only ablation remains frozen at v0.5 so changes to production screening do not silently move the baseline. Reports identify that baseline and fingerprint the new screening module.

## External benchmark readiness

The memory-poisoning MPBench is [Digital-Trust-Lab/mp-bench](https://github.com/Digital-Trust-Lab/mp-bench), accompanying [Dash et al., 2026](https://arxiv.org/abs/2606.04329). It is distinct from the multimodal process-reward benchmark with the same short name. Its repository exposes an Apache-2.0 license and adversarial/benign JSONL files.

The repository and schema were checked on 2026-09-28 at revision `6886880a7c29625e0109e0ad91d0e095029f1577`. MPBench cases contain user queries, external context, an expected memory, and follow-up queries; benign rows additionally distinguish legitimate memory writes. Those fields describe an agent's write and later-use behavior. Simply loading every `expected_memory` into RecallGuard would skip the write decision and would not reproduce the paper's evaluation. The paper's license also must not be confused with the dataset repository's license.

No MPBench rows are bundled, no MPBench score is claimed, and no automatic schema adapter is implemented here. A valid next step requires a pinned dataset revision, attribution, an explicit mapping of write decisions and action scopes, a controlled model/agent setup, and adjudication of later behavior. Hosted-model comparisons and an LLM-filter baseline also remain future work.
