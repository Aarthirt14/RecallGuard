# Reproducible context-admission evaluation

RecallGuard now includes an offline runner that compares three methods on the same data and retrieval scores:

| Method | Behavior |
|---|---|
| `unfiltered` | Return matching records without lifecycle, text, lineage, or grant checks |
| `text_filter` | Reject each record matching RecallGuard's instruction or credential patterns; do not propagate parent restrictions or enforce grants |
| `recallguard` | Replay writes, grants, and revocations through the real policy engine, then retrieve through a fresh engine instance over the same store |

The first two methods are deliberately minimal ablations. They are not tuned defenses or an LLM-filter baseline. Every run uses new, isolated in-memory stores. There is no database connection, hosted LLM, payment, message, shell payload, or external tool execution. Source locators are data and are never fetched.

## Run

```bash
python -m pip install -e '.[dev]'
python -m recallguard.evaluation \
  --output evaluation/results/lexical.json \
  --markdown evaluation/results/lexical.md
```

The installed `recallguard-eval` command is equivalent. Omit `--output` to print JSON to stdout. A valid evaluation returns exit code 0 even when cases reveal weaknesses; input, setup, or provider failure returns a nonzero code. Invalid runs are not counted as successful defenses.

For semantic retrieval:

```bash
python -m pip install -e '.[dev,semantic]'
python -m recallguard.evaluation --mode semantic \
  --model-cache .model-cache \
  --output evaluation/results/semantic.json \
  --markdown evaluation/results/semantic.md
```

Use `--offline` after provisioning the model cache, or supply `--model-path`. The model is the same local MiniLM adapter used by the API. The first online run downloads assets; inference stays local. Semantic scores depend on the fingerprinted model and runtime versions. Thresholds come from each case's `query.min_score` (default 0.25).

The bundled JSON and Markdown [reference results](../evaluation/results/) were generated from this implementation. They are examples of the runner's output, not a published security benchmark. Regenerate them after code or fixture changes; source and data hashes identify the exact run inputs.

## What is measured

The 19 original, handwritten scenarios cover exact grants, scope mismatches, inherited quarantine, revocation, late conflicts, authority ceilings, credential rejection, filtering before top-k, benign information, and known limitations. Each case supplies required memory IDs and forbidden memory IDs independently of the policy being tested. Both sets can be present; unlabelled distractors are allowed but can consume retrieval slots.

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

Reports include a canonical normalized dataset hash, engine and runner source hashes, package version, retrieval mode, model identity, and a result hash. Random runtime IDs and timestamps are excluded. The result hash is computed over the report before adding the hash itself. Repeated lexical runs with the same software and dataset produce identical JSON bytes; semantic reproducibility also depends on model/runtime identity and numerical behavior.

A fresh RecallGuard instance represents another session over the same in-memory store. This is not a process-restart or Neo4j durability test; the separate integration suite covers persistent storage.

## Add cases

The packaged [cases.json](../src/recallguard/evaluation/cases.json) is the format reference. `--dataset PATH` accepts a strict JSON object with:

- `schema_version: 1`, a dataset ID, `kind` (`synthetic` or `adapted`), and an honest provenance statement.
- A list of cases with unique IDs, a category (`security`, `utility`, or `limitation`), source registrations, ordered operations, a retrieval query, and outcome labels.
- Operations: `write` with `MemoryInput` and a stable alias; `grant` for an earlier alias, action, and target; or `revoke` for an earlier alias. Parent references must point to earlier writes. Trusted roots require a fixture reviewer actor.
- Optional `expected_error` on a write for an intentional 403/404/409/422 denial. Unexpected errors abort the run; an expected denial that does not happen also aborts it.

Each case is capped at 64 memories and 128 operations; datasets at 500 cases and 4 MiB. Duplicate IDs, unknown references, contradictory labels, and impossible required-result counts are rejected. The selected retrieval mode applies to the entire run. Case query limits and thresholds are included in the dataset fingerprint.

Reports omit source text and queries. Case aliases and policy reasons remain visible, so avoid sensitive identifiers when adapting private data. Validation errors do not echo input values. JSON writes are atomic, and the CLI refuses to overwrite the input dataset or use one path for both output formats.

## Findings in the reference suite

The lexical run passes 16 of 19 RecallGuard case checks; semantic retrieval passes 17. The remaining failures are intentionally reported:

1. A benign sentence containing “must deliver” is quarantined by the English instruction pattern.
2. A preference-like instruction without a recognized trigger can enter informational context. Scoped action gates do not make arbitrary informational context safe against prompt injection.
3. Lexical retrieval misses a paraphrased delivery question. MiniLM retrieves it in this fixture.

The evaluator does not automatically approve memories, weaken policy to improve scores, or hide these failures. Fixes need independent cases and evidence, not just changes that fit these examples.

## External benchmark readiness

The memory-poisoning MPBench is [Digital-Trust-Lab/mp-bench](https://github.com/Digital-Trust-Lab/mp-bench), accompanying [Dash et al., 2026](https://arxiv.org/abs/2606.04329). It is distinct from the multimodal process-reward benchmark with the same short name. Its repository exposes an Apache-2.0 license and adversarial/benign JSONL files.

The repository and schema were checked on 2026-09-28 at revision `6886880a7c29625e0109e0ad91d0e095029f1577`. MPBench cases contain user queries, external context, an expected memory, and follow-up queries; benign rows additionally distinguish legitimate memory writes. Those fields describe an agent's write and later-use behavior. Simply loading every `expected_memory` into RecallGuard would skip the write decision and would not reproduce the paper's evaluation. The paper's license also must not be confused with the dataset repository's license.

No MPBench rows are bundled, no MPBench score is claimed, and no automatic schema adapter is implemented here. A valid next step requires a pinned dataset revision, attribution, an explicit mapping of write decisions and action scopes, a controlled model/agent setup, and adjudication of later behavior. Hosted-model comparisons and an LLM-filter baseline also remain future work.
