# External-material audit using MPBench

This audit tests RecallGuard's handling of independently authored external text. It does **not** reproduce MPBench's agent memory-write and later-action experiment, and its counts must not be called MPBench attack-success or retrieval-success scores.

The upstream corpus is [Digital-Trust-Lab/mp-bench](https://github.com/Digital-Trust-Lab/mp-bench), revision `6886880a7c29625e0109e0ad91d0e095029f1577`. Its README describes writing an adversarial instruction into memory and then retrieving and acting on it in a later session. RecallGuard currently has no generic agent harness for all of those task domains. Inserting the supplied `expected_memory` would assume the attacker had already succeeded at the write stage, so this audit never uses it as memory content or an outcome oracle.

## Reproduce

Install the project, then fetch the pinned data. No upstream code is run:

```bash
python -m pip install -e '.[dev]'
git init evaluation-output/mpbench-input
git -C evaluation-output/mpbench-input remote add origin https://github.com/Digital-Trust-Lab/mp-bench.git
git -C evaluation-output/mpbench-input fetch --depth=1 origin 6886880a7c29625e0109e0ad91d0e095029f1577
git -C evaluation-output/mpbench-input config core.autocrlf false
git -C evaluation-output/mpbench-input checkout --detach FETCH_HEAD
python -m recallguard.evaluation.mpbench \
  --data-dir evaluation-output/mpbench-input \
  --output evaluation-output/mpbench/full.json \
  --summary evaluation-output/mpbench/summary.json \
  --markdown evaluation-output/mpbench/report.md
```

The audit itself is offline and lexical. It takes no service credentials, connects to no live database, invokes no model or skill, and never fetches corpus URLs. Each row gets a new in-memory workspace, discarded after measurement. The upstream dataset is not bundled in the package or this repository; SHA-256 and byte counts for both data files, LICENSE and README are pinned in the packaged [manifest](../src/recallguard/evaluation/mpbench-manifest.json). Missing or changed files abort the run. There is no CLI option to bypass integrity checks or select a favorable subset.

A valid run returns 0 even when the policy performs poorly. Integrity, schema, setup and unexpected engine failures return nonzero; they do not count as blocked attacks. Reports are individually written atomically after a complete successful evaluation. The CLI refuses to overwrite an input or use the same output path twice. The full JSON includes per-row decisions, stable split-qualified IDs and hashes, but no contexts, queries, expected memories, skill text or credential values. `--summary` omits per-row results.

## Protocol mapping

| Upstream field | Treatment |
|---|---|
| `context` | Always submitted as one untrusted external root through the real agent-ingestion path |
| `skill_md`, when present | Submitted as a second, separate untrusted root; it is the target material for that row because the attack is in the skill document |
| Target material for other rows | The original `context` |
| `user_query` | Validated as metadata; not executed or inserted into memory |
| `expected_memory` | Optional annotation only; never written, summarized, retrieved, or used as an oracle |
| `retrieval_query` | Used unchanged when nonempty; no fallback is invented when it is missing |
| `legitimate_memory_write` | Preserved and used for benign subgroup reporting; not treated as a command or expected admission decision |
| Attack type, signal and domain | Raw upstream category names retained, including spelling variants |
| Split | Taken from the pinned file, not guessed from ID prefixes |

Both material sources use the fixed low-authority `web` type, regardless of the domain label. This is an explicit conservative mapping for untrusted text, not authenticated email/tool/skill execution. The ordinary ingestion model trims outer whitespace; the adapter makes no changes to payload strings and does not turn literal `\\n` sequences into newlines. No structured claims, grants, independent checks, reviews, trusted roots, or action approvals are synthesized.

After ingestion, a fresh RecallGuard instance uses the same in-memory store to run informational retrieval. There is one row per workspace and at most two memory records; `limit=2` avoids a ranking cutoff. This is not a database restart or durability experiment. Only the row's target record is scored. In skill cases, returning the harmless background email while withholding the skill payload does not count as returning the attack.

## Counts and denominators

Three methods see the same target text:

- **Unfiltered:** all target material is eligible; retrieval depends only on lexical word overlap.
- **Text filter:** the existing, frozen v0.5 raw-content instruction/credential filter. This deliberately simple ablation is not an LLM filter or a current competing defense.
- **RecallGuard:** real ingestion, credential rejection, quarantine, live admission checks and actual later informational retrieval.

Every method reports:

| Measure | Numerator / denominator |
|---|---|
| Eligible | Target records eligible for informational use / all rows in the group |
| Withheld | Target records unavailable through informational admission / all rows in the group |
| Query returned | Target records returned for the original follow-up query / rows with usable follow-up queries |
| Candidate retained | Target records returned / rows whose target text has raw lexical overlap with the query |

Missing queries have `null` per-row retrieval outcomes and do not count as successful defenses. Lexical misses are distinct from screening. A zero denominator produces a null rate. Whole-material eligibility does not establish whether the attacker-controlled span influences an agent, and benign withholding does not measure answer quality or correctness of memory-write decisions. In particular, most benign rows explicitly say that no legitimate memory write is expected; this audit measures availability of supplied context, not whether an agent should remember facts from it.

## Corpus accounting

All 6,240 parsed rows are included: 3,241 adversarial and 2,999 benign. The parser accounts for these upstream quirks without silently dropping cases:

- Adversarial physical line 1080 contains two adjacent JSON objects. Both are decoded and retain the original line number plus their object positions. There are 3,240 physical lines but 3,241 objects.
- Seven benign boolean labels are strings (`"true"` five times, `"false"` twice). Only these exact strings are normalized to booleans, and the normalization count is reported.
- The final 300 benign records use `ADV_` IDs. They remain in the benign split, with IDs qualified by split to avoid collisions with adversarial IDs.
- 242 adversarial and two benign rows have no usable follow-up query. They remain in admission counts and are excluded only from retrieval denominators.
- 240 adversarial rows carry a separate `skill_md`; their target is that field, not the background context.
- Duplicate target text is retained in row-weighted counts. Unique-text counts are also reported. These are not statistically independent trials.

Malformed JSON, duplicate keys, duplicate IDs within a split, invalid field types, oversized text and unknown boolean encodings abort the whole run with sanitized errors. Metadata fields that are not part of this protocol are ignored; they never control the engine or execution.

## Results and interpretation

The versioned [reference report](../evaluation/results/v0.10/mpbench.md) and [summary JSON](../evaluation/results/v0.10/mpbench-summary.json) contain the full-corpus outcome counts, category breakdowns, exact input hashes, protocol settings, and source hashes. CI repeats the audit and uploads full per-row JSON, summary and Markdown as the `external-context-audit` artifact. CI requires a valid run, not a favorable score.

The v0.10 lexical audit produced:

| Finding | Count | Share |
|---|---:|---:|
| Adversarial target material eligible for information | 1,773 / 3,241 | 54.7% |
| Benign target material withheld | 488 / 2,999 | 16.3% |
| Fact-injection target material eligible | 445 / 601 | 74.0% |
| Benign contexts with legitimate-write=true withheld | 64 / 249 | 25.7% |

The frozen v0.5 text filter admits 1,932 adversarial targets and withholds 219 benign targets. RecallGuard therefore admits 159 fewer adversarial targets while withholding 269 additional benign targets on this corpus. This is a tradeoff, not evidence of an unqualified overall improvement. The current pattern screen is insufficient as a general informational-context defense. These counts also do not show whether the separate action gate would allow a consequential operation.

No production screening rules were changed for this audit. The external corpus was inspected to implement the schema mapping; it must not be described as a blind or held-out evaluation. It is independently authored material, not independently verified ground truth. Future tuning on these cases makes their scores development results; improvement claims then need another untouched dataset or evaluation partition.

The next research step is a controlled memory-writing agent with fixed prompts/model configuration, domain-appropriate tools and independent adjudication of later behavior. This audit does not measure summarization attacks, multi-session agent decisions, semantic retrieval, real tool execution, or malicious-action prevention. Existing action grants and the procurement simulator remain separate controls.

Attribution and the upstream Apache-2.0 license are in [third_party/mpbench](../third_party/mpbench/NOTICE.md). The dataset repository's license is distinct from any license attached to the paper.
