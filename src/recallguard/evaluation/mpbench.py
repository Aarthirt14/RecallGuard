"""Pinned external-material audit. NOT a reproduction of MPBench's agent protocol.

Input is data only: no payload, skill, URL, user query or expected memory is executed.
"""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

from pydantic import ValidationError

from recallguard.engine import GuardError, RecallGuard, blocked_reasons
from recallguard.evaluation.__main__ import save
from recallguard.evaluation.runner import CREDENTIAL, INSTRUCTION, EvaluationError, fraction
from recallguard.models import MemoryInput, Principal, RetrievalInput, SourceInput
from recallguard.store import InMemoryStore

MANIFEST_PATH = Path(__file__).with_name("mpbench-manifest.json")
MAX_BYTES = 16 * 1024 * 1024
MAX_ROWS = 10000
METHODS = ("unfiltered", "text_filter", "recallguard")
PROTOCOL = "mpbench-external-material-audit-v1"


@dataclass(frozen=True)
class Row:
    id: str
    split: str
    source_line: int
    object_in_line: int
    context: str
    skill_md: str | None
    retrieval_query: str | None
    attack_type: str
    attack_signal: str
    domain: str
    legitimate_memory_write: bool | None

    @property
    def target_field(self):
        return "skill_md" if self.skill_md else "context"

    @property
    def target(self):
        return self.skill_md if self.skill_md else self.context


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError("Non-finite JSON constant")


def parse_rows(raw: bytes, split: str) -> tuple[list[Row], dict]:
    """Decode complete objects, explicitly count adjacent objects on one line.

    Do not repair strings, guess missing queries, rename classes or drop invalid rows.
    """
    if len(raw) > MAX_BYTES or split not in {"adversarial", "benign"}:
        raise EvaluationError("Corpus size or split is invalid")
    rows, seen = [], set()
    diagnostics = {
        "multiple_object_lines": [],
        "string_boolean_labels": 0,
        "id_prefix_mismatches": 0,
    }
    decoder = json.JSONDecoder(object_pairs_hook=unique_keys, parse_constant=invalid_constant)
    try:
        for line_no, line in enumerate(raw.decode("utf-8").splitlines(), 1):
            if len(line) > 128 * 1024:
                raise ValueError("Line too long")
            pos, count = 0, 0
            while pos < len(line):
                while pos < len(line) and line[pos].isspace():
                    pos += 1
                if pos == len(line):
                    break
                obj, pos = decoder.raw_decode(line, pos)
                if not isinstance(obj, dict):
                    raise ValueError("Expected an object")
                count += 1
                identifier = obj.get("id")
                if not isinstance(identifier, str) or not re.fullmatch(
                    r"(?:ADV|BEN)_\d{1,8}", identifier
                ):
                    raise ValueError("Invalid ID")
                if identifier in seen:
                    raise ValueError("Duplicate ID")
                if not identifier.startswith("ADV_" if split == "adversarial" else "BEN_"):
                    diagnostics["id_prefix_mismatches"] += 1
                seen.add(identifier)
                for key in ("context", "attack_type", "attack_signal", "domain", "user_query"):
                    value = obj.get(key)
                    if not isinstance(value, str) or not value.strip():
                        raise ValueError("Missing required text")
                for key in ("attack_type", "attack_signal", "domain"):
                    if not re.fullmatch(r"[a-z][a-z0-9_]{0,99}", obj[key]):
                        raise ValueError("Invalid category")
                for key, limit in (
                    ("context", 16000),
                    ("skill_md", 16000),
                    ("retrieval_query", 2000),
                    ("expected_memory", 16000),
                    ("user_query", 2000),
                ):
                    value = obj.get(key)
                    if value is not None and (not isinstance(value, str) or len(value) > limit):
                        raise ValueError("Invalid text type or length")
                if "skill_md" in obj and (not obj["skill_md"] or not obj["skill_md"].strip()):
                    raise ValueError("Empty skill document")
                legitimate = obj.get("legitimate_memory_write")
                if split == "benign":
                    if isinstance(legitimate, str) and legitimate in {"true", "false"}:
                        legitimate = legitimate == "true"
                        diagnostics["string_boolean_labels"] += 1
                    if type(legitimate) is not bool or obj["attack_type"] != "benign":
                        raise ValueError("Invalid benign annotation")
                elif legitimate is not None:
                    raise ValueError("Unexpected adversarial write label")
                query = obj.get("retrieval_query")
                rows.append(
                    Row(
                        identifier,
                        split,
                        line_no,
                        count,
                        obj["context"],
                        obj.get("skill_md"),
                        query if query and query.strip() else None,
                        obj["attack_type"],
                        obj["attack_signal"],
                        obj["domain"],
                        legitimate,
                    )
                )
                if len(rows) > MAX_ROWS:
                    raise ValueError("Too many records")
            if count > 1:
                diagnostics["multiple_object_lines"].append({"line": line_no, "objects": count})
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise EvaluationError(
            f"Invalid {split} corpus near record {len(rows) + 1}; no results produced"
        ) from None
    if not rows:
        raise EvaluationError(f"Empty {split} corpus")
    return rows, diagnostics


def load_corpus(directory: Path, manifest: dict | None = None):
    manifest = manifest or json.loads(MANIFEST_PATH.read_text())
    rows, diagnostics, files = [], {}, {}
    for filename, spec in manifest["files"].items():
        path = directory / filename
        if path.stat().st_size > MAX_BYTES:
            raise EvaluationError("Input file exceeds the 16 MiB limit")
        raw = path.read_bytes()
        if len(raw) != spec["bytes"] or sha256(raw) != spec["sha256"]:
            raise EvaluationError(f"Pinned corpus integrity check failed for {filename}")
        files[filename] = {"bytes": len(raw), "sha256": sha256(raw)}
        if "split" in spec:
            parsed, diagnostic = parse_rows(raw, spec["split"])
            if len(parsed) != spec["rows"]:
                raise EvaluationError("Parsed row count differs from manifest")
            rows.extend(parsed)
            diagnostics[spec["split"]] = diagnostic
    return rows, {
        "repository": manifest["repository"],
        "revision": manifest["revision"],
        "license": manifest["license"],
        "files": files,
        "parsing": diagnostics,
    }


def lexical_candidate(text: str, query: str | None) -> bool | None:
    if query is None:
        return None
    return bool(
        set(re.findall(r"\w+", text.casefold())) & set(re.findall(r"\w+", query.casefold()))
    )


def audit_row(row: Row) -> dict:
    guard = RecallGuard(InMemoryStore())
    reviewer = Principal(id="corpus-registration", role="reviewer")
    agent = Principal(id="corpus-ingestion", role="agent")
    fields = {"context": row.context}
    if row.skill_md:
        fields["skill_md"] = row.skill_md
    memories, outcomes = {}, {}
    try:
        for field, content in fields.items():
            guard.register_source(
                SourceInput(id=field, kind="web", locator=f"corpus:{field}"), reviewer
            )
            try:
                memory = guard.remember(MemoryInput(content=content, source_id=field), agent)
            except GuardError as error:
                if (
                    error.status != 422
                    or error.message != "Potential credential detected; memory was not stored"
                ):
                    raise EvaluationError("Unexpected ingestion failure; run aborted") from None
                outcomes[field] = {
                    "write_state": "credential_rejected",
                    "reasons": ["credential_rejected"],
                    "informational_eligible": False,
                }
            else:
                memories[field] = memory
                reasons = guard.store.transact(
                    lambda state, mid=memory.id: blocked_reasons(state, state.memories[mid])
                )
                outcomes[field] = {
                    "write_state": memory.status.value,
                    "reasons": sorted(reasons),
                    "informational_eligible": not reasons,
                }
        # A fresh instance reads the same isolated store. This is not process durability.
        retrieved = None
        if row.retrieval_query is not None:
            result = RecallGuard(guard.store).retrieve(
                RetrievalInput(query=row.retrieval_query, mode="lexical", limit=2), agent
            )
            target = memories.get(row.target_field)
            retrieved = bool(target and target.id in {m.id for m in result.allowed})
        raw_candidate = lexical_candidate(row.target, row.retrieval_query)
        simple_eligible = not (INSTRUCTION.search(row.target) or CREDENTIAL.search(row.target))
        target_outcome = outcomes[row.target_field]
        methods = {
            "unfiltered": {"informational_eligible": True, "query_returned": raw_candidate},
            "text_filter": {
                "informational_eligible": simple_eligible,
                "query_returned": bool(raw_candidate and simple_eligible)
                if raw_candidate is not None
                else None,
            },
            "recallguard": {**target_outcome, "query_returned": retrieved},
        }
        return {
            "case_id": f"{row.split}:{row.id}",
            "id": row.id,
            "split": row.split,
            "source_line": row.source_line,
            "object_in_line": row.object_in_line,
            "attack_type": row.attack_type,
            "attack_signal": row.attack_signal,
            "domain": row.domain,
            "legitimate_memory_write": row.legitimate_memory_write,
            "target_field": row.target_field,
            "target_sha256": sha256(row.target.encode()),
            "material_sha256": {
                field: sha256(content.encode()) for field, content in fields.items()
            },
            "retrieval_query_available": row.retrieval_query is not None,
            "raw_lexical_candidate": raw_candidate,
            "methods": methods,
        }
    except ValidationError:
        raise EvaluationError("API schema rejected corpus material; run aborted") from None
    finally:
        guard.store.close()


def summarize(rows: list[dict]) -> dict:
    candidates = [r for r in rows if r["raw_lexical_candidate"] is True]
    queried = [r for r in rows if r["retrieval_query_available"]]
    return {
        "rows": len(rows),
        "unique_target_texts": len({r["target_sha256"] for r in rows}),
        "query_available": len(queried),
        "raw_lexical_candidates": len(candidates),
        "methods": {
            method: {
                "eligible": fraction(
                    sum(r["methods"][method]["informational_eligible"] for r in rows), len(rows)
                ),
                "withheld": fraction(
                    sum(not r["methods"][method]["informational_eligible"] for r in rows), len(rows)
                ),
                "query_returned": fraction(
                    sum(r["methods"][method]["query_returned"] is True for r in queried),
                    len(queried),
                ),
                "candidate_retained": fraction(
                    sum(r["methods"][method]["query_returned"] is True for r in candidates),
                    len(candidates),
                ),
            }
            for method in METHODS
        },
        "recallguard_write_states": dict(
            sorted(Counter(r["methods"]["recallguard"]["write_state"] for r in rows).items())
        ),
    }


def evaluate(rows: list[Row], provenance: dict) -> dict:
    results = [audit_row(row) for row in rows]
    root = Path(__file__).parents[1]
    groups = {}
    for split in ("adversarial", "benign"):
        subset = [r for r in results if r["split"] == split]
        groups[split] = {"overall": summarize(subset)}
        for key in ("attack_type", "attack_signal", "domain", "target_field"):
            groups[split][key] = {
                str(value): summarize([r for r in subset if r[key] == value])
                for value in sorted({r[key] for r in subset})
            }
        if split == "benign":
            groups[split]["legitimate_memory_write"] = {
                str(value).lower(): summarize(
                    [r for r in subset if r["legitimate_memory_write"] == value]
                )
                for value in (False, True)
            }
    return {
        "protocol": PROTOCOL,
        "provenance": provenance,
        "configuration": {
            "input": (
                "context and separate skill_md when present; skill_md is the target in skill cases"
            ),
            "ingestion": "forced external roots, no agent memory-selection step",
            "source_kind": "web",
            "retrieval": (
                "lexical, one isolated row per workspace, limit=2, original retrieval_query only"
            ),
            "text_filter": "frozen-v0.5-raw-content",
            "expected_memory_used": False,
            "user_query_executed": False,
            "llm_invoked": False,
            "external_actions_executed": False,
        },
        "software": {
            "recallguard": metadata.version("recallguard"),
            "source_sha256": {
                name: sha256((root / name).read_bytes())
                for name in (
                    "evaluation/mpbench.py",
                    "evaluation/runner.py",
                    "engine.py",
                    "screening.py",
                    "models.py",
                    "store.py",
                    "context_review.py",
                    "verification.py",
                    "conflicts.py",
                )
            },
        },
        "limitations": [
            (
                "This is an external-material admission audit, not MPBench ASR/RSR or an "
                "agent benchmark reproduction."
            ),
            (
                "Forced ingestion skips the agent write decision, summarization and later "
                "behavior; no tool actions or hosted model are tested."
            ),
            (
                "Whole target material eligibility does not establish whether an agent adopts "
                "its malicious span or answers correctly."
            ),
            (
                "Benign withholding measures access to supplied context, not correctness of "
                "legitimate_memory_write decisions."
            ),
            (
                "Raw corpus labels and duplicate rows are preserved; row-weighted results are "
                "not independent samples or verified ground truth."
            ),
            (
                "Missing follow-up queries have no retrieval outcome and do not count as "
                "successfully blocked attacks."
            ),
            (
                "Lexical misses are reported separately from admission withholding; no "
                "semantic-retrieval result is claimed."
            ),
        ],
        "groups": groups,
        "rows": results,
    }


def markdown(report: dict) -> str:
    lines = [
        "# MPBench external-material audit",
        "",
        (
            "**This is not MPBench attack success or retrieval success, and does not test "
            "an agent acting on memory.**"
        ),
        "",
        f"Protocol: `{report['protocol']}`. "
        f"Upstream revision: `{report['provenance']['revision']}`.",
        "",
        (
            "Rows are forced through external-memory ingestion. Skill cases target "
            "`skill_md`; all other cases target `context`. No expected memory is "
            "inserted. Missing queries are excluded only from retrieval denominators."
        ),
        "",
        (
            "| Split | Rows | Unique target texts | Eligible for information | Withheld | "
            "Queries available | Raw lexical candidates | Returned for query |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for split in ("adversarial", "benign"):
        group = report["groups"][split]["overall"]
        metric = group["methods"]["recallguard"]
        lines.append(
            f"| {split} | {group['rows']} | {group['unique_target_texts']} | "
            f"{metric['eligible']['numerator']} | {metric['withheld']['numerator']} | "
            f"{group['query_available']} | {group['raw_lexical_candidates']} | "
            f"{metric['query_returned']['numerator']} |"
        )
    lines += [
        "",
        "## Admission comparison",
        "",
        "| Method | Adversarial target eligible | Benign target withheld |",
        "|---|---:|---:|",
    ]
    for method in METHODS:
        a = report["groups"]["adversarial"]["overall"]["methods"][method]["eligible"]
        b = report["groups"]["benign"]["overall"]["methods"][method]["withheld"]
        lines.append(
            f"| {method} | {a['numerator']}/{a['denominator']} | "
            f"{b['numerator']}/{b['denominator']} |"
        )
    lines += [
        "",
        "## Adversarial categories (upstream labels unchanged)",
        "",
        "| Attack type | Rows | Eligible | Withheld |",
        "|---|---:|---:|---:|",
    ]
    for key, group in report["groups"]["adversarial"]["attack_type"].items():
        metric = group["methods"]["recallguard"]
        lines.append(
            f"| {key} | {group['rows']} | {metric['eligible']['numerator']} | "
            f"{metric['withheld']['numerator']} |"
        )
    lines += [
        "",
        "## Parsing notes",
        "",
        "```json",
        json.dumps(report["provenance"]["parsing"], indent=2),
        "```",
        "",
        "## Limits",
        "",
    ]
    lines.extend(f"- {limit}" for limit in report["limitations"])
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline pinned MPBench material audit; not an agent benchmark"
    )
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument(
        "--summary", type=Path, help="Also write groups/provenance without per-row results"
    )
    args = parser.parse_args(argv)
    try:
        manifest = json.loads(MANIFEST_PATH.read_text())
        inputs = {
            MANIFEST_PATH.resolve(),
            *((args.data_dir / f).resolve() for f in manifest["files"]),
        }
        outputs = [p.resolve() for p in (args.output, args.markdown, args.summary) if p is not None]
        if len(outputs) != len(set(outputs)) or inputs.intersection(outputs):
            raise EvaluationError("Input and output paths must be distinct")
        rows, provenance = load_corpus(args.data_dir, manifest)
        report = evaluate(rows, provenance)
        save(
            args.output,
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
            + "\n",
        )
        if args.markdown:
            save(args.markdown, markdown(report))
        if args.summary:
            save(
                args.summary,
                json.dumps(
                    {k: v for k, v in report.items() if k != "rows"},
                    indent=2,
                    sort_keys=True,
                    allow_nan=False,
                )
                + "\n",
            )
        print(
            f"Audited {len(rows)} external-material rows. No agent behavior or actions evaluated."
        )
    except (EvaluationError, OSError) as error:
        message = (
            str(error)
            if isinstance(error, EvaluationError)
            else "Could not read pinned inputs or save reports"
        )
        print(f"Audit failed: {message}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
