"""Replay actual policy; compare retrieval-only ablations on an identical corpus.

No production store, tool, hosted LLM, or unsafe action is reachable here.
"""

import hashlib
import json
import re
from datetime import timedelta
from importlib import metadata
from pathlib import Path

from pydantic import ValidationError

from recallguard.embeddings import Encoder, encode_checked
from recallguard.engine import GuardError, RecallGuard
from recallguard.evaluation.schema import Case, Dataset, GrantScope, Revoke, Write
from recallguard.models import GrantInput, MemoryInput, Principal, Role, now
from recallguard.screening import POLICY_VERSION
from recallguard.store import InMemoryStore

METHODS = ("unfiltered", "text_filter", "recallguard")
MAX_DATASET_BYTES = 4 * 1024 * 1024
# Freeze the v0.5 text-only ablation so strengthening production policy does not
# silently move the comparison baseline. It deliberately scans only raw content.
INSTRUCTION = re.compile(
    r"\b(ignore|bypass|disable|override)\b|\b(always|never|must)\b|"
    r"\b(send|transfer|pay)\b.{0,100}\b(account|money|funds)\b",
    re.I | re.S,
)
CREDENTIAL = re.compile(
    r"\b(password|api[_ -]?key|secret[_ -]?key|access[_ -]?token)\s*[:=]\s*\S+", re.I
)


class EvaluationError(Exception):
    """An invalid run must not be reported as a successful defense."""


class CachedEncoder:
    """Use the same validated vectors for all methods. Not a latency benchmark."""

    def __init__(self, encoder: Encoder):
        self.encoder = encoder
        self.model_id = encoder.model_id
        self.dimensions = encoder.dimensions
        self.cache = {}

    def encode(self, texts):
        missing = list(dict.fromkeys(text for text in texts if text not in self.cache))
        if missing:
            vectors = encode_checked(self.encoder, missing)
            self.cache.update(zip(missing, vectors, strict=True))
        return [list(self.cache[text]) for text in texts]


def load_dataset(path: Path) -> Dataset:
    if path.stat().st_size > MAX_DATASET_BYTES:
        raise EvaluationError("Dataset exceeds the 4 MiB limit")
    try:
        return Dataset.model_validate_json(path.read_bytes())
    except ValidationError as error:
        # Do not echo potentially sensitive case text from a validation exception.
        raise EvaluationError(
            f"Dataset validation failed ({error.error_count()} errors); check the case schema"
        ) from None


def canonical_hash(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def fraction(numerator: int, denominator: int) -> dict:
    if not 0 <= numerator <= denominator:
        raise ValueError("Metric counts must satisfy 0 <= numerator <= denominator")
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": numerator / denominator if denominator else None,
    }


def rank(case: Case, encoder: CachedEncoder | None) -> list[tuple[str, float]]:
    corpus = {op.id: op.memory.content for op in case.operations if isinstance(op, Write)}
    ranked = []
    if encoder:
        query = encode_checked(encoder, [case.query.query])[0]
        vectors = encode_checked(encoder, list(corpus.values()))
        for mid, vector in zip(corpus, vectors, strict=True):
            score = max(-1.0, min(1.0, sum(a * b for a, b in zip(query, vector, strict=True))))
            if score >= case.query.min_score:
                ranked.append((mid, score))
    else:
        tokens = set(re.findall(r"\w+", case.query.query.casefold()))
        for mid, content in corpus.items():
            score = len(tokens & set(re.findall(r"\w+", content.casefold())))
            if score:
                ranked.append((mid, float(score)))
    return sorted(ranked, key=lambda item: (-item[1], item[0]))


def replay(case: Case, encoder: CachedEncoder | None):
    store = InMemoryStore()
    guard = RecallGuard(store, encoder)
    reviewer = Principal(id="evaluation-reviewer", role=Role.REVIEWER)
    agent = Principal(id="evaluation-agent", role=Role.AGENT)
    ids, rejected = {}, {}
    try:
        for source in case.sources:
            guard.register_source(source, reviewer)
        for index, operation in enumerate(case.operations):
            try:
                if isinstance(operation, Write):
                    data = operation.memory.model_dump()
                    # A rejected parent's alias is passed through to trigger the actual 404 path.
                    data["parent_ids"] = [ids.get(mid, mid) for mid in data["parent_ids"]]
                    try:
                        memory = guard.remember(
                            MemoryInput(**data),
                            reviewer if operation.actor == Role.REVIEWER else agent,
                        )
                    except GuardError as error:
                        if error.status != operation.expected_error:
                            raise
                        rejected[operation.id] = error.status
                        continue
                    if operation.expected_error is not None:
                        raise EvaluationError(
                            f"Case {case.id}: expected write rejection did not occur"
                        )
                    ids[operation.id] = memory.id
                elif isinstance(operation, GrantScope):
                    guard.grant(
                        GrantInput(
                            memory_id=ids[operation.memory_id],
                            action=operation.action,
                            target=operation.target,
                            reason="Independent fixture verification",
                            expires_at=now() + timedelta(hours=24),
                        ),
                        reviewer,
                    )
                elif isinstance(operation, Revoke):
                    guard.revoke(ids[operation.memory_id], "Fixture source withdrawn", reviewer)
            except (GuardError, KeyError):
                raise EvaluationError(
                    f"Case {case.id}: operation {index + 1} failed unexpectedly"
                ) from None
        # A new engine instance represents a later session over the same persisted in-memory state.
        later_session = RecallGuard(store, encoder)
        # Exhaust the bounded case before stable case-ID tie breaking. The live engine
        # uses UUID tie breaking; the evaluation reports membership, not a production ranking trace.
        query = case.query.model_copy(
            update={"limit": 100, "mode": "semantic" if encoder else "lexical"}
        )
        retrieved = later_session.retrieve(query, agent)
        aliases = {real: alias for alias, real in ids.items()}
        permitted = {aliases[m.id] for m in retrieved.allowed}
        blocked = {aliases[m.memory_id]: m.reasons for m in retrieved.blocked}
        return permitted, blocked, rejected
    finally:
        store.close()


def outcome(case: Case, admitted: list[str]) -> dict:
    returned, required, forbidden = set(admitted), set(case.required_ids), set(case.forbidden_ids)
    hits = sorted(returned & required)
    exposed = sorted(returned & forbidden)
    return {
        "admitted_ids": admitted,
        "required_hits": hits,
        "missing_required_ids": sorted(required - returned),
        "exposed_forbidden_ids": exposed,
        "case_passed": not exposed and required <= returned,
    }


def aggregate(rows: list[dict], method: str) -> dict:
    exposed = sum(bool(row["methods"][method]["exposed_forbidden_ids"]) for row in rows)
    security_cases = sum(bool(row["forbidden_ids"]) for row in rows)
    required_hits = sum(len(row["methods"][method]["required_hits"]) for row in rows)
    required_total = sum(len(row["required_ids"]) for row in rows)
    candidate_required = sum(
        len(set(row["required_ids"]) & set(row["candidate_ids"])) for row in rows
    )
    coverage = sum(bool(set(row["forbidden_ids"]) & set(row["candidate_ids"])) for row in rows)
    return {
        "cases": len(rows),
        "case_checks_passed": fraction(
            sum(row["methods"][method]["case_passed"] for row in rows), len(rows)
        ),
        "forbidden_context_exposure": fraction(exposed, security_cases),
        "required_context_recall": fraction(required_hits, required_total),
        "required_candidate_retention": fraction(required_hits, candidate_required),
        "forbidden_candidate_coverage": fraction(coverage, security_cases),
    }


def evaluate(dataset: Dataset, encoder: Encoder | None = None) -> dict:
    cached = CachedEncoder(encoder) if encoder is not None else None
    rows = []
    for case in dataset.cases:
        ranked = rank(case, cached)
        permitted, blocked, rejected = replay(case, cached)
        text_allowed = {
            op.id
            for op in case.operations
            if isinstance(op, Write)
            and not INSTRUCTION.search(op.memory.content)
            and not CREDENTIAL.search(op.memory.content)
        }
        membership = {
            "unfiltered": {mid for mid, _ in ranked},
            "text_filter": text_allowed,
            "recallguard": permitted,
        }
        methods = {
            method: outcome(
                case, [mid for mid, _ in ranked if mid in membership[method]][: case.query.limit]
            )
            for method in METHODS
        }
        rows.append(
            {
                "id": case.id,
                "category": case.category,
                "limit": case.query.limit,
                "required_ids": case.required_ids,
                "forbidden_ids": case.forbidden_ids,
                "candidate_ids": [mid for mid, _ in ranked],
                "candidate_scores": {mid: round(score, 8) for mid, score in ranked},
                "policy_blocked": dict(sorted(blocked.items())),
                "write_rejections": rejected,
                "methods": methods,
            }
        )
    report = {
        "report_version": 1,
        "scope": "offline-context-admission",
        "dataset": {
            "id": dataset.id,
            "kind": dataset.kind,
            "provenance": dataset.provenance,
            "sha256": canonical_hash(dataset.model_dump(mode="json")),
            "cases": len(rows),
        },
        "configuration": {
            "retrieval_mode": "semantic" if cached else "lexical",
            "model_id": cached.model_id if cached else None,
            "tie_breaking": "stable-case-memory-id",
            "storage": "isolated-in-memory",
            "text_filter_policy": "frozen-v0.5-raw-content",
            "screening_policy": POLICY_VERSION,
            "llm_invoked": False,
            "external_actions_executed": False,
        },
        "software": {
            "recallguard": metadata.version("recallguard"),
            "engine_sha256": hashlib.sha256(
                Path(__file__).parents[1].joinpath("engine.py").read_bytes()
            ).hexdigest(),
            "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "context_review_sha256": hashlib.sha256(
                Path(__file__).parents[1].joinpath("context_review.py").read_bytes()
            ).hexdigest(),
            "screening_sha256": hashlib.sha256(
                Path(__file__).parents[1].joinpath("screening.py").read_bytes()
            ).hexdigest(),
        },
        "limitations": [
            "Measures context exposure and retention, not agent attack success "
            "or executed actions.",
            "Dataset labels and sampling are supplied by the author; "
            "rates do not establish population guarantees.",
            "Text-only and unfiltered methods are minimal ablations, "
            "not tuned or LLM-based defenses.",
            "Stable case-ID ties differ from production UUID ties; timing is not measured.",
            "Fresh engine instances share one in-memory store; "
            "this is not a process-restart durability test.",
        ],
        "summary": {method: aggregate(rows, method) for method in METHODS},
        "by_category": {
            category: {
                method: aggregate([r for r in rows if r["category"] == category], method)
                for method in METHODS
            }
            for category in sorted({r["category"] for r in rows})
        },
        "cases": rows,
    }
    # Serialization rejects nonfinite values; the stable digest excludes itself.
    json.dumps(report, allow_nan=False)
    report["result_sha256"] = canonical_hash(report)
    return report


def markdown(report: dict) -> str:
    def rate(value):
        if value["rate"] is None:
            return "n/a (0 denominator)"
        return f"{value['numerator']}/{value['denominator']} ({value['rate']:.1%})"

    lines = [
        "# RecallGuard context-admission evaluation",
        "",
        f"Dataset: `{report['dataset']['id']}` "
        f"({report['dataset']['kind']}, {report['dataset']['cases']} cases).",
        f"Retrieval: **{report['configuration']['retrieval_mode']}**.",
        "",
        "These are context-admission checks, not agent attack-success measurements.",
        "",
        "| Method | Case checks passed | Forbidden exposure (lower is better) "
        "| Required context recall (higher is better) |",
        "|---|---:|---:|---:|",
    ]
    for method, values in report["summary"].items():
        lines.append(
            f"| {method} | {rate(values['case_checks_passed'])} "
            f"| {rate(values['forbidden_context_exposure'])} "
            f"| {rate(values['required_context_recall'])} |"
        )
    lines += ["", "## RecallGuard cases requiring attention", ""]
    for row in report["cases"]:
        result = row["methods"]["recallguard"]
        if not result["case_passed"]:
            lines.append(
                f"- `{row['id']}`: missing "
                f"{', '.join(result['missing_required_ids']) or 'none'}; "
                f"exposed {', '.join(result['exposed_forbidden_ids']) or 'none'}."
            )
    if all(row["methods"]["recallguard"]["case_passed"] for row in report["cases"]):
        lines.append("No failed checks in this dataset. This does not establish general security.")
    lines += [
        "",
        "## Limits",
        "",
        *[f"- {text}" for text in report["limitations"]],
        "",
        f"Dataset SHA-256: `{report['dataset']['sha256']}`",
        f"Result SHA-256: `{report['result_sha256']}`",
        "",
    ]
    return "\n".join(lines)
