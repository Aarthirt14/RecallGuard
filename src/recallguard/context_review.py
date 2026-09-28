"""Narrow, explicit review exceptions for direct-source informational context.

Never clears stored restrictions or propagates permission to derived records.
"""

import hashlib
import json
from pathlib import Path

from recallguard.models import ContextReview, Memory, Status, now
from recallguard.screening import screen_memory
from recallguard.store import State

# Invalidate prior exceptions when either review eligibility or screening changes.
POLICY_FINGERPRINT = hashlib.sha256(
    Path(__file__).read_bytes()
    + Path(__file__).with_name("screening.py").read_bytes()
    + Path(__file__).with_name("engine.py").read_bytes()
).hexdigest()


def review_fingerprint(memory: Memory) -> str:
    return hashlib.sha256(
        json.dumps(
            {"memory": memory.model_dump(mode="json"), "policy": POLICY_FINGERPRINT},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def review_request_fingerprint(state: State, memory: Memory) -> str:
    previous = sorted(
        (r.id, r.withdrawn_at.isoformat() if r.withdrawn_at else None)
        for r in state.context_reviews.values()
        if r.memory_id == memory.id
    )
    fingerprint = review_fingerprint(memory)
    if not previous:
        return fingerprint
    # A delayed approval request must not recreate an exception after withdrawal.
    return hashlib.sha256(json.dumps([fingerprint, previous]).encode()).hexdigest()


def review_blockers(memory: Memory) -> list[str]:
    """Only own instruction screening may be excepted; reject everything else."""
    reasons = []
    screening = screen_memory(memory.content, memory.claim)
    if memory.parent_ids or not memory.source_id:
        reasons.append("direct_source_required")
    if memory.status == Status.REVOKED:
        reasons.append("memory_revoked")
    if memory.conflict_ids:
        reasons.append("unresolved_conflict")
    if screening.credential:
        reasons.append("credential_not_reviewable")
    if set(memory.taint_labels) - {"untrusted_external", "contains_instruction"}:
        reasons.append("non_instruction_taint")
    if any(
        r not in {"instruction_requires_review", "instruction_taint"}
        and r not in {f"content_policy:{signal}" for signal in screening.instruction_signals}
        for r in memory.reasons
    ):
        reasons.append("non_instruction_restriction")
    if memory.status == Status.QUARANTINED and not (
        "contains_instruction" in memory.taint_labels and memory.reasons
    ):
        reasons.append("unclassified_quarantine")
    if not screening.instruction_signals and memory.status != Status.QUARANTINED:
        reasons.append("review_not_required")
    return reasons


def current_review(state: State, memory: Memory) -> ContextReview | None:
    candidates = [
        r
        for r in state.context_reviews.values()
        if r.memory_id == memory.id and r.withdrawn_at is None and r.expires_at > now()
    ]
    if not candidates or review_blockers(memory):
        return None
    fingerprint = review_fingerprint(memory)
    return next((r for r in candidates if r.memory_fingerprint == fingerprint), None)
