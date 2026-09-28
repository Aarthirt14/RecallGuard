"""Reviewer attestations of independent checks, never automatic truth detection."""

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

from recallguard.models import ClaimVerification, Memory, Source, now
from recallguard.store import State

Restrictions = Callable[[State, Memory], list[str]]
POLICY_FINGERPRINT = hashlib.sha256(
    Path(__file__).read_bytes()
    + Path(__file__).with_name("engine.py").read_bytes()
    + Path(__file__).with_name("screening.py").read_bytes()
).hexdigest()


def record_fingerprint(memory: Memory, source: Source) -> str:
    value = {
        "memory": memory.model_dump(mode="json"),
        "evidence_source": source.model_dump(mode="json"),
        "policy": POLICY_FINGERPRINT,
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def request_fingerprint(state: State, memory: Memory, source: Source) -> str:
    history = sorted(
        (v.id, v.withdrawn_at.isoformat() if v.withdrawn_at else None)
        for v in state.claim_verifications.values()
        if v.memory_id == memory.id
    )
    return hashlib.sha256(
        json.dumps([record_fingerprint(memory, source), history]).encode()
    ).hexdigest()


def verification_blockers(
    state: State, memory: Memory, source_id: str, restrictions: Restrictions
) -> list[str]:
    reasons = []
    if memory.claim is None:
        reasons.append("structured_claim_required")
    if restrictions(state, memory):
        reasons.append("restricted_memory")
    source = state.sources.get(source_id)
    if source is None:
        reasons.append("evidence_source_missing")
    else:
        # This rejects obvious reuse, not undisclosed mirrors or colluding sources.
        origins = [state.sources.get(sid) for sid in memory.origin_ids]
        if any(origin is None for origin in origins):
            reasons.append("origin_source_missing")
        if source_id in memory.origin_ids or any(
            origin
            and origin.locator.casefold().rstrip("/") == source.locator.casefold().rstrip("/")
            for origin in origins
        ):
            reasons.append("separate_evidence_source_required")
    return reasons


def valid_verification(
    state: State, memory: Memory, verification_id: str | None, restrictions: Restrictions
) -> ClaimVerification | None:
    verification = state.claim_verifications.get(verification_id)
    if (
        verification is None
        or verification.memory_id != memory.id
        or verification.withdrawn_at is not None
        or verification.expires_at <= now()
        or verification.claim != memory.claim
        or verification_blockers(state, memory, verification.evidence_source_id, restrictions)
    ):
        return None
    source = state.sources[verification.evidence_source_id]
    if verification.record_fingerprint != record_fingerprint(memory, source):
        return None
    return verification


def current_verification(
    state: State, memory: Memory, restrictions: Restrictions
) -> ClaimVerification | None:
    return next(
        (
            valid
            for v in state.claim_verifications.values()
            if v.memory_id == memory.id
            and (valid := valid_verification(state, memory, v.id, restrictions)) is not None
        ),
        None,
    )
