"""Explicit synthetic evidence setup for tests that already require approved claims."""

from datetime import timedelta

from recallguard.engine import blocked_reasons
from recallguard.models import ClaimVerificationInput, SourceInput, now
from recallguard.verification import current_verification, request_fingerprint


def verify_claim(guard, memory_id, reviewer):
    state = guard.inspect(reviewer)
    memory = state.memories[memory_id]
    existing = current_verification(state, memory, blocked_reasons)
    if existing:
        return existing
    source_id = "fixture-independent-check"
    if source_id not in state.sources:
        guard.register_source(
            SourceInput(
                id=source_id,
                kind="user",
                locator="fixture:independent-check",
            ),
            reviewer,
        )
        state = guard.inspect(reviewer)
    return guard.verify_claim(
        ClaimVerificationInput(
            memory_id=memory_id,
            evidence_source_id=source_id,
            expected_fingerprint=request_fingerprint(state, memory, state.sources[source_id]),
            evidence_reference="fixture:reviewer-checked-evidence",
            method="callback",
            independently_checked=True,
            reason="Independent verification for this synthetic fixture",
            expires_at=now() + timedelta(hours=1),
        ),
        reviewer,
    )
