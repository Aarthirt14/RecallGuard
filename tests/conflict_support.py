"""Synthetic reviewer requests for conflict retirement tests."""

from recallguard.conflicts import resolution_fingerprint
from recallguard.models import ConflictResolutionInput


def resolution_request(guard, reviewer, selected, source="user", **changes):
    state = guard.inspect(reviewer)
    memory = state.memories[selected.id]
    return ConflictResolutionInput(
        **{
            "selected_memory_id": memory.id,
            "evidence_source_id": source,
            "expected_fingerprint": resolution_fingerprint(state, memory, state.sources[source]),
            "evidence_reference": "fixture:independent-record-001",
            "method": "official_record",
            "independently_checked": True,
            "reason": "Synthetic independent check of the selected value",
            **changes,
        }
    )
