"""Synthetic conflict recovery; no real source check or external action."""

import json

from recallguard.engine import RecallGuard
from recallguard.models import (
    ConflictResolutionInput,
    MemoryInput,
    Principal,
    RetrievalInput,
    SourceInput,
)
from recallguard.review import review_snapshot
from recallguard.store import InMemoryStore


def main():
    guard = RecallGuard(InMemoryStore())
    reviewer = Principal(id="example-reviewer", role="reviewer")
    agent = Principal(id="example-agent", role="agent")
    for sid in ("supplier-page", "supplier-email", "independent-record"):
        guard.register_source(SourceInput(id=sid, kind="web", locator=f"fixture:{sid}"), reviewer)
    first = guard.remember(
        MemoryInput(
            content="Orion account is OR1234",
            source_id="supplier-page",
            claim={"entity": "supplier:Orion", "attribute": "bank_account", "value": "OR1234"},
        ),
        agent,
    )
    guard.remember(MemoryInput(content="Orion account summary", parent_ids=[first.id]), agent)
    guard.remember(
        MemoryInput(
            content="Orion account is OR9999",
            source_id="supplier-email",
            claim={"entity": "supplier:Orion", "attribute": "bank_account", "value": "OR9999"},
        ),
        agent,
    )
    query = RetrievalInput(query="Orion")
    assert not guard.retrieve(query, agent).allowed
    options = review_snapshot(guard, reviewer, "memory")["conflict_resolution_options"][first.id]
    # A real reviewer must complete the actual check before submitting this assertion.
    result = guard.resolve_conflict(
        ConflictResolutionInput(
            selected_memory_id=first.id,
            evidence_source_id="independent-record",
            expected_fingerprint=options["evidence_sources"][0]["fingerprint"],
            evidence_reference="fixture:independent-record/page-1",
            method="official_record",
            independently_checked=True,
            reason="Synthetic example of a completed independent check",
        ),
        reviewer,
    )
    context = guard.retrieve(query, agent)
    assert [m.id for m in context.allowed] == [result.replacement_memory_id]
    assert context.unverified_claim_ids == [result.replacement_memory_id]
    assert not guard.retrieve(
        RetrievalInput(query="Orion", action="payment", target="supplier:Orion"), agent
    ).allowed
    guard.revoke(result.replacement_memory_id, "Independent evidence withdrawn", reviewer)
    assert not guard.retrieve(query, agent).allowed
    print(
        json.dumps(
            {
                "retired_records": len(result.retired_memory_ids),
                "replacement_informational_context": 1,
                "replacement_payment_context": 0,
                "context_after_replacement_revocation": 0,
                "real_checks_or_payments_performed": 0,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
