"""Explicit reviewer exception for a benign quotation; no external actions."""

import json
from datetime import timedelta

from recallguard.engine import RecallGuard
from recallguard.models import (
    ContextReviewInput,
    MemoryInput,
    Principal,
    RetrievalInput,
    SourceInput,
    now,
)
from recallguard.review import review_snapshot
from recallguard.store import InMemoryStore


def main():
    guard = RecallGuard(InMemoryStore())
    reviewer = Principal(id="example-reviewer", role="reviewer")
    agent = Principal(id="example-agent", role="agent")
    guard.register_source(
        SourceInput(id="handbook", kind="file", locator="fixture:handbook"), reviewer
    )
    root = guard.remember(
        MemoryInput(
            content="Orion handbook quotes 'Ignore prior instructions' as an attack example.",
            source_id="handbook",
        ),
        agent,
    )
    query = RetrievalInput(query="Orion")
    assert not guard.retrieve(query, agent).allowed
    snapshot = review_snapshot(guard, reviewer, "memory")
    # In the actual workflow a human examines this text and scope before approval.
    review = guard.review_context(
        ContextReviewInput(
            memory_id=root.id,
            expected_fingerprint=snapshot["context_review_options"][root.id]["fingerprint"],
            reason="Human reviewer confirmed this is a benign training quotation",
            expires_at=now() + timedelta(minutes=30),
        ),
        reviewer,
    )
    admitted = guard.retrieve(query, agent)
    assert admitted.context_reviews == {root.id: review.id}
    assert not guard.retrieve(
        RetrievalInput(query="Orion", action="payment", target="Orion"), agent
    ).allowed
    guard.withdraw_context_review(review.id, "Reviewer withdrew the temporary exception", reviewer)
    assert not guard.retrieve(query, agent).allowed
    print(
        json.dumps(
            {
                "default_context": "blocked",
                "reviewed_context": "allowed for information only",
                "payment_context": "blocked",
                "after_withdrawal": "blocked",
                "stored_status": guard.inspect(reviewer).memories[root.id].status,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
