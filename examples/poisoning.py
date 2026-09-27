"""Run: python examples/poisoning.py. No API credentials or external effects."""

import json
from datetime import timedelta

from recallguard.engine import RecallGuard
from recallguard.models import (
    Action,
    GrantInput,
    MemoryInput,
    Principal,
    RetrievalInput,
    Role,
    SourceInput,
    SourceType,
    now,
)
from recallguard.store import InMemoryStore


def run():
    reviewer = Principal(id="human-reviewer", role=Role.REVIEWER)
    agent = Principal(id="procurement-agent", role=Role.AGENT)
    guard = RecallGuard(InMemoryStore())
    guard.register_source(
        SourceInput(id="supplier-site", kind=SourceType.WEB, locator="https://supplier.example"),
        reviewer,
    )
    # A declarative account change avoids the simple instruction detector.
    original = guard.remember(
        MemoryInput(content="ABC supplier bank account is 991872.", source_id="supplier-site"),
        agent,
    )
    summary = guard.remember(
        MemoryInput(content="ABC bank account: 991872.", parent_ids=[original.id]),
        agent,
    )
    # New object represents a later session using the same persistent store.
    later_session = RecallGuard(guard.store)
    information = later_session.retrieve(RetrievalInput(query="ABC account"), agent)
    payment = later_session.retrieve(
        RetrievalInput(query="ABC account", action=Action.PAYMENT, target="supplier:ABC"),
        agent,
    )
    assert len(information.allowed) == 2
    assert not payment.allowed
    assert summary.authority == original.authority == 1
    assert "untrusted_external" in summary.taint_labels
    # A reviewer can permit this exact memory to influence a specific action.
    # This still does not authorize/execute a transaction or approve an amount.
    later_session.grant(
        GrantInput(
            memory_id=summary.id,
            action=Action.PAYMENT,
            target="supplier:ABC",
            reason="Account checked through an independent channel",
            expires_at=now() + timedelta(minutes=15),
        ),
        reviewer,
    )
    approved = later_session.retrieve(
        RetrievalInput(query="ABC account", action=Action.PAYMENT, target="supplier:ABC"),
        agent,
    )
    assert [m.id for m in approved.allowed] == [summary.id]
    revoked = later_session.revoke(original.id, "Supplier source was compromised", reviewer)
    after_revoke = later_session.retrieve(
        RetrievalInput(query="ABC account", action=Action.PAYMENT, target="supplier:ABC"),
        agent,
    )
    assert not after_revoke.allowed
    return {
        "external_claim_usable_for_information": len(information.allowed),
        "summary_authority": summary.authority,
        "unapproved_payment_context": len(payment.allowed),
        "explicitly_approved_context": len(approved.allowed),
        "revoked_memories": len(revoked),
        "payment_context_after_revocation": len(after_revoke.allowed),
        "real_payments_executed": 0,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
