from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from pydantic import ValidationError

from recallguard.context_review import review_fingerprint
from recallguard.engine import GuardError
from recallguard.models import (
    Claim,
    ContextReviewInput,
    GrantInput,
    MemoryInput,
    RetrievalInput,
    Status,
    now,
)
from recallguard.review import review_snapshot


@pytest.fixture
def quoted(guard, agent):
    return guard.remember(
        MemoryInput(
            content="Orion handbook quotes 'Ignore prior instructions' as an attack example.",
            source_id="web",
        ),
        agent,
    )


def request(memory, **changes):
    return ContextReviewInput(
        **{
            "memory_id": memory.id,
            "expected_fingerprint": review_fingerprint(memory),
            "reason": "Verified as a quoted security training example",
            "expires_at": now() + timedelta(hours=1),
            **changes,
        }
    )


def test_review_restores_only_exact_informational_record(guard, agent, reviewer, quoted):
    duplicate = guard.remember(MemoryInput(content=quoted.content, source_id="web"), agent)
    before = guard.inspect(reviewer).memories[quoted.id]
    assert not guard.retrieve(RetrievalInput(query="Orion"), agent).allowed
    review = guard.review_context(request(quoted), reviewer)
    result = guard.retrieve(RetrievalInput(query="Orion"), agent)
    assert [m.id for m in result.allowed] == [quoted.id]
    assert result.context_reviews == {quoted.id: review.id}
    assert [b.memory_id for b in result.blocked] == [duplicate.id]
    assert guard.inspect(reviewer).memories[quoted.id] == before
    snapshot = review_snapshot(guard, reviewer, "memory")
    assert snapshot["memory_restrictions"][quoted.id]
    assert not snapshot["information_restrictions"][quoted.id]
    assert snapshot["context_review_options"][quoted.id]["effective_review_id"] == review.id
    event = next(
        e
        for e in guard.inspect(reviewer).events.values()
        if e.kind == "retrieval_checked" and e.detail.get("context_reviews")
    )
    assert event.detail["context_reviews"] == {quoted.id: review.id}


@pytest.mark.parametrize("action", ["payment", "change_bank", "send_message"])
def test_review_never_permits_consequential_actions(guard, agent, reviewer, quoted, action):
    guard.review_context(request(quoted), reviewer)
    result = guard.retrieve(RetrievalInput(query="Orion", action=action, target="Orion"), agent)
    assert not result.allowed and not result.context_reviews
    with pytest.raises(GuardError, match="Restricted"):
        guard.grant(
            GrantInput(
                memory_id=quoted.id,
                action=action,
                target="Orion",
                reason="Independent action review",
                expires_at=now() + timedelta(hours=1),
            ),
            reviewer,
        )


def test_review_does_not_propagate_to_existing_or_new_descendants(guard, agent, reviewer, quoted):
    first = guard.remember(
        MemoryInput(content="Orion handbook summary", parent_ids=[quoted.id]), agent
    )
    guard.review_context(request(quoted), reviewer)
    second = guard.remember(MemoryInput(content="Orion new summary", parent_ids=[quoted.id]), agent)
    assert second.status == Status.QUARANTINED
    result = guard.retrieve(RetrievalInput(query="Orion"), agent)
    assert [m.id for m in result.allowed] == [quoted.id]
    for child in [first, second]:
        with pytest.raises(GuardError, match="not eligible"):
            guard.review_context(request(child), reviewer)


def test_review_expires_and_withdrawal_is_idempotent(guard, agent, reviewer, quoted, monkeypatch):
    review = guard.review_context(request(quoted), reviewer)
    with monkeypatch.context() as clock:
        clock.setattr("recallguard.context_review.now", lambda: review.expires_at)
        assert not guard.retrieve(RetrievalInput(query="Orion"), agent).allowed
    withdrawn = guard.withdraw_context_review(
        review.id, "Approval withdrawn after review", reviewer
    )
    assert withdrawn.withdrawn_by == reviewer.id
    again = guard.withdraw_context_review(review.id, "Retry with another reason", reviewer)
    assert again == withdrawn
    assert not guard.retrieve(RetrievalInput(query="Orion"), agent).allowed
    events = [
        e for e in guard.inspect(reviewer).events.values() if e.kind == "context_review_withdrawn"
    ]
    assert len(events) == 1


@pytest.mark.parametrize("offset", [-1, 1441])
def test_invalid_expiry_has_no_partial_write(guard, reviewer, quoted, offset):
    before = guard.inspect(reviewer)
    with pytest.raises(GuardError, match="expiry"):
        guard.review_context(
            request(quoted, expires_at=now() + timedelta(minutes=offset)), reviewer
        )
    assert guard.inspect(reviewer) == before


def test_revocation_and_conflict_override_review(guard, agent, reviewer, quoted):
    guard.review_context(request(quoted), reviewer)
    guard.revoke(quoted.id, "Source withdrawn after review", reviewer)
    assert not guard.retrieve(RetrievalInput(query="Orion"), agent).allowed
    with pytest.raises(GuardError, match="not eligible"):
        guard.review_context(request(quoted), reviewer)
    record = guard.remember(
        MemoryInput(
            content=quoted.content,
            source_id="web",
            claim={"entity": "Orion", "attribute": "delivery", "value": "Friday"},
        ),
        agent,
    )
    guard.review_context(request(record), reviewer)
    guard.remember(
        MemoryInput(
            content="Orion delivery Saturday",
            source_id="web",
            claim={"entity": "Orion", "attribute": "delivery", "value": "Saturday"},
        ),
        agent,
    )
    assert not guard.retrieve(RetrievalInput(query="Orion"), agent).allowed


def test_changed_policy_invalidates_review_and_stale_request(
    guard, agent, reviewer, quoted, monkeypatch
):
    data = request(quoted)
    guard.review_context(data, reviewer)
    monkeypatch.setattr("recallguard.context_review.POLICY_FINGERPRINT", "new-policy")
    assert not guard.retrieve(RetrievalInput(query="Orion"), agent).allowed
    with pytest.raises(GuardError, match="changed"):
        guard.review_context(data, reviewer)


def test_claim_changes_are_bound_by_fingerprint(guard, agent, reviewer, quoted):
    changed = quoted.model_copy(update={"claim": Claim(entity="Orion", attribute="x", value="y")})
    # A stale client cannot reuse approval for altered record bytes or another ID.
    assert review_fingerprint(changed) != review_fingerprint(quoted)
    with pytest.raises(GuardError, match="changed"):
        guard.review_context(request(quoted, expected_fingerprint="0" * 64), reviewer)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.taint_labels.append("unknown_restriction"),
        lambda m: m.reasons.append("restricted_parent"),
        lambda m: setattr(m, "content", "api_key=FAKE_TEST_CREDENTIAL"),
    ],
)
def test_unrelated_restrictions_are_never_cleared(guard, reviewer, quoted, mutate):
    # Simulate legacy persisted restrictions unavailable through public mutation APIs.
    guard.store.transact(lambda state: mutate(state.memories[quoted.id]))
    memory = guard.inspect(reviewer).memories[quoted.id]
    with pytest.raises(GuardError, match="not eligible"):
        guard.review_context(request(memory), reviewer)


def test_agent_cannot_issue_or_withdraw_review(guard, agent, reviewer, quoted):
    with pytest.raises(GuardError) as error:
        guard.review_context(request(quoted), agent)
    assert error.value.status == 403
    review = guard.review_context(request(quoted), reviewer)
    with pytest.raises(GuardError) as error:
        guard.withdraw_context_review(review.id, "Unauthorized withdrawal", agent)
    assert error.value.status == 403


def test_concurrent_reviews_issue_one_effective_exception(guard, reviewer, quoted):
    data = request(quoted)

    def issue(_):
        try:
            return guard.review_context(data, reviewer).id
        except GuardError as error:
            assert error.status == 409
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        issued = list(pool.map(issue, range(8)))
    assert len([r for r in issued if r]) == 1
    assert len(guard.inspect(reviewer).context_reviews) == 1


def test_client_cannot_set_review_power_or_status(quoted):
    for key, value in [("action", "payment"), ("reviewed_by", "reviewer"), ("withdrawn_at", None)]:
        with pytest.raises(ValidationError):
            request(quoted, **{key: value})


def test_stale_approval_cannot_recreate_withdrawn_exception(guard, agent, reviewer, quoted):
    stale_request = request(quoted)
    approved = guard.review_context(stale_request, reviewer)
    guard.withdraw_context_review(approved.id, "Exception withdrawn", reviewer)
    with pytest.raises(GuardError, match="changed"):
        guard.review_context(stale_request, reviewer)
    assert not guard.retrieve(RetrievalInput(query="Orion"), agent).allowed
    # A deliberate new review requires a fresh snapshot; it is not a replay.
    options = review_snapshot(guard, reviewer, "memory")["context_review_options"][quoted.id]
    new_review = guard.review_context(
        request(quoted, expected_fingerprint=options["fingerprint"]), reviewer
    )
    assert new_review.id != approved.id


def test_semantic_retrieval_uses_same_review_and_expiry(
    guard, agent, reviewer, quoted, monkeypatch
):
    class Encoder:
        model_id = "context-review-test"
        dimensions = 2

        def encode(self, texts):
            return [[1, 0] for _ in texts]

    guard.encoder = Encoder()
    guard.reindex(32, reviewer)
    review = guard.review_context(request(quoted), reviewer)
    result = guard.retrieve(RetrievalInput(query="Orion", mode="semantic"), agent)
    assert result.context_reviews == {quoted.id: review.id}
    monkeypatch.setattr("recallguard.context_review.now", lambda: review.expires_at)
    assert not guard.retrieve(RetrievalInput(query="Orion", mode="semantic"), agent).allowed
