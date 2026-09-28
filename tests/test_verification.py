from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from pydantic import ValidationError

from recallguard.engine import GuardError
from recallguard.models import (
    Action,
    ClaimVerificationInput,
    GrantInput,
    MemoryInput,
    RetrievalInput,
    SourceInput,
    now,
)
from recallguard.review import review_snapshot
from recallguard.verification import request_fingerprint


@pytest.fixture
def claim(guard, agent):
    return guard.remember(
        MemoryInput(
            content="Orion bank account is OR1234",
            source_id="web",
            claim={"entity": "supplier:Orion", "attribute": "bank_account", "value": "OR1234"},
        ),
        agent,
    )


def verification_request(guard, reviewer, memory, source="user", **changes):
    state = guard.inspect(reviewer)
    return ClaimVerificationInput(
        **{
            "memory_id": memory.id,
            "evidence_source_id": source,
            "expected_fingerprint": request_fingerprint(state, memory, state.sources[source]),
            "evidence_reference": "callback-log:Orion-001",
            "method": "callback",
            "independently_checked": True,
            "reason": "Account checked using independent contact details",
            "expires_at": now() + timedelta(hours=1),
            **changes,
        }
    )


def grant_request(memory):
    return GrantInput(
        memory_id=memory.id,
        action="payment",
        target="supplier:Orion",
        reason="Action scope reviewed independently",
        expires_at=now() + timedelta(hours=2),
    )


def payment_query():
    return RetrievalInput(query="Orion", action="payment", target="supplier:Orion")


def test_verification_is_required_and_never_substitutes_for_action_grant(
    guard, agent, reviewer, claim
):
    with pytest.raises(GuardError, match="independent verification"):
        guard.grant(grant_request(claim), reviewer)
    info = guard.retrieve(RetrievalInput(query="Orion"), agent)
    assert info.unverified_claim_ids == [claim.id] and not info.claim_verifications
    verification = guard.verify_claim(verification_request(guard, reviewer, claim), reviewer)
    assert verification.claim == claim.claim
    assert not guard.retrieve(payment_query(), agent).allowed
    grant = guard.grant(grant_request(claim), reviewer)
    assert grant.claim_verification_id == verification.id
    result = guard.retrieve(payment_query(), agent)
    assert [m.id for m in result.allowed] == [claim.id]
    assert result.claim_verifications == {claim.id: verification.id}
    assert not result.unverified_claim_ids
    assert verification.evidence_reference not in result.model_dump_json()
    assert guard.inspect(reviewer).memories[claim.id] == claim


@pytest.mark.parametrize("action", ["payment", "change_bank", "send_message"])
def test_legacy_grants_without_bound_verification_cannot_authorize_claims(
    guard, agent, reviewer, claim, action
):
    verification = guard.verify_claim(verification_request(guard, reviewer, claim), reviewer)
    grant = guard.grant(
        grant_request(claim).model_copy(update={"action": Action(action)}), reviewer
    )
    guard.store.transact(lambda s: setattr(s.grants[grant.id], "claim_verification_id", None))
    result = guard.retrieve(
        RetrievalInput(query="Orion", action=action, target="supplier:Orion"), agent
    )
    assert not result.allowed
    assert "claim_verification_required" in result.blocked[0].reasons
    assert verification.id in guard.inspect(reviewer).claim_verifications


def test_original_source_and_same_locator_alias_are_rejected(guard, reviewer, claim):
    with pytest.raises(GuardError, match="separate_evidence_source_required"):
        guard.verify_claim(verification_request(guard, reviewer, claim, "web"), reviewer)
    guard.register_source(SourceInput(id="alias", kind="user", locator="FIXTURE:WEB/"), reviewer)
    with pytest.raises(GuardError, match="separate_evidence_source_required"):
        guard.verify_claim(verification_request(guard, reviewer, claim, "alias"), reviewer)


def test_all_inherited_origins_are_excluded(guard, reviewer, agent, claim):
    trusted = guard.remember(MemoryInput(content="Orion observation", source_id="system"), reviewer)
    child = guard.remember(
        MemoryInput(
            content=claim.content,
            parent_ids=[claim.id, trusted.id],
            claim=claim.claim,
        ),
        agent,
    )
    for source in ["web", "system"]:
        with pytest.raises(GuardError, match="separate_evidence_source_required"):
            guard.verify_claim(verification_request(guard, reviewer, child, source), reviewer)


def test_verification_does_not_transfer_to_copy_or_descendant(guard, reviewer, agent, claim):
    guard.verify_claim(verification_request(guard, reviewer, claim), reviewer)
    for origin in [{"source_id": "web"}, {"parent_ids": [claim.id]}]:
        other = guard.remember(
            MemoryInput(content=claim.content, claim=claim.claim, **origin), agent
        )
        with pytest.raises(GuardError, match="independent verification"):
            guard.grant(grant_request(other), reviewer)


def test_withdrawal_is_idempotent_and_reverification_does_not_revive_old_grant(
    guard, reviewer, agent, claim
):
    data = verification_request(guard, reviewer, claim)
    verified = guard.verify_claim(data, reviewer)
    old_grant = guard.grant(grant_request(claim), reviewer)
    first = guard.withdraw_claim_verification(verified.id, "Evidence withdrawn", reviewer)
    assert guard.withdraw_claim_verification(verified.id, "Duplicate withdrawal", reviewer) == first
    with pytest.raises(GuardError, match="changed"):
        guard.verify_claim(data, reviewer)
    replacement = guard.verify_claim(verification_request(guard, reviewer, claim), reviewer)
    assert replacement.id != verified.id
    assert not guard.retrieve(payment_query(), agent).allowed
    new_grant = guard.grant(grant_request(claim), reviewer)
    assert new_grant.claim_verification_id == replacement.id
    assert old_grant.claim_verification_id == verified.id
    assert guard.retrieve(payment_query(), agent).allowed
    events = guard.inspect(reviewer).events.values()
    assert sum(e.kind == "claim_verification_withdrawn" for e in events) == 1


def test_expiry_policy_change_and_revocation_invalidate_verification(
    guard, reviewer, agent, claim, monkeypatch
):
    verification = guard.verify_claim(verification_request(guard, reviewer, claim), reviewer)
    guard.grant(grant_request(claim), reviewer)
    with monkeypatch.context() as clock:
        clock.setattr("recallguard.verification.now", lambda: verification.expires_at)
        assert not guard.retrieve(payment_query(), agent).allowed
    with monkeypatch.context() as policy:
        policy.setattr("recallguard.verification.POLICY_FINGERPRINT", "changed-policy")
        assert not guard.retrieve(payment_query(), agent).allowed
    guard.revoke(claim.id, "Original evidence withdrawn", reviewer)
    assert not guard.retrieve(payment_query(), agent).allowed


def test_new_conflict_invalidates_checked_claim(guard, reviewer, agent, claim):
    guard.verify_claim(verification_request(guard, reviewer, claim), reviewer)
    guard.grant(grant_request(claim), reviewer)
    guard.remember(
        MemoryInput(
            content="Orion bank account is OR9999",
            source_id="email",
            claim={"entity": "supplier:Orion", "attribute": "bank_account", "value": "OR9999"},
        ),
        agent,
    )
    assert not guard.retrieve(payment_query(), agent).allowed
    assert (
        review_snapshot(guard, reviewer, "memory")["claim_verification_options"][claim.id][
            "current_id"
        ]
        is None
    )


@pytest.mark.parametrize("offset", [-1, 1441])
def test_invalid_expiry_leaves_no_evidence_or_audit(guard, reviewer, claim, offset):
    before = guard.inspect(reviewer)
    with pytest.raises(GuardError, match="expiry"):
        guard.verify_claim(
            verification_request(
                guard,
                reviewer,
                claim,
                expires_at=now() + timedelta(minutes=offset),
            ),
            reviewer,
        )
    assert guard.inspect(reviewer) == before


def test_agent_cannot_verify_or_withdraw(guard, reviewer, agent, claim):
    data = verification_request(guard, reviewer, claim)
    with pytest.raises(GuardError) as error:
        guard.verify_claim(data, agent)
    assert error.value.status == 403
    verification = guard.verify_claim(data, reviewer)
    with pytest.raises(GuardError) as error:
        guard.withdraw_claim_verification(verification.id, "Unauthorized withdrawal", agent)
    assert error.value.status == 403


@pytest.mark.parametrize(
    "change",
    [
        {"independently_checked": False},
        {"method": "model_guess"},
        {"claim": {}},
        {"verified_by": "reviewer"},
        {"record_fingerprint": "0" * 64},
    ],
)
def test_caller_cannot_forge_verification_metadata(guard, reviewer, claim, change):
    with pytest.raises(ValidationError):
        verification_request(guard, reviewer, claim, **change)


def test_concurrent_verification_only_creates_one_record(guard, reviewer, claim):
    data = verification_request(guard, reviewer, claim)

    def verify(_):
        try:
            return guard.verify_claim(data, reviewer).id
        except GuardError as error:
            assert error.status == 409
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(verify, range(8)))
    assert len([r for r in results if r]) == 1
    assert len(guard.inspect(reviewer).claim_verifications) == 1


def test_informational_exception_cannot_bootstrap_claim_verification(guard, agent, reviewer):
    from recallguard.context_review import review_fingerprint
    from recallguard.models import ContextReviewInput

    memory = guard.remember(
        MemoryInput(
            content="Orion handbook quotes 'Ignore prior instructions' as an attack.",
            source_id="web",
            claim={"entity": "Orion", "attribute": "account", "value": "OR1234"},
        ),
        agent,
    )
    guard.review_context(
        ContextReviewInput(
            memory_id=memory.id,
            expected_fingerprint=review_fingerprint(memory),
            reason="This is a benign quotation",
            expires_at=now() + timedelta(hours=1),
        ),
        reviewer,
    )
    with pytest.raises(GuardError, match="restricted_memory"):
        guard.verify_claim(verification_request(guard, reviewer, memory), reviewer)


def test_unstructured_record_cannot_receive_verification(guard, agent, reviewer):
    memory = guard.remember(MemoryInput(content="Orion information", source_id="web"), agent)
    with pytest.raises(GuardError, match="structured_claim_required"):
        guard.verify_claim(verification_request(guard, reviewer, memory), reviewer)
