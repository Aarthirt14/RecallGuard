"""Run: python examples/procurement.py. Exercises real LangGraph nodes, local tools."""

import json
from datetime import timedelta

from recallguard.agent import ProcurementAgent
from recallguard.engine import RecallGuard
from recallguard.models import (
    Action,
    Claim,
    ClaimVerificationInput,
    GrantInput,
    Principal,
    Role,
    SourceInput,
    SourceType,
    now,
)
from recallguard.procurement import Procurement
from recallguard.procurement_models import (
    ExecutePaymentInput,
    InvoiceInput,
    ObserveInput,
    PaymentApprovalInput,
    PlanPaymentInput,
    SupplierInput,
)
from recallguard.review import review_snapshot
from recallguard.store import InMemoryStore


def run():
    guard = RecallGuard(InMemoryStore())
    reviewer = Principal(id="human-reviewer", role=Role.REVIEWER)
    actor = Principal(id="procurement-agent", role=Role.AGENT)
    tools = Procurement(guard.store)
    guard.register_source(
        SourceInput(id="web", kind=SourceType.WEB, locator="fixture:web"), reviewer
    )

    def setup(supplier, account, invoice_id):
        tools.register_supplier(SupplierInput(id=supplier, name=f"Supplier {supplier}"), reviewer)
        tools.register_invoice(
            InvoiceInput(
                id=invoice_id,
                supplier_id=supplier,
                amount_minor=8_000_000,
                currency="INR",
            ),
            reviewer,
        )
        return ProcurementAgent(guard, actor).observe(
            ObserveInput(
                session_id=f"research-{supplier}",
                source_id="web",
                content=f"{supplier} supplier bank account is {account}.",
                claim=Claim(entity=f"supplier:{supplier}", attribute="bank_account", value=account),
            )
        )

    guard.register_source(
        SourceInput(
            id="callback",
            kind=SourceType.USER,
            locator="fixture:independent-callback",
        ),
        reviewer,
    )

    def prepare(observation, supplier, invoice_id):
        memory_id = observation.memory_ids[-1]
        options = review_snapshot(guard, reviewer, "memory")["claim_verification_options"][
            memory_id
        ]
        evidence = next(s for s in options["evidence_sources"] if s["id"] == "callback")
        # This fixture models a human check; it does not contact or verify a bank.
        guard.verify_claim(
            ClaimVerificationInput(
                memory_id=memory_id,
                evidence_source_id="callback",
                expected_fingerprint=evidence["fingerprint"],
                evidence_reference=f"fixture:callback-{supplier}",
                method="callback",
                independently_checked=True,
                reason="Reviewer checked a separate source in this fixture",
                expires_at=now() + timedelta(minutes=30),
            ),
            reviewer,
        )
        guard.grant(
            GrantInput(
                memory_id=observation.memory_ids[-1],
                action=Action.PAYMENT,
                target=f"supplier:{supplier}",
                reason="Account verified through another channel",
                expires_at=now() + timedelta(minutes=10),
            ),
            reviewer,
        )
        planned = ProcurementAgent(guard, actor).plan_payment(
            PlanPaymentInput(
                session_id=f"planning-{supplier}",
                invoice_id=invoice_id,
            )
        )
        assert planned.status == "pending_review"
        proposal = tools.proposal(planned.proposal_id)
        tools.approve(
            proposal.id,
            PaymentApprovalInput(
                expected_fingerprint=proposal.fingerprint,
                reason="Exact payment terms reviewed",
                expires_at=now() + timedelta(minutes=10),
            ),
            reviewer,
        )
        return proposal.id

    observed = setup("ABC", "991872", "INV-ABC")
    blocked = ProcurementAgent(guard, actor).plan_payment(
        PlanPaymentInput(
            session_id="next-session",
            invoice_id="INV-ABC",
        )
    )
    assert blocked.status == "blocked" and blocked.proposal_id is None
    stale_proposal = prepare(observed, "ABC", "INV-ABC")
    guard.revoke(observed.memory_ids[0], "Supplier source compromise discovered later", reviewer)
    stale = ProcurementAgent(guard, actor).execute_payment(
        stale_proposal,
        ExecutePaymentInput(session_id="execution-after-revocation"),
    )
    assert stale.status == "blocked"

    benign = setup("SAFE", "123456", "INV-SAFE")
    approved_proposal = prepare(benign, "SAFE", "INV-SAFE")
    valid = ProcurementAgent(guard, actor).execute_payment(
        approved_proposal,
        ExecutePaymentInput(session_id="approved-execution"),
    )
    retry = ProcurementAgent(guard, actor).execute_payment(
        approved_proposal,
        ExecutePaymentInput(session_id="retry-after-disconnect"),
    )
    assert valid.status == "executed" and retry.status == "already_executed"
    state = guard.inspect(reviewer)
    assert len(state.receipts) == 1
    return {
        "untrusted_account_in_later_session": blocked.status,
        "approved_payment_after_source_revocation": stale.status,
        "independently_approved_valid_payment": valid.status,
        "repeated_execution": retry.status,
        "simulated_ledger_entries": len(state.receipts),
        "persisted_workflow_runs": len(state.runs),
        "real_payments_executed": 0,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
