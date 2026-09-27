import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import uuid4

import pytest

from recallguard.agent import ProcurementAgent
from recallguard.engine import RecallGuard
from recallguard.models import Action, Claim, GrantInput, SourceInput, SourceType, now
from recallguard.neo4j_store import Neo4jStore
from recallguard.procurement import Procurement
from recallguard.procurement_models import (
    ExecutePaymentInput,
    InvoiceInput,
    ObserveInput,
    PaymentApprovalInput,
    PlanPaymentInput,
    SupplierInput,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.getenv("NEO4J_TEST_URI"), reason="NEO4J_TEST_URI not configured"),
]


def test_workflow_review_restart_execution_and_revocation(reviewer, agent):
    namespace = f"procurement-test-{uuid4()}"
    args = (os.environ["NEO4J_TEST_URI"], "neo4j", os.environ["NEO4J_TEST_PASSWORD"], namespace)
    store = Neo4jStore(*args)
    try:
        guard = RecallGuard(store)
        procurement = Procurement(store)
        guard.register_source(
            SourceInput(id="web", kind=SourceType.WEB, locator="fixture:web"), reviewer
        )
        procurement.register_supplier(SupplierInput(id="ABC", name="ABC Supplies"), reviewer)
        observed = ProcurementAgent(guard, agent).observe(
            ObserveInput(
                session_id="first-session",
                source_id="web",
                content="ABC account is 991872",
                claim=Claim(entity="supplier:ABC", attribute="bank_account", value="991872"),
            )
        )
        guard.grant(
            GrantInput(
                memory_id=observed.memory_ids[-1],
                action=Action.PAYMENT,
                target="supplier:ABC",
                reason="Account verified independently",
                expires_at=now() + timedelta(minutes=10),
            ),
            reviewer,
        )
        proposals = []
        for invoice_id in ("INV-1", "INV-2"):
            procurement.register_invoice(
                InvoiceInput(
                    id=invoice_id,
                    supplier_id="ABC",
                    amount_minor=8_000_000,
                ),
                reviewer,
            )
            run = ProcurementAgent(guard, agent).plan_payment(
                PlanPaymentInput(
                    session_id="second-session",
                    invoice_id=invoice_id,
                )
            )
            proposal = procurement.proposal(run.proposal_id)
            procurement.approve(
                proposal.id,
                PaymentApprovalInput(
                    expected_fingerprint=proposal.fingerprint,
                    reason="Exact invoice reviewed",
                    expires_at=now() + timedelta(minutes=10),
                ),
                reviewer,
            )
            proposals.append(proposal.id)
        store.close()
        store = Neo4jStore(*args)
        guard = RecallGuard(store)
        workflow = ProcurementAgent(guard, agent)
        assert guard.inspect(reviewer).runs[observed.id].session_id == "first-session"
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(
                pool.map(
                    lambda i: workflow.execute_payment(
                        proposals[0],
                        ExecutePaymentInput(session_id=f"execute-{i}"),
                    ),
                    range(8),
                )
            )
        assert sum(r.status == "executed" for r in results) == 1
        assert len({r.receipt_id for r in results}) == 1
        assert len(guard.inspect(reviewer).receipts) == 1
        guard.revoke(observed.memory_ids[0], "Compromised supplier source", reviewer)
        store.close()
        store = Neo4jStore(*args)
        guard = RecallGuard(store)
        later = ProcurementAgent(guard, agent).execute_payment(
            proposals[1],
            ExecutePaymentInput(session_id="after-restart-and-revocation"),
        )
        assert later.status == "blocked"
        assert "memory_revoked" in later.reasons
        assert len(guard.inspect(reviewer).receipts) == 1
        assert guard.inspect(reviewer).invoices["INV-2"].status == "open"
    finally:
        with store.driver.session() as session:
            session.run(
                "MATCH (n:RGObject {namespace: $ns}) DETACH DELETE n", ns=namespace
            ).consume()
            session.run("MATCH (n:RGWorkspace {id: $ns}) DELETE n", ns=namespace).consume()
        store.close()
