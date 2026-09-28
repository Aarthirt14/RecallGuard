"""Payment simulator boundary. No network, banking SDK, or external side effects.

Fresh eligibility checks and the simulated ledger write share one transaction.
Never move a real payment API call inside a retryable database callback.
"""

import hashlib
import json
from datetime import timedelta

from pydantic import ValidationError

from recallguard.engine import (
    GuardError,
    action_blocked_reasons,
    audit,
    blocked_reasons,
    get_memory,
    require_reviewer,
)
from recallguard.models import Action, Principal, now
from recallguard.procurement_models import (
    Invoice,
    InvoiceInput,
    PaymentApprovalInput,
    PaymentProposal,
    PaymentResult,
    PaymentStatus,
    PaymentTerms,
    SimulatedReceipt,
    Supplier,
    SupplierInput,
)
from recallguard.store import State, Store
from recallguard.verification import current_verification, valid_verification


def fingerprint(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def invoice_from(state: State, invoice_id: str) -> Invoice:
    if invoice_id not in state.invoices:
        raise GuardError("Invoice not found", 404)
    return state.invoices[invoice_id]


def payment_from(state: State, proposal_id: str) -> PaymentProposal:
    if proposal_id not in state.payments:
        raise GuardError("Payment proposal not found", 404)
    return state.payments[proposal_id]


def evidence_reasons(state: State, terms: PaymentTerms) -> list[str]:
    memory = get_memory(state, terms.memory_id)
    reasons = action_blocked_reasons(state, memory, Action.PAYMENT, f"supplier:{terms.supplier_id}")
    if memory.content_hash != terms.memory_hash:
        reasons.append("memory_changed")
    if not valid_verification(state, memory, terms.claim_verification_id, blocked_reasons):
        reasons.append("evidence_verification_invalid")
    claim = memory.claim
    if not claim or (
        claim.entity != f"supplier:{terms.supplier_id}"
        or claim.attribute != "bank_account"
        or claim.value != terms.bank_account
    ):
        reasons.append("account_evidence_mismatch")
    return reasons


def proposal_reasons(state: State, proposal: PaymentProposal) -> list[str]:
    terms = proposal.terms
    invoice = invoice_from(state, terms.invoice_id)
    reasons = evidence_reasons(state, terms)
    if invoice.status != "open":
        reasons.append(f"invoice_{invoice.status}")
    if invoice.fingerprint != terms.invoice_fingerprint or (
        invoice.supplier_id,
        invoice.amount_minor,
        invoice.currency,
    ) != (terms.supplier_id, terms.amount_minor, terms.currency):
        reasons.append("invoice_changed")
    if fingerprint(terms.model_dump()) != proposal.fingerprint:
        reasons.append("proposal_changed")
    if proposal.status == PaymentStatus.CANCELLED:
        reasons.append("proposal_cancelled")
    return sorted(set(reasons))


class Procurement:
    def __init__(self, store: Store):
        self.store = store

    def register_supplier(self, data: SupplierInput, actor: Principal) -> Supplier:
        require_reviewer(actor)

        def operation(state):
            if data.id in state.suppliers:
                raise GuardError("Supplier already exists", 409)
            supplier = Supplier(**data.model_dump(), registered_by=actor.id)
            state.suppliers[supplier.id] = supplier
            audit(state, actor, "supplier_registered", [supplier.id])
            return supplier

        return self.store.transact(operation)

    def register_invoice(self, data: InvoiceInput, actor: Principal) -> Invoice:
        require_reviewer(actor)

        def operation(state):
            if data.id in state.invoices:
                raise GuardError("Invoice already exists; terms are immutable", 409)
            if data.supplier_id not in state.suppliers:
                raise GuardError("Supplier not found", 404)
            invoice = Invoice(
                **data.model_dump(),
                registered_by=actor.id,
                fingerprint=fingerprint(data.model_dump()),
            )
            state.invoices[invoice.id] = invoice
            audit(state, actor, "invoice_registered", [invoice.id])
            return invoice

        return self.store.transact(operation)

    def invoice(self, invoice_id: str) -> Invoice:
        return self.store.transact(lambda state: invoice_from(state, invoice_id))

    def proposal(self, proposal_id: str) -> PaymentProposal:
        return self.store.transact(lambda state: payment_from(state, proposal_id))

    def propose(self, invoice_id: str, memory_id: str, actor: Principal) -> PaymentProposal:
        """Derive all action arguments from stored records, never model-supplied values."""

        def operation(state):
            invoice = invoice_from(state, invoice_id)
            memory = get_memory(state, memory_id)
            if not memory.claim:
                raise GuardError("A structured account claim is required", 409)
            verification = current_verification(state, memory, blocked_reasons)
            try:
                terms = PaymentTerms(
                    invoice_id=invoice.id,
                    invoice_fingerprint=invoice.fingerprint,
                    supplier_id=invoice.supplier_id,
                    amount_minor=invoice.amount_minor,
                    currency=invoice.currency,
                    bank_account=memory.claim.value,
                    memory_id=memory.id,
                    memory_hash=memory.content_hash,
                    claim_verification_id=verification.id if verification else None,
                )
            except ValidationError:
                raise GuardError("Unsupported account format", 422) from None
            proposal = PaymentProposal(
                terms=terms, fingerprint=fingerprint(terms.model_dump()), proposed_by=actor.id
            )
            reasons = proposal_reasons(state, proposal)
            if reasons:
                raise GuardError("Cannot propose payment: " + ", ".join(reasons), 409)
            # Graph retries/repeated sessions do not create duplicate identical proposals.
            for existing in state.payments.values():
                if (
                    existing.fingerprint == proposal.fingerprint
                    and existing.status != PaymentStatus.CANCELLED
                ):
                    return existing
            state.payments[proposal.id] = proposal
            audit(state, actor, "payment_proposed", [proposal.id, invoice.id, memory.id])
            return proposal

        return self.store.transact(operation)

    def approve(
        self, proposal_id: str, data: PaymentApprovalInput, actor: Principal
    ) -> PaymentProposal:
        require_reviewer(actor)

        def operation(state):
            proposal = payment_from(state, proposal_id)
            if proposal.status == PaymentStatus.EXECUTED:
                raise GuardError("Payment has already executed", 409)
            if data.expected_fingerprint != proposal.fingerprint:
                raise GuardError("Approval does not match the reviewed payment terms", 409)
            if not now() < data.expires_at <= now() + timedelta(hours=24):
                raise GuardError("Payment approval must expire in the next 24 hours", 422)
            reasons = proposal_reasons(state, proposal)
            if reasons:
                raise GuardError("Cannot approve payment: " + ", ".join(reasons), 409)
            proposal.status = PaymentStatus.APPROVED
            proposal.approved_by = actor.id
            proposal.approved_fingerprint = data.expected_fingerprint
            proposal.approval_expires_at = data.expires_at
            audit(
                state,
                actor,
                "payment_approved",
                [proposal.id],
                fingerprint=proposal.fingerprint,
                reason=data.reason,
            )
            return proposal

        return self.store.transact(operation)

    def execute(self, proposal_id: str, actor: Principal) -> PaymentResult:
        """Only entry point to the simulated ledger. Safe to call again after a retry."""

        def operation(state):
            proposal = payment_from(state, proposal_id)
            if proposal.status == PaymentStatus.EXECUTED:
                return PaymentResult(
                    proposal_id=proposal.id,
                    status="already_executed",
                    receipt_id=proposal.receipt_id,
                )
            reasons = proposal_reasons(state, proposal)
            if proposal.status != PaymentStatus.APPROVED or not proposal.approved_by:
                reasons.append("payment_approval_required")
            if not proposal.approval_expires_at or proposal.approval_expires_at <= now():
                reasons.append("payment_approval_expired_or_missing")
            if proposal.approved_fingerprint != fingerprint(proposal.terms.model_dump()):
                reasons.append("approved_terms_mismatch")
            if any(r.invoice_id == proposal.terms.invoice_id for r in state.receipts.values()):
                reasons.append("invoice_already_paid")
            if reasons:
                reasons = sorted(set(reasons))
                # Return a decision, not an exception: denied attempts must be audited.
                audit(state, actor, "payment_blocked", [proposal.id], reasons=reasons)
                return PaymentResult(proposal_id=proposal.id, status="blocked", reasons=reasons)
            receipt = SimulatedReceipt(
                proposal_id=proposal.id,
                invoice_id=proposal.terms.invoice_id,
                terms=proposal.terms.model_copy(deep=True),
                approved_by=proposal.approved_by,
                executed_by=actor.id,
            )
            state.receipts[receipt.id] = receipt
            proposal.status = PaymentStatus.EXECUTED
            proposal.receipt_id = receipt.id
            invoice = invoice_from(state, receipt.invoice_id)
            invoice.status = "paid"
            invoice.receipt_id = receipt.id
            audit(state, actor, "simulated_payment_executed", [proposal.id, invoice.id, receipt.id])
            return PaymentResult(proposal_id=proposal.id, status="executed", receipt_id=receipt.id)

        return self.store.transact(operation)

    def cancel_invoice(self, invoice_id: str, reason: str, actor: Principal) -> Invoice:
        require_reviewer(actor)

        def operation(state):
            invoice = invoice_from(state, invoice_id)
            if invoice.status == "paid":
                raise GuardError("A paid invoice cannot be cancelled", 409)
            invoice.status = "cancelled"
            audit(state, actor, "invoice_cancelled", [invoice.id], reason=reason)
            return invoice

        return self.store.transact(operation)

    def cancel_payment(self, proposal_id: str, reason: str, actor: Principal) -> PaymentProposal:
        require_reviewer(actor)

        def operation(state):
            proposal = payment_from(state, proposal_id)
            if proposal.status == PaymentStatus.EXECUTED:
                raise GuardError("An executed payment cannot be cancelled", 409)
            proposal.status = PaymentStatus.CANCELLED
            audit(state, actor, "payment_cancelled", [proposal.id], reason=reason)
            return proposal

        return self.store.transact(operation)
