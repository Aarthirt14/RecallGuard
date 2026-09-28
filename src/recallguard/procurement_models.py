"""Persisted simulator records. Requests cannot supply payment approval state."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from recallguard.models import BlockedMemory, Claim, Identifier, Model, Text, new_id, now

BusinessID = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
Account = Annotated[str, Field(pattern=r"^[A-Za-z0-9]{4,64}$")]
Fingerprint = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class SupplierInput(Model):
    id: BusinessID
    name: Annotated[str, Field(min_length=1, max_length=200)]


class Supplier(SupplierInput):
    registered_by: str


class InvoiceInput(Model):
    id: BusinessID
    supplier_id: BusinessID
    amount_minor: Annotated[int, Field(strict=True, gt=0, le=10**12)]
    currency: Annotated[str, Field(pattern=r"^[A-Z]{3}$")] = "INR"


class Invoice(InvoiceInput):
    registered_by: str
    fingerprint: str
    status: Literal["open", "paid", "cancelled"] = "open"
    receipt_id: str | None = None


class PaymentStatus(StrEnum):
    PENDING = "pending_review"
    APPROVED = "approved"
    EXECUTED = "executed"
    CANCELLED = "cancelled"


class PaymentTerms(Model):
    invoice_id: str
    invoice_fingerprint: str
    supplier_id: str
    amount_minor: int
    currency: str
    bank_account: Account
    memory_id: str
    memory_hash: str
    claim_verification_id: str | None = None


class PaymentProposal(Model):
    id: str = Field(default_factory=new_id)
    terms: PaymentTerms
    fingerprint: str
    status: PaymentStatus = PaymentStatus.PENDING
    proposed_by: str
    approved_by: str | None = None
    approved_fingerprint: str | None = None
    approval_expires_at: datetime | None = None
    receipt_id: str | None = None
    created_at: datetime = Field(default_factory=now)


class PaymentApprovalInput(Model):
    expected_fingerprint: Fingerprint
    expires_at: datetime
    reason: Annotated[str, Field(min_length=5, max_length=2000)]

    @model_validator(mode="after")
    def timezone_required(self):
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        return self


class SimulatedReceipt(Model):
    id: str = Field(default_factory=new_id)
    proposal_id: str
    invoice_id: str
    terms: PaymentTerms
    approved_by: str
    executed_by: str
    simulated: Literal[True] = True
    created_at: datetime = Field(default_factory=now)


class PaymentResult(Model):
    proposal_id: str
    status: Literal["blocked", "executed", "already_executed"]
    reasons: list[str] = Field(default_factory=list)
    receipt_id: str | None = None


class ObserveInput(Model):
    session_id: Identifier
    source_id: Identifier
    content: Text
    claim: Claim | None = None


class PlanPaymentInput(Model):
    session_id: Identifier
    invoice_id: BusinessID


class ExecutePaymentInput(Model):
    session_id: Identifier


class AgentStep(Model):
    node: str
    decision: str


class AgentRun(Model):
    id: str = Field(default_factory=new_id)
    session_id: str
    actor: str
    operation: Literal["observe", "plan_payment", "execute_payment"]
    status: str = "running"
    memory_ids: list[str] = Field(default_factory=list)
    proposal_id: str | None = None
    receipt_id: str | None = None
    blocked: list[BlockedMemory] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    steps: list[AgentStep] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=now)
