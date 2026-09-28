"""Requests intentionally cannot set authority, provenance, risk, or lifecycle fields."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


def now() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid4())


Text = Annotated[str, Field(min_length=1, max_length=16000)]
Identifier = Annotated[str, Field(min_length=1, max_length=200)]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SourceType(StrEnum):
    WEB = "web"
    EMAIL = "email"
    FILE = "file"
    TOOL = "tool"
    USER = "user"
    SYSTEM = "system"


class MemoryType(StrEnum):
    EXTERNAL_CLAIM = "external_claim"
    OBSERVATION = "observation"
    INSTRUCTION = "instruction"
    CREDENTIAL = "credential"


class Status(StrEnum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"


class Action(StrEnum):
    INFORM = "inform"
    PAYMENT = "payment"
    CHANGE_BANK = "change_bank"
    SEND_MESSAGE = "send_message"


class Role(StrEnum):
    AGENT = "agent"
    REVIEWER = "reviewer"


class Principal(Model):
    id: Identifier
    role: Role


class SourceInput(Model):
    id: Identifier
    kind: SourceType
    locator: Annotated[str, Field(min_length=1, max_length=2000)]


class Source(SourceInput):
    registered_by: str
    created_at: datetime = Field(default_factory=now)


class Claim(Model):
    """Structured conflict keys; these are asserted, not semantically verified."""

    entity: Identifier
    attribute: Identifier
    value: Annotated[str, Field(min_length=1, max_length=2000)]


class MemoryInput(Model):
    content: Text
    source_id: Identifier | None = None
    parent_ids: list[Identifier] = Field(default_factory=list, max_length=32)
    claim: Claim | None = None

    @model_validator(mode="after")
    def require_origin(self):
        if bool(self.source_id) == bool(self.parent_ids):
            raise ValueError("Provide exactly one source_id or a nonempty parent_ids list")
        if len(self.parent_ids) != len(set(self.parent_ids)):
            raise ValueError("Duplicate parents are not allowed")
        return self


class Memory(Model):
    id: str = Field(default_factory=new_id)
    content: str
    content_hash: str
    memory_type: MemoryType
    source_id: str | None
    parent_ids: list[str]
    origin_ids: list[str]
    authority: int = Field(ge=0, le=5)
    influence_scopes: list[str] = Field(default_factory=lambda: ["inform"])
    taint_labels: list[str]
    status: Status
    reasons: list[str]
    claim: Claim | None = None
    conflict_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=now)


class GrantInput(Model):
    memory_id: Identifier
    action: Action
    target: Identifier
    reason: Annotated[str, Field(min_length=5, max_length=2000)]
    expires_at: datetime

    @model_validator(mode="after")
    def consequential_only(self):
        if self.action == Action.INFORM:
            raise ValueError("Informational access does not need a grant")
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        return self


class Grant(GrantInput):
    id: str = Field(default_factory=new_id)
    memory_hash: str
    claim_verification_id: str | None = None
    approved_by: str
    created_at: datetime = Field(default_factory=now)


class ContextReviewInput(Model):
    memory_id: Identifier
    expected_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    reason: Annotated[str, Field(min_length=5, max_length=2000)]
    expires_at: datetime

    @model_validator(mode="after")
    def timezone_required(self):
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        return self


class ContextReview(ContextReviewInput):
    memory_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    id: str = Field(default_factory=new_id)
    reviewed_by: str
    created_at: datetime = Field(default_factory=now)
    withdrawn_at: datetime | None = None
    withdrawn_by: str | None = None
    withdrawal_reason: str | None = None


class ClaimVerificationInput(Model):
    memory_id: Identifier
    evidence_source_id: Identifier
    expected_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    evidence_reference: Annotated[str, Field(min_length=5, max_length=2000)]
    method: Literal["official_record", "callback", "in_person"]
    independently_checked: Literal[True]
    reason: Annotated[str, Field(min_length=5, max_length=2000)]
    expires_at: datetime

    @model_validator(mode="after")
    def timezone_required(self):
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        return self


class ClaimVerification(ClaimVerificationInput):
    id: str = Field(default_factory=new_id)
    record_fingerprint: str
    claim: Claim
    verified_by: str
    created_at: datetime = Field(default_factory=now)
    withdrawn_at: datetime | None = None
    withdrawn_by: str | None = None
    withdrawal_reason: str | None = None


class RetrievalInput(Model):
    query: Annotated[str, Field(min_length=1, max_length=2000)]
    action: Action = Action.INFORM
    target: Identifier | None = None
    limit: int = Field(default=10, ge=1, le=100)
    mode: Literal["lexical", "semantic"] | None = None
    min_score: float = Field(default=0.25, ge=-1, le=1, allow_inf_nan=False)

    @model_validator(mode="after")
    def action_needs_target(self):
        if self.action != Action.INFORM and not self.target:
            raise ValueError("Consequential actions require an exact target")
        return self


class BlockedMemory(Model):
    memory_id: str
    reasons: list[str]


class RetrievalResult(Model):
    allowed: list[Memory]
    blocked: list[BlockedMemory]
    action: Action
    target: str | None
    mode: str = "lexical"
    model_id: str | None = None
    scores: dict[str, float] = Field(default_factory=dict)
    unindexed_count: int = 0
    # Exact review IDs used for exceptional informational admission, never action grants.
    context_reviews: dict[str, str] = Field(default_factory=dict)
    claim_verifications: dict[str, str] = Field(default_factory=dict)
    unverified_claim_ids: list[str] = Field(default_factory=list)


class ReindexInput(Model):
    limit: int = Field(default=32, ge=1, le=256)


class RevokeInput(Model):
    reason: Annotated[str, Field(min_length=5, max_length=2000)]


class AuditEvent(Model):
    id: str = Field(default_factory=new_id)
    kind: str
    actor: str
    subject_ids: list[str]
    detail: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=now)
