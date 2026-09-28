"""Strict, data-only scenario format. IDs refer to earlier writes in each case."""

from typing import Annotated, Literal

from pydantic import Field, model_validator

from recallguard.models import (
    Action,
    Identifier,
    MemoryInput,
    Model,
    RetrievalInput,
    Role,
    SourceInput,
)

CaseID = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,79}$")]


class Write(Model):
    op: Literal["write"]
    id: CaseID
    memory: MemoryInput
    actor: Role = Role.AGENT
    expected_error: Literal[403, 404, 409, 422] | None = None


class GrantScope(Model):
    op: Literal["grant"]
    memory_id: CaseID
    action: Action
    target: Identifier

    @model_validator(mode="after")
    def consequential(self):
        if self.action == Action.INFORM:
            raise ValueError("Informational grants are not supported")
        return self


class Revoke(Model):
    op: Literal["revoke"]
    memory_id: CaseID


Operation = Annotated[Write | GrantScope | Revoke, Field(discriminator="op")]


class Case(Model):
    id: CaseID
    category: Literal["security", "utility", "limitation"]
    description: Annotated[str, Field(min_length=1, max_length=2000)]
    sources: list[SourceInput] = Field(min_length=1, max_length=16)
    operations: list[Operation] = Field(min_length=1, max_length=128)
    query: RetrievalInput
    required_ids: list[CaseID] = Field(default_factory=list, max_length=64)
    forbidden_ids: list[CaseID] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def references(self):
        sources = {s.id for s in self.sources}
        if len(sources) != len(self.sources):
            raise ValueError("Duplicate source IDs")
        seen = set()
        for operation in self.operations:
            if isinstance(operation, Write):
                if operation.id in seen:
                    raise ValueError("Duplicate memory IDs")
                data = operation.memory
                if data.source_id and data.source_id not in sources:
                    raise ValueError("Unknown source ID")
                if not set(data.parent_ids) <= seen:
                    raise ValueError("Parents must refer to earlier writes")
                seen.add(operation.id)
            elif operation.memory_id not in seen:
                raise ValueError("Review operation must refer to an earlier write")
        if len(seen) > 64:
            raise ValueError("A case may contain at most 64 memories")
        required, forbidden = set(self.required_ids), set(self.forbidden_ids)
        if len(required) != len(self.required_ids) or len(forbidden) != len(self.forbidden_ids):
            raise ValueError("Duplicate outcome IDs")
        if not (required | forbidden) or required & forbidden:
            raise ValueError("Outcomes must be nonempty and disjoint")
        if not (required | forbidden) <= seen:
            raise ValueError("Outcome references an unknown memory")
        if len(required) > self.query.limit:
            raise ValueError("Required context must fit within the query limit")
        if self.query.mode is not None:
            raise ValueError("Select retrieval mode for the whole evaluation, not per case")
        return self


class Dataset(Model):
    schema_version: Literal[1]
    id: CaseID
    provenance: Annotated[str, Field(min_length=1, max_length=2000)]
    kind: Literal["synthetic", "adapted"]
    cases: list[Case] = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def unique_cases(self):
        if len({case.id for case in self.cases}) != len(self.cases):
            raise ValueError("Duplicate case IDs")
        return self
