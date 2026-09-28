"""Security policy is deterministic. Text detection is only a quarantine signal."""

import hashlib
import re
from datetime import timedelta

from recallguard.embeddings import EmbeddingError, Encoder, encode_checked, find_record, make_record
from recallguard.models import (
    Action,
    AuditEvent,
    BlockedMemory,
    Grant,
    GrantInput,
    Memory,
    MemoryInput,
    MemoryType,
    Principal,
    RetrievalInput,
    RetrievalResult,
    Role,
    Source,
    SourceInput,
    SourceType,
    Status,
    now,
)
from recallguard.store import State, Store


class GuardError(Exception):
    def __init__(self, message: str, status: int = 400):
        self.message = message
        self.status = status
        super().__init__(message)


AUTHORITY = {
    SourceType.WEB: 1,
    SourceType.EMAIL: 1,
    SourceType.FILE: 1,
    SourceType.TOOL: 2,
    SourceType.USER: 3,
    SourceType.SYSTEM: 5,
}
EXTERNAL = {SourceType.WEB, SourceType.EMAIL, SourceType.FILE}
INSTRUCTION = re.compile(
    r"\b(ignore|bypass|disable|override)\b|\b(always|never|must)\b|"
    r"\b(send|transfer|pay)\b.{0,100}\b(account|money|funds)\b",
    re.I | re.S,
)
CREDENTIAL = re.compile(
    r"\b(password|api[_ -]?key|secret[_ -]?key|access[_ -]?token)\s*[:=]\s*\S+", re.I
)


def require_reviewer(actor: Principal) -> None:
    if actor.role != Role.REVIEWER:
        raise GuardError("Reviewer credentials are required", 403)


def audit(state: State, actor: Principal, kind: str, subjects: list[str], **detail) -> None:
    event = AuditEvent(kind=kind, actor=actor.id, subject_ids=subjects, detail=detail)
    state.events[event.id] = event


def get_memory(state: State, memory_id: str) -> Memory:
    try:
        return state.memories[memory_id]
    except KeyError:
        raise GuardError("Memory not found", 404) from None


def ancestors(state: State, memory: Memory) -> list[Memory]:
    pending = list(memory.parent_ids)
    seen = set()
    result = []
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        parent = get_memory(state, current)
        result.append(parent)
        pending.extend(parent.parent_ids)
    return result


def blocked_reasons(state: State, memory: Memory) -> list[str]:
    reasons = []
    if memory.status != Status.ACTIVE:
        reasons.append(f"memory_{memory.status}")
    if any(p.status != Status.ACTIVE for p in ancestors(state, memory)):
        reasons.append("inactive_ancestor")
    if memory.conflict_ids:
        reasons.append("unresolved_conflict")
    return reasons


def action_blocked_reasons(
    state: State, memory: Memory, action: Action, target: str | None
) -> list[str]:
    """Shared by retrieval and the tool gate; no cached permission decisions."""
    reasons = blocked_reasons(state, memory)
    if action != Action.INFORM and not any(
        g.memory_id == memory.id
        and g.memory_hash == memory.content_hash
        and g.action == action
        and g.target == target
        and g.expires_at > now()
        for g in state.grants.values()
    ):
        reasons.append("scoped_approval_required")
    return reasons


class RecallGuard:
    def __init__(self, store: Store, encoder: Encoder | None = None):
        self.store = store
        self.encoder = encoder

    def _encode(self, texts: list[str]) -> list[list[float]]:
        if self.encoder is None:
            raise GuardError("Semantic retrieval is not configured", 503)
        try:
            return encode_checked(self.encoder, texts)
        except EmbeddingError:
            raise GuardError("Embedding generation failed; no changes were saved", 503) from None

    def register_source(self, data: SourceInput, actor: Principal) -> Source:
        require_reviewer(actor)

        def operation(state):
            if data.id in state.sources:
                raise GuardError("Source already exists; source identity is immutable", 409)
            source = Source(**data.model_dump(), registered_by=actor.id)
            state.sources[source.id] = source
            audit(state, actor, "source_registered", [source.id], source_type=source.kind)
            return source

        return self.store.transact(operation)

    def remember(self, data: MemoryInput, actor: Principal) -> Memory:
        if CREDENTIAL.search(data.content):
            raise GuardError("Potential credential detected; memory was not stored", 422)
        vector = self._encode([data.content])[0] if self.encoder else None

        def operation(state):
            parents = [get_memory(state, mid) for mid in data.parent_ids]
            reasons = []
            taints = set()
            if parents:
                origin_ids = sorted({origin for p in parents for origin in p.origin_ids})
                authority = min(p.authority for p in parents)
                taints.update(t for p in parents for t in p.taint_labels)
                if any(blocked_reasons(state, p) for p in parents):
                    reasons.append("restricted_parent")
            else:
                source = state.sources.get(data.source_id)
                if source is None:
                    raise GuardError("Source not found", 404)
                # The agent may ingest only low-authority external roots. Tool results
                # are reviewer-ingested until authenticated tool adapters exist.
                if source.kind not in EXTERNAL:
                    require_reviewer(actor)
                authority = AUTHORITY[source.kind]
                origin_ids = [source.id]
                if source.kind in EXTERNAL:
                    taints.add("untrusted_external")
            is_instruction = bool(INSTRUCTION.search(data.content))
            if is_instruction:
                taints.add("contains_instruction")
                reasons.append("instruction_requires_review")
            if "contains_instruction" in taints:
                reasons.append("instruction_taint")
            memory_type = (
                MemoryType.INSTRUCTION
                if is_instruction
                else MemoryType.EXTERNAL_CLAIM
                if "untrusted_external" in taints
                else MemoryType.OBSERVATION
            )
            memory = Memory(
                content=data.content,
                content_hash=hashlib.sha256(data.content.encode()).hexdigest(),
                memory_type=memory_type,
                source_id=data.source_id,
                parent_ids=data.parent_ids,
                origin_ids=origin_ids,
                authority=authority,
                taint_labels=sorted(taints),
                status=Status.QUARANTINED if reasons else Status.ACTIVE,
                reasons=sorted(set(reasons)),
                claim=data.claim,
            )
            if memory.claim:
                key = (memory.claim.entity.casefold(), memory.claim.attribute.casefold())
                for other in state.memories.values():
                    if not other.claim or other.status == Status.REVOKED:
                        continue
                    other_key = (other.claim.entity.casefold(), other.claim.attribute.casefold())
                    if key == other_key and memory.claim.value != other.claim.value:
                        memory.conflict_ids.append(other.id)
                        other.conflict_ids.append(memory.id)
                        # Conservative until an explicit conflict-resolution workflow exists.
                        for item in (other, memory):
                            item.status = Status.QUARANTINED
                            item.taint_labels = sorted(set(item.taint_labels) | {"conflicted"})
                            item.reasons = sorted(set(item.reasons) | {"conflicting_claim"})
                        audit(state, actor, "conflict_detected", [other.id, memory.id])
            state.memories[memory.id] = memory
            if vector is not None:
                record = make_record(memory, self.encoder, vector)
                state.embeddings[record.id] = record
            audit(state, actor, "memory_written", [memory.id], decision=memory.status)
            return memory

        return self.store.transact(operation)

    def grant(self, data: GrantInput, actor: Principal) -> Grant:
        require_reviewer(actor)

        def operation(state):
            memory = get_memory(state, data.memory_id)
            if blocked_reasons(state, memory):
                raise GuardError("Restricted memory cannot receive an action grant", 409)
            if not now() < data.expires_at <= now() + timedelta(hours=24):
                raise GuardError("Grant expiry must be in the next 24 hours", 422)
            grant = Grant(
                **data.model_dump(), memory_hash=memory.content_hash, approved_by=actor.id
            )
            state.grants[grant.id] = grant
            audit(
                state,
                actor,
                "grant_issued",
                [memory.id, grant.id],
                action=grant.action,
                target=grant.target,
                reason=grant.reason,
            )
            return grant

        return self.store.transact(operation)

    def retrieve(self, data: RetrievalInput, actor: Principal) -> RetrievalResult:
        mode = data.mode or ("semantic" if self.encoder else "lexical")
        query_vector = self._encode([data.query])[0] if mode == "semantic" else None

        def operation(state):
            tokens = set(re.findall(r"\w+", data.query.casefold()))
            candidates = []
            unindexed = 0
            for memory in state.memories.values():
                if query_vector is not None:
                    record = find_record(state.embeddings, memory, self.encoder)
                    if record is None:
                        unindexed += memory.status != Status.REVOKED
                        continue
                    score = max(
                        -1.0,
                        min(
                            1.0,
                            sum(a * b for a, b in zip(query_vector, record.vector, strict=True)),
                        ),
                    )
                    if score < data.min_score:
                        continue
                else:
                    score = len(tokens & set(re.findall(r"\w+", memory.content.casefold())))
                    if not score:
                        continue
                candidates.append((score, memory))
            candidates.sort(key=lambda pair: (-pair[0], pair[1].id))
            allowed, blocked, scores = [], [], {}
            # Live policy filtering precedes top-k, including when vectors predate a revoke.
            for score, memory in candidates:
                reasons = action_blocked_reasons(state, memory, data.action, data.target)
                if reasons:
                    blocked.append(BlockedMemory(memory_id=memory.id, reasons=reasons))
                elif len(allowed) < data.limit:
                    allowed.append(memory)
                    scores[memory.id] = score
            result = RetrievalResult(
                allowed=allowed,
                blocked=blocked[:100],
                action=data.action,
                target=data.target,
                mode=mode,
                model_id=self.encoder.model_id if mode == "semantic" else None,
                scores=scores,
                unindexed_count=unindexed,
            )
            audit(
                state,
                actor,
                "retrieval_checked",
                [m.id for m in result.allowed],
                action=data.action,
                target=data.target,
                allowed_count=len(result.allowed),
                blocked_count=len(blocked),
                mode=mode,
                model_id=result.model_id,
                unindexed_count=unindexed,
            )
            return result

        return self.store.transact(operation)

    def _missing_embeddings(self, state):
        return [
            m
            for m in state.memories.values()
            if m.status != Status.REVOKED and find_record(state.embeddings, m, self.encoder) is None
        ]

    def embedding_status(self, actor: Principal) -> dict:
        require_reviewer(actor)
        if self.encoder is None:
            raise GuardError("Semantic retrieval is not configured", 503)

        def operation(state):
            eligible = sum(m.status != Status.REVOKED for m in state.memories.values())
            missing = len(self._missing_embeddings(state))
            return {
                "model_id": self.encoder.model_id,
                "dimensions": self.encoder.dimensions,
                "eligible": eligible,
                "indexed": eligible - missing,
                "remaining": missing,
            }

        return self.store.transact(operation)

    def reindex(self, limit: int, actor: Principal) -> dict:
        require_reviewer(actor)
        if self.encoder is None:
            raise GuardError("Semantic retrieval is not configured", 503)
        if not 1 <= limit <= 256:
            raise GuardError("Reindex limit must be between 1 and 256", 422)
        pending = self.store.transact(
            lambda state: sorted(self._missing_embeddings(state), key=lambda m: m.id)[:limit]
        )
        # Model inference is outside transaction callbacks (which Neo4j may retry).
        vectors = self._encode([m.content for m in pending]) if pending else []

        def operation(state):
            written = []
            for snapshot, vector in zip(pending, vectors, strict=True):
                current = state.memories.get(snapshot.id)
                if (
                    current is None
                    or current.status == Status.REVOKED
                    or current.content_hash != snapshot.content_hash
                    or find_record(state.embeddings, current, self.encoder) is not None
                ):
                    continue
                record = make_record(current, self.encoder, vector)
                state.embeddings[record.id] = record
                written.append(current.id)
            if written:
                audit(state, actor, "embeddings_indexed", written, model_id=self.encoder.model_id)
            return {
                "model_id": self.encoder.model_id,
                "indexed": len(written),
                "remaining": len(self._missing_embeddings(state)),
            }

        return self.store.transact(operation)

    def revoke(self, memory_id: str, reason: str, actor: Principal) -> list[str]:
        require_reviewer(actor)

        def operation(state):
            get_memory(state, memory_id)
            affected = {memory_id}
            changed = True
            while changed:
                changed = False
                for memory in state.memories.values():
                    if memory.id not in affected and affected.intersection(memory.parent_ids):
                        affected.add(memory.id)
                        changed = True
            for mid in affected:
                memory = state.memories[mid]
                memory.status = Status.REVOKED
                memory.reasons = sorted(set(memory.reasons) | {"revoked_lineage"})
            audit(state, actor, "lineage_revoked", sorted(affected), reason=reason)
            return sorted(affected)

        return self.store.transact(operation)

    def inspect(self, actor: Principal) -> State:
        require_reviewer(actor)
        return self.store.transact(lambda state: state)
