"""Conflict replacement plans; no old record is promoted or restored."""

import hashlib
import json
from pathlib import Path

from recallguard.models import Memory, Source, Status
from recallguard.screening import screen_memory
from recallguard.store import State

POLICY_FINGERPRINT = hashlib.sha256(
    b"".join(
        Path(__file__).with_name(name).read_bytes()
        for name in ("conflicts.py", "engine.py", "screening.py")
    )
).hexdigest()


def descendants_of(state: State, roots: set[str]) -> list[str]:
    affected = set(roots)
    while True:
        added = {
            m.id for m in state.memories.values() if affected.intersection(m.parent_ids)
        } - affected
        if not added:
            return sorted(affected)
        affected.update(added)


def conflict_members(state: State, selected: Memory) -> list[str]:
    if not selected.claim or not selected.conflict_ids or selected.status == Status.REVOKED:
        return []
    key = (selected.claim.entity.casefold(), selected.claim.attribute.casefold())
    # Include historical revoked records: their origins still cannot be repackaged
    # as independent evidence, and the complete history remains visible to reviewers.
    return sorted(
        m.id
        for m in state.memories.values()
        if m.claim and (m.claim.entity.casefold(), m.claim.attribute.casefold()) == key
    )


def replacement_content(selected: Memory) -> str:
    claim = selected.claim
    return f"{claim.entity} / {claim.attribute}: {claim.value}"


def evidence_origins(state: State, memory_ids: list[str]) -> set[str]:
    """Exclude declared and retired origins across successive replacements.

    Historical links limit evidence reuse; they do not propagate old lifecycle
    restrictions to a newly asserted, independently sourced replacement.
    """
    retired = {
        r.replacement_memory_id: r.retired_memory_ids for r in state.conflict_resolutions.values()
    }
    pending, seen, origins = list(memory_ids), set(), set()
    while pending:
        mid = pending.pop()
        if mid in seen:
            continue
        seen.add(mid)
        memory = state.memories.get(mid)
        if memory is None:
            # No public deletion endpoint exists; incomplete history fails closed.
            origins.add(f"missing-memory:{mid}")
            continue
        origins.update(memory.origin_ids)
        pending.extend(memory.parent_ids)
        pending.extend(retired.get(mid, []))
    return origins


def resolution_blockers(state: State, selected: Memory, source: Source) -> list[str]:
    members = conflict_members(state, selected)
    if not members:
        return ["open_structured_conflict_required"]
    affected = descendants_of(state, set(members))
    origins = evidence_origins(state, affected)
    if any(s not in state.sources for s in origins):
        return ["unknown_origin"]
    locator = source.locator.casefold().rstrip("/")
    if source.id in origins or any(
        state.sources[s].locator.casefold().rstrip("/") == locator for s in origins
    ):
        return ["separate_evidence_source_required"]
    if screen_memory(replacement_content(selected), selected.claim).blocked:
        return ["replacement_content_restricted"]
    return []


def resolution_fingerprint(state: State, selected: Memory, source: Source) -> str:
    members = conflict_members(state, selected)
    affected = descendants_of(state, set(members))
    payload = {
        "policy": POLICY_FINGERPRINT,
        "selected": selected.id,
        "members": members,
        "affected": [state.memories[mid].model_dump(mode="json") for mid in affected],
        "source": source.model_dump(mode="json"),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def resolution_options(state: State, selected: Memory) -> dict:
    members = conflict_members(state, selected)
    return {
        "conflicting_memory_ids": members,
        "retired_memory_ids": descendants_of(state, set(members)),
        "replacement_content": replacement_content(selected) if members else None,
        "evidence_sources": [
            {"id": s.id, "fingerprint": resolution_fingerprint(state, selected, s)}
            for s in state.sources.values()
            if members and not resolution_blockers(state, selected, s)
        ],
    }
