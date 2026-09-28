"""Reviewer-only projections. Each response is one consistent store snapshot."""

from recallguard.context_review import current_review, review_blockers, review_request_fingerprint
from recallguard.embeddings import find_record
from recallguard.engine import (
    RecallGuard,
    action_blocked_reasons,
    blocked_reasons,
    require_reviewer,
)
from recallguard.models import Action, Principal, Status, now
from recallguard.procurement import proposal_reasons


def review_snapshot(guard: RecallGuard, actor: Principal, backend: str) -> dict:
    require_reviewer(actor)

    def project(state):
        encoder = guard.encoder
        eligible = [m for m in state.memories.values() if m.status != Status.REVOKED]
        indexed = (
            sum(find_record(state.embeddings, m, encoder) is not None for m in eligible)
            if encoder
            else 0
        )
        events = sorted(state.events.values(), key=lambda e: (e.created_at, e.id), reverse=True)
        return {
            "captured_at": now(),
            "storage": backend,
            "actions": [action.value for action in Action],
            "retrieval_mode": "semantic" if encoder else "lexical",
            "memories": sorted(
                state.memories.values(), key=lambda m: (m.created_at, m.id), reverse=True
            ),
            "sources": list(state.sources.values()),
            "grants": list(state.grants.values()),
            "memory_restrictions": {
                m.id: blocked_reasons(state, m) for m in state.memories.values()
            },
            "context_reviews": list(state.context_reviews.values()),
            "context_review_options": {
                m.id: {
                    "fingerprint": review_request_fingerprint(state, m),
                    "blockers": review_blockers(m),
                    "effective_review_id": r.id if (r := current_review(state, m)) else None,
                }
                for m in state.memories.values()
            },
            "information_restrictions": {
                m.id: action_blocked_reasons(state, m, Action.INFORM, None)
                for m in state.memories.values()
            },
            "payments": sorted(
                state.payments.values(), key=lambda p: (p.created_at, p.id), reverse=True
            ),
            "payment_blockers": {p.id: proposal_reasons(state, p) for p in state.payments.values()},
            "suppliers": list(state.suppliers.values()),
            "invoices": list(state.invoices.values()),
            "receipts": list(state.receipts.values()),
            "events": events[:200],
            "event_count": len(events),
            "embeddings": {
                "enabled": encoder is not None,
                "model_id": encoder.model_id if encoder else None,
                "eligible": len(eligible),
                "indexed": indexed,
                "remaining": len(eligible) - indexed if encoder else 0,
            },
        }

    return guard.store.transact(project)
