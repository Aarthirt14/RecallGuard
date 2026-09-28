"""Authenticated FastAPI boundary. Reviewer credentials must stay outside agents."""

import os
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader

from recallguard.agent import ProcurementAgent
from recallguard.embeddings import Encoder, LocalMiniLMEncoder
from recallguard.engine import GuardError, RecallGuard
from recallguard.models import (
    Grant,
    GrantInput,
    Memory,
    MemoryInput,
    Principal,
    ReindexInput,
    RetrievalInput,
    RetrievalResult,
    RevokeInput,
    Role,
    Source,
    SourceInput,
)
from recallguard.procurement import Procurement
from recallguard.procurement_models import (
    AgentRun,
    ExecutePaymentInput,
    Invoice,
    InvoiceInput,
    ObserveInput,
    PaymentApprovalInput,
    PaymentProposal,
    PlanPaymentInput,
    Supplier,
    SupplierInput,
)
from recallguard.store import InMemoryStore, Store


@dataclass(frozen=True)
class Settings:
    agent_key: str
    reviewer_key: str
    backend: str = "neo4j"
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    retrieval_mode: str = "lexical"
    embedding_cache: str | None = None
    embedding_offline: bool = False
    embedding_model_path: str | None = None

    def __post_init__(self):
        if min(len(self.agent_key), len(self.reviewer_key)) < 32:
            raise ValueError("Set distinct RECALLGUARD_AGENT_KEY and REVIEWER_KEY (32+ characters)")
        if secrets.compare_digest(self.agent_key.encode(), self.reviewer_key.encode()):
            raise ValueError("Agent and reviewer keys must be different")
        if self.backend not in {"memory", "neo4j"}:
            raise ValueError("RECALLGUARD_BACKEND must be memory or neo4j")
        if self.retrieval_mode not in {"lexical", "semantic"}:
            raise ValueError("RECALLGUARD_RETRIEVAL_MODE must be lexical or semantic")

    @classmethod
    def from_env(cls):
        return cls(
            agent_key=os.getenv("RECALLGUARD_AGENT_KEY", ""),
            reviewer_key=os.getenv("RECALLGUARD_REVIEWER_KEY", ""),
            backend=os.getenv("RECALLGUARD_BACKEND", "neo4j"),
            neo4j_uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            neo4j_user=os.getenv("NEO4J_USER", "neo4j"),
            neo4j_password=os.getenv("NEO4J_PASSWORD", ""),
            retrieval_mode=os.getenv("RECALLGUARD_RETRIEVAL_MODE", "lexical"),
            embedding_cache=os.getenv("RECALLGUARD_EMBEDDING_CACHE"),
            embedding_offline=os.getenv("RECALLGUARD_EMBEDDING_OFFLINE", "0") == "1",
            embedding_model_path=os.getenv("RECALLGUARD_EMBEDDING_MODEL_PATH"),
        )


def create_app(
    settings: Settings | None = None, store: Store | None = None, encoder: Encoder | None = None
) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app):
        selected_encoder = encoder
        if selected_encoder is None and settings.retrieval_mode == "semantic":
            selected_encoder = LocalMiniLMEncoder(
                cache_dir=settings.embedding_cache,
                local_files_only=settings.embedding_offline,
                model_path=settings.embedding_model_path,
            )
        if store is not None:
            selected = store
        elif settings.backend == "memory":
            selected = InMemoryStore()
        else:
            from recallguard.neo4j_store import Neo4jStore

            if not settings.neo4j_password:
                raise ValueError("NEO4J_PASSWORD is required for persistent storage")
            selected = Neo4jStore(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
        app.state.guard = RecallGuard(selected, selected_encoder)
        app.state.procurement = Procurement(selected)
        try:
            yield
        finally:
            selected.close()

    app = FastAPI(
        title="RecallGuard",
        version="0.3.0",
        lifespan=lifespan,
        description="Origin-bound memory controls. This API does not execute external actions.",
    )
    key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

    def principal(key: Annotated[str | None, Depends(key_header)]) -> Principal:
        if key and secrets.compare_digest(key.encode(), settings.reviewer_key.encode()):
            return Principal(id="reviewer", role=Role.REVIEWER)
        if key and secrets.compare_digest(key.encode(), settings.agent_key.encode()):
            return Principal(id="agent", role=Role.AGENT)
        raise HTTPException(status_code=401, detail="Valid API credentials are required")

    Actor = Annotated[Principal, Depends(principal)]

    @app.exception_handler(GuardError)
    async def guard_error_handler(request, exc):
        return JSONResponse(status_code=exc.status, content={"detail": exc.message})

    @app.get("/health")
    def health():
        app.state.guard.store.transact(lambda state: None)
        return {"status": "ok", "storage": settings.backend}

    @app.post("/sources", response_model=Source, status_code=201)
    def register_source(data: SourceInput, actor: Actor):
        return app.state.guard.register_source(data, actor)

    @app.post("/memories", response_model=Memory, status_code=201)
    def remember(data: MemoryInput, actor: Actor):
        return app.state.guard.remember(data, actor)

    @app.post("/retrieve", response_model=RetrievalResult)
    def retrieve(data: RetrievalInput, actor: Actor):
        return app.state.guard.retrieve(data, actor)

    @app.post("/grants", response_model=Grant, status_code=201)
    def grant(data: GrantInput, actor: Actor):
        return app.state.guard.grant(data, actor)

    @app.get("/embeddings/status")
    def embedding_status(actor: Actor):
        return app.state.guard.embedding_status(actor)

    @app.post("/embeddings/reindex")
    def reindex(data: ReindexInput, actor: Actor):
        return app.state.guard.reindex(data.limit, actor)

    @app.post("/memories/{memory_id}/revoke")
    def revoke(memory_id: str, data: RevokeInput, actor: Actor):
        return {"revoked_ids": app.state.guard.revoke(memory_id, data.reason, actor)}

    @app.get("/memories", response_model=list[Memory])
    def memories(actor: Actor):
        return list(app.state.guard.inspect(actor).memories.values())

    @app.get("/graph")
    def graph(actor: Actor):
        state = app.state.guard.inspect(actor)
        return {
            "sources": list(state.sources.values()),
            "memories": list(state.memories.values()),
            "edges": [
                {"from": parent, "to": m.id, "kind": "derived_into"}
                for m in state.memories.values()
                for parent in m.parent_ids
            ]
            + [
                {"from": m.source_id, "to": m.id, "kind": "originated"}
                for m in state.memories.values()
                if m.source_id
            ],
        }

    @app.get("/audit")
    def events(actor: Actor):
        return list(app.state.guard.inspect(actor).events.values())

    @app.post("/procurement/suppliers", response_model=Supplier, status_code=201)
    def supplier(data: SupplierInput, actor: Actor):
        return app.state.procurement.register_supplier(data, actor)

    @app.post("/procurement/invoices", response_model=Invoice, status_code=201)
    def invoice(data: InvoiceInput, actor: Actor):
        return app.state.procurement.register_invoice(data, actor)

    @app.post("/procurement/invoices/{invoice_id}/cancel", response_model=Invoice)
    def cancel_invoice(invoice_id: str, data: RevokeInput, actor: Actor):
        return app.state.procurement.cancel_invoice(invoice_id, data.reason, actor)

    @app.post("/agent/observe", response_model=AgentRun)
    def observe(data: ObserveInput, actor: Actor):
        return ProcurementAgent(app.state.guard, actor).observe(data)

    @app.post("/agent/plan-payment", response_model=AgentRun)
    def plan_payment(data: PlanPaymentInput, actor: Actor):
        return ProcurementAgent(app.state.guard, actor).plan_payment(data)

    @app.get("/procurement/payments/{proposal_id}", response_model=PaymentProposal)
    def payment(proposal_id: str, actor: Actor):
        return app.state.procurement.proposal(proposal_id)

    @app.post("/procurement/payments/{proposal_id}/approve", response_model=PaymentProposal)
    def approve_payment(proposal_id: str, data: PaymentApprovalInput, actor: Actor):
        return app.state.procurement.approve(proposal_id, data, actor)

    @app.post("/procurement/payments/{proposal_id}/cancel", response_model=PaymentProposal)
    def cancel_payment(proposal_id: str, data: RevokeInput, actor: Actor):
        return app.state.procurement.cancel_payment(proposal_id, data.reason, actor)

    @app.post("/procurement/payments/{proposal_id}/execute", response_model=AgentRun)
    def execute_payment(proposal_id: str, data: ExecutePaymentInput, actor: Actor):
        return ProcurementAgent(app.state.guard, actor).execute_payment(proposal_id, data)

    @app.get("/agent/runs", response_model=list[AgentRun])
    def runs(actor: Actor):
        return list(app.state.guard.inspect(actor).runs.values())

    @app.get("/procurement/receipts")
    def receipts(actor: Actor):
        return list(app.state.guard.inspect(actor).receipts.values())

    return app
