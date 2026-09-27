"""Authenticated FastAPI boundary. Reviewer credentials must stay outside agents."""

import os
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader

from recallguard.engine import GuardError, RecallGuard
from recallguard.models import (
    Grant,
    GrantInput,
    Memory,
    MemoryInput,
    Principal,
    RetrievalInput,
    RetrievalResult,
    RevokeInput,
    Role,
    Source,
    SourceInput,
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

    def __post_init__(self):
        if min(len(self.agent_key), len(self.reviewer_key)) < 32:
            raise ValueError("Set distinct RECALLGUARD_AGENT_KEY and REVIEWER_KEY (32+ characters)")
        if secrets.compare_digest(self.agent_key.encode(), self.reviewer_key.encode()):
            raise ValueError("Agent and reviewer keys must be different")
        if self.backend not in {"memory", "neo4j"}:
            raise ValueError("RECALLGUARD_BACKEND must be memory or neo4j")

    @classmethod
    def from_env(cls):
        return cls(
            agent_key=os.getenv("RECALLGUARD_AGENT_KEY", ""),
            reviewer_key=os.getenv("RECALLGUARD_REVIEWER_KEY", ""),
            backend=os.getenv("RECALLGUARD_BACKEND", "neo4j"),
            neo4j_uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            neo4j_user=os.getenv("NEO4J_USER", "neo4j"),
            neo4j_password=os.getenv("NEO4J_PASSWORD", ""),
        )


def create_app(settings: Settings | None = None, store: Store | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app):
        if store is not None:
            selected = store
        elif settings.backend == "memory":
            selected = InMemoryStore()
        else:
            from recallguard.neo4j_store import Neo4jStore

            if not settings.neo4j_password:
                raise ValueError("NEO4J_PASSWORD is required for persistent storage")
            selected = Neo4jStore(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
        app.state.guard = RecallGuard(selected)
        try:
            yield
        finally:
            selected.close()

    app = FastAPI(
        title="RecallGuard",
        version="0.1.0",
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

    return app
