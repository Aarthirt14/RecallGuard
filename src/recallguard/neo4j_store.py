"""Small-workspace transactional adapter; every operation locks its workspace.

This deliberately loads workspace state for the reference policy engine. It is
correctness-first, not a large-scale vector database implementation.
"""

import json
from collections.abc import Callable
from typing import TypeVar

from neo4j import GraphDatabase

from recallguard.embeddings import EmbeddingRecord
from recallguard.models import (
    AuditEvent,
    ClaimVerification,
    ConflictResolution,
    ContextReview,
    Grant,
    Memory,
    Source,
)
from recallguard.procurement_models import (
    AgentRun,
    Invoice,
    PaymentProposal,
    SimulatedReceipt,
    Supplier,
)
from recallguard.store import State

T = TypeVar("T")
MODELS = {"sources": Source, "memories": Memory, "grants": Grant, "events": AuditEvent}
MODELS.update(
    suppliers=Supplier,
    invoices=Invoice,
    payments=PaymentProposal,
    receipts=SimulatedReceipt,
    runs=AgentRun,
    embeddings=EmbeddingRecord,
    context_reviews=ContextReview,
    claim_verifications=ClaimVerification,
    conflict_resolutions=ConflictResolution,
)


class Neo4jStore:
    def __init__(self, uri: str, user: str, password: str, namespace: str = "default"):
        self.namespace = namespace
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        try:
            self.driver.verify_connectivity()
            with self.driver.session() as session:
                session.run(
                    "CREATE CONSTRAINT rg_workspace IF NOT EXISTS "
                    "FOR (w:RGWorkspace) REQUIRE w.id IS UNIQUE"
                ).consume()
                session.run(
                    "CREATE CONSTRAINT rg_object IF NOT EXISTS "
                    "FOR (o:RGObject) REQUIRE o.key IS UNIQUE"
                ).consume()
        except Exception:
            self.driver.close()
            raise

    def transact(self, operation: Callable[[State], T]) -> T:
        def run(tx):
            # Direct property dependency obtains a write lock before reading state.
            tx.run(
                "MERGE (w:RGWorkspace {id: $namespace}) "
                "ON CREATE SET w.revision = 0 "
                "SET w.revision = w.revision + 1",
                namespace=self.namespace,
            ).consume()
            state = State()
            before = {}
            for record in tx.run(
                "MATCH (o:RGObject {namespace: $namespace}) "
                "RETURN o.kind AS kind, o.payload AS payload, o.key AS key",
                namespace=self.namespace,
            ):
                kind = record["kind"]
                obj = MODELS[kind].model_validate_json(record["payload"])
                getattr(state, kind)[obj.id] = obj
                before[record["key"]] = obj.model_dump_json()
            result = operation(state)
            changed = []
            for kind in MODELS:
                for obj in getattr(state, kind).values():
                    key = json.dumps([self.namespace, kind, obj.id])
                    payload = obj.model_dump_json()
                    if before.get(key) != payload:
                        changed.append(
                            {
                                "key": key,
                                "kind": kind,
                                "id": obj.id,
                                "payload": payload,
                            }
                        )
            if changed:
                tx.run(
                    "UNWIND $rows AS row MERGE (o:RGObject {key: row.key}) "
                    "SET o.namespace = $namespace, o.kind = row.kind, "
                    "o.id = row.id, o.payload = row.payload",
                    rows=changed,
                    namespace=self.namespace,
                ).consume()
            # Relationships mirror immutable lineage in the validated record.
            edges = [
                {"parent": parent, "child": memory.id}
                for memory in state.memories.values()
                for parent in memory.parent_ids
            ]
            tx.run(
                "UNWIND $edges AS edge "
                "MATCH (p:RGObject {namespace: $ns, kind: 'memories', id: edge.parent}) "
                "MATCH (c:RGObject {namespace: $ns, kind: 'memories', id: edge.child}) "
                "MERGE (p)-[:DERIVED_INTO]->(c)",
                edges=edges,
                ns=self.namespace,
            ).consume()
            roots = [
                {"source": m.source_id, "memory": m.id}
                for m in state.memories.values()
                if m.source_id
            ]
            tx.run(
                "UNWIND $roots AS root "
                "MATCH (s:RGObject {namespace: $ns, kind: 'sources', id: root.source}) "
                "MATCH (m:RGObject {namespace: $ns, kind: 'memories', id: root.memory}) "
                "MERGE (s)-[:ORIGINATED]->(m)",
                roots=roots,
                ns=self.namespace,
            ).consume()
            return result

        with self.driver.session() as session:
            return session.execute_write(run)

    def close(self) -> None:
        self.driver.close()
