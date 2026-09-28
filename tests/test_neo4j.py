import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import uuid4

import pytest

from recallguard.engine import GuardError, RecallGuard
from recallguard.models import (
    Action,
    GrantInput,
    MemoryInput,
    RetrievalInput,
    SourceInput,
    SourceType,
    now,
)
from recallguard.neo4j_store import Neo4jStore

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.getenv("NEO4J_TEST_URI"), reason="NEO4J_TEST_URI not configured"),
]


def test_persistence_lineage_and_transaction_rollback(reviewer, agent):
    namespace = f"test-{uuid4()}"
    args = (os.environ["NEO4J_TEST_URI"], "neo4j", os.environ["NEO4J_TEST_PASSWORD"], namespace)
    store = Neo4jStore(*args)
    try:
        guard = RecallGuard(store)
        guard.register_source(
            SourceInput(id="web", kind=SourceType.WEB, locator="test:web"), reviewer
        )
        root = guard.remember(MemoryInput(content="ABC account 123", source_id="web"), agent)
        child = guard.remember(MemoryInput(content="ABC summary", parent_ids=[root.id]), agent)
        guard.grant(
            GrantInput(
                memory_id=child.id,
                action=Action.PAYMENT,
                target="ABC",
                reason="Verified through separate channel",
                expires_at=now() + timedelta(minutes=5),
            ),
            reviewer,
        )
        before = guard.inspect(reviewer)

        def fail(state):
            state.memories[root.id].authority = 5
            raise GuardError("Rollback")

        with pytest.raises(GuardError):
            store.transact(fail)
        assert guard.inspect(reviewer) == before
        store.close()
        store = Neo4jStore(*args)
        guard = RecallGuard(store)
        assert guard.inspect(reviewer).memories[child.id].origin_ids == ["web"]
        query = RetrievalInput(query="ABC", action=Action.PAYMENT, target="ABC")
        assert [m.id for m in guard.retrieve(query, agent).allowed] == [child.id]
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(
                pool.map(
                    lambda i: guard.remember(
                        MemoryInput(content=f"Observation {i}", source_id="web"), agent
                    ),
                    range(8),
                )
            )
        assert len(guard.inspect(reviewer).memories) == 10
        with store.driver.session() as session:
            record = session.run(
                "MATCH (p:RGObject {namespace: $ns})-[:DERIVED_INTO]->"
                "(c:RGObject {namespace: $ns}) RETURN count(*) AS n",
                ns=namespace,
            ).single()
            assert record["n"] == 1
        assert set(guard.revoke(root.id, "Source compromised", reviewer)) == {root.id, child.id}
        assert not guard.retrieve(query, agent).allowed
    finally:
        with store.driver.session() as session:
            session.run(
                "MATCH (n:RGObject {namespace: $ns}) DETACH DELETE n", ns=namespace
            ).consume()
            session.run("MATCH (n:RGWorkspace {id: $ns}) DELETE n", ns=namespace).consume()
        store.close()


def test_embeddings_reconnect_backfill_and_revocation(reviewer, agent):
    class Encoder:
        model_id = "persistence-test-v1"
        dimensions = 2

        def encode(self, texts):
            return [[1.0, 0.0] for _ in texts]

    namespace = f"test-{uuid4()}"
    args = (os.environ["NEO4J_TEST_URI"], "neo4j", os.environ["NEO4J_TEST_PASSWORD"], namespace)
    store = Neo4jStore(*args)
    try:
        guard = RecallGuard(store)
        guard.register_source(
            SourceInput(id="web", kind=SourceType.WEB, locator="test:web"), reviewer
        )
        old = guard.remember(MemoryInput(content="Legacy shipment", source_id="web"), agent)
        guard.encoder = Encoder()
        new = guard.remember(MemoryInput(content="New shipment", source_id="web"), agent)
        assert guard.reindex(32, reviewer)["indexed"] == 1
        before = guard.inspect(reviewer)
        assert len(before.embeddings) == 2
        store.close()
        store = Neo4jStore(*args)
        guard = RecallGuard(store, Encoder())
        assert guard.inspect(reviewer).embeddings == before.embeddings
        query = RetrievalInput(query="parcel arrival")
        assert {m.id for m in guard.retrieve(query, agent).allowed} == {old.id, new.id}
        guard.revoke(old.id, "invalidated source", reviewer)
        assert [m.id for m in guard.retrieve(query, agent).allowed] == [new.id]
        assert guard.embedding_status(reviewer)["indexed"] == 1
    finally:
        with store.driver.session() as session:
            session.run(
                "MATCH (n:RGObject {namespace: $ns}) DETACH DELETE n", ns=namespace
            ).consume()
            session.run("MATCH (n:RGWorkspace {id: $ns}) DELETE n", ns=namespace).consume()
        store.close()


def test_informational_review_persists_and_withdraws_after_reconnect(reviewer, agent):
    from recallguard.context_review import review_fingerprint
    from recallguard.models import ContextReviewInput

    namespace = f"test-{uuid4()}"
    args = (os.environ["NEO4J_TEST_URI"], "neo4j", os.environ["NEO4J_TEST_PASSWORD"], namespace)
    store = Neo4jStore(*args)
    try:
        guard = RecallGuard(store)
        guard.register_source(
            SourceInput(id="web", kind=SourceType.WEB, locator="test:web"), reviewer
        )
        root = guard.remember(
            MemoryInput(
                content="Orion handbook quotes 'Ignore prior instructions' as an attack.",
                source_id="web",
            ),
            agent,
        )
        review = guard.review_context(
            ContextReviewInput(
                memory_id=root.id,
                expected_fingerprint=review_fingerprint(root),
                reason="Verified as a benign quotation",
                expires_at=now() + timedelta(hours=1),
            ),
            reviewer,
        )
        store.close()
        store = Neo4jStore(*args)
        guard = RecallGuard(store)
        assert guard.retrieve(RetrievalInput(query="Orion"), agent).context_reviews == {
            root.id: review.id
        }
        guard.withdraw_context_review(review.id, "Reviewer withdrew exception", reviewer)
        store.close()
        store = Neo4jStore(*args)
        guard = RecallGuard(store)
        assert not guard.retrieve(RetrievalInput(query="Orion"), agent).allowed
        assert guard.inspect(reviewer).context_reviews[review.id].withdrawn_at is not None
    finally:
        with store.driver.session() as session:
            session.run(
                "MATCH (n:RGObject {namespace: $ns}) DETACH DELETE n", ns=namespace
            ).consume()
            session.run("MATCH (n:RGWorkspace {id: $ns}) DELETE n", ns=namespace).consume()
        store.close()
