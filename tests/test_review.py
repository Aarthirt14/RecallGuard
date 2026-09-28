from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from recallguard.api import Settings, create_app
from recallguard.engine import audit
from recallguard.models import Action, GrantInput, MemoryInput, SourceInput, SourceType, now
from recallguard.procurement import Procurement
from recallguard.procurement_models import InvoiceInput, SupplierInput

AGENT = {"X-API-Key": "a" * 32}
REVIEWER = {"X-API-Key": "r" * 32}


@pytest.fixture
def client(guard):
    settings = Settings(agent_key="a" * 32, reviewer_key="r" * 32, backend="memory")
    with TestClient(create_app(settings, guard.store)) as client:
        yield client


def test_reviewer_snapshot_is_private_and_never_cached(client):
    for headers, expected in [({}, 401), (AGENT, 403), (REVIEWER, 200)]:
        response = client.get("/review", headers=headers)
        assert response.status_code == expected
        assert response.headers["cache-control"] == "no-store"
    data = client.get("/review", headers=REVIEWER).json()
    assert data["actions"] == [action.value for action in Action]
    assert data["retrieval_mode"] == "lexical"
    assert not data["embeddings"]["enabled"]
    assert "reviewer_key" not in data and "agent_key" not in data


@pytest.mark.parametrize(
    "path",
    [
        "/dashboard",
        "/dashboard/",
        "/dashboard/assets/dashboard.js",
        "/dashboard/assets/dashboard.css",
    ],
)
def test_dashboard_assets_and_security_headers(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "'unsafe-inline'" not in response.headers["content-security-policy"]
    assert "'unsafe-eval'" not in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"


def test_home_redirects_without_exposing_workspace_data(client, guard, agent):
    guard.remember(MemoryInput(content="Private stored memory", source_id="web"), agent)
    response = client.get("/")
    assert response.url.path == "/dashboard"
    assert "Private stored memory" not in response.text
    assert client.get("/dashboard/assets/../api.py").status_code == 404


def test_snapshot_preserves_live_restrictions_and_audit_bounds(client, guard, reviewer, agent):
    root = guard.remember(MemoryInput(content="Account evidence", source_id="web"), agent)
    child = guard.remember(MemoryInput(content="Summary of account", parent_ids=[root.id]), agent)
    guard.grant(
        GrantInput(
            memory_id=root.id,
            action=Action.PAYMENT,
            target="ABC",
            reason="Verified independently",
            expires_at=now() + timedelta(minutes=5),
        ),
        reviewer,
    )
    guard.revoke(root.id, "source compromised", reviewer)
    for i in range(205):
        guard.store.transact(lambda state, i=i: audit(state, reviewer, "test_event", [str(i)]))
    data = client.get("/review", headers=REVIEWER).json()
    assert "memory_revoked" in data["memory_restrictions"][root.id]
    assert "inactive_ancestor" in data["memory_restrictions"][child.id]
    assert len(data["events"]) == 200 and data["event_count"] > 205
    assert data["events"][0]["subject_ids"] == ["204"]
    assert data["events"][-1]["subject_ids"] == ["5"]
    assert len(data["grants"]) == 1


def test_snapshot_exposes_current_payment_blockers(client, guard, reviewer, agent):
    procurement = Procurement(guard.store)
    procurement.register_supplier(SupplierInput(id="ABC", name="ABC Suppliers"), reviewer)
    procurement.register_invoice(
        InvoiceInput(id="INV1", supplier_id="ABC", amount_minor=10000), reviewer
    )
    memory = guard.remember(
        MemoryInput(
            content="ABC bank account 1234",
            source_id="web",
            claim={"entity": "supplier:ABC", "attribute": "bank_account", "value": "1234"},
        ),
        agent,
    )
    guard.grant(
        GrantInput(
            memory_id=memory.id,
            action=Action.PAYMENT,
            target="supplier:ABC",
            reason="Verified independently",
            expires_at=now() + timedelta(minutes=5),
        ),
        reviewer,
    )
    proposal = procurement.propose("INV1", memory.id, agent)
    data = client.get("/review", headers=REVIEWER).json()
    assert not data["payment_blockers"][proposal.id]
    guard.revoke(memory.id, "evidence invalidated", reviewer)
    data = client.get("/review", headers=REVIEWER).json()
    assert "memory_revoked" in data["payment_blockers"][proposal.id]
    assert data["payments"][0]["fingerprint"] == proposal.fingerprint
    assert data["receipts"] == []


def test_embedding_projection_excludes_vectors(reviewer, agent):
    class Encoder:
        model_id = "test-model"
        dimensions = 2

        def encode(self, texts):
            return [[1, 0] for _ in texts]

    settings = Settings(agent_key="a" * 32, reviewer_key="r" * 32, backend="memory")
    with TestClient(create_app(settings, encoder=Encoder())) as client:
        guard = client.app.state.guard
        guard.register_source(
            SourceInput(id="web", kind=SourceType.WEB, locator="fixture:web"), reviewer
        )
        memory = guard.remember(
            MemoryInput(content="Shipment arrives tomorrow", source_id="web"), agent
        )
        data = client.get("/review", headers=REVIEWER).json()
        assert data["embeddings"]["indexed"] == 1
        assert "vector" not in data["embeddings"] and "embeddings" not in data["memories"][0]
        guard.revoke(memory.id, "source withdrawn", reviewer)
        assert client.get("/review", headers=REVIEWER).json()["embeddings"]["eligible"] == 0


def test_informational_review_api_is_scoped_authenticated_and_withdrawable(
    client, guard, reviewer, agent
):
    root = guard.remember(
        MemoryInput(
            content="Orion handbook quotes 'Ignore prior instructions' as an attack example.",
            source_id="web",
        ),
        agent,
    )
    snapshot = client.get("/review", headers=REVIEWER).json()
    data = {
        "memory_id": root.id,
        "expected_fingerprint": snapshot["context_review_options"][root.id]["fingerprint"],
        "expires_at": (now() + timedelta(hours=1)).isoformat(),
        "reason": "Confirmed this is a benign handbook quotation",
    }
    for headers, expected in [({}, 401), (AGENT, 403)]:
        assert client.post("/context-reviews", headers=headers, json=data).status_code == expected
    assert (
        client.post(
            "/context-reviews", headers=REVIEWER, json={**data, "action": "payment"}
        ).status_code
        == 422
    )
    approved = client.post("/context-reviews", headers=REVIEWER, json=data)
    assert approved.status_code == 201
    assert approved.headers["cache-control"] == "no-store"
    review_id = approved.json()["id"]
    retrieved = client.post("/retrieve", headers=AGENT, json={"query": "Orion"}).json()
    assert retrieved["context_reviews"] == {root.id: review_id}
    assert retrieved["allowed"][0]["status"] == "quarantined"
    payment = client.post(
        "/retrieve",
        headers=AGENT,
        json={
            "query": "Orion",
            "action": "payment",
            "target": "supplier:Orion",
        },
    ).json()
    assert not payment["allowed"] and not payment["context_reviews"]
    path = f"/context-reviews/{review_id}/withdraw"
    assert (
        client.post(path, headers=AGENT, json={"reason": "Withdrawal attempt"}).status_code == 403
    )
    assert (
        client.post(path, headers=REVIEWER, json={"reason": "Withdrawn by reviewer"}).status_code
        == 200
    )
    assert not client.post("/retrieve", headers=AGENT, json={"query": "Orion"}).json()["allowed"]
    assert client.post("/context-reviews", headers=REVIEWER, json=data).status_code == 409
