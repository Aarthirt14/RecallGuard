from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from recallguard.api import Settings, create_app
from recallguard.models import now
from recallguard.store import InMemoryStore

AGENT = {"X-API-Key": "a" * 32}
REVIEWER = {"X-API-Key": "r" * 32}


@pytest.fixture
def client():
    settings = Settings(agent_key="a" * 32, reviewer_key="r" * 32, backend="memory")
    with TestClient(create_app(settings, InMemoryStore())) as client:
        yield client


def test_observe_review_execute_api_and_forged_arguments(client):
    for path, payload in [
        ("/sources", {"id": "web", "kind": "web", "locator": "fixture:web"}),
        ("/procurement/suppliers", {"id": "ABC", "name": "ABC Supplies"}),
        ("/procurement/invoices", {"id": "INV-1", "supplier_id": "ABC", "amount_minor": 8_000_000}),
    ]:
        assert client.post(path, json=payload).status_code == 401
        assert client.post(path, headers=AGENT, json=payload).status_code == 403
        assert client.post(path, headers=REVIEWER, json=payload).status_code == 201
    observed = client.post(
        "/agent/observe",
        headers=AGENT,
        json={
            "session_id": "one",
            "source_id": "web",
            "content": "ABC bank account is 991872",
            "claim": {"entity": "supplier:ABC", "attribute": "bank_account", "value": "991872"},
        },
    )
    assert observed.status_code == 200
    plan = {"session_id": "two", "invoice_id": "INV-1"}
    assert (
        client.post("/agent/plan-payment", headers=AGENT, json=plan).json()["status"] == "blocked"
    )
    expires = (now() + timedelta(minutes=5)).isoformat()
    assert (
        client.post(
            "/sources",
            headers=REVIEWER,
            json={
                "id": "callback",
                "kind": "user",
                "locator": "fixture:independent-callback",
            },
        ).status_code
        == 201
    )
    memory_id = observed.json()["memory_ids"][-1]
    options = client.get("/review", headers=REVIEWER).json()["claim_verification_options"][
        memory_id
    ]
    fingerprint = next(
        s["fingerprint"] for s in options["evidence_sources"] if s["id"] == "callback"
    )
    assert (
        client.post(
            "/claim-verifications",
            headers=REVIEWER,
            json={
                "memory_id": memory_id,
                "evidence_source_id": "callback",
                "expected_fingerprint": fingerprint,
                "evidence_reference": "fixture:callback-record",
                "method": "callback",
                "independently_checked": True,
                "reason": "Independently confirmed account",
                "expires_at": expires,
            },
        ).status_code
        == 201
    )
    assert (
        client.post(
            "/grants",
            headers=REVIEWER,
            json={
                "memory_id": observed.json()["memory_ids"][-1],
                "action": "payment",
                "target": "supplier:ABC",
                "expires_at": expires,
                "reason": "Account verified independently",
            },
        ).status_code
        == 201
    )
    result = client.post("/agent/plan-payment", headers=AGENT, json=plan).json()
    assert result["status"] == "pending_review"
    path = f"/procurement/payments/{result['proposal_id']}"
    proposal = client.get(path, headers=REVIEWER).json()
    approval = {
        "expected_fingerprint": proposal["fingerprint"],
        "expires_at": expires,
        "reason": "Exact invoice and account approved",
    }
    assert client.post(path + "/approve", headers=AGENT, json=approval).status_code == 403
    assert (
        client.post(path + "/execute", headers=AGENT, json={"session_id": "three"}).json()["status"]
        == "blocked"
    )
    assert client.post(path + "/approve", headers=REVIEWER, json=approval).status_code == 200
    assert (
        client.post(
            path + "/execute",
            headers=AGENT,
            json={
                "session_id": "three",
                "amount_minor": 1,
                "bank_account": "555555",
                "action": "inform",
            },
        ).status_code
        == 422
    )
    assert (
        client.post(path + "/execute", headers=AGENT, json={"session_id": "three"}).json()["status"]
        == "executed"
    )
    assert (
        client.post(path + "/execute", headers=AGENT, json={"session_id": "four"}).json()["status"]
        == "already_executed"
    )
    receipts = client.get("/procurement/receipts", headers=REVIEWER).json()
    assert len(receipts) == 1
    assert receipts[0]["simulated"] is True
    assert client.get("/agent/runs", headers=AGENT).status_code == 403
    assert client.get("/procurement/receipts", headers=AGENT).status_code == 403
    assert len(client.get("/agent/runs", headers=REVIEWER).json()) == 6


@pytest.mark.parametrize("route", ["/agent/observe", "/agent/plan-payment"])
def test_agent_routes_require_credentials(client, route):
    assert client.post(route, json={}).status_code == 401


def test_plan_cannot_supply_approval_state(client):
    response = client.post(
        "/agent/plan-payment",
        headers=AGENT,
        json={
            "session_id": "fake",
            "invoice_id": "INV-1",
            "approved": True,
        },
    )
    assert response.status_code == 422


def test_verification_endpoint_rejects_agent_and_forged_fingerprint(client):
    client.post(
        "/sources", headers=REVIEWER, json={"id": "web", "kind": "web", "locator": "fixture:web"}
    )
    client.post(
        "/sources",
        headers=REVIEWER,
        json={"id": "record", "kind": "user", "locator": "fixture:record"},
    )
    memory = client.post(
        "/memories",
        headers=AGENT,
        json={
            "source_id": "web",
            "content": "Orion account OR1234",
            "claim": {"entity": "Orion", "attribute": "account", "value": "OR1234"},
        },
    ).json()
    data = {
        "memory_id": memory["id"],
        "evidence_source_id": "record",
        "expected_fingerprint": "0" * 64,
        "evidence_reference": "fixture:callback",
        "method": "callback",
        "independently_checked": True,
        "reason": "Independent account verification",
        "expires_at": (now() + timedelta(hours=1)).isoformat(),
    }
    assert client.post("/claim-verifications", json=data).status_code == 401
    assert client.post("/claim-verifications", headers=AGENT, json=data).status_code == 403
    assert client.post("/claim-verifications", headers=REVIEWER, json=data).status_code == 409
    options = client.get("/review", headers=REVIEWER).json()["claim_verification_options"][
        memory["id"]
    ]
    data["expected_fingerprint"] = next(
        s["fingerprint"] for s in options["evidence_sources"] if s["id"] == "record"
    )
    approved = client.post("/claim-verifications", headers=REVIEWER, json=data)
    assert approved.status_code == 201
    assert approved.headers["cache-control"] == "no-store"
    path = f"/claim-verifications/{approved.json()['id']}/withdraw"
    assert (
        client.post(path, headers=AGENT, json={"reason": "Unauthorized withdrawal"}).status_code
        == 403
    )
    assert (
        client.post(
            path, headers=REVIEWER, json={"reason": "Reviewer withdrew evidence"}
        ).status_code
        == 200
    )
    assert client.post("/claim-verifications", headers=REVIEWER, json=data).status_code == 409
