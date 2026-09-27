import pytest

from recallguard.engine import RecallGuard
from recallguard.models import Principal, Role, SourceInput, SourceType
from recallguard.store import InMemoryStore


@pytest.fixture
def reviewer():
    return Principal(id="reviewer", role=Role.REVIEWER)


@pytest.fixture
def agent():
    return Principal(id="agent", role=Role.AGENT)


@pytest.fixture
def guard(reviewer):
    service = RecallGuard(InMemoryStore())
    for kind in SourceType:
        service.register_source(
            SourceInput(id=kind.value, kind=kind, locator=f"fixture:{kind.value}"), reviewer
        )
    return service
