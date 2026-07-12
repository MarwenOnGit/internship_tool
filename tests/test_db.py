from unittest.mock import Mock, patch

import pytest

from azauth.db.client import Neo4jConnection
from azauth.db.schema import ensure_schema
from azauth.exploit.arm_enum import (
    ResourceInRG,
    ServicePrincipalInfo,
    Subscription,
    UserAssignedIdentity,
    VirtualMachine,
)


@pytest.fixture
def mock_driver():
    with patch("azauth.db.client.GraphDatabase.driver") as md:
        driver = Mock()
        md.return_value = driver
        session = Mock()
        session.__enter__ = Mock(return_value=session)
        session.__exit__ = Mock(return_value=None)
        record = Mock()
        record.data.return_value = {}
        result = [record]
        session.run.return_value = result
        tx = Mock()
        tx.run.return_value = result
        session.execute_write = Mock(side_effect=lambda fn: fn(tx))
        driver.session.return_value = session
        driver.verify_connectivity = Mock()
        yield md


def test_connection(mock_driver):
    conn = Neo4jConnection("bolt://localhost:7687", "neo4j", "pass")
    conn.connect()
    assert conn._driver is not None
    conn.close()


def test_connection_context_manager(mock_driver):
    with Neo4jConnection("bolt://localhost:7687", "neo4j", "pass") as conn:
        assert conn._driver is not None


def test_run(mock_driver):
    conn = Neo4jConnection("bolt://localhost:7687", "neo4j", "pass")
    conn.connect()
    result = conn.run("MATCH (n) RETURN n LIMIT 1")
    assert isinstance(result, list)


def test_run_in_tx(mock_driver):
    conn = Neo4jConnection("bolt://localhost:7687", "neo4j", "pass")
    conn.connect()
    conn.run_in_tx("CREATE (n:Test {id: $id})", {"id": "test-1"})


def test_ensure_schema(mock_driver):
    conn = Neo4jConnection("bolt://localhost:7687", "neo4j", "pass")
    conn.connect()
    ensure_schema(conn)


def test_ingest_exploit_result(mock_driver):
    from azauth.db.ingest import ingest_exploit_result

    sub = Subscription(
        id="/subscriptions/sub-1", subscription_id="sub-1",
        display_name="Test Sub", state="Enabled",
    )

    result = Mock()
    result.subscriptions = [sub]
    result.interesting_groups = [
        {
            "subscription": "Test Sub",
            "resource_group": "rg-1",
            "roles": ["Owner"],
            "all_resources": [
                ResourceInRG(
                    id="/sub/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
                    name="vm-1", type="Microsoft.Compute/virtualMachines",
                    user_can_read=True, user_can_write=True,
                    effective_actions=["Microsoft.Compute/virtualMachines/read"],
                ),
            ],
            "virtual_machines": [
                VirtualMachine(
                    id="/sub/rg/vm-1", name="vm-1", resource_group="rg-1",
                    subscription_id="sub-1", location="eastus", os_type="Linux",
                    has_system_assigned_identity=True,
                ),
            ],
            "managed_identities": [
                UserAssignedIdentity(
                    id="/sub/rg/mi-1", name="mi-1", resource_group="rg-1",
                    subscription_id="sub-1", principal_id="p-1",
                    client_id="c-1", tenant_id="t-1",
                ),
            ],
            "service_principals": [
                ServicePrincipalInfo(
                    principal_id="sp-1", display_name="SP1", app_id="app-1",
                    roles=["Owner"],
                ),
            ],
        },
    ]

    conn = Neo4jConnection("bolt://localhost:7687", "neo4j", "pass")
    conn.connect()
    counts = ingest_exploit_result(conn, result, tenant_id="test-tenant")

    assert counts["subscriptions"] == 1
    assert counts["groups"] == 1
    assert counts["resources"] == 1
    assert counts["vms"] == 1
    assert counts["mis"] == 1
    assert counts["sps"] == 1


def test_ingest_azurehound(mock_driver):
    from azauth.db.ingest import ingest_azurehound
    import json
    import tempfile
    from pathlib import Path

    ah_data = {
        "data": [
            {
                "type": "node",
                "label": "AZUser",
                "props": {"objectid": "user-1", "displayname": "Test User"},
            },
            {
                "type": "edge",
                "label": "AZOwns",
                "props": {"source_id": "user-1", "target_id": "app-1"},
            },
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(ah_data, f)
        fpath = f.name

    try:
        conn = Neo4jConnection("bolt://localhost:7687", "neo4j", "pass")
        conn.connect()
        counts = ingest_azurehound(conn, fpath, tenant_id="test-tenant")
        assert counts["nodes"] == 1
        assert counts["edges"] == 1
    finally:
        Path(fpath).unlink(missing_ok=True)


def test_ingest_azurehound_file_not_found(mock_driver):
    from azauth.db.ingest import ingest_azurehound
    conn = Neo4jConnection("bolt://localhost:7687", "neo4j", "pass")
    conn.connect()
    result = ingest_azurehound(conn, "/nonexistent/file.json")
    assert "error" in result


def test_docker_status():
    from azauth.db.docker import get_container_status, is_container_running
    status = get_container_status()
    assert isinstance(status, str)


def test_connection_params():
    from azauth.db.docker import get_connection_params
    params = get_connection_params()
    assert "uri" in params
    assert "user" in params
    assert "password" in params
