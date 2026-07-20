from unittest.mock import Mock

from fenrir.bloodhound.client import CypherResult
from fenrir.edges.edge_builder import EdgeDescriptor
from fenrir.edges.neo4j_writer import Neo4jWriter


def _make_writer(bh_client=None):
    if bh_client is None:
        bh_client = Mock()
        bh_client.query_cypher.return_value = CypherResult(success=True, data=[])
    return Neo4jWriter(bh_client)


def test_write_edges_empty():
    writer = _make_writer()
    result = writer.write_edges([])
    assert result["total"] == 0
    assert result["written"] == 0


def test_write_edges_single():
    bh = Mock()
    bh.query_cypher.return_value = CypherResult(success=True, data=[])
    writer = _make_writer(bh)

    edges = [EdgeDescriptor(
        source_id="user-1", source_type="User",
        target_id="app-1", target_type="Application",
        edge_type="AZOwns",
        properties={"collected_at": "2025-01-01T00:00:00Z"},
    )]
    result = writer.write_edges(edges)

    assert result["total"] == 1
    assert result["written"] == 1
    assert bh.query_cypher.call_count == 1


def test_write_edges_batch():
    bh = Mock()
    bh.query_cypher.return_value = CypherResult(success=True, data=[])
    writer = _make_writer(bh)

    edges = [
        EdgeDescriptor(
            source_id=f"user-{i}", source_type="User",
            target_id="app-1", target_type="Application",
            edge_type="AZOwns",
            properties={"collected_at": "2025-01-01T00:00:00Z"},
        )
        for i in range(5)
    ]
    result = writer.write_edges(edges, batch_size=2)

    assert result["total"] == 5
    assert result["written"] == 5
    assert bh.query_cypher.call_count == 5


def test_write_edges_error():
    bh = Mock()
    bh.query_cypher.return_value = CypherResult(success=False, error="Connection refused")
    writer = _make_writer(bh)

    edges = [EdgeDescriptor(
        source_id="user-1", source_type="User",
        target_id="app-1", target_type="Application",
        edge_type="AZOwns",
        properties={"collected_at": "2025-01-01T00:00:00Z"},
    )]
    result = writer.write_edges(edges)

    assert result["total"] == 1
    assert result["written"] == 0
    assert len(result["errors"]) == 1
    assert "Connection refused" in result["errors"][0]


def test_build_merge_cypher():
    bh = Mock()
    writer = _make_writer(bh)

    edge = EdgeDescriptor(
        source_id="user-1", source_type="User",
        target_id="app-1", target_type="Application",
        edge_type="AZOwns",
        properties={
            "source_id": "user-1",
            "target_id": "app-1",
            "collected_at": "2025-01-01T00:00:00Z",
            "app_role_id": "role-1",
        },
    )
    cypher = writer._build_merge_cypher(edge)

    assert "MATCH (src:User {objectid: $source_id})" in cypher
    assert "MATCH (tgt:Application {objectid: $target_id})" in cypher
    assert "MERGE (src)-[r:`AZOWNS`]->(tgt)" in cypher
    assert "SET r.collected_at = $collected_at" in cypher
    assert "SET r.app_role_id = $app_role_id" in cypher


def test_ensure_edge_type():
    bh = Mock()
    bh.query_cypher.return_value = CypherResult(success=True, data=[])
    writer = _make_writer(bh)

    result = writer.ensure_edge_type("AZOwns")
    assert result is True
    assert bh.query_cypher.call_count == 1
