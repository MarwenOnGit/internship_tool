from __future__ import annotations

import logging
from typing import Any

from fenrir.bloodhound.client import BloodHoundClient, BloodHoundError, CypherResult
from fenrir.edges.edge_builder import EdgeDescriptor

log = logging.getLogger(__name__)


class Neo4jWriterError(Exception):
    pass


class Neo4jWriter:
    def __init__(self, bh_client: BloodHoundClient):
        self._bh = bh_client

    def write_edges(self, edges: list[EdgeDescriptor], batch_size: int = 50) -> dict[str, Any]:
        if not edges:
            return {"total": 0, "written": 0, "errors": []}

        written = 0
        errors: list[str] = []

        for i in range(0, len(edges), batch_size):
            batch = edges[i : i + batch_size]
            try:
                result = self._write_batch(batch)
                written += result["written"]
                errors.extend(result["errors"])
            except Neo4jWriterError as e:
                errors.append(str(e))
                log.error("Batch write failed at offset %d: %s", i, e)

        return {"total": len(edges), "written": written, "errors": errors}

    def _write_batch(self, edges: list[EdgeDescriptor]) -> dict[str, Any]:
        if not edges:
            return {"written": 0, "errors": []}

        written = 0
        errors: list[str] = []

        for edge in edges:
            try:
                self._write_single(edge)
                written += 1
            except Neo4jWriterError as e:
                errors.append(f"{edge.edge_type} {edge.source_id}->{edge.target_id}: {e}")

        return {"written": written, "errors": errors}

    def _write_single(self, edge: EdgeDescriptor) -> None:
        cypher = self._build_merge_cypher(edge)
        result = self._bh.query_cypher(cypher, edge.properties)
        if not result.success:
            raise Neo4jWriterError(f"Cypher query failed: {result.error}")

    def _build_merge_cypher(self, edge: EdgeDescriptor) -> str:
        src_type = edge.source_type or "Base"
        tgt_type = edge.target_type or "Base"
        edge_type = edge.edge_type.upper().replace("-", "_").replace(" ", "_")
        escaped_edge = f"`{edge_type}`"

        cypher = (
            f"MATCH (src:{src_type} {{objectid: $source_id}})\n"
            f"MATCH (tgt:{tgt_type} {{objectid: $target_id}})\n"
            f"MERGE (src)-[r:{escaped_edge}]->(tgt)\n"
            f"SET r.collected_at = $collected_at\n"
        )

        extra_props = [k for k in edge.properties if k not in ("source_id", "target_id", "collected_at")]
        for prop in extra_props:
            safe = prop.replace(" ", "_").replace("-", "_")
            cypher += f"SET r.{safe} = ${safe}\n"

        return cypher

    def ensure_edge_type(self, edge_type: str) -> bool:
        cypher = (
            f"CALL db.createRelationshipType('{edge_type}')\n"
            f"RETURN true"
        )
        try:
            result = self._bh.query_cypher(cypher)
            if not result.success:
                log.warning("ensure_edge_type %s: %s", edge_type, result.error)
            return result.success
        except Exception as e:
            log.warning("Failed to register edge type %s: %s", edge_type, e)
            return False
