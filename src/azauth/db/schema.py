from __future__ import annotations

import logging

from azauth.db.client import Neo4jConnection

log = logging.getLogger(__name__)

CREATE_INDEXES = [
    # --- MERGE-key indexes (idempotent upsert perf) ---
    "CREATE INDEX IF NOT EXISTS FOR (n:Subscription) ON (n.id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:ResourceGroup) ON (n.id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Resource) ON (n.id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:VirtualMachine) ON (n.id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:UserAssignedIdentity) ON (n.id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:ServicePrincipal) ON (n.principal_id)",
    # --- Cross-entity query indexes ---
    "CREATE INDEX IF NOT EXISTS FOR (n:Subscription) ON (n.subscription_id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Resource) ON (n.resource_type)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Resource) ON (n.subscription_id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Resource) ON (n.resource_group)",
    "CREATE INDEX IF NOT EXISTS FOR (n:ResourceGroup) ON (n.name)",
    "CREATE INDEX IF NOT EXISTS FOR (n:VirtualMachine) ON (n.name)",
    "CREATE INDEX IF NOT EXISTS FOR (n:UserAssignedIdentity) ON (n.principal_id)",
    # --- Tenant / multi-sub query support ---
    "CREATE INDEX IF NOT EXISTS FOR (n:ResourceGroup) ON (n.tenant_id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:VirtualMachine) ON (n.tenant_id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:ServicePrincipal) ON (n.tenant_id)",
]


def ensure_schema(conn: Neo4jConnection) -> None:
    for cypher in CREATE_INDEXES:
        try:
            conn.run_in_tx(cypher)
            log.debug("Index created: %s", cypher.split("ON")[1].strip())
        except Exception as e:
            log.warning("Failed to create index: %s", e)
