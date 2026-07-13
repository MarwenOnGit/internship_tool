from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from azauth.db.client import Neo4jConnection
from azauth.exploit.arm_enum import (
    ResourceInRG,
    ServicePrincipalInfo,
    Subscription,
    UserAssignedIdentity,
    VirtualMachine,
)

log = logging.getLogger(__name__)


def _sanitize(val: Any) -> Any:
    if val is None:
        return None
    if isinstance(val, dict):
        return json.dumps(val)
    if isinstance(val, list):
        return json.dumps(val)
    return val


def ingest_exploit_result(
    conn: Neo4jConnection,
    result: Any,
    tenant_id: str = "default",
) -> dict[str, int]:
    counts: dict[str, int] = {"subscriptions": 0, "groups": 0, "resources": 0, "vms": 0, "mis": 0, "sps": 0}

    for sub in result.subscriptions:
        conn.run_in_tx(
            """
            MERGE (s:Subscription {id: $id})
            SET s.subscription_id = $subscription_id,
                s.display_name = $display_name,
                s.state = $state,
                s.tenant_id = $tenant_id
            """,
            {
                "id": sub.id,
                "subscription_id": sub.subscription_id,
                "display_name": sub.display_name,
                "state": sub.state,
                "tenant_id": tenant_id,
            },
        )
        counts["subscriptions"] += 1

    for group in result.interesting_groups:
        sub_name = group["subscription"]
        sub_id = _find_sub_id(result.subscriptions, sub_name)
        rg_name = group["resource_group"]
        roles = group["roles"]
        rg_id = f"/subscriptions/{sub_id}/resourceGroups/{rg_name}"

        conn.run_in_tx(
            """
            MATCH (s:Subscription {subscription_id: $sub_id, tenant_id: $tenant_id})
            MERGE (rg:ResourceGroup {id: $id})
            SET rg.name = $name,
                rg.tenant_id = $tenant_id,
                rg.roles = $roles,
                rg.subscription_id = $sub_id
            MERGE (rg)-[:IN_SUBSCRIPTION]->(s)
            """,
            {
                "id": rg_id,
                "name": rg_name,
                "sub_id": sub_id,
                "roles": _sanitize(list(roles)),
                "tenant_id": tenant_id,
            },
        )
        counts["groups"] += 1

        for r in group.get("all_resources", []):
            _ingest_resource(conn, r, rg_name, sub_id, tenant_id)
            counts["resources"] += 1

        for vm in group.get("virtual_machines", []):
            _ingest_vm(conn, vm, rg_name, sub_id, tenant_id)
            counts["vms"] += 1

        for mi in group.get("managed_identities", []):
            _ingest_mi(conn, mi, rg_name, sub_id, tenant_id)
            counts["mis"] += 1

        for sp in group.get("service_principals", []):
            _ingest_sp(conn, sp, rg_name, sub_id, tenant_id)
            counts["sps"] += 1

    return counts


def _find_sub_id(subs: list[Subscription], display_name: str) -> str:
    for s in subs:
        if s.display_name == display_name:
            return s.subscription_id
    return "unknown"


def _ingest_resource(
    conn: Neo4jConnection,
    r: ResourceInRG,
    rg_name: str,
    sub_id: str,
    tenant_id: str,
) -> None:
    conn.run_in_tx(
        """
        MATCH (rg:ResourceGroup {name: $rg_name, subscription_id: $sub_id, tenant_id: $tenant_id})
        MERGE (res:Resource {id: $id})
        SET res.name = $name,
            res.resource_type = $type,
            res.location = $location,
            res.can_read = $can_read,
            res.can_write = $can_write,
            res.can_act = $can_act,
            res.effective_actions = $actions,
            res.tenant_id = $tenant_id,
            res.subscription_id = $sub_id,
            res.resource_group = $rg_name
        MERGE (res)-[:IN_RESOURCE_GROUP]->(rg)
        """,
        {
            "id": r.id,
            "name": r.name,
            "type": r.type,
            "location": r.location,
            "can_read": r.user_can_read,
            "can_write": r.user_can_write,
            "can_act": r.user_can_act,
            "actions": _sanitize(r.effective_actions),
            "tenant_id": tenant_id,
            "sub_id": sub_id,
            "rg_name": rg_name,
        },
    )


def _ingest_vm(
    conn: Neo4jConnection,
    vm: VirtualMachine,
    rg_name: str,
    sub_id: str,
    tenant_id: str,
) -> None:
    conn.run_in_tx(
        """
        MATCH (rg:ResourceGroup {name: $rg_name, subscription_id: $sub_id, tenant_id: $tenant_id})
        MERGE (v:VirtualMachine {id: $id})
        SET v.name = $name,
            v.os_type = $os_type,
            v.has_system_assigned_identity = $has_si,
            v.tenant_id = $tenant_id,
            v.subscription_id = $sub_id,
            v.resource_group = $rg_name
        MERGE (v)-[:IN_RESOURCE_GROUP]->(rg)
        """,
        {
            "id": vm.id,
            "name": vm.name,
            "os_type": vm.os_type,
            "has_si": vm.has_system_assigned_identity,
            "tenant_id": tenant_id,
            "sub_id": sub_id,
            "rg_name": rg_name,
        },
    )


def _ingest_mi(
    conn: Neo4jConnection,
    mi: UserAssignedIdentity,
    rg_name: str,
    sub_id: str,
    tenant_id: str,
) -> None:
    conn.run_in_tx(
        """
        MATCH (rg:ResourceGroup {name: $rg_name, subscription_id: $sub_id, tenant_id: $tenant_id})
        MERGE (m:UserAssignedIdentity {id: $id})
        SET m.name = $name,
            m.principal_id = $principal_id,
            m.client_id = $client_id,
            m.tenant_id = $tenant_id,
            m.subscription_id = $sub_id,
            m.resource_group = $rg_name
        MERGE (m)-[:IN_RESOURCE_GROUP]->(rg)
        """,
        {
            "id": mi.id,
            "name": mi.name,
            "principal_id": mi.principal_id,
            "client_id": mi.client_id,
            "tenant_id": tenant_id,
            "sub_id": sub_id,
            "rg_name": rg_name,
        },
    )


def _ingest_sp(
    conn: Neo4jConnection,
    sp: ServicePrincipalInfo,
    rg_name: str,
    sub_id: str,
    tenant_id: str,
) -> None:
    conn.run_in_tx(
        """
        MATCH (rg:ResourceGroup {name: $rg_name, subscription_id: $sub_id, tenant_id: $tenant_id})
        MERGE (sp:ServicePrincipal {principal_id: $pid})
        SET sp.display_name = $display_name,
            sp.app_id = $app_id,
            sp.roles = $roles,
            sp.tenant_id = $tenant_id,
            sp.subscription_id = $sub_id,
            sp.resource_group = $rg_name
        MERGE (sp)-[:HAS_ROLE_IN]->(rg)
        """,
        {
            "pid": sp.principal_id,
            "display_name": sp.display_name,
            "app_id": sp.app_id,
            "roles": _sanitize(sp.roles),
            "tenant_id": tenant_id,
            "sub_id": sub_id,
            "rg_name": rg_name,
        },
    )


def ingest_azurehound(
    conn: Neo4jConnection,
    filepath: str | Path,
    tenant_id: str = "default",
) -> dict[str, int | str]:
    filepath = Path(filepath)
    if not filepath.exists():
        log.error("AzureHound output not found: %s", filepath)
        return {"error": "file not found"}

    raw = filepath.read_text()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        log.error("Invalid JSON: %s", e)
        return {"error": str(e)}

    if isinstance(data, dict) and "data" in data:
        entries = data["data"]
    elif isinstance(data, list):
        entries = data
    else:
        entries = [data]

    counts = {"nodes": 0, "edges": 0, "skipped": 0}
    for entry in entries:
        if not isinstance(entry, dict):
            counts["skipped"] += 1
            continue

        label = entry.get("label") or entry.get("type", "Base")
        props = {k: _sanitize(v) for k, v in entry.get("props", entry.get("properties", {})).items()}
        props["tenant_id"] = tenant_id

        if entry.get("type") == "node" or "objectid" in props:
            _ingest_ah_node(conn, label, props)
            counts["nodes"] += 1
        elif entry.get("type") == "edge" or ("source_id" in props and "target_id" in props):
            _ingest_ah_edge(conn, label, props)
            counts["edges"] += 1
        else:
            counts["skipped"] += 1

    return counts


def _ingest_ah_node(conn: Neo4jConnection, label: str, props: dict[str, Any]) -> None:
    oid = props.get("objectid") or props.get("id", "unknown")
    safe_label = label.replace("-", "_").replace(" ", "_").replace("`", "_")
    set_clause = ", ".join(f"n.{k} = ${k}" for k in props if k != "objectid")
    conn.run_in_tx(
        f"MERGE (n:`{safe_label}` {{objectid: $oid}}) SET {set_clause}",
        {"oid": oid, **props},
    )


def _ingest_ah_edge(conn: Neo4jConnection, label: str, props: dict[str, Any]) -> None:
    src = props.get("source_id") or props.get("source", "unknown")
    tgt = props.get("target_id") or props.get("target", "unknown")
    edge_label = label.replace("-", "_").replace(" ", "_").upper()
    conn.run_in_tx(
        f"""
        MATCH (s {{objectid: $src}})
        MATCH (t {{objectid: $tgt}})
        MERGE (s)-[r:`{edge_label}`]->(t)
        SET r.tenant_id = $tenant_id
        """,
        {"src": src, "tgt": tgt, "tenant_id": props.get("tenant_id", "default")},
    )
