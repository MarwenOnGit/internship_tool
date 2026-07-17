from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fenrir.enumeration.app_graph_enum import (
    AppInfo,
    CredentialInfo,
    FederatedCredentialInfo,
    GraphEnumResult,
    ServicePrincipalInfo,
    UserInfo,
)


@dataclass
class EdgeDescriptor:
    source_id: str
    source_type: str
    target_id: str
    target_type: str
    edge_type: str
    properties: dict[str, Any] = field(default_factory=dict)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_az_owns_edges(result: GraphEnumResult) -> list[EdgeDescriptor]:
    edges: list[EdgeDescriptor] = []
    for app in result.apps:
        for owner in app.owners:
            oid = owner.get("id") or owner.get("objectId")
            otype = owner.get("@odata.type", "User")
            if not oid:
                continue
            source_type = otype.split(".")[-1].title()
            edges.append(EdgeDescriptor(
                source_id=oid,
                source_type=source_type,
                target_id=app.id,
                target_type="Application",
                edge_type="AZOwns",
                properties={"collected_at": _now_iso()},
            ))
    for sp in result.service_principals:
        for owner in sp.owners:
            oid = owner.get("id") or owner.get("objectId")
            otype = owner.get("@odata.type", "User")
            if not oid:
                continue
            source_type = otype.split(".")[-1].title()
            edges.append(EdgeDescriptor(
                source_id=oid,
                source_type=source_type,
                target_id=sp.id,
                target_type="ServicePrincipal",
                edge_type="AZOwns",
                properties={"collected_at": _now_iso()},
            ))
    return edges


def build_az_has_app_role_edges(result: GraphEnumResult) -> list[EdgeDescriptor]:
    edges: list[EdgeDescriptor] = []
    for sp in result.service_principals:
        for assignment in sp.app_role_assignments:
            principal_id = assignment.get("principalId")
            resource_id = assignment.get("resourceId")
            app_role_id = assignment.get("appRoleId")
            if not principal_id or not resource_id:
                continue
            edges.append(EdgeDescriptor(
                source_id=principal_id,
                source_type="ServicePrincipal",
                target_id=resource_id,
                target_type="ServicePrincipal",
                edge_type="AZHasAppRole",
                properties={
                    "app_role_id": app_role_id or "",
                    "collected_at": _now_iso(),
                },
            ))
    return edges


def build_az_oauth2_permission_grant_edges(result: GraphEnumResult) -> list[EdgeDescriptor]:
    edges: list[EdgeDescriptor] = []
    for sp in result.service_principals:
        for grant in sp.oauth2_permission_grants:
            client_id = grant.get("clientId") or grant.get("client_id", "")
            resource_id = grant.get("resourceId") or grant.get("resource_id", "")
            scope = grant.get("scope", grant.get("consentType", ""))
            if not client_id or not resource_id:
                continue
            edges.append(EdgeDescriptor(
                source_id=client_id,
                source_type="ServicePrincipal",
                target_id=resource_id,
                target_type="ServicePrincipal",
                edge_type="AZOAuth2PermissionGrant",
                properties={
                    "scope": scope,
                    "consent_type": grant.get("consentType", ""),
                    "collected_at": _now_iso(),
                },
            ))
    return edges


def build_az_expired_credential_edges(result: GraphEnumResult) -> list[EdgeDescriptor]:
    edges: list[EdgeDescriptor] = []
    now = datetime.now(timezone.utc)

    for cred in result.credentials:
        for kc in cred.key_credentials:
            end_date = kc.get("endDateTime") or kc.get("end_date")
            key_id = kc.get("keyIdentifier", kc.get("keyId", ""))
            if end_date:
                try:
                    end = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
                    if end < now:
                        edges.append(EdgeDescriptor(
                            source_id=cred.object_id,
                            source_type="Application",
                            target_id=cred.object_id,
                            target_type="Application",
                            edge_type="AZExpiredCredential",
                            properties={
                                "key_id": key_id,
                                "end_date": end_date,
                                "credential_type": "key",
                                "collected_at": _now_iso(),
                            },
                        ))
                except ValueError:
                    pass

        for pc in cred.password_credentials:
            end_date = pc.get("endDateTime") or pc.get("end_date")
            key_id = pc.get("keyIdentifier", pc.get("keyId", ""))
            if end_date:
                try:
                    end = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
                    if end < now:
                        edges.append(EdgeDescriptor(
                            source_id=cred.object_id,
                            source_type="Application",
                            target_id=cred.object_id,
                            target_type="Application",
                            edge_type="AZExpiredCredential",
                            properties={
                                "key_id": key_id,
                                "end_date": end_date,
                                "credential_type": "password",
                                "collected_at": _now_iso(),
                            },
                        ))
                except ValueError:
                    pass

    return edges


def build_az_federated_credential_edges(result: GraphEnumResult) -> list[EdgeDescriptor]:
    edges: list[EdgeDescriptor] = []
    for fc in result.federated_credentials:
        edges.append(EdgeDescriptor(
            source_id=fc.app_id,
            source_type="Application",
            target_id=fc.app_id,
            target_type="Application",
            edge_type="AZFederatedCredential",
            properties={
                "credential_name": fc.credential_name,
                "issuer": fc.issuer,
                "subject": fc.subject,
                "audiences": ",".join(fc.audiences),
                "collected_at": _now_iso(),
            },
        ))
    return edges


def build_all_edges(result: GraphEnumResult) -> list[EdgeDescriptor]:
    edges: list[EdgeDescriptor] = []
    edges.extend(build_az_owns_edges(result))
    edges.extend(build_az_has_app_role_edges(result))
    edges.extend(build_az_oauth2_permission_grant_edges(result))
    edges.extend(build_az_expired_credential_edges(result))
    edges.extend(build_az_federated_credential_edges(result))
    return edges
