from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import requests

from fenrir.core.authenticator import AzureAuthenticator

log = logging.getLogger(__name__)

GRAPH_API = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class GraphEnumError(Exception):
    pass


@dataclass
class AppInfo:
    id: str
    app_id: str
    display_name: str
    publisher_domain: str | None = None
    sign_in_audience: str | None = None
    created_date: str | None = None
    owners: list[dict] = field(default_factory=list)


@dataclass
class ServicePrincipalInfo:
    id: str
    app_id: str
    display_name: str
    tenant_id: str | None = None
    app_role_assignments: list[dict] = field(default_factory=list)
    oauth2_permission_grants: list[dict] = field(default_factory=list)
    owners: list[dict] = field(default_factory=list)


@dataclass
class CredentialInfo:
    object_id: str
    display_name: str
    key_credentials: list[dict] = field(default_factory=list)
    password_credentials: list[dict] = field(default_factory=list)


@dataclass
class FederatedCredentialInfo:
    app_id: str
    app_display_name: str
    credential_name: str
    issuer: str
    subject: str
    audiences: list[str]
    description: str | None = None


@dataclass
class UserInfo:
    id: str
    display_name: str
    user_principal_name: str | None = None
    on_premises_extension_attributes: dict | None = None


@dataclass
class GraphEnumResult:
    apps: list[AppInfo] = field(default_factory=list)
    service_principals: list[ServicePrincipalInfo] = field(default_factory=list)
    credentials: list[CredentialInfo] = field(default_factory=list)
    federated_credentials: list[FederatedCredentialInfo] = field(default_factory=list)
    users_with_attributes: list[UserInfo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _get_graph_token(auth: AzureAuthenticator) -> str:
    r = auth.get_token_for_scopes([GRAPH_SCOPE])
    if not r.success or not r.token:
        raise GraphEnumError(f"Graph token acquisition failed: {r.error}")
    return r.token["access_token"]


def _headers(auth: AzureAuthenticator) -> dict[str, str]:
    token = _get_graph_token(auth)
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _graph_get(auth: AzureAuthenticator, path: str, params: dict | None = None) -> list[dict]:
    headers = _headers(auth)
    results = []
    url = f"{GRAPH_API}{path}"
    while url:
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            params = None
            if resp.status_code == 403:
                log.warning("Access denied: %s", url)
                break
            if resp.status_code == 404:
                log.debug("Not found: %s", url)
                break
            resp.raise_for_status()
            data = resp.json()
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        except requests.RequestException as e:
            raise GraphEnumError(f"Graph GET {path}: {e}") from e
    return results


def _get_app_owners(auth: AzureAuthenticator, app_id: str) -> list[dict]:
    return _graph_get(auth, f"/applications/{app_id}/owners")


def _get_sp_owners(auth: AzureAuthenticator, sp_id: str) -> list[dict]:
    return _graph_get(auth, f"/servicePrincipals/{sp_id}/owners")


def enumerate_applications(auth: AzureAuthenticator) -> list[AppInfo]:
    apps_data = _graph_get(auth, "/applications")
    apps = []
    for a in apps_data:
        owners = _get_app_owners(auth, a["id"])
        apps.append(AppInfo(
            id=a["id"],
            app_id=a.get("appId", ""),
            display_name=a.get("displayName", "Unnamed"),
            publisher_domain=a.get("publisherDomain"),
            sign_in_audience=a.get("signInAudience"),
            created_date=a.get("createdDateTime"),
            owners=owners,
        ))
    return apps


def enumerate_service_principals(auth: AzureAuthenticator) -> list[ServicePrincipalInfo]:
    sps_data = _graph_get(auth, "/servicePrincipals")
    sps = []
    for sp in sps_data:
        sp_id = sp["id"]
        owners = _get_sp_owners(auth, sp_id)
        app_role_assignments = _graph_get(auth, f"/servicePrincipals/{sp_id}/appRoleAssignments")
        oauth2_grants = _graph_get(auth, f"/servicePrincipals/{sp_id}/oauth2PermissionGrants")
        sps.append(ServicePrincipalInfo(
            id=sp_id,
            app_id=sp.get("appId", ""),
            display_name=sp.get("displayName", sp.get("appDisplayName", "Unnamed")),
            tenant_id=sp.get("appOwnerOrganizationId"),
            app_role_assignments=app_role_assignments,
            oauth2_permission_grants=oauth2_grants,
            owners=owners,
        ))
    return sps


def enumerate_credential_metadata(auth: AzureAuthenticator) -> list[CredentialInfo]:
    apps_data = _graph_get(auth, "/applications")
    creds = []
    for a in apps_data:
        key_creds = a.get("keyCredentials", [])
        pass_creds = a.get("passwordCredentials", [])
        if key_creds or pass_creds:
            creds.append(CredentialInfo(
                object_id=a["id"],
                display_name=a.get("displayName", "Unnamed"),
                key_credentials=key_creds,
                password_credentials=pass_creds,
            ))
    return creds


def enumerate_federated_credentials(auth: AzureAuthenticator) -> list[FederatedCredentialInfo]:
    apps_data = _graph_get(auth, "/applications", {"$select": "id,appId,displayName,federatedIdentityCredentials"})
    results = []
    for a in apps_data:
        app_id = a.get("appId", "")
        app_display = a.get("displayName", "Unnamed")
        creds = a.get("federatedIdentityCredentials", [])
        if not creds:
            fed_data = _graph_get(auth, f"/applications/{a['id']}/federatedIdentityCredentials")
            creds = fed_data if fed_data else a.get("federatedIdentityCredentials", [])
        for fc in creds:
            results.append(FederatedCredentialInfo(
                app_id=app_id,
                app_display_name=app_display,
                credential_name=fc.get("name", "Unnamed"),
                issuer=fc.get("issuer", ""),
                subject=fc.get("subject", ""),
                audiences=fc.get("audiences", []),
                description=fc.get("description"),
            ))
    return results


def enumerate_users_with_attributes(auth: AzureAuthenticator) -> list[UserInfo]:
    users = _graph_get(
        auth,
        "/users",
        {"$select": "id,displayName,userPrincipalName,onPremisesExtensionAttributes", "$top": 999},
    )
    results = []
    for u in users:
        ext = u.get("onPremisesExtensionAttributes")
        if ext and any(ext.get(k) for k in ext):
            results.append(UserInfo(
                id=u["id"],
                display_name=u.get("displayName", "Unnamed"),
                user_principal_name=u.get("userPrincipalName"),
                on_premises_extension_attributes=ext,
            ))
    return results


def run_graph_enumeration(auth: AzureAuthenticator) -> GraphEnumResult:
    result = GraphEnumResult()
    try:
        result.apps = enumerate_applications(auth)
        log.info("Enumerated %d applications", len(result.apps))
    except GraphEnumError as e:
        result.errors.append(f"App enumeration: {e}")

    try:
        result.service_principals = enumerate_service_principals(auth)
        log.info("Enumerated %d service principals", len(result.service_principals))
    except GraphEnumError as e:
        result.errors.append(f"SP enumeration: {e}")

    try:
        result.credentials = enumerate_credential_metadata(auth)
        log.info("Enumerated credentials for %d objects", len(result.credentials))
    except GraphEnumError as e:
        result.errors.append(f"Credential enumeration: {e}")

    try:
        result.federated_credentials = enumerate_federated_credentials(auth)
        log.info("Enumerated %d federated credentials", len(result.federated_credentials))
    except GraphEnumError as e:
        result.errors.append(f"Federated cred enumeration: {e}")

    try:
        result.users_with_attributes = enumerate_users_with_attributes(auth)
        log.info("Enumerated %d users with extension attributes", len(result.users_with_attributes))
    except GraphEnumError as e:
        result.errors.append(f"User attribute enumeration: {e}")

    return result
