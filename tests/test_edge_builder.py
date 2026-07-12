from dataclasses import replace

from azauth.edges.edge_builder import (
    build_all_edges,
    build_az_expired_credential_edges,
    build_az_federated_credential_edges,
    build_az_has_app_role_edges,
    build_az_oauth2_permission_grant_edges,
    build_az_owns_edges,
)
from azauth.enumeration.app_graph_enum import (
    AppInfo,
    CredentialInfo,
    FederatedCredentialInfo,
    GraphEnumResult,
    ServicePrincipalInfo,
)


def _make_graph_result(**overrides) -> GraphEnumResult:
    defaults = GraphEnumResult()
    return replace(defaults, **overrides)


def test_build_az_owns_app_to_user():
    result = _make_graph_result(apps=[
        AppInfo(
            id="app-1", app_id="00000000-0000-0000-0000-000000000001",
            display_name="Test App",
            owners=[{"id": "user-1", "@odata.type": "#microsoft.graph.user"}],
        ),
    ])
    edges = build_az_owns_edges(result)
    assert len(edges) == 1
    e = edges[0]
    assert e.source_id == "user-1"
    assert e.source_type == "User"
    assert e.target_id == "app-1"
    assert e.target_type == "Application"
    assert e.edge_type == "AZOwns"
    assert "collected_at" in e.properties


def test_build_az_owns_sp_to_user():
    result = _make_graph_result(service_principals=[
        ServicePrincipalInfo(
            id="sp-1", app_id="00000000-0000-0000-0000-000000000002",
            display_name="Test SP",
            owners=[{"id": "user-1", "@odata.type": "#microsoft.graph.user"}],
        ),
    ])
    edges = build_az_owns_edges(result)
    assert len(edges) == 1
    assert edges[0].source_id == "user-1"
    assert edges[0].target_id == "sp-1"
    assert edges[0].target_type == "ServicePrincipal"


def test_build_az_owns_skips_owner_without_id():
    result = _make_graph_result(apps=[
        AppInfo(
            id="app-1", app_id="00000000-0000-0000-0000-000000000001",
            display_name="No-ID Owner",
            owners=[{"@odata.type": "#microsoft.graph.servicePrincipal"}],
        ),
    ])
    edges = build_az_owns_edges(result)
    assert len(edges) == 0


def test_build_az_has_app_role_edges():
    result = _make_graph_result(service_principals=[
        ServicePrincipalInfo(
            id="sp-1", app_id="00000000-0000-0000-0000-000000000001",
            display_name="Source SP",
            app_role_assignments=[{
                "principalId": "sp-1",
                "resourceId": "sp-2",
                "appRoleId": "role-1",
            }],
        ),
    ])
    edges = build_az_has_app_role_edges(result)
    assert len(edges) == 1
    e = edges[0]
    assert e.source_id == "sp-1"
    assert e.target_id == "sp-2"
    assert e.edge_type == "AZHasAppRole"
    assert e.properties["app_role_id"] == "role-1"


def test_build_az_has_app_role_skips_missing_principal():
    result = _make_graph_result(service_principals=[
        ServicePrincipalInfo(
            id="sp-1", app_id="00000000-0000-0000-0000-000000000001",
            display_name="No principal",
            app_role_assignments=[{
                "resourceId": "sp-2",
                "appRoleId": "role-1",
            }],
        ),
    ])
    assert len(build_az_has_app_role_edges(result)) == 0


def test_build_az_oauth2_permission_grant_edges():
    result = _make_graph_result(service_principals=[
        ServicePrincipalInfo(
            id="sp-1", app_id="00000000-0000-0000-0000-000000000001",
            display_name="Client SP",
            oauth2_permission_grants=[{
                "clientId": "sp-1",
                "resourceId": "sp-2",
                "scope": "User.Read",
                "consentType": "AllPrincipals",
            }],
        ),
    ])
    edges = build_az_oauth2_permission_grant_edges(result)
    assert len(edges) == 1
    e = edges[0]
    assert e.source_id == "sp-1"
    assert e.target_id == "sp-2"
    assert e.edge_type == "AZOAuth2PermissionGrant"
    assert e.properties["scope"] == "User.Read"
    assert e.properties["consent_type"] == "AllPrincipals"


def test_build_az_expired_credential_edges_key():
    result = _make_graph_result(credentials=[
        CredentialInfo(
            object_id="app-1", display_name="Expired App",
            key_credentials=[{
                "keyIdentifier": "key-1",
                "endDateTime": "2020-01-01T00:00:00Z",
                "type": "AsymmetricX509Cert",
            }],
        ),
    ])
    edges = build_az_expired_credential_edges(result)
    assert len(edges) == 1
    e = edges[0]
    assert e.source_id == "app-1"
    assert e.target_id == "app-1"
    assert e.edge_type == "AZExpiredCredential"
    assert e.properties["credential_type"] == "key"
    assert e.properties["key_id"] == "key-1"


def test_build_az_expired_credential_edges_password():
    result = _make_graph_result(credentials=[
        CredentialInfo(
            object_id="app-1", display_name="Expired App",
            password_credentials=[{
                "keyIdentifier": "pw-1",
                "endDateTime": "2020-06-15T00:00:00Z",
            }],
        ),
    ])
    edges = build_az_expired_credential_edges(result)
    assert len(edges) == 1
    assert edges[0].properties["credential_type"] == "password"
    assert edges[0].properties["key_id"] == "pw-1"


def test_build_az_expired_credential_skips_future():
    result = _make_graph_result(credentials=[
        CredentialInfo(
            object_id="app-1", display_name="Valid App",
            key_credentials=[{
                "keyIdentifier": "key-1",
                "endDateTime": "2099-01-01T00:00:00Z",
            }],
        ),
    ])
    assert len(build_az_expired_credential_edges(result)) == 0


def test_build_az_federated_credential_edges():
    result = _make_graph_result(federated_credentials=[
        FederatedCredentialInfo(
            app_id="00000000-0000-0000-0000-000000000001",
            app_display_name="Fed App",
            credential_name="my-fc",
            issuer="https://token.actions.githubusercontent.com",
            subject="repo:org/repo:branch:main",
            audiences=["api://AzureADTokenExchange"],
        ),
    ])
    edges = build_az_federated_credential_edges(result)
    assert len(edges) == 1
    e = edges[0]
    assert e.source_id == "00000000-0000-0000-0000-000000000001"
    assert e.edge_type == "AZFederatedCredential"
    assert e.properties["issuer"] == "https://token.actions.githubusercontent.com"
    assert e.properties["subject"] == "repo:org/repo:branch:main"


def test_build_all_edges_aggregates():
    result = _make_graph_result(
        apps=[
            AppInfo(
                id="app-1", app_id="00000000-0000-0000-0000-000000000001",
                display_name="App",
                owners=[{"id": "user-1", "@odata.type": "#microsoft.graph.user"}],
            ),
        ],
        service_principals=[
            ServicePrincipalInfo(
                id="sp-1", app_id="00000000-0000-0000-0000-000000000002",
                display_name="SP",
                app_role_assignments=[{
                    "principalId": "sp-1",
                    "resourceId": "sp-2",
                    "appRoleId": "role-1",
                }],
                oauth2_permission_grants=[{
                    "clientId": "sp-1",
                    "resourceId": "sp-2",
                    "scope": "User.Read",
                    "consentType": "AllPrincipals",
                }],
            ),
        ],
        credentials=[
            CredentialInfo(
                object_id="app-1", display_name="App",
                key_credentials=[{
                    "keyIdentifier": "key-1",
                    "endDateTime": "2020-01-01T00:00:00Z",
                }],
            ),
        ],
        federated_credentials=[
            FederatedCredentialInfo(
                app_id="00000000-0000-0000-0000-000000000003",
                app_display_name="Fed App",
                credential_name="fc-1",
                issuer="https://token.actions.githubusercontent.com",
                subject="repo:org/repo",
                audiences=["api://AzureADTokenExchange"],
            ),
        ],
    )
    edges = build_all_edges(result)
    assert len(edges) == 5
    edge_types = {e.edge_type for e in edges}
    assert "AZOwns" in edge_types
    assert "AZHasAppRole" in edge_types
    assert "AZOAuth2PermissionGrant" in edge_types
    assert "AZExpiredCredential" in edge_types
    assert "AZFederatedCredential" in edge_types
