from __future__ import annotations

import logging
import os
from pathlib import Path

import typer

from fenrir.bloodhound.client import BloodHoundClient, BloodHoundConfig
from fenrir.collectors.azurehound_runner import (
    AzureHoundConfig,
    AzureHoundError,
    run_azurehound,
)
from fenrir.core.authenticator import AzureAuthenticator, Credentials
from fenrir.edges.edge_builder import build_all_edges
from fenrir.edges.neo4j_writer import Neo4jWriter
from fenrir.enumeration.app_graph_enum import run_graph_enumeration

log = logging.getLogger(__name__)

pipeline_app = typer.Typer(
    name="pipeline",
    help="Run the full Azure → BHCE → Custom Graph enumeration pipeline.",
    no_args_is_help=True,
)


@pipeline_app.callback(invoke_without_command=True)
def pipeline(
    ctx: typer.Context,
    skip_azurehound: bool = typer.Option(
        False, "--skip-azurehound", help="Skip AzureHound collection phase",
    ),
    skip_ingest: bool = typer.Option(
        False, "--skip-ingest", help="Skip BHCE ingest of AzureHound output",
    ),
    skip_graph_enum: bool = typer.Option(
        False, "--skip-graph-enum", help="Skip custom Graph enumeration phase",
    ),
    skip_write: bool = typer.Option(
        False, "--skip-write", help="Skip writing novel edges to Neo4j",
    ),
    azurehound_path: str = typer.Option(
        None, "--azurehound-path", envvar="AZUREHOUND_PATH",
        help="Path to AzureHound binary",
    ),
    fenrir_client_id: str = typer.Option(
        None, "--client-id", envvar="AZAUTH_CLIENT_ID",
        help="Azure AD app client ID for AzureHound (app-only mode)",
    ),
    fenrir_client_secret: str = typer.Option(
        None, "--client-secret", envvar="AZAUTH_CLIENT_SECRET",
        help="Azure AD app client secret (app-only mode)",
    ),
    tenant_id: str = typer.Option(
        None, "--tenant-id", envvar="AZAUTH_TENANT_ID",
        help="Tenant ID for app-only auth",
    ),
    output_dir: str = typer.Option(
        None, "--output-dir", envvar="AZUREHOUND_OUTPUT_DIR",
        help="Directory for AzureHound output",
    ),
    bhce_url: str = typer.Option(
        "http://localhost:8080", "--bhce-url", envvar="BHCE_URL",
        help="BloodHound CE base URL",
    ),
    bhce_secret_key: str = typer.Option(
        ..., "--bhce-secret-key", envvar="BHCE_SECRET_KEY",
        prompt=True, hide_input=True,
        help="BloodHound CE secret key",
    ),
):
    creds = Credentials()
    auth = AzureAuthenticator(creds)

    azh_config = AzureHoundConfig(
        binary=azurehound_path or "azurehound",
        client_id=fenrir_client_id,
        client_secret=fenrir_client_secret,
        tenant_id=tenant_id,
        output_dir=output_dir or str(Path.cwd()),
    )

    if fenrir_client_id and fenrir_client_secret:
        log.info("Using app-only auth for AzureHound")
    else:
        log.info("Acquiring delegated token for AzureHound")
        token_result = auth.get_token_for_scopes(["https://graph.microsoft.com/.default"])
        if not token_result.success or not token_result.token:
            typer.secho(f"Authentication failed: {token_result.error}", fg="red", err=True)
            raise typer.Exit(code=3)
        refresh_token = token_result.token.get("refresh_token")
        if refresh_token:
            azh_config.refresh_token = refresh_token
            log.info("Using refresh token for AzureHound")
        elif fenrir_client_id and fenrir_client_secret:
            pass
        else:
            typer.secho(
                "No refresh_token in auth result and no client-id/secret provided. "
                "AzureHound requires either a refresh token (delegated) or client credentials.",
                fg="red", err=True,
            )
            raise typer.Exit(code=3)

    bh_config = BloodHoundConfig(
        base_url=bhce_url,
        secret_key=bhce_secret_key,
    )
    bh_client = BloodHoundClient(bh_config)

    if not skip_azurehound:
        typer.secho("=== Phase 1: AzureHound Collection ===", fg="cyan", err=True)
        try:
            result = run_azurehound(azh_config)
            if not result.success:
                typer.secho(f"AzureHound failed: {result.error}", fg="red", err=True)
                raise typer.Exit(code=4)
            typer.secho(f"AzureHound output written to: {result.output_path}", fg="green", err=True)
        except AzureHoundError as e:
            typer.secho(str(e), fg="red", err=True)
            raise typer.Exit(code=4)
    else:
        result = None
        typer.secho("=== Phase 1: Skipped ===", fg="yellow", err=True)

    if not skip_ingest:
        typer.secho("=== Phase 2: BHCE Ingest ===", fg="cyan", err=True)
        try:
            bh_client.login()
        except Exception as e:
            typer.secho(f"BHCE login failed: {e}", fg="red", err=True)
            raise typer.Exit(code=5)

        if result and result.output_path:
            ingest_result = bh_client.ingest_file(str(result.output_path))
            if not ingest_result.success:
                typer.secho(f"Ingest failed: {ingest_result.error}", fg="red", err=True)
                raise typer.Exit(code=6)
            typer.secho(f"Ingest submitted (job={ingest_result.job_id})", fg="green", err=True)

            typer.secho("Polling ingest completion...", fg="cyan", err=True)
            poll = bh_client.poll_ingest(ingest_result.job_id)
            if not poll.success:
                typer.secho(f"Ingest did not complete: {poll.error}", fg="red", err=True)
                raise typer.Exit(code=6)
            typer.secho(f"Ingest complete (status={poll.status})", fg="green", err=True)
        else:
            typer.secho("No AzureHound output to ingest (was skip-azurehound set?)", fg="yellow", err=True)
    else:
        typer.secho("=== Phase 2: Skipped ===", fg="yellow", err=True)

    if not skip_graph_enum:
        typer.secho("=== Phase 3: Custom Graph Enumeration ===", fg="cyan", err=True)
        try:
            enum_result = run_graph_enumeration(auth)
            if enum_result.errors:
                for e in enum_result.errors:
                    typer.secho(f"  Warning: {e}", fg="yellow", err=True)
            typer.secho(
                f"Enumerated: {len(enum_result.apps)} apps, "
                f"{len(enum_result.service_principals)} SPs, "
                f"{len(enum_result.credentials)} credential sets, "
                f"{len(enum_result.federated_credentials)} federated creds, "
                f"{len(enum_result.users_with_attributes)} users with extension attrs",
                fg="green", err=True,
            )
        except Exception as e:
            typer.secho(f"Graph enumeration failed: {e}", fg="red", err=True)
            raise typer.Exit(code=7)
    else:
        enum_result = None
        typer.secho("=== Phase 3: Skipped ===", fg="yellow", err=True)

    if not skip_write and enum_result:
        typer.secho("=== Phase 4: Writing Novel Edges ===", fg="cyan", err=True)
        edges = build_all_edges(enum_result)
        typer.secho(f"Built {len(edges)} edge descriptors", fg="cyan", err=True)

        writer = Neo4jWriter(bh_client)
        try:
            edge_types = set(e.edge_type for e in edges)
            for et in edge_types:
                writer.ensure_edge_type(et)
            write_result = writer.write_edges(edges)
            typer.secho(
                f"Wrote {write_result['written']}/{write_result['total']} edges",
                fg="green" if write_result["errors"] else "green", err=True,
            )
            if write_result["errors"]:
                for err in write_result["errors"][:10]:
                    typer.secho(f"  Error: {err}", fg="red", err=True)
        except Exception as e:
            typer.secho(f"Edge writing failed: {e}", fg="red", err=True)
            raise typer.Exit(code=8)
    elif not skip_write and not enum_result:
        typer.secho("=== Phase 4: Skipped (no enumeration data) ===", fg="yellow", err=True)
    else:
        typer.secho("=== Phase 4: Skipped ===", fg="yellow", err=True)

    typer.secho("Pipeline complete", fg="cyan", err=True)
