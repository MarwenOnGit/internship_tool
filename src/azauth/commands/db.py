from __future__ import annotations

import json
import logging
from pathlib import Path

import typer
from rich.console import Console

from azauth.db.client import Neo4jConnection
from azauth.db.docker import (
    get_container_status,
    get_connection_params,
    is_container_running,
    start_container,
    stop_container,
    wait_for_ready,
)
from azauth.db.schema import ensure_schema
from azauth.exploit.orchestrator import ExploitResult

log = logging.getLogger(__name__)
console = Console(stderr=True)
out_console = Console()

db_app = typer.Typer(
    name="db",
    help="Manage local Neo4j database (Docker) for storing Azure findings.",
    no_args_is_help=True,
)


def _get_db_connection() -> Neo4jConnection | None:
    params = get_connection_params()
    try:
        conn = Neo4jConnection(**params)
        conn.connect()
        return conn
    except Exception as e:
        console.print(f"[red]Failed to connect to Neo4j:[/red] {e}")
        console.print("[yellow]Run 'azauth db up' first[/yellow]")
        return None


@db_app.command(name="up")
def db_up(
    password: str = typer.Option("azauth_neo4j", "--password", "-p", help="Neo4j password"),
    wait: int = typer.Option(60, "--wait", "-w", help="Seconds to wait for Neo4j to be ready"),
):
    """Start Neo4j Docker container."""
    from azauth.db.docker import is_docker_available
    if not is_docker_available():
        console.print("[red]Docker is not available. Install Docker to use the Neo4j database.[/red]")
        raise typer.Exit(code=1)

    if is_container_running():
        console.print("[green]Neo4j container is already running[/green]")
    else:
        console.print("[cyan]Starting Neo4j container...[/cyan]")
        if not start_container(password):
            console.print("[red]Failed to start Neo4j container[/red]")
            raise typer.Exit(code=1)
        console.print("[cyan]Waiting for Neo4j to be ready...[/cyan]")
        if not wait_for_ready(wait):
            console.print("[red]Neo4j did not become ready in time[/red]")
            raise typer.Exit(code=1)

    conn = _get_db_connection()
    if conn:
        ensure_schema(conn)
        conn.close()
        console.print("[green]Neo4j is ready and schema is initialized[/green]")
        console.print(f"  Bolt:  bolt://localhost:7687")
        console.print(f"  HTTP:  http://localhost:7474")
        console.print(f"  User:  neo4j")
        console.print(f"  Pass:  {password}")


@db_app.command(name="down")
def db_down():
    """Stop Neo4j Docker container."""
    if stop_container():
        console.print("[green]Neo4j container stopped[/green]")
    else:
        console.print("[red]Failed to stop Neo4j container[/red]")
        raise typer.Exit(code=1)


@db_app.command(name="status")
def db_status():
    """Show Neo4j container status."""
    status = get_container_status()
    running = is_container_running()
    if running:
        console.print("[green]Neo4j is running[/green]")
    else:
        console.print(f"[yellow]Neo4j status:[/yellow] {status}")
    console.print(f"  Container: azauth-neo4j")
    console.print(f"  Status:    {status}")


@db_app.command(name="reset")
def db_reset():
    """Stop and remove the Neo4j container + data volume."""
    from azauth.db.docker import remove_container
    stop_container()
    remove_container()
    console.print("[green]Container removed[/green]")
    console.print("[yellow]Run 'azauth db up' to create a fresh instance[/yellow]")


@db_app.command(name="ingest")
def db_ingest(
    tenant: str = typer.Option("default", "--tenant", "-t", help="Tenant identifier for multi-tenant indexing"),
    azurehound: str | None = typer.Option(None, "--azurehound", "-a", help="AzureHound output JSON file to ingest"),
):
    """Ingest exploit findings (from cache) and/or AzureHound data into Neo4j."""
    conn = _get_db_connection()
    if not conn:
        raise typer.Exit(code=1)

    from azauth.db.ingest import ingest_azurehound

    if azurehound:
        console.print(f"[cyan]Ingesting AzureHound data from[/cyan] {azurehound}")
        ah_counts = ingest_azurehound(conn, azurehound, tenant)
        console.print(f"  Nodes: {ah_counts.get('nodes', 0)}, Edges: {ah_counts.get('edges', 0)}")

    ensure_schema(conn)
    conn.close()

    console.print("[green]Ingest complete[/green]")


@db_app.command(name="query")
def db_query(
    cypher: str = typer.Argument(..., help="Cypher query to execute"),
    params: str | None = typer.Option(None, "--params", help="Query parameters as JSON"),
):
    """Run a Cypher query against the local Neo4j database."""
    conn = _get_db_connection()
    if not conn:
        raise typer.Exit(code=1)

    parsed_params = {}
    if params:
        try:
            parsed_params = json.loads(params)
        except json.JSONDecodeError as e:
            console.print(f"[red]Invalid JSON params:[/red] {e}")
            conn.close()
            raise typer.Exit(code=2)

    try:
        results = conn.run(cypher, parsed_params)
        if results:
            out_console.print_json(json.dumps(results, indent=2, default=str))
        else:
            console.print("[yellow]No results[/yellow]")
    except Exception as e:
        console.print(f"[red]Query failed:[/red] {e}")
    finally:
        conn.close()


@db_app.command(name="export")
def db_export_query(
    cypher: str = typer.Argument(..., help="Cypher query to export"),
    output: str = typer.Option("export.json", "--output", "-o", help="Output file path"),
):
    """Export query results to JSON."""
    conn = _get_db_connection()
    if not conn:
        raise typer.Exit(code=1)

    try:
        results = conn.run(cypher)
        Path(output).write_text(json.dumps(results, indent=2, default=str))
        console.print(f"[green]Exported {len(results)} results to[/green] {output}")
    except Exception as e:
        console.print(f"[red]Export failed:[/red] {e}")
    finally:
        conn.close()



