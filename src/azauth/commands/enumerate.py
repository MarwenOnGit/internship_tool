from __future__ import annotations

import json
import logging
import time

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from azauth.core.authenticator import AzureAuthenticator, Credentials
from azauth.core.enumerate.collector import EnumerateCollector
from azauth.core.enumerate.models import EnumerationResult

log = logging.getLogger(__name__)
console = Console(stderr=True)
out_console = Console()


def _build_tree(result: EnumerationResult) -> Tree:
    me = result.me or {}
    upn = me.get("userPrincipalName", me.get("displayName", "Unknown"))
    tree = Tree(f"[bold cyan]{upn}[/bold cyan]", guide_style="bright_black")

    if result.errors:
        err_node = tree.add("[bold red]Errors[/bold red]")
        for e in result.errors:
            err_node.add(f"[red]{e}[/red]")

    tenant = tree.add(f"[bold]Tenant[/bold]  {me.get('tenantId', '?')}")

    domains = result.domains
    if domains:
        d_node = tenant.add(f"[bold]Domains[/bold] ({len(domains)})")
        for d in domains:
            verified = "[green]verified[/green]" if d.is_verified else "[yellow]unverified[/yellow]"
            d_node.add(f"{d.id}  ({verified})")

    roles = result.directory_roles
    if roles:
        r_node = tenant.add(f"[bold]Directory Roles[/bold] ({len(roles)})")
        seen = set()
        for ra in roles:
            name = ra.role.display_name
            if name not in seen:
                seen.add(name)
                r_node.add(f"{name}")

    pim = result.pim_roles
    if pim:
        p_node = tenant.add(f"[bold]PIM Roles[/bold] ({len(pim)})")
        for p in pim:
            p_node.add(f"{p.role_name}  [{p.status}]")

    groups = result.groups
    if groups:
        g_node = tenant.add(f"[bold]Groups[/bold] ({len(groups)})")
        for g in groups[:30]:
            g_node.add(f"{g.display_name}  ({g.group_type})")
        if len(groups) > 30:
            g_node.add(f"[dim]... and {len(groups) - 30} more[/dim]")

    owned_apps = result.owned_applications
    if owned_apps:
        a_node = tenant.add(f"[bold]Owned Applications[/bold] ({len(owned_apps)})")
        for app in owned_apps:
            creds = []
            if app.password_credentials:
                creds.append(f"{app.password_credentials}pwd")
            if app.key_credentials:
                creds.append(f"{app.key_credentials}key")
            suffix = f"  [yellow]({', '.join(creds)})[/yellow]" if creds else ""
            a_node.add(f"{app.display_name}{suffix}")

    owned_sps = result.owned_service_principals
    if owned_sps:
        sp_node = tenant.add(f"[bold]Owned Service Principals[/bold] ({len(owned_sps)})")
        for sp in owned_sps[:20]:
            creds = []
            if sp.password_credentials:
                creds.append(f"{sp.password_credentials}pwd")
            if sp.key_credentials:
                creds.append(f"{sp.key_credentials}key")
            suffix = f"  [yellow]({', '.join(creds)})[/yellow]" if creds else ""
            sp_node.add(f"{sp.display_name}{suffix}")
        if len(owned_sps) > 20:
            sp_node.add(f"[dim]... and {len(owned_sps) - 20} more[/dim]")

    devices = result.managed_devices
    if devices:
        d_node = tenant.add(f"[bold]Managed Devices[/bold] ({len(devices)})")
        for dev in devices[:15]:
            d_node.add(f"{dev.display_name}  ({dev.operating_system or '?'})")
        if len(devices) > 15:
            d_node.add(f"[dim]... and {len(devices) - 15} more[/dim]")

    subs = result.subscriptions
    if subs:
        sub_node = tree.add(f"[bold green]Subscriptions[/bold green] ({len(subs)})")
        for sub in subs:
            roles_str = ", ".join(sub.roles) if sub.roles else "[dim]no direct role[/dim]"
            s = sub_node.add(
                f"[bold]{sub.display_name}[/bold]  ({sub.state}) — {roles_str}"
            )
            for rg in sub.resource_groups:
                rg_roles = f"  [{', '.join(rg.roles)}]" if rg.roles else ""
                rg_node = s.add(f"{rg.name}  ({rg.location}){rg_roles}")
                for res in rg.resources[:10]:
                    rg_node.add(f"{res.name}  ({res.type})")
                if len(rg.resources) > 10:
                    rg_node.add(f"[dim]... and {len(rg.resources) - 10} more[/dim]")

    mg = result.management_groups
    if mg:
        mg_node = tree.add(f"[bold]Management Groups[/bold] ({len(mg)})")
        for m in mg:
            mg_node.add(m.display_name)

    return tree


def _build_json(result: EnumerationResult) -> dict:
    return {
        "me": result.me,
        "domains": [{"id": d.id, "verified": d.is_verified, "default": d.is_default} for d in result.domains],
        "directory_roles": list({ra.role.display_name for ra in result.directory_roles}),
        "pim_roles": [{"role": p.role_name, "status": p.status} for p in result.pim_roles],
        "groups": [
            {"display_name": g.display_name, "type": g.group_type}
            for g in result.groups
        ],
        "owned_applications": [
            {"display_name": a.display_name, "app_id": a.app_id, "password_creds": a.password_credentials, "key_creds": a.key_credentials}
            for a in result.owned_applications
        ],
        "owned_service_principals": [
            {"display_name": sp.display_name, "app_id": sp.app_id, "password_creds": sp.password_credentials, "key_creds": sp.key_credentials}
            for sp in result.owned_service_principals
        ],
        "managed_devices": [
            {"display_name": d.display_name, "os": d.operating_system, "compliant": d.is_compliant}
            for d in result.managed_devices
        ],
        "subscriptions": [
            {
                "display_name": s.display_name,
                "subscription_id": s.subscription_id,
                "state": s.state,
                "roles": s.roles,
                "resource_groups": [
                    {
                        "name": rg.name,
                        "location": rg.location,
                        "resources": [
                            {"name": r.name, "type": r.type}
                            for r in rg.resources
                        ],
                    }
                    for rg in s.resource_groups
                ],
            }
            for s in result.subscriptions
        ],
        "management_groups": [
            {"name": mg.name, "display_name": mg.display_name}
            for mg in result.management_groups
        ],
        "errors": result.errors,
    }


def enumerate_cmd(
    ctx: typer.Context,
    output: str = typer.Option(
        None, "--output", "-o",
        help="Output file path (default: stdout)",
    ),
    fmt: str = typer.Option(
        "tree", "--format", "-f",
        help="Output format: tree (default), json",
    ),
    no_resources: bool = typer.Option(
        False, "--no-resources",
        help="Skip per-subscription resource enumeration (faster)",
    ),
    token_cache: str = typer.Option(None, "--token-cache"),
):
    """Enumerate all accessible Azure assets — roles, groups, apps, subscriptions, resources.

    Pulls data from both Microsoft Graph and Azure Resource Manager to give a
    comprehensive view of what the authenticated user owns or has privileges on.
    """
    if fmt not in ("tree", "json"):
        err_console = Console(stderr=True)
        err_console.print(f"[red]Invalid format:[/red] {fmt} — use tree or json")
        raise typer.Exit(code=2)

    from pathlib import Path
    creds = Credentials()
    if token_cache:
        creds.token_cache_path = Path(token_cache)

    authenticator = AzureAuthenticator(creds)
    collector = EnumerateCollector(authenticator)
    collector.result.subscriptions = []  # reset

    # Quick auth check first
    auth_result = authenticator.get_token()
    if not auth_result.success:
        console.print("[red]Not authenticated. Run[/red] azauth login [red]first.[/red]")
        raise typer.Exit(code=3)

    from rich.progress import (
        Progress,
        SpinnerColumn,
        TextColumn,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Enumerating Azure assets...", total=None)
        collector.collect_me()
        collector.collect_domains()
        collector.collect_directory_roles()
        collector.collect_pim_roles()
        collector.collect_groups()
        collector.collect_owned_apps()
        collector.collect_owned_service_principals()
        collector.collect_managed_devices()
        collector.collect_management_groups()
        if not no_resources:
            collector.collect_subscriptions()

    result = collector.result

    if fmt == "json":
        data = _build_json(result)
        text = json.dumps(data, indent=2, default=str)
        if output:
            Path(output).write_text(text)
            console.print(f"[green]Written to[/green] {output}")
        else:
            out_console.print(text)
        return

    tree = _build_tree(result)

    if output:
        from rich.text import Text as RichText
        from io import StringIO
        buf = StringIO()
        from rich.console import Console as RichConsole
        RichConsole(file=buf).print(tree)
        Path(output).write_text(buf.getvalue())
        console.print(f"[green]Written to[/green] {output}")
    else:
        console.print(tree)
