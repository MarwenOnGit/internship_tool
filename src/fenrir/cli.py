from pathlib import Path

import typer

from fenrir.commands import login, logout, status, token
from fenrir.commands import enumerate as enumerate_cmd_mod
from fenrir.commands import pipeline as pipeline_mod
from fenrir.commands import exploit as exploit_mod
from fenrir.commands import db as db_mod

app = typer.Typer(
    name="fenrir",
    help="Azure CLI authenticator — email/password login with automatic MFA fallback.",
    no_args_is_help=True,
)

app.command(name="login")(login.login)
app.command(name="logout")(logout.logout)
app.command(name="status")(status.status)
app.command(name="token")(token.token_cmd)
app.command(name="enumerate", help="Enumerate all accessible Azure assets.")(enumerate_cmd_mod.enumerate_cmd)
app.command(
    name="pipeline",
    help="Run the full Azure → BHCE → custom Graph enumeration pipeline.",
)(pipeline_mod.pipeline)
app.command(
    name="exploit",
    help="Discover Azure resources, check RBAC, and extract managed identity tokens.",
)(exploit_mod.exploit)
app.add_typer(db_mod.db_app)


def _version_callback(value: bool) -> None:
    if value:
        from importlib.metadata import version
        try:
            ver = version("fenrir")
        except Exception:
            ver = "0.1.0 (dev)"
        typer.echo(f"fenrir {ver}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit", callback=_version_callback,
        is_eager=True,
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-data output"),
):
    import logging

    level = logging.WARNING
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.ERROR

    logging.basicConfig(
        level=level,
        format="%(levelname)s %(message)s",
        stream=__import__("sys").stderr,
    )

    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet


if __name__ == "__main__":
    app()
