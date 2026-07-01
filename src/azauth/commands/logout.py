from __future__ import annotations

import typer
from rich.console import Console

from azauth.core.authenticator import AzureAuthenticator, Credentials

console = Console(stderr=True)


def logout(
    ctx: typer.Context,
    token_cache: str = typer.Option(
        None, "--token-cache", help="Path to token cache file",
    ),
):
    """Remove cached tokens and sign out."""
    creds = Credentials()
    if token_cache:
        creds.token_cache_path = __import__("pathlib").Path(token_cache)

    authenticator = AzureAuthenticator(creds)
    authenticator.logout()
    console.print("[green]Logged out — cache cleared[/green]")
