from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

log = logging.getLogger(__name__)

AZUREHOUND_DEFAULT_PATH = "azurehound"


class AzureHoundError(Exception):
    pass


@dataclass
class AzureHoundConfig:
    binary: str = os.environ.get("AZUREHOUND_PATH", AZUREHOUND_DEFAULT_PATH)
    refresh_token: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    tenant_id: str | None = None
    output_dir: str | None = None
    extra_args: list[str] = field(default_factory=list)


@dataclass
class AzureHoundResult:
    success: bool
    output_path: Path | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None


def _find_binary(path_hint: str) -> str:
    if os.path.isabs(path_hint):
        return path_hint
    candidate = Path.cwd() / path_hint
    if candidate.is_file():
        return str(candidate.resolve())
    import shutil
    resolved = shutil.which(path_hint)
    if resolved:
        return resolved
    raise AzureHoundError(f"AzureHound binary not found at '{path_hint}' — set AZUREHOUND_PATH or place it on PATH")


def run_azurehound(config: AzureHoundConfig) -> AzureHoundResult:
    binary = _find_binary(config.binary)
    output_dir = Path(config.output_dir or Path.cwd())
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "azurehound_output.json"

    cmd = [binary, "list", "--output-file", str(output_path)]

    if config.refresh_token:
        cmd.extend(["--refresh-token", config.refresh_token])
    elif config.client_id and config.client_secret:
        cmd.extend(["--client-id", config.client_id, "--client-secret", config.client_secret])
        if config.tenant_id:
            cmd.extend(["--tenant-id", config.tenant_id])
    else:
        raise AzureHoundError("Either refresh_token or client_id+client_secret must be provided")

    cmd.extend(config.extra_args)

    log.info("Running: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return AzureHoundResult(success=False, error="AzureHound timed out after 600s")
    except FileNotFoundError:
        return AzureHoundResult(success=False, error=f"AzureHound binary not found: {binary}")

    if proc.returncode != 0:
        err_msg = proc.stderr.strip() or f"exit code {proc.returncode}"
        return AzureHoundResult(
            success=False,
            stdout=proc.stdout,
            stderr=proc.stderr,
            error=f"AzureHound failed: {err_msg}",
        )

    if not output_path.exists():
        return AzureHoundResult(success=False, error="AzureHound exited OK but no output file was created")

    return AzureHoundResult(
        success=True,
        output_path=output_path,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def parse_azurehound_output(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise AzureHoundError(f"Failed to parse AzureHound output: {e}")
    if not isinstance(data, dict):
        raise AzureHoundError(f"Expected JSON object, got {type(data).__name__}")
    return data
