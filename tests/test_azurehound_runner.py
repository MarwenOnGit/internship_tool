from pathlib import Path
from subprocess import TimeoutExpired
from unittest.mock import Mock, patch

import pytest

from fenrir.collectors.azurehound_runner import (
    AzureHoundConfig,
    AzureHoundError,
    AzureHoundResult,
    run_azurehound,
)


def test_run_azurehound_success(tmp_path: Path):
    out_file = tmp_path / "azurehound_output.json"
    out_file.write_text('{"data": "ok"}')

    config = AzureHoundConfig(
        binary="/fake/azurehound",
        refresh_token="rt-abc",
        output_dir=str(tmp_path),
    )

    mock_proc = Mock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = ""

    with patch("subprocess.run", return_value=mock_proc), \
         patch("shutil.which", return_value="/fake/azurehound"):
        result = run_azurehound(config)

    assert result.success is True
    assert result.output_path == out_file


def test_run_azurehound_error_exit(tmp_path: Path):
    config = AzureHoundConfig(
        binary="/fake/azurehound",
        refresh_token="rt-abc",
        output_dir=str(tmp_path),
    )

    mock_proc = Mock()
    mock_proc.returncode = 1
    mock_proc.stdout = ""
    mock_proc.stderr = "something went wrong"

    with patch("subprocess.run", return_value=mock_proc), \
         patch("shutil.which", return_value="/fake/azurehound"):
        result = run_azurehound(config)

    assert result.success is False
    assert "something went wrong" in result.error


def test_run_azurehound_needs_auth(tmp_path: Path):
    config = AzureHoundConfig(
        binary="/fake/azurehound",
        output_dir=str(tmp_path),
    )

    with pytest.raises(AzureHoundError, match="Either refresh_token or client_id"):
        run_azurehound(config)


def test_run_azurehound_binary_not_found():
    config = AzureHoundConfig(
        binary="nonexistent-azurehound",
        refresh_token="rt-abc",
    )

    with pytest.raises(AzureHoundError, match="not found"):
        run_azurehound(config)


def test_run_azurehound_app_only_auth(tmp_path: Path):
    out_file = tmp_path / "azurehound_output.json"
    out_file.write_text("{}")

    config = AzureHoundConfig(
        binary="/fake/azurehound",
        client_id="client-id",
        client_secret="secret",
        tenant_id="tenant-id",
        output_dir=str(tmp_path),
    )

    mock_proc = Mock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = ""

    with patch("subprocess.run", return_value=mock_proc), \
         patch("shutil.which", return_value="/fake/azurehound"):
        result = run_azurehound(config)

    assert result.success is True


def test_run_azurehound_timeout(tmp_path: Path):
    config = AzureHoundConfig(
        binary="/fake/azurehound",
        refresh_token="rt-abc",
        output_dir=str(tmp_path),
    )

    with patch("subprocess.run", side_effect=TimeoutExpired(cmd=["azurehound"], timeout=600)), \
         patch("shutil.which", return_value="/fake/azurehound"):
        result = run_azurehound(config)

    assert result.success is False
    assert "timed out" in result.error



