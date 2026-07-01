from pathlib import Path
from unittest.mock import Mock, patch

from typer.testing import CliRunner

from azauth.cli import app

runner = CliRunner()


def test_help_succeeds():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "authenticator" in result.stdout.lower()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0


def test_login_bad_auth_flow():
    result = runner.invoke(app, ["login", "--auth-flow", "nope"])
    assert result.exit_code == 2


@patch("azauth.commands.login.AzureAuthenticator")
def test_login_device_code_success(MockAuth):
    instance = Mock()
    instance.authenticate.return_value = Mock(
        success=True,
        token={"access_token": "fake"},
        username="test@example.com",
        tenant_id="tenant-id",
    )
    MockAuth.return_value = instance

    result = runner.invoke(app, ["login"])
    assert result.exit_code == 0
    assert "Authenticated" in result.stderr


@patch("azauth.commands.login.AzureAuthenticator")
def test_login_ropc_success(MockAuth):
    instance = Mock()
    instance.authenticate.return_value = Mock(
        success=True,
        token={"access_token": "fake"},
        username="test@example.com",
        tenant_id="tenant-id",
    )
    MockAuth.return_value = instance

    result = runner.invoke(
        app,
        ["login", "--auth-flow", "ropc", "--username", "test@example.com", "--password", "hunter2"],
    )
    assert result.exit_code == 0
    assert "Authenticated" in result.stderr


def test_login_ropc_missing_password():
    result = runner.invoke(
        app,
        ["login", "--auth-flow", "ropc", "--username", "test@example.com"],
    )
    assert result.exit_code == 2


@patch("azauth.commands.login.AzureAuthenticator")
def test_login_with_password_file(MockAuth):
    pf = Path("/tmp/test_password_file.txt")
    pf.write_text("supersecret\n")

    instance = Mock()
    instance.authenticate.return_value = Mock(
        success=True,
        token={"access_token": "fake"},
        username="test@example.com",
        tenant_id="tenant-id",
    )
    MockAuth.return_value = instance

    result = runner.invoke(
        app,
        [
            "login",
            "--auth-flow", "ropc",
            "--username", "test@example.com",
            "--password-file", str(pf),
        ],
    )
    pf.unlink(missing_ok=True)
    assert result.exit_code == 0


@patch("azauth.commands.login.AzureAuthenticator")
def test_login_failure(MockAuth):
    instance = Mock()
    instance.authenticate.return_value = Mock(
        success=False,
        error="Invalid credentials",
        token=None,
    )
    MockAuth.return_value = instance

    result = runner.invoke(app, ["login"])
    assert result.exit_code == 3
    assert "Invalid" in result.stderr


def test_logout_help():
    result = runner.invoke(app, ["logout", "--help"])
    assert result.exit_code == 0


def test_status_help():
    result = runner.invoke(app, ["status", "--help"])
    assert result.exit_code == 0


def test_token_help():
    result = runner.invoke(app, ["token", "--help"])
    assert result.exit_code == 0


@patch("azauth.commands.token.AzureAuthenticator")
def test_token_missing_token(MockAuth):
    instance = Mock()
    instance.get_token.return_value = Mock(
        success=False,
        error="No cached token",
        token=None,
    )
    MockAuth.return_value = instance

    result = runner.invoke(app, ["token"])
    assert result.exit_code != 0


@patch("azauth.commands.token.AzureAuthenticator")
def test_token_raw(MockAuth):
    instance = Mock()
    instance.get_token.return_value = Mock(
        success=True,
        token={"access_token": "abc123", "expires_on": "1234567890"},
        username="test@example.com",
        tenant_id="tenant-id",
    )
    MockAuth.return_value = instance

    result = runner.invoke(app, ["token", "--raw"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "abc123"
