from __future__ import annotations

import logging
import os
import subprocess
from typing import Any

log = logging.getLogger(__name__)

CONTAINER_NAME = "azauth-neo4j"
IMAGE = "neo4j:latest"
DEFAULT_HTTP_PORT = 7474
DEFAULT_BOLT_PORT = 7687
DEFAULT_PASSWORD = "azauth_neo4j"
DATA_VOLUME = "azauth-neo4j-data"


def _docker_cmd(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def is_docker_available() -> bool:
    try:
        result = _docker_cmd("info")
        return result.returncode == 0
    except FileNotFoundError:
        return False
    except subprocess.TimeoutExpired:
        return False


def is_container_running() -> bool:
    try:
        result = _docker_cmd("ps", "--filter", f"name={CONTAINER_NAME}", "--format", "{{.Names}}")
        return CONTAINER_NAME in result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_container_status() -> str:
    try:
        result = _docker_cmd("ps", "-a", "--filter", f"name={CONTAINER_NAME}", "--format", "{{.Status}}")
        status = result.stdout.strip()
        return status or "not found"
    except FileNotFoundError:
        return "docker not available"
    except subprocess.TimeoutExpired:
        return "docker timed out"


def get_connection_params() -> dict[str, Any]:
    password = os.environ.get("NEO4J_PASSWORD", DEFAULT_PASSWORD)
    bolt_port_env = os.environ.get("NEO4J_BOLT_PORT")
    bolt_port = int(bolt_port_env) if bolt_port_env else DEFAULT_BOLT_PORT
    return {
        "uri": f"bolt://localhost:{bolt_port}",
        "user": "neo4j",
        "password": password,
    }


def start_container(password: str | None = None) -> bool:
    if is_container_running():
        log.info("Container %s is already running", CONTAINER_NAME)
        return True

    pwd = password or os.environ.get("NEO4J_PASSWORD", DEFAULT_PASSWORD)

    try:
        result = subprocess.run(
            [
                "docker", "run", "-d",
                "--name", CONTAINER_NAME,
                "-p", f"{DEFAULT_HTTP_PORT}:7474",
                "-p", f"{DEFAULT_BOLT_PORT}:7687",
                "-v", f"{DATA_VOLUME}:/data",
                "-e", f"NEO4J_AUTH=neo4j/{pwd}",
                IMAGE,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            log.error("Failed to start Neo4j container: %s", result.stderr.strip())
            return False
        log.info("Neo4j container started: %s", result.stdout.strip())
        return True
    except FileNotFoundError:
        log.error("Docker not found — install Docker to use the Neo4j database feature")
        return False
    except subprocess.TimeoutExpired:
        log.error("Docker start timed out")
        return False


def stop_container() -> bool:
    if not is_container_running():
        log.info("Container %s is not running", CONTAINER_NAME)
        return True
    try:
        result = _docker_cmd("stop", CONTAINER_NAME)
        if result.returncode != 0:
            log.error("Failed to stop container: %s", result.stderr.strip())
            return False
        log.info("Neo4j container stopped")
        return True
    except FileNotFoundError:
        log.error("Docker not found")
        return False


def remove_container() -> bool:
    try:
        _docker_cmd("rm", "-f", CONTAINER_NAME)
        return True
    except FileNotFoundError:
        return False


def wait_for_ready(timeout: int = 60) -> bool:
    import time
    from azauth.db.client import Neo4jConnection

    params = get_connection_params()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            conn = Neo4jConnection(**params)
            conn.connect()
            conn.close()
            log.info("Neo4j is ready")
            return True
        except Exception as e:
            log.debug("Waiting for Neo4j: %s", e)
            time.sleep(3)
    return False
