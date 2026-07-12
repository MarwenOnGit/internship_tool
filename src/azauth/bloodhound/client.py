from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

log = logging.getLogger(__name__)

BHCE_DEFAULT_URL = os.environ.get("BHCE_URL", "http://localhost:8080")
BHCE_DEFAULT_SECRET_KEY = os.environ.get("BHCE_SECRET_KEY", "")


class BloodHoundError(Exception):
    pass


@dataclass
class IngestResult:
    success: bool
    job_id: str | None = None
    status: str | None = None
    error: str | None = None
    details: dict | None = None


@dataclass
class CypherResult:
    success: bool
    data: list[dict] = field(default_factory=list)
    error: str | None = None


@dataclass
class BloodHoundConfig:
    base_url: str = BHCE_DEFAULT_URL
    secret_key: str = BHCE_DEFAULT_SECRET_KEY
    verify_ssl: bool = True
    timeout: int = 120


class BloodHoundClient:
    def __init__(self, config: BloodHoundConfig):
        self.config = config
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})
        self._token: str | None = None
        self._user: dict | None = None

    @property
    def _base(self) -> str:
        return self.config.base_url.rstrip("/")

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self._base}{path}"
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("verify", self.config.verify_ssl)
        headers = kwargs.pop("headers", {})
        merged = self._headers()
        merged.update(headers)
        kwargs["headers"] = merged
        return self._session.request(method, url, **kwargs)

    def login(self) -> bool:
        payload = {"secret_key": self.config.secret_key}
        try:
            resp = self._request("POST", "/api/v2/login", json=payload)
            resp.raise_for_status()
            data = resp.json()
            self._token = data.get("token") or data.get("access_token")
            self._user = data.get("user")
            if not self._token:
                raise BloodHoundError("Login response did not contain a token")
            log.info("Authenticated to BHCE at %s", self.config.base_url)
            return True
        except requests.RequestException as e:
            raise BloodHoundError(f"BHCE login failed: {e}") from e

    def _ensure_auth(self) -> None:
        if not self._token:
            self.login()

    def ingest_file(self, file_path: str | Path) -> IngestResult:
        self._ensure_auth()
        file_path = Path(file_path)
        if not file_path.exists():
            return IngestResult(success=False, error=f"File not found: {file_path}")

        try:
            log.info("Starting file upload: %s", file_path.name)

            upload_resp = self._request("POST", "/api/v2/file-upload/start")
            upload_resp.raise_for_status()
            upload_data = upload_resp.json()
            upload_id = upload_data.get("id") or upload_data.get("upload_id")

            with file_path.open("rb") as f:
                file_data = f.read()

            upload_headers = self._headers()
            upload_headers.pop("Content-Type", None)
            chunk_resp = self._request(
                "POST",
                f"/api/v2/file-upload/{upload_id}",
                headers=upload_headers,
                data=file_data,
            )
            chunk_resp.raise_for_status()

            end_resp = self._request("POST", "/api/v2/file-upload/end")
            end_resp.raise_for_status()
            end_data = end_resp.json()
            job_id = end_data.get("job_id") or end_data.get("id")

            log.info("File uploaded, job_id=%s", job_id)
            return IngestResult(success=True, job_id=job_id, status="submitted", details=end_data)

        except requests.RequestException as e:
            return IngestResult(success=False, error=str(e))

    def poll_ingest(self, job_id: str, poll_interval: int = 5, timeout: int = 300) -> IngestResult:
        self._ensure_auth()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                resp = self._request("GET", f"/api/v2/file-upload/{job_id}/status")
                if resp.status_code == 404:
                    resp = self._request("GET", f"/api/v2/collectors/{job_id}")
                resp.raise_for_status()
                data = resp.json()
                status = data.get("status", "unknown")
                if status in ("complete", "completed", "finished", "done"):
                    return IngestResult(success=True, job_id=job_id, status=status, details=data)
                if status in ("error", "failed"):
                    err = data.get("error_message", "Unknown ingest error")
                    return IngestResult(success=False, job_id=job_id, status=status, error=err, details=data)
                log.debug("Ingest job %s status: %s", job_id, status)
            except requests.RequestException as e:
                log.warning("Poll ingest job %s: %s", job_id, e)
            time.sleep(poll_interval)
        return IngestResult(success=False, job_id=job_id, status="timeout", error=f"Timed out after {timeout}s")

    def query_cypher(self, cypher: str, parameters: dict | None = None) -> CypherResult:
        self._ensure_auth()
        payload: dict[str, Any] = {"cypher": cypher}
        if parameters:
            payload["parameters"] = parameters
        try:
            resp = self._request("POST", "/api/v2/graph/cypher", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return CypherResult(success=True, data=data.get("data", data))
        except requests.RequestException as e:
            return CypherResult(success=False, error=str(e))

    def fetch_node(self, object_id: str, label: str = "Base") -> dict | None:
        cypher = f"MATCH (n:{label} {{objectid: $object_id}}) RETURN n LIMIT 1"
        result = self.query_cypher(cypher, {"object_id": object_id})
        if result.success and result.data:
            return result.data[0]
        return None
