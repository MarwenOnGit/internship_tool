from unittest.mock import Mock, patch

import pytest

from fenrir.bloodhound.client import BloodHoundClient, BloodHoundConfig


@pytest.fixture
def client():
    config = BloodHoundConfig(base_url="http://localhost:8080", secret_key="test-secret")
    return BloodHoundClient(config)


def test_login_success(client):
    mock_resp = Mock()
    mock_resp.json.return_value = {"token": "jwt-token", "user": {"id": "1"}}
    mock_resp.status_code = 200

    with patch.object(client._session, "request", return_value=mock_resp):
        result = client.login()

    assert result is True
    assert client._token == "jwt-token"


def test_login_failure(client):
    import requests
    mock_resp = Mock(spec=requests.Response)
    mock_resp.raise_for_status.side_effect = requests.HTTPError("HTTP 401")

    with patch.object(client._session, "request", return_value=mock_resp):
        with pytest.raises(Exception, match="BHCE login failed"):
            client.login()


def test_ingest_file_success(client, tmp_path):
    client._token = "jwt"

    f = tmp_path / "test.json"
    f.write_text("{}")

    start_resp = Mock()
    start_resp.json.return_value = {"id": "upload-1"}
    start_resp.status_code = 200

    chunk_resp = Mock()
    chunk_resp.status_code = 200

    end_resp = Mock()
    end_resp.json.return_value = {"job_id": "job-1"}
    end_resp.status_code = 200

    with patch.object(client._session, "request") as mock_request:
        mock_request.side_effect = [start_resp, chunk_resp, end_resp]
        result = client.ingest_file(str(f))

    assert result.success is True
    assert result.job_id == "job-1"


def test_ingest_file_not_found(client):
    client._token = "jwt"
    result = client.ingest_file("/nonexistent/file.json")
    assert result.success is False
    assert "not found" in result.error


def test_query_cypher_success(client):
    client._token = "jwt"

    mock_resp = Mock()
    mock_resp.json.return_value = {"data": [{"n": {"objectid": "test-1"}}]}
    mock_resp.status_code = 200

    with patch.object(client._session, "request", return_value=mock_resp):
        result = client.query_cypher("MATCH (n) RETURN n")

    assert result.success is True
    assert len(result.data) == 1
    assert result.data[0]["n"]["objectid"] == "test-1"


def test_query_cypher_error(client):
    import requests
    client._token = "jwt"

    mock_resp = Mock(spec=requests.Response)
    mock_resp.raise_for_status.side_effect = requests.HTTPError("Bad request")

    with patch.object(client._session, "request", return_value=mock_resp):
        result = client.query_cypher("BAD CYPHER")

    assert result.success is False
    assert "Bad request" in result.error


def test_poll_ingest_complete(client):
    client._token = "jwt"

    mock_resp = Mock()
    mock_resp.json.return_value = {"status": "complete"}
    mock_resp.status_code = 200

    with patch.object(client._session, "request", return_value=mock_resp):
        result = client.poll_ingest("job-1", poll_interval=0)

    assert result.success is True
    assert result.status == "complete"


def test_poll_ingest_failed(client):
    client._token = "jwt"

    mock_resp = Mock()
    mock_resp.json.return_value = {"status": "failed", "error_message": "bad data"}
    mock_resp.status_code = 200

    with patch.object(client._session, "request", return_value=mock_resp):
        result = client.poll_ingest("job-1", poll_interval=0)

    assert result.success is False
    assert result.status == "failed"


def test_fetch_node_found(client):
    client._token = "jwt"

    mock_resp = Mock()
    mock_resp.json.return_value = {"data": [{"n": {"objectid": "test-1", "name": "Test"}}]}
    mock_resp.status_code = 200

    with patch.object(client._session, "request", return_value=mock_resp):
        node = client.fetch_node("test-1")

    assert node is not None
    assert node["n"]["objectid"] == "test-1"


def test_fetch_node_not_found(client):
    client._token = "jwt"

    mock_resp = Mock()
    mock_resp.json.return_value = {}
    mock_resp.status_code = 200

    with patch.object(client._session, "request", return_value=mock_resp):
        node = client.fetch_node("nonexistent")

    assert node is None
