import json
import sqlite3
import stat
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict

import pytest

from mimclave.telemetry.checkpoint_service import create_checkpoint_server
from mimclave.telemetry.checkpoints import EvidenceCheckpoint


TOKEN = "mimclave-test-checkpoint-token-0123456789abcdef"
RESOURCE = "/v1/mimclave/checkpoint"


@pytest.fixture
def running_service(tmp_path):
    database = tmp_path / "private" / "checkpoint.sqlite3"
    server = create_checkpoint_server(
        database_path=database,
        bearer_token=TOKEN,
        host="127.0.0.1",
        port=0,
        resource_path=RESOURCE,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}{RESOURCE}", database
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def send_request(url, method="GET", *, headers=None, body=None):
    request = urllib.request.Request(
        url,
        data=body,
        headers=headers or {},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()


def auth_headers(**extra):
    return {"Authorization": f"Bearer {TOKEN}", **extra}


def encode(checkpoint):
    return json.dumps(asdict(checkpoint), sort_keys=True).encode("utf-8")


def test_checkpoint_service_starts_empty_and_requires_auth(running_service):
    url, _ = running_service

    status, _, body = send_request(url)
    assert status == 401
    assert json.loads(body)["error"] == "unauthorized"

    status, _, body = send_request(url, headers=auth_headers())
    assert status == 404
    assert json.loads(body)["error"] == "checkpoint not initialized"


def test_checkpoint_service_initial_create_read_and_update(running_service):
    url, database = running_service
    first = EvidenceCheckpoint(1, 1, "a" * 64)

    status, headers, body = send_request(
        url,
        "PUT",
        headers=auth_headers(
            **{"If-None-Match": "*", "Content-Type": "application/json"}
        ),
        body=encode(first),
    )
    assert status == 200
    first_etag = headers["ETag"]
    assert first_etag.startswith('"') and first_etag.endswith('"')
    assert json.loads(body) == asdict(first)

    status, headers, body = send_request(url, headers=auth_headers())
    assert status == 200
    assert headers["ETag"] == first_etag
    assert json.loads(body) == asdict(first)

    second = EvidenceCheckpoint(2, 2, "b" * 64)
    status, headers, body = send_request(
        url,
        "PUT",
        headers=auth_headers(
            **{"If-Match": first_etag, "Content-Type": "application/json"}
        ),
        body=encode(second),
    )
    assert status == 200
    assert headers["ETag"] != first_etag
    assert json.loads(body) == asdict(second)
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    assert stat.S_IMODE(database.parent.stat().st_mode) == 0o700


def test_checkpoint_service_rejects_stale_etag_and_rollback(running_service):
    url, _ = running_service
    first = EvidenceCheckpoint(1, 4, "a" * 64)
    status, headers, _ = send_request(
        url,
        "PUT",
        headers=auth_headers(
            **{"If-None-Match": "*", "Content-Type": "application/json"}
        ),
        body=encode(first),
    )
    assert status == 200
    etag = headers["ETag"]

    second = EvidenceCheckpoint(2, 5, "b" * 64)
    status, _, _ = send_request(
        url,
        "PUT",
        headers=auth_headers(
            **{"If-Match": etag, "Content-Type": "application/json"}
        ),
        body=encode(second),
    )
    assert status == 200

    status, _, _ = send_request(
        url,
        "PUT",
        headers=auth_headers(
            **{"If-Match": etag, "Content-Type": "application/json"}
        ),
        body=encode(EvidenceCheckpoint(2, 6, "c" * 64)),
    )
    assert status == 412

    status, headers, _ = send_request(url, headers=auth_headers())
    current_etag = headers["ETag"]
    status, _, _ = send_request(
        url,
        "PUT",
        headers=auth_headers(
            **{"If-Match": current_etag, "Content-Type": "application/json"}
        ),
        body=encode(EvidenceCheckpoint(3, 4, "d" * 64)),
    )
    assert status == 412


def test_checkpoint_service_serializes_competing_conditional_writes(running_service):
    url, _ = running_service
    first = EvidenceCheckpoint(1, 1, "a" * 64)
    status, headers, _ = send_request(
        url,
        "PUT",
        headers=auth_headers(
            **{"If-None-Match": "*", "Content-Type": "application/json"}
        ),
        body=encode(first),
    )
    assert status == 200
    etag = headers["ETag"]

    candidates = [
        EvidenceCheckpoint(2, 2, "b" * 64),
        EvidenceCheckpoint(2, 3, "c" * 64),
    ]

    def publish(candidate):
        return send_request(
            url,
            "PUT",
            headers=auth_headers(
                **{"If-Match": etag, "Content-Type": "application/json"}
            ),
            body=encode(candidate),
        )[0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(publish, candidates))

    assert sorted(results) == [200, 412]


@pytest.mark.parametrize(
    ("body", "content_type", "expected_status"),
    [
        (b'{"generation":1,"generation":1,"record_count":1,"head_hash":"' + b"a" * 64 + b'"}',
         "application/json", 400),
        (b"{}", "text/plain", 415),
        (b"x" * 4097, "application/json", 413),
    ],
)
def test_checkpoint_service_rejects_invalid_or_oversized_requests(
    running_service, body, content_type, expected_status
):
    url, _ = running_service
    status, _, _ = send_request(
        url,
        "PUT",
        headers=auth_headers(**{
            "If-None-Match": "*",
            "Content-Type": content_type,
        }),
        body=body,
    )
    assert status == expected_status


def test_checkpoint_service_rejects_non_loopback_bind(tmp_path):
    with pytest.raises(ValueError, match="loopback"):
        create_checkpoint_server(
            database_path=tmp_path / "private" / "checkpoint.sqlite3",
            bearer_token=TOKEN,
            host="0.0.0.0",
            port=8080,
        )


def test_checkpoint_service_persists_state_across_restart(tmp_path):
    database = tmp_path / "private" / "checkpoint.sqlite3"
    server = create_checkpoint_server(
        database_path=database,
        bearer_token=TOKEN,
        host="127.0.0.1",
        port=0,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    url = f"http://{host}:{port}{RESOURCE}"
    checkpoint = EvidenceCheckpoint(1, 8, "e" * 64)
    try:
        status, _, _ = send_request(
            url,
            "PUT",
            headers=auth_headers(
                **{"If-None-Match": "*", "Content-Type": "application/json"}
            ),
            body=encode(checkpoint),
        )
        assert status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    reopened = create_checkpoint_server(
        database_path=database,
        bearer_token=TOKEN,
        host="127.0.0.1",
        port=0,
    )
    thread = threading.Thread(target=reopened.serve_forever, daemon=True)
    thread.start()
    host, port = reopened.server_address
    try:
        status, _, body = send_request(
            f"http://{host}:{port}{RESOURCE}",
            headers=auth_headers(),
        )
        assert status == 200
        assert json.loads(body) == asdict(checkpoint)
    finally:
        reopened.shutdown()
        reopened.server_close()
        thread.join(timeout=2)



def test_checkpoint_service_rejects_short_bearer_token(tmp_path):
    with pytest.raises(ValueError, match="at least 32 characters"):
        create_checkpoint_server(
            database_path=tmp_path / "private" / "checkpoint.sqlite3",
            bearer_token="too-short",
            host="127.0.0.1",
            port=0,
        )



def test_checkpoint_service_history_is_hash_chained_and_append_only(running_service):
    url, database = running_service
    first = EvidenceCheckpoint(1, 1, "a" * 64)
    status, headers, _ = send_request(
        url,
        "PUT",
        headers=auth_headers(
            **{"If-None-Match": "*", "Content-Type": "application/json"}
        ),
        body=encode(first),
    )
    assert status == 200

    second = EvidenceCheckpoint(2, 2, "b" * 64)
    status, _, _ = send_request(
        url,
        "PUT",
        headers=auth_headers(
            **{"If-Match": headers["ETag"], "Content-Type": "application/json"}
        ),
        body=encode(second),
    )
    assert status == 200

    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            """
            SELECT generation, previous_history_hash, entry_hash
            FROM checkpoint_history ORDER BY generation
            """
        ).fetchall()
        assert [row[0] for row in rows] == [1, 2]
        assert rows[0][1] == "0" * 64
        assert rows[1][1] == rows[0][2]
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE checkpoint_history SET head_hash = ? WHERE generation = 1",
                ("f" * 64,),
            )


def test_checkpoint_service_detects_rewritten_history(running_service):
    url, database = running_service
    checkpoint = EvidenceCheckpoint(1, 1, "a" * 64)
    status, _, _ = send_request(
        url,
        "PUT",
        headers=auth_headers(
            **{"If-None-Match": "*", "Content-Type": "application/json"}
        ),
        body=encode(checkpoint),
    )
    assert status == 200

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER checkpoint_history_no_update")
        connection.execute(
            "UPDATE checkpoint_history SET entry_hash = ? WHERE generation = 1",
            ("f" * 64,),
        )

    status, _, body = send_request(url, headers=auth_headers())
    assert status == 503
    assert json.loads(body)["error"] == "checkpoint storage unavailable"
