import threading
import time
from http.server import HTTPServer

import pytest
import requests
import main

BASE_URL = "http://127.0.0.1:8080"


@pytest.fixture(scope="module")
def server():
    main.init_db()
    main.ensure_default_keys()

    httpd = HTTPServer((main.hostName, main.serverPort), main.MyServer)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    time.sleep(1)
    yield

    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=2)


def test_auth_valid(server):
    response = requests.post(
        f"{BASE_URL}/auth",
        auth=("userABC", "password123")
    )
    assert response.status_code == 200
    assert response.text.count(".") == 2


def test_auth_expired(server):
    response = requests.post(
        f"{BASE_URL}/auth?expired=true",
        auth=("userABC", "password123")
    )
    assert response.status_code == 200
    assert response.text.count(".") == 2


def test_jwks(server):
    response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
    assert response.status_code == 200

    data = response.json()
    assert "keys" in data
    assert isinstance(data["keys"], list)
    assert len(data["keys"]) >= 1

    key = data["keys"][0]
    assert key["kty"] == "RSA"
    assert "kid" in key
    assert "n" in key
    assert "e" in key


def test_auth_without_auth_returns_401(server):
    response = requests.post(f"{BASE_URL}/auth")
    assert response.status_code == 401


def test_invalid_post_path_returns_405(server):
    response = requests.post(
        f"{BASE_URL}/not-real",
        auth=("userABC", "password123")
    )
    assert response.status_code == 405


def test_invalid_get_path_returns_405(server):
    response = requests.get(f"{BASE_URL}/not-real")
    assert response.status_code == 405


def test_put_returns_405(server):
    response = requests.put(f"{BASE_URL}/auth")
    assert response.status_code == 405


def test_patch_returns_405(server):
    response = requests.patch(f"{BASE_URL}/auth")
    assert response.status_code == 405


def test_delete_returns_405(server):
    response = requests.delete(f"{BASE_URL}/auth")
    assert response.status_code == 405


def test_head_returns_405(server):
    response = requests.head(f"{BASE_URL}/auth")
    assert response.status_code == 405


def test_int_to_base64():
    assert isinstance(main.int_to_base64(65537), str)
    assert main.int_to_base64(0) == "AA"


def test_generate_private_key_pem():
    pem = main.generate_private_key_pem()
    assert isinstance(pem, bytes)
    assert b"BEGIN RSA PRIVATE KEY" in pem


def test_load_private_key():
    pem = main.generate_private_key_pem()
    key = main.load_private_key(pem)
    assert key is not None


def test_get_signing_key_valid():
    row = main.get_signing_key(False)
    assert row is not None
    assert "kid" in row.keys()


def test_get_signing_key_expired():
    row = main.get_signing_key(True)
    assert row is not None
    assert "kid" in row.keys()


def test_get_valid_keys():
    rows = main.get_valid_keys()
    assert isinstance(rows, list)
    assert len(rows) >= 1


def test_utc_timestamp():
    now = main.utc_timestamp()
    later = main.utc_timestamp(60)
    assert isinstance(now, int)
    assert later >= now + 60


def test_send_json_response_helper():
    handler = main.MyServer.__new__(main.MyServer)
    output = []

    handler.send_response = lambda code: output.append(("code", code))
    handler.send_header = lambda key, value: output.append((key, value))
    handler.end_headers = lambda: output.append(("end", True))

    class Writer:
        def write(self, data):
            output.append(("body", data))

    handler.wfile = Writer()
    handler.send_json_response(200, {"ok": True})

    assert ("code", 200) in output
    assert ("Content-type", "application/json") in output


def test_send_text_response_helper():
    handler = main.MyServer.__new__(main.MyServer)
    output = []

    handler.send_response = lambda code: output.append(("code", code))
    handler.send_header = lambda key, value: output.append((key, value))
    handler.end_headers = lambda: output.append(("end", True))

    class Writer:
        def write(self, data):
            output.append(("body", data))

    handler.wfile = Writer()
    handler.send_text_response(200, "hello")

    assert ("code", 200) in output
    assert ("Content-type", "text/plain") in output


def test_has_mock_auth_with_basic_auth():
    handler = main.MyServer.__new__(main.MyServer)
    handler.headers = {"Authorization": "Basic abc123"}
    assert handler.has_mock_auth() is True


def test_has_mock_auth_false():
    handler = main.MyServer.__new__(main.MyServer)
    handler.headers = {}
    assert handler.has_mock_auth() is False
