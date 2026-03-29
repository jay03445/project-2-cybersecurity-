from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

hostName = "localhost"
serverPort = 8080
DB_FILE = "totally_not_my_privateKeys.db"


def utc_timestamp(offset_seconds=0):
    """Return a UTC unix timestamp with an optional offset."""
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + offset_seconds


def int_to_base64(value):
    """Convert an integer to Base64URL format without padding."""
    if value == 0:
        return "AA"

    value_hex = format(value, "x")
    if len(value_hex) % 2 == 1:
        value_hex = "0" + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("utf-8")


def generate_private_key_pem():
    """Generate an RSA private key and return it serialized as PEM bytes."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(pem_bytes):
    """Deserialize PEM bytes into an RSA private key object."""
    return serialization.load_pem_private_key(pem_bytes, password=None)


def get_db_connection():
    """Open a connection to the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the keys table if it does not already exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def ensure_default_keys():
    """
    Ensure the database contains:
    - at least one expired key
    - at least one valid key
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = utc_timestamp()

    cursor.execute("SELECT COUNT(*) AS count FROM keys WHERE exp <= ?", (now,))
    expired_count = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM keys WHERE exp > ?", (now,))
    valid_count = cursor.fetchone()["count"]

    if expired_count == 0:
        expired_pem = generate_private_key_pem()
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (expired_pem, now - 3600)
        )

    if valid_count == 0:
        valid_pem = generate_private_key_pem()
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (valid_pem, now + 3600)
        )

    conn.commit()
    conn.close()


def get_signing_key(expired=False):
    """
    Fetch a single key from the DB for signing.
    If expired=False, return a valid key.
    If expired=True, return an expired key.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now = utc_timestamp()

    if expired:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1",
            (now,)
        )
    else:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1",
            (now,)
        )

    row = cursor.fetchone()
    conn.close()
    return row


def get_valid_keys():
    """Fetch all valid keys from the DB."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = utc_timestamp()

    cursor.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid",
        (now,)
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def build_jwk_from_private_key(kid, pem_bytes):
    """Build a public JWK from a stored private key."""
    private_key = load_private_key(pem_bytes)
    public_numbers = private_key.public_key().public_numbers()

    return {
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig",
        "kid": str(kid),
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e),
    }


class MyServer(BaseHTTPRequestHandler):
    def send_json_response(self, status_code, payload):
        """Helper to send JSON responses."""
        self.send_response(status_code)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def send_text_response(self, status_code, payload):
        """Helper to send plain text responses."""
        self.send_response(status_code)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(payload.encode("utf-8"))

    def parse_request_body(self):
        """Read and decode JSON request body if present."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}

        raw_body = self.rfile.read(content_length)
        if not raw_body:
            return {}

        try:
            return json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def has_mock_auth(self):
        """
        Mock authentication support for the test client.
        Accept either:
        - HTTP Basic Authorization header
        - JSON payload with username/password
        """
        auth_header = self.headers.get("Authorization")
        if auth_header and auth_header.startswith("Basic "):
            return True

        body = self.parse_request_body()
        if "username" in body and "password" in body:
            return True

        return False

    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path != "/auth":
            self.send_response(405)
            self.end_headers()
            return

        if not self.has_mock_auth():
            self.send_json_response(401, {"error": "Missing mock authentication"})
            return

        use_expired = "expired" in params
        row = get_signing_key(expired=use_expired)

        if row is None:
            self.send_json_response(500, {"error": "No suitable signing key found"})
            return

        kid = row["kid"]
        pem_bytes = row["key"]
        exp = row["exp"]

        token_payload = {
            "user": "userABC",
            "username": "userABC",
            "exp": exp
        }

        headers = {
            "kid": str(kid)
        }

        encoded_jwt = jwt.encode(
            token_payload,
            pem_bytes,
            algorithm="RS256",
            headers=headers
        )

        self.send_text_response(200, encoded_jwt)

    def do_GET(self):
        parsed_path = urlparse(self.path)

        if parsed_path.path != "/.well-known/jwks.json":
            self.send_response(405)
            self.end_headers()
            return

        rows = get_valid_keys()
        jwks = {"keys": [build_jwk_from_private_key(row["kid"], row["key"]) for row in rows]}
        self.send_json_response(200, jwks)


if __name__ == "__main__":
    init_db()
    ensure_default_keys()

    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server running at http://{hostName}:{serverPort}")

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
