#!/usr/bin/env python3
"""EXAMPLE ONLY: a verifier for figcraft-server's `external` identity provider.

It knows a fixed list of tokens (by their SHA-256) and answers who each one is. It is a starting
point for a verifier of your own (replace `lookup` with a question to your directory, SSO or
database), not something to run as is. Python 3.8+, standard library only.

The contract (docs/server-accounts.md, "An external verifier"):

    POST <verify_url>   Content-Type: application/json
    {"provider": "<the provider's id>", "token": "<what the person pasted>"}

    200 {"subject": "a stable id", "email": "ann@example.com"?, "email_verified": true?, "name": "Ann"?}
    401 or 403 {"error": "why, shown to the person"}?
    anything else: the verifier is unavailable

Usage: python3 verify.py [--port 8787] [--tokens tokens.json]

tokens.json maps the SHA-256 (hex) of each token you handed out to who it is:

    {"<sha256 hex>": {"subject": "ann", "email": "ann@example.com", "email_verified": true, "name": "Ann"}}

Make a token:  python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
Its hash:      printf %s 'THE-TOKEN' | sha256sum
"""

import argparse
import hashlib
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Largest request read (figcraft-server sends tokens of up to 8 KiB).
MAX_REQUEST = 16 * 1024

PEOPLE = {}


def lookup(provider, token):
    """Who `token` is (a dict for the answer), or None. Replace this with your own check."""
    digest = hashlib.sha256(token.encode()).hexdigest()
    who = None
    # Compare every entry in constant time, so timing doesn't tell which hashes are close.
    for known, person in PEOPLE.items():
        if hmac.compare_digest(known, digest):
            who = person
    return who


class Verify(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_REQUEST:
                raise ValueError("size")
            request = json.loads(self.rfile.read(length))
            provider = str(request.get("provider", ""))
            token = str(request.get("token", ""))
        except (ValueError, AttributeError):
            return self.answer(400, {"error": "bad request"})
        who = lookup(provider, token)
        if who is None:
            return self.answer(401, {"error": "that token isn't valid"})
        self.answer(200, who)

    def answer(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass  # don't log requests (they hold tokens)


def main():
    parser = argparse.ArgumentParser(description="EXAMPLE verifier for figcraft-server's external provider")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--tokens", default="tokens.json", help="SHA-256 of each token -> who it is")
    args = parser.parse_args()
    with open(args.tokens, encoding="utf-8") as f:
        PEOPLE.update(json.load(f))
    # The loopback interface only: put HTTPS in front of it to serve another machine.
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Verify)
    print(f"verifier on http://127.0.0.1:{args.port}/ with {len(PEOPLE)} token(s)")
    server.serve_forever()


if __name__ == "__main__":
    main()
