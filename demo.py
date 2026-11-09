#!/usr/bin/env python3
"""
trust-matrix — zero-setup demo. No real target, no credentials, no risk.

Spins up a local fixture API that simulates a classic BOLA bug (every bearer
token — even an expired one — is handed tenant B's private object; no token
gets a 403), then runs trust-matrix against it so you can see the live
cross-identity matrix, the CANDIDATE verdict, and the PII-redacted Markdown
report, in one command:

    python3 demo.py

It sends only to 127.0.0.1 and writes the report under ./trust_matrix_out/.
Nothing leaves your machine.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "trust_matrix.py")

# Tenant B's private object — the "owner" data the trust boundary must protect.
TENANT_B = {"id": 123, "email": "bob@example.com", "name": "Bob", "balance": 500}


class _Fixture(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep the demo output clean
        pass

    def do_GET(self):
        # The planted bug: ANY Authorization header is served B's object.
        if self.headers.get("Authorization"):
            body, code = json.dumps(TENANT_B).encode(), 200
        else:
            body, code = json.dumps({"error": "forbidden"}).encode(), 403
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    srv = HTTPServer(("127.0.0.1", 0), _Fixture)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    out = os.path.join(HERE, "trust_matrix_out")

    with tempfile.TemporaryDirectory() as tmp:
        conf = os.path.join(tmp, "identities.conf")
        with open(conf, "w") as f:
            f.write(
                "TenantB         | owner   | Bearer BBB |\n"
                "TenantA         | acct    | Bearer AAA |\n"
                "anon            | anon    |            |\n"
                "TenantB-expired | expired | Bearer OLD |\n"
            )
        print(f"[demo] fixture API with a planted BOLA bug is live on {base}", flush=True)
        print("[demo] running: trust_matrix.py --go --report md\n", flush=True)
        r = subprocess.run(
            [sys.executable, TOOL, "--identities", conf, "--base", base,
             "--path", "/account/123", "--rate", "0", "--out", out,
             "--go", "--report", "md"],
            text=True,
        )
    srv.shutdown()
    print(f"\n[demo] open the PII-redacted report: {os.path.join(out, 'trust_matrix_report.md')}")
    return r.returncode


if __name__ == "__main__":
    raise SystemExit(main())
