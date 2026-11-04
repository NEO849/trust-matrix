"""
End-to-End gegen einen LOKALEN Fixture-Server (kein echtes Target).
Beweist: Replay-Verdrahtung, CANDIDATE-Erkennung live, DRY-RUN sendet NICHTS,
Artefakt ist PII-redacted.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TOOL = os.path.join(ROOT, "trust_matrix.py")

TENANT_B = {"id": 123, "email": "bob@example.com", "name": "Bob", "balance": 500}

REQUESTS_SEEN = {"n": 0}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        REQUESTS_SEEN["n"] += 1
        # Simulierter BOLA: JEDER Authorization-Header bekommt B's Objekt;
        # ohne Auth -> 403 (Zugriffskontrolle greift normal).
        if self.headers.get("Authorization"):
            payload = json.dumps(TENANT_B).encode()
            self.send_response(200)
        else:
            payload = json.dumps({"error": "forbidden"}).encode()
            self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)


def _serve():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _conf(tmp_path):
    p = tmp_path / "identities.conf"
    p.write_text(
        "TenantB | owner | Bearer BBB |\n"
        "TenantA | acct | Bearer AAA |\n"
        "anon | anon | |\n"
        "TenantB-expired | expired | Bearer OLD |\n"
    )
    return str(p)


def _run(conf, base, out, go, rate="0"):
    cmd = [sys.executable, TOOL, "--identities", conf, "--base", base,
           "--path", "/account/123", "--rate", rate, "--out", out]
    if go:
        cmd.append("--go")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


def test_dry_run_sends_nothing(tmp_path):
    REQUESTS_SEEN["n"] = 0
    srv = _serve()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        r = _run(_conf(tmp_path), base, str(tmp_path / "out"), go=False)
    finally:
        srv.shutdown()
    assert r.returncode == 0
    assert "DRY-RUN" in r.stdout
    assert REQUESTS_SEEN["n"] == 0, "Dry-Run darf KEINEN Request senden"


def test_live_run_flags_candidate_and_redacts(tmp_path):
    REQUESTS_SEEN["n"] = 0
    srv = _serve()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        out = str(tmp_path / "out")
        r = _run(_conf(tmp_path), base, out, go=True)
    finally:
        srv.shutdown()

    assert r.returncode == 0, r.stderr
    assert REQUESTS_SEEN["n"] == 4, "je Identität genau 1 GET"
    assert "CANDIDATE" in r.stdout
    assert "CONFIRMED" not in r.stdout
    assert "expired/revoked token still honored" in r.stdout  # net-neue Dimension live

    artifact = json.load(open(os.path.join(out, "trust_matrix_findings.json")))
    assert artifact["control_ok"] is True
    # anon muss blocken, A + expired = CANDIDATE
    by = {row["label"]: row for row in artifact["rows"]}
    assert by["anon"]["verdict"] == "blocked"
    assert by["TenantA"]["verdict"] == "CANDIDATE"
    assert by["TenantB-expired"]["verdict"] == "CANDIDATE"
    # PII-Gate: kein Klartext-Email im ganzen Artefakt
    assert "bob@example.com" not in json.dumps(artifact)
