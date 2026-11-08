#!/usr/bin/env python3
"""
trust_matrix.py — Identity-Matrix Trust-Boundary-Differenz-Harness.

Replayt EINE GET-Operation über eine Identitäts-Matrix {anon, Acct-A, Acct-B,
expired} und baut eine strukturierte Kreuz-Diff-Tabelle: jedes Angreifer-Leg wird
gegen die owner-Baseline (= Kontrolle, der/die Besitzer:in holt das eigene Objekt)
verglichen.

Reine Vergleichslogik ist offline testbar (build_matrix_table). Der Netz-Replay
(CLI, --go) ist davon getrennt und wird in den Offline-Tests NICHT ausgeführt.
"""
from diff_core import (
    flatten, extract_schema, find_pii_fields,
    schema_similarity, value_overlap, detect_structured_data,
)


VALID_KINDS = {"owner", "acct", "anon", "expired", "revoked"}


def cold_witness_pair(baseline, legs):
    """Kontrastpaar für das erste CANDIDATE-Leg: das gelingende Angreifer-Leg
    plus die Besitzer-Kontrolle (owner holt eigenes Objekt = 200). Sonst None.

    Genau die Before/After-Evidenz, die eine saubere, unabhängige Verifikation braucht.
    """
    table = build_matrix_table(baseline, legs)
    by_label = {lg["label"]: lg for lg in legs}
    for row in table["rows"]:
        if row["verdict"] == "CANDIDATE":
            return {"attacker": by_label[row["label"]], "control": baseline}
    return None


def load_identities(path):
    """Liest die Identitäts-Matrix: eine Identität je Zeile, '|'-getrennt:
        label | kind | auth | cookie
    Kommentare (#) und Leerzeilen werden ignoriert. kind muss gültig sein.
    """
    identities = []
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            label = parts[0] if len(parts) > 0 else ""
            kind = parts[1] if len(parts) > 1 else ""
            auth = parts[2] if len(parts) > 2 else ""
            cookie = parts[3] if len(parts) > 3 else ""
            if kind not in VALID_KINDS:
                raise ValueError(f"unbekannte kind {kind!r} (erlaubt: {sorted(VALID_KINDS)})")
            identities.append({"label": label, "kind": kind, "auth": auth, "cookie": cookie})
    return identities


def format_table(table, op_label):
    """Rendert die Kreuz-Diff-Matrix als lesbare Text-Tabelle.

    Druckt NIE 'CONFIRMED' — nur Kandidaten; Server-Confirm folgt extern.
    """
    lines = [f"== Trust-Matrix :: {op_label} =="]
    if not table["control_ok"]:
        lines.append("[INVALID] Control failed: the owner did not retrieve its own object as HTTP 200.")
        return "\n".join(lines)

    header = f"{'LABEL':<18} {'KIND':<8} {'STATUS':<6} {'SCHEMA':<7} {'VALUES':<7} {'PII-LEAK':<9} VERDICT"
    lines.append(header)
    lines.append("-" * len(header))
    for r in table["rows"]:
        lines.append(
            f"{r['label']:<18} {r['kind']:<8} {r['status']:<6} "
            f"{r['schema_sim']:<7.0%} {r['value_overlap']:<7.0%} "
            f"{len(r['pii_leaked']):<9} {r['verdict']}"
            + (f"  <- {r['note']}" if r.get("note") else "")
        )
    cands = [r for r in table["rows"] if r["verdict"] == "CANDIDATE"]
    if cands:
        lines.append("")
        lines.append(f"{len(cands)} CANDIDATE — reproduce independently and verify server-side before reporting. No auto-submit.")
    return "\n".join(lines)


def format_report_md(table, cold_witness, operation):
    """Einreichfertiger Markdown-Report aus einem Lauf.

    Before/After cold-witness-Paar, PII immer redacted, Verdikt NIE 'CONFIRMED'
    (nur CANDIDATE) — der Nutzer bekommt einen reviewbaren Entwurf, kein Auto-Submit.
    """
    lines = [f"# Authorization Trust-Boundary Report — {operation}", ""]

    if not table["control_ok"]:
        lines += [
            "> **Invalid run — no valid control.** The owner identity did not retrieve "
            "its own object (HTTP 200 + structured data), so no cross-identity claim "
            "can be made. Fix the owner leg and re-run.",
            "",
        ]
        return "\n".join(lines)

    cands = [r for r in table["rows"] if r["verdict"] == "CANDIDATE"]
    lines += [
        "> Candidate finding — not confirmed. Reproduce independently and run "
        "server-side verification before reporting.",
        "",
        "## Verdict",
        f"{len(cands)} CANDIDATE across {len(table['rows'])} non-owner identities tested.",
        "",
        "## Cross-identity matrix",
        "| Identity | Kind | Status | Schema | Values | PII-leak | Verdict |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in table["rows"]:
        lines.append(
            f"| {r['label']} | {r['kind']} | {r['status']} | "
            f"{r['schema_sim']:.0%} | {r['value_overlap']:.0%} | "
            f"{len(r['pii_leaked'])} | {r['verdict']} |"
        )
    lines.append("")

    if cold_witness:
        ctrl, atk = cold_witness["control"], cold_witness["attacker"]
        lines += [
            "## Evidence — cold-witness pair",
            f"**Control** (owner `{ctrl['label']}` fetches own object) — proves the object is real:",
            f"- HTTP {ctrl['status']}, body `{redact(ctrl['body'])}`",
            "",
            f"**Candidate** (`{atk['label']}`, kind `{atk['kind']}`, fetches the same object):",
            f"- HTTP {atk['status']}, body `{redact(atk['body'])}`",
            "",
            "The control proves the object belongs to the owner identity; the candidate "
            "leg obtained the same data anyway.",
            "",
        ]

    leaked = []
    for r in table["rows"]:
        for p in r["pii_leaked"]:
            if p not in leaked:
                leaked.append(p)
    if leaked:
        lines += ["## Leaked owner PII fields (paths only, values redacted)"]
        lines += [f"- {p}" for p in leaked]
        lines.append("")

    notes = [r for r in table["rows"] if r.get("note")]
    if notes:
        lines += ["## Notes"]
        lines += [f"- `{r['label']}`: {r['note']}" for r in notes]
        lines.append("")

    lines += [
        "## Reproduction",
        f"1. As the owner identity, `{operation}` -> HTTP 200 (control: object exists and is owned).",
        f"2. As each non-owner identity, replay the same `{operation}` with that identity's credentials.",
        "3. A non-owner identity returning HTTP 200 with the owner's data is the candidate.",
        "",
        "---",
        "_Generated by trust-matrix — GET-only, dry-run by default, PII redacted. "
        "Verdict is CANDIDATE only; independent server-side verification required._",
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# Netz-Replay + CLI (gated; in Offline-Unit-Tests NICHT ausgeführt)
# ─────────────────────────────────────────────────────────────

def hdrs(auth, cookie, ua="trust-matrix/1.0 (authorized-test)"):
    h = {"Accept": "application/json", "User-Agent": ua}
    if auth:
        h["Authorization"] = auth
    if cookie:
        h["Cookie"] = cookie
    return h


def redact(v):
    """PII-Redaction: nie Klartext. Nur Länge + kurzer Hash (Herkunft: bola_probe.py)."""
    import json as _json
    import hashlib
    s = _json.dumps(v, sort_keys=True, default=str)
    return f"<{len(s)}B sha1:{hashlib.sha1(s.encode()).hexdigest()[:10]}>"


def replay(base, path, identities, rate=1.0, timeout=12, ua="trust-matrix/1.0 (authorized-test)"):
    """GET-only Replay EINER Operation über alle Identitäten. Gibt Legs zurück."""
    import time
    import requests
    sess = requests.Session()
    url = base.rstrip("/") + path
    legs = []
    for idn in identities:
        auth = idn["auth"] or None
        cookie = idn["cookie"] or None
        try:
            r = sess.get(url, headers=hdrs(auth, cookie, ua), timeout=timeout)
            try:
                body = r.json()
            except Exception:
                body = None
            status = r.status_code
        except Exception:
            status, body = 0, None
        legs.append({"label": idn["label"], "kind": idn["kind"], "status": status, "body": body})
        time.sleep(rate)
    return legs


def main():
    import argparse
    import json
    import os
    import sys
    ap = argparse.ArgumentParser(description="Identity-matrix trust-boundary differential tester (GET-only, read-only)")
    ap.add_argument("--identities", required=True, help="identities.conf (label|kind|auth|cookie per line)")
    ap.add_argument("--base", required=True, help="API base, e.g. https://api.target.com/v1")
    ap.add_argument("--path", required=True, help="path of the object to test, e.g. /account/123")
    ap.add_argument("--rate", type=float, default=2.0, help="seconds between requests (be gentle)")
    ap.add_argument("--out", default="trust_matrix_out", help="output directory")
    ap.add_argument("--report", choices=["none", "md"], default="none",
                    help="also write a submittable Markdown report (PII-redacted)")
    ap.add_argument("--go", action="store_true", help="send LIVE (otherwise dry-run, sends NOTHING)")
    a = ap.parse_args()

    identities = load_identities(a.identities)
    owners = [i for i in identities if i["kind"] == "owner"]
    if len(owners) != 1:
        print(f"[ERROR] exactly ONE owner identity required (the control); found: {len(owners)}")
        sys.exit(2)
    owner_label = owners[0]["label"]

    print(f"== Trust-Matrix == {a.base.rstrip('/')}{a.path}")
    print(f"   identities ({len(identities)}): " + ", ".join(f"{i['label']}({i['kind']})" for i in identities))
    print(f"   owner/control: {owner_label} | rate={a.rate}s | {'LIVE' if a.go else 'DRY-RUN'}")

    if not a.go:
        print("\n[DRY-RUN] plan (sends NOTHING):")
        print(f"  for EACH identity: GET {a.base.rstrip('/')}{a.path} with its own credentials")
        print(f"  owner={owner_label} MUST return 200 (control). Every other leg MUST be blocked.")
        print("  200 + leaked owner values/schema = CANDIDATE (never a confirmed verdict). A 200 on the")
        print("  expired/revoked leg = broken token invalidation.")
        print("\n  You supply the sessions; trust-matrix never creates accounts (AUP). Re-run with --go.")
        sys.exit(0)

    legs = replay(a.base, a.path, identities, rate=a.rate)
    baseline = next(lg for lg in legs if lg["label"] == owner_label)
    attackers = [lg for lg in legs if lg["label"] != owner_label]
    table = build_matrix_table(baseline, attackers)
    print()
    print(format_table(table, f"GET {a.path}"))

    pair = cold_witness_pair(baseline, attackers)
    os.makedirs(a.out, exist_ok=True)
    artifact = {
        "operation": f"GET {a.base.rstrip('/')}{a.path}",
        "control_ok": table["control_ok"],
        "rows": table["rows"],  # enthält nur Pfade/Risiko, KEINE PII-Werte
        "legs_redacted": [{"label": lg["label"], "kind": lg["kind"], "status": lg["status"],
                           "body": redact(lg["body"]) if lg["body"] is not None else None} for lg in legs],
        "cold_witness": None if not pair else {
            "attacker": {"label": pair["attacker"]["label"], "kind": pair["attacker"]["kind"],
                         "status": pair["attacker"]["status"], "body": redact(pair["attacker"]["body"])},
            "control": {"label": pair["control"]["label"], "status": pair["control"]["status"],
                        "body": redact(pair["control"]["body"])},
        },
    }
    outf = os.path.join(a.out, "trust_matrix_findings.json")
    with open(outf, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifact (PII-redacted): {outf}")

    if a.report == "md":
        report_md = format_report_md(table, pair, f"GET {a.base.rstrip('/')}{a.path}")
        repf = os.path.join(a.out, "trust_matrix_report.md")
        with open(repf, "w") as f:
            f.write(report_md)
        print(f"Report (submittable, PII-redacted): {repf}")


def _leaked_pii(baseline_body, leg_body):
    """Baseline-PII-WERTE, die im Leg-Body wieder auftauchen → geleakte Felder.

    Gibt Pfade (mit Risikostufe) zurück, nie die Klartext-Werte selbst.
    """
    base_flat = flatten(baseline_body)
    leg_values = [str(v) for v in flatten(leg_body).values()]
    leaked = []
    for path, (risk, val) in find_pii_fields(base_flat).items():
        if val in (None, "", 0):
            continue
        if str(val) in leg_values:
            leaked.append(f"{path} [{risk}]")
    return leaked


def build_matrix_table(baseline, legs):
    """Vergleicht jedes Angreifer-Leg gegen die owner-Baseline.

    baseline / legs: {"label","kind","status","body"} — body = dict/list/None.
    Rückgabe: {"control_ok": bool, "rows": [ {label,kind,status,schema_sim,
               value_overlap,pii_leaked,verdict}, ... ]}.
    Verdikt ist NIE 'CONFIRMED' (Server-Confirm folgt extern, unabhängige Verifikation).
    """
    control_ok = baseline["status"] == 200 and detect_structured_data(baseline["body"])
    base_body = baseline["body"]
    base_schema = extract_schema(base_body) if control_ok else set()
    base_flat = flatten(base_body) if control_ok else {}

    rows = []
    for lg in legs:
        status, body = lg["status"], lg["body"]
        accessible = status == 200 and detect_structured_data(body)

        if not control_ok:
            verdict, sim, overlap, leaked = "invalid-no-control", 0.0, 0.0, []
        elif not accessible:
            verdict, sim, overlap, leaked = "blocked", 0.0, 0.0, []
        else:
            sim = schema_similarity(base_schema, extract_schema(body))
            overlap = value_overlap(base_flat, flatten(body))
            leaked = _leaked_pii(base_body, body)
            verdict = "CANDIDATE" if (leaked or overlap > 0.6) else "accessible-review"

        note = ""
        if verdict == "CANDIDATE" and lg["kind"] == "expired":
            note = "expired token still honored — broken token expiry enforcement"
        elif verdict == "CANDIDATE" and lg["kind"] == "revoked":
            note = ("server-issued token still honored after revocation/logout "
                    "— broken session invalidation")

        rows.append({
            "label": lg["label"], "kind": lg["kind"], "status": status,
            "schema_sim": sim, "value_overlap": overlap,
            "pii_leaked": leaked, "verdict": verdict, "note": note,
        })

    # Anti-WAI-Quercheck: holt das anon-Leg selbst die Baseline-Daten, sind sie
    # öffentlich → jeder CANDIDATE ist mit hoher Wahrscheinlichkeit WAI (kein Boundary-Bruch).
    public = any(r["kind"] == "anon" and r["verdict"] == "CANDIDATE" for r in rows)
    if public:
        for r in rows:
            if r["verdict"] == "CANDIDATE":
                r["verdict"] = "public-data-review"
                r["note"] = "anon leg also returns this data — data appears public (WAI likely), not cross-tenant"

    return {"control_ok": control_ok, "rows": rows}


if __name__ == "__main__":
    main()
