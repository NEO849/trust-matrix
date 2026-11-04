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


VALID_KINDS = {"owner", "acct", "anon", "expired"}


def cold_witness_pair(baseline, legs):
    """Kontrastpaar für das erste CANDIDATE-Leg: das gelingende Angreifer-Leg
    plus die Besitzer-Kontrolle (owner holt eigenes Objekt = 200). Sonst None.

    Genau die Before/After-Evidenz, die cold-witness / skeptical-validator braucht.
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
        lines.append("[UNGÜLTIG] Kontrolle fehlgeschlagen (owner bekam eigenes Objekt nicht = 200).")
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
        lines.append(f"{len(cands)} CANDIDATE — cold-witness/skeptical-validator bestätigen, dann /submit-gate. KEIN Auto-Submit.")
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
    ap = argparse.ArgumentParser(description="Identity-Matrix Trust-Boundary-Differenz-Harness (GET-only, read-only)")
    ap.add_argument("--identities", required=True, help="identities.conf (label|kind|auth|cookie je Zeile)")
    ap.add_argument("--base", required=True, help="API-Basis, z.B. https://api.target.com/v1")
    ap.add_argument("--path", required=True, help="Pfad des FREMDEN Objekts, z.B. /account/123")
    ap.add_argument("--rate", type=float, default=2.0, help="Sekunden zwischen Requests (sanft)")
    ap.add_argument("--out", default="trust_matrix_out", help="Ausgabe-Verzeichnis")
    ap.add_argument("--go", action="store_true", help="LIVE senden (sonst Dry-Run, sendet NICHTS)")
    a = ap.parse_args()

    identities = load_identities(a.identities)
    owners = [i for i in identities if i["kind"] == "owner"]
    if len(owners) != 1:
        print(f"[FEHLER] genau EINE owner-Identität nötig (= Kontrolle), gefunden: {len(owners)}")
        sys.exit(2)
    owner_label = owners[0]["label"]

    print(f"== Trust-Matrix == {a.base.rstrip('/')}{a.path}")
    print(f"   Identitäten ({len(identities)}): " + ", ".join(f"{i['label']}({i['kind']})" for i in identities))
    print(f"   owner/Kontrolle: {owner_label} | rate={a.rate}s | {'LIVE' if a.go else 'DRY-RUN'}")

    if not a.go:
        print("\n[DRY-RUN] Plan (sendet NICHTS):")
        print(f"  Für JEDE Identität: GET {a.base.rstrip('/')}{a.path} mit ihren Credentials")
        print(f"  owner={owner_label} MUSS 200 liefern (Kontrolle). Jedes andere Leg MUSS blocken.")
        print("  200 + geleakte owner-Werte/Schema = CANDIDATE (nie CONFIRMED). expired-200 = Token-Invalidierung.")
        print("\n  Account-Anlage + echte Sessions = deine Hände (AUP). Danach dieselbe Zeile mit --go.")
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
    print(f"\nArtefakt (PII-redacted): {outf}")


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
    Verdikt ist NIE 'CONFIRMED' (Server-Confirm folgt extern über skeptical-validator).
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
            note = "expired/revoked token still honored — broken token invalidation"

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
