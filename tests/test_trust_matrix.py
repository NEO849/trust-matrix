"""
Offline-Tests für den Identity-Matrix Trust-Boundary-Harness.
Kein Live-Target: alle Legs sind handgebaute, erfasste Antworten (Fixtures).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trust_matrix import (  # noqa: E402
    build_matrix_table, cold_witness_pair, load_identities, format_table,
)


def leg(label, kind, status, body):
    return {"label": label, "kind": kind, "status": status, "body": body}


# Fixture: zwei Fake-Tenants, KEINE echten Daten.
TENANT_B = {"id": 123, "email": "bob@example.com", "name": "Bob", "balance": 500}


def test_clean_bola_candidate_is_flagged_candidate_never_confirmed():
    # B holt B's eigenes Objekt = Kontrolle (200, definiert die echten Daten).
    baseline = leg("TenantB", "owner", 200, TENANT_B)
    # A holt MIT A's Token B's Objekt und bekommt B's Daten zurück → BOLA-Kandidat.
    legs = [leg("TenantA", "acct", 200, dict(TENANT_B))]

    table = build_matrix_table(baseline, legs)

    assert table["control_ok"] is True, "Kontrolle (owner=200, strukturiert) muss gelten"

    a_row = next(r for r in table["rows"] if r["label"] == "TenantA")
    assert a_row["verdict"] == "CANDIDATE"
    assert a_row["value_overlap"] == 1.0
    assert any("email" in p for p in a_row["pii_leaked"]), "geleaktes email-Feld muss erscheinen"

    # Hard-Gate: NIE 'CONFIRMED' aussprechen — nur Kandidat, Server-Confirm folgt extern.
    assert all(r["verdict"] != "CONFIRMED" for r in table["rows"])


def test_anon_leg_blocked_is_not_candidate():
    baseline = leg("TenantB", "owner", 200, TENANT_B)
    legs = [leg("anon", "anon", 403, {"error": "forbidden"})]
    table = build_matrix_table(baseline, legs)
    row = table["rows"][0]
    assert row["verdict"] == "blocked"
    assert row["pii_leaked"] == []


def test_accessible_but_own_data_is_review_not_candidate():
    """FP-Wächter: 200 mit den EIGENEN Daten des Angreifers (nicht B's) = kein BOLA."""
    baseline = leg("TenantB", "owner", 200, TENANT_B)
    own = {"id": 999, "email": "alice@example.com", "name": "Alice", "balance": 10}
    legs = [leg("TenantA", "acct", 200, own)]
    table = build_matrix_table(baseline, legs)
    row = table["rows"][0]
    assert row["value_overlap"] == 0.0
    assert row["pii_leaked"] == []
    assert row["verdict"] == "accessible-review"


def test_no_control_marks_rows_invalid():
    """Wenn der/die Besitzer:in das eigene Objekt NICHT bekommt, ist der Test ungültig."""
    baseline = leg("TenantB", "owner", 404, {"error": "not found"})
    legs = [leg("TenantA", "acct", 200, dict(TENANT_B))]
    table = build_matrix_table(baseline, legs)
    assert table["control_ok"] is False
    assert all(r["verdict"] == "invalid-no-control" for r in table["rows"])


def test_expired_token_still_honored_is_flagged_candidate_with_note():
    """Net-neue Dimension: abgelaufener/entzogener Token liefert noch Daten
    → kaputte Token-Invalidierung. Eigene Notiz, damit die Bug-Klasse sichtbar ist."""
    baseline = leg("TenantB", "owner", 200, TENANT_B)
    legs = [leg("TenantB-expired", "expired", 200, dict(TENANT_B))]
    table = build_matrix_table(baseline, legs)
    row = table["rows"][0]
    assert row["verdict"] == "CANDIDATE"
    assert "expired" in row.get("note", "").lower()


def test_format_table_renders_rows_and_never_says_confirmed():
    baseline = leg("TenantB", "owner", 200, TENANT_B)
    legs = [leg("TenantA", "acct", 200, dict(TENANT_B))]
    table = build_matrix_table(baseline, legs)
    out = format_table(table, "GET /account/123")
    assert "TenantA" in out
    assert "CANDIDATE" in out
    assert "CONFIRMED" not in out   # Hard-Gate im Output


def test_public_endpoint_downgrades_candidate_when_anon_also_accessible():
    """Anti-WAI: holt anon selbst 200 + dieselben Daten, sind sie öffentlich →
    acct/expired-CANDIDATE wird auf 'public-data-review' herabgestuft (kein BOLA)."""
    baseline = leg("TenantB", "owner", 200, TENANT_B)
    legs = [
        leg("anon", "anon", 200, dict(TENANT_B)),
        leg("TenantA", "acct", 200, dict(TENANT_B)),
    ]
    table = build_matrix_table(baseline, legs)
    by = {r["label"]: r for r in table["rows"]}
    assert by["TenantA"]["verdict"] == "public-data-review"
    assert by["anon"]["verdict"] == "public-data-review"
    assert all(r["verdict"] != "CANDIDATE" for r in table["rows"])


def test_blocked_anon_keeps_real_bola_candidate():
    """Wächter: blockiertes anon (403) = Daten NICHT öffentlich → acct bleibt CANDIDATE."""
    baseline = leg("TenantB", "owner", 200, TENANT_B)
    legs = [
        leg("anon", "anon", 403, {"error": "forbidden"}),
        leg("TenantA", "acct", 200, dict(TENANT_B)),
    ]
    table = build_matrix_table(baseline, legs)
    by = {r["label"]: r for r in table["rows"]}
    assert by["TenantA"]["verdict"] == "CANDIDATE"


def test_cold_witness_pair_extracted_for_first_candidate():
    """Das Kontrastpaar (Angreifer-Leg gelingt + Kontrolle) fällt automatisch raus."""
    baseline = leg("TenantB", "owner", 200, TENANT_B)
    legs = [
        leg("anon", "anon", 403, {"error": "forbidden"}),
        leg("TenantA", "acct", 200, dict(TENANT_B)),
    ]
    pair = cold_witness_pair(baseline, legs)
    assert pair is not None
    assert pair["attacker"]["label"] == "TenantA"   # das gelingende Angreifer-Leg
    assert pair["control"]["label"] == "TenantB"     # die Besitzer-Kontrolle


def test_cold_witness_pair_none_when_nothing_candidate():
    baseline = leg("TenantB", "owner", 200, TENANT_B)
    legs = [leg("anon", "anon", 403, {"error": "forbidden"})]
    assert cold_witness_pair(baseline, legs) is None


def test_load_identities_parses_matrix_rows(tmp_path):
    conf = tmp_path / "identities.conf"
    conf.write_text(
        "# label | kind | auth | cookie\n"
        "TenantB | owner | Bearer BBB |\n"
        "anon | anon | |\n"
    )
    ids = load_identities(str(conf))
    assert len(ids) == 2
    assert ids[0] == {"label": "TenantB", "kind": "owner", "auth": "Bearer BBB", "cookie": ""}
    assert ids[1]["kind"] == "anon"
    assert ids[1]["auth"] == ""


def test_load_identities_rejects_unknown_kind(tmp_path):
    conf = tmp_path / "bad.conf"
    conf.write_text("X | superuser | Bearer Z |\n")
    try:
        load_identities(str(conf))
        assert False, "unbekannte kind muss abgelehnt werden"
    except ValueError:
        pass
