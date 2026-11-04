#!/usr/bin/env python3
"""
diff_core.py — generische, response-agnostische JSON-Diff-Primitive.

Herkunft: sauber kopiert aus dem privaten Arsenal (idor_analyzer.py), hier als
eigenständige, OSS-fähige Bibliothek isoliert. Enthält KEINE Target-Daten, keine
PII, keine Credentials — nur reine Vergleichslogik. Bewusst unverändert gehalten,
damit das Verhalten bit-genau dem bewährten Original entspricht.

Alles hier ist rein (keine Netz-/Datei-IO) und damit offline testbar.
"""
from typing import Any

# ─────────────────────────────────────────────────────────────
# PII-Felder nach Risikostufe (Feldnamen-Heuristik)
# ─────────────────────────────────────────────────────────────

PII_HIGH = {
    'email', 'email_address', 'mail',
    'phone', 'phone_number', 'mobile', 'telephone',
    'ssn', 'social_security', 'tax_id', 'vat_id',
    'credit_card', 'card_number', 'cvv', 'pan',
    'password', 'passwd', 'secret', 'token',
    'bank_account', 'iban', 'routing_number',
    'dob', 'date_of_birth', 'birth_date',
    'passport', 'drivers_license', 'national_id',
}

PII_MEDIUM = {
    'name', 'full_name', 'first_name', 'last_name', 'username', 'display_name',
    'address', 'street', 'city', 'zip', 'postal_code', 'country',
    'ip_address', 'ip', 'device_id',
    'balance', 'amount', 'total', 'price', 'payment',
    'order_id', 'transaction_id', 'invoice_id',
    'user_id', 'account_id', 'customer_id', 'seller_id', 'buyer_id',
    'profile_picture', 'avatar',
    'location', 'latitude', 'longitude', 'coordinates',
}

PII_LOW = {
    'id', 'uid', 'uuid', 'created_at', 'updated_at',
    'status', 'type', 'role', 'permissions', 'scope',
    'preferences', 'settings', 'config',
}

ALL_PII = PII_HIGH | PII_MEDIUM | PII_LOW


def flatten(obj: Any, prefix: str = "") -> dict:
    """Alle Blatt-Werte eines JSON-Objekts mit Pfad-Keys."""
    result = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                result.update(flatten(v, path))
            else:
                result[path] = v
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            result.update(flatten(item, f"{prefix}[{i}]"))
    else:
        result[prefix] = obj
    return result


def extract_schema(obj: Any, prefix: str = "") -> set:
    """Nur die Feld-Namen (Schema) ohne Werte."""
    keys = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            keys.add(path)
            keys.update(extract_schema(v, path))
    elif isinstance(obj, list) and obj:
        keys.update(extract_schema(obj[0], f"{prefix}[]"))
    return keys


def find_pii_fields(flat: dict) -> dict:
    """Findet PII-Felder und bewertet sie. {pfad: (risk, value)}"""
    found = {}
    for path, value in flat.items():
        key_lower = path.split('.')[-1].lower().rstrip('[]0123456789')
        if key_lower in PII_HIGH:
            found[path] = ('HIGH', value)
        elif key_lower in PII_MEDIUM:
            found[path] = ('MEDIUM', value)
        elif key_lower in PII_LOW:
            found[path] = ('LOW', value)
    return found


def schema_similarity(schema_a: set, schema_b: set) -> float:
    """Jaccard-Ähnlichkeit zweier Schemata."""
    if not schema_a or not schema_b:
        return 0.0
    intersection = schema_a & schema_b
    union = schema_a | schema_b
    return len(intersection) / len(union)


def value_overlap(flat_a: dict, flat_b: dict) -> float:
    """Anteil identischer Werte bei gemeinsamen Feldern."""
    common_keys = set(flat_a.keys()) & set(flat_b.keys())
    if not common_keys:
        return 0.0
    matches = sum(1 for k in common_keys if flat_a[k] == flat_b[k])
    return matches / len(common_keys)


def has_value_in_response(value: Any, flat: dict) -> bool:
    """Prüft ob ein bestimmter Wert irgendwo in der Response vorkommt."""
    if value is None:
        return False
    str_val = str(value)
    return any(str(v) == str_val for v in flat.values())


def detect_structured_data(obj: Any) -> bool:
    """Ist das ein echtes Datenobjekt (nicht nur eine Fehlermeldung)?"""
    if not isinstance(obj, (dict, list)):
        return False
    if isinstance(obj, list) and len(obj) == 0:
        return False
    if isinstance(obj, dict):
        error_only = {'error', 'message', 'code', 'status', 'detail', 'errors'}
        keys = set(k.lower() for k in obj.keys())
        if keys.issubset(error_only):
            return False
    return True
