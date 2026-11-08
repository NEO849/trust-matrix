# Safety & Responsible Use

trust-matrix is an authorization-testing tool for **authorized** security work only:
your own systems, or targets covered by a bug-bounty / penetration-test scope you are
permitted to test.

## Built-in guardrails (by design, not optional)

- **GET-only.** It never sends write methods. It cannot create, modify, or delete data.
- **Dry-run by default.** Without `--go` it prints the plan and sends nothing.
- **No account creation.** It consumes sessions *you* provide. It never signs up, solves
  CAPTCHAs, or touches anti-fraud-protected flows (AUP risk).
- **PII is never written in clear text.** Response bodies are redacted to a length + short
  SHA-1 hash. The diff shows leaked PII *field paths*, never their values.
- **No "confirmed" verdict.** The strongest label is `CANDIDATE`. Server-side confirmation
  and the decision to report are always yours.
- **No auto-submit.** Output is a reviewable artifact; nothing is sent anywhere.

## What you are responsible for

- Having permission to test the target and the accounts/sessions you supply.
- Request rate: the default is one request every 2s — keep it gentle.
- Reproducing a `CANDIDATE` independently before disclosing it.

## Threat model (what it does and does not do)

trust-matrix helps you *detect* a broken authorization boundary and produce clean,
triage-safe evidence. It does **not** find objects for you, does **not** prove exploitability
beyond a single GET, and a `CANDIDATE` is a hypothesis until you reproduce it against a
known-owned object with a working control leg.
