# Contributing

Thanks for looking. trust-matrix is deliberately small and sharp — contributions that keep it that
way are very welcome.

## Principles (please keep these)

- **Test-first.** Every behavior change ships with a test. The suite must stay green
  (`python -m pytest -q` → 20+ passed). A new feature starts with a failing test.
- **The guardrails are not negotiable.** GET-only, dry-run by default, no account creation, PII
  never in clear text, verdict is `CANDIDATE` (never "CONFIRMED"), no auto-submit. A change that
  weakens any of these will not be merged.
- **Stay in scope.** This is an *evidence* tool, not a discovery tool or a scanner. Object/identity
  discovery, write methods, and auto-submission are out of scope by design.
- **Honesty over hype.** Claims in the README must be backed by the code and tests. No "0% false
  positives", no inflated differentiators.

## Workflow

1. Fork and branch.
2. Write the failing test, then the minimal code to pass it.
3. `python -m pytest -q` — all green, no new warnings.
4. Open a PR describing the behavior change and the test that proves it.

## Good first contributions

- Additional response-format support in the diff core (e.g. structured non-JSON bodies).
- More identity-kind test fixtures.
- Report-format polish (`--report md`).

Found a security issue in the tool itself? Please open an issue describing the class of problem
rather than a working exploit.
