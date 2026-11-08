# trust-matrix

**Replay one request across many identities — see where the trust boundary breaks.**

A focused CLI for authorization (BOLA / IDOR) testing that produces *triage-safe evidence*,
not noisy "CONFIRMED!" claims. You give it one GET operation and a small matrix of identities;
it replays the request as each identity and builds a cross-identity diff table with an honest
verdict.

> GET-only · dry-run by default · PII redacted · never prints "CONFIRMED", only "CANDIDATE".

## The problem

Broken Object Level Authorization (BOLA) is [OWASP API Security #1](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/).
Finding it means replaying the same request as different users and comparing responses — which
by hand is fiddly and error-prone:

- You need several real accounts and have to juggle their sessions.
- A `200 OK` is easy to misread: the data might just be **public**, not cross-tenant — a false
  positive that burns your credibility at triage.
- Easy-to-forget dimensions (an expired or **revoked** token that still works) go untested.

## What it does

Given one operation and an identity matrix, it replays once per identity and diffs every leg
against the **owner control**:

```
== Trust-Matrix :: GET /v1/account/123 ==
LABEL              KIND     STATUS SCHEMA  VALUES  PII-LEAK  VERDICT
--------------------------------------------------------------------
anon               anon     403    0%      0%      0         blocked
TenantA            acct     200    100%    100%    4         CANDIDATE
TenantB-expired    expired  200    100%    100%    4         CANDIDATE  <- expired token still honored — broken token expiry enforcement
TenantB-revoked    revoked  200    100%    100%    4         CANDIDATE  <- server-issued token still honored after revocation/logout — broken session invalidation

3 CANDIDATE — reproduce independently and verify server-side before reporting. No auto-submit.
```

The **owner** leg is the control: the owner fetching its own object must return `200`. That
proves the object is real and owned — so *candidate + control* is automatic before/after
evidence. With `--report md` you get a submittable Markdown write-up (redacted) out of the box.

## Why it's different (honestly)

Plenty of tools replay requests across accounts (Burp's Autorize / AuthMatrix, and several
CLIs). trust-matrix isn't trying to beat them at discovery. Its edge is **evidence discipline**
and **the revocation dimension**:

| | trust-matrix | Typical BOLA tools |
|---|---|---|
| Verdict wording | **CANDIDATE** only (you confirm) | often hard "Confirmed" / "Critical" |
| PII in output | actively **redacted** (length + hash) | frequently raw body / headers |
| Public-data false positive | auto-downgraded to `public-data-review` | varies |
| Revoked-token leg | **yes** — issue → revoke/logout → replay | essentially none |
| Interface | CLI (scriptable, CI-friendly) | often GUI / Burp extension |

Two of these — **"CANDIDATE not CONFIRMED" wording** and **active PII redaction** — are, at the
time of writing, near-universal gaps in comparable open tools. The **public-data auto-downgrade**
is a quality feature, not a unique one (a few tools do it too); it's here because it kills the
most common authorization false positive.

## What it is NOT

- **Not a discovery tool.** You tell it which object and which identities. It won't crawl your
  app or guess IDs.
- **Not a scanner.** One operation per run, by design. Sharp, not broad.
- **Not an exploit or auto-submitter.** GET-only, dry-run by default, and it never decides a bug
  is real — that is your job.

## Install

```
git clone <repo-url>
cd trust-matrix
pip install -r requirements.txt   # just: requests
```

## Quickstart

1. Create your identity matrix (copy `identities.conf.sample`):

```
TenantB          | owner   | Bearer <OWNER_TOKEN>    |
TenantA          | acct    | Bearer <OTHER_TOKEN>    |
anon             | anon    |                         |
TenantB-revoked  | revoked | Bearer <REVOKED_TOKEN>  |
```

2. Dry-run first (sends nothing — shows the plan):

```
python3 trust_matrix.py --identities identities.conf \
  --base https://api.target.com/v1 --path /account/123
```

3. Go live (read-only GETs) and emit a submittable report:

```
python3 trust_matrix.py --identities identities.conf \
  --base https://api.target.com/v1 --path /account/123 --go --report md
```

Outputs land in `trust_matrix_out/`: a PII-redacted `trust_matrix_findings.json` and, with
`--report md`, a `trust_matrix_report.md` you can adapt into a disclosure.

## Identity kinds

| kind | meaning |
|---|---|
| `owner` | the control — fetches its **own** object, must return 200 (exactly one required) |
| `acct` | a second, separate account (the attacker identity) |
| `anon` | no credentials — if this leg also gets the data, it is **public** → auto-downgrade |
| `expired` | a token whose lifetime has passed (tests expiry enforcement) |
| `revoked` | a token you revoked / logged out server-side (tests session invalidation) |

## How it decides

- **blocked** — leg got a non-200 or only an error object. Good: the boundary held.
- **CANDIDATE** — leg got 200 + the owner's data (value overlap > 60% or a leaked PII value).
  Worth confirming.
- **accessible-review** — leg got 200 but *its own* data, not the owner's. Not cross-tenant.
- **public-data-review** — the anon leg also got the data → likely public (working as intended).
- **invalid-no-control** — the owner leg failed, so no claim can be made. Fix it and re-run.

## Responsible use

Authorized testing only. You supply sessions for accounts you control; trust-matrix never
creates accounts (anti-fraud / AUP), only sends GET, and defaults to dry-run. See
[`SAFETY.md`](SAFETY.md).

## License

[MIT](LICENSE).
