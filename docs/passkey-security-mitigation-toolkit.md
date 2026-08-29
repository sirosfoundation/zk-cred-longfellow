# Mitigating the Findings of "The State of Passkeys" (USENIX Security '26)

Analysis of [Jannett et al., *The State of Passkeys: Studying the Adoption and Security of
Passkeys on the Web*](https://www.usenix.org/conference/usenixsecurity26/presentation/jannett),
35th USENIX Security Symposium, with a focus on **what tooling, libraries and software actually
exist to mitigate each finding**.

Artifacts (paper PDF, both tools, the intentionally-vulnerable learning platform):
<https://github.com/RUB-NDS/state-of-passkeys-artifacts> (Zenodo DOI `10.5281/zenodo.17898769`).

---

## 1. What the paper found

The authors built two tools — **PASSKEYS-RADAR** (continuous discovery of passkey-enabled sites;
872 relying parties found, +125% over all community directories combined) and
**PASSKEYS-ATTACKER** (a browser extension plus virtual client/authenticator that intercepts,
decodes, mutates and re-encodes every WebAuthn message). They derived **15 attack types (ATs)** and
**28 detection methods** directly from the mandatory validation steps in the WebAuthn spec
(§7.1/§7.2) and its security considerations (§13.4/§14.6), then ran them against 103 relying
parties (RPs).

**Headline result: all 103 RPs failed at least one mandatory validation. 18 had a critical finding,
53 a high finding.** Counter-intuitively, Tranco top-1k sites were *more* susceptible than
lower-ranked ones — the authors suggest smaller sites benefit from simply using a well-written
third-party library instead of hand-rolling verification.

Two observations drive everything below:

1. **Most of the failures are omitted validation steps, not novel cryptography.** They are exactly
   the class of bug a maintained RP library removes by construction — *if* it is configured
   strictly and *if* the deployment does not defeat it.
2. **The most severe finding (Credential Overwrite, CVSS 9.1) is not a protocol bug at all** — it
   is an RP database-schema bug. No WebAuthn library fixes it for you, and no scanner in the
   ecosystem looks for it. That gap is the single most important takeaway for implementers.

### Findings beyond the attack catalog (§4)

| Finding | Scale |
|---|---|
| Deprecated COSE algorithms requested (ES256/RS256); RSASSA-PKCS1-v1_5 with SHA-1 still requested; 8 sites requested symmetric HMAC algorithms | 207 of 208 sites |
| No re-authentication / confirmation before registering a new passkey | 66% of sites |
| `rpId` upscoped to the registrable domain (exposes to subdomain takeover) | 80 sites (38%) |
| User verification explicitly disabled while used for passwordless login | 17 sites |
| PII (email/username) embedded in the `userId` handle — spec violation (§14.6.1) | 8 sites |
| Signal API (`signalAllAcceptedCredentials`/`signalUnknownCredential`) implemented, so revoked passkeys are cleaned off authenticators | only 7 sites |
| Only a single passkey supported, or no delete path, or delete requires the lost passkey | 25 / 5 / 3 sites |
| Attestation requested (66) but **never enforced** — no site rejected a registration for missing attestation | 0 sites enforce |

---

## 2. Mitigation stack

Six layers. Layers 1–3 remove whole bug classes; 4–5 keep them removed; 6 is the "don't build it"
option.

### Layer 1 — Use a maintained RP library, configured strictly

This is the highest-leverage mitigation: it covers ATs *Signature, Context, User Present, User
Verified, RP ID, Origin, Signature Counter, Backup Eligible/State* and *credId length* — 10 of the
15 attack types — provided you do not weaken the defaults.

| Ecosystem | Library | Notes relevant to the paper's ATs |
|---|---|---|
| Java | [webauthn4j](https://github.com/webauthn4j/webauthn4j) | The most complete on the paper's axes. Explicit `topOrigin(...)`/`topOrigins(...)`/`topOriginPredicate(...)` for the **Framing** AT (102/103 sites failed this); `MaliciousCounterValueHandler` for the **Signature Counter** AT; FIDO MDS metadata module for attestation. Also `webauthn4j-spring-security`. |
| Java | [Yubico java-webauthn-server](https://github.com/Yubico/java-webauthn-server) | Conservative API; strict origin matching by default. |
| Java | Spring Security 6.4+ built-in passkey support | Convenient, but check the origin/top-origin surface it exposes before relying on it. |
| Go | [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) | Rejects cross-origin ceremonies **by default** (`RPAllowCrossOrigin`), and `RPTopOrigins` + `RPTopOriginVerificationMode` (defaults to explicit verification) directly address the **Framing** AT. `Config.RPOrigins` is exact-match. Clone/counter warning surfaced via `Credential.Authenticator`. |
| Rust | [kanidm/webauthn-rs](https://github.com/kanidm/webauthn-rs) | Best "safe by construction" posture. Dangerous behaviour is gated behind opt-in `danger-*` features (`danger-insecure-rs1` for RSA-SHA1, `danger-credential-internals`, `danger-allow-state-serialisation`). Its docs explicitly warn that many WebAuthn fields are UI hints, not security policy — which is precisely the confusion the paper measures. |
| Node/TS | [SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn) | Strong on `expectedOrigin` (array, exact match), `expectedRPID`, `expectedType`, `supportedAlgorithmIDs`. **Gap:** the request to add explicit `clientDataJSON.crossOrigin`/`topOrigin` verification ([#613](https://github.com/MasterKale/SimpleWebAuthn/issues/613)) was closed as not planned — if you use it, add the `crossOrigin`/`topOrigin` check yourself against the decoded client data. Ships a documented [FIDO conformance runner](https://simplewebauthn.dev/docs/advanced/fido-conformance). |
| Python | [duo-labs/py_webauthn](https://github.com/duo-labs/py_webauthn), [Yubico python-fido2](https://github.com/Yubico/python-fido2) | py_webauthn mirrors SimpleWebAuthn's API; same top-origin caveat applies. |
| .NET | [passwordless-lib/fido2-net-lib](https://github.com/passwordless-lib/fido2-net-lib) | Has MDS/metadata support for attestation enforcement. |
| PHP | [web-auth/webauthn-framework](https://github.com/web-auth/webauthn-framework) (Spomky-Labs) | Symfony/Laravel bundles available. |
| Ruby | [cedarcode/webauthn-ruby](https://github.com/cedarcode/webauthn-ruby) | Rails-friendly; check top-origin handling manually. |

**Configuration rules that matter more than the library choice:**

- `expectedOrigin` / `RPOrigins` / `origins(...)` must be an **exact-match allowlist**. Any
  `endsWith()`, suffix, or regex origin check reintroduces the **Origin** AT (40 sites failed).
  Worth a custom [Semgrep](https://semgrep.dev/) rule banning suffix comparison against
  `clientData.origin` in your codebase.
- Set `rpId` to the **narrowest** host that needs the credential (`login.rp.com`, not `rp.com`).
  Upscoping is what makes subdomain takeover an account-takeover.
- Pin `pubKeyCredParams` to `-7` (ES256), `-8` (EdDSA) and `-257` (RS256, for Windows Hello).
  Never `-65535` (RSASSA-PKCS1-v1_5 + SHA-1) and never symmetric HMAC identifiers. Cross-check
  against the [IANA COSE Algorithms registry](https://www.iana.org/assignments/cose/cose.xhtml).
- Require user verification (`userVerification: "required"`) **and verify the `UV` flag on the
  server**. Requesting it without checking it is the exact false-sense-of-security the paper found
  on 10 sites.

### Layer 2 — Deployment and domain hygiene

Covers **Related Origins (8.8)**, **Origin/RP ID (8.1)** and **Framing (5.1)**.

- **Response headers (Framing).** 102 of 103 sites failed the framing checks. Send
  `Content-Security-Policy: frame-ancestors 'self'` (plus legacy `X-Frame-Options: DENY`) and
  restrict `Permissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self)`.
  Tooling: [helmet](https://helmetjs.github.io/) (Node), [django-csp](https://github.com/mozilla/django-csp),
  [secure_headers](https://github.com/github/secure_headers) (Ruby), Spring Security header config,
  or edge config in nginx/Caddy/Cloudflare. Verify with
  [Mozilla HTTP Observatory](https://developer.mozilla.org/en-US/observatory),
  OWASP ZAP passive rules, or [nuclei](https://github.com/projectdiscovery/nuclei) header templates.
  Headers alone are **not** sufficient — also validate `crossOrigin`/`topOrigin` server-side (Layer 1).
- **Related Origin Requests whitelist hygiene.** The paper found 2,177 related origins across 177
  domains, one whitelist with 102 entries, and a dangling entry buyable for €10/year that would
  have exposed 72 origins. There is no purpose-built tool for this, so compose one:
  - Resolve and claim-check every origin in `/.well-known/webauthn` on a schedule with
    [dnsReaper](https://github.com/punk-security/dnsReaper) (40+ takeover fingerprints, reads zones
    from Route53/Azure/Cloudflare/DigitalOcean),
    [BadDNS](https://github.com/blacklanternsecurity/baddns), or nuclei's takeover templates.
  - Reference [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) and
    [can-i-take-over-dns](https://github.com/indianajson/can-i-take-over-dns) for fingerprints, and
    the [OWASP Subdomain Takeover Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html)
    for the process controls.
  - Add a **CI gate** that fails the build if any origin in the ROR document is NXDOMAIN, expired,
    or serving an unclaimed-provider page. This is ~50 lines and is the only thing that keeps the
    whitelist honest as it grows.
  - Enumerate your own attack surface with [OWASP Amass](https://github.com/owasp-amass/amass) /
    [subfinder](https://github.com/projectdiscovery/subfinder) plus Certificate Transparency
    monitoring, and keep registrar auto-renew + registry lock on every listed domain.

### Layer 3 — Data model: the Credential Overwrite class (CVSS 9.1)

**No library or scanner covers this.** It is entirely your persistence layer, and it produced the
worst outcomes in the paper: victim lockout, victim's passkey silently deleted, and session
swapping where the victim signs into the *attacker's* account.

Concrete mitigations:

- **`UNIQUE` constraint on `credential_id` across the whole table**, not per user. This single
  constraint kills the *Database Update*, *Database Append* and *Database Delete* outcomes. Enforce
  it in the schema (Flyway / Liquibase / Alembic / `sqlx migrate` / Rails migration) — not only in
  application code — and add a migration test that asserts the duplicate insert fails.
- **Never `INSERT ... ON CONFLICT DO UPDATE` / upsert on `credential_id`.** Registration of an
  existing `credential_id` must be a hard rejection, per WebAuthn §7.1.26.
- **Look up credentials by `(credential_id)` and then check the resolved `user_id` matches the
  authenticating session** — do not look up by `credential_id` alone and trust the row's owner, and
  never accept a client-supplied `user_id`.
- **Enforce key attestation** if your threat model includes a leaked credential database. Attestation
  proves the registrant controls the private key, which defeats registering a victim's public key.
  Tooling: FIDO [Metadata Service (MDS3)](https://fidoalliance.org/metadata/), consumed by
  webauthn4j's metadata module or Fido2NetLib. Note the paper's finding that *zero* sites actually
  reject registrations lacking attestation — requesting it is not enforcing it.
- **Random 64-byte `userId` handles** (UUIDv4 or CSPRNG bytes), mapped to accounts in the database.
  Never an email or username (§14.6.1).
- Bound `credential_id` storage at 1023 bytes (`VARBINARY(1023)`) to match §7.1.25.

### Layer 4 — Testing: make the 28 detection methods a CI job

- **[PASSKEYS-ATTACKER](https://github.com/RUB-NDS/state-of-passkeys-artifacts)** — the paper's own
  tool, and the only one implementing all passive and active spec tests plus replay, key-swap,
  user-swap and session-swap. The authors explicitly note that teams with automated account-management
  tests can wire it in for fully automated evaluation. Do that.
- **["Fun with Flags and Passkeys"](https://github.com/RUB-NDS/state-of-passkeys-artifacts/tree/main/learning)**
  — the deliberately vulnerable CTF-style platform covering the Table 2 vulnerabilities. Use it to
  train the team on what each failure looks like before auditing your own stack.
- **Virtual authenticators for regression tests.** The Chrome DevTools Protocol `WebAuthn` domain
  and the WebDriver `/session/{id}/webauthn/authenticator` endpoints let you script authenticators
  with attacker-controlled flags (`isUserVerified=false`, `isUserConsenting=false`) — the cheapest
  way to get automated coverage of the **User Verified** and **User Present** ATs. Drivers:
  Playwright (via CDP session), Selenium `HasVirtualAuthenticator`, Puppeteer.
- **Server-side unit tests with a software authenticator**, e.g.
  [SoftWebauthnDevice](https://github.com/bodik/soft-webauthn) (Python) or your library's test
  helpers, to assert that malformed assertions are *rejected* — a negative-test suite mirroring
  Table 2.
- **[FIDO Conformance Self-Validation Test Tools](https://fidoalliance.org/certification/functional-certification/conformance/)**
  (FIDO2 Server suite, via the [conformance-test-tools-resources](https://github.com/fido-alliance/conformance-test-tools-resources)
  REST API). Necessary but not sufficient: it tests spec conformance, not the RP-specific key
  management failures of Layer 3.
- **Manual/interactive:** **WebDevAuthn** (Grammatopoulos et al., the closest prior tool — 5 passive + 5
  active tests), and the Burp extensions Passkey Raider and Passkey Scanner for
  traffic-level work.

### Layer 5 — Continuous monitoring

- **PASSKEYS-RADAR** and the **Well-Known Detector** from the artifacts repo: run them against your
  own domain portfolio to see what you are advertising (`/.well-known/webauthn`,
  `/.well-known/passkey-endpoints`) and catch drift.
- **Signature counter regressions**: store the counter, and on a decrease raise a security event to
  your SIEM and prompt the user, rather than hard-blocking the login. Note the counter is zero for
  most synced passkeys, so treat it as a signal for roaming hardware authenticators only.
- **Credential lifecycle sync** — fixes the "dead passkeys" problem (only 7 of 208 sites do this):
  call `signalAllAcceptedCredentials()` after every successful sign-in,
  `signalUnknownCredential()` after a failed one, and `signalCurrentUserDetails()` on profile change.
  Available in Chrome/Edge 132+ and Safari 26; not in Firefox — so feature-detect and treat it as
  progressive enhancement, never as the authoritative revocation path.

### Layer 6 — Or don't implement it yourself

The paper's Tranco finding — smaller sites were *less* vulnerable — is an argument for offloading.
Self-hostable: [Keycloak](https://www.keycloak.org/), [Ory Kratos](https://github.com/ory/kratos),
[Zitadel](https://github.com/zitadel/zitadel), [Authentik](https://goauthentik.io/),
[SuperTokens](https://supertokens.com/), [Hanko](https://github.com/teamhanko/hanko). Managed:
Auth0/Okta, Corbado, Stytch, Descope, 1Password Passage.

**Caveat from the data:** 178 of 386 confirmed sites used third-party passkey providers, and the
authors deduplicated them because every site on the same provider shared the same SDK-based setup.
A single provider defect is therefore a fleet-wide defect. Offloading changes *whose* bug it is, not
whether you should test for it — run PASSKEYS-ATTACKER against your provider-backed deployment too.

---

## 3. Attack type → mitigation index

| # | Attack Type (CVSS) | CWE | Primary mitigation | Tooling / library |
|---|---|---|---|---|
| 1 | Signature (9.8) | 347 | Never hand-roll verification | Any Layer-1 library; FIDO conformance suite; PASSKEYS-ATTACKER bit-flip test |
| 2 | Credential Overwrite (9.1) | 639 | Global `UNIQUE(credential_id)`; reject duplicates; attestation | Schema migrations + constraint tests; FIDO MDS3 (**no library covers this**) |
| 3 | Related Origins (8.8) | 610 | Minimal, monitored ROR whitelist | dnsReaper, BadDNS, nuclei, Amass/subfinder, CT monitoring, CI gate |
| 4 | Challenge (8.2) | 384 | Single-use, session-bound, TTL'd challenge stored server-side | Library challenge repositories (webauthn4j `ChallengeRepository`, go-webauthn `SessionData`); Redis `SETNX`+TTL; CSRF middleware; `SameSite` cookies |
| 5 | Origin (8.1) | 346 | Exact-match origin allowlist | `RPOrigins` / `expectedOrigin` / `origins(...)`; Semgrep rule banning suffix matching |
| 6 | RP ID (8.1) | 346 | Narrowest `rpId`; verify `authData` RP ID hash | Library `expectedRPID`; subdomain-takeover monitoring |
| 7 | User Verified (6.8) | 287 | Require **and check** the `UV` flag | Library UV policy; CDP/WebDriver virtual authenticator with `isUserVerified=false` |
| 8 | Context (6.4) | 347 | Verify `clientData.type` per ceremony | Library `expectedType`; separate reg/auth code paths |
| 9 | User Present (5.9) | 287 | Check the `UP` flag unconditionally | Library default; virtual authenticator with `isUserConsenting=false` |
| 10 | Allow Credentials (5.3) | 204 | Deterministic dummy `allowCredentials` for unknown/passwordless users; uniform errors and timing | **Custom** — e.g. HMAC(server-secret, username) → fake credential IDs. Plus rate limiting (nginx `limit_req`, WAF). Best avoided entirely by using discoverable credentials / conditional UI |
| 11 | Framing (5.1) | 1021 | `frame-ancestors`/XFO **and** server-side `crossOrigin`/`topOrigin` validation | helmet / django-csp / secure_headers; go-webauthn `RPTopOrigins`, webauthn4j `topOriginPredicate`; ZAP, Observatory |
| 12 | Signature Counter (4.8) | 287 | Store and compare; alert on regression | webauthn4j `MaliciousCounterValueHandler`; go-webauthn clone warning; SIEM rule |
| 13 | Backup State (0.0) | — | Reject `BS=true` when `BE=false` | Library flag validation |
| 14 | Backup Eligible (0.0) | — | `BE` must match between registration and authentication | Library flag validation; use `BE`/`BS` to prompt for a backup passkey |
| 15 | `credId` length (0.0) | — | Reject >1023 bytes | Library validation + bounded DB column |

### Non-AT findings

| Finding | Mitigation | Tooling |
|---|---|---|
| Deprecated / nonsensical COSE algorithms | Pin `pubKeyCredParams` to `-7`, `-8`, `-257` | IANA COSE registry; `supportedAlgorithmIDs` (SimpleWebAuthn); webauthn-rs excludes RSA-SHA1 unless `danger-insecure-rs1` is enabled |
| No confirmation before adding a passkey (66%) | Step-up / "sudo mode" re-authentication before credential changes | Keycloak required actions + ACR, Ory Kratos privileged sessions, Auth0 step-up MFA |
| `rpId` upscoped to registrable domain (38%) | Narrow scope; use ROR instead of upscoping | Config review; subdomain-takeover monitoring |
| PII in `userId` | Random 64-byte handle | CSPRNG + DB mapping |
| Dead passkeys on authenticators | Signal API | Chrome/Edge 132+, Safari 26 (feature-detect; absent in Firefox) |
| Single passkey / no delete / delete requires lost key | Support N passkeys, always-available deletion, non-passkey recovery path | IdP account-management consoles (Layer 6) |
| Attestation requested but never enforced | Decide: enforce or stop requesting | FIDO MDS3 via webauthn4j metadata module / Fido2NetLib |

---

## 4. Where the tooling genuinely runs out

Honest gaps — worth knowing before assuming a scanner has you covered:

1. **Credential Overwrite has no detector outside PASSKEYS-ATTACKER.** It is a schema/lookup bug,
   invisible to conformance suites and to every passive tool in the paper's Table 1. Code review of
   the credential lookup path plus a DB constraint is the only real control.
2. **No library ships anti-enumeration `allowCredentials`.** The dummy-credential generation
   required by §14.6.2 is left to the application. The paper found 25 sites whose *password* login
   was enumeration-safe while their *passkey* login was not — adopting passkeys actively reduced
   their security.
3. **Related-origin whitelist hygiene has no purpose-built tool.** Generic subdomain-takeover
   scanners work but must be pointed at the ROR document deliberately.
4. **There is no linter for WebAuthn configuration.** Suffix-matched origins, upscoped `rpId`,
   requested-but-unenforced attestation, and junk algorithm identifiers are all statically
   detectable and nothing checks them today. A Semgrep ruleset here would be a small, high-value
   piece of open-source work.
5. **Full automation of RP testing is unsolved.** The authors' Playwright + agentic-LLM prototype
   succeeded on 1 of 5 sites; CAPTCHAs, OTP, and rate limiting defeat the rest. Only the RP itself,
   inside its own CI, can run these tests at scale — which is precisely why this belongs in your
   pipeline rather than in an external scanner.

---

## 5. If you only do five things

1. Replace hand-rolled verification with a maintained library, and set origins as an **exact-match
   allowlist** with the narrowest possible `rpId`.
2. Add a global `UNIQUE` constraint on `credential_id` and make duplicate registration a hard
   rejection. (Highest-severity finding, zero library coverage.)
3. Send `frame-ancestors` **and** validate `crossOrigin`/`topOrigin` server-side — 102 of 103 sites
   failed this.
4. Wire PASSKEYS-ATTACKER, or virtual-authenticator negative tests, into CI as a regression gate.
5. Put the `/.well-known/webauthn` related-origins list under scheduled dangling-domain scanning
   with a build-failing CI gate.

---

## Appendix — read-across to this repository

`zk-cred-longfellow` is a ZK credential-presentation library (Longfellow / mdoc), not a WebAuthn
relying party, so none of the ATs apply directly. Three structural lessons do transfer, and are
worth holding in mind for the ZK credential work:

- **The worst bug was in binding a public key to the right subject, not in the cryptography.**
  Credential Overwrite is a subject-binding failure. Any credential system that lets a holder
  present a key identifier alongside a proof needs the same "one credential belongs to exactly one
  subject, enforced at the storage layer" invariant.
- **Session/challenge binding was the second-worst class.** 22 of 103 sites failed to bind the
  challenge to the session, enabling replay and injection. Nonce freshness and session binding for
  presentation requests deserve the same explicit test coverage.
- **A validation that is *requested* but not *enforced* is worse than no validation** — it creates
  a false sense of security. Zero sites rejected registrations lacking the attestation they asked
  for; 10 requested user verification without checking the flag. Verifier-side enforcement of every
  requested property is the invariant to test for.
