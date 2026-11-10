# Decisions, interpretations and findings

## Scope (agreed with Steve Lyons)

| Claim | Decision |
|---|---|
| catreplay, catv, catm, catr | CTA-5007-B as written |
| catpor | CTA-5007-B array form `[probability 0..1, id, ?exp]`. Reuse blocking (blocking later tokens with the same id) is **out of scope**: reuse tracking is done outside VCL. The id and expiry are still checked for well-formedness. |
| catalpn | CTA-5007-B: array of **byte strings** |
| cattpk | CTA-5007-B: full DER SubjectPublicKeyInfo |
| catnetprint | rust-cat's `cattprint` definition: key 324, `{0: FingerprintType int, 1: tstr}`; value compared case-insensitively |
| cnf, catdpop | Skipped for now |
| catreplay value 3 | Well-formed but behaviour undefined (§4.6.6): no pass/fail asserted |
| TLS context in varnishtest (ALPN, client certs, fingerprint) | Left to the engineers |

## How expected results are derived

* §4.3.1.2: a CAT is *valid* only if "the syntactic requirements of any present claims are
  met", and *acceptable* only if valid and every claim is acceptable. So a CDDL violation
  in a claim → **reject**.
* §4.5: claim values (except catnip) MUST NOT be tagged, and recipients MUST reject an
  improperly tagged value → **reject**.
* §4.5: a CAT that is not deterministically encoded MAY be treated as ill-formed →
  **undefined**.
* MAY-level behaviour (limits above 50 members, replay of a 1/2 catreplay token) → **undefined**.

## Assumptions behind every expected result

* A CAT is **required** for the requested content (§4.3.1.4). If it is not, an unacceptable
  token must not be used to deny access, and every `reject` below would become `accept`.
* The recipient **supports** the claim under test. catreplay, catpor, catalpn, cattpk and catr
  are "Recipients MAY support"; §4.5 says an unsupported claim is ignored. An implementation
  that does not support one of these would accept where these cases say reject.

`basis` values: MUST / MUST NOT / SHOULD / SHOULD NOT / MAY (RFC 2119 keyword in the cited
text); CDDL (syntax requirement → not valid → reject via §4.3.1.2); normative-text (a
normative statement without a keyword, e.g. catpor "is rejected with probability equal to
that value"); rust-cat (rust-cat source is the definition); interpretation (needs confirmation).

## Known defect in the spec's catr CDDL (§4.9.2 and Annex D)

`? renewal-deadline-label ^ => renewal-deadline-label` makes the deadline value the literal 2;
`renewal-name-label` and `renewal-params-label` are never defined; `renewal-code-label ^ =>
renewal-code-label` has the same flaw. Read literally, keys 2, 3, 5, 6, 7 would accept almost
anything. The suite applies the value types the spec does define (`renewal-deadline-value =
number`, `renewal-cookie-name-value = tstr`, `renewal-cookie-params-value = [ *tstr ]`, ...),
which also match the prose. CATR-MAL-06/07 depend on this and are marked `interpretation`.

## Interpretations to confirm

| Case | Interpretation |
|---|---|
| CATTPK-REJ-05 | cattpk over plain HTTP → reject. The MUST sentence in §4.6.18 only names TLS/QUIC; the reject follows from the first sentence ("limits access to only clients that present a certificate chain..."). |
| CATTPK-ACC-02 / REJ-03 | "Chain" means the chain the client presented. An intermediate in the presented chain matches; a root the client did not send does not. |
| CATR-NOR-03 | Automatic renewal with an additional-parameters member → MUST NOT renew (issuer "MUST not have" + recipient "MUST NOT renew ... parameters not appropriate"). |
| CATR-UND-01 | Redirect status outside 300–399: the spec says the status MUST be in range but not what the recipient does → renewal undefined. |
| catr deadline cases | Deadline 4000000000 puts "now" inside the window [exp − deadline, exp) for any date up to exp (2100); deadline 60 keeps "now" before it. |
| CATREPLAY-UND-01/02 | Replay of a 1/2 token: spec says MAY reject; tracking is outside VCL → undefined. |
| catnetprint | The connection is modelled as having one fingerprint `{type, value}`, matching rust-cat's `VerificationOptions` (one type + one value). An implementation that computes whichever fingerprint type the claim asks for would see CATNETPRINT-REJ-01 differently; the harness must supply the fingerprint the rust-cat way. |
| CATNETPRINT-ACC-03 | Claim absent and no fingerprint → accept. rust-cat's `verify_claims` errors here if `verify_cattprint` is on (finding 8). |
| CATREPLAY-MAL-03, CATV-MAL-02 | `1.0` (a float) read as a type error → reject. Alternative: §4.5 "numbers have only their real numeric meaning" makes it an encoding defect → MAY reject. |
| CATTPK-ACC-03 | Intermediate SPKI with a different valid leaf under the same intermediate → accept. |
| CATTPK-UND-01 | Intermediate SPKI with a self-signed leaf + appended intermediate (chain does not validate) → **undefined, needs a Fastly decision**. Anyone can append a public intermediate certificate, so accepting this would let any client satisfy an intermediate-pinned cattpk. |
| CATR-NOR-07 | Expired token with catr → reject (exp) and MUST NOT renew. |
| catr SHOULD renew | Assumes the service has a renewal signing key (§4.9.2: "If the recipient has a signing key suitable for token renewal, it MAY issue a new token"). |

## Not covered yet (follow-ups)

* Encoding cases for catm, catalpn, cattpk, catr (non-shortest lengths). Indefinite-length
  items are rejected by this suite's decoder, so they cannot be generated as-is.
* catr header renewal with Additional Header Parameters (6): the expected RFC 8941 text form
  of each parameter is not spelled out in §4.9.2.3.
* catr automatic renewal for a token in the `Authorization` header: how a CAT is carried in
  `Authorization` is not defined in the sections used here.
* catr: ≥50 members inside the cookie/header parameter arrays.
* catreplay: replay of value 1 with no cti.
* cattpk: `h''`, and the same key in a different DER form (e.g. compressed point).

## rust-cat findings (fastly/rust-cat `main`)

Relevant to anyone using rust-cat as a reference for these claims:

1. `verify_claims` checks only exp, nbf, iss, aud, catu, catm, catreplay and cattprint. It does
   not check catpor, catv, catalpn, cattpk or catr.
2. `catm` is compared case-insensitively (`to_uppercase()`); §4.6.11 requires case-sensitive.
   CATM-REJ-02 (`["get"]` with `GET`) is expected to be rejected; rust-cat accepts it.
3. `catpor::create` builds a single integer percentage; §4.6.7 requires an array with a
   probability in [0, 1]. `CborValue` has no float variant, so rust-cat cannot build or decode
   fractional probabilities.
4. `catalpn::create` builds text strings; §4.6.12 requires byte strings.
5. `cattpk` docs describe the value as a SHA-256 hash; §4.6.18 requires the DER SPKI.
6. `catdpop` doc example puts the text `"RS256"` under key 1 (the jti setting, a uint).
7. `from_bytes` fails on any claim value containing a float, bool or tag, and on non-integer
   map keys.
8. `verify_cattprint_claim` returns an error when no fingerprint is supplied in the options,
   even if the token has no cattprint claim.
9. For HMAC, `Token::verify` tries the COSE_Sign1 (`"Signature1"`) context first, then
   `"MAC0"`, so it also accepts a MAC computed over the wrong COSE context. This suite's own
   check (`tools/validate.py`) uses MAC0 only.
10. Indefinite-length arrays/maps decode as empty (`.unwrap_or(0)`) instead of failing.

## Test material

* `keys/hs256-test-key.json`: random 32-byte HMAC key generated for this suite. Test only.
* `certs/`: P-256 root → intermediate → client/other certificates (valid 100 years). Test only.
* catnetprint values other than the JA4 example from rust-cat are synthetic strings (the claim
  is an opaque string comparison); they are not real fingerprints.
* The toolchain check uses the Annex B.3 example key published in CTA-5007-B for validating
  its examples.
