# DKIM vectors

For smtpedgeservice's DKIM checks (SMTP-M5-04). Lines end in LF here; the tests turn every LF into
CRLF.

- `rfc8463.eml` and `rfc8463.txt`: RFC 8463 Appendix A.3's signed message with its Ed25519
  signature, and A.2's key record for `brisbane._domainkey.football.example.com`. The appendix's
  second, RSA signature is left out. The values were checked before they were kept: A.1's secret key
  derives A.2's public key, the relaxed body hashes to the bh= shown, and signing the relaxed headers
  with that key, which Ed25519 does deterministically, gives the b= shown. `football.example.com` is
  the RFC's own documentation name.

RFC 6376's canonicalization examples (§3.4.6) are in report_dkim_canon_test.go, since they are
fragments rather than messages. Signed fixtures of URnetwork's own shapes are made at run time by
sidecartest's signer, whose keys exist only for the run.
