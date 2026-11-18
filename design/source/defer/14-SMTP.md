### smtp-designated-verifier-prover: A designated-verifier prover
Stage: Later
- **Deferred:** A designated-verifier (VOLE) prover for the proofs of TLS delivery, so that phones can prove and DATA mode carries megabytes a message (§14.15's risk rows; §14.16; §23.4).
- **Why:** DESIGN.md gives no reason beyond the Later rows. M9's gate is the proofs as designed: sound BDAT and DATA circuits, working and fast enough (owner decisions 35, 99, 125).
- **Launch instead:** M9's prover runs on a member's prover hosts, never on a phone: a phone writes its mailbox outbox and a prover host sends it (D-SMTP-18). A message goes in one-record parts, each proving within 2 minutes. DATA mode proves minutes per 100 KiB, so a message above `smtp_data_proof_bytes`, about 3 MiB on an M1, to an MX without CHUNKING gets a DSN, and `Check` and the `too_large` outcome name the size, the cap and the domain.
- **Lost:** A member with only phones sends no internet mail; an MX without a covered TLS version or suite gets none; and DATA-mode mail to an MX without CHUNKING is slow and capped (§14.15's risk rows).
- **Dark in code:** Nothing is built. `SmtpProver` (sidecar/smtp_proof.go) is the one seam a new prover replaces.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for the designated-verifier scheme, what the edge then holds as verifier and what §2.8 publishes, its soundness review under the gate owner decision 35 set, and a second implementation behind `SmtpProver`.

### smtp-dkim2: DKIM2
Stage: Later
- **Deferred:** DKIM2, named in §14.16's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row.
- **Launch instead:** DKIM with per-sidecar RSA-2048 keys and opaque selectors that rotate every 90 days (§14.6; owner decision 36).
- **Lost:** DESIGN.md does not say.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** The standard settles and receivers adopt it; then a design for signing under it beside DKIM.

### smtp-v1: §14's v1 set
Stage: v1 (Team, from M9)
- **Deferred:** §14.16's v1 row: sending from a Team's custom domains.
- **Why:** Custom domains are a Team item (owner decision 55), and sending starts at M9.
- **Launch instead:** v0 at M9 sends from `<net>.<root>` under §14.6's identity.
- **Lost:** Until then a team sends only from its network's name under `<root>`.
- **Dark in code:** Built in the same run on the `sidecar` branches.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: it ships with M9's gate and M6's custom domains (§23.6).
