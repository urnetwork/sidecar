### trust-key-transparency: Key transparency
Stage: Later
- **Deferred:** Key transparency, named in §2.19's and §10.16's Later rows and nowhere else in DESIGN.md. It has no requirement, D- item, task or FS row, and DESIGN.md does not say what such a log would hold or who would run it.
- **Why:** DESIGN.md gives no reason beyond the Later rows. Nothing in M0-M10 depends on it.
- **Launch instead:** Each network's authorization log is its own key record. Devices pin it, check every admission and key against it, and witness each other's heads through HeadCheck, alarming and stopping on a fork (§6.4, §7.9; owner decision 129).
- **Lost:** A check from outside a network's own devices that servers showed every device the same keys. A fork is caught only when two devices of the network compare heads.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design first: what is logged, who runs the log, who witnesses it, and what §2.8's list then publishes. Then an owner decision, tasks and FS rows.

### trust-release-log: A release log
Stage: Later
- **Deferred:** A release log, named in §2.19's Later row and nowhere else in DESIGN.md. It has no requirement, D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row.
- **Launch instead:** A release is promoted: both holders of the offline two-person Ed25519 key sign its `SHA256SUMS`, and `install.sh` checks that signature before it installs (§4.10; owner decision 264).
- **Lost:** A public record of every promoted release. A signed release offered to one host and to no one else leaves no trace that others can find.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for the log and for who checks it, then a step in the promotion that §4.10 describes.

### trust-web-code-transparency: Web code transparency
Stage: Later
- **Deferred:** Web code transparency, named in §2.19's Later row. It would let a visitor check that the page code a server gave them is the published code. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row. Owner decision 76 (Q-TRUST-4) accepts served code now, labeled as such.
- **Launch instead:** Web pages decrypt with served code, and say so: ur.io/recurd and the team console are labeled as served code (§2.8's EX7), and their page Worker runs in its own key origin, read-only (§18.8).
- **Lost:** A visitor cannot tell altered page script from the published script. §18.8's disclosed row names who could alter it: the server, Cloudflare's page scripts, an XSS.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for publishing and checking the web bundle's hash, and a decision on whether the label then changes.

### trust-external-audit: An external security review and audit
Stage: Later, unless the owner reinstates it
- **Deferred:** An independent review or audit of the cryptography: the in-house MLS subset whose audit owner decision 43 planned, which is Later with MLS itself (owner decision 610), the key ladder, the storage format and path tokens, and the zero-knowledge mail proofs (owner decisions 99 and 119; Q-TEST-3, Q-TRUST-8, Q-KEYS-1).
- **Why:** The owner's words (owner decision 99): "No review at the moment, just get it working."
- **Launch instead:** The mlswg vectors and differential tests (owner decision 43), fuzzing (owner decision 101), and the outbound-mail gate as owner decision 99 restates it: sound by design analysis, working, fast enough and interop-tested. Product copy may say "end-to-end encrypted" with §2.18's unaudited-cryptography disclosure on the security page, no audit gating it (owner decision 119).
- **Lost:** Independent assurance. §2.18's risk row rates unaudited novel cryptography Medium likelihood and Critical impact, and the security page discloses it.
- **Dark in code:** Nothing: an audit is not code.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** The owner reinstates it, names a reviewer and a scope, and decides whether a release or the "end-to-end encrypted" copy then waits on the result.
