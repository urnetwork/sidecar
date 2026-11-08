# The 0x0010 interop artifact (§22.10, D-KEYS-10)

M2's Gn-out freezes suite 0x0010, credential 0xF552 and the MLS and delivery wire on this artifact. Each row
below names the tests that are its evidence. All of them run in every `test.sh`: `make check` runs this
module's tests in both legs, and the root's.

Pins: tmc/mls `v0.0.0-20260930074835-1c42a372504a` (go.sum's h1 is the proxy's; no tags exist upstream, and it
needs Go 1.27), whose `wire.go` has SHA-256
`0ece3d08383e79b61917ef78ef9c6f96fa535b4b3daf3d18a2832a781cf81e28`; Go 1.27.3's `crypto/hpke`. A new pin of
tmc/mls reruns every row (D-TEST-7), and `TestTmcStacksUnderTheSuitePatch` refuses to run until the patch below
is read again against the new `wire.go`.

## The patch

tmc/mls numbers its X-Wing suite with draft-ietf-mls-pq-ciphersuites-06's provisional 0x004F, with exactly
0x0010's algorithms (ML-KEM-768 with X25519, AES-128-GCM, SHA-256, Ed25519). The suite number sits inside
signed and hashed structures, a KeyPackage's content and the GroupContext among them, so it feeds every
signature and the key schedule and cannot be mapped on the wire: both stacks must use one number. The stacks row
therefore runs tmc/mls with one line changed, recorded in `overlay/wire.go.patch`:

```
-	MLKEM768X25519AES128GCMSHA256Ed25519        CipherSuite = 0x004F // TBD1
+	MLKEM768X25519AES128GCMSHA256Ed25519        CipherSuite = 0x0010 // TBD1
```

No other tmc/mls suite uses 0x0010, which the launcher checks. The resolution of
plan-KEYS-interop-independence #1 calls for a build overlay; the go command refuses `-overlay` for any file
under GOMODCACHE, so `TestTmcStacksUnderTheSuitePatch` applies the patch to a temporary copy of the pinned
module, puts that copy in the build through a temporary `go.work`, and runs `tmc_test.go` (build tag
`mlsinterop_tmc`) in a second `go test`. Nothing else in the copy changes. tmc/mls's comments cite draft -06,
where §10.4 cites -07.

## kem: passes, and what it shows

- `TestXWingHpkePqVectorsThroughCryptoHpke`: draft-ietf-hpke-pq's X-Wing vectors, as GOROOT's
  `crypto/hpke/testdata/hpke-pq.json` carries them (two, KEM 0x647a), through `crypto/hpke`'s
  `MLKEM768X25519()`: `DeriveKeyPair(ikmR)` gives `skRm` and `pkRm`, `enc` decapsulates and opens every
  ciphertext, and every export matches. `DeriveKeyPair` is what MLS derives every node key through, and an
  encapsulation KAT alone misses it.
- The root's `mls_xwing_test.go` runs the X-Wing draft's own Appendix C beside these: key generation,
  derandomized encapsulation recomputed from `crypto/mlkem` and `crypto/ecdh`, decapsulation through HPKE, and
  the hpke-pq draft's `DeriveKeyPair`.
- `TestXWingTmcDeriveKeyPairMatchesCryptoHpke` and `TestXWingTmcEncryptWithLabelMatchesCryptoHpke`: tmc/mls's
  `DeriveKeyPair`, and its `EncryptWithLabel` on one fixed random stream, equal `crypto/hpke`'s byte for byte,
  and each side opens the other's.

tmc/mls builds X-Wing on `crypto/hpke`, the code `mls_*` runs, so the tmc/mls half passes by construction. It
shows tmc/mls wires the KEM to RFC 9420's `EncryptWithLabel` as `mls_*` does; it is not a second X-Wing. **The
drafts' vectors are the only independent X-Wing evidence here.** OpenMLS's 0x004D was not run: §22.10 asks for
it only if a required stacks step has a gap, and none does.

## stacks: passes

`TestTmcLifecycleInBothDirections`, under the patch, drives `mls_*` through the exported `MlsEngine` and
tmc/mls through its `Client` and `Group`, in one group of ur_group kind general:

| epoch | step | direction |
|---|---|---|
| 0 | A creates the group | mls_* |
| 1 | A adds T and P; both join A's Welcome on the tree from A's GroupInfo | mls_* → tmc/mls |
| 2 | T adds B with a path; B joins T's Welcome in two phases, completing on T's GroupInfo | tmc/mls → mls_* |
| 3 | B commits a path | mls_* → tmc/mls |
| 4 | T commits a path | tmc/mls → mls_* |
| 5 | A adds U with a path; U joins A's Welcome | mls_* → tmc/mls |
| 6 | U removes B, which sees its removal | tmc/mls → mls_* |
| 7 | A removes U, which sees its removal | mls_* → tmc/mls |
| 8 | T commits a path | tmc/mls → mls_* |
| 9 | A's path commit loses epoch 8 to V's external commit with ExternalInit, from A's GroupInfo | tmc/mls → mls_* |
| 10 | V commits a path | tmc/mls → mls_* |
| 11 | T's path commit loses epoch 10 to C's external commit with ExternalInit, from T's GroupInfo | mls_* → tmc/mls |
| 12 | C commits a path | mls_* → tmc/mls |
| 13 | V commits a path | tmc/mls → mls_* |

A, B and C are `mls_*`; T, U, V and the passive P are tmc/mls. At every epoch every member of either stack
computes one `epoch_authenticator` and one exporter output under `"UR evs 1.0 kek"` with the repo's id (KEK_e)
and under a label of the test's, and `MlsKek` equals the first. Member commits are PrivateMessages, so each epoch
from 1 to 12 has at least one that the other stack decrypts (22 in all); in epochs 8 and 10, which an external
commit ends, it is a member's commit that loses the race, which the other stack decrypts and drops as gkm's 409
would (KF6). Every commit also passes `ParseMlsHeader`, gkm's one parse.

How the two stacks were made to meet, each a fact of tmc/mls and not a change to `mls_*`:

- tmc/mls's leaves carry credential 0xF552, registered with `RegisterCredential` as an opaque body: a
  `UrMlsCredential` that `SignUrMlsCredential` signs for the leaf's signature key. Its default capabilities list
  no extension, so the harness builds and signs its KeyPackages to advertise ur_group, which the group requires.
- tmc/mls's commits always carry a path and never `authenticated_data`, so `mls_*` runs below gkm's
  `GkmCommitHeader` checks, which the engine leaves to its caller (KEYS-M2-19).
- `mls_*`'s Welcome carries no ratchet tree (§10.6): tmc/mls joins on the tree from the GroupInfo beside it.
- Credentials are judged against the identity keys the test admitted, standing in for KEYS-M2-19's check
  against the log.

## ladder: passes

`TestLadderSealsMatchMls` and `TestLadderWrapAadMatchesMls` write KEK_e's exporter call, C_g, K_link_g,
GenWrap_e's and LeafWrap's AAD, GenLink_g's AAD, and KeyDelivery's `wrap_aad` from §10.5's text, in this
module's own code, never calling the root's helpers. Each of `mls_*`'s seals opens under the key and AAD written
here and seals again under its own nonce to the same bytes; `mls_*` opens a GenWrap and a GenLink sealed here;
GenLink refuses another cause; and every STAGED and LATE ReaderWrap and DelegationWrap `mls_*` seals opens under
the `wrap_aad` written here and under no single-byte change of it. The KEK comes from a real `mls_*` epoch's
exporter; the stacks row shows tmc/mls exports the same KEK at every epoch.

## vectors: passes

`testdata/mls/0x0010/lifecycle.json` is the stacks row's run from P's view, in the mlswg's passive-client form
(its `SOURCE` says how to record another). The root's `TestMlsInteropTranscripts` replays it through `mls_*`,
on production's suite and settings, and `TestTmcReplaysTheInteropTranscripts` through tmc/mls: both land on every
`epoch_authenticator` of its 12 commits.

## required: no gap

Welcome, path commit, Remove, external commit with ExternalInit and PrivateMessage each ran in both directions,
so no step holds the freeze and OpenMLS is not needed.

## gaps: steps the script does not run

None of these is a required step. Each is named so the artifact claims nothing it did not show.

- A resync: an external commit removing its joiner's own old leaf. Both external joins here are new members.
  tmc/mls finds the old leaf by its signature key, so a script would rotate no key before a tmc-side resync.
- GroupContextExtensions commits, which v0's flows never send (§10.9 gives them to a repo admin's leaf).
- A last-resort KeyPackage from tmc/mls, which carries no last_resort extension of its own.
- Handshake padding: neither side pads here.
- A group past 16 leaves, where GroupInfo moves out of the epoch object (§10.6); this group peaks at 5 members.

The mlswg vectors under 0x0001 cover the subset's logic, and the root runs every file covering a v0 feature,
but they count toward no part of this artifact (§10.4).
