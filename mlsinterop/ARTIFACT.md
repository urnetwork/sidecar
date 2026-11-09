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
but they count toward no part of this artifact (§10.4). The next part records them.

# Beside the artifact: §10.4's other M2 evidence

§22.10's M2 exit also asks for the mlswg vectors under 0x0001, owner decision 43's differential runs and the
fuzz seeds. None of these counts toward the 0x0010 artifact above; each is recorded here with the tests that are
its evidence, all of which run in every `test.sh`.

## mlswg vectors under 0x0001: every file accounted for

The root's `TestMlsVectorFilesEachHaveAnOutcome` holds the record below: it names each file's tests by value and
logs each file's counts. Every named test fails on any 0x0001 entry it runs and does not reproduce.
`TestMlsVectorFilesMatchUpstream` holds the files to the mlswg's bytes.

| file | entries, under 0x0001 | run by | skipped, and why |
|---|---|---|---|
| crypto-basics | 7, 1 | `TestMlsCryptoBasicsVectors` | nothing |
| deserialization | 14, suite-free | `TestMlsVectorHeaderVectors` | nothing |
| key-schedule | 7, 1 | `TestMlsKeyScheduleVectors` | nothing |
| message-protection | 7, 1 | `TestMlsMessageProtectionVectors` | every message opens and verifies through a test reader; the production parse refuses the standalone proposals, a member's PublicMessage commit and the application message, and the PrivateMessage commit once it decrypts to a PSK proposal (§10.4) |
| messages | 300, suite-free | `TestMlsMessagesVectors`, `TestMlsMessagesFramingVectors`, `TestMlsMessagesKeyPackageVectors`, `TestMlsMessagesWelcomeVectors` | syntax alone; Update, PSK and ReInit proposals, every framed message but a PrivateMessage commit, and group secrets naming a PSK are refused when parsed |
| passive-client-handling-commit | 91, 13 | `TestMlsPassiveClientVectors` | all 13: each Welcome names a PSK |
| passive-client-random | 1, 1 | `TestMlsPassiveClientVectors` | joins; its first commit is a member's PublicMessage (D-KEYS-3), so the rest goes with it |
| passive-client-welcome | 56, 8 | `TestMlsPassiveClientVectors` | 4 of 8, whose Welcomes name a PSK; the other 4 join |
| psk_secret | 77, 11 | none | the whole file: PSKs are refused when parsed, so it covers no v0 feature |
| secret-tree | 21, 3 | `TestMlsSecretTreeVectors` | nothing |
| transcript-hashes | 7, 1 | `TestMlsTranscriptHashVectors` | nothing |
| tree-math | 10, suite-free | `TestMlsTreeMathVectors` | nothing |
| tree-operations | 5, 5 | `TestMlsTreeOperationsVectors` | the 1 whose proposal is an Update |
| tree-validation | 98, 14 | `TestMlsTreeValidationVectors` | nothing |
| treekem | 77, 11 | `TestMlsTreeKemVectors` | nothing |
| welcome | 7, 1 | `TestMlsWelcomeVectors` | nothing |

So no mlswg vector exercises a commit mls_* processes: every commit in the passive-client files is a member's
PublicMessage or follows a Welcome naming a PSK. The differential below is where mls_* follows another
implementation's commits under 0x0001.

## Differential runs: mls-go v1.6.0 under 0x0001, both directions

mls-go has no 0x0010, and mls_* runs 0x0001 and basic credentials only in the root's tests, which import no peer
(D-REPO-2). The stacks meet through transcripts in the mlswg's passive-client form, `testdata/mls/0x0001/` (its
`SOURCE` says how each was recorded), each replayed through both stacks:

- **mls-go writes, mls_* reads.** `TestMlsGoLifecycle` runs mls-go alone for 13 epochs, every member commit a
  PrivateMessage: Adds with Welcomes, path commits, Removes, an external commit with ExternalInit, and a resync,
  an external commit removing its joiner's old leaf, which the 0x0010 stacks row does not run. Its passive P and
  Q are `mlsgo.json`; the root's `TestMlsGoTranscripts` follows all 12 commits of each through mls_*.
- **mls_* writes, mls-go reads.** The root's `TestMlsGoContinuation` joins that group as P and goes on in it
  through mls_*'s own code: path commits, an Add with its Welcome, a Remove of one of mls-go's members, an
  external commit with ExternalInit from mls_*'s own GroupInfo, and a Remove of that joiner, 8 commits.
  `mls.json` is Q's view, mls-go's 12 commits then mls_*'s 8, which `TestMlsGoReplaysTheTranscripts` follows
  through mls-go, and the joiner's join.
- `TestMlsGoIsPinned` fails on any other mls-go than v1.6.0 until the transcripts are recorded again (D-TEST-7).

Every epoch_authenticator agrees, in both directions. What the runs are, and what they found:

- They run below the engine, on the group state machine with the vectors' rules: basic credentials and no
  ur_group, since mls-go keeps no body of a credential type it has no codec for and refuses to join a group
  whose GroupContext holds an extension it does not implement (RFC 9420 §13.4). They check RFC 9420's mechanics,
  not the subset's own rules, which the stacks row and the engine's tests hold. mls_*'s leaves advertise basic
  through `mlsLeafIdentity.capabilities`, which every engine leaves nil, the subset's.
- mls-go takes a Welcome's tree only from its GroupInfo, and mls_*'s Welcome carries none (§10.6), so mls-go's
  read of mls_*'s Welcome is its join alone: the group secrets, the GroupInfo they decrypt, its confirmation tag
  and the joined epoch's authenticator.
- **Divergence, mls-go's:** v1.6.0 never returns from joining a Welcome with no tree whose group secrets carry a
  path_secret: it stands in a one-leaf tree and walks the committer's direct path in it forever. The Add whose
  Welcome mls-go reads therefore carries no path, and the replay refuses such a view before mls-go sees it.

## Fuzz targets: §22.6's MLS row

Five targets, each held to tmc/mls (byte for byte) and mls-go (field by field, where its suite allows), run as
ordinary tests on their seeds (owner decision 101): `FuzzMlsHeaderAgreesWithPeers` (MLS messages, through
`ParseMlsHeader`), `FuzzMlsGkmCommitHeaderAgreesWithPeers` and `FuzzMlsWelcomeAgreesWithPeers` in `fuzz_test.go`,
and `FuzzMlsGroupInfoAgreesWithPeers` and `FuzzMlsRatchetTreeAgreesWithPeers` in `fuzz_hooks_test.go`, under
`sidecar_testhooks`, the one build in which the root exports those two decoders. Seeds: the 0x0010 and 0x0001
transcripts, the mlswg's messages, Welcomes and trees, values the exported engine writes, mutations each
`TestFuzzMls...SeedsReachEveryRule` holds to the rule it reaches, and the files under `testdata/fuzz/mls_*/`.
A peer decodes only what mls_* reads, since the rule binds nowhere else.

What they found, in seeds and in runs of 20 to 30 seconds each:

- **mls_*, fixed:** nothing held a received GroupContext's `confirmed_transcript_hash` to the suite's hash length;
  it only feeds the confirmation tag's MAC. mls-go refused such a GroupInfo as it decoded it, and mls_*'s full
  GroupInfo check took one its signer had signed. `checkHashLengths` now refuses it in `openMlsWelcome` and the
  full GroupInfo's check (`TestMlsGroupContextHashLengthsAreTheSuites`); the input is
  `testdata/fuzz/mls_group_info/confirmed_transcript_hash_of_three_bytes`.
- **mls-go's:** given a ratchet tree cut short by one byte, its decoder falls back to an older format and
  allocates by the leaf count it reads there, past a gigabyte.

Not done in this draft: fuzz campaigns longer than those runs, a mutation sweep of mls_*, and OpenMLS, which
§22.10 needs only if a required step has a gap.
