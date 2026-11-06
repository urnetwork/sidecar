## 10. Group keys for evs: MLS and the GKM service

### 10.1 Purpose and scope

This section owns X12: the in-house MLS subset, ciphersuite, credentials and groups; GKM, stateless over metadata-cluster objects (owner decisions 2, 145); the key hierarchy, generations, key holders and their wraps, the write-gate predicate, membership flows and committers, revocation, erasure, recovery, re-seeding, key domains and sizes. §5 owns the identity key and recovery code, §6 push and `HeadCheck`, §7.9 the config repo, the authorization log and the `leaves` rule of the config and team directory groups, §16.11 the directory, §8 readers and consent, §11 the object format, placement and the gate's enforcement, and §19 the file cluster.

### 10.2 Requirements

| id | requirement | source |
|---|---|---|
| R-KEYS-1 | MLS (RFC 9420) secures evs from v0 | PLAN.md:44; owner decision 1 |
| R-KEYS-2 | One directory = one git repo, under "one session key stored in GKM" | PLAN.md:53 |
| R-KEYS-3 | Lazy rewrap: a client that detects a needed rewrap sends a checkpoint | PLAN.md:47-50, :338 |
| R-KEYS-4 | Forward-only revocation: a removed or expired holder reads nothing new | PLAN.md:149, :167-168; I-15 |
| R-KEYS-5 | One accepted Commit per epoch | PLAN.md:157-161; RFC 9420 §14 |
| R-KEYS-6 | No server holds a group secret, epoch key or file key; gkm sees ciphertext and 10.6's headers | CONVENTIONS §0; PLAN.md:221; I-1; owner decision 115 |
| R-KEYS-7 | MLS built in house in the sidecar repo, pure Go, no cgo | owner rule 1; owner decision 43; sdk/js/Makefile:69 |
| R-KEYS-8 | A breached server yields only ciphertext and listed metadata and adds no reader | P5:745 |
| R-KEYS-9 | Two key domains: sessions for their author, others reading only by consent or as the audit reader; actions and approvals for admins | P5:579, :640; MK2:482-486; owner decision 126 |
| R-KEYS-10 | Per-entry keys for records from the first release | REC:217-223; owner decision 61 |
| R-KEYS-11 | MLS membership follows the signed readers, which clients verify; agents, and config and team directory readers past a network's first 1,000 member devices, hold wraps, so no member-device cap applies | owner decisions 3, 6, 114, 144, 182; §8.12 |
| R-KEYS-12 | Ciphertext resists harvest-now-decrypt-later by a passive adversary | [R:ext-storage-crypto] §2.5, §2.12; owner decision 44 |
| R-KEYS-13 | Signed grants, admissions and revocations decide membership, waiting for no admin; members update their own leaves | owner decisions 7, 8, 113, 128 |
| R-KEYS-14 | gkm's durable state is objects on its repo's metadata cluster, never Postgres or Redis, written within §11.13's NVMe write budget; acks are Redis soft state | owner decisions 2, 136, 140, 145 |

### 10.3 What exists today

- **GKM** appears only at PLAN.md:53; no repo has code for it [R:ext-storage-crypto].
- **Go 1.27.3** (connect/go.mod:3). `crypto/hpke` implements X-Wing as `MLKEM768X25519()`, KEM 0x647a, from draft-ietf-hpke-pq (GOROOT/src/crypto/hpke/pq.go:21, :39-41); `crypto/mldsa` arrived in Go 1.27 (GOROOT/api/go1.27.txt:4).
- **Constraints.** The browser build is `CGO_ENABLED=0` (sdk/js/Makefile:69). server's `BlobStore` has `PutIfAbsent` but no Delete, If-Match or ranged read (server/blob.go:160-192); `ServiceHost.Blobs` adds them, per metadata cluster (§4.5, §19).
- **Test material** (2026-11-03). The mlswg's 16 vector files carry only RFC 9420's classical suites (https://github.com/mlswg/mls-implementations/tree/main/test-vectors). MIT differential peers: thomas-vilte/mls-go v1.6.0 (0x0001-0x0003; [R:ext-storage-crypto] §2.4); tmc/mls, whose provisional 0x004F has exactly 0x0010's algorithms (wire.go:33-50); OpenMLS, whose unregistered 0x004D pairs X-Wing with ChaCha20-Poly1305 (https://cryspen.com/post/pq-openmls/).

### 10.4 Implementation, ciphersuite, credentials

**Subset (D-KEYS-12).** Only what evs uses; anything else is refused when parsed.

| RFC 9420 feature | v0 |
|---|---|
| Tree math; codec, mls10 only (§6, App. C) | yes |
| Labeled crypto, key schedule, exporter (§5, §8) | yes |
| Secret tree, PrivateMessage, transcript hashes (§6.3, §8.2, §9) | handshakes only |
| TreeKEM, parent and tree hashes, validation (§7) | yes |
| Add, Remove, GroupContextExtensions, inline (§12.1); path-only commits for self-update (§12.4) | yes |
| Welcome, `ratchet_tree`, ExternalInit (§12.4.3) | external commits only to resync or recover |
| KeyPackages, last resort; credential 0xF552 (§10, §16.8, §17.5) | yes |
| PSK, ReInit, branching, application messages, external senders, standalone and Update proposals | refused |

**Conformance.** No vectors exist for 0x0010, so every mlswg vector file covering a v0 feature runs under 0x0001; 0x0010 adds X-Wing known-answer tests (KATs) and owner decision 43's differential runs: mls-go under 0x0001, tmc/mls under 0x004F mapped to 0x0010, and OpenMLS's 0x004D once an M0 KAT matches its X-Wing to Go's. **The 0x0010 gate (D-KEYS-10)** adds what those cannot show:

```text
specified  the MLS wire (credential 0xF552, GkmCommitHeader, GenRotate, ur_group), the delivery wire
           (ReaderKey, KeyDelivery under its ReaderWrap and DelegationWrap types, 10.6's wrap and recovery
           paths) and suite 0x0010, at M2's entry review; no field is removed after it
frozen     at M2's exit review (D-PHASE-7), on §22.10's 0x0010 interop artifact:
  kem      X-Wing KATs: tmc/mls's encapsulation and decapsulation equal Go's crypto/hpke MLKEM768X25519() on
           fixed seeds
  stacks   one scripted lifecycle in both directions between mls_* and tmc/mls (0x004F mapped to 0x0010): at
           least 10 epochs with a Welcome, path commits, a Remove, an external commit with ExternalInit and a
           PrivateMessage decrypted per epoch, both sides computing equal epoch_authenticator and "UR evs 1.0
           kek" exporter outputs
  ladder   GenWrap's, LeafWrap's and GenLink's AAD and KeyDelivery's wrap_aad (10.5), reproduced by
           mlsinterop/'s own code
  gaps     no stacks step may be a gap: one tmc/mls lacks holds the freeze unless a second peer runs it in
           both directions (OpenMLS's 0x004D, once its M0 KAT matches); mlswg vectors under 0x0001 count toward
           no part of it
```

**Ciphersuite (owner decision 44; D-KEYS-12).** 0x0010, MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519, in groups and credentials from v0 (draft-ietf-mls-pq-ciphersuites-07, Publication Requested 2026-11-01; [R:ext-storage-crypto] §2.1). Each MLS AEAD key is used once, so wasm's table-based AES (GOROOT/src/crypto/internal/fips140/aes/aes_generic.go:58-74) is no practical timing target.

**Framing (D-KEYS-3).** Member commits are PrivateMessage (RFC 9420 §6.3), whose clear header shows group_id, epoch and content type; only external commits (resync, recovery self-join) are PublicMessage, as RFC 9420 §6 requires for non-members. `authenticated_data`, clear but bound into the AEAD and signature, adds only what the gate needs and no roster delta (owner decision 59):

```proto
message GkmCommitHeader {   // sidecar/protocol/gkm.proto, in authenticated_data of every commit
  uint64  generation = 1;   // the generation of this epoch's GenWrap: the newest gen/ the committer holds;
                            //   0 only for a recovery self-join that carries no GenWrap (10.6's epoch PUT, 10.8)
  AuthPin auth = 2;         // the state (§7.9) the new roster was checked against
}
```

**Leaves and readers (D-KEYS-2, D-KEYS-23).** Member devices that read a repo are its group's leaves, at most 1,000 (owner decisions 1, 7, 60); in a data repo, those past the 1,000 seats wait keyless (§8.12). Agents read by 10.5's wraps, outside that cap (owner decision 114). Readers are §8's `RepoReaders`, which every device evaluates (owner decision 6) and the projection carries as ids. In the config group, which every admitted sidecar reads, §7.9's `leaves` rule alone ranks member devices, whose admissions carry no not_after, and moves them between leaf and wrap, as a function of the log (owner decision 144); the team directory's group, its own MLS group (owner decision 60), which every admitted sidecar of a team network reads (§16.11), follows the same rule: the first 1,000 live member devices are its leaves, and a rotation costs ~1.3 KB a wrap per overflow device (owner decision 182). In both, the rest, and an entitled device not yet added, read by ReaderWraps (wrapped) and stay leaves of their data repos. §10 adds:

```text
adds      in both groups members accept an Add or external join only of a leaf-entitled device (§7.9); one
          without a KeyPackage reads by ReaderWrap until it uploads one, and no other device takes its place
wrapped   a wrapped member device commits no Add or Remove in them, only first wraps and rotations (10.9)
```

**Credential.** Private-use type `ur_sidecar = 0xF552` (RFC 9420 §17.5), required through `required_capabilities`; KeyPackages are public, so it names no member, tag or client:

```proto
message UrMlsCredential {                         // sidecar/protocol/gkm.proto
  bytes sidecar_id = 1;                           // durable leaf identity (§5)
  bytes identity_public_key = 2; string identity_alg = 3;  // §5; ed25519 in v0
  bytes mls_signature_public_key = 4;             // rotated by self-update
  uint32 cipher_suite = 5; int64 not_after = 6;   // 0x0010 (owner decision 44)
  bytes admission_sha256 = 7;                     // its §7.9 SidecarAdmit; Genesis for the first device
  bytes identity_signature = 8;                   // §6 signing, purpose mls-credential, fields 1-7
}
```

- **Admission (owner decisions 3, 5, 110, 112, 127).** Members accept a credential only if an unrevoked, unparked `SidecarAdmit`, verified through the authorization log back to the genesis and signed as §7.9 allows (one admin, the member's own device unless `self_admit` is off, or k of n for AdminSet members), names its sidecar_id and identity key. Only a network's first device is trusted on first use, against its safety number (§2.8 EX5). Clients pin that key, refuse a second and share pins through §6's `Hello` (D-PROTO-13). After a `SidecarRevoke`, GKM deletes the sidecar's KeyPackages.
- **Self-updates and forks.** A leaf that commits no path for 7 days (30 in groups above 50 leaves) commits a path-only commit (D-KEYS-14). Clients pin each push's sealed (group_id, epoch, epoch_authenticator) (§11.6) and each generation's C_g, refuse a lower or conflicting pin with an alarm and compare pins by §6's `HeadCheck`, whose generation heads serve holders that are not leaves (I-16, D-PROTO-14, D-TRUST-10; owner decision 129).

### 10.5 The key hierarchy: what "one session key stored in GKM" means

The MLS exporter changes every epoch, is not forward-secure (draft-ietf-mls-extensions-11 §4.4), and gives a new member nothing earlier, so the evs keys sit above MLS:

```text
MLS epoch e --MLS-Exporter("UR evs 1.0 kek", repo_id, 32)--> KEK_e (key-encryption key)
RK_g: repo key generation g, 32 random bytes = PLAN's "session key"; cause_g ∈ {remove, request, schedule}
GKM stores only:
  GenRotate_g = the Signed record in gen/<g> (below): C_g, parent C_{g-1}, cause, auth pin, time, holders
                hash, GenLink_g, an optional LeafWrap, the drop key
  GenLink_g   = XChaCha20-Poly1305(K_link_g, RK_{g-1}; aad repo_id||g||cause_g)         the ladder
  GenWrap_e   = XChaCha20-Poly1305(KEK_e, RK_g; aad group_id||e||g)    in epoch object e, g its newest
  LeafWrap    = XChaCha20-Poly1305(KEK_e, RK_g; aad group_id||e||g)    in GenRotate_g, for every leaf of e
  GroupInfo_e = XChaCha20-Poly1305(K_groupinfo, GroupInfo incl. ratchet_tree; aad group_id||e)
                inside each epoch object at <= 16 leaves; on demand above (10.6)
  RecoveryWrap_{m,g}   = HPKE-XWing(recovery_pub_m, RK_g)                                    (10.8)
  ReaderWrap_{g,s,k}   = §6 Signed, purpose reader-wrap, a KeyDelivery (below): {group_id, g, C_g, s, k,
                         staged or late, a late one's auth pin and time, HPKE-XWing(ReaderKey_{s,k}, RK_g)}
  DelegationWrap_{g,d} = the same to the reader key of d, which d fixes, d = delegation_id = SHA-256(Signed
                         Delegation); k = SHA-256 of the X-Wing public key sealed to, its incarnation
RK_g --HKDF-SHA256(salt repo_id, info "UR evs 1.0 "||purpose||u64be(g) [||group_id||u64be(e)])-->
     link|fek|manifest|path|ref|drop|groupinfo|index
ReaderKey_{s,k} = §6 Signed, purpose reader-key, {sidecar_id, xwing_public_key, not_after}, not_after at most
              7 days after signing; every reader holds one, a fresh X-Wing pair once it is 6 days old, k its
              incarnation (readerkey, below)
ur_group    = GroupContext extension {network_id, repo_id, kind, owner_member_id}, fixed at creation; kind is
              one of §11.12's kinds, directory among them from M2's reservation (owner decision 171)
```

- **PLAN.md:53, precisely.** One current key, RK_g, encrypts every new object, and GKM stores it only wrapped (I-1). It rotates when a key holder drops or its authorization expires (`remove`), on `ur keys rotate` (`request`) and after 30 days (`schedule`); Adds and self-updates keep it, so in-flight writes stay valid.
- **Ladder.** RK_g opens every earlier generation, so a joiner gets the whole history; to withhold history, use a new repo (§11). A removed reader gets no later KEK, RK or wrap, but keeps every generation it held and opens files untouched since its removal until they are rewritten or `ur evs rekey` re-checkpoints them. MLS updates heal the tree and its KEKs, but a copied keychain derives every KEK until the device's own next path commit (10.4) and opens every delivery to a ReaderKey it holds, to which a rotator or deliverer seals only before that key's not_after, at most 7 days after its signing, whatever advertisement gkm serves (readerkey, below); so content heals only at the first generation sealed after both. A passive copy (the keychain's bytes, used only to open what the operator serves, a stale advertisement included) therefore reads, while the device runs, what is sealed up to about 37 days after the copy, 60 above 50 leaves (the path commit within 7 days, 30 above 50 leaves, the newest copied ReaderKey's not_after within 7, then up to 30 days to the next generation), and every earlier generation through the ladder; while the device does not run, its copied leaf derives each later epoch's KEK until it commits again or a stale Remove (10.9) removes it, and a copy of a wrapped reader's keychain heals at that not_after whether or not the device runs. An active clone, one that uses the copy's identity key or ClientKey, signs fresh ReaderKeys and KeyPackages and commits as the device, so no path commit or key replacement ends it: only a `SidecarRevoke{reason: compromise}` from a since_n at or before the copy, whose cascade parks what the clone admitted (§7.9), and the device's enrollment anew, since `--replace` keeps its identity key (§5.5), as for a compromised backup (10.8). A Delegation's reader key in it reads as the Residual below says. X-Wing protects ciphertext against harvest-now-decrypt-later by a passive adversary (owner decision 44); signatures are Ed25519, so an adversary that can forge them (a future quantum computer, say) and that the operator serves could forge admissions and, through the ladder, read all retained history. External resync needs RK_g, under which the GroupInfo is sealed, never a published identity key alone.
- **Authentication.** The key schedule and every GroupInfo signature bind `ur_group`; clients accept RK_g only if it matches `gen/<g>`'s signed C_g; the newer, verified generation authenticates each GenLink, whose AAD covers the cause §11's rewrap rule reads; a missing key is refused, never defaulted (ePrint 2024/546).

**Generations (D-KEYS-15).** C_g = SHA-256("UR evs 1.0 commit" ‖ repo_id ‖ u64be(g) ‖ RK_g), and every evs head carries the generation pin {group_id, g, C_g} (§11.8). `gkm/<group_id>/gen/<g>`, created If-None-Match, is the only place a generation exists: MLS commits change the tree and give joiners the newest generation's key in GenWrap_e, and the rotation a Remove requires is a separate gen/ claim, by any writer.

```proto
message GenRotate {              // sidecar/protocol/gkm.proto; §6 Signed, purpose gen-rotate, by the rotator's identity key
  bytes   group_id = 1; bytes repo_id = 2;
  uint64  generation = 3;        // g; generation 1 is written with epoch 0 (KF1) and has no parent
  bytes   parent_commitment = 4; // C_{g-1}
  bytes   commitment = 5;        // C_g
  uint32  cause = 6;             // 1 REMOVE, 2 REQUEST, 3 SCHEDULE; REMOVE iff it covers a shrink, an
                                 //   authorization expiry or a compromise retirement since the parent (10.9)
  AuthPin auth = 7;              // the state KeyHolders was computed at (§7.9); never below the previous
                                 //   base or the parent's auth
  int64   time_ms = 8;           // the evaluation time for expiries; within 10 min of gkm's clock
  bytes   holders_sha256 = 9;    // SHA-256 over the sorted KeyHolders(R, auth, time) identities (below)
  uint32  wrap_count = 10;       // staged wraps and recovery wraps, for completeness checks
  bytes   genlink = 11;          // GenLink_g
  LeafWrap leaf_wrap = 12;       // optional: one wrap for every leaf of that epoch, 72 B
  bytes   drop_public_key = 13;  // only for kinds that take deposits (D-KEYS-17)
  int64   drop_not_after_ms = 14;
}
message LeafWrap { uint64 epoch = 1; bytes ciphertext = 2; }  // RK_g under KEK_epoch, aad group_id||epoch||g
message KeyDelivery {              // the body of a ReaderWrap or DelegationWrap, gkm's wrap/ object (10.6)
  bytes   group_id = 1;
  uint64  generation = 2;          // g
  bytes   commitment = 3;          // C_g, all 32 bytes
  bytes   recipient = 4;           // sidecar_id; a DelegationWrap's, the delegation_id
  bytes   recipient_key_sha256 = 5;  // SHA-256 of the X-Wing public key sealed to: a ReaderKey's, which a
                                     //   replacement changes, or the Delegation's reader_xwing_public_key
  uint32  delivery_kind = 6;       // 1 STAGED: by gen/<g>'s rotator before its claim; 2 LATE: after it (10.9)
  AuthPin auth = 7;                // LATE only: the signer's newest verified state when it signs
  int64   time_ms = 8;             // LATE only: the signer's clock or, if later, gen/<g>'s time_ms; within 10 min of gkm's
  bytes   ciphertext = 9;          // HPKE-XWing(that key, RK_g), info "UR evs 1.0 wrap", aad wrap_aad
}
message ReaderWrap { KeyDelivery wrap = 1; }      // §6 Signed, purpose reader-wrap, by the signer's identity key
message DelegationWrap { KeyDelivery wrap = 1; }  // the same, to a Delegation's reader key
// wrap_aad = u8(1 ReaderWrap | 2 DelegationWrap) || group_id || u64be(g) || C_g || SHA-256(recipient)
//            || recipient_key_sha256 || u8(delivery_kind), then, LATE only, u64be(auth.version) || auth.chain
//            || i64be(time_ms)
```

```text
Rotate: one algorithm for every cause and every rotator
1  S = my newest verified state (n, A_n); t = now; H = KeyHolders(R, S, t); require me in H or covered by a
   Delegation in H, and me ∈ writers(R, S) or, in the config group, me = the signer of an admission or
   revocation this rotation answers (owner decision 128) or, after api's reap of an uncovered ephemeral
   agent, of its admission (§7.10)
2  g = the newest generation (GET gen/<g+1> answers 404); RK' = 32 random bytes; persist RK' and the
   GenRotate draft in my keychain
3  stage deliveries for g+1, each a STAGED KeyDelivery at wrap/<g+1>/<c8>/<recipient>/<k8> (10.6), c8 =
   hex(C_{g+1}[0:8]), up to 16 PUTs at once:
     leaves        if I am a leaf at the current epoch e and e's tree holds no leaf outside H, one leaf_wrap
                   under KEK_e inside GenRotate; else a ReaderWrap to each leaf's ReaderKey
     wrapped       in the config and directory groups, member devices in H that e's tree lacks, wrapped or not
                   yet added, a device a restored binding admitted among them once activated (10.8): a
                   ReaderWrap each (owner decisions 144, 182); in other groups they join by Add (KF2)
     agents        not covered by a live Delegation: a ReaderWrap each
     Delegations   live ones in H: a DelegationWrap each
     recovery      members reading R with a current RecoveryBind: a RecoveryWrap each
4  PUT gen/<g+1> If-None-Match                                          <- the linearization point
     201      done; hint (D-KEYS-19); the generation is complete, since every delivery already exists
     412      GET it and check it (10.9); if it covers every shrink and expiry I rotate for, adopt it and fetch
              my wrap; else go to 1, rotating at g+2
     unknown  GET gen/<g+1>: my commitment = done; another = 412; 404 = repeat 4 with the same bytes
5  seal content to g+1; delete my keychain draft
retry      the GenRotate bytes, named by their commitment; every delivery precedes the claim, so a crash before
           4 leaves only staged objects, which GC removes after 24 h, and one after it a complete generation;
           a recipient whose ReaderKey appears or changes later gets a LATE delivery to that key from any
           holder but a read_only one (10.6's late wraps, 10.9)
remove X   a writer leaf commits Remove(X) at epoch e+1 (the revoking device first, 10.9); then any writer
           rotates (in the directory group, in 10.9's order), a leaf by leaf_wrap under KEK_{e+1}, which X
           cannot derive; until a leaf commits the Remove, a wrapped writer (an agent, or in the config or
           directory group a wrapped member device, 10.4) may rotate by ReaderWraps to every remaining leaf,
           no leaf_wrap uses an epoch whose tree holds X, and the next leaf commit must remove X; wrapped
           writers never commit Removes (owner decisions 114, 144, 182), yet no repo stays gated while every
           leaf is offline
```

**Key holders (D-KEYS-16).** For repo R at state S and time t:

```text
KeyHolders(R, S, t) = leaf(s)        member devices reading R (§8.12), MLS leaves of R's group; in the config
                                     and directory groups wrapped ones (10.4) hold wraps and keep this identity
                    ∪ agent(s)       other admitted sidecars reading R, unless covered
                    ∪ delegation(d)  live Delegations whose reach holds R
                    ∪ recovery(m)    members reading R with a current RecoveryBind
covered(s, R)  = s was admitted under a Delegation d with delegation(d) ∈ KeyHolders(R, S, t)
reach(d)       = the config, in a team network the directory, and each repo that a read or write grant
                 naming one of d's tags reads (the grants §8.6's ceiling counts for a tag a sidecar carries);
                 every agent d admits carries exactly d's tag_ids (§7.9's scoped), so a covered agent reads
                 each repo d's key opens
live(d)        = d has not ended (§7.9's delegation row) at S, t < d.not_after, and no Suspend, and no
                 revocation for any reason but reaped, of a sidecar d admitted precedes S; d.key_dropped_at
                 is the position of the first such Suspend or revocation, or of d's end, and no Unsuspend
                 undoes it; an ephemeral covered agent's own not_after drops nothing, as its reap does not,
                 since it can close itself, and api can reap it, at any time before (§7.7), and §7.9's
                 scoped rule refuses a non-ephemeral one whose not_after precedes d's
identity bytes = kind byte (1 leaf, 2 agent, 3 delegation, 4 recovery) || sidecar_id | delegation_id | member_id
readerkey  every reader, leaves included, keeps a current ReaderKey at gkm/rk/<sidecar_id>, replacing it with a
           fresh X-Wing pair once it is 6 days old, its not_after at most 7 days after signing, never re-signing
           an old pair, and keeping a replaced or lapsed private key until 30 days past its not_after, for the
           deliveries made to it, which open nothing a copy of its key cache does not; a delivery to s seals to
           the ReaderKey gkm serves at its time_ms, only if s's admitted identity key signed it and time_ms <
           not_after <= time_ms + 7 days + 10 min; a lapse stops deliveries, not authorization, so it is no
           expiry (§7.9), KeyHolders stays a function of the log and time, and s gets a late delivery to its
           new key, which one to an older key never blocks (10.6, 10.9)
covered    a covered agent reads R through its Delegation's wrap and holds no ReaderWrap there; it holds a key
           in its own right only where a grant names it
dwraps     the admin device that signs a Delegation writes late DelegationWraps of the current generation of
           every repo it can read in the Delegation's reach; any holder but a read_only one writes the rest
           on wrap-pending (10.9's late row); every rotation stages one per live Delegation in H
signer     every GenRotate is signed by a holder of R's key, or one covered, at a pin covering what it rotates
           for (a writer of R, or a config statement signer; 10.9), so a dropped sidecar, whose ReaderKey and
           wraps no later rotation contains, cannot sample or reissue the generation that excludes it

event                                     KeyHolders change                   gate, rotation, path epoch (§11.6)
reap of a covered agent, or a covered     none where its Delegation covers    none there; its own grants' repos
  ephemeral agent's not_after passing                                         shrink, or see an expiry
reap, revocation or Suspend of an         agent(s) leaves                     shrink: a REMOVE rotation excluding
  uncovered agent                                                             it; path epoch in 24 h, at once for
                                                                              compromise
DelegationRevoke{since_n}, or not_after   delegation(d) leaves; d's live      shrink or expiry: a REMOVE rotation
  passing                                 agents become uncovered holders,    excludes d and any parked agent and
                                          but those it admitted from a        wraps to the rest; path epoch in
                                          since_n > 0, which §7.9 parks; d    24 h, at once with a since_n > 0
                                          admits nothing more
Suspend, or SidecarRevoke for lost or     d's key drops at that position      shrink, as DelegationRevoke: the next
  removed, of a sidecar d admitted        (key_dropped_at); d's other live    generation is wrapped neither to d
                                          agents become uncovered holders;    nor to that agent (owner decision
                                          d admits until it ends, its later   114); path epoch in 24 h; after an
                                          agents uncovered                    Unsuspend the agent reads uncovered,
                                                                              by a late ReaderWrap (KF2)
SidecarRevoke{reason: compromise} of a    d ends there, as DelegationRevoke   shrink: a REMOVE rotation excludes d
  sidecar d admitted (§7.9's cascade)     with that since_n: its agents       and the parked agents; a path epoch
                                          admitted from since_n parked, the   at once
                                          rest uncovered holders
SidecarRevoke{reason: compromise}         delegation(d) leaves there          shrink: a REMOVE rotation excludes d
  whose closure voids d (§7.9)            (key_dropped_at); its agents,       and its parked agents; a path epoch
                                          parked, hold nothing until an       at once
                                          AdmissionConfirm, then uncovered
RepoGrant or requested grant expires,     the holder leaves at T_e, with no   expiry: a REMOVE rotation; path epoch
  or an uncovered agent's SidecarAdmit    entry (§7.9)                        in 24 h
  not_after passes
RecoveryRebind{reason: compromise}        none: recovery(m) keeps its         shrink by §7.9's compromise clause: a
                                          identity under a new key            REMOVE rotation; a path epoch at once
removal of a member device                leaf(s) leaves                      shrink: remove X above, a wrapped one
                                                                              by the rotation alone; a path epoch
                                                                              at once
ReaderKey lapse or replacement; a move    none                                none; its holder gets a late
  between leaf and wrap (owner decisions                                      delivery to its new key (10.9)
  144, 182)
```

**Residual (owner decision 114).** Every holder of a Delegation's reader key reads every later generation of the Delegation's reach (the config, a team network's directory and its tag repos) until the key drops: each agent it admitted, reaped ones and ephemeral ones past their own `not_after` included, since such an agent can close itself, and api can reap it, before any cutoff keyed to that `not_after` (§7.7), and each copy of its auth key. The key drops, at its position, at `DelegationRevoke`, at a revocation for any reason but reaped or a `Suspend` of one of its agents, and at a compromise revocation whose closure voids the Delegation (§7.9's cascade), and at `not_after`; reaping an agent does not drop it. A copy of the whole auth-key bundle also holds the Delegation's signing seed, which no honest daemon's erasure reaches: it admits fresh agents, uncovered once the key has dropped and so reading by their own ReaderWraps, until the Delegation ends at its `DelegationRevoke`, its void or a compromise revocation of one of its agents, or passes `not_after` or `max_admits`, after which api and every reader refuse its admissions, whatever bearer or client the operator supplies (§7.9's delegation row). A lost or removed revocation, or a `Suspend`, thus retires the key but not the admission authority; the revoking device's plan says so and offers `DelegationRevoke`, whose `since_n`, like a compromise revocation's, parks the agents the Delegation admitted from that position on (§7.10's agents row). Bounds: `not_after` is required, at most 90 days (§7.8); `max_admits` counts every admission for the Delegation's life; the console gives CI and cloud Delegations 30 days and replaces them (a new Delegation, then `DelegationRevoke` of the old) at each CI secret rotation and after a key drop.

| Content key | Use (symmetric sealing with XChaCha20-Poly1305; ids, tokens and pads with HMAC-SHA256) |
|---|---|
| `fek` | Wraps each object's random 256-bit key (PLAN.md:148) in a sealed segment header (general repos) or a deletable slot (record-class repos, group inboxes; 10.8); a versionless path in those repos, the search index's files included, keeps one key in a slot only that path's versions name, until a REMOVE generation, a CLOSURE or `ur evs rekey` replaces it (§11.7, §11.14) |
| `manifest` | Names, entry fields, push metadata and ref names (§11) |
| `path` | Token keys per path epoch (§11.6, owner decision 2) |
| `ref` | Ref ids and the search index's document keys, from RK_1 for the repo's life, since ref ids name every `head/`, `log/` and `idx/` key (§11.6) and a document's key must not change at a rotation (§11.14) |
| `drop` | An X-Wing key pair for deposits that depositors cannot read back, published in its generation's GenRotate under the depositor rule below |
| `groupinfo` | Seals GroupInfo and its tree per (group_id, epoch) |
| `index` | Draws the keyed pad that hides which trigrams a search-index shard's documents share (§11.14); per generation, which the shard's header names, so a removed reader cannot predict a later shard's size |

```text
depositor (D-KEYS-17)  before sealing to generation g's drop key, a depositor, which reads the config,
           requires: GenRotate_g verifies; g is the newest generation gkm serves (10.14's drop-key route); g
           covers R's holders_shrunk_at and every holder expiry up to now in its own state (§7.9); now <
           drop_not_after_ms; g is not below its pin for R, which it then raises; else it waits for a newer
           rotation, which the gate makes writers write
```

Clients cache every RK_g in the §5 keychain, keep MLS state, trees included, on disk under §5's AEAD, load one group's tree at a time (§18.4's budgets) and delete other epoch secrets (RFC 9420 §9.2). Every derivation and unwrap calls §22's `testHookSecret`.

### 10.6 GKM: the Delivery Service and wrapped-key store

GKM is a strongly consistent Delivery Service (DS; RFC 9750 §5.2.1) with no state of its own: its records are metadata-cluster objects ordered by conditional writes (owner decisions 2, 21, 145). It verifies 15-minute capability tokens offline (aud `gkm`; scopes `repo:<id>:r|rw|admin`, `deposit` on the drop-key route only, and an unadmitted client's `recovery:<member_id>` for that member's own recovery wraps), honors an `r`, `rw` or `admin` scope only while its subject reads or writes the repo, as the scope says, in gkm's newest verified state (§8.12), and honors §7.8's `rev/` objects. Each route takes the scope the scopes block below gives.

```text
object (epochs zero-padded)                   written                       holds
on the repo's cluster
gkm/repo/<repo_id>/<seq>                      If-None-Match                 GroupForm, Signed by a repo admin's device
                                                                            (for owner-bound kinds, only the owner's
                                                                            consented device) or by a network admin's
                                                                            outside owner-bound kinds
gkm/<group_id>/epoch/<n>                      If-None-Match, once n-1       0: creation; else the commit, header,
                                                exists                      uploader, time, GenWrap_n of the newest
                                                                            generation; at most 16 leaves, the sealed
                                                                            GroupInfo
gkm/<group_id>/gen/<g>                        If-None-Match, by the         the Signed GenRotate, for the repo's life,
                                                rotating writer (10.5)      or until a gen pack holds it (10.16)
gkm/<group_id>/group-info                     If-Match, rising              at most 16 leaves, a pointer {epoch},
                                                                            rewritten at each Add and by gkm with any
                                                                            epoch object carrying a GroupInfo 16 or
                                                                            more past it, so a crash between the two
                                                                            PUTs heals at the next commit; above, the
                                                                            sealed GroupInfo a leaf writes on demand,
                                                                            at most once per epoch and only for a join
                                                                            or resync, never with another commit,
                                                                            since a 1,000-leaf GroupInfo is ~0.7 MB on
                                                                            each drive; a resyncing device reads the
                                                                            pointer and probes epoch/<n+1>.. until a
                                                                            404, uncapped, ~16 GETs without a crash
gkm/<group_id>/welcome/<n>                    after epoch n, by its         the Welcome; recipients' KeyPackageRefs in
                                                uploader                    the clear
gkm/<group_id>/wrap/<g>/<c8>/<recipient>/<k8> If-None-Match; staged before  ReaderWrap (s:<sidecar_id>) or
                                                a claim, or late by any     DelegationWrap (d:<delegation_id>),
                                                holder but a read_only one  sealed to the key k8 names,
                                                (10.9)                      k8 = hex(recipient_key_sha256[0:8])
gkm/recovery/<member_id>/<group_id>/<g>/<c8>/<b8>
                                              If-None-Match, staged like    RecoveryWrap (bindings: §7.9's
                                                wraps or by a rebind        RecoveryBind) of the binding b8 names:
                                                (10.8)                      hex(SHA-256(its Ed25519 key)[0:8])
on the first cluster, per sidecar
gkm/welcome/<sidecar_id>/<ref>                with the Welcome              pointer {group_id, n}
gkm/kp/<sidecar_id>/<ref>                     by the sidecar                a one-time or last-resort KeyPackage
gkm/kp/<sidecar_id>/<ref>.claim               If-None-Match, then <ref>     {group_id, claimer}
                                                deleted
gkm/rk/<sidecar_id>                           by the sidecar                ReaderKey
in Redis (soft state, owner decision 136)
{gka_<group_id>}                              gkm for the leaf, at most     each leaf's newest applied epoch and when;
                                                daily                       since, the family's creation time; 31 d
c8 = hex(C_g[0:8]); staged objects whose c8 is not gen/<g>'s are deleted after 24 h; a recipient's delivery of
  g to an older key goes 30 days after one of g to a newer key of that recipient exists

placement (owner decision 145): a group's objects live on the cluster its repo's create-only place/<repo_id>
  names, which evs writes on the first cluster when it creates the repo, its If-None-Match deciding a race
  (§11.8); gkm resolves it from the token's repo and caches it for the repo's life, since a repo's cluster
  never changes without a later move tool, and a re-formed group stays on its repo's cluster; per-sidecar
  objects live on the first cluster beside place/, proj/, projrows/ and rev/, as §11.8's first-cluster row
  lists (§7.8, §7.9); a recovery fetch lists recovery/<member_id>/ on each cluster; v0 has one cluster,
  8 × PM9A3 1.92 TB at EC:4, ~7.7 TB usable (§19.6)
```

```text
duty               mechanism
one commit         epoch/<n> is created with If-None-Match once epoch/<n-1> exists; the first wins, and the loser
                   gets 409 with the winner
checks             the token scopes the repo, whose newest GroupForm names the group and whose repo/<id>, reread
                   as gkm issues each write (cached at most 5 s, like §11.13's skip rule), is active, or keying
                   for its group's creation or re-forming (KF1, 10.8: the GroupForm, epoch 0, ladder and first
                   wraps), or deleted for a repo re-seeded as deleted in §19.10's re-seed mode; so a write in
                   flight at a shred lands before §11.12 repeats the group's deletion; an external commit names
                   the uploader; the header passes the epoch PUT check, gen/ claims the claim checks and wraps
                   the wrap checks below, each route under its scope (scopes, below); sizes; 60 commits per
                   hour per uploader per group; §11.13's NVMe write budget, which never refuses Removes and
                   REMOVE rotations and queues other commits, Adds, Welcomes, KeyPackages, ReaderKeys, LATE
                   deliveries and GroupInfo per network, refusing the heaviest first (429, RESOURCE_EXHAUSTED);
                   a staged delivery or claim of g+1 is a REMOVE rotation's only while gkm's newest verified
                   state shows a shrink, an authorization expiry or a compromise retirement since gen/<g>'s
                   auth pin and time (the causes of 10.9's REMOVE that gkm can see, a poisoned parent not among
                   them), and a commit to epoch/<n>, whose PrivateMessage gkm cannot read, counts as a Remove
                   only while that state shows a holder dropped since epoch/<n-1>'s auth pin and time (10.9's
                   roster row); else each is §11.13's P1
Welcomes           written only after their epoch object, by its uploader, so a loser's never exist; joiners get
                   a pointer and a welcome hint; if the uploader crashes first, a writer leaf removes and re-adds
                   the joiner after 10 minutes
GroupInfo          with an Add, for its joiners, and inside every epoch object in groups of at most 16 leaves,
                   for recovery with no leaf online (10.8); else a resyncing device's ?want= hints wrap-pending
                   every 60 s until a leaf writes the current epoch's (KF5)
KeyPackages        up to 128 one-time and 1 last-resort per sidecar, valid 90 days, refilled below 32; a sidecar's
                   first upload hints pending to the writers of each repo it reads (KF2); a claim creates
                   <ref>.claim with If-None-Match, then deletes <ref>, so a one-time KeyPackage serves one claim,
                   for a target the newest state lists as a reader; 10 per minute per (claimer, target)
retention          (Q-KEYS-11) the reconciler deletes epoch/<n> once it is 30 days old and every ack written in
                   the last 30 days has passed n, never the newest epoch, and only while the ack family has
                   existed 30 days, so a lost family delays deletions and never causes one; before deleting the
                   epoch group-info names, it moves the pointer to the newest; a preservation hold pauses this
                   sweep (§21.9; owner decision 133)
pending changes    the reconciler hints pending on the per-client gkm topic of the group's writers, the revoking
                   device first, when an entry shrinks or grows the repo's key holders, and every 60 s while its
                   gate is closed; in the directory group this hint, and a first KeyPackage upload's, goes only
                   to the signer of the statement it answers and to the config writers (10.9)
late wraps         a recipient whose GET wraps/<g> finds no delivery of g, the newest generation, to a key it
                   holds asks with ?want=<its current k8>&since=<its first ask>, at most once a minute; gkm then
                   hints wrap-pending naming it on the per-client gkm topic of R's writers (in the directory
                   group, the config writers) and, once since is 15 min old, of up to 64 other holders, the
                   recipient's member's (an agent's sponsor's) devices first, then by identity bytes; a hinted
                   holder waits 0-15 s at random and, only if its newest verified state lists the recipient in
                   KeyHolders (10.5), GETs the recipient's ReaderKey, checks it (10.5's readerkey) and PUTs a
                   LATE delivery to it at that state (10.9's late row); a 412 returns the winner, which it judges
                   (10.9), and an unknown outcome repeats the PUT, which then answers 201 or 412

claim checks, POST /gkm/groups/<id>/gen/<g>
scope      rw on the repo, or in the config group a member device's rw, never a read_only one's (§7.8)
chain      generation = g; gen/<g-1> exists and parent_commitment equals its commitment
auth       auth.version >= gen/<g-1>'s and the previous base's position, and auth matches proj/ at that version
time       time_ms within 10 min of gkm's clock
signer     admitted, not read_only, and not revoked, parked or suspended in gkm's newest state
leaf wrap  its epoch exists
rate       60 per hour per uploader per group

wrap checks, POST /gkm/groups/<id>/wraps/<g>/<c8>
object     wrap/<g>/<c8>/<recipient>/<k8>, If-None-Match; the body's group, generation, commitment prefix,
           recipient and key digest agree with the path; STAGED only while gen/<g> is absent, or of generation 1
           by gen/1's signer while the repo is keying for its creation (KF1); LATE only once gen/<g> exists, is
           gen/'s newest and carries the body's commitment
signer     admitted, not read_only, and not revoked, parked or suspended in gkm's newest state
late       auth.version >= gen/<g>'s and the previous base's position, auth matching proj/ at that version;
           time_ms within 10 min of gkm's clock; the recipient reads R in gkm's newest state; a ReaderWrap's
           key digest names the ReaderKey gkm serves at rk/<recipient>
bound      one object per (recipient, key); the late row's key check allows one LATE one per ReaderKey a
           recipient publishes, which own's upload limit bounds (scopes, below), and §11.13's budget queues
           them; an uploader's STAGED objects in a group stay within 60 an hour per reader and live
           Delegation of R, the claim rate's worth

epoch PUT check, POST /gkm/groups/<id>/epochs/<n>
header     GkmCommitHeader.generation is gen/'s newest index as gkm read it before the PUT (a rotation landing
           in between is harmless: joiners fetch a late wrap) and never below the previous epoch's; its auth
           pin exists and never falls; one exception: an external commit by a device that its member's
           recovery key admitted may say generation 0 and carry no GenWrap (10.8), and the group's next
           commit carries gen/'s newest generation

scopes, per route (aud gkm; §7.8's exchange gives a read_only device, and a reader that writes nothing, only r)
own        POST /gkm/reader-key and /gkm/key-packages: any gkm token whose ur_sidecar_id is the record's
           sidecar_id (a KeyPackage's, its credential's), of a sidecar admitted and not revoked, parked or
           suspended in gkm's newest state; KeyPackages only from member devices (untagged, not ephemeral);
           a ReaderKey at most once per 24 h per sidecar after its first
read       GET of a group, its epochs, gen/, wraps (the caller's own: its s: objects and its covering
           Delegation's d: ones), group-info and Welcomes, and POST ack (its own leaf's): r, rw or admin;
           GET reader-key/<sidecar_id>, a public record, under any gkm token of an admitted sidecar
leaf       POST epochs/<n>: r, rw or admin, from a member device reading R; gkm sees no proposal in a
           PrivateMessage, so members refuse what its committer may not commit (10.9), from a read_only
           device all but a path-only commit; an external commit names its uploader and removes at most its
           own old leaf, but for 10.9's recovery self-join
info       POST group-info: r, rw or admin, from a member device reading R that is not read_only
deliver    POST wraps/<g>/<c8>: r, rw or admin, under the wrap checks
write      POST gen/<g> (claim checks), key-packages/claim and welcome/<n> (epoch n's uploader only): rw, or
           in the config and directory groups the rw §7.8 gives a member device or a sidecar that is not
           read_only; admin: POST /gkm/groups and forms
recovery   GET recovery/<member_id>/wraps: a device of that member, or its unadmitted client under
           recovery:<member_id> (§7.9); POST: a rotator staging, or that member's device re-wrapping after a
           rebind (10.8), under r, rw or admin of the group's repo; DELETE: that member's device
deposit    reaches GET drop-key only, which r, rw and admin also reach (10.14)
```

**Write gate (D-KEYS-6; D-EVS-18).** The predicate below, over §7.9's causal identities, decides which writes a key-holder change blocks; §11.8 enforces it at each ref's head CAS. Target: p99 close-to-reopen ≤5 min with a writer online, in the directory group a hinted or pushing one (10.9); alarm at 1 h.

```text
pass      a push or deposit to R declaring generation g passes only if g covers R's holders_shrunk_at in evs's
          newest verified state and no holder of R expired in (t_g, now] (§7.9's coverage)
shrinks   SidecarRevoke, MemberRevoke and parks (§7.9's compromise cascade); api's reap of an ephemeral
          sidecar no live Delegation covers; Suspend; GrantRevoke and RepoRevoke of a grant that reads;
          DelegationRevoke and a Delegation's key drop (10.5); a compromise retirement (SidecarRevoke or
          RecoveryRebind with reason compromise, or a leaked bundle's DelegationRevoke with since_n > 0), a
          shrink by §7.9's test though a rebind keeps recovery(m)'s
          identity; an authority statement's completion that drops a holder; any base whose rows drop one
expiries  RepoGrant and requested grants' expires; an uncovered agent's SidecarAdmit and a Delegation's
          not_after (a member device's admission carries none, §7.9); a ReaderKey's lapse is none (10.5)
never     admissions, grants, OwnerConfirm, Unsuspend, routine RecoveryRebinds, reaps of covered agents and,
          where their Delegation covers, ephemeral agents' own not_after, and a member device's move between
          leaf and wrap (10.4; owner decisions 144, 182)
window    heads' auth pins never fall (§11.8); a push validated before a shrink commits ordered before it,
          within §11.8's bound: about 10 s, 5 min if api's notification is lost, plus §19.6's 10 s store
          request deadline, since §11.8 issues and reissues a head PUT only within 5 s of its validation, or,
          for one whose drive commits stalled, until §19.6's settle rule releases the head, which no read or
          commit passes meanwhile
```

**Sizes (D-KEYS-14)**, from RFC 9420's structures, which §22.8 measures at M2:

```text
inputs: X-Wing key 1,216 B, ciphertext 1,120 B (GOROOT/src/crypto/mlkem/mlkem.go:27, :30;
  GOROOT/src/crypto/hpke/pq.go:27-29, :110, :165); Ed25519 key 32 B, signature 64 B
  (GOROOT/src/crypto/ed25519/ed25519.go:34, :38); credential 207 B

per group                                   10 leaves    100 leaves    1,000 leaves
tree (ratchet_tree), parents blank .. full  16-27 KB     158-282 KB    1.58-2.83 MB
commit with a path (Remove, self-update),   11-17 KB     18-126 KB     26 KB-1.18 MB
  every parent full .. blank
sealed GroupInfo                            the tree plus 1.6 KB (GroupInfo with external_pub); at most
                                            16 leaves, under 50 KB, inside each epoch object
self-updates a day at 10.4's interval       1.4 (7 d)    3.3 (30 d)    33 (30 d); 143 at 7 d
  so a full 1,000-leaf group uploads ~0.86 MB of self-updates a day, which each leaf fetches, and a
  device a week away lacks ~233 commits (~6 MB) and resyncs from one 2.8 MB GroupInfo (KF5)

per object
KeyPackage 2.85 KB; leaf 1.54-1.57 KB; parent 1.25 KB plus 4 B per unmerged leaf
Add-only commit 0.2 KB plus 2.85 KB per joiner; Welcome without the tree 0.4 KB plus 1.2 KB per joiner
ReaderKey 1.34 KB; ReaderWrap and DelegationWrap ~1.37 KB per holder per rotation, ~1.42 KB late;
  RecoveryWrap 1.17 KB; GenRotate ~0.5 KB, ~1.7 KB with a drop key; GenWrap, LeafWrap and GenLink 72 B

store operations, for §11.13's budget (§7.8's rev/ GETs besides)
commit       gkm: GET epoch/<n-1>, GET repo/<id> (5 s cache), GET gen/<g+1> (404), If-None-Match PUT epoch/<n>;
             each leaf: 1 LIST, 1 GET; at most 16 leaves, +1 group-info GET (5 s cache) and, 16 epochs past it,
             a pointer PUT
rotation     GET gen/<g+1> (404), W staged PUTs, 1 claim PUT; a leaf rotator's leaf wrap rides in the claim
Add          +per joiner: claim PUT and DELETE, Welcome and pointer PUTs; +1 group-info PUT (the pointer at
             <= 16 leaves)
ack          one Redis write per leaf per group per day; none on the metadata cluster
ReaderKey    one gkm/rk/ overwrite per sidecar every 6 days, on the first cluster
late wrap    GET rk/<recipient> (first cluster) and gen/<g>, 1 PUT; a fetch 1 GET, +1 LIST of the recipient's
             prefix on a miss
drive cost   ~17 KiB a commit (three blocks) and ~9 KiB per other create on each drive, 14 KiB an overwrite
             (§11.13); gkm totals ~0.014 DWPD in year one and ~0.14 in year two at the rotation upper bound
capacity     gkm/ holds ~15M objects, ~70 GB of each 1.92 TB drive, in year one (§19.9)
```

**What GKM sees.** §2.8 adopts these rows verbatim; owner decision 115 confirmed them (Q-KEYS-12).

```yaml
gkm-1:
  sees: GroupForm chain (repo_id, group_id, previous group, generation, signer); epoch 0 (network_id, cipher suite 0x0010 (owner decision 44), creator)
  why: one accepted commit per epoch; re-forming
  ttl: life of the repo
gkm-2:
  sees: epoch objects; group_id, epoch, content type, generation, auth pin, size, time, uploader sidecar_id; the commit as PrivateMessage ciphertext; GenWrap
  why: ordering; the write gate
  ttl: 30 d, then until every leaf acking in the last 30 d has applied it; never the newest epoch
gkm-3:
  withdrawn: no roster delta in the clear (owner decision 59); membership shows only as sidecar ids in gkm-4, gkm-5, gkm-7 and gkm-10, as in api-7
gkm-4:
  sees: "KeyPackages (init and leaf HPKE keys, signature key, credential: sidecar_id, identity key, suite, not_after, admission hash, signature); claims (group, claimer, target); ReaderKeys (owner decision 114)"
  why: asynchronous adds; wrapped readers
  ttl: KeyPackages until claimed, or 90 d; claims 90 d; ReaderKeys until replaced or past their not_after, at most 7 d
gkm-5:
  sees: Welcome objects and pointers; recipient sidecar_ids and KeyPackageRefs in the clear; secrets and GroupInfo encrypted
  why: deliver joins
  ttl: until every recipient has acked, at most 90 d
gkm-6:
  sees: external commits, for resync and recovery only (PublicMessage); the joiner's leaf and credential, its removed old leaf, their ExternalInit and Remove proposals and their UpdatePath's public keys and encrypted path secrets
  why: offline catch-up and recovery
  ttl: as gkm-2
gkm-7:
  sees: key ladder; GenRotates (group, generation, parent and own commitments, cause, auth pin, time, holders hash, signer; GenLink and leaf-wrap ciphertexts; the drop public key where the kind takes deposits); GroupInfo pointers and, above 16 leaves, sealed GroupInfo; staged and late wraps (group, generation, commitment, recipient sidecar_id or delegation_id and the SHA-256 of the key sealed to, staged or late, a late one's auth pin and time, ciphertext, signer; owner decisions 114, 144, 182)
  why: ladder, resync, deposits; wrapped readers
  ttl: life of the repo, a gen pack's GenRotates as gen/'s; GroupInfo until superseded; wraps until the next generation's exist, staged wraps of a lost claim 24 h, a recipient's wrap to an older key 30 d after one to a newer key exists
gkm-8:
  sees: recovery wraps (member_id, group_id, generation, an 8-byte prefix of the binding's Ed25519 key hash, which the authorization log already shows, HPKE ciphertext); the bindings are §7.9's RecoveryBind config records, not gkm objects
  why: recovery after losing every device
  ttl: until a RecoveryRebind replaces them or the repo is deleted; staged ones of a lost claim 24 h
gkm-9:
  sees: request log; client, route, group, time, bytes (GroupInfo requests included)
  why: rate limits, abuse
  ttl: 7 d
gkm-10:
  sees: acks in Redis {gka_<group_id>}; group_id, sidecar_id, newest applied epoch, time; written at most daily
  why: retention
  ttl: overwritten by the leaf's next ack; 31 d after its last write; deleted with its group's gkm objects at a shred (§11.12); soft state outside the rdb bundles, lost with Redis, after which gkm deletes no epoch for 30 d; a hold's copy excepted (api-14)
```

### 10.7 Flows

**KF1. Create a repo.** A member's device C files §8.8's `RepoCreate`, creates the repo in evs as `keying` (§11.12), placing it (owner decision 145), and becomes its admin (owner decision 8); a config repo follows §7.9's bootstrap. `POST /gkm/groups` writes `epoch/0` (a random 16-byte group_id, GenWrap_0 and the sealed GroupInfo), `gen/1` (the GenRotate of a new RK_1, without a parent) and C's GroupForm. C writes generation 1's deliveries (10.5's step 3: ReaderWraps, DelegationWraps, RecoveryWraps) while the repo is still keying, resuming from its keychain after a crash, and only then has evs activate it, so no content predates its recovery wraps. C then adds the other leaves in one Add-only commit with its Welcome and GroupInfo.

**KF2. Add a device D.** D enrolls, its `SidecarAdmit` enters the authorization log (§5.6, §7.9), and it uploads a ReaderKey and, as a member device, KeyPackages (a device a restored binding admitted, only once anchored, 10.8). Once the state lists D where its subject reads, and again at D's first KeyPackage upload (10.6), GKM hints `pending` to the writers, and a committer per 10.9 claims a KeyPackage and commits the Add with other pending changes, the Welcome, the sealed GroupInfo and GenWrap; an agent, or in the config or directory group a member device that is wrapped or has no KeyPackage (10.4; owner decisions 144, 182), gets a late ReaderWrap of the current generation instead, signed at a state that lists D (10.9's late row), and a covered agent reads at once through its Delegation's wrap. D checks RK_g against `gen/<g>`'s C_g and walks the ladder (10.5). Owner-bound repos park a D without its owner's consent (§8.5; owner decision 126), whose devices raise `approval_pending` until an `OwnerConfirm`.

**KF3. Add a member N.** A repo or network admin signs N's grant into the repo's access log (§8.8; owner decisions 7, 8), or in an owner-bound repo the owner's device an `EvsShare` (owner decision 126), and KF2 runs for N's devices: the granting device at once, other writer leaves after 15 s plus jitter; while none is online, N waits and nothing leaks.

**KF4. Remove a member or device X** (§7.10). The revocation's log entry n' drops X from the key holders of every repo it read, so evs refuses writes whose generation does not cover n' (10.6, §11.8), and evs and gkm refuse X's tokens (§7.8). A committer per 10.9, the revoking device first, commits the Remove with a path; any writer then rotates (10.5), staging its wraps before it claims `gen/<g+1>`, at the latest through `EnsureWritable` before its next write, so reaps batch. A wrapped X needs only the rotation, and a wrapped revoker in the config or directory group rotates first, leaving a leaf X's Remove to the next leaf commit (owner decisions 114, 144, 182). D-TRUST-10's witness stop never holds a Remove, rotation or revocation (owner decision 129).

```text
   api (§7.10)       evs               gkm               writers
1  |--entry n'------>|                 |                 |   holders_shrunk_at = n': 412 below; receivers 451
2  |                 |                 |--hint pending-->|   per-client gkm topic, the revoking device first
3  |                 |                 |<--epoch/<e+1>---|   a writer leaf: Remove + path; header (g, (n', A'))
4  |                 |                 |<--gen/<g+1>-----|   any writer: staged wraps, then the claim at (n', A')
5  |                 |<--write at g+1, auth >= n'---------|   the gate passes it
```

**KF5. Offline catch-up.** Up to 100 epochs behind, the device replays each later commit in order (each epoch derives from the previous `init_secret`). Further behind, or if commits were pruned, processing fails or its leaf was removed as stale, it opens the current sealed GroupInfo (10.6) with the key of the generation it names, from its wrap (a device none of whose keys opens a delivery of it, its ReaderKey lapsed or past retention, publishes a new one and asks for a late delivery to it, 10.6's late wraps), and resyncs by external commit (ExternalInit, a Remove of its old leaf, GenWrap_{e+1}); else it awaits a re-add or uses its recovery code (10.8). Nothing is lost.

**KF6. Concurrent commits.** The 409 loser, having stored no Welcome, processes the winner and retries what remains. Rotations race only on `gen/<g+1>` (10.5).

**KF7. gkm unavailable.** Cached keys serve reads and deposits; evs checks the gate itself from the authorization log, so writes continue while every shrink is covered, and a removal still stops them until gkm returns and a writer rotates. Joins, catch-up and membership changes wait.

### 10.8 Revocation, erasure, recovery, re-seeding, key domains

**Removed or expired holder X (owner decision 64).** X keeps what it held up to generation g and loses everything after: the generation that covers its drop is cause REMOVE (10.9), so content rewraps lazily, each file's next write a full checkpoint under a fresh object key (§11.7; Q-KEYS-10), the search index's versionless files included (its heads at their writer's next push, its shards at their next merge or roll-up; §11.14), and path tokens re-key through §11.6's path epoch, at once for a member's device or a compromise, within 24 h for other drops and for expiries (owner decision 2), or, while two source epochs stand, once one drops; §11.6 reconciles the two.

**Erasure (owner decision 61).** An entry's key lives only in a deletable slot (§11.12), so an ERASE push deleting it, cached copies and mirrors' slot copies (§11.12) shred the entry even if ciphertext survives; §11.12's CUT first fences the index's publication of it, then its CLOSURE rewrites the search index's files holding its postings without it, under fresh keys in new slots, and the ERASE destroys their old slots' keys, one of which every older stored version of those files uses, staged bytes in a batch included (§11.14); no operator copy holds slots or wraps (owner decision 90), and owner devices' mirrors hold slot copies and apply each erasure (§11.13). gkm, like evs, refuses a `deleted` repo but for a re-seed's GroupForm (below; owner decision 82); its shred (§11.12) deletes the repo's gkm objects and `{gka_}` acks, and again after 10 min for writes in flight (10.6's checks), even under a preservation hold, subject to counsel (owner decision 133), and members drop its keys.

**Recovery when M loses every device (owner decisions 62, 127, 128, 149).** §5.9's recovery code derives X-Wing and Ed25519 keys that §7.9's `RecoveryBind` binds to M; every rotator, agents included, wraps RK_g to every reading member's current X-Wing recovery key, a public key every config reader holds, and the ladder opens older generations.
- With the code, a new device is admitted by the recovery key under §7.9's window and veto, meanwhile reading only the authorization log and M's own recovery wraps (10.14). The window and veto bound admission, not those wraps, which the code opens at once: a code holder with M's login holds every generation wrapped to M's recovery key and, through the ladder, each earlier one, and with the operator's ciphertext reads them, whatever a veto does, until `RecoveryRebind{reason: compromise}`; revoking the device it admitted does not retire the code (§2.10). It fetches its recovery wraps (the newest per group whose b8 names its code's binding, 10.6) and, once admitted, first passes §7.9's `anchor` on its config-group RecoveryWrap, raising §5.4's `head_alarm` (fork) and acting no further otherwise; only then does it open each group's sealed GroupInfo, self-join by external commit the config group and every group M writes (owner decision 128), join the others through KF2, revoke M's lost devices through §5.6's calls (D-CORE-20; k of n for an AdminSet member's devices, its own signature counting as one), remove their leaves and rotate (10.5), in any order: a self-join may leave revoked leaves if it carries no GenWrap (generation 0) and its next commit removes them, so no generation reaches a thief's leaves. Above 16 leaves, a self-join waits for one leaf online to write the current GroupInfo; past the first 1,000, the device reads the config and the team directory by their RecoveryWraps, then by wraps (§7.9; owner decisions 144, 182).
- A binding a void restored takes no RecoveryWrap until a signer outside P signs it again (§7.9's cascade), so the device it admits, once its proposal activates, keeps §7.9's `restored` order, anchoring on a ReaderWrap, never an Add: it uploads its ReaderKey but no KeyPackage, fetches the late ReaderWrap of the config group's current generation that a config writer gives it (KF2), or one a later rotation stages while e's tree lacks it (10.5), and passes the anchor on that wrap's RK_g, with the same alarm and stop on a failure. Only then does it self-join the config group if leaf-entitled, by the one sealed GroupInfo that RK_g opens (else reading the config by those wraps), upload KeyPackages, so that KF2 adds it to its other groups, revoke, remove and rotate as above, and offer `ur keychain recovery-rotate` (§5.9), whose binding takes RecoveryWraps again; a group whose leaves are all in P opens to it only through that binding's surviving RecoveryWraps.
- `ur keychain recovery-rotate` (§5.9) signs a `RecoveryRebind` (§7.9), re-wraps each group's current generation to the new binding at that binding's own b8 path (10.6), deletes M's old binding's wraps only once every new one exists, so a crash between leaves both and its retry finishes, and requests a `request` rotation in M's groups, or, for a code retired as compromised (`RecoveryRebind{reason: compromise}`), a `remove` one, which starts an immediate path epoch and full checkpoints (§11.6, §11.7). No rebind or void reaches a keychain backup sealed before it, whose `keychain.wrap` the retired or voided code still opens (§5.9), yielding that device's identity key, ClientKey seed, ReaderKeys and key cache, so after a compromise rebind or a void each device whose backups may hold such a sealing is revoked as compromised (§7.9) and enrolled anew, since `--replace` keeps its identity key (§5.5).
- Without the code, admins revoke the lost devices and admit a new one (§7.9), moving every team repo M read to a new generation; M's owner-bound repos, which need M's consent (owner decision 126), and single-member repos are lost.

**Site loss (D-KEYS-13; order in §19.10).** gkm objects have no off-site copy (owner decisions 90, 94), but devices keep each group's MLS state and every RK_g: a device 10.6's GroupForm rules allow, a repo admin's and for owner-bound kinds the owner's consented device, re-forms each group under a GroupForm linked to the cached RK_g, re-uploads the ladder and re-adds readers and RecoveryWraps, and members check the signer and their cached C_g. A repo re-seeded as deleted (§11.13) takes only that GroupForm, with its epoch 0 and ladder, while deleted (owner decision 82): devices open its files from their cached RK_g once it is restored, its readers rejoin by KF2 and late wraps, and a shred deletes the group. Slots return from owner devices' mirrors (§11.13). Repos no device holds are lost (§2.18).

**Key domains ([R:product] S4)**, each its own repo and group, take §8.5's kind defaults as readers, which policy narrows (owner-bound kinds: owner decision 126).

| Domain | Readers (agents by wrap) | Deposits by drop key |
|---|---|---|
| Author vault ([R:product] S1, S2) | the author's consented devices; `EvsShare` recipients | the author's other devices, tagged and headless sidecars |
| Team record ([R:product] S3; X20) | admins' and auditors' devices | members' and tagged sidecars; authors keep copies |
| Shared team repos | every reading sidecar (§8) | — |
| Config (§7.9); a team network's directory (§16.11) | every admitted sidecar; member devices past the first 1,000 by wrap (owner decisions 144, 182) | — |
| Burner vault and mailbox (§15) | the user's consented devices | `tag:mail` mail indexers (owner decision 150), which cannot read the archive |

**Escrow (owner decision 63).** None by default, and never silent: Team's v1 opt-in `tag:audit` reader on a customer device (sidecar/design/improve.md:106-108; §8.5's `audit` block under a k-of-n `AuditOptIn`) gets ReaderWraps only once every member's config holds the block and each affected reader list shows it.

### 10.9 Authorization of MLS operations

GKM sees no proposal (owner decision 59), so members verify each decrypted commit and each wrap against its header, the authorization state at its auth pin (§7.9) and the repo's access log (§8.8). On a mismatch a member alarms and never adopts or encrypts to the epoch or generation; a bad commit can stall a group until an admin revokes its committer and the group re-forms through the ladder. GKM originates nothing; no group has external senders (I-4).

**Committers (owner decisions 113, 114, 128, 144, 182).** The signed input, not the committer, carries the authority, so no membership change waits for an admin, and members reject a commit without it. Wrapped writers (agents, and the config and directory groups' wrapped member devices, 10.4) rotate by re-wrapping but never commit an Add or Remove.

```text
Add            committer  a writer leaf, the granting device first; for a first wrap (an agent's, a
                          Delegation's or a wrapped member device's), any holder but a read_only one by the
                          delivery checks' late row, gkm hinting writers first (10.6); in the config and
                          directory groups also the admission's signer, by an Add from its leaf, or by the first
                          wrap if it or the device is wrapped, and from its leaf the signer of a revocation that
                          made the device leaf-entitled (§7.9's move)
               check      a signed grant in the access log, admission or EvsShare, or owner decision 63's audit
                          assignment; in an owner-bound repo only the owner's consented devices (§8.5) and their
                          EvsShares (owner decision 126); in the config and directory groups a leaf only for a
                          leaf-entitled device (§7.9); admitted, unrevoked, unparked, outside URnetwork platform
                          networks, key pinned, KeyPackage claimed for this group
Remove         committer  a writer leaf, the revoking device first; in the config and directory groups also the
                          revocation's signer from its leaf, a wrapped signer rotating instead; never the target
                          (RFC 9420 §12.2)
               check      its signed input: a SidecarRevoke or MemberRevoke (which a server deactivation
                          follows), a park (§7.9), a Suspend, a revoked or expired grant, in the config and
                          directory groups the target's loss of leaf entitlement at the auth pin under §7.9's
                          rank (it reads on by wraps), or staleness, whose input is §7.9's stale_leaf_days (90)
                          past the target leaf's last change epoch, which members check against their own record
                          and the epochs' times; a stale-removed device returns by resync (KF5)
Rotation       committer  any writer that holds the key, as a holder or covered by a Delegation, at a pin
  alone                   covering what it rotates for, wrapped ones included (owner decision 114); in the config
                          group also the signer of the admission or revocation (owner decision 128) or, after
                          the reap of an uncovered ephemeral agent, of its admission (§7.10), each while a holder
               check      the rotation checks below; deliveries only to key holders (10.5)
Self-update    committer  the leaf itself, by a path-only commit
               check      sidecar_id and identity key unchanged
External       committer  the sidecar itself
  commit       check      resync (same sidecar_id and key, removing at most its old leaf), or a recovery-admitted
                          device's self-join in the config group, if leaf-entitled, or in a group its member
                          writes, under the Add row's checks; it may leave revoked leaves, carrying no GenWrap
                          (generation 0), if its next commit removes them
GroupContext   committer  a repo admin's leaf (required_capabilities); rotations need none
  Extensions   check      kind and owner never change
Directory      committer  every admitted sidecar reads the team directory and all but read_only ones write it
  group                   (§16.11), so each admission makes its subject a reader there and its signer seats it
                          at once by the Add row; a revocation's signer commits by the Remove row a leaf
                          target's Remove, then the rotation, and after api's reap of an uncovered ephemeral
                          agent the device that signed its admission rotates, as in the config group; any other
                          writer leaf may commit after 15 s plus jitter (KF3; owner decisions 113, 182)
               hints      gkm hints pending there only to that signer, at once, and to the config writers, which
                          act after 15 s plus jitter; an unhinted writer rotates only for a push the gate
                          refuses, after a random wait of up to 15 s that a covering generation ends, so one
                          rotator normally stages a rotation's wraps (~1.3 KB a wrapped reader) and the gate
                          reopens within ~20 s of the first push it refuses
ReInit, PSK, external or standalone proposals: refused

rotation checks: every member, for each GenRotate
signer    in KeyHolders(R, auth, time) or covered by a Delegation in it, and a writer at auth or, in the config
          group, the signer of the statement it answers (owner decision 128) or, after the reap of an
          uncovered ephemeral agent, of its admission (§7.10)
chain     parent_commitment chains; auth is on my chain and not before my previous base
holders   holders_sha256 equals my recomputation; each staged delivery I read passes the delivery checks
          below; a leaf_wrap's epoch tree holds no non-holder leaf
cause     REMOVE iff the generation covers a shrink, an authorization expiry (10.6's expiries) or a compromise
          retirement since the parent, or its parent is poisoned (below)
time      time_ms <= my clock + 60 s and >= the parent's
poisoned  a delivery the delivery checks below judge invalid: members alarm, never seal to the generation and
          rotate at once (cause REMOVE), and admins revoke the signer
roster    every commit's roster lies within the key holders at its auth pin, and in the config and directory
          groups within the leaf-entitled devices (§7.9), except a recovery self-join's revoked leaves (10.8),
          whose generation-0 epoch has no GenWrap; the next leaf commit after a leaf's drop, or its loss of
          leaf entitlement there, removes it, and no leaf wrap uses an epoch whose tree holds a non-holder

delivery checks: every member, for each ReaderWrap or DelegationWrap it reads (its own when it fetches it,
others' when it answers wrap-pending), judged at the delivery's own state, never at the member's later one
body      it verifies as its SignedType under the signer's identity key; group_id, generation and commitment
          equal gen/<g>'s; recipient and recipient_key_sha256 match its path's recipient and k8 (10.6)
staged    STAGED: no auth or time; the signer is gen/<g>'s; the recipient is in the KeyHolders set whose hash
          gen/<g> carries, and wrap_count counts it
late      LATE, a first delivery or a replacement to a newer key alike: auth (n_d, A_d) lies on my chain with
          n_d >= gen/<g>'s auth.version; gen/<g>'s time_ms <= time_ms <= my clock + 60 s; the recipient is in
          KeyHolders(R, auth, time_ms); the signer is in it or covered by a Delegation in it, and not
          read_only (§7.9)
judged    at the delivery's auth, a STAGED one's being gen/<g>'s, only from my previous base to my tip, and
          invalid if a row above fails, an auth off my chain included; one above my tip waits until I reach
          it, one I cannot reach being withheld (§7.9's retain row); one before my previous base I do not
          judge, and it counts against no one
history   a delivery valid at its own state stays valid after its recipient's or signer's revocation, a key
          replacement or a replay, and poisons nothing later
use       the recipient opens only a delivery to itself and to a key it holds whose body verifies and whose
          RK_g matches C_g, then judges it as any member does
```

### 10.10 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| PublicMessage handshakes or a clear roster delta | GKM checks proposals or rosters | GKM reads credentials, proposals, the tree (RFC 9420 §16.4) or the roster | Ruled out (owner directive; owner decision 59) |
| Every admitted sidecar a leaf | One key path; read is membership | A commit per CI join and reap; agents share the 1,000 leaves | Rejected (owner decision 114) |
| Generations raised both by MLS commits and by wrapped writers | No separate claim object | Two paths mint g+1 and fork the ladder | Rejected (D-KEYS-15) |
| A rotation at every reap of a Delegation-covered agent | Each reap looks like a removal | Excludes nothing the Delegation's key still reads | Rejected (D-KEYS-16) |
| Suspend as a server-only control | No rotation or individual wraps when one agent pauses | A suspended agent opens what the server still delivers to its Delegation's key; the one-switch claim and §8.12's invariant would need another exception | Rejected (D-KEYS-16) |
| A time identity at each covered agent's own `not_after` | Keeps non-ephemeral admissions shorter than their Delegation | An admission landing after a rotation's pin would shorten a holder's life that the generation never saw; an ephemeral agent closes itself, or api reaps it, before any such cutoff | Rejected: §7.9 floors a non-ephemeral one at its Delegation's `not_after`, and an ephemeral one ends as a reap (D-KEYS-16) |
| 1,000 member devices per network, or a larger config tree | No member wraps | The cap refuses Teams past ~330 members; 5,000 leaves make a 7.9-14 MB tree and path commits to ~6 MB, past §18.4's budgets | Rejected (owner decision 144) |
| Proxy re-encryption (PLAN.md:223, :284-327) | The server re-wraps headers blind | Semi-honest (PLAN.md:323), against D-TRUST-1; no supported Go pairings (golang.org/x/crypto/bn256 is deprecated: bn256.go:22-23) | Rejected |

### 10.11 Decisions proposed

**D-KEYS-1 (proposed).** MLS, built in house, distributes key-encryption keys under 10.5's hierarchy from v0 (owner decisions 1, 43). *Why:* tree post-compromise security for KEKs; against a passive keychain copy, content keys heal only at the first generation after a device's next path commit and its copied ReaderKeys' 7-day not_after, and against an active clone only after a compromise revocation and a new enrollment (10.5); the ladder keeps §11's format distributor-independent.

**D-KEYS-2 (proposed).** One MLS group per evs repo, with a leaf per reading member device, at most 1,000; other readers hold ReaderWraps, and in the config and team directory groups so do member devices past §7.9's first 1,000, which commit there only wraps and rotations. *Why:* owner decisions 1, 7, 60, 114, 144 and 182.

**D-KEYS-3 (proposed).** Member commits are PrivateMessage whose clear header adds only the generation and the auth pin; only external commits are PublicMessage. *Why:* owner decision 59; the gate needs both.

**D-KEYS-4 (proposed).** Credential 0xF552 binds the MLS key to `sidecar_id` and the identity key under a config-repo `SidecarAdmit`; only the genesis rests on trust on first use, and owner-bound repos add only consented readers (10.9). *Why:* owner decisions 3, 5, 110, 112, 126; R-KEYS-8, R-KEYS-9.

**D-KEYS-5 (proposed).** GKM keeps no state of its own and orders, claims, delivers and retains through conditional object writes on its repo's metadata cluster, with acks as Redis soft state (10.6). *Why:* owner decisions 2, 136, 145; RFC 9420 §14.

**D-KEYS-6 (proposed).** Commit before write: an authorization-log entry that shrinks a repo's key holders, or a holder's expiry, closes evs's gate (D-EVS-18) until a generation covering it is claimed (§7.9, 10.5), which is cause REMOVE (10.9); generations also rotate on request and every 30 days. *Why:* no server transaction changes readers (owner decision 5), and an expired holder must lose new content as a removed one does (R-KEYS-4).

**D-KEYS-7 (withdrawn).** Superseded by owner decisions 113 and 128: the signed statement, not an admin committer, authorizes each membership change (10.9).

**D-KEYS-8 (proposed).** Drop keys in each generation's signed GenRotate give write-only deposits, which depositors accept only if the generation covers every shrink they know (10.5); each key domain is its own repo. *Why:* agents deposit sessions they cannot read (R-KEYS-9).

**D-KEYS-9 (proposed).** Rotating devices wrap each generation to every reading member's current `RecoveryBind` key; Team's only escrow is a visible audit reader. *Why:* owner decisions 62, 63, with no server-guessable secret.

**D-KEYS-10 (proposed).** M2's entry fixes the MLS wire's fields and the delivery wire's (ReaderKey, KeyDelivery, 10.6's wrap and recovery paths); its exit freezes them and suite 0x0010 on §22.10's 0x0010 interop artifact (10.4), with 10.4's conformance plan, fuzz targets run as Go tests and 10.6's sizes measured (§22.8); the security page says this MLS on draft suite 0x0010 is not independently audited. *Why:* owner decisions 99, 101, 119 (§2.18).

**D-KEYS-11 (proposed).** Tagged, ephemeral, CI and cloud sidecars read and write through ReaderWraps, and live Delegations get DelegationWraps that cover their agents (10.5). *Why:* owner decision 114: no commits, and reads with no member online.

**D-KEYS-12 (proposed).** MLS is 10.4's subset on ciphersuite 0x0010 from v0, migrating through GroupForm and the ladder if IANA assigns this suite another value. *Why:* owner decision 44.

**D-KEYS-13 (proposed).** After a site loss, repo admins' devices, and for owner-bound kinds the owner's consented devices, re-seed each group from their keychains under a GroupForm linked through the ladder (10.8). *Why:* gkm has no off-site copy (owner decisions 90, 94).

**D-KEYS-14 (proposed).** Groups scale by 10.6's sizes: 10.4's self-update interval, KF5's resync, GroupInfo on demand above 16 leaves, daily acks, trees on disk. *Why:* a full 1,000-leaf tree is 2.8 MB, which a per-epoch GroupInfo would rewrite about 143 times a day.

**D-KEYS-15 (proposed).** `gkm/<group_id>/gen/<g>`, created If-None-Match by the rotating writer, is the only place a generation exists; MLS commits never raise the generation, and a removal is a Remove commit followed by an independent rotation (10.5). *Why:* two paths minting g+1 fork the ladder; one claim object serializes every rotator (owner decisions 1, 114, 128).

**D-KEYS-16 (proposed).** KeyHolders are leaves (in the config and directory groups, member devices past their first 1,000 by wrap), uncovered agents, live Delegations over their reach (the config, a team's directory and the repos a grant names one of their tags for) and recovery keys; live Delegations get DelegationWraps keyed by delegation_id; a covered agent's reap, or an ephemeral one's own `not_after`, is no shrink, and a Delegation's key drops at its end (`DelegationRevoke`, a void, or a compromise revocation of one of its agents; §7.9), at `not_after`, and at any other revocation but a reap, or any `Suspend`, of one of its agents, which no `Unsuspend` undoes (10.5). *Why:* owner decision 114's read-at-once, bounded, with no dropped party signing the rotation that excludes it; a suspended agent must lose what the server can still deliver to its Delegation's key, and an ephemeral agent can close itself, or api reap it, before any cutoff keyed to its own expiry.

**D-KEYS-17 (proposed).** Drop keys ride each generation's signed GenRotate, only for kinds that take deposits; a depositor seals only to a generation that covers every shrink and expiry it knows and is not below its pin; the deposit scope reaches only the drop-key route (10.6, 10.14). *Why:* a stale but unexpired drop key would reach a removed reader.

**D-KEYS-18 (proposed).** At most 16 leaves, the epoch object carries the sealed GroupInfo and `group-info` is a pointer rewritten at each Add and by gkm with any epoch 16 or more past it, resync probing to a 404; KF1 writes its first wraps, recovery wraps included, before evs activates the repo; above 16, recovery and resync need one leaf online (10.6-10.8). *Why:* a crash between two PUTs must not break code-only recovery.

**D-KEYS-19 (proposed).** `gkm:<group_id>` is versioned epoch × 2^24 + generation, and work hints go on the per-client `gkm` topic of the sidecars that must act (10.14). *Why:* same-epoch work hints and commit-less rotations must not be dropped as stale.

**D-KEYS-20 (proposed).** Retention never deletes a group's newest epoch, moves the `group-info` pointer before deleting the epoch it names, and keeps every GenRotate for the repo's life, as a gen/ object or in a gen pack (10.6, 10.16). *Why:* the next commit needs its predecessor, and code-only recovery needs no epoch history.

**D-KEYS-21 (proposed).** gkm acks are Redis soft state, and the epoch reconciler deletes only while the ack family is 30 days old; a GroupInfo above 16 leaves is written at most once per epoch, on request. *Why:* acks are rebuildable (owner decision 136), and a 1,000-leaf GroupInfo costs ~0.7 MB on each drive.

**D-KEYS-22 (proposed).** The search index's document keys derive from `ref` (RK_1), and its keyed pad from a per-generation `index` key that each shard's header names. In slot-keyed repos each versionless index file keeps one key, in a slot only that path's versions name, until a REMOVE generation, a CLOSURE or a rekey replaces it (§11.7). *Why:* document keys must survive rotations, or every rotation reindexes the repo; a removed reader must not predict new shards' sizes; and an ERASE must reach postings (owner decision 61) without a slot object per index write (owner decision 140).

**D-KEYS-23 (proposed).** The team directory's group follows §7.9's leaves rule as the config group does: the first 1,000 live member devices are leaves, and later member devices and agents read by per-generation wraps (owner decision 182). An admission's signer seats its subject at once; gkm hints only the statement's signer and the config writers, and other writers rotate only for a push the gate refuses, after up to 15 s of jitter (10.9). *Why:* every admitted sidecar reads the directory, and §8.12's data-repo seats would leave members of a large Team keyless; every sidecar but read_only ones also writes it, so hinting every writer would race rotations that each stage a wrap per wrapped reader.

**D-KEYS-24 (proposed).** Every ReaderWrap and DelegationWrap is a typed `KeyDelivery` whose immutable identity, in its path `wrap/<g>/<c8>/<recipient>/<k8>`, its body and its wrap_aad, includes the recipient key it seals to, so a delivery to one ReaderKey never blocks, replaces or opens as one to another, and a rebind's RecoveryWraps take their binding's own path (10.6, 10.8). A STAGED delivery is its claim's and is judged against the claim's holder set; a LATE one, first or replacement, carries its signer's AuthPin and time, is judged at that state, may be signed by any holder that is not read_only, and stays valid after later revocations (10.9). *Why:* a fresh ReaderKey needs a delivery its old one's object cannot occupy, and a delivery made after its generation's claim needs its own authorization state, which neither the claim's pin nor a verifier's newer one gives.

**D-KEYS-25 (proposed).** A ReaderKey is valid at most 7 days after signing and replaced at 6 days, its private key kept 30 days past its not_after, and rotators and deliverers seal only to an unexpired one valid no longer than that; so a passive keychain copy heals at the first generation after the device's next path commit and that not_after, about 37 days after the copy (60 above 50 leaves) whatever advertisement gkm serves, and an active clone, which signs fresh keys, ends only at a compromise revocation and a new enrollment (10.5). *Why:* gkm serves one overwriteable advertisement with no authenticated retirement, so only the key's own validity bounds a stale one, and whoever holds an identity key can sign another.

**D-KEYS-26 (proposed).** gkm's routes take 10.6's scopes: a sidecar's own ReaderKey and KeyPackages under any gkm token of its own; reads, acks and a member device's commits under r; GroupInfo and deliveries under r from a sidecar that is not read_only; claims, Welcomes and KeyPackage claims under rw; members, not gkm, check what a commit carries (10.9). *Why:* reader-only and read_only leaves must keep their keys and leaves current (D-TEAM-24), and gkm cannot see a PrivateMessage's proposals.

### 10.12 Open questions

**Q-KEYS-1.** [X12] Build MLS or fork it? **Decided by owner 2026-11-03 (owner decision 43):** build 10.4's subset in house (~5-8k lines); its audit is deferred (owner decision 99). *Residual:* none.

**Q-KEYS-2.** [X12] Which ciphersuite? **Decided by owner 2026-11-03 (owner decision 44):** 0x0010 (X-Wing, Ed25519) from v0; groups migrate through the ladder if IANA assigns another value. *Residual:* post-quantum confidentiality against a passive adversary only; a future Ed25519 forgery is retroactive through the ladder (10.5, §2.18) until 10.16's hybrid signatures.

**Q-KEYS-3.** [X12] At what granularity are groups formed? **Decided by owner 2026-11-03 (owner decision 60):** per repo, grants mapping onto membership; agents hold wraps (owner decision 114). *Residual:* none.

**Q-KEYS-4.** [X12] What do "GKM" and "one session key stored in GKM" mean? **Decided by owner 2026-11-03 (implied by owner decision 59):** a DS plus wrapped, laddered generations (10.5) in the file cluster. *Residual:* none.

**Q-KEYS-5.** What admission evidence must a credential carry? **Decided by owner 2026-11-03 (owner decisions 3, 5, 110):** a config-repo `SidecarAdmit` chained to the genesis, subsuming DeviceAdmit; a member's own device may sign it (owner decision 112). *Residual:* none.

**Q-KEYS-6.** Is per-entry crypto-shredding required? **Decided by owner 2026-11-03 (owner decision 61):** for record-class repos and mail, through format 1's key slots. *Residual:* none.

**Q-KEYS-7.** How does a member recover after losing every device? **Decided by owner 2026-11-03 (owner decision 62):** a recovery code receiving wraps under a signed, rotatable binding, plus admin re-add of team repos (10.8); its key counts as one of k after a 72 h veto window (owner decision 127); a binding the cascade restored admits only through that window, its device anchoring on a config ReaderWrap (owner decision 149). *Residual:* §2.10's row for an operator colluding with a recovery-code thief: the code opens its wraps at once, whatever the window or a veto, until `RecoveryRebind{reason: compromise}` (revoking the device it admitted does not retire it), and keychain backups sealed before a rebind stay open to the old code (10.8).

**Q-KEYS-8.** Should teams get escrow? **Decided by owner 2026-11-03 (owner decision 63):** a visible audit reader on a customer-operated device, a Team opt-in in v1, never silent (10.8). *Residual:* none.

**Q-KEYS-9.** [X12] Does v0 ship MLS, or per-device wraps with MLS in v1? **Decided by owner 2026-11-03 (owner decision 1):** MLS in v0 (PLAN.md:44); agents' wraps carry its generations (owner decision 114). *Residual:* none.

**Q-KEYS-10.** Is 10.8 the right reading of PLAN.md:50 and :338? **Decided by owner 2026-11-03 (owner decision 64):** lazy rewrap, a full checkpoint at the first write after a `remove` generation, plus `ur evs rekey`. *Residual:* none.

**Q-KEYS-11.** How long does GKM keep epoch objects? **Closed by peer review 2026-11-04:** (a), 30 days, then until every leaf that acked in the last 30 days has applied them, on four conditions (10.6): the newest epoch is never deleted, and the `group-info` pointer moves before the epoch it names goes; nothing the ladder, resync or recovery needs lives in an epoch (generations are `gen/` objects, GroupInfo rides in the newest epoch at 16 leaves or fewer or in `group-info` above, and recovery wraps are their own objects), so a device past retention resyncs from GroupInfo; a preservation hold pauses the sweep (owner decision 133); and §19.9 sizes the family at M2's benchmark: a 10-leaf group keeps about 42 commits of 11-17 KB plus inline GroupInfo (1.2-1.9 MB), a 1,000-leaf group about 26 MB. *Residual:* §19.9's measured size.

**Q-KEYS-12.** [X12; directive residual] Which header values does gkm see? **Decided by owner 2026-11-04 (owner decision 115):** 10.6's rows: ciphertext, group id, epoch, sizes and sidecar ids (membership, as api-7 shows it; owner decision 72), never, in a member commit, a proposal, credential change, tree or key; external commits show gkm-6's values. *Residual:* none.

**Q-KEYS-13.** Does owner decision 7's "only from keys allowed to grant" bind the committer or the change? **Decided by owner 2026-11-04 (owner decision 113):** (b) the change (10.9), withdrawing D-KEYS-7. *Residual:* none.

**Q-KEYS-14.** Who commits the config group's membership changes, when only admins write config records (§8.8)? **Decided by owner 2026-11-04 (owner decision 128):** (a) also the leaf that signed the admission or revocation; recovery-admitted devices self-join by external commit (10.9). *Residual:* none.

**Q-KEYS-15.** How many member devices may one network hold, given the config group's 1,000-leaf cap? **Decided by owner 2026-11-04 (owner decision 144):** (b), with no member-device cap: from the start, member devices past the first 1,000 read the config group by per-generation wraps, as agents do, and stay leaves of their data repos, each still at most 1,000 leaves, amending owner decision 114 for the config group only; §20.4 keeps 5,000 Team admissions. §7.9's `leaves` rule ranks and promotes (10.4); wrapped devices commit no config-group Add or Remove, so a wrapped signer writes an admission's first wrap or a revocation's rotation, and the next leaf commit removes a leaf (10.9). Cost: ~1.3 KB of wrap per wrapped device per config rotation. *Residual:* none.

**Q-KEYS-16.** Cross-cutting (§7.9, §8.12). How does the team directory's group seat every admitted sidecar? **Decided by owner 2026-11-05 (owner decision 182):** (a), its own MLS group under §7.9's leaves rule, extending owner decision 144 to one more group, at ~1.3 KB a wrap per overflow device per rotation (options (b), keys derived from the config group, and (c), data-repo seats, not taken). 10.4 and 10.9 apply it with the config group's committers, gkm hinting only a statement's signer and the config writers, since every sidecar but read_only ones writes the directory. *Residual:* none.

### 10.13 Departures from PLAN.md

- **PLAN.md:147** ("participants are leaves"). Member devices are leaves (owner decision 60); agents hold wraps (owner decision 114 on Q-ACL-9; D-KEYS-11), as do member devices past the first 1,000 in the config and team directory groups (owner decisions 144 and 182 on Q-KEYS-15 and Q-KEYS-16).
- **PLAN.md:148.** Per-object keys are wrapped under RK_g, which the epoch KEK or a holder's wrap delivers (Q-KEYS-4).
- **PLAN.md:221.** Narrowed by the owner directive: gkm holds ciphertext plus 10.6's header values (Q-KEYS-12).
- **PLAN.md:223, :284-327.** Proxy re-encryption is rejected (10.10).

### 10.14 Interfaces

- **Provides:** `GkmClient` (`CurrentRepoKey`, `RepoKey(repoId, generation)`, `EnsureWritable`, which first commits the pending changes its device may, `DropKey`); `EvsRepoKey.DeriveKey(purpose, context)`; credential validation and pins (also for §6's `Hello`); GenRotates and drop keys, ReaderWraps and DelegationWraps (`KeyDelivery`, 10.5) with 10.9's delivery checks, and recovery wraps; 10.5's KeyHolders and 10.6's gate predicate (§7.9, §11.8, §11.12).
- **Consumes:** keys, bindings, keychain, recovery code, `SidecarEvent` (§5); topics, `Signed`, `HeadCheck` (§6); tokens, `rev/` (§7.8); the authorization log, `AuthPin`, causal identities, recovery, the `leaves` rule and removals (§7.9, §7.10); `RepoReaders`, seats, kind defaults, consent, `OwnerConfirm`, access logs, `audit`, `EvsShare` (§8); kinds, `repo/` state, `place/`, slots, manifests, path epochs, the head-CAS gate and the write budget (§11); `ServiceHost.Blobs` per cluster and Redis (§4.5, §19).
- **Subprotocol messages:** `GkmHint{group_id, epoch, kind, recipient}` in `PushHint` (§6.11, 0x1301): commit on `gkm:<group_id>` (version = epoch × 2^24 + generation); pending, welcome, key-packages-low and wrap-pending (a GenWrap, wrap or sealed GroupInfo is missing; for 10.6's late wraps, `recipient` names the ask's `s:` or `d:` recipient, and a hint lost or coalesced comes again at the next ask) on the per-client `gkm` topic (§6.8).
- **API routes:** Client class, under 10.6's tokens and scopes, specified in connect/api/bringyour.yml.

  ```text
  POST /gkm/key-packages, /gkm/key-packages/claim, /gkm/reader-key;  GET /gkm/reader-key/<sidecar_id>
  POST /gkm/groups;  GET /gkm/groups/<id>;  POST /gkm/repos/<id>/forms    (GroupForm: create, re-form)
  GET  /gkm/groups/<id>/epochs?after=          epoch objects, in order, with their sizes
  POST /gkm/groups/<id>/epochs/<n>             200, 409 (with the winner), 403, 429
  POST /gkm/groups/<id>/gen/<g>                the claim: 201, 412 (with the winner), 403, 429
  POST /gkm/groups/<id>/wraps/<g>/<c8>         staged or late ReaderWraps and DelegationWraps: 201, 412 (with
                                               the winner), 403, 409 (stale kind, generation or key), 429
  POST /gkm/groups/<id>/welcome/<n>, /group-info, /ack (Redis)
  GET  /gkm/groups/<id>/gen?since=;  GET /gkm/welcomes
  GET  /gkm/groups/<id>/wraps/<g>?recipient=&want=<k8>&since=   the caller's deliveries of g, the object at
                                               want first, the recipient's prefix on a miss, which hints
                                               wrap-pending (10.6's late wraps)
  GET  /gkm/groups/<id>/drop-key?since=<g>     deposit, r, rw, admin: the newest GenRotate, up to 64 after since
  GET  /gkm/groups/<id>/group-info?want=<epoch>  sealed; an older one also hints wrap-pending (KF5)
  GET|POST|DELETE /gkm/recovery/<member_id>/wraps  GET also under an unadmitted client's recovery:<member_id>,
                                                   for that member's own wraps only (§7.8, §7.9)
  ```
- **Tables:** none; gkm's durable state is 10.6's objects (owner decisions 2, 21, 145), and Redis `{gka_<group_id>}` holds acks as soft state (owner decision 136).
- **Services and config:** `server/cli/gkm` hosts `gkmservice` from v0; root `mls_*` and `gkm_*` files and the nested `mlsinterop/` test module (D-REPO-2, D-REPO-3, D-OPS-2); the reconciler (retention, hints, staged-wrap GC) in taskworker; limits in config/all/pro.yml.
- **Assumptions about other sections:**
  - §7.9 defines the authorization log, `AuthPin`, the causal identities (a compromise retirement shrinks though a rebind keeps the holder's identity; ReaderKey lapses are no expiry, 10.5) and `holders_shrunk_at`, `RecoveryBind` and its reasons, `stale_leaf_days`, Delegations, the recovery window, `anchor` and `restored` order, the compromise cascade, the Delegations it voids and the bindings it restores, which take no wrap until re-signed, the Delegations it or a `DelegationRevoke` ends, parking their agents admitted from `since_n`, the scoped rule giving each Delegation-signed admission exactly the Delegation's tags and, unless ephemeral, a not_after no earlier than its own, with `max_admits` counted for the Delegation's life, and the `leaves` rule of the config and directory groups, refusing a not_after on a member device's admission; §7.8 gives member devices other than read_only ones gkm `rw` in the config group, every sidecar but read_only ones `rw` in the team directory, and issues the `deposit` and `recovery:<member_id>` scopes; §7.10 and §8.12 name 10.9's committers, §7.10 also the reaped agent's admission signer, §8.12 the data repos' seats, which the directory does not take, and §8.5 consent and the directory kind default (every admitted sidecar of a team network reads, every one not read_only writes; §16.11), and §8.6's ceiling passes the config kind default's read row, so ephemeral sidecars read the config as 10.5's depositor rule needs; §7.9's read_only row accepts a read_only device's own ReaderKeys, KeyPackages, path-only commits, resyncs and acks under its r scopes and refuses its wraps and GroupInfo (10.6's scopes), and §5.9 keeps ReaderKeys and their private keys as 10.5's readerkey row says; §5.4 alarms on admissions a member's devices did not sign and raises `head_alarm` (fork) on a failed recovery anchor, and §5.9 has each device re-seal `keychain.wrap` at every change to its member's current binding, a void included, with no HPKE copy while none is current.
  - §11.8 enforces 10.6's predicate at each ref's head CAS, reissuing a timed-out head PUT only within 5 s of its validation, owns `place/` and lists the first cluster's families, gkm's per-sidecar objects included; §11 owns path epochs (authorization expiries batched within 24 h), §11.7's checkpoint after a REMOVE generation, deletion (its shred deleting the group's gkm objects and `{gka_}`, again after 10 min; a re-seed's GroupForm the only gkm route it admits while deleted), mirrors, re-seeding and §11.13's write budget, whose inputs count expiry rotations and path epochs; §19.6 sets the 10 s store request deadline; §19.9 sizes gkm's objects, gen/ unpacked until 10.16's packs start, expiry rotations, the config and directory groups' rotation wraps and the first cluster's per-sidecar ones included.
  - §11.14 derives search-index document keys under `ref` and shard pads under `index` through `EvsRepoKey.DeriveKey`, keeps each index file's key in its path's own slot in slot-keyed repos (§11.7), and destroys an erased document's index files' old slot keys by its ERASE.
  - §22.7 covers 10.5-10.9's cases, the gate's 412 (a compromise rebind's at the old generation included), an expired RepoGrant's REMOVE rotation, checkpoint and path epoch (FS-18), gkm accepting a generation-0 recovery self-join, a reap's config rotation by the admission's signer, an admin-only admission never reading its member's vault or mailbox, a recovery self-join with no leaf online, FS-20 also killing KF1's creator before activation and gkm between an epoch 16 past the pointer and the pointer's rewrite, a 1,001st member device reading the config and the team directory by wrap, the directory group's hint audience and rotation wait (10.9) and FS-87's directory Removes and rotation reaching leaves and wraps, and a Team member whose only device was stolen recovering by the restored code, its device anchoring after the window on its config ReaderWrap (a forged one raising `head_alarm`), then self-joining, KF2 adding it elsewhere; FS-6 holds a gkm commit at a barrier across a --now shred and restores a repo re-seeded as deleted; FS-103 to FS-106 test delivery identity, delivery authority, copied keychains and key upkeep under r; §22.8's M2 benchmark measures 10.6's sizes and drive costs, a 1,000-leaf group on the iOS surrogate cell and 1 h requested grants on large repos included; its schedules lose the ack family and race a repo's placement, its group landing on the repo's cluster.

### 10.15 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| The unreviewed in-house MLS misreads RFC 9420 or skips a check (owner decision 99) | Medium | Critical | 10.4's subset, conformance plan and 0x0010 gate; disclosure (§2.18, owner decision 119) |
| IANA assigns this suite another value, or X-Wing changes | Medium | Medium | Migration through GroupForm and the ladder (owner decision 44) |
| An operator substitutes a network's first device at trust on first use | Low | High | Safety numbers; genesis in invites and auth keys |
| A member stalls a group with a commit the others refuse | Low | Medium | Alarms; revocation; re-forming (10.9) |
| A rogue or compromised admin admits a device under a member | Medium | Medium | Consent gates owner-bound repos (owner decision 126; 10.9); the member's devices alarm (§5.4); team repos stay readable until revocation |
| A removed leaf stays in a repo's MLS tree until a writer leaf commits its Remove (owner decisions 114, 144, 182) | Medium | Low | Wrapped writers' rotations reopen the gate meanwhile, and no leaf wrap uses an epoch that holds it (10.5); hints wake writer leaves |
| A reaped Delegation-admitted agent, an ephemeral one past its own `not_after`, or a leaked reader seed reads later config, directory and tag-repo generations, and a leaked whole auth key admits fresh agents (owner decision 114) | Medium | High | `not_after` ≤ 90 d (30 d for CI), replaced at each CI secret rotation and after a key drop; any `Suspend` or non-reap revocation of its agents, or a cascade voiding it, drops the key; a `DelegationRevoke` or a compromise revocation of one of its agents ends its admissions (10.5, §7.9) |
| Large groups strain phones (10.6's sizes); a large Team's leaves sit in two 1,000-leaf groups, the config's and the directory's | Medium | Medium | D-KEYS-14; §22.8's benchmark |
| Short grants (1 h requested grants) expire often, and each covering generation is REMOVE, so files re-checkpoint at their next write and a repo's batched path epoch recurs daily, ~17 h of copying for a 1M-file ref (§11.6) | Medium | Medium | One rotation covers every expiry up to its time_ms, and writers batch them at a pending hint or their next write (KF4); 16-diff chains checkpoint anyway; at most one batched path epoch per repo a day (§11.6); §11.13's inputs and §19.9's gen/ row count these rotations and epochs, and §22.8's fixture of 1 h requested grants on large repos reports rotations, full checkpoints and path-epoch copy operations a day |
| A config or directory rotation stages a wrap per wrapped reader and a RecoveryWrap per member, up to ~6,000 objects (~7.5 MB, ~50 MiB a drive) at §20.4's 5,000 Team admissions, and a wrap per leaf more if its rotator is wrapped; the directory, whose writers push often, rotates at nearly every shrink of a Team's sidecars, and racing rotators would multiply each | Medium | Low | A leaf rotator's one LeafWrap covers every leaf; covered agents' reaps rotate nothing (10.5); the directory group hints only a statement's signer and the config writers, and unhinted writers rotate after a jitter (10.9); §11.13 runs REMOVE rotations at once as P0, never refusing them, so many large Teams shrinking at once can wear a cluster's drives past the budget (owner decision 186; §11.21's P0 row), and §19.9's projection counts both groups' rotations |
| With no witness, shared writes stop at `witness_bound_hours` (default 72 h), a lone cloud agent's included (§2.8's bound, which a split defeats) | Medium | Medium | Agents witness (owner decision 129); 24 h alarm; up to 168 h; Removes, rotations and revocations never stop |
| After a void leaves M no current binding, M, its network's only config writer, loses every device: no config writer remains to give the device M's restored code admits its ReaderWrap (KF2), so it anchors only once a config holder that is not read_only, among the up to 64 other holders gkm hints 15 min after its ask (10.6's late wraps), runs, and never if none does (owner decision 149) | Low | High | M's devices raise `recovery_rebind` at the void (§5.4), and any of them can run `ur keychain recovery-rotate` (§5.9) to bind a code that takes wraps; meanwhile only surviving RecoveryWraps open (10.8) |
| A device offline past its ReaderKey's 7-day not_after gets no staged wrap and, back with a new key, waits for a late delivery, longer where no writer is online | Medium | Low | Lapsed private keys kept 30 days for what was staged (10.5); any holder but a read_only one delivers, gkm hinting writers, then after 15 min up to 64 other holders (10.6); a leaf also takes the next GenWrap |
| An active clone of a keychain (its identity key and ClientKey) reads and acts as the device past any path commit or ReaderKey replacement | Low | High | `SidecarRevoke{reason: compromise}` from a since_n before the copy, whose cascade parks what it admitted, and a new enrollment (10.5, 10.8); the 37-day heal is a passive copy's (§2.10) |
| Site loss erases every gkm object (owner decision 94) | Low | Critical | Device re-seed (D-KEYS-13); owner-device mirrors |

### 10.16 Phasing

- **v0 (M2):** all of 10.4-10.9 but v1's items, with `directory` among `ur_group`'s kinds (§11.12), D-KEYS-10's gates, D-KEYS-14's scaling and `ur evs rekey`, a client job that re-checkpoints every file of a repo under the current generation in multi-part pushes of at most 1,024 entry writes, at most 50 files/s per repo, resumable from its last committed push.
- **v1:** the Team audit reader (owner decision 63), and with Team at M6 the config group's wraps for member devices past the first 1,000 (owner decision 144) and the team directory's group under the same leaves rule (owner decision 182); at M10 (owner decision 169), the `index` purpose, with storage format 2's search index (owner decision 163; §11.14), and format 2's one slot key per versionless path (§11.7).
- **Later:** 0x0020 by migration, with hybrid Ed25519 and ML-DSA-65 authority signatures; SafeExportSecret (draft-ietf-mls-extensions-11); key transparency; moving a group with its repo once a move tool exists (owner decision 145); gen packs, once §19.9's projection from §22.8's M2 count needs them: taskworker writes `gkm/<group_id>/genpack/<k>`, holding gen/<256k+1>..<256k+256> verbatim, If-None-Match with repo/ rechecked as for every gkm write, once 64 newer generations exist, then deletes those objects, a retry that finds the pack verifying it and resuming the deletes; a read falls back from `gen/<g>`'s 404 to `genpack/<⌊(g-1)/256⌋>`, and a claim still needs `gen/<g-1>` as an object, so none lands at or below a pack; packs count as gen/ for every other rule (gkm-7's life of the repo, shreds and their 10-minute repeat, re-seeds) and hold no slot, so erasure is unchanged.
- **Dependencies:** §7.9's authorization log and config repo, §8.5's consent, §11's format 1 and §19's conditional writes block v0; §22.8's M2 benchmark sets §19.9's epoch-retention size (Q-KEYS-11's residual).
