### keys-mls: MLS
Stage: Later
- **Deferred:** MLS as v0's key distributor: §10.4's RFC 9420 subset on ciphersuite 0x0010, one group per repo with member devices as leaves, PrivateMessage commits, KeyPackages and Welcomes, external commits, epochs and their KEK_e, GenWrap and LeafWrap, sealed GroupInfo, acks, resync and the config and directory groups' leaves rule (owner decisions 1, 43, 44, 60, 113, 128, 144, 182, 361, 363 and 366; D-KEYS-1, -2, -3, -12, -14, -18 and -23; Q-KEYS-9; ledger ids QD-002, QD-074, QD-442, QD-464, QD-526, QD-616 to QD-618, QD-638, QD-641, QD-659, QD-747, QD-956 and QD-1040; DESIGN-DETAILS.md section 6's MLS rules, which wait with it: the roster rule with its committer and member clauses, its D-KEYS-27 row, KF2's and KF5's commits, the dropped-leaf and waiting-leaf hints, D-KEYS-24's Welcome pointer clause, §10.6's note on the claim key, and the commit legs of FS-15, FS-24, FS-97 and FS-104).
- **Why:** The complexity review of 2026-11-17 counted about 42.5k MLS-only lines, 15.9k of them production, about 23 decisions, 98 KB of DESIGN-DETAILS.md section 6, about 14 of KEYS' 36 tasks and 27-63 MB of heap at 1,000 leaves; and MLS kept an agent's repo keyless until a member device formed its group, and made recovery above 16 leaves wait for a leaf online. Wraps had grown into a full distributor already, serving agents, member devices past the first 1,000, Delegations and recovery codes. The owner chose wraps only (owner decision 610).
- **Launch instead:** Every group key RK_g goes by §10.5's `KeyDelivery` wraps: a join is a LATE delivery, a removal the REMOVE rotation, a resync fetches deliveries; gkm keeps no epochs, Welcomes, KeyPackages, GroupInfo or acks, so `gkm:<group_id>` is versioned by generation alone, and the format's epoch fields, GenRotate's `leaf_wrap` among them, stay unset.
- **Lost:** TreeKEM's post-compromise healing of the key-encryption keys: a copied keychain heals by §10.5's bounds, a reader at its ReaderKey's not_after plus the next generation, where a leaf healed in about 37 days (60 above 50 leaves). Each rotation costs about 1.37 KB a holder, about 1.37 MB and 1,000 objects at 1,000 holders, against one 72 B leaf wrap a leaf.
- **Dark in code:** The root's `mls_*` files, mlsinterop/, gkm's MLS files, gkmservice's epochs, groupinfo, keypackages, welcomes, acks and reform, and sidecartest's fake_mls, mlssuite and bench_groups stay on the branch, dark, for Later, with owner decision 99's deferred audit; the review phase reworks key formation (KF1 to KF7) onto deliveries and removes gkm's MLS routes and state or leaves them dark.
- **Held:** The MLS interop freeze (KEYS-M2-11's 0x0010), fuzzing of the `mls_*` decoders, and the MLS legs of FS-15, FS-20, FS-24, FS-97 and FS-104 leave the gates; QD-641's MLS engine rewrite is dropped; the core lane's gkm-guard-right-set is re-briefed to the routes wraps-only keeps.
- **To bring back:** An owner decision that reverses owner decision 610. Then: freeze the MLS wire and suite 0x0010 on §22.10's interop artifact; return KF1-KF7's MLS steps, §7.9's leaves rule and DESIGN-DETAILS.md section 6's MLS rules; restore the interop, fuzzing and FS legs to their gates; and move existing groups onto MLS by a GroupForm under the ladder, which the generations carry unchanged.

### keys-suite-0x0020-hybrid-signatures: Suite 0x0020 with hybrid authority signatures
Stage: Later
- **Deferred:** Moving groups to ciphersuite 0x0020 by migration, with hybrid Ed25519 and ML-DSA-65 authority signatures (§10.16; owner decision 358's not-taken option (3)).
- **Why:** v0 freezes draft suite 0x0010. Owner decision 358 declined ML-DSA signatures on ReaderKeys from v0: they close one forgery route only, add ML-DSA keys to admissions and about 3.3 KB to each ReaderKey, and pull this Later work forward.
- **Launch instead:** Suite 0x0010, post-quantum against passive adversaries only, with Ed25519 authority signatures (§10.4, §10.5).
- **Lost:** A future forgery of an Ed25519 signature, by a forged admission or ReaderKey, would be retroactive. §2.18's risk row states it and the security page discloses it.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for the migration: the new suite's objects beside the old, ML-DSA keys in admissions, and how a group moves without a gap in its ladder.

### keys-safe-export-secret: SafeExportSecret
Stage: Later
- **Deferred:** SafeExportSecret from draft-ietf-mls-extensions-11, named in §10.16's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row. The extension is an IETF draft.
- **Launch instead:** The MLS exporter gives each epoch's key-encryption key. It changes every epoch and is not forward-secure, so the evs keys sit above it (§10.5).
- **Lost:** A forward-secure export. DESIGN.md does not say what would use one.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** The draft settles; then a design for which secrets move to it and how a group changes over.

### keys-gen-packs: Gen packs
Stage: Later, at §19.9's gen trigger
- **Deferred:** Packing a group's old generation objects: taskworker writes `gkm/<group_id>/genpack/<k>`, holding 256 generations verbatim, once 64 newer generations exist, then deletes those objects; a read falls back from a `gen/` 404 to the pack (§10.16, §19.18, §23.4; D-KEYS-20; Q-OPS-2; QD-401).
- **Why:** They are not in this build and have no task or FS row (QD-401). They start on a cluster only at §19.9's gen trigger, which is projected from §22.8's M2 count.
- **Launch instead:** Every generation is its own `gen/` object for the repo's life (D-KEYS-20).
- **Lost:** Nothing until the trigger.
- **Dark in code:** Nothing is built. Gen reads go through one accessor, so the fallback to a pack has one place to go (the plan's KEYS-M2-15).
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** §19.9's gen trigger on a cluster. M2's exit raises it if §22.8's M2 count projects the trigger within a year. Then build §10.16's rules: packs count as `gen/` for shreds, their 10-minute repeat and re-seeds, hold no slot, and no claim lands at or below a pack.

### keys-v1: §10's v1 set
Stage: v1 (M6, M10)
- **Deferred:** §10.16's v1 row: the Team audit reader (owner decision 63); with Team at M6, the config group's wraps for member devices past the first 1,000 (owner decision 144) and the team directory's group (owner decision 182); at M10 (owner decision 169), the `index` purpose with the search index (owner decision 163) and format 2's one slot key per versionless path.
- **Why:** Team ships at M6 and format 2 at M10.
- **Launch instead:** v0's key management at M2: all of §10.4 to §10.9 but these and MLS, every group key going by wraps (owner decision 610), with `directory` already among `ur_group`'s kinds.
- **Lost:** Until M6: the audit reader and large teams' wraps. Until M10: index keys and slot keys.
- **Dark in code:** Built in the same run on the `sidecar` branches.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: each ships when its milestone's gate passes (§23.6).
