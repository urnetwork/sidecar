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
- **Launch instead:** v0's key management at M2: all of §10.4 to §10.9 but these, with `directory` already among `ur_group`'s kinds.
- **Lost:** Until M6: the audit reader and large teams' wraps. Until M10: index keys and slot keys.
- **Dark in code:** Built in the same run on the `sidecar` branches.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: each ships when its milestone's gate passes (§23.6).
