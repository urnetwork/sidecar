### evs-compaction: Compaction
Stage: Later
- **Deferred:** Compaction of packs, parcels and batches: rewriting them without the records that erasure or a drop left unreadable (owner decision 247; QD-053; §11.7, §11.12, §11.13, §20.6, §20.7; §2.8's evs-4 and evs-12; §23.4).
- **Why:** §11.22 once listed compaction for v1, but no row specified it, and §11.8 deletes packs only whole, so it would be a new deletion path. Designing it for v1 meant new design and peer review before M6's entry and a rewrite of immutable packs, in the costliest bug class.
- **Launch instead:** Erased and dropped inline ciphertext and packed segments stay stored, unserved and unreadable once their keys are gone, "until a later compaction, unscheduled". A drop's job deletes whole objects only (§11.13).
- **Lost:** Those bytes count against the repo's storage, and are billed, for the repo's life.
- **Dark in code:** Nothing is built. §22.8's drop row expects a pack to keep its dropped records, since compaction is Later.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for rewriting an immutable container under §11.8's commit rules and under holds, its peer review, an owner decision, and new wording for evs-4's and evs-12's ttl.

### evs-expired-ciphertext-reclaim: The reclaim of expired ciphertext
Stage: Later
- **Deferred:** A GC that deletes a record-class repo's expired segments after retention erases their keys (owner decision 246; QD-047; §11.13's gc row, §16.8; §2.8's evs-4; §23.4).
- **Why:** §11.13's row deleted "segments no retained push names" while every push statement stays, so read literally it deleted nothing, and no section defined "retained". Building it at M6 meant a scan like the drop job's before M10 proves one, in the costliest bug class.
- **Launch instead:** Retention at M6 is expiry, ERASE and BASE: keys are erased and the live set re-listed. The expired ciphertext stays, keyless, "until a later GC, unscheduled". What M2 does delete is defined: a deposit's version is retained until a committed CONSUME removes it, and its segments go 7 days later once no other version names them.
- **Lost:** A record-class repo's expired segments stay stored and billed for the repo's life, unreadable.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** Owner decision 246 gives its shape: 7 days after a BASE, delete only segments that no entry of the live set and no later version names, by a mark and verify like the drop job's, under holds. It needs that design written out, its FS row, and evs-4's ttl reworded.

### evs-working-tree-sync: Working-tree sync
Stage: Later
- **Deferred:** Working-tree sync, which §11.22's v1 list once named (owner decision 250; QD-276).
- **Why:** No section said what it is: it had no requirement, row or test. R-EVS-9 and §11.11 cover a bare repository and stock git only.
- **Launch instead:** A git user updates a working tree with stock git against the local git server (§11.11).
- **Lost:** Nothing that was specified.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** The owner says what it is; if cli/UI.md turns up with a requirement, the owner reads it first. Then a design for dirty trees with its own tests.

### evs-derived-shares: Derived shares
Stage: Later
- **Deferred:** "Derived shares", which §11.22's v1 list once named and no other section mentions (owner decision 250; QD-276).
- **Why:** No section says what a derived share is, and nothing depends on one.
- **Launch instead:** Shares are `EvsShare` statements on a repo (§8.8) and, across networks, §17.9's IP path.
- **Lost:** Nothing that was specified.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** The owner says what a derived share is; then it is designed as a new item.

### evs-sha256-object-format: Git's SHA-256 object format
Stage: Later
- **Deferred:** Mounting or importing a repository that uses git's sha256 object format (owner decision 249; QD-237; §11.6, §11.11).
- **Why:** Supporting both from v0 meant a second hash through the local tier, hooks, export, the mobile and wasm git codec, vectors and §22.9's matrix.
- **Launch instead:** SHA-1 only. The daemon creates its bare repository with `--object-format=sha1`, and `ur mount add`, `ur evs import` and `git-remote-ur` refuse a sha256 repository, naming it, before any evs write.
- **Lost:** A sha256 repository cannot be mounted. That will bite once Git 3.0 makes sha256 the default for new repositories.
- **Dark in code:** The width is reserved: format 1 carries a 32 B oid and `oid_kind`, so adding sha256 needs no format change.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A second `oid_kind`, the hash through the local tier, hooks, head mode's codec and export, new vectors, and the sha256 column of §22.9's git matrix.

### evs-mobile-full-sync: Full sync on mobile
Stage: Later
- **Deferred:** A phone holding a full-sync copy of a repo, named in §11.22's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row. R-EVS-14 holds evs to 4 MiB in the iOS app process.
- **Launch instead:** Mobile and wasm hosts read in head mode, read both ref modes and write only file-mode refs; a mobile catch-up fetches at most 4 MiB of statements and proofs (§11.7, §11.9).
- **Lost:** A phone is not a full-sync device, so it cannot do what needs every name of a ref unless it mirrors that ref.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for the sync engine within a phone's memory and storage, storage over RAM, and an app that asks for it.

### evs-state-commitment: A state commitment over the token tree
Stage: Later, if measurements ask for it
- **Deferred:** A commitment over a ref's whole state, which would give a head reader freshness for paths older than its pin (§11.22; Q-EVS-6; owner decision 209's option (3), not taken).
- **Why:** The peer review closed Q-EVS-6 without a Merkle root: head readers replay signed statements from their pin and check the statement behind every entry they read. Owner decision 209 declined to reopen that before M2's freeze.
- **Launch instead:** Q-EVS-6's answer (c), made cheap (§11.9, D-EVS-24), and a sealed record of each path a head reader has read, at most 16,384 a network (owner decision 209): a recorded path served below its record is refused and alarmed.
- **Lost:** Pre-pin freshness for a path the reader never read or no longer remembers: evs could serve it at an older committed version from before the reader's pin, unseen. §2.8 publishes that limit.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** Measurements showing that head readers need pre-pin freshness, then a design for the commitment and its cost on each head write, and a format change after the freeze.

### evs-directory-resident-children: Directory-resident children
Stage: Later, if §22.8 shows the need
- **Deferred:** Keeping an append-only record directory's children inside the directory's own object, paged, through the reserved `layout` (§11.7's directory row; §11.22).
- **Why:** It is worth its cost only if §22.8 shows stream entries' index objects binding.
- **Launch instead:** Each child has its own index object; a directory holds at most 4,096 children and 448 KiB of name table, and §15 and §16 shard their streams by sequence under that bound.
- **Lost:** Nothing unless the measurement binds: then a stream's index objects cost more metadata-cluster writes and inodes than a resident layout would.
- **Dark in code:** `layout` is reserved in format 1 (sidecar/protocol/evs.proto), so the layout needs no new field.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** §22.8's count of stream entries' index objects, then a design for the paged layout and a storage-format step.

### evs-repo-move-tool: A tool that moves placed repos between clusters
Stage: Later, before the first cohort exhaustion
- **Deferred:** A tool that moves a repo, with its gkm group, from the metadata cluster it was placed on to another, keeping one commit point (owner decision 145; §10.16, §11.22, §19.18, §23.4; Q-OPS-10's residual).
- **Why:** Owner decision 145 grows the metadata tier by whole clusters, places each repo once at creation, and names the move tool a later item.
- **Launch instead:** A repo stays on the cluster placed at its creation. New repos go to the next cluster from §19.9's triggers, and §11.13's write budget refuses the heaviest network first.
- **Lost:** An existing repo cannot be moved off a full cluster, so the first cluster's writes can outgrow its set (§3.14's and §11.21's risk rows). A cluster that fills answers 507 CLUSTER_FULL.
- **Dark in code:** Nothing is built. `place/` never moves.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** §19.9's cohorts row projects each cluster's exhaustion, and the tool is built to land before the earliest one. It needs a design that moves `place/`, the repo's metadata objects and its gkm group while a single commit point holds.

### evs-per-cluster-batcher: A per-cluster batcher
Stage: Later, if §22.8 shows it saves a set
- **Deferred:** Two evs processes batching each cluster's records together, near 5 records a batch (§11.21's risk row; §11.22; §19.17).
- **Why:** It is worth building only if §22.8 shows that it saves a drive set.
- **Launch instead:** Each evs process batches its own records (§11.8). §22.8's M2 gate measures records per batch per cluster.
- **Lost:** Nothing unless the measurement shows small batches: then drive writes per push are higher than a shared batcher would give, and the next cluster is needed sooner.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** §22.8's records-per-batch figure on production load, then a design for routing a cluster's pushes to two batching processes.

### evs-reverse-citation-index: A reverse citation index in pidx/
Stage: Later, if §22.8 shows scans binding
- **Deferred:** An index from each segment to the versions that cite it, kept in `pidx/` at evacuation, so a drop's scan reads `pidx/` only (§11.16's alternatives row; §11.22).
- **Why:** §11.16: it is a permanent NVMe cost on every push for a rare action.
- **Launch instead:** The drop job scans to find what still cites a segment (§11.13).
- **Lost:** Nothing unless §22.8's `drop` row shows the scans binding: then drops run slower than they could.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** §22.8's `drop` row showing the scan as the limit, then the index, its write on every evacuation, and its rebuild for existing repos.

### evs-index-semantic-layer: A word complement or semantic layer in the search index
Stage: Later
- **Deferred:** A word complement or a semantic layer stored in the search index's own buckets, named in §11.22's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row.
- **Launch instead:** A trigram index: each document's set of distinct 24-bit keys over its normalized text, searched on the device (§11.14).
- **Lost:** Search matches text by trigrams only: no ranking by meaning and no whole-word postings.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for the layer's keys and for what it lets evs infer, then an index-format step. See also semantic search in §16's entries.

### evs-index-elias-fano-key-sets: Elias-Fano key sets
Stage: Later
- **Deferred:** Encoding the search index's key sets as Elias-Fano, named in §11.22's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row.
- **Launch instead:** Key sets in §11.14's encoding, which protocol/INDEX-FORMAT.md fixes.
- **Lost:** Whatever bytes or decode time Elias-Fano would save; DESIGN.md gives no figure.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A measurement against the current encoding, then an index-format step.

### evs-index-per-field-postings: Per-field postings
Stage: Later, if §22.8 shows field-scoped queries common
- **Deferred:** A posting set for each field of a document, in place of one set for all fields (§11.14's fields row; §11.22).
- **Why:** One posting set gives 12.6 to 17.3% less index, and a field-scoped query is confirmed against the doc table row, which costs nothing for header fields.
- **Launch instead:** One posting set covers every field.
- **Lost:** A field-scoped query over body text does more confirming work on the device.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** §22.8 showing that field-scoped queries are common, then an index-format step.

### evs-slot-orphan-pass: A pass that collects orphaned slot objects
Stage: Later
- **Deferred:** A pass over `slot/` that removes a slot object no record names (§11.8's step 6; owner decision 400; DESIGN-DETAILS.md section 14).
- **Why:** DESIGN-DETAILS.md section 14: the pass is not designed, and nothing rests on it.
- **Launch instead:** A crash between a slot's creation and its record leaves at worst a slot that no record names. The same statement's retry takes it; otherwise it stays, at most 8 KiB.
- **Lost:** A few stray objects of at most 8 KiB each, stored for the repo's life.
- **Dark in code:** Each slot object carries the statement that created it as its origin, in object metadata, which is what such a pass would read.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design: remove a slot that carries an origin and no hold once Resolve finds its origin's statement dead and the evacuation horizon has passed the minute its record could lie in.

### evs-v1: §11's v1 set
Stage: v1 (M6, M10)
- **Deferred:** §11.22's v1 row: retention as expiry, ERASE and BASE (owner decision 246); agent-subkey provenance; the `directory` kind at M6 on format 1's streams. Format 2 at M10 (owner decision 169): versionless files with staging, the purge and its sweep, rules and the repo lock, migration and the git-lfs store; the search index with its erasure cut and erasure sets; the directory's cards and index; the drop-history action behind §19.11's `format2.drop` gate; remote search.
- **Why:** Team ships at M6 and format 2 at M10 (owner decisions 55, 163, 169).
- **Launch instead:** Format 1 (v0a) with the local tier (v0b), both at M2. Format 1 reserves format 2's numbers and refuses data that uses them as FORMAT_UNSUPPORTED.
- **Lost:** Until M6: retention and the directory. Until M10: versionless files, search and drops.
- **Dark in code:** Built in the same run on the `sidecar` branches. §19.11's `format2` gate, with its purge and drop modes, holds format 2 to internal networks and design partners first.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: each ships when its milestone's gate passes (§23.6).
