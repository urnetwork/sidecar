## 11. Encrypted versioned storage: format, git service, head API, subscriptions

### 11.1 Purpose and scope

This section owns evs repos and kinds, `config` and `directory` included; the format and what the server sees (X2, owner decision 2); the file-cluster objects, their placement and the push, commit and read protocols; refs and their modes, record streams and deposits; git compatibility and the local tier (X19, owner decision 24); subscriptions; per-object versioning, the versionless purge and the drop-history action (11.7, 11.13; owner decision 173); GC and evacuation, the metadata write budget and fair share, quotas, durability, deletion and export; and the encrypted search index's placement, format, upkeep, erasure and read path, with remote search, an app host's "search more" answered end to end by a designated indexer (11.14; owner decisions 175, 178), whose search tools are §16's and §18's.

Keys come from §10, identity from §5, push from §6, tokens, the projection and grants from §7 and §8, hardware from §19 (X13), quotas from §20 and layouts from §15 and §16. The metadata clusters also store, and 11.13 budgets, §7's `proj/`, `projrows/` and `rev/`, §10's `gkm/` and §21's `hold/` objects.

### 11.2 Requirements

| id | requirement | source |
|---|---|---|
| R-EVS-1 | One directory = one git repo = one encryption domain, keyed through GKM | PLAN.md:53 |
| R-EVS-2 | Subscribe to a dir and subpath; notified by a subprotocol message | PLAN.md:55 |
| R-EVS-3 | "The storage service speaks git over https", at the sidecar | PLAN.md:57; owner decision 24 |
| R-EVS-4 | Git identity forced to the sidecar client id | PLAN.md:59; owner decision 81 |
| R-EVS-5 | Servers see only ciphertext, keyed path tokens and small headers | owner directive 2026-11-03; owner decision 2 |
| R-EVS-6 | Blobs in minio, in a new file cluster whose metadata tier grows only by whole clusters | PLAN.md:61; owner decisions 18, 21, 94, 116, 136-139, 145 |
| R-EVS-7 | Diffs, with a checkpoint every N commits of a file and on a rewrap | PLAN.md:50, :63 |
| R-EVS-8 | A file's head read without a clone, in 2-3 GETs and two store round trips (three when the head is not cached), plus one range GET per uncached statement after the reader's pin and at most two cached log-page GETs when its last change is older than the head window | PLAN.md:63; owner decisions 2, 136; [R:product] S11 |
| R-EVS-9 | A local git server per dir over http and ssh, plaintext only on loopback; `git clone ur://<net>/<repo>` | cli/UI.md:31-34, :91-94; owner decisions 24, 84, 130 |
| R-EVS-10 | Real-time agent branches, tip CAS on shared git refs, a twenty-agent test, plain-git export | sidecar/design/market2.md:513-531; owner decision 141 |
| R-EVS-11 | Per-entry erasure for record-class repos and mail from the start, never deferred by a hold | REC:217-223; owner decisions 61, 133 |
| R-EVS-12 | Every server-visible field published; signed pushes; refs pinned against rollback | sidecar/design/pitch5.html:745; I-4, I-16, I-18 |
| R-EVS-13 | Storage quotas of 1/20/200 GB; transfer debits the balance | PLAN.md:353-355; owner decisions 10, 27 |
| R-EVS-14 | Desktop, gomobile, wasm; ≤ 4 MiB in the iOS app process | PLAN.md:28; §18.4 |
| R-EVS-15 | No Postgres or durable Redis storage state (Redis holds only rebuildable soft state); 3-5 store round trips per push: three, one more for new slots and one when the head is not cached (11.8's costs) | owner decisions 2, 136 |
| R-EVS-16 | Reader or writer grants, by repo or network admins; owner-bound readers need the owner's consent | owner decisions 7, 8, 126 |
| R-EVS-17 | Record-class repos mirrored on owner devices, indexers first, which recover site loss | owner decisions 90, 94, 150 |
| R-EVS-18 | A git push of any size commits atomically; no network starves the others' store operations | derived: R-EVS-12; owner decisions 2, 21 |
| R-EVS-19 | Metadata writes other than P0's stay within 0.8 DWPD and 50% of rated write IOPS on every metadata drive, less the P0 writes the write budget's bucket held; past that, the heaviest network is refused first; P0 safety work is never queued or refused, its bytes measured and reported and its excess past the bucket forgiven, so a P0 storm can pass the bound | owner decisions 140, 186, 190 |
| R-EVS-20 | Versioning on or off per object: a versionless object keeps only its newest version's content, purged a minute after its replacement commits; never on git-mode refs or in config and mailcfg repos; git-lfs's versionless store collected once no ref tip and no commit of the last 30 days (per repo) references an object; a repo lock; a per-network rule, versionless above 64 MiB by default, applied when a path is created; the index always versionless | owner decisions 158-165, 167 |
| R-EVS-21 | A per-repo encrypted search index, on by default and turned off by any repo admin (never the team directory's), in every repo but config, mailcfg and secret ones (D-EVS-43), a locked repo keeping it, that devices download whole and search locally; each committer updates it with its commit, git-mode refs and record streams by companion pushes on `ur/index` at most once a minute per writer on 1 KiB blocks, else every 5 minutes | owner decisions 151, 156, 168, 171, 172 |
| R-EVS-22 | Two latest buckets of the repo's window (30 days by default, 7-365) and an all partition that roll-ups keep complete; search stays correct during a roll-up | owner decisions 152, 153, 157 |
| R-EVS-23 | The index is versionless, so an erasure removes its postings, within the rekey bounds and the eraser's allowance | owner decisions 61, 133, 146, 159 |
| R-EVS-24 | The index's cost per commit stays bounded for code and large-file repos, binaries skipped, within R-EVS-19 | owner decisions 140, 156 |
| R-EVS-25 | A designated indexer answers its network's app hosts' searches over repos both read, from the partitions and text it holds, in fixed-size messages, fetching nothing for them; a network has none by default | owner decisions 175-178 |
| R-EVS-26 | A repo admin can drop a path's history on a file-mode ref in v1: a signed action held 7 days for any repo admin to cancel, deleting only content that the dropped versions alone name, keeping every statement, hash and the head, and deferred silently under a hold | owner decisions 173, 183, 184 |

### 11.3 What exists today

- **No code** exists for evs or a git server [R:server-platform] §5.10.
- **BlobStore** has an overwriting Put (server/blob.go:674-679), PutIfAbsent as one If-None-Match request (:683-697), whole-object Get, List and SetLifecycle, but "deliberately no Delete", no ranged read and no streamed put (:155-183).
- **MinIO.** The deployed build (§19.3) checks If-Match and If-None-Match under its namespace lock but proceeds when that read loses quorum (minio@v0.0.0-20251015172955-9e49d5e7a648 cmd/erasure-object.go:1261-1279); PR #21653, merged 2025-10-24, fixes it, and owner decision 18's clusters build from the final upstream source (§19.6). MinIO verifies `x-amz-checksum-sha256` before an object exists (cmd/object-handlers.go:1993-2006) and inlines shards of up to 128 KiB in xl.meta (internal/config/storageclass/storage-class.go:278-294). It stores an object as a directory and lists that directory as one object without descending (cmd/metacache-walk.go:239-264). Names are at most 1,024 B (cmd/object-api-utils.go:197-203). xl.meta up to 4 KiB is written O_DSYNC, and larger ones with O_DIRECT and fdatasync (cmd/xl-storage.go:2247-2285). An overwrite also writes the previous xl.meta, inline data included, as a backup until quorum (:2784-2800, :2874-2887). With several pools, a PUT picks its pool by free space even when its key lives in another pool, and checks its precondition only there (cmd/erasure-server-pool.go:637-656; cmd/erasure-object.go:1261-1285). Upstream's DELETE evaluates no precondition (cmd/object-handlers.go:2563-2671; cmd/object-api-options.go:273-318), so an If-Match sent with it is ignored; §19.6's in-house build honors one condition of its own, `x-ur-if-unmodified-ms`, under the key's lock. A cancel stops a PUT on the handling host's own drives before their commit rename (cmd/xl-storage.go:2891-2893) but reaches no drive operation on another host, whose storage RPCs run under context.Background() (cmd/storage-rest-server.go:366, :708; internal/grid/handlers.go:294), and the handler's deferred unlock frees the object's lock while they run on (cmd/erasure-object.go:1269), so a cancelled write can land after a later request on its key, and holding the lock to the 30 s drive timeout would still release a commit stalled after its last check; §19.6's in-house build (D-OPS-20) closes both with its deadline and settle rules.
- **lb.** `client_max_body_size 16m` is global (warp/warpctl/config.go:1301); `streamable_paths` (warp/services/services.go:694-701) get 60 s timeouts and no request buffering (warp/warpctl/config.go:2311-2319).
- **Crypto and clients.** x/crypto v0.54.0 (connect/go.mod:30) has XChaCha20-Poly1305 (chacha20poly1305/xchacha20poly1305.go:24) and no AES-SIV. Clients are reaped after 30+30 idle days (server/model/network_client_model.go:4179, :4199), so the durable signer is §5's `sidecar_id`.

### 11.4 Architecture

```text
git, harnesses        sidecar daemon                                  evs (stateless)             file cluster (§19.6)
 push/fetch ------->  local git server (http, ssh), git-remote-ur     tokens verified offline     metadata clusters (NVMe); a
                      bare repo; sealed mirror of evs objects         head CAS: tip on git refs,  repo lives on the one its
 MCP tools -------->  sync engine --segments, signed pushes, HTTPS--> path-level on file refs --> place/ names: repo/ head/
 apps (head mode) ->  EvsClient  <--PushHint evs:<repo_id> (§6)-----  batches; lazy index folds   log/ pb/ idx/ slot/ hp/ pmap/
                      keys: §10 RK_g -> path, ref, manifest, fek      hints via §6's Redis        pidx/ drops/ gkm/; the first also
                                                                      Redis: hints, leases, push  place/ proj/ projrows/ rev/
                                                                      sequence, head cache        hold/, per-sidecar gkm/
                                                                      usage events -> §20         segment cluster (HDD):
                                                                      write budget, fair share    seg/ pack/ dropscan/
```

evs never parses git, holds no key (I-1) and keeps no Postgres or durable Redis state; Redis carries §6's hints and rebuildable soft state: leases, the push sequence, drop hints, a verified head cache (owner decisions 2, 17, 136). Its one queue, of versionless purges due a minute after their replacement, lives in each process's memory, and evacuation's sweep covers its loss (11.13).

### 11.5 X2: what the server sees

Owner decision 2 settles X2's residual (Q-EVS-1): the server sees exactly §2.8's evs rows, one per 11.8 family: each ref's token tree, push DAG, pins and per-file changes (token, time, uploader, Padmé-padded size), each client's reads and subscribed prefixes, and which pushes one evs process batched. It never sees names, contents, messages, authors, branch or display names, agent ids or entry sequence numbers, nor links equal content across or within repos (per-repo keys, random nonces, records reused only for renames and merges). It also sees each file version's versioning setting (11.7), which content rides staged inside a push, and when the purge deletes a replaced versionless version's content, about a minute after the replacement commits, staged content with its batch, at most 26 h (11.13); each drop's token-path lineages, listed entry hashes, window, cancel, the deletions its job makes and admins' dry runs (§2.8's evs-12, evs-28); and, in a team directory, when each sidecar's card and each request's notice change, never their contents (evs-27). Of the search index it sees only shape and fetch times (11.14's server rows), never a query, a match, or which trigrams documents share, and nothing of a remote search (§2.8's connect-5).

**Token leak bound.** A token alone shows only its place in the tree. With the server's help, a key holder can test guessed names created before the path epoch that drops it (11.6), which a member device's removal or a compromise makes due at once, new names in general, config and mailcfg repos waiting for it, and other drops and authorization expiries within 24 h, or, while two source epochs stand, once one drops (11.6's commit row), each landing when a mapper commits (writers alarm an hour past due, not while such an epoch waits), and guessed branch names for the repo's life, since ref ids stay keyed from RK_1. A Delegation's reader key counts as dropped only when §10.5's live(d) ends: at the Delegation's end (its DelegationRevoke, its void, or a compromise revocation of one of its agents), at its `not_after`, or at a `Suspend` or a revocation for any reason but reaped of one of its agents (§10.5). Holders follow files they knew through the map.

### 11.6 Format: keys, tokens, records, segments

**Keys** are §10.5's `fek`, `manifest`, `drop`, `path` (tokens of path epoch p, from RK_p), `ref` (ref ids and the search index's document keys, from RK_1, since ref ids name every `head/` and `log/` key and a document's key must not change at a rotation) and `index` (the search index's keyed pad, per generation; 11.14).

**Tokens:**

```text
names    name_i is the path component's raw bytes as git stores them, never normalized, so NFC and NFD names are
         distinct paths, as in git
tokens   t_i = HMAC-SHA256(K_path_p, t_{i-1} || name_i)[:16], t_0 = 16 zero bytes, K_path_p = HKDF-SHA256(RK_p, salt
         repo_id, info "UR evs 1.0 path" || u64be(p)); 26 base32 characters in keys; at most 32 components, keeping
         keys within MinIO's 1,024 B; deposits, whose writers hold no path key, use random ids
ref ids  ref_id = HMAC-SHA256(K_ref, "ref" || ref name bytes)[:16], K_ref = HKDF-SHA256(RK_1, salt repo_id, info
         "UR evs 1.0 ref" || u64be(1)), so any reader derives head/<repo>/<ref> for `main`; deposit refs: the first
         16 B of SHA-256(repo_id || sidecar_id)
leaks    K_path is per repo, so one path has one token on every ref of a repo in one epoch (overlays need this);
         ref ids stay keyed from RK_1, so a removed holder can test guessed branch names for the repo's life
         (11.5, §2.8's evs-2)
```

**Path epochs (owner decision 2 item 9)** are named by the generation p that derives K_path, 1 at creation:

```text
due      the first commit whose generation pin crosses a REMOVE generation (§10.5: it covers a shrink, an
         authorization expiry or a compromise retirement, §7.9) records it in head.path_epoch.due; evs classifies
         it by what it covers and sets due_by_ms; writers alarm 1 h past due_by_ms, but not while the commit row
         defers a batched epoch, which §19.8 reports, nor within 1 h of that deferral's end:
         immediate: a member's or a member device's removal, or a compromise retirement (a SidecarRevoke or
           RecoveryRebind with reason compromise, agents included, or a leaked bundle's DelegationRevoke with
           since_n > 0; §10.6), due_by_ms that commit's time; in
           general, config and mailcfg repos, whose names carry meaning, a push creating a path (a change with
           base_entry_version 0, or a directory add) then gets 412 PATH_EPOCH_DUE until the epoch lands; vault,
           mailbox, record and team_record name entries only by random id or sequence (§15.7, §16.8) and keep
           creating
         batched: other key-holder shrinks (§7.9; a reap of an agent its live Delegation covers is none) and
           authorization expiries (a RepoGrant's or requested grant's expires, an uncovered agent's SidecarAdmit
           or a Delegation's not_after); no block; due_by_ms 24 h after the first
map      the writer that rotates, or any writer holding every name of the ref (a full-sync device, or a mobile
         mirror of under 100,000 names), wrapped agents included (owner decision 114), uploads Signed EvsPathMap
         parts for the newest generation p_new to pmap/<repo>/<ref>/<p_new>/<path_map_sha256>/<k>/_: per live
         path, its token path in p_new, in the current epoch and in every source the head lists, and its name
         re-sealed for the new parent and child tokens; the map binds its source head (map_source_version,
         map_source_chain); keys name the map, so a mapper whose source left the window, or that finds another's
         map abandoned, uploads a fresh one; once p or a newer epoch commits, taskworker deletes p's uncommitted
         maps, and the nightly pass deletes a map above the head's epoch once 11.13's horizon has passed its oldest
         part's LastModified + 24 h + 2 min, each part by a DELETE naming its LastModified (owner decision 203)
tail     paths that window versions after the map's source create get moves like the map's, which the mapper
         builds from those pushes: the PATH_EPOCH push carries them in its payload under path_tail_sha256, and evs
         checks every token path those versions create (base_entry_version 0) against them, else 409 naming the
         paths, so a creation costs the mapper a longer tail, never a fresh map
block    10 min past due_by_ms, a mapper may stop creation for at most 2 min, at most once each 10 min: POST
         .../path-epoch/block {ref_id, ms <= 120,000} sets head.path_epoch.block_until_ms by one head CAS that
         raises only the fence (11.8); until it passes, a push creating a path gets 412 PATH_EPOCH_DUE after a
         fence (11.8's refuse row), so the mapper's tail stops growing and its epoch commits; evs refuses a
         block for a batched epoch while two sources stand, since the commit row defers it
commit   a PATH_EPOCH push (file and git mode alike; it carries no git commit, and in git mode it takes TIP like
         every push, its mapper re-signing on a newer head or, on a busy ref, first taking the seal lease) commits
         if its map's parts exist, each under 24 h old, path_map_sha256 matches, its source version is in the
         window with a matching chain, its tail covers every creation after that version, and its own process's
         fold left nothing unfolded (11.7 (4)); the head then makes p_new current, lists the old current epoch
         first among the sources (at most 3: a fourth waits, 412 EPOCH_SOURCES_FULL, while creation stays
         blocked; a batched epoch waits so while two sources stand, with no block and no map built meanwhile,
         covering every expiry due when it lands, so the third stays for an immediate epoch), clears due and the
         block; pushes declaring an older epoch get 412 PATH_EPOCH, part and seal
         checks included, and re-tokenize
copy     one taskworker job per ref, for the newest map and its tail only, as P2 work (11.13), running the moves in
         descending token-path order, so a directory moves after its children: each move reads the entry from the
         newest source holding it, keeps its folded versions and drop mark (11.7), rewrites a directory's name table
         from its children's moves, matching each row in that row's own epoch, PUTs the new entry (If-None-Match,
         carried) and deletes
         every source copy; on 412 a file, or a removed or fresh entry (11.7), is done, its source copies deleted
         unmoved, and a carried directory's carried rows are translated and the entry PUT If-Match, read again on
         412; after each PUT it HEADs the path's prefixes in the current epoch and, finding one removed or fresh,
         turns what it put into a marker (If-Match on that PUT's ETag, 11.7; on 412 the newer entry stands); at most
         50 operations a second per repo, 150 while two or more sources stand, and 250 in all on the repo's metadata
         cluster, its taskworker processes together through {nvb_<set>} (each cluster's copies spend that cluster's
         P2 budget, 11.13), up to 1,000 while A1 left a quarter of T unspent over the last minute; jobs whose ref
         holds the most sources run first, then the one with the oldest source; each job reports the moves it has
         left, §19.8's copy liability; it rereads the head at least every 5 s (11.7's stale rule) and stops when a
         newer map supersedes its own; at the end it LISTs
         idx/<repo>/<ref>/<p_i>/ for each source, deletes the markers there unmoved, alarms on any other entry or
         carried row the map missed and keeps that source listed; when every source is empty, a fence write drops the
         sources (11.8), and 11.7 collects the current epoch's markers; one a fold left racing a move reads as absent
read     clients send each path's token path in the current epoch and in each listed source that may hold it:
         where they knew its name before the cut-over, or their listing showed it in that epoch (a carried row, or
         a row of an entry that source served); a name they hold no row for they look up through its parent, and
         an untagged row's child is in the current epoch (copy, above); while sources stand, evs also HEADs in the
         same round a path's prefixes' current entries, whose state (11.7) rides in object metadata, each settled
         by 11.7's rule: under a removed prefix the path is absent, and under a fresh one too unless its own
         current entry is fresh; else evs uses the current entry, else the newest source's, and if every GET of the
         path returned 404 it GETs the current one again, since the copy PUTs it before deleting a source copy;
         changes name their source paths by the same rule (the payload's source paths) and a delta removing a
         child lists its token in each epoch that may hold it, so a fold drops a carried row too, and the server
         sees no source-epoch token of a name created since the cut-over; readers check a carried row under its
         epoch's tokens and AAD
leases   the PATH_EPOCH hint reaches every lease holder of the ref, which re-creates its leases in p_new; a
         holder that missed it does so at its next resync (11.10)
costs    a 1M-file ref moves in about 17 h at 50 operations a second (3 per entry), about 6 h at 150, and one
         cluster's copies together move at most 7.2M entries a day at 250, so §19.9 plans each cluster's copy load as
         the live entries of its rotating refs times their epochs a day, under half of that; while sources stand, a
         read takes a HEAD per prefix and, for an unmoved path, a GET per listed source, in the same round
```

**Removal: tokens now, content later (owner decisions 2, 64).** Tokens re-key at once, server-side: the server sees them, a removed key holder could keep testing them, and the copy moves no content. New names in general, config and mailcfg repos wait for the map, so none is tokenized under a removed key. Content rewraps lazily: the removed reader already holds every version it could decrypt, so a file's first write checkpoints it under the new generation (11.7 (4)), or `ur evs rekey` does; moved entries keep their bodies under their old generation, which the ladder opens for current readers.

**Nonces.** Every AEAD is XChaCha20-Poly1305 with random 192-bit nonces, so writers share no counter, wasm needs no lookup tables (§10.4), and nothing is encrypted deterministically.

```text
record          header sealed under manifest (160 B): record id, kind, key ref, body length, base record id,
                result git oid, nonce prefix. Body: 64 KiB STREAM frames under its object key, nonce = 19 B
                prefix || 32-bit counter || final flag, as in age (https://github.com/C2SP/C2SP/blob/main/age.md).
                AAD = repo_id || file_id || record id || generation || frame index. evs checks nothing.
segment         immutable, <= 8 MiB: 32 B public header {URvs, format 1, flags, repo_id, generation}, records,
                random padding to Padme(length); id = SHA-256 of all bytes. evs checks id, size, repo, generation.
                A kind-5 segment's header is format 2's, 48 B, adding the push_id that introduces it, which evs
                checks against the uploading or staging push, so no other push adopts its bytes (11.7).
object key      random 32 B, wrapped under fek_g. General repos: one per segment or inline chain, in its sealed
                header, which is owner decision 61's slot per segment, erased with the repo. Group inboxes: one
                per message, in a deletable slot/ object (§15.7). Record-class repos: one per entry or chain, in
                a deletable slot/ object; in group inboxes and record-class repos, one per versionless path, in a
                slot only that path's versions name (11.7). Deposits: one per deposit, HPKE to the drop key, in a
                slot/ object CONSUME deletes. Slot ids are 16 random bytes drawn per statement: a push rebuilt
                after a refusal draws new ones, and a retry of the same statement keeps them (11.8)
statements      §6 Signed by the §5 identity key only: EvsPush (purpose evs-push; a DROP by a repo admin, in an
                owner-bound repo only by a consented, not-read-only device of its owner, 11.7), EvsPathMap
                (evs-path-epoch, by a writer), EvsImport (evs-import, by a repo admin; 11.11), EvsReseed
                (evs-reseed, by a repo admin; 11.13)
kinds           EvsLocator.kind 1 (segment) and 2 (inline) ship in format 1, which also reserves kind 5 (versionless
                segment), EvsEntryVersion.versioning (14; owner decision 167 needs no field 15), EvsLocator.staged
                (6), the kind-5 segment header (above), EvsUploadReceipt.versionless (8), batch format 2 (11.8),
                EvsPush flag 256 (DROP) and field 33 (drop_sha256; owner decision 173), flag 512 (CUT) and field
                34 (index_epoch) with EvsHead's index_epoch (24; 11.8, 11.12), the read reply's per-path
                states drop_pending and dropped (11.9) and the push provenance's tainted bit (Records); format-1
                code refuses each in use as FORMAT_UNSUPPORTED {needs_format: 2} (owner decision 163), never as a
                fork, tampering or a missing segment, and ignores window bits 4 and 5 and the tainted bit; it
                verifies §7.9's VersioningRules and §8.8's RepoVersioning by signature and chain, folds the head
                holding the first and the lock of the second, and applies nothing from either, so no device stalls
                or forks (D-PHASE-9; §7.9, §8.8); repo/'s kind directory is known from M2, since the team directory
                runs on format-1 streams from M6 (11.12; owner decision 171); format-1 clients refuse to write the
                .ur-index/ directory on file-mode refs and the ur/index and ur/lfs refs (11.14); format 2 (v1) gives
                them meaning (11.7); kinds 3 (push-payload range) and 4 (pack range) stay reserved and refused, so
                either can ship with a format version that readers learn before writers use it
format          a repo's format is repo/'s object format: 1, or 2 from v1; evs takes format-2 values only from
                networks in §19.11's format2 gate, raising a format-1 repo at the first such push by an If-Match on
                repo/ before its step 7 (11.8), and GET .../refs returns it; format-1 data is valid format 2, so
                nothing is rewritten; a reader below format 2 says the repo needs an update and refuses its format-2
                values, reading every other file; format-1 evs, as after a rollback, serves a format-2 repo's stored
                bytes, refuses its pushes (503) and purges nothing
```

**Records** are `checkpoint`, `diff` (a git pack delta against the file's previous version, https://git-scm.com/docs/gitformat-pack) or `chunk`. Trees are not stored: directory names and each child's sealed {mode, oid} rebuild them exactly. Commits travel sealed in push records with provenance (§5.5's `agent_id`; agent-subkey signatures from v1; from format 2, the writing run's `tainted` bit, which format 1 reserves and ignores, so §16.6 and the search index can mark files from a tainted run) and §10's `epoch_authenticator`. A file's random 16-B `file_id`, sealed in its entry, lets a rename keep its chain and stops evs swapping chains between files.

```proto
message EvsPush {                       // sidecar/protocol/evs.proto, inside §6 Signed, purpose evs-push; <= 1 KiB signed
  bytes repo_id = 1; bytes ref_id = 2; uint32 ref_kind = 3; bytes owner_sidecar_id = 4;
  bytes push_id = 5;                    // 16 random bytes; names this statement only (11.8)
  uint64 base_version = 6; bytes base_chain = 7;        // the head it read: v and C_v
  repeated EvsChange changes = 8;       // every change, while the signed statement stays <= 1 KiB
  bytes sealed_metadata_sha256 = 9;     // commits, messages, provenance, epoch_authenticator, EvsImport
  uint64 generation = 10; uint64 path_epoch = 11;
  AuthPin auth = 12;                    // the authorization pin (n, A_n), §7.9
  bytes signer_sidecar_id = 13; bytes client_id = 14; int64 time_ms = 15;
  uint32 flags = 16;                    // 1 FORCE, 2 DELETE, 4 BASE, 8 IMMUTABLE, 16 CONSUME, 32 PATH_EPOCH,
                                        // 64 ERASE, 128 CLOSURE (an erasure's re-checkpoint, 11.12), 256 DROP
                                        // (a drop-history action or its cancel, 11.7; format 2), 512 CUT (an
                                        // erasure's index cut, 11.12; format 2)
  bytes path_map_sha256 = 17;           // PATH_EPOCH: SHA-256 over the epoch's EvsPathMap parts, in order
  uint32 part_count = 18;               // 0 for a one-part push, else 2 to 1,024
  bytes parts_sha256 = 19;              // SHA-256 over the parts' SHA-256s in part order (the list is in the payload)
  uint32 ref_mode = 20;                 // 1 git, 2 file (11.7)
  reserved 21;                          // the pin's chain lives in auth (12)
  bytes group_id = 22; bytes generation_commitment = 23;     // the generation pin with generation: {group, g, C_g}
  bytes changes_root = 24; uint32 change_count = 25;         // when changes are not inline: the root over all of them
  repeated EvsTokenPath changed_prefixes = 26;               // then: token paths, <= 512 B in all, covering every change
  bytes new_objects_sha256 = 27;        // segments (id, padded size, upload day) and slots (id) it introduces
  uint64 map_source_version = 28; bytes map_source_chain = 29;  // PATH_EPOCH: the head the map covers (11.6)
  bytes erased_sha256 = 30;             // ERASE, CLOSURE: SHA-256 of its payload's (slot id, key index) list (11.12)
  bytes path_tail_sha256 = 31;          // PATH_EPOCH: SHA-256 of the tail's moves in its payload (11.6), or empty
  bytes source_paths_sha256 = 32;       // while sources stand: SHA-256 of the payload's source paths (11.6), or empty
  bytes drop_sha256 = 33;               // DROP: SHA-256 of the payload's EvsDropHistory; else empty (format 2)
  uint64 index_epoch = 34;              // a CUT, or a push other than a CLOSURE creating or replacing an index
                                        // file: the head's index_epoch it was built at, the ref's erasure set at
                                        // that epoch applied (11.8's 5d, 11.14); else 0 (format 2)
}
message EvsTokenPath { repeated bytes token = 1; }            // 16 B per component
message EvsChange {
  repeated bytes token_path = 1;        // 16 B per component, in the push's path epoch
  uint64 base_entry_version = 2;        // 0 creates; the path-level CAS condition (directories merge, 11.7)
  bytes entry_sha256 = 3;               // SHA-256 of the new EvsEntryVersion; empty deletes
}
message EvsPushPart {                   // unsigned; parts_sha256 binds it
  bytes push_id = 1; uint32 part = 2;
  repeated EvsChange changes = 3;       // at most 1,024 entry writes; a path appears in one part only
  repeated bytes entry_versions = 4;    // EvsEntryVersion bytes, as each change's entry_sha256 names
  repeated bytes inline_records = 5;    // those that fit in 1 MiB; the rest go into segments
  bytes sealed_metadata = 6;            // a slice; sealed_metadata_sha256 covers the slices in order
  bytes changes_root = 7;               // root over this part's changes; the statement's root is over these roots
}
message EvsEntryVersion {               // what entry_sha256 hashes; in the push record, and folded into idx/
  uint64 version = 1;                   // base_entry_version + 1; a creation's max(the push's effective base
                                        // version, an overlay's chain included, a standing removal's) + 1, so it
                                        // never restarts (11.7)
  bytes push_id = 2; uint64 base_version = 3;            // the push that wrote it and the head it read
  bytes prev_push_id = 4; uint64 prev_commit_version = 5; // the version it replaces, for history walks
  int64 time_ms = 6; uint32 kind = 7; uint64 padded_size = 8;
  bytes sealed_fields = 9;              // file: {file_id, mode, git oid, size}, plus content_sha256 (the
                                        // plaintext's SHA-256) for a versionless file; directory: none
  repeated EvsLocator chain = 10;       // file: at most N+1 records
  repeated bytes slot_ids = 11;
  EvsNameTable names = 12;              // directory: a push's delta; in idx/, a fold's table (11.7)
  uint32 layout = 13;                   // directory: 0 single; other values reserved and refused
  uint32 versioning = 14;               // file: 0 every version kept, 1 versionless, 2 a versionless file of the
                                        // search index (11.7); directory: 0; format 1 refuses any value but 0
}
message EvsNameTable { repeated EvsName names = 1; repeated bytes removed_tokens = 2; }  // a fold's table removes none
message EvsName {                       // sealed as 11.7's name row
  bytes token = 1; uint32 kind = 2; bytes sealed_name = 3;
  uint64 epoch = 4;                     // 0, or the source epoch whose token and AAD a carried row keeps (11.6)
}
message EvsLocator {
  uint32 kind = 1;                      // 1 segment, 2 inline, 5 versionless segment (format 2, 11.7); 3
                                        // (push-payload range) and 4 (pack range) reserved
  bytes id = 2;                         // kinds 1 and 5: segment_id, at seg/<repo>/<id> (kind 1 also through
                                        // spidx/, 11.13)
  uint32 offset = 3; uint32 length = 4; bytes inline = 5;
  bool staged = 6;                      // kind 5: the segment rides in this version's push (11.7); format 1
                                        // refuses true
}
message EvsPathMap {                    // purpose evs-path-epoch; at most 8 MiB per part
  bytes repo_id = 1; bytes ref_id = 2; uint64 path_epoch = 3; uint32 part = 4; uint32 parts = 5;
  repeated EvsPathMove moves = 6;
  uint64 source_version = 7; bytes source_chain = 8;    // the head whose paths the map covers
}
message EvsPathMove {
  repeated bytes new_token_path = 1;
  repeated EvsSourcePath sources = 2;   // the path in the current epoch and in each listed source
  bytes sealed_name = 3;                // re-sealed under AAD with the new parent and child tokens
}
message EvsSourcePath { uint64 epoch = 1; repeated bytes token_path = 2; }
message EvsImport {                     // purpose evs-import; carried in the push's sealed metadata
  bytes repo_id = 1; bytes ref_id = 2; bytes tip_oid = 3; bytes oid_list_sha256 = 4; uint32 count = 5;
}
message EvsReseed {                     // §6 Signed, purpose evs-reseed, by a repo admin (§8.8); §19.10
  bytes repo_id = 1; bytes ref_id = 2;
  uint64 version = 3; bytes chain = 4;  // the re-seeded head: v and C_v
  bytes incident_id = 5;                // the recovery's identity (§19.10)
}
message EvsDropHistory {                // a DROP push's payload body (format 2; 11.7)
  bytes drop_id = 1;                    // 16 random bytes drawn per statement; a retry of the statement keeps it
  uint32 action = 2;                    // 1 drop, 2 cancel
  bytes cancels_drop_id = 3;            // cancel: the drop it ends, committed on this ref
  uint64 cancels_version = 4;           // cancel: that drop's ref version
  int64 not_before_ms = 5;              // drop: time_ms + 604,800,000 (7 days), or time_ms with now (owner
                                        // decision 183)
  repeated EvsDropPath paths = 6;       // drop: 1 to 1,024 lineages, sorted by their newest token path's bytes
  bytes preview_id = 7;                 // drop: the dry run its signer confirmed (11.13), or empty
}
message EvsDropPath {                   // one lineage: one path name on this ref, as far as evs can follow it
  repeated EvsSourcePath lineage = 1;   // its token path per path epoch, newest first; each older entry a source of
                                        // the next in that epoch's committed map or PATH_EPOCH tail (11.6)
  repeated uint32 map_parts = 2;        // per older entry, the map part (1 to parts) holding its move; 0 the tail
  uint64 through_version = 3;           // the path version that stays; every listed version is older
  uint32 boundary = 4;                  // 1 written: this push writes through_version, the head's content again;
                                        // 2 removed: through_version is the path's standing removal
  uint32 count = 5;                     // listed versions, 1 to 1,048,576
  bytes listed_sha256 = 6;              // SHA-256 over the listed entry_sha256 values, ascending, which follow the
                                        // body in the payload, spread over the push's parts past one part's 1 MiB
}
message EvsUploadReceipt {              // unsigned; evs MACs it (11.13), the push carries it back
  bytes repo_id = 1; bytes segment_id = 2; uint64 padded_size = 3; int64 upload_ms = 4;
  bytes uploader_sidecar_id = 5; uint32 key_id = 6; bytes mac = 7;  // HMAC-SHA256 over fields 1-6 and 8, first 16 B
  bool versionless = 8;                 // the segment's header is a kind-5 header naming the receipt's push
                                        // (11.7); format 1 issues false
}
message EvsPlace {                      // where a batch record's bytes are (11.8); assigned by evs, 20 B packed
  uint32 minute = 1; uint32 instance = 2; uint32 seq = 3; uint32 offset = 4; uint32 length = 5;
}
```

```text
size     a signed statement is at most 1 KiB, so log pages hold statements; big change lists move to the payload
         under changes_root
payload  in the push's batch record for a one-part push, else spread over its parts and its seal: entry versions,
         sealed metadata, inline records, the change list when not inline, the part hashes, the new-objects list
         (segment id, padded size and the UTC day of its upload, from its receipt, or a staged mark for a staged
         segment, whose bytes follow the payload outside every payload hash, 11.7; slot ids), new slot bodies, the
         erased list, a DROP's EvsDropHistory and then its sorted lists, across the push's parts when large (11.7),
         a PATH_EPOCH's tail moves, the source paths (per change, an EvsSourcePath for each listed
         source that may hold it, 11.6's read rule, in change order), the reuse list of committed versions whose
         segments a new version cites ((ref, token path, entry version), 11.8) and, per entry version, its Merkle
         proof to changes_root (empty when inline)
checks   at push time evs checks that each entry version hashes to its change's entry_sha256, that the change list
         matches changes_root, is sorted (merkle, below) and changed_prefixes cover it, that the payload lists
         match new_objects_sha256, parts_sha256, erased_sha256, path_tail_sha256, source_paths_sha256 and
         drop_sha256, each drop list its listed_sha256 and count, sorted and unrepeated (409 DROP_LIST), that each
         staged segment hashes to its id and names this push in its header, and that versionless versions keep
         11.7's rules (409 VERSIONING); a statement over 1 KiB is refused
merkle   RFC 9162 hashing: leaf SHA-256(0x00 || bytes), node SHA-256(0x01 || left || right); changes sort by
         their token paths' bytes, each part a contiguous run in part order, so inclusion proofs of two adjacent
         leaves show that no path between them changed (11.9)
```

### 11.7 Diffs, checkpoints, index entries, reconstruction

**Mapping to git.** Each ref has a mode: git-mode refs, which the local tier writes, commit only on their tip; file-mode refs land by path (owner decision 141). One evs push carries one git ref update, in parts when large (11.8); its cleartext changes are the net change per path, and its sealed metadata holds every commit with each intermediate commit's sealed changes, so export rebuilds every original oid.

```text
mode  written by                commit condition                       on a lost race                  export
git   the local tier: ur mount, TIP: base_version = v, a whole-ref     409; git reports a stock        the original commits
      git-remote-ur, ur evs     CAS for every push, FORCE and          non-fast-forward; the client    and oids
      import, and evs_write     PATH_EPOCH included                    fetches, merges or rebases
      through it (§16.2)                                               (new commits) and pushes again
file  evs_write on file-mode    path-level CAS: each changed file      evs lands a disjoint push at    one deterministic commit
      refs, head mode, record   path's newest committed entry version  the next version itself; a      per version: tree = the
      streams, deposits, mail,  equals its base_entry_version, and     shared path answers 409 with    state, parent = the previous
      config, mailcfg           base_version >= v - 63                 the paths                       version's, committer
                                                                                                       <client_id>@ur.invalid of the
                                                                                                       signer, time time_ms, message
                                                                                                       "ur push <push_id hex>"
set       the ref's first push sets ref_mode in its statement and the head; another mode is refused (409 REF_MODE);
          only git-mode refs take overlays (below), which are git mode
replay    replaying readers of a git-mode ref check TIP; that the first new commit's parent is the previous tip, and
          descent, except on a FORCE push the refs table allows or the first push after a DELETE; oids; and that
          every new commit's committer is the signer's <client_id>@ur.invalid (owner decision 81) except the oids
          an EvsImport lists, so the forced identity is a property of the stored history, not only of the hook;
          PATH_EPOCH pushes carry no commit and are skipped in descent
head mode mobile and wasm read both modes and write only file-mode refs; the SDK's Write on a git-mode ref returns
          EVS_GIT_REF, since a head-mode client cannot build a git tree, which needs every sibling's oid
scope     tags are git-mode refs pushed IMMUTABLE; git-mode refs refuse versioning off (versionless files, below);
          LFS (v1: 11.11's versionless store), replace refs, notes other than export's refs/notes/ur, partial-clone
          filters and atomic multi-ref pushes are outside v0 (11.11)
why tip   a path-disjoint landing gives a git ref a tree no git commit has, so export could not keep the original
          oids, and a server-made merge would merge shared branches automatically, which sidecar/design/market2.md:519-520
          forbids; tip CAS costs a client retry only when two merges meet (about 2% in the twenty-agent test)
```

**Checkpoints (PLAN.md:63)** are written when (1) the chain has N = 16 diffs; (2) its diffs exceed 50% of the file's size (Mercurial's revlog rule, [R:ext-storage-crypto] §2.10); (3) the file is new, or the delta outgrows it; or (4) a REMOVE generation (§10.5's GenRotate `cause`: it covers a shrink, an authorization expiry or a compromise retirement) is newer than the chain's key, which is PLAN.md:50's rewrap rule (owner decision 64); or (5) a DROP writes the path's kept head (Dropped history, below); every checkpoint draws a fresh object key, except that a slot-keyed repo's versionless path keeps its key until (4), a CLOSURE or a rekey replaces it. A versionless file's every version is a checkpoint or a chunk set: (1)-(3) do not apply to it, and (4) makes its next write re-encrypt every chunk.

**Large files** over 8 MiB are 4 MiB `chunk` records, rewritten only where touched; fixed sizes avoid content-defined chunking, whose chunk sizes leak and whose keyed variants were broken in 2025 (ePrint 2025/558). The v0 file cap is 2 GiB.

**Versionless files (owner decisions 158-165).** A file version whose `versioning` is 1 or 2 is versionless: its path keeps only its newest version's content, and the purge deletes a replaced version's content once its replacement commits (11.13). Format 2 (v1) carries it (11.6).

```text
setting   per file version: 0 keeps every version (the default); 1 versionless; 2 versionless, marking the search
          index's own files, which readers accept only under the index's roots (.ur-index/ on a file-mode ref, or
          the repo's ur/index ref; 11.14; owner decision 168); in format 2 only 11.14's mechanisms write under
          .ur-index/ and on ur/index, and readers ignore any other version there and alarm; directories carry 0;
          a path's setting is its newest version's, and a new version keeps it unless its writer sets another
choose    a writer sets a new path's setting from the rules in force at its creation (owner decision 167): the
          repo's own, from its access log's RepoVersioning (§8.8), else its network's VersioningRules (§7.9), else
          the platform rule, versionless above 64 MiB of plaintext; first match wins; a present rule set replaces
          the next source entirely, so a path none of its rules matches is created versioned (0), and the platform
          rule applies only where neither the repo nor the network has a record (owner decision 164); an
          owner-bound repo's own rules are sealed to its generation, so only that repo's readers read them (§8.8);
          the index writes 2, 11.11's git-lfs store 1 and §15.7's mail component s/model 1 (each 0 in a locked
          repo, the index excepted), and the team directory 1 on its cards ref's d/, r/ and q/ paths from its
          format 2 (format 1's notices are versioned files; §16.11), whatever the rules say; a writer changes an
          existing path's setting only explicitly (ur evs versioning, MCP's and the SDK's argument), as a new
          version that rewrites nothing stored; evs never reads rules
refused   409 VERSIONING for 1 or 2 in config and mailcfg repos, whose replaying readers verify authority from
          every version (§7.9, §15.7), on git-mode refs, and on creates-only refs (record-class streams, deposit
          and erasure refs); for 1, not 2 (owner decision 168), in a repo whose access log holds a lock §8.8's
          signer filed (a repo admin or a config writer; in an owner-bound repo only a consented device of its
          owner) in the authorization state evs validates against (5d), so a write validated before the lock
          serializes before it; readers refuse a 1 in a push whose auth pin includes the lock; the directory kind
          refuses every RepoVersioning (§8.8)
content   one checkpoint record, or 4 MiB chunk records above 8 MiB, never a diff or an inline record (readers
          check; evs sees only locator kinds): kind 5 for what its push writes and for unchanged chunks its path's
          previous version named as kind 5; kind 1 for chunks that version named as kind 1 (versioning just turned
          off; never purged); content_sha256 in its sealed fields
kind 5    a segment holding exactly one record of one versionless version, its 48 B header naming its introducing
          push (11.6), at seg/<repo>/<id> or, while staged, in that push's batch record; read and verified as kind 1
          (id, AEAD, then content_sha256 and the git oid); an upload whose header names another push than its
          ?push= gets 409 VERSIONING, and its receipt marks it versionless (11.6), so equal bytes are only ever the
          same push's retry and no push adopts another's segment as its own upload
staged    a record that pads to at most 16 KiB rides in its push's or part's payload as a one-record segment
          (Padmé-padded) instead of PUT .../segments: its new-objects entry carries a staged mark and its locator
          staged = true; no receipt; evacuation moves the record without the staged bytes and writes them to seg/
          only while their version is retained (11.13), so content replaced within about a day of its write never
          reaches the HDDs; packs and parcels never hold it, and pidx/ lists the staged segments a record
          introduced, as it lists uploads
cite      a kind-5 segment is named only by the version that introduced it and then, in turn, by its path's next
          version on the same ref, or, in the push that removes the path, by a version that push creates (a
          rename); never by another path, ref or repo, nor through a reuse source (a copy re-uploads); a staged
          segment only by its introducing version, a later version re-staging its <= 16 KiB
keys      general repos keep each kind-5 segment's key in its sealed header, so it goes with the segment; slot-keyed
          repos (record-class repos, group inboxes) keep a versionless path's one key in a slot that only that
          path's versions name, reused by each next version until checkpoint rule (4), a CLOSURE or ur evs rekey
          draws a fresh one in a new slot, so an overwrite writes no slot
removal   a push removing a directory, and a ref's DELETE, list each versionless file below as a file removal (the
          client holds the tree), so the commit names every version it replaces and the purge deletes their content
          a minute later, at most ~26 h when its queue is lost (11.13's sweep); a versionless file below that the
          push did not list goes at its marker's collection: the removal fold alarms and carries its kind-5 segment
          and slot ids in its marker, and the collection deletes them (collect, below; §2.8's evs-4, evs-5)
off       version k+1 written versionless keeps the path's earlier versions, written on, for the repo's life unless
          a drop lists them (Dropped history, below; owner decision 173); if its content is unchanged and k's chain
          holds no diff or inline record, it cites k's records as kind 1, with no upload; else it writes one
          checkpoint as kind 5
on        version k+1 written with versioning on starts history there; k's content is purged once k+1 commits,
          unless k+1 adopts k's uploaded kind-5 segments as kind 1 (no re-upload; then kept for good); staged
          content becomes inline again
history   a replaced versionless version keeps its statement and entry version for the repo's life: history shows
          its hashes, padded size, time and signer, and answers `collected` for its content, which nothing restores;
          a dropped version keeps its statement likewise (Dropped history, below)
reads     head reads are unchanged: every path's newest version has its content (I-EVS-1); a staged locator
          resolves by id in its push's record while that record is batch-resident, else at seg/, which evacuation
          writes before deleting the batch; a version replaced mid-read stays readable at least 60 s after its
          replacement commits, after which its reads answer `collected` and the client re-reads the head fresh and
          restarts on the newest version
writers   a racing write to a versionless path gets path-level CAS's 409 like any write; the SDK, MCP and the sync
          engine surface it and never retry by rebasing blindly, since the loser's content would replace the
          winner's with no history to recover it from (the index's heads, which hold only what their writer wrote,
          are the one exception, 11.14)
git       git-mode refs hold no versionless version: a git commit names every blob, and exact oids (owner decision
          141) and export need every blob of every commit; a repo's git-mode refs keep their search index on its one
          ur/index file-mode ref (11.14), and large git files use 11.11's git-lfs store (v1)
root      no Merkle root: a 2 GiB file's 512 chunk locators (~23 KiB) sit in one entry version, which the statement
          signs through entry_sha256; per-frame AEAD covers ranged reads
cli       ur evs versioning on|off <path|glob>... [--ref r] writes new versions with the same content; ur evs ls -l
          shows each path's setting; ur evs log marks replaced versionless versions `collected`; ur status reports
          each repo's versionless bytes, its search index's bytes apart from content (§20.7; D-QUOTA-10) and the
          versioned paths whose history holds most of its storage; ur history drop|drops|cancel (below)
```

This is Perforce's rule, applied per version: each version's own setting says whether it is kept once replaced, so no later write destroys history written under the keep-forever default.

**Dropped history (owner decisions 173, 183, 184).** A repo admin may drop a path's history on a file-mode ref: content that only its earlier versions name goes, and every statement, hash and the head stay. Format 2 (v1) carries it.

```text
action    a DROP push (flags 256) on the path's ref carries EvsDropHistory (11.6): per lineage of the path's token
          paths across epochs, its versions below through_version, by entry hash; not_before_ms is time_ms + 7
          days, or time_ms with now, as RepoDelete's (owner decision 183); one repo admin signs it, in an owner-bound
          repo only a consented, not-read-only device of its owner (owner decision 126), never MCP (§16.6); any repo
          admin (owner-bound: such a device of the owner) cancels it by a DROP with action 2 committed before
          not_before_ms less 60 s by evs's clock; a lock standing when its job starts voids it (§8.8); 11.13's job
          deletes nothing before not_before_ms + 25 min, and marks only once evacuation's horizon has passed the
          drop's commit by 2 min, so a now drop's deletions start about 25 to 26 h after it (owner decision 204)
rule      once it executes: kind-1 segments and slots that only listed versions name, on any ref and path, are
          deleted, each once over 25 h old; listed versions' statements, window entries, log pages, chain values,
          times, signers and entry hashes stay for the ref's life, so history verifies, and their entry versions
          stay where their chains name no inline record; ids a live version (11.13) names (a rename, a copy on
          another ref, a revert, the kept head's chunks) stay, kind-5 segments stay the purge's (I-EVS-9), and the
          pushes' sealed metadata stays; inline records in batches, parcels and packs, and packed segments, stay
          unserved until v1's compaction, though deleting a slot makes slot-keyed inline content unreadable at
          once; the DROP's index rewrites remove listed versions' postings (11.14); devices delete their copies
boundary  1 written: the DROP writes through_version, the path's next version, with the head's plaintext, mode and
          git oid: up to 8 MiB as one checkpoint under a fresh object key (an upload, or inline when it pads to at
          most 16 KiB; a new slot in slot-keyed repos), above that the head's chunk set cited as it stands; evs
          checks one locator naming an upload or inline record of this push, or chunk locators each an upload of
          this push or a kind-1 locator its base names, all but the last a whole 4 MiB chunk, and versioning 0;
          readers check record kinds, oid and mode; 2 removed: through_version is the path's standing removal,
          which stays, nothing is written, and a re-creation continues from it (owner decision 148)
why       a diff chain's checkpoint and early diffs are older versions' content, so a head still citing them would
          keep listed versions reconstructable; the fresh checkpoint leaves those records named only by listed
          versions, and chunk records hold only the head's bytes
not       no boundary below the head: a drop keeps one version's content, and nothing keeps the newest n (owner
          decision 165)
fence     from its commit, 5h refuses (409 DROPPED) as a base, deleted path or reuse source any version a DROP
          lists: a window version a DROP in the window lists (window bit 5), or one below its entry's drop mark
          (index entries, below); a seal reruns this against the heads it rereads; a cancel lifts nothing, so a
          later copy re-uploads
states    drop_pending: a listed version before not_before_ms by the reader's clock, with no cancel seen and evs
          not reporting the drop refused: readable, shown "drop pending until <time>"; dropped: after
          not_before_ms or at any 404 of its content, unless a committed cancel names the drop or evs reports it
          refused: nothing fetched or shown, history keeping its version, time, signer, entry hash and, where
          served, padded size; no alarm for a listed version, while a 404 on a version no live drop lists alarms
          as a missing segment does; a DROP failing a reader's checks (its signer's role at its auth pin, for a
          drop no lock there (§8.8), drop_sha256 and listed_sha256, each lineage entry the path's token path in
          its epoch, the boundary, and, replaying, the listed set equal to the lineage's versions below
          through_version) raises SidecarEvent history_drop in state invalid, naming the signer (§5.4), and drops
          nothing for that reader; a replaced versionless version in range stays collected; D-TEST-18's observe
          mode changes only whether the server deletes
holds     a hold never refuses the DROP push; its deletions wait while a hold covers the repo, and the drop reads,
          lists and bills as finished (owner decision 184; 11.13)
refused   409 DROP_KIND in config and mailcfg repos; REF_MODE on git-mode refs, overlays included, and creates-only
          refs; DROP_PATH for ur/index, ur/lfs, .ur-index/ and directory paths; VERSIONING for a versionless head, a
          locked repo (a drop, never a cancel), or a format-1 repo outside §19.11's format2 gate; DROP_CONSENT for
          an owner-bound repo's other signers; DROP_BOUNDARY for a written version that is not the path's next,
          versioning 0 and self-contained, or a removed one that is not the standing removal; DROP_LIST for a list
          whose count, order or repeats are wrong, past 2^20, or, written, lacking the base step 4 read; DROP_STATE
          for a cancel of no pending drop on this ref, or within 60 s of its not_before_ms; 403 below admin scope;
          429 past evs_drops_per_day (§20.4), which counts drops (EvsDropHistory action 1) only: a cancel never
          counts and is never refused by it, so one admin's drops cannot block another's cancel (owner decision 183;
          D-QUOTA-12); QuotaRefusal at the limit when the kept checkpoint needs an upload
cli       ur history drop <repo>:<path>... [--ref r] [--follow] [--recursive] [--now] [--dry-run] [--confirm
          <path>] [--detach | --resume <preview_id>] [--json] files the mandatory server dry run (11.13), stops on a
          list mismatch, prints what frees and what stays, then asks for the typed path (and the word now with
          --now); --follow adds rename ancestors and --recursive a directory's files, each a lineage in one push;
          ur history drops [<repo>] lists drops and their states; ur history cancel <repo> <drop_id>; the command
          that files a repo lock (§8.8's RepoVersioning) lists the repo's pending drops and offers to cancel each,
          since the lock voids them at their start (11.13); ur evs log marks each listed version drop pending or
          dropped
```

**Index entries** cache each path's committed versions, folded from committed pushes; push records hold every one:

```text
version   an EvsEntryVersion (11.6): a file's sealed fields, its chain (at most N+1 locators, inline when it pads to
          <= 16 KiB) and slot ids; a directory's names
holds     only committed versions, written by folds: per file up to four folded EvsEntryVersions with their push id
          and commit version u, the newest with its inline records and older ones with inline records elided (evs
          restores them from the push record before serving the signed bytes); per directory one name table, as of
          the newest delta applied; per removed path its marker (removal, below); per dropped path its drop mark
          {drop_id, through_version}; a fold never drops the newest folded version, and drops older ones only for
          newer
newest    a path's newest committed version at a head H is the newer of its entry's newest folded version, a marker's
          removal included, and the newest version after h that changes the path or a prefix holding it (the digest
          first, then the statement's change list), h being the folded_through of a head evs read before the entry: a
          fold's PUTs precede the commit that raises folded_through over them, so the entry holds every version
          through h; H's window must hold every version after h, else evs reads the entry again after H, and a folded
          version committed after H's v sends evs to a newer head; head reads, listings and 11.8's path-level CAS,
          reruns included, all use this rule
versions  a write's version is base_entry_version + 1; a creation's (base_entry_version 0, naming the path absent,
          never written or removed) is max(b, m) + 1, m the version of the newest removal its marker or the window
          holds, else b, and b its push's effective base version: its base_version, plus, on an overlay, the base
          versions along its chain of EvsOverlay bases, which evs reads at the ref's creation and caches, so a
          path's versions never fall below any it held on a base ref; a removal is one of the path's versions, one
          past its last, which its marker keeps (owner decision 148); evs (5g, 409 for any other version) and
          replaying readers (alarming) check both rules, so no version exceeds the effective ref version it commits
          at; an honest creation's base shows the path absent, so every earlier version is at most b, and a removal
          after b is in the window (b >= v - 63): a path's versions never restart, whether its marker stands, was
          collected or was dropped by a path-epoch copy, and a push based on one from before a removal fails 5g; a
          client refused creating (409) reads the removal (11.9) and retries
fold      for a ref's window versions (f, u]: read their statements and entry versions (the process's cache, else
          batch ranges); per changed file path, its newest version or removal (its own or a prefix's) in (f, u],
          skipped when a window version after u changes that file again; per changed directory, every delta in (f, u]
          past the version its entry holds, applied in version order, since a newer delta never replaces an older
          one; GET each entry (404: create it, once a cluster read of the ref's head in this fold succeeds, 11.13's
          skip rule), merge (a file's folded versions, the newest four kept; a creation, or a DROP's written version,
          replaces what the entry held, carrying nothing, the DROP's setting the entry's drop mark {drop_id,
          through_version}), PUT If-Match (If-None-Match to create), on 412 read again and merge; an entry that
          already holds a version is not written, and a marker takes only a newer one (collect, below); folds are
          idempotent, and any evs process may run one
stale     each fold and copy write carries a store deadline 15 s after it issued the cluster read of the ref's head
          it relies on (§19.6's settle rule: past it the store neither takes the write nor begins a drive commit of
          it, and one it began lands before the next request on its key or never), a page-out's fold reading the
          head from the cluster when step 4's came from the cache; a fold relies only on a read whose
          folded_through is at most its f, stopping at one above it (another folded its range), and a copy only on
          one still listing its sources, so no write planned before the horizon rose or the sources dropped is
          taken past 15 s, or lands after a later request on its key
when      (1) after a commit that leaves 96 or more versions unfolded, the committing process folds the oldest 64,
          off the reply path, at most once per ref per 10 s; (2) 10 min after a ref's last commit, the process that
          made it folds the rest; (3) a commit that pages versions out of the window first folds any of them still
          unfolded (11.8 step 6); (4) a PATH_EPOCH push's process first folds every unfolded version, as step 6
          does for a page-out (on a busy git-mode ref under the seal lease), and its step-7 head sets
          folded_through = v, so an idle ref whose folded_through trails v still commits its epoch
horizon   folded_through: every file change at or below it, a removal as its marker, is in its path's entry or
          replaced by a newer window version of that file, and every directory delta at or below it is applied to its
          name table; it rises only with a commit by the process that folded, so folds add no head write, and a stale
          value costs readers only statement reads
lag       if a page-out's fold cannot finish within 11.8's 5 s rule, the commit proceeds without paging, the window
          growing to at most 255 versions; past that, pushes to the ref get 429 FOLD_BEHIND with retry_after_ms
epochs    a fold writes the current path epoch's entries, each, while the head lists sources, with its state in its
          object metadata: carried, as the copy writes, when the change's source paths (its push record) name a
          source still holding the path, keeping that source's folded versions and drop mark and tagging its
          untagged rows with its epoch, rows already carried keeping theirs until the copy translates them (11.6);
          fresh when the path is new to the current epoch, a re-creation replacing a marker and carrying nothing;
          or removed:
removal   a fold never deletes an entry (owner decision 148): a removal at r gives the path and, for a directory,
          every current-epoch entry below it (LIST) a marker {removing push id, r, the path's version (versions,
          above), and, for a versionless file the removing push did not list, its kind-5 segment and slot ids, with
          an alarm}, in version order with the versions below it, by PUT If-Match on the entry it read (If-None-Match
          on a 404) only while that entry holds a version older than r, a marker staying as it is; on 412 it reads
          again; the path's own marker precedes that LIST, so while sources stand no read or copy falls back to a
          source at or below it (11.6), and no repeated, queued or late removal fold writes over an entry a later
          fold wrote, which holds a newer version
collect   markers whose removal r the horizon has passed by a base range (folded_through >= r + 64, so no push based
          before it can commit, 11.8) are collected while the head lists no source, by taskworker's nightly pass from
          the removals the ref's statements name after head.collect.done (a removed directory's markers by LIST), in
          windows: one head CAS raising only the fence sets collect {through: the window's newest r, until_ms: 30 s
          on}, opening only 150 ms after the last window lapsed by the opener's clock; 15.3 s later, every fold and
          copy write planned on an older head having landed or never landing (stale, above: a 15 s deadline the
          store host checks by its own clock, plus up to 50 ms of slew in each of the folder's, the opener's, the
          collector's and that host's clocks, which §19.6 holds within 50 ms of UTC), it GETs each marker of a
          removal at or below through, deletes the kind-5 segments and slot it carries that no hold keeps (a 404 is
          done), and DELETEs the marker once, unconditionally (11.3), unless a hold kept part of what it carries,
          which leaves the marker for a window after the hold ends, each DELETE carrying a deadline 50 ms before
          until_ms by its own clock, or cancelled at once if that clock turns unsure, so the store takes none after
          until_ms in UTC, and once all have answered sets done to through, or below the oldest marker it left, by
          another such CAS; a fold that read a head whose until_ms is ahead writes over no such marker until 150 ms
          past it by its own clock, at least 100 ms past in UTC, nor does one on a process whose clock is unsure
          (11.8's fence row), and a 404 needs no wait, a window deleting a key once; each margin needs only those
          clocks and §19.6's deadline and settle rules, never a measured lag, and on a cluster whose build has not
          passed §22.9's settle cases (FS-114) taskworker opens no window, markers staying
directory a push's directory change is a delta {names added, child tokens removed} that merges without a path-level
          CAS, since each child's own path is checked, except that a child directory D is checked both ways: a push
          removing D gets 409 with D's path if a delta to D committed after its base, and a push changing D gets
          that 409 if D's removal committed after its base; a fold applies committed deltas to the name table {child
          token, kind, sealed name}; at most 4,096 children and 448 KiB of name table (its EvsName rows: tokens,
          kinds, sealed names with nonce and tag; a carried row counted at its untagged size, so the bound holds
          through a copy, its epoch adding 3-5 B, under 466 KiB at the bound, within idx/'s 512 KiB), checked in
          step 5g against the folded table plus the deltas after h (newest, above; 409 DIRECTORY_FULL), which is
          v0's git limit; the bytes bind first, at 3,584 children whose names are under 64 B; `layout` reserves
          paging; §15 and §16 shard by sequence and size directories by these bytes
name      sealed alone: the name, then 0x80 and zeros to the next multiple of 64 B, under a random 24 B nonce with
          a 16 B tag; AAD repo_id || path epoch || parent and child tokens; with its token, kind and framing, an
          untagged row takes 128 B for a name under 64 B, 194 B under 128 B, and 64 B more per further 64 B
repair    an entry that lacks its path's newest committed version older than the window is refolded from that push's
          record; a version a newer one replaced is reached by the history walk, a dropped one as `dropped` (11.9);
          push records, log pages, packs and parcels are the record, idx/ the cache
keys      idx/<repo>/<ref>/<p>/<t1>/.../<tn>.e: the entry of path t1..tn sits beside the directory t1/.../tn/ that
          holds its children's keys, so no key prefixes another (11.3), and a file entry takes one directory and one
          file on each drive instead of two directories and a file; LIST by prefix still lists a subtree
```

Readers check each name against its token, so evs folds committed directory deltas itself, and pushes adding different files to one directory never conflict on a file-mode ref.

**Overlays.** Only git-mode refs take overlays: a ref created from one (an agent branch) records its base (ref, version) and writes only the paths it changes. A path it has not changed has the base ref's version at that base version, which its writers (the local tier) and its readers settle and check by replaying both refs; head mode reads no overlay (§18.5's `ReadHead` names no ref). So 5g checks an overlay only on paths its own entries or window hold, TIP settling the rest, a chain citing the base's segments names that base version as a `reuse` source (5h), and 11.9 answers `base` {ref, version} for any other path; §22 covers overlays by FS rows, not the model.

**Reconstruction:** check the entry version against its statement (11.9), read the chain, unwrap its keys, apply the deltas and check the blob oid. Delta bases over 1 MiB spill to the sealed local store.

### 11.8 The evs service: objects, push, commit, reads

**Objects.** `ServiceHost.Blobs` (§4) gives stateless evs an unversioned bucket on each cluster, so a DELETE or overwrite keeps no prior version (owner decision 90):

```text
metadata cluster (NVMe)                    holds                                            written             size       lifetime
place/<repo_id>                            the repo's metadata cluster (placement, below);  If-None-Match       <= 256 B   the repo and its
                                           first cluster only                                                              tombstone
repo/<repo>                                kind, owner_member_id, state and deletion_id     If-Match            <= 4 KiB   the repo; a shredded
                                           (11.12), object format, sealed name                                           tombstone stays
head/<repo>/<ref>                          the commit point: fields, 64-byte window         If-Match; created   <= 9 KiB   the ref; DELETE leaves
                                           entries                                          If-None-Match       (17 while  a tombstone head
                                                                                                                folds lag)
log/<repo>/<ref>/<n>                       versions 64n..64n+63: their window entries and   If-None-Match;      <= 70 KiB  history; packed after
                                           Signed EvsPush, C_{64n-1} and C_{64n+63}          equal bytes on 412             24 h (11.13)
pb/<yyyymmddhh>/<mm>/<instance>-<seq>      a batch: push, part, seal and reseed records     If-None-Match and   <= 256 KiB 25-26 h, then evacuated
                                           of one evs process (below), with their staged    its checksum        (one record: 1 MiB) whole (11.13)
                                           versionless segments
idx/<repo>/<ref>/<p>/<t1>/.../<tn>.e       index entry in path epoch p: folded committed    If-Match; created   <= 512 KiB the path; a
                                           versions, or a removal's marker, its state in    If-None-Match                  marker until
                                           object metadata (11.7)                                                          collected (11.7)
slot/<repo>/<slot_id>                      up to 64 sealed object keys: under fek_g, or     If-None-Match;      <= 8 KiB   until erased, consumed,
                                           HPKE to the drop key for deposits                rewritten If-Match             shredded or dropped
                                                                                                                           (11.13); a dead
                                                                                                                           push's, <= ~26 h; a
                                                                                                                           versionless path's
                                                                                                                           until a minute after
                                                                                                                           no retained version
                                                                                                                           names it (11.13)
hp/<repo>/<parcel_id>                      a small repo's records older than 24 h (11.13)   If-None-Match       <= 256 KiB until packed, <= 7 d
pmap/<repo>/<ref>/<p>/<map>/<part>/_       a Signed EvsPathMap part (11.6); <map> is its    If-None-Match       <= 8 MiB   the committed map:
                                           map's path_map_sha256                                                           the ref's history;
                                                                                                                           others go (11.6)
pidx/<repo>/<ref>/<v_first>-<id>           a pack's records and log pages, or a parcel's    If-None-Match       <= 1 MiB   as its pack or parcel
                                           records (none of its log pages), and the
                                           segments they introduce; <id> is that
                                           container's (11.13)
spidx/<repo>/<n>/_                         reserved (11.13): offsets of segments in a pack  If-None-Match       <= 1 MiB   as its pack
hold/<network_id>/<case_id>/_              §21.9's preservation hold, written by api;       api                 <= 1 KiB   its kind's (§21.9):
                                           first cluster only                                                              90 d, renewable
                                                                                                                           once, or 1 year for
                                                                                                                           report_2258a
drops/<repo>/_                             the repo's drop table, running drop job and dry  If-Match; created   <= 64 KiB  the repo; an entry
                                           runs (11.13)                                     If-None-Match                  30 d after its drop
                                                                                                                           or dry run ends
segment cluster (HDD)
seg/<repo>/<segment_id>                    one segment; segment_id = SHA-256 of its bytes   If-None-Match and   <= 8 MiB   while a retained
                                                                                            its checksum                   version names it; a
                                                                                                                           kind-5 segment until a
                                                                                                                           minute after the push
                                                                                                                           replacing its version
                                                                                                                           commits; or until an
                                                                                                                           executed drop's job
                                                                                                                           deletes it (11.13)
pack/<repo>/<pack_id>                      records and log pages older than 24 h, >= 256    If-None-Match and   >= 256 KiB history
                                           KiB or 7 d old (owner decision 136); reserved:   its checksum        or 7 d
                                           segments
dropscan/<repo>/<id>/<f>                   a drop job's or dry run's file: snap, cand,      If-None-Match                  30 d after its job
                                           mark, del or held (11.13)                                                       or dry run ends
Redis (soft state, owner decision 136)     {evsq_} push sequence, {evsl_} leases, {evsh_} head cache, {evsd_} drop hints
                                           (11.9, 11.10, 11.13)
C_0 = SHA-256("UR evs 1.0 ref" || repo_id || ref_id);  C_v = SHA-256(C_{v-1} || push_id_v || SHA-256(Signed EvsPush_v))
```

```text
decides   head/ alone: a ref's state changes only by a head If-Match (If-None-Match to create)
immutable place/ log/ pb/ hp/ pmap/ pidx/ spidx/ seg/ pack/ dropscan/: created once; a 412 on equal bytes is
          success; never overwritten; deleted only whole, by evacuation, packing, orphan GC, consumption, retention,
          shred, a drop's job for kind-1 seg/ objects and its own dropscan/ files (11.13) or, for kind-5 seg/
          objects, the versionless purge (11.13) or a marker's collection (11.7), and place/ never in v0
cache     idx/: If-Match (owner decision 2), written only by folds of committed versions and removals (markers), each
          also in its push record, and deleted only by a copy (its sources), 11.7's collection or a shred; none
          decides an outcome
fences    repo/ (lifecycle CAS, 11.12), slot/ (created If-None-Match, equal bytes on 412 success, from M2 only on an
          object under 23 h old, step 6; rewritten only to drop erased keys; a versionless path's deleted by the
          purge or a marker's collection, 11.7, 11.13; deleted by a drop's job when only listed versions name it),
          drops/ (the drop job's state, If-Match, 11.13)
keys      no key prefixes another (11.3): entries end in .e beside their children's directory; map, spidx, hold and
          drops keys end in /_, pidx/ keys under a ref have fixed lengths, and no dropscan/ name prefixes another
```

**Placement (owner decision 145).** The metadata tier grows only by whole clusters, never MinIO pools, whose PUTs can pass a precondition in a pool the key is not in (11.3):

```text
place     PUT /evs/v1/repos/<id> first creates place/<repo_id> {cluster id, creator sidecar_id} on the first
          metadata cluster (If-None-Match), naming the cluster that takes new repos (§19.9); on 412 it reads the
          object: the same creator continues on the cluster it names, any other gets 409; only then does it write
          repo/<id> there, so of two racing creates exactly one places the repo, and a retry never moves it
resolve   evs and gkm read a repo's place/ once and cache it for the process's life, since it never changes (a 404
          for 5 s); every metadata object of the repo and its gkm group, batch records included, lives on that
          cluster, so each ref keeps one commit point
first     the first cluster also holds §7's proj/, projrows/ and rev/, §10.6's per-sidecar gkm/ objects (KeyPackages
          and their claims, ReaderKeys, Welcome pointers) and §21's hold/
form      each cluster is one homogeneous 8-drive set at EC:4 in one pool (owner decisions 116, 139); a repo's
          cluster changes only with a later move tool that keeps one commit point
```

**Authorization.** The daemon's §7 service token (aud `evs`, scope `repo:<id>:deposit|r|rw|admin`, 15 min) never leaves it (I-7). evs verifies it offline, checks §7.8's `rev/` objects for its three subjects, honors a scope only while its newest verified state agrees (D-ACL-21), read from §7.9's verified `{acl_}e` cache, which only api writes, else from `proj/`, and matches `ur_sidecar_id` to §5's binding; `admin` covers FORCE, DELETE, BASE, ERASE, CUT, CLOSURE and its uploads (in the team directory too, whose `admin` §7.8 mints only to its consented, not-read-only admins; 11.12), DROP pushes, their cancels and dry runs, re-seeding, deletion and restore, and in §19.10's re-seed mode only `/reseed` (§7.8). evs-7 is evs's 7-day service log (§19.8).

**The head** (D-EVS-29) is server-internal, never a client wire format:

```proto
message EvsHead {                       // head/<repo>/<ref>; written only by If-Match (create: If-None-Match)
  uint64 version = 1; bytes chain = 2;  // v, C_v
  bytes push_id = 3;                    // the push committed at v
  uint32 ref_kind = 4; uint32 ref_mode = 5; bytes owner_sidecar_id = 6; bytes sealed_ref_name = 7;
  EvsOverlay base = 8;                  // an overlay's (ref_id, version)
  AuthPin auth = 9; reserved 10;        // authorization pin (n, A_n), §7.9: never falls (below)
  bytes group_id = 11; uint64 generation = 12; bytes generation_commitment = 13;  // generation pin: never falls
  EvsPathEpoch path_epoch = 14;         // 11.6
  bytes window = 15;                    // 64-byte EvsWindowEntry records, versions v-w+1..v, oldest first;
                                        // w in 64..127, at most 255 while folds lag (11.7)
  uint32 fence = 16;                    // raised by every write that changes no version (below, 11.13)
  EvsSealLease lease = 17;              // git mode: {push_id, until_ms}, or empty
  bool deleted = 18;                    // DELETE committed; a later push to the name continues the versions
  bytes window_base_chain = 19;         // C at version v-w, so the window's chain is computable forward
  uint64 folded_through = 20;           // 11.7's horizon: file changes folded or replaced, directory deltas applied
  int64 written_ms = 21;                // evs's clock at this head's write
  int64 fence_ms = 22;                  // its writer's clock at the newest evacuation fence (outcomes)
  EvsCollect collect = 23;              // 11.7's marker collection: done, through and a window's until_ms
  uint64 index_epoch = 24;              // on a ref holding an index: its newest CUT's version, else 0 (11.12);
                                        // never falls; a re-seed sets it from the newest CUT it replays
  bytes refused = 25;                   // 16-byte EvsRefusal records, at most 8, oldest first (outcomes)
  int64 refused_ms = 26;                // its writer's clock at the newest refusal fence
}
message EvsOverlay { bytes ref_id = 1; uint64 version = 2; }
message EvsSealLease { bytes push_id = 1; int64 until_ms = 2; }
message EvsPathEpoch {
  uint64 current = 1;                   // p: the generation whose RK derives K_path
  repeated EvsEpochSource sources = 2;  // at most 3 older epochs still holding entries, newest first
  uint64 due_generation = 3;            // a generation that requires a new epoch, or 0
  bool due_blocks_creation = 4; int64 due_by_ms = 5;
  int64 block_until_ms = 6;             // a mapper's creation block (11.6), or 0
}
message EvsEpochSource { uint64 epoch = 1; bytes map_sha256 = 2; }
message EvsCollect { uint64 done = 1; uint64 through = 2; int64 until_ms = 3; }
```

```text
entry     EvsWindowEntry, 64 B, fixed layout: push_id (16) | statement_sha256[0:16] (16) | place (20) | paths_digest
          (8) | flags (4: bit 0 the push creates a path; bit 1 its change list is in the payload under changes_root;
          bit 2 PATH_EPOCH; bit 3 FORCE, DELETE, BASE or ERASE; bit 4 it replaces or removes a versionless version,
          its record listing the purge's candidates (11.13); bit 5 a DROP push (11.7); bits 16-31 its change count,
          saturating)
refusal   EvsRefusal, 16 B, fixed layout: push_id[0:8] (8) | statement_sha256[0:2] (2) | code (2: the refusal's
          status and reason, from evs's fixed code table) | until_s (4: UTC seconds, rounded up); only outcomes'
          refuse row adds one, and any head write drops each whose until_s its writer's clock has passed, but
          one by a process whose clock §19.6 finds unknown or over 50 ms off drops none
digest    a 64-bit Bloom filter, k = 2, over each changed token path and, when the change list is not inline, each
          covering prefix: indexes from SHA-256("UR evs digest" || token path)[0:4] mod 64 and [4:8] mod 64; evs
          queries a path and each of its prefixes: a match only sends it to the statement's change list, and a miss on
          all of them proves the push changed neither the path nor a prefix holding it
size      at most ~0.85 KiB of fields, 127 entries and 8 refusal records: ~8.9 KiB, typically ~7 KiB with no
          record, so its xl.meta is one 4 KiB block (or three 1 KiB blocks) on each drive; a log page holds its 64
          versions' entries and Signed EvsPush statements and C at both ends, at most ~70 KiB
fill      at step 7 evs appends P's entry from the statement it checked and the place its batch write returned;
          readers never parse the head object (they get 11.9's head summary)
etag      every head write raises the version or, for a write that commits nothing (a refusal record, a fence, a
          seal lease, a creation block, dropping drained path-epoch sources, a collection window), the fence, so an
          ETag never repeats; only evacuation's fences also set fence_ms, and a refusal fence sets refused_ms
          (the outcome rules below)
trust     a wrong place, hash or digest can only produce a missing or mismatched statement, which breaks the chain
          and alarms; the digest cannot hide a change, because readers check every returned statement's change list
```

**Batches (D-EVS-30):**

```text
key       pb/<yyyymmddhh>/<mm>/<instance>-<seq>: the UTC hour and minute the batch was opened, the evs process's
          random 32-bit id (8 hex) and its counter within that minute (8 hex)
bytes     header {"URpb", format 1, or 2 for a batch holding staged segments or purge candidates, instance, minute,
          seq, created_ms, record count} | records | index | trailer {index offset, SHA-256 of all bytes before it};
          at most 256 KiB, or one record of up to 1 MiB; an evacuator that does not know a batch's format leaves it,
          alarming
record    {type, repo_id, ref_id, push_id, signer_sidecar_id, time_ms, length, body}; push: the Signed EvsPush and its
          payload (11.6); part: the Signed EvsPush, EvsPushPart k, its receipts and the head version evs checked it
          at; seal: the Signed EvsPush, its parts' places and each part's changes_root and first token path;
          reseed: a re-seeded push (11.13); a push's or part's record carries its staged segments after its
          payload, and a push, part or seal record replacing versionless versions lists the purge's candidates
          (11.13)
place     an EvsPlace (11.6), 20 B: where a record's bytes are
open      each evs process holds one open batch per metadata cluster, for repos placed there; a request's record
          joins it at step 6 (a part or seal at its own step), and the request waits for that batch's write
flush     a process writes an open batch when it reaches 256 KiB, when its oldest record has waited 20 ms, or at once
          when it has no batch write in flight there and took fewer than 50 records in the last second; at most two
          batch writes in flight per process and cluster; a record over 256 KiB is a batch alone
write     PUT If-None-Match, the SHA-256 as x-amz-checksum-sha256; a 412 reads the key back: equal bytes are success,
          others a fault that alarms; an unknown outcome GETs the key: equal bytes written, 404 written again with the
          same bytes; with the store unreachable, every waiting request gets 503, retryable, since nothing it carried
          reached a head
bind      step 7 adds P's window entry with the place, so a record is committed only at the place its version's entry
          (window or log page) names; another copy of P (a retry on another process, a part posted twice) is dead
          weight that evacuation drops (11.13)
read      evs reads a record by range at its place; on 404 (evacuated) it finds the version in pidx/ (11.13); readers
          verify what evs returns as before: statements by signature and chain, payloads by the statement's hashes
cache     each process keeps the records it wrote or read by place; they never change
latency   under light load a push's record is written at once, in step 6's round: no added round; under load it
          waits at most 20 ms, ~10 ms on average
```

**Push (owner decision 2):**

```text
client 1  choose push_id P; build the statement on the head it read (v = b, C_b)
       2  PUT each new segment (chains over 16 KiB; at most 4 at once; a versionless record padding to at most 16 KiB
          is staged in the payload instead, 11.7) with ?push=P: evs streams it with If-None-Match and its id as
          x-amz-checksum-sha256 and answers 200 {receipt} (11.13's uploads); the client posts only after every 200
       3  POST .../push {Signed EvsPush, payload, receipts}
evs    4  the head first: its verified cache entry (11.9) when that version is at least b, else a cluster GET, a
          round (any refusal rests on a cluster read, outcomes below), with the head of any other ref a `reuse`
          source names; then one round on the repo's cluster, after it, so that 11.7's rule combines what it reads
          with that head's folded_through: repo/<repo> (cached at most 5 s), every changed entry (while the head
          lists sources, by 11.6's read rule, with the source copies the payload's source paths name), each `reuse`
          source (committed in its ref's entry, or, with its statement, in that ref's window) and, from the
          process's cache or batch ranges, the statement of each window version after that folded_through whose
          digest matches a changed path or a prefix holding it, and for a PATH_EPOCH, of each window version after
          its map's source that creates a path; for versions older than the window, the log pages that settle them
          (cached); the authorization state and the generation record from evs's caches (§10)
       5  checks:
          a  retry: P already committed (the head window, or the log pages of (b, b+64]) -> 200 {its version}; a
             committed P with another statement hash -> 409 PUSH_ID_REUSED; P in the head's refusal records ->
             their status and code with recorded: true (outcomes' refuse row), and 409 PUSH_ID_REUSED when its
             record's statement prefix differs
          b  signature by the token's sidecar and client; time_ms within 10 min (parts and seal: 30 min), a time_ms
             further ahead of evs's clock getting 429 TIME_AHEAD with retry_after_ms, which refuses nothing, so a
             refusal record lasts at most twice that bound and 1 s; statement <= 1 KiB; payload hashes (11.6)
          c  scope, ref kind and ref mode rules (the refs table below), 11.7's versioning refusals and lock, and the
             repo's format (11.6), else 409 VERSIONING; a DROP's kind, path, consent and cancel rules and, for a
             drop but never a cancel, its network's evs_drops_per_day (11.7's refused row); repo/ state active;
             11.13's storage limit
          d  pins (the gate below): the auth pin (n, A_n), generation and C_g satisfy §10.6's gate predicate against
             the newest authorization state evs holds, and neither pin is below the head's; index epoch: a CUT, and
             a push other than a CLOSURE that creates or replaces an entry version with versioning 2 (an index
             file, 11.14), names index_epoch equal to the head's, else 409 INDEX_EPOCH (11.12's cut row)
          e  path epoch: the head's current one; PATH_EPOCH: a newer generation, its map's parts present and under
             24 h old, its source binding valid, its tail covering every later creation (else 409 with the paths),
             nothing unfolded after its process's fold (11.6, 11.7 (4)); a creation while due_blocks_creation or
             before block_until_ms -> 412 PATH_EPOCH_DUE
          f  base: git mode b = v (TIP) and no live lease of another push; file mode b >= v - 63, so the push lands
             within (b, b+64], and C_b matches the history
          g  path-level CAS on each changed file path: its newest committed version (11.7's rule: the entry, or a
             newer version after the folded_through of the head read before it) equals base_entry_version, 0 naming
             it absent, each new version following 11.7's versions rule (a creation's max(b, m) + 1, b the effective
             base version, an overlay's chain included; else 409), on a rerun
             too; directory deltas merge, but for 11.7's two-way check of a removed directory and its bound (409
             DIRECTORY_FULL); git mode: implied by f, still checked on paths the ref holds a version of (an overlay's
             others rest on TIP, 11.7)
          h  new segments: each receipt valid, for this repo and this signer, under 24 h old; every other segment a
             new version names appears in a committed version evs read in step 4 (the path's base, a path the push
             deletes, or a `reuse` source); evs does not HEAD segments, and a locator to an upload that never
             completed fails only that file's reads, which readers alarm on; kind-5 locators only in versionless
             versions, each naming a staged segment of this push, an upload of this push whose receipt is marked
             versionless, or an unstaged kind-5 locator of its path's base version or of a path this push removes,
             never a reuse source's; a versionless version's kind-1 locators only from its path's base version, and
             no kind-2 locator; no slot a versionless version names named by another path's version; else 409
             VERSIONING; no base, deleted path or reuse source a DROP lists (11.7's fence; 409 DROPPED); from M2
             (11.22), every slot a new version names introduced by this push or named by a version step 4 read; a
             DROP's written boundary and its lists' base (409 DROP_BOUNDARY, DROP_LIST; 11.7); then the push's purge
             candidates (11.13)
       6  one round: append P's record to the process's open batch and await its write (batches, above); if the window
          would pass 127 versions, fold any of its oldest 64 still unfolded (If-Match) and PUT log/<n> for them
          (If-None-Match; equal bytes on 412), or, if that cannot finish within the 5 s rule, page nothing (up to
          255 versions; then 429 FOLD_BEHIND); then, for a push with new slots, one more round PUTs each slot
          (If-None-Match; equal bytes on 412 are success, from M2 (11.22) only if a HEAD shows that object under
          23 h old, else 409 SLOT_STALE, as a re-upload gets SEGMENT_STALE; unequal ones send evs to a cluster read
          of the head, where 5a finds P committed if an ERASE rewrote it, else alarm), so a record names every slot
          written
       7  PUT head {v+1, C_{v+1}, P, the push's pins, window + P's entry (P, statement hash, place, digest, flags)
          - any paged out, window_base_chain, folded_through, written_ms, lease cleared, and for a CUT index_epoch
          v+1} If-Match step 4's ETag: the commit point; issued only within 5 s of step 4's reads, else steps 4
          and 5 (a-h) run again first
       8  outcome (below): 200 -> reply 200 {v+1}; then the push sequence and hints (11.10), usage events (11.13),
          the head cache entry (11.9), a DROP's or cancel's append to drops/<repo>/_ (If-Match, retried on 412)
          and its {evsd_} hint to taskworker (11.13), the fold of the oldest 64 if 96 are unfolded, and, 60 s
          later, the purge of its candidates (11.13), off the reply path
parts     a push over 1 MiB or 1,024 entry writes goes in n <= 1,024 parts within both bounds; the client signs the
          statement with part_count, parts_sha256 and changes_root, then POSTs .../push/P/<k> {Signed EvsPush,
          EvsPushPart k, receipts}, at most 4 at once; evs runs steps 4, 5 (a-e, g, h) for that part's entries,
          appends the part, its receipts and the head version it checked as a batch record (a batch alone above
          256 KiB) and answers 200 {place}; a part posted twice is two records, and the seal names one; git mode
          first takes the seal lease
lease     git mode: POST .../push/P/lease {ref_id, base_version, ms <= 120,000} (rw), after the push's segments and
          before its parts: it reads the head as step 4 does, and one head CAS sets lease {P, until} and raises the
          fence without changing the version, only if v = base_version and no other push's lease is live (P's own
          -> 200; P in the head's refusal records -> their refusal, as 5a); on 412 it rereads the head from the
          cluster: the version still base_version with no other live lease -> the CAS again on the reread ETag, at
          most 8 times, then 429 BUSY; another push's live lease -> 429 with retry_after_ms; another version, read
          from the cluster -> 409 non-fast-forward; other pushes to the ref get 429 with retry_after_ms until the
          lease ends or the seal clears it; reads never wait; an expired lease is ignored, and the seal still
          commits only by TIP and the head If-Match, so a stalled holder cannot commit over a newer tip
seal      POST .../push {Signed EvsPush, the parts' places} within 30 min of time_ms: evs reads the parts at their
          places and, in that round, the head from the cluster, since a git-mode push's own lease left the cached
          ETag stale (one part missing -> 409 PARTS_MISSING, which records and refuses nothing: the client posts
          that part again and seals P again), checks them against
          parts_sha256 and runs step 5 (a-f, h's age check on every part's receipts, and h's DROPPED check of each
          part's bases and sources against their refs' heads, reread from the cluster) against that head; in file
          mode, if the head moved after the earliest version a part was checked at, it reruns 5g's rules for each
          part against every statement after the version that part was checked at (a statement's prefixes sending
          it to that push's change list): a later change to one of its file paths refuses it (409 with the paths),
          and directory deltas merge, except that a later removal of a directory D refuses a part changing D or a
          path below it, a later delta to D refuses one removing D, and the parts' deltas are checked against D's
          bound by 11.7's rule (409 DIRECTORY_FULL, once recorded); then step 6's record (the seal) and step 7, so
          a git seal fails 412 only on a write after its read; a failed seal leaves its parts to evacuation; an
          import past 1,024 parts splits at commit boundaries, each push carrying the EvsImport
costs     steps 4, 6 and 7 are three sequential store round trips, 40-80 ms (owner decision 2), with the head from
          the verified cache and step 4's statements in its round; an uncached head adds one, new slots one, a
          retry after a 412, of a push, seal or lease in either mode, two (its reread and new PUT; three when a
          file-mode rerun reads statements or entries again), a recorded refusal one, each part three, a seal four,
          a lease one; the batch write adds at most 20 ms under load and none when light
```

**Linearizability.** A ref's history is its head's sequence of successful If-Match PUTs, evaluated under MinIO's namespace lock with quorum reads (strictly since PR #21653) and read-after-write consistent (§22's suite checks both), and a PUT whose answer was lost, cancelled or timed out takes effect before the next request on its key or never (§19.6's settle rule, D-OPS-20), so the lock's order is the history even when answers are lost. Nothing a push writes before step 7 is visible: readers and writers use only versions whose push the head history names, at the place it names; unfolded versions are themselves in the head. A push linearizes at its step-7 PUT, where its checks hold: each reads an object that PUT's If-Match covers (head pins, path epoch, index epoch, tip, base window), a state evs read in step 4, at most 5 s before it, from a cache at most 5 s old (repo/ state; the authorization state, as fresh as §8.9 delivers it), or a receipt's age. `idx/` entries are read state outside the If-Match, sound by 11.7's rule: each was read after a head whose folded_through it is combined with, and every later version is in the window that PUT's If-Match covers; while sources stand, a path that no epoch's GET found is read again in the current epoch, which the copy writes before it deletes a source copy, and a removed or fresh prefix entry stops any fall-back to a source (11.6). File-mode pushes commit only if their paths are unchanged since their base, as in a serial order; git-mode pushes only on their tip. A refusal the head does not settle linearizes at the head CAS that records it (outcomes), after which no attempt of its push id commits.

**Outcomes (D-EVS-23):**

```text
retry id  a push id names one statement; the client retries with the same push id and statement, one attempt at a
          time, until it gets 200, 409 or 412, and the lb re-sends a POST whose upstream erred, answered 503 or sent
          nothing for 30 s to a sibling while its client waits (warp/warpctl/config.go:1317-1320), so attempts may
          overlap, and one may reach its evs handler at any time, even after another's answer reached the client;
          a committed push id returns its original version from the head window or from the log pages of
          (b, b+64], packed or not, however many commits followed, and a recorded one its refusal (refuse, below)
fence     evacuation's fences raise the head's fence and set fence_ms (GC raises none, 11.13); refusal records,
          leases, blocks, source drops and collection windows set no fence_ms and end nothing; an attempt that may
          issue step 7 (a push or seal, never a part) and reads a head whose fence_ms, from a write it did not
          make, is later than its own
          arrival less 100 ms ends with 503 {push_id, outcome: unknown} and no further step 7, so a fence ends every
          such attempt that arrived before it, whether it read the head before the fence or after, and one arriving
          after it fails the time or receipt-age check the fence waited out (Resolve, below; 11.13's orphans); the
          margin needs every clock that writes fence_ms or an arrival within 50 ms of UTC: chrony on the evs, gkm
          and taskworker hosts, alarmed past 25 ms (§19.6); an evs process whose offset is unknown or over 50 ms
          answers pushes 503 before step 4, and a taskworker in that state raises no fence and GC deletes nothing,
          so a pending record or an unadopted segment simply stays
refuse    every refusal rests on a head read from the cluster (a cached step 4 that would refuse reruns with a GET);
          one the head or a terminal repo/ state settles for good (5a, 5c's shredding and ref rules and DROP_KIND,
          5d's pins and an index_epoch below the head's, 5e's epoch and tail, 5f, 5g's path and removal checks,
          11.12's rekey rule) is final, and a part's needs nothing more, since only its push's seal commits; before
          answering any other (5b's time, 5c's scope, keying, deleted state or storage limit, DROP_PATH, DROP_CONSENT
          and DROP_STATE, 5d's predicate and an index_epoch above the head's, 5e's map parts, EPOCH_SOURCES_FULL and
          a block's PATH_EPOCH_DUE, 5g's DIRECTORY_FULL, 5h with DROPPED, DROP_BOUNDARY and DROP_LIST, step 6's
          SLOT_STALE, 11.12's NOTHING_TO_ERASE), evs records it: one head CAS, the push's refusal fence, raises the
          fence and adds {P, its statement prefix, the code, until} to the head's refusal records, until being
          time_ms plus P's bound (10 min, a seal's 30 min) and 1 s, retried after a 412 at most 8 times until it
          lands, P shows committed (-> 200) or P shows recorded (-> that refusal), else 503 {push_id, outcome:
          unknown}; then an attempt of P that read an older head fails its step 7 on the new ETag, one that reads the
          record gets it from 5a, and one that reads the head after the record lapsed fails 5b, the dropping
          writer's clock being within 50 ms of UTC, so no attempt of P, however late it reaches evs, commits after
          the answer, a stale over-limit list included; with 8 records live, or a refusal fence under 1 s old
          (refused_ms), evs answers 429 with retry_after_ms instead; a 429 refuses nothing, and the client retries P
first     a push creating its ref, whose head is absent, records a refusal in a placeholder head created
          If-None-Match at version 0 with no window, kind or mode, which reads, listings and GET .../refs treat as
          absent and the ref's first commit replaces by If-Match, as a later push continues a tombstone head's
          versions; a creating attempt then fails If-None-Match and meets the record on its reread; the
          placeholder stays, as a tombstone head does; evacuation fences a ref with no head by creating the same
          placeholder with its fence raised and fence_ms set (11.13; owner decision 203), and a creating attempt
          then fails its If-None-Match and ends at the fence
412       reread the head from the cluster; P committed -> 200; P recorded -> that refusal (5a); else, since an ETag
          never repeats, the old PUT can never apply: a fence after the attempt's arrival ends it (above); otherwise
          step 5 (b-h) reruns against the reread head, pins and path epoch included, then step 7 on its ETag: in git
          mode only while its version is still b, another push's live lease answering 429 with retry_after_ms and a
          higher version 409 non-fast-forward; in file mode at the next version, 5g keeping the folded_through its
          entries were read after (11.7); at most 8 times, then 429 BUSY with retry_after_ms, since another attempt
          of P may still land; or 409 with the conflicting paths
unknown   a timeout (evs waits at least the store's request deadline), EOF or 5xx on step 7 deletes nothing: evs
          rereads the head from the cluster (3 tries, 200 ms apart), a read §19.6's settle rule orders after the PUT,
          which has then landed or never will; P committed -> 200; P recorded -> that refusal; the ETag still the
          one step 7 named -> within 5 s of step 4's reads reissue the identical PUT, else rerun steps 4 and 5 (b-h)
          and issue step 7 anew if they pass, or refuse by the refuse row, whose recording CAS on that ETag also
          fails the first PUT; another ETag -> as 412; the store unreachable -> 503 {push_id, outcome: unknown};
          the client's retry resolves it
cleanup   none at answer time: a refused or unknown push's record and new slots stay until evacuation's Resolve finds
          it dead, which no attempt, earlier or later, survives (11.13); nothing in idx/ was written
evacuate  hourly, 11.13's evacuation resolves every record of batches over 25 h old, fencing a ref, one with no head
          by a placeholder head, before it drops a pending record, and finds orphan pushes without trusting the log
Resolve   head window, then at most two log pages of (b, b+64]: P is committed at u, with its place, iff they name P
          at a version u in (b, b+64] (file mode) or at b+1 (git mode); dead iff not committed and the head is at or
          past b+64 (git mode: b+1), or its statement can no longer pass the time checks (time_ms + 35 min) and the
          head's fence_ms is later than that; otherwise pending; log pages never change, so evs caches them
```

Invariants (§22 model-checks them):

```text
I-EVS-1  a committed head's dependency closure (statements, payloads, entry versions, segments, slots) stays
         readable, except keys a committed ERASE or a shred destroyed, the content of versionless versions that a
         committed version replaced (11.13's purge), and the content of versions an executed drop lists (11.13's
         drop job)
I-EVS-2  no answer deletes anything: a push's new slots go only once Resolve finds it dead, and a batch record only
         once Resolve finds its push dead or committed at another place
I-EVS-3  a push id commits at most once; its retry returns the original version; once any attempt of it is
         answered a refusal, no attempt of it commits, however late it reaches evs, save one validated before
         its repo's shred began, which the shred destroys (11.12): the head settles the refusal for good, or
         records it until the statement can pass 5b nowhere
I-EVS-4  pending state never evicts the newest committed version of a path, and a reader finds that version in its
         entry or its push payload
I-EVS-5  no segment becomes reachable after GC decided to delete it: a push, or a seal for its parts, adopts only
         an upload under 24 h old at its last check and writes its batch record before its head write; evacuation
         settles every record before its batch goes, a committed one behind a pidx/ entry that names its
         segments and a pending one by a fence on its ref, a ref with no head by a placeholder head; and GC
         deletes a segment only once no batch is left from before its LastModified + 24 h + 2 min, no pidx/
         entry read after that names it, and by a DELETE that names its LastModified (owner decision 203)
I-EVS-6  a file path's newest committed version is in its idx/ entry or the head window: a file version leaves the
         window only once it is folded or a newer window version of that file replaces it, and a removal only once
         its marker is written, which stays until collected past the horizon (11.7); a directory delta leaves only
         once it is applied to its name table; older versions are reached by the history walk
I-EVS-7  a batch is deleted only after each committed record it holds is in a pack or parcel that a pidx/ entry names
I-EVS-8  a file-mode push commits at u only if each file path it changes has, through u-1, newest version equal to
         its base_entry_version (0 naming it absent, a removal one of its versions), each creation's version
         max(its push's base_version, the newest removal its marker or the window holds) + 1, so a path's versions
         never restart, however folds, reruns, copies and collections interleave, and 11.7's two-way directory
         checks hold; a head read or listing at v serves each path's newest version through v and none newer
I-EVS-9  a kind-5 segment, or a slot that only a versionless path's versions name, is deleted only once every
         version naming it is versionless and replaced by a committed version at least 60 s earlier by the
         deleting process's clock, and no hold keeps it; every path's newest version keeps its content
I-EVS-10 no committed version names a kind-5 segment except the version that introduced it, that path's later
         versions on the same ref in turn, and rename targets in the push that removes the path; a staged
         segment only its introducing version; a versionless path's slot only that path's versions
I-EVS-11 at a ref version, each document key has at most one version in the all partition and at most one in each
         bucket's shards, and a reader's merged view holds each document's newest indexed version or nothing; the
         push that removes an expired bucket adds its documents to all
I-EVS-12 a roll-up commits only from the lock version its runner took, so two roll-ups of one bucket never both
         commit
I-EVS-13 in a slot-keyed repo, once an erasure completes, no stored index file version holding the document
         has a key a reader can obtain: current versions were rewritten under fresh keys by its CLOSUREs, every
         older version still stored, staged copies included, shares a slot key its ERASEs destroyed, and after
         its CUT on that ref no push but a CLOSURE wrote it into an index file version (I-EVS-17), a CLOSURE
         only into a file whose replaced version held it, which the erasure's list or path CAS then covers;
         this holds whatever pushes were prepared, delayed or sealed late, with no indexer and every hint lost
I-EVS-14 every directory card, repo file and notice a reader accepts was written by the sidecar §16.11's path rules
         allow at the version's auth pin, and, where the format signs inside, signed by the same key; a card's or
         notice's signer is admitted and unrevoked and, for a member device, consented, and a repo file's held
         the right at its push's pin, judged by retained history (§16.11's repo file row); any other version is
         ignored and alarms
I-EVS-15 a drop deletes a kind-1 segment or a slot only once every committed version naming it is listed by a drop
         whose window passed with no cancel and whose list its job proved exact, the job's two scans at snapshots
         after every such drop's fence found no other version naming it, the object is over 25 h old and no hold
         keeps it; no push commits citing a listed version after its drop's fence; every path's newest version
         keeps all its content
I-EVS-16 in a directory repo evs takes ERASE, CUT and CLOSURE pushes, ?closure=1 uploads and slots/delete only at
         admin scope, which §7.8 mints only to the directory's consented, not-read-only admins, refusing them below
         it before any commit or slot rewrite, so a refused erasure leaves every slot as it was
I-EVS-17 a CUT, or a push other than a CLOSURE creating or replacing an index file version, commits only at the
         head's index_epoch, which only a CUT moves, to its own version: so no such push built before a CUT commits
         after it, its honest builder has applied the ref's erasure set at that epoch, and a CLOSURE, which only
         replaces committed versions, never puts a document into a file whose replaced version lacked it
```

**Refs.** evs (step 5) and replaying readers check:

| Ref kind | Mode | Writer | FORCE, DELETE and DROP |
|---|---|---|---|
| `shared` (`main`, …) | git or file | `rw` scope | `admin` only, DROP on file mode; an IMMUTABLE ref takes only DELETE |
| `owned`, general repos (`ur/<sidecar_id>/…`) | git or file | its sidecar | its sidecar; DROP `admin`, on file mode |
| `owned`, record-class: a per-writer stream | file | its sidecar, creates only | refused; BASE (`admin`) keeps every push statement; erasure by ERASE pushes |
| `deposit` | file | its depositor, creates only | refused; a reader with `rw` deletes ingested entries with CONSUME |
| `erasure` (per repo) | file | `admin`, the team directory's included (11.12), creates only | refused |

**Gate (D-EVS-18):**

```text
pins      every statement declares the authorization pin auth = (n, A_n) (§7.9's AuthPin) and the generation pin
          {group_id, generation, C_g}; the head records the newest committed ones
fence     step 7 commits only if (1) the push's pins pass §10.6's gate predicate against the newest authorization
          state evs holds, and (2) neither pin is below the head's (equal versions need equal chains and
          commitments); the head If-Match makes (2) atomic with the commit, so once any commit carries a newer
          state, no commit under an older one follows on that ref, retries included
timing    evs issues step 7 within 5 s of reading the authorization state it validated against, and reissues a
          timed-out PUT only within that window (outcomes, below); api's notification brings a new projection to evs
          within 5 s (§8.9), at worst at its 5-min poll
contract  a removal takes effect, per ref, at the first commit validated against a state that includes it; a write
          validated before then serializes before the removal; so no write sealed to an excluded generation commits
          more than about 10 s (worst case 5 min) after api stores the dropping projection, plus one store request
          deadline for a PUT already sent (§19.6's 10 s, under the lb's 30 s read timeout), or, for a PUT whose
          drive commits began within that deadline and stalled, until §19.6's settle rule releases the head,
          which no read or commit passes meanwhile (§22's suite checks both); the writers' own rule never to seal
          to a generation a non-reader holds (§8.12) stays the primary control; expiries close the gate too,
          through the predicate's time identity (§7.9)
refusals  412 GATE_CLOSED to pushes and deposits below the requirement; receivers answer 451 (§15); new refs are
          fenced by the same check on their creating push
```

No gate object exists, and no gate write precedes a commit.

**Readers verify** against a malicious server (I-4, I-16). The signed head of owner decisions 2 and 7 is C_v over Signed `EvsPush` statements: a head is accepted only if a writer signed every push since the reader's pin, each covering its parts through `parts_sha256` and its segments through `entry_sha256` and segment ids, wherever evs read them:

```text
replay    syncing devices replay pushes from their pin, checking signers against their config's writer set, ref
          rules, the 64-version bound, path-level CAS, C_v, pins, generations, path epochs, maps and tails and,
          decrypted, git oids, descent, TIP and the forced committer on git-mode refs (owner decision 81), imports,
          stream chains (§16.8) and epoch_authenticator; they pin (ref, version, C_v) and alarm on any head not
          extending it
head      head readers verify every statement after their pin and the statement behind each entry they read (11.9)
witness   §6's HeadCheck, which any admitted reader may witness (owner decision 129; D-TRUST-10), compares
          authorization, generation, epoch and ref pins (§6.4-§6.5's RefHead); a lower side reads the ref's
          statements from its version up (11.9) and recomputes C forward
```

### 11.9 Head-read API

```text
request   POST /evs/v1/repos/<repo_id>/read (r): {ref_id, pin_version (0 if none), fresh (no cached head), up to 64
          paths, each with its token path in the current epoch and in each listed source that may hold it (11.6),
          ranges (64, <= 32 MiB), wanted slots, maps, log pages, push records and parts by push id}
streams   POST .../read {refs: up to 64 (ref_id, pin_version)} (r) reads a record-class repo's owned streams: per
          ref, the head summary and the Signed EvsPush of every version after its pin with the entries those
          versions create, their records and slots, in one framed stream of at most 4 MiB, a ref past it
          answering more with its next version and a pin older than its window behind (the client pages GET
          .../log for it); the team directory's daemons read the streams a sync finds moved 64 at a time (§16.11)
moved     GET .../refs?moved_after=<push sequence> lists only the refs whose last commit raised the repo's push
          sequence (11.10) past that value, from {evsh_<repo_id>}, which keeps each ref's value beside its head;
          a value from before the sequence's restart, or a hash that lacks a ref, answers every ref, as GET
          .../refs does; a commit whose raise a crash lost (11.10's sequence row) is listed only at its ref's
          next commit, so a reader also lists every ref, with no moved_after, at its first sync each UTC day
reply     one framed stream: the head summary (v, C_v, push id, pins, path epoch, index epoch); the Signed EvsPush
          of every version after pin_version, from the window's places, or `behind` with the first missing
          version when the pin is older than the window (the client pages GET .../log?ref=&since=, <= 1,000
          statements a page); per
          path, the newest committed version (older ones on request, a replaced versionless version answering
          `collected` for its content, a listed one `drop_pending` {drop_id, not_before_ms} or `dropped` {drop_id,
          version} with the DROP's statement, body and the list range proving membership; for a removed path, its
          removal's push id, version and path version, from its marker or the window; on an overlay, `base` for a
          path it holds no version of; 11.7), with the statement
          that wrote it (when not among those returned) and its Merkle proof,
          and for each later statement whose change list is not inline and whose covering prefixes match the path,
          the adjacent-leaf proofs (11.6's order) that neither the path nor a prefix holding it is among its
          changes; then the records and slots it names
newest    a path's newest committed version follows 11.7's rule: each entry combines with the folded_through h of
          the head read before it, also when a folded version above v sends evs to a newer head, whose window then
          supplies the versions after h, else evs reads the entries again after that head; a reader checks the
          version against its statement either way; a listing is the directory's folded table plus, in version
          order, the deltas after h past the version the table holds
cache     {evsh_<repo_id>} maps each ref to its head, the time evs cached it and the push sequence its commit
          raised (moved, above), written after each commit only if its version rises, the sequence raised first;
          evs serves an entry within 10 min of that time (the key's TTL, which any ref's write
          extends, only bounds memory) when its version is at least pin_version and any version a hint named and
          the request is not fresh, else the cluster's; readers verify as always; pushes use it only as 11.8's
          step 4 and outcomes allow, where a stale ETag fails step 7 and costs a cluster read and a second PUT,
          and a seal reads the cluster's head
rounds    the head first, from the cache; then the entries and, for a path a version after its folded_through
          changes, that version's statement and payload range in one round; records, any log page, the
          change-list ranges its proofs need and one range GET per uncached statement after the pin in the next:
          2-3 GETs, plus those statements, in two store round trips, 20-50 ms (owner decision 2); one more round
          when the head is not cached, its cluster GET preceding the entries; plus at most two cached log-page GETs
          when an entry's push is older than the window; segments up to 256 KiB are read whole and larger ones in
          64 KiB-aligned ranges
reader    checks each returned statement's signature against its config's writer set and the ref rules, and the chain
          from its pin to C_v; for each entry version, that it hashes to its statement's entry_sha256 (directly, or
          by its proof to changes_root), and for a removal, that its statement removes the path or a prefix holding
          it; that no statement after the version's own changes the path, or a prefix holding it, again (a prefix
          sends it to that push's change list: inline, or by its adjacent-leaf proofs, never the whole list); then it
          pins (ref, v, C_v) durably, and keeps, sealed under §5's AEAD, one record per path read (ref_id, path,
          entry version, pin at last read), at most HeadReadRecordCount = 16,384 a network, least recently used
          out (§5.9); a read of a recorded path sets pin_version to the record's pin, not the ref's (a request of
          several paths takes the oldest of their pins), checks every statement after it as above, refuses and
          alarms if the served version is below the record's or a later statement changes the path, then raises
          the record (owner decision 209); a head below its pin is refused unless a verified EvsReseed covers it
          (11.13, §19.10), which it shows as a loss
collected a kind-5 segment or staged range that 404s answers `collected` for a replaced versionless version, whose
          reader re-reads the head fresh and restarts on the newest version, and a 404 of a listed version's content
          reads `dropped`, with no alarm, unless its drop was cancelled or refused (11.7's states); for a path's
          newest version it alarms as a missing segment does (11.7)
dropped   a reader shows a listed version by 11.7's states, which the DROP's signed list, window and cancels decide;
          evs's refused report is unsigned and only lets a reader show content still stored, so a lying server can
          at most hide content; a read of its content answers EVS_DROPPED (§18.5; MCP FAILED_PRECONDITION)
serve     from not_before_ms, unless the drop is cancelled or refused, evs serves for each listed version its
          statement and `dropped`, its entry version only when its chain names no inline record, never an inline
          record of its chain (elided from any record it serves, every other entry version keeping its own hash),
          and, once the job's delete set exists, no byte of a deleted, held or packed id in it (404, as if
          deleted), so a held drop reads as a finished one
trusts    for a path it has never read or no longer remembers (its record evicted, or its record's pin past the
          budget), which writer-signed version is current at its first pin, and, after a
          re-pin past the budget, for every path, is evs's word (it could serve an older version or a refused
          push's entry); every later change is verified; its next HeadCheck with a replaying peer confirms the pin
          (v, C_v), not those versions (§2.8)
budget    a mobile catch-up fetches at most 4 MiB of statements and proofs (4,000-8,000 versions); further behind,
          the reader re-pins at the head and marks the gap, shown as "verified since <time>"
```

### 11.10 Subscriptions

The sidecar reads the statements after its pin (11.9), fetching payloads only for what it syncs, and raises a change event (ref, version, matching paths, signer) to MCP sessions and §18's `SidecarRepoChangeListener`; §18 wakes phones a hint cannot reach (owner decision 88).

```text
lease    POST /evs/v1/subscriptions {repo_id, ref or *, path epoch, <= 16 token prefixes} (r) writes one lease per
         prefix into Redis {evsl_<repo_id>} (holder, ref, path epoch, prefix -> expiry; an empty prefix is the
         whole ref) and raises {evsl_<repo_id>}v in the same script, then answers 200; DELETE removes them; the
         sidecar retries until 200, keeping the subscription in its sealed store across restarts, and rereads the
         head fresh (11.9) 5 s after the 200; the sidecar API subscribes by dir and subpath (PLAN.md:55) and
         computes the prefixes
renew    the sidecar renews each lease once it is over 24 h old, at a random time within the next hour, never
         because it reconnected; a lease expires 7 d after its last renewal, and a daily sweep drops expired ones
match    after each commit, the statement's changes, or its covering prefixes, are matched against the repo's
         leases from a copy each evs process keeps until a GET of {evsl_<repo_id>}v after the commit shows a new
         value; a lease matches if its prefix and a changed path are on one branch of the tree; holders a rev/
         object names, or the newest projection no longer lists as readers, are skipped; a commit whose GET
         preceded a lease's write precedes its 200, so the holder's fresh reread covers it, whatever the head cache
         holds
epochs   leases name their path epoch; a PATH_EPOCH commit is hinted to every lease holder of the ref, which
         re-creates its leases in the new epoch (11.6)
sequence after a commit, evs raises the push sequence {evsq_<repo_id>} in Redis by one script: if absent, SET it to
         the master's TIME, read inside the script as server/model/subscription_redis_admission.go:225 reads it,
         in µs x 1,000: the reply's seconds, its microseconds zero-padded to six digits and "000", joined as
         strings, so no arithmetic touches it; then INCR, PEXPIRE 30 d, and a reply of GET's bulk string, never
         INCR's integer, which Lua holds as a double (near 1.8 x 10^18, a multiple of 256); evs parses it with
         strconv.ParseUint and hints with the new value: one past a client's names the only commit between, and a
         skip sends it to the window; GET .../refs returns it; a crash before the raise leaves that commit to the
         hourly resync; the hint's delta also lets a client compare the ref's version with its pin
hint     §6.8's PushHint{topic "evs:<repo_id>", version: the push sequence, delta} per matching client, delta
         EvsHeadChanged{ref_id, version, chain, push_id}, coalesced to 10 per second per repo
gap      hints are lossy (§6): a client catches up at once on repos whose versions moved in §6.8's PushReset,
         reading the window or GET .../log?ref=&since= (<= 1,000 versions a page); its full resync of every
         subscribed ref, fresh, runs hourly at a random offset, and after an incomplete reset a background daemon
         first waits a random 0-10 min
loss     leases and the sequence are soft state outside the rdb bundles (owner decision 136); after a loss or
         expiry the sequence restarts above every earlier value, which clients see as a gap, provided the new
         master's clock trails the old one's by less than the lost family's age less 1 µs per 1,000 raises
         (§19.6's chrony on the Redis hosts); holders re-create their leases at their next hourly resync, which
         reads every subscribed head
slots    every script touches one hash tag ({evsl_<repo_id>}, {evsq_<repo_id>}, {evsh_<repo_id>} or
         {evsc_<client_id>}, whose script runs before the lease script), and hints use §6.8's per-client script,
         so no command crosses Redis Cluster slots
caps     pro.yml's sidecar_abuse: 1,000 subscribed clients per repo, except the team directory, up to the
         network's config_admissions, whose readers poll the cards ref (§16.11) and lease only notice prefixes
         q/<target>/; 500 repos per client, counted in {evsc_<client_id>}, a sorted set of repo ids scored by last
         subscribe or renewal ms: one script drops members older than 7 d, refuses if the repo is absent and the set
         holds evs_repos_per_client, else adds it, and sets EXPIRE 8 d; a DELETE removes the repo once the client's
         last lease on it goes; a loss fails open, and renewals rebuild the set within a day
```

### 11.11 The local tier

**Git access (owner decision 24).** `ur mount add <dir>` (cli/UI.md:31-34) resolves or creates the repo and serves it over http and ssh; only the sidecar talks to evs. The server is the system git on a plain bare repository: `git http-backend` (https://git-scm.com/docs/git-http-backend) behind the daemon's authenticating HTTP front, `git-upload-pack` and `git-receive-pack` behind x/crypto/ssh; the bare repository is plaintext like the working tree (owner decision 47), while evs mirrors stay sealed. `git-remote-ur` serves `ur://<net>/<repo>` wherever a sidecar runs; the pre-receive hook enforces owner decision 81:

```text
helper      git-remote-ur (§4.10) answers capabilities with connect (gitremote-helpers(7)) and pipes its
            stdio to §5.8's git hello; the daemon runs the system git-upload-pack or git-receive-pack on
            the bare repository behind the same hook
names       <net>: a label or alias (§12's ResolveNetworkLabel); <repo>: a display name from the config
            repo, or id:<repo_id>; the first use creates an implicit mount under <state>, with no listener
new commit  one that no ref of this repo's local mirror reaches
committer   a new commit's email is <client_id>@ur.invalid, where §5's binding log maps client_id to this
            sidecar_id (any generation); the name is the agent label, free-form; author fields stay free
set by      ur mount add, ur mount share and git-remote-ur write committer.name and committer.email into
            the clone's config (git >= 2.22, within §22.9's matrix); a refusal prints both
import      ur evs import <dir> [<ref>]: a repo admin signs EvsImport; the hook accepts exactly its oids,
            and the push, in parts (11.8), carries it in its sealed metadata for replaying readers, into a
            new or owned ref; a large merge into a busy shared ref takes the seal lease (11.8); from v1 it
            first uploads, through the agent, each git-lfs object the imported tips require (R, below)
            that <dir>'s own git-lfs store holds, so the tip check refuses only what neither store holds
```

**Binding (owner decisions 84, 130; D-TRUST-8).** Listeners bind all interfaces unless `--listen` narrows them (cli/UI.md:11). Plain http with Basic auth, which git needs before 2.46 (https://github.com/git/git/blob/v2.46.0/Documentation/RelNotes/2.46.0.txt), answers only on 127.0.0.1 and ::1; beyond loopback the mount serves only ssh, whose host key `ur mount` prints, or https with the device's §13 certificate, else a self-signed one whose fingerprint it prints (§15.10). HTTP checks Host; an ssh key maps to the sidecar or an isolated agent (§5.5).

**Refs (D-EVS-28):**

```text
receive   the daemon sets receive.procReceiveRefs to refs/heads and refs/tags and receive.advertiseAtomic to false
          (git >= 2.29; §22.9's matrix starts at 2.34), so `git push --atomic` fails before any write and each ref
          update reports its own status; the pre-receive hook keeps owner decision 81's committer check for all
journal   per ref update, before any evs write, the daemon appends {ref, old, new, push id, statement hash, state} to a
          journal in its sealed store, from v1 runs the git-lfs tip check on a git-mode tip (below), whose refusal drops
          the entry (an owned ref's waits), then seals and commits the evs push; the proc-receive hook answers `ok` only
          after evs's 200, and then runs `git update-ref <ref> <new> <old>` under the ref's daemon lock;
          `ng <ref> non-fast-forward` only when the head gained a git commit after old; the daemon itself re-signs when
          only PATH_EPOCH versions moved the head, re-tokenizes on 412 PATH_EPOCH, re-uploads on SEGMENT_GONE, re-posts
          on PARTS_MISSING, and waits on 429, PATH_EPOCH_DUE and GATE_CLOSED (re-sealing at the next generation) for up
          to the hook's 3 min, journaling each new push id before its POST; unknown -> `ng <ref> remote outcome pending`,
          the journal resolving it; any other refusal -> `ng <ref> <code>`
restart   the daemon resolves each unfinished entry by retrying its push id: committed -> update the local ref if it
          still equals old, else move the local commits to ur/<sidecar_id>/conflicts/<ref>/<time> and raise
          EvsConflict; refused -> drop the entry
owned     ur/<sidecar_id>/… refs are accepted at once (the local ref first, the journal pushing within 250 ms, then
          at most once per 2 s; sidecar/design/market2.md:518); offline pushes queue in the journal, and on reconnect the
          engine re-seals chains whose generation changed
locks     the sync engine applies remote commits with `git update-ref --stdin` transactions under the same per-ref
          locks, so receive-pack and sync never race on a ref
index     after each git push commits, the daemon journals the index entries of its changed text files and pushes
          them to its head on ur/index at most once a minute on 1 KiB XFS blocks, else once every 5 minutes (owner
          decision 172; 11.14); a ref DELETE journals a ref tombstone
```

**Git and versionless content (owner decisions 141, 162).** Git-mode refs hold no versionless version (11.7). A repo's git-mode refs keep their search index on its `ur/index` file-mode ref, written by companion pushes after git pushes commit (11.14). Export skips `ur/index` and `ur/lfs`, so git history stays exact. From v1, git-lfs carries large files:

```text
store     one per repo: the shared file-mode ref ur/lfs, each object at <oid[0:2]>/<oid[2:4]>/<oid> (names sealed and
          tokenized), versioning 1, or 0 in a locked repo (§8.8); its content is uploaded once, and later versions
          (touch, below) only cite it; pointers stay ordinary git blobs, so oids stay exact
agent     ur mount and git-remote-ur configure a standalone custom transfer agent (lfs.standalonetransferagent,
          lfs.customtransfer.<name>.path; git-lfs-config(5), https://www.mankier.com/5/git-lfs-config), so git-lfs
          moves objects through the daemon with no LFS server; uploads run in git-lfs's pre-push hook, before the
          ref update
touch     for each object git-lfs asks it to upload, the agent writes the object's path: a creation, or a new
          version citing the stored content (no re-upload); a creation's 409 means another writer stored it
requires  R(c), the objects a commit or tag c requires: each blob of c's tree (a tag peeled to it) at a path whose
          filter attribute, under that tree's own .gitattributes files (gitattributes(5)), is lfs and whose bytes are
          a git-lfs v1 pointer (under 1024 bytes; https://github.com/git-lfs/git-lfs/blob/main/docs/spec.md)
tip check git-lfs uploads only objects of commits the remote's old tip does not reach, so a force push to an
          ancestor, a new ref or tag at old history, an import, or a push that skips the pre-push hook (--no-verify,
          GIT_LFS_SKIP_PUSH) uploads nothing; so for every git-mode update from old to new, through any listener or
          git-remote-ur, the daemon takes R(new) less R(old), old being the tip the push's TIP CAS names (none for a
          new ref or the first push after a DELETE), by git's tree diff unless a .gitattributes file differs, and
          reads each object's newest ur/lfs version, by a head read (11.9) wherever its cache does not show one:
  fresh   a creation or touch signed under 5 days ago: nothing to write
  stale   older: a protecting touch, all in one ur/lfs push (parts as needed) retried as the journal's pushes are,
          whose 200 precedes the git push's POST, each naming the version read, so a prune that read it fails
          path-level CAS; a 409 rereads the path, a newer version counting as fresh
  missing absent or removed: `ng <ref> lfs objects missing`, nothing published, the hook printing
          `git lfs push --object-id <remote> <oid>...`, which uploads them through the agent, and up to 20 oids, each
          with a path that needs it and when its prune committed, if one did
  again   before a push id's first POST when the check is over 1 h old; an owned ref, accepted at once, is checked at
          receive when online, else before its first POST, where a missing object holds its entry, `ur status` naming
          the objects and the command, until an upload or a later tip that does not need them
  why     an object R(old) also names is safe, since the push commits only while old is the tip, so a prune's start
          read finds old or new (or a later tip, checked in turn); a fresh one is under N days old (N >= 7) at any
          prune start up to 2 days after the check, by when the tip has committed and a start reads it; ordinary
          pushes write nothing more, their objects just uploaded, and an object takes at most one protecting touch in
          5 days
smudge    checkout reads objects through the agent; ur mount sets lfs.skipdownloaderrors, so a commit whose objects
          were pruned checks out with pointer files in their place, and ur names each such object and when its prune
          committed; the tip check keeps every current tip's objects present, so only history checks out pointers
prune     daily, an indexer (§7.9's IndexerSet) or another device holding every ref reads every ref's head from evs
          at its start s (syncing a tip it lacks, else refusing) and removes, in one push (parts as needed), each
          object that no tip of that read and no commit of the last N days requires (R) and whose newest version, its
          last upload or touch, is older than N days at s; N is 30, or a repo admin's setting of at least 7 days in
          ur/lfs's signed settings file (a smaller value reads as 7); each removal names the object's version, so a
          concurrent touch wins at path-level CAS and the prune reruns; the purge deletes the content a minute after
          the prune commits (11.13)
```

**Mobile and wasm** run head mode: the evs core with its own git codec and delta code (about 1k lines) reads and writes single files on file-mode refs (git-mode refs are read-only in head mode) and commits only changed entries; mobile never diffs files over 1 MiB, runs at most 2 transfers, and fetches versionless content only on an explicit open, except the search index's, which follows the index's fetch policy. They write their own index entries in the push that changes a document, keep the latest buckets of the repos they sync, fetch the all partition under §18.4's policy, and merge only when out of slots or on Wi-Fi while charging (11.14).

**Drops.** Every mirror and cache applies an executed drop (11.7: `not_before_ms` passed, no cancel, evs not reporting it refused): it deletes from its sealed store the segments, inline records and slot copies that only listed versions name, and every decrypted copy of a listed version it manages (index caches, local stores; §5.9, D-CORE-19), keeping statements and served entry versions; one offline at the drop keeps its copy until it syncs, as with an ERASE (§2.18). `ur history` (11.7) sits beside `ur evs`.

### 11.12 Repos: kinds, naming, grants, deposits, lifecycle, export

**Kinds** are fixed at creation and bound into §10's `ur_group`; §8's `*` matches only `general` and `record`:

```text
kind         one per                            class          read and written by
general      any: git repos, group inboxes      general        grantees
record       any: ledgers                       record-class   grantees
config       network (§7.9)                     general        every admitted sidecar reads; config writers write
directory    team network (§16.11): the team    record-class   every admitted sidecar of the team reads; each one
             directory, also its coordination                  that is not read_only writes only its own paths and
             log                                               stream
team_record  network (§16.8)                    record-class   grantees
mailcfg      network and Team scope (§15.7)     record-class   grantees
vault        member, owner-bound                record-class   the owner's consented devices (below)
mailbox      member, owner-bound                record-class   the owner's consented devices (below)
secret       any number a member, owner-bound:  record-class   the owner's consented devices (below)
             one secret, such as a custom
             domain's ACME account key (§13.8)
```

**Owner-bound** repos carry `owner_member_id` (D-EVS-11). Only the owner's consented devices (§8.5) read and write them, so one admin signature never makes a reader; others read through a consented device's `EvsShare` or as a Team's visible audit reader, the only reader admins may add, though they may revoke (owner decisions 63, 126); the owner's other sidecars deposit into its vault and mailbox, and a `secret` takes only read receipts; MCP's evs tools reach no `secret` repo and never read the config's contents (§16.6). Members refuse, and no writer commits, any other Add or wrap; KF2 parks such a device with `approval_pending`, and the owner's devices alarm on admissions under the owner they did not sign (§10.7, §5.4).

**Naming and creation.** `repo_id` is random, URLs carry only ids (I-13), display names are sealed, and labels exist only in the config repo (owner decision 59). A sidecar files §8.8's `RepoCreate`, becoming repo admin; `PUT /evs/v1/repos/<id>` then places the repo (11.8) and writes `repo/<id>` (If-None-Match) with kind and owner from the projection, `keying` until §10's KF1. A config repo's `repo/<id>` follows its network's first projection base, whose sidecar alone holds the first `admin` token (§7.9). A team network's one `directory` repo is filed by `team-create`'s first Owner device after the config's first base (§7.5, D-TEAM-28), or by an admin device that finds none; api and readers refuse a second in a network, and api one outside the team tier, which readers cannot see (§20.5's `NetworkTierOf`). Its admins are its creator and every config writer.

**Grants (owner decisions 7, 8, 60, 114, 144, 182).** Member devices are leaves of the repo's MLS group, except readers of the config and of the team directory past §7.9's first 1,000, which read by wraps; the directory's readers are fixed by kind, which refuses `RepoAdmin` adds, `RepoGrant` and `RepoRevoke` (§8.5, D-ACL-24); tagged, ephemeral, CI and cloud sidecars hold per-generation `ReaderWrap`s or a covering Delegation's wrap (§10.5), and RecoveryWraps hold recovery copies (owner decision 62). Writers are sidecars whose pushes readers accept. Repo admins and config writers sign the access log (§8.8), which clients verify from the config repo and the token exchange mirrors as scopes. `ur mount share` files a grant, or an `EvsShare` for owner-bound kinds; `ur share` is §9's (D-SOCK-16).

**Deposits.** `Deposit(name, reader)` checks the drop key against §10's `GenRotate_g` and §10.5's depositor rule, then appends entries under random ids, each body under a random key that a slot holds HPKE-wrapped to the drop key (below), to the depositor's `deposit` ref (11.6); entries may span segments, so 50 MiB messages pass the lb (§15). Receivers and tagged or headless sidecars deposit; a reader with `rw` ingests in version order, then commits a CONSUME deleting the entries and their slots. A reader of an owner-bound repo that is not its writer deposits only `read` receipts (§16.8): at most 4 KiB each and 256 a day per repo, else 429; evs sees only sealed bytes, so the owner's ingest enforces the kind, taking from such a depositor only entries of kind `read` with source `observed` and consuming any other without ingesting it, with an alarm.

**Erasure** (owner decisions 61, 133) is key destruction:

```text
push      POST .../slots/delete (admin) commits an ERASE push on the repo's `erasure` ref (shared, file mode,
          creates only, admin writers): its statement binds erased_sha256 over [(slot id, key index)], and its
          payload lists them and, sealed, what they covered: its erasure's id and documents, and each one whose last
          key it destroys (reconcile, below); evs reads the named slots in step 4, refuses one naming no key they
          still hold (409 NOTHING_TO_ERASE, once recorded, 11.8), commits it (steps 4-7), then rewrites each named
          slot object without those keys (If-Match) before answering 200, under a preservation hold too (owner
          decision 133); a crash between leaves the client's retry, then taskworker's reconciler, to finish the
          rewrites; a network's ERASE, CUT and CLOSURE pushes past 60 a minute queue as P1, their slot rewrites
          staying P0 (11.13)
closure   the erasing device names every key of the entry's representations: each retained version's slot keys;
          each derived-field chain (§15.7's i/ segment holding the message's IndexEntry, and each search-index file
          holding the entry's postings, 11.14), which it first
          re-checkpoints without the entry under a fresh object key by a CLOSURE push, then lists the old chain's
          keys; and an unconsumed deposit's slot (the deposit id is the message id); in a format-2 repo that may
          hold an index, a CUT (below) on each index ref of its documents precedes every list of index files; its
          first ERASE carries at least the entry's own keys and deposit slot, which re-key nothing, so at the
          storage limit and while spent its body goes at once and its derived chains follow in CLOSURE and ERASE
          pairs (rekey, below; 11.13's wait); a record entry's erasure is
          then noted by §16.8's `erasure` entry, a new record, which its device holds while the network is at the
          storage limit or spent (11.13), the committed ERASE, with its payload's sealed note of what the keys
          covered, standing as the record meanwhile
rekey     a CLOSURE push (flag 128, admin) on the entry's ref, or on `ur/index` for its search-index files (11.14),
          carries in erased_sha256 and its payload the list of the ERASE that follows it, and, sealed, its
          erasure's id; it needs no index_epoch (11.8's 5d), since it only replaces versions; evs takes one only if
          each change replaces a committed file version (no creation, deletion or directory delta), the list names
          every slot the versions it replaces name, and each new chain's record lengths sum to at most Padme of the
          replaced chain's summed record lengths, so an entry-removing re-checkpoint passes when its merged record
          crosses a padding step; else 409 with the paths; at the storage limit and while spent (11.13) it takes
          ?closure=1 segment uploads (admin), each at most 1,088 KiB, a padded segment of one padded record of a 1
          MiB file, §15.7's largest i/ segment and 11.14's largest index file (larger: QuotaRefusal), and CLOSURE
          pushes' inline records only within their eraser's own limits (the token's
          ur_sidecar_id; owner decision 146): its uploads within 60 a minute and within its turn of §20.7's
          network pacing (k erasers asking at once each get one ?closure=1 upload every k/4 s, at most 4 a second
          a network, evs_closure_uploads_per_s, fixed, a refused eraser counting in k until its turn), and its
          closure bytes, uploads and inline records, within its evs_closure_bytes_per_day a UTC day, which §21 may
          tighten but never below evs_closure_bytes_floor (§20.4); §20.7's {sq_} counts these per eraser, and an
          upload past any, or a CLOSURE push past the allowance, gets 429 with retry_after_ms (the allowance's at
          the next 00:00 UTC), so
          no admin's closures spend another's; a CLOSURE push past the push row's network rate still queues as P1 and
          commits; the bytes count and debit as usual, and an upload no CLOSURE push adopts is an orphan (11.13)
cut       a CUT push (flag 512, format 2; admin, and in a directory repo the authority the directory row gives an
          ERASE) on an index ref of its documents (their file-mode ref, under .ur-index/, or the repo's ur/index,
          which a CUT creates if absent), the index on or off, changes one file only, the ref's erasure set (11.14's
          x), created or replaced, staged, at most 16,208 B: per erasure its id, its eraser, the index_epoch its CUT
          named, its time and, per document of it the ref indexes, the doc_key and the newest version erased; the CUT
          keeps every erasure still pending and every one whose CUT named an epoch at or above the set's
          listed_since, drops a complete one only by raising listed_since past the epoch that one's CUT named, and
          adds its own; evs takes it only at the head's index_epoch, which its step 7 sets to the CUT's version
          (11.8's 5d), else 409 INDEX_EPOCH, or 409 with the paths past those bounds; so no index push but a CLOSURE
          built before it commits after it, and a list of index files taken at or after it is complete (11.14's epoch
          and erase rows); at the storage limit and while spent it is maintenance, spending no allowance, since its
          one staged record replaces its ref's set; an erasure that finds the set full cuts once pending ones
          complete, its first ERASE (closure, above) not waiting
deposits  a depositor draws a random object key per deposit, seals the body under it, and puts HPKE-XWing(drop key
          of g, object key) in a slot its deposit push introduces, so the drop private key, which every reader
          derives from RK_g, opens a deposit only while its slot exists; CONSUME deletes the consumed entries and
          their slots; segments of consumed deposits go after 7 d
after     readers mask in search, from its CUT or first ERASE, each document an erasure lists (11.14); readers and
          mirrors, on an ERASE's hint, delete their cached object keys, slot copies and every decrypted copy of
          the erased entries (local mail stores and IMAP caches, record and index caches; §15.7, §16.8, §5.9's
          index cache, D-CORE-16), and refuse
          those keys; a re-seed uploads slot copies after the history replay, minus every key an ERASE in the
          replayed history names (§19.10)
residual  a mirror offline at the erasure keeps its copy until it syncs; if the site is lost and no surviving device
          holds the ERASE, a stale mirror can re-seed the key; any device holding the ERASE re-applies it; keys a
          former reader cached are beyond recall (§2.18); a ref's erasure set shows its current readers an erased
          document's doc_key until a later CUT drops it; an erasure no device that may finish it runs stays pending,
          masked and fenced, its remaining keys live (reconcile, below)
reconcile an erasure resumes from evs's state, not one device's memory: its CUTs' sets list it until it is complete,
          its CLOSUREs' and ERASEs' sealed notes name its id, and its ERASEs' notes name its documents and each one
          whose last key went, so a derived chain of a document whose own keys are gone is still owed; its eraser's
          device resumes it at its next start; 25 h after its CUT or its last ERASE, whichever is later, with none
          since, another device of the eraser's member that may erase it (owner-bound: a consented device not
          read_only) finishes it, and once its eraser is revoked, reaped, suspended or parked any device that may
          erase it does, each within its own allowance, from a head at or after its CUT, which it commits itself
          where a crash or a full erasure set left it missing: first an ERASE for each
          CLOSURE of it no ERASE followed (that CLOSURE's payload lists it), then the remaining pairs; a duplicate
          CLOSURE gets 409 and a duplicate ERASE NOTHING_TO_ERASE, both counted done; an erasure that committed
          nothing never began, and its device's journal retries it; `ur status` and §5.4's erasure event show each
          one's state, what is left and its next turn (11.13's wait)
retention a record-class BASE or retention expiry erases keys as above; export renders an erased or expired entry
          as a stub {token path, entry hash, erased}
bytes     ciphertext stays in batch records (at most 26 h), parcels, packs and segments until v1's compaction, except
          a versionless version's, which the purge deletes a minute after the push that replaces or removes it, and a
          staged one when its batch is evacuated (11.13); slots are their own objects, so erasure is immediate; a
          drop's listed inline records also wait for compaction, never served (11.7), slot-keyed ones shredded with
          their slot
versionless a slot-keyed repo's versionless path keeps its key in its own slot (11.6), so an ERASE destroys it at
          once, under a hold too; an erasure's CLOSURE rewrites a versionless derived file (the search index's) in
          place under a fresh key in a new slot, its staged bytes counting as inline records for the rekey row's
          limits, the ERASE destroys the key of every slot a stored version of each rewritten file names, a version
          a hold kept from before a REMOVE generation or ur evs rekey re-keyed the path included, and the purge
          deletes the old ciphertext and slot a minute after the CLOSURE commits; in general repos a versionless
          segment's key goes with the segment
drops     an ERASE's slot rewrite that meets a slot a drop deleted (If-Match answering 404, cmd/erasure-object.go:
          1281-1285) is done, since every key it held is gone; a drop's DELETE of a slot an ERASE rewrote removes
          the rewritten object, only once no live version names it; a CLOSURE landing on a path with a pending drop
          is a later version, kept; a drop writes no CLOSURE, spends no eraser's allowance and takes no ?closure=1
          upload, so it never delays an erasure at the floor (owner decision 146)
directory the team directory's ERASE, CUT and CLOSURE pushes, their uploads and slots/delete take admin, as every
          repo's: evs cannot see whose copies a key covers, so it checks the authority before any key mutation,
          refusing a caller below admin, a push at step 5c before any commit and an upload or slots/delete with 403
          at arrival, and §7.8 mints the directory's admin only to its consented, not-read-only admins; a repo
          owner's revocation reaches the keys through an erasure_request that the directory's erasure runner, a
          directory admin's indexer or daemon, checks and erases (§16.11; owner decision 181); readers count a
          directory ERASE only from a directory admin and alarm on any other, which only a server breaching this rule
          commits
```

**Deletion (owner decision 82)** is a state of `repo/<id>` (D-EVS-19):

```text
state      keying -> active (KF1) -> deleted{deletion_id, time, signer} -> shredding{deletion_id, time}
           -> shredded{deletion_id, time}; every transition is If-Match on repo/<repo>
log first  the device files §8.8's RepoDelete{repo_id, deletion_id, now} or RepoRestore{repo_id, deletion_id} into
           the access log, then calls the route, which requires that statement in evs's newest projection
           (AclRepo) and takes deletion_id, now and time from its entry, else 409 STATEMENT_MISSING; taskworker's
           reconciler applies a projected statement repo/ lacks, so a device killed between the two leaves a
           state the log records, and a re-seed after a site loss can trust the log (§19.10)
delete     DELETE /evs/v1/repos/<id> (admin; ur evs delete): active -> deleted; members get a hint and stop syncing,
           and stored bytes count until the shred (§20.7); with now (?now=1, --now): active, or deleted under a
           newer RepoDelete{now}, -> shredding at once, never restorable
refused    evs and gkm refuse every route but restore and DELETE with now while deleted, except /reseed and gkm's
           GroupForm in §19.10's re-seed mode for a repo re-seeded as deleted (11.13), and all while shredding or
           shredded; the token exchange mints only admin for a deleted repo
restore    POST /evs/v1/repos/<id>/restore (admin; ur evs restore): deleted -> active by If-Match on the deleted
           object read; a repo past deleted answers 409 SHREDDING
start      taskworker, 7 d 10 min after the RepoDelete's entry, once the newest projection holds no RepoRestore of its
           deletion_id, which api takes only within 7 d (§8.8): deleted -> shredding by If-Match; exactly one of
           restore and start wins, as the log says; members get a hint, drop RK_g and caches, and mirrors drop the
           repo (11.13)
phases     each step rereads repo/ and runs only while it shows shredding with the job's deletion_id, so a stale
           job of an earlier incarnation deletes nothing; steps are idempotent and resume after a crash:
           1 wait 20 s, two of 11.8's 5 s validation windows plus §19.6's 10 s request deadline, so a push
             validated before the CAS has landed or never will, or holds its keys until §19.6's settle rule
             decides it, which the later phases' requests on those keys wait for
           2 delete slot/<repo>/* (keys first)
           3 delete the repo's gkm objects, its group's {gka_<group_id>} acks and recovery wraps (§10.8)
           4 under a preservation hold, stop: the ciphertext a shred leaves stays until the hold ends, evacuation
             still moving its batched records into packs and parcels (11.13; owner decision 133)
           5 delete every other family: idx/ head/ log/ pmap/ pidx/ spidx/ hp/ drops/ and the repo's Redis families
             ({evsq_}, {evsl_}, {evsh_}, {evsd_}), and seg/, pack/ and dropscan/ on the HDDs; its records in shared
             batches go with them, at most 26 h after each batch was written (11.13)
           6 after 10 min, longer than the issue-time recheck of repo/ (cached at most 5 s) that 11.13's P2 writes
             and every gkm write make (§10.6), plus the store's request deadline, so no fold, evacuation or gkm
             write lands later, repeat 2, 3 and 5 once for stragglers; a DELETE's settle copy (§19.6's settle row,
             evs-10) is gone by then, since §19.6 keeps the settle sweep's interval inside this pass
           7 rewrite repo/<repo> as shredded{deletion_id, time}, a tombstone kept with its place/ for the
             network's life
drops      a drop's job pauses while repo/ shows deleted, resumes at a restore and ends at shredding, the shred
           deleting everything (11.13)
```

**Export** (`ur evs export`) rebuilds plain git: git-mode refs with their original oids, file-mode refs with one deterministic commit per version (11.7), leaving out the search index's `.ur-index/` files (its roots and erasure set) and the `ur/index` ref, which are derived (11.14), and the `ur/lfs` store (11.11), checked by `git fsck`, with signed provenance in `refs/notes/ur`; a purged versionless version exports as a git-lfs pointer to its content_sha256 and size, noted there, and a dropped version as the stub blob `ur-dropped <drop id hex> <entry hash hex>\n`, its mode from its entry version where served, else the next kept version's, the drop noted there; a pending drop's versions export with their content.

### 11.13 Backend, IOPS, GC, quotas, durability

**Store needs (X13):**

```text
needs     ServiceHost.Blobs declares, on every cluster, quorum-evaluated conditional PUT, consistent reads and LIST,
          streamed and ranged I/O, object metadata on PUT and HEAD (11.7's entry states), a Delete, unconditional
          or naming its object's LastModified (11.3, §19.6), §19.6's deadline and settle rules: a request refused
          once its x-ur-deadline-ms has passed, and a PUT or DELETE that takes effect before any later request on
          its key or never (D-OPS-20; 11.7's stale and collect rows), and lifecycle rules, each metadata cluster in
          one pool (11.8), which §22's suite checks;
          segment PUTs ride streamable_paths: ["/evs/v1/repos/[^/]+/segments/[^/]+"]
address   a segment is addressed only by segment_id = SHA-256 of its bytes, never by cluster, bucket, pack or
          offset; locators are signed (inside entry versions), so packing never rewrites them; readers GET
          seg/<repo>/<id>, and on 404 look the id up in spidx/<repo>/ (LIST-cached, packs never change); records
          authenticate by AEAD, so a range read from a pack needs no segment hash
```

**Operation budget (owner decisions 21, 116, 140).** Every drive takes every metadata write, an overwrite twice (11.3), so drive writes bind before IOPS; inferred from §19.6's inputs until §22.8 measures them:

```text
inputs   §19.6's pushes and hints; one sidecar per Community network, 3 per Pro and 20 per Team (~28,000 in year
         one, ~150,000 in year two); gkm commits from weekly self-updates and device changes; rotations from
         removals, holder expiries (1 h requested grants, not_after) and reaps of agents no Delegation covers, each
         followed by full checkpoints at files' next writes and a batched path epoch, at most one a repo a day,
         all measured at M2 (§22.8); ~2 projection changes a second (then ~20); a segment in 1 push of 5; 0.2 new
         slots a push
event                               GET            PUT                    LIST   DELETE   counted
push of k = 3 entry writes          k + 2, + the   1 head; 1 batch share; -      -        head (the verified cache spares most
                                    unfolded       ~0.9 folded entries;                   reads), entries, rev/ subjects;
                                    statements     0.2 slots                              unfolded statements from the
                                    it matches                                            process's cache or batch ranges;
                                                                                          log/ 1 in 64
  its hints, 3 each (§19.6)         ~3             -                      -      -        the head summary from the cache;
                                                                                          one statement range a receiver,
                                                                                          outside the GET/s below
  evacuating it after 25-26 h       1 batch share  ~0.01 parcels, pidx/   -      1 batch  a pack PUT on the HDDs per ~300
                                                                                 share    pushes
a part of a large push              <= 1,029       1 batch record         -      -        steps 4-6; the seal reads parts by
                                                                                          place
a segment upload                    -              -                      -      -        a receipt; nothing on this cluster
lease, renewal, push sequence       -              -                      -      -        Redis (owner decision 136)
gkm commit, rotation, Add           as §10.6       as §10.6               as     as       acks in Redis
                                                                          §10.6  §10.6
a path-epoch copy, per live entry   1              1 entry                -      1        P2, <= 250 operations a second a
                                                                                          cluster (11.6)
a removed entry, with its marker's  2              1 marker (an           -      1        its fold's (P2), then the collection's
collection (owner decision 148)                    overwrite, or a                        GET and DELETE, and a window's two
                                                   create on a 404)                       head CAS (11.7)
a versionless replacement           X's newest     -                      -      <= 1     the candidate slot in slot-keyed
                                    version and                                  slot     repos; candidates from step 4's reads,
                                    hold/, cached                                         listed in the record; each kind-5 one
                                                                                          an HDD DELETE a minute later and a
                                                                                          HEAD at the sweep; staged ones
                                                                                          dropped at evacuation, after one GET
                                                                                          of their path's newest version
projection base or delta            1 a proc.      1                      -      -        api writes it; evs, gkm, gates read it
an indexed push (11.14)             -              its head staged in its -      -        ~2-4 KiB a drive in its batch; the
                                                   batch; the head's                      head's entry once a fold; a seal per
                                                   entry once a fold                      ~14 pushes adds one; a merge per ~128
                                                                                          KiB of entries (one push, a <= 1 MiB
                                                                                          HDD shard)
  its companion push (git refs,     as a one-change push, at most one a minute per writer on 1 KiB blocks, else one
  streams)                          every 5 minutes (owner decision 172)
a team directory push (§16.11)      as a push, per drive on 4 KiB blocks: a card's content change ~55 KiB (its index
                                    head's entry at folds included), a renewal ~37, a notice created ~46, rewritten
                                    ~37 and removed ~53 (its marker); about half on 1 KiB blocks
a drop (11.7, below)                its DROP push as a push (~27-43 KiB, its written version's fold included) and
                                    its index rewrites as an indexed push's; drops/<repo>/_ ~14-22 KiB an append
                                    and at most one overwrite a minute a running job (~1.3 MB a job-hour); a slot
                                    DELETE ~3.5 KiB; scans read only; ~0.3 MB a drive in all for a 10-minute job
load                                GET/s          PUT/s     LIST/s   DELETE/s   drive writes, busiest drive
twenty-agent test, 4.3 pushes/s     ~50            ~15       < 1      ~5         ~0.2 MiB/s
year one, 200 pushes/s              ~2,400         ~670      ~25      ~240       ~8.5 MiB/s, 0.40 DWPD; ~2,800 write IOPS
year two, 2,000 pushes/s            ~21,000        ~5,000    ~250     ~740       ~69 MiB/s, 3.3 DWPD on one set at
                                                                                 ~5 records a batch, 3.7-4.0 DWPD at
                                                                                 the ~1-1.6 records a batch of a set
                                                                                 near capacity; ~21,000 write IOPS
a restart, every reset incomplete   +~930 GET/s in year one, +~5,000 in year two, for 10 min
reads    per drive, GET/s + 10 x LIST/s uncached: ~2,650 in year one and ~23,500 at year two's one-set load, 0.3% and
         2.9% of 800k random-read IOPS, under 4% with the receivers' statement reads (+~600 and +~6,000 GET/s), so
         reads are not metered
cost     per drive, objects under ~14 KiB on 4 KiB XFS blocks: a create ~9 KiB, an overwrite ~14 KiB (its old
         xl.meta written again), a delete ~3.5 KiB, a GET or LIST nothing; ~43 KiB a push at about one record a
         batch (year one, and a set near capacity at ~8 evs processes) and ~35 at five, ~33 and ~27 on 1 KiB
         blocks; the head's overwrite alone is ~14 KiB (~10.5 on 1 KiB blocks); a removed entry's marker and its
         collection's DELETE ~17.5 KiB, ~14 more than the DELETE they replace, and ~12.5 where the fold met a 404
```

Owner decision 140's binding limits are the drive budget: at most 0.8 DWPD and 50% of rated write IOPS at the design load, met at ~27-43 KiB a push before owner decision 148's markers, which add ~12.5-14 KiB a removed entry (§22.8's fold row counts them); the head's If-Match overwrite alone (~14 KiB, owner decision 2) sets the floor (Q-EVS-9). §22.8's M2 exit runs this mix at 2× year one with the write budget on, refilled at 0.8 DWPD for the run, a restart included: p99 ≤ 25 ms per operation, at most 43 KiB per push per drive (owner decision 140), no push refused by the budget, no ref at FOLD_BEHIND and no batch past 26 h, after FS-116's exact-cost run, with P0's bytes by kind measured against the refill to set §19.8's P0 warn line (D-TEST-11); that sizing bounds the drives' wear at the admitted mix only, since P0 work past the refill writes past it (owner decision 186). Batches are per process and cluster (11.8), so at ~8 evs processes a set near its capacity sees ~1-1.6 records a batch and sustains ~400-450 pushes/s (~530-600 on 1 KiB blocks), not the ~490-650 owner decision 145 records, which assumed batches shared across the whole load; year two needs five to six sets, sized from §22.8's records per batch per cluster. Each next cluster starts at §19.9's triggers, the second at about 1.25× year one (about 1.2× with v1's index on 4 KiB blocks, at owner decision 172's cadence; §19.9), and takes new repos (owner decision 145). v1's search index (11.14) adds to this mix at owner decision 172's cadence: on 1 KiB blocks one companion push a minute per writer, about 4 KiB a push, ~34-37 KiB a push at 2× year one, inside D-TEST-11's 43, a set near capacity sustaining ~475-535 pushes/s; on 4 KiB blocks one every 5 minutes, about 2 KiB, ~42-45 KiB; year one stays under the ~0.45 DWPD that one a minute would cost on 4 KiB blocks, and year two needs five to six sets.

**Fair share and the write budget (owner decisions 140, 186).** No network can wear or take a metadata cluster, or the segment cluster's drives, from the others by P1 or P2 work, and no count cap applies (owner decision 66); P0 safety work runs at once whatever its volume, so P0 work past the refill, from one network or many, wears a cluster's drives past the budget and holds its other classes while it lasts (gates, below):

```text
budget   every metadata write spends its cluster's one budget: 0.8 DWPD and 50% of rated write IOPS on the busiest
         drive not under heal (§19.6), a bucket B that every measured drive byte drains, P0's included (§19.6's
         counters), refilled at r = 0.768 DWPD (0.8 x 24/25) with a depth D of 1 h of r and floored at zero: P0's
         bytes past what B holds are P0's excess, forgiven, counted and reported by kind and never repaid (owner
         decision 190); every class but P0 issues only while B holds it (gates, below), so no 24 h window passes
         0.8 DWPD but by P0's forgiven excess, and P0, which never waits, passes the budget whenever it alone outruns
         r (owner decision 186); the other classes' IOs are bounded, not metered: each drive write moves at least one
         512 B sector, so the refill caps their sustained writes at ~33,000 a second, 39% of 85,000, while P0's follow
         its bytes
price    each write is priced before it is issued in drive bytes: the cost row above (§22.8's measurement) times k,
         the measured over the priced bytes of the last 10 min
classes  P0, never queued, refused or paced, bounded only by its classes' own rate limits (§10.6's 60 commits an hour
         per uploader and group; §7.9's per-network append limits; 11.12's ERASE rate), never by the budget: rev/,
         proj/, repo/ lifecycle (deletion, restore), shred steps, ERASE, CUT and CLOSURE pushes within that rate and
         every slot rewrite, gkm Removes and REMOVE rotations, a staged delivery or claim of generation g+1 being P0
         only while gkm's newest verified state shows a shrink, an authorization expiry or a compromise retirement
         since gen/<g>'s auth pin and time (the causes of §10.9's REMOVE that gkm can see), and an MLS commit,
         which gkm cannot read, counting as a Remove only while that state shows a holder dropped since the
         previous epoch's auth pin and time (§10.6), else P1; P1, queued per network: pushes, parts, gkm commits,
         Adds, Welcomes, KeyPackages, ReaderKeys, LATE key deliveries (§10.6), GroupInfo, path maps; P2: folds,
         evacuation, packing, GC, copies, retention, fences, drop jobs and dry runs
accounts every 5 s §19.6's loop publishes in {nvb_<set>} B and the allowance T: 5 s of r, times 1 while B is at least
         D / 2 and falling linearly to 0.2 as B falls to zero, less P0's measured writes of the last 5 s, and never
         more than B holds less the priced bytes in flight, so T is zero while P0 takes the refill or B is at
         zero; T is the only account P1 and unfunded P2 debit, split as A_U, what unfunded P2 can issue in the next
         5 s within its own rates, at most 40% of T while its backlog lasts, and A1, the rest, T - A_U; a P1 admission
         debits A1 at full price, its own writes plus the P2 work it causes (fold share, batch delete, evacuation,
         parcel and pidx/ writes, its purge), and moves that deferred part into W, so shedding a push sheds its P2
         work; funded P2 spends W alone, through A2 = min(W, B - T - the priced bytes in flight), none while that is
         not positive, and never T, so a push's P2 work is paid once; conservation: the priced bytes issued in any
         window are P0's, A_U's, the immediate part of what A1 admitted, and A2's, A2 spending only what P1 moved into
         W, and the drives write k times them, so at a steady load P1 admits all of T at full price and the drives
         write T and P0's bytes, r while P0 stays under it
wallet   W, per metadata cluster in {nvb_<set>}, funds the P2 work a P1 admission caused (funded P2); P2 with no payer
         (copies, GC, nightly passes, dry runs, a lapsed credit) is unfunded; each process adds in its 5 s report the
         deferred part it admitted and subtracts the funded P2 it issued; the loop clamps W to the priced cost of the
         funded backlog the processes report, so the credit of a push that aborts, of a deduplicated retry or of a
         record evacuation drops lapses; a retry is priced again only for the writes it repeats; a process killed
         before its report loses at most 5 s of credit, whose work then runs as unfunded P2, paid once from A_U; a
         lost {nvb_<set>} restarts W at zero, the backlog unfunded until admissions refill it; priced and measured
         bytes differ only through k, and B, which measured bytes drain, carries any difference into its level and so
         into T's factor, never into W
gates    P0 issues at once, never queued, refused or paced (owner decision 186); its bytes drain B as any class's do,
         down to its floor, and come off the next T; every other class issues only within its account, and no account
         passes what B holds less the priced bytes in flight, so only P0 empties B (one interval's issue times the
         pricing error aside); while P0 takes the refill T is zero and pushes are shed, and funded P2 spends only what
         B still holds, so folds and evacuation stop once P0 empties B, within an hour from a full bucket at the
         stress below; when the storm ends, P0 back at its ordinary rate, B refills by the difference, P0's excess
         forgiven (owner decision 190), and the other classes restart within one interval: funded P2 at once on what B
         holds beyond T, evacuation's oldest minute directories first, up to four-fifths of r while its backlog lasts,
         and pushes at a fifth of r less P0's own, T rising with its factor once that backlog is spent and B refills;
         with pushes then taking all of T, T reaches half of r ~18 minutes later and 90% after ~78, the ramp holding
         back D / 2, 30 minutes of r, in all; P0 is bounded only by its classes' rates, per uploader, group and
         network, never per cluster: 100 large Teams on one cluster, each shrinking every 5 minutes within every rate,
         ask ~57,600 config and directory rotations a day, ~2.9 TiB a day a drive, about twice r, which the drives
         write past 0.8 DWPD and their 1 DWPD rating while it lasts (11.21; §19.8's P0 page)
reports  every evs, gkm, api and taskworker process reports in {nvb_<set>} every 5 s its queued P1 priced bytes, its
         unfunded P2 demand and backlog, its funded backlog, the credit it moved into W and spent from it, and its P0
         priced bytes by kind (revocation, log, lifecycle, shred, erasure, remove, rotation); P0's measured writes are
         those bytes times k; §19.6's loop splits A1, A_U and A2 across processes by the reports
order    P2 runs by deadline: evacuation, oldest minute directory first; the folds a page-out needs; other folds,
         path-epoch copies, packing, retention, GC and drops; a fence goes with the work that raises it, a refusal's
         record with its request
queue    each evs, gkm and taskworker process queues P1 work per network (the token's) and serves the queues by
         weighted fair queuing on priced bytes, with tier weights in pro.yml (<tier>.sidecar: store_weight; 1, 4 and
         16), within its A1 share
shed     past 100 ms of queueing delay it refuses first the network with the most queued priced bytes per weight:
         429 RESOURCE_EXHAUSTED with retry_after_ms (§6.5's codes)
fallback a process without a fresh allowance for 60 s runs P1 and unfunded P2 at half its last shares and funded P2 at
         most at its last minute's rate, and one that never had an allowance, at start, runs them within the refill
         over twice the process count unless the loop's saved state shows B at zero; P0 runs at once throughout;
         §19.6's loop resumes B and W from their saved state, else W at zero and B at zero, its floor, which is
         conservative
backlog  §19.8 exports per metadata cluster, with no network or repo label, P0's bytes by kind and their share of the
         last hour's refill, B and P0's forgiven excess by kind, the busiest drive's wear against its rating, and the
         outstanding work by class: queued P1 priced bytes, W and the funded backlog, the unfunded backlog and the
         path-epoch copy moves left (11.6), each with its drain time at the last hour's rate
bound    no request does more than a part's ~2,060 operations, so an import interleaves with other networks
outside  §19.5's W2 zones still count per address
hdd      per-network fair queues admit segment PUTs on each segment cluster against its drive operations a second
         (its HDDs' reads and writes completed) and its measured capacity, both read from {nvb_<cluster>}, which
         §19.6's hdd row publishes every 5 s with a 15 s ttl, the figures Q-OPS-2's trigger and the drop job's pause
         read; past 50% of that capacity evs refuses the heaviest network's uploads first (503, Retry-After), never
         authorization, deletion, shredding, erasure or closure uploads within their own bounds; §19.8 counts
         refusals by cluster, with no network label
```

**GC and evacuation (owner decision 136)**, all P2 work under the write budget:

```text
gc        folds keep up to four folded versions a path, and markers go in 11.7's collection windows; history stays
          forever by default, except replaced versionless content (purge, below) and executed drops (Drop history,
          below), and record-class repos follow
          §16's retention through an admin BASE that re-lists the live set and keeps every push statement; deposits
          go after CONSUME, and segments no retained push names after 7 d; taskworker works from the log, the hourly
          evacuation and one LIST of each repo's prefixes a night, and skips held networks' in-scope objects (§21.9)
when      hourly (so each day everything older than 24 h leaves the batches; owner decision 136), taskworker
          evacuates each minute directory pb/<h>/<m>/ of each metadata cluster once that minute is over 25 h old:
          batches leave NVMe within 26 h, and a small repo's history leaves its parcels within 7 d (move, below),
          except while P0 holds the write budget's bucket empty, when evacuation waits with every class but P0 and
          batches pass 26 h within the hour; it restarts as the P0 storm ends, oldest minute first, while the bucket
          refills (owner decisions 186, 190; 11.21)
resolve   per batch, GET it whole; per record, Resolve its push id on its ref (11.8): committed at this place ->
          keep; committed at another place -> drop; dead -> drop, deleting the new slots its record lists, the only
          cleanup (11.8); pending -> raise the ref's fence (one head CAS, or for a ref with no head one
          placeholder head created with its fence raised, 11.8's first row), then Resolve again; parts follow
          their seal; reseed records count as committed
move      per repo, the kept records, one pack or parcel per repo a run across all the minute directories it
          evacuates: once its aged material (these, its parcels, and its log pages older than 24 h, which wait at
          log/ until a pack takes them) reaches 256 KiB, one pack/<repo>/<pack_id> on the segment cluster
          (If-None-Match, its SHA-256 as checksum) holds all of it, then a pidx/ entry per ref, then its parcels
          and those log pages are deleted; below 256 KiB, one parcel hp/<repo>/<parcel_id> (If-None-Match) of the
          records alone and its pidx/ entries, the log pages staying at log/; a repo's aged material
          also packs once its oldest (parcel content or unpacked log page) is 7 d old: in the run that evacuates
          the repo, or, for an idle repo, in the nightly pass, which packs any whose oldest would pass 7 d before
          the next pass
delete    once every repo of a minute directory is moved, DELETE each of its batches, whole (I-EVS-7)
skip      every P2 write for a repo (folds, moves, packing, copies) rereads repo/ when issued, not when queued (cached
          at most 5 s), and proceeds only while it shows active or deleted, or, for moves and packing, shredding
          while a hold/ has the repo in scope (§21.9); so an unheld repo in shredding or shredded loses its batched
          records here, and no write re-creates its objects after its shred; a deleted, restorable repo keeps them;
          a held network's records, a shredding repo's included, are moved as usual and nothing deletes them while
          the hold stands; phases 5-6 remove a shredding repo's once it ends (11.12)
index     pidx/<repo>/<ref>/<v_first>-<id> (v_first zero-padded to 20 digits, <id> the container's pack_id or
          parcel_id, the first 16 B of SHA-256 over its bytes; nothing extends it, and containers never share a
          key): {container kind, versions v_first..v_last with each record's kind, offset and length, the log pages
          a pack holds (a parcel's entry lists none), the segment ids its records introduce}; a push whose parts
          and seal evacuate in different runs has an entry in each container; a parcel is replaced by its pack's
          entries first, then the parcel and its entries are deleted
readers   a record whose batch is gone is found by LIST pidx/<repo>/<ref>/ (cached; entries never change), a pack's
          entry taken over a parcel's for a record both name, and a range read
negative  a reader whose cached pidx/ or spidx/ lookup misses or names a deleted container, and so gets a 404, drops
          the cache and lists again; a container precedes its index entries, and both precede the deletion of what
          they replace, so one retry finds the object
resume    a run first lists the repo's pidx/ entries and moves only what no container holds (from a parcel, what no
          pack holds); a container with equal bytes on 412 is reused, entries are create-only, and a batch is
          deleted only after its minute's moves finished, so a killed run restarts the minute; the nightly pass
          deletes a pack or parcel with its entries once newer containers' entries name its every record, and one
          no entry names after 25 h
cost      at year two ~6 HDD PUTs a second (busy repos' packs); on the metadata cluster ~3 parcel and pidx/ writes a
          second in year one and ~30 in year two at 10 records a parcel (§22.8 measures records per parcel), and one
          DELETE per batch; NVMe residency 25-26 h for batches, and for a small repo's history at most 7 d after its
          commit plus an hour
purge     a versionless version V of path X is replaced at the first committed version u of X's ref that writes X
          or removes it (directly, as a listed file below a removed directory, or by the ref's DELETE); u's
          candidates are V's kind-5 segments less every segment a version of u's push names, and, in slot-keyed
          repos, V's slot when no version of u's push names it; evs computes them in step 5 from the versions step
          4 read (a part's at part time), lists them in the record of the push, part or seal (at most 2,048 ids,
          else a mark from which the sweep recomputes them) and sets window bit 4 (11.8)
who       the evs process that commits u: once its step-7 PUT answers 200, or a reread shows u committed, it
          queues u's candidates in memory; 60 s later, the readers' allowance, it rereads X's newest version and
          the network's hold/ objects (cached at most 5 s), and DELETEs each candidate that the newest version
          does not name and no hold keeps: kind-5 segments on the segment cluster, slots on the repo's metadata
          cluster (204: done, MinIO answering 204 for a missing object, cmd/object-handlers.go:2678-2691); a staged
          candidate whose version's time_ms is under 23 h old is left to its batch's evacuation, an older one
          deleted at seg/; at most 200 deletes a second and 1M queued a process (§22.8 tunes both); a stopping
          process drains its queue for up to 70 s; what it cannot delete within 10 min, or while its clock is unsure
          (§19.6), is left to the sweep; it reports as stored-byte deltas in its usage batches (§20.6) each kind-5
          segment at seg/ that it deletes or that only a hold now keeps, at its stored size, a staged one only once
          its batch was evacuated, leaving batch-resident ones to evacuation's report; slots, outside §20.7's stored
          count, report nothing
holds     a hold whose scope covers the repo keeps each candidate that existed at its placement: a staged one whose
          push's batch predates it, an uploaded one whose LastModified (a HEAD, only then) does; content created
          after placement is purged as usual, since a hold collects nothing new (owner decision 133, §21.9); an
          ERASE still destroys keys at once
staged    evacuation decides each staged segment of a committed record as it evacuates the batch: written to
          seg/<repo>/<id> (If-None-Match, its id as checksum; equal bytes on 412 are success) before the batch's
          DELETE when its version is still its path's newest committed version, was replaced under 60 s earlier, or
          a hold keeps it; dropped otherwise; a dead or duplicate record's staged segments go with it; taskworker
          reports the staged content it drops, or writes only for a hold, as negative stored-byte deltas in its
          usage batches (producer taskworker, §20.6)
sweep     evacuation, resolving each committed record that lists candidates, HEADs each candidate that its path's
          newest version does not name and no hold keeps, staged ones at seg/, and DELETEs only a present one (most
          are already gone, the committing process or an earlier evacuation having removed them, and MinIO answers a
          DELETE 204 either way, cmd/object-handlers.go:2678-2691), counting each as deleted or absent for §19.8's
          urnetwork_evs_versionless_sweep_deletes_total and purged_bytes_total{by="sweep"}, recomputing a marked
          list from the replaced versions, before the minute's batches are deleted, so a lost queue or a failed
          delete leaves content at most ~26 h; it reports nothing, the nightly pass counting what it frees; when a
          hold ends, one pass rereads the repo's versions flagged from 26 h before its placement to its end (log
          pages, then their records) and deletes what the hold kept; when §19.11's purge turns on from observe, one
          pass per admitted repo rereads its versions flagged with window bit 4 since its migration and deletes
          what observe mode kept, as at a hold's end; the side that ends each condition queues its pass, both
          idempotent: AbuseHoldPass schedules EvsSweepHoldEndTaskRequest for each hold it ends, before it deletes
          the hold/ object, and `sidecarctl evs purge-turn-on`, run in the runbook step that sets format2.purge to
          on, schedules EvsSweepTurnOnTaskRequest, a monitor row watching for observe's retained count staying flat
          while purge is on (owner decision 206); §22.8's testHookBarrier sites include the purge's hold/ reread
          and evacuation's staged decision
budget    the purge is P2 work that u pays for at admission (accounts, above); HDD DELETEs spend no NVMe budget,
          and a candidate slot's DELETE writes ~3.5 KiB a drive
```

**Drop history (owner decisions 173, 183, 184)** runs 11.7's drops as taskworker P2 work, paid at the DROP's admission:

```text
who       a job per repo, covering every drop whose start has passed, from drops/<repo>/_ (the drop table, the
          running job and the dry runs; each drop's state one of pending, cancelled, executing (with its phase),
          done, refused {locked, mismatch, verify}, held (its deletions waiting on a hold) or observed (§2.8's
          evs-28); GET .../drops (11.20) reports held as done, as owner decision 184 requires; evs writes it at each
          DROP, cancel and dry run, the job at most once a minute) and the {evsd_<repo_id>} hint, whose loss the
          nightly LIST of drops/ bounds to a day; evacuation appends a committed DROP the table lacks; an instance
          takes the job by If-Match on drops/ (none running, or the owner's lease lapsed 30 s ago by its checked
          clock), as owner until now + 2 min, renewed at each checkpoint, and stops at once on a lost If-Match
start     pending -> executing at the start CAS once not_before_ms + 25 min has passed (owner decision 183), with no
          cancel of the drop after it in its ref's history (read at the CAS); a lock then standing makes it refused
          {locked}; pending -> cancelled when a cancel commits; neither deletes anything
resolve   check each lineage's older entries against the map part or tail map_parts names, and each list against
          the ref's statements and records: the listed set must equal every version of the lineage's token paths,
          each in its epoch, below through_version, itself the DROP's write or the standing removal, else refused
          {mismatch}, which pages (§19.8); then write to dropscan/ the candidates: every segment and slot id a
          listed version names through a kind-1 locator or a slot id, less ids listed versions name only through
          kind-5 locators
horizon   the job marks only once the horizon of the repo's metadata cluster (11.13's orphans row) has passed each
          covered drop's commit time by 2 min, so every push validated before a drop has committed on a head a scan
          reads, or is dead (owner decision 204)
mark      at snapshot M, each ref's head read from the cluster after every covered drop's fence, over every ref of
          the repo (file and git mode, shared and owned, creates-only, deposit and erasure refs, overlays and DELETE
          tombstones; owner decision 173), each live version (every committed version no executing or done drop
          lists) marks the candidates it names, comparing locators and slot ids from log pages, windows and records
          and decrypting nothing; a dry run's marks for the same paths stand, so mark reads only later versions;
          marks only grow, checkpointed with the cursor
verify    at snapshot V >= M, reread from the cluster, a separate implementation (§22's oracle, shipped in
          taskworker) looks every id each live version at or below V names up in D, the unmarked candidates; any
          hit refuses the job {verify}, which pages too; it rereads each drop's ref for a cancel and the repo for a
          lock
delete    per id of D: reread hold/ and repo/ (cached at most 5 s), a covering hold moving the rest of D to held;
          HEAD seg/<repo>/<id>: a 404 with a spidx/ entry is packed (withheld until compaction), any other 404 done,
          a LastModified under 25 h before V's read young; else DELETE (204: done); slots likewise on the metadata
          cluster; the job reports each seg/ object once, at its stored size, when it is deleted or moves to held, a
          held object's DELETE after its hold reporting nothing, and slots, outside §20.7's stored count, report
          nothing; the cursor advances by CAS only past answered ids, and usage batches keyed by (scan id, cursor
          range) count freed bytes once (§20.6); refused, cancelled and observed drops delete nothing
young     candidates under 25 h old at V wait for a later round, whose mark and verify read only versions after V
holds     no hold refuses the DROP, since a refusal would reveal a sealed hold (owner decision 93); the job deletes
          nothing a hold keeps, rereads hold/ before each batch of DELETEs, one already issued completing, and
          withholds held ids from reads (404) and stored bytes, so a held drop reads, bills and lists as finished;
          once every covering hold ends it deletes them after an incremental mark and verify (owner decision 184)
bound     one job a repo and one a segment cluster at a time, others queued; at most 32 MB/s of reads and 10
          deletes a second a job; paused while the cluster's drive operations a second exceed 50% of its measured
          capacity, both from {nvb_<cluster>} (§19.6's hdd row); a repo/ deleted pauses it, a restore resumes it,
          shredding ends it
clock     an instance whose offset is unknown or over 50 ms starts and deletes nothing (§19.6); one whose lease is
          under 1 s away issues nothing, and it cancels each DELETE 50 ms before until_ms by its own clock
observe   under §19.11's format2.drop: observe (D-TEST-18), executing ends after verify with D recorded and nothing
          deleted; when drop turns on, an observed drop runs again from mark
preview   a dry run (11.20's preview route, admin) is P2, one at a time a repo and at most
          evs_drop_previews_per_day (20) a repo (§20.4): resolve and mark at a snapshot, reporting per path
          list_match against the client's count and listed_sha256, and the versions, freed, shared, inline, packed
          and young bytes; a job reuses its marks
```

**Uploads (D-EVS-34):**

```text
receipt   a segment PUT (?push=P) that stores the segment (If-None-Match, its id as x-amz-checksum-sha256) answers
          200 {EvsUploadReceipt} (11.6), MAC'd under evs's receipt key key_id and marked versionless when the
          segment's header is a kind-5 header naming P (one naming another push: 409 VERSIONING; 11.7); nothing is
          written to the metadata cluster; equal bytes carry an equal header, so a re-upload's receipt (existing,
          below) takes the same mark with no extra read
existing  if the segment exists (412), evs HEADs it (one HDD operation, only on re-uploads) and answers a receipt
          with its LastModified as upload_ms, or 409 SEGMENT_STALE when that is over 23 h old: the client re-seals
          the chain under a new key and nonce, so a new segment id
push      the push request (step 3) and each part carry one receipt per new segment, unsigned and outside the
          statement; check h: each receipt's mac is valid, for this repo, its uploader is the push's signer, and
          upload_ms is under 24 h old by evs's clock; parts are checked at part time, and their records keep their
          receipts, whose age the seal checks again
keys      receipt keys are evs configuration, rotated monthly with the previous key kept 48 h (§19.4); losing a key
          only makes pending uploads re-upload
orphans   the nightly pass first takes each metadata cluster's horizon, from one LIST of pb/: the start of the
          minute its oldest batch names, or 25 h before the LIST if that is earlier or none is left; it then LISTs
          each repo's seg/ prefix on the segment cluster, as it does for stored bytes, and its pidx/ entries; a
          segment whose LastModified + 24 h + 2 min is at or before its repo's cluster's horizon and that no pidx/
          entry lists as introduced is an orphan, which taskworker deletes by a DELETE that names its LastModified
          (§19.6), at most 10 a second a segment cluster, on clusters whose build passed §19.6's settle cases; it
          raises no fence and reads no batch, so an orphan goes 49 to 75 h after its upload (owner decision 203);
          an uncommitted path map above its ref's current epoch goes the same way, by its oldest part (11.6)
why       a push, or a seal for its parts, adopts a segment only with a receipt under 24 h old at its last check,
          writes its batch record within 5 s of that check and before its head write, in a minute that began no
          later; so every record that can adopt the segment is in a batch from before its LastModified + 24 h +
          2 min; evacuation deletes a batch only once it settled each record: committed, behind a pidx/ entry
          naming the segment, or dead, its ref fenced after its statement lapsed, which ends every attempt however
          late its head write lands, a write that stalled holding the key included, since the fence waits behind
          it; past the horizon nothing is pending, so a segment no entry names is named by no version and never
          will be, and a later upload of the same bytes is a new object, which the DELETE's LastModified refuses
```

**Quotas (§20.6, §20.7):**

```text
bytes     a repo's stored bytes are the sizes of its seg/, pack/ and hp/ objects as LIST returns them, plus the
          record lengths its head windows and log pages give for versions still in batches, minus what only a hold
          keeps (owner decision 133) and any pack or parcel whose every record a newer container's pidx/ entry
          names (the nightly pass deletes it unless held; §20.7); usage batches move the count between passes
cost      by inference, one LIST per repo prefix a night (~6 LIST/s on the metadata clusters at year two's ~555,000
          repos, the rest on the HDDs) and one head GET per ref written in the last 26 h
limit     at the storage limit, and while the network is spent, evs refuses from its cached over-limit list
          (overshooting by up to a minute), with §20.7's QuotaRefusal, segment uploads and any push that names a new
          segment or inline record; it accepts maintenance pushes, which add no payload (CONSUME, BASE, ERASE,
          PATH_EPOCH and its maps, DELETE, deletion and restore, EvsReseed), a CUT, whose one staged record only
          replaces its ref's erasure set (11.12), and re-seed uploads, an erasure's
          CLOSURE push with its payload and ?closure=1 uploads within 11.12's rekey bounds, its eraser's own
          allowance and its turn of §20.7's pacing, a DROP push that uploads no segment (an inline kept checkpoint
          within 11.12's rekey bound, a re-cited chunk set or a removed boundary; one needing an upload gets
          QuotaRefusal) and a cancel, its index rewrites waiting as merges do, and config and mailcfg pushes within
          §7.9's limits, so a full network can still change policy and erase, at the floor within the wait below, a
          record entry's `erasure` note waiting until the network is under the limit and not spent (11.12); their
          bytes count as usual; from v1, deleting versionless files adds no payload, so it is accepted at the limit
          and frees their bytes a minute after it commits; other erased or deleted ciphertext stays until v1's
          compaction (11.12)
freed     a drop's listed content counts as stored until its job deletes it or moves it to held: each seg/ object's
          stored size leaves once, in the job's usage batch within 60 s, its batch id derived from (scan id, cursor
          range), a held object's later DELETE reporting nothing; slots, outside the count, report nothing; the
          nightly pass corrects drift; inline records and packed segments count until compaction (§20.7); drops
          spend no closure allowance (owner decision 146)
wait      an eraser's allowance (§20.4's evs_closure_bytes_per_day: 64 MiB a UTC day, never under
          evs_closure_bytes_floor's 4 MiB whatever §21 sets) re-keys 60 full i/ segments a day, 3 at the floor; an
          erasure's work is its rekey objects, each one file version its CLOSUREs write: per i/ segment and per
          index file version holding one of its documents, and per index path whose stored version holds one
          (11.14's erase row), one ?closure=1 upload at its padded size (at most 1,088 KiB) or one staged record (at
          most 16 KiB); one message or entry is several when its text spans 1 MiB chunks, a backfill or late
          companion push copied it, a merge left it in an absorbed slot or a hold kept an earlier version, so no
          fixed wait per message holds; its first ERASE re-keys nothing (11.12's closure row), and it runs the rest
          as CLOSURE and ERASE pairs sized to what remains, since a push adopts only uploads under 24 h old
          (uploads, above): with B closure bytes left when its allowance first refuses it and allowance A, each UTC
          day but its last takes more than A - 1,088 KiB of whole objects, so its last pair commits after at most
          the ⌈B / (A - 1,088 KiB)⌉-th 00:00 UTC that follows, plus one turn of §20.7's pacing per upload of that
          day: at the floor, n full re-keys after the ⌈n/3⌉-th, and a one-document message no copy, chunk or hold
          multiplies (its i/ segment, one shard or large entry and its slots, under 3,008 KiB) after the next,
          within two turns; the eraser's device shows what is left and its estimate (§5.4's erasure event); each
          pair's entries keep their index fields openable to key holders until its ERASE commits, masked in search
          from the CUT (11.14); an erasure that finds a ref's erasure set full makes its CUT there, and so its
          list and rewrites, only once pending erasures complete (11.12's cut row), a wait this bound leaves out and
          its erasure event shows; below the limit and not spent, none waits but for such room
index     the search index's files count like any file (11.14; owner decision 10); its heads ride content pushes and
          stop with them at the limit or while spent; its merges, roll-ups and builds add payload and wait until the
          network is under the limit and not spent, search answering from its partitions as they stand; turning it
          off there deletes the index files first (a deletion, accepted) and writes the off settings version, an
          inline record, once the network is under the limit and not spent (11.14's off row); an erasure's CUT is
          maintenance, and its index rewrites are rekey objects of the wait row, one per index file version holding
          a chunk, copy or kept version of its documents (11.14's bound), so its wait follows from their bytes
transfer  evs reports transfer and payload deltas in 60 s usage batches whose batch id is their retry identity
          (§20.6), so a crash loses at most one window of one process's bytes: under-billing, never double-billing
```

**Durability (owner decisions 89, 90, 94, 116, 136-139, 150).** Erasure coding survives two of four hosts for objects whose every shard exists (§19.6), on 8 × PM9A3 1.92 TB at EC:4 (~7.7 TB usable); with two down, writes get 503 until the cold spare returns one. A site loss loses server-held data (§19.10), so owner devices keep full mirrors of every record-class repo and the config, slots included, as the customer's own copies (no operator copy holds slots or wraps; owner decision 90): first the indexers designated for `mirror` (§3.6), the owner's for vaults and mailboxes and an admin's for team records and the config. A phone-only user, on iOS or Android, has no indexer (owner decisions 12, 197), so the app mirrors `mailcfg` and the mailbox's `vault/` and `i/` and head-reads `m/` bodies, which a site loss erases (§2.18, §15.16). Unconsumed deposits and unmirrored repos are lost.

```text
contents  a full mirror holds every record and object a committed push names (statements, payloads, parts, segments,
          packs' contents), the repo's slot objects as their wrapped bytes (fek-wrapped or drop-HPKE), the RK ladder
          in its keychain (§10.5) and the ERASE pushes; the device that signs an ERASE keeps it for §19.10's 30-day
          re-seed window; for a versionless path, only its newest version's content, a replaced version's dropped
          when the mirror applies the replacing push; for an executed drop's listed versions, only their statements
          and served entry versions (11.11)
status    `ur status` reports each repo's coverage: full when every ref is mirrored within 1 h of its head, objects
          and slots are complete, erasures are applied and a hash check ran within 7 days; otherwise partial, naming
          what is missing; an unmirrored record-class repo is named, as is a network no indexer mirrors, and each
          indexer is listed with its services and the newest sign of it this device holds (§3.6)
erasure   immediate on the server; on each mirror, which applies each ERASE push before its next sync (11.12)
re-seed   by §19.10's runbook (POST .../reseed): config first, then groups, then per repo, placed afresh (11.8), the
          ERASE pushes devices hold first, then statements, payloads, parts, segments and pack contents past the
          current head in version order, as reseed records, and last, after every ref's history, the slots; evs
          applies every ERASE before it serves a slot, accepts a slot only if a re-seeded version names it and no
          ERASE covers its key, and takes re-seeds only for repos the projection lists live or restorable (a repo
          whose access log ends in RepoDelete past 7 d or with now is refused; one whose log ends in an unrestored
          RepoDelete without now, under 7 d old, is placed with repo/ deleted{deletion_id, its entry's time} first,
          then takes its history, group and slots (11.12's re-seed exception), so access stays refused and restore
          and the timer resume); where every surviving copy ends below a reader's pin, a repo admin's
          EvsReseed{repo, ref, version, C_v, incident} (11.6) lets that reader accept the shorter history, shown as
          a loss; a versionless path re-seeds content only for versions its devices hold, staged content as
          ordinary segment uploads, and its replaced versions as statements and entry versions reading `collected`;
          a re-seeded replacement purges as a commit does, and re-seeds take only versions past the current head, so
          no stale mirror returns purged content; DROP pushes replay with the rest of history, and listed content a
          stale mirror still holds returns only until the re-seeded repo's drops, run again from their signed state
          (not_before_ms, cancels), delete it, which §19.10's close report names
```

### 11.14 The encrypted search index

Each indexed repo keeps an encrypted, versionless trigram index that devices download whole and search locally or, on an app host whose network designates a search indexer, ask it (remote search, below), so evs never sees a query (owner decisions 151-156, 175-178). Every committer updates it. An indexer serving the repo for search is one whose `IndexerSet` names `search` at a scope covering the repo (network scope: repos other than members' owner-bound ones; member scope, or a personal network's network scope: that member's own; §7.9); it runs roll-ups, backfills and verification first (owner decisions 150, 157), but a network has none by default (owner decision 177), so each row's fallback below (the next capable writer, a desktop or the daemon, the first writer after expiry) is the default path, and a roll-up still needs a writer of the ref. This subsection owns its placement, format, upkeep, erasure and read path, remote search included; §5.9 holds the local cache (D-CORE-16), §18.4 each device's fetch policy, remote mode and targets, §16.10 and §18.5 the tools, and §15.7, §16.8 and §16.11 their documents' fields.

**Placement and settings.**

```text
in-ref    a file-mode ref whose documents change in place (a mailbox's or group inbox's ref, a general repo's or
          vault's file-mode refs) holds its own index under <root> = .ur-index/i1; a push that changes a document
          changes the index in the same statement, so one head CAS commits both (11.8)
companion git-mode refs hold no versionless file (11.7) and record-class streams take creates only (11.8), so each
          repo's are indexed on one shared file-mode ref, ur/index (<root> = i1), by companion pushes (commit path,
          below); a document's key names its ref, so one root serves every branch and stream of the repo
settings  <root>/settings, a versioned IndexSettings (files and format, below); a version counts only if one of
          the repo's admins (§8.8) signed it, else devices alarm and use the newest version an admin signed; absent,
          the index is on, with 30-day windows; `ur evs index on|off|window <days>` writes every root's settings in
          a repo, and `ur evs index status|rebuild` reports coverage and sizes or rebuilds under the lock
files     every other index file is versionless, versioning 2 (11.7), whatever the repo's versioning rules say
          (owner decision 159), and a repo lock does not refuse 2 (owner decision 168)
never     config, mailcfg and secret repos; .ur-index/ paths and index files; binaries; a mailbox's i/, r/, vault/,
          o/, forward, ra/, f/ and s/model (only m/ messages are mail documents); deposits before their ingest; an
          index covers only documents every reader of its ref can open, so a mailbox's never covers vault/
head      no single index head exists: the listing of <root> at a ref version is the index's state, each file's
          plaintext SHA-256 in its entry version (11.7's content_sha256), its buckets' and all's manifests naming
          their shards; one head file written by every committer would turn disjoint pushes into 409s
```

**Documents.**

```text
document  a text file; a mail message (§15.7's m/ files); a record entry, or a document §16.8 derives from entries
          (a run card); text past 1 MiB is one document per 1 MiB of the file, each with the next 256 B, so a
          query of up to 256 B across a boundary is found and an append to a large file re-indexes its last chunk
key       doc_key = HMAC-SHA256(K_ref, "UR evs 1.0 doc" || ref_id || u16be(len(name)) || name || u32be(chunk))[:16];
          name = the path's bytes, or a derived document's registered name (a run card run/ || run_id, a directory
          announcement a/ || announcement_id); K_ref from RK_1 (§10.5), so keys survive rotations and path epochs;
          a rename is a removal and a creation
version   the path's entry version (11.7's versions: known before the commit, never restarting, overlays
          included); a derived document's, its writer's sequence; everywhere the newest version of a key wins, and
          a removal is a tombstone at its version, as is a version that drops a chunk, for that chunk's key; a ref
          DELETE is a ref tombstone at the ref version it commits at, above every version of the ref's documents
          before it and below every re-creation's (11.7's versions)
sniff     a file is text when its first 8,000 bytes hold no NUL and are valid UTF-8 but for a cut final sequence
          (git's rule), or it opens with a UTF-16 byte-order mark and is decoded; a chunk whose key set would
          encode past 512 KiB, which nearly every query would match, is skipped; a version that turns binary or
          skipped is a tombstone at its version
fields    1 subject, 2 from, 3 to (to and cc), 4 title, 5 body; 6-15 registered per document class: §16.8's record
          entries and run cards (6 kind, 7 writer sidecar_id, 8 agent_id, 9 agent label, 10 run_id, 11 session ids,
          12 tools, 13 claim expires, 14 claim state, 15 reserved; title in 4, text in 5) and §16.11's directory
          documents (6 announcement or entry kind, 7 sidecar_id, 8 agent_id, 9 agent label, 10 run_id, 11
          member_id, 12 project, 13 branch, 14 repo_id, 15 state; a run's title or a repo's display name in 4,
          prose and the harness, host label, service names, topics and claim targets in 5); started, expires,
          private and tainted are the row's attributes, not fields; one posting set covers every field, and a
          field-scoped query is
          confirmed against the doc table row (at most 2 KiB, 256 B a field), which costs nothing for header fields
          (12.6-17.3% less index than per-field postings)
directory the team directory's derived documents (§16.11): one per announcement, from the card or repo file holding
          it, its version the Announcement's, and one per stream entry; a renewal keeps the version and writes no
          index entry, and an item dropped from its card after its end writes no tombstone, only a withdrawal
          or a revocation does (owner decision 181); the kind's window is 7 days by default (7-90; a window_days
          of 0, or no settings, means 7 there), and it refuses IndexSettings.off (owner decision 171, over owner
          decision 156's general rule, for this repo)
extract   mail: MIME-decoded (RFC 2045-2047, 2231): From, To, Cc and Subject values, text/plain parts, text/html
          parts with tags, scripts and styles stripped, and attachment names; never transport headers, attachment
          bytes or base64; files: title = the first heading or line (at most 80 B), indexed with the path, body =
          the text; records: §16.8's mapping of an entry's sealed body; the extractor's id is in every file header
```

**Normalization (normalizer 1).**

```text
text      invalid UTF-8 -> U+FFFD; NFKC; full case folding; accents: NFD, nonspacing marks after a Latin, Greek,
          Cyrillic, Arabic or Hebrew letter dropped, NFC (so が and กิน keep their marks and Hangul stays one
          syllable); each run of code points that are not letters, marks or numbers -> one space (so Indic vowel
          signs stay); subject, from, to and title cut at 1 KiB on a code point; each field padded with one space
          each side, fields joined in field order
tables    golang.org/x/text links Unicode 15.0.0 tables under Go < 1.27 and 17.0.0 under Go 1.27
          (.gomodcache/golang.org/x/text@v0.43.0/unicode/norm/tables15.0.0.go:3, tables17.0.0.go:3; cases/ alike),
          and connect and sdk declare go 1.27.3 (connect/go.mod:3, sdk/go.mod:3): normalizer 1 is Unicode 17.0.0
          from one x/text module version, at least v0.43.0, linked by every leg with one toolchain, since one
          norm.Version does not fix NFC: v0.40.0 and v0.41.0 compose U+05D2 U+0307 to U+105C9 and U+05DA U+0307 to
          U+105E4 (U+FB32 and U+FB3A alike), where v0.42.0 and v0.43.0 keep them, all reporting 17.0.0, examples
          of a defect covering 19,960 two-rune strings, supplementary letters included (U+10044 U+0307 to U+1E0A;
          §4.7), and connect/go.mod:33 and sdk/go.mod:97 still require v0.40.0 (server/go.mod:59, v0.43.0);
          headers record norm.Version, cases.UnicodeVersion and the module version; another table or module
          version is another normalizer, and a rebuild
trigrams  every 3-byte window of the normalized UTF-8; a document's set of distinct 24-bit keys; an aligned CJK
          character is one trigram, so one- and two-character queries resolve
```

**Files and format.**

```text
paths     <root>/settings, <root>/lock, <root>/a/m and <root>/a/<n> (the all partition); per bucket <root>/b/<S>/m,
          <root>/b/<S>/s/<n> (bucket shards) and <root>/b/<S>/w/<h>/<writer>/<k> (slots: <writer> the sidecar_id in
          hex, <h> its first two hex digits, k 0-15) and .../<writer>/L<seq> (large entries); per ref, beside its
          roots, its erasure set x (.ur-index/x on a file-mode ref, x on ur/index), an IndexErasureSet only a CUT
          writes (11.12); names are sealed and tokenized like any path
slot      one writer's entries, at most 16,208 B, so its record (11.6's 160 B header and one 16 B frame tag) is 16
          KiB and is staged in its push's batch (11.7); a writer's head is its slot with the highest seq, and keeps
          one entry per doc_key, a newer one replacing the writer's older one there
entry     kind (1 full, 2 diff, 3 tombstone, 4 ref tombstone) | doc_key (a ref tombstone: ref_id) | VByte version |
          VByte time (s) | diff: VByte base version | full and diff: row | full: key set; diff: added and removed
          key sets against its base's set (commit path's dependency row); encoded from its own document only
row       doc kind (file, mail, record, derived) | VByte flags (bit 0 tainted, from the push's provenance; bit 1
          outside: mail from outside the network, or an EvsImport's content; bit 2 private, a directory document's;
          bits 3-17 a field cut at its cap) | VByte size | VByte chunk | VByte trigram count | VByte started and
          expires (s; a derived document's, else 0) | ref_id (in ur/index only) | locator (the path or derived name,
          at most 512 B), subject, from, to, title (each at most 160 B) and §16.8's and §16.11's registered display
          fields (each at most 256 B), each a VByte length and UTF-8 cut on a code point; at most 2 KiB
key set   VByte count, then VByte gaps between ascending keys, the first gap key + 1
large     one entry over 8 KiB, alone, at most 1 MiB, a segment upload
shard     at most 1,032,192 B before its pad and 1 MiB with it (the Padmé step there is 16 KiB), so every index
          file is one ?closure=1 upload (11.12): "URix" | header | doc table | tombstones | dictionary | postings |
          pad
doc table live documents ascending by doc_key, a document's docid its rank: doc_key, VByte version, VByte time,
          row; no row refers to another
tombstones the deletions a bucket keeps for older partitions until its roll-up (merges, roll-up): header field
          15's count of entries ascending by kind, then key: kind (3 tombstone, 4 ref tombstone) | doc_key or
          ref_id | VByte version | VByte time (s), with no postings; a key at most once in a shard and never in
          both its tables, a ref tombstone only on ur/index, and none in an all shard
dictionary VByte block count; per block of 64 keys, its first key (3 B) and the VByte offsets of its entries and of
          its first list; per key, ascending: a byte {bits 0-1 prefix shared with the previous key of its block,
          0 for a block's first; bit 2 bitset}, the key's other bytes, VByte document count, VByte list bytes; a
          1 MiB shard's block index is typically ~10-16 KiB (more for CJK-heavy text), so a phone finds a key's
          list by frame
postings  per key, VByte gaps between ascending docids (the first, docid + 1) or a bitset of ⌈N/8⌉ bytes, whichever
          is shorter, VByte on a tie; document-level, with no positions
pad       slots and large entries: none of their own, since their sizes add per document; a shard: zero bytes,
          u32be(HMAC-SHA256(K_index_g, "pad" || SHA-256(the shard before its pad))[0:4]) mod the Padmé step at its
          length (§10.5's index key at the writer's newest generation g, which the header names), so a shard's size
          does not show which trigrams a probe document shares with others, even at a padding boundary; a CLOSURE
          pads to the replaced version's exact length instead (erasure, below)
codes     VByte, bitsets and front coding only; nothing is compressed across documents, since inbound mail and
          collaborators' commits can inject probes (a compression oracle); a shard's dictionary and lists, the
          only structures shared across documents, sit under the keyed pad
determinism a file is a function of its inputs: pinned tables and ids, docids by doc_key, ascending keys, minimal
          VByte, the shorter-list rule, blocks of 64, no clock, randomness or library-version input; headers and
          manifests are proto3 marshaled deterministically, repeated fields sorted; devices that build one file
          from the same inputs write the same plaintext, whose SHA-256 its entry version carries (11.7)
shrink    removing a document never lengthens a shard: rows, keys and lists only go, a merged VByte gap is never
          longer than the two it replaces, and the shorter-list rule picks again; so a CLOSURE rewrite always fits
          its pad
caps      a writer holds at most 16 slots in a bucket; a bucket's shards and a/ at most 3,500 files each (11.7's
          name table), past which a/ splits into a/<k>/ directories of 1,000
```

```proto
// sidecar/protocol/evsindex.proto: plaintext inside index files, which evs seals as any file; index format 1
message IndexSettings {                 // <root>/settings, versioned; only a repo admin's version counts
  bool off = 1;                         // false (the default): the index is on
  uint32 window_days = 2;               // 0 means 30; else 7-365
}
message IndexLock {                     // <root>/lock, versionless; an empty holder is free
  bytes holder_sidecar_id = 1; uint32 bucket_start_day = 2; int64 until_ms = 3;
}
message IndexErasureSet {               // x beside a ref's roots (paths, above): versionless, staged, at most
                                        // 16,208 B; only a CUT writes it (11.12)
  uint64 listed_since = 1;              // every erasure whose CUT named an index_epoch at or above it is listed,
                                        // and every pending one
  repeated IndexErasure erasures = 2;   // sorted by erasure_id
}
message IndexErasure {
  bytes erasure_id = 1;                 // 16 random bytes an erasure draws; its CLOSUREs' and ERASEs' notes name it
  bytes eraser_sidecar_id = 2;
  uint64 epoch = 3;                     // the index_epoch the CUT that added it named
  int64 cut_ms = 4;                     // that CUT's signed time_ms
  repeated IndexErased docs = 5;        // sorted by doc_key
}
message IndexErased { bytes doc_key = 1; uint64 version = 2; }  // every indexed version up to it is erased
message IndexFileHeader {               // after "URix", VByte-length-prefixed, leading each slot, large entry and shard
  uint32 format = 1;                    // 1
  uint32 type = 2;                      // 1 slot, 2 large entry, 3 bucket shard, 4 all shard
  uint32 normalizer = 3; uint32 extractor = 4; string unicode_version = 5;  // norm.Version, as linked
  uint32 bucket_start_day = 6; uint32 bucket_days = 7;   // slots, large entries and bucket shards
  bytes writer_sidecar_id = 8; uint32 seq = 9;           // slots and large entries
  repeated IndexCoverage coverage = 10; // companion heads and backfillers': per content ref, sorted by ref_id
  uint64 pad_generation = 11;           // shards: the generation whose index key drew the pad
  uint32 body_length = 12; uint32 count = 13;            // bytes before the pad; entries or documents
  string text_module_version = 14;      // golang.org/x/text's module version, as linked (runtime/debug.ReadBuildInfo)
  uint32 tombstones = 15;               // shards: the tombstone table's entries; 0 in an all shard
}
message IndexCoverage {                 // horizon: every writer's, set by a backfiller (commit path's coverage)
  bytes ref_id = 1; uint64 version = 2; bool horizon = 3;
}
message IndexManifest {                 // <root>/b/<S>/m and <root>/a/m, versionless
  uint32 start_day = 1; uint32 days = 2;          // a bucket's window
  repeated IndexShard shards = 3;                 // in document order
  repeated IndexWatermark absorbed = 4;           // a bucket's: per writer, the highest slot seq its shards hold
  uint32 rolled_through_day = 5;                  // a/m: the first day of the newest bucket rolled up
}
message IndexShard { uint32 n = 1; uint32 docs = 2; uint32 first_day = 3; uint32 last_day = 4; }  // a/: bucket days held
message IndexWatermark { bytes writer_sidecar_id = 1; uint32 seq = 2; }
```

**Buckets.**

```text
window    bucket S holds UTC days [S, S+W), S counted from 1970-01-01, its W fixed when it is created and kept in
          its files; the first starts at ⌊day/W⌋·W, each next where the newest ends, whole empty windows skipped; a
          changed W applies from the next bucket
entry     an entry goes to the bucket of its push's signed time_ms (11.6), which evs keeps within 10 min of its
          clock, or to the newest bucket already holding an entry of its document where that is newer, so clock
          skew at a boundary never leaves a newer version in an older bucket; the first writer into a window
          creates its bucket
latest    the window holding today and the one before it: 30 to 60 days at the default (owner decision 152); a
          bucket older than both is expired, and stays searched until its roll-up lands
```

**Commit path.**

```text
in-ref    the sidecar building a push extracts each changed document and appends an entry to its head: a full set,
          a diff (dependency, below) or a tombstone for a removal; the head's new version, staged, joins the push's
          statement, so the index commits with the content (owner decision 153)
dependency a diff for version v names its base by version and is written only where the index at the push's
          base keeps that base while the diff is current, in the current bucket: the document's newest entry is
          at the version v replaces (v - 1 for a path) and no tombstone, and either (a) an entry of it there lies
          outside every writer's head in this bucket (a shard, or a sealed slot or large entry its manifest has
          not absorbed) and is the base, while no writer's head holds a diff at that version, whose base a merge
          based before this push may keep instead (merges, below), or (b) it is this writer's own head entry, a
          diff whose base is the document's newest entry outside every head of this bucket: the new entry takes
          that base, its delta composed, and replaces the entry, as one entry per doc_key requires; anything else
          is full, so no entry rests on the entry it replaces or on any head; the base's chain plus one stays
          under 16 diffs and the delta under half the base's set; a re-applied or rebuilt entry (conflict, below)
          is chosen anew against what it reread; merges keep a base a head names (merges, below), a DROP writes
          its kept head full (drop, below), and an erasure removes a document's entries together
seal      when the head cannot take an entry within 16,208 B, the next slot becomes the head: the lowest k whose
          seq the bucket's manifest shows absorbed, else a new k up to 8; with none free the writer merges first
          (merges, below) or, unable to, takes up to 16 slots and alarms; an entry over 8 KiB is a large entry; a
          push's entries past 256 KiB go straight into the bucket's shards, a merge inside that push
companion for git-mode refs and streams, the committer journals the entries in its sealed store once the content
          push commits, and pushes its head on ur/index at most once a minute on 1 KiB XFS blocks, else once every
          5 minutes, while it holds any (owner decision 172), at once when its head fills, and before it sleeps or
          exits; the head's coverage names, per content ref, the newest version whose changes it holds; its own
          device searches the journal meanwhile; a git FORCE indexes the trees' difference, and a ref DELETE
          journals a ref tombstone; each entry is encoded when its head push is built (dependency, above), and one
          whose document an entry at that push's base holds at a higher version, or a ref tombstone of its ref
          deletes, is dropped as superseded, as a backfill's is; at an ERASE or CUT hint the committer drops an
          erased or listed document's journaled entries, and every companion push and 409 re-apply first applies
          the ref's erasure set (epoch, below), so a lost hint publishes nothing
conflict  only an eraser's CLOSURE, a DROP's rewrite, a roll-up's step 4 or the writer's own other push rewrites a
          head; on 409 for it the writer rereads it and re-applies its pending entries, less the erasure set's
          documents: the one versionless path a client rebases (11.7), since it holds what it wrote; a 409 on
          content rebuilds the entries with the push
epoch     every push but a CLOSURE that creates or replaces an index file version (a head, slot, large entry,
          shard, manifest, lock or the erasure set), a CUT, merge, roll-up, build, backfill or DROP rewrite
          included, names the head's index_epoch (11.8's 5d) and writes no entry, posting or field of a document
          the ref's erasure set at that epoch lists, at or below its version; on 409 INDEX_EPOCH its builder
          rereads the head and the set, drops the listed documents from its pending entries, journal and inputs,
          and rebuilds (a merge, roll-up, build or backfill reruns on the new state, a multi-part push under a new
          push id); work begun at an epoch below the set's listed_since is rebuilt from content at the head, which
          an erased document's destroyed keys no longer open, or dropped and left to backfill (coverage, below); a
          replaying reader alarms on an index push that names another epoch than the version of the ref's newest
          CUT before it; hints only speed this, and no indexer takes part
coverage  a push is indexed when it changes its writer's head (in-ref) or a coverage reaches its version; readers
          derive indexed_through, the newest version up to which every push is indexed, and show later ones as not
          yet searchable; an indexer serving the repo for search (above), else the next capable writer, backfills a
          push still unindexed 10 min after its commit into its own head and raises its horizon, holding the
          buckets and all current at its push's base, dropping superseded entries (companion, above) and skipping
          the erasure set's documents and any whose content an ERASE left unopenable
devices   desktops, the daemon and indexers index every push they make; phones and wasm index what they write and
          merge only when out of slots or on Wi-Fi while charging
```

**Merges.**

```text
when      a bucket's sealed slots (all but each writer's head) and large entries reach 128 KiB, or a writer is out
          of slots; an indexer serving the repo for search first, else a desktop or the daemon; never on an
          expired bucket
input     the bucket's manifest, shards, sealed slots and large entries at the merge's base version, and its
          writers' heads there for output's base rule alone; the new manifest's absorbed seqs and the files the
          push replaces or removes name them, and the ref's listing at that version the heads, so a reproducer
          learns its inputs from the push
output    each document's newest version among the inputs, diffs composed and the erasure set's documents left
          out (commit path's epoch row), unless its newest entries in writers' heads, at a version no input
          exceeds, are all diffs with a base among the inputs: then the oldest such base, so no merge drops a base
          a current head entry needs; a live version as a doc-table row with its postings, a tombstone in the
          tombstone table, dropping the bucket's older rows of its key, and a ref tombstone those of its ref below
          its version, each kept for older partitions until the roll-up; copies of one version are one, a
          self-contained copy kept; appended in doc_key order to the youngest shard, a next one opening at the
          cap, its older version dropped from the shard holding it, so a bucket's shards hold one version per
          document, a row or a tombstone; adjacent shards under 512 KiB together are joined; absorbed large
          entries are removed; slots stay for their writers to reuse, their tombstones in the shards
commit    one push: the shards (uploads with receipts), the manifest and the removals; a 409 means another merge
          or an erasure landed first, and the merge reruns on the new state; merges take no lock
```

**Roll-up.**

```text
trigger   an expired bucket, oldest first (owner decision 153)
runner    an indexer serving the repo for search that writes it (owner decision 150); where one exists, any writer
          committing a day past the expiry with no roll-up landed; with none, the first desktop, daemon, or phone
          on Wi-Fi while charging, that commits to the ref after the expiry, in the background (owner decision
          157); the runner must hold every bucket and the all partition at the ref's head
lock      <root>/lock: the runner takes it by a push changing it from a free version, or one whose until_ms is 10
          min past (the time check's bound), to {itself, S, now + 30 min}, renewing by the same CAS while it works;
          a 409 shows another holder, left alone until its until_ms; one roller at a time per ref
steps     1 read the bucket, the newer buckets and all at the head; 2 compute the bucket's documents as a merge
          does, writers' heads included: each key's newest version or tombstone and each ref's newest ref tombstone;
          3 per key, the newer of that and all's row stays and the other goes, all's rows of a ref below its ref
          tombstone go, and so does every version the erasure set lists; 4 append the live ones that stay in doc_key
          order to all's youngest shard, a next opening at the cap, and join adjacent shards under 512 KiB; an entry
          of a newer bucket below a version or tombstone this roll-up carries, or below a ref tombstone of its ref,
          which racing index pushes near a boundary can leave, leaves its file in the same push, rewritten in place
          and padded to its replaced length as a DROP's rewrite is; every tombstone then goes, nothing older
          remaining; 5 upload the changed shards; 6 one push, in parts if large (11.8): the shards and rewrites, a/m
          with rolled_through_day = S, the removal of b/<S>/ listing each of its files (11.7), and the lock set free
          from the version the runner holds
fence     step 6's change to the lock is the fencing token: a runner whose lock lapsed and was taken gets 409 on
          it and stops, its uploads left to 11.13's orphan rule
crash     nothing shows before step 6's head CAS (11.8): a crash leaves the bucket and all as they were and the
          lock lapses within 30 min; an unknown outcome resolves by push id (11.8's outcomes)
idempotent outputs are functions of the inputs, so a rerun writes the same plaintext; a runner that finds b/<S>/
          gone and rolled_through_day >= S stops; any other 409 (an erasure, a late merge) reruns from step 1
one       all holds one version per document: a roll-up drops the older version it supersedes, so all needs no
          dead-document bitmap, and an eraser finds a document in one shard; with step 4, every all row is older
          than each bucket entry of its key and each bucket's ref tombstone of its ref, so all holds no tombstone
cost      once per bucket length: one merge of the bucket, the changed shards' uploads, ~25 removals and, rarely,
          one newer bucket's file rewritten; the purge then deletes the bucket's and the replaced shards' content
          (owner decision 161)
```

**Reads.** Devices sync index files by position and search only their cache:

```text
pin       per (repo, ref): the reader's 11.9 pin (v, C_v) and a search manifest of the index files it holds (path,
          version, content_sha256, padded size, partition, state)
trigger   a hint (11.10) or wake (§18.7), the app coming to the foreground, the hourly resync, "search more", or a
          background window (§18.4); a search reads only the cache and triggers no fetch, except "search more"
          for the all files the device lacks in repos no designated search indexer answers (remote search, below)
replay    POST .../read from the pin returns the statements after it; a change under the index's token prefix marks
          that file; past the 4 MiB catch-up budget the reader re-pins and lists the index directories instead (one
          read per partition directory)
fetch     whole files by sync position, never a range or file a query chose: each marked file the device keeps, up
          to 64 paths and 32 MiB of ranges a read (11.9), buckets first, then all's shards youngest first, the most
          recently searched repos first; every device keeps the buckets of the repos it syncs (phones too, the
          exception to 11.11's versionless fetch rule, but the team directory's only desktops keep, §16.11), and
          each index ref's erasure set wherever it keeps or writes that ref's index, and
          desktops, the daemon and indexers keep all in the background, others at "search more" where no
          designated search indexer answers, or on Wi-Fi while charging (owner decisions 154, 178; §18.4)
verify    11.9's checks (signed statement, entry hash), then content_sha256 after decryption; a file that breaks the
          format (past 1 MiB, a dictionary out of order, a docid out of range, a tombstone table out of order or
          naming a key its doc table holds, a tombstone in an all shard, a non-canonical encoding) is dropped and
          raises SidecarEvent index_malformed {repo, ref, path, signer} (§5.4); nothing is compressed, so no
          decoder needs a memory bound
swap      the new manifest replaces the old one atomically once every kept file of the new pin is cached and the
          version table (§5.9) covers it; running searches keep their snapshot; files no manifest names are
          deleted once no search holds them
reproduce a device holding every input of a merge, roll-up or CLOSURE at its push's base version (the new
          manifest's absorbed seqs and the files the push replaces name them, the ref's listing there a merge's
          heads) builds the result and compares content_sha256 with each new file's entry version: equal, it
          caches its own output and fetches nothing; unequal, it fetches the file and raises SidecarEvent
          index_mismatch {repo, ref, path, signer: the push's} (§5.4); a device lacking an input downloads,
          raising nothing; after a CLOSURE it deletes the replaced files (§5.9); a team directory reader (§16.11)
          holding a writer's previous head and that push's bucket at its base, which the head's encoding follows
          (dependency, above), derives the new head from the card version the push wrote, fetching the head only
          if content_sha256 differs and then alarming; merges run at 7.0-9.7 ns a posting natively, 2.5-5x that
          in wasm, so a bucket merge is sub-second; phones reproduce only in the foreground or a background
          window, else download
retained  readers search every bucket present, expired ones included, so search stays complete while a roll-up is
          pending; a device keeping all applies the roll-up by reproduction or download, then drops the bucket; one
          keeping only latest drops it, its instant coverage the last W to 2W days; one holding a stale all keeps
          the dropped bucket's files, masked as usual, until its all copy shows the bucket rolled up (a/m's
          rolled_through_day), an ERASE occurs in the repo or 2W days pass, after which "search more" refreshes all
          before answering for that span and reports the gap
collected a fetch of a replaced index file that answers `collected` (11.9) rereads the head, drops what it fetched of
          that file and fetches the newest version; only writers' heads change often, each one read, and all's
          shards change only at roll-ups and erasures
subscribe file-mode refs need no new lease, since index files change in the same push as content; a repo whose
          git-mode refs or record streams are indexed adds one whole-ref lease on its ur/index ref (11.10)
traffic   at 100 messages a day a phone's heads and sealed slots cost ~4-6 MB a month at about ten syncs a day, and
          merges nothing by reproduction (~10-25 MB a month downloaded without it); a first five-year all is
          ~110-165 MB (~27-41 at 25 a day, ~330-495 at 300); every download debits the transfer balance (owner
          decision 10), and a device that reproduces shows the server nothing
```

```text
query     normalized by normalizer 1 under the tables the index records; space-separated terms are ANDed; "a
          quoted phrase" is one term; -term drops a hit only where this host confirms the term; a term of 1-2 bytes
          matches as a whole word through its space-padded trigrams (" a "; " go" and "go "), since fields are padded
          and punctuation folds to spaces; a CJK run is one substring term; from:, subject: and date ranges filter
          doc-table fields before any posting is read (§16.10 adds agent, run, kind and path prefix), a date range
          inside the buckets never needing all; a query with no trigram matches nothing
plan      per (repo, ref), newest first: the current bucket, the previous one, any expired and retained buckets,
          then all's shards youngest first (scope latest stops before all); per shard the query's trigrams are
          looked up rarest first, one absent ending that shard, and absent from every shard of a partition, that
          partition; only the query's lists are decoded, in their 64 KiB frames, and intersected rarest first,
          galloping into VByte runs and ANDing bitsets; heads and unmerged slots are scanned per document, whose key
          set or composed diff chain (chains, below) must hold every query trigram; a median query touches
          374-73,000 postings (p90 under 120,000), about a millisecond in wasm, frame decryption dominating, within
          11.15's 4 MiB working set
chains    a diff resolves by its doc_key and base version in its bucket's shards, sealed slots and large entries,
          the base's chain likewise, copies of one version being one and a self-contained copy answering first; a
          diff below its key's newest entry (newest, below) is no candidate, resolved or not, and alarms nothing,
          since a merge keeps only a current head entry's base; a current diff's chain that does not resolve, or
          whose composed set's size is not the diff row's trigram count, breaks the format: index_malformed
          (verify, above) names its signer, the document reads not yet searchable in coverage, never no match, and
          a host with the text re-enters that version full, as a backfill
newest    per doc key, the entry with the highest version over every partition the device holds, tombstones
          included, is current; a hit from partition X counts only if X holds that entry, it is not a tombstone, no
          ref tombstone of its ref (its row's ref_id) is above its version, and no ERASE names its key; equal
          versions in two partitions (during a roll-up) are the same content; every all row being older than each
          bucket entry of its key (roll-up's one row), a device keeping only the buckets masks exactly too; each
          candidate is answered from the device's version table (§5.9), built as it caches the files, never by
          collecting the partitions' keys at search time: lazily in rank order, as confirmation is, one probe reading
          a page of each run through a 256 KiB cache a process, so a search's mask state is its pending candidates
          (at most 20,000 a partition, too_broad past that) whatever the partitions hold; keys an ERASE names are
          masked in every partition until the rewritten files are cached, as is each document the ref's erasure set
          lists, at or below its version, from the CUT on, the version table holding both as erased; a branch's
          search adds its base ref's documents for paths it has not changed (11.7's overlays), probing the table for
          the branch's own key of each such path; hits stream as each partition finishes
confirm   hosts with the document's text (a desktop or indexer mirroring the ref, a mounted working tree, an indexer
          answering a remote search, whose verified hits the phone labels "verified by <device>") verify each
          candidate, decrypted, normalized and checked for every term and phrase, lazily in rank order until a
          page (50) is full, the count reading "about n" until all are checked, with a snippet around the first
          match; other hosts confirm a hit whose display fields contain the query, or, for mail, whose i/ address or
          200 B snippet does (§15.7), or whose body they already cache, and show the rest as possible matches from
          subject, from and date, fetching no body to check them, opening one confirming or rejecting it (owner
          decision 155); a desktop without a document's text shows it as possible; on 20 Newsgroups, headers alone
          confirmed 11% of true rare-word matches, headers and the snippet 26%
rank      1 matches (verified and confirmed), newest first, or by term density on hosts with the text; 2 possible
          matches by trigram overlap J = |T(q)| / n_d (n_d the row's trigram count), fewest distinct trigrams first,
          ties newest first, the app able to switch to newest first; 3 near hits (typos, below) by J against the
          corrected query; on 20 Newsgroups overlap raised P@5 for rare words from recency's 0.19 to 0.45 (0.54 with
          confirmations first), the true hit first from 21% to 68%, and for common words and two-word phrases from
          0.48 and 0.17 to 0.93 and 0.60 with confirmations first; a long document assembles a query's trigrams by
          chance far more often than a short one
typos     when a term has fewer than 3 exact hits, or on request, never for CJK: desktops expand it against a local
          vocabulary (the text's words with document counts) by trigram similarity (words padded with two spaces
          before and one after, shared over union trigrams, threshold 0.3, ties by count), the intended word first
          76% of the time and in the top five 92%; phones test each one-edit variant over the term's script whose
          padded trigrams all exist and share a document, display-vocabulary words first (the subjects, senders and
          i/ snippets they hold), 66% and 83%, at a median ~0.2M posting probes a term (0.4-2 ms natively); a hit
          says "showing results for <word>", one correction a term; documents missing up to 3 of a typo's trigrams
          gave 324-3,564 candidates for 8-13 true ones, so that rule is not used
cjk       UTF-8 lead and continuation bytes are disjoint (RFC 3629), so a trigram starting with a 3-byte
          character's lead byte is that character: a one-character CJK, kana or Hangul query is one exact list, a
          two-character one four lists, a 4-byte character two trigrams; two or more characters give candidates,
          verified on desktops and possible on phones; §22 measures a Japanese and a Chinese corpus; NFKC and case
          folding are stable for assigned characters, so a reader on other tables misses only characters assigned
          between them, says so, and the next writer on the newer tables rebuilds
coverage  a content version newer than the index's coverage is not yet searchable: hosts with the text index it into
          a local overlay at once, an indexer answering a remote search covering it from that overlay and reporting
          the rest as uncovered, and phones show "n recent changes not yet searchable" until the backfill lands;
          hosts with the text re-extract each document version a delta adds, check each tombstone against its
          path's history and reproduce merges and roll-ups, on a mismatch using their own result and raising
          SidecarEvent index_mismatch {repo, ref, path, signer} (§5.4), indexers for every repo they read (owner
          decision 150); phones compare an opened document with its row; every writer of a ref writes its index,
          so an agent could otherwise hide a document or plant hits
off       a ref with no index: hosts with the text scan it (exact, linear), phones and browsers match names and,
          for mail, i/'s fields, and the result says "index off"; an index in a newer format turns search off for
          that ref, status "update"; no search reaches a secret, config or mailcfg repo; an owner-bound repo's
          reader that is not one of its owner's consented devices (an EvsShare subject, the audit reader) deposits
          §16.8's read receipt naming the index files before it decrypts them
```

**Remote search (owner decisions 175-178).** With no designated search indexer, which is the default (owner decision 177), every repo follows owner decision 155's download. Where one is designated, an app host's "search more", never a keystroke, sends its query end to end over §6.6's RPC on the pair's Network contract (`SEARCH` 0x1404, `SEARCH_RESULT` 0x1405; D-PROTO-21) to an indexer that may answer, which searches what it holds and returns verified hits. §18.4 owns the requester's mode (`on`, `own`, `off`), the notice it shows before another member's device is first asked, and the UI states; the engine is root `search_remote_*.go`.

```text
who       per repo, first an own search indexer (a device of the requester's member) that reads it; an owner-bound
          repo only on a consented device of its owner (owner decision 126), so the requester's own vault and
          mailbox never reach another member, and a repo another member shared by EvsShare only on that owner's
          search indexer; a team repo (general, record, team_record, the directory) otherwise on one network-scope
          search indexer that reads it, a tagged one answering only team repos, its sponsor named; in a personal
          network every indexer is own; never secret, config, mailcfg or deposit-only repos
eligible  eligible(d, R, p), which each side evaluates in its own newest verified state, so a stale or forged view
          reaches nothing the other refuses: d's newest IndexerSet at some scope names search, unretired, and d is
          not revoked, parked or suspended; d is a ur daemon host advertising Hello feature bit 0; p is an admitted
          member device, untagged and not ephemeral, revoked, parked or suspended (in v1 an app host); d and p are
          in RepoReaders(R) (§8.12); for R owner-bound to M, consented(d, M) (§8.5) and p reads R as M's consented
          device or by an EvsShare; for a team R, d is a device of p's member or its designation is network scope;
          d holds R's all current under its background policy (§18.4), with R's index on in a format d reads
auth      the phone checks d's IndexerSet, admission and consent evidence in its own config (owner decision 6) and,
          before the first request, §6.4's identity binding with HelloResult's bit 0, a failure alarming and
          dropping d until its admission changes; each reply's coverage carries the (v, C_v) its cursor pinned,
          matched at the phone's own version (else §6.4's FORK alarm) or at its next sync, never prompting a read
order     own search indexers first (the one that answered within 10 min, then by rendezvous hash of the two
          sidecar_ids), hedged in parallel; then, where `who` allows, other members' by rendezvous hash of
          (member_id, indexer sidecar_id), one at a time and sticky until it fails, so a member's queries reach at
          most one other device for a set of repos; repos sharing a first choice go in one request of at most 64,
          and the phone remembers for 24 h which repos each indexer served
failover  no first page within Search.RemoteTimeout (3 s, 5 s metered), RESOURCE_EXHAUSTED, UNIMPLEMENTED or a repo
          refused in coverage sends those repos to the next eligible indexer; liveness comes from the foreground
          Hello and §6.10's keepalive (online 10 min after a HelloResult or Pong within 3 s, a failed indexer
          skipped for 2 min; D-SDK-27); an indexer first asked on failover gets its bit-1 Hello then, which opens
          its §6.10 window at that search; a repo no indexer answers, in off mode or behind an unanswered notice
          follows owner decision 155's download; an indexer seen again while the search screen is open is asked
          once more for the repos that fell back
```

```proto
// sidecar/protocol/search.proto (11.14): remote search over §6.6's RPC, MessageType SEARCH 0x1404 and
// SEARCH_RESULT 0x1405 (§6.11). No oneof (§6.11's rule); nothing compressed; every body padded (sizes, below).
message SearchRequest {
  uint32 search_version = 1;          // 1
  fixed64 search_id = 2;              // random per search, chosen by the requester; names the cursor
  uint32 page = 3;                    // 0 opens the search; n asks page n once page n-1 arrived; a repeat
                                      //   of n returns page n again
  fixed64 supersedes = 4;             // an earlier search_id of this requester, whose work and cursor end; 0 none
  uint32 steps = 5;                   // the reply's size in 16 KiB steps, 1-4; v1 requesters send 1
  uint32 scope = 6;                   // page 0 only: 1 latest (buckets), 2 all (buckets, then all)
  string query = 7;                   // page 0 only: §16.10's grammar, <= 512 B and 16 terms, NFC as typed;
                                      //   the indexer normalizes it with each index's normalizer
  repeated SearchRepo repos = 8;      // page 0 only: <= 64 repos the requester reads and asks of this indexer
  int64 since_ms = 9;                 // page 0 only; 0 unbounded
  int64 until_ms = 10;
  SearchFilters filters = 11;         // page 0 only: §16.10's filters
  bool fuzzy = 12;                    // page 0 only: near hits even with 3 or more exact hits
  reserved 13, 14;                    // group_by and withhold_untrusted, for later requesters
  bytes pad = 15;                     // zeros, sizing the body to exactly 4,016 B
}
message SearchRepo { bytes repo_id = 1; bytes ref_id = 2; }   // ref_id empty: the repo's default ref
message SearchFilters {
  repeated string agents = 1;         // agent labels, or agent ids in hex
  repeated bytes sidecar_ids = 2;
  repeated bytes member_ids = 3;
  repeated bytes run_ids = 4;
  repeated string session_ids = 5;
  repeated uint32 kinds = 6;          // RECORD.md's kinds
  string path_prefix = 7;
  repeated SearchField fields = 8;    // field:text terms
}
message SearchField { uint32 field = 1; string text = 2; }    // 11.14's field numbers (1 subject, 2 from, ...)
message SearchReply {
  uint32 search_version = 1;          // the version answered
  uint32 min_version = 2;             // this indexer's supported range
  uint32 max_version = 3;
  fixed64 search_id = 4;
  uint32 page = 5;
  uint32 status = 6;                  // SearchStatus
  uint32 phase = 7;                   // 1 latest, 2 all, 3 done
  bool complete = 8;                  // no later page holds a hit
  int64 checked_through_ms = 9;       // SERVED_TEXT repos: every candidate newer than this was checked, and
                                      //   returned on this or an earlier page if it matched
  repeated SearchCoverage coverage = 10;   // page 0: one per repo named; later pages: none
  repeated SearchHit hits = 11;       // as many as fit the steps, at most 20
  SearchCounts counts = 12;
  bytes pad = 15;                     // zeros, sizing the body to exactly steps x 16,384 B
}
enum SearchStatus {
  SEARCH_STATUS_UNSPECIFIED = 0; SEARCH_OK = 1; SEARCH_PARTIAL = 2; SEARCH_TOO_BROAD = 3;
  SEARCH_CURSOR_EXPIRED = 4; SEARCH_INVALID = 5; SEARCH_UNSUPPORTED_VERSION = 6;
}
message SearchCoverage {
  bytes repo_id = 1;
  bytes ref_id = 2;
  uint32 served = 3;                  // SearchServed
  uint64 ref_version = 4;             // the (v, C_v) the cursor pinned (11.9)
  bytes chain = 5;
  int64 ref_time_ms = 6;              // that version's signed time
  int64 latest_from_ms = 7;           // the oldest bucket day searched
  uint32 uncovered = 8;               // pushes past indexed_through that this indexer's text does not cover
}
enum SearchServed {
  SEARCH_SERVED_UNSPECIFIED = 0; SERVED_TEXT = 1; SERVED_INDEX = 2; REFUSED_NOT_READER = 3;
  REFUSED_NOT_CONSENTED = 4; REFUSED_SCOPE = 5; REFUSED_INDEX_OFF = 6; REFUSED_ALL_ABSENT = 7;
  REFUSED_FORMAT = 8;
}
message SearchHit {
  bytes repo_id = 1;
  bytes ref_id = 2;
  bytes doc_key = 3;                  // 11.14's doc_key, the same on every reader, so merges match
  uint64 version = 4;
  int64 time_ms = 5;
  uint32 doc_kind = 6;                // 1 file, 2 mail, 3 record, 4 derived (a run card)
  string locator = 7;                 // the path or derived name, <= 512 B, which the requester opens
  uint32 state = 8;                   // 1 verified, 2 confirmed, 3 possible, 4 near
  string correction = 9;              // near: the corrected term
  uint32 partition = 10;              // 1 current, 2 previous, 3 older or retained, 4 all
  uint32 trust = 11;                  // 1 own, 2 member, 3 untrusted, relative to the requester (§16.10)
  bytes signer = 12;                  // the version's writer sidecar_id
  repeated SearchField fields = 13;   // display fields from the row, at most 8, each <= 256 B
  string snippet = 14;                // verified hits: <= 200 B around the first match
  uint32 line = 15;                   // files: the first matching line
}
message SearchCounts { uint32 checked = 1; uint32 verified = 2; uint32 possible = 3; uint32 near = 4; uint32 masked = 5; }
```

```text
exchange  page 0 carries the query, scope (v1 phones send 2), repos, since, until, filters and fuzzy; the indexer
          authorizes, pins a snapshot per repo and answers with coverage for every repo named and the first hits;
          later pages carry only search_version, search_id, page, supersedes, steps and pad; one page in flight a
          search, page n only after n-1 arrived, a repeat of n returning the cursor's last reply unchanged
ranking   across SERVED_TEXT repos, candidates go newest first by (time, doc_key), buckets first, then all's shards
          youngest first, each verified against the text before it is returned; SERVED_INDEX repos' confirmed and
          possible hits follow, ranked as a phone ranks them; near hits come last, when a term has fewer than 3
          exact hits or fuzzy is set; checked_through_ms is the newest candidate not yet checked, so every newer
          one was checked and, if verified, returned; phase 1 inside the buckets, 2 inside all, 3 done
sizes     every request body exactly 4,016 B, one envelope, timeout_ms always 10,000; every reply body exactly
          steps x 16,384 B (steps 1-4, 1 in v1), failures after parsing included; nothing compressed, no Cancel,
          no early or short reply; errors decided before parsing are small envelope Errors that depend on the
          requester's identity, rate or build, never on a query: UNAUTHENTICATED (§6.4's identity check),
          PERMISSION_DENIED (not an admitted, untagged, non-ephemeral member device, or no search designation or
          Search.RemoteServe off), RESOURCE_EXHAUSTED (retry_after_ms), UNIMPLEMENTED
status    OK; PARTIAL (2 s of CPU or 1,000 verifications ended the page, more to come); TOO_BROAD (a partition over
          20,000 candidates: header-confirmed hits and counts, complete); CURSOR_EXPIRED (search_id unknown, idle
          10 min, superseded, a third search of the requester, or an ERASE, CUT or lost read in its scope; the phone
          reopens once); INVALID (a wrong size, a non-zero pad, a query over 512 B or 16 terms, over 64 repos, a
          malformed filter); UNSUPPORTED_VERSION; per repo in coverage, SERVED_TEXT, SERVED_INDEX or a refusal,
          which sends that repo on (failover, above)
limits    requester: at most 2 open searches an indexer, a third's page 0 superseding the oldest, 30 requests a
          minute (burst 10), 64 repos a request, a larger scope split by indexer, then by 64; indexer: per
          requester the same, else RESOURCE_EXHAUSTED before parsing; Search.RemoteSearchCount (4) computing beside
          §16.10's 4 local searches, RemoteQueueCount (16) waiting at most 1 s, RemoteCpuPerMinute (30 s of CPU a
          minute), RemoteCursorCount (64) cursors idle at most 10 min, each at most 16 KiB of resume state plus its
          last reply; a lost reply is retried by page and answered from the cursor, not §6.6's idempotency cache,
          which holds only mutating methods' responses, and SEARCH mutates nothing (§6.6)
serve     the indexer authorizes in its own state, naming a refused repo in coverage, never as an error; it runs
          this subsection's plan over the buckets, retained buckets and all it holds, plus its local overlay for
          pushes past indexed_through that its text covers, verifying against its mirror, mounted tree or bare
          repository (11.11, 11.13), with masks, newest wins and searchable_days; it reads nothing from evs, api or
          gkm for a remote search, reporting in coverage what it lacks, so evs sees nothing of one on either device;
          a daemon designated for search keeps all of every repo it reads within Search.CacheByteCount (16 GiB),
          answers no index-off repo (REFUSED_INDEX_OFF), holds at most 8 MiB of working set a search, its masks
          probing the version table (newest, above), and persists no query (§5.9, D-CORE-17)
phones    never serve: readers ignore search on a read_only or ephemeral subject, ur indexer add refuses it on an
          app host, and app-host builds set Search.RemoteServe false and never advertise bit 0; a laptop daemon may
          serve, within the CPU window
merge     per (repo, ref, doc_key) over the remote pages and the phone's own hits: the higher version wins, and at
          one version a remote verified state wins; in a SERVED_TEXT repo a local possible or near hit with time_ms
          above checked_through_ms and at most ref_time_ms - 10 min that no page returned moves to a collapsed "n
          not matched by <device>" row; the phone's own confirmed hits always stay, hits newer than the pinned
          version keep the phone's state, and SERVED_INDEX hits merge as possible, dropping nothing; a hit from a
          repo the request did not name or the phone does not read is dropped with an alarm; the phone's ERASE
          and erasure-set masks and read checks (§5.9) apply; an opened hit is extracted and checked against the
          query, its doc_key and version, and a mismatch, or a local confirmed hit inside the checked span that
          no page
          returned, raises SidecarEvent search_alarm {mismatch or omission, indexer, repo} (§5.4), three mismatches
          in a day skipping that indexer for 24 h
```

**Erasure, holds, limits, on and off.**

```text
keys      in slot-keyed repos (record-class repos, group inboxes) each versionless index file keeps one key (settings
          is versioned), in a slot that only
          that path's versions name, reused by each next version until checkpoint rule (4), a CLOSURE or a rekey
          draws a fresh one in a new slot (11.7's versionless keys), so an overwrite writes no slot; in general
          repos it sits in the segment header (11.6) and goes with the segment
cut       an erasure's first push on the index's ref (the entry's own, or ur/index) is its CUT (11.12): it adds its
          documents to the ref's erasure set (x, Files and format) and moves the ref's index_epoch, so every index
          push but a CLOSURE built before it is refused and rebuilt without them (commit path's epoch row); readers
          mask each listed document, at or below its version, from the CUT on; a set version from a signer who may
          not erase its documents is ignored and alarms (the directory, §16.11)
erase     at a head at or after its CUT the eraser lists every index file holding the document: each writer's slots
          and large entries in each bucket, the bucket shard holding it, and the one all shard holding it, found by
          a/m's days and that shard's doc table (I-EVS-11), a list no later push lengthens; CLOSURE pushes on the
          index's ref rewrite each in place without the document (at the storage limit or while spent, in pairs
          sized to the eraser's allowance, 11.13's wait), padded to the replaced version's exact length, so 11.12's
          rekey bound holds and the size shows nothing, each under a fresh key in a new slot; each pair's ERASE
          destroys the old slots' keys (the entry's own going with the erasure's first ERASE, owner decision 61), and
          every stored version of those files, staged bytes still in a batch included, shares one of them; the purge
          deletes the old ciphertext and slots a minute later; the ERASEs also name the key of every index path whose
          retained version still holds the document (a version a hold kept, a writer slot reused after a merge, a
          shard the document left, a bucket a roll-up removed, found from the ref's history), a live one rewritten
          under a fresh key by a CLOSURE first, so no stored version keeps an openable key (owner decisions 61,
          133; FI-19); a CLOSURE refused 409 for a path another push changed after the list rereads that path's
          history and rebuilds; no watch follows an ERASE, and no indexer takes part
bound     an erasure's cost is the index file versions erase lists, not its document count: one message or entry with
          one version is one document per 1 MiB chunk of its text, each chunk in a writer's slot or a large entry,
          then a bucket shard, then all, and a backfill, a late companion push, an absorbed slot or a hold adds
          copies; 11.13's wait row bounds it from those bytes, the eraser's allowance and its turns (owner decision
          146; §20.7), and the eraser's device shows what is left (§5.4's erasure event); staged slots count as the
          CLOSURE's inline records
writers   a writer whose head an erasure rewrote, or whose push a CUT outdated, gets 409 at its next push and
          re-applies its entries without the erasure set's documents (commit path)
holds     a hold keeps the index content that existed at its placement, staged copies written to seg/ at
          evacuation, and later churn is purged as usual, since a hold collects nothing new (11.13's hold rule;
          owner decisions 133, 161); it never pauses an ERASE, so slot-keyed index content stays unreadable
limit     at the storage limit or while spent, heads ride content pushes and stop with them; merges, roll-ups and
          builds add payload and wait, search answering from the partitions as they stand; an erasure's CUT is
          maintenance, and its CLOSURE is taken within 11.12's bounds and its eraser's allowance, each index file
          one ?closure=1 upload
drop      a DROP push also rewrites in place, without the listed versions, each index file holding a listed version
          of a dropped path, padded to the replaced length as erase's rewrite is, with no ERASE or CLOSURE flag; the
          kept head's entries enter the signer's own head full, since no older version stays as a base; the purge
          deletes the replaced ciphertext a minute later, and a writer whose head it rewrote re-applies (writers,
          above); a signer not holding the index leaves the rewrite to an indexer serving the repo for search, else
          the next capable writer, within 10 min as a backfill, searches masking the older version meanwhile (newest
          wins); the rewrite lands at commit, so a cancel loses nothing; hosts with the text reproduce it and raise
          index_mismatch on one that left a listed version's postings; a DROP refused 409 INDEX_EPOCH is rebuilt and
          signed again by its device under the person's same confirmation, or sent without its index rewrites, left
          to that backfill
off       an admin's settings version turns the index off (never the team directory's); that device, or an
          indexer, removes <root> but settings in one push listing each file, whose content the purge deletes,
          the ref's erasure set staying for a later build to apply, and never DELETEing ur/index, which would
          drop the settings file whose absence means on; at the storage
          limit or while spent the settings version, a new inline record, is refused, so the device removes the
          files first (a deletion, accepted), writes the off version once under the limit and not spent, then
          removes heads writers re-created meanwhile
on        a device holding the repo's text builds the index under the lock: documents changed in the latest windows
          into their buckets' shards, older ones into all, in pushes of parts, the erasure set's documents left out
          (commit path's epoch row); migration to storage format 2 builds it the same way (§23)
rebuild   a new normalizer or index format builds .ur-index/i2 beside .ur-index/i1, then removes i1; the ref's
          erasure set and index_epoch serve both roots
site loss the index re-seeds as versionless files do, its erasure set first, or a device holding the text rebuilds
          it, applying that set: an indexer serving the repo for search, else its next capable writer (§19.10; owner
          decision 177)
```

**What the server sees** (§2.8's evs-26):

```text
shape     one versionless directory per indexed ref, or the ur/index ref: a small staged overwrite in each indexed
          push (the writer's head, whose size step shows roughly how much text the push indexed, as its content
          sizes already do); a shard rewrite per ~128 KiB of entries; once per window a bulk removal and shard
          rewrites, rarely with one newer bucket's file rewritten in place (roll-up's step 4); CUTs and CLOSUREs at
          erasure (a CUT a staged rewrite of its ref's erasure set, whose size step shows roughly how many
          documents pending erasures hold, and a 409 INDEX_EPOCH for each index push it outdates), and a drop's
          rewrites, shaped as an erasure's; on ur/index, pushes that trail content pushes by up to a minute on
          1 KiB blocks, else five minutes (owner decision 172)
reads     which index files each device reads, and when (evs-4, evs-7): a first sync of a repo's index, a fetch to
          verify and each opened hit show that the device read those files, and a phone's or browser's on-demand
          "search more" that no indexer answered, that its person searched past the buckets; background sync and
          reproduction hide most of it
remote    an app host's remote search: relays see each request's and page's time and fixed size, and api's contract
          rows each contract's creation and, for a pair that §6.11's bit 1 marks, one report a contract at each
          §6.10 window's end, both directions, the window's floor whatever up to five exchanges ran in it (C19;
          owner decisions 176, 188); evs sees nothing (§2.8's connect-5)
never     a query, which documents match it, or which trigrams documents share: fetches follow sync position, sizes
          are Padmé-padded (shards by the keyed pad as well), and nothing is compressed across documents
```

### 11.15 Performance and concurrency (verified in §22)

| Path | Target |
|---|---|
| Commit → hint at an online subscriber | p50 ≤ 300 ms, p99 ≤ 2 s |
| Local push (≤ 64 KiB) → remote commit, desktop | p50 ≤ 1 s |
| Agent commit on device A → visible on device B | p50 ≤ 2 s, p99 ≤ 5 s |
| Head read, file ≤ 1 MiB | p50 ≤ 250 ms on desktop, ≤ 600 ms on mobile |
| Head read 100 versions behind its pin | statements ≤ 100 KiB, verify ≤ 20 ms on mobile |
| Head read of a path a later 100,000-change push left alone | adjacent-leaf proofs of ~1.4 KiB a path level, never its change list |
| Throughput per repo | ≥ 50 MB/s on desktop, ≥ 5 MB/s on mobile |
| evs working set | ≤ 4 MiB in the iOS app process (§18.4); never a whole file, segment or delta base over 1 MiB in RAM |
| Drive writes per push on the metadata set | ≤ 43 KiB per drive at 2× year one's mix; ≤ 0.8 DWPD and 50% of rated write IOPS at any load but P0 work past the refill, which owner decision 186 exempts (11.13) |
| Versionless content after its replacement | readable ≥ 60 s; deleted within ~2 min, ≤ ~26 h when its committing process failed (the sweep) |
| Staged versionless content | ≤ 4 KiB per drive a version; no HDD write when replaced before its batch's evacuation |
| Index entries per push | proportional to the changed text where 11.14's dependency row allows a diff (an edit in the current bucket onto a base outside every head, or composed onto its own head diff's base), else the document's whole key set, as when another writer's head holds its previous version; a 1 MiB document per changed chunk of a large file (11.14) |
| Drive writes per indexed push | in-ref ~7 KiB on 4 KiB blocks, ~4.3 on 1 KiB; a companion push a whole push, at most one a minute per writer on 1 KiB blocks, else one every 5 minutes (11.13; owner decision 172) |
| Latest buckets, 100 messages a day | both ≤ ~5.4 MB; each file ≤ 1 MiB, decrypted by frame within the working set above |
| Search masks | one probe per candidate, lazily in rank order, into §5.9's version table through 256 KiB of cached pages a process; no set of the partitions' keys in memory; the table updated at a swap within 1 MiB (11.14) |
| Cold "search more" | first progress ≤ 500 ms; each shard's hits ≤ 100 ms after it lands, ≤ 300 ms on phones and page Workers; complete within the missing bytes over the throughput, plus 1 s (§16.10's cold contract) |
| A drop | nothing deleted before `not_before_ms` + 25 min, nor before evacuation's horizon passes the drop's commit by 2 min, about 25 to 26 h after a `now` drop (owner decision 204); a job's two passes read ≤ 32 MB/s; 10,000 segments deleted in about 17 min; ≤ ~0.3 MB written a metadata drive for a drop whose job runs 10 min |

**Concurrency.** Pushes to one ref meet only at its head's If-Match: a file-mode loser with disjoint paths retries inside evs, so one ref sustains roughly 20-50 pushes/s; a git-mode loser gets a stock non-fast-forward and merges. Distinct refs never contend. In the twenty-agent test (§22), agents write their own refs in real time, and a merge into main every 60 s meets another in its ~60 ms window about 2% of the time, then merges again.

### 11.16 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Plaintext paths (PLAN.md:59), or a sealed client index ordered in Postgres (the drafted Q-EVS-1 (c)) | Server-side paths; or only repos and refs visible | Names, shape and sizes in the clear; or 3-RTT cold reads, client-side GC, Postgres on the storage path | Ruled out (owner directive; owner decision 2) |
| A per-ref lock with a fencing token | No retries | One more round trip; a stalled holder still writes, since no store condition spans two objects | Rejected; the git-mode seal lease lives in the head |
| Disjoint git landing, then a merge push by any writer | No client retry | No defined tip until the merge; two pushes per landing; automatic merges | Rejected (owner decision 141) |
| A server-made deterministic merge commit | No client work | Merges shared branches automatically (sidecar/design/market2.md:519) | Used only for file-mode export |
| Folds every ~10 s or 32 versions | Fresher entries | Agents pushing every ~10 s fold each push alone: ~3 index writes, ~54 KiB a drive | Rejected |
| One head PUT for several pushes, or batches per repo | Fewer writes | Gains only past ~50 pushes/s a ref; most repos see under one a second | Rejected |
| A head per version, created If-None-Match | ~5 KiB less a push | Owner decision 2 fixes the head If-Match as the commit point | Rejected |
| MinIO pools for the metadata tier | One namespace | A multi-pool PUT checks its precondition only in the pool it picks (11.3) | Rejected (owner decision 145) |
| go-git as the local server | No git binary | v6 is a beta (https://github.com/go-git/go-git) | Rejected |
| Versioning per ref, or a separate per-path attribute object | Simplest purge | The index must change in the content's push; or a mutable object outside the commit point | Rejected |
| Purge at evacuation, 25-26 h after replacement | No queue in evs; a day to restore | Replaced content lingers a day | Rejected (owner decision 161); kept as the sweep |
| Small versionless content as its own NVMe object, HDD segment or inline record | Simple | ~12.5 KiB a drive a version; an HDD PUT and DELETE a version; or kept in packs | Rejected: staged in batches |
| A purge watermark in batch headers | No redundant HEADs at the sweep | A field, look-ahead reads and a rule for ~1% of year two's HDD operations | Only if §22.8's hdd row shows the redundant HEADs matter |
| A fresh key and slot per versionless version in slot-keyed repos | Uniform | A slot create (~9 KiB a drive) and delete per overwrite | Rejected: one key per path |
| A server-registered index prefix confining versioning 2 | evs enforces it | A prefix per ref, re-registered every path epoch | Rejected: readers check |
| A hold pausing every purge | Simple | Keeps content created after placement | Rejected (owner decision 133) |
| Content-defined chunking for versionless dedup | Dedups insertions | Chunk sizes fingerprint content; keyed CDC's keys are recoverable (ePrint 2025/558) | Rejected |
| Versionless git blobs | No LFS | Breaks exact oids, export and old checkouts | Rejected |
| Trust git-lfs's pre-push uploads to cover a new tip | No daemon work | git-lfs uploads only objects of commits the remote's old tip does not reach, so a force push to an ancestor, a new ref at old history or `--no-verify` uploads nothing | Rejected: the tip check (11.11) |
| Touch every object a new tip requires on each push | No timing margin | A new branch over k objects writes k versions | Rejected: touch only versions 5 days old or more |
| A two-phase prune: condemn, wait, then remove | Pushes write only for condemned objects | A format field, and a fence every push must time | Rejected |
| Keep the newest n versions, or d days | Undo | n× storage, or due lists | Rejected (owner decision 165) |
| A new index delta file per commit | No overwrite | An entry, a marker and its collection: ~15-37 KiB a push | Rejected |
| Sealing an index head into a new path per seal | Simple | ~27-40 KiB of path churn per seal | Rejected: a reused slot ring |
| Merging each full head into shards at once | No sealed slots | A <= 1 MiB HDD PUT and DELETE per seal (~125 a second in year two) | Rejected |
| One index head file per ref | One read gives the state | Every committer rewrites one path, so disjoint pushes collide | Rejected |
| zstd over shards, blocks or doc tables | ~25-40% smaller | A size oracle for injected mail and commits (DBREACH, https://crypto.unc.edu/papers/dbreach.pdf) | Rejected |
| Padmé alone on shards | Simpler | A probe at a padding boundary reads a trigram's presence per rebuild | Rejected: a keyed pad |
| 16 MiB all objects | ~10-25% smaller | Past 11.12's 1,088 KiB closure upload, so an erasure at the floor takes days | Rejected |
| All shards by doc-key hash range | A document's shard is computable | Every roll-up rewrites every shard | Rejected for roll-up order |
| Dead-document bitmaps in all | Cheaper roll-ups | Old postings linger; erasure still rewrites | Rejected: one version per document |
| Diffs on any earlier entry in the bucket | Smaller entries | The head's own replacement, or a merge absorbing a newer copy, drops the base a current diff needs | Rejected: bases outside every head, which merges keep (11.14's dependency row) |
| Every index entry full, no diffs | Self-contained entries | Each edit of a large file uploads its whole key set again as a large entry | Rejected: diffs onto bases outside every head |
| Deletions as empty doc-table rows or flag bits | No new table | An empty posting set is also a live document with no trigrams, and names no ref | Rejected: a tombstone table |
| Tombstones kept in all | Roll-ups never touch a newer bucket | All keeps every deletion for good | Rejected: a roll-up removes an older newer-bucket entry instead |
| A mask set of every bucket key, built per search | Simple | ~7.6 MiB of keys alone at 500,000 changed files, past a phone's 4 MiB working set | Rejected: §5.9's version table, probed per candidate |
| A watch after the ERASE, by the eraser's device or an indexer, re-closing racing copies (the 41ba6670 rule) | No format change | Not a barrier: a crash, or a push delayed past the watch, publishes a copy under a key the ERASE never named; no indexer exists by default (owner decision 177) | Rejected: the CUT and index epoch (11.12) |
| A per-document erasure check at evs | Exact | evs cannot see documents (owner directive) | Rejected: an opaque epoch and a sealed erasure set |
| The epoch fencing CLOSUREs too | One rule | Another eraser's CUT would void a CLOSURE whose uploads its eraser paid for at the floor (owner decision 146) | Rejected: CLOSUREs only replace versions, and path CAS orders them |
| A fixed per-message erasure wait, indexing at most one 1 MiB document a message | A next-day promise | Backfill copies, absorbed slots and holds still multiply copies, and long messages lose search | Rejected: the wait from closure bytes, with progress (11.13) |
| A companion ref per git ref | Per-branch isolation | A head and roll-ups per agent branch, no shared companion push | Rejected: one `ur/index` per repo |
| Drop by a path spec alone, with no signed list | A smaller payload | Epoch and token mistakes delete another path's history; no cross-check | Rejected: an explicit list that the client and resolve cross-check |
| Keep the old head unlisted, with no re-write | No extra version | Its diff chain keeps listed content reconstructable | Rejected: the head is written again |
| A reverse citation index (segment to citing versions) kept in `pidx/` at evacuation | Scans read `pidx/` only | A permanent NVMe cost on every push for a rare action | Later, if §22.8's `drop` row shows scans binding |
| Same-mode or no-stream reuse rules, so scans skip refs | Smaller scans | New format-1 rules, each a hole a skipped ref could fall through | Rejected: every ref is scanned (owner decision 173) |
| One scan, no independent verify | Half the reads | One scanner bug deletes live content | Rejected |
| Rewrite shared slots and packs without the listed parts | Frees more at once | evs cannot see key indexes or record ownership, so a wrong list destroys live keys | Rejected; compaction owns containers |
| A hold refuses the DROP | A visible refusal | Reveals sealed holds | Rejected (owner decision 184) |
| k-of-n signatures for a drop | Collusion needed | Blocks routine hygiene, where a window does the same | Rejected (owner decision 183) |
| A boundary below the head | Keeps recent history | Keep-last-n by another name | Rejected (owner decision 165) |
| The ref's owner may drop on owned refs | Self-service | Bypasses repo admins | Rejected: repo admins (owner decision 173) |
| Store the drop in the access log | Ordered with grants | Not ordered with the path's versions, so the head re-write cannot be atomic with it | Rejected: a push on the ref |
| Ask an indexer for verified hits | No download; verified hits, better typo correction, exact CJK checks | Relays see timing; the indexer sees the query | Chosen where an indexer is designated, none by default (owner decisions 175, 177, 178) |
| Replies sized to the next 16 KiB step their content needs | Fewer bytes for short results | Sizes show a result-size class | Rejected: one fixed step (steps = 1), a round trip per ~20 hits |
| Requests sized to the query and scope, or padded to 16 KiB | Fewer bytes; or one step for both | Lengths show query and scope size; or 4× the bytes and five frames, hiding nothing more | Rejected: one 4,016 B body |
| An envelope Error for every failure, or a Cancel message | Simple; frees indexer work sooner | Sizes after parsing show failure kinds; a Cancel's small frame shows an abandoned search | Rejected: padded statuses after parsing; supersede and expiry |
| A contract class of its own | Policy could cut it | The gate marks which contracts carry search; a new class for C13 to seal | Rejected: the pair's Network contract, data or control (D-PROTO-21); admins retire `search` instead |
| Any member device answers, with no designation | More coverage | No anchor for disclosure; any member could collect queries | Rejected: owner decision 175 says indexers |
| Other members' indexers only by opt-in | Strongest privacy | Turns off what owner decision 175 turns on | Rejected |
| Blind the query: trigram ids, or PIR | The indexer learns less | Trigrams reveal the query; verification needs the words; PIR costs orders of magnitude more | Rejected |
| Phones as indexers | More indexers | Battery, 16-32 MiB budgets, no all, no text, iOS suspends | Rejected |
| The indexer brings partitions current before answering | Fresher results | evs sees a fetch at every search | Rejected: it answers from what it holds |
| The owner's indexer deposits a receipt for an `EvsShare` reader | Parity with D-MCP-18 | An evs write at search time | Rejected: the local served record (§5.9) |
| Remote search on every keystroke | Verified bucket hits while typing | Relays and team indexers see every keystroke's query | Rejected: "search more" only |
| Group by agent on the indexer | One call for agent views | Paging and merging groups across two sources | Rejected for v1: phones group the hits they hold |

### 11.17 Decisions proposed

**D-EVS-1 (proposed).** Plaintext git lives only on reading sidecars; evs holds segments, index entries and signed pushes and never parses git. *Why:* server plaintext is a design error (CONVENTIONS §0).

**D-EVS-2 (withdrawn).** Superseded by owner decision 2: the token tree replaced the sealed client index (D-EVS-12).

**D-EVS-3 (proposed).** Blobs are git-delta chains under 11.7's checkpoint rules. *Why:* PLAN.md:50 and :63; a reconstruction reads at most 17 records and 1.5× the file size.

**D-EVS-4 (withdrawn).** Superseded by owner decision 2: ref CAS lives in `head/` objects (D-EVS-13).

**D-EVS-5 (proposed).** Only the §5 identity key signs pushes, which name `sidecar_id` and `client_id` and are pinned as (ref, version, C_v); agent attribution is sealed. *Why:* I-4, I-16 and PLAN.md:59.

**D-EVS-6 (withdrawn).** Superseded by owner decision 2: the server keeps a path index of objects (D-EVS-12).

**D-EVS-7 (withdrawn).** Superseded by owner decision 24: the local git tier ships with `git-remote-ur` (D-EVS-15).

**D-EVS-8 (proposed).** Owned refs sync in real time; shared git-mode refs serialize by tip CAS, with explicit client merges, and file-mode refs land disjoint pushes by path-level CAS; no conflict is resolved automatically. *Why:* sidecar/design/market2.md:513-531; owner decisions 2, 24, 141.

**D-EVS-9 (withdrawn).** Superseded by owner decision 2: usage flows as events (D-EVS-16).

**D-EVS-10 (proposed).** Record-class owned refs are append-only streams, and deposits end in a reader's CONSUME. *Why:* §16's chains need streams a stolen writer cannot rewrite (Q-ARCH-9 (a)).

**D-EVS-11 (proposed).** Kinds are fixed at creation; `vault`, `mailbox` and `secret` (any number a member, such as §13.8's ACME account keys) bind `owner_member_id` and are read only by the owner's consented devices (§8.5), their `EvsShare`s' subjects and owner decision 63's audit reader. *Why:* owner decision 126; sessions and mail stay with their owner unless shared (R-ACL-11, R-KEYS-9, R-TRUST-7).

**D-EVS-12 (proposed).** Paths are 11.6-11.7's token tree, re-keyed by a signed map bound to its source head and keyed by its hash, plus a tail for paths created since: due at once on a member device's removal or a compromise, new names in name-bearing repos waiting for it, else (other shrinks, authorization expiries) due within 24 h, or, while two source epochs stand, once one drops; re-keyed when a mapper commits, which a creation block of at most 2 min, 10 min past due, assures; up to three source epochs overlap, the third kept for an immediate epoch, each cluster's copies sharing 250 operations a second that §19.9 plans by live entries per rotating ref, the copy translating directory rows a fold carried and removals during it leaving removed entries, so no read falls back to a stale source, and no name created after cut-over gets a source-epoch token. *Why:* owner decisions 2 and 64, with no index rewrite per CI reap, no epoch starved by steady creation and no batched epoch's copy backlog taking the source an immediate epoch needs.

**D-EVS-13 (proposed).** evs is stateless over 11.8's objects, each repo's on the cluster its `place/` names: only the head If-Match decides; all else a push writes is immutable or an index cache that committed records rebuild; readers use only versions the head history names. *Why:* owner decisions 2, 20, 145; no lost response or cleanup removes committed data.

**D-EVS-14 (proposed).** Subscriptions are token-prefix leases per path epoch, Redis soft state that holders re-create after a loss, answered once the lease exists; hints carry only server-held fields, versioned by the push sequence, a Redis counter seeded from the master's clock, so it restarts above every earlier value. *Why:* owner decisions 2, 17, 136.

**D-EVS-15 (proposed).** The local tier is the system git behind the daemon's authenticating fronts plus `git-remote-ur`, with plaintext only on loopback, TLS or ssh beyond it, and owner decision 81's committer hook. *Why:* owner decisions 24, 81, 84 and 130, without a go-git server.

**D-EVS-16 (proposed).** Stored bytes are each repo's `seg/`, `pack/` and `hp/` object sizes plus its batch-resident record lengths, less held-only objects and superseded containers, counted nightly and moved by usage batches; at the limit only payload-adding uploads and pushes stop, except re-seeding, an erasure's bounded CLOSURE push with its uploads, a DROP push that uploads no segment, and config and mailcfg pushes within §7.9's limits. *Why:* stateless evs has no counter to lock, and shared batches cannot be listed per repo.

**D-EVS-17 (proposed).** Owner devices, first the indexers designated for `mirror` (owner decision 150), mirror record-class repos and the config in full, slots included, and re-seed evs after a site loss, erasures first and slots last; a repo admin's EvsReseed lets readers accept a shorter history as a loss. *Why:* owner decisions 90 and 94 keep no operator copy; a slotless mirror cannot open unread entries; an indexer's mirror stays current while other devices sleep.

**D-EVS-18 (proposed).** The write gate is the head CAS: a commit's authorization and generation pins pass §10.6's predicate against evs's newest authorization state, read within 5 s, and never fall below the head's. *Why:* owner decision 5 leaves no server transaction, and a separate gate object cannot fence the commit.

**D-EVS-19 (proposed).** Deletion is a `repo/` state machine that follows the access log: RepoDelete or RepoRestore is filed first and the route, or taskworker's reconciler, applies it; restore and shred contend for one CAS, the timer waiting out api's 7-day RepoRestore window; terminal `shredding` precedes any key destruction, and deletion ids fence jobs. *Why:* owner decisions 82, 133; no restore returns a keyless repo, and no re-seed trusts a log that shows a deleted repo live.

**D-EVS-20 (proposed).** A push over 1 MiB or 1,024 entry writes travels in up to 1,024 hashed parts that its signed statement binds and one head PUT commits; a git-mode one holds a seal lease of at most 2 min. *Why:* imports and large merges stay one atomic, verifiable git push.

**D-EVS-21 (proposed).** 11.13 budgets every metadata write in drive bytes, which bound its IOs too, with leases, the push sequence and gkm acks in Redis and a per-network fair share that sheds the heaviest network first. *Why:* every drive takes every write (owner decisions 21, 116, 140).

**D-EVS-22 (decided; owner decision 141).** Refs have a mode fixed at creation: git-mode refs commit only on their tip and keep the original commits; file-mode refs use path-level CAS and export one deterministic commit per version; head mode writes file-mode refs only. *Why:* git commits bind tree and parents (owner decisions 2, 24, 81).

**D-EVS-23 (proposed).** A push id names one statement, whose retry returns its original version; an unknown outcome resolves from the head and at most two log pages, or stays unknown; a refusal the head does not settle for good is answered only once a head CAS records the push id, its code and its statement's time bound in the head, at most 8 records a ref and one a second, else 429, and every attempt of that push id that reads the record gets that refusal; no answer deletes anything, and evacuation deletes only a dead push's slots. *Why:* a store can apply a write and lose its response, and another attempt of the same push id, a client's retry or the lb's re-send, can reach evs at any time, even after another attempt's answer reached the client, so only state the commit point covers keeps a refusal true; a fence timed by attempts' arrival cannot.

**D-EVS-24 (proposed).** Log pages hold the signed statements (at most 1 KiB each), and the head window names each recent one's place and hash; head readers verify every statement after their pin and the one behind each entry they read. *Why:* owner decision 7 for every reader (Q-EVS-6), at one block per head write.

**D-EVS-25 (proposed).** Orphans are found without the log: hourly evacuation resolves every batch record, which names every slot its push wrote, fencing a pending record's ref, one with no head by a placeholder head; and an unadopted segment or path map, found by the nightly LIST, is deleted only once evacuation's horizon has passed every batch that could adopt it (owner decision 203). *Why:* an upload that never reached the log is otherwise invisible; a grace period cannot fence a late commit, and a fence cannot reach a ref that does not exist yet, but every commit leaves its record first.

**D-EVS-26 (proposed).** Erasure is a committed ERASE push that destroys every key of every representation: each retained version, each derived-field chain, the search index's files included (re-keyed first, by a CLOSURE push that only replaces committed file versions, each new chain within Padmé of the one it replaces, taken at the storage limit with size-bounded uploads within its eraser's own rate and daily allowance, which has a floor §21 cannot lower) and the deposit, which is slot-keyed; with the index, a CUT on each index ref first fences its publication (D-EVS-66), and its first ERASE takes the entry's own keys, which re-key nothing. *Why:* owner decisions 61, 133, 146; a shared index or live deposit would otherwise outlive the erasure, and no admin's closures spend another's.

**D-EVS-27 (proposed).** Segments are addressed only by content id, locators carry a kind with two reserved values, and `spidx/` is reserved, so packing needs no format change. *Why:* locators are signed and cannot be rewritten; Q-OPS-2.

**D-EVS-28 (proposed).** The local tier publishes through git's proc-receive hook with per-ref statuses, no atomic pushes and a durable journal resolved by push id. *Why:* a pre-receive hook cannot report per-ref outcomes or survive a crash between the remote and local updates.

**D-EVS-29 (proposed).** The head holds the commit point and a window of 64-byte entries (push id, statement hash prefix, place, path digest, flags), at most ~9 KiB: one block on each drive per commit. *Why:* every push rewrites the head on all 8 drives, plus a backup (owner decision 140).

**D-EVS-30 (proposed).** evs group-commits push, part and seal records into immutable minute-bucketed batches of at most 256 KiB, written at once when load is light, within 20 ms under load, and evacuated whole after 25-26 h. *Why:* bursts, and a process's stream to a cluster past ~50 pushes/s, share one create and one delete per batch (owner decision 140); at ~8 evs processes a set near capacity sees ~1-1.6 records a batch.

**D-EVS-31 (proposed).** `idx/` holds only committed versions, folded lazily (the oldest 64 at 96 unfolded, the rest after 10 min idle, always before a page-out and in a path epoch's own commit), a file's newest version per fold and every directory delta in order; a removal writes, If-Match and only over an older version, a marker that keeps the path's version, and markers go in head-announced collection windows once the horizon passes them by a base range, their DELETEs cancelled before the window ends, and folds over covered markers held past it, by margins that cover the clock bounds and the cancel's lag; a creation's version is max(its push's effective base version, on an overlay its base_version plus its chain's base versions, a standing removal's) + 1, so a path's versions never restart once its marker goes, nor fall below those it held on a base ref; reads and the CAS read an entry only after a head and merge the window versions after that head's folded_through. *Why:* a busy path is written once per fold, nothing pending evicts a committed version (owner decision 140), and a DELETE, which MinIO applies unconditionally, could remove an entry a later fold wrote; versions must only rise, for 5g and the search index's newest-wins rule (owner decision 148).

**D-EVS-32 (proposed).** Hourly evacuation moves each repo's records and log pages older than 24 h into one HDD pack once they reach 256 KiB; below that it moves the records into NVMe parcels while the log pages wait at log/, both packing within 7 d. *Why:* owner decision 136's residency, with whole-batch deletes and no tiny HDD objects.

**D-EVS-33 (proposed).** evs, gkm, api and taskworker share each metadata cluster's write budget (0.8 DWPD and 50% of rated write IOPS on its busiest drive not under heal), a bucket that every measured drive byte drains, P0's included. P0 safety work (`rev/` and `proj/` writes, `repo/` lifecycle, shred steps, ERASE, CUT and CLOSURE pushes within their rate and every slot rewrite, Removes and REMOVE rotations) issues at once, never queued or refused, its bytes reported by kind and drawn from the bucket down to zero, past which they are P0's excess, forgiven; every other class issues only while the bucket holds it, restarting when a P0 storm ends and ramping up as the bucket refills, so their writes stay within the budget less the P0 writes the bucket held, and their IOs within it too (at least 512 B each, ≤ 39% of rated). P1 pays at admission for itself and the P2 work it causes, the deferred part moving into a prepaid wallet that funded P2 spends and the allowance never pays again, so a steady load is admitted at the full physical rate; unfunded P2 takes at most 40% of the allowance; P2 runs in deadline order; per-network fair queues refuse the heaviest network first, never P0 work; segment PUTs likewise queue per network on each segment cluster, refused heaviest first (503) past 50% of §19.6's measured drive-operation capacity. *Why:* owner decision 140, which owner decision 186 amends for P0 writes only: P0 work always runs at once and the wear bound exempts it, since per-tenant rates bound no cluster's aggregate safety work (100 large Teams each shrinking every 5 minutes ask ~2.9 TiB a day a drive, about twice the refill), so a P0 storm can wear the drives past 0.8 DWPD and their 1 DWPD rating, disclosed with §19.8's P0 alarms (11.21; Q-EVS-24); owner decision 190 forgives P0's excess, so a cluster's pushes and evacuation restart when a storm ends, at the cost of the storm's extra wear, ~0.23 drive-writes a 6-hour storm at that stress, which §19.8 counts against the rating; charging P2 at admission and again from the allowance would admit ~27% fewer pushes; a capped P2 would let evacuation outgrow 26 h.

**D-EVS-34 (proposed).** Segment uploads write nothing to the metadata cluster: evs returns a MAC'd receipt that the push presents, and GC deletes an unadopted segment only once every batch record that could adopt it has been evacuated, 49 h or more after its upload, by a DELETE that names the object (owner decision 203). *Why:* markers cost three writes per segment.

**D-EVS-35 (proposed).** Versioning is a per-version setting of a file, signed in its entry version: 0 keeps every version, 1 only the newest's content, 2 the same for the search index's files; config and mailcfg repos, git-mode refs and creates-only refs refuse 1 and 2, and a repo lock refuses 1 (owner decision 168). *Why:* owner decisions 158-160; authority histories and exact git need every version.

**D-EVS-36 (proposed).** Versionless content lives in one-record kind-5 segments whose headers name the introducing push, cited only by that path's next version or a rename target of the push removing it; content padding to at most 16 KiB is staged in its batch; slot-keyed repos keep one key per versionless path. *Why:* path-level CAS fences every citation; short-lived small content costs no HDD write or NVMe object, and an overwrite no slot.

**D-EVS-37 (proposed).** The committing evs process deletes replaced versionless content 60 s after the commit is certain; evacuation drops replaced staged content and HEADs every candidate, deleting any still present, so a lost queue leaves content at most ~26 h; a hold keeps only content that existed at its placement. *Why:* owner decisions 161 and 133, with no new object family or metadata write.

**D-EVS-38 (proposed).** Turning versioning off keeps every version written while it was on; turning it on starts history there, possibly adopting the replaced version's uploads; a replaced versionless version reads `collected`. *Why:* owner decision 158's per-revision rule.

**D-EVS-39 (proposed).** Format 1 reserves and refuses every format-2 construct as FORMAT_UNSUPPORTED; a repo migrates when its first push carrying one raises `repo/`'s format. *Why:* owner decision 163, with nothing rewritten.

**D-EVS-40 (proposed).** Directory removals and ref DELETEs list each versionless file below them, and the removal fold carries an omitted file's content ids into its marker, whose collection deletes them. *Why:* evs computes candidates at the commit; an omission costs at most a marker's life of storage.

**D-EVS-41 (proposed).** From v1, git-lfs pointers are backed by the repo's versionless `ur/lfs` store through a standalone transfer agent that touches each object it uploads; before a git-mode tip commits, the local tier's tip check touches each object the tip requires that the old tip did not and whose newest version is 5 days old or more, and refuses the update, naming the objects and `git lfs push --object-id`, when one is gone; an indexer or a device holding every ref prunes daily, from one read of every ref's head, what no tip of that read and no commit, upload or touch of the last N days references, N being 30 or a repo setting of at least 7 days (11.11). *Why:* owner decisions 141 and 162; reachability is a client computation; git-lfs uploads only what the remote's old tip does not reach, so a force push to an ancestor, a new ref at old history or a skipped hook uploads nothing; touches settle a prune's race at path-level CAS, and a version under 5 days old outlasts every prune start that could miss the tip.

**D-EVS-42 (proposed).** Writers set a new path's versioning from the rules in force at its creation: the repo's, else its network's, else versionless above 64 MiB, a present rule set replacing the next entirely; it persists until a writer changes it. *Why:* owner decision 164; no rule edit flips existing paths (owner decision 167).

**D-EVS-43 (proposed).** A file-mode ref whose documents change in place holds its index under `.ur-index/i1`, changed in the push that changes a document; git-mode refs and streams share `ur/index`, written by companion pushes; every index file but its admin-signed settings is versionless; config, mailcfg and secret repos get none, and an index covers only documents every reader of its ref opens. *Why:* owner decisions 151 and 159; vault entries have narrower readers than their mailbox; it narrows owner decision 156 for secret repos: each holds one credential (11.12), which an index would only copy into postings, and MCP never reads them (§16.6).

**D-EVS-44 (proposed).** Index format 1 is document-level byte trigrams of normalized text on Unicode 17.0.0, one posting set over every field in VByte gaps or bitsets, a front-coded dictionary, doc tables and tombstone tables, with no compression across documents, a keyed pad on shards and byte-exact determinism. *Why:* substring and CJK search at about a word index's size; no compression oracle for injected mail; devices rebuild and verify instead of downloading; a merged deletion must still mask older partitions, and an empty posting set cannot say so.

**D-EVS-45 (proposed).** Buckets are UTC windows of the repo's W days (30, or 7-365) holding entries by signed push time, an entry going instead to the newest bucket already holding its document where that is newer; latest is the current and previous window, and expired buckets roll up oldest first. *Why:* owner decisions 152 and 153; every device computes the same boundaries.

**D-EVS-46 (proposed).** Each writer appends to a head of at most 16,208 B, staged in its push's batch, sealing into a ring of up to 8 reused slots that merges absorb by watermark into bucket shards. A diff rests only on its document's previous version outside every head in the current bucket, or carries over the base of the writer's own head diff it replaces, and merges keep a base a head names. *Why:* no index path per commit or seal: a new path costs ~27-40 KiB a drive, an overwrite one entry rewrite per fold; a head keeping one entry per doc_key would otherwise overwrite its own diff's base, and the purge leaves no older copy.

**D-EVS-47 (proposed).** Merges and roll-ups are functions of their base version's files, a merge's writers' heads included; a roll-up is one push moving its bucket into all under a versionless lock whose path-level CAS fences a stale runner, applying the bucket's tombstones, which its shards keep until then, and removing any older entry racing pushes left in a newer bucket, so all holds no tombstone; readers search every bucket present. *Why:* crash safety and idempotence with no server state (owner decision 157); a deletion must outlive the slot that wrote it until all's row is gone.

**D-EVS-48 (proposed).** Index files are at most 1 MiB; an erasure's CLOSURE rewrites those holding the document, listed at or after its CUT, in place, padded to their replaced lengths, under fresh keys in new slots, the ERASE destroying the old slots' keys, which every stored version shares. *Why:* one closure upload per file within owner decision 146's floor; one destroyed key covers staged copies (owner decision 61).

**D-EVS-49 (proposed).** Companion pushes carry a committer's journaled entries at most once a minute per writer on 1 KiB blocks, else every 5 minutes (owner decision 172), with coverage; an indexer, else the next capable writer, backfills pushes unindexed after 10 min. *Why:* a companion per content push would cost a whole push each.

**D-EVS-50 (proposed).** Devices fetch whole index files only by sync position, and at "search more" every all shard they lack, youngest first; a search reads only the cache; a device holding a merge's, roll-up's or rewrite's inputs reproduces it against `content_sha256`, downloading only on a mismatch, which alarms. *Why:* the server learns when a device syncs, never what it searches (owner decisions 154, 155); reproduction spares most bucket and roll-up traffic.

**D-EVS-51 (proposed).** A device with a stale cached all keeps the buckets rolled up since, masked, until its all shows them rolled up, an ERASE occurs in the repo or 2W days pass. *Why:* complete coverage with no refresh at search time.

**D-EVS-52 (proposed).** Newest wins: a hit counts only if its partition holds the document's highest version, tombstones and ref tombstones included, masked per candidate through the device's version table (§5.9) over the partitions it holds, the ERASE lists and the erasure sets. *Why:* owner decision 152; erased documents never show while caches catch up; a mask built from every bucket key at each search outgrows a phone's working set.

**D-EVS-53 (proposed).** Hosts with the text verify every candidate they show; others confirm from display fields, mail's `i/` and cached bodies, label the rest possible, fetch nothing to check them, and exclude only confirmed containment. *Why:* owner decision 155; no query-dependent fetch.

**D-EVS-54 (proposed).** Possible matches rank by trigram overlap, after matches and before near hits; under 3 exact hits, desktops expand a term against a local vocabulary and phones by one-edit variants checked in the index. *Why:* on 20 Newsgroups P@5 rose from 0.19 to 0.45 (0.54 with confirmations first), the true hit first from 21% to 68%; the intended word came first 76% (desktops) and 66% (phones) of the time, with no word index (owner decision 155).

**D-EVS-55 (proposed).** Terms under 3 bytes match as whole words through boundary trigrams, and CJK runs are substring terms. *Why:* short words would match nothing, and a CJK character is one trigram (owner decision 151).

**D-EVS-56 (proposed).** Hosts with the text re-extract each new document, check each tombstone against its path's history and reproduce merges and roll-ups, raising `index_mismatch` naming the signer and using their own result; indexers do so for every repo they read. *Why:* every writer of a ref writes its index (owner decisions 150, 151).

**D-EVS-57 (proposed).** An app host's "search more" asks one of its network's designated search indexers (none by default) over §6.6's RPC on the pair's Network contract; the indexer authorizes the requester and each repo in its own state, pins its cached snapshot, verifies candidates newest first against its text and answers pages with each repo's coverage and pinned (v, C_v), fetching nothing from evs, api or gkm; with none answering, owner decision 155 applies. *Why:* owner decisions 175 and 177; evs stays blind on both devices, and a forged or stale requester view reaches nothing the indexer refuses.

**D-EVS-58 (proposed).** A repo is asked first of the requester's own search indexers that read it, an owner-bound repo only of its owner's consented ones, a team repo otherwise of one network-scope search indexer and an `EvsShare`'d repo of its owner's, each other member only after the app has named them once (§18.4); no app host, browser Worker, or ephemeral or read_only sidecar answers. *Why:* owner decisions 126, 150, 175, 177 and 178; queries stay on the member's devices where they can, reach another's only knowingly and where entitled, and never fan out.

**D-EVS-59 (proposed).** Every request body is exactly 4,016 B and every reply the requester's steps × 16,384 B (1 in v1), failures after parsing included; only failures before parsing are small Errors, and nothing is compressed, cancelled or answered early. *Why:* owner decision 175's padding; with every size set by the requester, relays learn when searches and pages run and the indexer's answer time, never what was asked or found.

**D-EVS-60 (proposed).** The phone merges per doc key, the newest version winning and, at one version, a remote verified state; in a repo the indexer verifies by text, a local possible or near hit no page returned collapses into a "not matched" row when it is newer than `checked_through_ms` and at least 10 min older than the pinned version; the phone's confirmed hits, ERASE masks and read checks always apply, and an opened hit is checked. *Why:* pages stream newest first, so only the checked span proves a candidate false; this bounds what a faulty indexer can hide.

**D-EVS-61 (proposed).** The `directory` kind has one repo per team network, record-class: a shared file-mode `cards` ref, whose `d/`, `r/` and `q/` paths are versionless from its format 2 and checked by readers against their writers; per-writer streams; `ur/index`; and `erasure`, whose ERASE, CUT and CLOSURE take `admin`, as every repo's, held only by its consented, not-read-only admins, a repo owner's revocation erasing through §16.11's erasure runner. Its index is on by kind, with a 7-day window, and refuses `off`; its group seats readers under §7.9's leaves rule; its daemons read moved streams 64 to a request (11.9). *Why:* owner decision 171 gives this repo's index every announcement, specific beside owner decision 156; evs sees no path, so readers enforce writers, as Q-EVS-3's prefix rules do, but a reader's check after a key is destroyed restores nothing, so erasure needs an authority evs checks first; owner decisions 177, 181, 182.

**D-EVS-62 (proposed).** A drop is a DROP push (flag 256) on the path's file-mode ref, signed by one repo admin (owner-bound: only a consented, not-read-only device of the owner; never MCP), listing per lineage every dropped version by entry hash and the version that stays; it waits 7 days, in which any repo admin may cancel, `now` skipping the window as RepoDelete's does, and a lock voids it; config and mailcfg repos, git-mode, creates-only and derived refs, directory paths and versionless heads refuse it. *Why:* owner decisions 126, 173 and 183; a push orders the drop with the path's versions and the head fences it.

**D-EVS-63 (proposed).** A drop deletes only kind-1 segments and slots that only listed versions name; statements, hashes and entry versions without inline records stay, so history verifies, and listed inline content waits for compaction, unserved; the kept head is written as a fresh checkpoint or re-cited chunk set; readers show pending, then dropped, never missing or tampered. *Why:* no diff chain keeps dropped content, and no drop reads as tampering.

**D-EVS-64 (proposed).** From its commit no push may cite a listed version; the job starts 25 min after the window, marks every ref's live versions at one snapshot once evacuation's horizon has passed each covered drop's commit by 2 min (owner decision 204), verifies with a separate implementation at a later one, deletes only objects over 25 h old, and resumes from `drops/`. *Why:* a mutator cannot move a reference past a scan of immutable history, and two implementations must agree before any DELETE.

**D-EVS-65 (proposed).** A hold defers a drop's deletions silently, the drop reading, listing and billing as finished; stored bytes fall as the job deletes; the DROP rewrites listed versions out of the index; mirrors apply it; compaction may later remove listed inline content, keeping every statement and every byte a live version needs. *Why:* owner decisions 93, 133, 159, 165 and 184.

**D-EVS-66 (proposed).** An erasure's first push on each index ref of its documents is a CUT that rewrites the ref's erasure set, a versionless list of the documents pending erasure there, and moves the head's `index_epoch` to its own version; every other push creating or replacing an index file but a CLOSURE names that epoch at its head CAS, else 409 INDEX_EPOCH, and its builder has applied the set, so delayed, resealed and retried index work (fresh writer-head and large-entry paths, merges, roll-ups, builds, backfills, DROP rewrites and companion journals) cannot publish a listed document after the cut; the eraser lists index files only after it, so no watch follows the ERASE; an erasure resumes from the sets and its ERASE notes on its eraser's device, else after 25 h on another device of its member that may erase, else, once its eraser is revoked, on any such device. *Why:* the meta review's F09: path CAS fences only paths a CLOSURE rewrites, a hint is not a barrier and a network has no indexer by default (owner decision 177), so FI-19 needs a durable cut at the index's one commit point; evs enforces an opaque counter and the set stays sealed (owner directive); CLOSUREs stay outside the epoch so that no eraser's CUT voids another's paid uploads (owner decision 146).

**D-EVS-67 (proposed).** An erasure's wait is stated from its rekey objects, not per message: at the storage limit or while spent, with B closure bytes left when its allowance first refuses it and allowance A, its last pair commits after at most the ⌈B / (A - 1,088 KiB)⌉-th 00:00 UTC that follows plus one pacing turn per upload of that day; its CUT and its first ERASE, of the documents' own keys, land at once; the eraser's device reports each erasure's state, remaining objects and bytes, next try and finish (§5.4, §18.5). *Why:* the meta review's F19: one message is one document per 1 MiB chunk of its text, and backfills, absorbed slots and holds add copies, so the fixed next-day bound did not hold; owner decision 146 asks §11.13 and §15.7 to state the wait, and an estimate from the eraser's own allowance and turns is that statement.

### 11.18 Open questions

**Q-EVS-1.** [X2] Which header values may evs see, and how do head reads and subpath subscriptions work without plaintext paths? **Decided by owner 2026-11-03 (owner decision 2):** keyed path tokens in an object index, token-prefix subscriptions, path-key rotation on member removal and all storage state as objects (11.5-11.8). *Residual:* Q-EVS-6, closed by peer review 2026-11-04.

**Q-EVS-2.** [X19] How does evs stay git-compatible? **Decided by owner 2026-11-03 (owner decision 24):** a local git tier over authenticated http and ssh plus `git-remote-ur`; only the sidecar talks to evs; owner decisions 84 and 130 set the bind, with only TLS or ssh beyond loopback (11.11). *Residual:* none.

**Q-EVS-3 (closed 2026-11-03).** Separate repos for path prefixes in v0; in v1, prefix rules in the encrypted repo config, enforced by sidecars with an alarm; applied in §8 (D-ACL-11) and 11.22. *Residual:* none.

**Q-EVS-4.** How does PLAN.md:59's forced git identity apply to plaintext commits? **Decided by owner 2026-11-03 (owner decision 81):** signed pushes authenticate commits, and the local git server refuses new commits whose committer is not the pushing sidecar, except signed imports (11.11). *Residual:* none.

**Q-EVS-5.** Should repo deletion start as a soft delete? **Decided by owner 2026-11-03 (owner decision 82):** yes: access ends at once, and keys are shredded after 7 days unless restored, or at once with `--now` (11.12). *Residual:* none.

**Q-EVS-6.** Must a head reader that does not replay verify per-file freshness? **Closed by peer review 2026-11-04:** (c), made cheap: head readers replay signed statements, not payloads, from their pin, carried by the read response, and check the statement behind every entry they read (11.9), in D-EVS-24's format (statements of at most 1 KiB; for larger change lists, `changes_root` over sorted changes, so inclusion and adjacent-leaf proofs settle a path); phones keep durable pins and catch up by at most 4 MiB of statements and proofs, else re-pin and mark the gap. The sensitive classes (config, mailcfg, the mailbox's `vault/` and `i/`, approvals) are mirrored and replayed in full (11.13), and a head below a pin needs a verified EvsReseed. Disclosed limit (§2.8): for a path a head reader has never read or no longer remembers (owner decision 209), which writer-signed version is current as of its first pin, and, after a re-pin past that budget, for every path, rests on evs; HeadCheck confirms the pin, not those versions. (b), a Merkle root over the token tree, is rejected: a PUT per path level, root contention, d+1 GETs per read. *Residual:* that limit.

**Q-EVS-7.** Cross-cutting (§11, §21). Does a preservation hold pause user-initiated shredding (`--now`, the 7-day timer, slot erasure)? **Decided by owner 2026-11-04 (owner decision 133):** (a) no: holds pause only the server's TTL sweeps and GC for in-scope records and, from M10, drops' deletions, silently (owner decision 184; §21.9), and user-initiated shredding always proceeds (11.12), if counsel confirms that deleting wrapped keys to ciphertext URnetwork cannot read is permitted (§21). A hold keeps only the ciphertext a shred leaves. *Residual:* none.

**Q-EVS-8.** Cross-cutting (owner decisions 2, 24). On a shared git ref, disjoint landing (owner decision 2) leaves a tree no git commit has, so git compatibility and R-EVS-10's CAS cannot both hold. **Decided by owner 2026-11-04 (owner decision 141):** (a): git-mode refs commit only on their tip (D-EVS-22), and file-mode refs (vaults, mailboxes, records, the config) keep disjoint landing, so exact git oids and stock non-fast-forward errors hold; a loser pulls or merges, about 2% of merges in the twenty-agent test. *Residual:* none.

**Q-EVS-9.** Cross-cutting (owner decisions 2, 140, 145; §19, §22). Must the design meet the ~10-15 KiB of drive writes a push in owner decision 140's record, when owner decision 2's commit point, the head's If-Match overwrite, alone writes ~14 KiB a drive (~10.5 on 1 KiB blocks), since MinIO also rewrites the old xl.meta (11.3)? **Decided by owner 2026-11-04 (owner decision 140, record corrected):** (a): the binding budget, gated at 43 KiB a push per drive (D-TEST-11). The ~10-15 KiB figure was the design team's first estimate, not the owner's requirement, which is the PM9A3 profile itself ("We have to make that iop profile work"): at most 0.8 DWPD and 50% of rated write IOPS at the design load. Not taken: (b) a head per version created If-None-Match, which departs from owner decision 2's If-Match commit point; (c) patching MinIO to skip the old xl.meta's copy on overwrite, which gives up its torn-write backup. *Residual:* none.

**Q-EVS-10.** What happens to a path's history when versioning is turned off? **Decided by owner 2026-11-05 (owner decision 158):** per version, as Perforce does: versions written with it on stay for the repo's life unless a repo admin drops them (owner decision 173; 11.7), and turning it back on restarts history (11.7). *Residual:* none.

**Q-EVS-11.** Are the search index's files always versionless? **Decided by owner 2026-11-05 (owner decision 159):** yes, so erasing postings is real (11.14). *Residual:* none.

**Q-EVS-12.** Which repo kinds may hold versionless files? **Decided by owner 2026-11-05 (owner decision 160):** all but config and mailcfg, with a repo admin's lock in v1 (§8.8). *Residual:* none.

**Q-EVS-13.** How long does replaced versionless content stay? **Decided by owner 2026-11-05 (owner decision 161, revising about a day):** as briefly as is safe: a minute, a sweep catching failures, with no recovery window (11.13). *Residual:* none.

**Q-EVS-14.** How do git-mode refs handle large files? **Decided by owner 2026-11-05 (owner decision 162):** they stay versioned, with v1's git-lfs on a versionless store pruned outside a per-repo 30-day window (11.11). *Residual:* none.

**Q-EVS-15.** When does versionless ship? **Decided by owner 2026-11-05 (owner decision 163):** in v1 as storage format 2, its numbers reserved at M2, older repos migrating (11.6). *Residual:* none.

**Q-EVS-16.** Is there a default versioning rule? **Decided by owner 2026-11-05 (owner decision 164):** per network, versionless above 64 MiB by default, edited by admins in the config repo (§7.9). *Residual:* none.

**Q-EVS-17.** Does replaced content count toward storage? **Decided by owner 2026-11-05 (owner decision 165):** until it is purged (§20.7). *Residual:* none.

**Q-EVS-18.** Should evs keep the newest n versions or d days? **Decided by owner 2026-11-05 (owner decision 165):** never; no field is reserved. *Residual:* none.

**Q-EVS-19.** Should v1 ship an admin "drop history" action for a path, which owner decision 158 allows? **Decided by owner 2026-11-05 (owner decision 173):** (b), as 11.7 and 11.13 write: a repo admin's signed DROP push on a file-mode ref, refused in config and mailcfg repos, deletes after a 7-day window the kind-1 segments and slots that only the dropped versions name, found by scanning every ref's versions; inline records in packs wait for compaction; statements and hashes stay; under a preservation hold its deletions wait silently (owner decision 184). Not taken: (a), deferring it to compaction. *Residual:* none (Q-EVS-23 decided).

**Q-EVS-20.** When does a network's versioning rule take effect? **Decided by owner 2026-11-05 (owner decision 167):** (a), at a path's creation, from the rules then in force, as 11.7's `choose` row writes, so an edit reaches every repo without its own rules, for new paths, and no path changes without a writer's act; no field 15 is reserved. Not taken: (b) at a repo's creation, (c) at every unpinned write. *Residual:* none.

**Q-EVS-21.** Cross-cutting (§19, §22). How often do git-mode refs and record streams update the index on `ur/index`? **Decided by owner 2026-11-05 (owner decision 172):** at most once a minute per writer on 1 KiB XFS blocks (~34-37 KiB a push at 2× year one), else once every 5 minutes (~42-45 KiB on 4 KiB blocks), the block size being §22.8's M2 choice; either way each committer indexes its own commits and its own device searches its journal at once (11.13, 11.14). Not taken: an indexer pushing for every writer. *Residual:* none.

**Q-EVS-22.** Cross-cutting (§8). Does a repo locked fully versioned (owner decision 160) keep its always-versionless index (owner decision 159)? **Decided by owner 2026-11-05 (owner decision 168):** (b), through the distinct value `versioning` 2, which the lock does not refuse, readers accept only under an index root and format 1 reserves at M2 (11.7, 11.14); the lock keeps content history, and the index is derived and rebuildable. Not taken: (a), the lock turning the index off. *Residual:* none.

**Q-EVS-23.** Does a drop wait out a cancellable window before it deletes? **Decided by owner 2026-11-05 (owner decision 183):** (a), a 7-day window in which any repo admin can cancel; `now` skips it, as RepoDelete's does; a repo lock voids a pending drop; deletion starts after the window and the 25-minute fence (11.7, 11.13). Not taken: (b) no window, (c) a network setting. *Residual:* none.

**Q-EVS-24.** Cross-cutting (§10.6, §19.6, §22.8; owner decision 140). Must the PM9A3 write bound hold against aggregate safety work? Per-tenant rates bound each uploader, group and network, never a cluster: 100 large Teams on one metadata cluster, each shrinking every 5 minutes, ask ~57,600 config and directory rotations a day of ~50 MiB a drive, ~2.9 TiB a day against the 0.768 DWPD refill's ~1.5 TB, every rate respected (the meta review's F12). **Decided by owner 2026-11-05 (owner decision 186):** (b), P0 unlimited: P0 work runs at once, never queued or refused, its bytes measured, reported by kind and taken from the other classes' later allowances (11.13); FI-14 bounds the other classes' writes less P0's and leaves P0's unbounded, so a P0 storm wears the drives past 0.8 DWPD and their 1 DWPD rating while it lasts, disclosed with §19.8's P0 page; owner decision 140's hard budget is amended for P0 writes only. Not taken: (a) a bounded P0 with its fan-out paced ahead of pushes, which kept the bound unconditional at a write-availability cost in that stress; (c) a finite admitted liability, a count cap owner decision 66 rules out. **Amended by owner 2026-11-06 (owner decision 190), refining owner decision 186 after the (b) orders had the other classes repay P0's excess:** P0's excess is forgiven, not repaid: the write budget's bucket floors at zero, P0's bytes past what it holds are counted and reported by kind (§19.8), and a cluster's pushes and evacuation restart when a storm ends and ramp up as the bucket refills (11.13); FI-14 subtracts from the other classes' bound only the P0 writes the bucket held; each storm's forgiven excess stays as wear, ~0.23 drive-writes a 6-hour storm at that stress, which §19.8 shows against the ~420 drive-writes that five years at the refill leave under the 1 DWPD rating, ~1,800 such storms. Not taken: repaying the excess from the other classes' later allowances, which kept long-run writes at the refill but stopped the cluster's pushes for about 2.2 times a storm's length. *Residual:* 11.21's P0 row: the storm's wear, its forgiven excess kept; its cluster's pushes and evacuation stopped while it lasts, batches passing 26 h; and an M2 sizing that bounds wear only at the admitted mix.

### 11.19 Departures from PLAN.md

- **PLAN.md:59**, second sentence (plaintext paths, the git-crypt model): superseded by owner directive 2026-11-03; paths are keyed tokens and names are sealed (owner decision 2). Its first sentence stands (Q-EVS-4).
- **PLAN.md:57** is met at the sidecar's local git server; evs speaks an object API (owner decision 24).
- **Not in PLAN.md:** cli/UI.md:94 requires an active remote to start the git server, but only the first sync needs one; cli/UI.md:11's 0.0.0.0 default stands (owner decision 84), with TLS or ssh off loopback (owner decision 130; D-TRUST-8); cli/UI.md:87-89's quotas give way to PLAN's (owner decision 27); git directories over 4,096 entries or 448 KiB of name table (3,584 entries whose names are under 64 B; 11.7) are refused in v0.
- **PLAN.md:50 and :63** (diff chains with periodic checkpoints) hold for versioned files; versionless files keep only a checkpoint or chunk set of their newest version (owner decisions 158, 161; 11.7).

### 11.20 Interfaces

- **Provides:** `EvsClient` and `EvsRepo` (`evs_*.go`: `CreateRepo`, `ReadHead`, `List`, `History`, `Write`, `Deposit`, `Consume`, `Subscribe`, `Shred`, `Erasures`, `Delete`, `Restore`, `Import`, `Export`, `Mount`, and v1's `IndexSettings`, `IndexStatus` and `IndexRebuild`; `Write` takes a versioning setting, and `List` and `History` report it and `collected`, 11.7), whose per-path version, signer and git oid answer §16.6's `Lookup(effect_key)` for an evs effect (D-MCP-11); the index writer the push builder calls, its format (`evs_index_*.go`, `sidecar/protocol/evsindex.proto`) and the partitions §16.10's engine reads (11.14); remote search, asking and serving, in the root engine (`search_remote_*.go`, `sidecar/protocol/search.proto`; 11.14); ref modes (11.7); the drop-history engine behind `ur history` and `SidecarEvs`'s four drop calls (`DropHistoryPreview`, `DropHistory`, `CancelDrop`, `Drops`; 11.7, 11.13, §18.5); the `directory` kind (11.12); the sync engine, local git server, `git-remote-ur` and v1's git-lfs transfer agent and tip check (11.11); the `sidecar/evsservice` engine (owner decision 104); the push sequence that versions §6.8's `evs:<repo_id>`; `place/` and storage for `proj/`, `projrows/`, `rev/`, `hold/` and `gkm/`; 11.13's write budget, its classes, accounts and wallet, and fair share, shared with gkm, api and taskworker; §2.8's evs-1 to evs-26 and evs-28, and connect-5 (evs-10 is §19.6's, evs-27 §16.11's; evs-20 withdrawn).
- **Consumes:** §3.6's indexers; §5 `ServiceToken`, binding log, `git` hello, §5.9's index cache and served record; §6 hints, `Signed`, `HeadCheck` and `RefHead`, `PushReset`, §6.6's RPC and §6.4's control contracts; §7 token exchange and its re-seed mode, `rev/`, the authorization log and its `{acl_}e` cache, `AuthPin`, bootstrap, §7.9's `VersioningRules` and `IndexerSet`; §8 `RepoReaders`, writer sets, kind defaults, §8.5's consent (`consented`), `audit`, access logs (`RepoDelete`, `RepoRestore`, `RepoVersioning`), `EvsShare`, `OwnerConfirm`; §10 `GkmClient`, `DeriveKey`, `GenRotate`, the gate predicate, the `index` purpose; §12 `ResolveNetworkLabel`; §13 certificates; §16.11's path rules and fields; §18 wakes and §18.4's fetch policies and remote mode; §19 clusters, drive counters, `{nvb_<set>}` and §19.6's `{nvb_<cluster>}`, §19.11's `format2` gate and its `purge` and `drop` modes; §20 `ReportUsage`; §21.9 holds.
- **Subprotocol messages:** `EvsHeadChanged` (0x1401; server→client in §6 `PushHint`; a ref moved); `RefHead` inside §6's `HeadCheck` (compare ref pins); 0x1402-0x1403 stay reserved, never reused; `SearchRequest` in `SEARCH` (0x1404) and `SearchReply` in `SEARCH_RESULT` (0x1405) (app host to indexer and back over §6.6's RPC; remote search, 11.14; §6.11).
- **API routes:** Client class, authorized by a service token with aud `evs`, specified in connect/api/bringyour.yml.

  ```text
  PUT|GET|DELETE /evs/v1/repos/<id>[?now=1];  POST /evs/v1/repos/<id>/restore (409 SHREDDING past deleted), /reseed (admin);
       DELETE and restore answer 409 STATEMENT_MISSING without their projected RepoDelete or RepoRestore
  PUT  /evs/v1/repos/<id>/segments/<sid>?push=<push_id>[&closure=1] (rw, deposit; closure: admin, the team
       directory's included): 200 {EvsUploadReceipt}, or 409 SEGMENT_STALE, or 409 VERSIONING for a kind-5 header naming
       another push, or 503 with Retry-After past the segment cluster's HDD share for the heaviest network
       (11.13's hdd row), or 507 CLUSTER_FULL while the repo's metadata cluster stands at §19.9's cohort limit;
       at the storage limit or while spent, §20.7's QuotaRefusal (402 with x402 terms when a
       purchase lifts the limit, else RESOURCE_EXHAUSTED; a closure upload past its eraser's 60 a minute or daily
       closure allowance 429 with retry_after_ms, 11.12, §20.7)
  POST /evs/v1/repos/<id>/push {statement, payload, receipts}, /push/<push_id>/<k> {part, receipts}: 200 {place}
       (rw; deposit only to the caller's deposit ref); the seal POSTs .../push {statement, the parts' places}
  POST /evs/v1/repos/<id>/push/<push_id>/lease, /path-epoch, /path-epoch/block (rw)
  POST /evs/v1/repos/<id>/read {..., fresh} (`base` {ref, version} for an overlay's path it holds no version of),
       or {refs} for up to 64 owned streams (11.9's streams row);
       GET /evs/v1/repos/<id>/refs[?moved_after=<push sequence>], /log?ref=&since=
  POST /evs/v1/repos/<id>/slots/delete (admin, the team directory's included);  POST|GET|DELETE /evs/v1/subscriptions
  POST /evs/v1/repos/<id>/drops/preview (admin) {ref_id, paths: each EvsDropPath, its through_version the one a
       drop now would keep} -> 202 {preview_id}; 429 past evs_drop_previews_per_day; one at a time a repo, P2
  GET  /evs/v1/repos/<id>/drops/preview/<preview_id> (admin) -> state, progress, list_match per path, versions,
       frees, shared, inline, packed, young, snapshot;  GET /evs/v1/repos/<id>/drops (r) -> each drop's state,
       progress and freed bytes, a held drop reading done; DROP pushes and cancels go through POST .../push
  push refusals, each with the push id: 409 REF_MODE, PUSH_ID_REUSED, SEGMENT_GONE, SEGMENT_STALE, SLOT_STALE,
       PARTS_MISSING, VERSIONING, DIRECTORY_FULL, NOTHING_TO_ERASE, INDEX_EPOCH, SHREDDING, DROPPED, DROP_KIND,
       DROP_PATH, DROP_CONSENT, DROP_BOUNDARY, DROP_LIST, DROP_STATE, non-fast-forward; 412 GATE_CLOSED,
       PATH_EPOCH, PATH_EPOCH_DUE, EPOCH_SOURCES_FULL; QuotaRefusal at the storage limit or while spent, as for
       uploads, and 507 CLUSTER_FULL with Retry-After for what the storage limit refuses while the repo's
       cluster stands at §19.9's cohort limit, each once the head records it; a recorded refusal again, with
       recorded: true, to every later attempt of its push id; 429 BUSY, FOLD_BEHIND, the budget's
       RESOURCE_EXHAUSTED, a CLOSURE past its eraser's daily closure allowance (§20.7), a drop (never a cancel)
       past evs_drops_per_day, TIME_AHEAD, a refusal meeting 8 live refusal records or a refusal fence under
       1 s old, and lease and fence waits, with retry_after_ms, which refuse nothing; 503 outcome: unknown, or
       before step 4 while evs's clock is unsure; reads of a dropped version's content: EVS_DROPPED
  ```
- **Tables:** none; evs keeps only 11.8's objects (owner decision 2), plus Redis soft state: §6's hint keys, {evsl_} leases, the {evsq_} push sequence, the {evsh_} head cache and {evsd_} drop hints (owner decision 136).
- **Services and config:** `server/cli/evs` (staged, stateless) with 11.13's `streamable_paths`; the segment bucket and one bucket per metadata cluster (owner decisions 94, 145); limits in config/all/pro.yml (`<tier>.sidecar:` with `store_weight` and `evs_drops_per_day`, `sidecar_abuse:` with `evs_drop_previews_per_day`); the receipt keys; the `{nvb_<set>}` allowance, which taskworker publishes from §19.6's drive counters; GC, evacuation, path-epoch copies, drop jobs and dry runs, shredding and reconciliation in taskworker; §19.11's `format2` gate with its `purge` and `drop` modes; the system git where the local tier runs.
- **Assumptions about other sections:**
  - §2.8's evs rows follow 11.8's families (evs-8 and evs-24 in Redis; evs-21 to evs-23 `spidx/`, `pb/`, `hp/`; evs-25 `place/`; evs-28 `drops/`, `dropscan/` and `{evsd_}`; evs-20 withdrawn), evs-1 listing the `secret` kind, evs-3 a mapper's creation-block end (block_until_ms), an index ref's index_epoch, the time of the newest evacuation fence (fence_ms; GC raises none, owner decision 203), the refusal records (each a refused push id's first 8 bytes, its statement prefix, code and until) with the newest's time (refused_ms), for a refused push that would have created its ref a placeholder head holding only them (and for a ref evacuation fences before its first commit, one holding only its fence), and a marker collection's done, through and window end, evs-4 whether an upload was a closure upload, evs-11 a carried row's epoch, each removal's marker (the removing push id and version, the path's version) until collected and, while sources stand, each entry's state (carried, fresh or removed), evs-12 the CLOSURE and CUT flags and an index push's index_epoch, an ERASE's or CLOSURE's erased-list hash (a CLOSURE's equals its ERASE's, linking the re-keyed paths to that erasure), a PATH_EPOCH's tail hash with its tail moves (old and new token paths, linking created paths across epochs as evs-15's maps do) and the source-paths hash with each change's source token paths, evs-24 each cached head's time and the push sequence value each ref's last commit raised (GET .../refs?moved_after=), and the head-reader disclosure every path after a re-pin past 11.9's budget; §3.7's F2 follows 11.8's commit and 11.9's statement reads; §22.7's guard lists the families, `place/` included, and lets evs, gkm, api and taskworker write their `{nvb_<set>}` reports.
  - §8.5's kind defaults take the `secret` kind (§13.8's account keys) as `vault`, deposits aside; §8.8's RepoDelete and RepoRestore precede 11.12's routes; §7.9's append limits bound 11.13's P0 log writes; §20.7 states 11.12's rekey bounds, its {sq_} counting each eraser's closure uploads against its own 60 a minute, not the network's, and its closure bytes against its own `evs_closure_bytes_per_day`, never below `evs_closure_bytes_floor`, with 11.13's wait (owner decision 146).
  - §15 and §16 size directories by 11.7's 448 KiB of name table (EvsName rows of token, kind and sealed name with nonce and tag: 3,584 names under 64 B), not by the 4,096 count; evs sees each record entry's token, time and padded size; ingest ends in CONSUME, §16.8's taking only `read` entries from a receipt-only depositor (11.12); §15.7 re-keys an erased message's `i/` chains by CLOSURE pushes, and it and §8 make every device that erases a mailbox's or group repo's messages, the trash shred included, a repo admin, since ERASE, CLOSURE and closure uploads take `admin`; §16.8 holds a record entry's `erasure` entry while the network is at the storage limit or spent (11.12); §15.7 and §16.8 delete an erased entry's decrypted copies; §16.2's `evs_write` on a git-mode ref commits through the local tier at the tip.
  - §19.6 quotes 11.13's mix and drive writes (~670 and ~5,000 PUT/s; ~8.5 and ~69 MiB/s a drive; 3.7-4.0 DWPD at a near-capacity set's ~1-1.6 records a batch), sets the store's 10 s request deadline, which a request's own earlier deadline shortens, sent with every request but a streamed segment PUT as x-ur-deadline-ms, and D-OPS-20's settle rule (a request refused past its deadline, a PUT or DELETE taking effect before any later request on its key or never, a key held while a write that lacks a write quorum could still be read), which 11.7's stale and collect margins need instead of a measured lag, runs chrony on the evs, gkm, taskworker, Redis master and MinIO hosts within 50 ms of UTC, alarmed past 25 ms, a taskworker whose offset is unknown or over 50 ms raising no fence and GC deleting nothing (§19.10's clock row), exports drive counters, publishes B, T and 11.13's accounts (A_U, A1 and A2), keeps B and the wallet W across lease changes (19.6's budget row), exports 11.13's liabilities and P0 figures with their page (§19.8), tracks each cluster's cohort and its limit (§19.9's cohorts row) and provides the clusters and a conformance suite that refuses multi-pool metadata, and §19.9's triggers start each next cluster (owner decision 145), §19.9 sizing year two at five to six sets by 11.13's per-cluster batches; §19.10 re-seeds slots last and places a repo re-seeded as deleted in that state first; §10.6 keeps gkm's objects on the repo's cluster, acks in Redis; §21.9's api writes `hold/`, and §21 tracks counsel's confirmation for owner decision 133.
  - §22's evs tests add a helper clone with no prior mount, a shred under a hold, and placement: two creates of one id racing at `place/`, a retried create, and a second cluster never receiving a placed repo's objects. Beyond the FS rows §22 already writes, they add: FS-1, every refusal recorded whether evs2 serves a retry or the lb's re-send of a first send, a paused attempt of the refused push answering the recorded refusal at its next read, evs1 slowed past the lb's 30 s read timeout while evs2 loses 8 races and answers 429 BUSY (the retry returning evs1's version), DIRECTORY_FULL and EPOCH_SOURCES_FULL only once recorded, an instance 150 ms fast answering 503 and committing nothing after a sibling's recorded refusal, and recorded refusals streamed beside honest pushes (one record a second and 8 live, the rest 429; no other push's attempt, lease, part or seal ended by them); FS-113, an attempt held before its handler starts while the lb's re-send is refused and recorded, then released with a stale below-limit list, through the lb's own re-send path too: it answers the recorded refusal and never commits, a seal's attempt too; FS-3, A's PUT timing out after the gate closes, not reissued past 5 s: A's rerun checks refuse, and A answers 412 GATE_CLOSED after its fence, or 200 if its first PUT applied first; FS-4, a child added to an unmoved directory in a paused copy and folded first, then, the copy still paused, a carried child removed and folded, its row dropped, the copy resuming to translate the rest, and a fold of that directory between the copy's GET and its If-Match PUT (a reread; no row lost or duplicated), the listing name-verified after the sources drop; a file and a directory removed after cut-over before the copy reaches them, and a directory removed then re-created with one new child, each read and listed once the removal leaves the window and again after the sources drop: nothing removed served or listed, no reader alarming; a move landing between one round's GETs, for a push creating the path, one modifying it and a listing; a directory carried from p1 into p2, then into p3 after a superseded copy, listed and name-verified before and after the p3 copy; no source-epoch token of a name created after cut-over reaching the server; and steady creation through a batched epoch, which commits with a tail, then under a block; FS-5, a push after a commitless PATH_EPOCH succeeding with no ng, and with a warm head cache a lease, parts and seal with no ng, a lease taken after another push's refusal fence, a git push after a refusal fence committing, one during another's lease getting 429; a git-mode agent branch from a main with unfolded changes whose first push changes one of those paths and commits; an overlay of a file-mode ref refused (409 REF_MODE), and a read of an overlay's unchanged path answering `base`; FS-6, a gkm commit held across a `--now` shred re-creating nothing, a held `--now` shred whose records in 25 h-old batches are packed, kept and deleted once the hold ends, and a re-seed of a soft-deleted repo, then a restore that opens every file; FS-9, the reverse order: D's removal first, then a push based before it creating D/n (409), the bound built from real sealed names (3,584 under 64 B), held through a paused copy with carried rows counted untagged, and a multi-part file-mode push in both orders and at the bound; FS-10, a refused push's entry served as current for a never-read path, accepted as §2.8 publishes, a path a 100,000-change push left alone verified by adjacent-leaf proofs with no change list fetched, and an unsorted change list refused; FS-30, a receipt-only depositor's other entry consumed, not ingested, with an alarm; FS-47, a mail erasure at the exact limit whose IndexEntry shares an `i/` segment, its merged record crossing a padding step: its CLOSURE push and upload pass; a CLOSURE growing a chain refused below the limit too; a non-admin one and a plain upload refused, and at the limit a closure upload over 1,088 KiB; a CLOSURE push past the network's erasure rate queuing as P1 and committing; an eraser's closure uploads past its own 60 a minute, and its uploads and CLOSURE pushes past its daily allowance, getting 429 while another eraser's pass; a record entry's `erasure` entry held at the limit and committed once under it; FS-58, a PATH_EPOCH on an idle ref whose folded_through trails v folding and committing, and a fold plus a horizon-raising commit between a push's step 4 and its 412 rerun, and between its head and entry reads: 409, never a commit over the change; a rerun after the window paged out versions past A's horizon, from a cluster head and from a cached head minutes old: A reads X's entry again after the reread head (409); a fold and a horizon-raising commit between an entry GET and a newer head's GET, then a listing; two folds of a range holding D's removal, the first queued in P2 or its marker PUT applying late, D and D/x re-created and folded between: nothing newer overwritten, D/x served and listed, a creation of D/x refused; a file removed and re-created, a push based on its old version refused before and after, its versions continuing, and again re-created after its marker's collection and after a path-epoch copy dropped its source marker, its version above every earlier one, while a creation whose version is not max(b, m) + 1 gets 409 and replaying readers alarm on one; a collection window held at a barrier while a fold re-creates a covered path, deleting no live entry, with the collector's and the folder's clocks each 50 ms off in opposite directions, the store host's 50 ms off, each fold's 15 s deadline slewed by 100 ms and a fold write held at a drive past it (I-EVS-8 as FI-15, read with 0 naming an absent path and a creation's version max(its push's base_version, a standing removal's) + 1, so versions never restart, checked in EvsCommit.tla with its fold thresholds and window bounds scaled, the minimum window above the base range, and a version bound fitting a page-out between a push's step 4 and its rerun; its head's lease field and the lease route reaching FI-9's 429 branch; its folder running a stale or late removal and its collector a window); FS-59, the stalled push ending 503 unknown and its retry getting 409 SEGMENT_GONE; FS-60, a run killed after its container and restarted once its material aged, nothing stored twice past the nightly pass; FS-61 and §22.8's `nvme` row, the budget refilled at 0.8 DWPD and refusing no push at 2× year one, then a full-rate path-epoch copy beside that load; FS-116, 11.13's conservation on exact costs, before the `nvme` run; FS-117, a day of P0 alone past the refill and the day after it, no P0 write waiting, the other classes held within the budget less the P0 writes the bucket held and restarting within one interval of the storm's end; FS-118, a week of path-epoch copies at and past a cluster's planned copy load; FS-62, one ref's cached head past 10 min, another ref writing, not served, and the exact sequence and version vectors (§11.10, §6.8); FS-114, D-OPS-20's settle rule: a head PUT, a marker DELETE and v1's purge and drop DELETEs whose drive commits are held after their checks past 30 s, the coordinator killed, a newer request on the key waiting only while the write could still be read, nothing newer lost after release and heal; §22.8, the rotations, full checkpoints and copy operations a day of 1 h requested grants on large repos.
  - §7.9 holds VersioningRules and §8.8 RepoVersioning, their types reserved at M2; the index writes its files with versioning 2 under its reserved paths and rewrites them in place at erasure, each within the closure upload bound; §15 and §16 add no versionless rule of their own beyond the index's and §15.7's `s/model`; §19's evs credentials include DELETE on the segment bucket, §19.11's format2 gate rolls format 2 out, Q-OPS-2's packing never takes kind-5 segments, and §19.8 exports the purge's metrics; §20.7 counts replaced versionless content until purged; §21.9's holds keep only content existing at placement.
  - v1's search index (11.14): §15.7 and §16.8 give their documents' and run cards' fields and names; §18.4 sets each device class's all-partition policy; §5.9 holds the sealed `search` cache and its version table (D-CORE-16); §7.9's IndexerSet names the indexers serving a repo; §2.8's evs-26 shows the index's shape and reads; §19.10 rebuilds an index no mirror holds; §20.7 counts it (owner decision 10); §22's index schedules run head slots against an eraser's CLOSURE, roll-ups killed at each step and raced by two runners, a differential run against a brute-force scan, byte-identical vectors on darwin/arm64, linux/amd64, android/arm64 and js/wasm, an erasure's CUT fencing every kind of delayed index push with no indexer (FS-111), an erasure at the floor committing within 11.13's wait for its closure bytes (FS-112), coverage and backfill, on, off, migration and holds, fresh-cache diff and deletion recovery after slot reuse and purges, large mutable-corpus masks and cold last-shard and no-hit downloads (FS-107 to FS-110); §23 ships it at M10 (owner decision 169), and M2 reserves `.ur-index/`, `ur/index` and `ur/lfs`.
  - Erasure (11.12, 11.14): §5.4's `erasure` SidecarEvent and §18.5's `Erasures` report each erasure's state, what is left and its estimate (11.13's wait); §15.7 and §16.8 order an erasure as its CUT and first ERASE, then CLOSURE and ERASE pairs; §16.11's readers apply a directory CUT's erasure set only from a signer that may erase its documents; §10.8 puts the CUT before the CLOSURE; §20.7 takes the CUT as maintenance and counts it with ERASE and CLOSURE pushes.
  - Remote search and the directory (11.12, 11.14): §7.9's `search` scopes are 11.14's; §6.4 carries Hello bits 0 (serves) and 1 (asks), §6.11 the SEARCH pair, and §4.6's C19 reports a marked pair per §6.10's windows, both directions, at a fixed floor (owner decisions 176, 188); §18.4 owns the requester's mode, notice and states, §5.9 the served record; §16.11 owns the directory's paths, fields, announcements and requests, §7.5 its creation, §10.4 its group, and §7.8 mints its `rw` to every admitted sidecar not read_only and its `admin` only to its consented, not-read-only admins; §16.11's daemons read moved streams 64 to a request (11.9).
  - Drops (11.7, 11.13): §8.5 lists DROP pushes and cancels among an owner's consented acts; §8.8's lock refuses and voids drops; §16.6 refuses them from MCP; §19.11 gives `format2.drop: observe | on`, §19.8 its metrics; §20.7 counts as 11.13's `freed` row; §21.9 defers deletions under a hold, silently (owner decision 184); §5.9 deletes dropped content locally (D-CORE-19); §18.5 surfaces the drop calls and `history_drop`, with state `invalid` for a DROP failing a reader's checks.

### 11.21 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| A flaw in the format, token tree or commit protocol, unaudited and so disclosed (owner decisions 99, 119) | Medium | High | Peer review before format 1 freezes; vectors, fuzzing, a model check of 11.8 (§22) |
| The final MinIO build loses conditional-write or listing consistency | Low | High | One-object commit point; §22's suite gates every build |
| A 1M-file ref's path epoch copies for ~17 h, while readers read both epochs; a cluster's copies share 250 operations a second, so refs whose live entries times epochs a day pass ~7.2M keep sources standing, and an immediate epoch on a ref already holding three waits (EPOCH_SOURCES_FULL), creation blocked there | Medium | Medium | Epochs only on removal or compromise, else daily; up to three sources read in one round; the copy speeds to 150 operations a second with two sources, and a cluster's to 1,000 while pushes leave room; refs holding the most sources copy first; a batched epoch waits while two sources stand, keeping the third for an immediate one; §19.8's copy liability and drain time; §19.9 plans live entries per rotating ref; FS-118 |
| P0 work runs at once whatever its volume (owner decision 186): safety work past the refill, legal within every rate, as from 100 large Teams on one cluster each shrinking every 5 minutes (~2.9 TiB a day a drive of rotations, about twice it), wears the cluster's drives past 0.8 DWPD and the PM9A3's 1 DWPD rating while it lasts, its excess forgiven and kept as wear (owner decision 190), ~0.23 drive-writes a 6-hour storm at that stress; every push there is shed, and folds and evacuation wait once P0 empties the bucket, so batches stay on NVMe past 26 h until the storm ends; the M2 sizing bounds wear only at the admitted mix | Low | High | Each uploader's, group's and network's rates (11.13's classes); pushes and evacuation restarting within one interval of the storm's end and ramping up as the bucket refills (11.13); the drives' lifetime writes passing the refill's only by the bucket's depth and each storm's forgiven excess, ~1,800 such storms fitting in the ~420 drive-writes that five years at the refill leave under the rating; §19.8's P0 bytes by kind, forgiven excess and wear projection, and its page within an hour of P0 passing the refill, with §19.10's runbook (capacity, place_new, the networks); FS-117; Q-EVS-24 |
| No writer able to map is online when an epoch is due, so creation stays blocked in a name-bearing repo, and dropped holders keep testing names past due elsewhere | Low | Medium | Writers alarm 1 h past due_by_ms, batched epochs included; `ur status` names the ref; any capable writer maps, a tail and a 2-min creation block landing it under steady creation |
| A writer floods a ref with refusals, so others' refusals there answer 429 until a record lapses, at most about an hour for a seal's | Low | Low | 8 refusal records a ref, one added a second, each kept only until its statement's time bound plus 1 s; a refusal ends no other push's attempt, lease, part or seal; evs counts full lists; FS-1, FS-113 |
| Counsel does not confirm owner decision 133's condition (shredding under a hold) | Low | High | §21's counsel item, before holds ship (M5) |
| Site loss destroys repos no device mirrors | Low | High | Mirrors; coverage in `ur status`; re-seeding |
| Read and subscription patterns leak more than 11.5 states | Medium | Medium | Whole small reads; 64 KiB alignment; publish the leak |
| A client bug corrupts history, which the server cannot check | Low | High | Oid checks; replay; mirrors; export |
| An import, hostile tenant or reconnect storm saturates the NVMe set | Medium | High | 11.13's write budget and fair share, part bounds, leases in Redis; §22.8; §19.9's triggers (owner decision 145) |
| Measured per-operation costs hold a set below ~400 pushes/s (~530 on 1 KiB blocks) at the ~1-1.6 records a batch of a set near capacity, or year two arrives early | Medium | High | §22.8's M2 gate and records per batch per cluster; 1 KiB blocks; the write budget sheds the heaviest network; §19.9's triggers order the next cluster ahead of its lead time, for new repos (owner decision 145); a per-cluster batcher (Later) |
| Per-push drive writes cannot fall far below ~27 KiB: the head's If-Match overwrite alone is ~14 KiB (owner decision 2) | Certain | Low | The binding DWPD and IOPS limits hold at ~27-43 KiB a push (owner decision 140); D-TEST-11's §22.8 gate measures it |
| A shredded repo's statements and ciphertext stay up to 26 h in shared batches | Certain | Low | Keys go first (11.12); §2.8 states the bound |
| Owner decision 148's markers add ~12.5-14 KiB of drive writes a removed entry, and a collection window holds a fold re-creating a covered path for up to 30 s | Medium | Low | §22.8's fold row counts removals and markers a push before the 43 KiB gate; a window per ref at most nightly, and only re-creations over covered markers wait |
| A build's deadline or settle check fails, so a write lands after a later request on its key and a marker's DELETE removes a live entry | Low | Critical | §22.9's suite and FS-114 per build, upgrade and cluster, and StoreSettle.tla (§19.6, D-OPS-20); until a build passes, taskworker opens no collection window and markers stay |
| At owner decision 172's cadence the index adds ~2 KiB a push on 4 KiB blocks (~42-45 KiB at 2× year one, at D-TEST-11's 43 KiB) and ~4 KiB on 1 KiB blocks (~34-37 KiB) | Medium on 4 KiB blocks | Medium | 1 KiB blocks, chosen at M2 (D-TEST-11); D-TEST-13's computed gate, confirmed on production after the freeze (owner decision 174); the write budget sheds the heaviest network |
| A writer corrupts index files others rely on | Low | Medium | Hosts with text verify; indexers re-derive and alarm (owner decision 150); a rebuild from text |
| A diff's base or a deletion's mask leaves the index before the entries relying on it, so a fresh device misses or resurrects a document | Low | Medium | 11.14's dependency, merge, tombstone and roll-up rules; an unresolvable chain is `index_malformed` and reads not yet searchable; FS-107, FS-108 and IndexRollup.tla |
| A heavily edited corpus's bucket keys outgrow a phone's working set | Medium | Medium | §5.9's version table on disk, probed per candidate in rank order (11.14's newest row); FS-109 |
| Trigram precision falls as partitions grow, so phones show many possible matches | Certain | Low | Small buckets; overlap ranking; labels; confirmation on open (owner decision 155) |
| The index is about twice the research's zstd sizes (~110-165 MB for five years at 100 messages a day) | Certain | Low | Phones fetch all only at "search more" or on Wi-Fi while charging; buckets ≤ ~5.4 MB |
| A hold keeps the index files that existed at its placement, staged copies written to seg/ | Low | Low | Later churn is purged as usual (11.13's hold rule); holds are scoped |
| Old or index-unaware clients leave commits unindexed | Medium | Low | Coverage, "not yet searchable", backfill within 10 min |
| A purge bug deletes content a retained version needs | Low | High | Kind 5 adopted only through CAS bases and its header's push; I-EVS-9 and I-EVS-10 model-checked; the purge's reread; §19.11's observe mode first |
| Users lose content they expected to keep | Medium | Medium | Versioning stays on below 64 MiB; history written while on stays; listings and `ur status` show the setting; a repo lock |
| A versionless file replaced mid-download makes a slow reader restart | Medium | Low | The 60 s allowance; all files change only at roll-ups and erasures |
| Pre-v1 devices in a migrated repo cannot read versionless files or the index | Medium | Low | FORMAT_UNSUPPORTED, never misread; §19.11's format2 gate |
| A git-mode tip needs a git-lfs object ur/lfs lost or a prune is removing (a force push to a pruned ancestor, a new ref or tag at old history, an import, a skipped pre-push hook) | Medium | Medium | The tip check touches what a prune could take and refuses what is gone, naming the objects and `git lfs push --object-id` (11.11); a prune keeps every tip of its start read; FS-73 with stock clients |
| Purges and sweeps add HDD DELETEs and HEADs | Low | Medium | ~1-4% of year two's drive operations; a rate per process; §22.8's hdd and trash rows |
| An evs crash leaves queued purges for up to ~26 h | Medium | Low | A 70 s drain on stop; the sweep; §19.8's sweep metric |
| A drop bug deletes content a live version needs | Low | Critical | The fence, two independent scans, the 25 h age rule, whole-object deletes only, I-EVS-15 model-checked, observe mode and its soak (D-TEST-18) |
| A rogue or compromised admin destroys history | Low | High | The 7-day window, notices, any repo admin's cancel, a lock voiding it, owner-bound consent (owner decision 183); `now` as RepoDelete's (§2.18) |
| Inline content outlives the drop in packs | Certain until compaction | Low | Never served again; slot-keyed repos shred it at once; disclosed |
| Large repos' scans load the HDDs | Medium | Low | Rate caps, one job a cluster, the 50% pause, coalescing, dry-run marks reused |
| A stale mirror returns dropped content at a site-loss re-seed | Low | Low | The re-seeded job deletes it again; §19.10's close report names it |
| A faulty or compromised indexer hides or invents a phone's hits | Low | Medium | Open and omission checks, the collapsed row, alarms naming the indexer (11.14's merge) |
| A merge bug drops true local matches | Low | Medium | It only collapses, inside the checked span, never the phone's confirmed hits; FS-83 against the oracle |
| Reader transfer binds the directory at 5,000 members | Medium | Medium | §16.11's polling policy, phones off the follow, heads reproduced from cards; a sharded cards ref if §22.8 binds |
| One cards ref's head limits the directory | Low | Medium | One ref sustains ~20-50 pushes/s against ~5.8 at 5,000 members' peak (2.3 at the Team limit of 2,000); FS-86's commit ceilings and §22.8's directory row; a sharded cards ref |
| A repo owner's revocation waits for a directory admin's device to erase its copies | Medium | Low | The private marker hides the name from honest readers at once; any directory admin's indexer or daemon runs it; the wait is shown and alarms past 24 h (§16.11); evs refuses every directory erasure below `admin` (11.12) |
| Per-stream reads bind the directory's readers in M6's form | Medium | Medium | 11.9's streams read, 64 refs a request, and the moved listing; FS-86's M6 case at the Team limit (§16.11's cost table) |
| An erasure's CUT refuses every index push in flight on its ref but CLOSUREs, a mailbox's ingest included, each rebuilt and retried | Certain at each erasure | Low | One CUT a ref per erasure batch; a rebuild re-applies only pending entries; §22.8's index row counts the retries |
| An erasure whose eraser's device is lost stays pending until another device that may erase it runs: masked and fenced, its derived fields openable to key holders | Low | Medium | Its CUTs' sets and ERASE notes keep it on evs; the member's other devices after 25 h, any eligible device once the eraser is revoked; status and the erasure event show it (11.12's reconcile row) |
| A ref's pending erasures fill its 16,208 B erasure set (about 600 documents), so a bulk erasure at the floor cuts in batches | Low | Low | Complete erasures leave at the next CUT; below the limit erasures complete in minutes; bodies go at the first ERASE whatever the set holds |

### 11.22 Phasing

- **v0a** (§23 M2): format 1 with 11.8's objects and protocols (parts, ref modes, the seal lease, batches, receipts, lazy folds with removal markers and their collection, placement); streams, deposits, slots and ERASE, and the owner-bound read-receipt budget, which an `EvsShare` reader needs before it reads (§16.8, D-MCP-18); subscriptions, Redis soft state, the verified head cache and reads of §7.9's `{acl_}e`; head mode; path epochs; the gate and HeadCheck's ref pins (§6.4); usage events, fair share and the write budget, with its classes, accounts and wallet (11.13); GC and hourly evacuation; mirrors and re-seeding; soft deletion; export; format 1's reservations for format 2 (11.6), refused as FORMAT_UNSUPPORTED (EvsPush flags 256 and 512, fields 33 and 34, EvsHead's index_epoch and the read states `drop_pending` and `dropped` among them; window bits 4 and 5 ignored), and its reserved names, the `.ur-index/` directory on file-mode refs and the `ur/index` and `ur/lfs` refs, which format-1 clients refuse to write (11.14); the `directory` kind, known from M2 (11.12); the slot rule (11.8's 5h and step 6), which format 2 requires, checked by format 1 from M2 too, since it costs one NVMe HEAD on a rare slot 412 and hardens erasure, though M10 suffices for drops; `ur evs rekey`, re-checkpointing every file of a repo under the current generation (§10.16). Format 1's specification freezes at M2's entry review, after peer review of 11.5-11.8 and RECORD.md, and its bytes at M2's exit (D-PHASE-7), after §22.8's drive-write gate (owner decisions 25, 99, 140).
- **v0b** (§23 M2, with v0a; no format change): the local git server, `git-remote-ur`, the identity hook, the proc-receive journal and imports, the desktop sync engine, overlays and conflict branches, which M2's twenty-agent test uses (§3.15).
- **v1:** compaction and retention; working-tree sync; Q-EVS-3's prefix rules; cross-network and derived shares; agent-subkey provenance; the `directory` kind at M6 on format 1's streams (11.12), with 11.9's streams read and moved listing; format 2 at §23's M10 (owner decision 169): versionless files with staging, the purge and its sweep, rules and the repo lock, migration and the git-lfs store with its tip check (11.7, 11.11, 11.13), the search index (11.14) with its erasure cut and erasure sets, each repo's index built at its migration, the directory's versionless cards and its index, the drop-history action behind §19.11's `format2.drop` gate, observe first (D-TEST-18), and remote search, its app-host cases at the later of M10's and M8's exits and its team-indexer cases at the later of M10's and M6's.
- **Later:** full sync on mobile; a state commitment if measurements show head readers need pre-pin freshness; directory-resident children for append-only record directories (the reserved `layout`), if §22.8 shows stream entries' index objects binding; a tool moving placed repos between clusters with one commit point (owner decision 145), built to land before the earliest cohort exhaustion §19.9's cohorts row projects; a per-cluster batcher, two evs processes batching each cluster's records near ~5 a batch, if §22.8 shows it saves a set; a segment placement that keeps the receipt check and moves upload load, not only new repos, before any added HDD set, ordered by §19.9's hdd trigger ahead of year two's HDD load; a reverse citation index in `pidx/`, if §22.8's `drop` row shows scans binding; for the index, a word complement or semantic layer in the same buckets, Elias-Fano key sets, and per-field postings if §22.8 shows field-scoped queries common.
- **Blocking:** §7's token exchange, `rev/`, authorization log and bootstrap, §8's projection, consent rule and access logs, and §10's objects block v0a; counsel's confirmation of owner decision 133's condition precedes holds (M5, §21); X13's clusters passing §22's suite and 11.13's benchmark block production storage.
