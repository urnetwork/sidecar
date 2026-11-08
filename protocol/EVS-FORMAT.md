# evs format 1

The bytes of §11's format 1 that DESIGN.md names without fixing: its enumerations and refusal codes, the encodings of the stored objects and the ids in their keys, the fixed layouts of segments, record headers, batches, window entries and refusal records, the push payload's framing, and the HTTP bodies of push, part, seal, lease, read and the listings. `evs.proto` holds every value that is protobuf. §11.5 to §11.13 own the design. Where this file and DESIGN.md part, DESIGN.md wins, and the mismatch is reported.

**Status.** Proposed, as plan-EVS1-format-bytes's first option: EVS1-M2-01, EVS1-M2-04 and EVS1-M2-05 write the missing bytes here, `testdata/evs/` pins them in vectors as those tasks land, and design-records folds this file into §11.6 before M2's entry review, where peer review judges real bytes. Nothing is frozen: the specification freezes at M2's entry review and the bytes at its exit review (§23.8). A choice a reviewer dislikes costs a vector rewrite. Each rule below cites the owner's answer it comes from, by question file and row, and the last section lists what this file chose beyond those answers. Two parts wait on questions this file raised, and say so where they appear.

## Common encodings

- **Integers** in a fixed layout are big-endian, unsigned unless named signed. Times are milliseconds since the Unix epoch, UTC, as signed 64-bit integers, unless named seconds or days (plan-EVS1-format-bytes#7).
- **Ids** are 16 bytes: repo, ref, push, slot, parcel, drop, deletion and file ids, sidecar and client ids. A segment id is 32 bytes, the SHA-256 of the segment's bytes. A token is 16 bytes, and a token path is its tokens concatenated in order, 16 B per component, at most 32 components.
- **Protobuf.** Every message is proto3 from `evs.proto`. No message holds a map or a oneof (§22.5), so `proto.MarshalOptions{Deterministic: true}` writes one encoding for a value on every leg. A reader keeps the fields it cannot name. Hashes and signatures cover bytes as received, never a re-marshal (§22.6): `entry_sha256`, `statement_sha256`, `parts_sha256`, every payload hash, C_v and every Merkle leaf read the stored or received bytes.
- **AEAD.** Every seal is XChaCha20-Poly1305 with a random 24 B nonce, written nonce | ciphertext | 16 B tag unless a layout below places them (§11.6's nonces row). Nothing is encrypted deterministically.
- **Keys** are §10.5's, each `HKDF-SHA256(RK_g, salt repo_id, info "UR evs 1.0 " || purpose || u64be(g))`, through `EvsRepoKey.DeriveKey`: `fek` wraps object keys, `manifest` seals names, entry fields, push metadata and ref names, `path` keys tokens, `ref` keys ref ids from RK_1 for the repo's life.
- **Statement hash.** `statement_sha256` is the SHA-256 of a Signed `EvsPush`'s bytes as received.

## Enumerations

Each is an `evs.proto` enum, so the numbers live in one place. Fields the design fences as `uint32` (`ref_kind`, `ref_mode`, `kind`, `flags`, `layout`, `versioning`) carry these numbers.

| Value | Numbers | From |
|---|---|---|
| Ref kind (`EvsRefKind`) | 1 shared, 2 owned, 3 deposit, 4 erasure | plan-EVS1-format-bytes#6 |
| Ref mode (`EvsRefMode`) | 1 git, 2 file | `EvsPush.ref_mode`'s comment |
| Entry kind (`EvsEntryKind`), `EvsEntryVersion.kind` and `EvsName.kind` | 1 file, 2 directory | #6 |
| Record kind (`EvsRecordKind`) | 1 checkpoint, 2 diff, 3 chunk | #6 |
| Key ref kind (`EvsKeyRefKind`) | 0 the container's own key block, 1 a slot | #3 |
| Oid kind (`EvsOidKind`) | 1 SHA-1, 2 SHA-256; format 1 writes SHA-1 only | #3, #4 |
| Batch record type (`EvsBatchRecordType`) | 1 push, 2 part, 3 seal, 4 reseed | #6 |
| Repo kind, `repo/`'s kind | `acl.proto`'s `RepoKind`, general 1 to secret 9 | #6 |
| Repo state (`EvsRepoState`) | 1 keying, 2 active, 3 deleted, 4 shredding, 5 shredded | #6 |
| Payload section (`EvsPayloadSection`) | 1 to 14, below | #7 |
| New-object kind (`EvsNewObjectKind`) | 1 segment, 2 staged segment (format 2), 3 slot | #7 |
| Read path state (`EvsReadPathState`) | 1 collected, 2 drop_pending, 3 dropped, all format 2's | #8, protos-services-read-states |
| Read object kind (`EvsReadObjectKind`) | 1 segment, 2 slot, 3 map part, 4 log page, 5 batch record | this file |
| Push outcome (`EvsPushOutcome`) | 0 settled, 1 unknown | this file |

## Refusal codes

`EvsRefusalCode` is §11.8's fixed code table. The head's 16 B `EvsRefusal` record holds a code in 2 bytes, and `EvsRefusalReply.code` names why evs answered anything but a 200, on every route. A code has one status, and its range says how it lives:

- **1 to 63: recordable.** What §11.8's refuse row records in the head before answering, which every later attempt of the push id then gets with `recorded: true`. Some of these codes are also final in a case the refuse row names, such as 5c's VERSIONING from a kind or ref rule and 5d's INDEX_EPOCH below the head's (plan-EVS1-format-unsupported). 1 to 25 are plan-EVS1-format-bytes#6's. Format 2's refusals are numbered from format 1, so a format-1 binary after a rollback answers a recorded one by its code.
- **64 to 127: final.** Refusals the head or a terminal `repo/` state settles for good, which are never recorded.
- **128 and up: refuse nothing.** The client may retry the same statement.

| Code | Name | Status | Where |
|---|---|---|---|
| 1 | SCOPE | 403 | 5c's scope |
| 2 | TIME_STALE | 409 | 5b's time |
| 3 | REPO_KEYING | 409 | 5c: `repo/` keying |
| 4 | REPO_DELETED | 409 | 5c: `repo/` deleted |
| 5 | QUOTA_PAYMENT | 402 | 11.13's storage limit, a purchase lifting it (§20.7) |
| 6 | QUOTA_LIMIT | 403 | the storage limit otherwise; never 429, which refuses nothing |
| 7 | CLUSTER_FULL | 507 | the storage limit at §19.9's cohort limit |
| 8 | GATE_CLOSED | 412 | 5d's predicate |
| 9 | INDEX_EPOCH | 409 | 5d's index epoch |
| 10 | MAP_PARTS | 409 | 5e: a map's parts missing or over 24 h old |
| 11 | EPOCH_SOURCES_FULL | 412 | 5e |
| 12 | PATH_EPOCH_DUE | 412 | 5e: a creation while blocked |
| 13 | DIRECTORY_FULL | 409 | 5g |
| 14 | SEGMENT_GONE | 409 | 5h: a receipt past its age |
| 15 | VERSIONING | 409 | 5c and 5h |
| 16 | SLOT_UNKNOWN | 409 | 5h's slot rule |
| 17 | SLOT_STALE | 409 | step 6 |
| 18 | NOTHING_TO_ERASE | 409 | 11.12 |
| 19 | DROPPED | 409 | 5h (format 2) |
| 20 | DROP_PATH | 409 | 5c (format 2) |
| 21 | DROP_CONSENT | 409 | 5c (format 2) |
| 22 | DROP_STATE | 409 | 5c (format 2) |
| 23 | DROP_BOUNDARY | 409 | 5h (format 2) |
| 24 | DROP_LIST | 409 | 5h and the checks row (format 2) |
| 25 | FORMAT_UNSUPPORTED | 409 | a format-2 construct, with `needs_format` (plan-EVS1-format-unsupported) |
| 64 | REF_MODE | 409 | 5c's ref rules, and plan-EVS1-ref-name-bytes#3's erasure ref |
| 65 | PUSH_ID_REUSED | 409 | 5a |
| 66 | NON_FAST_FORWARD | 409 | 5f and the lease, git mode |
| 67 | BASE_STALE | 409 | 5f, file mode (plan-EVS1-deposit-head) |
| 68 | PATH_CONFLICT | 409 | naming the paths: 5g, 5e's tail, a seal's rerun, a BASE's other changes |
| 69 | PATH_EPOCH | 412 | 5e: an older epoch |
| 70 | SHREDDING | 409 | 5c, and restore past deleted |
| 71 | DROP_KIND | 409 | 5c (format 2) |
| 72 | SEGMENT_STALE | 409 | the segment route, and a re-upload |
| 73 | STATEMENT_MISSING | 409 | DELETE and restore without their projected statement |
| 74 | GROUP_NOT_READY | 409 | the activate route (plan-EVS1-repo-activate-route) |
| 128 | INVALID | 400 | a body, statement or signature that does not parse or verify, or a statement over 1 KiB |
| 129 | NOT_FOUND | 404 | a repo, ref or object evs holds no record of |
| 130 | PARTS_MISSING | 409 | a seal's part missing at its place |
| 131 | BUSY | 429 | 8 lost head races |
| 132 | FOLD_BEHIND | 429 | step 6 |
| 133 | TIME_AHEAD | 429 | 5b |
| 134 | RESOURCE_EXHAUSTED | 429 | the write budget, and a quota's window (§20.7) |
| 135 | WAIT | 429 | another push's lease, a fence wait, or a refusal meeting 8 live records or a refusal fence under 1 s old |
| 136 | UNAVAILABLE | 503 | the store unreachable, evs's clock unsure, the HDD share, or the outcome unknown |

A 429 and a 503 carry `retry_after_ms` and a Retry-After header of the same delay rounded up to whole seconds. A 503 whose attempt may still have committed sets `outcome` to unknown, and the client's retry with the same push id and statement resolves it (§11.8's outcomes). A refusal past a quota carries `quota`, §20.7's QuotaRefusal. A route that meets a refusal no row above names takes the next free code in the range its refusal belongs to, here and in `evs.proto` at once.

## Ids and object keys

- **Ref ids.** `ref_id = HMAC-SHA256(K_ref, "ref" || ref name bytes)[:16]` (§11.6). The ref name bytes are `<b>` for `refs/heads/<b>`, the full `refs/tags/<t>` for a tag, and the bare name for every other ref, such as `main`, `ur/<sidecar_id>/…`, `ur/index`, `ur/lfs` and `cards`; `<sidecar_id>` inside a name is `Id.String()`, 36 characters, and a conflict ref's `<time>` is UTC `yyyymmddThhmmssZ` (plan-EVS1-ref-name-bytes#1 and #2).
- **Deposit ref ids** are the first 16 B of SHA-256(repo_id || sidecar_id), and the erasure ref's id is the first 16 B of SHA-256("UR evs 1.0 erasure" || repo_id) (plan-EVS1-ref-name-bytes#3). Deposit and erasure refs stay at path epoch 1 for life, their entries named by random 16 B ids (plan-EVS1-epoch-kinds#2).
- **Tokens.** t_i = HMAC-SHA256(K_path_p, t_(i-1) || name_i)[:16], t_0 sixteen zero bytes, over a component's raw bytes: nothing is normalized, so NFC and NFD spellings are two paths, and a component that is empty or holds a slash or NUL, which git's tree format cannot hold, is refused. A token path is 1 to 32 components in a change; a covering prefix may be shorter, down to the empty path, which covers every change. Deposit and erasure-ref entries take random 16 B ids in tokens' place (§11.6, plan-EVS1-epoch-kinds#2).
- **In object keys** repo, ref, slot and parcel ids are lowercase hex with no dashes; segment ids lowercase hex of their 32 B; tokens 26 lowercase RFC 4648 base32 characters, unpadded; versions, epochs, page numbers and parts decimal, zero-padded to 20 digits. A map's `<map>` is its `path_map_sha256` in lowercase hex. A batch's `<instance>` and `<seq>` are 8 lowercase hex digits each (§11.8's batches). The deepest `idx/` key is 956 B, within §11.3's 1,024 (plan-EVS1-format-bytes#9).
- **Entry state.** Objects carry no user metadata, except an `idx/` entry's state while its head lists sources: the key `entry-state`, whose value is `carried:<source epoch in decimal>`, `fresh` or `removed`, read by HEAD (plan-EVS1-entry-state-metadata).

## The chain and the digest

- C_0 = SHA-256("UR evs 1.0 ref" || repo_id || ref_id); C_v = SHA-256(C_(v-1) || push_id_v || statement_sha256_v) (§11.8).
- The paths digest is a 64-bit Bloom filter, k = 2: for each token path it covers, h = SHA-256("UR evs digest" || token path), and it sets bits u32(h[0:4]) mod 64 and u32(h[4:8]) mod 64. It is written as a u64 whose bit i is index i (#7).
  It covers each changed token path and, when the change list is not inline, each covering prefix in `changed_prefixes`. A query asks of a path and of each prefix holding it down to its first component; the empty path is no query, since no change names it. A miss on all of them proves the push changed neither the path nor a directory holding it, and a match only sends the asker to the change list.
- Merkle trees are RFC 9162's: leaf SHA-256(0x00 || bytes), node SHA-256(0x01 || left || right). A change's leaf is its `EvsChange` bytes as listed. Changes sort by their token paths' bytes, each part a contiguous run in part order; a part's `changes_root` is over its changes, and a statement's over its parts' roots as 32 B leaves (§11.6's merkle row).
  A one-part push whose change list is not inline states `changes_root` over its changes directly, so an inclusion proof is one RFC 9162 path there and two, part level last, in parts. The order is strict: a path listed twice is refused as out of order. The empty tree's root is SHA-256 of no bytes. An absence proof (§11.9) speaks for one token path: its leaves sort on either side of it, and they are adjacent in one part, the last and first of adjacent parts, or, with one side empty, the list's first or last leaf. A one-part proof's tree size must equal the statement's `change_count` and a part-level proof's its `part_count`; a part's own size is signed nowhere, so the two leaves of one part must claim one size, and RFC 9162's split of leaves from nodes lets no other leaf stand where a part's first or last does. A reader asks for absence proofs of the path and of each prefix holding it that a covering prefix covers.

## Segments, object keys and record headers

A segment (§11.6) is at most 8 MiB: a public header, then for a general repo the wrapped-key block, then records, then random padding to Padmé(length). Its id is the SHA-256 of all its bytes.

| Bytes | Field |
|---|---|
| 0-3 | "URvs" |
| 4 | format: 1; 2 for format 2's kind-5 header |
| 5 | flags: 0 in format 1, and a reader refuses any other |
| 6-7 | zero |
| 8-23 | repo_id |
| 24-31 | generation g, u64 |
| 32-47 | a kind-5 header only: the push_id that introduces it (format 2) |

The widths of the public header are this file's; §11.6 gives its fields. The **wrapped-key block** is 72 B: 24 B nonce | 32 B object key sealed | 16 B tag, under fek_g, g the header's generation, AAD "UR evs 1.0 object key" || repo_id || u64be(g). In a general repo's kind-1 segment it sits at byte 32, records following at byte 104; in a kind-5 segment at byte 48. An inline chain's first inline record opens with the same block, and the chain's later records use that key. Slot-keyed repos and deposits have no block (plan-EVS1-format-bytes#2).

A **record** is a 160 B header, then its body in 64 KiB STREAM frames under its object key: nonce = the header's 19 B prefix || u32 frame counter || a final-flag byte (1 on the last frame, else 0), AAD repo_id || file_id || record_id || u64be(generation) || u32be(frame index), as in age (§11.6). The header is 24 B nonce | 120 B sealed | 16 B tag, under manifest_g (a deposit's K_dep, below), g the segment header's generation or an inline record's push generation, AAD "UR evs 1.0 record" || repo_id || u64be(g) (#3). The 120 sealed bytes:

| Bytes | Field |
|---|---|
| 0-15 | record_id |
| 16-31 | base_record_id, zero unless a diff |
| 32-63 | oid; SHA-1 left-aligned and zero-filled |
| 64-79 | slot_id, zero unless key_ref_kind 1 |
| 80-87 | generation, u64 |
| 88-95 | body_length, u64 |
| 96-97 | key_index, u16 |
| 98 | kind |
| 99 | key_ref_kind |
| 100 | oid_kind |
| 101-119 | nonce_prefix, 19 B |

The widths of the frame AAD's generation and index are this file's. The header's `generation` is the one its frames' AAD names: the container's g for key_ref_kind 0, which a reader holds to the segment header's or the inline chain's, and for key_ref_kind 1 the slot key's own generation, which a reader holds to that key's `EvsSlotKey.generation`, so a versionless path's slot key keeps opening after a rotation. A body of L bytes is max(1, ceil(L / 64 KiB)) frames, every one but the last full and the last the remainder, empty only when L is 0; a whole record is 160 + L + 16 per frame bytes, which a locator's length must equal; and L is at most 8 MiB, since a record lives in a segment or inline. kind 1 to 3, key_ref_kind 0 or 1, oid_kind 1 (SHA-1, plan-EVS1-format-bytes#4), a generation from 1, a slot only for key_ref_kind 1 with key_index below 64, and a base only for a diff; a reader refuses any other header as tampering.

An **inline record** (§11.7: a chain that pads to at most 16 KiB) is its locator's bytes: for the chain's first record the block of a fresh key under fek of the push's generation, then the record; for a later one the record alone, under the chain's key and with the chain's generation in its header; either then random bytes to Padmé of its length, as a segment pads, so an entry version, which evs sees, shows no exact record length. A locator's bytes are at most 16 KiB.

EVS1-M2-04 owns the record and segment codecs and pins these in `testdata/evs/record_vectors.json` and `segment_vectors.json`.

**Deposits.** A depositor holds no manifest key, so a deposit seals its record header, its entries' `sealed_fields` and its push's sealed metadata under K_dep = HKDF-SHA256(object key, salt repo_id, info "UR evs 1.0 deposit"), the object key being the deposit's own, which its slot wraps by HPKE to the drop key. The header uses #3's layout with key_ref_kind 1; a push's sealed metadata goes under the K_dep of its first entry; bodies stay under the object key. `sealed_ref_name` stays empty and deposit entries carry no name row. A reader takes the slot from the entry's cleartext `slot_ids`, opens it with the drop private key, then derives K_dep (plan-EVS1-format-bytes#5).

A deposit's slot key is HPKE in base mode with §10.6's wraps' suite, X-Wing (`MLKEM768X25519`), HKDF-SHA256 and AES-128-GCM, info "UR evs 1.0 deposit key" and AAD repo_id || u64be(g), g the drop key's generation, which `EvsSlotKey.generation` carries: enc 1,120 B | the 32 B key sealed | 16 B tag, 1,168 B. A **slot object** lists its keys in ascending `key_index`, all wrapped one way, under fek or to a drop key; a slot every key of which was erased stays, holding none.

## Sealed values and names

- `EvsEntryVersion.sealed_fields` opens to `EvsSealedFields`, and a push's sealed metadata to `EvsSealedMetadata`. Each is sealed as 24 B nonce | ciphertext | 16 B tag under manifest_g, g the push's generation, AAD "UR evs 1.0 fields" or "UR evs 1.0 metadata" || repo_id || u64be(g) (#9). `content_sha256` is set for versioning 1 and 2 only, which are format 2's.
- `EvsSealedMetadata` holds §10's (group_id, epoch, epoch_authenticator) the writer pins, as §6's `GroupHead`; the provenance, §5.5's agent id and format 2's tainted bit, which format 1 ignores; in git mode every commit of the update, oldest first, each with its sealed changes against its first parent, so export rebuilds every original oid (§11.7's mapping to git); and an import's Signed `EvsImport`.
- A name (§11.7's name row) is sealed alone: the name, then 0x80 and zeros to the next multiple of 64 B, under a random 24 B nonce with a 16 B tag, AAD repo_id || u64be(p) || parent token || child token, p the path epoch whose tokens the row uses, under manifest_p. The key's generation and the AAD's widths are this file's reading, for EVS1-M2-04's vectors to pin.
  The padding is exactly one step: a reader refuses a marker outside the last 64 B, or a non-zero byte after it, and then recomputes the child's token from the parent's and the name, refusing a mismatch. A carried row (`EvsName.epoch`) opens under its source epoch's manifest and path keys and its directory's token in that epoch, an epoch older than its table's. A table that lists a token twice, or a kind other than file and directory, is refused whole. The 448 KiB bound counts each row as the table encodes it with its epoch cleared.
- A file's sealed fields hold a 16 B `file_id`, a git file mode (100644, 100664, 100755, 120000 or 160000; a directory is no file) and a SHA-1 oid; format 1 refuses `content_sha256` as FORMAT_UNSUPPORTED.

## Statements and payloads

A statement is a Signed `EvsPush`, at most 1 KiB as signed (§11.6). A **payload** is a sequence of sections, each type u8 | length u32 | bytes, in ascending type, each at most once and absent when empty (#7). Inside a section, repeated items are u32 length | bytes, but part hashes and DROP lists are bare 32 B values. Each `*_sha256` field of the statement hashes its section's bytes, the type and length excluded.

| Type | Section | Its bytes | Hashed by |
|---|---|---|---|
| 1 | entry versions | an item per change that writes an entry, in change order: the `EvsEntryVersion` bytes its `entry_sha256` names | each change's `entry_sha256` |
| 2 | sealed metadata | the sealed `EvsSealedMetadata`, one value | `sealed_metadata_sha256` |
| 3 | inline records | an item per inline record | see below |
| 4 | change list | an item per change, sorted: its `EvsChange` bytes, only when the statement carries `changes_root` | `changes_root` |
| 5 | part hashes | each part's SHA-256 in part order, bare | `parts_sha256` |
| 6 | new objects | an item per segment or slot the push introduces: kind u8 \| id (32 B, a slot's 16 B) \| padded_size u64 \| upload_day u32 (days since the Unix epoch, 0 for staged segments and slots) | `new_objects_sha256` |
| 7 | slot bodies | an item per new slot, in the order of its kind-3 new-objects item: its `EvsSlotObject` bytes | none: a key that is not its record's fails that record's AEAD |
| 8 | erased list | an item per erased key: slot_id 16 \| key_index u16 | `erased_sha256` |
| 9 | DROP body | the `EvsDropHistory` bytes, one value (format 2) | `drop_sha256` |
| 10 | DROP lists | each `EvsDropPath`'s listed `entry_sha256` values in `paths` order, ascending within a path, bare (format 2) | each path's `listed_sha256` |
| 11 | tail moves | an item per move: its `EvsPathMove` bytes | `path_tail_sha256` |
| 12 | source paths | an item per change, in change order: that change's `EvsSourcePath` encodings, each u32 length \| bytes, none for a change no listed source may hold | `source_paths_sha256` |
| 13 | reuse list | an item per committed version a new version's segments cite: ref_id 16 \| entry version u64 \| its token path | none: it only points 5h at what the chains, under their `entry_sha256`, already name |
| 14 | Merkle proofs | an item per entry version, in section 1's order: its `EvsMerkleProof` to its part's `changes_root`, empty when the change list is inline | `changes_root` |

Sections 1, 2 and 4 to 6 and 9 to 11 are plan-EVS1-format-bytes#7's. The item layouts of sections 7, 8, 12, 13 and 14 are this file's, for EVS1-M2-05's `push_vectors.json` to pin.

**Section 3 waits.** §11.7 puts an inline record in its entry version's chain, as `EvsLocator.inline` under `entry_sha256`, and folds the newest version "with its inline records", eliding them from older ones; §11.6 also lists inline records in the payload and in `EvsPushPart.inline_records`. Which of the two carries the bytes is questions/evs1-m2-01-inline-record-home.md. Until it is answered, a writer puts each inline record in its locator and leaves section 3 and `inline_records` empty, and evs refuses a push or part that sets them as INVALID.

**Parts.** A push over 1 MiB or 1,024 entry writes goes in 2 to 1,024 parts (§11.8). Each `EvsPushPart` carries its changes, entry versions, inline records and sealed metadata slice in fields 3 to 6, and its slice of every other section in `sections`, framed as a payload is: joined in part order, the slices of one section are what a one-part push carries, and a slice may split anywhere. `parts_sha256` covers `sections` because it sits inside the part, which counts against the part's 1 MiB. The seal, never a part, runs a DROP's body and list checks, since only the seal reads every part (plan-EVS2-drop-list-parts). The seal itself carries no payload.

**Staged bytes**, format 2's, follow the last section outside every hash: in a batch record after the payload, and in a request as `staged`.

**What EVS1-M2-05's codec reads into these rows.** A part's changes are its field-3 messages' bytes as the part was received, which its Merkle leaves are, never a re-marshal; parts number from 1 to `part_count`, and each holds at least one change. Section 5 is never carried in format 1: a part cannot hold its own hash and the seal carries no payload, so the seal computes `parts_sha256` from the parts it reads, and a payload or part holding section 5 is refused. Section 12 is present while the head lists sources, an item per change, empty for a change no source may hold. A one-part push's payload passing 1 MiB, or its entry writes passing 1,024, sends the push to parts. `changed_prefixes`' 512 B counts token bytes, 16 per component; a covering prefix may be the empty path, which covers every change, and a writer picks the deepest prefixes that keep the signed statement within 1 KiB. A removal (`entry_sha256` empty) names a version, so one with `base_entry_version` 0 is refused. The checks row refuses as INVALID what needs no head: an entry version naming another push or base version, a locator outside kinds 1 and 2 or out of shape, layout other than 0; it leaves the versions rule to 5g, whose answer is 409. A new slot body is an `EvsSlotObject` with at least one key, one per kind-3 new object in order.

## Batches

A batch (§11.8) is at most 256 KiB, or one record of up to 1 MiB: header | records | index | trailer (#7).

| Part | Layout |
|---|---|
| header, 32 B | "URpb" \| format u8 (1; 2 for a batch holding staged segments or purge candidates) \| 3 zero bytes \| instance u32 \| minute u32 (minutes since the Unix epoch) \| seq u32 \| created_ms i64 \| record_count u32 |
| record | type u8 \| 3 zero bytes \| repo_id 16 \| ref_id 16 \| push_id 16 \| signer_sidecar_id 16 \| time_ms i64 \| length u32 \| body |
| index | offset u32 \| length u32 per record, in record order |
| trailer, 36 B | index_offset u32 \| SHA-256 of every byte before the trailer |

A record's body is its items in the order §11.8's record row lists them, each u32 length | bytes: a push's Signed `EvsPush`, then its payload; a part's Signed `EvsPush`, its `EvsPushPart`, then one item per receipt (`EvsUploadReceipt` bytes), then the head version evs checked it at as a u64 item; a seal's Signed `EvsPush`, then one item per part of its 20 B `EvsPlace`, its 32 B `changes_root` and its first token path; a reseed's re-seeded Signed `EvsPush` with its payload. A push's or part's staged segments, and in a format-2 batch its purge candidates, follow its items. This framing is this file's; EVS1-M2-05 owns the batch codec and pins it in `batch_vectors.json`.

## Places, window entries and refusal records

- `EvsPlace` packs to 20 B: minute, instance, seq, offset and length, each u32 (#7).
- `EvsWindowEntry`, 64 B (§11.8's entry row): push_id 16 | statement_sha256[0:16] | place 20 | paths_digest u64 | flags u32. Flag bits are `EvsWindowFlag`'s, bits 16-31 the change count, saturating. Format 1 ignores bits 4 and 5.
- `EvsRefusal`, 16 B (§11.8's refusal row): push_id[0:8] | statement_sha256[0:2] | code u16 | until_s u32, until_s UTC seconds rounded up.

## Stored objects

| Key | Body | Notes |
|---|---|---|
| `place/<repo_id>` | `EvsRepoPlacement` | written once, on the first metadata cluster |
| `repo/<repo>` | `EvsRepoObject` | `network_id` from the creating token, checked against the projection's `AclRepo`, never changed, kept in the shredded tombstone; a reader finding none treats the repo as held (plan-EVSB-repo-network) |
| `head/<repo>/<ref>` | `EvsHead` | server-internal: readers get `EvsHeadSummary` |
| `log/<repo>/<ref>/<n>` | `EvsLogPage` | built alike by any writer, so a 412 on equal bytes is success; this message is this file's |
| `idx/<repo>/<ref>/<p>/<t1>/.../<tn>.e` | `EvsIndexEntry` | per file up to four `EvsIndexVersion`s, newest first, all but the newest elided; a directory's table with `names_through`; a removal's marker; a drop mark, which format-1 writers keep |
| `slot/<repo>/<slot_id>` | `EvsSlotObject` | up to 64 keys in ascending index; an erased key leaves the list and no index shifts (#9); a key's `wrapped` is the 72 B wrapped-key block a segment carries, under fek of the key's generation, and a deposit's is HPKE-XWing to that generation's drop key, as above |
| `pmap/<repo>/<ref>/<p>/<map>/<part>/_` | a Signed `EvsPathMap` part | |

EVSB's plan adds `EvsPidxEntry` for `pidx/` here when EVSB-M2-10 lands. `pb/` holds batches above, and `seg/` segments.

## HTTP bodies

Bodies are `evs.proto` messages, `application/x-protobuf`, except a segment PUT's raw bytes (#8). Every answer but a 200 is an `EvsRefusalReply`.

| Route | Request | 200 |
|---|---|---|
| `PUT .../segments/<sid>?push=<push_id>[&closure=1]` | the segment's bytes | `EvsUploadReceipt` |
| `POST .../push` | `EvsPushRequest`: a one-part push's statement, payload, receipts and staged bytes, or a seal's statement and `part_places` | `EvsPushReply`: `version` |
| `POST .../push/<push_id>/<k>` | `EvsPartRequest` | `EvsPushReply`: `place` |
| `POST .../push/<push_id>/lease` | `EvsLeaseRequest` | no body |
| `POST .../read` | `EvsReadRequest` | the framed reply, below |
| `GET .../refs[?moved_after=<push sequence>]` | none | `EvsRefsReply` |
| `GET .../log?ref=<ref_id hex>&since=<version>` | none | `EvsLogReply`, at most 1,000 statements |

Query values are decimal, and ids in them lowercase hex. The other routes' bodies are their tasks', added here as they land.

**The read reply** is a stream of u32 length | `EvsReadFrame`, each frame one of §11.9's parts by its set fields, with no oneof: the head summary first; the statement of each version after the pin, in order, or `behind` with the first missing version; one frame per path; then the records, slots, map parts, log pages and push records they name, an object past 1 MiB spanning frames by `offset`; and last a frame with `end` set. A streams read repeats head, statements, paths and objects per ref, and a ref it stops at its 4 MiB answers `more` with its next version (#8). A reader refuses a path frame holding any `EvsReadPathState` as FORMAT_UNSUPPORTED {needs_format: 2} (protos-services-read-states).

**The deposit head.** A push's 200 on the caller's own deposit ref carries `deposit_head`: for a commit the version it committed, for a 5a retry the current head. So does 5f's BASE_STALE there, read from the cluster head. `consumed_through` is the head's, which the ingester declares in its CONSUME's `EvsPush.consumed_through`, the highest version of the deposit ref at or below which its read left no unconsumed deposit, and which evs copies to `EvsHead.consumed_through`, never falling (plan-EVS1-deposit-head, plan-RECORD-depositor-spool). A depositor learns nothing else of the head.

## Not fixed here

- **A ref's sealed name and an overlay's base.** The head holds both, and no part of a push carries them: the statement has no field for either, and no payload section is theirs. questions/evs1-m2-01-ref-creation-fields.md asks how a creating push conveys them. Until it is answered, evs stores no sealed ref name, so a reader maps a listed ref back only by deriving ref ids from names it holds; and since no push can declare a base, writers create every ref whole and evs records no overlay.
- **Section 3's inline records**, above.
- **The upload receipt's MAC input**, whose bytes EVSB-M2-09 fixes with the receipt keys.
- **Fields no §2.8 row names yet**, which `testdata/evs/metadata_rows.yml` lists as pending and questions/evs1-m2-01-metadata-rows.md raises.

## What this file chose

For design-records, each is a reading that changes no D- item:

| Item | Chosen |
|---|---|
| Refusal codes past 25 | Ranges by how a refusal lives; 64 to 74 the final ones §11.20 and the answers name, 128 to 136 the answers that refuse nothing; PATH_CONFLICT for every 409 naming paths, INVALID, NOT_FOUND and WAIT where §11 names no code |
| `EvsRefusalReply.outcome` | The `EvsPushOutcome` enum, 0 settled and 1 unknown |
| Segment public header | "URvs" \| format u8 \| flags u8 \| 2 zero bytes \| repo_id \| u64 generation; flags 0 |
| Frame AAD widths | u64 generation, u32 frame index |
| Names | Under manifest_p, p the row's path epoch; AAD repo_id \| u64 p \| parent token \| child token |
| Slot keys | A fek-wrapped key is the segment's 72 B wrapped-key block, its AAD included |
| Payload items | Sections 7, 8, 12, 13 and 14 as tabled above |
| Batch record bodies | Items in §11.8's order, each u32 length \| bytes |
| `log/` | `EvsLogPage` |
| `EvsSealedMetadata` | `GroupHead`, provenance, commits with their changes, the signed import |
| Read reply | `EvsReadRequest`, `EvsReadFrame`, `EvsHeadSummary`, `EvsReadPathReply`, the two proof messages and `EvsReadObject` as `evs.proto` writes them |
| Listings | `EvsRefsReply` with the repo's format and push sequence; `EvsLogReply` with the next version |
| Path components | Empty, slash and NUL refused, as git's tree format refuses them; nothing else |
| Digest queries | A path and each prefix down to its first component, never the empty path |
| One-part `changes_root` | Over the changes directly, so a proof there is one level |
| Absence proofs | One per token path; sizes held to `change_count` and `part_count`, a part's two leaves to one claimed size |
| Padmé | Lengths 0 to 3 pad to themselves; past 2^63 nothing is computed |
| Record `generation` | The frames' AAD generation: the container's, or the slot key's own |
| Frames | max(1, ceil(L / 64 KiB)), only the last short; L at most 8 MiB |
| Inline records | The first carries the chain's key block; each locator pads to Padmé with random bytes, at most 16 KiB |
| Deposit slot keys | HPKE base mode, X-Wing, HKDF-SHA256, AES-128-GCM; info "UR evs 1.0 deposit key", AAD repo_id \| u64 g |
| Slot objects | Keys in ascending index, all wrapped one way; an emptied slot stays |
| Name padding | Exactly one step; a carried row's epoch older than its table's |
| Part hashes | Never carried; the seal computes `parts_sha256` from the parts it reads |
| Parts | Numbered 1 to `part_count`, each with a change; leaves are field 3's bytes as received |
| Covering prefixes | 512 B of token bytes; the empty path allowed; the deepest that keep 1 KiB |
| Window flags | Bits 6 to 15 refused on read |
| Refusal records | Only codes below 64; until_s the ceiling of the milliseconds over 1,000 |
