# Index format 1

The bytes of the search index: normalizer 1, extractor 1 and every file under an index root. DESIGN.md §11.14 owns the design, and `evsindex.proto` holds its messages. This file fixes what §11.14 names without bytes, so that two honest builds write the same plaintext (FI-22), whose SHA-256 an entry version carries as `content_sha256`. Where the two disagree, DESIGN.md wins and the mismatch is reported.

**Status.** Proposed. This file writes down the resolutions of plan-SEARCH-index-format-bytes (ledger QD-300; its items 1-8 are QD-444, QD-477, QD-476, QD-473, QD-475, QD-443, QD-579 and QD-474), with search-format-all-directory-names's correction to item 5 (QD-475), and the rules the owner decided for plan-SEARCH-cherokee-fold (QD-256) and plan-SEARCH-shrink-claim (QD-173). Nothing is frozen: the specification freezes at M10's entry review and the bytes at its exit review (§23.8), and `testdata/index/` pins each byte in between. The last section lists what this file adds to those, for `design-records` to fold into §11.14.

## Common encodings

**VByte.** An unsigned integer of at most 64 bits, as LEB128, which `encoding/binary.AppendUvarint` writes: seven bits a byte, least significant group first, bit 7 set on every byte but the last. Encodings are minimal, so the last byte of a multi-byte value is never zero, and a value takes at most ten bytes, the tenth at most 0x01. Decoders refuse anything else.

**Fixed widths.** An entry's kind, a row's doc kind and a tombstone table's kind are one byte each. A `doc_key`, a `ref_id` and a `sidecar_id` are 16 bytes, copied as they are. A trigram key in a dictionary's block index is 3 bytes, most significant first. `u16be`, `u32be` and `u64be` are big-endian integers of those widths.

**Key order.** 16-byte keys compare bytewise. A trigram key is the integer b0 x 65,536 + b1 x 256 + b2 of its three bytes in text order, so integer order and byte order agree.

**Text.** Every text field is UTF-8. Decoders refuse invalid UTF-8.

**Messages.** Headers, manifests, settings, locks and erasure sets are proto3 from `evsindex.proto`, marshaled with `proto.MarshalOptions{Deterministic: true}`, each repeated field sorted as its comment says. No format-1 message carries an unknown field. A decoder re-marshals what it read, and refuses it unless the bytes are equal.

**Times.** Days count from 1970-01-01 UTC. An entry's time is ⌊time_ms / 1000⌋ of the signed `time_ms` of the content push that made its version, never a clock's; its bucket follows the signed time of the index push that carries it (QD-689, reading 5).

## Paths

Each path component is ASCII, and §11.7 seals and tokenizes it like any other. `<root>` is `.ur-index/i1` on a file-mode ref and `i1` on `ur/index`.

```text
<root>/settings                          versioned IndexSettings; every other file here is versionless (versioning 2)
<root>/lock                              IndexLock
<root>/a/m                               the all partition's IndexManifest
<root>/a/<n>                             all shard n, for n below 3,499
<root>/a/<k>/<n>                         all shard n, from 3,499 on, with k = 3499 + ⌊(n - 3499) / 1000⌋
<root>/b/<S>/m                           bucket S's IndexManifest
<root>/b/<S>/s/<n>                       bucket shard n
<root>/b/<S>/w/<h>/<writer>/<k>          slot k of a writer, k 0-15
<root>/b/<S>/w/<h>/<writer>/L<seq>       a writer's large entry
.ur-index/x or x                         the ref's IndexErasureSet, beside its roots
```

`<S>` is the bucket's start day, and `<n>`, `<k>` and `<seq>` numbers, all decimal with no leading zero, and 0 is `0`. Shards number from 0: a new shard takes the manifest's highest n plus 1, and joined shards keep the lower n. `<writer>` is the `sidecar_id` as 32 lowercase hex digits, and `<h>` its first two.

`a/` holds `m` and shards 0 to 3,498 as files, 3,500 names. From shard 3,499 on, a shard sits in directory `a/<k>/`, numbered from where the files stop (search-format-all-directory-names): shard 3,499 is `a/3499/3499`, shard 4,498 is `a/3499/4498` and shard 4,499 is `a/3500/4499`. So a directory's name is never a shard file's, nothing moves at the split, and `a/` stays inside §11.7's 3,584 names until some 84,000 shards past it.

## Normalizer 1

The steps run in this order over each field.

1. Invalid UTF-8 becomes U+FFFD, one for each byte that does not begin a well-formed sequence (`utf8.DecodeRune`'s rule), a cut final sequence included.
2. NFKC.
3. Full case folding by `cases.Fold()`, with no locale, then a fixed map: U+AB70-U+ABBF to U+13A0-U+13EF and U+13F8-U+13FD to U+13F0-U+13F5. x/text's fold swaps the two cases of those 172 Cherokee code points, where CaseFolding.txt takes both to the first form. The map is plan-SEARCH-cherokee-fold's rule, as the owner decided it, and it changes nothing on a correct fold, so a later x/text fix changes no output; a module bump is another normalizer anyway. `SearchOracle` applies it too.
4. NFD. A nonspacing mark (general category Mn) goes when the nearest code point before it that is not Mn is a letter (category L) of the Latin, Greek, Cyrillic, Arabic or Hebrew script, so stacked marks after one base all go, and a spacing or enclosing mark in between keeps what follows it. Then NFC.
5. Each maximal run of code points outside categories L, M and N becomes one U+0020. U+FFFD is in such a run, and so is everything step 1 replaced.

Steps 1-5 are idempotent, and they are what `indexNormalize` means. A document's text then follows from its fields:

6. Fields 1-4 (subject, from, to, title) keep the longest prefix of at most 1,024 B that ends on a code point.
7. A field with no text adds nothing. Any other adds U+0020, its text and U+0020, nothing else being trimmed, so a text with a space at an end shows two. Fields join in field-number order with nothing between them.

x/text's normalization inserts U+034F after 30 non-starters (the stream-safe rule of UAX #15), and that is part of normalizer 1: after a base whose marks stay, the mark stays too.

What the steps leave open, settled (DESIGN-DETAILS 11.2.2): step 1 counts bytes, not maximal subparts, so an overlong form, a surrogate, a value past U+10FFFF and a sequence cut short by the end of the value each give one U+FFFD a byte, and a well-formed U+FFFD stays. Steps 1 to 5 run on each field's value by itself, step 4's "nearest code point before" starting afresh, and on each chunk by itself, so a chunk that begins or ends inside a character shows U+FFFD there. Step 6 cuts after step 5, on normalized bytes, and may cut between a base and a mark step 4 kept. No step maps a code point to nothing but step 4, which keeps the letter, so a value that is not empty never normalizes to nothing, and step 7's test reads the same on the value before normalization.

**Tables.** Normalizer 1 is Unicode 17.0.0 from golang.org/x/text v0.43.0, read through `norm.Version`, `cases.UnicodeVersion` and `unicode.Version`, and the module version as `runtime/debug.ReadBuildInfo` reports it. A build linking anything else is another normalizer: it writes nothing, and a search of an index needing normalizer 1 reads status `update`. `IndexFileHeader.unicode_version` and `text_module_version` are read from the linked build at run time and are never constants.

**Trigrams.** A document's key set is the distinct keys of every 3-byte window of its text, windows across a field's padding included. A text under 3 bytes has none.

## Files

Every slot, large entry and shard is:

```text
"URix" | VByte header length | IndexFileHeader | body | zero pad
```

`body_length` counts the bytes of the body, which begins after the header and ends before the pad. The header does not count itself, so no value depends on its own length. A file's length before its pad is 4, plus the header's VByte, plus the header, plus `body_length`. `format` is 1, `normalizer` and `extractor` are 1, and `type` is 1 slot, 2 large entry, 3 bucket shard or 4 all shard. A `format` above 1 is no malformation: the file is left unread and search reads status `update`.

## Rows

```text
row   = doc kind (1 B: 1 file, 2 mail, 3 record, 4 derived)
        VByte flags
        VByte size
        VByte chunk
        VByte trigram count
        VByte started
        VByte expires
        ref_id (16 B, in ur/index only)
        text locator, text subject, text from, text to, text title
        record and derived rows: text field 6, text field 7, ... text field 15
text  = VByte length, then that many bytes
```

A row is at most 2,048 B in all. Whether `ref_id` is there is not in the file: the reader knows its root. Field 5, the body, is never in a row. An empty field is one 0 byte. File and mail rows have no fields 6-15, since only §16.8 and §16.11 register any, and record and derived rows carry all ten by position, so no mask needs a canonical rule of its own.

**Flags.** Bit 0 tainted, bit 1 outside, bit 2 private, bit n + 2 for field n cut (bit 3 subject through bit 17 field 15), and bit 18 for a locator that is not the exact path, because it was cut or held bytes that are not UTF-8. Bit 7 stays zero, and so do bits 8-17 on file and mail rows, and every bit from 19 on.

**Values.** `size` is the source's length in bytes: a whole file's on each of its chunks' rows. `chunk` is the chunk number of the doc_key, 0 for the first or only chunk. `trigram count` is n_d, the size of the document's key set, on diffs too. `started` and `expires` are seconds, and zero except on derived rows. A field with several values (§16.8's session ids and tools) joins them with one U+0020.

**Trimming.** A value first has invalid UTF-8 replaced as in step 1, because a row's strings reach `SearchHit`. Each value then goes to its own cap, on a code point: 512 B locator, 160 B fields 1-4, 256 B fields 6-15. If the row still passes 2,048 B, a walk in the order locator, 1, 2, 3, 4, 6-15 lets each value keep what the 2,048 B leaves after the fixed part and the values before it, cut on a code point. That count takes every later value as empty, one length byte each, and the flags at their widest, 3 B, since a cut can widen them. A field that lost bytes sets its bit, and a locator that lost bytes or was replaced sets bit 18. Such a hit shows, and cannot be opened by its locator.

## Entries

```text
entry      = kind (1 B) | key (16 B) | VByte version | VByte time | by kind:
  1 full           row | key set
  2 diff           VByte base version | row | key set added | key set removed
  3 tombstone      nothing
  4 ref tombstone  nothing; key is the ref_id, and only ur/index holds one
key set    = VByte count | count VByte gaps
```

A key set's first gap is its first key + 1, and each later gap the difference from the key before, so no gap is zero. Keys are at most 0xFFFFFF. A key set encodes to at most 512 KiB, since a chunk past that is skipped. A full entry's trigram count equals its key set's count. A diff's base version is below its version, and no key is in both of its sets. A diff stands only in a slot. Its base is the full entry of its key at its base version in another file of the same writer and bucket: a slot that is not that writer's head, or a large entry; of two, the one in the file with the higher seq (DESIGN-DETAILS 1.2.1, R1; QD-685).

**The dependency rule** (DESIGN-DETAILS 1.2.3). A writer's entry for a live version d is a diff only on the newest full entry of d's key below d's version, that the erasure set does not list, in the writer's own large entries and its slots other than its head, as the push's base shows them, of two at one version the one in the file with the higher seq; the delta is taken against it; and only where 2 x (|added| + |removed|) < |keys(base)|, the diff encodes within 8,192 B, d is no creation, and the base's file is a large entry, is already kept, or keep holds fewer than 8 slots. Anything else is full, in a slot within 8,192 B, else as a large entry. A file is kept when a diff in one of its writer's unabsorbed slots rests on it; the keep set is counted over those slots as the push leaves them, in key order. A writer never reuses a kept slot nor removes a kept large entry, and removes each absorbed large entry that is not kept at its next push in the bucket. Every push that writes a file of a writer's in a bucket replaces that writer's head there at the version its base showed (R2): a head sealed as it stood is written again with its own bytes, a writer with no slot in the bucket gets slot 0, empty if every entry is a large entry, and a push whose entries pass 256 KiB writes its head without the keys it carried.

**Deltas.** A diff's set is its base's set less `removed` plus `added`, `added` holding no key of the base and `removed` only keys of it. Composing (A1, R1) and then (A2, R2) gives ((A1 - R2) + (A2 - R1), (R1 - A2) + (R2 - A1)): the symmetric differences compose, which is why the composition is associative. The second delta must apply to the first's result, so A1 and A2 share no key, and neither do R1 and R2. Format 1's writers take every delta against the base itself, so nothing composes two deltas; the rule stands for readers of a later format.

## Slots and large entries

A slot's entries sort ascending by their 16-byte key, doc_key or ref_id, then by kind, with one entry a key, so a key repeated under another kind is refused too. A replaced entry goes and its successor takes its sorted place, so a head is a function of its entry set and not of arrival order, which §16.11's head reproduction rests on.

- **Slot, type 1.** The whole file is at most 16,208 B, each entry at most 8,192 B. `count` entries fill `body_length` exactly, and zero entries is a slot an erasure emptied.
- **Large entry, type 2.** The whole file is at most 1,048,576 B, and its one entry is over 8,192 B. A large entry's one entry is full.
- **Headers.** Both carry `bucket_start_day`, `bucket_days` (at least 1), `writer_sidecar_id`, `seq` and the table fields, and `pad_generation` and `tombstones` stay zero. `coverage` ascends by ref_id, then horizon false before true, with at most one row of each a ref (QD-689, reading 4). One counter a writer a bucket, from 1, numbers both slots and large entries, so `IndexManifest.absorbed` reads as one watermark.
- **Pad.** A slot or large entry has no pad of its own. A CLOSURE or a DROP's rewrite pads to the replaced length with zero bytes (a roll-up rewrites no newer bucket's file in place: it promotes into that bucket's shards, DESIGN-DETAILS 1.2.5; QD-686), and those are the only bytes allowed after `body_length`, on any file type. A decoder accepts any count of them inside the file's cap, re-encoding takes the pad's length from the file, and a writer's next head rewrite writes no pad.

## Shards

```text
shard       = "URix" | VByte header length | header | doc table | tombstones | dictionary | postings | pad
doc table   = count x (doc_key | VByte version | VByte time | row)     ascending by doc_key; a docid is a rank
tombstones  = tombstones x (kind | key | VByte version | VByte time)   ascending by kind, then key
dictionary  = VByte block count | blocks x (first key 3 B | VByte entries offset | VByte list offset) | key entries
key entry   = flag byte | the key's other bytes | VByte document count | VByte list bytes
```

A shard is at most 1,032,192 B before its pad and 1,048,576 B with it. `count` is its live documents, N below. `tombstones` is zero in an all shard, a key is at most once in a shard and never in both tables, and a ref tombstone is only on `ur/index`.

- **Blocks.** Keys ascend, 64 a block, the last block holding 1-64, and a shard with no key has no block. Merges and roll-ups always re-block by 64. A rewrite padded to a replaced length (a CLOSURE, a DROP's rewrite) first builds the shard this way, and if that outgrows the replaced length, rebuilds it keeping the replaced shard's partition: each block keeps its surviving keys, prefix sharing resets at each block's first key, and an emptied block goes. A removed key saves at least 4 B and costs the next key at most 2, so that always fits. Decoders accept blocks of 1 to 64 keys, refuse an empty or larger one, and re-encode from the file's own partition. This is plan-SEARCH-shrink-claim's rule, as the owner decided it, and the rewrite keeps the replaced header's `pad_generation`.
- **Offsets.** A block's entries offset counts from the first byte after the block index, and its list offset from the first byte of postings, so block 0 has 0 and 0, and neither depends on the block index's own length. Both ascend strictly.
- **Flag byte.** Bits 0-1 hold the prefix shared with the previous key of the block, which is the longest one and 0 for a block's first key. Bit 2 marks a bitset, and bits 3-7 are zero. The key's other bytes are the 3 - prefix bytes after it, so a block's first key is written in full again here.
- **Postings.** Lists follow in key order. A list is VByte gaps between ascending docids, the first gap docid + 1, or a bitset of ⌈N/8⌉ bytes, whichever is shorter, VByte on a tie. In a bitset docid d is bit d mod 8 of byte ⌊d/8⌋, bit 0 being the least significant, and the spare bits of the last byte are zero.
- **Merges** (DESIGN-DETAILS 1.2.4; SEARCH-M10-10 builds them). Of a key's candidates the highest version wins; at one version a tombstone, then the shards' own entry, then the full entry from the lowest `writer_sidecar_id`, then the lowest seq. A merge's new rows, ascending by key, go to the youngest shard Y (shard 0 when there is none): all of them if Y with all encodes within 1,032,192 B, else the count c that `lo = 0; hi = len(A); while lo < hi: mid = (lo + hi + 1) / 2; if Y with A[0:mid] encodes within 1,032,192 B then lo = mid else hi = mid - 1; c = lo` finds, and a new shard, the highest n + 1, takes again from there. Then, by ascending n, while a shard and the next come to fewer than 524,288 B before their pads, the two become one under the lower n, the joined shard tested again with its next; a shard left with no row and no tombstone is removed. A merge reads no head and writes no file of any writer's.
- **Pad.** `pad_generation` names the writer's newest generation g, and K_index_g = HKDF-SHA256(RK_g, salt repo_id, info "UR evs 1.0 index" || u64be(g)), which is `EvsRepoKey.DeriveKey` with purpose `index` and no further context. With L the shard's length before its pad, the pad is u32be(HMAC-SHA256(K_index_g, "pad" || SHA-256(the shard before its pad))[0:4]) mod step(L) zero bytes, "pad" being its three ASCII bytes. step(L) is 2^(E - S), with E = ⌊log2 L⌋ and S = ⌊log2 E⌋ + 1, Padmé's step at L, 16 KiB near a shard's cap. A rewrite in place pads with zero bytes to the replaced length instead, keeping the replaced header's `pad_generation`, and no reader recomputes that pad.

## Small files

`settings`, `lock`, `a/m`, `b/<S>/m` and the erasure set are the bare marshaled message: no magic and no pad. `IndexManifest.absorbed` is sorted by `writer_sidecar_id`, `IndexErasureSet.erasures` by `erasure_id`, `IndexErasure.docs` by `doc_key`, and `shards` as its comment says. Each sort is strict. `absorbed` holds a row for each writer with a watermark above 0; a manifest may list no shard (QD-689, reading 3).

## Documents

DESIGN-DETAILS.md section 11.2 is the source of this section and the next, and `testdata/index/conformance/` pins every rule in them by a vector (`mail.json`, `file.json`, `entities.json`, `charsets.json`). The identifiers stay extractor 1 and normalizer 1 (QD-693's reading 10). Extraction is total: every byte string has exactly one output and there is no error to return.

`doc_key` = HMAC-SHA256(K_ref, "UR evs 1.0 doc" || ref_id || u16be(len(name)) || name || u32be(chunk))[:16], K_ref from RK_1, `name` the path's bytes or a derived document's registered name. The path given to extraction is the path's own bytes, the same in every path epoch.

```text
D1  A version is extracted as mail when its repo is a mailbox, or a general repo laid out as a group inbox
    (§15.7), and its path begins "m/". Every other version that §11.14's never row lets in is extracted as a
    file. A record entry's or a derived document's fields are its class's (§16.8, §16.11).
D2  A file that S1-S3 find to be text has, for each chunk c of its text (D4), one document: field 4 is the
    file's title (S4), one SP and the path's bytes; field 5 is c. Field 4 has that form even when the title
    is empty. Fields 1-3 are empty.
D3  A message has, for each chunk c of its body text, one document: field 1 is the decoded Subject, field 2
    the decoded From, field 3 the decoded To and the decoded Cc, each left out when empty and joined by one
    SP when both stand, and field 5 is c. Field 4 is empty. "Decoded X" is W applied to H6's joined value of
    X, of the message's own header block alone. The body text is the walk's pieces (M1-M6) in the order the
    walk gives them, the empty ones left out, joined by one SP.
D4  The chunks of a text t are t[k x ChunkBytes : min(len(t), (k+1) x ChunkBytes + Overlap)] for k = 0, 1, ...
    while k x ChunkBytes < len(t), and the one empty chunk when t is empty. Chunk k is the document with
    chunk number k. Bytes are counted in the text as extracted (a file's after S1 and S3, a message's body
    text), before normalization. Every chunk carries the same fields 1-4.
D5  A document's row is this file's Rows: its locator the path's bytes, its subject, from and to the values
    of fields 1-3 before normalization, its title the title of S4 alone, never the path, each with N1 applied
    and then cut by Trimming; its size the length in bytes of the whole file or message, the same on every
    chunk's row.
D6  A document whose key set would encode past KeySetMax is skipped: it has no entry, and where its key was
    indexed before, its version is a tombstone (§11.14's sniff row).
```

A path's words are found through field 4. A message's attachment names sit in field 5 where their parts stand. Field 4's cut (normalizer 1's step 6) means a path's tail past 1,024 normalized bytes of title and path is not indexed. A version's documents are numbered 0 to n - 1 with n = max(1, ⌈len(text) / ChunkBytes⌉), so a version with fewer chunks than the one before leaves tombstones for exactly the chunk numbers from its n up.

## Extractor 1

**Terms.**

```text
LF 0x0A   CR 0x0D   SP 0x20   HT 0x09
white      the bytes 0x09 to 0x0D and 0x20
blank      SP and HT
well-formed UTF-8   Unicode's table 3-7 (RFC 3629): no overlong form, no surrogate, nothing past U+10FFFF
lower(x)   x with each byte 0x41-0x5A raised by 0x20, every other byte as it is; "ignoring case" means equal
           under lower
trim(x)    x without its leading and its trailing white bytes
letter     A-Z and a-z; digit 0-9; alphanumeric either; hex digit 0-9, A-F and a-f
```

No rule reads a header, a parameter, a label, a tag name or an encoding's name as Unicode text: names compare under `lower`, and only white bytes are trimmed (QD-693's reading 2).

**Limits.** These are format bytes: changing one is another extractor. Code reads them from `IndexFormatSettings`, whose defaults are these values (QD-702), except the two that are the normalizer's and the key set's own.

```text
HeaderMax       16,384 B   a logical header line, and the joined values of one field name (H4, H6)
LineWindow       1,024 B   the longest delimiter line (B1); the longest blank run inside a soft line break (T3)
MimeDepth           16     the multipart levels entered (M2)
ChunkBytes   1,048,576 B   a document's share of its source's text (D4)
Overlap            256 B   what a document repeats of the next (D4)
SniffWindow      8,000 B   the bytes that decide text or binary (S2)
TitleMax            80 B   a file's title (S4)
FieldCut         1,024 B   normalized subject, from, to and title (normalizer 1's step 6)
KeySetMax      524,288 B   a key set's encoding, past which its document is skipped (D6)
```

**Tables**, each part of extractor 1 or normalizer 1:

```text
Unicode       17.0.0: general categories and scripts from Go's unicode package (unicode.Version), normalization
              and case folding from golang.org/x/text v0.43.0 (norm.Version, cases.UnicodeVersion). A build
              linking anything else is another normalizer and writes nothing (Normalizer 1's Tables).
charsets      golang.org/x/text v0.43.0's encoding/htmlindex: 228 labels naming 40 encodings, listed in
              charsets.json (SHA-256 9c94ee72a1db3f894cd3765b3805839835b66fcca57f9530cbee31968b36a4da), and
              that module's decoder for each (C1-C3)
references    HTML's 2,231 named character references, 106 of them also without their ';' and 93 of them two
              code points: entities.json, SHA-256 9e7bac4a454044f307050b23fefa224beea56525742cc4774e1d4c6da6d40e57
block tags    address article aside blockquote br center dd details dialog dir div dl dt fieldset figcaption
              figure footer form h1 h2 h3 h4 h5 h6 header hgroup hr li main menu nav ol p pre section summary
              table tbody td tfoot th thead tr ul                                              (44 names; X4)
C1 table      what numeric references 128 to 159 mean, in order (E1): U+20AC 0081 201A 0192 201E 2026 2020 2021
              02C6 2030 0160 2039 0152 008D 017D 008F 0090 2018 2019 201C 201D 2022 2013 2014 02DC 2122 0161
              203A 0153 009D 017E 0178
```

Extraction calls no parser of the standard library or of any module: base64, quoted-printable, character references, header fields, parameters and multipart bodies are each a rule below (QD-690). What it takes from outside is the tables above, each pinned.

**Files.**

```text
S1  A file that begins FE FF is UTF-16 big-endian, and one that begins FF FE little-endian. The mark is
    dropped. Each two bytes after it are a code unit; a surrogate pair is its code point; a surrogate with no
    partner is U+FFFD; an odd last byte is U+FFFD. The text is the result in UTF-8, and the file is text.
    Nothing else is asked of it: U+0000 is allowed.
S2  Otherwise take the window, the file's first SniffWindow bytes or the whole file when it is shorter. The
    file is binary, and gives no document, when the window holds a byte 0x00, or when, reading well-formed
    UTF-8 sequences from the window's start, a byte is met that does not begin one, unless the bytes from
    there to the window's end are a proper prefix of a well-formed sequence (a character the window cut).
    The prefix test is exact: E0 80, ED A0 and F4 90 begin nothing. Otherwise the file is text, and its text
    is all of its bytes, whatever lies past the window.
S3  A text of S2 that begins EF BB BF loses those three bytes, once.
S4  The title: split the text at each LF. The title line is the first line that holds a code point of
    category L or N, reading the line as UTF-8 with N1's rule (so U+FFFD, which is neither, stands for each
    ill-formed byte). Take that line; drop its leading run of '#' and SP bytes; drop its trailing run of SP,
    HT and CR bytes; apply N1; cut to the longest prefix of at most TitleMax bytes that ends on a code point.
    No such line: the title is empty.
```

**Mail.** A message is read as RFC 5322 and MIME lay it out, by the rules below and no others. `extract_mail(content)`:

```text
fields, body = header_block(content)                                      H1-H5
subject = words(joined(fields, "subject"))                                H6, W
from    = words(joined(fields, "from"))
to      = join_nonempty(words(joined(fields, "to")), words(joined(fields, "cc")))
pieces  = []
walk(fields, body, 0, pieces)                                             M1-M6
text    = join_nonempty(pieces...)             the non-empty ones, in order, with one SP between
one document per chunk of text (D3, D4)
```

The header block:

```text
H1  Lines end at LF. A line's content is its bytes before the LF, less one CR when it ends in one. The last
    line may end at the end of the input instead.
H2  The header block is the lines from the start up to the first line whose content is empty. That line
    belongs to neither part; the body is everything after its LF. With no empty line, everything is header
    and the body is empty. A line of only blank bytes is not empty.
H3  A line whose first byte is blank, when a logical line stands before it, is appended to that logical
    line as it is, its leading blank bytes included. Any other line begins a logical line.
H4  A logical line is at most HeaderMax bytes: bytes past that are dropped as they arrive.
H5  A logical line with no ':' is no field. Otherwise its name is lower(trim(bytes before the first ':'))
    and its value is trim(bytes after it). Fields keep their order.
H6  first(name) is the value of the first field of that name, or empty. joined(name) is the values of every
    field of that name, in order, with one SP between each two, an empty value included, cut to its first
    HeaderMax bytes.
```

Encoded words (RFC 2047). `words(v)` scans v from the left:

```text
W1  An encoded word is "=?" C "?" E "?" T "?=", where C, E and T hold no '?', and E is one byte: B, b, Q
    or q. It may stand anywhere in v, inside a token too.
W2  Its charset is C up to its first '*'. It is not an encoded word when the charset is empty, when the
    charset or T holds a blank byte, or when W3 or W4 refuses T. Its text is T decoded by W3 or W4 and then
    as the charset's label says (C1-C3).
W3  B: drop every '=' at T's end. What is left must be base64 alphabet bytes (A-Z a-z 0-9 + /) and not 1
    more than a multiple of 4 long, or T is refused. Each 4 bytes give 3; a last 2 give 1 and a last 3 give
    2, the unused bits ignored. An empty T decodes to nothing.
W4  Q: '_' is SP; '=' and two hex digits are that byte; '=' followed by anything else, or by fewer than two
    bytes, refuses T; every other byte is itself.
W5  Find the leftmost "=?" at or after the scan position. If an encoded word starts there, take it and move
    the position past its "?="; if not, move the position 2 bytes on and look again. When none is left, the
    rest of v is text.
W6  The text between two encoded words is dropped when it is empty or only blank bytes, and kept otherwise.
    Text before the first word and after the last is kept. So is text between a word and something that is
    not one.
```

Media values and parameters (RFC 2045, 2183, 2231), for Content-Type and Content-Disposition:

```text
P1  The value is lower(trim(bytes before the first ';')). An absent or empty field has the empty value and
    no parameters.
P2  The bytes after the first ';' are split at each ';' that is outside quotes. A '"' opens quotes and the
    next '"' closes them; inside quotes a '\' and the byte after it are passed over together. A quote left
    open runs to the end.
P3  A piece with no '=' is no parameter. Otherwise its name is lower(trim(bytes before the first '=')) and
    its raw value trim(bytes after it). A name ending in '*' is extended, and loses that '*'. If the name
    then holds a '*', the bytes before the first one are the parameter's name and the bytes after it its
    section, which must be 1 to 9 digits and nothing else, or the piece is no parameter. So a parameter has
    up to three kinds of piece: plain, extended, and sections 0, 1, ..., each plain or extended. Of two
    pieces of one name and kind (and one section number), the first counts.
P4  A plain piece's value is its raw value unquoted: when it is at least 2 bytes and begins and ends with
    '"', those two go, and inside, a '\' followed by a byte gives that byte. Anything else is as written. An
    extended piece's raw value is never unquoted.
P5  param(name), in this order: (a) if it has a section 0, join sections 0, 1, 2, ... up to the first
    number that is missing; if the result is not empty, that is the value; (b) else its extended piece;
    (c) else its plain piece; (d) else empty.
P6  An extended value is charset ' language ' text when it holds two "'" (the first two split it), and
    otherwise all text with no charset. Its text is percent-decoded: '%' and two hex digits are that byte;
    if any '%' is followed by anything else, the whole text stands as written. In (a), an extended section
    is percent-decoded, a plain one is not, and only section 0, when extended, is split for a charset. The
    bytes are then decoded as that charset's label says (C1-C3).
```

Charsets:

```text
C1  A label is trimmed. It names an encoding when every byte of it is 0x21 to 0x7E and lower(label) is one
    of charsets.json's 228 labels.
C2  No label, a label that names nothing, and a label that names utf-8 or replacement leave the bytes as
    they are. Ill-formed UTF-8 then meets N1.
C3  Any other label's bytes are decoded by x/text v0.43.0's decoder for its encoding. Those decoders answer
    malformed input with U+FFFD and never fail. No charset is guessed from content.
```

The walk, `walk(fields, body, depth, pieces)`:

```text
M1  type = P(first("content-type")), disposition = P(first("content-disposition")). The media type is
    type's value. When that is empty it is text/plain, or message/rfc822 for a part directly inside a
    multipart/digest (RFC 2046); type's parameters stand either way.
M2  A media type beginning "multipart/": let b = type.param("boundary"). If b is empty, or depth >=
    MimeDepth, the entity gives nothing. Otherwise for each part of parts(body, b) (B1-B4), in order:
    walk(header_block(part), depth + 1). The entity's own name is not read. Every part is walked, the parts
    of multipart/alternative like any others.
M3  Any other entity: its name is disposition.param("filename"), or when that is empty type.param("name").
    A name that is not empty gives the piece words(name).
M4  If disposition's value is "attachment", the entity gives nothing more.
M5  text/plain gives the piece: transfer(first("content-transfer-encoding"), body), decoded as the label
    type.param("charset") says (C1-C3). text/html gives html_to_text of the same.
M6  Every other media type gives nothing more: no bytes of it are decoded, and a message/rfc822 part is not
    entered.
```

Multipart bodies, `parts(body, b)`:

```text
B1  Split body into lines at each LF (a line's bytes exclude the LF; the last line may end at the end). A
    line is a delimiter line when it is at most LineWindow bytes and, without its trailing run of SP, HT and
    CR bytes, equals "--" b; it is the close delimiter when it equals "--" b "--". The comparison is of
    bytes, from the line's first byte.
B2  A part begins after a delimiter line's LF and ends before the next delimiter or close delimiter line,
    less that line's own break: when the part's last byte is LF it goes, and then a CR before it goes.
B3  Lines before the first delimiter line belong to no part. At the close delimiter the parts end, and
    whatever follows it belongs to none.
B4  With no close delimiter, the last part runs to the end of body and keeps its last line break.
```

When a line is a delimiter of two nested multiparts, the outer one takes it, since the inner body is cut out of an outer part before it is split. A boundary that ends in SP, HT or CR, or is longer than 1,022 B, matches no line, and its multipart gives nothing.

Transfer encodings, `transfer(e, body)`:

```text
T1  lower(trim(e)) equal to "base64" selects T2 and "quoted-printable" T3. Anything else, absent included,
    leaves body as it is.
T2  base64: white bytes are skipped. Alphabet bytes are taken up to the first byte that is neither, '='
    included, where decoding ends. Each 4 give 3 bytes; at the end a last 2 give 1 and a last 3 give 2, the
    unused bits ignored; a last 1 gives none.
T3  quoted-printable, left to right: '=' and two hex digits are that byte. Any other '=' is a soft line
    break, which gives nothing, when after it come at most LineWindow blank bytes and then LF, or CR LF, or
    the end of body; all of that is consumed. Any other '=' is itself. Every other byte is itself, control
    bytes included. No line is too long, and trailing blank bytes of a line stay.
```

**HTML.** `html_to_text(t)` is `references(tags(t))`: every tag goes first, and character references are decoded in what is left, once. Whitespace is copied as it stands, line breaks included, and N5 folds it. Nothing is read from an attribute: no `alt`, `title` or `href` reaches the text. An element's text is kept whatever the element, `script` and `style` apart: `title`, `option`, `noscript` and `textarea` give their text, and since `title`, `head`, `body`, `caption` and `option` are not block tags, a document's title joins its first body word.

`tags(t)` reads t from the left. A byte other than '<' is copied. At a '<':

```text
X1  "<!--" opens a comment, which ends after the first "-->" that begins 4 or more bytes past the '<'. It
    gives nothing.
X2  Otherwise "<!" or "<?" opens a declaration, which ends after the next '>'. It gives nothing.
X3  Otherwise '<' followed by a letter or '/' opens a tag, which ends at the first '>' outside quotes,
    looking from the byte after the '<': a '"' or a "'" opens quotes and the next byte equal to it closes
    them. The tag is a closing tag when the byte after '<' is '/'.
X4  The tag's name is lower of the alphanumeric bytes that follow the '<', or the "</", up to the first
    byte that is not one, and may be empty. A tag whose name is a block tag gives one SP, closing or not.
    Any other tag gives nothing.
X5  A tag named script or style that is not a closing tag also takes its content: look, from the byte
    after the tag's '>', for the first "</" followed by that name ignoring case and then by the end of t or
    a byte that is not alphanumeric. That "</" opens a tag by X3, and reading resumes after its '>'. All of
    it gives nothing, the SP of X4 too, since neither name is a block tag.
X6  Any other '<' is copied.
X7  A comment, declaration or tag with no end, a script or style with no end tag, and an end tag with no
    '>' each take everything to the end of t.
```

`references(u)` reads u from the left. A byte other than '&' is copied. At an '&':

```text
E1  "&#", then an optional 'x' or 'X', then one or more digits (hex digits after an x), then an optional
    ';' is a numeric reference; all of it is consumed. Its value is the digits' number, held at 0x110000
    once it passes that. A value 0x80 to 0x9F gives the C1 table's code point; 0, 0xD800 to 0xDFFF and
    anything past 0x10FFFF give U+FFFD; any other value gives that code point. With no digit, the '&' is
    copied and reading goes on after it.
E2  Otherwise take the alphanumeric bytes after the '&', as many as there are. With none, the '&' is copied
    and reading goes on after it. Else the name is those bytes and a ';' if one follows them. If the name is
    one of the 2,231, its one or two code points are given and all of it is consumed. Names match by exact
    bytes: "AMP;" is one and "Amp;" is not.
E3  Otherwise, for k = min(6, the name's length - 1) down to 2: if the name's first k bytes are one of the
    106 names without ';', its code point is given and the '&' and those k bytes are consumed. The first k
    that matches counts.
E4  Otherwise the '&' and the name are copied.
```

E1 to E4 are HTML's own rule for text outside attributes, with its table whole. They are not `html.UnescapeString` (QD-690).

**Malformed input.** Nothing is refused and nothing is guessed. Each kind of damage has one reading, already given by a rule:

```text
no empty line after the header                 all header, empty body (H2)
a header line with no ':'                      passed over; a continuation still joins it (H3, H5)
a field or a joined value past 16,384 B        its first 16,384 B (H4, H6)
several Subject, From, To or Cc fields         all, joined by SP before their words decode (H6)
several Content-Type fields                    the first (H6)
an encoded word that breaks W1-W4              text, as written
an unknown charset, or none                    the bytes as they are; N1 maps what is not UTF-8 (C2)
a multipart with no boundary, or 17 deep       nothing from it (M2)
a part with no header, or no blank line        text/plain, or all header and an empty body (M1, H2)
a digest's part with no Content-Type           message/rfc822: not entered (M1, M6)
no close delimiter                             the last part runs to the end (B4)
a delimiter line past 1,024 B                  not a delimiter: it is part of the body (B1)
base64 with a byte outside its alphabet        what came before it, the last partial group decoded (T2)
an '=' that is neither an escape nor a break   itself (T3)
an unknown transfer encoding                   the body as it is (T1)
a tag, comment or script with no end           everything after it is dropped (X7)
a reference that names nothing                 text, as written (E4)
a file with a NUL or ill-formed UTF-8 in       binary: no document; where it was indexed, a tombstone (S2;
  its first 8,000 B                              §11.14's sniff row)
ill-formed UTF-8 past 8,000 B                  U+FFFD a byte, at normalization (N1)
a chunk whose key set passes 512 KiB           skipped (D6)
```

## Decoders

A decoder is total: it refuses, and never panics or allocates past its input, since nothing is compressed. A count is checked against the bytes left before anything is sized by it. It takes a file's expected `content_sha256` and compares that first, so tampered bytes reach no parser. It accepts only canonical encodings, so re-encoding what it decoded reproduces its bytes (FI-22): non-minimal VByte, unsorted or repeated keys and docids, a bitset off the shorter-list rule, non-zero pad bytes, a value past its cap, a table out of order, and any other departure from this file are refused. A reader drops such a file and raises `index_malformed` (§11.14's verify row).

## What this file adds

The resolutions settle the rest. These readings are this file's, each changing no D- item, for `design-records` to take with them:

| Item | Reading |
|---|---|
| `body_length` | Counts from the header's end, so no value depends on its own length |
| Row trimming's count | Later values at one length byte each, and the flags at 3 B, or a walked row could end past 2,048 B |
| Row values | `size` is the whole source's on each chunk's row; a field of several values joins them with one U+0020 |
| Sequence numbers | One counter a writer a bucket, from 1, for slots and large entries, so `absorbed` reads as one watermark |
| Normalizer readings | A mark's base is the nearest code point that is not Mn; a field with no text adds nothing; padding trims nothing; x/text's stream-safe U+034F stands |
| Files | The title rule above; a file's UTF-8 mark is dropped (S3; QD-693, reading 1) |
| Own decoders | Base64, quoted-printable, character references, header fields, parameters and multipart bodies are this file's rules, with no library parser and HTML's reference table in the repository (QD-690, amending three sentences of QD-474) |
| Extraction's limits | HeaderMax 16,384 B and LineWindow 1,024 B, so extraction runs in one pass in fixed memory (QD-691) |
| Names and labels | Compare under ASCII `lower`; only the six white bytes are trimmed (QD-693, reading 2) |
| An unterminated multipart | Its last part keeps its last line break (B4; QD-693, reading 3) |
| RFC 2231 pieces | Of two pieces of one name, kind and section the first counts; sections that join to nothing fall through to the extended and then the plain piece (P3, P5; QD-693, reading 4); a section is 1 to 9 digits (P3; reading 5) |
| Base64 | A last partial group decodes, and an encoded word's base64 skips nothing (T2, W3; QD-693, reading 6) |
| Quoted-printable | Control bytes pass, no line is too long, a line's trailing blanks stay, and a soft line break may hold up to LineWindow blank bytes (T3; QD-693, reading 7) |
| Numeric references | One digit is enough, `&#x;` is text, a number past U+10FFFF is U+FFFD, and all 2,231 names decode (E1, E2; QD-693, reading 8) |
| Extractor number | Extractor 1 keeps its number (QD-693, reading 10) |
| A digest's part | One with no Content-Type is message/rfc822, and so not entered (M1; QD-693, reading 11) |
| Block tags | QD-474's 44 names, so `title`, `body`, `caption` and `option` leave no space (X4; QD-693, reading 12) |
| format=flowed | Not read: its soft line breaks stay breaks (QD-693, reading 13) |
| Decoders | A header with an unknown field is refused; a `format` above 1 reads status `update`, not malformed |
| Own bases | A diff rests only on a full entry in another file of its own writer in its bucket, which that writer keeps; every push writing a writer's file replaces that writer's head (DESIGN-DETAILS 1.2, R1 and R2; QD-685) |
| Absorbed files | A slot other than the head, or a large entry, at or below its writer's absorbed seq holds nothing for search, merges and roll-ups, only a diff's base (QD-689, reading 2) |
| Coverage | Sorted by ref_id, then horizon false before true, at most one row of each kind a ref (QD-689, reading 4) |
| Entry times | An entry's time is its content push's signed time; its bucket follows its index push's (QD-689, reading 5) |
| Merges | The tie order at one version and `take`'s search above (QD-689, readings 6 and 7); a merge with nothing to add still commits its manifest (reading 8) |
| DirectBytes | A push past 256 KiB of entries also writes its writer's head (QD-689, reading 9) |
