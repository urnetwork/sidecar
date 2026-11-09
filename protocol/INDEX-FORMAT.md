# Index format 1

The bytes of the search index: normalizer 1, extractor 1 and every file under an index root. DESIGN.md §11.14 owns the design, and `evsindex.proto` holds its messages. This file fixes what §11.14 names without bytes, so that two honest builds write the same plaintext (FI-22), whose SHA-256 an entry version carries as `content_sha256`. Where the two disagree, DESIGN.md wins and the mismatch is reported.

**Status.** Proposed. This file writes down the resolutions of plan-SEARCH-index-format-bytes (ledger QD-300; its items 1-8 are QD-444, QD-477, QD-476, QD-473, QD-475, QD-443, QD-579 and QD-474), with search-format-all-directory-names's correction to item 5 (QD-475), and the rules the owner decided for plan-SEARCH-cherokee-fold (QD-256) and plan-SEARCH-shrink-claim (QD-173). Nothing is frozen: the specification freezes at M10's entry review and the bytes at its exit review (§23.8), and `testdata/index/` pins each byte in between. The last section lists what this file adds to those, for `design-records` to fold into §11.14.

## Common encodings

**VByte.** An unsigned integer of at most 64 bits, as LEB128, which `encoding/binary.AppendUvarint` writes: seven bits a byte, least significant group first, bit 7 set on every byte but the last. Encodings are minimal, so the last byte of a multi-byte value is never zero, and a value takes at most ten bytes, the tenth at most 0x01. Decoders refuse anything else.

**Fixed widths.** An entry's kind, a row's doc kind and a tombstone table's kind are one byte each. A `doc_key`, a `ref_id` and a `sidecar_id` are 16 bytes, copied as they are. A trigram key in a dictionary's block index is 3 bytes, most significant first. `u16be`, `u32be` and `u64be` are big-endian integers of those widths.

**Key order.** 16-byte keys compare bytewise. A trigram key is the integer b0 x 65,536 + b1 x 256 + b2 of its three bytes in text order, so integer order and byte order agree.

**Text.** Every text field is UTF-8. Decoders refuse invalid UTF-8.

**Messages.** Headers, manifests, settings, locks and erasure sets are proto3 from `evsindex.proto`, marshaled with `proto.MarshalOptions{Deterministic: true}`, each repeated field sorted as its comment says. No format-1 message carries an unknown field. A decoder re-marshals what it read, and refuses it unless the bytes are equal.

**Times.** Days count from 1970-01-01 UTC. An entry's time is ⌊time_ms / 1000⌋ of its push's signed `time_ms`, never a clock's.

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

A key set's first gap is its first key + 1, and each later gap the difference from the key before, so no gap is zero. Keys are at most 0xFFFFFF. A key set encodes to at most 512 KiB, since a chunk past that is skipped. A full entry's trigram count equals its key set's count. A diff's base version is below its version, and no key is in both of its sets.

**Deltas.** A diff's set is its base's set less `removed` plus `added`, `added` holding no key of the base and `removed` only keys of it. Composing (A1, R1) and then (A2, R2) gives ((A1 - R2) + (A2 - R1), (R1 - A2) + (R2 - A1)): the symmetric differences compose, which is why the composition is associative. The second delta must apply to the first's result, so A1 and A2 share no key, and neither do R1 and R2.

## Slots and large entries

A slot's entries sort ascending by their 16-byte key, doc_key or ref_id, then by kind, with one entry a key, so a key repeated under another kind is refused too. A replaced entry goes and its successor takes its sorted place, so a head is a function of its entry set and not of arrival order, which §16.11's head reproduction rests on.

- **Slot, type 1.** The whole file is at most 16,208 B, each entry at most 8,192 B. `count` entries fill `body_length` exactly, and zero entries is a slot an erasure emptied.
- **Large entry, type 2.** The whole file is at most 1,048,576 B, and its one entry is over 8,192 B.
- **Headers.** Both carry `bucket_start_day`, `bucket_days` (at least 1), `writer_sidecar_id`, `seq` and the table fields, and `pad_generation` and `tombstones` stay zero. `coverage` is strictly ascending by ref_id. One counter a writer a bucket, from 1, numbers both slots and large entries, so `IndexManifest.absorbed` reads as one watermark.
- **Pad.** A slot or large entry has no pad of its own. A CLOSURE, a DROP or a roll-up's in-place rewrite pads to the replaced length with zero bytes, and those are the only bytes allowed after `body_length`, on any file type. A decoder accepts any count of them inside the file's cap, re-encoding takes the pad's length from the file, and a writer's next head rewrite writes no pad.

## Shards

```text
shard       = "URix" | VByte header length | header | doc table | tombstones | dictionary | postings | pad
doc table   = count x (doc_key | VByte version | VByte time | row)     ascending by doc_key; a docid is a rank
tombstones  = tombstones x (kind | key | VByte version | VByte time)   ascending by kind, then key
dictionary  = VByte block count | blocks x (first key 3 B | VByte entries offset | VByte list offset) | key entries
key entry   = flag byte | the key's other bytes | VByte document count | VByte list bytes
```

A shard is at most 1,032,192 B before its pad and 1,048,576 B with it. `count` is its live documents, N below. `tombstones` is zero in an all shard, a key is at most once in a shard and never in both tables, and a ref tombstone is only on `ur/index`.

- **Blocks.** Keys ascend, 64 a block, the last block holding 1-64, and a shard with no key has no block. Merges and roll-ups always re-block by 64. A rewrite padded to a replaced length (a CLOSURE, a DROP's rewrite, a roll-up's step 4 rewrite) first builds the shard this way, and if that outgrows the replaced length, rebuilds it keeping the replaced shard's partition: each block keeps its surviving keys, prefix sharing resets at each block's first key, and an emptied block goes. A removed key saves at least 4 B and costs the next key at most 2, so that always fits. Decoders accept blocks of 1 to 64 keys, refuse an empty or larger one, and re-encode from the file's own partition. This is plan-SEARCH-shrink-claim's rule, as the owner decided it, and the rewrite keeps the replaced header's `pad_generation`.
- **Offsets.** A block's entries offset counts from the first byte after the block index, and its list offset from the first byte of postings, so block 0 has 0 and 0, and neither depends on the block index's own length. Both ascend strictly.
- **Flag byte.** Bits 0-1 hold the prefix shared with the previous key of the block, which is the longest one and 0 for a block's first key. Bit 2 marks a bitset, and bits 3-7 are zero. The key's other bytes are the 3 - prefix bytes after it, so a block's first key is written in full again here.
- **Postings.** Lists follow in key order. A list is VByte gaps between ascending docids, the first gap docid + 1, or a bitset of ⌈N/8⌉ bytes, whichever is shorter, VByte on a tie. In a bitset docid d is bit d mod 8 of byte ⌊d/8⌋, bit 0 being the least significant, and the spare bits of the last byte are zero.
- **Pad.** `pad_generation` names the writer's newest generation g, and K_index_g = HKDF-SHA256(RK_g, salt repo_id, info "UR evs 1.0 index" || u64be(g)), which is `EvsRepoKey.DeriveKey` with purpose `index` and no further context. With L the shard's length before its pad, the pad is u32be(HMAC-SHA256(K_index_g, "pad" || SHA-256(the shard before its pad))[0:4]) mod step(L) zero bytes, "pad" being its three ASCII bytes. step(L) is 2^(E - S), with E = ⌊log2 L⌋ and S = ⌊log2 E⌋ + 1, Padmé's step at L, 16 KiB near a shard's cap. A rewrite in place pads with zero bytes to the replaced length instead, keeping the replaced header's `pad_generation`, and no reader recomputes that pad.

## Small files

`settings`, `lock`, `a/m`, `b/<S>/m` and the erasure set are the bare marshaled message: no magic and no pad. `IndexManifest.absorbed` is sorted by `writer_sidecar_id`, `IndexErasureSet.erasures` by `erasure_id`, `IndexErasure.docs` by `doc_key`, and `shards` as its comment says. Each sort is strict.

## Documents

`doc_key` = HMAC-SHA256(K_ref, "UR evs 1.0 doc" || ref_id || u16be(len(name)) || name || u32be(chunk))[:16], K_ref from RK_1, `name` the path's bytes or a derived document's registered name. Text past 1 MiB is one document for each 1 MiB of the file, each with the next 256 B. Field text forms past these bytes belong to §15.7, §16.8 and §16.11.

## Extractor 1

**Sniff.** A file is text when its first 8,000 bytes hold no NUL and are valid UTF-8 but for a cut final sequence, or when it opens with a UTF-16 byte-order mark, which selects the endianness and is dropped.

**Charsets.** A MIME part, an RFC 2047 word or an RFC 2231 value decodes through `golang.org/x/text/encoding/htmlindex`, from the pinned module, so normalizer 1's pin covers its tables. No charset, or a label it does not know, reads as UTF-8, and invalid bytes reach normalizer 1's step 1. No charset is guessed from content.

**HTML.** Our own scanner on the decoded text, with no parser library, so no library bump changes its output. Names compare ASCII-case-insensitively.

- `<script>` and `<style>` go with their content, up to the matching end tag, or to the end of the input if there is none.
- Comments, `<!...>` and `<?...>` go.
- A tag is `<`, then a letter or `/`, to the next `>` outside quotes. Any other `<` is text.
- A tag in this list becomes one U+0020, and any other tag nothing, so `<b>a</b>b` reads `ab`: address, article, aside, blockquote, br, center, dd, details, dialog, dir, div, dl, dt, fieldset, figcaption, figure, footer, form, h1-h6, header, hgroup, hr, li, main, menu, nav, ol, p, pre, section, summary, table, tbody, td, tfoot, th, thead, tr, ul.
- Entities then decode by the standard library's `html.UnescapeString`, after every tag is gone, so `&lt;` stays text. One Go toolchain builds every leg, which pins that table.

**Files.** A title is the first line holding a letter or number, without a leading run of `#` and spaces or trailing spaces, and cut to 80 B on a code point.

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
| Files | The title rule above |
| Decoders | A header with an unknown field is refused; a `format` above 1 reads status `update`, not malformed |
