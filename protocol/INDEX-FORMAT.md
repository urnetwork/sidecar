# Index format 1

The bytes of the search index: normalizer 1, extractor 1 and every file under an index root. DESIGN.md §11.14 owns the design, and `evsindex.proto` holds its messages. This file fixes what §11.14 names without bytes, so that two honest builds write the same plaintext (FI-22), whose SHA-256 an entry version carries as `content_sha256`. Where the two disagree, DESIGN.md wins and the mismatch is reported.

**Status.** Proposed, as plan-SEARCH-index-format-bytes's option 1. Nothing is frozen: the specification freezes at M10's entry review and the bytes at its exit review (§23.8), and `testdata/index/` pins each byte in between. A choice a reviewer dislikes costs a vector rewrite. The last section lists what this file chose, for `design-records` to fold into §11.14. Two parts wait on a question, and each says so where it appears: Cherokee case folding (plan-SEARCH-cherokee-fold) and blocks under 64 keys (plan-SEARCH-shrink-claim).

## Common encodings

**VByte.** An unsigned integer of at most 64 bits, as LEB128: seven bits a byte, least significant group first, bit 7 set on every byte but the last. Encodings are minimal, so the last byte of a multi-byte value is never zero, and a value takes at most ten bytes, the tenth at most 0x01. Decoders refuse anything else.

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
<root>/a/<n>                             all shard n, for n below 3,500
<root>/a/<k>/<n>                         all shard n, from 3,500 on, with k = 3500 + ⌊(n - 3500) / 1000⌋
<root>/b/<S>/m                           bucket S's IndexManifest
<root>/b/<S>/s/<n>                       bucket shard n
<root>/b/<S>/w/<h>/<writer>/<k>          slot k of a writer, k 0-15
<root>/b/<S>/w/<h>/<writer>/L<seq>       a writer's large entry
.ur-index/x or x                         the ref's IndexErasureSet, beside its roots
```

`<S>`, `<n>`, `<k>` and `<seq>` are decimal with no leading zero, and 0 is `0`. Shards number from 0. `<writer>` is the `sidecar_id` as 32 lowercase hex digits, and `<h>` its first two. A directory `a/<k>/` starts at 3500, so its name is never a shard's: `a/3500` is always a directory, and shard 3500 is `a/3500/3500`.

## Normalizer 1

The steps run in this order over each field.

1. Invalid UTF-8 becomes U+FFFD, one for each byte that does not begin a well-formed sequence (`utf8.DecodeRune`'s rule), a cut final sequence included.
2. NFKC.
3. Full case folding by `cases.Fold()`, with no locale. Cherokee waits on plan-SEARCH-cherokee-fold: x/text's fold swaps the two cases of the 172 code points U+13A0-U+13F5, U+13F8-U+13FD and U+AB70-U+ABBF, so folding is not idempotent on them. Until that is answered, the normalizer refuses text holding one of them, and no index byte depends on what the fold did to it.
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

**Flags.** Bit 0 tainted, bit 1 outside, bit 2 private, and bit n + 2 for field n cut at its cap (bit 3 subject through bit 17 field 15). Bit 7 stays zero, and so do bits 8-17 on file and mail rows, and every bit from 18 on.

**Values.** `size` is the source's length in bytes: a whole file's on each of its chunks' rows. `chunk` is the chunk number of the doc_key, 0 for the first or only chunk. `trigram count` is n_d, the size of the document's key set, on diffs too. `started` and `expires` are seconds, and zero except on derived rows. A field with several values (§16.8's session ids and tools) joins them with one U+0020.

**Trimming.** A value first has invalid UTF-8 replaced as in step 1, because a row's strings reach `SearchHit`. Then, in the fixed order locator, 1, 2, 3, 4, 6-15, each value keeps the longest prefix ending on a code point that is within its cap (512 B locator, 160 B fields 1-4, 256 B fields 6-15) and that leaves the row within 2,048 B, with every later value counted empty and the flags counted at their widest, 3 B, since a cut can widen them. A field that lost bytes sets its bit. A cut locator sets none, since §11.14 gives it no bit, and such a hit shows but cannot be opened by its locator.

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

A slot's body holds its entries in one order that depends only on what they are: kinds 1-3 ascending by doc_key, then ref tombstones ascending by ref_id. A key appears once among kinds 1-3, and a ref_id once among ref tombstones. A replaced entry therefore keeps no place of its own, and two writers of one entry set write one body, which §16.11's head reproduction rests on.

- **Slot, type 1.** The whole file is at most 16,208 B, each entry at most 8,192 B. `count` entries fill `body_length` exactly, and zero entries is a slot an erasure emptied.
- **Large entry, type 2.** The whole file is at most 1,048,576 B, and its one entry is over 8,192 B.
- **Headers.** Both carry `bucket_start_day`, `bucket_days` (at least 1), `writer_sidecar_id`, `seq` and the table fields, and `pad_generation` and `tombstones` stay zero. `coverage` is strictly ascending by ref_id. One counter a writer a bucket, from 1, numbers both slots and large entries, so `IndexManifest.absorbed` reads as one watermark.
- **Pad.** A slot or large entry has no pad of its own. A CLOSURE, a DROP or a roll-up's in-place rewrite pads to the replaced length with zero bytes, and those are the only bytes allowed after `body_length`. A decoder accepts any count of them inside the file's cap, and re-encoding takes the file's length as an input.

## Shards

```text
shard       = "URix" | VByte header length | header | doc table | tombstones | dictionary | postings | pad
doc table   = count x (doc_key | VByte version | VByte time | row)     ascending by doc_key; a docid is a rank
tombstones  = tombstones x (kind | key | VByte version | VByte time)   ascending by kind, then key
dictionary  = VByte block count | blocks x (first key 3 B | VByte entries offset | VByte list offset) | key entries
key entry   = flag byte | the key's other bytes | VByte document count | VByte list bytes
```

A shard is at most 1,032,192 B before its pad and 1,048,576 B with it. `count` is its live documents, N below. `tombstones` is zero in an all shard, a key is at most once in a shard and never in both tables, and a ref tombstone is only on `ur/index`.

- **Blocks.** Keys ascend, 64 a block, the last block holding 1-64. A shard with no key has no block. A CLOSURE's blocks wait on plan-SEARCH-shrink-claim: a rewrite that would outgrow its replaced length fails closed until it is answered.
- **Offsets.** A block's entries offset counts from the dictionary's first key entry, and its list offset from the first byte of postings, so block 0 has 0 and 0, and neither depends on the block index's own length. Both ascend strictly.
- **Flag byte.** Bits 0-1 hold the prefix shared with the previous key of the block, which is the longest one and 0 for a block's first key. Bit 2 marks a bitset, and bits 3-7 are zero. The key's other bytes are the 3 - prefix bytes after it, so a block's first key is written in full again here.
- **Postings.** Lists follow in key order. A list is VByte gaps between ascending docids, the first gap docid + 1, or a bitset of ⌈N/8⌉ bytes, whichever is shorter, VByte on a tie. In a bitset docid d is bit d mod 8 of byte ⌊d/8⌋, bit 0 being the least significant, and the spare bits of the last byte are zero.
- **Pad.** `pad_generation` names the newest generation g of the writer, and K_index_g = `EvsRepoKey.DeriveKey("index", no context)` at g, which is HKDF-SHA256(RK_g, salt repo_id, info "UR evs 1.0 index" || u64be(g)). With L the shard's length before its pad, the pad is u32be(HMAC-SHA256(K_index_g, "pad" || SHA-256(the shard before its pad))[0:4]) mod step(L) zero bytes, "pad" being its three ASCII bytes. step(L) is 2^(E - S), with E = ⌊log2 L⌋ and S = ⌊log2 E⌋ + 1, Padmé's step at L, 16 KiB near a shard's cap. A rewrite in place pads with zero bytes to the replaced length instead, keeping the replaced header's `pad_generation`, and no reader recomputes that pad.

## Small files

`settings`, `lock`, `a/m`, `b/<S>/m` and the erasure set are the bare marshaled message: no magic and no pad. `IndexManifest.absorbed` is sorted by `writer_sidecar_id`, `IndexErasureSet.erasures` by `erasure_id`, `IndexErasure.docs` by `doc_key`, and `shards` as its comment says. Each sort is strict.

## Documents

`doc_key` = HMAC-SHA256(K_ref, "UR evs 1.0 doc" || ref_id || u16be(len(name)) || name || u32be(chunk))[:16], K_ref from RK_1, `name` the path's bytes or a derived document's registered name. Text past 1 MiB is one document for each 1 MiB of the file, each with the next 256 B. Field text forms past these bytes belong to §15.7, §16.8 and §16.11.

## Extractor 1

**Sniff.** A file is text when its first 8,000 bytes hold no NUL and are valid UTF-8 but for a cut final sequence, or when it opens with a UTF-16 byte-order mark, which selects the endianness and is dropped.

**Charsets.** One table, matched ASCII-case-insensitively after trimming spaces and quotes, each decoder x/text's, so the module pin covers its tables:

| Labels | Decoder |
|---|---|
| utf-8, utf8, us-ascii, ascii, ansi_x3.4-1968 | none: the bytes go on as UTF-8 |
| utf-16 (big-endian unless a mark says otherwise), utf-16be, utf-16le | `unicode.UTF16` |
| iso-8859-1 to -10, -13 to -16, latin1 | `charmap.ISO8859_n` |
| iso-8859-11, tis-620, windows-874 | `charmap.Windows874` |
| windows-1250 to -1258, cp1250 to cp1258 | `charmap.Windows125n` |
| koi8-r, koi8-u | `charmap.KOI8R`, `charmap.KOI8U` |
| macintosh, ibm866, cp866 | `charmap.Macintosh`, `charmap.CodePage866` |
| shift_jis, sjis, windows-31j | `japanese.ShiftJIS` |
| euc-jp, iso-2022-jp | `japanese.EUCJP`, `japanese.ISO2022JP` |
| euc-kr, ks_c_5601-1987 | `korean.EUCKR` |
| gb2312, gbk, gb18030, hz-gb-2312 | `simplifiedchinese.GBK` (the first two), `.GB18030`, `.HZGB2312` |
| big5 | `traditionalchinese.Big5` |

An unknown label reads as utf-8, so its bytes reach normalizer 1's step 1. No charset is ever guessed from content.

**HTML.** Our own code in one left-to-right pass, with no tree and no library, so no bump changes its output. Names compare ASCII-case-insensitively.

- `<` before an ASCII letter opens a start tag, and `</` before one an end tag. The name runs to the first byte that is no ASCII letter or digit, and the tag to the first `>` outside a single- or double-quoted run. A tag with no end removes the rest of the input.
- `<!--` removes through the next `-->`, and `<!` or `<?` through the next `>`, in either case to the end of the input if there is none. Any other `<` is text.
- After a `script` or `style` start tag everything goes through the next end tag of that name, or to the end of the input.
- These tags, start or end, become one U+0020: address, article, aside, blockquote, body, br, center, dd, details, dialog, dir, div, dl, dt, fieldset, figcaption, figure, footer, form, h1-h6, head, header, hr, html, li, main, menu, nav, ol, p, pre, section, summary, table, tbody, td, tfoot, th, thead, title, tr, ul. Any other tag adds nothing, so `<b>a</b>b` reads `ab`.
- In text, `&#` decimal `;` and `&#x` hex `;` become their code point, or U+FFFD for 0, a surrogate or anything past U+10FFFF, with no Windows-1252 remap. `&name;` becomes its value for HTML 4.01's 252 names and `apos`, case-sensitively. Anything else, a missing semicolon included, stays as it is. One pass only, so `&amp;lt;` reads `&lt;`.

**Files.** A title is the first line holding a letter or number, without a leading run of `#` and spaces or trailing spaces, and cut to 80 B on a code point.

## Decoders

A decoder is total: it refuses, and never panics or allocates past its input, since nothing is compressed. A count is checked against the bytes left before anything is sized by it. It takes a file's expected `content_sha256` and compares that first, so tampered bytes reach no parser. It accepts only canonical encodings, so re-encoding what it decoded reproduces its bytes (FI-22): non-minimal VByte, unsorted or repeated keys and docids, a bitset off the shorter-list rule, non-zero pad bytes, a value past its cap, a table out of order, and any other departure from this file are refused. A reader drops such a file and raises `index_malformed` (§11.14's verify row).

## What this file chose

For `design-records`, each is a reading of §11.14 that changes no D- item:

| Item | Chosen |
|---|---|
| VByte | LEB128, least significant group first, minimal |
| Widths | Kinds one byte; ids 16 bytes; dictionary keys big-endian |
| `body_length` | Counts from the header's end, so it needs no fixed point |
| Slot order | By key, ref tombstones last, so a replaced entry keeps no place |
| Row | Field order above; registered fields by position on record and derived rows only |
| Row trimming | Greedy in field order, plan-SEARCH-index-format-bytes's recommendation |
| Dictionary offsets | From the first key entry and the first posting byte |
| Bitset | LSB first; N is the shard's `count` |
| Paths | Decimal, lowercase hex; `a/<k>/` numbered from 3500, because a smaller name would collide with a shard's |
| Sequence numbers | One counter for slots and large entries, from 1 |
| CLOSURE pad on a slot | Zero bytes after `body_length` |
| K_index_g | Empty context; "pad" is three ASCII bytes before the hash |
| Normalizer readings | The base of a mark is the nearest code point that is not Mn; an empty field adds nothing; padding trims nothing |
| Extractor 1 | The charset table, HTML rules and title rule above |
