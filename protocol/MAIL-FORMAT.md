# The mail formats

§15.5, §15.7 and §15.8 name these formats, and only `MailIngress`, `MailAuthEvidence` and `AuthLimits` have a fence. This note, with `mail.proto`, gives the rest their bytes under the answers to plan-MAIL-format-bytes and plan-SMTP-wire-gaps#4, with the readings of mail-proto-format-readings accepted. `testdata/mail/vectors.yml` pins them, and `design-records` folds them into §15 for M7's entry review. Nothing here is frozen: a format's bytes freeze at its milestone's exit review (§23.8). Where this note and DESIGN.md part, DESIGN.md wins.

Every value here but `MailIngress` and `MailHint` is sealed under §11, so none needs a §2.8 row. The device role parses none of it, so it lives in `protocol`, never `protocol/bridge`.

## Encoding

- **Messages.** A value is a proto3 message of `mail.proto`, written with `proto.MarshalOptions{Deterministic: true}`. No message holds a map or a oneof, so an encoding depends on no leg and no run. Fields a reader cannot name stay in what it rewrites (§16.8).
- **Numbers.** A message with a `version`, which here means `MailDeposit` and §15.5's `MailIngress` and `MailAuthEvidence`, holds 1 in this format, and a reader refuses one whose `version` it does not know, 0 included. The other files carry none, as plan-MAIL-format-bytes writes them. Times are ms since the epoch, whatever the field's name. An id is 16 B, a SHA-256 or `effect_key` 32 B.
- **Sender-controlled text.** A `string` field holds valid UTF-8, and `proto.Marshal` fails on anything else, which must never decide whether mail is taken. So each value a sender controls has a stated way in:
  - `MailDeposit.mail_from` is `bytes`, as received.
  - `MailIngress.ehlo_name`, a `string` by §15.5's fence, is cleared when it is not valid UTF-8 or passes 255 B, because a cut argument would claim a name the sender did not give.
  - An evidence identifier or record that is not valid UTF-8 is left empty or out. It never verified, so its verdict stands without it.
  - Any other `string` taken from a message, `IndexEntry`'s text fields and `MailReverseAlias.original_sender` among them, has each invalid sequence replaced with U+FFFD before any cap applies.

## Paths

| Repo | Path | Body |
|---|---|---|
| `mailcfg` | `addr/<h>/<address>` | `MailAddress` |
| `mailcfg` | `burner/<h>/<blabel>` | `MailBurner` |
| mailbox | `vault/<h>/<entry_id>` | `VaultEntry` |
| mailbox, group | `m/<yyyymm>/<h>/<id>` | the raw RFC 5322 bytes plus ingest headers |
| mailbox | `r/<yyyymm>/<h>/<id>` | `MailGroupRef` |
| mailbox, group | `i/<yyyymm>/<n>` | `MailIndexSegment` |
| mailbox, group | `f/<yyyymm>/<n>` | `MailFlagSegment` |
| mailbox | `o/<h>/<effect_key>` | u32be(length) ‖ a `Signed` around `SmtpOutboxEntry` ‖ the message |
| mailbox | `or/<h>/<effect_key>` | `MailOutcomeRecord` |
| mailbox | `p/<sidecar_id>` | `MailProverRecord` |
| mailbox | `forward` | `MailForward` |
| mailbox | `ra/<h>/<token>` | `MailReverseAlias` |
| mailbox | `s/model` | `MailSpamModel`, whose `counts` and bytes MAIL-M7-12 defines |

- **`<h>`** is the two lowercase hex digits of the first byte of SHA-256 over the path's last name, as spelled below: 256 directories a family.
- **`<yyyymm>`** is the UTC year and month of the sealed receive time: `MailAuthEvidence.receive_time_millis`, else `MailIngress.receive_time_millis`, else, on a deposit with neither, the depositing push's signed `time_ms`. Every reader holds the same three values, so racing readers write one path. An `f/` op sits under the month of the message it names, so one month's `i/` and `f/` make a view of that month.
- **`<n>`** is decimal with no leading zero, from 0.
- **`<id>`, `<entry_id>`, `<sidecar_id>` and `<effect_key>`** are lowercase RFC 4648 base32 with no padding: 26 characters for an id and 52 for an `effect_key`. Hex would make an `effect_key` 64 B, past the "under 64 B" row of §11.7's name table that §15.7 sizes every family but `addr/` by.
- **`<address>`, `<blabel>` and `<token>`** are as the address spells them, lowercase. A `<token>` fits `r-<token>` in §15.8's 64 characters.

## Bounds on `MailIngress` and `MailAuthEvidence`

`MailIngress` fits 1,024 B (plan-MAIL-format-bytes#7). The router's builder first holds `ip_listings` to the first 16 entries of at most 12 B, leaving a longer entry out, since a cut name would claim a category the feed did not give. If the message still passes 1,024 B, it drops `ptr_name`, since readers use the receiver's own PTR, and then `ip_listings` entries from the end, one at a time. It never drops `version`, `sender_ip`, `sender_port`, `sni`, `ehlo_name` or `receive_time_millis`. At every field's bound, with every number at its widest, a message with no listings takes 811 B and one with the 16 held listings and no `ptr_name` takes 779 B, so the order ends by its second step, and reaches the third only when a field is past its own bound.

`MailAuthEvidence` fits 8,192 B by §15.5's `evidence` row: keys and records go first, the last selected first, then whole `dkim` and `arc` entries from the end of the selection order, counted in `limits`. With all of those gone the rest always fits.

## `MailDeposit`

A deposit's sealed trailer (15.7), one per repo, holding that repo's recipients only, so BCC stays private across repos. The deposit id is the message id.

A deposit's plaintext is the message as received, then the encoded `MailDeposit`, then u32be of that encoding's length (plan-MAIL-deposit-shape), so a reader takes the trailer from the tail by a ranged read before the body. `MailAuthEvidence.message_sha256` names the message's bytes alone. To evs the whole plaintext is body, sealed under the deposit's object key, whose slot CONSUME and ERASE destroy, so the trailer needs no key of its own. How evs seals and slots that body is §11's (plan-EVS1-format-bytes).

A same-network deposit (D-MAIL-8) sets `version`, `mail_from` and `recipients` only, and its signature is the depositing push's (plan-MAIL-format-bytes#1). A receiver's deposit sets `receiver_sidecar_id` to itself, which ingest holds to the push's signer, and one with no `evidence` is "evidence unavailable". A direct-MX session has no router, so its receiver builds `ingress` itself (MAIL-M7-23), under the same bound and order.

Leaving those fields out earns nothing: a deposit takes `MAIL_TLS_MEMBER_SIGNED` only if the push's signer may send as the message's From (`mail:<alias>#send`, §15.10). Anything else without evidence is "evidence unavailable", so a receiver that drops `ingress` and `evidence` gets the weakest label, never the strongest.

A mailbox's deposit ref also takes §16.8's `read` receipts from readers that do not write. Ingest tells those by the depositor's role (§11.12), never by these bytes.

## `i/`: the message list

A `MailIndexSegment` is one `entries` record per message and nothing else, so an empty segment is no bytes and a new one is its first record. Encoded, it is the bytes it held before and then one record, so a writer appends: it adds the tag, length and encoded `IndexEntry` to the bytes it read and writes those. It never re-encodes what it read, so a newer writer's fields stay, and §11.7's git delta against the previous version is a copy and that record.

A writer takes the month's highest `<n>`. It starts `<n>` + 1 when the record would take the segment past 1,048,576 B or past 4,096 entries. A racing write gets evs's path 409, re-reads and starts again. A re-checkpoint (15.7) rewrites a segment without its erased entries and keeps its `<n>`, and a full segment stays under the 1,088 KiB §15.7 lets it re-key.

A segment is in append order, which is not time order. A list runs by `time`, newest first, then by `id` as bytes, highest first. An `id` has one entry, and a reader that meets another keeps the first.

| `IndexEntry` field | Cap | Past it |
|---|---|---|
| `address` | 318 B | never: it is a repo's own recipient |
| `from`, `subject` | 512 B | cut on a UTF-8 boundary |
| `snippet` | 200 B (15.7) | cut on a UTF-8 boundary |
| `message_id` | 256 B | left empty, since a cut id matches nothing |
| `one_time_code` | 32 B | left empty |
| `attachments` | 32 | the rest left out |
| `MailAttachment.name` | 256 B | cut on a UTF-8 boundary |
| `MailAttachment.type` | 128 B | cut on a UTF-8 boundary |
| `MailTlsBasis.operator_id` | 64 B | never: the list is ours |

An entry at these caps takes under 16 KiB, so a segment holds at least 64.

- **`address`** is the first of the deposit's recipients in this repo.
- **`thread_key`** is the first 16 B of SHA-256 over a message id without its brackets: the first of `References`, else the first of `In-Reply-To`, else the message's own `Message-ID`. A message with none of these takes its `id`. So two devices ingesting one thread agree.
- **`auth_results`** summarizes the evidence for a list. `dkim` is pass if any selected signature passed, else the first selected one's verdict, else 0. `checks_incomplete` says `limits` was set. `evidence_unavailable` says a receiver sealed none. The `Authentication-Results` header in `m/` has the rest. `spf` and `dkim` speak for whatever domain the sender chose, so only `dmarc` says anything about From, and a list never shows either as the sender's.
- **`tls_label`** is 0 on a sent copy, which no reception labeled: a sent message's level is `MailOutcome.tls_level`. A reader shows 0 as no label, never as validated. `MAIL_TLS_MEMBER_SIGNED` is same-network mail, whose sender's signature replaces the label (D-MAIL-8), under the deposit rule above.
- **`tls_basis`** has `rule` 0 on opportunistic mail and `list_version` on every label decided against the list, so a recheck knows which list it read.
- **`spam_score`** is parts per thousand, 0 to 1,000, and a reader takes more as 1,000.

## `f/`: flags and the clock

A `MailFlagSegment` is one `ops` record per op and nothing else, and grows and closes as `i/` does, at 4,096 ops. An op at its caps takes under 128 B, so the count binds before any byte bound.

An op changes one key, (`message_id`, `op`, `label`), and `set` says which way. A member's flags on a group message sit in that member's own mailbox, under the group message's month and id, and the group repo's `f/` holds what its admins set, its trash among them (15.7). `label` is empty unless `op` is label, and at most 64 B. `sent` marks a sent copy, `spam` and `not-spam` are a person's verdict, which `s/model` trains on and which outrank `spam_score`, and any other name is the person's own.

The clock is one number, `hlc`, holding what plan-MAIL-format-bytes#5 wrote as `hlc_ms` and `hlc_count`, so it compares as one and cannot wrap. `hlc_count`'s number, 6, stays reserved.

```text
hlc      wall << 16 | counter: wall the ms since the epoch in 48 bits, counter 16 bits
tick     hlc = max(now << 16, last + 1), last + 1 stopping at 2^64 - 1; then last = hlc
read     last = max(last, each op's hlc), for every f/ file the device reads
order    of two ops on one key, the higher (hlc, sidecar_id, set) wins: hlc as a number, sidecar_id as
         bytes, then true over false
```

`last` is per mailbox and needs no storage: a restart rebuilds it from `f/`, and an op that never reached `f/` has nothing to order against. A counter past 65,535 carries into `wall`. Since `order` is total over what an op says, devices that hold the same ops agree in any order of arrival. The sidecar id breaks equal clocks, and `set` two ops from one device whose clock stepped back.

The winning op's `wall` dates a trash for the 30-day shred. An op naming an erased message is ignored.

## The other mailbox files

- **`r/`.** A `MailGroupRef`, whose `<yyyymm>` and `<id>` are the group message's, and whose `message_id` equals `<id>`.
- **`o/`.** The file is u32be(length) ‖ `Signed` ‖ the message's RFC 5322 bytes (plan-SMTP-wire-gaps#4): the length counts the `Signed`'s encoding, and the message runs to the file's end. The `Signed` (`bridge/signed.proto`) has type `SIGNED_SMTP_OUTBOX` (0x1601) and purpose `smtp-outbox`, and its `body` is an encoded `SmtpOutboxEntry`, signed by the composing device's identity key (D-SMTP-18). SMTP-M9-09 registers that type and purpose. A sending host verifies `body` as stored, parses it only after that (§6.9), refuses an entry whose `effect_key` is not the path's, and refuses a message whose SHA-256 is not `message_sha256`. `sender` is the envelope's address at `b.<net>.<root>`. `flags` are `SmtpPreamble.flags`. `tl4_domains` carries the composing device's TL4 approvals to the prover host. `approval_not_after` is the approval's `not_after`, 0 with no approval, and §16's expiry row puts the retry window's end 10 min past it. A forward's `effect_key` is SHA-256("urnetwork-sidecar-v1/mail-forward" || its message id), so racing readers queue one.
- **`or/`.** A `MailOutcomeRecord` holds one `MailOutcome` per recipient domain, rewritten by the sending device as each finishes, and kept 30 days. `mode` 0 is §14.5's `unknown`. `byte_count` and `cap_byte_count` are set only on `too_large`, `retry_after_ms` on `deferred`, and `reply_code` on `refused`. `update_time_ms` is the sending device's last write of that domain's result. `tls_level` is the send's I-11 label, 1 to 4 for TL1 to TL4, or 0 if none was reached.
- **`p/`.** `MailProverRecord` is rewritten at each measurement, and `measure_time_ms` says when.
- **`forward`.** `burners` lists the opted-in `<blabel>`s, and `verified_time_ms` is when the address confirmed its 6-digit code (15.10). The evs push signs it, as every mailbox file.
- **`ra/`.** `<token>` is §15.10's MAC, and the record holds what it stands for.

## `mailcfg`

A record's authority is its evs push, whose signer readers check per version (§11.7). `MailAddress.creator` is that signer on the creating push (plan-MAIL-small-readings' reading 15), and a record whose field differs is ignored. A burn or pause is a later version of the same `burner/` path. `effect_key` is empty when no decision made the record.

## Vault entries

`entry_id` is 16 random bytes. `password_history` runs oldest first. `totp` follows RFC 6238, and a writer sets all four fields, so a reader never guesses a default. `state` is live, or burned once its burner burns: pausing a burner leaves it live.

## Hints

`MailHint` rides `PushHint.hint`, at most 256 B, with `PushHint.kind` `MAIL_HINT` (0x1702) on topic `mail`. It says a kind and a host, `mx` or `mx.<scope>`, as `mail_host_key` names it (§2.8's mx-3), so it carries nothing a server does not hold. The router raises `MAIL_HINT_RECEIVER_NEEDED` when it meets a host with no receiver, to that host's published receivers (plan-MAIL-hints#2). `MAIL_HINT_DEPOSIT` is reserved and never sent: a deposit reaches its readers by evs's `evs:<repo_id>` hint (plan-MAIL-hints#1). A kind of 0 is a protocol error (§6.11).

## Not fixed here

- How evs seals and slots a deposit's body (§11, plan-EVS1-format-bytes).
- `MailSpamModel`'s `counts` and its bytes, which are MAIL-M7-12's.
- `SIGNED_SMTP_OUTBOX` and `smtp-outbox`, which SMTP-M9-09 registers.
