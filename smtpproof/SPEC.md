# smtpproof: what the outbound-mail proofs prove

*Draft 3, the freeze candidate for M9's entry review, 2026-11-19; draft 2 was 2026-11-08 and draft 1 2026-11-06. Draft 3 states the relation as DESIGN-DETAILS.md section 3 revised it and DESIGN.md §14.5 now carries it (owner decisions 433 to 435): the key schedule is proven once a connection, in a key part that publishes a perfectly hiding commitment C to both directions' keys, and every later part opens C; every circuit fills one 2^20 domain, a unit, and a send takes as many units as it has to open, the envelope in groups, the header block and DATA's body a record a part; and a scan carries its state from one record to the next in a perfectly hiding commitment, the carry. Not frozen: this specification freezes at M9's entry review and its bytes at M9's exit review (DESIGN.md §22.10, D-PHASE-7), and nothing here does either. Until then every field, encoding and shape here may change. `testdata/vectors/` holds the bytes the exit review would freeze (5.1), and `testdata/mutations/table.md` the evidence that each check does work no other does (section 8).*

This document states the relation behind X7: what a sending sidecar proves to `smtpedge`, against which public values, and why that is sound against a malicious sidecar and zero knowledge against a malicious edge. It is the document D-SMTP-16 names. DESIGN.md §14.4, §14.5 and §14.9 are the source, with DESIGN-DETAILS.md section 3 for what they cite of it; where this draft and DESIGN.md disagree, DESIGN.md wins and the disagreement is a bug here, and none is known at this draft. Section 13 lists every reading taken where neither was explicit, and section 14 what is still open.

The code beside this file follows it. Section 12 says which parts of it exist.

## 1. The claim

Owner directive X7: TLS runs end to end from the sidecar to the destination MX, so the edge sees ciphertext plus a small declared preamble. Abuse control needs those declared values to be true, and a sidecar is not trusted to declare them. So:

**Soundness.** Let `smtpedge` and the MX be honest, and the sending sidecar be malicious. If the edge forwards records under this protocol, then except with negligible probability the MX's SMTP state machine sees, on that connection, at most one transaction, and any message the MX accepts in it has:

- an envelope sender in the network's envelope domain, and exactly `recipient_count` recipients, all at `recipient_domain`;
- exactly `message_byte_count` octets;
- a header block holding, once each, a From in `header_from_domain`, the declared Message-ID, the issued X-UR-Ref and Feedback-ID, and a DKIM-Signature with the declared `d=` and `s=` covering them.

**Reach.** A colluding MX gets only its own mail. The edge resolves and dials the MX for `recipient_domain` itself (E2), so a colluder can make any statement true about a connection that reaches only the colluder.

**Zero knowledge.** Let the sidecar be honest and the edge be malicious, including having run the setup. Beyond the public inputs of section 5, the edge learns nothing about the keys, the plaintext of any client or server application record, or the recipients. This holds for any well-formed setup, and the prover checks well-formedness (section 10).

Both claims stand word for word as draft 2 stated them, which DESIGN-DETAILS 3.1 required of the revision. What changed is how they are met. The public inputs now include the commitments the sidecar publishes, C and the carries, and each is a uniformly random group element whatever it commits to (10.2, K1), so they add nothing to what the edge learns; and soundness now also rests on discrete logarithms in the commitments' group (9.1).

What is deliberately **not** proved:

- The body. BDAT's body streams unopened; DATA's is scanned only for its framing.
- That the DKIM signature verifies. A sidecar that signs badly fails DMARC at the receiver, which costs only itself.
- That the MX is the right MX. That is the sidecar's job as TLS client, at TL1-TL3 (§14.4). It is why E2 needs no PKIX check: the proofs protect the edge from the sidecar, and TL1-TL3 protect the sidecar from the edge.
- Anything about the edge's honesty. A compelled edge can drop, delay or misreport, and can read TL4-override mail (§2.8 EX4).

## 2. Parties

| Party | Holds | Trusted for |
|---|---|---|
| Sidecar (prover) | Its own TLS client state: HS, MS, every application key and IV, all plaintext; the blinds of C and of each carry; the proving keys its own check derived (10.3) | Nothing, for soundness |
| smtpedge (verifier) | The TCP connection to the MX, every relayed byte, the preamble and issued values, the verifying keys of the key sets it lists; per connection, C and the latest carry | Nothing, for zero knowledge |
| MX | Its TLS and SMTP state | Assumed honest for soundness, and to follow RFC 5321, 3030, 3207, 2920 and 8446 or 5246 in the respects listed in 9.1. Assumed colluding only for Reach |

The edge sits on the TCP path. It relays the sidecar's bytes to the MX and the MX's bytes to the sidecar, and it alone decides which client records reach the MX. The sidecar is not on the path between edge and MX, which is ORIGO's no-MITM assumption (§14.4).

## 3. Notation

- `‖` is concatenation. `SHA-256`, `HMAC`, `HKDF-Expand-Label` and `Transcript-Hash` are as in RFC 8446. `PRF` is RFC 5246 §5 with SHA-256.
- `seq` is the TLS sequence number of a record in its direction, under its traffic key.
- Client application records in 1.3 begin at `seq` 0. In 1.2 the client's Finished takes `seq` 0, so they begin at 1.
- `CRLF` is octets 0D 0A. A **bare** CR is a CR not followed by LF; a bare LF is an LF not preceded by CR.
- `helo_name`, `x_ur_ref` and `feedback_id` are the issued values of `SmtpPreambleResult`.
- `envelope_domain` is `b.<net>.<root>`, or `b.<domain>` for a header From in a Team custom domain that is strict: a verified domain at or under which the ticket's network maps an active strict-mode MX host (§14.6, §12.8 step 4; owner decision 655). The edge derives it from the ticket's network alone, its gate facts taking the network's strict domains from those rows, and never takes it from the sidecar, which reads the same set from `GET /mail/status`'s `strict_domains` (§15.15) and compares the edge's result, section 5's issued value, with its own MAIL FROM's.
- `f` is the first client application record's `seq`: 0 in 1.3, 1 in 1.2. `R` is `recipient_count`, and `k` is `header_record_count`, the client records the header block takes.
- `r` is BN254's scalar field's prime, so circuit wires are elements of F_r. `E` is the twisted Edwards curve over F_r of 10.2, whose points are pairs of wires, and `l` the prime order of the subgroup the commitments live in. `Com(generators, blind generator, bits, blind)` is 10.2's Pedersen commitment. `C` is the key commitment, and a **carry** is a commitment to a scan's state between two records (7, Z5 and Z6).
- A **unit** is one 2^20 domain, the size every production circuit fills (10.4), and so one proof.

## 4. The wire shape an honest sidecar produces

The relation is simple because the sidecar's own client produces one normal form, and anything else is unprovable and fails before any effect. An MX sees ordinary SMTP. This section fixes the shape; section 7 states the checks over it.

### 4.1 The TLS client

The prover runs `tlsClient` (`tls_client.go`), the sidecar's own TLS client. It exists for three reasons no stock client serves:

1. Go's `crypto/tls` exports TLS 1.2's master secret through `KeyLogWriter` but never TLS 1.3's HS (§14.3), and HS is Z1's witness.
2. A proof must cover a record's ciphertext before the record is sent, so sealing and sending are separate steps.
3. Z3 needs exact control of record boundaries and of what is never sent: padding, KeyUpdate, early data.

It offers:

- TLS 1.3 with `TLS_CHACHA20_POLY1305_SHA256` and `TLS_AES_128_GCM_SHA256`; TLS 1.2 with `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` and `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`. These are E1's suites and no others, offered in that order, `ProverSettings.SuiteOrder`'s default. ChaCha20 comes first because an octet costs 341 constraints of its keystream against AES-128-GCM's 729 (11.2), so an MX that follows the client's preference about halves a header block's units (reading 35).
- Only the suites whose family has ready keys in the connection's key set (10.3): AES-128-GCM's family serves TLS 1.3's AES suite and both 1.2 suites, and 1.2 is offered only once its own key shape is ready too. A handshake that fits no ready family fails before EHLO, costing a burst token and no unit.
- SNI = the MX host.
- No `pre_shared_key`, `early_data`, `session_ticket` or `psk_key_exchange_modes`. Omitting the last is deliberate: RFC 8446 §4.2.9 lets a server skip tickets a client cannot use, so compliant MXs send no NewSessionTicket, and a ticket is pure proving cost. Z7 still handles one.
- An empty legacy session id, so no compatibility mode and no resumption. A CertificateRequest is answered with an empty Certificate.

It verifies CertificateVerify and Finished itself and hands the chain to an injected `VerifyPeer` for TL1-TL3. A nil `VerifyPeer` fails closed.

### 4.2 Records

Each opened client record holds exactly one of these contents, and 1.3 appends the inner type octet 17 with no padding:

| Content | Literal form |
|---|---|
| EHLO | `EHLO ` helo_name CRLF |
| MAIL | `MAIL FROM:<` local `@` envelope_domain `>` CRLF, or `> REQUIRETLS` CRLF when the REQUIRETLS flag is set |
| RCPT | `RCPT TO:<` local `@` recipient_domain `>` CRLF |
| BDAT | `BDAT ` decimal(n) ` LAST` CRLF |
| DATA | `DATA` CRLF |
| Header record | One of the 1 to `HeaderRecordMaxCount` (16) records the header block is cut into by its length alone (4.3), the block in section 7's Z5 form, with nothing after its final CRLF CRLF |
| Body record (DATA) | One of the records the dot-stuffed body is cut into by length at the body shape's capacity, the last shorter and ending CRLF (reading 3) |
| End mark (DATA) | `.` CRLF |
| QUIT | `QUIT` CRLF |

`local` is 1 to 64 octets of `A-Z a-z 0-9` and ``# $ & ' * + - / = ? ^ _ ` { | } ~ .``. That is RFC 5321's Dot-string with `%` and `!` removed, and with no leading, trailing or doubled dot enforced only by the sidecar, not the relation. No `@`, `<`, `>`, `,`, `:`, CR, LF or SP can occur, so a path holds one address at one domain. Quoted local parts, source routes and non-ASCII addresses are not expressible, and such a recipient gets a DSN.

Because one record holds one command and Z3 fixes its length, **every offset in a command is a function of public record lengths**. This is what keeps grammar out of the circuit: section 5's position templates are computed from public values by the edge, and the circuit only compares. A header or body record's length is a function of public values too: the header block's cut is `headerSplit` of its length (4.3), and a body record holds what the body shape holds, the last what is left, so a cut says nothing the edge does not already see.

### 4.3 The connection

A send is a run of parts, each one unit, as DESIGN.md §14.5 draws it (DESIGN-DETAILS 3.2.1):

```text
sidecar                                   smtpedge                              MX
 |--SmtpPreamble, naming its key set-------->|--banner, EHLO, STARTTLS----------->|
 |==ClientHello .. Finished (spliced; 1.3 discloses SHTS, E2)====================>|
 |--part 1 (key): Z1 once, C, the EHLO record-->| verify: C is the connection's from here
 |==EHLO=========================================================================>|
 |<=EHLO reply====================================================================|
 |--part 2 (env): opens C; that reply: 1 reply, all 250, CHUNKING; MAIL, RCPT x g1-->| verify
 |==MAIL, RCPT x g1==============================================================>|
 |<=their replies=================================================================|
 |--part 3.. (env): opens C; 1 + g1 replies, each 2xx; RCPT x g2-->|   one part a group, while recipients remain
 |--part m (msg): opens C; the last group's replies; BDAT n LAST, header record 1; carry S1-->| verify
 |==BDAT n LAST, header record 1=================================================>|
 |--part m+1.. (hdr): opens C and S1; header record 2; carry S2-->|   one part a record
 |--the last part: the header block's last record and QUIT; last-->| verify
 |==that record, the body unopened to octet n, QUIT==============================>|
 DATA: the last env part opens DATA; msg proves the 354 and opens header record 1; a body part opens each
 body record, opening and publishing a carry; the last also opens ". CRLF" and "QUIT CRLF". Without
 PIPELINING each command, QUIT included, goes only after the previous reply.
```

| Part | Kind | Client records it opens | Server records it covers | Checks |
|---|---|---|---|---|
| 1 | key | EHLO | None (`server_record_count` 0) | Z1 (the derivation and C), Z2 Z3 Z4 |
| 2 | env | MAIL and the first group of RCPT | Through the EHLO reply: one reply | Z1 (the opening) Z2 Z3 Z4 Z7 Z8 Z9 |
| Later envelope parts | env | The next group of RCPT; in DATA mode the last group ends with DATA | The replies to the group before | Z1 Z2 Z3 Z4 Z7 Z8 |
| The first message part | msg | In BDAT mode BDAT's command, then header record 1; in BDAT mode with a one-record header block also QUIT, and `last` | The replies to the last group; in DATA mode the 354 | Z1 Z2 Z3 Z4 Z5 Z6 Z7 Z8 |
| Header parts | hdr | One later header record; in BDAT mode the last also QUIT, and `last` | None | Z1 Z2 Z3 Z5 Z6 |
| Body parts, DATA | body | One body record; the last also the end mark and QUIT, and `last` | None | Z1 Z2 Z3 Z6 |
| A part that opens no client record | env | None | One or more: a late ticket, or replies the part before could not hold | Z1 Z7 Z8 |

Z1 is proven once a connection. The key part derives both directions' keys and IVs from the handshake, always both, and publishes C, a perfectly hiding commitment to them (10.2); every later part proves that the keys it uses open C, which the gate supplies from the key part, and holds no key schedule (D-SMTP-22; owner decision 433). A body with no octet has no body record, and its last part opens only the end mark and QUIT.

**Roles by position.** A client record's role follows from its `seq` alone, so the edge assigns every template with no word from the prover but k (DESIGN-DETAILS 3.2.5; `recordRoleAt`, `partRoles`):

```text
f                  EHLO
f+1                MAIL
f+2 .. f+1+R       RCPT
f+2+R              BDAT n LAST in BDAT mode, DATA in DATA mode
f+3+R .. f+2+R+k   header records 1 .. k
BDAT   every record after header record k and before the last part's last_record is body, unopened;
       QUIT is at last_record
DATA   body records from f+3+R+k, one a part; the end mark and QUIT follow the last, in the last part
commands, which the MX answers: EHLO, MAIL, RCPT, DATA
message records, which E3 step 5 holds: BDAT's command, header records, body records, the end mark
```

A part's kind follows from what it opens (`partKindOf`): MAIL, RCPT or DATA, or no record at all, is env; header record 1 is msg, with BDAT's command before it in BDAT mode; a later header record is hdr; a body record, or an empty body's end mark, is body. A part opens records of one kind, at most one header or body record, and QUIT only on the last part of one of the three message kinds.

**The header block's cut.** The sender cuts the header block by its length alone (DESIGN-DETAILS 3.2.4; `ProofSettings.headerSplit`):

```text
headBytes = what the family's msg shape's head holds; restBytes = what its hdr shape's rest holds
            (blocks x 16 or 64, less TLS 1.3's type octet a record: 831 and 1,215 under 1.3's AES-128-GCM,
             832 and 1,216 under 1.2's, 1,215 and 2,239 under ChaCha20)
split(L):   L the header block's octets, through its final CRLF CRLF
    L <= headBytes:  [L]
    else:            headBytes, then restBytes while more than restBytes is left, then what is left;
                     a last record under HeaderLastRecordMinByteCount (4) takes the difference from the one before
```

The gate accepts any cut of 1 to `HeaderRecordMaxCount` (16) records in which every record but the last holds at least `HeaderRecordMinByteCount` (128) octets and the last at least `HeaderLastRecordMinByteCount` (4). The first bound is longer than the longest literal the scan looks for, the fixed signature's 99-octet prefix (Z5.5), so a literal can straddle one record boundary and never two. A header block of 16,383 octets, the longest, takes 14 records under 1.3's AES-128-GCM and 8 under ChaCha20.

**Envelope groups.** The sender sends the envelope's commands, MAIL, R × RCPT and in DATA mode DATA, in groups, waits for a group's replies, and proves them with the next group (DESIGN-DETAILS 3.2.4; owner decision 434). Within a group it pipelines where the post-TLS EHLO reply offers PIPELINING and otherwise sends command by command, still under the one part:

```text
group(commands left, estimate):     the next group: commands in order while
    their records fit the env shape's client blocks,
    count x blocks(estimate) <= the env shape's server blocks, and
    count <= EnvelopeGroupMaxCount when that is set
  blocks(e) = ceil((e + 1) / 16) under 1.3's AES-128-GCM, ceil(e / 16) under 1.2, ceil((e + 1) / 64) under ChaCha20:
              a reply may come as a record of its own, and a record starts a block
  estimate  = ReplyEstimateByteCount (40) for the first group; afterwards the group before's mean reply, from public
              values alone: the content octets of the server records its part covered over its reply_count, rounded
              up, plus ReplyMarginByteCount (8)
```

For short addresses that is MAIL and 12 RCPT, then 13 RCPT a group, under AES-128-GCM, and 18, then 19, under ChaCha20. Group sizes are a function of public values alone, so the edge learns nothing from them it does not see (10.2, K3).

**The plan.** The prover plans the parts as the connection goes, since replies decide the next step (DESIGN-DETAILS 3.2.6; `prover_plan.go`): the key part after the handshake; part 2 after the EHLO reply, with the mode and group 1; an env part a group while commands remain. After the last group's replies it seals every message record in order, computes every scan state and draws every blind; the msg part covers those replies when its shape's server blocks hold them, and otherwise env parts that open no client record cover them first. The msg, hdr and body parts follow, proven up to `ProveConcurrency` at once (1 by default), each submitted once every part before it was answered OK, its records going to the stream once its own answer is OK. A server record read after a part was built, such as a late ticket, is covered by an env part that opens no client record, submitted next. A reply record larger than the env shape's server blocks fits no part: the prover ends the connection before any message record with `EnvelopeRetry`, and the sender retries once a command a group (DESIGN-DETAILS 3.5).

## 5. Public inputs

Each is a value the edge already holds or computes, or one the prover publishes whose form the gate checks. From the prover come `records`, which the stream must then repeat (E3); the disclosed SHTS, which is used only after E2 checks it; C and each carry, which the gate holds to 10.2's form and which are uniform whatever they commit to (K1); and `reply_count` and `header_record_count`, which the gate bounds (E3, steps 8 and 9) and the relation fixes (Z8, Z5). A later part's statement takes C and the carry it opens from the gate's state, never from the part (E3, step 12).

**Session.** TLS version and suite, the key set its preamble names (`proof_key_set`), then, in the key part's statement alone, Z1's handshake inputs, computed by the edge over the bytes it relayed:

```text
1.3  H_shts = SHA-256(SHTS)
     H_sh   = Transcript-Hash(ClientHello .. ServerHello)      a HelloRetryRequest included (RFC 8446 §4.4.1)
     H_sf   = Transcript-Hash(ClientHello .. server Finished)  the flight as E2 opened it
1.2  r_c, r_s   the hello randoms
     S_ckx      the SHA-256 state (chaining value, unhashed tail, length) after ClientHello .. ClientKeyExchange
     SF         the server Finished record as relayed: explicit nonce and ciphertext
```

**Preamble and issued values.** `recipient_domain`, `recipient_count`, `message_id`, `header_from_domain`, `dkim_selector`, `message_byte_count`, `flags`, `helo_name`, `x_ur_ref`, `feedback_id`, `envelope_domain`. The edge names its `envelope_domain` in `SmtpPreambleResult.envelope_domain` (QD-1154), and the sidecar resets the stream before any client record where it differs from its own MAIL FROM's, so a send whose strict set the edge has not loaded yet is held rather than cut (§14.7); the sidecar never sends at the edge's value, and the statement takes the edge's either way.

**Part.** `index`, `mode`, `first_record`, `last_record`, `server_record_count`, `last`, `reply_count`, and k as the part that opens header record 1 named it; `records`, the ciphertext of each client record the part opens; the server records it covers, as the edge relayed them, from the previous part's `server_record_count` on.

**Commitments.** `KeyCommitment`, C: the key part's own `key_commitment`, and for every later part the C the gate kept from it. `CarryIn`, on a hdr or body part: the carry the gate kept, the latest a part published, or the start constant Com(T, U, start, 0) wherever a scan starts, before the body's first record and after the header block's last. `CarryOut`, on a msg, hdr or body part: the part's own `carry`, of the state it leaves; an empty body's last part, which opens no body record, leaves the state as it was, so its `CarryOut` is its `CarryIn`.

**Position templates.** These are not new information: they are a fixed function of the values above, and the edge computes them itself. For each opened client byte position the template gives one of:

- `lit(b)`: the plaintext octet is b;
- `local`: the octet is in section 4.2's `local` set;
- `free`: no constraint at this position.

For example the template of a 40-octet MAIL record is `lit("MAIL FROM:<")`, then `local` up to the suffix, then `lit("@" envelope_domain ">" CRLF)`, which fixes the length of `local` from the record's length. A template whose `local` run falls outside 1 to 64 octets has no satisfying plaintext, and the edge refuses the part without verifying it.

The statement a circuit proves is this vector, encoded as field elements in the order the shape defines (5.1). Encoding is frozen with the bytes at M9's exit.

### 5.1 The statement as field elements

Groth16's verifier takes the statement as elements of BN254's scalar field, one for each public wire of the shape's circuit, in the order the circuit declares them: `partCircuit`'s fields in declaration order, depth first, as gnark's schema walks a struct, private wires skipped (`circuit_part.go`, `circuit_message.go`, `circuit_replies.go`). A wire a shape does not use is an empty slice or a nil pointer, which the schema counts as none, so each shape's statement holds only the rows below that its kind has. The edge computes every element from section 5's values (`partAssignment`), so nothing in the statement comes from the prover but the records it opens, C in the key part and the part's own carry. A hash, random or other octet string enters as eight elements an octet, least significant bit first; a ciphertext or literal octet as one element from 0 to 255; a flag as 0 or 1; a count as its integer; a commitment as two elements, its x then its y, each below r, which are the 64 octets on the wire read as two 32-octet big-endian integers.

| In order | Elements | Shapes | What the edge puts there |
|---|---|---|---|
| `ShtsHash`, `HelloHash`, `FinishedHash` | 256 each | 1.3's key | H_shts, H_sh, H_sf |
| `ClientRandom`, `ServerRandom`, `ClientFinishedHash`, `Chaining`, `ResumeBase`, `ResumeShift`, `ResumeTwoBlocks`, then SF's `Counter` and `Cipher` | 256, 256, 256, 256, 1,024, 6, 1, 1 and 16 | 1.2's key | 1.2's Z1 inputs: r_c, r_s, SHA-256 of ClientHello .. ClientKeyExchange, S_ckx's chaining value (each 32-bit word least significant bit first), its unhashed tail followed by room for the client Finished and SHA-256's padding, the tail's length, and whether that takes two blocks; then the server Finished record as relayed |
| `KeyCommitment` | 2 | every shape | C: the key part's own, or the one the gate kept from it |
| Each client pool block: `Counter`, `Cipher`, `Literal`, `IsLiteral`, then `IsLocal` on an env shape | 1, then one a block's octet for each of the rest | every shape | the block's counter (below), its ciphertext, and the template: lit's octet, 1 where the position is lit, 1 where it is local. Only env shapes, whose blocks hold MAIL's and RCPT's local parts, carry the local table |
| Each server block: `Counter`, `Cipher`, `Active`, `TypeOctet`, `FirstOctet`, `WindowActive`, `Continues` | 1, one a block's octet for each of the next five, 1 | env, msg | the counter and ciphertext, then what record lengths fix: a content octet, 1.3's type octet, a record's first octet, a position whose next 16 octets lie in one record's content (Z9's window), and whether the block continues its predecessor's record |
| Header record 1's scan: its pool blocks, `Active` and `Field`, then the Message-ID, X-UR-Ref, Feedback-ID, From address and DKIM tag literals, each as `Expected` then `Used`, then `Bulk` | pool blocks as above, with no `IsLocal`; one a header octet for each of `Active` and `Field`; 124, 124, 124, 93 and 93 for each of `Expected` and `Used`; 1 | msg | Z5's public side for the first record: a content octet, a position before the block's final CRLF, each literal's octets and which of them are used, and the BULK flag |
| A later header record's scan: its pool blocks, `Active`, `Field`, `Bulk` | as above, with no literals | hdr | the same for a later record, `Field` 0 on the block's last two octets when this record is the last (H13) |
| The body record's scan: its pool blocks, `Active`, `End` | pool blocks, then one a block's octet for each | body | Z6's public side: a content octet, and on the body's last record its last octet |
| `CarryIn` | 2 | hdr, body | the gate's carry, or the start constant (section 5) |
| `CarryOut` | 2 | msg, hdr, body | the part's own carry |
| `ReplyCount`, `EhloRule`, `RequireChunking`, `Last354`, `Tls13` | 1 each | env, msg | `reply_count`; 1 at part 2; 1 at part 2 in BDAT mode; 1 in DATA mode on the part whose replies bring the proven count to 3 + R; 1 under TLS 1.3 |

A block's counter is one element: the record's `seq` in 1.3 or its explicit nonce in 1.2, times 2^32, plus Z2's block counter, 2 + j under AES-GCM and 1 + j under ChaCha20. Unused blocks are zero throughout. The env, msg, hdr and body circuits of AES-128-GCM's family serve TLS 1.3 and 1.2 alike: the type octet, the explicit nonce and the lengths differ only in what the edge assigns to these wires, and a 1.2 IV is its salt and 8 zero octets, which the key part committed (Z1).

Every public wire is read by some constraint (`TestEveryPublicWireIsConstrained`, over the eleven production shapes). Groth16 weighs each public input by its own element of the verifying key, and for a wire no constraint reads that element is the identity, so such a wire would verify at any value (reading 29). A flag a shape cannot use is bound to 0 there. `TestGroth16RefusesEachPublicInputOneBitOff` holds a real key-part proof, of ChaCha20's key shape, to this one input at a time.

The vectors, recomputed on every run:

- `testdata/vectors/connection-*.json` are nine honest connections, fixed once, each with every part's witness: six over both versions, both 1.3 suites and both modes (`tls13-aes-bdat` and its five siblings), and three BDAT connections, one a leg, whose envelope goes a command a group and whose header block takes two records (`*-groups-bdat`), so that every production shape and every flag proves in some vector. Each witness holds the session's keys, rho, and for a scan part the state its carry in opens to with that carry's blind and its carry out's blind.
- `testdata/vectors/statements.json` gives each of their parts' production shape by its KeySet name, its count of public inputs, the SHA-256 of its elements each written as 32 octets big-endian, its `reply_count` and k, C and each carry in hex as on the wire, and the template of each command record it opens, a run of local octets written `⟨local×n⟩` (`TestSpecVectorsReproduce`). Every part satisfies the relation over its witness, so C is the commitment of its keys under rho and each carry the commitment of its state under its blind; every later part's C is the key part's, and every carry in is the carry the scan part before it published or the start constant. `TestSpecVectorsCoverEveryShape` holds the vectors to proving under each of the eleven shapes.
- `testdata/vectors/commit.json` gives the commitments' six generators as literals (10.2), which the code also computes (`TestCommitGeneratorsAreFixed`).
- `testdata/vectors/pi1-tls13-chacha.proof` is one key-part proof of the ChaCha20 BDAT connection, and `pi1-tls13-chacha.vk` the verifying key of the single-party test setup it was made under; the names keep draft 2's π1. Together they pin the proof's 164 octets (10.1) and the verifying key's encoding beside the statement: the proof verifies against its own statement and fails with a public input moved, C's among them (`TestSpecPi1ProofVectorVerifies`). The key is a test's, never a release's.

## 6. Checks at the edge

`edgeSession` runs E1-E3. They are ordinary code, not circuit: each fails closed, and each failure before the first forwarded application record is a refusal, not a record cut, unless 14.7 says otherwise.

**The key set, before anything.** The preamble's `proof_key_set` names the key set every part of the connection is proven under (10.3). A verifier that does not hold that set, or holds it past its `not_after`, answers `ErrSmtpProofKeySet` (`HoldsKeySet`), which the engine sends as KEYS before it dials an MX or debits anything; a session verifies every part under the set its preamble named, for its whole life.

**The preamble, before E1.** A template is a literal and the circuit proves a record equals it, so a declared value holding `>` or CRLF would have the proof vouch for a command of the sidecar's own: `recipient_domain` set to `a.example>` CRLF `RCPT TO:<victim@other.example` would make a second recipient at another domain part of the template. So a session refuses, and the prover too before it dials, any preamble in which:

- `recipient_count` is 0, or more than `RecipientMaxCount` (100, §20.4's largest). BDAT with no RCPT draws a refusal, an MX that then reads the chunk as commands runs the unopened body, and the first message part would be satisfiable with the EHLO and MAIL replies alone (9.6). This is also why `partRoles` refuses it, so no statement of that count has a satisfying witness;
- `recipient_domain`, `header_from_domain`, `dkim_selector`, `envelope_domain` or `helo_name` is not RFC 5321's Domain: labels of 1 to 63 octets of letters, digits and hyphens, no hyphen at either end, 255 octets in all;
- `message_id` is not one `@` between two non-empty runs of section 4.2's `local` set;
- `x_ur_ref` or `feedback_id` is not in its exact form: X-UR-Ref is `1.` then the lowercase unpadded base32 of 21 octets, 36 characters, and Feedback-ID is `n` or `b`, `:`, `c`, `p` or `t`, `:`, the lowercase unpadded base32 of the 16-octet report token, `:urnetwork`, 40 characters (§14.6; plan-SMTP-small-readings #3 and #4). Each has one spelling: base32's unused low bits are zero. The edge issues both, so this is a check on itself, and their fixed lengths are what let the sidecar declare the octet count before the mode is known (plan-SMTP-preamble-byte-count).

**E1, handshake shape.** Over the relayed handshake:

- The client's first bytes are a ClientHello in a record of type 22. Its extensions hold no `pre_shared_key`, `early_data` or `session_ticket`, and none repeats. Its session id is empty, and its `server_name` holds exactly one name, the MX host, so no MX can read it as naming another.
- The ServerHello selects 1.3 with `AES_128_GCM_SHA256` or `CHACHA20_POLY1305_SHA256` and no `pre_shared_key`, or 1.2 with one of section 4.1's two suites and no `session_ticket`.
- After a HelloRetryRequest a 1.3 server may send a dummy change_cipher_spec, which reaches the edge ahead of the second ClientHello and is dropped there.
- 1.3: after the ClientHello the client sends at most one change_cipher_spec, then exactly one record of type 23, whose length is that of the client's Finished under the suite, plus an empty Certificate's 8 octets when the flight held a CertificateRequest. Nothing else passes before the key part verifies. This is what makes "no early data" hold for the client's second flight too.
- 1.2: the flight is exactly ServerHello, Certificate, ServerKeyExchange, optional CertificateRequest, ServerHelloDone; then optional empty Certificate, ClientKeyExchange, change_cipher_spec, one Finished record; then the server's change_cipher_spec and Finished record. Any other shape fails, because S_ckx and SF depend on it.
- Once application data starts, each client record's outer type is application_data and its version 0303. In 1.2 a server record of type handshake is refused too: no renegotiation.

**E2, the server's signature.**

- The edge dialed the MX it resolved (§14.4).
- 1.3: the disclosed SHTS is exactly 32 octets. HMAC zero-pads a short key, so a longer one could open the same flight. From it the edge derives the server handshake key and IV, opens the server's flight, checks CertificateVerify over `Transcript-Hash(ClientHello .. Certificate)` under the leaf key, and checks Finished under `HKDF-Expand-Label(SHTS, "finished", "", 32)`. Only then does it compute H_shts and H_sf.
- 1.2: it checks ServerKeyExchange's signature, in clear, over `r_c ‖ r_s ‖ params`.
- Accepted signature schemes are those the client offers, and SHA-1 is never accepted.
- The edge then forgets SHTS. D-SMTP-10 forbids storing it.

**E3, the record gate.** The gate is a state machine under one lock, so that "relayed before it" has a single meaning. It keeps, for the connection: C; the verified parts; the next client record a part must start at, f at first; the server records covered; the replies proven and the commands opened; the mode; k; the carry; and `commits`, the count of parts landed. For each client record, in stream order:

1. Its `seq` is the next expected. A record arriving early is held, within a bound; past the bound the connection ends.
2. Some verified part covers `seq`, or the record is held.
3. An opened record must equal the ciphertext the part proved, byte for byte. Unequal is a record cut.
4. In BDAT, a record between header record k and the final QUIT is body. The edge adds `len - 17` (1.3) or `len - 24` (1.2) to its count of chunk octets, and a record taking the count past `message_byte_count` is a record cut.
5. A **message record** (BDAT's command and chunk, the header records, DATA's body records and end mark) is held until verified parts cover every server record relayed before it. Holding is not a cut.
6. After the final QUIT no client record is forwarded. A later one, such as close_notify, ends the connection and is not a cut.

**The parts.** `VerifyPart` runs DESIGN-DETAILS 3.2.5's fences in this order. Each refusal ends the session (reading 20), and only step 13's is a cut:

1. The session has ended: refused. The MX has closed: the part is moot, and nothing more is done.
2. The handshake's inputs do not exist yet: refused.
3. `index` is the latest part's: an exact resend of that part, byte for byte, is a no-op, and any other part there is refused, so a verified part is never replaced (reading 32). `index` is not the next, or passes `PartMaxCount` (8,192): refused.
4. Part 1 opens exactly the record at f, with `mode` 0, no server record, no reply, no carry, no k and not `last`, and carries `key_commitment` in 10.2's form: 64 octets, two values below r, a point of E. No other part carries a key commitment.
5. The client range starts at the next record. A part opens no record, with `last_record` = `first_record` − 1 and not `last`, or the records `first_record` to `last_record` in strictly increasing `seq`, except that BDAT's last part carries QUIT alone at `last_record`, past the unopened body: at a `seq` the header block already holds, QUIT would stand in for that record and pass `BDAT 0 LAST` with no header block. At most `PartRecordMaxCount` (64) records. Each opened record holds at least its type octet in 1.3, and its outer type is application_data: that octet is public, and the circuit sees only ciphertext, so the gate checks it before verifying (reading 26). After a part with `last`, only parts that open no record.
6. The server range: `server_record_count` never falls and never passes what was relayed, and a part that opens no client record covers at least one more server record.
7. Part 2 names BDAT or DATA, and every later part repeats it.
8. The roles of the records it opens, from their positions, and the part's kind (4.3). k is on the part that opens header record 1, from 1 to `HeaderRecordMaxCount` (16), and on no other.
9. Replies. Part 2's `reply_count` is 1, it covers at least one server record, and it opens MAIL. A later part's is at most the commands earlier parts opened that are not yet answered, and 0 if it covers no new server record. The part that opens the first message record, BDAT's command or in DATA mode header record 1, brings the replies proven to exactly 2 + R, or 3 + R in DATA mode: the EHLO reply, MAIL's, R RCPT replies and DATA's 354.
10. Lengths: every opened command has a template at its length (reading 23); every header record but the last holds at least `HeaderRecordMinByteCount` (128) octets and the last at least `HeaderLastRecordMinByteCount` (4); a header or body record holds a content octet; DATA's octets never pass `message_byte_count` and reach it on the last part.
11. A part that opens a header or body record carries a `carry` in 10.2's form; no other carries one.
12. The part's shape: the first shape of the key set's catalog of the part's kind and the suite's family whose pools hold its records (`partShapeFor`); none, refused unverified. The statement is built from the gate's state alone: C, the part's own in part 1 and the gate's after; the carry in, the gate's, which is the start constant before the body's first record; the part's own carry out; the counts and flags of 5.1. `commits` is noted as it stands.
13. The proof is verified under the session's key set, with no lock held, since it is the slow step and server records may arrive during it. A failure is a cut (`ErrSmtpRecordCut`), unless the call's context ended first.
14. The session ended meanwhile: refused. Another part landed while this one verified, so `commits` moved: refused, because its order checks ran against what no longer stands. That holds for an exact resend that verified beside its original too (reading 41).
15. Commit. The part joins the verified ones and `commits` grows by one; part 1's commitment is C from then on; the next record follows `last_record` if the part opened any; the covered server count, the replies proven and the commands opened grow by the part's; mode and k are as it named them; the carry becomes the part's own, and the start constant once it opened header record k.
16. Release, by the six rules above. The records step 16 hands back are all the call returns.

Once the MX has closed, outstanding parts are moot. A late server record, such as a NewSessionTicket, holds message records by rule 5 until a part that opens no client record covers it, before or after `last`.

Every refusal and every cut ends the gate, whichever of E1-E3 it came from: each later call is refused, and nothing more is released for the MX, not even by a part that finishes verifying afterwards. The engine ends the connection on any error too, so this does not rest on the engine alone.

The engine cannot read records, so the gate tells it when it has handed out the record at f + 1, MAIL's, which is when §14.7 charges the connection a unit (`MailForwarded`). Records cleared by a call that ends in a cut are never handed out, and do not count.

The edge stores none of this past the connection (D-SMTP-10). Beyond draft 2's bounds (`MaxHeldBytes`, `MaxServerBytes`), a session holds C and one carry, 128 octets, and at most `PartMaxCount` parts' ranges.

## 7. The relation

For each part, the prover knows a witness such that every listed check holds. Z1-Z9 are DESIGN.md's; the text below states them over the normal form.

**Z1, keys.**

```text
1.3  witness HS
     SHTS = HKDF-Expand-Label(HS, "s hs traffic", H_sh, 32);  SHA-256(SHTS) = H_shts
     dHS  = HKDF-Expand-Label(HS, "derived", SHA-256(""), 32)
     MS   = HMAC(dHS, 0^32)                                   RFC 8446 §7.1
     CATS = HKDF-Expand-Label(MS, "c ap traffic", H_sf, 32);  SATS likewise with "s ap traffic"
     key  = HKDF-Expand-Label(secret, "key", "", key_len);    iv = HKDF-Expand-Label(secret, "iv", "", 12)
1.2  witness master_secret
     key_block = PRF(master_secret, "key expansion", r_s ‖ r_c)
                 = client key 16 ‖ server key 16 ‖ client salt 4 ‖ server salt 4
     cf = 14 00 00 0c ‖ PRF(master_secret, "client finished", SHA-256 finished from S_ckx)[0:12]
     SF opened under the server key and salt =
          14 00 00 0c ‖ PRF(master_secret, "server finished", SHA-256 resumed from S_ckx over cf)[0:12]
```

That is Z1's first step, and only the key part takes it, deriving both directions always. Its second step is in every part (DESIGN-DETAILS 3.2.3; `relationZ1`):

```text
the key part   witness HS or master_secret, as above, and rho
               ck, civ, sk, siv the derived client and server keys and IVs; in 1.2 civ and siv are the
               4-octet salts, each followed by 8 zero octets
               C = Com(G, H, ck ‖ civ ‖ sk ‖ siv, rho)        C is public: the part carries it
later parts    witness ck, civ, sk, siv, rho
               Com(G, H, ck ‖ civ ‖ sk ‖ siv, rho) = C        C is public: the gate supplies the key part's
               Z2 and Z7 take their keystreams from these wires
```

A later part holds no handshake input and no key schedule. The opening costs 3,026 constraints under AES-128-GCM and 4,133 under ChaCha20, where the derivation costs 708,498 in 1.3 (11.2).

**Z2, keystream.** Each proven plaintext octet is its ciphertext octet XOR the keystream at its record and offset. For a record of nonce `N`:

```text
N    = iv XOR (0^32 ‖ seq)          1.3
N    = salt ‖ explicit_nonce        1.2
AES-128-GCM        keystream block j = AES(key, N ‖ uint32(2 + j)), 16 octets
CHACHA20-POLY1305  keystream block j = ChaCha20(key, N, counter 1 + j), 64 octets
```

No tag is checked in the circuit. For client records the MX checks it; for server records the edge relays what the MX sent, and the key is already bound by Z1. A 1.2 IV is its salt and 8 zero octets, so the same XOR of the IV with the counter's upper 64 bits forms both versions' nonces.

**Z3, framing.** 1.3: each opened client record's plaintext, of length `len - 16`, ends in the octet 17 at its final position, which with section 4.2's templates rules out padding and every other inner type, KeyUpdate included. 1.2: the outer type is application_data (E1), and the plaintext length is `len - 24`. The outer type is public in both versions, so the edge checks it, on the stream by E1 and on a part's records by E3, and in 1.2 Z3 holds nothing a witness could break (reading 26).

**Z4, envelope.** Each opened command record matches the template its position gives it (4.3): `EHLO` at f, `MAIL` at f + 1, `RCPT` at f + 2 to f + 1 + R, then `BDAT n LAST` or `DATA` at f + 2 + R. Over the connection's parts, which open records of one kind each and whose ranges E3 holds contiguous, that is `EHLO`, `MAIL`, exactly `recipient_count` × `RCPT`, then `BDAT n LAST` or `DATA`, and these are all the client records before the message: one transaction.

**Z5, header block.** The header block's content `H`, the concatenation of its k records' contents in order, satisfies:

1. Every octet of H is HTAB, SP through `~`, CR or LF. CR occurs only before LF, and LF only after CR.
2. H ends in CRLF CRLF, and no earlier line is empty.
3. The first line is not a continuation, and every line that does not begin with SP or HTAB begins with one or more octets of 21-7E other than `:`, then `:`, and its first octet is not `.`. So `From :` is refused rather than left to each receiver's reading of obsolete syntax, and `.From:` is refused because an MX reading DATA deletes that dot (RFC 5321 §4.5.2): the field Z5 read as `.from` would reach it as a second From.
4. Exactly one line has each of the field names `from`, `message-id`, `x-ur-ref` and `feedback-id`, compared without case, and no continuation follows any of them. Each has its literal form:
   - `From: ` [phrase SP] `<` local `@` header_from_domain `>` CRLF, where phrase holds only `local` octets and SP, so `From` holds one address. Encoded words fit in phrase, with no `"`, `,`, `:`, `;`, `<`, `>` or `@`.
   - `Message-ID: <` message_id `>` CRLF
   - `X-UR-Ref: ` x_ur_ref CRLF
   - `Feedback-ID: ` feedback_id CRLF
5. Exactly one line begins with the constant `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; `, and it continues `d=` header_from_domain `; s=` dkim_selector `; `. This is §14.6's second signature, the one that survives masked reports. `h=` comes first because DKIM's tag order is free, and a constant prefix is what makes "exactly one" cheap to count in the circuit. The fuller signature and any other are unconstrained.
6. If BULK is set, exactly one line has the field name `list-unsubscribe-post`, compared without case, no continuation follows it, and it is `List-Unsubscribe-Post: List-Unsubscribe=One-Click` CRLF. Without BULK the field is unconstrained.

One fact is added to the six rules: the four single fields of rule 4, `List-Unsubscribe-Post` on a BULK message, and the fixed signature's line through its `d=` and `s=` tags lie in the header block's first record. An honest sender writes them first, before both signatures and the message's other fields (SMTP-M9-04's order; reading 30), and refuses at assembly a block whose head passes `SmtpSenderSettings.HeaderHeadMaxByteCount` (720 octets), under the shortest msg head (831); a header block that puts them elsewhere is unprovable.

*Z5 by record* (DESIGN-DETAILS 3.2.4; `scanHeaderRecord` in `relation.go`, `checkHeaderRecordCircuit` in `circuit_message.go`). Each record's part scans its content c of n octets from a state `in` and leaves a state `out`, and the part's carries commit to both: the msg part starts from `start`, a constant inside its circuit, and a hdr part opens the gate's carry to its `in`. The state is 24 bits, least significant first; its bit positions are identifiers:

```text
 0-1    pos      0 inside a line; 1 the last octet was CR; 2 it was LF, so a line starts next;
                 3 it was "." at a line's start (body only)
 2      name     a field name is unfinished: a line that is no continuation has not reached its colon
 3-9    run      octets so far of the line in progress, when it began in this record and is no continuation:
                 1 to 126, or 127 for more; 127 for a line that began in an earlier record; 0 after a line's end
                 and inside a continuation
 10-15  prefix   one bit for each of from:  message-id:  x-ur-ref:  feedback-id:  list-unsubscribe-post:  and the
                 fixed signature's prefix: run is under that literal's length and the line so far is its first
                 run octets (names without case, the prefix exactly)
 16     single   the line that ended at the last octet is one of rule 4's or rule 6's single fields
 17-23  zero
start = pos 2 and nothing else: before a header block's first octet, and before a body's
```

`Field[i]` is public and 1 on every header octet but the block's final CRLF. L ranges over the six literals above.

```text
every header record
 H1  each octet is HTAB, SP to "~", CR or LF                                                            rule 1
 H2  LF at i exactly when CR at i-1; at i = 0, exactly when in.pos = 1                                  rule 1
 H3  lineStart(i) = Field[i] and (LF at i-1, or i = 0 and in.pos = 2); a line does not start with CR    rule 2
 H4  nameStart(i) = lineStart(i) and c[i] is neither SP nor HTAB; a name's first octet is neither ":" nor ".";
     from a nameStart, or from i = 0 when in.name, until the next ":", no octet is SP, HTAB or CR       rule 3
 H5  hit(L, i)  = nameStart(i) and c[i .. i+|L|) = L, with every octet of it inside the record
     cross(L)   = in.prefix[L] and c[0 .. |L| - in.run) = L[in.run ..)
 H6  in.single implies c[0] is neither SP nor HTAB                                                      rules 4, 6
 H7  out.pos = 1 if c[n-1] is CR, 2 if LF, else 0;  out.name = a name is unfinished after c[n-1];
     out.run = as the state defines it, for the line in progress after c[n-1];
     out.prefix[L] = 1 <= out.run < |L| and c[n - out.run .. n) = L[0 .. out.run)
the first record (msg): in = start
 H8  c[0] is neither SP nor HTAB                                                                        rule 3
 H9  sum over i of hit(L, i) = 1 for from:, message-id:, x-ur-ref:, feedback-id: and the fixed prefix;
     = Bulk for list-unsubscribe-post:                                                                  rules 4, 5, 6
 H10 each hit's literal form, read at the hit (the From positions among them); an octet past the record's
     end reads as 0 and fails, so each of those lines lies inside this record                           rules 4, 5, 6
 H11 a single field's line is not followed by SP or HTAB inside the record;
     out.single = a single field's line ends at c[n-1]                                                  rules 4, 6
a later record (hdr): in = what the gate's carry opens to
 H12 cross(L) = 0 and hit(L, i) = 0 for every L and i, list-unsubscribe-post: only when Bulk;  out.single = 0
the header block's last record
 H13 its last four octets are CR LF CR LF by its template, and Field is 0 on the last two               rule 2
```

Each part asserts Com(T, U, in, sigma_in) = `CarryIn` (hdr) and Com(T, U, out, sigma_out) = `CarryOut` (msg, hdr). A record the gate accepts is at least 128 octets unless it is the last, so a literal of at most 99 octets straddles one boundary at most, where `cross` finds it. 9.5 argues that H1 to H13 over the records give rules 1 to 6 over their concatenation.

**Z6, the end of the message.**

- BDAT: the header records' chunk octets are exact (opened), the body's are bounded by E3's count, and together they reach `message_byte_count` exactly at a record boundary, which the edge checks as records stream. The record at `last_record` opens to exactly `QUIT` CRLF.
- DATA: `message_byte_count` counts the octets of the header and body records. Over their concatenation in order, the octets end in CRLF, hold no bare CR or LF and no line that is exactly `.`, and the final records open to exactly `.` CRLF and `QUIT` CRLF. Records are cut by length, not at line ends (reading 3), so a body record's scan starts from the state the record before left, which its carry in opens to: `start` for the body's first record, since the header block ends at its CRLF CRLF.

*The body by record* (DESIGN-DETAILS 3.2.4; `scanBodyRecord`, `checkBodyRecordCircuit`), for a record c of n octets from `in`:

```text
 B1  LF at i exactly when CR at i-1; at i = 0, exactly when in.pos = 1
 B2  an octet at a line's start (after LF; at i = 0 when in.pos = 2) that is "." is not followed by CR;
     at i = 0, in.pos = 3 forbids CR
 B3  out.pos = 1 after CR; 3 after "." at a line's start; 2 after LF; else 0;  every other bit of out is 0
the body's last record: its last octet is LF, by the public End flag, so the end mark starts a line
```

A body part asserts its carry in and carry out as a hdr part does. A body with no octet has no body record, and its last part opens the end mark and QUIT alone, from the start constant, its carry out equal to its carry in. A header record's DATA conditions are Z5's H1 and H2, whose CR and LF rule is B1's, and the header block's CRLF CRLF leaves the body's first record at a line's start.

**Z7, server records.** The private server key and IV that open C decrypt every server record the part covers, at its `seq`. Each is either application data, whose content joins the reply stream, or in 1.3 a NewSessionTicket: inner type 16, first octet 04, content skipped. Which is which stays private. Any other inner type, a KeyUpdate included, fails. In 1.3 each server record is unpadded: a padded one is unprovable and ends the send. In 1.2 a server record's type is public, and E1 passes only application_data after the handshake; the public flag `Tls13` is 0 there, which forces every block's private ticket flag to 0, where draft 2 compiled 1.2's shapes apart. `relation.go` and the checker count a server record's opening at its `seq` under Z2, as a client record's (reading 27).

**Z8, replies.** The reply stream of the server records a part covers parses as RFC 5321 reply lines: three digits, then `-` or SP with text, or CRLF directly; text holds no CR or LF. A reply is its lines through one without `-`. A part's server records begin at the start of a reply and end at the end of one: nothing of the parser crosses a part, so there is no carry for it. Then, part by part:

- the stream holds exactly `ReplyCount` whole replies;
- with `EhloRule`, part 2's alone, that is one reply, every line coded 250;
- otherwise every reply is coded 2xx, except that with `Last354` the last is coded 354.

Across the connection the gate adds the counts, and the part that opens the first message record must bring them to 2 + R, or 3 + R in DATA mode (E3, step 9): §14.5's "exactly 1 + R replies, then 354" beside the EHLO reply. A server record relayed past the message's start is covered only by a part that opens no client record, whose `ReplyCount` the gate holds at most the commands left unanswered, which is 0 by then: a ticket can be covered, a reply never, so a reply there holds the message's records for good. In BDAT mode this ends at the chunk; in DATA mode the sidecar stops.

**Z9, mode.** `mode` is public and fixed from part 2, whose `RequireChunking` is set exactly when it names BDAT. For BDAT, the EHLO reply of Z8 holds a line that is exactly `250-CHUNKING` or `250 CHUNKING`, keyword compared without case, and it is not the reply's first line. That line and the CRLF before it lie in one application record, and a ticket's octets do not count. BDAT to an MX lacking it is unsatisfiable. DATA has no such condition: DATA to an MX offering CHUNKING is allowed, and interop forces it (§14.5).

## 8. Which adversarial case each check stops

D-SMTP-16's corpus, FS-31 included. Each row must fail before any effect, with honest controls passing.

What §22.10 asks of each check is shown by `testdata/mutations/table.md` (SMTP-M9-29): for each of E1 to E3 and Z1 to Z9, in each TLS version and mode the check applies to, a break of one honest connection that only that check refuses, the part refused named by its index and kind. The relation, through the gate, and `smtpproof/checker` name the one check alike; then the circuit refuses the part, through gnark's solver over the edge's own statement on a test shape sized to the part (Z1's key-part rows on the key part's production shape, which alone holds the derivation), or the gate refuses on its own with the solver as its verifier as well. The table also lists the cells no witness can break alone, and why: 1.2's Z3 and Z7, whose content is public (reading 26), and DATA's Z9, which has no condition.

DESIGN-DETAILS 3.6 added five cells for parts bound to one key part, and the table fills each in every TLS version and mode its check applies to:

| Check | Cell | Mutation, as the table runs it |
|---|---|---|
| Z1 | a later part opens other keys than the key part committed | the env part's client key one bit off, its records sealed again under that key |
| Z5 | a scan started from another state than the record before left | header record 2 scanned from the start state, where record 1 ended inside a field's name |
| Z6 | the same, in DATA's body | body record 2 scanned from the start state, where record 1 ended inside a line |
| Z8 | `reply_count` is not what the records hold | one more, MAIL's reply continued into the first RCPT's; one fewer, the first RCPT's reply rewritten as two; and an env part's own count one fewer, the envelope a command a group |
| E3 | a first message record before 2 + R replies are proven | the msg part covers none of the envelope's replies, its own count 0, so only the EHLO reply is proven |

| Case | Stopped by |
|---|---|
| Key substitution: one ciphertext, benign under one key, real under another | Z1 ties the key part's keys to the observed handshake, and every later part's to C (9.2, 9.3) |
| Key substitution between parts: a later part under other keys, or naming another C | Z1's opening: other keys open C only through a discrete logarithm (9.3); a later part's C is the gate's, never the part's (E3, step 12) |
| Record splits, a command split or two in one record | Z3 and Z4: one command per record, template by length |
| Replayed server replies | Z7: a record decrypts only at its own `seq`, which the edge assigns |
| A pipelined second transaction | Z4 and E3: every client record is proven; a second MAIL has no part |
| A declared value that carries a command, or no recipient at all | The preamble's forms, before any template is built (section 6) |
| A part's records stood on one number, to drop the header block | E3: `seq` strictly increases within a part |
| Smuggled headers, a second From, one behind a leading dot | Z5.3, Z5.4 |
| A header field name, or the fixed signature's prefix, split across two records | Z5's carries: `name`, `run` and `prefix` cross the boundary, and H12 refuses a crossing (9.5) |
| A header or body record scanned from a forged state | The carry: a part's carry in is the gate's, and opens only to the state the part before published (9.3, 9.5) |
| A BULK message whose one-click field is continued, doubled or of another value | Z5.6 |
| An early or bare-LF DATA end, wherever a record boundary falls | Z6, B1 and B2 across boundaries by the carry |
| No CHUNKING; CHUNKING only before TLS | Z8, Z9 over the post-TLS reply; the edge's pre-TLS hints are not inputs |
| No PIPELINING | The sidecar paces a group's commands; one part covers them; E3 forwards in order |
| A refused MAIL or RCPT, mixed recipients | Z8: the part that covers that reply is unsatisfiable, so no record after it is forwarded |
| A reply count the records do not hold | Z8: exactly `reply_count` whole replies |
| A message record before the envelope's replies are proven | E3, step 9: 2 + R replies, 3 + R in DATA mode, before the first message record |
| No 354 | Z8, `Last354` |
| A late NewSessionTicket | Z7 skips it; E3 holds message records until a part, which may open no client record, covers it |
| Two parts verified against one state | E3, step 14: a part commits only if no part landed while it verified |
| A verified part sent again, changed | E3, step 3: no part is replaced |
| A second transaction in the alleged BDAT body | Z8, Z9 prove the MX is reading a chunk; E3's count bounds it |
| Padded or KeyUpdate BDAT body records | May fail the send, smuggle nothing (9.7) |

FS-31 (SMTP-M9-30) runs these as adversarial rows through the real prover and gate, scripted MXs among them, each failing before any effect beside its honest controls, the 100-recipient and 16 KiB header-block controls included.

## 9. Why it is sound

This is a draft argument. Two engineers who did not write the circuits must argue soundness in writing before M9 (D-SMTP-16); this section is what they start from, not a substitute. It follows DESIGN-DETAILS 3.3: draft 2's argument with its key step replaced and three added, labelled S1 to S7.

### 9.1 Assumptions

- The proof system is knowledge sound for the honestly generated verifying key the edge holds (section 10).
- SHA-256 is collision resistant, and HMAC-SHA-256 is a PRF and collision resistant under the key input in the sense 9.2 uses.
- Discrete logarithms in the order-l subgroup of E are hard, about 2^125 work, above the 100 to 110 bits 9.10 gives BN254 for forging a proof; and nobody knows a relation among the generators of 10.2, which are hashed to the curve. Forging against this, like forging a proof, costs abuse control and never confidentiality.
- The honest MX: verifies AEAD tags with the keys of the handshake it took part in; assigns `seq` by counting; answers commands in order; reads exactly n octets after `BDAT n LAST`; and resets nothing after STARTTLS except what RFC 3207 §4.2 says.
- The edge's TCP path to the MX is not under the sidecar's control.

### 9.2 Keys are the MX's

**S1, once.** The key part's circuit derives ck, civ, sk, siv from a witness that the following shows is the MX's secret, and asserts C = Com of exactly those wires. So C commits to the MX's keys.

1.3. The MX computes its traffic secrets from one HS. Its Finished, verified in E2 under SHTS, and its AEAD-protected flight fix the SHTS the edge accepts: an honest MX's ciphertext opens under only that key, except with negligible probability, since the sidecar cannot choose that ciphertext. That removes the non-committing-AEAD attack for the flight. Z1 then shows the prover knows HS' with `SHA-256(Expand(HS', "s hs traffic", H_sh)) = H_shts`. If HS' differs from the MX's HS, that is a collision in SHA-256 or in HMAC under the key input. So HS' = HS, and everything derived from it under the edge's H_sf is what the MX derived. This is the step PLAN's "first N bytes" lacked.

1.2. No secret is disclosed (D-SMTP-21). Instead SF, a ciphertext the honest MX authored, must open under a key derived from master_secret' to a verify_data which that same master_secret' gives the relayed handshake. An honest master secret satisfies this. For any other, the 16-octet equality holds with probability 2^-128 per candidate, treating PRF outputs as random, and the prover has only offline trials. So it is the MX's. The margin is 128 bits with no tag check, the reason to treat 1.2's Z1 as a separate review item.

### 9.3 Every part uses them, and a verified part is fixed

**S2, every part uses them.** A later part's statement has the gate's C as a public input (E3, step 12), never a value the part carries. Its circuit asserts Com(its key wires, its rho) = C. If those wires differ from the MX's keys, the two openings of C, the key part's and this one, give a relation among the generators G_j and H whose discrete logarithms nobody knows (9.1). So every keystream in every part is the MX's, which is what 9.4 needs of each part. The key part's own keys are the MX's by S1, both directions, so the server records any part covers open under the MX's server key too.

**S3, a verified part is fixed.** Step 12 builds the statement from the gate's state, and step 14 commits a part only if no part landed while it verified (`commits`), so the C, the carry, the counts and the ranges a proof was verified against are the gate's at the moment it lands. No step replaces a part (step 3), so a part's published carry and counts cannot change after the records it covers have left.

### 9.4 What the MX reads is what was proven

With the key bound, CTR-mode decryption is a function of key, nonce and ciphertext. In 1.3 the nonce depends on `seq`, which E3 fixes by stream position; in 1.2 it is in the record the edge compares. So the plaintext the MX obtains from an opened record, if its tag verifies, is the proven plaintext. If its tag does not verify, the MX aborts and nothing happens. Z3's final octet makes the inner type application_data, so the MX treats the octets as SMTP input and nothing else. E3 forwards opened records only if they equal the proven ciphertext. So the MX's input stream, through every opened record, is exactly the concatenation of proven contents, part by part in `seq` order.

### 9.5 The header block across records

**S4, the header block across records.** Let the header block be c_1 .. c_k, every record but the last at least 128 octets and the last at least 4 (E3, step 10), and let each record's part verify with `CarryIn` the commitment the gate kept. By binding, the state a part opens is the state the part before published, and H2 and H7 make that the true state of the block's scan at the boundary, by induction from `start`. Then Z5 holds of the concatenation. Rules 1 to 3 are H1 to H4 at every octet, with `pos` and `name` standing for the octet and the name across a boundary, and H13 at the end. For rules 4 to 6, every line start of the block is a `nameStart` in exactly one record, and a literal L at it either lies inside that record, a `hit`, or runs past its end. In the second case it ends in the next record, since L has at most 99 octets and the record at least 128, and there `cross(L)` is true, because `run` and `prefix[L]` say exactly that the line so far is L's beginning. H9 counts one hit of each L in the first record, and H12 allows no hit and no crossing after it. So each single field and the fixed prefix begin exactly one line of the block, that line is in the first record, H10 reads its literal form there, and H11 with H6 let no continuation follow it. That is Z5, with the added fact of where those lines sit.

### 9.6 The MX's state is what the relation assumes

**S6, the replies.** Z7 opens the MX's own records under its own key, and E2's dial means they are the MX's. So Z8's parse is of what the MX really said, in order. This is why D-SMTP-22 proves replies rather than trust the sidecar's reading (RFC 3030 §2, RFC 3207 §4.2): the same bytes mean a message to a chunk-reading MX and commands to any other. A part's server records are contiguous from the last covered record (E3, step 6) and parse from a reply's start to a reply's end as exactly `reply_count` replies, each accepting, the last a 354 where `Last354` is set (Z8). So the verified parts' counts sum to the number of replies in the covered records, each proven. Step 9 lets the first message record be covered only when that sum is 2 + R, or 3 + R in DATA mode, and step 16 releases a message record only when every relayed server record is covered. The honest MX answers commands in order (9.1), so at that moment it has accepted EHLO, MAIL and exactly R recipients, has said 354 in DATA mode, and has said nothing since. So no refusal can be in flight unnoticed at the moment a message record is released. It can still arrive just after; 9.8 covers that.

That argument needs an envelope to accept. With `recipient_count` 0, the first message part needs only the EHLO and MAIL replies and the MX has no recipient, so it refuses BDAT however it reads what follows. Section 6 refuses that count for this reason.

### 9.7 BDAT's unopened body

The MX reads chunk octets from records. An honest edge counts each body record as carrying `len - 17` (or `len - 24`) octets. A 1.3 record carries at most that, and fewer if padded or if it is not application data; a 1.2 record of clear type application_data carries exactly that. So at every point the MX's count is at most the edge's, and the edge's never passes n. Hence:

- If every body record is unpadded application data, the MX reaches octet n exactly at the proven QUIT, and sees `QUIT`.
- Otherwise the MX is short of n when the QUIT record arrives, and the QUIT's octets are chunk data, or the chunk ends inside them and the MX reads at most the 5 remaining octets as a command. No client record follows (E3 step 6), and 5 octets hold no transaction.
- A KeyUpdate in the body makes the MX change keys, so the proven QUIT, sealed under the old key, fails its tag and the connection dies.

In no case does a body octet reach the MX's command parser.

### 9.8 DATA

**S5, DATA's body across records.** The same induction as S4 over B1 to B3: `pos` is the true state at every boundary, B1 pairs every CR with an LF across boundaries, and B2 with `pos` 3 refuses a line that is exactly "." wherever a boundary falls in it. The header block's records hold no bare CR or LF by H1 and H2 and no "." line by H4, and end at a line's start, which is the start constant the gate hands the body's first part. The last body record ends in LF, so the end mark starts a line. That is Z6 over the concatenation of header and body records.

Every octet is opened. Z6's no-bare-CR-or-LF and no-`.`-line conditions mean no receiver, strict or lax about line endings (CVE-2023-51764), sees an end of data before the proven end mark. A reply arriving after a message record was released, such as a late refusal, holds the next message record (E3 step 5), and a refusal is unprovable, so the connection ends with no further octets.

What the MX stores is not quite what was proven: it deletes each line's leading dot (RFC 5321 §4.5.2). Z5.3 keeps that from touching the header block, whose lines begin with a field name or with SP or HTAB, so the header block Z5 read is the one it stores. The body is unconstrained either way.

### 9.9 Conclusion

**S7, the claim.** With S1 to S6: 9.4 gives the exact client command stream, the concatenation of proven contents, Z4 gives its shape, 9.6 gives that the MX acted on it as a transaction, and 9.7 and 9.8 that nothing beyond it reaches the command parser. Z5 and Z6 give the message's properties, each over proven octets, across records by 9.5 and 9.8. That is section 1's claim.

### 9.10 Known weak points for the reviewers

- Z5 constrains what receivers parse only as far as receivers agree with RFC 5322 on the normal form. A receiver that treats some other octet as a line ending defeats Z5.3; none is known for the class Z5.1 permits, and the corpus should keep looking.
- Z5 does not bound a line's length. A hop that breaks a line past 998 octets without folding it would start a new header line mid-field, where Z5 saw none. Nothing here has tested what real hops do with such a line. A bound would be a counter and a range check per octet, by estimate about 50,000 constraints on a 4 KiB header block, if the reviewers want it.
- 1.2's 128-bit margin (9.2), BN254's estimated 100 to 110 bits for forging a proof and E's 125 bits of discrete logarithm for opening C to other keys (9.3) are the three smallest numbers in this document. Each costs abuse control, never confidentiality (10.2).
- S4's step from 128-octet records to "a literal straddles one boundary" holds only while every literal the scan seeks is shorter than `HeaderRecordMinByteCount`. The longest is the fixed signature's prefix at 99 octets; `TestSpecHeaderRecordsOutlastEveryLiteral` holds that order against the settings' default, and a host that lowered the setting would lose S4.
- The commitment gadget is new arithmetic, a fixed-base window table over E and its complete addition law, about 150 lines (`circuit_commit.go`). `TestCommitGadgetMatchesGnarkCrypto` holds it to gnark-crypto's own arithmetic over random messages and blinds; it has had no review outside this build.
- The Groth16 setup's soundness rests on the edge's own contribution (10.3). That is the right party, but a leaked toxic secret is silent. A key set is replaced only when a circuit or the catalog changes or the ceremony host is suspected exposed (owner decision 435), so a silent leak stays useful until then.

## 10. Proof system

### 10.1 Choice

**Groth16 over BN254, using gnark's `frontend`, R1CS builder, `backend/groth16` and its two-phase `mpcsetup`, with this module's own gadgets.**

- Speed decides. D-SMTP-16's bars rule out a prover much slower than Groth16's: PLONK over the same relation costs several times the rows, and transparent systems have no audited Go implementation under §4.7's licenses. A designated-verifier VOLE prover stays Later (§14.15).
- Proofs are 3 group elements and verify in milliseconds at the edge.
- The costs are a per-circuit setup and large proving keys (10.3, 11.3).

**License check against §4.7.** Read from each module's own LICENSE file at the pinned version, for everything linked with `CGO_ENABLED=0`:

| Module | Version | SPDX |
|---|---|---|
| github.com/consensys/gnark | v0.15.0 | Apache-2.0 |
| github.com/consensys/gnark-crypto | v0.20.1 | Apache-2.0 |
| github.com/bits-and-blooms/bitset | v1.24.4 | BSD-3-Clause |
| github.com/blang/semver/v4 | v4.0.0 | MIT |
| github.com/fxamacker/cbor/v2 | v2.9.0 | MIT |
| github.com/google/pprof | v0.0.0-20260202012954-cb029daf43ef | Apache-2.0 |
| github.com/mattn/go-colorable | v0.1.14 | MIT |
| github.com/mattn/go-isatty | v0.0.20 | MIT |
| github.com/ronanh/intcomp | v1.1.1 | Apache-2.0 |
| github.com/rs/zerolog | v1.34.0 | MIT |
| github.com/x448/float16 | v0.8.4 | MIT |
| golang.org/x/crypto, x/sync, x/sys | the shared versions | BSD-3-Clause |

All are on §4.7's list. Refused: ORIGO's artifact (no license, and anonymous research code), Reclaim's `zk-symmetric-crypto` circuits (custom license). Nothing here was copied from either. `icicle-gnark` appears in gnark's go.mod for its GPU backend, behind a build tag; it is not linked, and there is no cgo.

**Why v0.15.0, and the rule that follows from it.** Two constraints meet here.

- §4.7 requires shared modules to match connect, sdk and server. server and sn pin `gnark-crypto` v0.20.1, `bitset` v1.24.4, `go-colorable` v0.1.14 and `go-isatty` v0.0.20, and gnark v0.15.0 requires exactly those. Every v0.16.x raises all four, and v0.16.4 raises `gnark-crypto` to an untagged pseudo-version.
- gnark v0.15.0's `std/math/uints` is unsound. It trusts lookup results to be in range, but the log-derivative table constrains only a packed value, so a malicious prover can answer `Xor(1,0) = 1/256`, which packs to the same key as the true entry. v0.16.0 added the range check; the comment in `uints/bytes.go` there explains the collision. `std/permutation/sha2` and `std/hash/sha2` are built on `uints`, so **gnark v0.15.0's SHA-256 gadget must not be used.** Its source is byte-identical to v0.16.4's, which hides this.

So this module pins v0.15.0 and **imports nothing from gnark's `std/`**. `TestCircuitsImportNoGnarkStd` enforces that, and `TestCircuitsUseNoCommitments` that no compiled circuit carries a commitment; `setup.go` also refuses one. The one `std` package still reached is `std/math/bits`, which the R1CS builder itself calls for `api.ToBinary`; it has no lookup, and between v0.15.0 and v0.16.4 it only gained an optional bound. The gadgets here are plain R1CS over boolean wires. That costs constraints (AES most: 11.2) and buys two things: the v0.15.0 bug cannot reach the relation, and the circuits have no lookups, so no BSB22 commitment, which leaves vanilla Groth16 with three-element proofs and the simple ZK argument of 10.2.

The statement's own commitments, C and the carries, are not gnark's `Commit`: they are arithmetic inside each circuit over wires it already holds, this module's gadget over E (`circuit_commit.go`), with no lookup and nothing from `std/`, so the two tests above and the proof's single form stand. On the witness side and in tests the same commitments come from gnark-crypto's `ecc/bn254/twistededwards` (`commit.go`), which `TestCommitGadgetMatchesGnarkCrypto` holds the gadget to.

Between v0.15.0 and v0.16.4, the packages this module links differ only by `uints`-style `std` changes it does not use, a prover `Accelerator` refactor, a `Lookup2` optimization and a commitment index fix it cannot reach; `backend/groth16/bn254/verify.go` is unchanged. That comparison was by `diff` over those packages, and a reviewer should repeat it at each bump. `gnark-crypto` v0.21's security fixes touch EdDSA, shplonk, fflonk, KZG's ceremony and twisted Edwards curves. Draft 2 found none of them on this path; since draft 3 the twisted Edwards package is on it, on the witness side (`PointAffine`'s addition, scalar multiplication and `IsOnCurve`, and the gate's `IsOnCurve`), and no comparison of that fix against these uses has been made here, since nothing outside the module proxy's named modules may be fetched. It is a review item at the next bump (section 14). The KZG one would matter to a PLONK route.

Moving past v0.15.0 is a coordinated bump across server and sn, and it would still leave lookups subject to 10.2's review.

**Decoding a proof.** gnark's `Proof.ReadFrom` allocates the count of commitments the octets declare before it reads one, so a few hostile octets from a sidecar could ask an edge for 256 GiB, and a point marked uncompressed moves that count, so a length check alone does not help. These circuits carry no commitment, which leaves a proof one form, 164 octets, and `decodeProof` reads that and nothing else. A bump must keep it: `TestGroth16ProofOfARealEhlo` fails if gnark's encoding moves.

### 10.2 Zero knowledge

Groth16 is perfectly zero knowledge for every well-formed CRS: given the CRS trapdoor a simulator outputs proofs distributed identically to real ones, and the proof's `r`, `s` are uniform. A malicious edge that ran the setup holds that trapdoor. Holding it gains nothing, since the simulated and real distributions are the same.

A malformed CRS is different: a key element off its intended value can make a proof depend on the witness in a way the edge can test. So the prover must not take keys on trust. **A prover host uses a proving key only if `verifySetup`, which runs gnark's `VerifyPhase1` and `VerifyPhase2` over the setup transcript against the circuit it compiled from its own source, produced that key.** Those checks establish that the key is of the form Groth16's analysis needs, for whatever trapdoor. This is subversion zero knowledge by verification, in the sense of Bellare, Fuchsbauer and Scafuro (Asiacrypt 2016) and Fuchsbauer (PKC 2018). A transcript travels as bytes and is decoded for each verification: gnark's checks assume what its `ReadFrom` establishes, group membership among them, and they modify the last contribution they are given.

Three consequences:

- Confidentiality does not rest on BN254's hardness or on any secret being destroyed. The curve's bit security bounds only forgery, which is abuse control.
- No lookups and no gnark `Commit` means no element of the proof carrying witness data. gnark's `Commit` adds a random mask, but a masked Pedersen commitment under a basis whose discrete logs the edge knows would need its own argument inside the proof system, which this design does not have to make. The statement's own commitments are another matter, and K1 below argues them.
- Randomness: `r` and `s` come from `crypto/rand`. A repeated `(r, s)` across proofs under one key would break ZK, so no deterministic or seeded prover exists outside tests.

**The commitments** (DESIGN-DETAILS 3.2.2; `commit.go`, `circuit_commit.go`). Both are Pedersen commitments over the twisted Edwards curve whose base field is F_r, so a point is a pair of circuit wires and its group law a handful of constraints:

```text
E:  -x^2 + y^2 = 1 + d x^2 y^2  over F_r
    d = 12181644023421730124874158521699555681764249180949974110617291017600649128846
    order 8 l, l = 2736030358979909402780800718157159386076813972158567259200215660948447373041, prime
    (gnark-crypto's ecc/bn254/twistededwards, on the witness side and in tests; the circuit side is this
     module's own gadget). a = -1 is a square in F_r and d is not, so the addition law
       (x1, y1) + (x2, y2) = ( (x1 y2 + y1 x2) / (1 + d x1 x2 y1 y2),  (y1 y2 + x1 x2) / (1 - d x1 x2 y1 y2) )
     is complete: no pair of points has a zero denominator, and (0, 1) is the identity

generator(tag, i):                    a point of order l whose discrete log nobody knows
    for c = 0, 1, 2, ...:
        y  = SHA-256("urnetwork smtpproof commit v1" || 0x00 || tag || 0x00 || u32be(i) || u32be(c)), as a
             big-endian integer, mod r
        x2 = (1 - y^2) / (-1 - d y^2);  next c if the denominator is 0 or x2 is no square
        x  = the square root of x2 that is the smaller integer
        P  = 8 (x, y);  next c if P = (0, 1)
        return P
    G_j = generator("key", j), H = generator("key blind", 0)          C's, j = 0, 1, 2
    T_0 = generator("scan", 0), U = generator("scan blind", 0)        a carry's

Com(generators, blind generator, bits, blind):
    split bits into runs of 246, the last shorter; run j is the integer m_j = sum of bit_i 2^i
    return sum_j m_j G_j + blind × blind generator

C      = Com(G, H, ck || civ || sk || siv, rho)
         ck, sk: the client and server write keys, 16 octets under AES-128-GCM, 32 under ChaCha20
         civ, siv: 12 octets each; 1.3's write IVs, 1.2's 4-octet salts each followed by 8 zero octets
         octets in that order, each octet's bits least significant first: 448 bits and two runs, or 704 and three
a carry  = Com(T, U, state, sigma), state the 24 bits of Z5's scan state
the start constant = Com(T, U, start, 0), which the gate supplies wherever a scan starts: the state is public,
         so its commitment needs no blind
rho and each sigma: 251 bits, uniform in [0, l), drawn from crypto/rand by rejection, one rho a connection and
         one sigma a carry, never derived, never reused, and passed to testHookSecret where they are drawn
on the wire and as public inputs: x || y, each 32 octets big-endian and below r; the gate refuses any other
         length, a coordinate not below r, and a pair that is not on E
```

The generators are literals in `testdata/vectors/commit.json` as well as computed, so a change to either fails (`TestCommitGeneratorsAreFixed`). The gadget takes message and blind bits as boolean wires, three at a time: for window w of run j it selects from the eight constants v 8^w G_j, v = 0 to 7, by the table's multilinear form in the three bits, and adds the selection to the running point by the complete law; the result is asserted equal to the public pair. A point off the subgroup cannot equal that sum, so the gate's check that a pair is on E is enough of a form check, and the circuit does the rest.

**Why the statement says nothing** (DESIGN-DETAILS 3.3), against an edge that ran the setup and deviates as it likes:

- **K1, the commitments say nothing.** C is uniform over the order-l subgroup whatever the keys are, and each carry is uniform whatever the state is, because each has a fresh uniform blind on a generator of that subgroup. This is perfect, not computational: it does not depend on who knows what about the generators, nor on how they were chosen.
- **K2, the proofs say nothing.** Each proof is a Groth16 proof under a key the host's own check derived from a verified transcript over the circuit that proves (10.3), so it is distributed as a simulated proof of its statement. The statements hold C and the carries, which K1 makes simulatable without the witness. So the edge's whole view, commitments and proofs together, is distributed as a simulator's that is given only the public inputs.
- **K3, the part structure says nothing new.** A part's ranges, `last`, `mode` and `server_record_count` are as draft 2's. k and each header record's length are the cut of the header block's length, which the edge already sees. `reply_count` is the number of commands the group before held, which the edge relayed, unless an overflow split a group's replies, and that follows from server record lengths it relayed (reading 36). Group sizes follow from command record lengths and an estimate computed from public values alone (4.3). DATA's body records are cut by length where draft 2's ended at line ends, so their lengths reveal less than before.
- **K4, the key is the host's own.** No proof is made under a key that is malformed, torn, or of another circuit than the one proving, over every build, pin and cache state (`ProofKeys.tla`'s `ZkSafe`; 10.3).

*If the blinds failed.* K1 needs rho uniform and secret. Suppose a bug made rho known to the edge. C would then be a binding function of the 448 or 704 key bits: a way to test a guess of all of them, and nothing shorter. A record's ciphertext and tag already give the edge that test. So even a total failure of hiding hands the edge nothing it lacks; what would break is the claim, not the mail. `TestCommitBlindsAreFresh` holds that two connections' rho and every carry's sigma differ, each passing `testHookSecret` where it is drawn.

What a failed proof reveals: a part that cannot be proven tells the edge the MX's reply was not the accepted one. This is the "connections ending before the message part" signal §14.15 already counts, and the only intended leak beyond the public inputs.

### 10.3 Setup

The edge is the only party relying on soundness, so **the edge may run the setup alone**: for soundness it needs one honest contribution, and it trusts itself. No ceremony with outsiders is needed, and none adds anything to ZK, which verification provides.

A sidecar must never know a trapdoor, which holds because it contributes nothing. Every production circuit is one 2^20 domain (10.4), so one phase 1 serves them all:

1. Phase 1, once, for the one domain size: contribute, seal with a public beacon.
2. Phase 2 per shape: contribute, seal.
3. Publish the transcripts and the verifying keys, release-pinned by hash. Proving keys are not published: each host derives its own.
4. A prover host checks each shape once a key set (10.2, K4), then caches what its check produced.

Where the bytes live is the owner's answer to `smtpproof-start-key-distribution` (owner decision 266), with what DESIGN-DETAILS 3.2.7 filled in: a host fetches its key set's transcripts from a public path on ur.io, with no token and no account, pinned by hash in the release; the check makes the path need no trust. What the path's host sees is §2.8's smtp-7 (owner decision 253): per fetch the client's address and time, the key set's id and the names of the files fetched, which mark the address as a mail prover host. About 0.9 GiB a key set is fetched and about 3.7 GiB kept.

**The key set** (`setup_keys.go`). `keyset.json` version 2, whose SHA-256 is the key set's id, the release's pin and the preamble's `proof_key_set`:

```text
{ "version": 2,
  "beacon": hex,
  "phase1": [ { "domain_size": 1048576, "contributions": [ { "name", "sha256", "byte_count" } ] } ],
  "shapes": [ { "name": "hdr-aes128gcm-c2-r76",
                "circuit_sha256": hex,        SHA-256 of the shape's compiled R1CS as its WriteTo writes it
                "domain_size": 1048576,
                "contributions": [ { "name", "sha256", "byte_count" } ],
                "proving_key":   { "sha256", "byte_count" },             its WriteTo encoding; the file is not published
                "verifying_key": { "name", "sha256", "byte_count" } } ] }
```

- **The ceremony** is `smtpproof/setup -out <directory> -beacon <hex>`, which is `RunSetup`: one phase 1 for the one domain, phase 2 per catalog shape, each shape's `circuit_sha256` and every file's `byte_count`, and the keys each transcript fixes, derived by the same check a prover host runs. It prints the pin. `setup -extend <directory>` adds entries for catalog shapes a set lacks, on its phase 1, and leaves every existing entry byte-equal, which makes a new id under which the old shapes keep their keys; `setup -digests <file>` writes `shape_digests.go`. The command stays where reading 24 put it.
- **Published** at `<SmtpProofKeysUrl>/<id in hex>/<name>`: `keyset.json`, the phase 1 and phase 2 contributions, the verifying keys. `SmtpProofKeysUrl` comes from §18.9's host table, which OPS-M9-02 fills; until it does, `cli/` fetches nothing and a host checks only what its key directory holds.
- **At the edge**, `smtpedge.yml`'s `proof_key_sets` lists each set's id, the directory holding its `keyset.json` and verifying keys, and an optional `not_after`. `NewVerifier` takes up to `VerifierSettings.KeySetMaxCount` (4) sets, checks each file against `keyset.json` and `keyset.json` against its id, and drops a set past its `not_after` at start and at each session's open. The edge ran the ceremony, so it needs no transcript check, and it checks no circuit digest (reading 39).
- **In the release**, `cli/smtp_prover.go`'s `smtpKeySetPins`, newest first. The newest is the set this build's circuits were set up for; an older one stays listed only while this build compiles the same circuits for it, which the host checks by digest, not by trust. `shape_digests.go`'s `smtpShapeDigests` holds each catalog shape's R1CS digest beside the pins, held to the source by `TestShapeDigestsAreThisBuilds`, which compiles every catalog shape. The circuits' two hints take fixed ids, so a digest holds no package path (reading 38).

**What a host does.** `KeySet.EnsureKeys(ctx, family)`, which `SmtpProver.PrepareKeys` advances a shape at a time, runs at idle, only on a host that has sent mail or is a consented prover host and only once its member has enabled mail there (§14.5; SMTP-M9-09), for each pinned set, each family in `KeySettings.FamilyOrder` (aes128gcm, then chacha20), each of the family's shapes:

```text
 1  keyset.json: fetched to keys/<id>/, at most ManifestMaxByteCount, kept only if its SHA-256 is the pin
 2  compile the shape from this build; d = SHA-256 of its R1CS. d != smtpShapeDigests' entry, or != the set's
    circuit_sha256 -> the shape is refused for this set: it is not this build's circuit
 3  cache/<d>-<proving_key.sha256>.ok exists, names d and that key hash, and the .pk and .r1cs files beside it
    hash to what it records -> the shape is ready
 4  phase 1 for the domain: cache/phase1-<h>.commons with its .ok, h the SHA-256 over the beacon and the
    contributions' hashes -> use it. Else fetch each contribution (its byte_count bounds the read, its sha256
    is checked as it streams, gnark's compressed form is checked before gnark reads it), VerifyPhase1, and
    write the commons and its .ok
 5  fetch the shape's phase 2 contributions the same way; VerifyPhase2(r1cs, commons, beacon, contributions)
 6  the proving key's and the verifying key's WriteTo encodings hash to the entry's -> else the shape is refused
 7  write the proving key in gnark's dump form and the R1CS to cache as <name>.partial.<random>, sync, rename;
    then the .ok, the same way, last
 8  delete the fetched contributions unless KeySettings.KeepTranscripts
load, at a send:  step 3's test and nothing less, with d read from smtpShapeDigests: the .ok for this build's
                  digest and the pinned key hash, and both files hashing to it. Nothing is compiled. Anything
                  else is "no keys", and the shape is checked again at idle
```

The cache entry is named by the circuit's digest as well as the key's hash, and a build takes only its own circuit's entry. That closes DESIGN-DETAILS 3.1 E, where draft 2's cache was named by the key's hash alone and a build of another circuit could prove under a key checked against the first, which would give up zero knowledge for that part; `ProofKeys.tla`'s `ProofKeysWritten-StaleCache` is that install, and `TestCacheEntryOfAnotherCircuitIsNoKey` its twin in code. A torn write leaves `.partial` files and no `.ok`, which is no entry.

- **A family is ready** in a set when every shape of it is: for chacha20, its key, env, msg, hdr and body shapes; for aes128gcm the same with 1.3's key shape, and TLS 1.2 is offered once the 1.2 key shape is ready too. The TLS client offers only ready families' suites (4.1).
- **Which set a connection uses.** `Prover.KeySet()` is the newest pinned set with a ready family, or none, and then the host only queues (D-SMTP-18). The sender names it in the preamble; on KEYS it tries the next older pinned set with a ready family once, and otherwise holds the message as `deferred` for `SmtpSenderSettings.KeysRetryTimeout` (6 h).
- **The fetch** is a plain HTTPS GET with `Range` to resume, with no cookie, token, account or identifying header and a generic client name, one file at a time, following no redirect, retried from `KeySettings.FetchRetryInterval` (5 min) doubling to `FetchRetryMaxInterval` (6 h). Every byte is checked against a hash that chains to the release's pin before it is parsed.
- **Rotation.** A key set is replaced when a circuit changes (the new release pins the new set alone), when the catalog grows (`-extend`: the new release pins the new id first and the old second), or when the ceremony host is suspected exposed, and never on a schedule or with each release (owner decision 435). The edge lists the new set before the release that pins it ships, and gives the old one a `not_after` once that release is out. Who runs the production ceremony, and on which host, is the owner's.

### 10.4 Shapes

A circuit is fixed, so a part proves under a shape: pools of keystream blocks of each kind, sized ahead, that the part's records must fit (DESIGN-DETAILS 3.2.6). `ProofSettings.Shapes` lists this build's 11, each one 2^20 domain, a unit, in two families: AES-128-GCM's, which serves TLS 1.3's AES-128-GCM and both TLS 1.2 suites, and ChaCha20-Poly1305's. Only the key part's shape differs by version; every other circuit takes the version's differences, the type octet, the explicit nonce and the lengths, as public wires the edge assigns. A part's kind follows from the roles of the records it opens, which follow from their positions alone (`partKindOf`, `recordRoleAt`), and it takes the first shape of its kind and family whose pools hold its records (`partShapeFor`). One that fits none is refused on both sides: the prover cannot prove it, so nothing it would open is forwarded, and the edge refuses it unverified (DESIGN-DETAILS 3.2.5 step 12).

Every record starts a fresh keystream block, so a pool counts records as well as octets. A record of c content octets takes ⌈(c + 1) / 16⌉ blocks under 1.3's AES-128-GCM, its type octet included, ⌈(c + 1) / 64⌉ under ChaCha20, and ⌈c / 16⌉ under 1.2. Unused blocks cost as much as used ones.

Each shape's data pools are the largest counts that keep its compiled constraints and public inputs at or under 2^20 less 10,486 (`DomainHeadroomCount`, 1%), in the order the table lists them; a client pool that holds only BDAT's command, QUIT and the end mark keeps DESIGN-DETAILS 3.2.6's count. `TestProductionShapesFillOneDomain` compiles each, holds it to that bound and, but for the key shapes, to 90% of it, and holds every public input to a constraint. Compiled with gnark v0.15.0:

| KeySet name | Pools, in blocks | Constraints | Public inputs | Of 2^20 | Holds (TLS 1.3; 1.2 holds one octet more a record) |
|---|---|---|---|---|---|
| `key-v0304-aes128gcm-c8` | client 8 | 809,966 | 1,163 | 77.4% | an EHLO record of up to 127 octets, Z1 and C |
| `key-v0304-chacha20-c2` | client 2 | 758,011 | 1,157 | 72.4% | the same |
| `key-v0303-aes128gcm-c8` | client 8 | 769,679 | 2,467 | 73.6% | the same, under either TLS 1.2 suite |
| `env-aes128gcm-s40-c40` | server 40, client 40 with locals | 1,028,511 | 5,888 | 98.6% | MAIL and 12 RCPT of up to 47 octets; a reply record of 639 octets, or 40 of up to 15 |
| `msg-aes128gcm-s17-c4-h52` | server 17, client 4, head 52 | 1,026,444 | 6,929 | 98.6% | BDAT's command and QUIT; a first header record of 831 octets; replies in a record of 271 octets, or 17 of up to 15 |
| `hdr-aes128gcm-c2-r76` | client 2, rest 76 | 1,030,860 | 6,262 | 98.9% | a later header record of 1,215 octets; QUIT |
| `body-aes128gcm-c2-b81` | client 2, body 81 | 1,022,521 | 6,666 | 98.2% | a body record of 1,295 octets; the end mark and QUIT |
| `env-chacha20-s19-c20` | server 19, client 20 with locals | 1,022,120 | 11,266 | 98.6% | 20 commands of up to 63 octets; a reply record of 1,215 octets, or 19 of up to 63 |
| `msg-chacha20-s13-c2-h19` | server 13, client 2, head 19 | 1,021,207 | 11,798 | 98.5% | BDAT's command and QUIT; a first header record of 1,215 octets; replies in a record of 831 octets, or 13 of up to 63 |
| `hdr-chacha20-c1-r35` | client 1, rest 35 | 999,488 | 11,436 | 96.4% | a later header record of 2,239 octets; QUIT |
| `body-chacha20-c2-b40` | client 2, body 40 | 1,015,011 | 13,233 | 98.1% | a body record of 2,559 octets; the end mark and QUIT |

`TestSpecMdNamesEveryProductionShape` holds this table to the catalog, and the table counts this build's 11. A KeySet name spells kind, version for a key shape, family and every pool, so a changed pool is another name and another key.

Against DESIGN-DETAILS 3.2.6's table, built from compiled gadgets and estimates before these circuits existed, the compiled circuits moved three pools by a block: each msg shape holds one more server block, and AES's hdr shape one more rest block, 16 more header octets a record. Two of the planner's unit counts move by it, and no figure of 3.4 by more than a unit (11.4). Each shape was set up and proven under real Groth16 on 2026-11-19 (11.4).

There is no recipient class and no size class: a send takes more parts as it grows (4.3), up to `RecipientMaxCount` (100) recipients and a 16,384-octet header block, and no client record can outgrow a pool, the longest RCPT being 332 octets, 21 AES blocks or 6 of ChaCha20's. What no shape holds, each failing closed as above:

- **A reply record past the env shape's server blocks**, 639 octets under AES or 1,215 under ChaCha20. After MAIL it ends the connection before any message record with `EnvelopeRetry`, which the sender retries once a command a group; an EHLO reply that large, or in more records than the env shape's server blocks, ends the send before MAIL (DESIGN-DETAILS 3.5).
- **A header block past 16,384 octets** (`HeaderBlockMaxByteCount`), which assembly refuses; and a header block whose single fields and fixed signature do not lie in its first record, which Z5 refuses (DESIGN-DETAILS 3.2.3) and which the sender's order never writes (reading 30).

## 11. Costs

### 11.1 Gates

D-SMTP-16, at p95, as DESIGN.md §14.5 now states it in units (owner decision 433, which took the m5.large's rows from QD-144's rule for a confirmed miss). BDAT, for a 4 KiB header block and 10 recipients, six units under AES-128-GCM and five under ChaCha20: ≤ 10 s for the key part and ≤ 30 s for the send on an Apple M1 MacBook Air (8 GB); on an AWS m5.large, the time SMTP-M9-32's bench measures there, about 150 s by projection. DATA, for a 100 KiB message: ≤ 10 min on the M1; on the m5.large ≤ 20 min under ChaCha20 and the measured time under AES-128-GCM, about 35 min by projection. No relation over these circuits proves the gate's send on an m5.large in 60 s: the AES keystream for a 4 KiB header block alone is 2.99M constraints, 73 s at 41,000 a second. The targets are settings with these defaults. Draft 2's bar was ≤ 10 s for π1 and ≤ 30 s for π1 to π3 on the M1, ≤ 60 s on the m5.large.

### 11.2 Gadget sizes

Measured from the code with gnark v0.15.0, and held to these figures by `TestGadgetSizesAreSpecMds`, which fails on any change to a gadget until this table follows it. A gadget is measured alone, less the constraints its test harness adds, one for each boolean it asserts on an input or output bit and one for each output bit it compares. Z1 is measured as a part spends it: a shape against its twin that takes the keys as private bits, those bits' booleans added back. The first draft's estimates are kept beside them.

| Gadget | Constraints | Unit | First estimate |
|---|---|---|---|
| SHA-256 compression, private state and block | 26,480 | one compression | 26,482, scratch prototype |
| HMAC-SHA-256 pad states, private 32-octet key | 51,208 | once per key | |
| HMAC-SHA-256 sum, up to 55 private octets | 51,770 | per sum, after the pad states | |
| HKDF-Expand-Label to 32 octets, 32-octet context | 51,789 | per label, after the pad states | |
| TLS 1.2 PRF, 40-octet key block | 337,761 | pad states included | |
| AES-128 key schedule, private key | 3,136 | once per key | |
| AES-128 block | 11,504 | 16 octets | |
| ChaCha20 block, private key and nonce | 21,664 | 64 octets | |
| AES-128-GCM keystream, Z2's nonce included | 11,665 | per 16 octets, about 729 an octet, plus the schedule once per key | about 11,600, 725 an octet |
| ChaCha20 keystream, Z2's nonce included | 21,825 | per 64 octets, about 341 an octet | about 22,000, 340 an octet |
| Z1, TLS 1.3, both directions (29 compressions) | 708,498 | once a connection, in the key part, either suite | about 768,000 |
| Z1, TLS 1.2 (25 compressions, SF's AES block and its schedule) | 669,147 | once a connection, in the key part | about 675,000 |
| Z1's commitment, AES-128-GCM's keys and IVs (448 bits) and a blind | 3,026 | per part, booleans included | 3,261, DESIGN-DETAILS 3.2.2's prototype |
| Z1's commitment, ChaCha20's keys and IVs (704 bits) and a blind | 4,133 | per part, booleans included | 4,453, the same |
| A scan's carry (24 bits) and a blind | 1,186 | per carry, booleans included | 1,279, the same |
| Z2-Z4, a pool block with the local table (an env part's commands) | 12,545 under AES, 25,345 under ChaCha20 | per block, about 55 an octet beyond the keystream | |
| Z2-Z4, a pool block of literals only (the key part's EHLO, and a msg part's commands) | 11,969 under AES, 23,041 under ChaCha20 | per block, about 19 an octet beyond the keystream | |
| Z5, the header block's first record with its keystream | 57,264 under AES, 32,429 under ChaCha20 | per 64 header octets, about 166 an octet beyond the keystream | well under AES's 725 an octet |
| Z5, a later header record with its keystream | 52,513 under AES, 27,678 under ChaCha20 | per 64 header octets, about 91 an octet beyond the keystream | 90, DESIGN-DETAILS 3.2.4's prototype |
| Z7-Z9, a part's server records with their keystream | 51,758 under AES, 26,908 under ChaCha20 | per 64 octets, about 80 an octet beyond the keystream, Z9's window and the public flags' rules included | |

Some readings of these:

- A key's length does not move Z1: AES's 16-octet key and ChaCha20's 32-octet key each come from one HMAC, so both suites' Z1 cost the same.
- A compression over the constant initial state, as each HMAC pad state is, costs a little less than one over a private state, since gnark folds the constant terms.
- Z1 is proven once a connection, in the key part, which derives both directions and publishes a perfectly hiding commitment C to their keys and IVs; every later part opens C instead (DESIGN-DETAILS 3.2.3; QD-712). Where each part re-proved Z1, a BDAT send spent 515,322 + 2 × 708,498 = 1,932,318 constraints on it under 1.3; it now spends 708,498 once and an opening a part. The commitment's gadget adds a window's point by the complete law in six constraints, where DESIGN-DETAILS 3.2.2's prototype took seven.
- H_sh and H_sf enter HMAC messages, and gnark's `Xor` asserts its inputs boolean, so 512 constraints of 1.3's Z1 are booleans on public wires the verifier computes. Marking those wires boolean without a constraint would save them; it is not done.
- The 1.2 figure adds back what the twin's private IV costs over the real one: a 1.2 IV is the salt and 8 zero octets, so the real shape's nonce takes the explicit nonce without a XOR, 64 constraints a pool block.
- The pool, header and server rows are each two test shapes a few blocks apart, Z1 left out, so a row is whole blocks: keystream, opening and what the octets are checked against. `TestRecordPoolCostIsSpecMds`, `TestHeaderScanCostIsSpecMds` and `TestReplyScanCostIsSpecMds` hold them. They are 1.3's, and a later part's circuit is the same under 1.2: its IV is a private opening of C in both versions, so the 64 constraints a block that draft 2's 1.2 shapes saved are spent there too, about 5,000 a unit (DESIGN-DETAILS 3.2.3). Only 1.2's key shape, whose IVs' last 8 octets are constants, saves them.
- Z5's automaton costs about 166 constraints an octet beyond the keystream in the header block's first record, a quarter of AES's 729, and about 91 in a later record, which reads no literal, runs no From positions and needs no local-part table. Counting the one-click field by name (reading 25) added 6 an octet.
- A recipient costs an env part its RCPT record, 3 AES blocks for an address of up to 35 octets, and its reply, a server block or two in the next part. Each group of 12 or 13 under AES, 18 or 19 under ChaCha20, is one more unit (4.3; 11.4).

### 11.3 The first measurement

A scratch Groth16 run over chained compressions, gnark v0.15.0, Apple M4 Pro (14 cores), on a machine shared with other builds, so noisy:

| Constraints | Cores | Prove | Constraints/s |
|---|---|---|---|
| 4,237,153 | 14 | 8.5 s | 500,000 |
| 4,237,153 | 8 | 8.2 s | 519,000 |
| 4,237,153 | 4 | 9.6 s | 443,000 |
| 4,237,153 | 2 | 17.4 s | 243,000 |

Verification took 2.4 ms. Setup took 2 min 37 s. Peak memory was 10.5 GB, with compile and setup in the same process, so it overstates proving alone.

Draft 1 drew its budgets from this run and from ORIGO's own m5.large figure, 400,000 constraints in 9.8 s, before any shape existed. 11.2's gadgets and 11.4's units, measured on the real shapes, replace those estimates. Neither reference machine has been measured yet: that is SMTP-M9-32's bench, and the m5.large's figure stays ORIGO's until it runs there (section 14).

Levers. Taken in draft 3: a hiding commitment to the keys, proven once, so that later parts skip Z1, which draft 2 priced at about 1.4M of a BDAT send's constraints and the owner first kept out (QD-144). DESIGN-DETAILS 3.1 measured what that price left out, the domain: a part's time follows its 2^20-point domain at least as much as its constraint count, and Z1 pushed every π3 past 2^22. With the commitment every circuit fills one domain (owner decision 433). Not taken: lookups under a reviewed commitment argument (10.1, 10.2), which would at best halve AES; sharing AES's first round across blocks of a record; a designated-verifier prover (Later). See section 14.

### 11.4 Units, measured

`TestMeasureWholeSend` (`SMTPPROOF_MEASURE`) sends `testSpeedGateJob`'s messages through the real prover, the real gate and a `crypto/tls` MX under real Groth16, each shape set up the first time a part needs it by gnark's single-party test setup: D-SMTP-16's BDAT case, a header block of 3,998 octets in SMTP-M9-04's order to 10 recipients, then the same header block in DATA mode with a 6,100-octet body. It ran on 2026-11-19, on every leg, on the shared M4 Pro of 11.3 (14 cores, 64 GiB) at load averages of 40 to 50 from other builds, so wall times are noisy and CPU time is the steadier figure. Peak memory is that of a separate process that reads one shape's compiled circuit and its compressed proving key and proves once (`TestMeasureProveOnly`), as a prover host's first proof does, except that a host reads the dump its cache holds (10.3).

Each production shape, a unit (the AES-128-GCM family's env, msg, hdr and body rows from the TLS 1.3 leg; the TLS 1.2 leg proved under the same compiled circuits within 0.4 s of CPU and 75 MiB of these):

| Shape | Constraints | Public inputs | Proving key | Prove, CPU | Prove, wall | Peak memory |
|---|---|---|---|---|---|---|
| `key-v0304-aes128gcm-c8` | 809,966 | 1,163 | 97 MiB | 5.4 s | 1.2 s | 973 MiB |
| `key-v0304-chacha20-c2` | 758,011 | 1,157 | 93 MiB | 5.6 s | 0.9 s | 1,053 MiB |
| `key-v0303-aes128gcm-c8` | 769,679 | 2,467 | 96 MiB | 5.7 s | 1.6 s | 877 MiB |
| `env-aes128gcm-s40-c40` | 1,028,511 | 5,888 | 133 MiB | 5.8 s | 2.6 s | 1,344 MiB |
| `msg-aes128gcm-s17-c4-h52` | 1,026,444 | 6,929 | 133 MiB | 6.4 s | 1.7 s | 1,379 MiB |
| `hdr-aes128gcm-c2-r76` | 1,030,860 | 6,262 | 133 MiB | 6.2 s | 1.1 s | 1,281 MiB |
| `body-aes128gcm-c2-b81` | 1,022,521 | 6,666 | 132 MiB | 6.1 s | 2.2 s | 1,399 MiB |
| `env-chacha20-s19-c20` | 1,022,120 | 11,266 | 142 MiB | 6.4 s | 1.5 s | 1,427 MiB |
| `msg-chacha20-s13-c2-h19` | 1,021,207 | 11,798 | 141 MiB | 6.9 s | 1.8 s | 1,367 MiB |
| `hdr-chacha20-c1-r35` | 999,488 | 11,436 | 139 MiB | 6.9 s | 5.0 s | 1,385 MiB |
| `body-chacha20-c2-b40` | 1,015,011 | 13,233 | 141 MiB | 6.8 s | 1.2 s | 1,493 MiB |

Public inputs count gnark's constant wire, as 10.4's do. Over all 47 proofs of the run, a unit took 5.5 to 7.1 CPU-seconds, 6.2 at the median, whatever its shape. Verification took 1 to 7 ms for most parts, and 10 to 44 ms for eight of the 47 at this load. The single-party test setup took 26 s to 1 min 34 s a shape; the two-phase ceremony and a host's check of it are slower, and were not run at this size (section 12).

Whole sends, every part proved, submitted and accepted by the gate, against draft 2's catalog on the same message (11.5):

| Leg | Mode | Units | Proving, CPU | Proving, wall | Draft 2's catalog, CPU |
|---|---|---|---|---|---|
| TLS 1.3, ChaCha20 | BDAT | 5 | 32.7 s | 7.8 s | 42.4 s, 3 parts |
| TLS 1.3, AES-128-GCM | BDAT | 6 | 36.9 s | 7.0 s | 63.9 s, 3 parts |
| TLS 1.2, AES-128-GCM | BDAT | 6 | 36.5 s | 8.4 s | 61.9 s, 3 parts |
| TLS 1.3, ChaCha20 | DATA, a 6,100-octet body | 8 | 52.0 s | 9.7 s | 75.1 s, 6 parts |
| TLS 1.3, AES-128-GCM | DATA, the same | 11 | 67.5 s | 11.3 s | 131.4 s, 6 parts |
| TLS 1.2, AES-128-GCM | DATA, the same | 11 | 64.8 s | 16.3 s | 117.0 s, 6 parts |

What this says, neither reference machine having been measured:

- Every unit costs about the same, about 6.2 CPU-seconds here, and a key part filling 72 to 77% of its domain costs nearly a full unit's. On this machine a part's time follows its domain at least as much as its constraint count, which is DESIGN-DETAILS 3.1's open point, and the reading 3.4's projections by domain rest on.
- So a send's CPU is its units times about 6.2 s here. The gate's BDAT send took 32.7 s of CPU under ChaCha20 and 36.5 to 36.9 s under AES-128-GCM, where draft 2's catalog took 42.4 s and 61.9 to 63.9 s: 23% and 41% less. On 14 cores its proving took 7 to 8 s of wall time.
- Projections, which this run does not test: at DESIGN-DETAILS 3.4's 2.5 to 3.5 s a unit on the M1, the key part takes 2.5 to 3.5 s against its 10 s and the gate's send 15 to 21 s under AES-128-GCM and 13 to 18 s under ChaCha20 against its 30 s; at 19.6 s a unit by domain on an m5.large, about 20 s and 98 s under ChaCha20 or 118 s under AES-128-GCM, and about 150 s by the count, which is why 11.1's m5.large rows are SMTP-M9-32's bench's to set.
- DATA's 100 KiB with the gate's header block is 82 units under AES-128-GCM and 44 under ChaCha20 (below), so about 8.5 and 4.5 minutes of CPU here.
- A unit's proof needed 877 to 1,493 MiB of resident memory in a process of its own, against draft 2's 1.7 to 7.0 GB for a π3, and under `ProverSettings.MemoryMaxByteCount`'s 2,496 MiB, 2,240 MiB before QD-1115. How that budget's charges hold is `BenchmarkPartMemory`'s, below.

**What a send costs, in units.** The planner's counts, which `TestThePlannersUnitsFollowTheSend` and `TestThePlannersUnitsFollowADataSend` hold on every leg through the real gate, with each reply a record of its own of up to 15 octets, the worst packing for a pool that counts records, and RCPT records of 47 octets:

```text
units = 1                                       the key part
      + E                                       envelope groups: AES 12 RCPT with MAIL, then 13 a group; ChaCha20 18, then 19
      + X                                       0, or 1 when the last group's replies overflow the msg shape's server blocks
      + 1                                       the msg part
      + ceil(max(0, L - head) / rest)           header parts: head 831, rest 1,215 (AES, 1.3); head 1,215, rest 2,239 (ChaCha20)
      + DATA only: max(1, ceil(body / record))  body records of 1,295 (AES, 1.3) or 2,559 (ChaCha20) octets

recipients, header block                  TLS 1.3 AES-128-GCM   TLS 1.3 ChaCha20   TLS 1.2 AES-128-GCM
  1 to 12, 831 octets                              3                    3                    3
  1 to 12, 832 octets                              4                    3                    3
  10, 4,095 octets (the gate)                      6                    5                    6
  13, 4,095 octets                                 7                    6                    7
  50, 4,095 octets                                 9                    7                    9
  100, 831 octets                                 10                    8                   10
  100, 4,095 octets                               13                   10                   13
  100, 16,383 octets (the longest)                23                   15                   23
  DATA, 10 recipients, 100 KiB in all             82                   44                   82
```

TLS 1.2 holds one octet more a record, which is why its 832-octet header block takes one record. Against DESIGN-DETAILS 3.2.6's table two rows move, both from the compiled msg-chacha20 shape holding one server block more than that table's: 12 recipients under ChaCha20 fit three units, and 50 recipients' last group of 13 replies fits the msg part.

**Memory** (DESIGN-DETAILS 3.2.8; `prover_load.go`). The prover keeps to a budget by counting: a loaded shape is charged `ShapeMemoryByteCount` (768 MiB), a proof in flight `PartMemoryByteCount` (960 MiB), and loaded shapes and proofs stay at or under `MemoryMaxByteCount` (2,496 MiB, two loaded shapes and one proof, the defaults' relation `TestTheDefaultBudgetHoldsTwoShapesAndOneProof` holds); over it, the least recently used shape no proof uses is unloaded, and else the proof waits. A proof takes one of `ProveConcurrency` slots (1), runs a collection after it, and returns its charge; a shape unused for `ShapeIdleTimeout` (2 min) is unloaded, and when the last goes the heap is returned to the system. The tests `TestTheLoaderNeverChargesPastTheBudget`, `TestTheLoaderNeverUnloadsAShapeInUse`, `TestTheLoaderUnloadsAnIdleShapeAndThenReturnsTheHeap` and `TestACancelledProofReturnsItsCharge` hold the rule on a fake loader charging the defaults' figures in MiB.

`BenchmarkPartMemory` sets one body unit of a family up, then in a fresh process loads its compiled circuit and its key's dump as a host's cache holds them and proves three times back to back under the loader, a collection after each, reading the peak resident memory after the load and after the proofs. It ran on 2026-11-19 on the same machine:

| Family | Cores | The loaded shape | A proof over it |
|---|---|---|---|
| AES-128-GCM | 14 | 684 MiB | 666 MiB |
| AES-128-GCM | 8 | 683 MiB | 621 MiB |
| ChaCha20 | 14 | 546 MiB | 853 to 935 MiB over three runs |
| ChaCha20 | 8 | | 834 MiB |

AES-128-GCM's unit was within both charges. ChaCha20's proof was past the 704 MiB `PartMemoryByteCount` then held by 130 MiB at 8 cores and 149 to 231 MiB at 14, and its shape under `ShapeMemoryByteCount` by 222 MiB, so the benchmark failed on that family, which DESIGN-DETAILS 3.2.8 says is the sign to raise the default. Two loaded shapes and one proof, the default budget's case, still fit 2,240 MiB in both families, at about 2,000 MiB under ChaCha20 and 2,034 under AES-128-GCM; one shape and two proofs, which a host that raises `ProveConcurrency` was charged 2,176 MiB for, would take about 2,350 MiB under ChaCha20. The owner answered the question this raised, `smtp-m9-33-part-memory-default` (QD-1115): `PartMemoryByteCount` rose to 960 MiB, the largest proof measured rounded up, and `MemoryMaxByteCount` to 2,496 MiB, two loaded shapes at 768 MiB and one proof, `ShapeMemoryByteCount` staying 768 MiB, and `prover.go` holds them, so one shape and two proofs are charged 2,688 MiB. On those defaults the benchmark passed in both families, run once each the same evening on the same machine at 14 cores and load averages of 25 to 71: AES-128-GCM's loaded shape took 683 MiB and a proof over it 601 MiB, ChaCha20's 567 MiB and 888 MiB. DESIGN.md §5.4 says 2,240 MiB until design-records takes the new figure.

### 11.5 The retired catalog, measured

These measurements are of the retired catalog of 22 shapes over four domain sizes, π1 to π3 with Z1 in each, before the key commitment and unit shapes (DESIGN-DETAILS 3.2), made on 2026-11-08. They stand as that catalog's record and as the figures DESIGN-DETAILS 3.1, 3.4 and 11.4 compare against.

`TestMeasureWholeSend` sends `testSpeedGateJob`'s messages through the real prover, gate and a `crypto/tls` MX under real Groth16 and a single-party test setup. The header block is 3,979 octets, with 10 recipients. The machine is the shared M4 Pro of 11.3, with 14 cores and 64 GiB. Wall time depends on what else it runs, so CPU time is the steadier figure. Peak memory comes from a separate process that loads one key and proves, as a prover host would.

At load averages of 130 to 200, TLS 1.3 with AES-128-GCM, BDAT:

| Part | Constraints | Public inputs | Proving key | Prove, CPU | Prove, wall | Peak memory |
|---|---|---|---|---|---|---|
| π1 | 566,337 | 1,033 | 77 MiB | 5.3 s | 11.9 s | 788 MiB |
| π2 | 1,623,068 | 5,861 | 209 MiB | 11.6 s | 34.8 s | 1,138 MiB |
| π3 | 4,763,816 | 28,950 | 713 MiB | 47.0 s | 84.7 s | 1,715 MiB |
| Whole send | 6,953,221 | | 999 MiB | 63.9 s | 131.4 s | |

The same header block in DATA mode, with a 6,100-octet body: π3 holds the first 2 KiB of body at 6,324,518 constraints and an 866 MiB key, 53.6 s CPU. Each later part is 2,103,101 constraints with a 323 MiB key, about 20.4 s CPU and 1,778 MiB peak. The whole send, π1 to π6, took 131.4 s CPU. Verification took 2 to 443 ms a part. Setup took 1.5 to 46 minutes a shape at that load.

At load averages of 25 to 37, BDAT on the other two legs, with ChaCha20's shapes as they now are (below):

| Leg | Part | Constraints | Proving key | Prove, CPU | Prove, wall | Peak memory |
|---|---|---|---|---|---|---|
| TLS 1.3, ChaCha20 | π1 | 538,366 | 75 MiB | 5.0 s | 2.5 s | 844 MiB |
| | π2 | 1,326,925 | 186 MiB | 11.7 s | 3.5 s | 1,707 MiB |
| | π3 | 3,175,995 | 450 MiB | 25.7 s | 9.4 s | 3,271 MiB |
| | Whole send | 5,041,286 | 711 MiB | 42.4 s | 15.4 s | |
| TLS 1.2, AES-128-GCM | π1 | 719,906 | 91 MiB | 5.7 s | 1.2 s | 956 MiB |
| | π2 | 1,579,133 | 207 MiB | 11.7 s | 4.2 s | 2,122 MiB |
| | π3 | 4,706,313 | 710 MiB | 44.5 s | 8.5 s | 6,260 MiB |
| | Whole send | 7,005,352 | 1,008 MiB | 61.9 s | 13.9 s | |

Setup there took 24 s to 4 min 24 s a shape.

At load averages of 22 to 35, beside a real-size ceremony in another process, DATA on those two legs, with the same header block and a 6,100-octet body:

| Leg | Part | Constraints | Proving key | Prove, CPU | Prove, wall | Peak memory |
|---|---|---|---|---|---|---|
| TLS 1.3, ChaCha20 | π1 | 538,366 | 75 MiB | 5.0 s | 1.4 s | 723 MiB |
| | π2 | 1,326,925 | 186 MiB | 11.3 s | 3.6 s | 1,717 MiB |
| | π3 | 3,941,977 | 532 MiB | 24.5 s | 3.3 s | 3,890 MiB |
| | Each later part | 1,327,389 | 192 MiB | 11.3 to 11.7 s | 2.2 to 3.4 s | 1,762 MiB |
| | π1 to π6 | | | 75.1 s | 16.8 s | |
| TLS 1.2, AES-128-GCM | π1 | 719,906 | 91 MiB | 5.4 s | 4.1 s | 934 MiB |
| | π2 | 1,579,133 | 207 MiB | 9.9 s | 1.3 s | 2,126 MiB |
| | π3 | 6,258,823 | 862 MiB | 44.7 s | 6.1 s | 7,019 MiB |
| | Each later part | 2,248,606 | 336 MiB | 18.5 to 19.8 s | 2.4 to 2.5 s | 3,199 MiB |
| | π1 to π6 | | | 117.0 s | 18.7 s | |

Setup took 25 s to 3 min 5 s a shape. These runs used the later-part shapes without server blocks. The 1.3 shapes over a late ticket (section 12) compile, with no commitment, to 2,501,943 constraints under AES and 1,623,719 under ChaCha20, about a fifth more than their plain twins; none has been proven or timed, since no MX here sends a ticket.

Every production shape compiles, and none carries a commitment (`TestMeasureShapes`). ChaCha20's envelope and message shapes hold 12 server blocks, not the first draft's 6: a record starts a fresh keystream block, and 6 could not hold D-SMTP-16's 11 one-line replies, so the first ChaCha20 run failed at π3. The change costs about 158,000 constraints a shape. Body octets cost about 762 constraints each under AES and 374 under ChaCha20, by subtracting shapes. These counts predate reading 25, which adds about 25,000 constraints to each π3 shape, 6 an octet over its 4 KiB header block, and reading 29, which drops the 16 or 64 `IsLocal` inputs of every block that cannot hold a local part and adds a constraint or two a shape: π1's AES shape, for one, has 968 public inputs now, 969 counting gnark's constant wire as the column above does, not 1,033, and AES's BDAT π3 24,789, not 28,950. The tables above were not measured again. Every production shape was compiled again on 2026-11-08, after both readings, on the same shared M4 Pro (`TestMeasureShapes`, 260 s for all 22, none carrying a commitment); public inputs here count gnark's constant wire, as above, and `testdata/vectors/statements.json` gives them without it:

| Shape | TLS and suite | Constraints | Public inputs |
|---|---|---|---|
| π1 | 1.3 AES-128-GCM | 566,338 | 969 |
| π1 | 1.3 ChaCha20 | 538,367 | 966 |
| π2 | 1.3 AES-128-GCM | 1,623,070 | 5,861 |
| π2 | 1.3 ChaCha20 | 1,326,927 | 7,721 |
| π3, BDAT | 1.3 AES-128-GCM | 4,788,371 | 24,790 |
| π3, BDAT | 1.3 ChaCha20 | 3,200,550 | 26,684 |
| π3, DATA | 1.3 AES-128-GCM | 6,349,074 | 37,206 |
| π3, DATA | 1.3 ChaCha20 | 3,966,533 | 39,004 |
| later DATA part | 1.3 AES-128-GCM | 2,103,103 | 13,287 |
| later DATA part | 1.3 ChaCha20 | 1,327,391 | 13,479 |
| later DATA part over a ticket | 1.3 AES-128-GCM | 2,501,946 | 14,599 |
| later DATA part over a ticket | 1.3 ChaCha20 | 1,623,722 | 14,767 |
| π1 | 1.2 ECDHE-RSA | 719,906 | 2,272 |
| π1 | 1.2 ECDHE-ECDSA | 719,906 | 2,272 |
| π2 | 1.2 ECDHE-RSA | 1,579,134 | 7,164 |
| π2 | 1.2 ECDHE-ECDSA | 1,579,134 | 7,164 |
| π3, BDAT | 1.2 ECDHE-RSA | 4,730,867 | 26,093 |
| π3, BDAT | 1.2 ECDHE-ECDSA | 4,730,867 | 26,093 |
| π3, DATA | 1.2 ECDHE-RSA | 6,283,378 | 38,509 |
| π3, DATA | 1.2 ECDHE-ECDSA | 6,283,378 | 38,509 |
| later DATA part | 1.2 ECDHE-RSA | 2,248,607 | 14,590 |
| later DATA part | 1.2 ECDHE-ECDSA | 2,248,607 | 14,590 |

Each is within three constraints of the figure above for the same shape, reading 25's 24,555 on every π3 aside, so the times above stand as the best measure of these shapes there is until SMTP-M9-32's bench runs on the reference machines. `BenchmarkPi3Memory` ran once on the new ChaCha20 BDAT π3, at a load average of about 25: the process that only loads the key and proves took 22.3 s and peaked at 3,608 MiB, beside 3,271 MiB on lightly loaded cores above.

What they showed, and what DESIGN-DETAILS 3.1 drew from them: Z1 proven three times a send, 1.9M of a BDAT send's 7.0M constraints; every π3 pushed past 2^22 by it, so that one paid for 8.4M points of domain to prove 4.8M constraints; and peaks that grew with the cores a prover had, TLS 1.2's DATA π3 at 7.0 GB on lightly loaded cores, within 1 GB of the M1's 8 GB. Owner decision 433 answered all three with the key commitment and the unit shapes (11.4), and QD-144's rule for a confirmed miss on the m5.large stands in 11.1.

## 12. State of the code

Kept honest as the module grows. Anything not listed as built fails closed.

| Piece | State |
|---|---|
| `tls_*.go`: the TLS client, 1.3 and 1.2, HelloRetryRequest, CertificateRequest | Built. Checked against Go's `crypto/tls` server, whose key log confirms HS and the master secret regenerate its own secrets; against RFC 8448's trace through HS, MS, SHTS, CHTS, the handshake keys, the server application key and IV and the resumption secret; against NIST ACVP's TLS 1.3 KDF vector, which gives both application traffic secrets from MS; and against the TLS 1.2 PRF's published vector. RFC 8448's application traffic secrets are not derived from its MS: that needs its hash through the server's Finished, and no copy of the RFC was at hand. `FuzzTlsParse` runs the four parsers over one stream split at every offset, from a committed corpus of real flights, and compares each ClientHello with `crypto/tls`'s server's reading and each ServerHello with how `crypto/tls`'s client answers it: no ServerHello the parser takes is one `crypto/tls` cannot decode, reads at an unsupported version, or refuses for a 1.2 suite E1 covers |
| `relation.go`: Z1-Z9 over plain Go values | Built, both versions and modes, over parts bound to one key part (SMTP-M9-36, -37): Z1 in its two steps, Z4 by roles from positions, Z5 and Z6 record by record from the carries, Z8 part by part from its count and flags. Each check has mutated witnesses that it alone refuses. The record-by-record scans are held to one pass over the concatenation (`checkHeaderBlock`, `checkDataLines`): the sender's corpus cut at every length from 128 octets up, a single field's name and the fixed prefix cut at each of their octets across the first boundary and a later one, CR and LF either side of a boundary, a final CRLF CRLF cut at each of its four octets, and DATA's "." line cut after LF, after "." and after CR (`circuit_scan_test.go`) |
| `commit.go`, `circuit_commit.go`: C and the carries | Built (SMTP-M9-36). `TestCommitCurveIsComplete`; `TestCommitGeneratorsAreFixed` against `commit.json`'s literals, each of order l, none the identity; `TestCommitGadgetMatchesGnarkCrypto` over 448, 704 and 24 message bits and random blinds, one bit off refused in the message and in the blind; `TestCommitBlindsAreFresh`; `TestKeyPartBindsBothDirections`, a key part whose C holds another server key unsatisfiable; `TestLaterPartOpensTheKeyPartsCommitment`, every later shape with one key bit off or another blind unsatisfiable. The opening and carry sizes are 11.2's |
| `mutate_*_test.go`, `testdata/mutations/table.md`: §22.10's mutated witnesses | Built (SMTP-M9-29), on parts bound to one key part, with DESIGN-DETAILS 3.6's five cells (section 8). For each of E1-E3 and Z1-Z9, on every leg and in each mode the check applies to, a break of one honest connection that the gate's relation and the checker each pin on that check alone, refused by the circuit at its part (the key part's on its production shape, with Z1's derivation) or by the gate on its own; the table is held to the registry and lists the cells no witness can break alone. Holding the two readers to one table found two disagreements, now settled (readings 26 and 28) |
| `edge.go`: E1-E3 | Built (SMTP-M9-38), as one state machine per connection that ends at its first refusal: E1 and E2 as draft 2's, E3 as DESIGN-DETAILS 3.2.5's sixteen fences (section 6), with no replaced part, parts that open no client record, and `MailForwarded` at f + 1. A test a fence, in their order (`edge_gate_test.go`); `ProofParts.tla`'s five twins as tests, `TestGateSuppliesTheKeyCommitment`, `TestGateSuppliesTheCarry`, `TestGateCountsRepliesBeforeTheMessage`, `TestGateHoldsMessageRecordsBehindALateRecord` and `TestGateRefusesASecondPartThatVerifiedBesideTheFirst`, run on a blocking verifier, deterministic, rather than the named barriers; `FuzzEdgeRecordOrder` interleaves records, parts, late server records and parts that open none, and holds every message record behind coverage. `TestEdgeInputsEqualServerKeyLog` holds Z1's inputs to the MX's own key log, after a HelloRetryRequest too; every run of the handshake, 1.3's sealed flight included, passes split across two records at every offset with Z1's inputs unchanged; a SHA-1 signature that verifies is refused in both versions; `FuzzEdgeHandshake` edits real handshakes and holds the gate to its bounds |
| `prover.go`, `prover_plan.go`, `prover_load.go`, `prover_measure.go`: a whole connection | Built (SMTP-M9-37, -39): BDAT and DATA, pipelined or paced, the envelope in groups, the header block cut by `headerSplit`, a part that opens no client record over a late server record or replies the part before could not hold, `EnvelopeRetry` where a reply record fits no shape, and the message's parts proven up to `ProveConcurrency` at once and submitted in index order (4.3). It checks its own witness before proving. The planner's unit counts are held through the real gate on every leg for 1 to 100 recipients and header blocks of 831 to 16,383 octets (11.4); `TestEnvelopeGroupsAreAFunctionOfPublicValues`. The loader keeps the memory budget by counting (11.4). `Measure` proves one body unit per ready family and prices a send by the slowest (reading 22) |
| `circuit_*.go`: Z1-Z9 in R1CS | Built for the eleven production shapes of 10.4 (SMTP-M9-36, -37). Each gadget is tested against the standard library, and Z2-Z9 differentially against `relation.go`, each case through the relation and the solver alike: the envelope at 1, 10 and 100 recipients and every template break of SMTP-M9-22's list (`circuit_records_test.go`); the sender's own assembled and signed messages as Z5's corpus, and every break of SMTP-M9-23's list in both modes (`circuit_headers_test.go`); H1 to H13 and B1 to B3 across record boundaries (`circuit_scan_test.go`); every break of SMTP-M9-24's list beside an honest twin, `reply_count` one more and one fewer, a part ending inside a reply, `Last354` on a 250, `EhloRule` beside a 220 line and a ticket under `Tls13` 0 among them (`circuit_replies_test.go`). `TestAesShapesServeTls12AndTls13` solves both versions' parts on one compiled env, msg, hdr and body circuit. The header-block breaks also go through the gate and the independent checker beside the circuit (`circuit_agreement_test.go`). 11.2's sizes are held by `TestGadgetSizesAreSpecMds` and the per-block tests it names, 10.4's shapes by `TestProductionShapesFillOneDomain` and `TestSpecMdNamesEveryProductionShape` |
| `backend.go`: Groth16 prove and verify | Built. One real key-part proof, of ChaCha20's key shape, runs in the ordinary tests and fails one bit off in any of its 1,156 public inputs (`TestGroth16RefusesEachPublicInputOneBitOff`); no shape carries a public wire that no constraint reads (`TestEveryPublicWireIsConstrained`, reading 29). Every leg's honest BDAT and DATA connection, one whose header block takes two records and one whose envelope goes a command a group, passes the gate, the checker and each part's circuit through `edgeSession`, the key part's with Z1's derivation (`TestMutatedWitnessHonestTwins`). `TestMeasureWholeSend` proved whole sends that the gate accepted, BDAT and DATA on all three legs, under the eleven unit shapes (11.4). `BenchmarkPartMemory` measures a unit's memory under the loader's rule (11.4); `BenchmarkPi3Memory` is draft 2's and measures that catalog's largest parts |
| BDAT's unopened body (9.7) | A sidecar that pads its body records or puts a KeyUpdate among them, and sends the proven QUIT without waiting, smuggles nothing through a `crypto/tls` MX: past QUIT's 6 octets of padding the chunk never completes; short of them the MX takes a message of the declared length with the proven header block and reads at most 5 octets as a command; a KeyUpdate kills the connection at QUIT's tag (`part_bdat_test.go`) |
| DATA at D-SMTP-16's size | A 100 KiB message, leading dots stuffed, goes through the gate on every leg a body record a part, each fitting a production shape (`TestSendDataOf100KiBInPartsThroughTheGate`), and in 82 units under AES-128-GCM and 44 under ChaCha20 with the gate's header block (`TestThePlannersUnitsFollowADataSend`) |
| FS-31: D-SMTP-16's adversarial corpus | Built (SMTP-M9-30), row by row at T2 through the real prover and gate (`fs31_test.go`): D-SMTP-16's corpus with scripted MXs, DESIGN-DETAILS 3.6's five rows over parts bound to one key part, padded and KeyUpdate BDAT bodies and an edge that forges a reply, each in every cell it applies to and failing before any effect beside honest controls, a 100-recipient send and a 16 KiB header block among them, held to `testdata/fs31/matrix.md`. T3 reruns, in server's `cli/smtpedge`, the rows whose sender acts on the wire |
| `spec_test.go`, `testdata/vectors/`: this document held to the code | Built (SMTP-M9-33). `TestSpecNamesEveryCheck` requires each of E1-E3 and Z1-Z9 to have its definition here, tests of its own and a row in the mutation table, and each of S1 to S7 and K1 to K4 its one statement; `TestSpecHeaderRecordsOutlastEveryLiteral` holds S4's premise; the vectors of 5.1 reproduce on every run and prove under every production shape between them |
| `setup*.go`, `shape_digests.go`, `setup/`: the ceremony, key set 2, the cache and the fetch | Built (SMTP-M9-40) and tested on small circuits and against a local listener: a tampered file, another circuit's transcript, keys the transcript does not fix, a transcript out of gnark's form and a manifest out of shape are each refused; a cache entry of another circuit's digest is no key (`TestCacheEntryOfAnotherCircuitIsNoKey`, DESIGN-DETAILS 3.1 E), nor a partial or changed file; phase 1 is checked once for several shapes; `-extend` leaves every entry byte-equal; `TestShapeDigestsAreThisBuilds`; the fetch takes a whole file of its hash, refuses a short, a long and another file, resumes a cut one and sends nothing that identifies the host; the verifier takes several sets and drops one past its `not_after`. `TestAKeySetProvesARealEhlo` (`SMTPPROOF_FULL`) ran draft 2's path once at 2^20, the ceremony, a host's check and a proof the edge's key accepted taking 56 minutes and about 130 CPU-minutes on the shared M4 Pro; it has not run on key set 2's path. Never run at production size |
| `checker/`: the public relation, written apart | Drafted from this document, DESIGN.md and DESIGN-DETAILS 3.2.3 to 3.2.5 alone, importing nothing from this module, computing C and the carries itself in `math/big` (SMTP-M9-28). It passes every leg's honest BDAT and DATA connection, two-record header blocks and envelopes a command a group among them, and names the same failing checks as the gate and `relation.go` over the mutation table's breaks and DESIGN-DETAILS 3.6's cells, record by record (`checker_agreement_test.go`). It reads the relation and the gate's order rules, not the catalog's capacities, so a part no shape holds passes it. Written by an agent, not by an engineer outside the circuits' authorship, which §22.10 asks for |
| `bench/`: D-SMTP-16's runs on the reference machines | Built (SMTP-M9-32), with a scripted MX of its own: it takes a key set `smtpproof/setup` made for the purpose as a prover host does, timing each `PrepareKeys` shape, then sends D-SMTP-16's BDAT and DATA cases on every leg and reports p50, p95 and the most per leg and mode, a unit's time per shape beside its constraints, public inputs and domain, and the host. Never run on a reference machine, nor on a ceremony's key set |
| `smtp_proof.go` in the root: the injection seam | Built (SMTP-M9-35): `MailForwarded`, `Measure`, `KeySet`, `PrepareKeys` and `SmtpProverReadiness`, the preamble's `ProofKeySet`, `ErrSmtpProofKeySet` and `HoldsKeySet`, the job's `KeySet` and `EnvelopeGroupMaxCount` and the result's `EnvelopeRetry`. `cli/smtp_prover.go` builds the prover from the release's pins, of which there are none, so ur injects no prover. server's `cli/smtpedge` injects `smtpproof.NewVerifier` over `smtpedge.yml`'s `proof_key_sets`, which list none until OPS-M9-02, so the edge answers KEYS to every preamble |

Not built, each failing closed as stated:

- **Keys.** No production setup has run, so no release pins a key set and the edge lists none: ur injects no prover, hosts only queue, and every preamble gets KEYS. The fetch is built; it fetches nothing until OPS-M9-02 gives `SmtpProofKeysUrl` and a release pins a set (section 14).
- **The reference machines.** D-SMTP-16's runs on the M1 and the m5.large, `EnsureKeys` per shape on each, and the memory of a proof on an 8 GB M1: 11.4's figures are the shared M4 Pro's (section 14).
- **Mapping the key dump.** The loader reads a cached proving key's dump into the heap, where mapping the cache file would take about 261 MiB a shape out of it (DESIGN-DETAILS 3.2.8, in the spirit of QD-641); and a cancelled proof runs to its end inside gnark, holding its charge until then.
- **Witness edits end to end.** FS-31's rows that change a witness, its RecordMx rows and its forging-edge rows run at T2 alone, the circuits on test shapes sized to each part (the key part on its production shape); the scripted MX runs over `crypto/tls`, which cannot send a late ticket, a KeyUpdate or a padded record on demand, so those cases are held at the relation, the gate and through RecordMx, not through real Groth16 proofs.

**Names.** The plan's tasks SMTP-M0-03 to SMTP-M9-25, and SMTP-M9-35 to SMTP-M9-40 after them, name their Provides before the code existed; the code took these names, and where the two differ this document's are the ones that stand:

| Plan's name | In the code |
|---|---|
| `circuitSha256Compress`, `circuitSha256` | `sha256Compress`; `sha256Padded`, `sha256Absorb`, `sha256Sum` (`circuit_sha256.go`) |
| `circuitHmac`, `circuitHkdfExpandLabel`, `circuitTls12Prf` | `circuitHmacKey` with `sum`, `expandLabel` and `prf` (`circuit_sha256.go`, `circuit_keys.go`) |
| `circuitWord` | `circuitWord`, with `circuitByte` (`circuit_bits.go`) |
| `circuitAes128Block`, `circuitChacha20Block` | `aesEncrypt` over `aesExpandKey`'s round keys; `chachaBlock` (`circuit_cipher.go`) |
| `circuitAesKeystream`, `circuitChachaKeystream`, `circuitNonce13` | `circuitKeystream`: `newCircuitKeystream` and `block`, whose nonce is the IV XOR the counter's upper 64 bits (`circuit_part.go`) |
| `circuitXorOpen` | `openBlock` (`circuit_part.go`) |
| `circuitKeys13`, `circuitKeys12`, `circuitSessionKeys` | `tls13CircuitKeys`, `tls12CircuitKeys`, `circuitKeys` (`circuit_keys.go`) |
| `witnessKeys`, `newWitnessKeys`, `witnessRecords`, `witnessHeaderBlock`, `witnessReplies` | `assignWitness` over `partWitness`; `assignRecordBlocks`, `assignHeaderRecordPublic` and `assignHeaderPrivate`, `assignBodyRecordPublic`, `assignServerRecords` (`circuit_part.go`, `circuit_message.go`, `circuit_replies.go`) |
| `circuitRecords`, `circuitTemplate` | `checkPool` over `clientRecordTemplate`'s templates (`circuit_part.go`) |
| `circuitHeaderBlock` | `checkHeaderRecordCircuit`, a record at a time from a scan state (`circuit_message.go`) |
| `circuitServerRecords`, `circuitReplies` | the server blocks of `partCircuit` and `checkReplies` (`circuit_part.go`, `circuit_replies.go`) |
| `circuitTail`, `circuitDataLines` | QUIT's and the end mark's templates in `clientRecordTemplate`, and `checkBodyRecordCircuit` (`circuit_message.go`) |
| `shapeEnvelope`, `shapeHeaders`, `shapeReplies`, `shapeBdatPi1` to `shapeBdatPi3`, `shapeDataPart` | `ProofSettings.Shapes`, the catalog by kind, family and pools (`settings.go`), as `partShapes` reads it (`backend.go`) |
| `circuitPartProver`, `circuitPartVerifier` | `groth16Backend`'s `provePart` and `verifyPart` (`backend.go`) |
| `SmtpProverMeasure`, `Prover.Measure` | as named: the root type and `SmtpProver.Measure`, `Prover.Measure` (`prover_measure.go`) |
| `TestMutatedWitness*`, the M9 evidence table | as named, one test a check (`mutate_edge_test.go`, `mutate_circuit_test.go`), and `testdata/mutations/table.md` |
| `smtpproof/testdata/vectors/` | as named, with `statements.json`, `commit.json`, nine fixed connections and one key-part proof (5.1) |
| `commitGenerator`, `commitKeys`, `commitCarry`, `newCommitBlind`, `circuitCommit` | as named (`commit.go`, `circuit_commit.go`), with `assertCommitment` and `assertCarry` the circuit's two uses (`circuit_commit.go`, `circuit_scan.go`) |
| the key shapes `key-v0304-aes128gcm`, `key-v0304-chacha20`, `key-v0303-aes128gcm` | `key-v0304-aes128gcm-c8`, `key-v0304-chacha20-c2`, `key-v0303-aes128gcm-c8`: a KeySet name spells every pool (10.4) |
| `relationZ1` in two steps; `relationZ5`, `relationZ6` and `relationZ8` per part | as named, with `relationZ1Derive` and `relationZ1Open`, and `scanHeaderRecord` and `scanBodyRecord` under Z5 and Z6 (`relation.go`) |
| `recordRoleAt`, `partShapeFor` by roles, the scan state and `scanStart`, `headerSplit` | as named: `recordRoleAt` beside `ProofSettings.headerSplit` (`settings.go`), `partKindOf` and `partRoles` (`relation.go`), the scan state (`circuit_scan.go`) |
| `ReplyCount`, `EhloRule`, `Last354` and `Tls13` in the server gadget | `replyFlags`, with `RequireChunking` (`circuit_replies.go`) |
| the planner in `proverRun`; envelope groups | `proverRun` (`prover.go`) over `envelopeGroupSize` and the reply estimate (`prover_plan.go`) |
| the shape loader | `newProverLoader` (`prover_load.go`) |
| `KeySet.EnsureKeys`, `keyFetch`, `smtpShapeDigests`, `setup -extend` | as named (`setup_keys.go`, `setup_fetch.go`, `shape_digests.go`, `setup/`); the cache is `keyCache` (`setup_cache.go`) |

## 13. Readings taken

Each is one reading of a point DESIGN.md leaves open, followed because it changes no D- item, format or invariant. A reviewer should challenge them. Reconciled with the owner's answers as of draft 3. Draft 2's: reading 14 is the owner's decision, and the forms of reading 19 for the issued values are plan-SMTP-small-readings #3 and #4 as answered. Since then the owner answered DESIGN-DETAILS section 3's five questions (QD-712 to QD-716, owner decisions 253 and 433 to 435), and DESIGN.md §14 now carries what they decided: readings 2, 3, 11, 21, 22, 24 and 28 are restated for it, readings 11, 32 and 35 are now DESIGN.md's text as well, and DESIGN-DETAILS 3.9's own readings, which belong here (DESIGN-AMENDMENTS.md), are 3, 24 and 30 to 35. Readings 36 to 43 are the drafted tasks', SMTP-M9-35 to SMTP-M9-40. No answer touches the others.

1. **One command per record** (4.2). Z3's "lengths fix offsets" and §2.8 smtp-2's "each command's length, every RCPT TO's included" imply it.
2. **The header block is 1 to 16 records, cut by its length alone, ending at its CRLF CRLF** (4.2, 4.3, Z5). Draft 2 held it in one record; DESIGN-DETAILS 3.2.4 cuts it so that each part is a unit, by `headerSplit` of a length the edge already sees, so the cut adds nothing to what smtp-2 lists, which since owner decision 253 names the header block's record count. The block stays bounded at `HeaderBlockMaxByteCount`, 16,384 octets.
3. **DATA's records are cut by length** (Z6), replacing draft 2's whole lines (DESIGN-DETAILS 3.9, reading 3). A body record holds what the body shape holds, the last what is left, and the scan's state crosses each boundary in a carry, so a line may span records. The edge then sees the body's length and no line end, which reveals less than draft 2's lengths did (10.2, K3).
4. **MAIL takes no parameter but REQUIRETLS** (4.2), following Z4's literal form: no `SIZE=`, `BODY=` or `SMTPUTF8`. So bodies are 7-bit clean, and a non-ASCII address gets a DSN.
5. **`local` drops `%` and `!`** (4.2). §14.5 says every RCPT is at the recipient domain, and percent or bang routing would undercut that on an MX that honors them.
6. **Z5 proves its signature on §14.6's second signature** (Z5.5), whose `h=` is a fixed list, so "covering them" is a literal comparison. Other DKIM-Signature fields are unconstrained, which reads Z5's "once each" as applying to this one.
7. **`d=` equals `header_from_domain`** (Z5.5), from strict alignment (§14.6).
8. **`message_id` carries no angle brackets** in the preamble, and Z5 adds them.
9. **E1 fixes the client's second flight** to one record of Finished's length (section 6), which §14.5 implies by "no early data" but does not state.
10. **The edge decrypts the 1.3 flight only for E2.** E2 checks the server's signature and does not validate the chain (section 1).
11. **The key part's `mode` is 0** and not part of its statement. Now DESIGN.md's too: §14.5's `SmtpProof.mode` is 0 in part 1 and fixed from part 2 on.
12. **A padded 1.3 server record is unprovable** (Z7). No text requires padded server records, and the census will show whether any MX sends them.
13. **Whether a server record is a ticket stays private** (Z7). Making it public would be cheaper, and would add a value §2.8 smtp-2 does not list.
14. **The declared count follows the owner's answer to `plan-SMTP-preamble-byte-count`** (`prover.go`), so this one is decided rather than read. The sidecar declares the count of the mode it expects. The mode comes from the EHLO reply alone (Z9, reading 17), never from the count, and where that mode cannot meet the declared count the prover stops before MAIL and names this mode's count for one new connection. So an MX offering CHUNKING gets BDAT unless DATA is forced for interop (§14.5), and too_large means DATA was the only mode.
15. **The fixed signature leads with `h=`** (Z5.5), since DKIM's tag order is free and a constant prefix makes "exactly one" a sum.
16. **A chunk short of octet n at QUIT is a record cut** (E3). §14.7 names only a body past octet n, but Z6 requires n exactly and an honest sidecar never falls short.
17. **Z9 reads its keyword inside one record** (Z9). The window holds the CRLF before the line, the line and its own CRLF, so a line at a record's edge does not count, and the sidecar, which applies the same test, sends such an MX DATA. That costs coverage, never soundness, and the census will show how many MXs write a line per record.
18. **A header field name never starts with a dot, in either mode** (Z5.3). DATA needs it, since an MX deletes that dot. BDAT does not, but one rule is simpler, and a sidecar writing the header block has no reason to emit such a name. RFC 5322 allows one, so a message a mail client wrote that way fails the send.
19. **The preamble's forms** (section 6). §14.5 calls these values proven and says the edge resolves `recipient_domain`, but states no syntax. The proofs mean what the design says only if a template holds one command, so the forms are refused here, whatever the engine's own gate does.
20. **The gate ends at its first refusal** (section 6). §14.7 says a refused record or part cuts the connection, and the root's seam says an error ends it; the gate now ends itself too, so nothing is released after a refusal even where a caller would go on.
21. **MAIL counts as forwarded when a call hands it out** (`MailForwarded`). A record cleared by a call that then cuts is returned to no caller and never written, so the unit §14.7 charges "once its MAIL record is forwarded" is not charged for it. With envelope groups part 2 is no longer the whole envelope, so `MailForwarded` is "the record at f + 1 has been handed out" (DESIGN-DETAILS 3.2.5).
22. **A host's DATA cap and its price are the slowest family's** (`Measure`). Every production shape fills one domain, so a unit of any shape stands for the rest (11.4): the host proves one body unit per ready family over a session made up for it, the slowest family's time is the host's `UnitTime`, a body record's octets over it the DATA rate, and `smtp_data_proof_bytes` that rate over §14.4's 2 h. A host whose unit takes over 2 minutes sends nothing in DATA mode, and one that cannot prove a unit at all, for want of memory most likely, records no `p/` and only queues (QD-483; plan-SMTP-small-readings #19). A sender prices a BDAT send in units at that time (§14.5's Check). `Measure` is on `SmtpProver`, since the sender that records `p/` holds only that seam.
23. **A template no plaintext of the record's length can fill is refused as E3** (section 5). The edge refuses such a part before verifying it, so it is the gate's refusal, and the independent checker names it so too, though the relation would fail Z4 on it.
24. **`smtpproof/setup` stays a command of its own** (DESIGN-DETAILS 3.9, reading 8), now with `-extend` and `-digests` beside `-out` (10.3). C-23 moves into `sidecarctl` the commands plans put under `bringyourctl` or `warpctl`; this one the plan puts under `smtpproof`, and the root module cannot require `smtpproof`. Its work is `RunSetup` and `ExtendSetup`, which `sidecarctl` could call if the owner wants it there.
25. **On a BULK message `List-Unsubscribe-Post` is a single field** (Z5.6). DESIGN.md's Z5 asks for the field when BULK is set, and RFC 8058 §3.1 says it holds the single key/value pair `List-Unsubscribe=One-Click`. Counting only lines equal to that literal, as draft 1 did, let a continuation turn the field's value into something else, or a second field of another value stand beside it, and the relation, the circuits and the checker all passed both. So the field is counted by name, as rule 4 counts its four, held to the literal and to no continuation. A message without BULK keeps whatever such fields MAIL wrote.
26. **Z3's outer type, and all of 1.2's Z3, are the edge's** (sections 6 and 7). A record's outer type is public and the circuit sees only ciphertext, so a part whose record is not application_data is refused before verification, as E3, as the checker refuses it: the relation named it Z3, while a real proof of it would have verified, its record able only to meet E1. In 1.2 Z3 holds nothing more, the plaintext's length being the record's, so no witness can break Z3 alone there; and Z7's 1.2 half, a server record's type, is E1's likewise. The mutation table lists these cells as no witness's (section 8).
27. **A server record's opening is Z2's** in `relation.go` and the checker, as a client record's is, and Z7 is what an opened server record may hold. Z7's text names the opening too; section 8's row for replayed server replies means it, and the relation's Z2 is where a replay fails.
28. **A part that opens records its kind cannot open is refused as E3** (E3, step 8). Roles follow from positions and a part's kind from what it opens (4.3), both public, so the edge refuses such a part before verifying it, as reading 23 has it for a template. The checker named it Z4 or Z6 until SMTP-M9-29 held the two readers to one table.
29. **Every public wire is read by some constraint** (5.1). Groth16 weighs each public input by its own element of the verifying key, the identity for a wire no constraint reads, so such a wire verifies at any value. That was harmless where the edge always assigns the wire zero, as it does every wire found unread, but a verifier written apart from this one could not know it. So a shape carries `IsLocal` only on blocks that can hold a local part, and a wire only on the shapes that read it: draft 2 bound `DataMode` where only π3 read it, `ResumeTwoBlocks` in 1.3 and a body pool's last `Start` to that zero, and draft 3's statements hold the handshake's inputs in the key part's alone, the carries and the reply flags only in the kinds that use them (5.1). `TestEveryPublicWireIsConstrained` holds the eleven production shapes to it.
30. **The header block's order** (DESIGN-DETAILS 3.9, reading 1). The single fields come first, then the fixed signature and the full signature, then the message's other fields (SMTP-M9-04), where draft 2's assembler wrote the signatures first. RFC 6376 §5.6 asks only that a new signature go before any other DKIM-Signature field, and a verifier takes signed fields by name from the bottom up (§5.4.2) wherever the signature sits. D-SMTP-16's interop run is where this is confirmed; if a receiver objects, the fallback is a msg shape with a larger head and no server blocks, a unit more a send.
31. **The fixed signature's prefix is still counted over the whole header block** (DESIGN-DETAILS 3.9, reading 2), exactly once, as Z5.5 has it, though nothing rests on a second such line being absent. That keeps Z5 word for word, at about 12 constraints an octet in later records.
32. **No part is proven again** (DESIGN-DETAILS 3.9, reading 4). Draft 2's "a part proven again with a later `server_record_count` replaces it" becomes a later part that opens no client record. The cost is the same, one proof, and a verified part's published carry and counts can no longer change after its records left (9.3, S3). Now DESIGN.md's: "a verified part is never replaced".
33. **The check ids stay E1 to E3 and Z1 to Z9** (DESIGN-DETAILS 3.9, reading 5). The opening of C is Z1's second step, the carries are Z5's and Z6's, the counts Z8's and E3's, so §22.10's table and `TestSpecNamesEveryCheck` keep their rows.
34. **The reply estimate is a mean taken from public values** (DESIGN-DETAILS 3.9, reading 7), the content octets of the server records the group before's part covered over its `reply_count`, so that a group's size, which the edge sees, depends on nothing private (4.3; `TestTheReplyEstimateReadsLengthsAlone`).
35. **The TLS client offers ChaCha20 first** (DESIGN-DETAILS 3.9, reading 6; 4.1), where draft 2's offered AES-128-GCM first. Now DESIGN.md's: §14.5's Speed names ChaCha20 "which the client offers first".
36. **Replies spread over more records than one env part holds go in several parts that open no client record** (SMTP-M9-39), each the longest run of whole server records that ends at a reply's end. That tells the edge that a record boundary there ends a reply, which an MX that spread one group's replies over too many records gives away; it is K3's one exception (10.2). A record no part holds then ends the send in `EnvelopeRetry`, possibly after such a part went.
37. **The fill rule fills the data pools in the catalog's order** (SMTP-M9-37), and keeps a client pool that holds only BDAT's command, QUIT and the end mark at DESIGN-DETAILS 3.2.6's count. That gave `msg-aes128gcm-s17-c4-h52`, `msg-chacha20-s13-c2-h19` and `hdr-aes128gcm-c2-r76`, a block past 3.2.6's table each (10.4), and moved two of the planner's unit counts (11.4).
38. **The circuits' two hints take fixed ids** (SMTP-M9-40). A hint named by its function puts the package's path into every circuit digest, which the release's `/v2026` module rewrite changes, so `circuit_sha256` would differ between the tree and the release.
39. **The edge checks no circuit digest, and drops a set past its `not_after` at each session's open as well as at start** (SMTP-M9-40). The edge's soundness rests on its own ceremony, not on what a host compiles, so a set outlives a circuit change at the edge until its `not_after`; hosts on the new circuits refuse it at their step 2.
40. **The verifier answers KEYS before the dial** (`HoldsKeySet`, SMTP-M9-35). A session needs the MX its dial chose, so the engine asks whether the set is held before it dials, and §14.5's "no MX is dialed, nothing is debited" holds.
41. **An exact resend that verifies beside its original ends the connection** (SMTP-M9-38), by E3 step 14 and DESIGN-DETAILS 3.5's "two parts reach the gate at once", where draft 2's gate passed it as a no-op. A resend after its original landed is still one, by step 3.
42. **A fetched contribution is held to gnark's compressed form before gnark reads it** (SMTP-M9-40): its declared domain size and key counts the ones this circuit and domain fix, and every point compressed, so a file that hashes to its pin and is otherwise malformed is refused before any parse allocates by its counts.
43. **The fetch follows no redirect, and its backoff is per key set** (SMTP-M9-40), so a newer pin whose files are not yet published leaves the older set checked and offered.

## 14. Open

Raised to the owner (`.stack/questions/`, one file each), and answered in `.stack/decisions/RESOLUTIONS.md`:

- `smtpproof-start-shts-wire` (QD-487): `SmtpHandshake{send_id = 1, shts = 2}` as `SMTP_HANDSHAKE = 0x1607`, sidecar to edge as soon as the handshake ends, answered by `SmtpHandshakeResult{code = 1}` as `0x1608`, 1 OK and 2 INVALID, on which the edge ends the connection. TLS 1.2 sends none. The key part follows it.
- `smtpproof-start-key-distribution` (QD-123, owner decision 266): as 10.3 states, with DESIGN-DETAILS 3.2.7's fill. The key set, a host's check, the cache and the fetch are built; the fetch waits only for OPS-M9-02's `SmtpProofKeysUrl` and a release's pin.
- `smtpproof-start-z1-reproof-cost` (QD-144): reopened by DESIGN-DETAILS section 3 with the measurements its estimate lacked and answered again by `details-3-key-commitment`; its rule for a confirmed miss is the m5.large's rows (11.1).
- `details-3-key-commitment` (QD-712, owner decision 433): one perfectly hiding Pedersen commitment to the session's keys is public, so Z1 is proven once a connection (4.3, 7, 9.2, 9.3, 10.2).
- `details-3-speed-bar` (QD-713, owner decision 433): D-SMTP-16's rows in units, the M1's numbers kept and the m5.large's what SMTP-M9-32's bench measures (11.1).
- `details-3-recipient-groups` (QD-714, owner decision 434), which also answers `smtp-m9-22-recipient-classes`: envelope groups on one connection and no recipient class (4.3, 10.4).
- `details-3-key-rotation` (QD-715, owner decision 435): a ceremony again only on a circuit or catalog change or a suspected exposure of its host (10.3).
- `details-3-metadata-rows` (QD-716, owner decision 253): smtp-2 amended and smtp-7 added, both in `metadata_list.yml` since its v19, so the fetch may run once it has a url (10.3).
- `plan-SMTP-preamble-byte-count`: applied in `prover.go` (reading 14).
- `plan-SMTP-data-connection-lifetime`: grants become per `ur/` service, SOCK-M9-01's, with nothing in this module.

- `smtp-m9-33-part-memory-default` (QD-1115), raised by this draft: `BenchmarkPartMemory` found a ChaCha20 body unit's proof taking 834 to 935 MiB over its loaded shape, past `PartMemoryByteCount`'s 704 MiB, at 8 and at 14 cores, while its shape took 546 MiB of `ShapeMemoryByteCount`'s 768 (11.4). Option 1: `PartMemoryByteCount` rises to 960 MiB and `MemoryMaxByteCount` to 2,496 MiB, so the budget keeps DESIGN.md §5.4's meaning of two loaded shapes and one proof. Applied in `prover.go` (11.4).

Raised and not yet answered: none.

For the reviewers, and raised to no one:

- gnark-crypto v0.21's twisted Edwards fix against this module's use of `ecc/bn254/twistededwards` on the witness side and in the gate's form check (10.1), at the next bump.
- The witness side computes C and each carry with `math/big` and gnark-crypto's scalar multiplication over secret scalars, the keys and the blinds, neither of which claims constant time. The timing an edge can observe is a part's seconds of proving, so this is a local attacker's item on a prover host, not the edge's.

Evidence M9 still needs, none of which this draft provides (§22.10):

- two non-authors' written soundness argument, which now has S1 to S7 and K1 to K4 to argue (9, 10.2);
- a checker of the public relation by an engineer who did not write the circuits: `checker/` is a draft of it, written apart from the prover tree but by an agent;
- D-SMTP-16's speed, coverage and interop runs on its named hardware and census MXs, through SMTP-M9-32's bench for speed, with `EnsureKeys` per shape and a unit's memory on the 8 GB M1 beside them (11.4), the interop run also confirming reading 30's header order;
- FS-31's rows that change a witness, and its RecordMx and forging-edge rows, at T3, where they do not yet run (section 12);
- a production ceremony on the host the owner names, and a release that pins its key set (10.3);
- a review of the vectors of 5.1 against an implementation written apart, the bytes the exit review freezes.
