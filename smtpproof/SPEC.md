# smtpproof: what the outbound-mail proofs prove

*Draft 2, the freeze candidate for M9's entry review, 2026-11-08; draft 1 was 2026-11-06. Not frozen: this specification freezes at M9's entry review and its bytes at M9's exit review (DESIGN.md §22.10, D-PHASE-7), and nothing here does either. Until then every field, encoding and shape here may change. `testdata/vectors/` holds the bytes the exit review would freeze (5.1), and `testdata/mutations/table.md` the evidence that each check does work no other does (section 8).*

This document states the relation behind X7: what a sending sidecar proves to `smtpedge`, against which public values, and why that is sound against a malicious sidecar and zero knowledge against a malicious edge. It is the document D-SMTP-16 names. DESIGN.md §14.4 and §14.5 are the source; where this draft and DESIGN.md disagree, DESIGN.md wins and the disagreement is a bug here. Section 13 lists every reading taken where DESIGN.md was not explicit, and section 14 what is still open.

The code beside this file follows it. Section 12 says which parts of it exist.

## 1. The claim

Owner directive X7: TLS runs end to end from the sidecar to the destination MX, so the edge sees ciphertext plus a small declared preamble. Abuse control needs those declared values to be true, and a sidecar is not trusted to declare them. So:

**Soundness.** Let `smtpedge` and the MX be honest, and the sending sidecar be malicious. If the edge forwards records under this protocol, then except with negligible probability the MX's SMTP state machine sees, on that connection, at most one transaction, and any message the MX accepts in it has:

- an envelope sender in the network's envelope domain, and exactly `recipient_count` recipients, all at `recipient_domain`;
- exactly `message_byte_count` octets;
- a header block holding, once each, a From in `header_from_domain`, the declared Message-ID, the issued X-UR-Ref and Feedback-ID, and a DKIM-Signature with the declared `d=` and `s=` covering them.

**Reach.** A colluding MX gets only its own mail. The edge resolves and dials the MX for `recipient_domain` itself (E2), so a colluder can make any statement true about a connection that reaches only the colluder.

**Zero knowledge.** Let the sidecar be honest and the edge be malicious, including having run the setup. Beyond the public inputs of section 5, the edge learns nothing about the keys, the plaintext of any client or server application record, or the recipients. This holds for any well-formed setup, and the prover checks well-formedness (section 10).

What is deliberately **not** proved:

- The body. BDAT's body streams unopened; DATA's is scanned only for its framing.
- That the DKIM signature verifies. A sidecar that signs badly fails DMARC at the receiver, which costs only itself.
- That the MX is the right MX. That is the sidecar's job as TLS client, at TL1-TL3 (§14.4). It is why E2 needs no PKIX check: the proofs protect the edge from the sidecar, and TL1-TL3 protect the sidecar from the edge.
- Anything about the edge's honesty. A compelled edge can drop, delay or misreport, and can read TL4-override mail (§2.8 EX4).

## 2. Parties

| Party | Holds | Trusted for |
|---|---|---|
| Sidecar (prover) | Its own TLS client state: HS, MS, every application key and IV, all plaintext | Nothing, for soundness |
| smtpedge (verifier) | The TCP connection to the MX, every relayed byte, the preamble and issued values, the verifying keys | Nothing, for zero knowledge |
| MX | Its TLS and SMTP state | Assumed honest for soundness, and to follow RFC 5321, 3030, 3207, 2920 and 8446 or 5246 in the respects listed in 9.1. Assumed colluding only for Reach |

The edge sits on the TCP path. It relays the sidecar's bytes to the MX and the MX's bytes to the sidecar, and it alone decides which client records reach the MX. The sidecar is not on the path between edge and MX, which is ORIGO's no-MITM assumption (§14.4).

## 3. Notation

- `‖` is concatenation. `SHA-256`, `HMAC`, `HKDF-Expand-Label` and `Transcript-Hash` are as in RFC 8446. `PRF` is RFC 5246 §5 with SHA-256.
- `seq` is the TLS sequence number of a record in its direction, under its traffic key.
- Client application records in 1.3 begin at `seq` 0. In 1.2 the client's Finished takes `seq` 0, so they begin at 1.
- `CRLF` is octets 0D 0A. A **bare** CR is a CR not followed by LF; a bare LF is an LF not preceded by CR.
- `helo_name`, `x_ur_ref` and `feedback_id` are the issued values of `SmtpPreambleResult`.
- `envelope_domain` is `b.<net>.<root>`, or `b.<domain>` in Team strict mode (§14.6). The edge derives it from the ticket's network and never takes it from the sidecar.

## 4. The wire shape an honest sidecar produces

The relation is simple because the sidecar's own client produces one normal form, and anything else is unprovable and fails before any effect. An MX sees ordinary SMTP. This section fixes the shape; section 7 states the checks over it.

### 4.1 The TLS client

The prover runs `tlsClient` (`tls_client.go`), the sidecar's own TLS client. It exists for three reasons no stock client serves:

1. Go's `crypto/tls` exports TLS 1.2's master secret through `KeyLogWriter` but never TLS 1.3's HS (§14.3), and HS is Z1's witness.
2. A proof must cover a record's ciphertext before the record is sent, so sealing and sending are separate steps.
3. Z3 needs exact control of record boundaries and of what is never sent: padding, KeyUpdate, early data.

It offers:

- TLS 1.3 with `TLS_AES_128_GCM_SHA256` and `TLS_CHACHA20_POLY1305_SHA256`; TLS 1.2 with `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` and `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`. These are E1's suites and no others.
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
| Header block | Section 7's Z5 form, and nothing after its final CRLF CRLF |
| Body part (DATA) | Whole lines, each ending CRLF |
| End mark (DATA) | `.` CRLF |
| QUIT | `QUIT` CRLF |

`local` is 1 to 64 octets of `A-Z a-z 0-9` and ``# $ & ' * + - / = ? ^ _ ` { | } ~ .``. That is RFC 5321's Dot-string with `%` and `!` removed, and with no leading, trailing or doubled dot enforced only by the sidecar, not the relation. No `@`, `<`, `>`, `,`, `:`, CR, LF or SP can occur, so a path holds one address at one domain. Quoted local parts, source routes and non-ASCII addresses are not expressible, and such a recipient gets a DSN.

Because one record holds one command and Z3 fixes its length, **every offset in a command is a function of public record lengths**. This is what keeps grammar out of the circuit: section 5's position templates are computed from public values by the edge, and the circuit only compares.

### 4.3 The connection

```text
sidecar                       smtpedge                          MX
 |--SmtpPreamble--------------->|--banner, EHLO, STARTTLS-------->|
 |==ClientHello .. Finished (spliced; 1.3 discloses SHTS, E2)====>|
 |--pi1 + EHLO record---------->| verify
 |==EHLO record=================================================>|
 |<=EHLO reply===================================================|
 |--pi2 + MAIL, RCPT x R [, DATA]-->| verify
 |==MAIL, RCPT x R [, DATA], paced by the sidecar===============>|
 |<=their replies [, 354]========================================|
 |--pi3 + the rest (below)----->| verify
 |==BDAT n LAST, header block, body, QUIT, each once admitted===>|
```

| Part | `index` | Client records it opens | Server records it adds | Checks |
|---|---|---|---|---|
| π1 | 1 | EHLO | None (`server_record_count` 0) | Z1 Z2 Z3 Z4 |
| π2 | 2 | MAIL, RCPT × R, and DATA in DATA mode | Through the EHLO reply | Z1 Z2 Z3 Z4 Z7 Z8 Z9 |
| π3, BDAT (`last`) | 3 | BDAT, header block, QUIT | Through the last envelope reply | Z1 Z2 Z3 Z4 Z5 Z6 Z7 Z8 |
| π3, DATA | 3 | Header block, first body part | Through the 354 | Z1 Z2 Z3 Z5 Z6 Z7 Z8 |
| DATA part | 4.. | Body parts; the `last` part ends with the end mark and QUIT | Any since the previous part | Z1 Z2 Z3 Z6 Z7 Z8 |

Every part re-proves Z1: no application key or commitment to one is public (D-SMTP-22).

A part that needs only one direction's keys may derive only those: π1 opens no server record, so it omits SATS and the server key. Nothing is lost, because nothing in π1 uses them.

## 5. Public inputs

Each is a value the edge already holds or computes. None comes from the prover except `records`, which the stream must then repeat (E3), and the disclosed SHTS, which is used only after E2 checks it.

**Session.** TLS version and suite, then Z1's handshake inputs, computed by the edge over the bytes it relayed:

```text
1.3  H_shts = SHA-256(SHTS)
     H_sh   = Transcript-Hash(ClientHello .. ServerHello)      a HelloRetryRequest included (RFC 8446 §4.4.1)
     H_sf   = Transcript-Hash(ClientHello .. server Finished)  the flight as E2 opened it
1.2  r_c, r_s   the hello randoms
     S_ckx      the SHA-256 state (chaining value, unhashed tail, length) after ClientHello .. ClientKeyExchange
     SF         the server Finished record as relayed: explicit nonce and ciphertext
```

**Preamble and issued values.** `recipient_domain`, `recipient_count`, `message_id`, `header_from_domain`, `dkim_selector`, `message_byte_count`, `flags`, `helo_name`, `x_ur_ref`, `feedback_id`, `envelope_domain`.

**Part.** `index`, `mode`, `first_record`, `last_record`, `server_record_count`, `last`; `records`, the ciphertext of each client record the part opens; the server records it covers, as the edge relayed them.

**Position templates.** These are not new information: they are a fixed function of the values above, and the edge computes them itself. For each opened client byte position the template gives one of:

- `lit(b)`: the plaintext octet is b;
- `local`: the octet is in section 4.2's `local` set;
- `free`: no constraint at this position.

For example the template of a 40-octet MAIL record is `lit("MAIL FROM:<")`, then `local` up to the suffix, then `lit("@" envelope_domain ">" CRLF)`, which fixes the length of `local` from the record's length. A template whose `local` run falls outside 1 to 64 octets has no satisfying plaintext, and the edge refuses the part without verifying it.

The statement a circuit proves is this vector, encoded as field elements in the order the shape defines (5.1). Encoding is frozen with the bytes at M9's exit.

### 5.1 The statement as field elements

Groth16's verifier takes the statement as elements of BN254's scalar field, one for each public wire of the shape's circuit, in the order the circuit declares them: `partCircuit`'s fields in declaration order, depth first, as gnark's schema walks a struct, private wires skipped (`circuit_part.go`, `circuit_message.go`). The edge computes every element from section 5's values (`partAssignment`), so nothing in the statement comes from the prover but the records it opens. A hash, random or other octet string enters as eight elements an octet, least significant bit first; a ciphertext or literal octet as one element from 0 to 255; a flag as 0 or 1.

| In order | Elements | What the edge puts there |
|---|---|---|
| `ShtsHash`, `HelloHash`, `FinishedHash` | 256 each, 1.3 only | H_shts, H_sh, H_sf |
| Each client pool block: `Counter`, `Cipher`, `Literal`, `IsLiteral`, then `IsLocal` on a shape with the local table | 1, then one a block's octet for each of the rest | the block's counter (below), its ciphertext, and the template: lit's octet, 1 where the position is lit, 1 where it is local. Only π2's shapes carry the local table |
| Each server block: `Counter`, `Cipher`, `Active`, `TypeOctet`, `FirstOctet`, `WindowActive`, `Continues` | 1, one a block's octet for each of the next five, 1 | the counter and ciphertext, then what record lengths fix: a content octet, 1.3's type octet, a record's first octet, a position whose next 16 octets lie in one record's content (Z9's window), and whether the block continues its predecessor's record |
| The header scan (π3): its pool blocks, then `Active` and `Field`, then the Message-ID, X-UR-Ref, Feedback-ID, From address and DKIM tag literals, each as `Expected` then `Used`, then `Bulk` | pool blocks as above, with no `IsLocal`; one a header octet for each of `Active` and `Field`; 124, 124, 124, 93 and 93 for each of `Expected` and `Used`; 1 | Z5's public side: a content octet, a position before the final CRLF CRLF, each literal's octets and which of them are used, and the BULK flag |
| Each body block: its pool block, then `Active`, `Start`, `End` | as above, with no `IsLocal`; then one a block's octet for each | Z6's public side: a content octet, a record's first octet, a record's last octet |
| `ExpectedReplies`, `RequireChunking`, `DataMode` | 1 each | 1 at π2, and 1 + R at π3 with 1 more in DATA mode; 1 at BDAT's π2; 1 at DATA's π3; 0 elsewhere |
| `ClientRandom`, `ServerRandom`, `ClientFinishedHash`, `Chaining`, `ResumeBase`, `ResumeShift`, `ResumeTwoBlocks` | 256, 256, 256, 256, 1,024, 6 and 1, the first six 1.2 only | 1.2's Z1 inputs: r_c, r_s, SHA-256 of ClientHello .. ClientKeyExchange, S_ckx's chaining value (each 32-bit word least significant bit first), its unhashed tail followed by room for the client Finished and SHA-256's padding, the tail's length, and whether that takes two blocks. `ResumeTwoBlocks` is in every shape, and 0 in 1.3 |
| SF's `Counter`, `Cipher` | 1 and 16, 1.2 only | the server Finished record as relayed |

A block's counter is one element: the record's `seq` in 1.3 or its explicit nonce in 1.2, times 2^32, plus Z2's block counter, 2 + j under AES-GCM and 1 + j under ChaCha20. Unused blocks are zero throughout.

Every public wire is read by some constraint (`TestEveryPublicWireIsConstrained`). Groth16 weighs each public input by its own element of the verifying key, and for a wire no constraint reads that element is the identity, so such a wire would verify at any value (reading 29). `TestGroth16RefusesEachPublicInputOneBitOff` holds a real π1 proof to this one input at a time.

The vectors, recomputed on every run:

- `testdata/vectors/connection-*.json` are six honest connections, fixed once: both versions, both 1.3 suites, both modes, with each part's witness.
- `testdata/vectors/statements.json` gives each of their parts' production shape by its KeySet name, its count of public inputs, the SHA-256 of its elements each written as 32 octets big-endian, and the template of each command record it opens, a run of local octets written `⟨local×n⟩` (`TestSpecVectorsReproduce`).
- `testdata/vectors/pi1-tls13-chacha.proof` is one π1 proof of the ChaCha20 BDAT connection, and `pi1-tls13-chacha.vk` the verifying key of the single-party test setup it was made under. Together they pin the proof's 164 octets (10.1) and the verifying key's encoding beside the statement: the proof verifies against its own statement and fails with a public input moved (`TestSpecPi1ProofVectorVerifies`). The key is a test's, never a release's.

## 6. Checks at the edge

`EdgeSession` runs E1-E3. They are ordinary code, not circuit: each fails closed, and each failure before the first forwarded application record is a refusal, not a record cut, unless 14.7 says otherwise.

**The preamble, before E1.** A template is a literal and the circuit proves a record equals it, so a declared value holding `>` or CRLF would have the proof vouch for a command of the sidecar's own: `recipient_domain` set to `a.example>` CRLF `RCPT TO:<victim@other.example` would make a second recipient at another domain part of the template. So a session refuses, and the prover too before it dials, any preamble in which:

- `recipient_count` is 0. BDAT with no RCPT draws a refusal, an MX that then reads the chunk as commands runs the unopened body, and π3 would be satisfiable with one reply (9.4). This is also why `partRoles` refuses it, so no statement of that count has a satisfying witness;
- `recipient_domain`, `header_from_domain`, `dkim_selector`, `envelope_domain` or `helo_name` is not RFC 5321's Domain: labels of 1 to 63 octets of letters, digits and hyphens, no hyphen at either end, 255 octets in all;
- `message_id` is not one `@` between two non-empty runs of section 4.2's `local` set;
- `x_ur_ref` or `feedback_id` is not in its exact form: X-UR-Ref is `1.` then the lowercase unpadded base32 of 21 octets, 36 characters, and Feedback-ID is `n` or `b`, `:`, `c`, `p` or `t`, `:`, the lowercase unpadded base32 of the 16-octet report token, `:urnetwork`, 40 characters (§14.6; plan-SMTP-small-readings #3 and #4). Each has one spelling: base32's unused low bits are zero. The edge issues both, so this is a check on itself, and their fixed lengths are what let the sidecar declare the octet count before the mode is known (plan-SMTP-preamble-byte-count).

**E1, handshake shape.** Over the relayed handshake:

- The client's first bytes are a ClientHello in a record of type 22. Its extensions hold no `pre_shared_key`, `early_data` or `session_ticket`, and none repeats. Its session id is empty, and its `server_name` holds exactly one name, the MX host, so no MX can read it as naming another.
- The ServerHello selects 1.3 with `AES_128_GCM_SHA256` or `CHACHA20_POLY1305_SHA256` and no `pre_shared_key`, or 1.2 with one of section 4.1's two suites and no `session_ticket`.
- After a HelloRetryRequest a 1.3 server may send a dummy change_cipher_spec, which reaches the edge ahead of the second ClientHello and is dropped there.
- 1.3: after the ClientHello the client sends at most one change_cipher_spec, then exactly one record of type 23, whose length is that of the client's Finished under the suite, plus an empty Certificate's 8 octets when the flight held a CertificateRequest. Nothing else passes before π1 verifies. This is what makes "no early data" hold for the client's second flight too.
- 1.2: the flight is exactly ServerHello, Certificate, ServerKeyExchange, optional CertificateRequest, ServerHelloDone; then optional empty Certificate, ClientKeyExchange, change_cipher_spec, one Finished record; then the server's change_cipher_spec and Finished record. Any other shape fails, because S_ckx and SF depend on it.
- Once application data starts, each client record's outer type is application_data and its version 0303. In 1.2 a server record of type handshake is refused too: no renegotiation.

**E2, the server's signature.**

- The edge dialed the MX it resolved (§14.4).
- 1.3: the disclosed SHTS is exactly 32 octets. HMAC zero-pads a short key, so a longer one could open the same flight. From it the edge derives the server handshake key and IV, opens the server's flight, checks CertificateVerify over `Transcript-Hash(ClientHello .. Certificate)` under the leaf key, and checks Finished under `HKDF-Expand-Label(SHTS, "finished", "", 32)`. Only then does it compute H_shts and H_sf.
- 1.2: it checks ServerKeyExchange's signature, in clear, over `r_c ‖ r_s ‖ params`.
- Accepted signature schemes are those the client offers, and SHA-1 is never accepted.
- The edge then forgets SHTS. D-SMTP-10 forbids storing it.

**E3, the record gate.** The gate is a state machine under one lock, so that "relayed before it" has a single meaning. For each client record, in stream order:

1. Its `seq` is the next expected. A record arriving early is held, within a bound; past the bound the connection ends.
2. Some verified part covers `seq`, or the record is held.
3. An opened record must equal the ciphertext the part proved, byte for byte. Unequal is a record cut.
4. In BDAT, a record between the head and the final QUIT is body. The edge adds `len - 17` (1.3) or `len - 24` (1.2) to its count of chunk octets, and a record taking the count past `message_byte_count` is a record cut.
5. A **message record** (BDAT's command and chunk, DATA's octets) is held until verified parts cover every server record relayed before it. Holding is not a cut.
6. After the final QUIT no client record is forwarded. A later one, such as close_notify, ends the connection and is not a cut.

Parts are accepted in `index` order. `first_record` continues from the previous part, `mode` never changes from π2 on, and `server_record_count` never falls and never exceeds what was relayed. The records a part opens are in strictly increasing `seq`: BDAT's QUIT names its own, and at one the head already holds it would stand in for that record, passing `BDAT 0 LAST` with no header block. An opened record holds at least its type octet in 1.3, and its outer type is application_data: that octet is public, and the circuit sees only ciphertext, so the gate checks it before verifying (reading 26). A part resent under its `send_id` and `index` is idempotent. One proven again with a later `server_record_count` replaces it. Once the MX has closed, outstanding parts are moot.

A verification runs with no lock held, so another part may land during it. Then only an exact resend of what landed passes, as a no-op. Anything else ends the connection and is no cut, because its order checks ran against what no longer stands.

Every refusal and every cut ends the gate, whichever of E1-E3 it came from: each later call is refused, and nothing more is released for the MX, not even by a part that finishes verifying afterwards. The engine ends the connection on any error too, so this does not rest on the engine alone.

The engine cannot read records, so the gate tells it when it has handed out the MAIL record, π2's first, which is when §14.7 charges the connection a unit (`MailForwarded`). Records cleared by a call that ends in a cut are never handed out, and do not count.

The edge stores none of this past the connection (D-SMTP-10).

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

**Z2, keystream.** Each proven plaintext octet is its ciphertext octet XOR the keystream at its record and offset. For a record of nonce `N`:

```text
N    = iv XOR (0^32 ‖ seq)          1.3
N    = salt ‖ explicit_nonce        1.2
AES-128-GCM        keystream block j = AES(key, N ‖ uint32(2 + j)), 16 octets
CHACHA20-POLY1305  keystream block j = ChaCha20(key, N, counter 1 + j), 64 octets
```

No tag is checked in the circuit. For client records the MX checks it; for server records the edge relays what the MX sent, and the key is already bound by Z1.

**Z3, framing.** 1.3: each opened client record's plaintext, of length `len - 16`, ends in the octet 17 at its final position, which with section 4.2's templates rules out padding and every other inner type, KeyUpdate included. 1.2: the outer type is application_data (E1), and the plaintext length is `len - 24`. The outer type is public in both versions, so the edge checks it, on the stream by E1 and on a part's records by E3, and in 1.2 Z3 holds nothing a witness could break (reading 26).

**Z4, envelope.** The opened records match, in order, the templates for `EHLO`, `MAIL`, exactly `recipient_count` × `RCPT`, then `BDAT n LAST` or `DATA`. With the part's contiguous ranges and E3, these are all the client records before the message: one transaction.

**Z5, header block.** The header-block record's content `H` satisfies:

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

**Z6, the end of the message.**

- BDAT: the head's chunk octets are exact (opened), the body's are bounded by E3's count, and together they reach `message_byte_count` exactly at a record boundary, which the edge checks as records stream. The record at `last_record` opens to exactly `QUIT` CRLF.
- DATA: `message_byte_count` counts the octets of the header-block and body records. Every such record begins at a line start and ends in CRLF, holds no bare CR or LF, and no line in it is exactly `.`. The final records open to exactly `.` CRLF and `QUIT` CRLF. A record boundary is therefore always the scan state "at line start", so §14.5's carried state is that constant.

**Z7, server records.** The private server key and IV of Z1 decrypt every server record the part adds, at its `seq`. Each is either application data, whose content joins the reply stream, or in 1.3 a NewSessionTicket: inner type 16, first octet 04, content skipped. Which is which stays private. Any other inner type, a KeyUpdate included, fails. In 1.3 each server record is unpadded: a padded one is unprovable and ends the send. In 1.2 a server record's type is public, and E1 passes only application_data after the handshake. `relation.go` and the checker count a server record's opening at its `seq` under Z2, as a client record's (reading 27).

**Z8, replies.** The reply stream parses as RFC 5321 reply lines: three digits, then `-` or SP with text, or CRLF directly; text holds no CR or LF. A reply is its lines through one without `-`. Then:

- π2's stream is exactly one reply, every line coded 250.
- π3's holds exactly 1 + R replies, each coded 2xx, then in DATA mode one reply coded 354.
- Later parts add no reply: a server record past the message's start is unprovable, and so the part cannot release more message records. In BDAT mode this ends at the chunk; in DATA mode the sidecar stops.

**Z9, mode.** `mode` is public and fixed from π2. For BDAT, the EHLO reply of Z8 holds a line that is exactly `250-CHUNKING` or `250 CHUNKING`, keyword compared without case, and it is not the reply's first line. That line and the CRLF before it lie in one application record, and a ticket's octets do not count. BDAT to an MX lacking it is unsatisfiable. DATA has no such condition: DATA to an MX offering CHUNKING is allowed, and interop forces it (§14.5).

## 8. Which adversarial case each check stops

D-SMTP-16's corpus, FS-31 included. Each row must fail before any effect, with honest controls passing.

What §22.10 asks of each check is shown by `testdata/mutations/table.md` (SMTP-M9-29): for each of E1 to E3 and Z1 to Z9, in each TLS version and mode the check applies to, a break of one honest connection that only that check refuses. The relation, through the gate, and `smtpproof/checker` name the one check alike; then the circuit refuses the part, or the gate refuses on its own with the solver as its verifier as well. The table also lists the cells no witness can break alone, and why: 1.2's Z3 and Z7, whose content is public (reading 26), and DATA's Z9, which has no condition.

| Case | Stopped by |
|---|---|
| Key substitution: one ciphertext, benign under one key, real under another | Z1 ties the key to the observed handshake |
| Record splits, a command split or two in one record | Z3 and Z4: one command per record, template by length |
| Replayed server replies | Z7: a record decrypts only at its own `seq`, which the edge assigns |
| A pipelined second transaction | Z4 and E3: every client record is proven; a second MAIL has no part |
| A declared value that carries a command, or no recipient at all | The preamble's forms, before any template is built (section 6) |
| A part's records stood on one number, to drop the header block | E3: `seq` strictly increases within a part |
| Smuggled headers, a second From, one behind a leading dot | Z5.3, Z5.4 |
| A BULK message whose one-click field is continued, doubled or of another value | Z5.6 |
| An early or bare-LF DATA end | Z6 |
| No CHUNKING; CHUNKING only before TLS | Z8, Z9 over the post-TLS reply; the edge's pre-TLS hints are not inputs |
| No PIPELINING | The sidecar paces records; one part covers them; E3 forwards in order |
| A refused MAIL or RCPT, mixed recipients | Z8: π3 is unsatisfiable, so no message record is forwarded |
| No 354 | Z8 |
| A late NewSessionTicket | Z7 skips it; E3 holds message records until a part covers it |
| A second transaction in the alleged BDAT body | Z8, Z9 prove the MX is reading a chunk; E3's count bounds it |
| Padded or KeyUpdate BDAT body records | May fail the send, smuggle nothing (9.5) |

## 9. Why it is sound

This is a draft argument. Two engineers who did not write the circuits must argue soundness in writing before M9 (D-SMTP-16); this section is what they start from, not a substitute.

### 9.1 Assumptions

- The proof system is knowledge sound for the honestly generated verifying key the edge holds (section 10).
- SHA-256 is collision resistant, and HMAC-SHA-256 is a PRF and collision resistant under the key input in the sense 9.2 uses.
- The honest MX: verifies AEAD tags with the keys of the handshake it took part in; assigns `seq` by counting; answers commands in order; reads exactly n octets after `BDAT n LAST`; and resets nothing after STARTTLS except what RFC 3207 §4.2 says.
- The edge's TCP path to the MX is not under the sidecar's control.

### 9.2 Keys are the MX's

1.3. The MX computes its traffic secrets from one HS. Its Finished, verified in E2 under SHTS, and its AEAD-protected flight fix the SHTS the edge accepts: an honest MX's ciphertext opens under only that key, except with negligible probability, since the sidecar cannot choose that ciphertext. That removes the non-committing-AEAD attack for the flight. Z1 then shows the prover knows HS' with `SHA-256(Expand(HS', "s hs traffic", H_sh)) = H_shts`. If HS' differs from the MX's HS, that is a collision in SHA-256 or in HMAC under the key input. So HS' = HS, and everything derived from it under the edge's H_sf is what the MX derived. The key of every proven record is the MX's. This is the step PLAN's "first N bytes" lacked.

1.2. No secret is disclosed (D-SMTP-21). Instead SF, a ciphertext the honest MX authored, must open under a key derived from master_secret' to a verify_data which that same master_secret' gives the relayed handshake. An honest master secret satisfies this. For any other, the 16-octet equality holds with probability 2^-128 per candidate, treating PRF outputs as random, and the prover has only offline trials. So it is the MX's. The margin is 128 bits with no tag check, the reason to treat 1.2's Z1 as a separate review item.

### 9.3 What the MX reads is what was proven

With the key bound, CTR-mode decryption is a function of key, nonce and ciphertext. In 1.3 the nonce depends on `seq`, which E3 fixes by stream position; in 1.2 it is in the record the edge compares. So the plaintext the MX obtains from an opened record, if its tag verifies, is the proven plaintext. If its tag does not verify, the MX aborts and nothing happens. Z3's final octet makes the inner type application_data, so the MX treats the octets as SMTP input and nothing else. E3 forwards opened records only if they equal the proven ciphertext. So the MX's input stream, through every opened record, is exactly the concatenation of proven contents.

### 9.4 The MX's state is what the relation assumes

Z7 opens the MX's own records under its own key, and E2's dial means they are the MX's. So Z8's parse is of what the MX really said, in order. This is why D-SMTP-22 proves replies rather than trust the sidecar's reading (RFC 3030 §2, RFC 3207 §4.2): the same bytes mean a message to a chunk-reading MX and commands to any other. π3 holds only if the MX accepted the envelope, and E3 releases message records only behind verified coverage of every reply relayed so far, so no refusal can be in flight unnoticed at the moment a message record is released. It can still arrive just after; 9.6 covers that.

That argument needs an envelope to accept. With `recipient_count` 0, π3 needs only MAIL's reply and the MX has no recipient, so it refuses BDAT however it reads what follows. Section 6 refuses that count for this reason.

### 9.5 BDAT's unopened body

The MX reads chunk octets from records. An honest edge counts each body record as carrying `len - 17` (or `len - 24`) octets. A 1.3 record carries at most that, and fewer if padded or if it is not application data; a 1.2 record of clear type application_data carries exactly that. So at every point the MX's count is at most the edge's, and the edge's never passes n. Hence:

- If every body record is unpadded application data, the MX reaches octet n exactly at the proven QUIT, and sees `QUIT`.
- Otherwise the MX is short of n when the QUIT record arrives, and the QUIT's octets are chunk data, or the chunk ends inside them and the MX reads at most the 5 remaining octets as a command. No client record follows (E3 step 6), and 5 octets hold no transaction.
- A KeyUpdate in the body makes the MX change keys, so the proven QUIT, sealed under the old key, fails its tag and the connection dies.

In no case does a body octet reach the MX's command parser.

### 9.6 DATA

Every octet is opened. Z6's no-bare-CR-or-LF and no-`.`-line conditions mean no receiver, strict or lax about line endings (CVE-2023-51764), sees an end of data before the proven end mark. A reply arriving after a message record was released, such as a late refusal, holds the next message record (E3 step 5), and a refusal is unprovable, so the connection ends with no further octets.

What the MX stores is not quite what was proven: it deletes each line's leading dot (RFC 5321 §4.5.2). Z5.3 keeps that from touching the header block, whose lines begin with a field name or with SP or HTAB, so the header block Z5 read is the one it stores. The body is unconstrained either way.

### 9.7 Conclusion

9.3 gives the exact client command stream, Z4 gives its shape, 9.4 gives that the MX acted on it as a transaction, and 9.5 and 9.6 that nothing beyond it reaches the command parser. Z5 and Z6 give the message's properties, each over proven octets. That is section 1's claim.

### 9.8 Known weak points for the reviewers

- Z5 constrains what receivers parse only as far as receivers agree with RFC 5322 on the normal form. A receiver that treats some other octet as a line ending defeats Z5.3; none is known for the class Z5.1 permits, and the corpus should keep looking.
- Z5 does not bound a line's length. A hop that breaks a line past 998 octets without folding it would start a new header line mid-field, where Z5 saw none. Nothing here has tested what real hops do with such a line. A bound would be a counter and a range check per octet, by estimate about 50,000 constraints on a 4 KiB header block, if the reviewers want it.
- 1.2's 128-bit margin (9.2), and BN254's estimated 100 to 110 bits for forging a proof, are the two smallest numbers in this document. Forgery costs abuse control, never confidentiality (10.2).
- The Groth16 setup's soundness rests on the edge's own contribution (10.3). That is the right party, but a leaked toxic secret is silent. Rotation is a key-management item.

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

Between v0.15.0 and v0.16.4, the packages this module links differ only by `uints`-style `std` changes it does not use, a prover `Accelerator` refactor, a `Lookup2` optimization and a commitment index fix it cannot reach; `backend/groth16/bn254/verify.go` is unchanged. That comparison was by `diff` over those packages, and a reviewer should repeat it at each bump. `gnark-crypto` v0.21's security fixes touch EdDSA, shplonk, fflonk, KZG's ceremony and twisted Edwards curves, none on this path. The KZG one would matter to a PLONK route.

Moving past v0.15.0 is a coordinated bump across server and sn, and it would still leave lookups subject to 10.2's review.

**Decoding a proof.** gnark's `Proof.ReadFrom` allocates the count of commitments the octets declare before it reads one, so a few hostile octets from a sidecar could ask an edge for 256 GiB, and a point marked uncompressed moves that count, so a length check alone does not help. These circuits carry no commitment, which leaves a proof one form, 164 octets, and `decodeProof` reads that and nothing else. A bump must keep it: `TestGroth16ProofOfARealEhlo` fails if gnark's encoding moves.

### 10.2 Zero knowledge

Groth16 is perfectly zero knowledge for every well-formed CRS: given the CRS trapdoor a simulator outputs proofs distributed identically to real ones, and the proof's `r`, `s` are uniform. A malicious edge that ran the setup holds that trapdoor. Holding it gains nothing, since the simulated and real distributions are the same.

A malformed CRS is different: a key element off its intended value can make a proof depend on the witness in a way the edge can test. So the prover must not take keys on trust. **A prover host uses a proving key only if `verifySetup`, which runs gnark's `VerifyPhase1` and `VerifyPhase2` over the setup transcript against the circuit it compiled from its own source, produced that key.** Those checks establish that the key is of the form Groth16's analysis needs, for whatever trapdoor. This is subversion zero knowledge by verification, in the sense of Bellare, Fuchsbauer and Scafuro (Asiacrypt 2016) and Fuchsbauer (PKC 2018). A transcript travels as bytes and is decoded for each verification: gnark's checks assume what its `ReadFrom` establishes, group membership among them, and they modify the last contribution they are given.

Three consequences:

- Confidentiality does not rest on BN254's hardness or on any secret being destroyed. The curve's bit security bounds only forgery, which is abuse control.
- No lookups or commitments means no extra element carrying witness data. gnark's `Commit` does add a random mask, but a masked Pedersen commitment under a basis whose discrete logs the edge knows would need its own argument, which this design does not have to make.
- Randomness: `r` and `s` come from `crypto/rand`. A repeated `(r, s)` across proofs under one key would break ZK, so no deterministic or seeded prover exists outside tests.

What a failed proof reveals: a part that cannot be proven tells the edge the MX's reply was not the accepted one. This is the "connections ending before π3" signal §14.15 already counts, and the only intended leak beyond the public inputs.

### 10.3 Setup

The edge is the only party relying on soundness, so **the edge may run the setup alone**: for soundness it needs one honest contribution, and it trusts itself. No ceremony with outsiders is needed, and none adds anything to ZK, which verification provides.

A sidecar must never know a trapdoor, which holds because it contributes nothing. Per circuit shape:

1. Phase 1, once per domain size, reused across shapes: contribute, seal with a public beacon.
2. Phase 2 per shape: contribute, seal.
3. Publish the transcript and resulting keys, release-pinned by hash.
4. A prover host verifies once per release (10.2), then caches.

Where the bytes live is the owner's answer to `smtpproof-start-key-distribution`: keys and transcripts download on a host's first send from a public path on ur.io, with no token and no account, pinned by hash in the release. Verification makes the path need no trust. The server behind it sees which IPs fetch, which marks a prover host, so §2.8 gains a row for it. Before the first production setup the 22 shapes are cut to what M7's census justifies.

**The KeySet** (`setup_keys.go`). A release's keys are one directory: `keyset.json`, which names the beacon, each domain size's phase 1 contributions, and per shape its phase 2 contributions, proving key and verifying key, each file by its SHA-256; and those files. The release pins `keyset.json` by its own SHA-256, so every file is pinned through it. A shape's name in it spells every dimension of the shape, so a changed shape is another name.

- The edge runs `smtpproof/setup -out <dir> -beacon <hex>`, which is `RunSetup`: phase 1 once per domain size, phase 2 per shape, and the keys each transcript fixes, derived by the same `VerifySetupTranscript` a prover host runs. It prints the pin.
- `NewVerifier` takes the KeySet's verifying keys, each checked against its hash. The edge ran the ceremony, so it needs no transcript check.
- A prover host runs `KeySet.VerifyProvingKeys` once per release, at idle: for each shape it compiles the circuit from its own source, checks the transcript against it, and caches the proving key the check produced, only if it is the key `keyset.json` names. `NewProver` then loads each shape's key from that cache on first use, by its hash. A shape not yet verified, or a cached file changed since, has no keys, so its parts are refused and the host queues its mail.
- Nothing downloads yet: a host points `OpenKeySet` at a directory. The ur.io path waits for its §2.8 row, and no release pins a KeySet until the first production setup.

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

Against DESIGN-DETAILS 3.2.6's table, built from compiled gadgets and estimates before these circuits existed, the compiled circuits moved three pools by a block: each msg shape holds one more server block, and AES's hdr shape one more rest block, 16 more header octets a record. No unit count of 3.2.6 or 3.4 moves.

What no shape holds, each failing closed as above:

- **An envelope past one group.** An env part holds MAIL and 12 RCPTs of short addresses under AES, 19 commands under ChaCha20. DESIGN-DETAILS 3.2.4's envelope groups, one env part a group, are the planner's (SMTP-M9-39); until it lands the prover sends one group, and a send whose envelope one env shape cannot hold is refused before MAIL.
- **A reply record past the env shape's server blocks**, 639 octets under AES or 1,215 under ChaCha20, or an EHLO reply in more records than the env shape's server blocks: no shape, and the send ends before MAIL (DESIGN-DETAILS 3.5).
- **A header block past 16,384 octets** (`HeaderBlockMaxByteCount`), which assembly refuses; and a header block whose single fields and fixed signature do not lie in its first record, which Z5 refuses (DESIGN-DETAILS 3.2.3).

## 11. Costs

### 11.1 Gates

D-SMTP-16, at p95: BDAT with a 4 KiB header block and 10 recipients, ≤ 10 s for π1 and ≤ 30 s for π1 to π3 on an Apple M1 MacBook Air (8 GB), ≤ 60 s on an m5.large. DATA with a 100 KiB message, ≤ 10 min and ≤ 20 min.

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
| Z2-Z4, a pool block with the local table (π2's envelope) | 12,545 under AES, 25,345 under ChaCha20 | per block, about 55 an octet beyond the keystream | |
| Z2-Z4, a pool block of literals only (π1, and π3's commands) | 11,969 under AES, 23,041 under ChaCha20 | per block, about 19 an octet beyond the keystream | |
| Z5, the header block's first record with its keystream | 57,264 under AES, 32,429 under ChaCha20 | per 64 header octets, about 166 an octet beyond the keystream | well under AES's 725 an octet |
| Z5, a later header record with its keystream | 52,513 under AES, 27,678 under ChaCha20 | per 64 header octets, about 91 an octet beyond the keystream | 90, DESIGN-DETAILS 3.2.4's prototype |
| Z7-Z9, a part's server records with their keystream | 51,758 under AES, 26,908 under ChaCha20 | per 64 octets, about 80 an octet beyond the keystream, Z9's window and the public flags' rules included | |

Some readings of these:

- A key's length does not move Z1: AES's 16-octet key and ChaCha20's 32-octet key each come from one HMAC, so both suites' Z1 cost the same.
- A compression over the constant initial state, as each HMAC pad state is, costs a little less than one over a private state, since gnark folds the constant terms.
- Z1 is proven once a connection, in the key part, which derives both directions and publishes a perfectly hiding commitment C to their keys and IVs; every later part opens C instead (DESIGN-DETAILS 3.2.3; QD-712). Where each part re-proved Z1, a BDAT send spent 515,322 + 2 × 708,498 = 1,932,318 constraints on it under 1.3; it now spends 708,498 once and an opening a part. The commitment's gadget adds a window's point by the complete law in six constraints, where DESIGN-DETAILS 3.2.2's prototype took seven.
- H_sh and H_sf enter HMAC messages, and gnark's `Xor` asserts its inputs boolean, so 512 constraints of 1.3's Z1 are booleans on public wires the verifier computes. Marking those wires boolean without a constraint would save them; it is not done.
- The 1.2 figure adds back what the twin's private IV costs over the real one: a 1.2 IV is the salt and 8 zero octets, so the real shape's nonce takes the explicit nonce without a XOR, 64 constraints a pool block.
- The pool, header and server rows are each two test shapes a few blocks apart, Z1 left out, so a row is whole blocks: keystream, opening and what the octets are checked against. `TestRecordPoolCostIsSpecMds`, `TestHeaderScanCostIsSpecMds` and `TestReplyScanCostIsSpecMds` hold them. They are 1.3's; under 1.2 a pool block costs 64 fewer, as above.
- Z5's automaton costs about 178 constraints an octet beyond the keystream, a quarter of AES's 729, so a 4 KiB header block spends about 730,000 on Z5 and about 3M on its keystream. Counting the one-click field by name (reading 25) added 6 an octet.
- A recipient costs π2 its RCPT record, 3 AES blocks for an address of up to 35 octets, and π3 its reply, 1 or 2 server blocks. So 100 recipients add about 3.8M constraints to π2 under AES and 1.3M to 2.6M to π3 (10.4, section 14).

### 11.3 The first measurement

A scratch Groth16 run over chained compressions, gnark v0.15.0, Apple M4 Pro (14 cores), on a machine shared with other builds, so noisy:

| Constraints | Cores | Prove | Constraints/s |
|---|---|---|---|
| 4,237,153 | 14 | 8.5 s | 500,000 |
| 4,237,153 | 8 | 8.2 s | 519,000 |
| 4,237,153 | 4 | 9.6 s | 443,000 |
| 4,237,153 | 2 | 17.4 s | 243,000 |

Verification took 2.4 ms. Setup took 2 min 37 s. Peak memory was 10.5 GB, with compile and setup in the same process, so it overstates proving alone.

Draft 1 drew its budgets from this run and from ORIGO's own m5.large figure, 400,000 constraints in 9.8 s, before any shape existed. 11.2's gadgets and 11.4's whole sends, measured on the real shapes, replace those estimates. Neither reference machine has been measured yet: that is SMTP-M9-32's bench, and the m5.large's figure stays ORIGO's until it runs there (section 14).

Levers, none taken: a hiding commitment to the keys, proven once, so that later parts skip Z1 (saves about 1.4M of a BDAT send's constraints, but D-SMTP-22 forbids it as written, and the owner kept it so); lookups under a reviewed commitment argument (10.1, 10.2); sharing AES's first round across blocks of a record; a designated-verifier prover (Later). See section 14.

### 11.4 Whole sends, measured

These measurements are of the retired catalog of 22 shapes over four domain sizes, π1 to π3 with Z1 in each, before the key commitment and unit shapes (DESIGN-DETAILS 3.2). They stand as that catalog's record and as the figures DESIGN-DETAILS 3.1 and 3.4 compare against. The eleven unit shapes' compiled sizes are 10.4's; their times, a unit each part, are SMTP-M9-32's bench on both reference machines, and `TestMeasureWholeSend` has not been run under them.

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

What this says, neither reference machine having been measured:

- A whole BDAT send costs 42 to 64 s of CPU, and on this machine's 14 lightly loaded cores it took 14 to 15 s. The M1's eight cores likely do a third to a half of that parallel work, so its 30 s bar is close and may be missed.
- The m5.large's 2 vCPUs are the two hyperthreads of one server core, which likely does under half the work of an M4 Pro performance core. On that guess π1 to π3 take about two minutes there, so the 60 s bar is likely missed by about 2×, near 11.3's estimate.
- Peak memory grows with the cores the prover gets: AES's π3 peaked at 1.7 GB under heavy load, TLS 1.2's at 6.3 GB on lightly loaded cores. Whether π3 fits the 8 GB M1 beside everything else it runs is unproven, and a prover host may need to cap its parallelism.
- DATA at 100 KiB is π1 to π3 and about 48 later parts: about 17 minutes of CPU here under 1.3 with AES, 10 with ChaCha20 and 16 under 1.2. The M1 meets its 10 minutes only by keeping most of its cores busy, and the m5.large's one core likely misses its 20, as it misses 60 s for BDAT.
- TLS 1.2's DATA π3 peaked at 7.0 GB on lightly loaded cores, within 1 GB of the M1's 8 GB, so on an M1 that part needs its parallelism capped or its shape split before 1.2 DATA can be relied on there.

The owner's answer to `smtpproof-start-z1-reproof-cost` keeps D-SMTP-22 as written and has SMTP-M9-32's bench measure both machines. If the m5.large misses, its row of D-SMTP-16 is relaxed to the measured number.

## 12. State of the code

Kept honest as the module grows. Anything not listed as built fails closed.

| Piece | State |
|---|---|
| `tls_*.go`: the TLS client, 1.3 and 1.2, HelloRetryRequest, CertificateRequest | Built. Checked against Go's `crypto/tls` server, whose key log confirms HS and the master secret regenerate its own secrets; against RFC 8448's trace through HS, MS, SHTS, CHTS, the handshake keys, the server application key and IV and the resumption secret; against NIST ACVP's TLS 1.3 KDF vector, which gives both application traffic secrets from MS; and against the TLS 1.2 PRF's published vector. RFC 8448's application traffic secrets are not derived from its MS: that needs its hash through the server's Finished, and no copy of the RFC was at hand. `FuzzTlsParse` runs the four parsers over one stream split at every offset, from a committed corpus of real flights, and compares each ClientHello with `crypto/tls`'s server's reading and each ServerHello with how `crypto/tls`'s client answers it: no ServerHello the parser takes is one `crypto/tls` cannot decode, reads at an unsupported version, or refuses for a 1.2 suite E1 covers |
| `relation.go`: Z1-Z9 over plain Go values | Built, both versions and modes. Each check has mutated witnesses that it alone refuses |
| `mutate_*_test.go`, `testdata/mutations/table.md`: §22.10's mutated witnesses | Built (SMTP-M9-29). For each of E1-E3 and Z1-Z9, on every leg and in each mode the check applies to, a break of one honest connection that the gate's relation and the checker each pin on that check alone, refused by the circuit at its part (π1's with Z1 in its circuit) or by the gate on its own; the table is held to the registry and lists the cells no witness can break alone. Holding the two readers to one table found two disagreements, now settled: the gate passed a part's record of another outer type to its verifier, where a real proof would have verified it (reading 26), and the checker named a part with a record count its index has no roles for Z4 or Z6, where the gate refused it as E3 (reading 28) |
| `edge.go`: E1-E3 | Built, as one state machine per connection that ends at its first refusal, refusing a part's record of another outer type before verifying it (reading 26). Each check has refusals of its own, over replayed real connections. `TestEdgeInputsEqualServerKeyLog` holds Z1's inputs to the MX's own key log, after a HelloRetryRequest too; every run of the handshake, 1.3's sealed flight included, passes split across two records at every offset with Z1's inputs unchanged; a SHA-1 signature that verifies is refused in both versions; `FuzzEdgeHandshake` edits real handshakes and holds the gate to its bounds, to passing nothing after a refusal and to no cut before application data; `FuzzEdgeRecordOrder` interleaves records, parts, late server records and parts proven again, and holds every message record behind coverage. `MailForwarded` tells the engine when MAIL went |
| `prover.go`: a whole connection | Built: BDAT, DATA, pipelined or paced, a part proven again over a late ticket. It checks its own witness before proving. `Measure` first proves a part of each keyed suite's largest shape, DATA's π3, so a host that cannot records nothing (reading 22), then one full later DATA part per suite with keys, and holds later sends to the slowest suite's cap |
| `circuit_*.go`: Z1-Z9 in R1CS | Built for every suite. Each gadget is tested against the standard library, and Z2-Z9 differentially against `relation.go`, each case through the relation and the solver alike: the envelope at 1, 10 and 100 recipients and every template break of SMTP-M9-22's list (`circuit_records_test.go`); the sender's own assembled and signed messages as Z5's corpus, and every break of SMTP-M9-23's list in both modes (`circuit_headers_test.go`); every break of SMTP-M9-24's list beside an honest twin, CHUNKING offered only before TLS through sidecartest's ScriptedMx among them (`circuit_replies_test.go`). The header-block breaks also go through the gate and the independent checker beside the circuit (`circuit_agreement_test.go`). 11.2's sizes are measured and held by `TestGadgetSizesAreSpecMds` and the per-block tests it names; 10.4's shapes by `TestSpecMdNamesEveryProductionShape` |
| `backend.go`: Groth16 prove and verify | Built. One real proof of π1 runs in the ordinary tests, and fails one bit off in any of its 965 public inputs (`TestGroth16RefusesEachPublicInputOneBitOff`); no shape carries a public wire that no constraint reads (`TestEveryPublicWireIsConstrained`, reading 29). Every leg's honest BDAT and DATA connection passes the gate, the checker and each part's circuit through `edgeSession`, π1's with Z1 in it (`TestMutatedWitnessHonestTwins`). `TestMeasureWholeSend` has proved whole sends that the gate accepted, BDAT and DATA on all three legs (11.4). `BenchmarkPi3Memory` measures π3's peak in a process that only proves, as a host would; it has run once on the shared M4 Pro (11.4), never on the M1 |
| BDAT's unopened body (9.5) | A sidecar that pads its body records or puts a KeyUpdate among them, and sends the proven QUIT without waiting, smuggles nothing through a `crypto/tls` MX: past QUIT's 6 octets of padding the chunk never completes; short of them the MX takes a message of the declared length with the proven header block and reads at most 5 octets as a command; a KeyUpdate kills the connection at QUIT's tag (`part_bdat_test.go`) |
| DATA at D-SMTP-16's size | A 100 KiB message, leading dots stuffed, goes through the gate in 54 parts on every leg, each fitting a production shape (`TestSendDataOf100KiBInPartsThroughTheGate`) |
| `spec_test.go`, `testdata/vectors/`: this document held to the code | Built (SMTP-M9-33). `TestSpecNamesEveryCheck` requires each of E1-E3 and Z1-Z9 to have its definition here, tests of its own and a row in the mutation table; the vectors of 5.1 reproduce on every run |
| `setup.go`, `setup_keys.go`, `setup/`: the ceremony, its verification and the KeySet | Built and tested end to end on small circuits: a tampered file, another circuit's transcript, keys the transcript does not fix and a changed cache file are each refused. `TestAKeySetProvesARealEhlo` ran it once at π1's real size under ChaCha20, 538,366 constraints over a domain of 2^20: the ceremony, the prover host's check and a proof the edge's own key accepted took 56 minutes and about 130 CPU-minutes on the shared M4 Pro, so the 22 production shapes, up to 2^23, will take many hours. Never run at production size |
| `checker/`: the public relation, written apart | Drafted from this document and DESIGN.md alone, importing nothing from this module. It passes every leg's honest BDAT and DATA connection, and names the same failing checks as the gate and `relation.go` over a set of mutations (`checker_agreement_test.go`). Written by an agent, not by an engineer outside the circuits' authorship, which §22.10 asks for |
| `smtp_proof.go` in the root: the injection seam | Built, with `MailForwarded` and `Measure`. `cli/smtp_prover.go` builds the prover from the pinned KeySet; nothing calls it yet, and server does not inject a verifier, because `ur daemon`, `SmtpSender` and `smtpedgeservice` do not exist |

Not built, each failing closed as stated:

- **Keys.** No production setup has run, so no release pins a KeySet, ur injects no prover and server no verifier, and both sides would refuse every part. The ur.io download path is not built: it waits for its §2.8 row (section 14).
- **More than one late ticket in a later DATA part.** A later part over a late NewSessionTicket takes a 1.3 shape holding one ticket of up to 255 octets (`TestALaterDataPartCoversALateTicketAndNoReply`); a longer ticket, or several, finds no shape and the send fails. 1.2 sends no ticket here, and any reply during the body stays unprovable (Z8). π3 handles tickets within its server blocks.
- **Larger capacities.** Shapes hold a 4 KiB header block, about 10 recipients and a 2 KiB DATA part (10.4). Anything larger finds no shape and fails before MAIL or at the part. `smtp_recipients_per_message` allows 100, and whether a class or the sender holds more is the owner's call (section 14). Server blocks count records as well as octets: AES's 24 hold 12 replies only while each is under 32 octets, and replies that carry a queue or trace id run longer, so at about 5 recipients such an MX finds no shape. M7's census should size these. `TestProductionShapesHoldTheSpeedGatesSends` holds D-SMTP-16's sends to the shapes on every leg.
- **Scripted MXs for the rest of FS-31.** The scripted MX runs over `crypto/tls`, which cannot send a late ticket, a KeyUpdate or a padded record on demand. Those cases are tested at the relation and gate, and through RecordMx for tickets and padded replies, not end to end through the circuits. A client's padded or KeyUpdate body records are tested end to end (above), and FS-31's full matrix is SMTP-M9-30's.
- **Classes past the speed gate's send**, until `smtp-m9-22-recipient-classes` is answered (section 14).

**Names.** The plan's tasks SMTP-M0-03 to SMTP-M9-25 name their Provides before the code existed; the code took these names, and where the two differ this document's are the ones that stand:

| Plan's name | In the code |
|---|---|
| `circuitSha256Compress`, `circuitSha256` | `sha256Compress`; `sha256Padded`, `sha256Absorb`, `sha256Sum` (`circuit_sha256.go`) |
| `circuitHmac`, `circuitHkdfExpandLabel`, `circuitTls12Prf` | `circuitHmacKey` with `sum`, `expandLabel` and `prf` (`circuit_sha256.go`, `circuit_keys.go`) |
| `circuitWord` | `circuitWord`, with `circuitByte` (`circuit_bits.go`) |
| `circuitAes128Block`, `circuitChacha20Block` | `aesEncrypt` over `aesExpandKey`'s round keys; `chachaBlock` (`circuit_cipher.go`) |
| `circuitAesKeystream`, `circuitChachaKeystream`, `circuitNonce13` | `circuitKeystream`: `newCircuitKeystream` and `block`, whose nonce is the IV XOR the counter's upper 64 bits (`circuit_part.go`) |
| `circuitXorOpen` | `openBlock` (`circuit_part.go`) |
| `circuitKeys13`, `circuitKeys12`, `circuitSessionKeys` | `tls13CircuitKeys`, `tls12CircuitKeys`, `circuitKeys` (`circuit_keys.go`) |
| `witnessKeys`, `newWitnessKeys`, `witnessRecords`, `witnessHeaderBlock`, `witnessReplies` | `assignWitness` over `partWitness`; `assignRecordBlocks`, `assignHeaderPublic` and `assignHeaderPrivate`, `assignServerRecords` (`circuit_part.go`, `circuit_message.go`, `circuit_replies.go`) |
| `circuitRecords`, `circuitTemplate` | `checkPool` over `clientRecordTemplate`'s templates (`circuit_part.go`) |
| `circuitHeaderBlock` | `checkHeaderBlockCircuit` (`circuit_message.go`) |
| `circuitServerRecords`, `circuitReplies` | the server blocks of `partCircuit` and `checkReplies` (`circuit_part.go`, `circuit_replies.go`) |
| `circuitTail`, `circuitDataLines` | QUIT's and the end mark's templates in `clientRecordTemplate`, and `checkBody` (`circuit_message.go`) |
| `shapeEnvelope`, `shapeHeaders`, `shapeReplies`, `shapeBdatPi1` to `shapeBdatPi3`, `shapeDataPart` | entries of `partShapes()`, by kind and dimensions (`backend.go`) |
| `circuitPartProver`, `circuitPartVerifier` | `groth16Backend`'s `provePart` and `verifyPart` (`backend.go`) |
| `SmtpProverMeasure`, `Prover.Measure` | as named: the root type and `SmtpProver.Measure`, `Prover.Measure` (`prover_measure.go`) |
| `TestMutatedWitness*`, the M9 evidence table | as named, one test a check (`mutate_edge_test.go`, `mutate_circuit_test.go`), and `testdata/mutations/table.md` |
| `smtpproof/testdata/vectors/` | as named, with `statements.json`, six fixed connections and one π1 proof (5.1) |

## 13. Readings taken

Each is one reading of a point DESIGN.md leaves open, followed because it changes no D- item, format or invariant. A reviewer should challenge them. Reconciled with the owner's answers as of draft 2: reading 14 is now the owner's decision, the forms of reading 19 for the issued values are plan-SMTP-small-readings #3 and #4 as answered, and no answer touches the others.

1. **One command per record** (4.2). Z3's "lengths fix offsets" and §2.8 smtp-2's "each command's length, every RCPT TO's included" imply it.
2. **The header block is one record, ending at its CRLF CRLF** (4.2, Z5). It bounds the header block at the TLS record maximum of 16 KiB and adds nothing to what smtp-2 already lists.
3. **DATA records are whole lines** (Z6), which makes §14.5's carried scan state the constant "line start". RFC 5322's 998-octet limit keeps this satisfiable.
4. **MAIL takes no parameter but REQUIRETLS** (4.2), following Z4's literal form: no `SIZE=`, `BODY=` or `SMTPUTF8`. So bodies are 7-bit clean, and a non-ASCII address gets a DSN.
5. **`local` drops `%` and `!`** (4.2). §14.5 says every RCPT is at the recipient domain, and percent or bang routing would undercut that on an MX that honors them.
6. **Z5 proves its signature on §14.6's second signature** (Z5.5), whose `h=` is a fixed list, so "covering them" is a literal comparison. Other DKIM-Signature fields are unconstrained, which reads Z5's "once each" as applying to this one.
7. **`d=` equals `header_from_domain`** (Z5.5), from strict alignment (§14.6).
8. **`message_id` carries no angle brackets** in the preamble, and Z5 adds them.
9. **E1 fixes the client's second flight** to one record of Finished's length (section 6), which §14.5 implies by "no early data" but does not state.
10. **The edge decrypts the 1.3 flight only for E2.** E2 checks the server's signature and does not validate the chain (section 1).
11. **π1's `mode` is 0** and not part of its statement. §14.5 says `mode` is fixed from π2 on.
12. **A padded 1.3 server record is unprovable** (Z7). No text requires padded server records, and the census will show whether any MX sends them.
13. **Whether a server record is a ticket stays private** (Z7). Making it public would be cheaper, and would add a value §2.8 smtp-2 does not list.
14. **The declared count follows the owner's answer to `plan-SMTP-preamble-byte-count`** (`prover.go`), so this one is decided rather than read. The sidecar declares the count of the mode it expects. The mode comes from the EHLO reply alone (Z9, reading 17), never from the count, and where that mode cannot meet the declared count the prover stops before MAIL and names this mode's count for one new connection. So an MX offering CHUNKING gets BDAT unless DATA is forced for interop (§14.5), and too_large means DATA was the only mode.
15. **The fixed signature leads with `h=`** (Z5.5), since DKIM's tag order is free and a constant prefix makes "exactly one" a sum.
16. **A chunk short of octet n at QUIT is a record cut** (E3). §14.7 names only a body past octet n, but Z6 requires n exactly and an honest sidecar never falls short.
17. **Z9 reads its keyword inside one record** (Z9). The window holds the CRLF before the line, the line and its own CRLF, so a line at a record's edge does not count, and the sidecar, which applies the same test, sends such an MX DATA. That costs coverage, never soundness, and the census will show how many MXs write a line per record.
18. **A header field name never starts with a dot, in either mode** (Z5.3). DATA needs it, since an MX deletes that dot. BDAT does not, but one rule is simpler, and a sidecar writing the header block has no reason to emit such a name. RFC 5322 allows one, so a message a mail client wrote that way fails the send.
19. **The preamble's forms** (section 6). §14.5 calls these values proven and says the edge resolves `recipient_domain`, but states no syntax. The proofs mean what the design says only if a template holds one command, so the forms are refused here, whatever the engine's own gate does.
20. **The gate ends at its first refusal** (section 6). §14.7 says a refused record or part cuts the connection, and the root's seam says an error ends it; the gate now ends itself too, so nothing is released after a refusal even where a caller would go on.
21. **MAIL counts as forwarded when a call hands it out** (`MailForwarded`). A record cleared by a call that then cuts is returned to no caller and never written, so the unit §14.7 charges "once its MAIL record is forwarded" is not charged for it.
22. **A host's DATA cap is the slowest suite's** (`Measure`). A later part's circuit is fixed, so its cost does not depend on what it carries: the host proves one full part per suite it holds keys for, its rate is a part's octets over the slowest suite's time, `smtp_data_proof_bytes` is that rate over §14.4's 2 h, and a host whose part takes longer than 2 minutes sends nothing in DATA mode. π1 to π3 are left out of the 2 h, a few parts' worth. Before any of this the host proves one part of each suite's largest shape, DATA's π3, over a session made up for it, as plan-SMTP-small-readings #19 has it: a host that cannot, for want of memory most likely, records no `p/` and only queues. `Measure` is on `SmtpProver`, since the sender that records `p/` holds only that seam.
23. **A template no plaintext of the record's length can fill is refused as E3** (section 5). The edge refuses such a part before verifying it, so it is the gate's refusal, and the independent checker names it so too, though the relation would fail Z4 on it.
24. **`smtpproof/setup` stays where SMTP-M9-27 puts it.** C-23 moves into `sidecarctl` the commands plans put under `bringyourctl` or `warpctl`; this one the plan puts under `smtpproof`, and the root module cannot require `smtpproof`. Its work is `RunSetup`, which `sidecarctl` could call if the owner wants it there.
25. **On a BULK message `List-Unsubscribe-Post` is a single field** (Z5.6). DESIGN.md's Z5 asks for the field when BULK is set, and RFC 8058 §3.1 says it holds the single key/value pair `List-Unsubscribe=One-Click`. Counting only lines equal to that literal, as draft 1 did, let a continuation turn the field's value into something else, or a second field of another value stand beside it, and the relation, the circuits and the checker all passed both. So the field is counted by name, as rule 4 counts its four, held to the literal and to no continuation. A message without BULK keeps whatever such fields MAIL wrote.
26. **Z3's outer type, and all of 1.2's Z3, are the edge's** (sections 6 and 7). A record's outer type is public and the circuit sees only ciphertext, so a part whose record is not application_data is refused before verification, as E3, as the checker refuses it: the relation named it Z3, while a real proof of it would have verified, its record able only to meet E1. In 1.2 Z3 holds nothing more, the plaintext's length being the record's, so no witness can break Z3 alone there; and Z7's 1.2 half, a server record's type, is E1's likewise. The mutation table lists these cells as no witness's (section 8).
27. **A server record's opening is Z2's** in `relation.go` and the checker, as a client record's is, and Z7 is what an opened server record may hold. Z7's text names the opening too; section 8's row for replayed server replies means it, and the relation's Z2 is where a replay fails.
28. **A part whose record count its index has no roles for is refused as E3** (4.3's table). Roles follow from public values, so the edge refuses such a part before verifying it, as reading 23 has it for a template. The checker named it Z4 or Z6 until SMTP-M9-29 held the two readers to one table.
29. **Every public wire is read by some constraint** (5.1). Groth16 weighs each public input by its own element of the verifying key, the identity for a wire no constraint reads, so such a wire verifies at any value. That was harmless where the edge always assigns the wire zero, as it does every wire found unread, but a verifier written apart from this one could not know it. So a shape carries `IsLocal` only on blocks that can hold a local part, and binds `DataMode` where only π3 reads it, `ResumeTwoBlocks` in 1.3 and a body pool's last `Start` to that zero. This changes public input counts (11.4) and no gadget's cost.

## 14. Open

Raised to the owner (`.stack/questions/`, one file each), and answered in `.stack/decisions/RESOLUTIONS.md`:

- `smtpproof-start-shts-wire`: `SmtpHandshake{send_id = 1, shts = 2}` as `SMTP_HANDSHAKE = 0x1607`, sidecar to edge as soon as the handshake ends, answered by `SmtpHandshakeResult{code = 1}` as `0x1608`, 1 OK and 2 INVALID, on which the edge ends the connection. TLS 1.2 sends none. SMTP-M9-01 adds them to `protocol/smtp.proto`; the root's `DiscloseShts` on either side already carries them.
- `smtpproof-start-key-distribution`: as 10.3 now states. The KeySet and its loading are built; the ur.io download path waits for its §2.8 row, which is the design-records track's to add. Until a release pins a KeySet, no prover is injected, hosts only queue, and the verifier refuses every part.
- `smtpproof-start-z1-reproof-cost`: keep D-SMTP-22 as written, measure both reference machines with SMTP-M9-32's bench, and relax the m5.large row if it misses (11.4).
- `plan-SMTP-preamble-byte-count`: applied in `prover.go` (reading 14).
- `plan-SMTP-data-connection-lifetime`: grants become per `ur/` service, SOCK-M9-01's, with nothing in this module.

Raised and not yet answered:

- `smtp-m9-22-recipient-classes`: whether the shapes gain a class for §20.4's 50 and 100 recipients a message, at 12 shapes a class, or the sender splits a domain's recipients over connections of about 10, at a unit each (10.4). Until answered the shapes stay as 10.4 lists them, and a larger send finds no shape and ends before any message octet: before MAIL where π2's pool is what it overflows, after it where π3's server blocks are.

Evidence M9 still needs, none of which this draft provides (§22.10):

- two non-authors' written soundness argument;
- a checker of the public relation by an engineer who did not write the circuits: `checker/` is a draft of it, written apart from the prover tree but by an agent of this track;
- D-SMTP-16's speed, coverage and interop runs on its named hardware and census MXs;
- FS-31 and FS-123 on T2 and T3;
- `BenchmarkPi3Memory` on the 8 GB M1, which decides whether π3 fits there or a host caps its parallelism (11.4);
- a review of the vectors of 5.1 against an implementation written apart, the bytes the exit review freezes.
