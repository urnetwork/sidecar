# smtpproof: what the outbound-mail proofs prove

*Draft 1, 2026-11-06. Not frozen: this specification freezes at M9's entry review and its bytes at M9's exit review (DESIGN.md §22.10, D-PHASE-7). Until then every field, encoding and shape here may change.*

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

The statement a circuit proves is this vector, encoded as field elements in the order the shape defines. Encoding is frozen with the bytes at M9's exit.

## 6. Checks at the edge

`EdgeSession` runs E1-E3. They are ordinary code, not circuit: each fails closed, and each failure before the first forwarded application record is a refusal, not a record cut, unless 14.7 says otherwise.

**E1, handshake shape.** Over the relayed handshake:

- The client's first bytes are a ClientHello in a record of type 22. Its extensions hold no `pre_shared_key`, `early_data` or `session_ticket`, its session id is empty, and its `server_name` is the MX host.
- The ServerHello selects 1.3 with `AES_128_GCM_SHA256` or `CHACHA20_POLY1305_SHA256` and no `pre_shared_key`, or 1.2 with one of section 4.1's two suites and no `session_ticket`.
- 1.3: after the ClientHello the client sends at most one change_cipher_spec, then exactly one record of type 23, whose length is that of the client's Finished under the suite, plus an empty Certificate's 8 octets when the flight held a CertificateRequest. Nothing else passes before π1 verifies. This is what makes "no early data" hold for the client's second flight too.
- 1.2: the flight is exactly ServerHello, Certificate, ServerKeyExchange, optional CertificateRequest, ServerHelloDone; then optional empty Certificate, ClientKeyExchange, change_cipher_spec, one Finished record; then the server's change_cipher_spec and Finished record. Any other shape fails, because S_ckx and SF depend on it.
- Once application data starts, each client record's outer type is application_data and its version 0303. In 1.2 a server record of type handshake is refused too: no renegotiation.

**E2, the server's signature.**

- The edge dialed the MX it resolved (§14.4).
- 1.3: from the disclosed SHTS the edge derives the server handshake key and IV, opens the server's flight, checks CertificateVerify over `Transcript-Hash(ClientHello .. Certificate)` under the leaf key, and checks Finished under `HKDF-Expand-Label(SHTS, "finished", "", 32)`. Only then does it compute H_shts and H_sf.
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

Parts are accepted in `index` order. `first_record` continues from the previous part, `mode` never changes from π2 on, and `server_record_count` never falls and never exceeds what was relayed. A part resent under its `send_id` and `index` is idempotent. One proven again with a later `server_record_count` replaces it. Once the MX has closed, outstanding parts are moot.

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

**Z3, framing.** 1.3: each opened client record's plaintext, of length `len - 16`, ends in the octet 17 at its final position, which with section 4.2's templates rules out padding and every other inner type, KeyUpdate included. 1.2: the outer type is application_data (E1), and the plaintext length is `len - 24`.

**Z4, envelope.** The opened records match, in order, the templates for `EHLO`, `MAIL`, exactly `recipient_count` × `RCPT`, then `BDAT n LAST` or `DATA`. With the part's contiguous ranges and E3, these are all the client records before the message: one transaction.

**Z5, header block.** The header-block record's content `H` satisfies:

1. Every octet of H is HTAB, SP through `~`, CR or LF. CR occurs only before LF, and LF only after CR.
2. H ends in CRLF CRLF, and no earlier line is empty.
3. The first line is not a continuation, and every line that does not begin with SP or HTAB begins with one or more octets of 21-7E other than `:`, then `:`. So `From :` is refused rather than left to each receiver's reading of obsolete syntax.
4. Exactly one line has each of the field names `from`, `message-id`, `x-ur-ref` and `feedback-id`, compared without case, and no continuation follows any of them. Each has its literal form:
   - `From: ` [phrase SP] `<` local `@` header_from_domain `>` CRLF, where phrase holds only `local` octets and SP, so `From` holds one address. Encoded words fit in phrase, with no `"`, `,`, `:`, `;`, `<`, `>` or `@`.
   - `Message-ID: <` message_id `>` CRLF
   - `X-UR-Ref: ` x_ur_ref CRLF
   - `Feedback-ID: ` feedback_id CRLF
5. Exactly one line begins with the constant `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; `, and it continues `d=` header_from_domain `; s=` dkim_selector `; `. This is §14.6's second signature, the one that survives masked reports. `h=` comes first because DKIM's tag order is free, and a constant prefix is what makes "exactly one" cheap to count in the circuit. The fuller signature and any other are unconstrained.
6. If BULK is set, exactly one line is `List-Unsubscribe-Post: List-Unsubscribe=One-Click` CRLF.

**Z6, the end of the message.**

- BDAT: the head's chunk octets are exact (opened), the body's are bounded by E3's count, and together they reach `message_byte_count` exactly at a record boundary, which the edge checks as records stream. The record at `last_record` opens to exactly `QUIT` CRLF.
- DATA: `message_byte_count` counts the octets of the header-block and body records. Every such record begins at a line start and ends in CRLF, holds no bare CR or LF, and no line in it is exactly `.`. The final records open to exactly `.` CRLF and `QUIT` CRLF. A record boundary is therefore always the scan state "at line start", so §14.5's carried state is that constant.

**Z7, server records.** The private server key and IV of Z1 decrypt every server record the part adds, at its `seq`. Each is either application data, whose content joins the reply stream, or in 1.3 a NewSessionTicket: inner type 16, first octet 04, content skipped. Which is which stays private. Any other inner type, a KeyUpdate included, fails. In 1.3 each server record is unpadded: a padded one is unprovable and ends the send.

**Z8, replies.** The reply stream parses as RFC 5321 reply lines: three digits, then `-` or SP with text, or CRLF directly; text holds no CR or LF. A reply is its lines through one without `-`. Then:

- π2's stream is exactly one reply, every line coded 250.
- π3's holds exactly 1 + R replies, each coded 2xx, then in DATA mode one reply coded 354.
- Later parts add no reply: a server record past the message's start is unprovable, and so the part cannot release more message records. In BDAT mode this ends at the chunk; in DATA mode the sidecar stops.

**Z9, mode.** `mode` is public and fixed from π2. For BDAT, the EHLO reply of Z8 holds a line that is exactly `250-CHUNKING` or `250 CHUNKING`, keyword compared without case, and it is not the reply's first line. BDAT to an MX lacking it is unsatisfiable. DATA has no such condition: DATA to an MX offering CHUNKING is allowed, and interop forces it (§14.5).

## 8. Which adversarial case each check stops

D-SMTP-16's corpus, FS-31 included. Each row must fail before any effect, with honest controls passing.

| Case | Stopped by |
|---|---|
| Key substitution: one ciphertext, benign under one key, real under another | Z1 ties the key to the observed handshake |
| Record splits, a command split or two in one record | Z3 and Z4: one command per record, template by length |
| Replayed server replies | Z7: a record decrypts only at its own `seq`, which the edge assigns |
| A pipelined second transaction | Z4 and E3: every client record is proven; a second MAIL has no part |
| Smuggled headers, a second From | Z5.3, Z5.4 |
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

### 9.5 BDAT's unopened body

The MX reads chunk octets from records. An honest edge counts each body record as carrying `len - 17` (or `len - 24`) octets. A 1.3 record carries at most that, and fewer if padded or if it is not application data; a 1.2 record of clear type application_data carries exactly that. So at every point the MX's count is at most the edge's, and the edge's never passes n. Hence:

- If every body record is unpadded application data, the MX reaches octet n exactly at the proven QUIT, and sees `QUIT`.
- Otherwise the MX is short of n when the QUIT record arrives, and the QUIT's octets are chunk data, or the chunk ends inside them and the MX reads at most the 5 remaining octets as a command. No client record follows (E3 step 6), and 5 octets hold no transaction.
- A KeyUpdate in the body makes the MX change keys, so the proven QUIT, sealed under the old key, fails its tag and the connection dies.

In no case does a body octet reach the MX's command parser.

### 9.6 DATA

Every octet is opened. Z6's no-bare-CR-or-LF and no-`.`-line conditions mean no receiver, strict or lax about line endings (CVE-2023-51764), sees an end of data before the proven end mark. A reply arriving after a message record was released, such as a late refusal, holds the next message record (E3 step 5), and a refusal is unprovable, so the connection ends with no further octets.

### 9.7 Conclusion

9.3 gives the exact client command stream, Z4 gives its shape, 9.4 gives that the MX acted on it as a transaction, and 9.5 and 9.6 that nothing beyond it reaches the command parser. Z5 and Z6 give the message's properties, each over proven octets. That is section 1's claim.

### 9.8 Known weak points for the reviewers

- Z5 constrains what receivers parse only as far as receivers agree with RFC 5322 on the normal form. A receiver that treats some other octet as a line ending defeats Z5.3; none is known for the class Z5.1 permits, and the corpus should keep looking.
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

So this module pins v0.15.0 and **imports nothing from gnark's `std/`**. `TestCircuitsImportNoGnarkStd` enforces that, and `TestCircuitsUseNoCommitments` that no compiled circuit carries a commitment. The gadgets here are plain R1CS over boolean wires. That costs constraints (AES most: 11.2) and buys two things: the v0.15.0 bug cannot reach the relation, and the circuits have no lookups, so no BSB22 commitment, which leaves vanilla Groth16 with three-element proofs and the simple ZK argument of 10.2.

Between v0.15.0 and v0.16.4, the packages this module links differ only by `uints`-style `std` changes it does not use, a prover `Accelerator` refactor, a `Lookup2` optimization and a commitment index fix it cannot reach; `backend/groth16/bn254/verify.go` is unchanged. `gnark-crypto` v0.21's security fixes touch EdDSA, shplonk, fflonk, KZG's ceremony and twisted Edwards curves, none on this path. The KZG one would matter to a PLONK route.

Moving past v0.15.0 is a coordinated bump across server and sn, and it would still leave lookups subject to 10.2's review.

### 10.2 Zero knowledge

Groth16 is perfectly zero knowledge for every well-formed CRS: given the CRS trapdoor a simulator outputs proofs distributed identically to real ones, and the proof's `r`, `s` are uniform. A malicious edge that ran the setup holds that trapdoor. Holding it gains nothing, since the simulated and real distributions are the same.

A malformed CRS is different: a key element off its intended value can make a proof depend on the witness in a way the edge can test. So the prover must not take keys on trust. **A prover host uses a proving key only if `VerifyPhase1` and `VerifyPhase2` over the setup transcript, against the circuit it compiled from its own source, produced that key.** Those checks establish that the key is of the form Groth16's analysis needs, for whatever trapdoor. This is subversion zero knowledge by verification, in the sense of Bellare, Fuchsbauer and Scafuro (Asiacrypt 2016) and Fuchsbauer (PKC 2018).

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

## 11. Costs

### 11.1 Gates

D-SMTP-16, at p95: BDAT with a 4 KiB header block and 10 recipients, ≤ 10 s for π1 and ≤ 30 s for π1 to π3 on an Apple M1 MacBook Air (8 GB), ≤ 60 s on an m5.large. DATA with a 100 KiB message, ≤ 10 min and ≤ 20 min.

### 11.2 Gadget sizes

| Gadget | Constraints | Unit |
|---|---|---|
| SHA-256 compression | 26,482 | Measured, scratch prototype |
| Z1, TLS 1.3, both directions (29 compressions) | about 768,000 | Estimated |
| Z1, TLS 1.2 (25 compressions plus one AES block) | about 675,000 | Estimated |
| AES-128 keystream, no lookups | about 11,600 per 16 octets | Estimated; about 725 per octet |
| ChaCha20 keystream | about 22,000 per 64 octets | Estimated; about 340 per octet |

The code's measured figures replace these as gadgets land; see section 12.

### 11.3 First measurements, and what they say

A scratch Groth16 run over chained compressions, gnark v0.15.0, Apple M4 Pro (14 cores), on a machine shared with other builds, so noisy:

| Constraints | Cores | Prove | Constraints/s |
|---|---|---|---|
| 4,237,153 | 14 | 8.5 s | 500,000 |
| 4,237,153 | 8 | 8.2 s | 519,000 |
| 4,237,153 | 4 | 9.6 s | 443,000 |
| 4,237,153 | 2 | 17.4 s | 243,000 |

Verification took 2.4 ms. Setup took 2 min 37 s. Peak memory was 10.5 GB, with compile and setup in the same process, so it overstates proving alone.

Neither reference machine was measured. Taking ORIGO's own figure for the m5.large (400k constraints in 9.8 s, so about 41,000 per second) and assuming roughly 250,000 per second for an M1, the budgets are about 7.5M constraints for π1 to π3 on the M1 and **about 2.4M on the m5.large**.

BDAT at the speed gate's size, under 10's rules, comes to roughly 6M to 7M constraints with AES, because Z1 alone costs 3 × 768,000 ≈ 2.3M and the 4 KiB header block about 3M. So on these estimates:

- The M1 bar is plausible but close.
- **The m5.large bar is missed by about 2.5×.** Removing lookups was a choice for soundness and simplicity; putting them back (10.1, 10.2) would roughly halve AES and still miss.
- Memory on the 8 GB M1 for a 4M-constraint π3 is unproven and may force π3 to split.

Levers, none taken: a hiding commitment to the keys, proven once, so that later parts skip Z1 (saves about 1.5M, but D-SMTP-22 forbids it as written); lookups under a reviewed commitment argument; sharing AES's first round across blocks of a record; a designated-verifier prover (Later). See section 14.

## 12. State of the code

Kept honest as the module grows. Anything not listed as built fails closed.

*(Updated at the end of each work unit; see the repository history.)*

## 13. Readings taken

Each is one reading of a point DESIGN.md leaves open, followed because it changes no D- item, format or invariant. A reviewer should challenge them.

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

## 14. Open

Raised to the owner (`.stack/questions/`, one file each): how SHTS reaches the edge, since no message in §14.5 has a field for it; where keys live and who hosts them, given their size; and what to do about the m5.large bar, given 11.3.

Not started or not finished, in the order to take them: see section 12 and the track report.

Evidence M9 still needs, none of which this draft provides (§22.10): two non-authors' written soundness argument; a checker of the public relation written apart from the prover tree; D-SMTP-16's speed, coverage and interop runs on its named hardware and census MXs; FS-31 and FS-123 on T2 and T3.
