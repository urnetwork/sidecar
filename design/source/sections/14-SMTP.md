## 14. The SMTP edge: outbound mail and abuse attribution

### 14.1 Purpose and scope

This section owns outbound mail: the path through `smtpedge`, the preamble and its proofs (X7), TLS policy, sending identity, quotas, abuse attribution, halts and report intake. §15 owns the local mail server, inbound mail and burners; §12 publishes DNS; §20 sets prices and numbers; §21 owns abuse policy.

X7 is decided (CONVENTIONS §0; owner decisions 35, 36, 38, 99, 125): TLS runs end to end from the sidecar to the destination MX, so `smtpedge` sees ciphertext plus proven header values.

### 14.2 Requirements

| id | requirement | source |
|---|---|---|
| R-SMTP-1 | "N outgoing connects per day for free", more for Pro; N small | PLAN.md:89 |
| R-SMTP-2 | Send emails/day 5 / 200 / 20000 | PLAN.md:356 |
| R-SMTP-3 | A PROXY-like plaintext header (routing path, Message-ID), ZK-verified against the first N buffered bytes | PLAN.md:90, :94 |
| R-SMTP-4 | Abuse reports against the Message-ID halt the network's sending for a day | PLAN.md:91 |
| R-SMTP-5 | The header holds every field reports need to join back | PLAN.md:97 |
| R-SMTP-6 | The local mail server sends through the edge | PLAN.md:104 |
| R-SMTP-7 | Mail infrastructure sees only encrypted bytes and small header values, except D-SMTP-19's report and role-mail intake (§2.8 mx-4; D-TRUST-4) | owner directive 2026-11-03 |
| R-SMTP-8 | Usage counts toward the transfer balance | PLAN.md:353; owner decision 10 |
| R-SMTP-9 | TCP/25 never crosses providers | connect/ip_smtp_policy.go:16-19 |
| R-SMTP-10 | URnetwork holds no DKIM key; logs hold no recipients or client IPs | §2.6, §2.8 EX2, I-13 |
| R-SMTP-11 | Gmail, Yahoo and Outlook.com sender and bulk rules | [R:ext-email-zk] §2.8 |
| R-SMTP-12 | Team mail on custom domains | PLAN.md:364 |
| R-SMTP-13 | No outbound mail before sound, fast, interop-tested BDAT and DATA proofs | owner decisions 35, 99, 125 |
| R-SMTP-14 | Send from the shared lb addresses, with bringyour.com PTRs and HELO = PTR; no IP pools | owner decision 124 |

### 14.3 What exists today

- **connect.** TCP/25 stays local in both clients, "so an SMTP relay attempt can never reach a provider" (connect/ip.go:10694-10699; connect/ip_remote_multi_client.go:6705-6713), and providers check again (connect/ip.go:7869-7872). `DohCache.Forward` is exported (connect/net_http_doh.go:1111).
- **warp.** The lb carries ingress only, PROXY v1 on TCP streams (warp/warpctl/config.go:2477-2513), with no public TCP 25; hosts egress from their own addresses (warp/services/services.go:216-220) and can source-route by `--fwmark` (warp/warpctl/config.go:2686-2689).
- **Addresses (2026-11-03).** The 12 lb addresses are HE's (vault/main/services.yml:82-106, :338-461; §19.5), and none has a PTR. HE delegates classless reverse zones (https://faq.he.net/index.php/Reverse_DNS); its colocation port-25 policy is unknown.
- **Go; missing.** Go's `KeyLogWriter` exports TLS 1.2's master secret (Go 1.27.3 src/crypto/tls/handshake_client.go:785) but never TLS 1.3's HS (common.go:1605-1609; handshake_client_tls13.go:491). Missing: port-25 egress, PTRs, `smtpedge`, a prover, DKIM publishing, report ingestion, mail quotas.

### 14.4 Connection model

```text
MUA / agent --(submission or mail_send, §15)--> local mail server --> SmtpSender (sidecar)
  (a phone writes its mailbox outbox instead; a prover host sends it, D-SMTP-18)
 1 §9 Find ur/smtpedge (resolves in urnetwork-edge) --> ticket
 2 §6 stream (Required, Service mode) --> smtpedge (platform client, sending IP)
     SmtpPreamble -->        gate, halt, quota, §8 send, From domain (14.5); MX (validating);
                               TCP/25 from the sending IP, banner, EHLO <PTR name>, STARTTLS, 220
     <-- SmtpPreambleResult  send_id, X-UR-Ref, Feedback-ID, MX host, DNSSEC chain, EHLO keywords
 3 sidecar applies §15.10's header rules (BURNER), adds headers, DKIM-signs,
   sends ClientHello (SNI = MX host)
 4 sidecar <====== TLS 1.2/1.3, spliced by the edge ======> destination MX
     TL4, or below the domain's pin on the host: no data; retry on the schedule below, then DSN
     SmtpHandshake (1.3), then SmtpProof parts (RPC): the key part, one an envelope group, one a header
       or DATA body record --> each verified before the records it releases (14.5)
     inside: EHLO, MAIL FROM:<..@b.<net>.<root>>, RCPT x R, BDAT n LAST or DATA .. CRLF.CRLF, QUIT
 5 SmtpOutcome --> (self-report, untrusted; a NO_REPLY envelope to the ticket's listener, 14.14)
```

- **Transport.** The sidecar's Required client Finds `ur/smtpedge` in `urnetwork-edge` (§9.4); the Find-recorded pair authorizes the Service-mode stream (§6.10.1; owner decision 11).
- **MX.** The edge resolves MX with a DNSSEC-validating resolver, honors null MX (RFC 7505), and dials only public unicast IPv4 addresses (owner decision 34). With no MX RRset and no null MX, RFC 5321 §5.1's fallback to the domain's address applies: `mx_host` is the domain, DANE uses that host, and NO_MX answers only when no address exists either. The sidecar never names an IP, so the edge is no port-25 proxy and the proofs keep ORIGO's no-MITM assumption. An MX on mxedge's router interfaces (§19.5) is spliced to mxedge over the host LAN, with a PROXY header naming the dialed address (D-SMTP-13).
- **Pre-TLS.** The edge runs the banner, `EHLO <PTR name>` and `STARTTLS` itself, in MX preference order, and answers NO_TLS or TRY_LATER before any sidecar byte if no MX offers STARTTLS. The sidecar's first bytes must be a ClientHello with SNI = MX host and no early data; inside TLS it re-sends EHLO, and only that reply's keywords count (RFC 3207 §4.2; Z8, Z9).
- **Shape.** One transaction to one recipient domain per connection, in BDAT mode if the MX offers CHUNKING after TLS, else DATA (14.5). The sidecar sends the envelope's commands in groups, MAIL and 12 RCPT, then 13 RCPT a group, under AES-128-GCM (18, then 19, under ChaCha20), settings with these defaults, and waits for each group's replies before the next, so each group's replies are proven with the group that follows (14.5); within a group it pipelines (RFC 2920 §3.1) only if the post-TLS EHLO reply offers PIPELINING, and otherwise each command, QUIT included, waits for the previous reply, still under the part that covers it. A send costs one unit and is one transaction at the MX whatever its recipients, each further 12 to 19 adding one proof part; `smtp_recipients_per_message` caps the connection, and the sender never splits a domain's recipients over connections (owner decision 434).
- **Retries.** A send that fails retries first at 30 min, doubling to 4 h, then every 4 h, with a DSN at 5 days; HALTED, QUOTA and TRY_LATER honor `retry_after_ms` and still end at 5 days. A message's retries that reach MAIL spend at most `SmtpSenderSettings.RetryUnitsPerMessagePerDay` connection units a UTC day, 2 by default, and past that it waits for the next UTC day. Idle limits are 10 min after a client record (RFC 5321 §4.5.3.2.6) and 5 min after a server record (§4.5.3.2.7), 30 min in all, 2 h in DATA mode; a 421 banner backs the destination off.

**TLS policy (D-SMTP-2; owner decision 38).** STARTTLS is mandatory: stripping it fails the send. The sidecar, as TLS client, authenticates the server and records each message's level (I-11).

| Level | Authenticated by |
|---|---|
| TL1 DANE | TLSA under DNSSEC (RFC 7672): the edge returns the MX and TLSA chain (`dnssec_chain`), which the sidecar validates to the root |
| TL2 MTA-STS | The HTTPS policy (RFC 8461), which the sidecar fetches and caches, plus PKIX for a listed MX |
| TL3 independent MX | The sidecar's own DoH MX lookup agrees with the edge, and PKIX is valid for that host |
| TL4 unauthenticated | Nothing |

TL1-TL3 exclude a malicious or compelled edge (D-TRUST-1), TL4 only a passive one, so the sidecar refuses TL4 with a DSN giving the reason unless the user allowed the recipient domain; such mail is labeled "readable by an active URnetwork edge" (§2.8 EX4). The allowance is an outward action of its own (I-8), `SidecarActionKind` 18, `mail_tls_unauthenticated`, whose action's `host` (5) holds the recipient domain, lowercase with no trailing dot, and whose `expires_millis` (8) ends an allowance that ends; approvers render it from daemon-built fields as `Send mail to <domain> through a mail server that cannot be authenticated: an active URnetwork edge could read it`, and no ordinary `mail_send` approval counts as TL4 consent (owner decision 436). It is kept per recipient domain: a desktop keeps a granted allowance in its `SidecarStore`, and a phone's message carries the approval's id with its approved domains on its signed `o/` entry (`tl4_domains`, §15.7), which a prover host honors only if that entry's signature verifies and its signer is a consented device (§8.5) of the mailbox's owner, for that message only, never copying them to its own store. Each MX host's best level for each recipient domain is pinned for 90 days, and nothing goes below a pin. TL2 and TL1 are properties of the recipient domain, its own MTA-STS policy and its MX RRset validating under DNSSEC before the host's TLSA counts, so a shared MX host that reached TL2 or TL1 for one domain refuses no other domain that publishes less, while a send to a domain through a host below the level it reached there is refused as a downgrade, a malicious edge stripping TLSA for a domain that reached TL1 included; a domain never sent to carries no pin, even where its host holds one from another domain, and a TL4 allowance lifts no pin (owner decision 438). Until §13 issues a receiver's certificate (§15.5), mail to it authenticates only at TL1.

### 14.5 The preamble and what makes it trustworthy (X7)

PLAN's byte header becomes protobuf frames ahead of the raw TLS bytes (D-SMTP-3), and nothing ships before the proofs below make every value proven (owner decision 35).

```proto
message SmtpPreamble {           // 0x1601, sidecar -> edge
  uint32 version = 1;
  string recipient_domain = 2;    // enforced: the edge resolves and dials it; every RCPT is at it (Z4)
  uint32 recipient_count = 3;     // proven (Z4); capped per message and per day (14.7)
  string message_id = 4;          // proven (Z5)
  string header_from_domain = 5;  // proven (Z5); in the network's zone (§15.9) or a verified Team domain (§7.6)
  string dkim_selector = 6;       // proven with d= (Z5)
  uint64 message_byte_count = 7;  // proven: BDAT's n, or DATA's octets before the end mark (Z4, Z6); declared
                                  //   for the expected mode (below)
  bytes retry_of_send_id = 8;
  uint32 flags = 9;               // 1 BULK, 2 REQUIRETLS, 4 BURNER
  bytes proof_key_set = 10;       // SHA-256 of the keyset.json every part of this connection is proven under
                                  //   (14.9)
}
message SmtpPreambleResult {     // 0x1602, edge -> sidecar
  uint32 code = 1;  // §6.11: 1 OK, 2 HALTED, 3 QUOTA, 4 DENIED, 5 NO_MX, 6 NO_TLS, 7 TRY_LATER,
                    //   8 KEYS (the edge does not accept proof_key_set: no MX is dialed, nothing is debited);
                    //   0 UNSPECIFIED, a protocol error
  uint32 retry_after_ms = 2;
  bytes send_id = 3;
  string x_ur_ref = 4;            // issued; proven present (Z5)
  string feedback_id = 5;         // issued; proven present (Z5)
  string helo_name = 6;           // the sending address's PTR name (14.6)
  string mx_host = 7;
  bytes dnssec_chain = 8;         // every cut's DS and DNSKEY, then the MX and TLSA RRsets, with RRSIGs, in
                                  //   RFC 9102's order (TL1)
  repeated string ehlo_keywords = 9;  // pre-TLS hints only; Z8 proves the post-TLS reply
}
message SmtpProof {              // 0x1605, RPC sidecar -> edge (M9)
  bytes send_id = 1;
  uint32 index = 2;               // the part's ordinal, from 1; part 1 is the key part
  uint32 mode = 3;                // 0 in part 1; 1 BDAT or 2 DATA from part 2 on, which fixes it (Z9)
  uint64 first_record = 4;        // client application records covered, by TLS sequence number;
  uint64 last_record = 5;         //   a part that opens none has last_record = first_record - 1
  bytes proof = 6;                // 164 octets
  bool last = 7;                  // covers octet n, the end mark (DATA) and QUIT
  uint64 server_record_count = 8; // server records after Finished that this and earlier parts cover (0 in
                                  //   part 1); this part covers those past the previous part's count (Z7)
  repeated bytes records = 9;     // ciphertext of each client record the part opens, in sequence order
                                  //   (BDAT's last part: its header record from first_record, then QUIT at
                                  //   last_record)
  bytes key_commitment = 10;      // part 1 only: C, 64 octets (owner decision 433)
  uint32 reply_count = 11;        // the replies the server records it covers hold (Z8)
  uint32 header_record_count = 12;  // on the part that opens the header block's first record, and no other:
                                    //   how many client records hold the header block
  bytes carry = 13;               // on a part that opens a header or body record: the scan state after it,
                                  //   64 octets
}
message SmtpProofResult {        // 0x1606, edge -> sidecar
  uint32 code = 1;                // §6.11: 1 OK; 2 INVALID, and the edge cuts the connection (14.7);
                                  //   0 UNSPECIFIED, a protocol error
}
message SmtpOutcome {            // 0x1603, a NO_REPLY envelope to the ticket's listener (14.14), self-reported:
                                 //   it only tightens (14.8) and never feeds attribution
  bytes send_id = 1;              // the edge takes it from the connection's dialer for 15 min after the stream ends
  uint32 tls_level = 2;           // 1-4 for TL1-TL4, 0 if none was reached
  uint32 mode = 3;                // as SmtpProof.mode, 0 if the send ended before the mode was known
  repeated uint32 reply_codes = 4;  // the MX's reply codes, as the sidecar read them inside TLS
  uint32 dsn_count = 5;           // DSNs made or received since the last accepted outcome, so a late bounce
  uint32 hard_bounce_count = 6;   //   rides the next send
  bool downgrade_refused = 7;     // the send refused an MX below its pin, or TL4 without an allowance (14.4)
}
message SmtpStatus {             // 0x1604, in PushHint.hint on topic mail (14.14)
  uint32 kind = 1;                // SmtpStatusKind
  uint32 retry_after_ms = 2;      // when the queue may try again; GET /smtp/status gives a halt's scope
}
message SmtpHandshake {          // 0x1607, RPC sidecar -> edge, TLS 1.3 only (the disclosed SHTS, below)
  bytes send_id = 1;
  bytes shts = 2;                 // the server handshake traffic secret, which the edge forgets after E2
}
message SmtpHandshakeResult {    // 0x1608, edge -> sidecar
  uint32 code = 1;                // SmtpHandshakeCode
}
// §6.11's edge codes, each 0 a protocol error that the receiver answers by resetting the stream or dropping the hint
enum SmtpPreambleCode {          // SmtpPreambleResult.code
  SMTP_PREAMBLE_CODE_UNSPECIFIED = 0; SMTP_PREAMBLE_OK = 1; SMTP_PREAMBLE_HALTED = 2; SMTP_PREAMBLE_QUOTA = 3;
  SMTP_PREAMBLE_DENIED = 4; SMTP_PREAMBLE_NO_MX = 5; SMTP_PREAMBLE_NO_TLS = 6; SMTP_PREAMBLE_TRY_LATER = 7;
  SMTP_PREAMBLE_KEYS = 8;
}
enum SmtpProofCode { SMTP_PROOF_CODE_UNSPECIFIED = 0; SMTP_PROOF_OK = 1; SMTP_PROOF_INVALID = 2; }
enum SmtpStatusKind {
  SMTP_STATUS_KIND_UNSPECIFIED = 0; SMTP_STATUS_HALTED = 1; SMTP_STATUS_QUOTA = 2; SMTP_STATUS_CLEAR = 3;
}
enum SmtpHandshakeCode { SMTP_HANDSHAKE_CODE_UNSPECIFIED = 0; SMTP_HANDSHAKE_OK = 1; SMTP_HANDSHAKE_INVALID = 2; }
```

Recipient addresses, subjects, bodies and the MX's replies inside TLS stay private witnesses; §2.8 smtp-1 to smtp-6 list what the edge sees.

**Frames.** Only `SmtpPreamble` and `SmtpPreambleResult` travel as frames ahead of the raw TLS: u32be body length ‖ u16be `MessageType` ‖ body, the body at most 65,536 B. Raw TLS follows an OK result, any other result ends the stream after its frame, and a bad length or type resets it with PROTOCOL. A `dnssec_chain` that would pass the bound is sent empty, so TL1 is not available on that connection; the sidecar validates the chain to the keys of IANA's current root-anchors file, which it embeds, updated by release. `SmtpProof` and `SmtpHandshake` are RPCs to the edge, and `SmtpOutcome` a NO_REPLY envelope to the ticket's listener (14.14).

**The disclosed SHTS.** In TLS 1.3 the sidecar sends `SmtpHandshake` (`SMTP_HANDSHAKE` 0x1607, above) as soon as the handshake ends, and the edge answers `SmtpHandshakeResult` (0x1608): 1 OK, 2 INVALID, on which the edge ends the connection, 0 a protocol error. TLS 1.2 sends none. The edge forgets the SHTS after E2 (D-SMTP-10).

**Declared bytes.** The preamble declares `message_byte_count` for the expected mode, the pin's (14.4), else BDAT's unstuffed form, and every issued header has a fixed length (14.6), so each length is known first. If the mode the post-TLS EHLO selects cannot meet the declared count, the sidecar ends the connection before MAIL and reconnects once with the other count and `retry_of_send_id` set, costing a burst token and no unit (14.7); a second mismatch is `deferred` on 14.4's retry schedule, so an MX that offers CHUNKING always gets BDAT.

**Authorization.** A Find for `ur/smtpedge` needs no §8 grant (§9.4); preambles failing the gate, quota or halts (14.7, 14.8), `mail_send` or the From-domain check (§8.10, `ScreenName` §21.6) get DENIED, HALTED or QUOTA before any byte reaches the MX. `SmtpGate` answers from memory only, fed by §8.9's internal gate surface; a miss answers TRY_LATER and starts a refresh. The sidecar `mail_send` is judged for is the one the stream's admitted `ur/` ticket names in `dialer_sidecar_id`, which sockets filled at Find from the caller's authenticated `sidecar_id` claim and signed (§9.6's `ur/` tickets), so the edge needs no client-to-sidecar lookup or cache, and a ticket naming none answers TRY_LATER, failing closed (owner decision 560). A preamble naming a key set the edge does not hold gets KEYS, before any MX is dialed or anything debited.

**Soundness.** PLAN's "first N bytes" proof is unsound: the client authors the ciphertext, and AES-GCM and ChaCha20-Poly1305 do not commit to keys, so the bytes can open to benign headers under one key and the real transaction under another (https://eprint.iacr.org/2024/733 Theorem 4; https://eprint.iacr.org/2019/016). Nor is a malicious sidecar's control flow evidence of the MX's state: STARTTLS voids the pre-TLS keywords (RFC 3207 §4.2), and an MX without CHUNKING, or one that refused the envelope, parses an alleged message body as commands (RFC 3030 §2). So the proofs bind the keys to the observed handshake, cover the whole client flow and prove the MX replies that interpret it; E1-E3 run at the edge, Z1-Z9 in the circuit.

| # | Check |
|---|---|
| E1 | No PSK or resumption, early data or renegotiation (1.2: each client record it forwards is application_data by its clear type); SHA-256 suites (1.3: AES-128-GCM, CHACHA20-POLY1305; 1.2: ECDHE AES-128-GCM) |
| E2 | The edge dialed the MX it resolved and checks the server's signature: 1.3's CertificateVerify and Finished with the disclosed SHTS, 1.2's ServerKeyExchange in clear |
| E3 | Client records go in sequence order, each once a verified part covers it: an opened one only if it equals the ciphertext the part proved, BDAT's unopened body only up to octet n by the edge's count; no message record (BDAT's command and chunk, DATA's octets) goes before verified parts cover every server record relayed before it and every reply the envelope's commands are owed, proving each MX reply (Z8); PLAN's "first N bytes buffer" |
| Z1 | Under the edge's handshake inputs (below), in the connection's first part: 1.3: a private HS yields the disclosed SHTS, then MS and both directions' application keys and IVs (ORIGO); 1.2: a private master secret yields the key block, under which the relayed server Finished record decrypts to the verify_data that secret gives the relayed handshake (D-SMTP-21); and the public commitment C commits to those keys and IVs. In every later part: the keys and IVs it uses open C |
| Z2 | Each proven plaintext, client or server, is its ciphertext XOR the keystream at its sequence number (1.2: explicit nonce) |
| Z3 | Each client record the circuit opens is unpadded application_data, with no KeyUpdate, so lengths fix offsets; BDAT's unopened body rests on the relation's count bound |
| Z4 | `EHLO <helo_name>`, `MAIL FROM:<x@b.<net>.<root>>`, exactly R × `RCPT TO` at the recipient domain, then `BDAT n LAST` or `DATA`: one transaction |
| Z5 | Over the header block's records in order, the single fields and the fixed signature's line in the first, the header block holds, once each, a From in the declared domain, the declared Message-ID, the issued X-UR-Ref and Feedback-ID, and a DKIM-Signature with the declared d= and s= covering them; no bare CR or LF; List-Unsubscribe-Post if BULK |
| Z6 | BDAT: the chunk's n octets end at a record boundary, counted exactly over the opened head and by E3 over the unopened body, and the last client record, opened, is exactly `QUIT` CRLF. DATA: octets 1 to n, over the header and body records in order, end in CRLF, hold no bare CR or LF and no CRLF.CRLF, and exactly `.` CRLF `QUIT` CRLF follow |
| Z7 | The private server application key decrypts every server record the part covers (NewSessionTicket skipped; a KeyUpdate fails it); no key leaves the circuit |
| Z8 | Those replies are a valid SMTP exchange for the proven flow, part by part: the server records a part covers hold exactly its `reply_count` whole replies; the post-TLS EHLO reply advertises CHUNKING before a proven BDAT, MAIL and each RCPT get 2xx, DATA gets 354 before any message octet, and no message record is covered before all of them are proven |
| Z9 | `mode` is fixed from part 2 and matches Z8's post-TLS capabilities: BDAT to an MX whose EHLO reply lacks CHUNKING is unsatisfiable |

```text
Z1's handshake inputs (public; the edge computes each over the handshake it relayed, and uses the one prover
value, the disclosed SHTS, only once E2 has checked it)
1.3  H_shts = SHA-256(SHTS)
     H_sh   = Transcript-Hash(ClientHello .. ServerHello)       RFC 8446 §4.4.1, a HelloRetryRequest included
     H_sf   = Transcript-Hash(ClientHello .. server Finished)   the server's flight as E2 opened it
     Z1: SHA-256(HKDF-Expand-Label(HS, "s hs traffic", H_sh, 32)) = H_shts; MS from HS (RFC 8446 §7.1);
         each direction's key and IV (§7.3) from HKDF-Expand-Label(MS, "c ap traffic" | "s ap traffic", H_sf, 32)
1.2  r_c, r_s = the ClientHello and ServerHello randoms
     S_ckx  = the SHA-256 state (chaining value, unhashed tail, length) after ClientHello .. ClientKeyExchange,
              every handshake message before the client's Finished; the sidecar's client offers no SessionTicket,
              so the server's Finished is the next message after the client's; any other shape fails Z1
     SF     = the server Finished record as relayed: explicit nonce and ciphertext
     Z1: key_block = PRF(master_secret, "key expansion", r_s ‖ r_c), both directions' keys and IVs;
         cf = 14 00 00 0c ‖ PRF(master_secret, "client finished", SHA-256 finished from S_ckx)[0:12];
         SF opened under key_block's server key and IV = 14 00 00 0c ‖
           PRF(master_secret, "server finished", SHA-256 resumed from S_ckx over cf)[0:12]   RFC 5246 §6.3, §7.4.9
```

**Relation (D-SMTP-22; owner decision 433).** Public inputs are values the edge holds anyway: Z1's handshake inputs (above), the client ciphertexts a part opens (`records`, which the stream must repeat, E3), the server records it covers, the preamble and issued values, the part's ranges and counts, and the commitments the sidecar publishes: C, in the connection's first part, and a carry on each part that opens a header or DATA body record. Both directions' keys, IVs and plaintext are private witnesses. The first part, the key part, proves Z1 once and that C commits to both directions' keys and IVs; every later part proves that the keys it uses open C, and holds no key schedule. C and each carry are Pedersen commitments, over the curve embedded in BN254's scalar field, under a fresh uniform 251-bit blind drawn from the source of the TLS keys: each is a uniformly random group element whatever it commits to, so no public value depends on a key or on an octet of plaintext, even to an edge with unbounded computation or the setup's trapdoor, and binding, on discrete logs on that curve (about 2^125), ties every part to the keys the first fixed. A part covers the client records `first_record` to `last_record`, or none, and the server records from the previous part's `server_record_count` up to its own, which hold exactly its `reply_count` replies, so prover and edge check the same records, and it can verify before its records are sent, so the sidecar paces them (14.4). The envelope takes one part a group of commands, the header block one part a record, and DATA's body one part a record; the state a scan carries from one record to the next is the carry, which the edge hands from each part to the next. An MX awaiting a command sends no reply, so a server record relayed past a part's count, such as a late NewSessionTicket, only holds message records (E3) until the next part, which may open no client record, covers it; once the MX closes, a 421 included, outstanding parts are moot. DATA opens every octet. BDAT's parts open the records through the header block and the final `QUIT`; the body between streams unopened once the last part verifies, and the edge counts each of its records as its length minus 17 octets, the most a 1.3 record carries (RFC 8446 §5.2; a 1.2 record, typed in clear by E1, carries exactly its length minus 24). So the MX never counts more chunk octets than the edge: it reaches octet n and the proven `QUIT` only if every body record is unpadded application data, and otherwise ends the chunk inside the `QUIT` record, or never. No client record reaches the MX after it (14.7), and 6 octets hold no transaction, so a malformed body alters only its own unproven content or fails the send. A part that cannot be proven, as after a refused MAIL or RCPT, ends the connection before any message octet, and the sidecar retries or returns a DSN per recipient; a part resent under its `send_id` and `index`, byte for byte, is idempotent, and a verified part is never replaced.

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

**DATA mode (D-SMTP-20; owner decision 125).** An MX without CHUNKING after TLS gets DATA, which ends at the first CRLF.CRLF, or on some receivers at bare-LF forms (SMTP smuggling, CVE-2023-51764), so Z6 checks every message octet, at minutes per 100 KiB on desktops. Each part opens one record and carries the scan state to the next in a hiding commitment (D-SMTP-22); a part is one fixed circuit, and a host whose part takes over 2 min, against the MX's 5-minute timeout (RFC 5321 §4.5.3.2.7), sends no DATA. A 2 h connection therefore proves at most `smtp_data_proof_bytes`, measured on each host and recorded (about 3 MiB on the M1 reference and 360 to 460 KiB on an m5.large, by projection until D-SMTP-16's runs): a larger message to an MX without CHUNKING gets a DSN before MAIL, as does a body still unproven at 2 h, while other recipient domains and every CHUNKING MX are unaffected.

**Send capability and results (owner decision 125).** The cap stays; what a user needs is which recipient it stops, how large the message is and whether waiting helps, at composition when known and before MAIL otherwise.
- **Check.** `SmtpSender.Check(message)` reports, per recipient domain:
  - the mode: `bdat` or `data` from the post-TLS EHLO reply of this device's last session with that domain's MX, kept 90 days as its TLS pin is (14.4), or from a send outcome (`or/`, §15.7); else `unknown`;
  - the message's encoded bytes, headers, DKIM signatures and dot-stuffing included;
  - the cap: the `smtp_data_proof_bytes` of the host that will prove it, or for a phone's outbox the largest its member's prover hosts record (`p/`, §15.7);
  - the expected delay: BDAT's parts at that host's measured time a part (six parts for D-SMTP-16's send, ≤ 30 s on an M1), or a DATA send's parts at that host's measured rate (up to 2 h at the cap), plus, through an outbox, the wait for a prover host;
  - a prediction: `ok`, `too_large` (mode `data` and bytes over the cap) or `unknown` (mode `unknown` and bytes over the cap).
- **Outcomes.** Each send records, per recipient domain, one of: `sent`; `queued` (in the outbox for a prover host); `deferred` (TRY_LATER, QUOTA or HALTED, with `retry_after_ms`); `too_large` (bytes and cap); `refused` (the MX's reply code); `tls_refused` (TL4, below a pin, or a REQUIRETLS message without TL1 or TL2 and the post-TLS REQUIRETLS keyword, TL3 not qualifying, its DSN `5.7.30` for the missing keyword and `5.7.10` for missing TLS authentication); or `failed`. A phone's outbox entry goes to the prover host the rendezvous hash of its `effect_key` picks among the consented hosts in `p/`, which writes `or/<h>/<effect_key>` with outcome `queued` as it starts and rewrites it at least every 5 min while the send runs; the next host takes over only after 10 min with no change to `or/`, so a crash can still send twice, which §22.7 allows. `too_large` is decided before MAIL, once the post-TLS EHLO reply lacks CHUNKING: a prover host whose cap is under the bytes leaves the message, as `deferred`, to one whose recorded cap fits, and records `too_large` when none does. The outcome and the mode go to the outbox entry's result (§15.7), so every device of the member learns the domain's mode. Each domain's outcome also carries `tls_level`, the TLS level the send reached (1-4 for TL1-TL4, 0 for none), its I-11 label, and `or/` holds one `MailOutcome` a domain in a `MailOutcomeRecord`, whose bytes, as `o/`'s `SmtpOutboxEntry`'s, are §15.7's (owner decision 445).
- **Copy.** Only `too_large` cites the DATA cap, naming that domain, the size and the cap. Other recipient domains keep their own outcomes, and no outcome points to an inbound indexer, receiver or coverage setting (§18.5).

**Key sets (owner decision 266).** A prover host's proving keys and setup transcripts come in no package: it downloads its key set on first send from a public path on ur.io, pinned by hash in the release, with no token and no account, verifies the transcripts once per release and caches them (§4.10); §2.8's smtp-7 lists what the path's host sees. The fetch runs at idle, only on a host that has sent mail or is a consented prover host, and brings the set's `keyset.json` and transcripts: the host compiles each shape, refuses for that set one whose circuit digest is not the set's, derives the proving key itself, none being published, and caches it under the circuit's digest and the key's hash, so a build takes only its own circuit's entry and a torn write is no entry; a TLS family's suites are offered only once every shape of it is ready, a release may pin an older set beside its newest, and the edge holds each set `smtpedge.yml` lists until its `not_after`, a connection keeping the one set its preamble names (DESIGN-DETAILS.md section 3, 3.2.7). Until a key set loads, no prover is injected, a host only queues, and the verifier refuses every part. With the key schedule proven once (D-SMTP-22), every circuit fills one 2^20 domain, a unit, in eleven shapes of two families, none sized by a guess about recipients, a proof taking about 1.3 GiB (owner decision 433). The setup ceremony runs again, and a new key set replaces the old, only when a circuit changes, when the shape catalog changes, or when the ceremony host is suspected exposed, never on a schedule or with each release, and a set may gain shapes without replacing the rest; a leaked ceremony secret lets its holder forge proof parts under that set, which defeats abuse control for forged sends, §14.8's DKIM joins still attributing them, and exposes no mail, since prover hosts check every key against the setup's transcript (owner decision 435). Who runs the production ceremony, and on which host, is the owner's.

**The M9 gate (D-SMTP-16)** turns owner decisions 35, 99 and 125 into tests, in both modes:
- **Soundness.** `smtpproof/SPEC.md`, frozen at M9's entry review, states the relation (D-SMTP-22), public inputs, E1-E3, soundness against a malicious sidecar (a colluding MX gets only its own mail) and zero knowledge against a malicious edge that ran the setup, and names the sidecar's TLS client, whose TLS 1.3 handshake yields the HS that Go's `KeyLogWriter` never exports (14.3). Two engineers who did not write the circuits argue soundness in writing. Through that client, in both TLS versions and modes, §22's adversarial corpus must fail before any effect while honest controls pass: key substitution, record splits, replayed server replies, a pipelined second transaction, smuggled headers, an early or bare-LF DATA end, and scripted MXs with no CHUNKING, CHUNKING only before TLS, no PIPELINING, a refused MAIL or RCPT, mixed recipient outcomes, no 354, a late NewSessionTicket, or a second transaction in the alleged BDAT body; padded or KeyUpdate BDAT body records may fail the send but smuggle nothing.
- **Speed** (p95). Every part is one circuit of 2^20, a unit. BDAT, for a 4 KiB header block and 10 recipients, six units under AES-128-GCM and five under ChaCha20, which the client offers first: ≤ 10 s for the key part and ≤ 30 s for the send on an Apple M1 MacBook Air (8 GB); on an AWS m5.large, the time SMTP-M9-32's bench measures there, about 150 s by projection, since no relation over these circuits proves the send there in 60 s: the AES keystream for a 4 KiB header block alone is 2.99M constraints, 73 s at 41,000 a second. DATA, for a 100 KiB message: ≤ 10 min on the M1; on the m5.large ≤ 20 min under ChaCha20 and the measured time under AES-128-GCM, about 35 min by projection. The targets are settings with these defaults (owner decision 433). For scale, ORIGO proves in 1.5 s (c5.4xlarge) to 9.8 s (m5.large) with a 112 MB proving key, and in-circuit AES-GCM takes over 1 s per 512 B on an M2 MacBook Air ([R:ext-email-zk] §2.12).
- **Coverage.** The M7 census (D-MAIL-9) probes the Tranco top 10,000's MXs (EHLO, STARTTLS, a handshake and the EHLO inside it, no mail); Gmail, Outlook.com, Exchange Online, Yahoo, AOL, iCloud and ≥ 95% of its MX domains offer a covered TLS version and suite.
- **Interop.** Through the same client, strict DMARC passes at those providers in both modes (DATA forced where CHUNKING is offered), TLS 1.2 to Exchange Online included.

### 14.6 Sending identity

§12.7 is the only record table; this subsection sets the rules for its rows marked §14.6 and lists the rest:

```text
_spf.<root>                    TXT  "v=spf1 ip4:<sending addresses> -all" ; b.<net>.<root>'s SPF includes it
o<k>.out.bringyour.com         A    <sending address>, whose PTR is this name ; warpctl (§19 W11); HELO, FCrDNS
rpt.bringyour.com              MX   itself; A the report address         ; warpctl (§19); RUA, ARF, TLS-RPT, role mail
*._report._dmarc.rpt.bringyour.com  TXT  "v=DMARC1"                      ; warpctl; authorizes every network's rua (RFC 7489 §7.1)

headers (D-SMTP-6):
Message-ID: <26 base32 random>@<net>.<root>        ; the sidecar's; <blabel>.<net>.<root> for burners
X-UR-Ref: 1.<base32(key_id ‖ send_id[12] ‖ HMAC-SHA256(key, send_id ‖ network_id ‖ day)[0:8])>   ; the edge's:
          ; lowercase unpadded base32 of key_id (1 octet), send_id (12 random octets) and the MAC's first 8 octets,
          ; network_id 16 octets and day a u32be count of UTC days since the Unix epoch: 21 octets, 36 characters
Feedback-ID: <class>:<tier>:<nettoken>:urnetwork   ; the edge's: class n (network mail) or b (burners), tier c, p
          ; or t, nettoken the network's report token, 26 characters, so 40 characters in all
```

- **Report token.** `network_dns_zone.report_token` is 16 bytes from crypto/rand, shown as 26 lowercase base32 characters with no padding, unique-indexed, written in the zone's creating transaction and never rotated. It is `<report_token>` in the rua of `_dmarc` and `_smtp._tls` (§12.7), in the label zone and its alias and scope zones, and `<nettoken>` in Feedback-ID, with no key: `SmtpGate`'s cache carries it, so the preamble path stays off Postgres, and mxedge's platform listener finds a token's network by the index. A network's burners share its token. `_dmarc.<root>`'s rua uses the fixed local part `root`, which no 26-character token can equal, and the intake splits its rows by header_from's `<net>` label, so burner domains that fall back to it still count once.
- **Alignment (D-SMTP-5).** SPF never aligns (`-all` on the header domain `<net>.<root>`; the envelope domain `b.<net>.<root>` passes SPF), so on shared sending addresses only strict DKIM alignment stops network A passing DMARC as `From: x@B.<root>`. `_dmarc.<root>` is strict too, since burner domains have no `_dmarc` and receivers fall back to it (RFC 7489 §6.6.3).
- **DKIM (owner decision 36).** Each sending sidecar generates RSA-2048, and URnetwork publishes only public keys through `POST /smtp/dkim-keys`, replying and forwarding burners' selectors included until the PSL listing (owner decision 79; §15.9). Opaque selectors, 26 lowercase base32 characters from 16 random octets, one DNS label, rotate every 90 days, keeping the retired one 7 days; removal (§7.10, I-15) deletes the sidecar's selectors in the same write. Signing is relaxed/relaxed, no `l=`, oversigned From, `x=` 7 days, plus a second signature over only `from:date:message-id:x-ur-ref:feedback-id`, which survives reports that mask recipients.
- **Addresses (owner decision 124).** smtpedge sends from its hosts' shared lb IPv4 addresses, each with one PTR name, `o<k>.out.bringyour.com`, that HELO repeats and whose A record names it (FCrDNS); no address sends before its FCrDNS holds. Every network and burner shares every address, with no IP pools or per-IP warm-up; reputation is per sending domain and per network, through selectors, halts and rate limits (14.7, 14.8). A listed address leaves the sending set, not ingress, within the feed refresh, its mail spreading over the remaining shared addresses, and rejoins after delisting and 3 clean days (§21.5).
- **Team custom domains (v1, D-SMTP-15).** A Team network's verified `network_domain` (§7.6) may be the header domain, its `_domainkey` delegated to §12 or CNAMEd per selector to `<net>.<root>`, its `_dmarc` at `adkim=s` (§2.8 EX2). The envelope stays `b.<net>.<root>`; strict mode (§15.4) moves it to `b.<domain>`, with the customer's MX and SPF include, as Z4 proves.

**PSL listing (owner decision 79).** Once `<root>` is on the PSL (§12.4) and a test network's burner mail, signed only under its network selector, passes DMARC at Gmail, Outlook.com and Yahoo (D-SMTP-5), each `_dmarc.<net>.<root>` switches to `adkim=r` and burners sign with the network's selectors; 7 days later §12 deletes the per-burner selectors and records. `_dmarc.<root>` keeps `adkim=s`.

### 14.7 Quotas

The unit stays PLAN.md:89's outbound connections per UTC day (owner decision 30), at PLAN.md:356's 5/200/20,000, hard (owner decision 27); §20.4 holds the `smtp_*` keys and numbers. A connection carries one message to one recipient domain (14.4) and costs a unit once its MAIL record is forwarded, an earlier refusal only a burst token; retries, forwards and relayed replies are new connections (§15.10). The recipient cross-check is a daily cap (D-SMTP-14): each preamble reserves its recipient count, capped per message and proven exact by Z4, against `smtp_recipients_per_day`, or gets QUOTA.

**Abuse limits** (`sidecar_abuse:`, equal on every tier, D-QUOTA-7; §21 tightens them per network):
- **Send gate (D-SMTP-14).** Internet mail needs `network_abuse_state` standard or better and starts 24 h after `POST /mail/enable` (§15); restricted networks resume at Community caps after a halt, and probation and anonymous-only networks deliver only same-network deposits (§21.7; D-MAIL-8; owner decision 96).
- **Breaker.** Community connections are capped per hour at the larger of 500 and 3× the trailing 7-day hourly median (`smtp_community_connections_per_hour`, `smtp_community_median_multiple`); a trip answers Community preambles TRY_LATER and alerts §19.
- **Destinations.** At most 200 Community connections per destination domain per hour (`smtp_destination_connections_per_hour`); at most `smtp_destination_concurrency` (10) at once per (sending address, destination /24), in edge memory, tuned on M9's first runs.
- **Records.** The edge forwards exactly the records E3 admits, within 14.4's time limits; a client record its part refuses (unequal ciphertext, or a body past octet n), or a failed part, cuts the connection (14.8). Once the MX has closed, an outstanding part is moot, and a client record after the final `QUIT`, such as a close_notify, only ends the connection unforwarded; neither is a cut.

**Enforcement.** Each preamble runs one Redis script on `{smq_<networkId>}` (halt, bucket, concurrency, the day's counters and reservations); MAIL debits a connection and its recipients, and close the observed bytes, so one message may pass `smtp_bytes_per_day` and the next preamble's script answers QUOTA. Keys expire after 48 h; refusals return QUOTA with `retry_after_ms`. A Community preamble also runs, at accept, one single-key script on each fleet-wide counter: `{smg_<yyyymmddhh>}`, the Community total, and `{smd_<hex(SHA-256(domain)[0:16])>_<yyyymmddhh>}`, its destination domain's, by UTC hour, each expiring 2 h after its hour starts: INCR, and past the cap DECR and answer TRY_LATER, a breaker trip alerting §19. A taskworker job each hour counts `smtp_send` rows by UTC hour over the trailing 168 complete hours for networks whose current tier is Community, takes the median of those hours, empty hours included, and writes it to `{smg_median}` (TTL 2 h); the breaker is max(500, 3 × median), and a missing median means 500. Redis loss restarts the counters, as 14.9 accepts.

### 14.8 Abuse attribution and the halt rule

Reports and role mail reach `rpt.bringyour.com` (D-SMTP-19). Aggregate reports carry no Message-ID (RFC 9990), so attribution keys on each network's domain.

| Source | Carries | Joined by |
|---|---|---|
| ARF loops: JMRP (IP-based; headers only since 2026), Yahoo CFL (by DKIM d=) | Original headers, sometimes the body | A signature under the network's selector; X-UR-Ref; the Message-ID hash; last-hop Received IP and time against the send log |
| Gmail loop | Rates per Feedback-ID | `nettoken` |
| DMARC RUA, XML (TLS-RPT likewise, JSON, for §15), often gzipped | report_id, source_ip, header_from, DKIM d= and s=, counts | header_from, `rua` token |

**Confidence (D-SMTP-8).** High: a network signature verifies over the reported headers, and the last-hop Received shows a sending IP within ±10 min of a send. Medium: the X-UR-Ref MAC verifies and matches that IP and time, and the report carries a verifying DKIM signature whose `d=` is the MAC's network; without that `d=` the join is dropped, not demoted, since a recipient on the shared addresses could paste another network's X-UR-Ref into a complaint. Low: a Received join only, never halting; §21 reviews it.

False reports fail: replays come from other IPs, forgeries lack signatures, each (network, Message-ID hash) counts once, only allowlisted operators with verifying DKIM count, and `not-spam` (RFC 6430) cancels.

**Halt rule (owner decision 37).** Pro and Team halt on rates, since at 20,000/day Gmail's 0.1% target allows about 20 complaints.

| Trigger (high or medium confidence) | 24 h halt of |
|---|---|
| A complaint against one `<blabel>.<net>.<root>`, any tier | That label |
| Community: the first complaint against `<net>.<root>`, or a second halted label within 24 h | The network, burners included |
| Pro: complaints above 0.5% of 24 h recipients, at least 2 | The network |
| Team: above 0.1%, at least 5 | The network |
| Verified fraud, virus or phishing, any tier | The network, with §21 review |
| Two record cuts in 24 h (14.7) | The network |
| A network's RUA message counts from the sending addresses exceed its proven sends, per recipient (`smtp_send`), by >20% + 5 a day | No halt: §21 reviews it as an investigation signal |
| 3 network halts in 30 days, of any category, a burner label's never counting and one lifted as wrong never counting (§21.4) | Suspension until §21 reviews it |

- **Mechanics.** A Redis flag plus an `smtp_halt` row, for the network or one label, lasts 24 h from the report's arrival; edges reload every 60 s. New preambles in scope get HALTED, in-flight connections finish, and a §6 `mail` hint holds the sidecar's queue.
- **Appeals.** An admin, never a client token (AUTHZ1), appeals via `POST /smtp/appeal`; rechecks lift halts from duplicates, replays or contradicted medium joins, and §21 reviews the rest. smtpedge stores no session ciphertext (D-SMTP-10), so the only content evidence is the network's sealed report copy, which it may volunteer.
- **Reports (D-SMTP-12, D-SMTP-23; owner decision 78).** ARF parsing is header-only: the `message/feedback-report` part and, to the first CRLFCRLF (≤ 64 KiB), an enclosed `message/rfc822` or `text/rfc822-headers` header block (DKIM-Signature, Message-ID, X-UR-Ref, Feedback-ID, From domain, Received); no enclosed message body or attachment is decoded. Aggregate reports' XML or JSON, machine data rather than user content, is parsed within 8 MiB inflated (`report_inflate_bytes`) and a 100:1 ratio, with DTDs and external entities refused and nesting ≤ 32; it counts only from a reporter whose DKIM verifies, at the network's `rua` token, once per (reporter, `report_id`). The raw bytes pass once, in memory, through the reporter's DKIM body hash and an HPKE seal to the network mail key (§15.8), kept in `smtp_complaint.sealed_report` for 30 days; an aggregate's copy rides a `smtp_complaint` row of type `rua` or `tlsrpt`, which counts as no complaint and feeds no halt, `smtp_dmarc_daily` keeping its counts. The seal is HPKE-XWing as gkm's deliveries use it (KEM 0x647a, HKDF-SHA256, AES-128-GCM, base mode), streamed so the raw bytes pass once beside the body hash: `sealed_report = u8(1) ‖ enc (1,120 B) ‖ ct_0 ‖ … ‖ ct_k`, `ct_i` the HPKE context's i-th Seal of chunk i (65,536 B but the last, which holds 0 to 65,536 B, an empty report being one empty final chunk), `aad_i = u8(1) ‖ network_id (16 B) ‖ u64be(arrival ms) ‖ u8(1 for the last chunk, else 0)` and `info = "UR smtp 1.0 report"`; the context's sequence orders the chunks, the final flag stops truncation, and the network and arrival bind a copy to its row (owner decision 437). The intake finds the key by the network's own rows, which api already verifies, so `POST /mail/enable` takes no field: §15.8's mail repo's newest GenRotate, which api's gate read surface (§8.9) fetches from gkm under a self-issued 15-minute `repo:<id>:deposit` token, aud gkm, through `GET /gkm/repos/<id>/drop-key?since=<g>` (§10.14), a scope that reaches only this public-key read and that evs refuses. It seals only if g is the newest served, now is before `drop_not_after_ms`, and api's rows show g covers `holders_shrunk_at`, caching at most 5 min; otherwise it drops the raw bytes unread and keeps the fields, as for every report before M7. A report at `<root>`'s rua (`root@rpt.bringyour.com`), which names many networks, is sealed to none: its counts are split by header_from's label and stored per network, with no sealed copy and no `rua` home row, so no network sees another's header_from domains or counts. A burner's reports reach its network's own token once the PSL listing lands (14.6); before it, a network has its burners' counts and no sealed copy of their aggregates. The row keeps §2.8 smtp-5's fields; the last-hop Received IP and time serve the join only. Unattributable reports are dropped unread, and unattributable role mail is answered at the end of DATA with `550 5.7.1` and §21.8's pointer to the form, then dropped unread (owner decision 533).
- **Self-reports.** `SmtpOutcome` (reply codes, DSN counts, TLS level, refused downgrades; 14.14) only tightens and never feeds attribution. Its `dsn_count` and `hard_bounce_count` cover every DSN the sidecar made or received since its last accepted outcome, so bounces that arrive hours later ride the next send, and a sidecar that sends nothing more reports nothing. The network halts once its self-reported hard bounces pass `smtp_hard_bounce_percent` (10) of the recipients sent in the trailing 24 h and at least `smtp_hard_bounce_floor` (10) recipients were sent (§20.4's `sidecar_abuse:`), rates counting recipients, not connections, from `{smq_<networkId>}`'s 24 hourly bounce fields (§2.8 smtp-4).

### 14.9 The smtpedge service and the sidecar/server split

| Piece | sidecar repo | server, ops |
|---|---|---|
| `SmtpSender`: handoff, outbox, per-domain split, DKIM, preamble, proofs, TLS levels and pins, retries (14.4's schedule; `SmtpSenderSettings.RetryUnitsPerMessagePerDay`), DSNs, `Check` and per-domain outcomes (14.5); a `ReachReceipt` per send (recipients with BCC; §16.8, owner decision 25) | `smtp_*.go` | — |
| DKIM keys | `smtp_dkim_*.go`, keychain (§5) | `POST /smtp/dkim-keys`; §12 publishes |
| Engine (gate, quota, MX, pre-TLS, splice, timers, send log; E1-E3 run in `smtpproof`'s `edgeSession`) and reports (ARF and aggregate parsing, attribution, seal, halt, reconcile) | `smtpedgeservice` | `server/cli/smtpedge`, `SmtpEdgeStore`, vault `secret_files`; taskworker jobs; the report intake, `SmtpReportIntake`, runs in process in the `mxedge-platform` block from M5 (§19.4), attribution and halts joining it at M9 in the same package |
| Prover and verifier (TLS 1.2 and 1.3; BDAT and DATA), the edge's E1-E3 (`edgeSession`) and the dialog (`Prover`), through smtp_proof.go's seams; `SmtpSender` holds everything around `SendSmtp` | `smtpproof`, a nested module the root never requires; `cli/` injects its provers on desktop builds (owner decision 104; §4.4), with the key sets the release pins by hash, whose transcripts a prover host fetches from ur.io at idle and checks against the circuits it compiles before it uses a key | server injects the verifier into smtpedge, with the key sets `smtpedge.yml` lists |

```go
type SmtpEdgeStore interface { // batched, off the connection path; server implements it until the review phase
	                            // moves sidecar's SQL into sidecar, over an Env's db (§4.5; owner decision 251)
	InsertSends(ctx context.Context, sends []*SmtpSendRecord) error
	FindSends(ctx context.Context, key *SmtpJoinKey) ([]*SmtpSendRecord, error)
	InsertComplaint(ctx context.Context, complaint *SmtpComplaint) error
	InsertAggregate(ctx context.Context, report *SmtpAggregateReport) (inserted bool, err error) // once per (reporter, report_id)
	SetHalt(ctx context.Context, halt *SmtpHalt) error
	ActiveHalts(ctx context.Context) ([]*SmtpHalt, error)
}
// The six methods stay as written; a second interface, SmtpReportLookups, adds FindDkimKey and the
// recipient count the report intake reads.
func NewSmtpEdgeService(ctx context.Context, host *ServiceHost, store SmtpEdgeStore, verifier SmtpProofVerifier, settings *SmtpEdgeSettings) (*SmtpEdgeService, error)
func (self *SmtpSender) Send(ctx context.Context, message *SmtpOutboundMessage) (*SmtpSendResult, error)
```

- **Shape.** One connect client per process in `urnetwork-edge`, its jwt from `server.NewPlatformClientSource` on the `edge` class's bearer (§13.6; owner decision 428), on the two sending hosts (§19.4); `smtpedge.yml` lists (address, HELO name, fwmark) tuples, the block's own mark the default, and each dial binds one of its host's lb addresses in the sending set by its fwmark, a host with several sending addresses needing W7 to add the other rules (§19.5); no lb route or inbound port.
- **Prerequisites,** asked in M0, due at M9's entry review: HE's outbound TCP 25 and reverse delegation, with PTRs §12 serves from smtpedge.yml; the HELO names' A records and W7's rules (§19); SNDS, JMRP, Yahoo CFL and Postmaster Tools enrollment. No address sends until its PTR and its HELO name's A record agree (FCrDNS).
- **Failure.** An edge crash resets its streams, and the sidecar retries on the §9 backup ticket; mail waits in the sender's queue or outbox, never at the edge. Losing Redis reloads halts from Postgres and restarts counters, failing open by at most a day's quota; DNS or MX failure returns TRY_LATER without a debit.
- **Metrics** (`urnetwork_smtpedge_*`) carry results, modes, TLS levels and proof times, never network, domain or IP labels.

### 14.10 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Edge-terminated submission, an edge-held DKIM key, an SES relay, audit by disclosing the ECDHE secret, parsing enclosed message bodies, vendor report intake, a shared VERP bounce domain | Filtering, exact counts, sound without ZK, richer joins, bounce rates | URnetwork or a vendor reads user mail | Ruled out (owner directive 2026-11-03) |
| Prove client records only, trusting the sidecar's reading of MX replies | No server-record circuit, one part fewer | An MX without CHUNKING, or one that refused the envelope, runs commands smuggled in the alleged body | Rejected (D-SMTP-22) |
| BDAT only | No body-wide circuit | MXs without CHUNKING unreachable | Superseded (owner decision 125) |
| DMARC `ruf` | Failure samples | Mail copies at URnetwork | Rejected: `rua` only |

### 14.11 Decisions proposed

**D-SMTP-1 (proposed).** The sidecar reaches `smtpedge` only by a §6 stream; the edge dials the MX, runs pre-TLS and splices from the ClientHello on (14.4). *Why:* TCP/25 stays off providers, and the proofs get no-MITM.

**D-SMTP-2 (proposed).** STARTTLS is mandatory, TL4 needs the user's consent per recipient domain, and no recipient domain is sent through a host below the level it reached there, pins kept per (recipient domain, MX host) (14.4; owner decision 438). *Why:* an active edge could read such mail.

**D-SMTP-3 (proposed).** The preamble is protobuf frames ahead of raw TLS (14.5). *Why:* PLAN's placement without PROXY v2's 2,048 B parser cap (server/connect/transport_pp.go:28), and versioned.

**D-SMTP-4 (withdrawn).** Superseded by owner decision 35: no declared preamble ships, and D-SMTP-16 sets the proof gate.

**D-SMTP-5 (proposed).** 14.6's identity: header domain `<net>.<root>` with SPF `-all`, envelope `b.<net>.<root>`, strict DMARC with `rua` only, FCrDNS with HELO = PTR (owner decision 124), relaxed alignment only after the PSL test. *Why:* only the network's key passes, bulk rules hold (https://support.google.com/a/answer/81126), and old PSL copies still apply the strict `_dmarc.<root>`; a listed address leaves the sending set (14.6), with no separate IP pool (owner decision 124).

**D-SMTP-6 (proposed).** The sidecar declares the Message-ID; the edge issues a MAC'd X-UR-Ref and a per-network Feedback-ID (14.6). *Why:* unforgeable references with no recipient data.

**D-SMTP-7 (withdrawn).** Superseded by owner decisions 34 and 124: smtpedge sends from the shared lb addresses, with no IP pools.

**D-SMTP-8 (proposed).** Attribution has three confidence levels; only high and medium halt, and a medium join needs a verifying `d=` of the X-UR-Ref MAC's network (14.8). *Why:* resists replay, forgery and guessed Message-IDs, and a recipient on the shared addresses replaying another network's X-UR-Ref.

**D-SMTP-9 (proposed).** Halts are 24 h Redis flags with `smtp_halt` rows, per network or burner label (14.8). *Why:* PLAN.md:91 without per-packet work.

**D-SMTP-10 (proposed).** Retention follows §2.8 smtp-1 to smtp-6, plus 14 days of backups; send records keep the MX host, not its IP, and recipients, third-party IPs, subjects, bodies, report plaintext, session ciphertext and record lengths are never stored, nor the SHTS that sidecars disclose (E2); everything else a connection shows stays in memory. *Why:* joins need only a network and a time (§2.11).

**D-SMTP-11 (proposed).** The engine is `smtpedgeservice`, hosted by `server/cli/smtpedge`, its report intake running in process in `mxedge-platform` from M5; the prover and verifier are the nested module `smtpproof`, which the root never requires (owner decision 104). *Why:* owner rule 1; no client links the engine, and only desktops link the prover.

**D-SMTP-12 (proposed).** Reports are parsed header-only, aggregate attachments by D-SMTP-23's bounded parser, then sealed unparsed to the network mail key or dropped (14.8). *Why:* the directive; attribution needs only headers and aggregate counts, neither of them user content.

**D-SMTP-13 (proposed).** For a URnetwork MX, smtpedge splices to mxedge over the host LAN (14.4). *Why:* Q-ARCH-3 (a); TLS stays sidecar to sidecar.

**D-SMTP-14 (proposed).** 14.7's send gate, breaker and destination caps bound Community volume, and its daily recipient cap every tier. *Why:* free Sybils are the largest risk, and connections alone would allow a Team network 2,000,000 recipients a day.

**D-SMTP-15 (proposed).** In v1, Team networks send from verified custom domains (14.6). *Why:* PLAN.md:364.

**D-SMTP-16 (proposed).** M9's gate is 14.5's soundness, speed, coverage and interop tests, in both modes, through the sidecar's own TLS client. *Why:* owner decisions 35, 99 and 125 set the bar without a threshold or method.

**D-SMTP-17 (withdrawn).** Superseded by owner decision 125: the DATA-mode proof is built beside BDAT, and DATA coverage is part of D-SMTP-16's gate (D-SMTP-20).

**D-SMTP-18 (proposed).** Phones do not prove: they write outbound mail, signed by their identity key, to the member's mailbox outbox (§15.7), which one of the member's consented prover hosts (§8.5; owner decision 126) sends as in 14.4, burner replies and forwards included (owner decision 53). *Why:* no phone proves yet, and plaintext stays on the member's devices.

**D-SMTP-19 (proposed).** Reports and role mail go to `rpt.bringyour.com`, whose TCP 25 reaches only §15.4's platform listener, terminating every session, SNI or not; `<root>`'s MX names it for `abuse@` and `postmaster@` (§21.8), from M5. *Why:* reporters without SNI must deliver; platform names stay off `<root>` (owner decisions 13, 16).

**D-SMTP-20 (proposed).** 14.5's DATA mode: every message octet proven, in parts of one record, each proving within 2 min, within a 2 h connection, up to the host's measured `smtp_data_proof_bytes` (about 3 MiB on an M1); a larger message to an MX without CHUNKING gets a DSN and, for that recipient domain alone, a `too_large` outcome naming its size and the cap, which `Check` predicts once the domain's mode is known (14.5). *Why:* owner decision 125 keeps MXs without CHUNKING reachable, and its limit is outbound, so it belongs on the send, per recipient, not on receiver coverage (meta review K04); DATA ends by content, so an unchecked body could smuggle a second transaction; an idle MX closes after 5 min; and in-circuit AES-GCM bounds what 2 h proves.

**D-SMTP-21 (proposed).** Z1 proves TLS 1.2's server Finished in-circuit, so no 1.2 key is disclosed (14.5). *Why:* the server write key would open every MX reply, some of which echo recipients.

**D-SMTP-22 (proposed).** 14.5's relation also proves the MX's authenticated replies (post-TLS capabilities, envelope replies, the 354) under private server application keys (Z7-Z9). The key schedule is proven once, in the connection's first part, which publishes a perfectly hiding commitment to both directions' keys; every later part opens it (owner decision 433). Each part carries the client ciphertexts it opens and names the server records it covers and the replies they hold; no message record leaves the edge before verified parts cover every server record relayed before it and every reply the envelope is owed; state a scan carries across records travels in a perfectly hiding commitment; a verified part is never replaced; and BDAT's body streams unopened under the relation's count bound; `smtpproof/SPEC.md` freezes it. *Why:* a malicious sidecar's control flow is no evidence of the MX's grammar (RFC 3030 §2, RFC 3207 §4.2); an implicit server range fails an honest part when a record arrives during proving; a part that verifies before its records are sent lets the sidecar pace commands for an MX without PIPELINING and keeps message bodies out of edge memory; and proving the key schedule in every part cost three times what the gate allows and pushed every circuit past one domain, where a commitment uniform whatever it holds gives the edge nothing D-SMTP-21 withholds.

**D-SMTP-23 (proposed).** DMARC and TLS-RPT aggregates are parsed within 14.8's bounds and counted once per (reporter, `report_id`), and the RUA check compares message counts with proven sends per recipient, not connections, as a §21 signal. *Why:* the counters live only in the XML or JSON, which header-only parsing skips, and one connection's message can count once per recipient (RFC 9990 §3.1.1.8).

### 14.12 Open questions

**Q-SMTP-1.** [X7] How is the preamble made trustworthy, and what ships before a sound proof? **Decided by owner 2026-11-03 (owner decisions 35, 99):** nothing ships until 14.5's proofs pass D-SMTP-16's gate, with no external audit; burner email launches receive-only. **Decided by owner 2026-11-04 (owner decision 125):** always fund a DATA circuit, built beside BDAT and part of the gate (D-SMTP-20). DATA proves at most the host's `smtp_data_proof_bytes` in 2 h, so larger mail to an MX without CHUNKING gets a DSN, and both modes prove the MX's replies (D-SMTP-22). *Residual:* none.

**Q-SMTP-2.** What is the quota unit, given connects (PLAN.md:89) and emails/day (PLAN.md:356)? **Decided by owner 2026-11-03 (owner decision 30):** (a), outbound connections per day, with per-connection caps and a recipient cross-check, which D-SMTP-14 makes a daily cap (14.7). *Residual:* none.

**Q-SMTP-3.** Does any abuse report halt a network for a day on every tier (PLAN.md:91)? **Decided by owner 2026-11-03 (owner decision 37):** (d), tiered, domain-scoped halts (14.8). *Residual:* none.

**Q-SMTP-4.** [X7 residual] What happens to an unauthenticated MX (TL4)? **Decided by owner 2026-11-03 (owner decision 38):** (a), refused with a DSN unless the user allows the domain (14.4). *Residual:* none.

**Q-SMTP-5.** [X7 residual] Who holds DKIM keys? **Decided by owner 2026-11-03 (owner decision 36):** (a), each sending sidecar, under an opaque selector, at most 64, revealing how many devices send (§2.8 smtp-6). *Residual:* none.

**Q-SMTP-6.** Cross-cutting (§19.5, §21.5). Which IPv4 addresses send, under which PTR names? **Decided by owner 2026-11-04 (owner decision 124):** (a), the shared lb addresses, PTR names under bringyour.com, HELO = PTR, and no IP pools or per-IP warm-up (14.6). A listed address leaves the sending set but stays in ingress, with nothing to drain to; a listing that also hits api and connect ingress is an accepted risk (14.15). *Residual:* none.

**Q-SMTP-7.** Cross-cutting (§15, §21). What happens to an attributed report's raw bytes? **Decided by owner 2026-11-03 (owner decision 78):** (b), sealed unparsed to the network mail key for 30 days; URnetwork keeps only attribution fields (14.8). *Residual:* none.

### 14.13 Departures from PLAN.md

- **PLAN.md:90, :94.** The "first N bytes" proof is unsound as written; outbound mail waits for 14.5's BDAT and DATA proofs, which also prove the MX's replies (owner decisions 35, 99, 125; Q-SMTP-1). The "routing path" becomes the edge's trace (sending IP, HELO, MX, time).
- **PLAN.md:97.** DMARC aggregates carry neither Message-ID nor path, so joins use header_from, DKIM d= and IP; Message-ID and X-UR-Ref serve ARF (Q-SMTP-1).
- **PLAN.md:91.** A complaint halts its burner label, networks halt by 14.8's tiered ladder, and attribution is by DKIM, not Message-ID alone (owner decision 37; Q-SMTP-3).
- **PLAN.md:13.** The engine is a child package and the prover a nested module (owner decision 104; Q-REPO-5).

### 14.14 Interfaces

- **Provides:** `SmtpSender.Send`, `SmtpSender.Check` and per-recipient-domain outcomes (14.5), and the outbox sender (§15); send reach receipts (§16.8); `ur/smtpedge` and its LAN splice to mxedge; the report host, attribution and halts (§21); 14.6's record rules (§12, §19).
- **Consumes:** §4.4 module layout; §5 keychain; §6 streams, push, Service mode; §7.6 domains; §7.10 removal; §8 `mail_send`, consent; §9 Find; §10 drop keys in GenRotate (the network mail key, D-KEYS-17); §12 records, reverse zones; §15 handoff, header rules, outbox, forwarding, platform listener, mail key; §19 hosts, addresses, W7, W11; §20 tiers, leases; §21 standing, `ScreenName`, breakers; §22 corpus.
- **Subprotocol messages** (service 0x16, §6.11): `SmtpPreamble` and `SmtpPreambleResult`, frames on the stream to smtpedge (14.5); `SmtpOutcome` (0x1603), a NO_REPLY envelope to the ticket's listener, which the edge accepts from the connection's dialer for 15 min after the stream ends and then drops: `{bytes send_id = 1; uint32 tls_level = 2; uint32 mode = 3; repeated uint32 reply_codes = 4; uint32 dsn_count = 5; uint32 hard_bounce_count = 6; bool downgrade_refused = 7;}`, self-report only (14.8); `SmtpProof`/`SmtpProofResult` and `SmtpHandshake`/`SmtpHandshakeResult` (RPCs to smtpedge; the key part, envelope groups, header and DATA records; M9); `SmtpStatus` (0x1604, in `PushHint.hint` on topic `mail`): `{uint32 kind = 1; uint32 retry_after_ms = 2;}`, 1 HALTED, 2 QUOTA, 3 CLEAR, 0 a protocol error, with no label, since a client reads a halt's scope from `GET /smtp/status`; smtpedge's halt job hints the clients with a send in the last 24 h, off the path, and a client that misses it gets HALTED at its next preamble.
- **API routes** (connect/api/bringyour.yml; server/api/route_authz.go classifies the Client routes sidecar, on §7.4's `strict_exp` allowlist): `POST /smtp/dkim-keys` (Client with `mail_send`; network and burner selectors); `GET /smtp/status` (Client; quota, halt); `GET /smtp/reports?since=` (Client with §8 read on the repo that holds the network mail key, the audience its sealed copies are sealed to; fields, sealed copies); `POST /smtp/appeal` (admin scope, never a client token, so the allowlist still refuses it).
- **Tables** (smtpedge, and from M5 `mxedge-platform`'s intake for `smtp_complaint` and `smtp_dmarc_daily`, which MG5 creates, the rest in MG9 (§19.7); migrations ≥926): `smtp_send` (daily partitions, PK (send_day, send_id), dropped after 30 days), `smtp_complaint` (13 months, with `sealed_report`, cleared at 30 days; an aggregate's sealed copy rides a row of type `rua` or `tlsrpt`, 14.8), `smtp_halt` (13 months), `smtp_dkim_key` (deleted 30 days after its selector leaves DNS), `smtp_dmarc_daily` (13 months; per network, day, reporter, header_from and `report_id`, so each report counts once); Redis `{smq_<networkId>}`.
- **Services and config:** `server/cli/smtpedge`; `config/<env>/smtpedge.yml` (sending addresses with their HELO names and fwmarks, loop allowlist, report parser bounds, and the proof key sets it accepts: id, directory, not_after); vault X-UR-Ref keys; `pro.yml` keys and `sidecar_abuse:`; taskworker jobs for reconciliation, retention, sealed reports and key expiry.
- **Assumptions about other sections:** §12 runs 14.6's PSL steps, serves the reverse zones and Team `_domainkey` delegations, and writes a burner label's explicit MX and addresses with its first selector, removing them with its last (D-DNS-11); §19 W11 publishes the HELO names' A records; §21.5's breakers pull a listed address from the sending set; §2.8's smtp-2 lists the id of the key set the sidecar proves under, a proof per part (the key part, one per envelope group, one per header record and, in DATA mode, one per body record), each with its reply count and, once, the header block's record count, the key and scan-state commitments the sidecar publishes, and smtp-7 what the key set path on ur.io sees of a prover host's fetch, which stays off until that row has landed (owner decision 253), `helo_name`, the length and timing of every client and server record, and no key that opens application data (D-SMTP-21, D-SMTP-22), and smtp-5 the aggregate parser (D-SMTP-23); §22 runs FS-31's scripted MXs (no PIPELINING and a late NewSessionTicket included), padded and KeyUpdate BDAT body records, a mutated witness for each of E1-E3 and Z1-Z9, the X-UR-Ref replay, FS-39's report-intake cases at M5-out, halt scoping, and network A failing DMARC as B's burners too.

### 14.15 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| The BDAT or DATA proofs miss D-SMTP-16's bar, or unaudited circuits are unsound (owner decisions 99, 125) | High | High | Started in M0; `SPEC.md`, non-author analysts, §22's corpus, the RUA check; one key part and unit-sized parts (D-SMTP-22); disclosed as unaudited (owner decision 119); burner email launches receive-only (owner decisions 9, 35) |
| DATA proves minutes per 100 KiB, so a message above `smtp_data_proof_bytes` (about 3 MiB on an M1) to an MX without CHUNKING gets a DSN, and smaller ones are slow or hit the MX's session limit | Medium | Medium | one-record parts, each proving within 2 min; the cap reaches only the non-CHUNKING tail the M7 census sizes; `Check` and the `too_large` outcome name the size, the cap and the domain at composition or before MAIL (14.5); retries; a designated-verifier prover (Later) |
| Sybil free networks send their caps | High | High | Send gate, breaker, halts |
| A mail listing of a shared lb address also blocks api and connect ingress there; with no separate IP pool to drain to and no warm-up (owner decision 124), enough listings degrade sending and the shared ingress together (accepted) | Medium | High | The listed address leaves the sending set (14.6); per-domain and per-network reputation; halts; §21.5's breakers; delisting |
| HE refuses port 25 or reverse delegation | Unknown | Critical | Ask in M0 |
| The ceremony's secrets leak, and their holder forges proof parts | Low | Medium | Only abuse control rests on them, since a prover host checks every key it uses against the setup's transcript; a new ceremony and release retire the set; §14.8's DKIM joins still attribute forged sends (owner decision 435) |
| MXs without a covered TLS version or suite, and phone-only members, get no outbound mail | Medium | Medium | Census, DSN, outbox (D-SMTP-18); designated-verifier prover (Later) |
| A refused or mixed RCPT ends the connection before data, so the resend costs a second unit | Medium | Low | Resends go only to accepted recipients; Z8 keeps the proven envelope exact |
| Weak signals: bounces after the envelope are self-reported, hiding some list-washing; Postmaster Tools or Yahoo CFL ignore subdomains | High | Medium | Self-reports; connections ending before the message part bound envelope refusals (Z8); IP-based loops, RUA; test first |
| A compelled edge reads TL4-override mail | Low | High | Off by default; pins; label (§2.8 EX4) |
| After the PSL switch, a receiver on an old PSL copy aligns one network's selector with another's From | Low | High | 14.6's test gate (D-SMTP-5) |

### 14.16 Phasing

- **Before M9:** the report host with header-only and aggregate parsing (M5), whose M5-out waits on FS-39's report-intake cases, with S7's SNI-less abuse@`<root>` case run at M5 (§22.17, §23.6); the outbound probe (M7).
- **v0 (M9; owner decisions 35, 99, 124, 125):** the relay with edge-driven pre-TLS; TL1-TL3, TL4 refusal and pins; TLS 1.2 and 1.3 circuits in BDAT and DATA modes, proving the MX's replies (D-SMTP-22), past D-SMTP-16; the LAN splice; per-sidecar DKIM, strict DMARC; the shared lb addresses with bringyour.com PTR and HELO names, none sending before its FCrDNS holds; quotas, send gate, breaker, record cuts; header-only reports, reconciliation, halts; the outbox, with §15's replies and forwarding; the send check and per-recipient-domain outcomes (14.5). Blocked by D-SMTP-16, HE, C9 (M5), §12 and §15.
- **v1 (Team, from M9):** custom domains.
- **Later:** [a designated-verifier (VOLE) prover](DESIGN-DEFER.md#smtp-designated-verifier-prover) for phones and faster DATA (megabytes per message); [the PSL cut-over](DESIGN-DEFER.md#dns-psl-listing) (14.6); [DKIM2](DESIGN-DEFER.md#smtp-dkim2).
- **Deferred:** DESIGN-DEFER.md holds an entry for each Later item, linked above, and for [this section's v1 set](DESIGN-DEFER.md#smtp-v1) (owner decision 587).
