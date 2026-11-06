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
     TL4, or below the host's pin: no data; retry, then DSN
     SmtpProof pi1-pi3 (+ DATA parts) (RPC) --> each verified before the records it releases (14.5)
     inside: EHLO, MAIL FROM:<..@b.<net>.<root>>, RCPT x R, BDAT n LAST or DATA .. CRLF.CRLF, QUIT
 5 SmtpOutcome --> (self-report, untrusted)
```

- **Transport.** The sidecar's Required client Finds `ur/smtpedge` in `urnetwork-edge` (§9.4); the Find-recorded pair authorizes the Service-mode stream (§6.10.1; owner decision 11).
- **MX.** The edge resolves MX with a DNSSEC-validating resolver, honors null MX (RFC 7505), and dials only public unicast IPv4 addresses (owner decision 34). The sidecar never names an IP, so the edge is no port-25 proxy and the proofs keep ORIGO's no-MITM assumption. An MX on mxedge's router interfaces (§19.5) is spliced to mxedge over the host LAN, with a PROXY header naming the dialed address (D-SMTP-13).
- **Pre-TLS.** The edge runs the banner, `EHLO <PTR name>` and `STARTTLS` itself, in MX preference order, and answers NO_TLS or TRY_LATER before any sidecar byte if no MX offers STARTTLS. The sidecar's first bytes must be a ClientHello with SNI = MX host and no early data; inside TLS it re-sends EHLO, and only that reply's keywords count (RFC 3207 §4.2; Z8, Z9).
- **Shape.** One transaction to one recipient domain per connection, in BDAT mode if the MX offers CHUNKING after TLS, else DATA (14.5). The sidecar pipelines (RFC 2920 §3.1) only if the post-TLS EHLO reply offers PIPELINING; otherwise each command, QUIT included, waits for the previous reply, still under the part that covers it. Idle limits are 10 min after a client record (RFC 5321 §4.5.3.2.6) and 5 min after a server record (§4.5.3.2.7), 30 min in all, 2 h in DATA mode; a 421 banner backs the destination off.

**TLS policy (D-SMTP-2; owner decision 38).** STARTTLS is mandatory: stripping it fails the send. The sidecar, as TLS client, authenticates the server and records each message's level (I-11).

| Level | Authenticated by |
|---|---|
| TL1 DANE | TLSA under DNSSEC (RFC 7672): the edge returns the MX and TLSA chain (`dnssec_chain`), which the sidecar validates to the root |
| TL2 MTA-STS | The HTTPS policy (RFC 8461), which the sidecar fetches and caches, plus PKIX for a listed MX |
| TL3 independent MX | The sidecar's own DoH MX lookup agrees with the edge, and PKIX is valid for that host |
| TL4 unauthenticated | Nothing |

TL1-TL3 exclude a malicious or compelled edge (D-TRUST-1), TL4 only a passive one, so the sidecar refuses TL4 with a DSN giving the reason unless the user allowed the recipient domain (an outward action, I-8); such mail is labeled "readable by an active URnetwork edge" (§2.8 EX4). Each MX host's best level is pinned for 90 days, and nothing goes below a pin. Until §13 issues a receiver's certificate (§15.5), mail to it authenticates only at TL1.

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
  uint64 message_byte_count = 7;  // proven: BDAT's n, or DATA's octets before the end mark (Z4, Z6)
  bytes retry_of_send_id = 8;
  uint32 flags = 9;               // 1 BULK, 2 REQUIRETLS, 4 BURNER
}
message SmtpPreambleResult {     // 0x1602, edge -> sidecar
  uint32 code = 1;  // §6.11: 1 OK, 2 HALTED, 3 QUOTA, 4 DENIED, 5 NO_MX, 6 NO_TLS, 7 TRY_LATER;
                    //   0 UNSPECIFIED, a protocol error
  uint32 retry_after_ms = 2;
  bytes send_id = 3;
  string x_ur_ref = 4;            // issued; proven present (Z5)
  string feedback_id = 5;         // issued; proven present (Z5)
  string helo_name = 6;           // the sending address's PTR name (14.6)
  string mx_host = 7;
  bytes dnssec_chain = 8;         // MX, TLSA RRsets with RRSIGs (TL1)
  repeated string ehlo_keywords = 9;  // pre-TLS hints only; Z8 proves the post-TLS reply
}
message SmtpProof {              // 0x1605, RPC sidecar -> edge (M9)
  bytes send_id = 1;
  uint32 index = 2;               // 1 pi1; 2 pi2; 3 pi3; 4.. later DATA parts
  uint32 mode = 3;                // 1 BDAT, 2 DATA; fixed from pi2 on (Z9)
  uint64 first_record = 4;        // client application records covered,
  uint64 last_record = 5;         //   by TLS sequence number
  bytes proof = 6;
  bool last = 7;                  // covers octet n, the end mark (DATA) and QUIT
  uint64 server_record_count = 8; // server records after Finished that this and earlier parts cover (0 in
                                  //   pi1); this part covers those past the previous part's count (Z7)
  repeated bytes records = 9;     // ciphertext of each client record the part opens, in sequence order
                                  //   (BDAT's pi3: the head from first_record, then QUIT at last_record)
}
message SmtpProofResult {        // 0x1606, edge -> sidecar
  uint32 code = 1;                // §6.11: 1 OK; 2 INVALID, and the edge cuts the connection (14.7);
                                  //   0 UNSPECIFIED, a protocol error
}
```

Recipient addresses, subjects, bodies and the MX's replies inside TLS stay private witnesses; §2.8 smtp-1 to smtp-6 list what the edge sees.

**Authorization.** A Find for `ur/smtpedge` needs no §8 grant (§9.4); preambles failing the gate, quota or halts (14.7, 14.8), `mail_send` or the From-domain check (§8.10, `ScreenName` §21.6) get DENIED, HALTED or QUOTA before any byte reaches the MX.

**Soundness.** PLAN's "first N bytes" proof is unsound: the client authors the ciphertext, and AES-GCM and ChaCha20-Poly1305 do not commit to keys, so the bytes can open to benign headers under one key and the real transaction under another (https://eprint.iacr.org/2024/733 Theorem 4; https://eprint.iacr.org/2019/016). Nor is a malicious sidecar's control flow evidence of the MX's state: STARTTLS voids the pre-TLS keywords (RFC 3207 §4.2), and an MX without CHUNKING, or one that refused the envelope, parses an alleged message body as commands (RFC 3030 §2). So the proofs bind the keys to the observed handshake, cover the whole client flow and prove the MX replies that interpret it; E1-E3 run at the edge, Z1-Z9 in the circuit.

| # | Check |
|---|---|
| E1 | No PSK or resumption, early data or renegotiation (1.2: each client record it forwards is application_data by its clear type); SHA-256 suites (1.3: AES-128-GCM, CHACHA20-POLY1305; 1.2: ECDHE AES-128-GCM) |
| E2 | The edge dialed the MX it resolved and checks the server's signature: 1.3's CertificateVerify and Finished with the disclosed SHTS, 1.2's ServerKeyExchange in clear |
| E3 | Client records go in sequence order, each once a verified part covers it: an opened one only if it equals the ciphertext the part proved, BDAT's unopened body only up to octet n by the edge's count; no message record (BDAT's command and chunk, DATA's octets) goes before verified parts cover every server record relayed before it, proving each MX reply (Z8); PLAN's "first N bytes buffer" |
| Z1 | Under the edge's handshake inputs (below), 1.3: a private HS yields the disclosed SHTS, then MS and both directions' application keys and IVs (ORIGO); 1.2: a private master secret yields the key block, under which the relayed server Finished record decrypts to the verify_data that secret gives the relayed handshake (D-SMTP-21) |
| Z2 | Each proven plaintext, client or server, is its ciphertext XOR the keystream at its sequence number (1.2: explicit nonce) |
| Z3 | Each client record the circuit opens is unpadded application_data, with no KeyUpdate, so lengths fix offsets; BDAT's unopened body rests on the relation's count bound |
| Z4 | `EHLO <helo_name>`, `MAIL FROM:<x@b.<net>.<root>>`, exactly R × `RCPT TO` at the recipient domain, then `BDAT n LAST` or `DATA`: one transaction |
| Z5 | The header block holds, once each, a From in the declared domain, the declared Message-ID, the issued X-UR-Ref and Feedback-ID, and a DKIM-Signature with the declared d= and s= covering them; no bare CR or LF; List-Unsubscribe-Post if BULK |
| Z6 | BDAT: the chunk's n octets end at a record boundary, counted exactly over the opened head and by E3 over the unopened body, and the last client record, opened, is exactly `QUIT` CRLF. DATA: octets 1 to n end in CRLF, hold no bare CR or LF and no CRLF.CRLF, and exactly `.` CRLF `QUIT` CRLF follow |
| Z7 | The private server application key decrypts every server record the part covers (NewSessionTicket skipped; a KeyUpdate fails it); no key leaves the circuit |
| Z8 | Those replies are a valid SMTP exchange for the proven flow: the post-TLS EHLO reply advertises CHUNKING before a proven BDAT, MAIL and each RCPT get 2xx, DATA gets 354 before any message octet, and no reply refuses or reorders a record the flow treats as accepted |
| Z9 | `mode` is fixed from π2 and matches Z8's post-TLS capabilities: BDAT to an MX whose EHLO reply lacks CHUNKING is unsatisfiable |

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

**Relation (D-SMTP-22).** Public inputs are values the edge holds anyway: Z1's handshake inputs (above), the client ciphertexts a part opens (`records`, which the stream must repeat, E3), the server records it covers, the preamble and issued values, and the part's ranges. Both directions' keys, IVs and plaintext are private witnesses, and no application key or commitment to one is public, so every part re-proves Z1. A part covers the client records `first_record` to `last_record` and the server records from the previous part's `server_record_count` up to its own, so prover and edge check the same records, and it can verify before its records are sent, so the sidecar paces them (14.4). An MX awaiting a command sends no reply, so a server record relayed past a part's count, such as a late NewSessionTicket, only holds the part's message records (E3) until the next part, or the same part proven again, covers it; once the MX closes, a 421 included, outstanding parts are moot. DATA opens every octet. BDAT's π3 opens the records through the header block and the final `QUIT`; the body between streams unopened once π3 verifies, and the edge counts each of its records as its length minus 17 octets, the most a 1.3 record carries (RFC 8446 §5.2; a 1.2 record, typed in clear by E1, carries exactly its length minus 24). So the MX never counts more chunk octets than the edge: it reaches octet n and the proven `QUIT` only if every body record is unpadded application data, and otherwise ends the chunk inside the `QUIT` record, or never. No client record reaches the MX after it (14.7), and 6 octets hold no transaction, so a malformed body alters only its own unproven content or fails the send. A part that cannot be proven, as after a refused MAIL or RCPT, ends the connection before any message octet, and the sidecar retries or returns a DSN per recipient; a part resent under its `send_id` and `index` is idempotent, and one proven again with a later `server_record_count` replaces it.

```text
sidecar                         smtpedge                           MX
 (EHLO is answered before MAIL, RFC 2920 §3.1; data waits for proven replies, E3)
 |--SmtpPreamble------------------>|--banner, EHLO, STARTTLS---------->|
 |==ClientHello .. Finished (spliced; 1.3 discloses SHTS, E2)=========>|
 |--pi1: Z1 + EHLO record; key and IV are private witnesses-->| verify
 |==EHLO record (forwarded once pi1 verifies)=========================>|
 |<=EHLO reply: the post-TLS keywords==================================|
 |--pi2: server records to that reply (Z7-Z9) + MAIL, RCPT x R-->| verify
 |==MAIL, RCPT x R (forwarded once pi2 verifies)======================>|
 |<=their replies======================================================|
 |--pi3, last: replies 2xx (Z8) + BDAT n LAST, header block, QUIT--->| verify
 |==BDAT n LAST, header block, body (unopened, to n), QUIT, once pi3 verifies>|
 DATA: pi2 also covers DATA; pi3 also proves the 354 and covers the header
 block and the first body part; each later part goes once its own proof
 verifies, and the last ends ". CRLF QUIT CRLF". Without PIPELINING each
 command, QUIT included, goes only after the previous reply.
```

**DATA mode (D-SMTP-20; owner decision 125).** An MX without CHUNKING after TLS gets DATA, which ends at the first CRLF.CRLF, or on some receivers at bare-LF forms (SMTP smuggling, CVE-2023-51764), so Z6 checks every message octet, at minutes per 100 KiB on desktops. Parts carry the scan state across their boundaries, and the sidecar sizes them by its measured speed to prove within 2 min, inside the MX's 5-minute timeout (RFC 5321 §4.5.3.2.7). A 2 h connection therefore proves at most `smtp_data_proof_bytes`, measured on each host and recorded (≈1 MiB on the M1 reference, ≈600 KiB on an m5.large): a larger message to an MX without CHUNKING gets a DSN before MAIL, as does a body still unproven at 2 h, while other recipient domains and every CHUNKING MX are unaffected.

**Send capability and results (owner decision 125).** The cap stays; what a user needs is which recipient it stops, how large the message is and whether waiting helps, at composition when known and before MAIL otherwise.
- **Check.** `SmtpSender.Check(message)` reports, per recipient domain:
  - the mode: `bdat` or `data` from the post-TLS EHLO reply of this device's last session with that domain's MX, kept 90 days as its TLS pin is (14.4), or from a send outcome (`or/`, §15.7); else `unknown`;
  - the message's encoded bytes, headers, DKIM signatures and dot-stuffing included;
  - the cap: the `smtp_data_proof_bytes` of the host that will prove it, or for a phone's outbox the largest its member's prover hosts record (`p/`, §15.7);
  - the expected delay: BDAT's proofs (≤ 30 s on an M1), or a DATA send's parts at that host's measured rate (up to 2 h at the cap), plus, through an outbox, the wait for a prover host;
  - a prediction: `ok`, `too_large` (mode `data` and bytes over the cap) or `unknown` (mode `unknown` and bytes over the cap).
- **Outcomes.** Each send records, per recipient domain, one of: `sent`; `queued` (in the outbox for a prover host); `deferred` (TRY_LATER, QUOTA or HALTED, with `retry_after_ms`); `too_large` (bytes and cap); `refused` (the MX's reply code); `tls_refused` (TL4 or below a pin); or `failed`. `too_large` is decided before MAIL, once the post-TLS EHLO reply lacks CHUNKING: a prover host whose cap is under the bytes leaves the message, as `deferred`, to one whose recorded cap fits, and records `too_large` when none does. The outcome and the mode go to the outbox entry's result (§15.7), so every device of the member learns the domain's mode.
- **Copy.** Only `too_large` cites the DATA cap, naming that domain, the size and the cap. Other recipient domains keep their own outcomes, and no outcome points to an inbound indexer, receiver or coverage setting (§18.5).

**The M9 gate (D-SMTP-16)** turns owner decisions 35, 99 and 125 into tests, in both modes:
- **Soundness.** `smtpproof/SPEC.md`, frozen at M9's entry review, states the relation (D-SMTP-22), public inputs, E1-E3, soundness against a malicious sidecar (a colluding MX gets only its own mail) and zero knowledge against a malicious edge that ran the setup, and names the sidecar's TLS client, whose TLS 1.3 handshake yields the HS that Go's `KeyLogWriter` never exports (14.3). Two engineers who did not write the circuits argue soundness in writing. Through that client, in both TLS versions and modes, §22's adversarial corpus must fail before any effect while honest controls pass: key substitution, record splits, replayed server replies, a pipelined second transaction, smuggled headers, an early or bare-LF DATA end, and scripted MXs with no CHUNKING, CHUNKING only before TLS, no PIPELINING, a refused MAIL or RCPT, mixed recipient outcomes, no 354, a late NewSessionTicket, or a second transaction in the alleged BDAT body; padded or KeyUpdate BDAT body records may fail the send but smuggle nothing.
- **Speed** (p95). BDAT, for a 4 KiB header block and 10 recipients: ≤ 10 s for π1 and ≤ 30 s for π1 to π3 on an Apple M1 MacBook Air (8 GB), ≤ 60 s on an AWS m5.large. DATA, for a 100 KiB message: ≤ 10 min and ≤ 20 min. For scale, ORIGO proves in 1.5 s (c5.4xlarge) to 9.8 s (m5.large) with a 112 MB proving key, and in-circuit AES-GCM takes over 1 s per 512 B on an M2 MacBook Air ([R:ext-email-zk] §2.12).
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
X-UR-Ref: 1.<base32(key_id ‖ send_id[12] ‖ HMAC-SHA256(key, send_id ‖ network_id ‖ day)[0:8])>   ; the edge's
Feedback-ID: <class>:<tier>:<nettoken>:urnetwork   ; the edge's; nettoken: a keyed hash of the network id,
                                                   ; constant for burners, and the <token> of its rua
```

- **Alignment (D-SMTP-5).** SPF never aligns (`-all` on the header domain `<net>.<root>`; the envelope domain `b.<net>.<root>` passes SPF), so on shared sending addresses only strict DKIM alignment stops network A passing DMARC as `From: x@B.<root>`. `_dmarc.<root>` is strict too, since burner domains have no `_dmarc` and receivers fall back to it (RFC 7489 §6.6.3).
- **DKIM (owner decision 36).** Each sending sidecar generates RSA-2048, and URnetwork publishes only public keys through `POST /smtp/dkim-keys`, replying and forwarding burners' selectors included until the PSL listing (owner decision 79; §15.9). Opaque selectors rotate every 90 days, keeping the retired one 7 days; removal (§7.10, I-15) deletes the sidecar's selectors in the same write. Signing is relaxed/relaxed, no `l=`, oversigned From, `x=` 7 days, plus a second signature over only `from:date:message-id:x-ur-ref:feedback-id`, which survives reports that mask recipients.
- **Addresses (owner decision 124).** smtpedge sends from its hosts' shared lb IPv4 addresses, each with one PTR name, `o<k>.out.bringyour.com`, that HELO repeats and whose A record names it (FCrDNS); no address sends before its FCrDNS holds. Every network and burner shares every address, with no IP pools or per-IP warm-up; reputation is per sending domain and per network, through selectors, halts and rate limits (14.7, 14.8). A listed address leaves the sending set, not ingress, within the feed refresh, its mail spreading over the remaining shared addresses, and rejoins after delisting and 3 clean days (§21.5).
- **Team custom domains (v1, D-SMTP-15).** A Team network's verified `network_domain` (§7.6) may be the header domain, its `_domainkey` delegated to §12 or CNAMEd per selector to `<net>.<root>`, its `_dmarc` at `adkim=s` (§2.8 EX2). The envelope stays `b.<net>.<root>`; strict mode (§15.4) moves it to `b.<domain>`, with the customer's MX and SPF include, as Z4 proves.

**PSL listing (owner decision 79).** Once `<root>` is on the PSL (§12.4) and a test network's burner mail, signed only under its network selector, passes DMARC at Gmail, Outlook.com and Yahoo (D-SMTP-5), each `_dmarc.<net>.<root>` switches to `adkim=r` and burners sign with the network's selectors; 7 days later §12 deletes the per-burner selectors and records. `_dmarc.<root>` keeps `adkim=s`.

### 14.7 Quotas

The unit stays PLAN.md:89's outbound connections per UTC day (owner decision 30), at PLAN.md:356's 5/200/20,000, hard (owner decision 27); §20.4 holds the `smtp_*` keys and numbers. A connection carries one message to one recipient domain (14.4) and costs a unit once its MAIL record is forwarded, an earlier refusal only a burst token; retries, forwards and relayed replies are new connections (§15.10). The recipient cross-check is a daily cap (D-SMTP-14): each preamble reserves its recipient count, capped per message and proven exact by Z4, against `smtp_recipients_per_day`, or gets QUOTA.

**Abuse limits** (`sidecar_abuse:`, equal on every tier, D-QUOTA-7; §21 tightens them per network):
- **Send gate (D-SMTP-14).** Internet mail needs `network_abuse_state` standard or better and starts 24 h after `POST /mail/enable` (§15); restricted networks resume at Community caps after a halt, and probation and anonymous-only networks deliver only same-network deposits (§21.7; D-MAIL-8; owner decision 96).
- **Breaker.** Community connections are capped per hour at the larger of 500 and 3× the trailing 7-day hourly median; a trip answers Community preambles TRY_LATER and alerts §19.
- **Destinations.** At most 200 Community connections per destination domain per hour; concurrency caps per (sending address, destination /24).
- **Records.** The edge forwards exactly the records E3 admits, within 14.4's time limits; a client record its part refuses (unequal ciphertext, or a body past octet n), or a failed part, cuts the connection (14.8). Once the MX has closed, an outstanding part is moot, and a client record after the final `QUIT`, such as a close_notify, only ends the connection unforwarded; neither is a cut.

**Enforcement.** Each preamble runs one Redis script on `{smq_<networkId>}` (halt, bucket, concurrency, the day's counters and reservations); MAIL debits a connection and its recipients, and close the observed bytes. Keys expire after 48 h; refusals return QUOTA with `retry_after_ms`.

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
| 3 halts in 30 days | Suspension until §21 reviews it |

- **Mechanics.** A Redis flag plus an `smtp_halt` row, for the network or one label, lasts 24 h from the report's arrival; edges reload every 60 s. New preambles in scope get HALTED, in-flight connections finish, and a §6 `mail` hint holds the sidecar's queue.
- **Appeals.** An admin, never a client token (AUTHZ1), appeals via `POST /smtp/appeal`; rechecks lift halts from duplicates, replays or contradicted medium joins, and §21 reviews the rest. smtpedge stores no session ciphertext (D-SMTP-10), so the only content evidence is the network's sealed report copy, which it may volunteer.
- **Reports (D-SMTP-12, D-SMTP-23; owner decision 78).** ARF parsing is header-only: the `message/feedback-report` part and, to the first CRLFCRLF (≤ 64 KiB), an enclosed `message/rfc822` or `text/rfc822-headers` header block (DKIM-Signature, Message-ID, X-UR-Ref, Feedback-ID, From domain, Received); no enclosed message body or attachment is decoded. Aggregate reports' XML or JSON, machine data rather than user content, is parsed within 8 MiB inflated (`report_inflate_bytes`) and a 100:1 ratio, with DTDs and external entities refused and nesting ≤ 32; it counts only from a reporter whose DKIM verifies, at the network's `rua` token, once per (reporter, `report_id`). The raw bytes pass once, in memory, through the reporter's DKIM body hash and an HPKE seal to the network mail key (§15.8; burner reports included), kept in `smtp_complaint.sealed_report` for 30 days. The row keeps §2.8 smtp-5's fields; the last-hop Received IP and time serve the join only. Unattributable reports, role mail included, are dropped unread (§21.8).
- **Self-reports.** `SmtpOutcome` (reply codes, DSN counts, TLS level, refused downgrades) only tightens: over 10% hard bounces in 24 h halt.

### 14.9 The smtpedge service and the sidecar/server split

| Piece | sidecar repo | server, ops |
|---|---|---|
| `SmtpSender`: handoff, outbox, per-domain split, DKIM, preamble, proofs, TLS levels and pins, retries, DSNs, `Check` and per-domain outcomes (14.5); a `ReachReceipt` per send (recipients with BCC; §16.8, owner decision 25) | `smtp_*.go` | — |
| DKIM keys | `smtp_dkim_*.go`, keychain (§5) | `POST /smtp/dkim-keys`; §12 publishes |
| Engine (gate, quota, MX, pre-TLS, proof checks, splice, send log) and reports (ARF and aggregate parsing, attribution, seal, halt, reconcile) | `smtpedgeservice` | `server/cli/smtpedge`, `SmtpEdgeStore`, vault `secret_files`; taskworker jobs |
| Prover and verifier (TLS 1.2 and 1.3; BDAT and DATA) | `smtpproof`, a nested module the root never requires; `cli/` injects its provers on desktop builds (owner decision 104; §4.4) | server injects the verifier into smtpedge |

```go
type SmtpEdgeStore interface { // server implements; batched, off the connection path
	InsertSends(ctx context.Context, sends []*SmtpSendRecord) error
	FindSends(ctx context.Context, key *SmtpJoinKey) ([]*SmtpSendRecord, error)
	InsertComplaint(ctx context.Context, complaint *SmtpComplaint) error
	InsertAggregate(ctx context.Context, report *SmtpAggregateReport) (inserted bool, err error) // once per (reporter, report_id)
	SetHalt(ctx context.Context, halt *SmtpHalt) error
	ActiveHalts(ctx context.Context) ([]*SmtpHalt, error)
}
func NewSmtpEdgeService(ctx context.Context, host *ServiceHost, store SmtpEdgeStore, verifier SmtpProofVerifier, settings *SmtpEdgeSettings) (*SmtpEdgeService, error)
func (self *SmtpSender) Send(ctx context.Context, message *SmtpOutboundMessage) (*SmtpSendResult, error)
```

- **Shape.** One connect client per process on a platform JWT in `urnetwork-edge`, on the two sending hosts (§19.4); each dial binds one of its host's lb addresses in the sending set by fwmark; no lb route or inbound port.
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

**D-SMTP-2 (proposed).** STARTTLS is mandatory, TL4 needs the user's consent per recipient domain, and no host is sent below its pin (14.4). *Why:* an active edge could read such mail.

**D-SMTP-3 (proposed).** The preamble is protobuf frames ahead of raw TLS (14.5). *Why:* PLAN's placement without PROXY v2's 2,048 B parser cap (server/connect/transport_pp.go:28), and versioned.

**D-SMTP-4 (withdrawn).** Superseded by owner decision 35: no declared preamble ships, and D-SMTP-16 sets the proof gate.

**D-SMTP-5 (proposed).** 14.6's identity: header domain `<net>.<root>` with SPF `-all`, envelope `b.<net>.<root>`, strict DMARC with `rua` only, FCrDNS with HELO = PTR (owner decision 124), relaxed alignment only after the PSL test. *Why:* only the network's key passes, bulk rules hold (https://support.google.com/a/answer/81126), and old PSL copies still apply the strict `_dmarc.<root>`; a listed address leaves the sending set (14.6), with no separate IP pool (owner decision 124).

**D-SMTP-6 (proposed).** The sidecar declares the Message-ID; the edge issues a MAC'd X-UR-Ref and a per-network Feedback-ID (14.6). *Why:* unforgeable references with no recipient data.

**D-SMTP-7 (withdrawn).** Superseded by owner decisions 34 and 124: smtpedge sends from the shared lb addresses, with no IP pools.

**D-SMTP-8 (proposed).** Attribution has three confidence levels; only high and medium halt, and a medium join needs a verifying `d=` of the X-UR-Ref MAC's network (14.8). *Why:* resists replay, forgery and guessed Message-IDs, and a recipient on the shared addresses replaying another network's X-UR-Ref.

**D-SMTP-9 (proposed).** Halts are 24 h Redis flags with `smtp_halt` rows, per network or burner label (14.8). *Why:* PLAN.md:91 without per-packet work.

**D-SMTP-10 (proposed).** Retention follows §2.8 smtp-1 to smtp-6, plus 14 days of backups; send records keep the MX host, not its IP, and recipients, third-party IPs, subjects, bodies, report plaintext, session ciphertext and record lengths are never stored, nor the SHTS that sidecars disclose (E2); everything else a connection shows stays in memory. *Why:* joins need only a network and a time (§2.11).

**D-SMTP-11 (proposed).** The engine is `smtpedgeservice`, hosted by `server/cli/smtpedge`; the prover and verifier are the nested module `smtpproof`, which the root never requires (owner decision 104). *Why:* owner rule 1; no client links the engine, and only desktops link the prover.

**D-SMTP-12 (proposed).** Reports are parsed header-only, aggregate attachments by D-SMTP-23's bounded parser, then sealed unparsed to the network mail key or dropped (14.8). *Why:* the directive; attribution needs only headers and aggregate counts, neither of them user content.

**D-SMTP-13 (proposed).** For a URnetwork MX, smtpedge splices to mxedge over the host LAN (14.4). *Why:* Q-ARCH-3 (a); TLS stays sidecar to sidecar.

**D-SMTP-14 (proposed).** 14.7's send gate, breaker and destination caps bound Community volume, and its daily recipient cap every tier. *Why:* free Sybils are the largest risk, and connections alone would allow a Team network 2,000,000 recipients a day.

**D-SMTP-15 (proposed).** In v1, Team networks send from verified custom domains (14.6). *Why:* PLAN.md:364.

**D-SMTP-16 (proposed).** M9's gate is 14.5's soundness, speed, coverage and interop tests, in both modes, through the sidecar's own TLS client. *Why:* owner decisions 35, 99 and 125 set the bar without a threshold or method.

**D-SMTP-17 (withdrawn).** Superseded by owner decision 125: the DATA-mode proof is built beside BDAT, and DATA coverage is part of D-SMTP-16's gate (D-SMTP-20).

**D-SMTP-18 (proposed).** Phones do not prove: they write outbound mail, signed by their identity key, to the member's mailbox outbox (§15.7), which one of the member's consented prover hosts (§8.5; owner decision 126) sends as in 14.4, burner replies and forwards included (owner decision 53). *Why:* no phone proves yet, and plaintext stays on the member's devices.

**D-SMTP-19 (proposed).** Reports and role mail go to `rpt.bringyour.com`, whose TCP 25 reaches only §15.4's platform listener, terminating every session, SNI or not; `<root>`'s MX names it for `abuse@` and `postmaster@` (§21.8), from M5. *Why:* reporters without SNI must deliver; platform names stay off `<root>` (owner decisions 13, 16).

**D-SMTP-20 (proposed).** 14.5's DATA mode: every message octet proven, in 2-minute parts, within a 2 h connection, up to the host's measured `smtp_data_proof_bytes` (≈1 MiB on an M1); a larger message to an MX without CHUNKING gets a DSN and, for that recipient domain alone, a `too_large` outcome naming its size and the cap, which `Check` predicts once the domain's mode is known (14.5). *Why:* owner decision 125 keeps MXs without CHUNKING reachable, and its limit is outbound, so it belongs on the send, per recipient, not on receiver coverage (meta review K04); DATA ends by content, so an unchecked body could smuggle a second transaction; an idle MX closes after 5 min; and in-circuit AES-GCM bounds what 2 h proves.

**D-SMTP-21 (proposed).** Z1 proves TLS 1.2's server Finished in-circuit, so no 1.2 key is disclosed (14.5). *Why:* the server write key would open every MX reply, some of which echo recipients.

**D-SMTP-22 (proposed).** 14.5's relation also proves the MX's authenticated replies (post-TLS capabilities, envelope replies, the 354) under private server application keys (Z7-Z9); each part carries the client ciphertexts it opens and names the server records it covers, no message record leaves the edge before verified parts cover every server record relayed before it, and BDAT's body streams unopened under the relation's count bound; `smtpproof/SPEC.md` freezes it. *Why:* a malicious sidecar's control flow is no evidence of the MX's grammar (RFC 3030 §2, RFC 3207 §4.2); an implicit server range fails an honest part when a record arrives during proving; and a part that verifies before its records are sent lets the sidecar pace commands for an MX without PIPELINING and keeps message bodies out of edge memory.

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
- **Subprotocol messages** (service 0x16, §6.11): `SmtpPreamble`, `SmtpPreambleResult` and `SmtpOutcome` on the stream to smtpedge; `SmtpProof`/`SmtpProofResult` (RPC to smtpedge; π1-π3 and DATA parts; M9); `SmtpStatus` (push `mail`; halt, quota).
- **API routes** (connect/api/bringyour.yml; server/api/route_authz.go classifies the Client routes sidecar, on §7.4's `strict_exp` allowlist): `POST /smtp/dkim-keys` (Client with `mail_send`; network and burner selectors); `GET /smtp/status` (Client; quota, halt); `GET /smtp/reports?since=` (Client with §8 read; fields, sealed copies); `POST /smtp/appeal` (admin scope, never a client token, so the allowlist still refuses it).
- **Tables** (smtpedge; migrations ≥926): `smtp_send` (daily partitions, PK (send_day, send_id), dropped after 30 days), `smtp_complaint` (13 months, with `sealed_report`, cleared at 30 days), `smtp_halt` (13 months), `smtp_dkim_key` (deleted 30 days after its selector leaves DNS), `smtp_dmarc_daily` (13 months; per network, day, reporter, header_from and `report_id`, so each report counts once); Redis `{smq_<networkId>}`.
- **Services and config:** `server/cli/smtpedge`; `config/<env>/smtpedge.yml` (sending addresses, HELO names, loop allowlist, report parser bounds); vault X-UR-Ref keys; `pro.yml` keys and `sidecar_abuse:`; taskworker jobs for reconciliation, retention, sealed reports and key expiry.
- **Assumptions about other sections:** §12 runs 14.6's PSL steps, serves the reverse zones and Team `_domainkey` delegations, and writes a burner label's explicit MX and addresses with its first selector, removing them with its last (D-DNS-11); §19 W11 publishes the HELO names' A records; §21.5's breakers pull a listed address from the sending set; §2.8's smtp-2 lists proofs π1 to π3 and, in DATA mode, one per later body part, `helo_name`, the length and timing of every client and server record, and no key that opens application data (D-SMTP-21, D-SMTP-22), and smtp-5 the aggregate parser (D-SMTP-23); §22 runs FS-31's scripted MXs (no PIPELINING and a late NewSessionTicket included), padded and KeyUpdate BDAT body records, a mutated witness for each of E1-E3 and Z1-Z9, the X-UR-Ref replay, FS-39's report-intake cases at M5-out, halt scoping, and network A failing DMARC as B's burners too.

### 14.15 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| The BDAT or DATA proofs miss D-SMTP-16's bar, or unaudited circuits are unsound (owner decisions 99, 125) | High | High | Started in M0; `SPEC.md`, non-author analysts, §22's corpus, the RUA check; disclosed as unaudited (owner decision 119); burner email launches receive-only (owner decisions 9, 35) |
| DATA proves minutes per 100 KiB, so a message above `smtp_data_proof_bytes` (≈1 MiB on an M1) to an MX without CHUNKING gets a DSN, and smaller ones are slow or hit the MX's session limit | Medium | Medium | 2-min parts; the cap reaches only the non-CHUNKING tail the M7 census sizes; `Check` and the `too_large` outcome name the size, the cap and the domain at composition or before MAIL (14.5); retries; a designated-verifier prover (Later) |
| Sybil free networks send their caps | High | High | Send gate, breaker, halts |
| A mail listing of a shared lb address also blocks api and connect ingress there; with no separate IP pool to drain to and no warm-up (owner decision 124), enough listings degrade sending and the shared ingress together (accepted) | Medium | High | The listed address leaves the sending set (14.6); per-domain and per-network reputation; halts; §21.5's breakers; delisting |
| HE refuses port 25 or reverse delegation | Unknown | Critical | Ask in M0 |
| MXs without a covered TLS version or suite, and phone-only members, get no outbound mail | Medium | Medium | Census, DSN, outbox (D-SMTP-18); designated-verifier prover (Later) |
| A refused or mixed RCPT ends the connection before data, so the resend costs a second unit | Medium | Low | Resends go only to accepted recipients; Z8 keeps the proven envelope exact |
| Weak signals: bounces after the envelope are self-reported, hiding some list-washing; Postmaster Tools or Yahoo CFL ignore subdomains | High | Medium | Self-reports; connections ending before π3 bound envelope refusals (Z8); IP-based loops, RUA; test first |
| A compelled edge reads TL4-override mail | Low | High | Off by default; pins; label (§2.8 EX4) |
| After the PSL switch, a receiver on an old PSL copy aligns one network's selector with another's From | Low | High | 14.6's test gate (D-SMTP-5) |

### 14.16 Phasing

- **Before M9:** the report host with header-only and aggregate parsing (M5), whose M5-out waits on FS-39's report-intake cases, with S7's SNI-less abuse@`<root>` case run at M5 (§22.17, §23.6); the outbound probe (M7).
- **v0 (M9; owner decisions 35, 99, 124, 125):** the relay with edge-driven pre-TLS; TL1-TL3, TL4 refusal and pins; TLS 1.2 and 1.3 circuits in BDAT and DATA modes, proving the MX's replies (D-SMTP-22), past D-SMTP-16; the LAN splice; per-sidecar DKIM, strict DMARC; the shared lb addresses with bringyour.com PTR and HELO names, none sending before its FCrDNS holds; quotas, send gate, breaker, record cuts; header-only reports, reconciliation, halts; the outbox, with §15's replies and forwarding; the send check and per-recipient-domain outcomes (14.5). Blocked by D-SMTP-16, HE, C9 (M5), §12 and §15.
- **v1 (Team, from M9):** custom domains.
- **Later:** a designated-verifier (VOLE) prover for phones and faster DATA (megabytes per message); the PSL cut-over (14.6); DKIM2.
