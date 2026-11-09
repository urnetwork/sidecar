## 15. The local email server, inbound mail, and burner email

### 15.1 Purpose and scope

This section owns the sidecar's `mail` component (`mail_*.go`, §4) and the `mxedgeservice` engine that server hosts as `mxedge` (owner decisions 19, 104): the local SMTP server for `mx.<net>.<root>`, inbound routing (X6), platform report mail, offline behavior, the mailbox, labels, mail search's scope, addresses and burner email. mxedge sees ciphertext plus §2.8's mx-1 to mx-4. Sending, DKIM and abuse are §14's; records §12's; certificates §13's; keys §10's; deposits §11's; approvals §16's; phones §18's; hosts §19's; quotas §20's.

### 15.2 Requirements

| id | requirement | source |
|---|---|---|
| R-MAIL-1 | A local SMTP server "terminates a public `mail.<me>.ur.network`", stores mail encrypted and sends through the SMTP edge | PLAN.md:104 |
| R-MAIL-2 | Inbound TLS ends on customer devices; servers see ciphertext and small header values only, D-MAIL-10's report intake excepted (§2.8 mx-4) | CONVENTIONS §0; D-TRUST-4 |
| R-MAIL-3 | An admin address; unlimited aliases, each an id or a group, with members and a history | cli/UI.md:21-27, :68-71 |
| R-MAIL-4 | Each id or group has a title, password, one-time auth, URL and notes | cli/UI.md:72-73; MM:633-657 |
| R-MAIL-5 | Group addresses fan out to every member | RA:1584; [R:product] §2.2 N3 |
| R-MAIL-6 | Burners: generated addresses, "Used at", inbox, reply, compose, logins, notes, autofill | MM:467-657 |
| R-MAIL-7 | Burners show no network name without an alias, and a network's burners are linkable | [R:product] §2.3; owner decision 32 |
| R-MAIL-8 | Mail sent while devices are offline survives the sender's retry window | [R:product] §2.2 E6; owner decision 12 |
| R-MAIL-9 | Listeners use §9's `smtp/<port>/<host>` | PLAN.md:69 |
| R-MAIL-10 | Outside mail is untrusted and taints the run | sidecar/design/pitch5.html:707; I-9 |
| R-MAIL-11 | A released label routes no mail to a new owner while retries live | I-14; R-DNS-5 |
| R-MAIL-12 | Storage is 1/20/200 GB; sends are 5/200/20000 per day | PLAN.md:355-356; owner decision 27 |
| R-MAIL-13 | Works in the daemon, the apps and the extension worker | PLAN.md:28 |
| R-MAIL-14 | Approval by email reply: dropped (owner decision 80) | P5:899 |
| R-MAIL-15 | Abuse and DMARC, TLS-RPT and feedback-loop reports reach URnetwork without SNI | PLAN.md:91, :97; RFC 2142 |
| R-MAIL-16 | Received mail is labeled "validated" or "opportunistic", checkably, from DNS as it stood at reception | owner decisions 98, 135; I-11; RFC 6376 §3.1 |
| R-MAIL-17 | Find an email: substring, partial-word, multilingual and typo-tolerant search, answered at once over the last 30-60 days by default and on "search more" over older mail | owner decisions 151, 152 |

### 15.3 What exists today

- **No inbound mail.** Account mail is outbound-only SES (server/controller/aws_controller.go:638-705), whose bounces and complaints "never reach code" (server/EMAIL1.md:44). ur.network's MX is Google Workspace, with DMARC `p=none`, in a zone signed without a DS (§12.3).
- **lb and warp.** No port 25 exists. Stream ports send PROXY v1 with the sender's address (warp/warpctl/config.go:2508-2510), and an lb interface may send a TCP port to its own service (`tcp_stream_port_services`, warp/services/services.go:1001).
- **connect** keeps TCP/25 local (connect/ip_smtp_policy.go:16-19) and before TLS passes only EHLO, HELO, QUIT and STARTTLS, within 2,048 B and 510 B per line (:29-30). `DohCache.Forward` resolves over DoH (connect/net_http_doh.go:1111).
- **emersion/go-smtp v0.25.0 (MIT)** takes connections only through `Serve(net.Listener)`, whose `greet()` always writes a 220 (https://github.com/emersion/go-smtp, read 2026-11-03).
- **Senders** ([R:ext-email-zk] §2.2, §2.5). Postfix and Exim send SNI only under DANE (RFC 7672 §8.1); by anecdote Gmail does, Yahoo, AOL and Proton do not, and SES is unknown. Postfix at level `may` retries with TLS before plaintext (https://www.mail-archive.com/postfix-users@postfix.org/msg99840.html, 2023-08-15). Retry windows run 14 h (SES) to 5 d (Postfix).

### 15.4 Inbound architecture (X6)

**Roles.** mxedge's router serves TCP 25 on every lb interface but the platform listener's two (owner decision 34; §19.5 W4), as a `urnetwork-edge` platform client (§13.6) in Service mode (C9), holding no TLS key. A receiver is a sidecar with an approved `listen` on `sock:smtp/25/mx` (15.5): it holds its mail-host key and sees its hosts' mail in transit, but only deposits to the drop key (§10); readers decrypt (15.7). A mail indexer is a receiver its network designates (§3.6, §7.9; owner decision 150), the reliable kind (15.6).

```text
sender MTA --TCP/25--> lb stream port (PROXY v1: sender address) --> mxedge router (urnetwork-edge)
  router: 220; EHLO reply (STARTTLS, ENHANCEDSTATUSCODES); "220 2.0.0 Ready to start TLS"
  router: read ClientHello; route by SNI: mx.<net>.<root>, an alias's or scope's, or a custom MX host
  §9 Find <network_id>:smtp/25/mx (a scope's: mx.<scope>) with the edge's K client ids (§9.6)
  §6 StreamOpen{ticket, MailIngress, early_data=ClientHello's first 2,048 B} on a Required stream (D-PROTO-6)
receiver: tls.Server, no second 220; EHLO, MAIL, RCPT, BDAT/DATA; SPF, DKIM, DMARC and PTR as received
  --> deposit (§11.12): the body under its own key, that key in a slot to the drop key, a sealed header
      with MailIngress and MailAuthEvidence --> 250 once durable
reader: ingest; score and label from the sealed evidence (15.5); write the 15.7 layout

report sender --TCP/25--> rpt.bringyour.com (two other lb interfaces) --> platform listener
  TLS ends here, SNI or not; RCPT only <token>@rpt.bringyour.com, postmaster@<root>, abuse@<root>
```

**Routing (Q-MAIL-1).** RCPT arrives inside TLS, so the router routes on SNI alone, through `{mxr_}` (15.15), to the network, alias, Team scope (owner decision 58) or strict-mode custom MX host (§12.8) it names. DANE TLSA, live from M7 after §12's soak (owner decision 109), makes DANE senders send SNI.

**Team (v1; owner decisions 33, 98).** A direct MX (`POST /mail/direct-mx`) names up to two of the network's mail indexers answering public TCP 25 themselves; mxedge verifies each (a public unicast address, STARTTLS, its `mail_host_key` SPKI) before §12.8 points `mx.<net>.<root>` at it and `{mxr_}` drops the network, re-probes every 5 min and alerts with `MailHint{receiver_needed}` after 15 min of failures, reverting only on `DELETE`; a receiver's removal drops its address (I-15). Under the config's signed `mail.strict`, receivers refuse spliced sessions for URnetwork-zone MX hosts and accept direct-MX sessions and splices for custom MX hosts whose customer-signed zones carry their TLSA (§12.8 step 4), which they watch (D-TRUST-9). Only that custom-MX path, with every MX the recipient domain lists and its TLSA under customer authority, keeps URnetwork from redirecting a DANE sender, and only its mail carries `tls_basis.strict_custom_mx` (15.5). In URnetwork's zone, a direct MX included, an operator can replace the MX, A and TLSA records, and the sender then delivers where no receiver checks (RFC 7672 §2.2): ordinary mail with EX2's residual. Senders without DANE stay exposed (EX3).

**mxedge protocol (D-MAIL-2).** Before TLS, the router accepts only EHLO, HELO, STARTTLS and QUIT, within connect's limits; any byte between STARTTLS and its 220 resets the connection (the CVE-2011-0411 class). The banner names `mx.bringyour.com` (owner decision 16).

| Situation | Response |
|---|---|
| SNI names a mail-enabled network, and a receiver accepts (§9.6) | splice |
| SNI names one with no receiver, or sockets is down (§9.8) | close in the handshake, from M8 after a wake hold of up to 30 s (15.6) |
| SNI missing or unknown | close in the handshake (owner decision 34) |
| Plaintext MAIL, RCPT, DATA or BDAT | `451 4.7.0` within 1 h of a closed handshake from the sender's /24 or /48, fleet-wide; else `530 5.7.0`, linking the published deviation (owner decision 33, §21.11) |
| A botnet or exploit listing (below) | `554 5.7.1` at the banner (owner decision 111) |
| Over a cap: per sender /64 or /32, with /48 and /24 aggregates; 2 sessions per sender /24 per network; per network | `421 4.7.0` |

**Listings.** The banner rejects only a commercial feed's botnet and exploit categories (for example Spamhaus XBL: https://www.spamhaus.com/data-access/rsync/, read 2026-11-04), from a licensed local mirror refreshed every 5 min, so no sender IP leaves for a lookup; other categories pass in `MailIngress.ip_listings`, and with the feed down nothing is rejected.

**Memory and limits.** A closed handshake writes Redis `{mxc_<HMAC_k(prefix)>}` for the sender's /24 or /48, for 1 h under a daily `k`, storing no address (§2.8 mx-1), so a Postfix plaintext retry from a sibling sending address or another lb host gets 451. Splices end after 10 min idle (RFC 5321 §4.5.3.2.6), 10 min with under 1 MiB passed, 30 min, or 2× the message cap plus 1 MiB. Each router session leaves one `mail_connection_record` row (receiving network, time, size, result; no sender address or burner label), written in 10 s batches and kept 24 h, a §21.9 hold's copy excepted (§2.8 mx-2; 15.15).

**Platform mail (D-MAIL-10; from M5).** `<root>`'s MX and §14.8's report addresses name `rpt.bringyour.com` (D-SMTP-19; §19.5 W4). Its listener terminates every session under a bringyour.com certificate, with the router's caps and plaintext refusal, refuses other recipients with `550 5.1.1` and passes the rest to §14.8's intake, which parses headers and aggregate report data only (D-SMTP-23), seals the raw bytes and persists no plaintext (owner decision 78; §2.8 mx-4, the statement's one exception). Session envelopes stay in memory.

### 15.5 The receiver: local SMTP server, listener, certificates

**Library (D-MAIL-3).** emersion/go-smtp with an upstreamable `ServeConn(conn, ServeConnOptions{AfterStartTls: true})` that skips `greet()` (RFC 3207 §4.2), pure Go for gomobile and wasm (sdk/js/Makefile:69). Receivers verify mail as it arrives with emersion/go-message and mox's `spf`, `dkim` and `dmarc` (MIT) over `DohCache.Forward` (D-MAIL-14).

**Listener.** Each receiver holds one §9 registration, `smtp/25/mx` (a scope's: `smtp/25/mx.<scope>`), protocol `smtp-starttls`, `max_streams` 16, `serving=false` until its key is published; burners share it, a Find samples at most 64 receivers (§9.7), and the `listen` grant needs an I-8 approval. In a member scope (owner decision 58), `ValidateListen` (§9.4) and §12's `/dns/key-record` accept only that member's consented devices (§8.5; owner decision 126), and readers alarm on a scope deposit from any other receiver. Under `team_mail: indexers` (owner decisions 58, 150), a `tag:mail` device registers only once an `IndexerSet` designates it for mail (§7.9), members' devices list those mail indexers as the devices that see the network's mail in transit, and readers alarm on internet mail whose `MailAuthEvidence.receiver_sidecar_id` names any other receiver (D-MAIL-15).

```proto
message MailIngress {                // 0x1701 (§6.11), in StreamOpen.metadata, <= 1,024 B
  reserved 4, 6, 7;                  // destination_ip, route, burner_id: SNI-only routing
  uint32 version = 1;
  bytes sender_ip = 2;
  uint32 sender_port = 3;
  string sni = 5;
  string ehlo_name = 8;              // pre-TLS argument, <= 255 B
  string ptr_name = 9;               // mxedge's forward-confirmed PTR, or ""; labels use the receiver's own
  repeated string ip_listings = 10;  // categories from the local feed mirror, e.g. "pbl"
  uint64 receive_time_millis = 11;
}
```

**Session.** EHLO advertises SIZE (the tier cap), 8BITMIME, SMTPUTF8, PIPELINING, CHUNKING, ENHANCEDSTATUSCODES and REQUIRETLS (RFC 8689), without AUTH. MAIL must follow the handshake within 60 s. RCPT is checked against the signed `mailcfg` (15.8): unknown `550 5.1.1`, full `452 4.2.2`, at most 100. DATA and BDAT stream into the sealer in 64 KiB chunks. `250` follows evs's confirmation of the deposit, and `451 4.3.0` its failure, including a drop key still pending under D-KEYS-17's rule, §11.13's write-budget refusal and §11.8's closed write gate, or a reset (RFC 5321 §3.8). Accepted mail never bounces, and no authentication result refuses it.

**Reception-time evidence (D-MAIL-14).** Before the deposit commits, the receiver checks SPF, DMARC, the DKIM signatures and the ARC chain, resolves `sender_ip`'s forward-confirmed PTR itself, every lookup over DoH (§2.8 ext-3), and notes whether the SNI host's TLSA held its key and, under `mail.strict`, whether its zone watch holds the MX-to-TLSA chain customer-signed, sealing the verdicts and the records relied on, never a DNS transcript; a failed lookup records `temperror`. A sender chooses how many signatures it adds and how slowly its selectors answer, and RFC 6376 §6.1 lets a verifier limit the signatures it tries, so the work is bounded per message and per receiver (below). A check a bound stops counts as no result, the evidence's `limits` records what was skipped, and the message is deposited and answered 250 like any other, since no authentication result refuses mail (Session).

```proto
message MailAuthEvidence {         // sealed in the deposit header beside MailIngress (15.7); at most 8,192 B
  uint32 version = 1;              //   whatever its identifiers, by the evidence row below
  bytes message_sha256 = 2;        // the bytes as received, before ingest adds headers
  uint64 receive_time_millis = 3;
  bytes receiver_sidecar_id = 4;
  SpfResult spf = 5;               // pass|fail|softfail|neutral|none|temperror|permerror|incomplete;
                                   //   domain, ip, records
  repeated DkimResult dkim = 6;    // per selected signature, in selection order: d=, s=,
                                   //   pass|fail|permerror|temperror|incomplete, the public key relied on
  DmarcResult dmarc = 7;           // the record (p, adkim, aspf), alignment, pass|fail|none|temperror
  string ptr_name = 8;             // the receiver's own forward-confirmed PTR of sender_ip, or ""
  bool sni_tlsa_live = 9;          // the SNI host's TLSA held this receiver's key
  ArcResult arc = 10;              // cv= (none|pass|fail|incomplete), and each verified set's d=, s= and key
  bool strict_chain = 11;          // mail.strict: SNI named a custom MX host, and this receiver's zone watch
                                   //   (D-TRUST-9) holds every recipient domain's MX hosts and that host's
                                   //   TLSA, with this key, customer-signed, none in a URnetwork zone
  AuthLimits limits = 12;          // set only when a bound below cut the work
}
message AuthLimits {
  uint32 reason = 1;               // bits: 1 a count or size bound, 2 the 30 s deadline
  uint32 dkim_seen = 2;            // DKIM-Signature fields counted, at most 64
  uint32 dkim_checked = 3;         // those selected and looked up, at most 8
  uint32 arc_sets = 4;             // the highest ARC instance seen
  uint32 dns_queries = 5;          // queries sent, DohCache hits excluded
  uint32 dropped = 6;              // dkim and arc entries dropped to stay within 8,192 B
}
```

```text
headers   the header section's first 256 KiB; DKIM-Signature fields past it, or past the 64th, are only
          counted
dkim      syntax and tags first, with no lookup (RFC 6376 §6.1.1), rsa-sha1 and RSA keys outside 1,024 to
          8,192 bits being permerror (RFC 8301 §3); then at most 8 signatures, those whose d= aligns with
          the From domain under DMARC's relaxed rule first, each group from the bottom of the header up
          (oldest first), each (d=, s=) key looked up once; every other signature counted, never verified
arc       RFC 8617 §5.2's structure checks first, with no lookup: over 50 sets, a missing or repeated
          instance, or a newest set marked cv=fail is cv=fail; up to 8 sets, the newest
          ARC-Message-Signature and every ARC-Seal are verified; 9 to 50 sets are cv=incomplete,
          with no lookup
spf       RFC 7208 §4.6.4's limits: 10 terms that look up, 2 void lookups, 10 addresses per mx or ptr term
dns       at most 64 queries a message beyond DohCache hits, 8 in flight, each answered within 5 s or
          temperror; DMARC's record and the aligned DKIM keys go first, then SPF, the PTR, the other
          keys and ARC's
work      30 s for the whole check, whatever is unfinished then being incomplete, counted from when one of
          the receiver's 4 check slots (below) takes the message after its last byte (DATA's end or the
          last BDAT), so waiting for a slot costs it no checking; at most 9 body hashes (8 DKIM, ARC's
          newest) and 17 signature checks a message
receiver  at most 4 messages check at once, the rest waiting in arrival order, so with max_streams' 16
          sessions each check ends within 2 min of its message's last byte, inside the sender's 10 min
          (RFC 5321 §4.5.3.2.6)
verdicts  only a verified signature or SPF evaluation passes; a selected signature the deadline cut is
          incomplete, and an unselected one has no entry; DMARC passes only on a verified aligned pass,
          is temperror when an aligned check was cut and nothing aligned passed, and is otherwise RFC
          7489's fail or none over what was verified
evidence  at most 8,192 B whatever the identifiers: keys and records drop first, the last selected first,
          then whole dkim and arc entries from the end of the selection order, counted in limits
```

**Certificates (D-MAIL-4).**
- **Mail host.** Each receiver presents its own §13 P-256 certificate for `{*.<net>.<root>, <net>.<root>}`, covering `mx.<net>.<root>` and so every burner; a scope's receivers hold only that scope's pair (§13.8; owner decisions 40, 58). It is self-signed on the same key until §13 issues it, and no URnetwork component or evs repo holds a mail-host key.
- **TLSA** (from M7; owner decision 109): §12 publishes `_25._tcp.mx.<net>.<root>` (a scope's under `mx.<scope>`) `3 1 1` per receiver key, TTL 300 s, via `/dns/key-record`. A key goes live 2 TTLs after publication (RFC 7671 §8.1), and a removed receiver's record is dropped (I-15).
- **MTA-STS** (M8; verified networks, owner decision 96). Once every receiver holds a §13 certificate, receivers serve the `mode: enforce` policy at `mta-sts.<net>.<root>` as a system publish that `POST /mail/enable` turns on (`tls/443/mta-sts`, audience `public`, no `tls_endpoints` unit or expiry), and §12.7 publishes `_mta-sts`; later receivers serve only once certified. It needs no `tls/` listen or publish grant: each receiver's approved `smtp/25/mx` listen grant stands in for both at registration, Find and admission, and its expiry or revocation ends that receiver's publish (§9.10, §13.9). Burners rely on DANE: burner domains publish no policy, and senders never take a parent zone's (RFC 8461 §3.4), so a listed operator's MTA-STS enforcement never covers burner mail (Labels, below).

**Labels (owner decision 135; I-11).** Since opportunistic senders accept any certificate (§2.8 EX3), ingest labels a message "validated" only if MAIL carried REQUIRETLS (RFC 8689), or if the SNI host had live TLSA in our signed zone (in strict mode, the customer's) and the sender is a listed operator (D-MAIL-13), matched by the forward-confirmed PTR of `sender_ip` or a passing DKIM `d=` aligned with From; else "opportunistic". Every input is the receiver's sealed value (D-MAIL-14), and a receiver's deposit without evidence is "opportunistic", marked "evidence unavailable". An incomplete check is no result, so `limits` can only weaken a label, never strengthen it, and the UI marks such a label "checks incomplete". Beside the label, the UI and API state its basis and never claim end-to-end path confidentiality: the list is an operator-reputation check, not proof of a DANE or MTA-STS path, and REQUIRETLS, the only exact mark, records the final hop's requirement, never that URnetwork did not read the message (RFC 8689 §8.3). `tls_basis` keeps the rule, operator and list version for rechecks. Burner mail from an operator listed only for MTA-STS enforcement is still "validated" (owner decision 135), though it arrived opportunistically with no policy to apply; for any burner recipient the stated basis cites an entry's DANE enforcement where it publishes one, else the listing alone, never MTA-STS (15.16). Strict mode's exclusion claim (15.4) appears only where ingest set `tls_basis.strict_custom_mx` from a sealed `strict_chain`, never on direct-MX or URnetwork-zone mail, and says only that URnetwork could not redirect a DANE-validating sender, not that this sender validated; 15.16 states the residual.

### 15.6 When no receiver is online

The edge cannot queue: with no key holder online, no TLS session exists (owner decision 12).
1. **Several receivers.** §9's scheduler picks one; the backup ticket covers one that died.
2. **Sender retries.** No-receiver cases fail temporarily, so mail waits out the sender's retry window (15.3).
3. **Mail indexers** (owner decision 150). A network receives reliably only through its mail indexers, always-on devices its `IndexerSet`s designate for mail (§3.6, §7.9). With mail on, `ur daemon` never idles out (§5.8); `ur status` and the apps prompt for a desktop, NAS or VPS indexer until one exists; a remote-mode desktop app's `SetReceiverEnabled(true)` files its daemon's designation in a personal network or a member scope (§18.5), and no app is one, since apps run their sidecar only while open (owner decision 197); Teams designate two, or two per scope (owner decision 58). With none designated, receivers take mail only while they run, and `GetReceiverCoverage` answers `foreground-only`, or `none` with no receiver.
4. **Phones.** The VPN component runs only forwarding (§18.4), and the iOS and Android apps listen only while open, so each mostly resyncs mail an indexer took and catches only a retry that lands in that window: a phone alone cannot reliably receive, and phone-only users may miss time-sensitive codes, as `GetReceiverCoverage` says (owner decisions 12, 197).
5. **Wake (M8; owner decision 88).** On a miss, the router sets a forced `mail` hint (§6.8, §18.7) and holds the ClientHello up to 30 s (Postfix waits 300 s), at most 1,000 per process and 4 per network, while §18.7's trigger and §19's push sender wake a lapsed desktop receiver; an app's wake only resyncs (owner decision 197).

### 15.7 The mailbox in evs

**Repos (D-MAIL-5, D-MAIL-6)** in plaintext view: §11 replaces names with keyed path tokens (X2), so the server sees only shape, padded sizes, change times and which paths are versionless or hold the search index (§2.8).

```text
mailcfg             one per network and one per Team scope (kind mailcfg), always fully versioned (§11.7);
                    members write signed records (I-4); tag:mail mail indexers read, by ReaderWrap (owner
                    decisions 114, 150); a scope's is read only by its member's consented devices (§8.5) and
                    receivers; member devices hold at most 1,000 leaves, as in any data repo but the team
                    directory, and an unseated one waits keyless, creating no address until seated (§8.12;
                    owner decisions 144, 182)
  addr/<h>/<address>    MailAddress{kind: admin|id|group|agent|burner|bounce, mailbox, members, creator,
                        effect_key}, created only if absent (15.8)
  burner/<h>/<blabel>   mailbox, state (live, paused, burned), replying, created, effect_key; created only
                        if absent; burned labels kept forever
mailbox:<member>    kind mailbox, owner-bound (§8.5): one member's ids, agents and burners
group:<group>       a general repo on a file-mode ref, whose readers are the group's members (§8); in a team
                    network, announced in the directory at creation with requests closed and no roles offered,
                    or a private marker with --private (§16.11), and joined only by ur id group-add, which
                    writes the mailcfg record and the RepoGrant together, within mail_group_members (§20.4)
  vault/<h>/<entry_id>  VaultEntry, one key slot each (15.8); mailboxes only
  m/<yyyymm>/<h>/<id>   raw RFC 5322 bytes plus ingest headers, one deletable slot/ object each (§11.6);
                        yyyymm from the sealed receive time, so racing readers write one path
  r/<yyyymm>/<h>/<id>   reference to (group repo_id, message id); mailboxes only
  i/<yyyymm>/<n>        append-only index segment of the message list, which search does not replace (the
                        search index row), <= 1 MiB or 4,096 entries of
                        IndexEntry{id, address, time, from, subject, snippet (200 B), message_id,
                        thread_key, size, attachments[{name, type, size}], auth_results, tls_label,
                        tls_basis{rule: requiretls|operator, operator_id, list_version,
                        strict_custom_mx},
                        spam_score, one_time_code}; auth_results and tls_basis from the
                        deposit's MailAuthEvidence (15.5)
  f/<yyyymm>/<n>        flag-op segments of <= 4,096 ops (seen, flagged, label, trash); last writer
                        wins by hybrid logical clock
  o/<h>/<effect_key>    outbox: internet mail queued for a desktop sender, created only if absent
                        (15.10; §16 D-MCP-11), a forward's key derived from its message id; removed
                        once sent and past its approval's retry window; mailboxes only
  or/<h>/<effect_key>   that send's outcome per recipient domain (§14.5: mode, bytes, cap, outcome),
                        written by the sending device; kept 30 days; mailboxes only
  p/<sidecar_id>        a prover host's measured smtp_data_proof_bytes and DATA rate (§14.5),
                        rewritten at each measurement; mailboxes only
  forward               the verified forwarding address and the opted-in burners (15.10); mailboxes only
  ra/<h>/<token>        reverse alias: original sender and burner address (15.10); mailboxes only
  s/model               spam model trained by user verdicts, written versionless from v1 (versioning 1,
                        §11.7), since only its newest version is used; versioned in a locked mailbox
  search index          v1, on unless a repo admin turns it off: the two latest buckets and the all partition
                        (§11.14), every file but its settings versionless (§11.7); documents are m/ messages
                        only, keyed by message id, their text the From, To, Cc and Subject values and the
                        MIME-decoded, HTML-stripped text parts with attachment names, never transport headers,
                        attachment bytes or base64; its doc table holds subject, from, to and date, so no
                        reader fetches by query (D-MAIL-16); never vault/, o/, forward, ra/ or s/model; seen,
                        labels and trash join from f/, and spam from i/'s spam_score, on the device, never
                        stored in the index
  deposit refs          MailDeposit records from receivers (§11)
  shards                <h> = hex of SHA-256(the last name)[0]: 256 directories a family (a month, where
                        dated); each child is one EvsName row of §11.7's 448 KiB name table (token, kind, the
                        name sealed with its 24 B nonce and 16 B tag): 128 B for a name under 64 B, 194 B for
                        an addr/ address of 64-127 B, 2-3 B more while a path-epoch copy carries its epoch;
                        bytes bind before the 4,096 count, at §11.7's bound, which no copy moves: at least
                        3,500 children a directory (about 900,000 names a family), and 2,340 (600,000) for
                        addr/ addresses under 128 B
```

**Readers** are the owner's consented devices (§8.5), as MLS leaves, their `EvsShare` subjects (agents by ReaderWrap, owner decision 114) and owner decision 63's visible audit reader (owner decision 126; D-ACL-13). A device an admin admitted under the owner stays parked until a consented device signs `OwnerConfirm`; it, the tagged sidecars the owner sponsors and `tag:mail` mail indexers only deposit. **Admins.** ERASE and CLOSURE pushes take `repo:<id>:admin` (§11.8, §11.12), so each consented device that is not read-only files `RepoAdmin{add}` for itself once seated (§8.8), and any of them erases, shreds trash or deletes a vault entry, whether or not the mailbox's creating device survives; `EvsShare` subjects, the audit reader and deposit-only sidecars never erase.

**Group mail** is deposited once, into the group repo, and members' devices add `r/` references to their own mailboxes, so storage counts once (§20); a group has at most 100 members (§20.4). Only the group repo's admins (§8.8: its creating device and those a repo admin or config writer adds) erase its messages and shred its trash; members' devices then drop their `r/` references.

**Deposit** (§11.12): a body under a random key, HPKE-wrapped (X-Wing) in a slot to the drop key of the repo's newest signed GenRotate, which the receiver accepts only under D-KEYS-17's depositor rule. A sealed header holds `MailIngress`, `MailAuthEvidence` (15.5), MAIL FROM and its REQUIRETLS flag, this repo's recipients, the TLS version and suite, and the receiver's `sidecar_id`; evs sees the repo id, size, time, depositor and slot.

**Ingest.** On a §11 hint, any reader takes the deposits in order; checks that `MailAuthEvidence` names the message's hash and the signing receiver; scores and labels the message from it (15.5), never from later DNS, showing any re-check apart (D-MAIL-14); adds `Authentication-Results` and `Received`; writes `m/`, `i/` and, where the search index is on, the message's index delta in one push on the repo's file-mode ref, which lands by path (owner decision 141); records §16.8's reach receipt (owner decision 25); and consumes the deposit ref. The deposit id is the message id, so racing readers converge; slot ids are 16 random bytes drawn per statement, never derived from a deposit, message or entry id (§11.6): a deposit rebuilt for a newer drop key after 412 GATE_CLOSED, or an ingest re-sealed under a newer generation, draws new ones, and only a retry of the same statement keeps them. An admin's erasure, of one message or a batch such as the trash shred, first commits, in a format-2 mailbox, a CUT on the mailbox's ref that lists them in its erasure set, so no index push built before it publishes them and searches mask them at once (§11.12, §11.14), and an ERASE of their bodies' keys and any unconsumed deposit's slot, which re-key nothing and so go at once even at the storage limit; it then re-checkpoints each `i/` segment holding them once, without them, into one record under a fresh key, and, where the search index is on, rewrites in place each index file holding their postings (§11.14), by a CLOSURE push bound to its ERASE, one pair per part (Limits), which evs takes even at the storage limit (§11.13), since §11.12's closure bound admits a merged record that padding rounds up a step past the replaced records' sum; each such ERASE destroys the old chains' keys and the rewritten index files' old slot keys (§11.12), and a device whose `i/` write meets such a CLOSURE's 409 re-applies its change without the erased messages; on its hint, every reader and mirror deletes its cached keys, slot copies and every decrypted copy (local store, index and search caches) and refuses those keys, and a daemon serving IMAP expunges the messages; copies an IMAP client or agent already took stay beyond recall (§2.18). Attachments stay inside messages, as content-addressed extraction would leak equality.

**Limits** (`config/all/pro.yml`, §20.4): `mail_inbound_message_bytes` 25 MiB on Community, else 50 MiB; 100 recipients; all mail counts as evs storage (PLAN.md:355); erasing it frees no stored bytes in v0, and from v1 frees at once only its versionless content, while the search index's rewritten files keep their lengths (§11.14, §20.7), so at the storage limit RCPT gets `452 4.2.2`. Admins shred trash after 30 days, a per-entry erasure that preservation holds never block (owner decision 133) and the storage limit only paces: there, and while spent, §20.7 counts each erasing sidecar's closure uploads against its own 60 a minute and its closure bytes against its own `evs_closure_bytes_per_day` a UTC day, which §21 may tighten but never below `evs_closure_bytes_floor` (§11.12, §20.4; owner decision 146), and paces the network's closure uploads in equal turns, k erasers asking at once each getting one every k/4 s, at most 4 a second a network, a refused eraser counting in k until its turn, so no other admin's closures spend an eraser's rate, turns or allowance; ERASE and CLOSURE pushes past the network's 60 a minute queue as P1 and commit. An erasure therefore runs in parts, each one CLOSURE and its ERASE for the messages of whole `i/` segments, sized to what remains of the allowance, since a CLOSURE adopts only uploads under 24 h old (§11.13); a part refused 429 past its eraser's rate, turn or allowance resumes at its `retry_after_ms`. An allowance re-keys 60 full segments a day by default and 3 at the floor, each an `i/` segment or a search-index file of at most 1,088 KiB; a message's erasure re-keys its `i/` segment and every index file version holding any of its documents, which are one per 1 MiB chunk of its text and may have copies (§11.14's bound), so its wait follows from those bytes: at the floor its last part commits after at most the ⌈B / 3,008 KiB⌉-th 00:00 UTC after its allowance first refuses it, B its closure bytes left then, plus a turn per upload of that day, a one-document message with no copy after the next 00:00 UTC within two turns, and a backlog of n full re-keys after the ⌈n/3⌉-th (§11.13, §20.7); the eraser's device shows each erasure's progress and estimate (§5.4's erasure event); the waiting messages' bodies are gone from the first ERASE, and their IndexEntries and postings stay openable to key holders, masked in search, until their part's ERASE commits.

**Reads.** Apps head-read `i/` and messages through §11 (PLAN.md:63), learning of mail by hints or §18 pushes. **Search** (v1; D-MAIL-16), from M10 (owner decision 169), runs on the search index under §18.4's policy: the two buckets answer at once, and older mail follows from all, kept in the background on desktops and indexers, and on phones fetched at "search more" or on Wi-Fi while charging. Phones confirm a hit against `i/`'s subject, address and snippet, which they mirror, and show the rest as possible matches confirmed when opened; desktops verify against the mail they mirror. Once a search indexer is designated (§7.9), a phone's "search more" asks it end to end by default instead (§11.14, §18.4; owner decisions 175, 178), its hits verified where it mirrors the mail: the member's mailbox goes only to their consented search indexers (owner decision 126), a group inbox to their own search indexer that reads it, else to one network-scope search indexer that reads it, after the app names that device's member or sponsor. With none designated (the default, owner decision 177) or none answering, the phone fetches all and shows possible matches as above. A member's search covers their mailbox and the group repos they read, and leaves out spam and trash unless asked. The daemon serves §16's `mail_list`, `mail_read` and `ur://mail/{alias}`, and IMAP (emersion/go-imap v2; M8) under D-MAIL-11 and 15.10's AUTH; IMAP SEARCH (RFC 9051 §6.4.4) runs on the same engine, verified. Outside mail is `untrusted` and taints the run (I-9), whose outward actions, sends included, then each need a fresh second-device or presence-key decision; harness evidence counts only where the matching `requests` rule names it (owner decision 142).

### 15.8 Addresses, groups, vault entries

| Address | Form | Mailbox |
|---|---|---|
| Admin (`@` in the CLI) | `admin@<net>.<root>`, aliased by `postmaster@` and `abuse@` (RFC 5321 §4.5.1, RFC 2142) | the owner's; on Team, an `autogroup:admin` group repo |
| Id | `ur id create <name>` gives `<name>@<net>.<root>` | the creator's |
| Group | `ur id group-create [--private]`, `group-add` (the only way in, §16.11) | the group repo |
| Agent | `<agent>@<net>.<root>`, at registration ([R:product] §2.2 N2) | the sponsor's |
| Scoped (Team) | `<name>@<scope>.<net>.<root>` (owner decision 58) | the scope member's |
| Bounce | `bounces+<token>@b.<net>.<root>` (§14.6) | the sender's |
| Burner | `<name>@<blabel>.<net>.<root>` (15.9) | the owner's |

- **Local parts** match `[a-z0-9][a-z0-9._-]{0,63}`; `admin`, `postmaster`, `abuse`, `mailer-daemon`, `bounces` and `r-*` are reserved. No device can terminate cli/UI.md:21's shared `you@ur.network`, so cli/UI.md:68's form holds.
- **Address directory.** A receiver honors a creator-signed `mailcfg` record only if §8's policy grants the creator `mail:<alias>#listen` (D-ACL-12). Policy and `mailcfg` are encrypted, and the projection carries only `mail_send` (§8.8), so alias names never reach the server. Creating an alias or a burner is an I-8 outward action: the `mail` component writes the record only once `Authorize` passes (§5.4), for `ur id`, the apps and §16's `mail_alias_*` alike. The record is created only if absent and, under a decision, carries the use's `effect_key`, which also seeds the DRBG a burner draws its candidate labels from, so a retry or a restart's `Lookup` finds its own record (§16 D-MCP-11). MCP's evs tools never write `mailcfg` (D-MCP-17).
- **Same-network mail** is deposited to the recipient's drop key and signed with the sender's identity key (§6.9), without smtpedge, send quota or DKIM; that signature replaces the TLS label (D-MAIL-8).
- **Network mail key:** the admin mailbox's drop key, carried in each of that repo's GenRotates (a scope's: its member's mailbox; D-KEYS-17); §14.8 seals reports to it, burners' included.
- **Vault entries** (MM:594-605) each have their own slot, so deleting one shreds every version of it (owner decision 61); only the owner's consented devices (§8.5) read them or write "Used at".

```text
VaultEntry{entry_id, address, title, username, password, password_history,
           totp{secret, algorithm, digits, period} (RFC 6238), urls, notes,
           used_at[{registrable_domain, first, last}], created, updated, state}
```

### 15.9 Burner email

**Format.** Burners sit in the network's own zone (owner decision 32): `<name>@<blabel>.<net>.<root>`, with `<blabel>` a generated word-number label such as `otter-4821` (`^[a-z]+-[0-9]{4}$`) and `<name>` any local part (D-MAIL-7). They are linkable through `<net>`, and an alias, which shared receiver keys in TLSA and CT tie to the label, names the network (Q-MAIL-10). The sidecar picks unused labels, and §12.7 and §7.7 refuse word-number DNS owners and client names, so nothing shadows the wildcard; labels live only in `mailcfg`.

**Records** are §12.7's rows marked §15, outside the user's quota: the wildcard MX `*.<net>.<root>` → `mx.<net>.<root>` covers every burner label, with 15.5's TLSA, and alias zones and Team scopes repeat both with their own `mx` host. Until the PSL listing, a replying burner's selector (§14's `POST /smtp/dkim-keys`) gives its label its own records, guessable but not walkable under §12.6's compact denial (owner decision 79; §2.8 dns-1). Since a child name makes `<blabel>` an empty non-terminal the wildcard no longer answers (RFC 4592 §2.2.1), dns writes `<blabel>` MX and A/AAAA equal to the wildcard's in the journal write of its first `_domainkey` child and deletes them with its last selector, at §14.6's cut-over or a burn (D-DNS-11).

**Replies** come with sending (M9, owner decision 35), through §14 with `header_from_domain = <blabel>.<net>.<root>` and flag BURNER. They pass strict DMARC under the burner's own selector (owner decision 79), send from the shared lb addresses, sharing the domain's reputation (owner decisions 32, 124), and count against the daily connection quota (owner decision 30).

**Spam.** The edge applies only IP listings and rate limits (15.4); readers apply the sealed SPF, DKIM and DMARC results (a DMARC reject files it as spam), rules, a per-mailbox naive Bayes model (mox `junk` is a candidate) and user verdicts, never greylisting, since one-time codes cannot wait.

**Burn** is local (owner decision 32): receivers answer `550 5.1.1` for the label from then on, the label is never reissued, and devices mark the vault entry burned and may shred its mail; pause answers the same, reversibly. DNS and the server change only when a replying burner's selector retires (§14.6).

**App seams (§18).** `SidecarMail` gains `CreateBurner(site)`, `Burn(id)`, `GetVaultEntries`, `GetUsedAt(entry)`, `GetOneTimeCodes(since)` (from vault TOTP and mail) and `GetReceiverCoverage()` (§18.5). Its `foreground-only` copy reads "A phone alone cannot reliably receive mail: an indexer, an always-on device (a desktop `ur daemon`, a NAS or VPS), is needed; time-sensitive codes may not arrive" (owner decisions 12, 197), and no coverage copy speaks of sending, whose size limits `CheckSend` and `GetSendResult` give per recipient domain (§14.5, §18.5). Before the first burner, `CreateBurner` shows the `foreground-only` copy whenever coverage is `foreground-only` or `none`, and it never refuses for coverage (owner decision 12). Autofill is app work (§18.15). With no server burner state, the sidecar applies `mail_burners_active` and `mail_burner_creates_per_day` locally (§20.4).

### 15.10 Sending

The local server is the MTA (PLAN.md:104), on §5.8's submission port under D-MAIL-11 and D-TRUST-8's certificate rule (owner decisions 84, 130). AUTH uses a per-instance keychain credential granting only what the daemon grants its OS user (owner decision 47). Agents use §16's `mail_send`; both paths pass §5.4's outward-action gate (I-8). For each message the server:
1. checks From against `mail:<alias>#send` (D-ACL-12) and holds mail to unapproved recipients until an I-8 channel approves it (`ur approve <id>`, §16.6);
2. stores a copy in `sent`, and deposits same-network mail directly;
3. for BURNER sends, applies the header rules: removes every Received header and adds none, rewrites Date to UTC at minute precision, strips User-Agent, X-Mailer and client `X-*` headers, and regenerates the MIME boundaries and the Message-ID under `<blabel>.<net>.<root>`, so replies reveal no device, client or timezone (§14.4 step 3);
4. queues the rest at `o/<h>/<effect_key>`, created only if absent (§16 D-MCP-11), for §14's `SmtpSender.Send`, which holds it on HALTED, QUOTA or TRY_LATER (§14.7-14.8); probation and anonymous-only networks deliver only same-network deposits (§21.7, D-SMTP-14). The sending device writes each recipient domain's outcome to `or/<h>/<effect_key>` (§14.5), from which the composing device raises `mail_send` (§18.5).

Internet sending waits for smtpedge's BDAT and DATA proofs (M9, owner decisions 35, 125), which only desktop-class hosts run, so the owner's consented `ur daemon` sidecars, indexers among them (owner decision 150), send what a phone queues (D-SMTP-18). Each such prover host records its measured cap and DATA rate at `p/<sidecar_id>`, so a phone's composer can show them (§14.5).

**Forwarding (owner decision 53; M9).** (1) One external address per mailbox, confirmed by a 6-digit code sent through §14, is kept with the opted-in burners in the mailbox's signed `forward` entry. (2) Readers forward opted-in burner mail only if it scores below the spam threshold with no DMARC fail as received. (3) The forward is a new message From `r-<token>@<blabel>.<net>.<root>`, `<token>` being a MAC of the original sender under a vault key (`ra/`), with step 3's header rules and `X-UR-Forwarded`, DKIM-signed like a reply (15.9) and queued in `o/` for a prover host. (4) Mail to `r-<token>` from the verified address, passing DMARC as received, is relayed From the burner to the original sender. (5) Each code, forward or relay costs one connection (owner decision 30). (6) Forwards never go to `<root>` addresses or repeat a message carrying `X-UR-Forwarded`, which stops loops.

DSNs arrive at `b.<net>.<root>`, and receivers deposit them to the sending mailbox.

### 15.11 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| SNI splice with DANE | end to end for senders that send SNI | senders without SNI defer | chosen (owner decisions 31, 34) |
| Encrypt-on-receipt (Proton, Tuta) or plaintext SMTP at the edge | every sender; filtering; a queue | plaintext at URnetwork | ruled out (owner directive 2026-11-03) |
| Hosted or TEE receiver, delegated credentials (RFC 9345), or a receiver in an app's VPN component | always on; phone-only users | keys on our hardware, or in a component that runs only forwarding (§18.4) | ruled out (owner decisions 12, 197) |
| Per-network IPv6 or IPv4 | senders without SNI reach receivers | no dedicated addresses (§19.5, D-OPS-15) | not now (owner decision 34) |
| Shared burner domain (mock), or labels on a burner root | short; or unlinkable | routable only on RCPT; a new domain and per-burner DNS | ruled out (owner decision 32) |
| Verify SPF, DKIM and DMARC at ingest | one verifier, on the reader | judges DNS days after reception, past selector rotation (RFC 6376 §3.1) | rejected (D-MAIL-14) |
| An MTA-STS policy per burner | MTA-STS-only senders enforce for burners | a policy host, certificate and CT entry per burner | rejected (owner decision 32) |

### 15.12 Decisions proposed

**D-MAIL-1 (proposed).** Inbound TLS ends only at customer receivers, except at D-MAIL-10's platform listener for URnetwork's own report and role addresses (§2.8's statement, mx-4); mxedge's router routes by SNI alone, and every unroutable or offline case gets a temporary failure. *Why:* the directive, with D-TRUST-4's one exception; senders retry.

**D-MAIL-2 (proposed).** mxedge's router speaks only 15.4's pre-TLS dialog, refuses plaintext transactions and splices from the ClientHello on. *Why:* RFC 3207, CVE-2011-0411 and Postfix's retry with TLS.

**D-MAIL-3 (proposed).** Receivers run emersion/go-smtp with 15.5's upstreamable `ServeConn`, forked if declined, and verify with mox over DoH as mail arrives. *Why:* pure Go everywhere.

**D-MAIL-4 (proposed).** Each receiver presents its own §13 certificate and TLSA record for `mx.<net>.<root>`, which serves every burner, and serves MTA-STS as a system publish (15.5). *Why:* URnetwork holds no key, removal deletes one record (I-15), and user-publish rules would break policy fetches.

**D-MAIL-5 (proposed).** Receivers deposit each message under its own key, slotted to the drop key in the repo's newest GenRotate (D-KEYS-17), and answer 250 only once it is durable; readers ingest with per-message slots, and an erasure also takes the deposit slot, the index copies and every reader's decrypted copies. *Why:* receivers never read archives, no stale drop key reaches a removed reader, and erasure covers every copy (§11.12).

**D-MAIL-6 (proposed).** Each member has one owner-bound `mailbox` repo, which each of the member's consented devices that is not read-only joins as a repo admin, each group one general repo storing its mail once, which only its repo admins erase, and each network one signed `mailcfg`. *Why:* few MLS groups; one upload per message, not ~5 GB per 50 MiB message to 100 members; and erasure, which takes `admin` (§11.12), never waits on the device that created a mailbox, nor lets every group member destroy the group's mail.

**D-MAIL-7 (proposed).** Burners are `<name>@<blabel>.<net>.<root>` under the wildcard MX; receive-only burners have no records, keys or server state of their own, and burning is local (owner decisions 32, 79). *Why:* nothing can be enumerated, and URnetwork stores nothing.

**D-MAIL-8 (proposed).** Same-network mail is delivered by deposit and never crosses the internet. *Why:* "end to end between members" (sidecar/design/pitch5.html:708).

**D-MAIL-9 (proposed).** Burners launch once the owner accepts the SNI loss the M7 census measures (owner decision 34): per sending ASN, SNI, DANE, TLS version and plaintext fallback, from provider, ESP, top-100 sign-up and report senders, plus §14's destination-MX probe. Proposed bar: under 5% of sign-up and code mail, by volume, lacks SNI. *Why:* SES and Yahoo coverage is unknown ([R:ext-email-zk] §5 item 3).

**D-MAIL-10 (proposed).** Reports and role mail reach `rpt.bringyour.com`'s platform listener, which terminates every session and accepts only platform recipients (D-SMTP-19), for §14.8's intake, which parses headers and aggregate report data only (D-SMTP-23) and persists no plaintext. *Why:* reporters without SNI must deliver, the router holds no key, and no third party stores reports.

**D-MAIL-11 (proposed).** Submission and IMAP bind every interface unless `--listen` narrows them (owner decision 84); off loopback they speak implicit TLS (RFC 8314 §3), chosen per connection by local address, and plaintext stays on 127.0.0.1 and ::1 (owner decision 130; D-TRUST-8, I-17). *Why:* no credential or mail crosses a LAN in cleartext, and one port serves both.

**D-MAIL-12 (proposed).** A Team direct MX names at most two of its mail indexers, verified before §12 publishes them; strict mode refuses spliced URnetwork-zone hosts and accepts direct-MX sessions, and only an MX selection and TLSA both in customer-signed zones carry the claim that URnetwork cannot redirect mail, surfaced only as `tls_basis.strict_custom_mx`, so a URnetwork-zone direct MX keeps EX2's residual; a member scope's receivers are that member's consented devices (15.4, 15.5). *Why:* owner decisions 33, 58 and 98, trusting neither URnetwork's zone, which a DANE sender follows wherever it points (RFC 7672 §2.2), nor a lone admin.

**D-MAIL-13 (proposed).** Owner decision 135's operator list is `mail_operators.yml` in the public sidecar repo (owner decision 118), embedded in each release with a list version; each entry names an operator's PTR suffixes, DKIM domains and published DANE or MTA-STS enforcement, which a label's basis cites, never MTA-STS for burner mail (15.5). *Why:* anyone can recheck a label against it, with no new server or key; the list is an operator-reputation check, and REQUIRETLS records only the final hop's requirement (15.5).

**D-MAIL-14 (proposed).** Receivers capture 15.5's reception-time authentication evidence within its per-message and per-receiver bounds (8 DKIM signatures, aligned ones first; 8 ARC sets; RFC 7208's SPF limits; 64 queries; 30 s; 4 messages at once) and seal it in the deposit, bound to the message hash, time and receiver (`MailAuthEvidence`, at most 8,192 B, its `limits` naming what a bound skipped); readers label, score, receipt and forward from it, count an incomplete check as no result, and never rewrite a label from later DNS. *Why:* DKIM selectors have a lifecycle (RFC 6376 §3.1), and SPF, DMARC and PTR records change, so a later check would judge other DNS; a sender sets how many signatures it adds and how slowly its selectors answer, which RFC 6376 §6.1 lets a verifier limit, while authentication never decides whether mail is accepted (meta review F17).

**D-MAIL-15 (proposed).** Reliable reception rests on mail indexers (§3.6), the receivers an `IndexerSet` designates for mail (§7.9): a personal network's own always-on devices, a Team's `tag:mail` devices under `team_mail: indexers`, or a member scope's own devices; under `team_mail: indexers` an undesignated `tag:mail` device registers no listener and readers alarm on internet mail another receiver took; with none designated, any online receiver still takes mail. *Why:* owner decisions 12, 58 and 150; the designations are the list owner decision 58 discloses to members, and they never gate the receive path.

**D-MAIL-16 (proposed).** `i/` stays the mailbox's message list. Full-text search uses the repo's search index, which covers only `m/`, is keyed by message id, and holds subject, from, to and date in its own doc table. Phones confirm hits against `i/`, or take a designated indexer's verified hits (owner decisions 175, 178), and labels, trash and spam join on the device. *Why:* mail ships in v0, before the index (v1), and must list with the index off. An index that every mailbox reader can read must not hold vault entries, which only the owner's consented devices read. Display fields in the index spare every device a query-dependent fetch, at about 0.15 KB a message, uncompressed. On 20 Newsgroups, `i/`'s address and 200 B snippet confirmed 26% of true rare-word matches, against 11% for headers alone.

### 15.13 Open questions

**Q-MAIL-1.** [X6] How does mxedge route without terminating TLS? **Decided by owner 2026-11-03 (owner decisions 31, 34):** by SNI alone, with DANE TLSA; senders without SNI defer (15.4). *Residual:* none.

**Q-MAIL-2.** [X6 residual] Which devices receive mail? **Decided by owner 2026-11-03 (owner decision 12):** always-on receivers, which owner decision 150 names mail indexers, and the iOS app in the foreground, which listens only while open and so is no reliable receiver (15.6). **Amended by owner 2026-11-09 (owner decision 197):** Android with the VPN on is no longer an always-on receiver: the Android app, like the iOS app, receives only while it is open, so the always-on receivers are a desktop `ur daemon`, a NAS or a VPS. *Residual:* none.

**Q-MAIL-3.** [X6 residual] What are the burner format and domain? **Decided by owner 2026-11-03 (owner decision 32, superseding owner decision 29):** `<name>@<blabel>.<net>.<root>` under the wildcard MX (15.9). *Residual:* none.

**Q-MAIL-4.** Should burners forward to external inboxes (MM:583)? **Decided by owner 2026-11-03 (owner decision 53):** opt-in, to one verified address, with sending (15.10). *Residual:* none.

**Q-MAIL-5.** Who receives a Team network's mail? **Decided by owner 2026-11-03 (owner decision 58, superseding owner decision 54):** disclosed mail indexers the team designates (owner decision 150), or member scopes with their own `mx` host (15.5, 15.6). *Residual:* none.

**Q-MAIL-6.** Should mxedge reject at the banner on IP reputation? **Decided by owner 2026-11-03 (owner decision 111):** only on botnet and exploit listings, never greylisting (15.4). *Residual:* none.

**Q-MAIL-7 (withdrawn).** Withdrawn with Q-ARCH-4; §2.8 lists mx-1 to mx-4.

**Q-MAIL-8 (closed 2026-11-03).** (a): clients check `mail:<alias>`, and mxedge only `listen`; applied as D-ACL-12 (§8.10).

**Q-MAIL-9.** [X6 residual] Should mxedge refuse senders without STARTTLS, against RFC 3207 §4? **Decided by owner 2026-11-03 (owner decision 33):** yes, with 530 and a published deviation, plus a Team direct MX (15.4). *Residual:* none.

**Q-MAIL-10.** Cross-cutting (§2.8, §21.9). Can burners be linked? **Decided by owner 2026-11-03 (owner decision 32):** yes, through `<net>`, and an alias names the network; product copy says so (15.9). *Residual:* none.

**Q-MAIL-11.** Cross-cutting (§16.6). Does a DKIM-verified email reply count as an approval? **Decided by owner 2026-11-03 (owner decision 80):** no; email approval is dropped. *Residual:* none.

**Q-MAIL-12.** Cross-cutting (§14.6). How do burner replies pass strict DMARC? **Decided by owner 2026-11-03 (owner decision 79):** a replying burner's own selector and records until the PSL listing, then §14.6's cut-over (15.9). *Residual:* none.

**Q-MAIL-13.** Cross-cutting (§2.8 EX3, §21.9). What makes received mail "validated" (owner decision 98), given that few senders set REQUIRETLS? **Decided by owner 2026-11-04 (owner decision 135):** (b): REQUIRETLS, or TLSA for the SNI host in our signed zone plus a sender on a versioned list of DANE- or MTA-STS-enforcing operators, identified by forward-confirmed PTR or aligned DKIM `d=`; else "opportunistic" (15.5, D-MAIL-13). Ingest records the basis, from the receiver's sealed evidence (D-MAIL-14), in `tls_basis`. *Residual:* none.

### 15.14 Departures from PLAN.md

PLAN.md:104's `mail.<me>.ur.network` becomes `mx.<net>.<root>` (owner decision 32; Q-MAIL-3); the receiver is still the local server, and mxedge is the ingress a public mail host implies. Not PLAN.md: refusing plaintext SMTP departs from RFC 3207 §4 (owner decision 33); burners in the network zone replace the mock's `burner.ur` (MM:918) and are linkable, which [R:product] §2.3 asked to avoid (owner decision 32); and approval by email reply is dropped (owner decision 80; P5:899).

### 15.15 Interfaces

- **Provides:** the `mail` component (15.5-15.10, with mail, burner, vault, coverage and one-time-code APIs for §16 and §18); the `mxedgeservice` engine (15.4); `MailIngress`, `MailAuthEvidence`, `MailDeposit`, the network mail key (15.8) and the operator list (D-MAIL-13).
- **Consumes:** §5 (the outward-action gate, tainted runs); §6 (`mail` topic, 0x17); §7.9 (`IndexerSet`, `team_mail`); §8 (grants, consent, data-repo seats, `RepoAdmin`); §9; §10 (GenRotate drop keys and the depositor rule, D-KEYS-17; ReaderWraps); §11 (deposit slots, ERASE and CLOSURE's bound, file-mode refs, the write gate and budget); §12 (D-DNS-11's burner copies); §13 (certificates, the MTA-STS publish); §14 (`SmtpSender`, D-SMTP-13's LAN splice); §16 (D-MCP-11's effect keys); §18 (receiver hosting, forced wakes); §19 (lb ports, feed credential); §20; §11.14's search engine and remote search, and §18.4's device policy, notice and setting (D-MAIL-16).
- **Subprotocol messages:** `MailIngress` (0x1701; mxedge to receiver; StreamOpen metadata on a Required stream); `MailHint{kind: deposit|receiver_needed}` (0x1702; `mail` push; server to client).
- **API routes:** `POST /mail/enable` (Client class) turns on §12's mail records and the MTA-STS publish; `GET /mail/status`; `POST` and `DELETE /mail/direct-mx` (Network class, Admin role, Team only, an I-8 outward action; 15.4).
- **Tables** (mxedge; migrations ≥926) and Redis keys:

```sql
mail_network(network_id PK, create_time)
mail_host_key(network_id, host, receiver_sidecar_id, spki_sha256, state, publish_time, retire_time) -- host: mx or mx.<scope>
mail_direct_mx(network_id, receiver_sidecar_id, address, state, verify_time)
mail_connection_record(network_id, start_time, byte_count, result) -- router sessions, 10 s batches; no sender
--   address or burner label (§2.8 mx-2)
-- rows: mail_network until mail is turned off or the network is deleted; mail_host_key 30 days after
--   retire_time; mail_direct_mx until DELETE or its receiver's removal; mail_connection_record in hourly
--   partitions, dropped at 24 h after any §21.9 hold has copied out its network's rows; a hold's copy
--   excepted (api-14; owner decision 133)
-- Redis {mxr_<net>}: the route projection of mail-enabled labels, aliases, scopes and custom MX hosts, behind an
--   in-process cache, so connections never query Postgres; {mxc_<hash>}: the fleet's closed-handshake memory,
--   one key per sender /24 or /48
```

- **Services and config:** `server/cli/mxedge`'s router and platform-listener blocks on TCP 25 of different lb interfaces (§19.5's W4); `config/<env>/mxedge.yml`; the platform-mail key and feed credential in vault `secret_files`; `pro.yml`'s `mail_inbound_message_bytes` and `mail_group_members` (§20.4); the embedded `mail_operators.yml`.
- **Assumptions about other sections:** §9.10's gates and §13.9's `ValidateListen` admit only a mail-enabled network's receivers' `tls/443/mta-sts` system publish without `tls/` grants, on each receiver's `smtp/25/mx` listen grant (15.5); §8.8 lets a consented device that is not read-only file `RepoAdmin{add}` for itself in its owner's mailbox, §11.12's closure bound admits a merged `i/` record padded a step past the replaced records' sum, §11.12 and §20.7 give each erasing sidecar its own closure-upload rate, an equal turn of the network's paced closure uploads and its own UTC-day closure allowance, never under the re-keys of one message's erasure, the network's erasure rate only queueing pushes as P1 (owner decision 146), and §11.6 draws slot ids per statement (15.7); §21.11 publishes the RFC 3207 deviation from M5 (15.4); §2.8's mx-1 keys the closed-handshake memory per sender /24 or /48, and mx-2 names `mail_connection_record`, which §19.7's MG7 creates, with a ttl excepting a hold's copy, and §2.8's header, api-14's sees, §21.9's holds and §21.16 list its rows in `copied_rows` (15.4); §22 tests the labels, reception-time evidence and its bounds (FS-121), strict mode's sessions and its `strict_custom_mx` claim (15.4), erased deposit, index and decrypted copies, at the exact storage limit too, 429 past an eraser's own closure rate, turn or allowance, and with an `i/` re-checkpoint that crosses a padding step, and burners' records and missing MTA-STS, an MTA-STS-only listed operator's burner mail labeled "validated" on a basis citing no MTA-STS (FS-13, FS-33, FS-39, FS-47), FS-39's report intake and S7's SNI-less abuse@`<root>` gating M5; §23.4 states M8's mail-indexer criterion as release readiness (15.17), never a per-user gate.

### 15.16 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Senders without SNI (Yahoo, AOL, Proton by anecdote; SES unknown) lose sign-up codes | High | High | DANE, D-MAIL-9's gate, direct MX, copy |
| A phone alone cannot reliably receive (the iOS and Android apps listen only while open), so phone-only users miss codes (owner decisions 12, 197) | High | High | indexer prompt, wake hold, copy |
| A site loss erases an iOS-only user's message bodies; logins, burners and `i/` survive on the phone (§11.13) | Low | High | the owner's indexer mirrors the mailbox (§11.13); copy |
| Sites block `<root>` sign-ups as disposable, and network mail shares that reputation (owner decision 32) | High | High | abuse caps and burns (§21); no full mitigation |
| Owner decision 135's operator match trusts mxedge's sender address and the author's DKIM domain, not the delivering hop, so an intercepting mxedge can win "validated" for some opportunistic mail, and needs no fake for an operator listed only for MTA-STS enforcement, whose burner mail is "validated" though burner domains publish no policy; REQUIRETLS is exact only as the final hop's requirement, which an operator that read the first hop can add | Low | High | disclosed (§2.8 EX3, §2.18); no UI or API asserts path confidentiality, or MTA-STS for burner mail; `tls_basis` |
| Spam loads devices; the edge filters no content | Medium | Medium | banner rejects, prefix caps, `max_streams`, burn |
| A sender's many signatures, long identifiers or slow selectors tie up a receiver's authentication or overflow its evidence | Medium | Medium | 15.5's bounds: 8 DKIM signatures, 8 ARC sets, 64 queries, 30 s, 4 messages at once, 8,192 B of evidence; a cut check is no result, so it refuses no mail and strengthens no label (D-MAIL-14) |
| A compromised receiver exposes mail in transit | Low | High | per-device keys, I-15, Team scopes, listed mail indexers and the undesignated-receiver alarm (D-MAIL-15) |
| A site or Hurricane Electric outage stops both nameservers and with them every ur.network name, ACME, DANE and, from M7, inbound mail; a weekend outage can outlast senders' shorter retries (owner decision 123) | Medium | High | accepted; paged at all hours (owner decision 143); senders retry 14 h to 5 d (15.3) |
| A direct MX publishes a mail indexer's address and depends on its uptime | Medium | Medium | two mail indexers, probes, `receiver_needed` |
| A LAN host attacks submission or IMAP (owner decision 84) | Medium | Medium | TLS only off loopback (D-MAIL-11); `--listen` |
| Phone search over older mail shows possible matches that lack the query: on 20 Newsgroups, about half of the top five for rare words | High | Medium | labeled possible; ranked by trigram overlap; confirmed against `i/`, a cached body or on open; desktops and indexers verify; a designated indexer's verified answer where one is online (owner decision 178) |

### 15.17 Phasing

- **v0, M5:** the platform listener (D-MAIL-10), for §21's intake before any public name; its 530 links §21.11's RFC 3207 deviation, published from M5, and M5-out runs FS-39's intake cases and S7's SNI-less abuse@`<root>` case (§22, §23.6).
- **v0, M7 (network mail):** the router, IP listings and DANE TLSA; desktop, NAS and VPS mail indexers (owner decision 150); deposits with reception-time evidence inside 15.5's bounds, ingest, layout and labels; admin, id, group and agent addresses; same-network delivery; the census. Blocked by C9 (M5), §9 `smtp/`, §10's GenRotate drop keys, §11's deposit refs and slots, §12's signed root and mail records, and §19's TCP 25 ports.
- **v0, M8 (BS1, the receive-only burner launch on personal networks):** burners, vault entries and local burn; app seams and wakes (owner decision 88); IMAP; MTA-STS and TLS-RPT. BS1 ships once the owner accepts D-MAIL-9's census loss and, as release readiness, the mail indexer paths (desktop daemon, NAS or VPS; no app, owner decision 197) and the apps' indexer prompt pass §22 (§23.4); a user needs no indexer to create a burner, only 15.9's copy (owner decision 12).
- **v0, M9 (sending):** submission through §14, burner replies with their own records and MX copies (D-DNS-11), the BURNER header rules and forwarding, behind D-SMTP-16's gate with DATA coverage (owner decisions 35, 53, 79, 125).
- **v1 (Team; owner decisions 33, 58, 98, 150):** network-scope mail indexers, direct MX and strict mode from M7; scopes from M8.
- **v1, M10 (owner decision 169):** mail search (D-MAIL-16) at the later of M10's and M7's exits, and IMAP SEARCH on the engine and phones' remote search over mail (15.7) at the later of M10's and M8's, in team networks group inboxes' through network-scope search indexers once M6's has passed too; mailboxes and group repos created earlier are indexed by one full build on a device that holds their mail (§11.14).
- **Later:** destination routing if a routed IPv6 block is obtained (owner decision 34), Team burners, §14.6's PSL cut-over, edge reputation from receiver verdicts.
- **Ordering:** team B builds mail and burner after M2 (owner decision 9, X15); their lead times (port 25, PTR, the census) start in M0 (§23.7).
