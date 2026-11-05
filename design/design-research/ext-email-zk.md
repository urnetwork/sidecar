# ext-email-zk: email infrastructure and zero-knowledge header attestation

Fact sheet for the PLAN.md "SMTP edge" (PLAN.md:87-97), "Local Email server" (PLAN.md:102-104) and the burner-email product. Research date 2026-11-03. Code facts cite `repo/path:LINE` under /Users/brien/urnetwork. External facts cite URLs. "inference:" marks reasoning, not sourced fact. Live DNS was checked with `dig @1.1.1.1` on 2026-11-03.

## 1. Summary

1. Inbound SNI is not dependable. Postfix sends no SNI by default (`smtp_tls_servername` empty) unless DANE validates, and Exim's `tls_sni` is unset unless DANE applies. Anecdotal reports say Gmail and Outlook send SNI and Yahoo, AOL and Proton do not. DANE clients MUST send SNI (RFC 7672 §8.1). SNI routing therefore works for the big senders but not for the long tail, so a fallback is mandatory.
2. No mainstream proxy passes SMTP STARTTLS through by SNI. HAProxy can't, Traefik issue #7366 has been open since 2020, and Stalwart rejects the configuration. The edge has to answer the banner, EHLO and STARTTLS itself, peek at the ClientHello, then splice the connection to a device SMTP server that resumes after STARTTLS and sends no second 220. That is buildable but custom, and emersion/go-smtp has no such entry point.
3. Retry windows are short for the senders that matter: Amazon SES up to 14 h, Microsoft 365 24 h, Gmail about 48 h (from its delay notices), Postfix 5 days. If the edge answers 4xx while a device is offline, mail is lost. The edge needs an encrypt-on-receipt queue (the Proton/Tuta model), and that briefly exposes plaintext to URnetwork.
4. A shared burner domain can't be routed by SNI, because RCPT arrives after TLS, so the edge must terminate TLS. Per-user subdomains would make routing possible but link all of a user's aliases (addy.io says so itself).
5. DMARC aggregate reports (RFC 9990, May 2026) carry no Message-ID. Their rows key on source_ip, header_from, envelope_from/to, DKIM domain and selector, and SPF domain. PLAN.md:97 ("message id and routing path are the main DMARC headers") is wrong for aggregate reports. Message-ID matters for ARF feedback loops and manual abuse reports.
6. PLAN.md's ZK preamble is unsound as written. Proving that the "ciphertext decrypts under some key to headers H" lets the client, who authored the ciphertext, equivocate through key-commitment attacks. The AFT 2025 proxy paper covers only data the server sends. A sound version binds the client traffic key to the handshake the edge watched: the client discloses SHTS, the edge checks the server Finished, and the ZK proof derives the key and IV through HKDF (the ORIGO technique). The proof must also cover the SMTP grammar, header-block completeness, and the stream tail, so that no second transaction can be smuggled in.
7. Maturity is low. ORIGO (Go/gnark) is unaudited research code: about 400k constraints, 1.5 s online on a c5.4xlarge but 9.8 s on an m5.large, and a 112 MB proving key. TLSNotary proxy mode (May 2026) takes 1-2 s for 1 KB/2 KB but supports TLS 1.2 only. Microsoft 365 SMTP is documented only at TLS 1.2. No existing system proves client-sent SMTP. Treat ZK end-to-end sending as a v1+ research track.
8. Recommended v0: authenticated submission that terminates at the edge. URnetwork sees content like any email provider but stores none. Each network gets its own DKIM d= and header_from, the edge assigns the Message-ID and an opaque X-UR-Ref header, and quotas and auto-pause apply per network. Relay either through URnetwork's own IPs with forward-confirmed reverse DNS, or through SES tenants (August 2025), which give per-tenant reputation, an X-SES-TENANT header, auto-pause, and 10k tenants by default.
9. Prerequisites are missing today. ur.network has no SPF record, its DMARC is p=none with no sp, it has no DS record (so no DANE), no MTA-STS and no TLS-RPT, and it is not on the Public Suffix List. Because of that, Let's Encrypt's limit of 50 certificates per registered domain per week covers every *.ur.network name combined.
10. Code: connect never lets TCP/25 reach a provider. The nginx load balancer exposes TCP stream ports with PROXY v1 but has no mail module. pires/go-proxyproto, with full TLV support, is already in the dependency graph.

## 2. Facts with citations

### 2.1 URnetwork code and live state

- PLAN: sidecar depends on connect, not server/sdk (PLAN.md:7); a network owns zone `<me>.ur.network` (PLAN.md:25); SMTP edge rules and ZK preamble (PLAN.md:89-97); local SMTP server terminates `mail.<me>.ur.network`, writes to encrypted storage, sends via SMTP edge (PLAN.md:104); quota 5/200/20000 emails/day (PLAN.md:356).
- connect egress policy: "Port 25 is deliberately local-only. Port 465 must begin with a TLS ClientHello; port 587 may send only bounded SMTP negotiation until STARTTLS" (connect/ip_smtp_policy.go:16-19); `smtpMaxNegotiationBytes = 2048`, `smtpMaxCommandLineBytes = 510` (connect/ip_smtp_policy.go:29-30); pre-TLS vocabulary is only EHLO/HELO/QUIT/STARTTLS (connect/ip_smtp_policy.go:693-700); TCP/25 goes to `localUserNat` "so an SMTP relay attempt can never reach a provider" (connect/ip.go:10694-10699); providers re-enforce via `smtpIngressGuard` (connect/ip.go:7869-7872). These parsers are unexported.
- PROXY protocol: server imports `github.com/mailgun/proxyproto` v1.0.0 (server/go.mod:27; server/connect/transport_pp.go:14), caps headers at `PpMaxHeaderSize = 2048` (server/connect/transport_pp.go:28); that library exposes `Header.RawTLVs` and `ParseTLVs()` (.gomodcache/github.com/mailgun/proxyproto@v1.0.0/proxy.go:27,41). `github.com/pires/go-proxyproto` v0.15.0 is an indirect dep (connect/vlessinterop/go.mod:39) with `Header.Format()`, `TLVs()`, `SetTLVs()` (.gomodcache/github.com/pires/go-proxyproto@v0.15.0/header.go:241,253,259), `SplitTLVs`/`JoinTLVs` and `PP2_TYPE_MIN_CUSTOM=0xE0..PP2_TYPE_MAX_CUSTOM=0xEF` (.../tlv.go:35-36,62,88).
- Load balancer: nginx is built `--with-stream --with-stream_ssl_module --with-stream_ssl_preread_module`, no `--with-mail` (warp/lb/Dockerfile:56-58). warpctl emits TCP stream servers with `proxy_protocol on;` (v1 text: original source and destination address) and UDP with `proxy_protocol v2;` (warp/warpctl/config.go:2477-2513); stateful upstreams hash `$remote_addr` (warp/warpctl/config.go:2446). Ports come from `tcp_stream_ports` / `tcp_stream_port_services` (warp/services/services.go:558,616); only warp/services/testdata/services.yml declares any today. `ssl_preread` reads a ClientHello at connection start (https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html); inference: it cannot see SNI behind an SMTP plaintext preamble, so STARTTLS logic must live in a Go service.
- Existing mail: account mail goes through SES v1 `SendEmail` in us-west-1 (server/controller/aws_controller.go:638-705, `ses.New` :662), with optional configuration set and `template` tag (:693-700; `EmailConfig` :49-63). EMAIL1.md says "no configuration set" (server/EMAIL1.md:11); the code supports one now (code wins). EMAIL1 Phase A (DNS, SES identity, Postmaster Tools) is still open (server/EMAIL1.md:3).
- config/main/tls.yml:4,6 lists `ur.network` and `"**.ur.network"`; `app.ur.network` is a CORS origin (warp/services/services_test.go:349).
- Live DNS: ur.network NS = Route53 (awsdns-*); no DS record (unsigned); MX = Google Workspace (`aspmx.l.google.com`); `_dmarc.ur.network` = `v=DMARC1; p=none; rua=mailto:dmarc-reports@ur.network` (no sp/np); no apex SPF TXT; no `_mta-sts`, no `_smtp._tls`. ur.network is absent from the Public Suffix List (`github.io` present; https://publicsuffix.org/list/public_suffix_list.dat fetched 2026-11-03).
- Go stdlib: `net/smtp.SendMail` sets `tls.Config{ServerName: c.serverName}` (Go 1.27.3 src/net/smtp/smtp.go:339). `crypto/tls` `KeyLogWriter` (src/crypto/tls/common.go:839) exports CLIENT/SERVER_HANDSHAKE_TRAFFIC_SECRET and CLIENT_TRAFFIC_SECRET_0 (:1606-1608), but the handshake secret stays internal (src/crypto/tls/handshake_client_tls13.go:491).

### 2.2 SNI on inbound STARTTLS

- RFC 7672 §8.1: a DANE SMTP client "MUST send the TLS SNI extension containing the TLSA base domain"; servers "MUST NOT enforce the use of SNI" and must send a fallback chain. https://www.rfc-editor.org/rfc/rfc7672.html
- Postfix: `smtp_tls_servername` default empty (no SNI); values `hostname`/`nexthop`; when DANE authenticates, SNI is always on per RFC 7672; Postfix ≥3.4. https://manpages.debian.org/bookworm/postfix/postconf.5.en.html ; posttls-finger: "SNI is not used by default" except DANE. https://manpages.debian.org/bookworm/postfix/posttls-finger.1.en.html
- Exim: `tls_sni` default unset; "If DANE validated the connection attempt then the value of the tls_sni option is forced to the name of the destination host"; `hosts_try_dane` default `*`. https://www.exim.org/exim-html-current/doc/html/spec_html/ch-the_smtp_transport.html , https://www.exim.org/exim-html-current/doc/html/spec_html/ch-encrypted_smtp_connections_using_tlsssl.html
- Anecdotal: Levine (2020-06-17) says "Gmail gets SNI correct, Microsoft's Outlook.com doesn't", "Postfix doesn't send SNI." https://www.mail-archive.com/postfix-devel@postfix.org/msg00869.html . Sauleau (undated, mailway.app SNI routing) says Gmail, Outlook, Mailgun and Go net/smtp send SNI and Yahoo, AOL and ProtonMail do not. https://sauleau.com/notes/smtp-sni.html
- No primary source was found for Microsoft 365, Yahoo, iCloud or SES. Exchange Online validates DANE outbound by default. https://learn.microsoft.com/en-us/purview/how-smtp-dane-works ; inference: it sends SNI at least to DANE domains.
- inference: DNSSEC plus TLSA on `mail.<net>.ur.network` would make every DANE-capable sender (Postfix/Exim with validating resolvers, Exchange Online) send SNI. ur.network is unsigned today.

### 2.3 SNI routing and splicing for SMTP

- HAProxy maintainer: STARTTLS prevents SNI routing because the SNI "is not in the first packet." https://discourse.haproxy.org/t/smtp-imap-proxy-based-on-domain-pass-through/5480/2
- Traefik #7366 (opened 2020-09-29, still open): SMTP is "server first", "cannot be implemented as of now." https://github.com/traefik/traefik/issues/7366 . Traefik merged Postgres STARTTLS SNI routing, including passthrough, the client-first analogue (PR #9377, 2022-11-16, v3.0). https://github.com/traefik/traefik/pull/9377
- Stalwart: pass-through listeners may not use starttls; its SMTP proxy terminates and routes on credentials. https://stalw.art/docs/migration/proxy/routing/smtp/
- nginx mail proxy terminates TLS, picks the backend via `auth_http`, sends PROXY protocol (1.19.8, v2 since 1.31.4) and XCLIENT. https://nginx.org/en/docs/mail/ngx_mail_proxy_module.html
- RFC 3207 §4.2: the server MUST discard pre-TLS knowledge such as the EHLO argument, and the client SHOULD send EHLO again. https://www.rfc-editor.org/rfc/rfc3207.html ; inference: a device can start at the TLS handshake without seeing the plaintext dialog, but must not emit a 220 greeting afterward the way implicit-TLS servers do.
- emersion/go-smtp v0.25.0 (2026-08-13, MIT): the server supports CHUNKING, implicit TLS and `Serve(listener)`; there is no per-connection entry point or post-STARTTLS start; the client has no BDAT. https://pkg.go.dev/github.com/emersion/go-smtp
- mox (Go, MIT): SMTP with DANE, MTA-STS and TLS-RPT (in and out), REQUIRETLS, DMARC aggregate reports, rejection of bare CR; non-server packages "written to be reusable." https://github.com/mjl-/mox

### 2.4 MTA-STS, DANE, TLS-RPT for `mail.<net>.ur.network`

- MTA-STS (RFC 8461): policy at `https://mta-sts.<domain>/.well-known/mta-sts.txt` plus `_mta-sts` TXT `id`. Senders "MUST NOT attempt to fetch a policy from the parent zone", so each network needs its own policy. `mx:` wildcards match only the left-most label. The MX certificate must be PKIX-valid and match the name. In enforce mode, failures "SHOULD" be treated as transient. `max_age` ≤ 31,557,600 s. https://www.rfc-editor.org/rfc/rfc8461.html
- DANE: TLSA at `_25._tcp.<mx>`; DANE-EE(3) skips name and expiry checks (RFC 7672). Exim needs DNSSEC-secured MX, A and TLSA records (Exim spec above). Microsoft recommends `3 1 1`. On DANE failure Exchange Online retries after 15 min, 15 min, then hourly for 24 h, then sends an NDR, and it emits TLS-RPT as JSON. https://learn.microsoft.com/en-us/purview/how-smtp-dane-works (updated 2026-07-21)
- TLS-RPT (RFC 8460): `_smtp._tls.<domain>` `v=TLSRPTv1;rua=...`; one report per UTC day. Result types include starttls-not-supported, certificate-host-mismatch, validation-failure, tlsa-invalid, dnssec-invalid, dane-required and sts-*. Failure details give sending-mta-ip, receiving-mx-hostname, receiving-mx-helo, receiving-ip and counts, with no message identifiers. https://www.rfc-editor.org/rfc/rfc8460.html
- Let's Encrypt (updated 2026-08-05): 50 new certificates per registered domain per 7 days, refilling 1 per 202 min, with registered domain decided by the PSL; 300 orders per account per 3 h; 5 per exact identifier set per 7 days. https://letsencrypt.org/docs/rate-limits/
- inference: a device-held key satisfies MTA-STS (ACME DNS-01 in the network's zone) and DANE (`3 1 1`). An edge fallback that terminates TLS needs its own valid certificate or TLSA entry for the same name. MTA-STS and DANE therefore cannot keep URnetwork out whenever a fallback is allowed.

### 2.5 When the receiving device is offline

- RFC 5321: retry interval "at least 30 minutes", give-up "at least 4-5 days" (§4.5.4.1); server timeouts of 5 min for the initial 220, 3 min per data block and 10 min for DATA termination (§4.5.3.2); a dropped connection is treated as a 451 (§3.8). https://www.rfc-editor.org/rfc/rfc5321.html
- SES "will retry for up to 14 hours" (Spam Resource, 2025-07-26). https://www.spamresource.com/2025/07/understanding-4xx-deferrals.html ; the maximum delivery time is configurable from 5 min to 14 h (2024-10-15). https://aws.amazon.com/about-aws/whats-new/2024/10/amazon-ses-configurability-maximum-delivery-time-emails
- Microsoft 365 "continues to retry ... for 24 hours", then sends an NDR. https://learn.microsoft.com/en-us/exchange/monitoring/mail-flow-reports/mfr-queued-messages-report
- A 2017 Gmail delay notice reads "Gmail will retry for 47 more hours." https://www.wireshark.org/lists/wireshark-dev/201706/msg00085.html ; inference: Gmail retries for about 48 h. Postfix `maximal_queue_lifetime` is 5d with backoff 300-4000 s (postconf link above).
- inference: SES-sent sign-up codes bounce after 14 h offline, so "4xx while offline" is unsafe.

### 2.6 How E2EE providers handle inbound mail

- Proton: mail that isn't end-to-end encrypted in transit is "encrypted after receipt" with the recipient's public key; Proton "may briefly access the data before encryption"; subjects are not E2EE. https://proton.me/blog/zero-access-encryption , https://proton.me/support/proton-mail-encryption-explained
- Tuta: external mail is "only encrypted once they reach our servers"; "We never store unencrypted emails"; sender and recipient addresses and dates stay unencrypted. https://tuta.com/encryption
- StartMail: no primary source found, and secondary sources conflict (gap).

### 2.7 Alias and burner services

- SimpleLogin: re-sends each forwarded message from a reverse alias unique to the sender and alias pair (e.g. `abcdef123456@simplelogin.co`); replies to the reverse alias go out from the alias. https://simplelogin.io/docs/getting-started/reverse-alias/ ; original authentication headers are dropped and inbound DMARC failures quarantined. https://github.com/simple-login/app/discussions/408 , https://simplelogin.io/docs/getting-started/anti-phishing/
- addy.io: `*@username.anonaddy.com` aliases are "linked by your username"; random shared-domain aliases "cannot be linked to a user." Replies "look as if it has come from us." Free tier: 10 aliases/h, 200 forwards/h, 10 MB/month, no replies. Enrolled in feedback loops; accounts that repeatedly mark forwards as spam are disabled; uses rspamd, Spamhaus, SPF/DKIM/DMARC and PTR checks; forwards "may" land in spam. https://addy.io/faq/
- Firefox Relay: Premium replies go via `replies@relay.firefox.com`, within 3 months, at most 100/day, with a "[via Relay]" subject marker. https://support.mozilla.org/en-US/kb/reply-forwarded-emails-firefox-relay-premium ; reply metadata is a JWE (dir/A256GCM) under keys derived by HKDF-Expand from the forwarded Message-ID ("replay replies lookup key" and "... encryption key"). https://raw.githubusercontent.com/mozilla/fx-private-relay/main/emails/utils.py
- Apple: Sign in with Apple's Hide My Email uses `@private.icloud.com` or `@privaterelay.appleid.com` (2026-10-26). https://support.apple.com/en-us/105078 ; senders must register domains and pass SPF and/or DKIM with exact match, or mail bounces. https://developer.apple.com/help/account/configure-app-capabilities/configure-private-email-relay-service/ . DuckDuckGo: for most Duck Addresses "replies just work." https://duckduckgo.com/duckduckgo-help-pages/email-protection/duck-addresses/how-do-i-reply-from-my-duck-address
- inference: every forwarder re-sends under its own domain to survive DMARC, so forwarded mail rides the forwarder's outbound reputation.

### 2.8 Outbound authentication, alignment, organizational domain

- DMARC RFC 9989 (May 2026, obsoletes 7489 and 9091) replaces the PSL with a DNS tree walk of at most 8 queries. The Organizational Domain is the domain carrying `psd=n`, or one label below a `psd=y` record, or otherwise the record with the fewest labels. Relaxed alignment is the default (`foo.example.com` aligns with `news.example.com`). A subdomain without its own record inherits `sp`, then `np`, then `p`. https://www.rfc-editor.org/rfc/rfc9989.html
- RFC 9990 aggregate record = `row` (source_ip, count, policy_evaluated) + `identifiers` (header_from; optional envelope_from, envelope_to) + `auth_results` (dkim domain/selector/result; spf domain/scope/result). There is no Message-ID or other per-message identifier. https://www.rfc-editor.org/rfc/rfc9990.html
- Failure reports (RFC 7489 §7.3; now RFC 9991) use AFRF (RFC 6591), carry "as much of the message and message header as is reasonable", and may be redacted. https://www.rfc-editor.org/rfc/rfc7489.html . Secondary sources agree Gmail sends none; Microsoft and Yahoo are unclear (gap).
- Gmail, all senders: SPF or DKIM, forward-confirmed PTR, TLS, spam rate below 0.3% (target 0.10%), RFC 5322. Bulk senders (>5,000/day, since 2024-02-01): SPF and DKIM, DMARC p=none, From aligned with SPF or DKIM, one-click unsubscribe for marketing. "Gmail tracks volume, feedback, and limits per domain and IP"; other senders on a shared IP affect your reputation. https://support.google.com/a/answer/81126 ; enforcement is "gradual and progressive", and bulk classification is permanent. https://support.google.com/a/answer/14229414
- Yahoo: SPF or DKIM; bulk senders need both plus DMARC p=none, alignment, one-click unsubscribe honored within 2 days, spam rate below 0.3%. https://senders.yahooinc.com/best-practices/
- Outlook.com: since 2025-05-05, senders of >5,000/day need SPF, DKIM and DMARC; non-compliant mail goes to Junk first, then `550 5.7.515`. https://substrate.office.com/ip-domain-management-snds/postmaster/Policies , https://support.microsoft.com/en-us/outlook/fix-ndr-error-550-5-7-515-in-outlook-com
- SES: a verified parent domain lets you send from any subdomain; DKIM settings are inherited, and a subdomain may override them. https://docs.aws.amazon.com/ses/latest/dg/creating-identities.html

### 2.9 Feedback loops and the identifiers abuse reports carry

- ARF (RFC 5965): `multipart/report`. Part 2, `message/feedback-report`, requires Feedback-Type, User-Agent and Version; optional single fields are Original-Envelope-Id, Original-Mail-From, Arrival-Date, Reporting-MTA, Source-IP and Incidents; optional repeated fields are Authentication-Results, Original-Rcpt-To, Reported-Domain and Reported-URI. Part 3 is `message/rfc822` or `text/rfc822-headers`. https://www.rfc-editor.org/rfc/rfc5965.html ; `not-spam` comes from RFC 6430. https://www.rfc-editor.org/info/rfc6430 ; RFC 9477 adds a source-port field. https://www.rfc-editor.org/subjects/arf/
- Microsoft JMRP and SNDS: feeds are bound to SNDS-verified IPs. Since early 2026 reports are ARF-standard and keep the original headers, but the sender address is redacted and the body removed; feeds not tied to a verified SNDS account "may be purged" (2026-02-17). https://emailexpert.com/microsoft-overhauls-snds-jmrp-postmaster-tools-what-to-fix/ ; from about 2026-06-11, `X-HmXmrOriginalRecipient` is removed and To is masked, while Message-ID and custom X-headers survive (secondary). https://www.suped.com/learn/email-deliverability/did-microsoft-change-the-jmrp-spam-complaint-report-format
- Yahoo CFL "only supports DKIM-signed email and is a domain based service"; it reports messages signed with an enrolled DKIM key. https://senders.yahooinc.com/complaint-feedback-loop/
- Gmail FBL: header `Feedback-ID: a:b:c:SenderId` on mail DKIM-signed by a domain verified in Postmaster Tools. It is aggregate only, with a volume threshold; SenderId should be 5-15 characters; values unique per message (e.g. a Message-ID) are discouraged. https://support.google.com/a/answer/6254652
- SES "overwrites the headers" and assigns its own messageId. Complaints carry `mail.messageId`, and because ISPs strip recipients, "SES performs a lookup against the original message." https://docs.aws.amazon.com/ses/latest/dg/notification-contents.html . The SES Feedback-ID is `a:b:<region>.<accountId>:AmazonSES`, with a and b set by tags. https://aws.amazon.com/blogs/messaging-and-targeting/understanding-google-postmaster-tools-spam-complaints-for-amazon-ses-email-senders/

### 2.10 How bulk senders attribute complaints to tenants

- SES tenants (August 2025): a tenant contains identities, configuration sets and templates. You send with `TenantName` or the SMTP header `X-SES-TENANT`. Bounce and complaint metrics (including feedback loops) are kept per tenant; Standard, Strict and None policies auto-pause a tenant; suppression lists can be per tenant. Accounts get 10,000 tenants by default, auto-approved up to 300,000. "Combined sending activity still affects your overall account reputation." Tenants cost extra per month. https://docs.aws.amazon.com/ses/latest/dg/tenants.html , https://aws.amazon.com/about-aws/whats-new/2025/08/amazon-ses-tenant-isolation-automated-reputation-policies
- SendGrid reports spam per subuser (timestamp, recipient, sending IP). https://www.twilio.com/docs/sendgrid/v2-api/customer_subuser_api/subuser_spam_reports ; Postmark complaint webhooks carry the original MessageID. https://postmarkapp.com/developer/webhooks/spam-complaint-webhook ; inference: email providers stamp their own IDs at send time and match feedback-loop copies by header lookup, while IP pools stay shared.

### 2.11 Port 25, IP reputation, warm-up

- Port 25 egress: AWS blocks it by default (removal by request, up to 48 h, not guaranteed). https://aws.amazon.com/premiumsupport/knowledge-center/lightsail-port-25-throttle/ ; GCP blocks external destinations, with "some projects" exempt. https://docs.cloud.google.com/compute/docs/tutorials/sending-mail ; Azure blocks all VMs by default. https://learn.microsoft.com/en-us/answers/questions/2283594/cannot-send-email-(smtp-port-25) ; Vultr blocks by default (2025-09-15). https://docs.vultr.com/support/products/compute/why-is-smtp-blocked
- Warm-up: building reputation takes "around two weeks" at some providers and "up to six weeks" at others; SES auto warm-up runs 45 days; afterwards each IP should send about 1,000 emails/day to each provider. https://docs.aws.amazon.com/ses/latest/dg/dedicated-ip-warming.html
- IPv6: Spamhaus lists IPv6 at /64 granularity at minimum (operator reports; strategy page) https://www.spamhaus.org/news/article/668/spamhaus-releases-ipv6-blocklists-strategy .

### 2.12 zkTLS landscape and proxy-mode soundness

- "Proxying is Enough" (Luo, Jia, Shen, Kate; AFT 2025; ePrint 2024/733, rev. 2025-07-30): the verifier only relays and "cannot verify" key derivation. Server-data integrity comes from HTTP variable padding; "without variable padding ... data integrity cannot be guaranteed." ChaCha20-Poly1305 satisfies context unforgeability, AES-GCM does not. Scope: "mainly focuses on preventing the client from forging the server's messages." Theorem 4: a client builds c that decrypts to m under (k,n) and to m′ under (k′,n′). https://eprint.iacr.org/2024/733 , https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.AFT.2025.4
- Key commitment: for GCM, GCM-SIV and Poly1305-based schemes it is easy to find ciphertexts that decrypt under several keys (Dodis, Grubbs, Ristenpart, Woodage 2018, "invisible salamanders"). https://eprint.iacr.org/2019/016 ; partitioning oracles, including ChaCha20-Poly1305 (Len, Grubbs, Ristenpart 2021). https://eprint.iacr.org/2020/1491
- ORIGO (Ernstberger et al., PoPETs 2025(2):416-433; ePrint 2024/447), TLS 1.3 proxy mode:
  - The client discloses SHTS ("key independence"); the proxy decrypts the handshake and verifies the server certificate and Finished outside the circuit.
  - ZK proves the application traffic key derivation in 7 in-circuit SHA-256 compressions per key, with the IV derived in-circuit to block an AES-GCM "strong receiver binding" attack.
  - Assumes the client cannot MITM between proxy and server.
  - Implementation: about 5k lines of Go on gnark with a customized `crypto/tls`.
  - Costs: 400.2k constraints end to end; AES-GCM is 77.7k constraints and 0.23 s for 32 B, over 1 s for 512 B (M2 MacBook Air); online 1.5 s on c5.4xlarge and 9.8 s on m5.large; offline 28.6 s; proving key 111.9 MB; 2.4 kB online communication, against 206-476 MB for DECO.
  - Sources: https://crysp.petsymposium.org/popets/2025/popets-2025-0069.pdf ; code is an anonymous unaudited artifact ("should not be used in a production system"). https://github.com/anonymoussubmission001/origo
- TLSNotary: supports TLS 1.2, with "no immediate plans" for 1.3. MPC-TLS costs about 25 MB fixed + about 10 MB per 1 KB of outgoing data + about 40 KB per 1 KB incoming. https://tlsnotary.org/docs/faq . Proxy mode: the prover proves the TLS 1.2 PRF in ZK with the master secret private; the verifier checks Finished and recomputes GCM tags on server records; the residual risk is MITM of the verifier's TCP leg; authentication of data the prover sends is not described. https://tlsnotary.org/docs/protocol/proxy-mode . Benchmarks (2026-05-10, Ryzen 9 9950X), 1 KB request / 2 KB response: proxy 1.0-1.6 s native and 1.4-2.0 s in the browser, against MPC 3.6-15.5 s; MPC uploads about 30 MB first; at 51 KB browser proxy takes 7.3 s against 2.6 s native, since WASM lacks AES hardware. https://tlsnotary.org/blog/2026/05/10/blog-proxy-mode/
- DECO (CCS 2020): three-party handshake; its proxy variant needs a weaker network adversary (per ORIGO §2). https://arxiv.org/abs/1909.00938
- Reclaim: the attestor signs the (encrypted request, encrypted response) pair; security rests on known HTTP fragments, with request forgery around 1e-40 (2024-05-29). https://blog.reclaimprotocol.org/posts/proxying-is-enough ; circuits for chacha20, aes-256-ctr and aes-128-ctr (the last "may be insecure") in circom/snarkjs and gnark Groth16, under a custom license. https://github.com/reclaimprotocol/zk-symmetric-crypto
- zkPass: 3P-TLS proxy mode with an MPC fallback and VOLE-ZK. https://zkpass.gitbook.io/zkpass/overview/technical-overview-v2.0 ; Pluto Web Prover uses TEEs, last push 2025-03. https://github.com/pluto/web-prover ; Opacity has only secondary sources. None target SMTP.
- gnark: Apache-2.0, v0.16.4 (2026-10), Groth16 and PLONK, BN254 and BLS12-381 among others, 9 audits, "does not guarantee constant-time." https://github.com/Consensys/gnark ; ZK Email zk-regex compiles regex to NFA for Circom/Noir. https://github.com/zkemail/zk-regex , https://eprint.iacr.org/2026/1284
- Destination TLS: 98% of Gmail outbound is TLS. https://transparencyreport.google.com/safer-email ; there is no announced TLS 1.3 for Exchange Online SMTP (Q&A, 2023-12). https://learn.microsoft.com/en-us/answers/questions/1455239/do-we-support-tls-1-3-in-microsoft-smtp-server

### 2.13 SMTP framing that matters for proofs

- BDAT is `"BDAT" SP chunk-size [SP "LAST"]`. The server reads exactly that many octets without scanning for `CRLF.CRLF`, BDAT can't be mixed with DATA in one transaction, and BDAT after LAST gets 503. https://www.rfc-editor.org/rfc/rfc3030.html
- MAIL resets transaction state, a session may carry several transactions, and servers must buffer at least 100 recipients (RFC 5321 §3.3, §4.5.3.1.8, link above).

### 2.14 PROXY protocol v2 (for the preamble)

- Layout: 12-byte signature `\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A`; byte 13 is `0x21` PROXY or `0x20` LOCAL; byte 14 is `0x11` TCP4 or `0x21` TCP6; bytes 15-16 give the length, so the header is 16 + length (at most 65,551 bytes). The address block is 12 B for IPv4, 36 B for IPv6. TLVs are `type(1) length_hi length_lo value`. Registered types: `0x01` ALPN, `0x02` AUTHORITY, `0x03` CRC32C, `0x04` NOOP, `0x05` UNIQUE_ID, `0x20` SSL (subtypes `0x21-0x25`), `0x30` NETNS. `0xE0-0xEF` are for applications, `0xF0-0xF7` experimental, `0xF8-0xFF` future. The receiver "MUST NOT start processing the connection before it receives a complete and valid PROXY protocol header." https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt

### 2.15 Explicit answers

**(a) Inbound architecture options and what each reveals**

| Option | Mechanism | Reveals to URnetwork | Notes |
|---|---|---|---|
| A1 Edge MTA + encrypt-on-receipt | MX of every `<net>.ur.network` → shared `mx.ur.network`; edge terminates TLS, routes by RCPT, seals to the network's public key, queues, notifies the device over connect | Plaintext momentarily (Proton's wording), envelope, sender IP, size, timing; only ciphertext at rest | Most reliable; edge can do SPF/DKIM/DMARC/DNSBL and content filtering; edge-held certificate makes MTA-STS easy |
| A2 SNI splice to device, A1 fallback | MX → `mail.<net>.ur.network`; edge sends banner/EHLO/`220 Ready`, reads SNI, opens connect stream to the network's listener with PROXY v2 (src IP; AUTHORITY=SNI; custom TLVs for EHLO name and timestamp), replays the ClientHello and splices | Pre-TLS EHLO, SNI (which network), sender IP, timing and byte counts; not envelope or content | Falls back to A1 when there is no SNI or the device is offline; device needs ACME certificate and a post-STARTTLS SMTP server; a strict no-fallback mode defers mail and loses it after the sender's window (SES 14 h) |
| A3 Per-network IPv6 address | Unique AAAA per network MX; edge routes by destination address (PROXY v1 carries it, warp/warpctl/config.go:2510) | Same as A2 | inference: removes the SNI dependency for IPv6 senders only; their share is unmeasured |
| A4 Device is the MX | — | — | Not feasible: NAT, ISP port-25 blocks, devices offline |
| B1 Shared burner domain, edge terminates | RCPT → alias table → network; seal and deliver in-app; optional forwarding re-sends under the burner domain (SimpleLogin/addy pattern) | Plaintext momentarily + alias→network mapping (+ content on forwarding) | The only unlinkable option; forwarding adds outbound reputation risk |
| B2 Per-user burner subdomain | `alias@u.<burner>` allows SNI splice | As A2 | Linkable by the subdomain (addy.io), so not a burner |

inference: For burner replies, DKIM d= must be the shared domain, because a per-user d= would let recipients link a user's aliases.

**(b) Is ZK header attestation feasible now? Simpler v0**

What must be proven, as a minimum (inference, built on ORIGO and TLSNotary):
- Edge checks outside the circuit:
  - ClientHello offers no `pre_shared_key` or `early_data`.
  - Suite is TLS_AES_128_GCM_SHA256 or TLS_CHACHA20_POLY1305_SHA256 (AES-256-GCM-SHA384 would need SHA-384 circuits).
  - With the disclosed SHTS, the edge decrypts the server flight and verifies CertificateVerify and Finished, and optionally PKIX or DANE for the MX host. The edge resolves and dials the MX itself, which satisfies ORIGO's no-MITM assumption.
- In ZK:
  - (R1) HS is consistent with SHTS = Expand-Label(HS, "s hs traffic", H(CH‖SH)), and the client key and IV are derived through MS → CATS(H(CH..SF)).
  - (R2) Keystream XOR ciphertext gives plaintext for the proven records. No tag check is needed, because the honest server rejects bad tags.
  - (R3) Each record's inner content type is application_data with the exact inner length, so no KeyUpdate is hidden and TLS 1.3 padding cannot obscure offsets.
  - (R4) The plaintext parses as `EHLO <edge PTR name>`, `MAIL FROM:<...@<net domain>>`, 1..R `RCPT TO`, `BDAT n LAST`, then a header block ending at the first CRLFCRLF. That block must contain exactly one From (network domain), exactly one Message-ID equal to the declared value, every DKIM-Signature with `d=<net domain>` and `h=` covering From and Message-ID, and the declared Feedback-ID and X-UR-Ref exactly once, with no bare CR or LF.
  - (R5) The record holding the end of the n-byte chunk decrypts to the chunk tail followed by `QUIT` CRLF and nothing more. This kills any smuggled second transaction; with DATA instead of BDAT, the whole body would have to be proven.
- Edge enforcement: buffer client records until the proof verifies (PLAN's "first N bytes buffer"), forward only records that match, and drop the connection on any extra record.
- Feasibility: possible as a research prototype for TLS 1.3 destinations. TLS 1.2 (Exchange Online) needs a separate PRF circuit, as TLSNotary has. The client needs a forked TLS stack to obtain HS. The proving-key and phone/browser costs are untested. There is no SMTP implementation anywhere.
- v0: edge-terminated SMTP submission over 465/587 with a network credential. The edge validates the From and MAIL FROM domains, DKIM-signs with d=`<net>.ur.network` (or verifies a signature the device made), stamps Message-ID `<rand>@<net>.ur.network` and an `X-UR-Ref` HMAC token, logs metadata only, enforces daily quotas, and relays through its own IPs or SES with `X-SES-TENANT`. An optional v0.5 privacy mode is end-to-end TLS with no ZK, attributed by time and destination plus a per-network IPv6 /64 source address (inference).

**(c) Attribution keys, best first**

1. `X-UR-Ref` opaque token: survives JMRP redaction and appears in ARF part 3 and manual reports.
2. Message-ID whose id-right is `<net>.ur.network`: in ARF, JMRP and manual reports; not in RUA.
3. DKIM `d=` and `s=`: Yahoo CFL is keyed on them, they appear in ARF headers, and RUA rows include the DKIM domain and selector.
4. header_from domain: RUA `identifiers.header_from`.
5. VERP envelope_from (`bounces+<ref>@...`): RUA `envelope_from` (optional) and DSNs.
6. Feedback-ID with a per-network SenderId or field: Gmail aggregates only, above a threshold.
7. Source IP: RUA `source_ip`, ARF Source-IP, SNDS/JMRP. Only attributable if IPs are per network.
8. The receiver's own Received header (edge IP, HELO, time, TLS) joined to edge logs.
9. RFC 9477 source port, rarely sent.

**(d) Deliverability prerequisites**

- Static egress IPs that URnetwork controls (not cloud defaults, not provider egress), with forward-confirmed PTR and HELO equal to the PTR name. Monitor blocklists (Spamhaus lists IPv6 per /64).
- SPF for every MAIL FROM domain; ur.network has none today.
- 2048-bit DKIM keys; DMARC tightened from p=none toward `p=reject; sp=reject; np=reject` before untrusted networks can use `<net>.ur.network`; an RUA ingester that splits rows by header_from.
- TLS on outbound.
- Postmaster Tools, SNDS/JMRP (IP-based), Yahoo CFL (DKIM-based), and abuse@/postmaster@ mailboxes.
- Bulk rules (once >5,000/day to Gmail or Outlook.com): SPF+DKIM, aligned DMARC, one-click unsubscribe for marketing, spam rate below 0.1%.
- Warm-up of 2-6 weeks and about 1,000/day per provider per IP to stay warm.
- Separate domains and IPs per stream: user mail, burner forwarding/replies, and ur.io transactional mail (EMAIL1's "Separate streams", server/EMAIL1.md:113).

## 3. Constraints the design must respect

1. Owner rules: new pieces (SMTP edge logic, device SMTP server, PROXY TLV codec, ZK circuits, protocol messages) live in the sidecar repo, which may import connect but not server or sdk; server and sdk import sidecar (PLAN.md:7). Pieces that need AWS credentials (SES) should be implementations of sidecar interfaces, written in server.
2. connect hard-routes TCP/25 to the local NAT and blocks SMTP relay through providers (connect/ip.go:10694-10699). Outbound SMTP must run on URnetwork edge IPs, and the sidecar must reach the edge over connect streams, not raw TCP/25 inside the VPN.
3. SMTP STARTTLS can't be SNI-routed by nginx or HAProxy; a Go edge must speak the pre-TLS dialog. Its pre-TLS vocabulary should stay at EHLO/HELO/QUIT/STARTTLS, at most 2048 bytes, lines at most 510 (mirroring connect/ip_smtp_policy.go:29-30,693-700).
4. Mail that has been accepted must not depend on a device being online. Sender retry windows (SES 14 h, M365 24 h) are shorter than typical device offline periods.
5. RFC 3207 §4.2: the device-side SMTP server must resume after STARTTLS without a 220 greeting.
6. MTA-STS is per domain with no parent inheritance (RFC 8461 §3.4), so each `<net>.ur.network` needs `_mta-sts` and `mta-sts.<net>` hosting if MTA-STS is used. DANE requires signing the ur.network zone first.
7. Let's Encrypt allows 50 certs per registered domain per 7 days; with ur.network off the PSL, every network's certificates share that budget.
8. Any ZK attestation must bind keys to the handshake the edge observed (TLS 1.3 via disclosed SHTS plus HKDF proof; TLS 1.2 via PRF and Finished) and must cover header-block completeness and stream termination. Proving inclusion in the "first N bytes" alone is unsound.
9. DMARC RUA carries no Message-ID (RFC 9990). Per-network attribution in RUA requires per-network header_from or DKIM d= (or per-network IPs).
10. Microsoft JMRP is IP-based, needs SNDS-verified IPs, and now strips bodies and recipients. Never put recipient addresses in attribution headers; use opaque tokens (secondary-source guidance).
11. server's PROXY parser caps headers at 2048 bytes (server/connect/transport_pp.go:28). A sidecar preamble carrying proofs should use a sidecar protobuf frame, not oversized PROXY TLVs.
12. Free quotas (5/day, PLAN.md:356) can't keep a dedicated IP warm (about 1,000/day per provider), so IPs are shared and isolation has to come from domain identity (d=, header_from).

## 4. Reusable pieces

1. `github.com/pires/go-proxyproto` v0.15.0: `Header.Format()`, `Header.TLVs()`, `Header.SetTLVs([]TLV)`, `SplitTLVs`, `JoinTLVs`, `PP2_TYPE_AUTHORITY`, `PP2_TYPE_MIN_CUSTOM`..`PP2_TYPE_MAX_CUSTOM` (.gomodcache/github.com/pires/go-proxyproto@v0.15.0/header.go:241-259, tlv.go:35-88); already an indirect dependency (connect/vlessinterop/go.mod:39).
2. `github.com/mailgun/proxyproto` v1.0.0: `ReadHeader`, `Header.RawTLVs`, `Header.ParseTLVs()` (.gomodcache/.../proxy.go:27-62), used by server (server/connect/transport_pp.go:14).
3. warp lb TCP stream ports: `tcp_stream_ports` / `tcp_stream_port_services` (warp/services/services.go:558,616) → nginx `listen <port>; proxy_protocol on;` (warp/warpctl/config.go:2508-2513). This can front port 25 for a Go SMTP edge service with no nginx mail module.
4. connect's SMTP negotiation and ClientHello validators as reference logic: `validTlsClientHelloBodyWithScratch`, `tlsClientHelloStreamWithScratch`, `inspect587Stream`, the `smtpNegotiationCommands` allowlist (connect/ip_smtp_policy.go:512,573,645,693-700). They are unexported; copy them or ask connect to export.
5. Go `crypto/tls` `Config.KeyLogWriter` (src/crypto/tls/common.go:839) to obtain SHTS for disclosure. HS needs a fork (handshake_client_tls13.go:491).
6. `github.com/emersion/go-smtp` v0.25.0 (MIT): SMTP server with CHUNKING and implicit TLS; needs a post-STARTTLS start hook. `github.com/mjl-/mox` packages (MIT): DKIM, DMARC, SPF, MTA-STS, TLS-RPT, DANE.
7. `github.com/consensys/gnark` (Apache-2.0, Groth16/PLONK) for Go-native circuits; ORIGO's key-derivation circuit design (7 compressions per key; SHTS disclosure; `Π_Auth` Finished check) as the blueprint.
8. Firefox Relay's reply-key pattern: HKDF-Expand(Message-ID local part, "…lookup key"/"…encryption key") → JWE A256GCM reply metadata, for burner reverse aliases.
9. SES tenants (`TenantName`, `X-SES-TENANT`, per-tenant reputation policies and suppression) if relaying through SES; existing SES sender in server/controller/aws_controller.go:638-705 (v1 API; tenants need sesv2).

## 5. Gaps, risks, surprises

1. Surprise: DMARC aggregate reports never contain Message-ID; PLAN.md:97's join key does not exist in RUA.
2. Surprise: ur.network today has p=none DMARC with no sp. Anyone can spoof `<net>.ur.network` From addresses without quarantine, and there is no SPF record.
3. Risk: SNI coverage from Yahoo, iCloud, SES and Microsoft 365 is unverified and the sources are anecdotal or old (2019-2020). It has to be measured by logging ClientHello SNI per sending ASN before committing to A2.
4. Risk: in ZK end-to-end mode the edge cannot filter content, so phishing from a compromised network rides shared IPs until complaints arrive. Gmail asks for a spam rate below 0.10% and never 0.30%.
5. Risk: Exchange Online is documented only at TLS 1.2. A TLS 1.3-only ZK design excludes a large recipient share, so it needs either two circuits or the v0 fallback.
6. Risk: Groth16 proving keys around 112 MB are heavy for gomobile and the extension's WASM worker; WASM lacks AES acceleration (TLSNotary measured 2.8× slower at 51 KB). Interactive designated-verifier ZK (VOLE/QuickSilver, as TLSNotary and zkPass use) fits, because the edge is the only verifier. inference: it avoids trusted setup and large keys.
7. Risk: PSL inclusion of ur.network would isolate org domains and certificate rate limits but breaks relaxed alignment with ur.network, affects cookies for `app.ur.network`, and is slow and hard to reverse. The alternative is DMARC `psd=y` (RFC 9989), which only receivers using the tree walk honor.
8. Gap: no source found for Gmail's or iCloud's outbound retry policy, StartMail's inbound handling, Yahoo CFL subdomain enrollment, or whether Gmail counts subdomain volume toward bulk status. EMAIL1.md asserts it does (server/EMAIL1.md:115).
9. Risk: an encrypt-on-receipt fallback (A1) means URnetwork can read inbound mail at reception and can be compelled to. The product copy must state this, as Proton does.
10. Licensing: Reclaim's circuits carry a custom license and ORIGO is an unaudited artifact. Plan to write the circuits from scratch on gnark.

## 6. Open questions for the owner

1. Is transient plaintext exposure at the edge (A1, like Proton) acceptable for the passthrough fallback and for burners, or must the strict mode bounce or defer when a device is offline?
2. Should network mail use `<net>.ur.network` (shared organizational domain, shared reputation) or a separate mail-only domain, possibly on the PSL, to protect ur.network and ur.io reputation?
3. Will outbound run on URnetwork-owned IPs (who controls PTR for edge ranges? is there IPv6 space for per-network /64s?) or through SES tenants?
4. Is v0 edge-terminated submission (URnetwork sees content in transit, stores none) acceptable for launch, with ZK end-to-end as a later research track?
5. Should burner mail be delivered only into the URnetwork apps, or also forwarded to external inboxes (which needs re-send, From rewrite and forwarding reputation)?
6. Will the ur.network zone be DNSSEC-signed (Route53 supports it) so that DANE can be used and SNI from DANE senders becomes guaranteed?
7. What should "abuse halts sending for a day" trigger on: any feedback-loop complaint, a rate over N messages, or manual review? Should free networks be paused on the first complaint?
8. Should DKIM private keys for `<net>.ur.network` live only on devices (the edge verifies) or at the edge (the edge signs)? This decides whether URnetwork can forge a network's mail.
