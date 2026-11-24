### dns-psl-listing: The Public Suffix List listing and the mail cut-over
Stage: Later, once eligible
- **Deferred:** Listing `<root>` on the Public Suffix List, and after it §14.6's cut-over of burner mail's DMARC alignment (D-DNS-1's step 5; owner decisions 13 and 79; §12.4, §12.16, §13.17, §14.6, §14.16, §15.17, §23.4; D-SMTP-5).
- **Why:** The list has entry conditions the root does not meet yet: about 3,000 active users, the `_psl` proof record and an abuse contact, with over 2 years of registration term at listing.
- **Launch instead:** The root is renewed to 2036 at M0 and keeps the `_psl` proof record (§12.4). Until the listing, every network under `<root>` shares one site (cookies, saved logins), one reputation, one Let's Encrypt budget and one DMARC organization. DMARC alignment stays strict, and each replying or forwarding burner publishes selectors of its own (owner decision 79).
- **Lost:** Browser and mail isolation between networks' names: a cookie or a reputation hit on one label reaches all. A burner's aggregate reports do not reach its network's own token until the listing (§14.8).
- **Dark in code:** Nothing is switched off. The root zone carries `_psl`, and the application is an outward step the owner takes.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** The root reaches the list's conditions; the owner applies and asks for recategorization. Then §14.6's test: a test network's burner mail, signed only under its network selector, passes DMARC at Gmail, Outlook.com and Yahoo. Each `_dmarc.<net>.<root>` then switches to relaxed alignment, burners sign with the network's selectors, and 7 days later §12 deletes the per-burner selectors and records.

### dns-bring-your-own-ns: Bring-your-own nameservers
Stage: Later
- **Deferred:** A network delegating its names to nameservers of its own, named in §12.16's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row.
- **Launch instead:** The dns edge serves every name under `<root>`, and user records refuse NS (§12.7's refused row). A Team's own domain comes at M6 as a custom domain, verified and pointed at the edge (§12.8).
- **Lost:** A network cannot run its own DNS for names under `<root>`.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for delegation: what a child zone may hold, DNSSEC across the cut, and how abuse controls reach names the edge no longer serves.

### dns-https-svcb-records: HTTPS and SVCB records
Stage: Later
- **Deferred:** HTTPS and SVCB records for user names (§12.7's refused row; §12.16).
- **Why:** §12's refused row: there is no ECH or h3 for them to announce (§13).
- **Launch instead:** User records refuse HTTPS and SVCB; clients find the edge by A and AAAA records on TCP 443.
- **Lost:** Nothing until ECH or h3 exists at the edge.
- **Dark in code:** Nothing is built: the record types are refused.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** ECH split mode or h3 at the edge (§13's entries), then the record types and what they publish.

### dns-mta-sts-certificate-gate: `_mta-sts` waiting for every receiver's certificate
Stage: Review phase, once §13's issuance for receivers settles
- **Deferred:** The certificate condition on §12.7's `_mta-sts` record: the record is published only while every published `mail_host_key` row for host `mx` has an unexpired certificate on the same key, a certificate's issuance and a host-key change each reconciling the zone (§15.5's MTA-STS; owner decision 630, whose answer takes this part of the question's option 1 at the review phase; ledger id QD-1092).
- **Why:** The verified gate is what owner decision 96 names and is cheap to hold now. The per-key join waits for the receivers' issuance path (the plan's TLS-M8-01) to settle, since it adds two callers of the zone's reconcile on that path.
- **Launch instead:** `_mta-sts` is published for a network with network_verified and mail on, and a verification change reconciles the zone (§12.7). Each receiver serves the policy only once it holds its own §13 certificate (§15.5).
- **Lost:** While one of a network's receivers is still uncertified, a sender that cached the `mode: enforce` policy refuses that receiver (RFC 8461 §5): some deliveries fail temporarily, until the router's backup ticket or the sender's retry reaches a certified receiver. A receiver is certified minutes after its key is posted.
- **Dark in code:** Nothing is built. The zone's mail policy is computed in one place, where the condition joins.
- **Held:** The review phase's two reconcile callers, at a receiver certificate's issuance and at a host-key change.
- **To bring back:** The receivers' issuance path settles; then the zone's mail policy takes the per-key certificate condition, the two write paths call the zone's reconcile, and a test shows the record withheld while one receiver is uncertified.

### dns-scope-mta-sts: A Team scope's MTA-STS publish
Stage: Later, at the owner's call
- **Deferred:** MTA-STS for a Team scope's mail: a scope system publish, `tls/443/mta-sts.<scope>` standing on a scope receiver's `smtp/25/mx.<scope>` listen, the receiver serving the scope's policy and the edge records' sync setting the scope's `*` for it, so that a scope's zone publishes `_mta-sts.<scope>.<net>.<root>` as the network's does (§12.7's scope set, §12.16, §13.9, §15.5; owner decision 715, the question's option 2).
- **Why:** Nothing serves a scope's policy: the receiver answers MTA-STS only for the network's label and alias zones, and §13.9's system publish is `tls/443/mta-sts` on `smtp/25/mx` alone. A record pointing at a policy nothing serves fails every sender's fetch and may draw TLS-RPT reports to the network's rua.
- **Launch instead:** A scope's zone publishes no `_mta-sts` until a scope publish exists (§12.7), and scope mail keeps DANE, `_25._tcp.mx.<scope>` TLSA in the signed zone, for its TLS, as burner mail does.
- **Lost:** MTA-STS enforcement for senders that do not validate DANE when they mail a scope's addresses; such a sender delivers as to a domain that publishes no policy.
- **Dark in code:** Nothing is built: the scope set's builder leaves the record out, and the zone's mail policy reconcile, which already handles scopes, finds none.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** The scope system publish above, across the sidecar's access control, sockets and mail and the server's edge records sync; then the scope set publishes `_mta-sts` as the network's does, under the same verification and certificate conditions, and a test shows a scope receiver serving its policy.

### dns-push-notifications: DNS Push for DNS-SD on the device
Stage: Later
- **Deferred:** DNS Push Notifications (RFC 8765) from a device's own resolver for §12.9.1's DNS-SD names, which owner decision 778's design named to keep clients current, named in §12.16's Later row and §12.9.1. It has no D- item, task or FS row.
- **Why:** RFC 8765 runs only over DNS Stateful Operations on TLS whose server the client authenticates under DNS over TLS's Strict Privacy profile, by DANE where it can (RFC 8765 §7), and a resolver answering a private zone on the device has no identity a client can check that way; mDNSResponder sets up its push TLS in a library Apple does not publish, so what it would accept cannot be known.
- **Launch instead:** Between hosts, §17.7.1's watch delivers each change within a round trip; on the device, the advertising proxy's registrations change at once, and unicast answers carry RFC 8766 §5.5.1's 10 s TTL (§12.9.1).
- **Lost:** A unicast DNS-SD client sees a change only when it asks again, up to 10 s later, or later where its resolver raises short TTLs, and mDNSResponder polls a long-lived unicast browse every 15 minutes.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A server identity a push client verifies: a certificate for a name in the zone that the client's validation accepts, or DANE under a signed answer for the device's resolver, and a check of what mDNSResponder, Avahi and systemd-resolved require.

### dns-service-discovery-app-paths: DNS-SD answers on app paths
Stage: Later
- **Deferred:** Answering §12.9.1's DNS-SD names with records, not NODATA, in an app's VPN component through C14's `LocalZone`, named in §12.16's Later row and §12.9.1.
- **Why:** `LocalZone.Answer` carries addresses alone (§12.9), so PTR, SRV and TXT answers need a change to C14's interface in connect, and an app's discovery view would come from its sidecar role, which on Android runs only while the app is open (owner decision 197).
- **Launch instead:** The VPN component owns the names and answers each NODATA, so no browse leaves its tunnel; desktops answer them under `ur tun` (§12.9.1) and run the advertising proxy (§17.7.1).
- **Lost:** On iOS, Bonjour's default browses, AirPrint's among them, do not find the network's instances; on Android only an app that queries DNS itself could have found them.
- **Dark in code:** The NODATA ownership is built; no record answer is.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A `LocalZone` method that returns RRsets (a C14 amendment, §4.6), the sidecar role handing its view to the VPN component over the device RPC with each record's expiry, and `lb._dns-sd._udp` answered positively where no advertising proxy runs.

### dns-v1: §12's v1 set
Stage: v1 (M6, M7, M8)
- **Deferred:** §12.16's v1 row: aliases, custom domains in both CAA modes, Team scopes and §12.9.1's DNS-SD names in `ur tun`'s resolver at M6 (owner decision 778); `LocalZone` owning those names on app paths, scope mail hosts with §15 at M8; direct MX and strict-mode MX hosts at M7.
- **Why:** They are Team items (owner decisions 33, 55, 58); the DNS-SD names come with §17.7.1's discovery and `ur tun` on macOS and Windows at M6.
- **Launch instead:** v0's zone: labels, edge, challenge, SPF, DMARC, null MX and user records at M5; mail records, TLSA and the DS at M7; replying burners' selectors and the reverse zones' PTRs at M9.
- **Lost:** Until those milestones: a Team's own domain, aliases and scope hosts, and DNS-SD across hosts.
- **Dark in code:** Built in the same run on the `sidecar` branches. §13.4's generated split map blocks M6's custom hosts.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: each ships when its milestone's gate passes (§23.6).
