# Owner decisions (interview, 2026-11-03)

Asked one at a time, in the architecture reviewer's priority order. Each answer becomes "decided by owner" in DESIGN.md.

1. **X12 / Q-KEYS-9 — MLS in v0 (PLAN.md as written).** Fork an MLS implementation into the sidecar repo for v0; per-device wraps are not the v0 distributor. (Follow-ons Q-KEYS-1 fork choice and Q-KEYS-2 ciphersuite stay with their recommendations unless the owner answers them separately.)
2. **X2 / Q-EVS-1 — hashed path segments (owner's words):** "I don't think we can efficiently implement a git version control storage without exposing some idea of paths. I think we can use hashed path segments so the plaintext path names are not exposed. Review the efficiency of the implementation and what we need for efficiency."
   - Replaces the drafted option (c) (opaque segments + sealed client HAMT index). The server sees a keyed, parent-chained token tree, never names.
   - Efficiency review delivered to the owner (see the evs rewrite brief below). The design must include:
     1. Tokens `t = HMAC-SHA256(K_path, t_parent ‖ name)[:16]`. They are keyed (not a plain hash), parent-chained, fixed 16 B, with a per-repo key.
     2. A server path index in Postgres: (repo, ref, token path) → kind, padded size, chain locators, version. A head read is 1 RTT.
     3. Per-file checkpoint+diff chains (PLAN.md:63), XChaCha20-Poly1305 with random nonces.
     4. Records packed into ≤8 MiB segments with a server record index. The file cluster needs streaming PUT, ranged GET, and Delete.
     5. A push is segments + manifest delta {token path, base version, locators} + sealed commit metadata + signed head. Path-level CAS lets disjoint concurrent pushes land; clients verify by replaying signed deltas.
     6. Names stay encrypted in a sealed per-directory name table, used only for listing.
     7. Subscriptions match on token prefixes, server-side.
     8. Padmé size padding.
     9. Path-key rotation on member removal, via an old→new token translation map.
     10. Server-side GC from the index. Postgres durability (replica + WAL) becomes critical (X13/Q-OPS-3).
   - Published metadata: token tree shape, per-file change history (token, time, uploader sidecar), padded sizes, push DAG, timing. Never: names, contents, messages, author names, cross-repo equality.
   - **Owner follow-up (proposed revision to requirement 2):** "can't this be stored in minio with the dir and path as the key?"
     - Answer: yes. The index lives in the file cluster at `idx/<repo>/<ref>/<t1>/…/<tn>`, holding an entry plus the last few versions. Small files' chains are inlined.
     - Head read: GET on the computed key plus a ranged GET of the segment.
     - Listing and sparse fetch: native prefix LIST.
     - Atomic push: per-ref lock with a fencing token, entries written at v+1, then the head swapped v→v+1. Readers take the newest entry ≤ the committed head.
     - Commit point:
       - (a) v0: one tiny Postgres row per ref, rebuildable from immutable signed push-log objects (recommended now);
       - (b) a file cluster with reliable If-Match/If-None-Match, which removes Postgres from evs (X13).
     - Adds to X13: small-object IOPS (NVMe), reliable conditional writes, strongly consistent LIST, ranged GET, Delete.
     - Status: awaiting owner OK.
   - **Owner direction (supersedes the Postgres index and the one-Postgres-row-per-ref compromise):** "Ideally we do not need postgres or redis at all for file storage."
     - evs and gkm are stateless services over the file cluster. All storage state is objects:
       - `seg/<repo>/<id>`: immutable segments.
       - `idx/<repo>/<ref>/<t1>/…/<tn>`: the path index. Each entry keeps its last few versions, tagged with a push id, and is written with If-Match.
       - `head/<repo>/<ref>`: the commit point. If-Match CAS. Holds version, push id, signed head hash, and the last 64 versions' changed token paths.
       - `push/<repo>/<ref>/<push_id>`: immutable signed manifest deltas, used for history, GC, audit, and rebuilds.
       - `subs/<repo>/<client>`: lease objects.
       - `gkm/<group>/epoch/<n>`: MLS epochs. If-None-Match:* gives one accepted commit per epoch. KeyPackage and Welcome objects live alongside.
     - Readers use only entry versions whose push id the head records as committed. Orphans are pruned after a timeout.
     - Auth: capability tokens from the §7 token exchange (aud evs, scope repo:<id>:rw), verified offline.
     - Revocation: 15-minute tokens plus a signed revocation object in the cluster.
     - Quotas and billing: async usage events to the server, soft limits, reconciled from the push log.
     - Notifications: via the §6 push channel.
     - Costs: a push takes ~3–4 sequential store RTTs (40–80 ms); a head read takes 2–3 GETs (20–50 ms).
     - X13 becomes a hard requirement:
       - reliable If-Match and If-None-Match (the deployed MinIO fails under lost read quorum; options are a current MinIO build, AIStor, or a verified store; AWS S3, R2, GCS, and Azure support it);
       - strong read-after-write and LIST consistency;
       - ranged GET, Delete, and lifecycle rules;
       - small-object IOPS (NVMe);
       - multi-node erasure coding plus cross-site replication.
     - Q-OPS-3's Postgres durability concern no longer applies to storage.
3. **X3 / Q-ACL-1 — customer key authority from v0.** Admin keys sign policy and membership from launch. Clients refuse any rule or peer they cannot derive from signed inputs, so a breached server can only deny or delay. v0 must include §7's authority: quorum, bootstrap, and recovery. Server gates still evaluate policy, so the policy and reach graph stay server-visible (Q-ACL-2 wording). This supersedes the phased recommendation; Q-TRUST-1, Q-TEAM-5, and Q-KEYS-5 follow (member-signed admission is subsumed).
4. **X10 / Q-CORE-1 (+Q-CORE-2, Q-QUOTA-4) — own client per sidecar; no-egress sidecars exempt.**
   - One encryption-required client per sidecar: a child of the device's client where one exists in the same network, otherwise top-level. Never the device's own client; never one client per agent (per-agent subkeys in v1).
   - Sidecars that declare no internet egress are exempt from `concurrent_clients` and the 100 top-level cap. They count against a separate `sidecar_clients` cap (e.g. 20/200/2,000) and are refused Public provider contracts.
   - Q-CORE-6 (several networks per device) is still open.
5. **Owner proposal (X3 mechanism):** "Can we leverage the encrypted storage to sign and distribute config? If that already has key management, we can have an admin config dir per network that solves the signing issue."
   - Design: one evs repo per network, kind `config`, created by the owner's first device.
   - The genesis head (owner identity key) is the trust anchor, delivered inside invites and auth keys (or TOFU with a safety number).
   - Only admins write. Clients verify that each signed head chains back to genesis through the admin set recorded in the repo.
   - The repo holds:
     - the admin set;
     - member and device admissions (signed by an admin, or by the member for their own devices);
     - tags and groups;
     - policy source;
     - bridge rules;
     - service settings;
     - a signed, id-only projection that admins publish for the server's gates.
   - Distribution: evs subscriptions.
   - The server sees ciphertext plus that projection. This satisfies PLAN.md:119 ("rules stored on the server", now signed and encrypted).
   - The config repo's MLS group is driven by its own admission records.
   - Sub-question on read scope is next.
6. **Config repo read scope: all admitted devices read the whole config** and evaluate their own rules locally; no always-on compiler. Admins write. The server gets the signed id-only projection.
7. **Owner requirement:** "The encrypted storage will need to be able to grant a key as a reader or a reader+writer."
   - Read = possession of repo keys (membership in the repo's MLS group, or a wrap for deposits).
   - Write = acceptance of signed heads: readers accept a head only if its signer key is in the repo's writer set. The server also gates pushes by capability token scope (repo:<id>:r vs :rw), but clients do not rely on it.
   - A reader holds content keys yet cannot forge accepted writes, because heads are signed and cover manifests and segments.
   - MLS commits that change membership are accepted only from keys allowed to grant; any member may self-update its leaf.
   - Grants are signed records {repo, key or subject, role reader|writer, granted_by, expiry}.
   - Revoking a key = MLS Remove + a new key generation (lazy: the removed key keeps old data it already had).
   - Who may grant is the next question.
8. **evs grant authority: repo admins + network admins.** A repo's creator is its admin and can add admins. Repo admins sign grants into the repo's access log. Network admins can always grant or revoke via the config repo. Clients verify through the delegation chain from the config repo.
9. **X15 / Q-PHASE-1 — two parallel tracks after M2.** One team builds recURd (capture, reach, team); a second builds mail and burner. Both share M0–M2. Mail's external lead times start in M0. The plan must staff a second team.
10. **X11 / Q-QUOTA-2 (a) + Q-QUOTA-6 (a) — all traffic bytes count; capacity is quota.**
    - Debited byte for byte: edge traffic (TLS, SMTP), cross-network shares, storage uploads and downloads, and same-network sidecar relay traffic (relay-only until connect C3 restores P2P).
    - Storage GB, emails/day, DNS entries, and TLS endpoints are tier quotas, not debited.
    - Requires a service-usage debit path in the server: Service-mode leases plus metering from contract close reports.
11. **Q-QUOTA-5 (a) — the dialing network pays for cross-network share traffic** (source-pays escrow, as Public today). Accepted with it: Q-PROTO-3 (b). Edges use a new Service provide mode (connect C9); shares use FriendsAndFamily with the source network sealed (C13). Neither carries Network privilege or enters the egress index.
12. **X6 residual / Q-MAIL-2 — burner mail is received by always-on receivers only:** a desktop daemon, a NAS or VPS, or Android with the VPN on. There is no iOS tunnel receiver role. iOS-only users receive while the app is open, and time-sensitive codes may expire; the product copy must say so. No hosted or TEE receiver.
13. **X4 / Q-DNS-1 (b1) — ur.network becomes a user-content-only root.**
    - Platform names (api, connect, *.connect, mcp, gossip, grafana, lb hosts) and company mail move off ur.network, to bringyour.com or ur.io.
    - The lb routes all of *.ur.network to tlsedge.
    - The zone is signed (DNSSEC), set to strict DMARC, and PSL-listed when eligible.
    - Renew ur.network for 3+ years now (it expires 2027-07-02).
14. **X5 / Q-DNS-2 (a) — opaque, random, immutable network label** (e.g. k7q2m9.ur.network), with an opt-in public alias equal to network_name (e.g. brien.ur.network). Takeover-proof. CT shows random labels unless the alias is chosen. Renames never break addresses.
15. **X17 / Q-DNS-3 (owner's words):** "The initial recurd product will be hosted at ur.io/recurd and use the main env (bringyour.com) services. recurd.dev will just forward to ur.io/recurd." There is no dedicated recurd.dev infrastructure, issuer, or relays initially; recurd.dev is a redirect to ur.io/recurd.
16. **Service domain (owner):** "We will settle on bringyour.com as the urnetwork service domain."
    - Platform and service names (api, connect, mcp, auth, gossip, grafana, lb hosts, the new evs/gkm/sockets/dns-admin APIs) live on bringyour.com.
    - ur.network is user content only (decision 13).
    - ur.io is the web, including ur.io/recurd.
    - Q-TLS-1 simplifies: *.ur.network carries only user names, so it routes to dedicated tlsedge addresses with no SNI split against platform names.
17. **X8 / Q-PROTO-1 (b) — residents send sidecar subprotocol frames from ControlId.**
    - Amend SUBPROTOCOL.md decision 6 to: "the control id may send subprotocol frames to clients; clients never send them to it".
    - HTTPS long-poll fallback in v0.
    - Pushes are hints only (ControlId traffic is not e2e-encrypted); clients resync on reconnect.
    - Note: evs triggers pushes through the resident's Redis keyspace-event path. That is notification transport, not storage state, so it is consistent with "no Postgres/Redis for file storage".
18. **X13 / Q-OPS-1 (a) — a new self-hosted MinIO cluster built from the final upstream source** (it has the conditional-write fix), maintained in-house.
    - ~4 new SSD/NVMe hosts (~$14-37k of drives), separate from edge-5.
    - Off-site copy to B2 or R2.
    - Conformance tests for If-Match, If-None-Match, consistency, ranged reads, and Delete gate every upgrade.
    - The backend sits behind a sidecar storage interface (ServiceHost.Blobs), so it can be swapped.
    - Ordering lives in the object store (decision 2), not Postgres; Q-OPS-3 does not apply to storage.
19. **Q-REPO-1 (a) — engines in sidecar, hosted by server.**
    - All service logic (evs, gkm, sockets, dns, tlsedge, smtpedge, mail ingress, policy evaluation) is an engine in the sidecar repo behind small host interfaces.
    - server implements the interfaces, owns migrations and routes, and ships each engine as server/cli/<svc> via warp.
    - evs and gkm engines need only an injected S3 client.
20. **File cluster hardware (owner):** "The new minio will be 4 host each with 16x16TB jbod hdd."
    - 64 HDDs, ~1 PB raw.
    - Assumed layout: 16-drive erasure sets spanning hosts (4 drives per host per set) at EC:4, giving ~768 TB usable and survival of one host.
    - Implication: HDD small-object IOPS. MinIO writes each small object to every drive of its set, so the cluster caps at roughly 500–800 small PUT/s, about 50–130 pushes/s. 16 TB rebuilds take days.
    - Follow-up question asked: NVMe metadata tier vs HDD-only batching.
21. **Small writes — add a small NVMe metadata tier:** 2 NVMe drives per host, run as a separate small MinIO pool or cluster for metadata objects (index entries, heads, push logs, gkm, subscriptions). Encrypted segments stay on the HDDs. The storage interface separates the metadata bucket from the segment bucket.
22. **X9 / Q-REPO-2 (b) — approve the recommended connect changes on connect's sidecar branch:** C3 (M1), C5 (M4), C6a (M4), C8 (M4), C9 (M5), C11 (M1), C12 (M1), C13 (M4), C14 (v1), C15 (M1), C16 (M4), C4 (later). Rejected: C1, C2, C6b, C10. Deferred: C7. C17 is decided after the §18 spike.
23. **Q-CORE-6 (b) — one daemon hosts one Sidecar per network.** The networks share the keychain unlock and one MCP endpoint. Each has its own client, sidecar_id, and identity key, so no key links networks. MCP tools take a `network` argument whose default comes from the project's `.ur` file. A team-network sidecar is a top-level client of the team network (counted per decision 4).
24. **X19 / Q-EVS-2 — local git server + git-remote-ur.** The sidecar serves plaintext git on localhost (`ur mount`; http and ssh; loopback only; authenticated). A `git-remote-ur` helper makes `git clone ur://<net>/<repo>` work wherever the sidecar runs. Only the sidecar talks to evs, over its HTTPS object API (git-shaped encrypted objects). PLAN.md:57 is met at the sidecar.
25. **X20 / Q-MCP-1 (b) — record primitives in DESIGN.md; RECORD.md designed separately.**
    - DESIGN.md provides: append-only signed entries in evs, per-entry keys for erasure, approval signatures, reach receipts (§13, §14, §17), and a frozen record.proto.
    - RECORD.md (sidecar repo) owns entry semantics, search, exports, the verifiable log, and disclosure. It is an M0 deliverable, reviewed before storage format 1 freezes.
26. **X14 / Q-SDK-1 (a) — the extension runs a WASM worker, with a native companion meanwhile.**
    - A worker loader and a slimmed sidecar.wasm run in an offscreen document.
    - HTTPS-only to the APIs first; connect streams follow C4 (the browser WebSocket carrier).
    - Until then, where a desktop `ur daemon` exists, the extension uses it over native messaging.
    - Never a hosted sidecar.
27. **X16 / Q-QUOTA-1 (b) — PLAN's quota numbers; Team $100/month for 5 billable seats, then $20 per extra seat.**
    - Quotas: storage 1/20/200 GB, emails/day 5/200/20000, DNS entries 5/200/2000, TLS endpoints 1/20/200, IP and port forward unlimited, SSO and custom domains Team only.
    - Auditor and billing-admin seats and agents are free.
    - Sends, DNS entries, and TLS endpoints are hard caps. Overage only on transfer bytes and storage.
    - Replies-only for free (cli/UI.md) is dropped because it cannot be enforced on ciphertext.
28. **X18 / Q-BRIDGE-1 (owner's words):** "ipv4 overlay, allocate random /16 per network, let the user cycle or choose as they want."
    - IPv4 overlay only (no IPv6 overlay planned for now). Each network gets a random /16, drawn by default from 100.64.0.0/10, which the apps already route; C6a makes it non-public first.
    - Network admins can cycle (re-roll) or choose any /16 to avoid LAN, Tailscale, or CGNAT collisions. A chosen /16 outside 100.64/10 is exported by the SDK as an included tunnel route for the apps to add.
    - Changing the /16 renumbers the network's clients; private names (v1) soften that.
    - Uniqueness across networks is not required. Overlaps matter only on a device in several networks (decision 23): the daemon warns and the user cycles.
29. **Q-MAIL-3 — burners live under ur.network** (no new burner domain).
    - Default format (b): `<anything>@<adjective-noun-NNNN>.ur.network`, one label per burner, each with its own MX and its own device-held TLS key published via DANE, routed by SNI to the owner's receivers.
    - Alternative format (c): `adjective-noun-NNNN@<random label>.ur.network`. Interpretation pending owner confirmation.
    - Burner labels share the namespace with opaque network labels and opt-in aliases, so aliases may not use the adjective-noun-NNNN pattern.
    - Needs DNSSEC compact denial so friendly labels cannot be enumerated.
    - Burner mail reputation is shared with ur.network user content.
30. **Q-SMTP-2 — the send quota unit is outbound connections per day (owner):** "The smtp send quota can be roughly enforced because we can enforce the number of connections out."
    - PLAN.md:89's "N outgoing connects per day" is kept, approximating emails/day (5/200/20000).
    - Per-connection byte and duration caps stop one connection from carrying a bulk batch.
    - The recipient count declared in the preamble is cross-checked against the connection count.
31. **X6 residual / Q-MAIL-1 (c) — inbound routing by SNI + a per-network IPv6 + DANE.**
    - Route by SNI when present, else by a unique IPv6 per network behind a shared IPv4 A record.
    - ur.network is DNSSEC-signed, with DANE TLSA for device keys, so DANE senders always send SNI.
    - IPv4-only senders with no SNI are deferred; an M7 census measures the loss before burner launch.
    - Team may add dedicated IPv4.
32. **Burner format (owner, supersedes decision 29):** "i prefer something real like <name>@<word-number>.<me>.ur.network".
    - Burners live inside the network's zone (PLAN.md:25): `<name>@<word-number>.<me>.ur.network`. <me> is the opaque network label, or the opt-in alias. <word-number> is a generated label such as otter-4821. <name> is any local part.
    - Design: a wildcard MX `*.<me>.ur.network → mx.<me>.ur.network` gives burners zero DNS entries and no DNS-quota use.
    - Burning a label = receivers reject mail for it (5xx).
    - One DANE TLSA record at `_25._tcp.mx.<me>.ur.network` holds device keys. SNI is always mx.<me>.ur.network, so the edge routes by network.
    - A wildcard cannot be enumerated; no compact denial needed.
    - Trade-off (accepted): burners of one network share <me>, so correspondents can link them to each other. With an alias they reveal the network name. Q-MAIL-10's "unlinkable" copy must change accordingly.
33. **X6 residual / Q-MAIL-9 (a)+(c) — refuse plaintext (non-STARTTLS) senders with 530, and publish the RFC 3207 deviation.** Team networks may run a direct MX: MX points straight at their own always-on receiver, bypassing mxedge.
34. **Constraint (owner):** "There are no dedicated ipv4 or ipv6 options currently."
    - Decision 31 revised: inbound routing is SNI + DANE only. There is no per-network IPv6 and no Team dedicated IPv4. Senders that send no SNI are deferred.
    - The M7 SNI census (which senders, by ASN, send SNI) gates burner launch.
    - Note for the owner: a routed IPv6 block, if ever obtainable (e.g. from the transit provider), restores the fallback.
    - Q-TLS-1 → (a): tlsedge shares the existing lb addresses through an ssl_preread SNI split on TCP 443. ur.network names go to tlsedge; bringyour.com platform names go to the http listeners.
    - Q-SMTP-6: smtpedge sends from the existing shared IPv4 addresses. It needs port 25 egress and PTR/rDNS delegation from the provider.
    - mxedge listens on public TCP 25 on the existing lb interfaces (new port).
35. **X7 residual / Q-SMTP-1 — wait for sound ZK before launching outbound mail.**
    - smtpedge does not ship until preamble proofs are sound (ORIGO-style key binding plus proofs of the SMTP grammar and header block), externally audited, fast enough on desktops, and interop-tested with Gmail, Outlook, and Yahoo. TLS 1.2 coverage for Exchange Online is part of the bar.
    - Implications:
      - The ZK proof system is a research and engineering track on the mail team's critical path.
      - Inbound (mxedge) is independent, so burner email can launch receive-only.
      - Replies and sending arrive with smtpedge.
      - §23 must reorder the mail track and budget the audit.
36. **X7 residual / Q-SMTP-5 (a) — each sending sidecar holds its own DKIM key under an opaque selector** in the network zone (≤64 selectors). URnetwork publishes only public keys, so it cannot forge a network's mail. Removing a device deletes its selector. Selectors reveal the number of sending devices (published metadata).
37. **Q-SMTP-3 (d) — tiered, domain-scoped halts.**
    - A single complaint halts only the reported sending domain (e.g. that burner label) for a day.
    - Community: the first network-wide complaint halts the network for a day.
    - Pro and Team: halt on complaint-rate thresholds (e.g. 0.5% Pro, 0.1% Team).
    - Confirmed fraud or phishing halts immediately on any tier.
    - Appeals restore early.
    - This refines PLAN.md:91.
38. **X7 residual / Q-SMTP-4 (a) — refuse unauthenticated destination MXs** (no valid WebPKI certificate for the MX host, no DANE, no MTA-STS) with an explanatory DSN, unless the user allows that destination domain. Plaintext destinations are always refused.
39. **X1 residual / Q-TLS-2 (c) — certificate ordering.**
    - ur.network zones: the sidecar generates the key and CSR; URnetwork's cert service completes DNS-01 and returns the certificate, never seeing the key.
    - Team custom domains: the customer's own ACME account, pinned by customer CAA (accounturi), so URnetwork cannot issue for them.
    - Sidecars monitor CT for certificates they did not request.
40. **X1 residual / Q-TLS-3 (a) — per-device keys and per-device certificates for the network wildcard; scope sublabels when needed.**
    - Teams past LE's refill of 5 per exact set per week (then ~1 per 34 h), or wanting member isolation, use scope sublabels `*.<member-or-tag>.<me>.ur.network`.
    - A shared wildcard key is rejected.
41. **X1 residual / Q-TLS-4 (c) — abuse hooks plus a verified account for Community publishes.**
    - Hooks: L4 kill switch (≤5 s) with certificate revocation, connection and bandwidth caps, Safe Browsing and CT monitoring, the published-names list.
    - Community publishes last at most 7 days (renewable).
    - A verified account (payment method or verified phone or email) is required before any Community publish.
42. **Q-TLS-7 (a) — TLS edge access default: network members via URnetwork login.**
    - Per-service options: "members on an enrolled device" (not IdP-dependent), signed guest links, or explicit public (e.g. webhooks).
    - URnetwork users can also reach services over the overlay.
    - The check runs in the sidecar's front on the device; the edge only passes ciphertext.
43. **X12 / Q-KEYS-1 (c) — a narrow in-house MLS implementation** of only the RFC 9420 subset evs needs: ~5-8k lines, ~2-4 engineer-months, pure Go, in the sidecar root package (mls_* files).
    - Tested against the mlswg vectors, plus differential tests against thomas-vilte/mls-go and tmc/mls.
    - External audit planned.
44. **X12 / Q-KEYS-2 (b) — ciphersuite 0x0010: a hybrid post-quantum KEM (X-Wing: ML-KEM-768 + X25519) with Ed25519 signatures, from v0.** If the IANA codepoint changes, migrate groups to a new group linked into the key ladder.
45. **Q-TEAM-1 — the staged P0 auth fix.**
    - Before the first sidecar: mark sidecar and child tokens and refuse them on every AppAdmin route, including /auth/code-create.
    - Before the first desktop sidecar: move code-create, add-auth, remove-auth, the seed-phrase routes, and network delete to network-token-only, and stop persisting the app's network credential where same-user agents can read it (.auth_state).
    - Flip all 27 AppAdmin routes once the apps have migrated (the hard gate).
    - Also: Q-TEAM-5 is superseded by decision 3. The customer key authority is enforced from v0, not opt-in.
46. **Q-TEAM-4 (a) — Team SSO is OIDC only:** per-network OIDC IdP, domain verification, JIT provisioning. SAML-only customers broker through an OIDC-capable IdP.
    - Implied by decisions 3, 5, and 6 (Q-TEAM-7): the server keeps only what login and API authorization need (users, emails, roles). Groups, tags, device names, and admissions live in the encrypted config repo; the server sees the id projection.
47. **Q-TRUST-2 (a) — the harness and its agents are inside the device trust boundary.**
    - The sidecar defends only against tool misuse, not against same-user agents reading its state.
    - No separate daemon OS user or keystore isolation is required. Keystores are still used where convenient.
    - Implications:
      - Local approvals cannot tell a person from an agent on the same device, so human-only approvals need another device or a presence key (Q-MCP-3).
      - §2's threat model lists a compromised harness as device compromise.
      - The AUTHZ fix (decision 45) still applies, because sidecar tokens must never administer the network.
48. **Q-CTX-1 (b) — self-hosting comes at the later "assured" stage, kept possible from v0.** Engines reach URnetwork-only infrastructure (Route 53, warp, shared Postgres, connect relays) only through interfaces. There is no self-hosted bundle in v0.
49. **Q-MCP-4 (a) — cloud agents run `ur` inside the VM**, reaching bringyour.com through the sandbox's HTTP CONNECT proxy (connect C8, M4). A published hostname list is provided for allowlisting. Keys stay in the VM. Remote MCP to a user's sidecar is not planned.
50. **Q-BRIDGE-3 (b) — providers refuse LAN, loopback, link-local, and overlay destinations to same-network sources only in networks that have an ACL document;** there, the policy decides. Networks without one keep today's allow-all. Note for §2/§21: the default hole stays open for networks with no policy. Peer review should weigh making a default ACL document part of enrolling the first agent.
51. **Q-REPO-4 (a) — keep the docs and code together in the sidecar repo; publish later.** Before going public, decide what to scrub; history must then be rewritten or the repo kept private. The open-source publication date is deferred.
52. **Q-REPO-3 (a) — sidecar/protocol (the .proto files plus generated Go) is a test-enforced exception to the "no importing own subpackages" rule,** as in connect. A test enforces that protocol/ imports nothing from the sidecar module.
53. **Q-MAIL-4 — opt-in burner forwarding ships with outbound mail (smtpedge).** It goes to one verified external address through reverse aliases, spam-gated and counted against the send quota. Until then, burner mail is read in-app, via MCP, or over loopback IMAP from the user's own sidecar. The burner launch copy may say forwarding is "coming with sending".
54. **Q-MAIL-5 (a) — disclose that a team network's receivers see its inbound mail in transit; teams designate receivers** (e.g. tag:mail servers run by admins). Personal burners belong in members' personal networks.
55. **Q-TEAM-2 (a) — new team networks only in v1;** no in-place conversion of personal networks. Members keep their personal networks alongside (decision 23).
56. **Q-TEAM-3 (a) — SCIM provisioning is in Team v1** (with OIDC SSO, JIT provisioning, and the re-authentication deadline).
57. **Q-MCP-2 (b) — bare `ur` speaks stdio MCP when stdin is not a terminal, and prints help on a terminal.** `ur mcp` always speaks MCP.
58. **Q-MAIL-5 revised (owner): "a hybrid of team and per-device to give the user a choice."**
    - Each team chooses between (a) team-designated receivers (tagged devices receive for the whole network, disclosed) and (b) per-member or per-device receivers with their own mail subdomains (e.g. `<member>.<me>.ur.network`, each with its own MX host and DANE keys), so only that member's devices see that member's mail.
    - Supersedes decision 54's single option.
59. **Implied by earlier decisions (recorded, not asked):**
    - Q-CTX-3: a recURd team = a team network plus each member's personal network (decisions 23, 55).
    - Q-TLS-5: tlsedge runs platform clients in the Service provide mode, not a client per served network (decision 11). This departs from PLAN.md:82.
    - Q-SOCK-3 = Q-PROTO-3 (decided).
    - Q-TRUST-3: URnetwork can obtain certificates in its own zones; this is a published capability, and sidecars watch CT (decision 39).
    - Q-CORE-3: the daemon runs as the user (decision 47).
    - Q-ACL-8: moot. The policy source lives in the encrypted config repo; the server sees only an id projection (decisions 5, 6).
    - Q-KEYS-4: GKM = the MLS delivery service plus wrapped repo-key generations, stored in the file cluster (decision 2).
    - Q-KEYS-12: gkm sees only ciphertext plus small headers (group id, epoch, sizes) per the directive.
60. **X12 / Q-KEYS-3 (a) — one MLS group per evs repo** (PLAN: one dir = one repo = one key). Reader and writer grants map onto group membership.
61. **Q-KEYS-6 (b) — per-entry crypto-shredding for record-class repos and mail** (author vaults, team records, mailboxes, burner vaults), via a key slot per entry or file chain, in format 1. General repos use a slot per segment and repo-level erasure.
62. **Q-KEYS-7 (b) + Q-CORE-5 — recovery code plus admin re-add.** At setup the member records a recovery code (shown once, kept offline). It derives a recovery key that receives wrapped copies of the member's repo key generations, under a signed, rotatable binding. Team repos can also be restored by an admin re-add (new key generations).
63. **Q-KEYS-8 (b) — Team escrow is a visible audit member on a customer-operated device, as a Team opt-in in v1.** It is a normal reader of the repos policy assigns, shown to every member, and never silent. No URnetwork-held escrow.
64. **Q-KEYS-10 (a) — lazy rewrap (PLAN.md:50, :338).** The first write to a file after a removal writes a full checkpoint under the new key generation. Untouched files stay under old keys until written. `ur evs rekey` re-checkpoints on demand.
65. **Q-SOCK-1 (a) — the default scheduler is load-aware weighted power-of-two-choices on in-flight streams,** with drain and retry. Hash stickiness (affinity) is opt-in.
66. **Q-SOCK-2 (b) — no caps on IP and port forwarding or sockets; "unlimited" is literal.** Only the transfer balance (bytes count, decision 10) limits usage. The relays and scheduler keep system overload protection (backpressure, fair queuing, load shedding) but no per-network count caps. §9.10 and §17's caps are removed.
67. **Q-SOCK-4 — internal socket names are blinded:** the server stores HMAC(network key, name), with the key held in the config repo, consistent with evs hashed paths. Names published through the TLS edge stay plaintext (public via SNI and CT). Clients and the console resolve names locally.
68. **Q-TLS-8 (b) — published names may use 443 plus a short fixed list of TLS ports,** each a permanent lb port on the shared addresses. §13 proposes the exact list (e.g. 8443 plus a few TLS service ports) for owner approval.
69. **Q-DNS-4 — self-hosted authoritative DNS only** for ur.network (the dns engine, hosted by server), with online DNSSEC signing.
    - Requires:
      - resolving the port-53 conflict (connect WhoDis owns UDP 53 on the lb addresses, so either move WhoDis off 53 on some addresses or run dns on other existing hosts);
      - publishing TCP 53;
      - at least two NS addresses on separate hosts.
    - Risk: no secondary provider and no anycast, so availability and DDoS resilience depend on our hosts. Burner and mail delivery depend on DNS uptime.
70. **Q-DNS-6 (a) — networks create and edit their own records** (A/AAAA to public addresses, CNAME, TXT, extra MX within limits) under quota. System-managed records are refused: mail routing, DANE, SPF/DMARC, ACME, edge records, NS/DNAME delegation, and private or loopback addresses.
71. **DNS hosting (owner): "self-hosted dns. We will add a new edge type for this."** The authoritative dns service runs on a new edge host type with its own addresses. This resolves the port-53 conflict with connect WhoDis and provides the ≥2 NS addresses. §19 adds the dns edge type: warp service, hosts, TCP and UDP 53, DNSSEC online signing.
72. **Implied (Q-ACL-2 wording):** with decisions 3, 5, and 6, the policy is "signed under your key authority, stored encrypted in your network's config repo. URnetwork enforces an id-only projection: it sees which ids may reach which, never names or rule text." This replaces the mock's "transports it but never reads it" and "never sees connection metadata" (both false). §2.8 lists the reach graph.
73. **Q-ACL-6 (a) — every tier may write access-control policies,** with per-tier limits in pro.yml (rule counts; features such as groups, approvals, cross-network shares). Community can turn on LAN and loopback protection (decision 50).
74. **Q-ACL-7 (a) — requested grants.**
    - Approvers: the requester's owner (or a tagged agent's sponsor), from another device or a presence key. An admin approves grants touching other members, cross-network shares, or public exposure.
    - Durations: ordinary grants default to 1 h, maximum 30 days. Publishes follow the 7-day edge rule.
    - Team may require two approvers. All defaults are overridable per network.
75. **Q-MCP-3 (c) — for single-device users (no second device or presence key), the harness's own permission prompt counts as approval of outward actions,** consistent with decision 47.
    - Approvals in the record are labeled by evidence type: harness prompt, second device, or presence key.
    - Network policy (e.g. Team) may require stronger evidence.
    - Refines decision 74's "from another device" for single-device networks.
76. **Q-TRUST-4 (a) — web pages may decrypt, clearly labeled** that served code is trusted on each load. Implied:
    - Q-CTX-2 → (a): one browser sidecar runtime (the same WASM sidecar as the extension, decision 26) serves ur.io/recurd, the team console, and the ur.io quick tools.
    - Q-SDK-4 → (b): the ur.io quick burner may run an ephemeral, labeled wasm sidecar in the page.
    - §2 lists "web-served code" as a trust exception.
    - Code transparency (WEBCAT-style) is to be adopted when it matures.
77. **Q-TRUST-5 (c) — signed releases only** (standard code signing and notarization). No reproducible-build or transparency-log gate for the E2EE claim. §2 records the residual: users trust the build pipeline.
78. **Q-SMTP-7 (b) — the raw bytes of an attributed abuse report are sealed unparsed to the network's mail key (HPKE) and kept 30 days** for appeals. URnetwork retains only the attribution fields (domain, DKIM selector, Message-ID, attribution token).
79. **Q-MAIL-12 (b)→(a) — burner replies.**
    - Until ur.network is on the PSL: burners that send replies get their own DKIM selector and MX records (published, walkable) for strict alignment. Receive-only burners stay record-less under the wildcard MX.
    - After PSL listing: relaxed alignment with the network's selectors, and per-burner records are dropped.
    - Applies once outbound ships (decision 35).
80. **Q-MAIL-11 (c) — email approvals are dropped from the product.** Approvals come only through devices, presence keys, or the harness prompt (decision 75). pitch5:899's "approve by email reply" is removed. Q-PHASE-2 is moot.
81. **Q-EVS-4 (b) — forced git identity (PLAN.md:59).**
    - The signed head authenticates every push.
    - The sidecar's local git server refuses new commits whose committer is not the pushing sidecar (`<agent label> <client_id@ur.invalid>`, resolved via §5's binding log). Imports of existing history pass through a signed import exception.
    - Author fields stay free.
82. **Q-EVS-5 (a) — repo deletion is a soft delete:** access is refused at once, and keys are shredded after 7 days unless restored. `--now` shreds immediately.
83. **Q-TEAM-8 (b) — tagged agents a departing member enrolled are kept (Tailscale model)** and keep their tag's grants. Admins may reassign sponsorship.
    - Implied Q-TEAM-9 (a): a released network name is held 24 h, since DNS, mail, and certificates key on the immutable label (decision 14).
84. **Q-BRIDGE-5 (owner): "0.0.0.0/:: by default, --listen to narrow."**
    - Keeps cli/UI.md:11: forwards and local service listeners (git, mail, IMAP) bind all interfaces by default; `--listen` narrows.
    - Supersedes D-TRUST-8's loopback default and I-17 for these listeners.
    - Kept: the daemon's control/IPC channel stays a Unix socket or named pipe (not a service port); local servers authenticate callers; HTTP targets keep the DNS-rebinding Host check.
    - §2 records LAN exposure of granted forwards as an accepted risk.
85. **Q-BRIDGE-4 (b) in v0 — private split-DNS names for overlay addresses ship with the first bridge release:** `<client-name>.<me>.ur.network` → the overlay IP, answered locally on members' devices and built from the config repo. Delivered by connect C14 (UpgradeMux.SetLocalZone) on app paths, moved from v1 into the bridge milestone, plus a per-link resolver under `ur tun`. Never forwarded or published.
86. **Q-BRIDGE-6 (a) — the IP path carries all forwards and invites, including cross-network.**
    - Adds a connect change (new X9 row, e.g. C18): stop treating FriendsAndFamily sources as Public toward private destinations, at both ends (connect/ip_security.go:385-390, :574-576).
    - The accepting network maps foreign overlay addresses through aliases.
    - Cross-network packets enter the provider NAT, so §2 and §17 must cover the isolation.
87. **Q-SDK-2 (a) — the iOS app and the desktop `ur daemon` host the sidecar** (desktop apps use the daemon in remote mode). Network processes (the iOS tunnel, the desktop VPN service) hold only the keyless device role: routing and bridge hooks.
88. **Q-SDK-3 — content-free APNs/FCM wake pushes ship in v0** (new mail, pending approvals, evs changes). They carry only a topic version, best effort. A new server push-sender component goes in §19, with the token and payload spec in §18. Timing is visible to Apple and Google (§2 metadata list).
89. **Q-OPS-7 (a) — v0 runs at one site.**
    - RPO ≤ 5 min for the metadata tier (index, heads, logs, gkm) and ≤ 1 h for segments; RTO ≤ 4 h.
    - Off-site replication goes to B2 or R2.
    - Whether a second site comes in v1 or later is decided from operating data.
90. **Q-OPS-6 (c) — no backups of key metadata.**
    - Key slots and wraps are excluded from backups and the off-site copy, so erasure is immediate.
    - Refines decision 89: off-site replication covers segments and non-key metadata (index, heads, logs), not key slots or wraps.
    - Disaster recovery for content relies on the metadata tier's in-cluster erasure coding plus re-seeding from devices' local copies (synced repos).
    - Server-only data (unsynced agent deposits, records no device mirrors) is lost if the site is lost. Design note: record-class repos should mirror to at least one owner device, or §2 and §11 state the risk explicitly.
91. **Q-OPS-4 (b) — edges and mail are tested in main, dark only** (enabled for internal networks and design partners), with no canary stage. The SNI census runs there.
92. **Q-QUOTA-3 (a) — Team overage is post-paid** via Stripe meters, invoiced monthly. A credit line drawn last lets contracts settle at the overage rate, so providers are paid at once. Requires a benchmark and peer review of the escrow ordering on the settlement hot path.
93. **Q-ABUSE-5 (a) — legal posture.** Notify affected users unless an order seals the request. Keep a signed quarterly warrant canary. Build no prospective-collection capability. Counsel handles each order. URnetwork can produce only the published metadata.
94. **v0 storage topology (owner):** "v0 will have only one cluster and site for each metadata and storage, with 2 replicas in minio."
    - One site.
    - One MinIO cluster for metadata (the NVMe tier, decision 21) and one for storage (the 4 × 16 × 16 TB HDD hosts).
    - Each keeps 2 copies' worth of redundancy (interpreted as erasure coding with 50% parity, ~512 TB usable from ~1 PB raw, surviving the loss of half of each erasure set, e.g. 2 of 4 hosts). Interpretation pending owner confirmation.
    - No off-site copy in v0. This supersedes the off-site parts of decisions 18 and 89.
    - The RPO/RTO targets (decision 89) apply to drive and host failures only. Site loss = loss of server-held data, with recovery only from devices' local copies.
95. **Q-ABUSE-3 (a) — automated abuse actions act immediately** (host kills, spam-rate breakers), with human review of every automated action within 24 h. Business-hours staffing in v0, 24/7 on-call by v1.
96. **Q-ABUSE-2 (a)/(c) — anonymous-only networks** (guest, wallet, or seed-phrase sign-in) never publish public names or send internet mail without verifying or paying. They use storage, sockets, bridge, and private features normally.
97. **Q-ABUSE-4 (a) — screening limits "owns all entries".** Labels, aliases, and published hostnames are screened at creation against brand and phishing patterns, and probation networks have record caps.
98. **Q-ABUSE-1 (c) — inbound interception risk.**
    - Disclose it, and label each message "validated" (a DANE or MTA-STS validating sender) or "opportunistic".
    - Sidecars watch DNS and CT for their names.
    - Team strict mode: accept mail only through MX hosts in customer-signed DANE zones, or via direct MX.
99. **Q-TEST-3 (owner): "No review at the moment, just get it working."**
    - No external security review or audit is planned for now.
    - Decision 35's outbound gate becomes: sound by design analysis, working, fast enough, and interop-tested with Gmail, Outlook, and Yahoo, without an external audit unless the owner reinstates it.
    - Decision 43's MLS audit is deferred; the mlswg vectors and differential tests remain.
    - §2 and §22 record the residual risk: unaudited novel crypto (in-house MLS, the key ladder and format, ZK proofs).
100. **Q-TEST-4 (b) — iOS tunnel footprint is verified with host and Android surrogates only;** there is no physical iPhone in testing. Risk recorded: jetsam regressions in the device role may reach users.
101. **Q-TEST-7 (c) — fuzz targets with seed corpora run as ordinary Go tests;** no continuous fuzzing host or campaign for now.
102. **Q-PHASE-4 (a) — before M6, each pilot developer uses their own personal network;** team-level features wait for M6.
    - Q-PHASE-5 (external review schedule) is moot under decision 99.
103. **Q-PHASE-7 (b) — child and admin-refused tokens (held only by sidecars) get a hard 7-day expiry with no grace;** the token exchange refuses expired subject tokens. No app release is needed, so it ships with the P0 auth fix (decision 45). Fleet-wide expiry follows app adoption.
104. **Q-REPO-5 (b) — server-only engines live in child packages (`sidecar/<svc>service`) that only server imports;** client code stays in the root package. Mobile binaries stay lean by construction. The ZK prover, which is large, goes in its own nested package or module.
    - Departs from PLAN.md:13 ("all service code goes in the root"), owner-approved.
    - Engines in child packages import the root (child → parent is allowed); the root never imports them.
105. **Q-ACL-4 (b) — untagged sidecars act as app devices (today's allow-all same-network reach) until the network writes a policy.** Tagged agents, implicit-document details, and requests apply once a policy exists or when tags are used. Consistent with decisions 47 and 50.
106. **Q-ACL-5 (a) — in networks with a policy, legacy (non-enforcing) clients are reachable only through unrestricted grants;** otherwise they are source-only. The server records `acl_enforcing` at mint, and the console lists legacy clients.
107. **Q-PHASE-8 (b) — sidecar goes public at the first recURd release.** Until then, server's and sdk's sidecar code stays on their `sidecar` branches (private import), and merges to main wait for publication. The scrub of the business docs (decision 51) happens before release.
108. **Implied Q-TRUST-6 → no dedicated recURd issuer or keys initially;** recURd uses the main bringyour.com services (decision 15).

Remaining open items are peer-review deciders: Q-CORE-4, Q-TEAM-6, Q-KEYS-11, Q-DNS-5, Q-MAIL-6, Q-BRIDGE-2, Q-SDK-5, Q-OPS-2, Q-OPS-5, Q-TEST-1, Q-TEST-2, Q-TEST-6.
109. **Q-DNS-5 — ur.network is DNSSEC-signed from the self-hosted DNS edge's first deploy (main-dark),** soaked for several weeks before the mail track's inbound launch relies on DANE.
110. **Q-TEAM-6 (a) — one admin signature admits a sidecar or member;** changing the admin set or authority keys needs k-of-n admin signatures (configurable, e.g. 2-of-3) in the config repo.
111. **Q-MAIL-6 (b) — mxedge rejects at the greeting only for high-confidence botnet and exploit IP listings** (a commercial feed). Everything else passes to receiving devices, which filter content locally. Never greylist.

Left to peer review (engineering detail): Q-CORE-4, Q-KEYS-11, Q-BRIDGE-2, Q-SDK-5, Q-OPS-2, Q-OPS-5, Q-TEST-1, Q-TEST-2, Q-TEST-6.

## Follow-up interview (2026-11-04): owner questions raised by the fix rounds

112. **Q-TEAM-10 (a) — a member's own admitted device may admit that member's new device alone.** It signs a scoped admission delta into the config repo; a network setting `self_admit` can turn this off. An admin's new device that carries admin authority still needs the k-of-n signatures (owner decision 110), with the admin's existing device counting as one of the k. This subsumes §10's separate DeviceAdmit. Under Q-KEYS-13, the config group's MLS Add follows the signed admission.
113. **Q-KEYS-13 (b) — owner decision 7's "only from keys allowed to grant" binds the change, not the committer.** Any writer leaf may commit an Add or Remove that a signed grant, admission or revocation requires. Every member verifies that signed input before accepting the commit, and a commit without one is rejected. No membership change waits for an admin to be online. D-KEYS-7's admin-only committer rule is withdrawn.
114. **Q-ACL-9 (a) — sidecars that are not a member's own device (tagged, ephemeral, CI and cloud agents) read and write through per-generation X-Wing key wraps in every repo that grants them access, not through MLS leaves.**
    - This amends owner decision 60: member devices are MLS leaves; agents hold wraps. It rests on owner decision 7's wraps.
    - Agents read as soon as a grant exists, even with no member device online. CI joins and reaps cost no MLS commit, and agents do not count against the 1,000-leaf cap.
    - Any writer, wrapped ones included, may rotate by re-wrapping the new generation to the current readers. A reader key per delegation (§7.9) lets an agent read at once.
    - Wrapped writers cannot commit MLS Removes, so removing a member device still waits for a leaf. Revoking an agent = a new generation that is not wrapped to it (lazy rewrap, owner decision 64).
115. **Q-KEYS-12 confirmed — gkm's visible values.**
    - gkm sees ciphertext plus group id, epoch and sizes.
    - It also sees these sidecar ids and metadata, per §10.6's rows:
      - content type, generation, projection version, uploader and time;
      - GroupForm signers and creators;
      - KeyPackage credentials, claimers and targets;
      - Welcome recipients and external joiners;
      - wrap recipients (owner decision 114) and recovery wraps' member ids;
      - acks.
    - Membership is therefore visible to gkm as sidecar ids, as it already is to the server through the id-only projection (owner decision 72).
    - gkm never sees a proposal, credential change, ratchet tree or key.
    - Recorded as confirmed; it is no longer a residual at M2's entry.
116. **Q-OPS-1 residual — file cluster details approved as recommended.**
    - (i) "2 replicas" = erasure coding at 50% parity: EC:8 on the 16-drive HDD sets (about 512 TB usable of about 1 PB raw) and EC:4 on the 8-drive NVMe tier. Data survives two of four hosts failing; writes pause until one returns.
    - (ii) 3.84 TB NVMe drives, with a pool added before Y2.
    - (iv) Push logs older than a week are packed onto the HDDs (§11.13), refining owner decision 21.
    - (v) A cold spare chassis and drives on site, so a second host failure still meets the 4 h RTO.
    - (iii) The Y1/Y2 load inputs stay an engineering estimate in §19.6.
117. **Q-REPO-4 residual (owner): "We won't scrub it, just move forward."**
    - No scrub of the sidecar repo. This supersedes owner decision 51's "after a scrub" and owner decision 107's "the scrub of the business docs happens before release".
    - D-REPO-8 is withdrawn: no sidecar-archive rename, no filtered clone, and no `make check` path allowlist for business material.
    - The repo keeps its documents and history. Publication at the first recURd release (owner decision 107) is a visibility flip of this repo, so its business material (pitch decks, market notes, improve.md, cold5/) becomes public then, unless the owner decides otherwise before release.
    - D-REPO-9 stands: server's, sdk's, sn's and build's `sidecar` branches stay on private mirrors until that release.
118. **Q-OPS-8 (owner): "we will make sidecar repo public immediately, move forward."**
    - The sidecar repo goes public now (2026-11-04), as it is (owner decision 117). This supersedes owner decision 107's "public at the first recURd release" and owner decision 51's "publish later". Q-PHASE-8's publication timing is now immediate.
    - Implied: nothing waits for publication. server's and sdk's `sidecar` branches use their normal public remotes, and merge to `main` at each milestone's exit review like every other repo. D-REPO-9's private mirrors are withdrawn, and the branch policy's "wait for RS1" clause is removed.
    - This resolves Q-OPS-8: each migration group's SQL merges to server's `main` with its milestone at Gn-out, so the M3 pilot runs on production normally.
119. **Q-TRUST-8 (a) — product copy says "end-to-end encrypted" now, with the residual risk disclosed.**
    - The security page states that the cryptography is not yet independently audited: the in-house MLS on the draft ciphersuite 0x0010, the storage format and path tokens, and later the ZK mail proofs (owner decision 99).
    - pitch5's line promising an independent audit before the claim changes to match.
    - §2.18's residual-risk statement is the source text for the disclosure.
120. **Q-TRUST-7 (a) — keep allow-all, and disclose it.**
    - In networks without an access-control policy, sidecar sources keep today's same-network reach, LAN, loopback, link-local and overlay destinations included. Owner decisions 50 and 105 stand unchanged.
    - Product copy and §2 disclose this. pitch5's promise that agents reach only what they're granted applies once the network writes a policy.
    - I-10 is amended to that scope, with a residual-risk row.
121. **Q-TLS-8 residual (c) — the published-port list is 443 plus 8443, 8883 and 5671.**
    - 8443 is a second HTTPS service per host; 8883 is MQTT over TLS; 5671 is AMQP over TLS.
    - Each is a permanent lb port on the shared addresses, routed by SNI to tlsedge (§19 W7).
    - Mail ports, plaintext-before-TLS protocols and control-plane defaults stay excluded.
122. **Q-QUOTA-1 residual (a) — overage uses existing rates.**
    - Transfer bytes are billed at today's data-pack rate ($3 per TiB, config/all/pro.yml).
    - Storage is billed at a per-GiB-month price set from the file cluster's cost per usable TB (§19.6), reviewed yearly.
    - Prices live in pro.yml, with no hardcoded numbers.
123. **Q-DNS-7 (b) — two nameservers at the one site only; no off-site NS.**
    - Both dns edge hosts run at the site (owner decisions 69, 71 and 89).
    - Accepted risk: a site or Hurricane Electric outage takes down every ur.network name, plus ACME DNS-01, DANE and inbound mail from M7, until it is restored. §2, §12 and §19 record this.
    - Mail senders retry for 14-48 h, so a short outage defers mail rather than losing it.
124. **Q-SMTP-6 (a) — smtpedge sends from the shared lb addresses, with PTR names under bringyour.com** (owner decisions 13, 34).
    - HELO equals the PTR name, and forward-confirmed reverse DNS holds for each sending address.
    - There are no separate free, paid or burner IP pools and no per-IP warm-up. Reputation is managed per sending domain and per network (selectors, halts, rate limits).
    - Accepted risk, recorded in §14, §19 and §21: a mail blocklisting of an lb address also hits api and connect ingress on that address.
125. **Q-SMTP-1 residual (owner) — always fund a DATA circuit.**
    - The DATA-mode preamble proof is built whatever the census shows, alongside the BDAT proof, so destinations without CHUNKING stay reachable.
    - It is research and engineering on the mail team's critical path, and proving takes minutes per 100 KiB message on desktops.
    - Interpretation: DATA coverage is part of D-SMTP-16's outbound gate.
    - This supersedes D-SMTP-17's "accept the measured coverage loss".

## Follow-up interview, round 2 (2026-11-04): owner questions raised by the conformance pass

126. **Q-ACL-10 (a) — owner decision 8's admin authority does not reach owner-bound repos without the owner's consent.**
    - In a member's owner-bound repos (author vault, mailbox, other owner-bound kinds), network admins can revoke. They can add only owner decision 63's visible audit member.
    - Any other reader, including a device admitted under that member's member_id, needs the member's own signed consent:
      - the member's own admitted device or recovery key signs the admission (owner decision 112's scoped path); or
      - the member's first device joins from an invite; or
      - an admin-signed admission is countersigned by an OwnerConfirm{sidecar_id} delta from the member's device.
    - Members' devices and grantor leaves refuse Adds to owner-bound repos without that consent. A device without it is parked, with approval pending on the owner's devices.
    - The member's devices alarm on any admission under their member_id that they did not sign.
    - Keeps pitch5's "sessions open only when the developer shares them". Closes the final critic's blocker: one admin minting a device under a member to read that member's vault and mailbox.
127. **Q-TEAM-11 (b) — a recovery key counts as one signature toward k for authority statements.**
    - This covers AdminSet changes and other authority-key changes.
    - Any recovery-signed authority statement waits a 72 h window, during which any admin device may veto.
    - A personal network (k = 1) recovers alone. A team with k > 1 still needs the other signers (owner decision 110 holds).
128. **Q-KEYS-14 (a) — in the config repo's MLS group, the leaf that signed an admission or revocation may commit the MLS change it requires, even if that leaf is not a config writer.**
    - Devices admitted through a recovery key self-join by external commit.
    - A self-admitted device (owner decision 112) therefore reads the config at once, with no admin online, consistent with owner decision 113.
    - Writing config records stays admin-only; this rule covers only the MLS Add or Remove that a signed record requires.
129. **Q-TRUST-9 (c) — any admitted reader sidecar, agents included, may witness D-TRUST-10's HeadCheck.**
    - Writers in shared groups alarm at 24 h without a consistent witness. They stop at a per-network bound, `ServiceSettings.witness_bound_hours`: default 72 h, settable from 24 h to 168 h in the config repo.
    - §2.8 publishes that bound as the exposure bound for a withheld Remove.
    - Rotations, Removes and revocations never stop, since they only shrink exposure.
130. **Q-BRIDGE-5 residual confirmed — TLS only off loopback.** When the local git (http), IMAP or SMTP submission listeners bind beyond loopback (owner decision 84), they serve TLS only; git may also use ssh. Plaintext stays on 127.0.0.1 and ::1. Port forwards are unaffected. D-TRUST-8, D-EVS-15, D-MAIL-11 and I-17 state this rule.
131. **Q-PHASE-7 residual confirmed — the 7-day hard expiry applies only to sidecar-held child and admin-refused tokens.** The sdk's multi-client "window" clients, which apps hold and which never refresh, keep today's lifetime until fleet-wide expiry follows app adoption. The P0 auth fix needs no app release.
132. **Q-BRIDGE-7 (b) — a chosen overlay /16 must lie in 100.64.0.0/10 or RFC 1918 (10/8, 172.16/12, 192.168/16).** This narrows owner decision 28's "any /16". `ur bridge block` refuses other ranges. Once C6a lands, public exits refuse both ranges, so overlay traffic never leaks to the internet.
133. **Q-EVS-7 (a) — preservation holds never block user-initiated shredding.**
    - A hold pauses only the server's own TTL sweeps and GC for the records in scope.
    - Users' `--now`, the 7-day soft-delete timer (owner decision 82) and per-entry key erasure always proceed.
    - Condition: counsel confirms that deleting wrapped keys to ciphertext URnetwork cannot read is permitted. Until then, §21 records it as a counsel item.
134. **Q-ABUSE-6 (b) — business-hours review plus an emergency pager.**
    - v0's clocks run in business hours, and automated actions hold until they are reviewed (owner decision 95).
    - An on-call pager covers only registrar, registry and law-enforcement emergency notices, including EU removal orders, from M5's public names.
    - Full 24/7 on-call follows in v1.
135. **Q-MAIL-13 (b) — "validated" also covers listed operators that enforce DANE or MTA-STS.**
    - A received message is labeled "validated" when either:
      - the sender set REQUIRETLS; or
      - the SNI host has TLSA in our signed zone, and the sender is on a listed set of operators that publish DANE or MTA-STS enforcement (for example Exchange Online), identified by forward-confirmed PTR or aligned DKIM `d=`.
    - Otherwise the message is "opportunistic".
    - The operator list is versioned, so the label stays checkable against the operators' published policies.

After decisions 112-135, no owner-decider question remains open. The open items are left to peer review.

## Storage tier (2026-11-04)

136. **File cluster NVMe tier (owner): "Evaluate the initial storage tier as 4 hosts each with 2x2TB NVME and 16x16TB HDD"; then "Can we replace the NVME tier with redis?"**
    - Asked about Redis, the owner was told it cannot safely be the system of record: async replication means a failover can lose acknowledged head and MLS-epoch commits, and today's cluster has no replicas. The owner chose "2 TB NVMe + Redis soft state". MinIO stays the system of record, and owner decision 2's "no Postgres or Redis for file storage" holds for durable state.
    - **Hardware.** Each of the 4 hosts has 2 × 2 TB NVMe plus 16 × 16 TB HDD.
      - The NVMe metadata cluster is one 8-drive set, 16 TB raw, about 8 TB usable at EC:4 (owner decision 116's parity). This supersedes owner decision 116 (ii)'s 3.84 TB drives.
      - The HDD segment cluster is unchanged: 1,024 TB raw, about 512 TB usable at EC:8.
    - **Drives.**
      - Enterprise NVMe with power-loss protection, at least 1 DWPD.
      - Dedicated to MinIO, with separate boot media.
      - Free NVMe bays on each host for a second pool.
    - **Packing (refines owner decision 116 (iv)'s one week).**
      - Each day, taskworker packs every repo's log pages and push objects older than 24 h onto the HDD cluster.
      - A repo whose aged material is under 256 KiB packs once that material is 7 days old.
      - This replaces the per-repo 64 MiB trigger, which kept small repos' history on NVMe indefinitely.
    - **Filesystem.** XFS on the NVMe drives is created with a raised inode ceiling (`mkfs.xfs -i maxpct=25`, adjustable online). Alarms fire on inode and space use.
      - At about 44 KiB of raw NVMe per small object (8 shards of a 4 KiB block plus inodes), the 5% default caps a 2 TB drive at about 195M inodes. That is below year one's estimated 150-850M.
    - **Second NVMe pool.** It is added when the first pool reaches 50% of raw space, 40% of inodes, or a sustained 0.5 DWPD. That is expected within year one at §19.6's estimate. Index entries are rewritten in place and stay in the first pool, so its wear is watched, or a rebalance moves them.
    - **Redis soft state.**
      - Subscription leases (formerly `subs/` objects) and other rebuildable soft state move to Redis, under the platform's hash-tag rules and excluded from rdb bundles (D-OPS-7, D-OPS-16). Clients re-create them on loss.
      - A verified Redis read cache serves heads and projections. Readers verify signatures and versions, and fall back to the cluster when the cache is older than a version they know. Commits always go through the cluster's If-Match.
    - **Year-one fit at §19.6's estimate (200 pushes/s).**
      - Under the old 7-day window, the metadata cluster needs about 11-22 TB raw (70-135% of 16 TB).
      - Under the 24 h window, about 3-11 TB raw (20-70%).
    - **Engineering notes from the evaluation (not owner decisions):**
      - 2 × 25 GbE per host, since the HDD tier streams about 4 GB/s per host;
      - enough RAM per host that the HDD sets' xl.meta working set stays in the page cache by year two;
      - a 16 TB HDD heals in about 1.5-4 days;
      - an NVMe heal is bound by object count, taking hours to about a day.
137. **NVMe drive model (owner): "The NVME drives we will use are `MZ-1LW1T90 - Samsung PM963 1.92TB PCI Express NVMe MLC M.2 22110 SSD`" and "We have to be able to use an NVME of that spec. We can't buy newer drives."**
    - **The drive.** The metadata cluster is 8 × Samsung PM963 1.92 TB M.2 22110, 2 per host: 15.4 TB raw, about 7.7 TB usable at EC:4. This refines owner decision 136's "2 × 2 TB". Expansion and spares use the same model.
    - **Published specs** (reseller listings; confirm against Samsung's datasheet and each drive's label):
      - PCIe 3.0 x4 NVMe;
      - about 2,000 MB/s read and 1,200-1,800 MB/s write;
      - about 430k random-read and 40k random-write IOPS;
      - 0.8 DWPD for 5 years, about 2.8 PB written;
      - power-loss protection.
    - **Fit at §19.6's estimates.**
      - Year one fits at 20-75% raw with owner decision 136's 24 h packing.
      - Write IOPS run about 3-5k per drive in year one against the 40k steady-state limit. Year two's 30-45k saturates the set, so more drives are needed by then.
      - Wear is about 1.6 TB/day per drive (about 0.85 DWPD) at year-one load: about 4.8 years for a new drive, less for a used one.
    - **Conditions.**
      1. Before deployment, check each drive's NVMe SMART log: percentage used, media errors, available spare, data units written. Use the 8 healthiest in the set and keep 2-4 as the cold spare (owner decision 116). Retire drives with media errors or high wear.
      2. Each host has two M.2 22110 slots, or x4 adapters, inside its PCIe lane budget, with airflow so the drives do not throttle.
      3. The second pool is 2 more PM963s per host at owner decision 136's triggers. Year two needs about 4-8× year one's NVMe capacity and write IOPS, so the stock is planned.
      4. §22.8's M2 benchmark runs on these drives. It reports latency, write IOPS, wear per day, bytes and inodes per object, and the fill date, and it compares 4 KiB with 1 KiB XFS blocks (the drives default to 512 B sectors). 1 KiB blocks roughly halve a small object's raw cost.
    - **Design consequences.** The storage format must not depend on newer NVMe features or capacities. Small-object counts on the metadata cluster are a first-class budget, so prefer fewer objects: for example, one upload marker per push rather than per segment.
138. **Initial NVMe drives (owner): "We can actually use these for the initial NVME: MZ-1L21T90 Samsung PM9A3 1.92TB Triple-Level Cell PCI Express NVMe 4.0 x4 M.2 22110 Solid State Drive".** This supersedes owner decision 137's drive model for the initial metadata cluster.
    - **The drive.** The metadata set is 8 × Samsung PM9A3 1.92 TB M.2 22110 (MZ1L21T9HCLS), 2 per host: 15.4 TB raw, about 7.7 TB usable at EC:4.
    - **Published specs** (Thomas-Krenn wiki and reseller listings; confirm on Samsung's datasheet):
      - PCIe 4.0 x4 NVMe;
      - about 5,600 MB/s read and 2,000 MB/s write;
      - about 800k random-read and 85k random-write IOPS (4K);
      - 1 DWPD (about 3.5 PB written over 5 years);
      - enhanced power-loss data protection.
    - **Fit at §19.6's estimates.**
      - Capacity is as in owner decision 137: year one fits at 20-75% raw with owner decision 136's 24 h packing.
      - Write IOPS run about 3-5k per drive in year one, ≤6% of 85k. Year two's 30-45k per drive is about 35-55%, so year two's writes fit on 8 drives, though capacity still needs about 4-8× more NVMe.
      - Wear is about 1.6 TB/day per drive (about 0.85 DWPD) at year-one load: about 6 years for new drives. Year-two rates on 8 drives would wear them out in months, so expansion spreads writes (more drives or pools, plus a rebalance).
    - **Conditions.**
      - Every erasure set is homogeneous: spares are PM9A3 1.92 TB (2-4 drives; owner decision 116's cold spare).
      - The PM963s (owner decision 137) may form a separate, homogeneous later pool, never members of the PM9A3 set.
      - Each drive gets a SMART check before deployment.
      - Each host needs two M.2 22110 slots or x4 adapters (Gen4 preferred; Gen3 slots suffice for this small-object load), and airflow.
      - The other conditions of owner decisions 136 and 137 stand: the inode ceiling, the triggers, and the M2 benchmark on these drives with 4 KiB against 1 KiB XFS blocks.
139. **Initial deployment (owner): "The initial deployment will be only PM9A3".**
    - The initial metadata cluster and its spares are Samsung PM9A3 1.92 TB only: 8 drives in the set, 2 per host, plus 2-4 PM9A3 cold spares.
    - The PM963 (owner decision 137) is not part of the initial deployment.
    - Any later pool is homogeneous, and its drive model is chosen when that pool's trigger fires (owner decision 136).
140. **Owner requirement: "We have to make that iop profile work."** The storage design must fit the initial 8 × Samsung PM9A3 1.92 TB metadata set (owner decisions 136-139) as a hard budget: about 85k random-write and 800k random-read IOPS per drive, and 1 DWPD (about 22 MB/s per drive sustained).
    - **The binding constraint is endurance, not IOPS.** MinIO writes every metadata object to all 8 drives, so every drive sees every PUT and DELETE.
    - **Today's numbers.**
      - At about 12 KiB of drive writes per small operation, §19.6's year-one estimate (200 pushes/s, about 1,330 PUT/s and 240 DELETE/s) is about 0.85 DWPD. That is at the line.
      - The review brief's head object (up to 160 KiB, rewritten on every push) would push year one over the rating. Year two's 2,000 pushes/s would be about 8-11 DWPD.
      - Write IOPS are only about 6% of the rating in year one and about 60% in year two.
    - **Design rules.**
      - Target at most 0.8 DWPD and at most 50% of rated IOPS at the design load.
      - Prefer reads over writes on the metadata cluster.
      - Cut the drive bytes written per push, using (corrected 2026-11-04: the record first gave "about 10-15 KiB", a design-team estimate that is unreachable under owner decision 2's head overwrite of ~14 KiB alone; T6's model meets the binding budget at ~27-43 KiB a push, gated at ≤ 43 KiB by D-TEST-11; Q-EVS-9 closed):
        - small heads;
        - group-committed push payloads;
        - lazy index folding;
        - batch deletes;
        - soft state in Redis;
        - XFS and MinIO tuning.
      - Enforce a global NVMe write budget, measured from drive telemetry, through §11.13's fair-share shedder, so load can never wear the drives past the budget.
      - §22.8's M2 benchmark measures bytes written per push per drive and gates format 1 on that budget.

## Peer-review owner questions (2026-11-04)

141. **Q-EVS-8 (a) — git-mode refs commit only on their tip; file-mode refs keep disjoint landing.**
    - A git-mode push commits only when it is based on the ref's current tip (a tip CAS). A loser gets a stock non-fast-forward error and pulls or merges.
    - File-mode refs (vaults, mailboxes, records, the config) keep owner decision 2's path-level disjoint landing.
    - This narrows owner decision 2 to file-mode refs, so that git compatibility (owner decision 24) and exact git oids hold. D-EVS-22 is decided.
    - Cost: a client retry when two merges collide, about 2% in the twenty-agent test.
142. **Q-MCP-6 (c) — in a tainted run (I-9), harness evidence does not approve an outward action by default.**
    - Approval needs second-device or presence-key evidence. macOS and Windows offer a platform presence key cheaply, through T3.6's daemon presence prompt and `ur login`'s offer.
    - Harness evidence counts in a tainted run only where the matching `requests` rule names it explicitly, never through `evidenceDefault`.
    - Untainted runs keep owner decision 75's harness fallback unchanged.
    - I-9 and D-MCP-9 state this. It freezes with record.proto at M3's entry review.
143. **Q-OPS-9 (a) — a two-person out-of-hours infrastructure rota on one pager service from M3.** It has 30-minute acknowledgment and escalation.
    - Page-class alerts only:
      - a file-cluster set at risk or refusing writes;
      - the Postgres primary down;
      - SLO budget burn;
      - from M5, both nameservers down, a broken 443 split, or a failing canary signature.
    - Owner decision 134's registrar, registry and law-enforcement notices join the same pager at M5.
    - The 4 h RTO (owner decisions 89 and 116) and §19.8's SLOs therefore hold at all hours. §22.8's host drill (FS-50) measures them.
144. **Q-KEYS-15 (b) — member devices past the first 1,000 in a network read the config group by per-generation wraps, as agents do (owner decision 114), from the start.**
    - They stay MLS leaves of their data repos, each still capped at 1,000 leaves.
    - This amends owner decision 114's "member devices are MLS leaves" for the config group only.
    - Cost: about 1.3 KB of wrap per overflow device per config rotation.
    - §20.4's Team limits keep 5,000 admissions, and no member-device cap applies at 1,000.
    - The design must state:
      - which devices are leaves (the first 1,000 by admission order, or a deterministic rule) and how a device moves between leaf and wrap;
      - that wrapped member devices cannot commit config-group Removes;
      - how owner decision 128's signing-leaf commit applies when the admitting device is wrapped.
145. **Q-OPS-10 (b) — the metadata tier grows only by adding metadata clusters, never MinIO pools.**
    - **Why not pools.** In the pinned MinIO build, a multi-pool PUT picks its pool by free space even when the key exists in another pool, and checks If-Match / If-None-Match only inside the chosen pool. Head commits and gkm's one-commit-per-epoch could then break.
    - **How placement works.** Each new repo and its gkm group are placed on one metadata cluster at creation, by a create-only `place/<repo_id>` object on the first cluster. All of a repo's metadata objects stay on its cluster.
    - **Moving repos.** Existing repos do not spread to a new cluster without a move tool. A move tool is a later item, and must keep the commit point single.
    - **Supersedes:** owner decision 136's "second NVMe pool" and its pool wording. The triggers stay: 50% raw, 40% inodes, 0.5 DWPD, or a projection within the hardware lead time.
    - **Each new cluster:** one homogeneous 8-drive set at EC:4 (owner decisions 116, 139).
    - **Capacity per set (T6; record corrected 2026-11-04 to match the sections):**
      - The first set alone sustains about 490-650 pushes/s.
      - Once load spans several clusters, each evs process batches per cluster, so a set sustains about 400-450 pushes/s (§11.13, §19.9).
      - Year two (2,000 pushes/s) needs about five to six sets. The earlier "4-5 sets" was the design team's first estimate.
    - **Year one (T6's redesign):** about 0.31-0.40 DWPD on the first set, ≤ 3% of rated write IOPS.

## Second-round open items (2026-11-05)

146. **SL-N1 — the erasure closure allowance is per eraser, with a floor.**
    - Each erasing sidecar has its own daily closure allowance, in pro.yml.
    - §21's abuse controls may tighten it but never below a fixed floor, so erasure always stays possible at the storage limit, and one admin cannot use up other members' erasures.
    - Fixed alongside:
      - FS-47 expects a CLOSURE push past the erasure rate to queue as P1, keeping 429 for closure uploads past the rate and for bytes past the eraser's allowance;
      - §11.12, §11.13 and §11.19 state the allowance and its 429, citing §20.7;
      - §15.7 and §11.13 state how long erasure at the limit can wait under the floor.
147. **WR-N1 — phones keep their newest 64 KiB of authorization-log entries and serve proofs (§7.9 stands).**
    - FS-17's phone-holder case is fixed to match: phone R serves the proof, X sends `proven`, and W stops at once.
    - The NOT_FOUND, `unverified` and witness_bound_hours outcome applies only when a gap is wider than the holder's kept entries.
    - Aligned to this: §6.16's FS-17 summary, D-PROTO-17's Why, §6.17's risk row, and §6.4's auth row, which also states what a holder answers when its kept entries do not reach back far enough.
148. **ST-N1 — removal folds write tombstones that keep the path's version.**
    - A removal fold never blind-deletes an index entry. It writes a small removed-entry marker with If-Match on the entry it read, and re-reads on 412. It does so only when the entry's newest folded version is older than the removal.
    - The marker keeps the path's version, so a re-created path continues from it and versions never restart. A stale push based on a pre-delete version fails 5g.
    - Markers are garbage-collected once the fold horizon passes them. This needs only the If-Match PUT the store already gives; no conditional DELETE.
    - Cost: one short-lived metadata object per recent removal, counted in §11.13's object budget.
    - FS-58 adds the late-or-duplicate-removal schedule, and EvsCommit.tla's folder runs a stale or late removal. FI-15 is worded against version restarts.
149. **AU-N2 — a scoped admission by a binding the compromise cascade restored activates through the 72 h recovery window, with admin veto.**
    - **Activation.** The admission is carried as a recovery AuthorityProposal, or ApiTick names its statement id. It activates 72 h after it is filed, with no counted cosign, unless an AdminSet device signs a RecoveryVeto. It shows as `recovery_window` on admins' devices (§5.6, §18), the same rule as owner decision 127's recovery-key authority statements.
    - **Fixed alongside:**
      - §5.9 re-seals keychain.wrap whenever §7.9's cascade changes the member's binding, dropping the HPKE copy while no binding is current.
      - §7.9 and §5.9 apply the compromise-rebind backup rule to each device that sealed to a voided binding: revoke and re-enroll devices whose backups may hold that sealing.
      - §22.7 defines the outcome of the restored-code admission case.

## Terminology (2026-11-05)

150. **The indexer (owner): "The always-on device on the network I want to call the 'indexer'. I think this is a good term generally for the device that is the point device for the services."**
    - "Indexer" names a network's always-on point device for its background services:
      - receiving mail (owner decision 12's always-on receivers);
      - mirroring record-class repos;
      - search-index roll-ups and verification;
      - keeping the "all" search partition synced;
      - any future embedding work;
      - other services that need an always-on device.
    - The design uses "indexer" where it meant that role, and keeps "always-on" only as a device property.
    - A network may designate more than one indexer. Team receivers (owner decision 58) are indexers chosen for mail.

## v1 additions: the search index and versionless objects (2026-11-05)

The owner's answers in peer/EXPLORATIONS.md, as recorded there. They are numbered here in the order peer/v1/F-tests-phase.md §2.1 assumed, and section text cites them by these numbers.

151. **A per-repo encrypted search index, trigram-based.**
    - Owner: "Is it possible that every commit to the EVS also updates an encrypted search index in that repo? Can we build an efficient enough search index that a client who wants to search can download the entire latest index locally and use it? ... Each repo should have the option to turn on or off its search index, but when on each committer should also update the index with the commit changes."
    - Owner: "I think the trigram route is the most useful. A good use case is finding an email or a note."
    - Substance:
      - Each repo may keep an encrypted index that its committers update with their commits.
      - Clients download it whole and search locally.
      - Postings are document-level trigrams, with email and notes as the primary use case.
152. **Latest is two time buckets, plus all.**
    - Owner: "Time partitions make a ton of sense. The latest partition should include only files changed in that partition. We should maintain a latest time partition and an 'all' partition. Searches by default would use the latest time partition, and they can in parallel download and use the all partition as async background work or 'search more'."
    - Owner: "Well I think latest should be a bucket model based on time, so we need two latest indexes, and searches need to merge both."
    - Owner, on bucket size: each bucket spans the per-repo setting, 30 days by default, adjustable per repo (e.g. 7-365).
    - Substance:
      - Searches merge both buckets at once.
      - They merge all in the background or on "search more".
      - The newest document version wins.
153. **Commits update the current bucket; the roll-up moves an expired bucket into all.**
    - Owner: "When an old one expires, the entire block can be copied into all and the block dropped. That is what the rollup will do."
    - Substance:
      - Each commit adds its delta to the current bucket only.
      - When a bucket expires, the roll-up merges its whole block into all once and drops the bucket.
      - This supersedes the earlier "periodic daily roll-up ages files out".
154. **Fetching all, by device and network.**
    - Desktops, the daemon and indexers (owner decision 150) keep all synced in the background.
    - Phones and browser tabs fetch it on "search more", or in the background on Wi-Fi while charging.
    - Each device can override.
155. **Phone "search more" shows possible matches.**
    - On a phone, all-partition hits show as ranked "possible matches", using the index's display fields (subject, from, date), and each is confirmed when opened.
    - No bodies are fetched to verify them, and no word index is added.
    - Desktops and mirrors verify hits against local text.
156. **The index is on everywhere by default.**
    - Every repo indexes by default, and any repo admin can turn it off.
    - The per-commit cost stays bounded for code and large-file repos. For example, versionless files above the network rule are indexed only if they are text, and binary content is skipped by type sniffing.
157. **Roll-up runner: the indexer, else any writer.**
    - The network's indexer (owner decision 150) runs roll-ups for repos it writes. Otherwise the first writer that commits after the bucket expires runs it in the background.
    - A per-ref lock keeps it to one roller at a time.
    - Both buckets are searched until the roll-up lands.
158. **Versioning is set per object, and history follows it per version, as Perforce does (VQ-1 (a)).**
    - Owner: "Another addition I want to explore is a 'large object' setting per object that stores objects without a versioned history. The large object setting would just store the entire head version of the object and not use any patching or versioning of that object."
    - Owner: "Maybe we should call 'large object' as 'versionless' instead. Versioning can be turned on or off per object."
    - Substance:
      - Versions written while versioning was on stay forever.
      - From the switch on, only the head is kept.
      - Turning versioning back on restarts history at that version.
      - v1 may add an admin "drop history" action per path.
159. **The search index is always versionless (VQ-2 (a)).**
    - Owner: "The search index would be a candidate for 'large object' turned on."
    - The index never keeps history, so erasing index postings is real.
160. **Versionless files are allowed in every repo kind but config and mailcfg (VQ-3 (a)).**
    - Vaults, mailboxes, team records, record repos and general repos may hold versionless files.
    - In v1, a repo admin can lock a repo to stay fully versioned.
161. **Overwritten versionless content is purged as soon as it is safe (VQ-4, revised).**
    - Owner: "I think overwritten versionless files should purge the history as soon as possible. Keeping around lingering garbage will waaste resources."
    - Substance:
      - Superseded versionless content is purged right after the superseding head commit is certain, with only a short in-flight-reader allowance of about a minute.
      - The committing evs process issues the deletes, and a periodic sweep catches failures.
      - Small content inlined in a group-commit batch drops at that batch's evacuation.
      - There is no recovery window for overwritten versionless content. This supersedes the "about a day" answer.
162. **Git large files go through git-lfs in v1 (VQ-5 (a)).**
    - Git refs stay fully versioned.
    - In v1, git-lfs pointers are backed by a versionless store reached through a standalone transfer agent.
    - The store collects objects that no ref tip references, and that no commit from the last 30 days references (the window is adjustable per repo).
163. **Everything ships in v1, as a new storage format version (VQ-6 (c)).**
    - Versionless storage, the search index and its tools ship in v1 as a new format version, and repos created before it migrate.
    - Format 1 reserves the protobuf field numbers and locator kind at M2, so the new format is an additive extension that format-1 readers refuse cleanly.
164. **The default versioning rule is per network (VQ-7).**
    - Owner: "Per network default, default rule for all networks is off above 64mib. Admin can edit that rule."
    - The platform default, applied to every network, is versioning off for files above 64 MiB.
    - Network admins can edit the rule in the config repo.
    - It applies where versionless is allowed (owner decision 160). Git refs stay versioned (owner decision 162).
165. **Replaced content is counted until it is purged; there is never keep-last-n (VQ-8, VQ-9 (c)).**
    - Under immediate purge, replaced content counts toward storage only until it is purged.
    - Versionless always means head-only. Anyone who wants history turns versioning on, and no format field is reserved for keep-last-n.
166. **Search in the `ur` CLI and the MCP server.**
    - Owner: "I want to add some search capabilities to the ur cli mcp to make it easy to search repos, for example to find agents working on certain tasks."
    - This covers `ur search` and the MCP search tools, including finding agents working on certain tasks, over the repos the caller can read.

## v1 additions: owner questions (2026-11-05)

167. **Q-EVS-20: a versioning rule applies when a path is created (option (a)).**
    - A writer sets a new path's setting from the rules in force at that moment: the repo's own (its access log's `RepoVersioning`), else the network's current `VersioningRules`, else the platform rule.
    - An admin's edit reaches every repo without its own rules, for paths created after the edit.
    - Existing paths keep their setting until a writer changes it, as Perforce's typemap does.
    - No new format field is needed. `ur status` names the versioned paths whose history dominates a repo's storage.
168. **Q-EVS-22: a repo locked fully versioned keeps its search index, through a distinct value (option (b)).**
    - Index files carry `versioning` = 2, "versionless, the search index's own". The lock does not refuse that value.
    - Readers accept 2 only under an index root (`.ur-index/` on a file-mode ref, or the repo's `ur/index` ref), and alarm anywhere else.
    - Format 1 reserves the value at M2.
    - Why: the lock exists to keep content history, and the index is derived from that content and can be rebuilt from it.
169. **Q-PHASE-9: format 2 is its own milestone, M10, with about three more engineers (option (b)).**
    - M10 runs on track A from M4's exit, alongside M6. It carries versionless objects, the search index and the CLI/MCP search tools.
    - It has about three more engineers, and hiring starts by M3's entry.
    - RS2 does not wait for it.
    - M10's team-record, mail and phone cases run at the later of M10's exit and M6's, M7's or M8's.
170. **Q-MCP-7: in team networks, runs announce themselves by default, and members opt out (option (c)).**
    - In a team network, the daemon files an announcement at each run's start, carrying the run's title, project and branch. It renews the announcement hourly while the run moves, and hands it off at the run's end.
    - A member can opt out per member and per project. The harness config's `claims` setting defaults to `auto` in team networks; the other values are `prompt` and `off`.
    - In personal networks the setting defaults to `off`.
    - This narrows owner decision 126's "sessions open only when the developer shares them" in team networks to session contents. A run's who, what and where reach teammates by default. Its prompts, tool log and diffs stay in the owner-bound vault.
171. **One team directory repo indexes all announce metadata; it is where members request access to repos and workers.**
    - Owner (2026-11-05): "I would like one team repo with an index of all the announce meta data in it. That repo can be used to request access to other repos or workers. The announce meta data should contain who, what, and where."
    - Each team network has one directory repo.
    - Its search index covers every announcement: runs (owner decision 170), and the repos and workers members can request access to.
    - Each announcement carries who, what and where.
    - Members and their agents find repos and workers there and request access to them through it, under §8's requested grants and owner decision 126's consent.
    - Design: peer/v1/G-directory.md.
172. **Q-EVS-21: git-mode refs and record streams update `ur/index` at most once a minute per writer on 1 KiB blocks, else once every 5 minutes (the recommendation).**
    - If §22.8's M2 benchmark adopts 1 KiB XFS blocks (D-TEST-11 as amended): at most once a minute per writer, about 34-37 KiB a push at 2× year one.
    - Otherwise: at most once every 5 minutes, about 42-45 KiB a push on 4 KiB blocks.
    - Either way each committer indexes its own commits, and the committer's own device searches its journal at once.
173. **Q-EVS-19: v1 ships a limited admin "drop history" action (option (b)).**
    - A repo admin signs `DropHistory{path}` on a file-mode ref. It is refused in config and mailcfg repos.
    - evs deletes the kind-1 segments that only that path's earlier versions name. This takes a scan of every ref's versions in the repo, since renames and reuse copies share records.
    - Inline records in packs wait for compaction.
    - The signed version statements and their hashes stay, so history still verifies, but the dropped content is gone.
    - ~~A preservation hold (owner decision 133) blocks the action for paths in its scope.~~ *Corrected 2026-11-05: this line was the design team's addition when recording the answer, not the owner's words. Owner decision 184 sets how holds apply.*
    - Format 2 carries it (M10).
174. **Q-PHASE-10: format 2's drive-write gate is computed, then confirmed on production after the freeze (option (b)).**
    - The gate is projected from M2's measured price table (§22.8) and the index's T3 operation counts, with the index on in every eligible repo.
    - It is confirmed on production after format 2's freeze, while format 2 is dark to customers: the write budget's measured-over-priced ratio must stay within 10%.
    - No staging drives are bought early.
    - The accepted risk is that a miss found after the freeze costs more metadata clusters sooner (owner decision 145), or a later format change.
175. **Q-SDK-6: in v1, phones ask an indexer to search, on by default (option (c)).**
    - Whenever one of its network's indexers that reads the repo is online, a phone's "search more" sends the query end to end over the sidecar subprotocol (Required mode) and gets verified hits back, instead of downloading all.
    - For an owner-bound repo, the indexer must be one of that owner's consented devices (owner decision 126).
    - Replies are padded to 16 KiB steps.
    - With no indexer online, the phone falls back to owner decision 155's download-and-possible-matches model.
    - Connect relays see the request, its padded reply and their timing. evs sees nothing.
    - This amends owner decision 155 for phones that can reach an indexer. It is part of format 2's milestone (M10).
176. **Q-PROTO-4: connect rounds up the byte reports of phone-to-indexer search contracts (option (b), the recommendation).**
    - Connect keeps each contract's byte count: close reports for 35-91 days, contract rows for 300 days. A phone-to-indexer search contract (owner decision 175) lasts at most an hour, so its count would show roughly how many search pages the phone ran in that hour.
    - Connect therefore rounds those contracts' reported bytes up to 128 KiB, which hides up to five pages an hour.
    - This is a small connect change. It costs at most about 2.5 MiB a day per phone, against the free tier's 30 GiB daily grant. *Record corrected 2026-11-05: rounding both directions of each contract costs about 5 MiB a day per phone, as the sections state; the 2.5 MiB was the design team's estimate in the question.*
    - §2.8's connect-5 row states what remains visible.
    - Design: peer/v1/I-remote-search.md.
177. **No indexer by default; a phone downloads and searches its own index (owner, 2026-11-05).**
    - Owner: "By default there will be no indexer, and the phone has to download and use its own index."
    - A network starts with no `IndexerSet`. An indexer exists only once an Owner, an Admin or a member designates one (§7.9, D-TEAM-27).
    - With none designated, every service uses its fallback:
      - mail reaches whichever receivers are running, else waits on sender retries;
      - the first writer committing after a bucket expires rolls it up (owner decision 157);
      - each device fetches all under its own policy (owner decision 154).
    - By default a phone's "search more" downloads all and searches its own index, with possible matches (owner decision 155).
    - This amends owner decision 175, whose "on by default" applies only where an indexer is designated. Whether phones then use it is decided by owner decision 178.
178. **Phones use an indexer once one is designated (option (a), the recommendation).**
    - In a network that designates an indexer serving a repo, a phone's "search more" goes to it end to end, under owner decision 175's rules and peer/v1/I-remote-search.md, and gets verified hits.
    - A default network has none (owner decision 177), so its phones always download and search their own index.
    - Owner decision 176's byte rounding applies to those phone-to-indexer contracts.
179. **Q-MCP-8: in v1, access to a worker means reaching the services it announces (option (a)).**
    - An approved request through the directory becomes a grant to dial the ports, sockets and published names the worker announces. It works under the access policy, with an approver, an expiry and receipts.
    - Delegating tasks to the worker's agent, and sharing its run sessions, are later items, each with a design of its own.
    - Design: peer/v1/G-directory.md.
180. **Q-ACL-11: the device's owner approves reach to another member's device (option (a)).**
    - A request through the directory to reach another member's device or worker is approved by that device's owner. A tagged sidecar's sponsor approves for it.
    - This goes through a new approver atom, `autogroup:dst-owner`, in §8's `requests` rules.
    - It amends owner decision 74's approvers for this case: the affected member now consents directly, where an admin used to stand in.
181. **Q-MCP-9: every repo is announced by default; owners can create unannounced repos and revoke an announcement (owner's own answer).**
    - Owner: "Every repo by default, but let owners create repos that are private/non announced, and let the owner revoke the announce."
    - Each repo a team creates is announced in the directory by default, with its who, what and where. These are the general and record repos the question's option named.
    - At creation, the owner (the repo admin, or for an owner-bound repo its owner) can mark a repo private, so it is never announced.
    - The owner can revoke the announcement at any time. Revoking removes the card, and erases any record-entry copies so the name stops being readable.
    - A run in a repo that is not announced shows only the repo id and "private" (G-directory.md's rule), so others can still request access without learning the name.
    - Read as: members' own vaults, mailboxes and secret repos, the team record, and system repos (config, mailcfg, the directory itself) are not announced by default; group inboxes are announced with requests closed. **Confirmed by the owner, 2026-11-05.**
182. **Q-KEYS-16: the directory is its own MLS group under the config group's leaves rule (option (a)).**
    - The team directory is its own MLS group.
    - As with the config group (owner decision 144), member devices beyond the first 1,000 read it through per-generation wraps. This extends decision 144 to one more group.
    - The cost is about 1.3 KB per overflow device per key rotation.
183. **Q-EVS-23: a drop waits out a 7-day window in which it can be cancelled (option (a)).**
    - After a DropHistory push commits, readers see `drop pending` for 7 days. Any repo admin can cancel during that time.
    - A `now` flag skips the wait, as RepoDelete's does. A repo lock voids a pending drop.
    - Deletion starts after the window, and after the 25-minute safety fence.
    - Design: peer/v1/H-drop-history.md.
184. **Q-ABUSE-7: a preservation hold defers a drop's deletions silently (option (a)).**
    - A drop whose targets a preservation hold covers (owner decision 133) still commits. It reads, lists and bills as finished, and the dropped versions are not served to anyone.
    - Its deletions wait until the hold lifts. Nothing tells the network that a hold exists, as owner decision 93 requires for sealed orders.
    - Design: peer/v1/H-drop-history.md.

## SDK fixes: owner question (2026-11-05)

185. **Presence countersignature: verify it everywhere (option (a), the recommendation).**
    - Question: the presence check on a device revocation ran only on the revoking device. Other devices and api did not verify it, so a thief holding an unlocked device running modified software could skip it and compromise-revoke the member's other devices. In a personal network, that device could then also veto the member's recovery windows.
    - Answer: a `compromise` SidecarRevoke, and a KeyRevoke of a presence key, carry that presence key's countersignature whenever the signing device registered a live presence key (a KeyRegister{purpose: presence} it signed). api and every member device refuse one without it. §6.9's `Signed` already has a `webauthn` field for it.
    - A device that registered no presence key keeps the confirmation path (D-CORE-13).
    - This adds a verification rule to auth.proto before its M2 freeze.
    - Raised by the fix-2 checker (review-fix2/REPORT.md, BU4a); amends D-CORE-20 and D-TEAM-26.

## Final meta review: owner questions (2026-11-05 and 2026-11-06)

The owner had a final peer review done (DESIGN-REVIEW-META.md, of the 41ba6670 build) and asked for its feedback to be incorporated.

186. **F12: P0 work stays unlimited, and the wear bound exempts it (option (b); the design team recommended (a)).**
    - Question: the write governor promised a hard physical-write bound on the PM9A3 metadata set (0.8 DWPD), yet never queues P0 work: revocation rotations, shreds, slot rewrites and Removes. The review showed a legal workload of about 3 TB a day per drive, twice the budget, with every tenant under its own rate limits (100 large Teams each revoking a device every 5 minutes).
    - Answer: P0 work always runs at once. FI-14's wear bound exempts P0 writes, so a P0 storm can exceed 0.8 DWPD, up to and past the drives' 1 DWPD rating. This is disclosed, with P0 dashboards and alarms.
    - Rejected: (a) a reserved budget for the revocation commit with the bulk fan-out paced, which would have kept the bound unconditional.
    - Amends owner decision 140's hard budget for P0 writes only. The governor still bounds P1 and P2.

187. **Decision 185's countersignature extends to every revocation of another device, Suspend and RecoveryVeto (option (a), the recommendation).**
    - Question: under decision 185 alone, a thief holding an unlocked device that registered a presence key could still revoke the member's other devices as `lost` or `removed`, Suspend them, or veto the member's recovery windows. In a personal network, that locks the member out while the thief keeps the stolen device.
    - Answer: these also carry the presence countersignature whenever the signing device registered a live presence key, and api and every member device verify it:
      - a SidecarRevoke of another device, for any reason;
      - a Suspend of another device;
      - a RecoveryVeto.
    - Legitimate uses cost one presence prompt per act. A device that registered no presence key keeps the confirmation path.

188. **F18: decision 176's five-page promise holds, through 55-minute windows with a 256 KiB floor (option (a), the recommendation).**
    - Question: decision 176 promised that rounding the phone-indexer search pair's connect byte reports up to 128 KiB hides up to five pages an hour. The review showed one page can carry a contract past a 128 KiB multiple. Even with no other traffic, connect reports at every idle sequence exit and opens new contracts after idle exits, and the server stores each report's and contract's time.
    - Answer: C19 accounts a marked requester-indexer pair in 55-minute windows. It withholds every report of a window's contracts, checkpoint or close, to the window's end. Each direction then reports a fixed F = 256 KiB, or F plus 128 KiB steps on overflow.
      - F covers five one-step exchanges plus every scheduled message on the pair at its maximum: the keepalives, Hello and HeadCheck exchanges, and one HeadCheckProof each way, the review's 120 KiB case included.
      - The requester Pings the indexer once a minute while the app is in the foreground, so contracts open at foregrounds and window ends, never at searches.
    - Cost: 512 KiB a window, about 10 MiB a phone-day (decision 176's figure was about 5), at most 13.5 MiB. C19 grows to about 2 engineer-weeks, plus about 1.5 for the keepalive and tests. On LTE, one radio wake a minute while foregrounded.
    - Rejected: (b) the same windows at a 128 KiB floor, which a revoker's retries, any HeadCheckProof or the review's 120 KiB case overflow; (c) narrowing the claim to per-contract 128 KiB quantization.
    - Amends owner decision 176's mechanism; its promise stands. Design: peer/meta/remote-search.md, orders A-01 to A-51.

189. **The presence countersignature also covers admissions, consents, AdminSet changes, member removals and recovery bindings (option (a), the recommendation).**
    - Question: under decisions 185 and 187, a thief holding an unlocked, presence-protected device could still get around the countersignature in two ways.
      - It signs a SidecarAdmit of a fresh device the thief controls. That device registered no presence key, so it revokes, suspends and vetoes on the confirmation path, and no `admission_alarm` fires because one of the member's own devices admitted it.
      - It signs a RecoveryRebind of the member. That retires the member's recovery code and, by §7.9's `voiding` rule, voids the pending recovery, which locks out a member whose only other device is gone.
    - Answer: whenever the signing device registered a live presence key, the countersignature also covers:
      - every SidecarAdmit, AdmissionConfirm and OwnerConfirm of an untagged sidecar;
      - every AdminSet change and MemberRevoke;
      - every RecoveryBind and RecoveryRebind.

      api and every member device verify it, as for decisions 185 and 187.
    - Cost: one presence prompt on each of these acts. They are already rare and person-confirmed: approving or consenting a new device, lifting a park, an admin's AdminSet change or member removal, and `ur keychain recovery-rotate`.
    - Rejected: (b) recovery statements only, which leaves admitting a fresh device open; (c) keeping 185 and 187 as decided and disclosing both routes.
    - Raised by the meta review's sdkfix architect (peer/meta/sdkfix.md, OQ-sdk1; orders C-1 to C-9).

190. **After a P0 storm, the other classes resume at once: P0's excess is forgiven, not repaid (option (a), the recommendation).**
    - Question: under decision 186, a P0 storm takes a metadata cluster's whole write refill, so pushes and evacuation there are shed while it lasts. The (b) orders as first written also made the other classes repay P0's excess afterwards: the write bucket went negative, and pushes stayed stopped until the refill paid it back. At the review's stress (P0 at ~2.2 times the refill), a 6-hour storm would then stop every network's pushes on that cluster for ~12-13 hours, and NVMe batches would outstay the 26 h residency bound until the debt was repaid.
    - Answer: the bucket floors at zero. Pushes and evacuation restart when the storm ends, and ramp up as the bucket refills. FI-14's bound for the other classes excludes P0's bytes rather than subtracting them.
    - Cost: each storm's extra wear is kept. At the review's stress that is ~0.23 drive-writes per 6-hour storm. The ~420 drive-writes between the 0.768 DWPD refill and the drives' 1 DWPD five-year rating cover ~1,800 such storms (~365 and ~1,600 measured from the 0.8 DWPD budget). The dashboards track the rating used, and the page alarm still fires. A deliberate storm buys half the outage.
    - Rejected: (b) repaying P0's excess, which keeps long-run writes at the budget but stops pushes for about 2.2 times a storm's length.
    - Refines owner decision 186. Raised by the F12 (b) architect (peer/meta/governor-F12b.md, part 2.10's problem 2).

191. **A search that finds its indexer session lost re-establishes it at once, disclosed (option (a), the recommendation).**
    - Question: under decision 188, a phone in the foreground keeps its session with its search indexer by a Ping a minute. A session lost after 120 s with no Pong (a dropped network, an indexer outage) is re-established by the next Hello: at the next foreground or keepalive tick, or before a search that comes first. That search's Hello takes a new contract, and connect requests its successor then, so connect's contract rows keep the search's time for 300 days, against decision 188's "never at searches".
    - Answer: the search sends the Hello at once, at the cost of one round trip. §2.10's threat row and §2.8's connect-5 disclose the case beside a failover's window opening at its search, which they already disclosed.
    - Cost: in a rare case, a search's time stays in a contract row for 300 days: a session lost for 2 minutes or more while the app is in the foreground, and a search before the next minute's keepalive.
    - Rejected: (b) the search waits for the keepalive's re-establishment, which the keepalive would also send when the phone's network returns. That keeps decision 188's words, but after an outage at the indexer's end a search can stall up to 60 s, and failing over instead records the search's time anyway.
    - Narrows owner decision 188's "never at searches". Raised by the meta review's remote-search checker (finding remote-search-6).

## Implementation handoff: owner questions (2026-11-06)

The owner answered the questions HANDOFF.md left for them, and those the build raised, as implementation started.

192. **The presence countersignature also covers a DelegationRevoke that parks other devices: ratified as written.**
    - Question: the final meta review extended the presence countersignature to a DelegationRevoke that parks other devices (`since_n` > 0), in §7.9, D-TEAM-32, §5.6 and FS-124. That follows decision 187's intent, but no owner decision named it.
    - Answer: ratified as written.
    - Cost: none beyond what the text already carries.
    - Not taken: removing it, which would let a compromised device park other devices with no presence check.
    - Raised by HANDOFF.md section 10, from the final meta review's fixes.

193. **The owner signs G0 on 2026-11-06; the re-checks, the density review and the RECORD.md draft run beside M0's bootstrap.**
    - Question: D-PHASE-2 says no code before G0, and G0 had not passed: 21 ledger items needed a reviewer's re-check, the density rule needed a judgment, and no one was named to sign.
    - Answer: the owner signs G0 on 2026-11-06. The re-checks, the density review and the RECORD.md draft run beside M0's bootstrap, and their findings return as Q- items.
    - Cost: a finding could change something already built.
    - Not taken: agents re-checking first; the owner's reviewers re-checking first.
    - Raised by HANDOFF.md sections 7 and 10.

194. **M0-M10 build straight through on the `sidecar` branches; what a gate needs from hardware, production or people is listed open.**
    - Question: several gates cannot be met from the build machine: M2's format-1 freeze needs the benchmark on the PM9A3 hardware, M0 and M1 need stages in production, and each Gn-out needs the owner's approval to merge. How does the build move past such a gate?
    - Answer: build M0-M10 straight through in dependency order on the `sidecar` branches. Each gate's local checks run and are reported, and anything needing hardware, production or people is listed open.
    - This changes how the milestones are executed, not what freezes when: §23.8's freeze order still decides what may reach a production store.
    - Cost: formats stay unfrozen, so a later hardware miss could force rework in later milestones.
    - Not taken: stopping at each Gn-out; building M0-M2 then re-planning.
    - Raised in planning the build from the handoff.

195. **D-OPS-20's MinIO build lives in a new `urnetwork/minio` fork.**
    - Question: D-OPS-20 needs an in-house MinIO build, and DESIGN.md names no repo for it.
    - Answer: a new `urnetwork/minio` fork, a sibling checkout with its own `sidecar` branch, keeping MinIO's AGPL source in one public place. The owner creates the GitHub repo before any push.
    - Cost: the owner stated none.
    - Not taken: a patch series in warp; deciding at M2.
    - Raised by HANDOFF.md section 9.15.

196. **Warp's, config's, mmm's and vault's `sidecar` branches all open at M0.**
    - Question: HANDOFF.md asked when warp's `sidecar` branch opens, since the branch policy and §23.4 open it at M5 but §19.11 lands W5 at M0 and W2 and W8 by M4.
    - Answer: the owner directed a `sidecar` branch on all repos, so warp's, config's, mmm's and vault's all open at M0. The branch policy and §23.4's branch starts match.
    - Cost: the owner stated none.
    - Not taken: moving those changes later.
    - Raised by HANDOFF.md section 10.

## Building the apps' integration: owner question (2026-11-09)

197. **Q-SDK-2, amended: the apps' network extensions run only IP and port forwarding, always on and self-contained.**
    - Question: owner decision 87 put a keyless device role in network processes (the iOS tunnel, the desktop VPN service). It enforces the bridge rules and names its sidecar role compiles, gets each link's signed `WindowDelegation` from that role, and waits for it to build new links. On Android both roles share the app's process, so mail, sockets, search and file sync ran in the background while the VPN ran. Which parts of sidecar belong in the apps' network extension, and how independent of the app should they be?
    - Answer, in the owner's words: "On the apps, the only part of sidecar that i want to push into the network extension is the ip and port forwarding. I want that to be always on with the network extension." Asked the points that left open, the owner chose:
      1. Self-contained: forwarding runs fully inside the extension, with its own forwarding key, and takes rule changes directly, so it never waits on the app. Nothing else of sidecar goes in.
      2. All of the device's forwarding: its overlay IP address (§17.4), port forwards into the device (§17.6's port mapping), routes to other devices' subnets (§17.7), and advertising its own subnet.
      3. Every app's VPN component: Apple's network extension on iOS and macOS, Android's VPN service, and the Windows and Linux app services.
      4. On Android, mail, sockets, search and file sync (evs) run only while the app is open, as on iOS.
    - "Always on" means that whenever the VPN component runs, forwarding runs; no setting turns it off.
    - Owner decision 87 still holds for everything but forwarding: the iOS app and the desktop `ur daemon` host the sidecar. Point 4 also amends owner decision 12: Android with the VPN on is no longer an always-on receiver, so an Android app is no mail indexer (owner decision 150).
    - Cost: the VPN component follows the config repo and compiles its rules itself, so it links the sidecar's config follower, policy engine and bridge compiler, which today's 1 MiB budget for the iOS tunnel cannot hold; each app device keeps a forwarding key, a forwarding Delegation in the authorization log and a forwarding client; Android-only users, like iOS-only users, receive mail only while the app is open.
    - Not taken: keeping the keyless device role, where the extension forwards with the rules and signed links the app last gave it and new links wait for the app; Apple's extension only; keeping Android's mail, sockets, search and file sync running in the background with the VPN.
    - Raised in planning the apps' integration (the build's ledger, QD-597).

## The build's owner questions (2026-11-06 and 2026-11-10)

The build raised its questions in a ledger (`.stack/decisions/LEDGER.json`, outside git), copied into sidecar/DESIGN-AMENDMENTS.md until folded here. On 2026-11-06 the owner accepted the ledger's owner and defect items as recommended, in bulk, except eleven costly to reverse, which the owner decided one at a time; on 2026-11-10 the owner answered the later owner questions one at a time. The design-records tracks number each answer that changes a behavior or a rule as it folds it, citing its ledger id; defect fixes the owner accepted, and the build's readings and fills, are applied as text without a number.

198. **The nightly stored count combines its shard jobs' sums in Redis, under a new `{evsn_<night>}` family (option 2; the build recommended option 1).**
    - Question: taskworker's nightly pass bounds its work by sharding repos by id prefix into jobs, each listing one shard on one metadata cluster. §20.7's stored count is per network, and `model.SetNetworkStoredByteCount` writes a network's whole count, but a network's repos fall in every shard and on every metadata cluster, so no shard job holds a network's sum, and nothing said where a shard's sums wait for the others'.
    - Answer: each shard job replaces its per-network sums for the night under `{evsn_<night>}`, kept 48 h. A closing job, once every shard of every metadata cluster has reported for the night, writes each network's sum through `model.SetNetworkStoredByteCount`, zero for a network with a count and no sums. A night that some shard never finished, or whose sums Redis lost, leaves the old count standing. No migration.
    - Cost: a new Redis family and its §2.8 line; a lost Redis loses that night, and the count then moves by usage batches alone until the next whole night. Until the change lands the pass writes the count only from a run that saw every repo.
    - Not taken: (1) a per-night accumulator table in Postgres beside `network_quota_state`, the recommendation; (3) per-shard deltas, which still need last night's figures stored; (4) one job per cluster run in sequence, unbounded at year two's ~555,000 repos.
    - Raised by the build (EVSB-M2-23; the build's ledger, QD-636).

199. **A `team_subscription` table records whether each Team's Stripe subscription is live, with its customer and anchor (option 2, the recommendation).**
    - Question: the Team grant job writes each period's `team` grant and credit line for every Team whose subscription is live with no unresolved payment failure, yet nothing recorded that a subscription had ended, so a Team that cancelled would be granted the period after its last paid one. The job guessed its anchor from renewal rows, and the meter reports had nowhere to read a Team's Stripe customer or its subscription's start.
    - Answer: MG6's quota group gains `team_subscription(network_id, subscription_id, customer_id, anchor_time, start_time, end_time NULL)`, written at a Team's first `invoice.paid` and ended at `customer.subscription.deleted`, which the hourly reconciler can repair from Stripe. `RefreshTeamTransferBalances` grants only Teams whose row is live (no end time) with no unresolved payment failure, and reads the anchor from it; the meter reports, which only such Teams get, read its customer and start. It replaces the draft's `team_ended` mark in `subscription_renewal`.
    - Cost: one migration in MG6 and a line in §2.8's api-13: a Team's Stripe subscription and customer ids, kept for the network's life.
    - Not taken: (1) keeping the draft's `team_ended` mark, which gives renewal rows a second meaning and costs a period when a deletion event is lost; (3) asking Stripe for each due Team's status inside the daily job, which no outage may delay.
    - Raised by the build (QUOTA-M6-02; the build's ledger, QD-649).

200. **The fold records where each folded version's change sits in its own statement's list, so evs proves a version an older path epoch wrote without that epoch's token (option 1, the recommendation).**
    - Question: a statement names its changes by token paths in its own path epoch. After a cut-over a file's entry is found by its current-epoch token, but its version was written by a statement of the older epoch, whose change list is sorted by that epoch's tokens. evs holds no key, and a client may send an old token only where it holds evidence the server already has it, so evs could not find the change to serve the proof that ties the version to its statement, and every unrewritten file whose push listed its changes out of line was unreadable after a cut-over.
    - Answer: the fold records, beside each folded version, the place of its change in its statement's list (`leaf_part`, `leaf_index`; the same on a removal marker and for a directory's newest folded delta). evs builds the proof from the place, and the reader checks that the proof's leaf names its own token for that epoch, so no one sends an old token. §2.8's evs-11 shows the places.
    - Cost: four small fields on server-held entries that read replies also serve; the place is a fact the push record already shows the server.
    - Not taken: (2) keeping each path's token in every epoch it lived in, up to 512 B an epoch an entry and still missing epochs the entry was never copied into; (3) scanning the statement's change list for the entry's hash, reading up to 100,000 changes to serve one file; (4) the client sending the old token when evs asks, which would let evs ask for any name's token under a removed key.
    - Raised by the design details (DESIGN-DETAILS.md section 9; the build's ledger, QD-611).

201. **A group's first object is an owner marker, `gkm/<group_id>/owner`, through which alone gkm resolves a group to its repo (option 1, the recommendation).**
    - Question: gkm tied a group to its repo only through its GroupForms, resolving a group route to the repo among the token's scopes whose newest form names it, so a reader of repo A who administers repo B could file B's form naming A's group and reach A's group with B's rw, wedging A's rotations; the LIST that the build put before a form left a race between a repo's form and its `epoch/0`.
    - Answer: a group's first object is `gkm/<group_id>/owner`, `GkmGroupOwner{repo_id, network_id}`, created If-None-Match by gkm from the token as the first write of a creation or re-form; other bytes get 409 with nothing else written, and equal bytes resume a crashed request. Every group route resolves through it, immutable and cached per process: the repo it names must be among the token's scopes, and its newest form must name the group. A shred deletes it and a re-seed's form writes it again; the LIST before a form goes.
    - Cost: one 40 B object a group and a §2.8 line under gkm-1, which already shows each repo and group pair, so no new value.
    - Not taken: (2) the LIST before a form, with its race, in which the resolver must refuse both repos; (3) accepting the reach, so any reader can stall another repo's rotations.
    - Raised by the design details (DESIGN-DETAILS.md section 6) and the build (KEYS-M2-12; the build's ledger, QD-614).

202. **A forwarding Delegation's row carries its reader key's SHA-256, and the key itself is a gkm object (option 1, the recommendation).**
    - Question: a Delegation's row held its 1,216 B X-Wing reader key, so that a rotator can seal to it. Owner decision 197 gives every app device a forwarding Delegation, which put a 5,000-device team's rows at 5.9 MB, over the 4 MiB every verifier refuses (§8.8), and tripled a phone's compile memory.
    - Answer: the row carries `reader_key_sha256`, and the key is the gkm object `gkm/dkey/<delegation_id>`, which the Delegation's signer uploads and gkm and every rotator check against the digest. A 5,000-device team's rows are then about 2.2 MB, and the 4 MiB cap sits near 9,600 devices. The cipher suite is unchanged.
    - Cost: one object family, two routes, a digest check, and §2.8 lines (gkm-1, api-7) for a value the rows already showed.
    - Not taken: (2) keeping the key in the row, which stops networks at about 2,600 app devices; (3) X25519-only forwarding keys, 32 B in the row, which would leave the config generations wrapped to forwarding keys without post-quantum protection.
    - Raised by the design details (DESIGN-DETAILS.md section 4; the build's ledger, QD-622).

203. **An unadopted segment lives 49 to 75 h, so segment GC waits for evacuation's horizon and raises no fence (option 1, the recommendation).**
    - Question: §11.13 deleted a segment no committed push introduced once it was 25 h old, after fencing each idle ref of its repo. A fence is a head CAS, so a ref with no head gets none, and a first commit to a new ref whose drive commits stall could land after GC's second check and leave a committed head naming a deleted segment.
    - Answer: segment GC deletes such a segment only once no batch is left from before its LastModified + 24 h + 2 min, so an unadopted segment lives 49 to 75 h, in place of D-EVS-34's 25 to 49 h. GC then raises no fence, waits no deadline and makes no second check, and the push route is unchanged; the fence of a ref with no head is left to evacuation, a placeholder head created If-None-Match with its fence raised.
    - Cost: a day more of an orphan's bytes on the HDDs, counted in its uploader's network's stored bytes; it saves every GC fence, a head overwrite of about 14 KiB a drive per idle ref of a repo each night it has an orphan.
    - Not taken: (2) keeping 25 h by reading every batch of the last day each night to fence the refs of pending records; (3) keeping 25 h by having every push that creates a ref write a placeholder head first, which changes the landed push route.
    - Raised by the design details (DESIGN-DETAILS.md section 2; the build's ledger, QD-623).

204. **A drop job takes its mark only once evacuation's horizon has passed each covered drop's commit, so a `now` drop's deletions start about 25 to 26 h after it (option 1, the recommendation).**
    - Question: the drop job marks and verifies from each ref's head, and a push that creates its ref has no head to read. One validated before a DROP committed that cites a listed version, its head write stalled past mark and verify, could land naming segments the job deleted; with `now` the job started 25 min after the DROP, so the write need only be held that long.
    - Answer: the job takes its mark only once the horizon of DESIGN-DETAILS.md 2.2.4, the oldest batch left on the repo's metadata cluster, has passed each covered drop's commit time by 2 min, so every push validated before the drop has committed on a head a scan can read, or is dead. A drop with the 7-day window costs nothing; a `now` drop's deletions start about 25 to 26 h after it.
    - Cost: a `now` drop's content stays about a day longer. This amends owner decision 183's 25-minute fence for `now` drops; its window and its cancel stand.
    - Not taken: (2) the job reading the batches since each drop's commit and resolving their records itself, a second resolver beside evacuation; (3) accepting the loss, which breaks I-EVS-15.
    - Raised by the design details (DESIGN-DETAILS.md section 2; the build's ledger, QD-626).

205. **`self_admit` and `scim_signer` compile into the authorization log's rows, where api and every gate judge by them (option 1, the recommendation).**
    - Question: §7.9's scoped row admits a member's untagged device on its consented device's signature only while `self_admit` is on, and `self_admit` rides config heads, which api never opens, so api could not judge a member's self-admission and refused every personal network's second device; the same held for a MemberRevoke an admin's indexer signs under `scim_signer`.
    - Answer: those two ServiceSettings values, the ones a verifier judges a statement by, compile into `ProjectionRows.settings` (`ProjectionSettings{uint32 self_admit = 1; bytes scim_signer = 2}`); full readers check them against the head at compile, and rows-only verifiers, api among them, take them. Nothing else of ServiceSettings is compiled.
    - Cost: two small fields and an api-7 line in §2.8; the server learns a setting whose effect it already sees in which admissions land and who signed them.
    - Not taken: (2) compiling every id-level ServiceSettings value, three more values no gate judges by; (3) compiling none, so api sequences statements devices refuse, the split D-TEAM-19 forbids.
    - Raised by the design details (DESIGN-DETAILS.md section 5) and the build (TEAM-M2-02; the build's ledger, QD-629).

206. **The side that ends each condition queues the versionless sweep's one-off passes: a hold's end and the purge's turn-on (option 1, the recommendation).**
    - Question: §11.13's sweep rereads and deletes what a hold kept once the hold ends, and what `purge: observe` kept once §19.11's purge turns on, but neither event is a write evs or taskworker sees: a hold's object and row are gone within the hour of its end, and the purge turns on in a config file, so nothing queued either pass and the kept content stayed for the repo's life.
    - Answer: `AbuseHoldPass` schedules `EvsSweepHoldEndTaskRequest(holdRecord, endTime)` for each hold it ends, before it deletes the `hold/` object. The purge's turn-on is a `sidecarctl evs purge-turn-on` command that schedules `EvsSweepTurnOnTaskRequest`, run in the same runbook step that sets `format2.purge: on`, and a monitor row watches for observe's retained count staying flat while purge is on. Both passes are idempotent.
    - Cost: a line in the hold pass, one operations command and a runbook line; server/task's `pending_task` and `finished_task` rows carry a hold pass's network, repo ids and placement and end times, which §2.8's api-14 lists with their retention.
    - Not taken: (2) taskworker detecting both from an object of its own recording the purge mode and the holds it last saw, a new object family and a second notion of a hold's end; (3) detecting the turn-on from the evacuation chain's task arguments, which a coalesced start could lose.
    - Raised by the build (EVSB-M3-02; the build's ledger, QD-635).

207. **A case keeps a reported URL's path and query only until its first review ends (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: api-14 listed a case's target host, label or network and dropped third-party data at the join, yet §13.9 has reviewers open reported URLs as visitors; both cannot hold for a URL with a path, and a review that sees only the host can miss the page it was asked to judge.
    - Answer: a case keeps a reported URL's path and query until its first review ends, at most that case's review clock, then clears them; api-14 lists the field with that ttl. A reporter's address or free text is never kept; of free text only an appeal's own reason is stored.
    - Cost: api-14 gains a field living hours to days, and a URL can carry a victim's token for that long.
    - Not taken: (2) never keeping them, so reviewers see only the host and one bad path on a host may go unfound.
    - Raised by the build (plan-ABUSE; the build's ledger, QD-141).

208. **The abuse and legal-request mailboxes sit at one provider outside URnetwork, every record sealed to a vault-held key before it leaves api (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §21.10 mails each action and lift to an abuse mailbox held off site, and §19.10 re-places holds from a legal-request mailbox, but no §2.8 row listed either, and in the clear these records would put network ids, targets and the existence of sealed holds at a third party, which owner decision 93's sealed orders must not reveal.
    - Answer: both mailboxes sit at one provider outside URnetwork's Postgres and clusters, which the owner names. Every record is sealed to a vault-held HPKE key before it leaves the process, so the provider and SES see only sender, time and size; §19.10's restore opens them with that key. api-14 names both mailboxes' copies, action records kept as api-14's actions and hold records until the hold's `expire_time`, and an ext row lists the provider with what it sees: sealed records, their time and size.
    - Cost: a vault key and an open step at restore, and a restore fails if that key is lost.
    - Not taken: (2) clear records at a third-party mailbox, as §21.10 read; (3) a URnetwork-run mailbox on an off-site host, another mail service to run, with SES still carrying the records unless sealed.
    - Raised by the build (plan-ABUSE; the build's ledger, QD-030).

209. **Head readers keep a sealed record of each path they read, so the published limit stays "a path it never read or no longer remembers" (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §2.8, §11.9, Q-EVS-6 and FS-10 limited a head reader's trust in evs to a path it had never read, yet its durable state was only (ref, v, C_v) and a reply starts after pin_version, so once its pin passed a path's change, a server could serve that path at an older committed version unseen.
    - Answer: head readers durably keep, sealed under §5's AEAD, one record per path read: (ref_id, path, entry version, pin at last read), at most HeadReadRecordCount = 16,384 a network, least recently used out. A read of a recorded path sets pin_version to the record's pin, not the ref's (a request of several paths takes the oldest of their pins); the reader checks every statement after it by §11.9's reader row, refuses and alarms if the served version is below the record or a later statement changes the path, then raises the record. A path whose record was evicted, or whose pin is past §11.9's 4 MiB budget, counts as never read. No wire change.
    - Cost: a bounded sealed table, about 1 MiB at 16,384 paths, and larger catch-up reads.
    - Not taken: (2) widening the disclosure to every path older than the pin, so a phone re-reading its own file could be rolled back silently; (3) a state commitment over the token tree, §11.22's Later item, which reopens Q-EVS-6's rejected Merkle root before M2's freeze.
    - Raised by G0's re-checks (the build's ledger, QD-043).

210. **The primary's physical copies count as backups: each lives at most 7 d, and the 24 h edge records' partitions are UNLOGGED (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: D-TRUST-7 says no backup may outlive a published ttl, and ops-2 named only dumps, but edge-6's `pg-base`, the base the main dump reads, and edge-5's `main-pgbase-<date>` are physical copies of the whole primary, every sidecar row included, and the dump's timer is held today, so a base can sit for weeks.
    - Answer: count them. Each copy is refreshed or destroyed within 7 d: `pg-base` by the main dump's timer, else the base goes and the next run makes a full copy, and edge-5's generation by a timer or destruction. `tls_connection_record`'s and `mail_connection_record`'s partitions become UNLOGGED, so pg_basebackup copies none of the 24 h edge records, and a primary crash loses them, as a restore already does. ops-2 discloses the rest: physical working copies of the primary hold every table for at most 7 d.
    - Cost: the dump's timer must run, or a lost base costs a 19 h full copy; edge-5 needs a timer; a crash loses a day of join records.
    - Not taken: (2) not counting them and disclosing their real age, which changes a published promise; (3) a separate database or tablespace for sidecar tables, against owner decisions 2 and 18's single Postgres.
    - Raised by the build (the dump work in xops; the build's ledger, QD-051).

211. **`sidecar.ur.io` is served direct, never through Cloudflare, which terminates https://ur.io, and §2.8 discloses what Cloudflare can see (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: Cloudflare terminates the public ur.io connection (mmm/mmm/nginx/nginx.conf.j2:65-66), yet no §2.8 row, EX7 or §2.4 named it, so a third party sat undisclosed in a decrypting page's path, and proxying `sidecar.ur.io` would let it replace `sidecar.wasm` and take keys.
    - Answer: serve `sidecar.ur.io` direct: it joins warpctl's `domains` and mmm's `expose_aliases` as W10's names do, under a W5 certificate at the lb, as an unproxied record, and `warpctl dns` refuses it proxied (a new name starts unproxied today). Those values live in vault, so that edit is external. §2.8 gains an EX7 clause and an ext row saying Cloudflare terminates https://ur.io: it sees page requests and can alter page script, so it can request views while that script runs, never the key origin's code, key or token.
    - Cost: one DNS guard and §2.8's text, and the disclosure that a third party can read views through altered page script.
    - Not taken: (2) moving ur.io/recurd off Cloudflare too, which moves the whole ur.io origin and loses its CDN and country analytics; (3) the key origin behind Cloudflare, disclosed, which would let a third party swap the loader and wasm and undo D-SDK-18's reason for a key origin.
    - Raised by the build (plan-SDK; the build's ledger, QD-012).

212. **One procedure after a compromise rebind: the member's devices listed, the rebind kept standing, and its signer revoked last (option 1, amended, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: a compromise rebind retires a leaked recovery code, but a keychain backup sealed to the old code still opens with it, and §5.9's rule to revoke each such device for compromise was worked out only for a voided binding: nothing triggered it after a rebind, a since_n before the copy voids a rebind its device signed, and a personal network's last device had no other signer.
    - Answer: once the rebind lands at position r, `recovery-rotate --compromise` lists each device of the member live while the retired binding was current, raises `recovery_rebind` naming that span on its own device too, and offers each a compromise revocation. since_n defaults to §7.9's loss-time proposal, clamped to r + 1 for the rebind's signer and for any device whose closure would reach that signer, so the rebind stands; a person who believes a clone acted may move it earlier, and the plan then shows the rebind voiding and who must sign it again. The rebind's signer goes last: it enrolls a replacement, which revokes it from a since_n after that admission. §18.5's `recovery_rebind` answer splits in two: "not me" keeps since_n at or before the rebind, and "I did this" takes this rule. Only the rebind's signer is clamped, so other devices keep the loss-time since_n.
    - Cost: a stated residual: where no signer outside exists, what a clone signed before that position stands.
    - Not taken: (2) the void rule as written, since_n at the retired binding's entry, which voids a rebind its device signed and cannot be met for a personal network's last device; (3) advice the CLI prints, which leaves §2.10's bound unmet.
    - Raised by G0's re-checks (the build's ledger, QD-016).

213. **v1 ships no apt or yum repository: `.deb` and `.rpm` stay direct downloads through `install.sh`'s verified path (the build recommended a second offline key).**
    - Question: §4.18 listed apt and yum for v1 and nothing more, but apt needs a signed InRelease and dnf a signature in each rpm, §2.6 listed no GPG key, and an online key would let one host ship a client to every apt and yum user at their next upgrade, which D-REPO-7's offline key prevents for `install.sh`.
    - Answer, in the owner's words: drop apt and yum from v1, and keep .deb and .rpm as direct downloads through install.sh's verified path. No GPG key and no repository host. §4.18 loses that item, and `apt upgrade` needs a Q- item.
    - Cost: Linux users lose `apt upgrade` and `dnf upgrade` for `ur`.
    - Not taken: a second offline GPG key used in the same two-person ceremony at promotion, the trees under ur.io/recurd through mmm (the recommendation); an online key in vault used by the release, which reopens the single-origin risk.
    - Raised by the build (plan-REPO; the build's ledger, QD-023).

214. **A checkpointer's HTTPS call to a customer's witness is no URnetwork carrier (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: D-ARCH-2 says a new carrier needs an owner's decision, and none of §3.5's six planes runs from a sidecar to a customer's service, so a checkpointer's POST of its checkpoint to a C2SP witness that a log admin names needed one.
    - Answer: it is no URnetwork carrier: a checkpointer's own outbound HTTPS call to a witness a log admin named in a signed, /dev/tty-confirmed `log_settings`. It carries a signed note and a consistency proof, never an entry; no agent can set the host; and §2.8 stands, since no URnetwork server takes part. §3.5's map names it outside the six planes, and RECORD.md section 10.2's step 6 turns on.
    - Cost: a daemon dials a host URnetwork does not run; a witness learns only the log's origin, size and growth times.
    - Not taken: (2) running a witness as a sidecar, which costs each customer or auditor a sidecar and an adapter in front of its C2SP witness; (3) no online call, so a person or forwarder carries each checkpoint and witnessed times lag.
    - Raised by the RECORD.md draft (the build's ledger, QD-242).

215. **Forwarding adds at most 6 MiB of stripped executable to the iOS network extension, whose signed ceiling rises from 50 MiB to 54 MiB (option 1, the recommendation; Q-SDK-7's executable half).**
    - Question: Q-SDK-7 proposed that forwarding, which owner decision 197 has follow the config and compile its own rules in every VPN component, add at most 4 MiB of executable to the iOS extension, but nobody had measured it. Measured on 2026-11-10, the `ios_extension` leg with forwarding's entry points and every other root file tagged out adds 5,040,248 B stripped over the pre-sidecar leg, before the bridge statements and compiler, which add about 350,000 B more.
    - Answer: the leg adds at most 6 MiB (6,291,456 B) of executable, measured stripped as the shipped binding is, and the signed extension's ceiling rises from 50 MiB to 54 MiB (56,623,104 B). One implementation of the rule table stays. `make size`'s limit for the leg and `check_apple_size.sh`'s ceiling take these numbers.
    - Cost: artifact size, and about 1 MiB more static memory in the tunnel.
    - Not taken: (2) holding the proposed 4 MiB, which one shared verifier cannot reach (without evs head reads, the gkm client and the poll it still adds 4,400,320 B), so part of the rules would need a second implementation; (3) holding D-SDK-20's original 1 MiB with a second follower, policy evaluator and compiler in `sidecar/device`, two implementations of security-critical rules to keep equal.
    - Raised by the design details (DESIGN-DETAILS.md section 4; the build's ledger, QD-619).

216. **A forwarding compile in the Apple network extensions is admitted only within a 10 MiB cap under a 30 MiB process ceiling, and a network past it keeps its last verified state there (option 1, the recommendation; Q-SDK-7's memory half).**
    - Question: owner decision 197 has the VPN component compile its own rules from the network's verified rows, which decode at about five times their bytes (10,528,336 B for a 5,000-device team, measured), while the iOS tunnel's Go runtime runs at 19.6 MiB connected and 26.0 to 27.4 MiB under provider load, against a 28 MiB target and a 32 MiB soft limit; §18.10 had proposed 8 MiB while compiling, unmeasured. How much may a compile take there, and what happens to a network whose compile does not fit?
    - Answer: a compile in the iOS and macOS network extensions is admitted only when 5 × rows + 2 × head + 1 MiB fits a 10 MiB per-compile cap and the room under a 30 MiB process ceiling, which networks to about 4,300 devices fit at the tunnel's connected baseline; under provider load a compile waits for room. A larger network keeps its last verified state on that device, applies every revocation it can check, raises `bridge_alarm` once a statement that could narrow reach has waited 10 minutes, and does not go pending for that wait (the build's ledger, QD-621), and it compiles on Android, Windows and Linux. §22.9's cell compiles a 3,000-device team within the cap and refuses a 5,000-device one with the alarm.
    - Cost: teams past about 4,300 devices do not compile in the Apple extensions until review-phase work removes the bound, if such teams matter on iOS.
    - Not taken: (2) a 12 MiB cap at the 32 MiB soft limit, which admits a 5,000-device team only while the tunnel is otherwise idle and leaves the collector running continuously while packets flow; (3) the app's sidecar role compiling for networks over the cap and handing the state over the device RPC, which waits on the app as owner decision 197 ruled out; (4) a compact per-host state in the shared verifier now, a rework of landed code.
    - Raised by the design details (DESIGN-DETAILS.md section 4; the build's ledger, QD-620).

217. **The key origin keeps one IndexedDB database per network, `urnetwork-sidecar-v1-<network_id>`, each its own sidecar instance (option 1, the recommendation).**
    - Question: §18.8 keeps one page Worker per network under a per-network Web Lock, but the key origin's whole state sat in one IndexedDB database whose one instance document lists every network and which the core edits read-modify-write; two tabs on two networks each hold their own lock, so nothing ordered their edits, and an enrollment in one tab and a sign-out in the other could each write back the document it read, losing one change. Which serializes it?
    - Answer: one IndexedDB database per network, `urnetwork-sidecar-v1-<network_id>`, each its own sidecar instance with its own instance document and WebCrypto root key, so two networks' page Workers share nothing and §18.8's per-network Web Lock covers everything a Worker writes.
    - Cost: the page Worker's open and its single-database layout change, and a root key per network; a browser eviction still clears every network at once.
    - Not taken: (2) a second, instance-wide Web Lock around every edit of the instance document, which needs a hook in the core and holds a lock another network's tab may wait on; (3) one Worker per browser for every network, which needs multi-network Workers before M4 and makes every tab wait on one Worker.
    - Raised by the build (SDK-M4-04; the build's ledger, QD-645).

218. **A bridge rule filed under a multi-use decision carries the decisions' template beside its own use's action, as `BridgeApproval.template_action` (option 1, the recommendation).**
    - Question: §16.6 lets one multi-use decision activate up to its uses `bridge_expose` rules, each under the rule id §17.8 derives from its use's effect_key, so a reader needs both the template every decision's payload_sha256 hashes and the use's own action, but `BridgeApproval` carried one action, and the two agree only when uses is 1.
    - Answer: `BridgeApproval` gains `bytes template_action = 3`. With it set, every decision's payload_sha256 hashes the template, `canonical_action` is this use's action, from which §17.8 derives the rule id through effect_key, and readers check that the use matches the template; with it unset, the single-use reading stands. A multi-use decision then files up to its uses rules, which the ledger's count binds. Binding a rule's body to `expose`'s fields is settled with the question on CanonicalAction's detail (record-m2-01-canonical-action-detail).
    - Cost: one additive field inside the sealed body, so no §2.8 line.
    - Not taken: (2) single-use bridge rules, so a decision with uses above 1 files none and §16.6's bridge half of AD2 goes; (3) the template in the ApprovalRequest, fetched from the record, which a forwarding role does not read.
    - Raised by the build (BRIDGE-M2-01; the build's ledger, QD-631).

219. **The key origin signs a page Worker in by a hand-off from the ur.io session, a one-time `/auth/code-create` code passed by postMessage (option 2; the build recommended sign-in inside the key origin).**
    - Question: §18.8 has the key origin mint each page Worker's `admin_refused`, `strict_exp` top-level client, and re-mint it after a lapse, but no section named the credential: `POST /network/enroll` takes an auth key, a client token cannot create a top-level client (server/model/network_client_model.go:382), and pages may hold no token.
    - Answer, in the owner's words: "the file's option 2, a hand-off from the ur.io session: the page calls /auth/code-create and passes the one-time code to the key origin by postMessage, and the key origin runs /auth/code-login, mints the client with POST /network/auth-client and drops the network token." Re-minting after a lapse takes the same hand-off.
    - Cost: the one-time code crosses a page an XSS may read, as ur.io's `localStorage` network token already does, so §18.8's pages row says the page handles both.
    - Not taken: (1) sign-in inside the key origin with PKCE under a new public client `ur-web`, a single-use auth key of at most 5 min and `POST /network/enroll`, which keeps every token out of https://ur.io at the cost of a second public client, a redirect landing on `sidecar.ur.io`, a popup and a sign-in at each lapse (the recommendation); (3) a single-use auth key issued by the member's consented device, the strongest, which a person with no other device cannot start and which needs app work.
    - Raised by the build (plan-SDK; the build's ledger, QD-015).

220. **A requested `dial` or `route` grant seals its prefixes and ports in its CanonicalAction, so api checks it by ids alone (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §8.8 has api hash and read a requested grant's CanonicalAction, whose `cidrs`, `grant_dst` and `target_port` carry its prefixes and ports, and §17.9's `bridge_forward` files a GrantActivate, so a forward's port and a requested route's LAN prefix reach api in the log whatever rows hold, while D-BRIDGE-6 and §17.8 promise that no prefix or port reaches the server.
    - Answer: in a `dial` or `route` grant's CanonicalAction, `rule_id`, `subject`, `grant_allow`, `expires_millis` and a subject-only `grant_dst` stay clear, and its prefixes and ports (`cidrs`, `target_port`, any `ip:` or port text in `grant_dst`) move to a new `bytes sealed_detail = 38`, sealed as a statement's body is, raising CanonicalAction's version. `payload_sha256` still covers the stored bytes, so api's match check is unchanged and checks ids only; approvers and readers open the detail to render and enforce it. Publishes keep their clear fields, which are public anyway.
    - Cost: one CanonicalAction field and version, approvers opening a seal before they render, and the change before record.proto freezes at M3.
    - Not taken: (2) disclosing it, so §17.8, D-BRIDGE-6 and api-7 say a requested grant's prefix and port reach the operator, which falls short of owner decisions 5 and 72's id-only wording.
    - Raised by the build (plan-BRIDGE; the build's ledger, QD-003).

221. **The key origin serves only a promoted build, whose loader and `sidecar.wasm` the release's signed `SHA256SUMS` lists (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §18.8 said the key origin serves "only the signed loader", but no section said signed how, and no browser can verify a loader before running it (EX7).
    - Answer: from M4 the loader and `sidecar.wasm` join the release's signed `SHA256SUMS` (§4.10), `sidecar.ur.io` serves only a promoted build, and the loader pins `sidecar.wasm`'s SHA-256 and checks it before instantiating. "Signed" means listed in those sums, so anyone can compare the served bytes to them; no browser verifies them on load, so EX7 stands.
    - Cost: each page Worker fix waits for the release's two-person signing.
    - Not taken: (2) the same sums for audit only, web fixes shipping at once, so "signed" means only that some served builds were; (3) dropping the word, so the key origin's bytes have no signed record.
    - Raised by the build (plan-SDK and plan-REPO; the build's ledger, QD-037).

222. **`ur tun` on Windows neither bundles nor fetches wintun.dll, and loads a copy already on the host only after checking it against the Windows app's pins (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §17.10 puts `ur tun`'s OS tun on `golang.zx2c4.com/wireguard/tun`, which on Windows loads wintun.dll, whose prebuilt binary carries a custom license that §4.7 refuses, so a release zip that carried it would need an exception.
    - Answer: do not bundle or fetch it. `ur tun` on Windows looks for wintun.dll beside `ur.exe` or at the installed app's path, loads it only after its SHA-256 and Authenticode signer match the pins in windows/app/tools/fetch-deps.ps1 (0.14.1), since `ur tun` runs elevated and an unchecked DLL there is a privilege path, and otherwise prints where to get it. The release zip holds no DLL. Bundling can follow once counsel has read the license.
    - Cost: a worse first run, and CLI-only hosts need a manual step.
    - Not taken: (2) bundling the pinned DLL under an owner-approved exception to §4.7, after counsel reads the license; (3) no OS tun on Windows, dropping §17.18's `ur tun` there, a departure from the phasing.
    - Raised by the build (plan-BRIDGE; the build's ledger, QD-125).

223. **A minimal real ur.io/recurd page is built on mmm's `sidecar` branch, its visual design out of scope (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §23.4 puts ur.io/recurd's sign-in, downloads and page Worker in M4, with "ur.io/recurd opens a vault record" an exit criterion, while owner rule 6 and the implementation brief leave app, console and extension UI out, so it was unclear whether the page itself is built.
    - Answer: build a minimal real page at `mmm/ur.io/astro/src/pages/recurd/` on mmm's `sidecar` branch: the served-code label, the key-origin frame, the sign-in hand-off, a record list, one record view and download links, unstyled beyond the site's layout. Visual design stays out. The seams and the fixture page are built either way.
    - Cost: about 300 lines in mmm.
    - Not taken: (2) seams only, M4's exit shown on a fixture and listed open until someone builds the page; (3) the owner's web work building it against those seams.
    - Raised by the build (plan-SDK; the build's ledger, QD-140).

224. **C16's receive gate latches at this side's seal for M4, and before M8 turns it on for app-device hosts the plaintext an Opportunistic peer has in flight at the seal is measured (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: a responder usually seals first, so for about one round trip an Opportunistic initiator still sends plaintext, legitimately, which a host whose C16 gate latched at its own seal acknowledges and discards, ending the sender's retry. Should the gate latch at this side's seal or at the peer's first sealed frame?
    - Answer: keep it as landed for M4, latching at this side's seal. Before M8 turns the setting on for app-device hosts, measure how much plaintext an Opportunistic client has in flight at the seal, and if the loss is visible take option 3: latch at the peer's first sealed frame, bounded by `TlsTimeout` from this side's seal.
    - Cost: until then each session start at a sticky host can lose up to a round trip of an Opportunistic peer's frames.
    - Not taken: (2) latching at the peer's first sealed frame alone, which accepts a forged plaintext pack until then, without end for a silent peer; (3) now, before the measurement.
    - Raised by the build (connect's C16; the build's ledger, QD-275).

225. **The in-house MinIO build honors `x-ur-if-unmodified-ms` on a DELETE, so a GC run deletes only the object it listed (option 1, the recommendation).**
    - Question: a segment's key is the hash of its bytes, and orphan GC's DELETE was unconditional. Two GC runs can hold a decision on one orphan, since a worker paused past its claim's 5 min lease wakes beside its successor: the first deletes the segment, its uploader stores the same bytes again under a fresh receipt and commits, and the second run's DELETE then takes the new, committed object. No fence or check of the second run helps, since each was made before the re-upload, and upstream's DELETE evaluates no precondition.
    - Answer: the build honors `x-ur-if-unmodified-ms: T` on a DELETE, under the key's lock: 412, with nothing sent to a drive, when the object it finds was stored a second or more after T; a missing key answers 204 as today. `sidecar.WithBlobUnmodified(ctx, lastModified)` carries it, as `WithBlobDeadline` carries a deadline, and orphan GC, the nightly pass's container deletes and the sweep send it.
    - Cost: about thirty lines in the fork, one context helper, the fake and three suite cases. The header is a time in a request, as `x-ur-deadline-ms` is, so it adds no §2.8 line.
    - Not taken: (2) a HEAD of each orphan just before its DELETE, the DELETE's deadline 2 s after it, which leaves the hazard when a second run's DELETE, the re-upload and its commit all fall inside those 2 s; (3) a lease object per GC shard, as a drop job has, which costs a new object family, its §2.8 row and a renewal write per checkpoint.
    - Raised by the design details (DESIGN-DETAILS.md section 2; the build's ledger, QD-624).

226. **The in-house MinIO build answers a LIST 503 when it could have dropped a key, so evacuation's horizon and every deletion decided on a LIST rest on a whole listing (option 1, the recommendation).**
    - Question: MinIO's LIST asks a set's online drives and returns a key only if at least half of those asked hold it, while an acknowledged key is on N/2 + 1 drives, so with three of eight drives offline it can drop a batch that five drives took. Evacuation's horizon (owner decision 203), and GC and the nightly pass, which delete on LISTs of pb/ and pidx/, would then act on what is missing, and a negative pidx/ lookup is a LIST too.
    - Answer: the build asks every online drive of each set a LIST reads, whatever `list_quorum` says, and answers 503 when three or more of a set's drives are offline, or any is while another heals. LISTs then fail in §19.6's at_risk state on a metadata set and with one host down on a 16-drive segment set, where evacuation, the nightly pass and uncached pidx/ lookups wait.
    - Cost: a few lines in the fork's cmd/metacache-set.go and one FS-114 clause; deletions, and the reads that need a LIST, wait while a set is at risk, a state the cluster is already paged for.
    - Not taken: (2) taskworker reading each set's drive states from admin info and deleting nothing past that line, which leaves readers' lookups exposed and a 60 s window from the info's age; (3) accepting it, which costs I-EVS-5 its "only" while three drives of one metadata set are out of reach on hosts that still answer.
    - Raised by the design details (DESIGN-DETAILS.md section 2; the build's ledger, QD-625).

227. **While path-epoch sources stand, a fold deletes the source copies its pushes named once the current entry holds the change, so a source holds only what still has to move (option 1, the recommendation).**
    - Question: while sources stand, a fold writes a changed path's entry in the current epoch and left the source copy for the copy job, whose move deletes it unmoved. If a second cut-over superseded the copy before it reached the path, no honest map would name the leftover, since a map lists a source for a path only where the server was already shown its token and holds no move for a removed path: the copy's end LIST then alarms and keeps the source listed for good, and three such leftovers refuse every creation on the ref (EPOCH_SOURCES_FULL), as TLC shows on PathEpoch.tla.
    - Answer: while sources stand, a fold deletes each listed source copy its pushes' source paths name once the current entry holds the change, and under a removed directory lists and deletes everything below it in those sources; its range counts as folded only when the deletes answered. A source then holds only what still has to move, at every moment.
    - Cost: a change to the landed fold: at most three DELETEs a changed path while sources stand, each one the copy then skips, and for a directory removal a LIST per named source and a DELETE per child copy.
    - Not taken: (2) the copy following a leftover back through the superseded maps and tails, which must keep and chain every map since the oldest source, hundreds of MB each at 1M paths, while a removed path has no move to follow; (3) the copy's end deleting whatever its map does not name, so a map that omits a live path, by a bug or by malice, silently loses that path's entry instead of raising the alarm.
    - Raised by the design details (DESIGN-DETAILS.md section 9; the build's ledger, QD-607).

228. **A path map's source may be any version at or below the head, and evs checks the tail against the creations the window holds (option 1, the recommendation).**
    - Question: a PATH_EPOCH committed only if its map's source version was in the window, 64 to 127 versions, with a matching chain. A 1M-path map is about 293 MB, two minutes of upload at 20 Mbit/s, and a ref that commits once a second moves its window past any source in one to two minutes, so a large busy ref could never cut over, and under an immediate due its creations stayed blocked.
    - Answer: the source may be any version at or below the head. evs reads the source's statement and chain from the window or from that version's log page, and requires the epoch it declares to be the head's current one, so no PATH_EPOCH lies between. It checks the tail against every creation among the versions the window holds; creations between the source and the window are the mapper's to cover, and a miss there is caught by the copy's end LIST (alarm, source kept) and by replaying readers. A map part's 24 h age still bounds a map's staleness.
    - Cost: one cached log-page GET of at most 70 KiB at the commit; evs's tail check no longer covers a careless mapper's own versions.
    - Not taken: (2) keeping the window and letting a mapper block every push on the ref while it uploads, which stops a busy ref for minutes at each epoch; (3) evs reading every creating version since the source from log pages and push records, thousands of reads inside one commit's 5 s on exactly the refs that need it.
    - Raised by the design details (DESIGN-DETAILS.md section 9; the build's ledger, QD-608).

229. **evs refuses a creation in the push whose own commit would record a due that blocks, and records the due by that refusal (option 2, the recommendation).**
    - Question: §11.6 records a due at the first commit whose generation pin crosses a REMOVE generation and blocks creations then, but the crossing push was checked against the head before it, where no due was recorded yet, so a creation in it committed under the key the removed holder has. The token reaches the server once the push is sent, and only the client holding the removal's generation can keep it from being sent; should evs also refuse the crossing creation?
    - Answer: evs refuses a creation in a push whose own commit would record a due that blocks: 412 PATH_EPOCH_DUE, recorded, and the refusal's fence write sets the head's due fields as the commit would have. It cannot unsend a token, as §11.5's bound says, but it keeps §11.6's rule that no new name is tokenized under a removed key true of everything committed, and it gets the due onto the head early, which stops the other writers' creations. Client and evs classify a due by one shared function.
    - Cost: about a dozen lines in 5e and the refuse path; the due is recorded by the first push across the removal whether or not it commits.
    - Not taken: (1) the client rule alone, under which an older or dishonest client's crossing creation commits under the removed key, and a due is recorded only when some push commits, so on a ref where every writer waits to create the head shows no due and evs blocks nobody.
    - Raised by the design details (DESIGN-DETAILS.md section 9; the build's ledger, QD-609).

230. **The path-epoch copy, which reads every part of a committed map, checks the whole map against the head's hash before it moves anything, and no replaying reader downloads a map (option 1, the recommendation).**
    - Question: `path_map_sha256` is the SHA-256 over a map's parts, but evs never computed it at the commit and the copy moved entries by the parts without checking them, while §11.8 had replaying readers check "maps and tails", which read literally means every full-sync device downloads every committed map, 293 MB a device a cut-over at 1M paths.
    - Answer: the copy job hashes the parts against the head's map_sha256 and checks their order before it moves anything, moving nothing and alarming on a mismatch. Readers check each row and entry as they use it, and no replaying reader downloads a map. A wrong map can then withhold or break, never substitute: an entry moved under another name's token is served with a statement naming that token, which the reader refuses.
    - Cost: a few lines in the copy, under a second of hashing for 280 MiB.
    - Not taken: (2) every replaying reader downloading and checking every committed map, 293 MB a device a cut-over at 1M paths, on devices that already hold every name; (3) evs hashing the parts inside the PATH_EPOCH commit, 40 GETs of 7 MiB within a commit's 5 s, or a format change to `path_map_sha256` over per-part hashes.
    - Raised by the design details (DESIGN-DETAILS.md section 9; the build's ledger, QD-610).

231. **The root is a directory whose token path is empty in every epoch, so lookups, listings and path maps start there (option 1, the recommendation).**
    - Question: no change could name the root and idx/ had no key for it, so a top-level name's sealed row had nowhere to live, and a listing of the root and file-mode export refused. Section 9's lookups reach a name a client knows nothing of through its parent's table, level by level, which needs a table at the top that any client may read without sending a token, and a mapper must enumerate top-level paths too.
    - Answer: the root is a directory whose token path is empty in every epoch: a change may name the empty path only for a directory delta; its entry is `idx/<repo>/<ref>/<p>.e` beside `idx/<repo>/<ref>/<p>/`; a read may name it in any epoch with no token; a path map holds its move first, with an empty path in each epoch and no sealed name, and the copy moves it last.
    - Cost: the token-path rule (0 to 32 components in a directory change), the digest's empty-path rule, 5g's bound at the root, and the task that built them.
    - Not taken: (2) top-level names riding in the creating push's sealed metadata, which no reader could look up without replaying from version 1 and a mapper could enumerate only by replaying the whole ref; (3) a reserved first component under every path, a visible change to every path and to git mode's tree mapping.
    - Raised by the design details (DESIGN-DETAILS.md section 9) and the build (EVS1-M2-24; the build's ledger, QD-612).

232. **A new ref starts in the newest path epoch its creator holds, and an overlay in its base ref's current epoch (option 2, the recommendation).**
    - Question: a ref started in path epoch 1, and evs refused any other epoch on a ref with no head, so in a general, config or mailcfg repo whose group had rotated past a REMOVE generation every new ref's first push crossed that removal. Refusing its creations would wedge the ref for good, since a PATH_EPOCH needs a committed head, so the build exempted a ref's first push, whose names were then tokenized under the removed holder's key until a first cut-over.
    - Answer: a ref that is not an overlay starts in the newest path epoch its creator holds: on a ref with no head, 5e accepts a path_epoch p with 1 <= p <= the push's generation, taking p as the new head's current epoch with no sources and no due below p, and the creator names its newest REMOVE generation held. An overlay's first push takes its base ref's current epoch, so overlay and base share token paths. No new ref's first names are then tokenized under a removed key. This replaces the exemption that had a ref's first push create in epoch 1.
    - Cost: a small change to 5e and head creation and a client change; refs of one repo may sit in different epochs, which an overlay settles by taking its base's.
    - Not taken: (1) keeping the exemption, a leak window per new ref after a removal, closed by its first map; (3) letting a PATH_EPOCH commit on a placeholder head with an empty map, so the first push is refused and the creator maps first, two round trips and a map upload per new ref after a removal.
    - Raised by the build (EVS1-M2-44; the build's ledger, QD-632).

233. **The fold records the leaf place of an inline change list too, so evs serves every committed version of an older path epoch in one round (option 1, the recommendation).**
    - Question: owner decision 200 has the fold record beside each folded version the place of its change in its statement's list, with 0 for an inline list, which the statement holds. That serves the reader, but evs must still send the version's entry-version bytes, which for a directory's delta or an elided version it can find only by the path's token path in that epoch, named in a request only when the reader's floor is at or below it; after a cut-over most directories, whose last delta came from a small inline push, could not be served until written again.
    - Answer: the fold records the place for an inline change list too: leaf_part 0 and leaf_index the change's index in the statement's list plus 1, with 0 meaning only "not recorded". evs then serves every committed version, directories and elided versions included, in one round after a cut-over; the statement-alone answer stays only for entries folded before the fields existed. §2.8's evs-11 reads as it does.
    - Cost: the fold's recording and the read route change; the place shows the server nothing the push record's ordered change list does not.
    - Not taken: (2) the statement-alone answer, a second round for each such directory after every cut-over; (3) the copy recording a directory delta's entry-version bytes in the entry, a new field per directory entry and a second copy of each delta in idx/.
    - Raised by the build (EVS1-M2-45; the build's ledger, QD-633).

234. **§11.8's "no key prefixes another" means a path prefix, so a KeyPackage's claim stands beside it (option 1, the recommendation).**
    - Question: §10.6 stores a KeyPackage at `gkm/kp/<sidecar_id>/<ref>` and its claim at `<ref>.claim`, and sidecartest's FakeBlobs read §11.8's rule as a byte prefix and reported every claim, while §11.3's reason for the rule, MinIO's directory-object listing, bites only a path prefix (`a/b` beside `a/b/c`), where `a/b` and `a/b.claim` are siblings.
    - Answer: the rule means a path prefix: an existing key followed by '/' at the new key's next byte, or the reverse. `gkm/kp/<sidecar_id>/<ref>.claim` stands beside `gkm/kp/<sidecar_id>/<ref>`, and FakeBlobs checks path prefixes only.
    - Cost: one change in sidecartest's fake and a sentence in §11.8.
    - Not taken: (2) moving claims to their own family, `gkm/kpc/<sidecar_id>/<ref>`, a key-form change to §10.6 and its wrap paths; (3) exempting `.claim` in the fake, a special case in a shared fake.
    - Raised by the design details (DESIGN-DETAILS.md section 6) and the build (KEYS-M2-13; the build's ledger, QD-613).

235. **Format-1 code reads past a head's index_epoch, as it does window bits 4 and 5 (option 1, the recommendation).**
    - Question: §11.6's kinds row named EvsHead's index_epoch among what format-1 code refuses in use, but the code carried it and no format-1 reader looked at it, so a format-1 device pinned before an erasure's CUT would answer FORMAT_UNSUPPORTED for the ref, while one that re-pinned past the CUT would read the ref's format-1 paths with no sign of it.
    - Answer: format-1 code reads past a head's index_epoch: EvsHeadSummary's is ignored and EvsHead's kept, since format-1 writes carry it, and §11.6's kinds row lists them beside the window bits. A format-1 device keeps reading a ref's format-1 files after an erasure's CUT, as FS-72's "serves stored bytes" keeps.
    - Cost: two rows of testdata/evs/reserved_numbers.yml and a reader row in the format-2 sweep; no code change.
    - Not taken: (2) refusing, so a format-1 device answers FORMAT_UNSUPPORTED for every read of a ref whose head summary carries an index_epoch, losing every format-1 file on that ref, the user's main ref when it holds `.ur-index/`, from the first erasure's CUT on.
    - Raised by the build (EVS1-M2-39; the build's ledger, QD-640).

236. **An import carries every history stock git can walk: an imported commit travels as its bytes, and a tree that does not rebuild from its entries travels as its bytes beside the commit that brought it (option 3, the recommendation).**
    - Question: a reader rebuilt every tree from directory names and each child's sealed {mode, oid}, and the codec refused any tree or commit its encoder would not reproduce, yet stock git stores and serves trees with a mode outside git's six, a zero-padded mode or entries out of order, and commits with a late header, forms that older tools left in real histories; such a history imported only after a rewrite that changes every later oid.
    - Answer: an imported commit travels as its bytes, and a tree that does not rebuild from names, modes and oids travels as its bytes beside the commit that brought it (`EvsSealedCommit.trees`); the tree builder uses those bytes after checking that git's reading of them equals the entries it built. The strict codec is asked only of new commits a sidecar makes, so owner decision 81's committer rule stays as strict as it is. Still refused: a tree entry name holding a slash, a tree naming one entry twice, a tag of a tree or blob, and a sha256 repository.
    - Cost: one sealed field, a lenient tree reader and a graph decoder beside the strict codecs, and a tree builder that takes raw trees, all on the desktop tier and in export.
    - Not taken: (1) keeping those forms refused, so a history with one zero-padded mode imports only after a rewrite of every later oid; (2) widening the codec for odd modes and late headers but not zero-padded modes, a wider tree surface for every reader, the committer rule split into two checks that must agree, and the commonest real form still refused.
    - Raised by the design details (DESIGN-DETAILS.md section 8) and the build (the codec's import forms; the build's ledger, QD-598).

237. **A git-mode push carries each blob its commits name and its net change does not as one sealed history record, and no GC takes a segment a retained push introduced (option 1, the recommendation).**
    - Question: a push's cleartext changes are the net change per path, and its sealed metadata held every commit with each intermediate commit's sealed {path, mode, oid} changes, which rebuild every tree and commit oid but no blob, so a blob that an intermediate commit names and the tip's tree does not (a file changed twice in one push, added and removed, or on a merged side branch) was nowhere: export refused such a push, and a syncing device held commits whose trees named missing blobs.
    - Answer: each such blob is carried as one sealed history record, a checkpoint, chunks, or a diff against the same path's blob in the commit's first parent, in a segment the push introduces, located from the sealed metadata by `EvsSealedBlob {git_oid, size, base_oid, file_id, records}`. No entry version's chain names a history record, and no GC may take a segment a retained push introduced.
    - Cost: one sealed message and its locator, about 80 B of sealed metadata and one diff a blob; evs sees one more segment per 8 MiB of history and its padded size, and a million-commit import is about 6 GiB of history records beside 1.1 GiB of entry content.
    - Not taken: (2) a sealed git pack per push, which needs a pack reader on every leg that reads history, a second object format, and compressed sizes that show more of the content; (3) not carrying them, so export and `git fsck` fail on any push of more than one commit that touches a file twice.
    - Raised by the design details (DESIGN-DETAILS.md section 8; the build's ledger, QD-599).

238. **A git-mode push names as sources up to 16 committed versions of the repo's other git-mode refs, which a replaying reader replays first, so owner decision 81's committer rule judges only the commits the push carries (option 1, the recommendation).**
    - Question: the hook holds a new commit, one no ref of the local mirror reaches, to the committer rule, but a replaying reader could not tell new from old, since that depends on the order in which pushes reached one device and evs orders nothing across refs; so a pull of `main` into an agent branch, or a fast-forward of `main` to a colleague's branch, carried other sidecars' commits, which replay refused.
    - Answer: a git-mode push names up to 16 committed versions of other git-mode refs of the repo (`EvsGitUpdate.sources`), chosen by its writer from tips its mirror has applied, and a reader replays each source to that version first. What a source's tip reaches is neither carried nor judged again; everything the push carries is new and held to owner decision 81's committer rule, or listed by the push's own EvsImport. A version is applied only after the versions it names, a cycle of waits is refused, and a ref whose source cannot be replayed waits with no alarm of its own.
    - Cost: a ref's replay may need other refs' histories, read by (ref id, version), which a later FORCE or DELETE of that ref does not remove from evs's history; a merge then carries its merge commit alone.
    - Not taken: (2) carrying everything the ref lacks and letting the pusher vouch for others' commits, so any writer could attribute a commit to another sidecar and the forced identity would stop being a property of the stored history; (3) holding every carried commit to the signer, so no pull, merge or fast-forward of another sidecar's commits could be pushed.
    - Raised by the design details (DESIGN-DETAILS.md section 8; the build's ledger, QD-600).

239. **A part of a push may hold no change when it holds a slice of a spilled section, so sealed metadata larger than the room beside a push's changes can be sent (option 1, the recommendation).**
    - Question: a push in parts is cut by its changes, at most 1,024 entry writes and 1 MiB a part, and sections with no change of their own, sealed metadata above all, spill into the parts' room; a git push of 2,000 commits that touch 30 files is 1.1 MiB of sealed commits and one part's worth of changes, and a part with no change was refused, so it could not be sent.
    - Answer: a part may hold no change when it holds a slice of a spilled section such as sealed metadata. Such parts come after every part that holds a change, carry no changes_root and are no leaf of the statement's root; parts_sha256 covers them as it covers every part; evs records and hashes them and runs no entry check for them.
    - Cost: a rule in protocol/EVS-FORMAT.md, the builder, the part check, the parted change tree and the part and seal routes.
    - Not taken: (2) moving sealed commits past a part's room into segments behind a locator, a second way to read a push's commits for every replaying reader, which then no longer arrive with their statement; (3) capping a push at what fits beside its changes, about 1,800 small commits, which a run of metadata-only commits never leaves room for.
    - Raised by the design details (DESIGN-DETAILS.md section 8; the build's ledger, QD-601).

240. **A conflict branch is made only by settle, published as an owned overlay of the conflicted ref, and removed only by its owner (option 1, the recommendation).**
    - Question: §11.11's restart row moved local commits to a conflict branch whenever an unfinished entry had committed while the local ref no longer equalled old, which made one for a commit that was already the ref's tip, and it said nothing of a local ref that really holds what evs does not, nor of who publishes such a branch and who removes it.
    - Answer: a conflict branch is made only by settle, at the local ref's commit, named `ur/<sidecar_id>/conflicts/<ref's name>/<time>` with the next free second. It is an owned ref of its sidecar, published by the queue as an overlay of the conflicted ref, so the member's other devices see it. The daemon never merges, moves or deletes it; its owner does, with stock git. `ur status` lists each until its ref is deleted, and `evs_conflict` carries the conflicted ref and the branch's name. A ref with 64 conflict branches stops settling, its local ref left alone, until one is deleted.
    - Cost: one push per conflict, and branches that stay until someone looks at them.
    - Not taken: (2) local only, commits on one device's disk that a lost device takes with it; (3) published and deleted by the daemon after a period, commits deleted on a timer, which D-EVS-8 does not allow.
    - Raised by the design details (DESIGN-DETAILS.md section 8; the build's ledger, QD-602).

241. **An EvsImport signs the commits of the one push that carries it, so a reader checks each push of a split import alone (option 1, the recommendation).**
    - Question: §11.8 split an import past 1,024 parts at commit boundaries, each push carrying the import's one EvsImport, so a reader of one of those pushes held the hash of a list it had not seen, covering commits in other pushes; it could not tell whether a commit in front of it was listed, and any writer, who can open the admin's EvsImport from the sealed metadata, could attach it to a push of its own whose commits' committers it forged.
    - Answer: an EvsImport signs the commits of the one push that carries it: tip_oid is that push's new tip, oid_list_sha256 the SHA-256 over that push's carried commit oids in carried order, count their number. The importing daemon signs one for each push as it cuts it, and a push with an EvsImport carries imported commits only. No field changes; a reader checks it against the push in front of it and needs nothing else.
    - Cost: an import of k pushes is k signatures by the admin's device, made as the import runs.
    - Not taken: (2) one EvsImport for the import with its whole oid list in the first push's sealed metadata, 20 MiB for a million commits and state in every reader keyed by import; (3) as written, a split import unverifiable until its last push, with the signature borrowable meanwhile.
    - Raised by the design details (DESIGN-DETAILS.md section 8; the build's ledger, QD-603).

242. **An import whose one first-parent step would pass a push's bounds makes helper refs itself, imports the merged side into them and carries the step's merge commit alone (option 2; the design recommended refusing such a step for v0).**
    - Question: an import is cut at commits of its tip's first-parent line, and a push holds at most 1,024 parts and 1,048,576 entry writes, about a million commits, but one step of that line, a merge joining two histories of a million commits each, can pass those bounds alone, where no cut helps. Should v0 refuse such a step and name the way round, or take the way round itself?
    - Answer: when one first-parent step of an import would pass a push's bounds, the import itself creates helper refs under `ur/<sidecar_id>/import/<id>/<n>`, imports the merged side into them, and then carries the step's merge commit alone, naming the helper refs as sources (owner decision 238); this recurses where a side has such a step of its own. No format changes. A single commit that changes more than 1,048,576 entries stays a hard bound that no option can pass.
    - Cost: a recursive import and refs the user did not ask for, whose naming, cleanup, resume after a kill and failure handling DESIGN-DETAILS.md settles before the import task is built.
    - Not taken: (1) refusing such a step before any evs write, naming the commit and the way round, which leaves one manual step for histories that join very large ones; (3) staged pushes that carry history without moving the tip, staged state in every replaying reader keyed by import and rules for an abandoned stage.
    - Raised by the design details (DESIGN-DETAILS.md section 8; the build's ledger, QD-604).

243. **An overlay holds a directory whole or not at all, so it can remove a path it inherits and list a directory with no evs change (option 1, the recommendation).**
    - Question: an overlay records its base and writes only the paths it changes, a path it holds no version of reading as the base's, but nothing said how it states that an inherited path is gone: a removal needs a standing version the overlay does not hold, a parent's delta a table it does not hold for a directory it only inherited, and a marker would be collected after its window, after which the path would read as the base's again.
    - Answer: the first push on an overlay that adds or removes a child of a directory writes that directory as a creation whose delta lists every child it has in the new tree; later pushes send deltas. A path reads as the overlay's own standing entry; else absent if any ancestor directory the overlay holds does not list the next name; else the base's. No evs change.
    - Cost: one table the first time a directory's names change on a branch, at most 448 KiB, 13 KiB for a directory of 100 names, and none for a change of content alone; a reader of an overlay through evs asks for the path and its ancestors in one request.
    - Not taken: (2) removals on base 0 for overlays, writing markers that collection and the path-epoch copy keep and move on overlay refs, three changes to landed evs code and a marker that lives as long as the ref; (3) an overlay holding its whole tree, so a branch of a 100,000-file repo writes 106,000 entries.
    - Raised by the design details (DESIGN-DETAILS.md section 8; the build's ledger, QD-605).

244. **A tag ref holds no path state and has no base, so a tag of history a ref already reaches is one push with no change (option 1, the recommendation).**
    - Question: a tag is a git-mode ref created IMMUTABLE. Holding a path state like a branch, a tag of an old commit would be an overlay writing the whole difference between its base's tree and the tagged tree, uploading content again, its tokens never moving to a new path epoch nor its content re-checkpointed, since an IMMUTABLE ref takes neither push, while nothing reads a tag's paths through evs.
    - Answer: a tag ref holds no path state and has no base. Its one push carries no change and names, as sources, the refs whose tips already reach its commit (owner decision 238); what its commit reaches beyond those is carried as commits and history blobs (owner decision 237). A tag of anything a branch already reaches is one push with no commit, no change and no upload. Writers and replaying readers refuse a change on a tag ref; a reader that wants a file at a tag reads it through a device with the commits, or resolves the tag's commit to a branch version.
    - Cost: a rule for writers and replaying readers.
    - Not taken: (2) a tag ref as an overlay like any branch, which writes and uploads the tree's difference per tag and keeps its tokens under its creation epoch for life, which a removed key holder can go on testing, beyond `ur evs rekey`'s reach.
    - Raised by the design details (DESIGN-DETAILS.md section 8; the build's ledger, QD-606).

245. **From M3 a push bound to a tainted run carries format 1's reserved tainted bit, and readers honor it, so I-9 holds as written from M3 (option 3, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: I-9 counts tainted runs' writes and §2.19 ships it at M3, but §11.6 and §16.16 gave the push provenance's tainted bit to format 2, at M10, so from M3 to M10, and on repos never migrated, one run's injected file reached another device's agent as `member`.
    - Answer: the bit is already reserved in format 1's sealed push provenance, which format-1 code ignores rather than refuses, so no byte changes and no repo rises to format 2. From M3, `EvsRepo.Write` sets `tainted` in the push provenance when the write's run is tainted, and `evs_read`, `ur://evs` and §16.6's taint row read it from the same sealed metadata that carries EvsImport: a version so marked is `trust: untrusted`, and reading it taints the run first. A push bound to no run, a person's own `git push` included, carries no bit.
    - Cost: taint crosses members' files from M3, not M10, so more runs lose harness evidence sooner; nothing a server sees changes, since the bit is sealed.
    - Not taken: (1) trusting by what each device knows, which leaves a tainted run on one device able to plant a file that reads as `member` on another from M3 to M10, I-9 and §2.8 narrowed to say so; (2) treating every version not written by this run as untrusted on format 1, so nearly every shared-repo read taints and single-device members lose harness approvals in ordinary work.
    - Raised by the build (plan-MCP; the build's ledger, QD-042).

246. **Retention stays expiry, ERASE and BASE at M6, and the reclaim of expired ciphertext moves to Later beside compaction (option 2, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §11.13's gc row deleted "segments no retained push names" while keeping every push statement, so read literally nothing went and evs-4's ttl never ended, and no section defined "retained", while §16.8 and evs-4 promised that GC removes the expired ciphertext.
    - Answer: retention stays at M6 as expiry, ERASE and BASE; the reclaim of expired ciphertext moves to Later beside compaction, so expired ciphertext stays, keyless, until a later GC, as §11.13, §16.8 and evs-4 say. "Retained" is defined for what M2 deletes: a deposit's version is retained until a committed CONSUME removes it, and its segments go 7 d after that once no other version names them. If the reclaim is built, it deletes, 7 d after a BASE, only segments that no entry of its live set and no later version names, by a mark and verify like the drop job's, under holds.
    - Cost: a record-class repo's expired segments stay stored and billed for the repo's life, unreadable once their keys are erased; evs-4's published ttl and §16.8 change.
    - Not taken: (1) building retention GC at M6, which keeps the published ttl and frees segments at the cost of a scan like the drop job's, built before M10 proves one, in the costliest bug class.
    - Raised by the build (plan-EVSB; the build's ledger, QD-047).

247. **Compaction moves to Later, so erased and dropped inline ciphertext and packed segments stay stored and billed for the repo's life, unreadable once their keys are gone (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §11.22 listed compaction for v1, and §2.8, §11 and §20 leaned on it, but no row specified it, and §11.8 deletes packs only whole, so compaction would be a new deletion path.
    - Answer: compaction moves to Later, in §11.22's and §23.4's Later lists, and each "until v1's compaction" reads "until a later compaction, unscheduled" in §11.7, §11.12, §11.13, §20.6, §20.7 and §2.8's evs-4 and evs-12. Erased and dropped inline ciphertext and packed segments stay stored and billed for the repo's life, unreadable once their keys are gone.
    - Cost: those bytes count against storage for the repo's life; §2.8, §11 and §20 change wording.
    - Not taken: (2) designing and building it in v1, new design and peer review before M6's entry and a rewrite of immutable packs in the costliest bug class; (3) building what can be inferred, which deletes ciphertext by an unreviewed mechanism.
    - Raised by the build (plan-EVS1; the build's ledger, QD-053).

248. **A file stays capped at 2 GiB of plaintext through M10, versionless files and git-lfs objects included (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §11.7 said only "The v0 file cap is 2 GiB", while owner decisions 158 and 162 began from a large-object setting and git-lfs, so what stock git-lfs users can store was an unstated product promise.
    - Answer: 2,147,483,648 B of plaintext (512 chunks) through M10. Writers and the git-lfs agent refuse a larger file by name (`EVS_FILE_TOO_LARGE`), so `git push` fails before the ref moves. A later raise to about 8 GiB is a constant and tests, with no format change.
    - Cost: assets over 2 GiB cannot use ur/lfs or a versionless path, and a stock git-lfs push of one fails at the agent.
    - Not taken: (2) raising versionless files and ur/lfs to about 8 GiB at M10, which needs no new fold rule but larger fault, working-set and transfer-agent runs inside M10; (3) raising past about 11 GiB, where four folded versions no longer fit idx/'s 512 KiB, so a new fold rule before format 2 freezes.
    - Raised by the build (plan-EVS2; the build's ledger, QD-233).

249. **A repo uses git's SHA-1 object format only in v0, with the oid's width reserved for SHA-256 (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: no section said whether a repo may use git's sha256 object format, while §11.7 promises exact oids and §22.9's matrix includes the latest git, whose BreakingChanges.adoc (2.56) has Git 3.0 make sha256 the default for new repositories, with no date set.
    - Answer: SHA-1 only in v0, with the width reserved: format 1 carries a 32 B oid and oid_kind, the daemon creates its bare repository with `--object-format=sha1`, and `ur mount add`, `ur evs import` and `git-remote-ur` refuse a sha256 repository, naming it, before any evs write. Head mode's codec and export stay SHA-1 only. Adding sha256 later needs no format change.
    - Cost: a sha256 repository cannot be mounted until a later release, which will bite once Git 3.0 ships its new default.
    - Not taken: (2) both from v0, a second hash through the local tier, hooks, export, the mobile and wasm git codec, vectors and §22.9's matrix; (3) reserving nothing, so a wider oid would need a format change after the freeze.
    - Raised by the build (plan-EVS1; the build's ledger, QD-237).

250. **Working-tree sync and derived shares leave v1's list for Later, since no section says what either is (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §11.22's v1 list named working-tree sync and derived shares once each, with no requirement, row or test: R-EVS-9 and §11.11 cover only a bare repository and stock git, and "derived shares" appeared nowhere else.
    - Answer: both move to Later and leave §11.22's v1 list; git users update a working tree with stock git. If cli/UI.md turns up with a requirement, the owner reads it first.
    - Cost: nothing is promised that is not built.
    - Not taken: (2) specifying them for M6, which needs the owner to say what each is, then new design for dirty trees with its own tests.
    - Raised by the build (plan-EVS1; the build's ledger, QD-276).

## The operator-core seam: owner questions (2026-11-15)

The owner proposed a module of core-service interfaces between server and its extensions, answered the questions it left one at a time, added follow-ups that amend the first answers, and accepted the defaults the orchestrator had stated beside them.

251. **Q-REPO-1, amended: a new operator-core module holds the core services' interfaces, rooted at an Env that creates every service an extension holds, and server's shared value types; server/core implements it, and sidecar's server-hosted code takes it and owns its SQL (the recommendation on every point but one: sidecar.Id aliases operator.Id on every leg).**
    - Question: server imports sidecar to host its engines and sidecar may never import server, yet the engines need server's core services. sidecar/host_service.go's ServiceHost (§4.5, D-REPO-3) declares the host interfaces, which server implements in sidecarhost, evshost, dnshost, mxedgehost and quotahost; ServiceHost holds no database, so each engine's store is implemented in server over Postgres, sidecar features' SQL and migrations live in server, and the host interfaces name connect.Id. Where do the core services' interfaces, the value types both sides use and sidecar's SQL live, and how does a hosted engine reach the services?
    - Answer, in the owner's words: "Where server uses functions in a shared namespace, I want operator-core to use Interfaces that are created from an Env instance. The Env should be the root factory of all services. This is a change from the server approach, because I want extensions to use instances and not a single namespace for services." The end state: server imports sidecar and operator-core, sidecar imports operator-core, operator-core imports connect, and connect imports none of them. Asked the points that left open, the owner chose:
      1. A new repository and module, operator-core (github.com/urnetwork/operator-core, Go package `operator`, since server/core is package core), holds the interfaces of every core service an extension service uses, rooted at operator-core/env.go's Env, the root factory of every service: a database, Redis, blobs and the rest of today's ServiceHost (authenticator, quota, metrics, tasks, push, clock, clock check, service clients, gates, write budget, abuse). It holds no service implementation. Each accessor answers its service or a typed not-granted error, never a nil.
      2. Instances, not a namespace: where server uses package-level functions in a shared namespace (server.Db, server.Tx, its Redis and blob helpers), operator-core declares interfaces whose instances an Env creates, and an extension holds instances, never a package-level service function or global service state. server/core's Env wraps server's namespace functions for now.
      3. operator-core imports connect, which stays independent and imports nothing new. Only the shared value types move from server, those an operator-core interface names or an extension uses: Id, ByteCount, NanoCents, the blob object records and the sentinel errors. Server-internal types stay in server, which keeps aliases of the moved ones.
      4. operator.Id is server.Id moved: `type Id connect.Id`, with server.Id's marshalling (database/sql Scan and Value, JSON, Hash) and its parsing, formatting and comparison delegating to connect. Its pgx codec stays in server/core, registered for operator.Id. server.Id and sidecar.Id become aliases of operator.Id, sidecar's on every leg. The generators stay where they are: server's NewId over connect.NewId, and sidecar's on crypto/rand, returning operator.Id.
      5. server/core implements operator-core: it builds the Env from server's existing services, wrapping sidecarhost, evshost, dnshost, mxedgehost and quotahost, and passes it to sidecar's server-hosted code, the `<svc>service` engines and any Sidecar core a server process runs, which take the Env or the instances they need. Device-side code (the `ur` daemon, the apps, the iOS network extension) takes no Env and keeps its own settings and local stores.
      6. The db interface mirrors server's helpers as methods on instances: callback-style Db and Tx whose implementation owns retries (serialization failures, lock timeouts), the isolation and read-before-begin options, Query, Exec and Batch, Rows that scan into standard types and operator.Id, named args and temp tables, all in operator-core's own types with no pgx type; server/core adapts server's pgx helpers to it. Each process grants it only where allowed: evs and gkm get none, so the T3 test that a planted Postgres touch from evs fails still holds.
      7. Sidecar owns its SQL: its stores live in sidecar over the granted db and touch only sidecar's own tables, and server-owned data (networks, clients, accounts) reaches it through operator-core's domain interfaces. This replaces D-REPO-3's stores implemented by server, and amends owner decision 19, under which server owned the migrations.
      8. operator-core declares the engine contract an extension hands back (§4.5's Engine, HttpEngine and StreamEngine), so server hosts any extension's engines alike, and an Extension interface, an extension's migrations and its engines' constructors over an Env, which server/core iterates, running the migrations, so hosting another extension is one import and one registration.
      9. A separate test-support module, operator-core/coretest, holds in-memory fakes and conformance suites; only test legs import it, server/core runs the suites against the real stack, and every extension reuses the fakes. Sidecar's SQL stores are tested against real Postgres by server's T3 harness, which runs their suites over server/core's db on the private test stack; sidecar never dials Postgres itself.
      10. operator-core is licensed MPL-2.0, copyright 2026 BringYour, Inc., as sidecar, server and connect are.
      11. Timing: the seam is built now: operator-core with ServiceHost's interfaces moved over, the Env, the db interface and the shared value types, Go type aliases left in sidecar and server so existing code compiles unchanged, and server/core building the Env over the existing host packages; new code uses operator-core. The call sites, the move of sidecar's SQL and migrations from server into sidecar, and the fakes' move into coretest come in the build's review phase, the pass of reviews and fixes after the draft of the whole surface, as the settings sweep does.
    - Cost: a new repository and module, its require and replace in every consumer and a release step between connect's and sidecar's; two shapes of the host contract until the review phase moves the call sites. With the alias on every leg, the page Worker's `sidecar_http` leg links connect and gVisor (connect compiles for js/wasm), and the iOS extension's leg links operator-core beside the connect it links through `sidecar/device`, so §4.4's rule that every-leg files never name connect lapses, and D-SDK-19's 41,943,040 B goal with its miss rule's sdk.wasm gate and owner decision 215's 6 MiB extension budget (DESIGN-DETAILS.md 4.2.3) are re-measured with the seam and revisited.
    - Not taken: operator-core importing only the standard library, its own Id converting to connect.Id (the first answer, which the follow-ups replaced); sidecar keeping its own Id type on every leg (the recommendation), which kept connect out of the page Worker; moving server-internal types too; package-level service functions, as server has; keeping sidecar's SQL in server behind each engine's store interface; moving the call sites now.
    - Raised by the owner's proposal of 2026-11-15, settled one question at a time in the orchestrator's dialog (the build's ledger, QD-841, with the owner's follow-ups QD-842 and the orchestrator's defaults accepted as QD-843).

## The build's owner questions on the published list and its rows (2026-11-10 to 2026-11-16)

On 2026-11-16 the owner said: "Accept all recommended decisions going forward. Record the decisions in the design document." The design-records track for §2 and §3 folded the answers below that day, each citing its ledger id: those the owner decided one at a time from 2026-11-10 to 2026-11-15, and the recommendations of 2026-11-15 that the instruction accepted, which the ledger dates 2026-11-15. With them it wrote into §2.8's block every line that owners' answers had added to the published list ahead of a fold (list versions v12 to v25), so the block and the file are one text again.

252. **The published list may run ahead of §2.8's block only by named owner additions, and a design-records track adds the one code-side line a new row or §4 id needs (option 1 of each question, the recommendations).**
    - Question: `metadata_list.yml` is §2.8's fenced block, byte for byte, and only a design-records track edits the design, so two things could not land. A new §2.8 row fails §22.7's schema guard without its `planned` line in `testdata/metadata/fields.yml`, and a new §4 id fails `check/`'s evidence matrix without its entry, both outside a design-records track's files. And a code track whose owner-answered field needed its row's words in the list before release (I-18) could not write them without editing the design.
    - Answer: a design-records track that adds a §2.8 row or a §4 R-, D- or Q-REPO id adds, in the same commit, the line its guard needs and nothing else outside the design files: the row's `planned` line, at the milestone that first serves its value, or the id's evidence entry; the row and its line are one fact. A code track may add an owner-answered row's words to `metadata_list.yml` ahead of the fold, with an entry in `check/`'s list of additions naming the question that holds the answer; where no owner wording exists it adds the field's `pending` line in its metadata rows instead. Design-records later writes the words into §2.8's block and the entry leaves, the guard failing if the design and an entry both hold the line. So the public list stays the design's block plus named owner additions (D-TRUST-4), and only design-records edits `design/source/`.
    - Cost: one line of test data or test code per new id in a design-records commit; between a code track's addition and the fold the list's words are in the file and the guard's entry, not yet in DESIGN.md.
    - Not taken: a code track adding the guard's line and the design text together; folding a new row into an existing one, which left Cloudflare unlisted; a code track editing §2.8's block itself; keeping only `pending` lines until a fold, the list lagging the wire.
    - Raised by the build (the build's ledger, QD-683, decided 2026-11-11, and QD-886).

253. **smtp-2 lists a proof per part under a named key set, and a new row, smtp-7, lists what the key set path on ur.io sees of a prover host's fetch (option 1, the recommendation).**
    - Question: the mail proofs' detailed design (DESIGN-DETAILS.md section 3) binds proofs as parts to one key part, under a key set the sidecar fetches from ur.io, since the transcripts are about 0.9 GiB a key set, too large for the `ur` package. smtp-2 listed "proofs π1 to π3 and, in DATA mode, one per later body part", and no row said what the fetch shows a server (I-18).
    - Answer: smtp-2 (smtpedge, connection memory only) lists the id of the key set the sidecar proves under; a proof per part, the key part, one per envelope group, one per header record and, in DATA mode, one per body record, each with its reply count and, once, the header block's record count; and the key commitment and scan-state commitments the sidecar publishes, uniformly random group elements that depend on no key and no plaintext. smtp-7 is new: per fetch the key set path on ur.io sees the client's address and time, the key set's id and the names of the files fetched, which mark the address as a mail prover host, on which key set and with which TLS families prepared; the request carries no account, token, cookie or sidecar id, and its ttl is that of ur.io's other static downloads, which the ops owner confirms against how ur.io serves and logs its static files (EX7). The fetch stays off until smtp-7 has landed. Key sets are fetched, not bundled.
    - Cost: a prover host's address is marked as one to whoever serves ur.io's static files, Cloudflare included (ext-11).
    - Not taken: (2) shipping the transcripts in the `ur` package, about a gigabyte more for every install.
    - Raised by the design details (DESIGN-DETAILS.md 3.8; the build's ledger, QD-716).

254. **A certificate row keeps its issued chain, a requested revocation's reason and the time of its latest state, and a failed order's row goes 30 days after its failure (option 1 of each question, the recommendations).**
    - Question: cert-1 named chains only for Team custom domains, yet `GET /tls/cert-order/<id>` answers a chain to a device that polls after a restart or while it was offline, and a revocation requested by a route is made later by a sweep, which needs its reason (`keyCompromise` or `cessationOfOperation`). And cert-1's ttl, 30 d after expiry or revocation, had nothing to read for a revoked row, whose validity ends later than its revocation, and named no time at all for a failed order.
    - Answer: `network_tls_cert` keeps a URnetwork-zone row's issued chain and a requested revocation's reason until the sweep's revocation reaches the CA, and gains `state_time timestamp NOT NULL`, set with every state change, in MG5's CREATE while the group is pending, so no running release sees a migration. cert-1's sees gains "the time of its latest state; issued chains until 30 d after expiry or revocation, and a requested revocation's reason", and its ttl reads "30 d after expiry, revocation or failure": the purge reads `not_after` for an expired row and `state_time` for a revoked or failed one, and §13.8's rebuild of a lost `{tcb_}` key may read an order's admission from it. The 30 d is a setting. Neither value shows anything a CT log (cert-2) or a CA's CRL does not publish.
    - Cost: a list version, two columns and a timestamp.
    - Not taken: re-downloading the chain from the CA's certificate URL on each GET, itself a stored value with no row; the reason folded into the row's state; revoking inside the request handler, which fails the route in a CA outage; purging a revoked row at `not_after` + 30 d, past the published ttl; deleting part of a revoked row at revocation.
    - Raised by the build (TLS-M5-05 and TLS-M5-14; the build's ledger, QD-741 and QD-742).

255. **evs-5's ttl says a dead push's own slots stay until the repo is shredded while evacuation's delete of them is off, in the release that brings slot origins (option 2; the build offered either).**
    - Question: evacuation deletes a dead record's own slots by each slot's origin (DESIGN-DETAILS.md section 14), and that delete is off by default in the release that brings origins and on in the next, since an evs of the release before writes no origin. evs-5's ttl described only the delete on, "until evacuation finds it dead, at most about 26 h after its batch", so the published list overstated deletion for one release.
    - Answer: evs-5's ttl gains the clause "while evacuation's delete of them is off, in the release that brings slot origins, until the repo is shredded", beside the text for the delete on, so the list is exact for the release that ships the switch off by design; a later list version removes the clause when the switch turns on.
    - Cost: a list version now and another when the switch turns on.
    - Not taken: (1) keeping the text and a rule that no Gn-out ships with the switch off unless the list says the slots stay, the branch overstating deletion meanwhile.
    - Raised by the build (the build's ledger, QD-884, which also answers evs-slot-interim-dead-slot-ttl).

256. **The evs rows gain words for the wire fields their families already hold; no field is dropped and no store is added (option 1 of each question, the recommendations).**
    - Question: §22.7's guard held a set of evs.proto fields as pending because no §2.8 row named them: the CONSUME mark, a repo's creator, a wrapped key's generation, a name table's fold version, a read's pins and an answer's retry delay and outcome, a quota refusal's retry delay and upgrade flag, format 2's read states, purge-list mark and dry-run progress, and the batch place a `pidx/` record keeps.
    - Answer: each row says the value in its next version, in these words. evs-3: "an ingester's CONSUME mark (consumed_through, the version through which its deposits are consumed), which a deposit's head in a push's answer repeats". evs-12: "a CONSUME's consumed_through" beside its flags, and "a purge list's mark past 2,048 ids or the record's 1 MiB" beside each record's purge candidates. evs-25: "its creator's sidecar_id", set once at the repo's creation. evs-5: "each wrapped key's generation, in clear beside it". evs-11: "the version the table is folded through (names_through)". evs-7: "a read's pin version, the version of a path it asks for and whether it asks for a fresh head; each answer's retry delay, a push's outcome where evs cannot say it committed, and a framed reply's end". evs-9: "a quota refusal's retry delay and whether a purchase lifts its limit". evs-28, for format 2: "what a read answers for a version a drop holds or took or collection removed: its read state (collected, drop pending, dropped), the drop's id, not_before_ms and version", in the existing row, no row being added for it, and in its dry-run clause "its state and progress, and per path whether the client's list matched and the resolved count, and young bytes". evs-17: "each record's place in the batch it left (§11.8's EvsPlace)", the 20 B place a `pidx/` record keeps so that a seal, which names its parts by place, finds a part after evacuation deletes the batch; it shows only what evs-3's window entry showed for the same record. Each field's `pending` line then quotes its row.
    - Cost: none beyond the list's version; nothing new becomes visible to a server.
    - Not taken: dropping the fields, which the design or an owner's answer requires; a new row for format 2's read states; finding a seal's parts by ref, version and part number, a change to the seal's record layout.
    - Raised by the build (EVS1-M2-01, EVS2-M10-01 and EVSB-M2-07; the build's ledger, QD-910, QD-923 and QD-932).

257. **A segment cluster's PUT rate comes from the evs processes' own reports in `{nvb_<cluster>}`, which evs-10 names (option 1, the recommendation, as built).**
    - Question: the hdd loop's gauge of segment PUTs a second, `urnetwork_filecluster_hdd_puts{cluster}`, needs a source, and the reports the evs processes write for it are a Redis value no row named.
    - Answer: each evs process counts the segments the segment cluster stored for it, a PUT that returned 200, a 412 re-upload or a refusal counting nothing, and every 5 s writes its random 16-byte process id, its start time, the time and its count since its start as the field `puts:<process>` of `{nvb_<cluster>}`, with a 15 s ttl; the lease-holding hdd loop sums each process's rate into the gauge and deletes a report past its ttl. The report names no host, network or repo. evs-10's sees gains "and each evs process's 5 s count of the segments stored for it since its start, which the hdd loop sums into §19.8's hdd_puts", and §19.6's hdd row says the loop sums the reports beside the drive counters it reads.
    - Cost: one clause in each row.
    - Not taken: (2) MinIO's own request metrics through the storage hosts' exporter, which needs MinIO's bearer token on each storage host and counts PUTs that are not segment uploads.
    - Raised by the build (EVSB-M2-07; the build's ledger, QD-934).

258. **Each file cluster's readiness object, `sentinel/_`, has its own row, evs-30 (option 1, the recommendation).**
    - Question: §19.4 makes evs ready only when each cluster's sentinel is readable, an object xops writes into each cluster's bucket, and no §2.8 row listed it.
    - Answer: the object keeps §19.4's check, that this block's own credentials reach this bucket, and gets the next free evs row: xops writes it at provisioning, and evs's, gkm's and taskworker's hosts read it, a HEAD every 30 s with the block's own credentials; its store is `sentinel/_`, one fixed key in each file cluster's bucket; it holds a constant body and no network, repo, user or client id; it lives the cluster's life, written once and never rewritten; its owner is §19.6. §11.8's keys row lists `sentinel/_` among the families, none of which it prefixes. A missing or unreadable sentinel reads not ready.
    - Cost: one row and its `planned` line.
    - Not taken: (2) reading readiness from an object that already has a row, which loses the check of the block's own credentials.
    - Raised by the build (EVSB-M2-01; the build's ledger, QD-918).

259. **api-14 names the legal and engineering sign-off ids that `legal_request` keeps (option 1, the recommendation).**
    - Question: §21.10 requires legal and engineering sign-off for a production, and `legal_request` keeps who signed, `legal_signoff_id` and `engineering_signoff_id`, each a staff member's opaque id from abuse-staff.yml, as a reviewer id is. api-14 named reviewer ids and not these.
    - Answer: api-14's sentence on reviewer ids reads "with a reviewer id, the staff member's opaque id and never a customer's, on each read, review and appeal decision, and the legal and engineering ids that sign a production off", so the published list says every staff id it keeps.
    - Cost: one clause.
    - Not taken: (2) reading "productions" as covering who signed them, the list then keeping a staff id it does not say it keeps.
    - Raised by the build (ABUSE-M5-03; the build's ledger, QD-916).

260. **api-13 names the tier's Redis cache key, api-11 an OAuth client's creating member and api-3 a verified domain's TXT challenge (option 1 of each question, the recommendations).**
    - Question: three values the Team and quota tables hold were only implied by their rows: the tier cached in Redis under `network_tier_versioned:<network_id>`, `network_oauth_client.creator_member_id`, and the TXT value a domain's verification checks.
    - Answer: the tier's cache key stays a key of its own, holding `<tier>:<version>` for 60 s, so `pro_versioned:`'s value format, which both releases match during a rolling deploy, does not change; api-13's store gains "Redis network_tier_versioned:<network_id> (the tier, cached 60 s)" and its ttl "tier cache 60 s". `creator_member_id` stays, a member_id, so `client_credentials` scopes are intersected with the creator's for the client's whole life (§7.5) and a re-joined creator's clients do not regain reach; api-11's sees reads "network OAuth clients (hashed secret, scopes, creating member)". api-3's reads "verified domains (domain, TXT challenge, verification and daily check times)", the challenge being the value `_urnetwork-challenge.<domain>` must hold. A webhook's delivery cursor and a SCIM change's kind and detail are covered by api-8's "SIEM webhook endpoints and deliveries" and api-3's "SCIM changes awaiting an admin" as those words stand, and no webhook key column is added, since api-8 names each webhook's signing key as derived.
    - Cost: none beyond the list's version; each value is already disclosed or one the server must hold.
    - Not taken: treating the tier cache as covered by Pro's existing cache; moving the tier into `{sq_<network_id>}`; reading a client's creator from its admin event, which ages out at 400 days while the client lives until revoked.
    - Raised by the build (QUOTA-M1-02 and TEAM-M6-01; the build's ledger, QD-939 and QD-940).

261. **`POST /network/enroll` is limited per auth key and per caller address through Redis attempt histories, which api-11 shows (option 1, the recommendation, as built).**
    - Question: §7.8 limits enrollment per key and per address, and the code keeps the attempts in Redis as every other Public route does; no row showed those histories.
    - Answer: the route stays limited through `server.CheckIpRateLimitAttempt`'s attempt histories: one keyed by the caller address's peppered hash, never the address (I-13), and one keyed by the auth key's id, each holding attempt ids and times for the lookback, 10 minutes by default. api-11's sees gains "enrollment attempts per auth key and per caller address hash, for 10 minutes (§7.8's limits; keyed by the key's id and the address's peppered hash, no address held)", its store "Redis enrollment attempt histories", and its ttl "enrollment attempt histories 10 min".
    - Cost: one clause in each of the row's three fields.
    - Not taken: (2) limiting per key only through the key's own row and per address in api's process memory, weaker limits that every api instance counts separately and that still need a row.
    - Raised by the build (TEAM-M1-04; the build's ledger, QD-951).

262. **A config head's fold records include the BASE entries, so the log's chain through the fold is a function of the genesis and the head (option 1, the recommendation).**
    - Question: the build's fill for the config head's fold record format had its records run in position order with no BASE. A_n hashes every entry, bases included, so a reader holding the genesis and a head could not recompute the chain through the folds: every BASE position was a gap. A new full device starting at a base, and a reader that fell behind its base pins' 30 days, then rest on the base's signer being a config writer in the base's own rows.
    - Answer: a fold's records include the BASE entries in (after, folded_through], each with its Signed ProjectionHeader as its body, ignored by compile and compared by the head check like any record, so the chain A_1..A_folded_through is a function of the genesis and the head. A new device binds the head's pruned history to its invite's genesis, and a far-behind reader links its last pin to the retained run through the head. This amends the fill before the format freezes; the config head's parser, writer and anchor are built to it.
    - Cost: about 400 B a base in the config repo, and one more record kind in the head's parser and the BASE check.
    - Not taken: (2) keeping the fill, a far-behind full reader anchoring its restart on the signer the rows it restarts from name, bounded by no hash chain.
    - Raised by the design details (DESIGN-DETAILS.md section 5; the build's ledger, QD-627, amending QD-456's fill).

## The build's owner questions on repositories, releases and the build (2026-11-06 to 2026-11-16)

The design-records track for §4 folded the answers below on 2026-11-16, each citing its ledger id: the owner items of that section accepted in bulk on 2026-11-06 (263-266, 269-271), those the owner decided one at a time from 2026-11-11 to 2026-11-15, and the recommendations of 2026-11-15 that the owner's instruction of 2026-11-16 accepted, which the ledger dates 2026-11-15. A decision that groups several answers carries its latest answer's date.

263. **The mlswg's 16 MLS vector files stay committed in `testdata/mls/mlswg/` (option 2; the build recommended fetching them at test time and committing none until the mlswg grants a license).**
    - Question: §4.4 and §10.4 run every mlswg vector file covering a v0 feature under suite 0x0001, but the mlswg's repository carries no license, §4.7 refuses unlicensed modules, and the 16 files had already landed in the `sidecar` branch's history.
    - Answer: the files are committed in `testdata/mls/mlswg/` with their SOURCE and SHA256SUMS, as §4.4 and §10.4 say, and stay in git; no history is rewritten and no test fetches them. They are test data, never a required or linked module, so §4.7's list and `dependencies.yml` need no exception.
    - Cost: unlicensed test vectors of an IETF working group sit in a public repository.
    - Not taken: (1) keeping only SOURCE and SHA256SUMS in git, a `make mls-vectors` step fetching the files, the owner asking the mlswg for a license, and an exception to rewrite the landed history.
    - Raised by the build (mls-base and plan-KEYS; the build's ledger, QD-002).

264. **A release is promoted, not every build signed: the two holders sign a chosen release's sums offline, and ur.io publishes them with a pointer `install.sh` reads (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §4.10 has `SHA256SUMS` signed by an offline two-person Ed25519 key, and the release pipeline runs unattended and almost daily, so a signature on every release would stop each one for two people.
    - Answer: every release builds `ur`'s artifacts and an unsigned `SHA256SUMS` as ordinary assets, and run.sh waits for no one. When both holders pick a release they sign its sums offline, and a commit on mmm publishes `SHA256SUMS`, `SHA256SUMS.sig` and `latest.json` under `https://ur.io/recurd/ur/`; `latest.json` is listed in the signed sums, and `ur-promote.zsh` never moves it backward. `install.sh` reads that pointer, verifies, and fetches the artifacts from the GitHub release. No private key touches the build host, a repo or vault.
    - Cost: only promoted releases install through `install.sh`; a fresh install cannot tell an older signed pair from the newest, so ur.io could roll a new install back to an older signed release, which §4.10 states.
    - Not taken: (2) stopping each release until the holders upload a signature, which also holds the apps' releases; (3) signing in the run with an online key on the build host, neither offline nor two-person.
    - Raised by the build (plan-REPO; the build's ledger, QD-017).

265. **A copy of the `ur` command sketch, cli/UI.md, goes to `sidecar/design/UI.md`, and its spellings replace the build's own (the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: DESIGN.md cites cli/UI.md for `ur`'s commands, and the file sits at `urnetwork/cli/UI.md`, outside every git repository, on no path the build can read.
    - Answer: a copy is put at `sidecar/design/UI.md`. Until it is there the build keeps the spellings it filled in (`ur keychain pass` and `ur lock`, `--replace` on `ur login` and `ur connect --token`, `ur login --recover`, `ur daemon --port` from 17000) and what DESIGN.md quotes for every other command; the copy's spellings then replace those, each a one-line rename.
    - Cost: the sketch becomes public with the repository's other design documents (owner decisions 117, 118).
    - Not taken: building on the fills alone, the sketch staying outside every repository.
    - Raised by the build (plan-CORE; the build's ledger, QD-024).

266. **Proving key sets are downloaded on first send from a public path on ur.io, pinned by hash in the release, and never shipped in the `ur` package (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: `smtpproof`'s proving keys and setup transcripts are gigabytes across its shapes, and no section said where a sending desktop gets them.
    - Answer: keys and transcripts download on first send from a public path on ur.io, pinned by hash in the release; the host verifies the transcript once per release and caches it; the fetch carries no token and no account. §2.8 lists what the path's host sees, the fetching address, which marks a prover host (smtp-7, owner decision 253). The 20 shapes are cut to what M7's census justifies before the first production setup.
    - Cost: a download and a disk cost on every sending desktop, a slow first send, and a prover host's address marked to whoever serves ur.io's static files.
    - Not taken: (2) shipping the keys in the `ur` package, a package of gigabytes; (3) a universal setup serving every shape, at several times the proving cost against a speed gate already at risk.
    - Raised by the build (smtpproof; the build's ledger, QD-123).

267. **server's competition graph and sn's release gates take sidecar as a repository before the first merge to `main`, the competition through new producer releases under the identifiers the build chose (option 1 of each question, the recommendations; the first accepted in bulk on 2026-11-06).**
    - Question: server's competition evaluator and sn's release gates each hold a closed list of the repositories a build's sources come from, ten and thirteen, and sidecar is in neither, though server and sn compile it from M0. The evaluator's programs are sealed by hash, its source ledger pins every repository per generation, and one historical pin did not match the tree's file.
    - Answer: both lists take `sidecar` in one change landing with M0's Gn-out, before server and sn merge to `main`: a fourteenth release repository with a new `sidecar_go_source_hash`, and an eleventh competition repository with an additive migration. The evaluator takes it through new producer releases, as minimum-work and work-coverage were added: six program files with sidecar last in their repository lists (evaluator-sidecar.sh, evaluator-minimum-work-sidecar.sh, evaluator-work-coverage-sidecar.sh and the three prepare-round-baseline programs that pin them), new dependency maps, and the selector `source_graph_policy`, whose value `sidecar/1` means the eleven repositories and whose omission the ten, an empty, null or unknown value refused. The historical producers and their pins stay byte for byte, except that the controller's entry for evaluator-work-coverage.sh is corrected to the tree's file, which is the ten-repository competition's qualified release and the sidecar producer's lineage. The source ledger stays strict: once the eleven-repository release is in use every epoch and generation pins sidecar, so it opens only with a new ledger, at a season boundary or by an explicit re-baseline. The owner qualifies the release on the evaluator hosts with the go1.27.4 re-qualification (owner decision 272); until then the evaluator stays at ten repositories and fails closed on a server commit that needs sidecar.
    - Cost: a competition epoch boundary and a lock format change; server's `main` is not a competition epoch's source between the merge and the qualification; a season cannot switch midway, and once deployed the control plane on `main` cannot serve a season of the ten.
    - Not taken: holding server's and sn's merges until an epoch and the testnet gate close; merging them at M0 without the two go.mod lines; a ledger whose earlier generations keep the ten repositories; keeping the controller's stale pin.
    - Raised by the build (the consumer wiring and the competition's producers; the build's ledger, QD-128, QD-769, QD-874, QD-875, QD-877).

268. **A Gn-out merges the commit set recorded at its gate, never the tip, and every Gn-out merge of connect waits for FS-125's sweep (option 1 of each question, the recommendations; the first accepted in bulk on 2026-11-06).**
    - Question: the build runs M0-M10 straight through (owner decision 194), so by the time a Gn-out is approved its `sidecar` branches have run past that milestone, and §4.8 did not say which commits merge. C19's window accounting then landed on connect's `sidecar` branch eight milestones early, off by default, while §4.17 wants FS-125's sweep in connect's own tests before C19 reaches `main`.
    - Answer: each gate's pinned commit set is recorded when its local checks are reported, and an approved Gn-out merges that set, never the tip, in §4.8's order; a later milestone's merge brings the rest, and a group's migration registration (D-OPS-6) is the one commit on top of the set. §4.17 holds to the letter at every gate: `TestX9ReadyForMain`, which the merge runs before any recorded commit reaches connect's `main`, refuses C19's marker while connect's tests hold no FS-125 sweep, so the sweep is built ahead of its milestone, before M1's Gn-out, and the sdk, sidecar and server merges behind connect's wait with it.
    - Cost: one record per gate; M10's sweep in connect's tests is owed before M1's merge.
    - Not taken: merging the tip at each approved Gn-out; holding every merge until M10's build ends; a hand-picked commit set that leaves C19 out; merging default-off C19 code unswept.
    - Raised by the build (design-records and REPO-M1-01; the build's ledger, QD-131 and QD-929).

269. **A new connect change, C20, lets a device fetch DNSSEC records over DoH, and `strict_chain` is true only when the device validates the whole chain itself; the validator moves from M9 to M7 (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §15.5's `strict_chain` claims a customer-signed MX-to-TLSA chain, but connect's `DohCache.Forward` asks for no DNSSEC data, so a receiver could not show it.
    - Answer: C20, `DohCache.ForwardDnssec(ctx, qType, domain)`, sets EDNS0's DO bit on `Forward`'s query and returns the raw response: generic, additive, off by default, tested in connect and merged to connect `main` first (D-REPO-5). The device fetches MX, TLSA, DS and DNSKEY with RRSIGs and validates to its embedded root anchors, and `strict_chain` is true only when that passes for every MX host of every recipient domain and the host's TLSA, with this key, in zones outside `<root>` and bringyour.com. The chain's wire parser and validator move from M9 to M7, since FS-33 gates M7's exit, and ext-3 lists the DS and DNSKEY lookups.
    - Cost: one more connect change, merged first; DoH resolvers see the added lookups.
    - Not taken: (2) the device sending its own RFC 8484 queries outside connect's resolver policy; (3) trusting the AD bit from two public resolvers.
    - Raised by the build (plan-MAIL; the build's ledger, QD-145).

270. **The minio fork joins the warp, config, vault, xops and mmm group in the merge order, and its `master` plays `main` (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: owner decision 195 put D-OPS-20's MinIO build in a new fork with a `sidecar` branch, and neither the branch policy nor §4.8's order named it; its default branch is `master`.
    - Answer: minio joins that group in §4.8's order and the branch policy, and `master` plays `main`. Its weekly merge in is a no-op while upstream stays archived. xops pins a commit of the fork in place of playbook-minio-clusters.yml's `minio_commit`, and that commit is on the public fork before a host runs it, as owner decision 195 keeps the AGPL source in one public place.
    - Cost: none beyond the note that this repo's default branch has another name.
    - Not taken: (2) a `main` created in the fork beside upstream's `master`; (3) the fork outside the order, xops pinning a commit of its `sidecar` branch.
    - Raised by the build (design-records; the build's ledger, QD-238).

271. **X11 joins §4.7's allowed licenses, read as MIT's text plus only its no-advertising clause (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: src.agwa.name/tlshacks, connect's ClientHello parser, is on every connect leg under MIT's text plus a clause that bars advertising with the author's name, which §4.7's list read as custom, so `make check` passed only by a one-module exception.
    - Answer: X11 is allowed for any module, defined as MIT's text plus only that clause, so `check/` pins both texts, lets that one id through its refused phrases and drops the module's exception; `dependencies.yml` keeps `X11`, the closest SPDX id.
    - Cost: one more license id in §4.7's list.
    - Not taken: (2) allowing the one module by name, every later X11 module coming back to the owner; (3) refusing it, connect first replacing tlshacks.
    - Raised by the build (make check; the build's ledger, QD-240).

272. **Every repo moves from Go 1.27.3 to 1.27.4 for GO-2026-6859, server's lock follows by one authorized hand edit and re-pin, and two measurement harnesses stay on 1.27.3 until re-qualified.**
    - Question: GO-2026-6859, an HTTP/1 server crash in net/http, fails `make check`'s govulncheck rule under go1.27.3, which every repo pinned. server's source-graph lock names the go line and only the owner edits it, and two harnesses require go1.27.3 for their frozen baselines.
    - Answer: one coordinated change moves the go directive in every go.mod of connect, sidecar, sdk, server and sn, any toolchain line, the build images' Go base, `check/`'s rules that name the version and R-REPO-6's and §4.7's pin to go1.27.4; `check/` accepts no advisory, and the toolchain comes through the module proxy, checked against the checksum database. D-TEST-15's one-toolchain rule holds, since x/text chooses its tables by go1.27. Once the bumps land, lock.yml's go line is set to 1.27.4 and the siblings re-pinned, the one hand edit and re-pin the owner authorized; otherwise both stay the owner's. Server's competition evaluator and the tests repo's perf runner stay on go1.27.3 so their baselines stay comparable, and move when the owner re-qualifies them, at the latest before sidecar merges to `main`.
    - Cost: on these branches the evaluator image cannot build server's module and a perf run fails its preflight until the re-qualification.
    - Not taken: an advisory exception in `check/` while staying on go1.27.3; moving the two harnesses with the repos, their records no longer comparable.
    - Raised by the build (TEAM-M2-21 and the bump's track; the build's ledger, QD-674, QD-697 and QD-698).

273. **A design-records fold that writes a field into a proto fence drops that field's line from protocol's fence additions in the same commit.**
    - Question: protocol's fence test holds every .proto declaration to its fence in DESIGN.md, a field the code declares ahead of a fold sitting in the test's additions lists. Writing that field into its fence fails the test until its line leaves the list, which is test code, outside a design-records track's files.
    - Answer: a design-records track that writes a field into its DESIGN.md proto fence drops that field's line from protocol/design_unfenced_test.go's `testFenceAdditions` or `testFenceValueAdditions` in the same commit, touching only those entries. The fence rule stands: a fence never moves ahead of the code. Answered with owner decision 252's rule for a new row's or §4 id's guard line.
    - Cost: one line of test code per folded field in a design-records commit.
    - Not taken: a code track editing the fence; leaving the fence behind the wire for good.
    - Raised by the build (the fold of §17 and §18; the build's ledger, QD-684).

274. **`sidecarctl`, the one binary for every operations command this build adds, lives in server, not in the sidecar repo.**
    - Question: the owner put every new operations command in one binary, `sidecarctl`, at first a module of the sidecar repo. §4.7's license list and §4.4's layering let no module there link server's model or an engine package, so the commands that read Postgres or schedule an engine's task could not be built.
    - Answer: `sidecarctl` moves to server/sidecarctl: still one binary for every operations command this build adds, beside the model code its commands call and under server's own dependency, license and layering rules. The certs commands already built move once, with their tests and `check/`'s rows; `dns census`, `evs purge-turn-on`, `dns restoring`, `dns restore` and `dns ceremony` are built there, and later commands that read the database (`sidecar restore`, `network sidecar-limit`, the abuse commands) go there too. Existing `bringyourctl` and `warpctl` commands stay where they are, and the customer-facing `ur admin` commands stay in `ur`.
    - Cost: the operations binary is server's, built and released with it.
    - Not taken: a second binary in server for the commands that need it; widening the sidecar repo's license and layering rules for one module.
    - Raised by the build (DNS-M0-01, OPS-M10-01 and DNS-M5-15; the build's ledger, QD-750).

275. **The `ios_extension` leg's seed rule stands as written: a file it takes wrongly is renamed, and a declaration the closure needs is moved, never the rule narrowed or a tag dropped (option 1 of each question).**
    - Question: `check/` seeds the `ios_extension` leg from every Forwarder file, the root's `bridge_forward*` among them, and holds the leg to the Forwarder's and the compiler's closure (owner decision 197). The sidecar role's forwarding setup was named bridge_forward_setup.go, so the rule took it for a Forwarder file, and the closure took evs_git_build.go, tagged `!ios_extension`, for one variable's initializer.
    - Answer: the forwarding setup never runs in a VPN component, so it leaves the prefix, as bridge_setup_forward.go, the daemon's port forwards staying in bridge_daemon_forward.go; `EvsGitEmptyTreeOid` moves to evs_git_object.go, so evs_git_build.go keeps its tag and leaves the list. The regenerated list is exactly the Forwarder's and the compiler's closure, with no gate, filer, ACL engine or record file in it, and the rule still fails closed for a Forwarder file tagged out by mistake.
    - Cost: a rename, a four-line move, and one 20-byte variable with its hash at start on the extension's leg.
    - Not taken: narrowing the seed rule to named files; removing evs_git_build.go's tag, the tree builder joining the extension.
    - Raised by the build (BRIDGE-M4-20 and its fix track; the build's ledger, QD-811 and QD-866).

276. **Amending owner decision 251: on the page Worker's leg `sidecar.Id` stays its own type, a twin of `operator.Id`, and `operator.Id`'s JSON decode refuses what either id refused before the seam (option 1 of each question, the second as built).**
    - Question: owner decision 251 made `sidecar.Id` an alias of `operator.Id` on every leg, so the page Worker's sdk.wasm linked connect and gVisor through it. And server.Id's JSON decode was looser than sidecar's, so the one moved type had to choose.
    - Answer: on the `sidecar_http` leg only, `sidecar.Id` stays its own `[16]byte` type with methods and encodings identical to `operator.Id`'s, a build-tag twin of id.go, so the browser build links no connect or gVisor and §4.4's rule that the leg names no connect holds again; every other leg keeps the alias. The page Worker runs no engine and takes no `Env`, so nothing on that leg needs operator-core. `make size` then measures about 57.8 MB unstripped; D-SDK-19's 41,943,040 B goal stays a recorded slip and the 74,965,628 B gate stands. `operator.Id`'s `UnmarshalJSON` refuses everything server.Id or sidecar.Id refused: server's null and length refusals keep server's words, sidecar's (an unquoted value, a separator other than a dash, bad hex) answer `ErrInvalidId` without echoing input (I-13), and every refusal matches `operator.ErrInvalidId`. Well-formed ids decode as before, encodings are byte-identical, and the Scanner and Valuer stay server's exactly.
    - Cost: two id declarations to hold equal, by a test; server accepts fewer malformed inputs than it did, none of which a conforming encoder produces.
    - Not taken: the alias on the page Worker's leg, at connect's IP stack in every page; keeping server.Id's looser decode.
    - Raised by the build (the operator-core seam; the build's ledger, QD-856 and QD-887).

277. **§4.7's legs are sdk's table, which lists every target gomobile binds with the tags gomobile adds (option 1, the recommendation).**
    - Question: sdk's leg table listed only the arm64 targets, so `make check` never read or compiled sidecar for 32-bit android/arm, android/amd64, macos/amd64 or the simulator, which sdk/build/Makefile binds.
    - Answer: the legs stay sdk's table (sdk/dependency_boundary_test.go's `messagingBoundaryLegs`), and that table lists every target sdk/build/Makefile binds, each with gomobile's tags: android/arm and android/amd64 beside android/arm64, iossimulator/arm64 beside ios/arm64 (the `ios` tag), macos/amd64 beside macos/arm64 (the `macos` tag), and the extension bind's slices likewise. sidecar's `check/` mirrors the table and fails a row of sdk's with no leg here, so every rule reads sidecar, and the compile test builds it, for each. One list serves sdk and sidecar.
    - Cost: more legs in every `make check`.
    - Not taken: `check/` adding gomobile targets of its own, a second list to keep.
    - Raised by the build (make check; the build's ledger, QD-908).

278. **The release step keeps `third_party/` at the repository's top beside `v2026/` (option 1, the recommendation).**
    - Question: the release moves the root's tree into `v2026/`. The patched go-smtp fork and the mox subset are modules of their own under `third_party/`, which cli's and mlsinterop's replaces reach as `../third_party/X`; moved into `v2026/`, those replaces pointed at nothing.
    - Answer: `third_party` joins the names the release step gives `go_mod_fork`, as `design/` does, and `check/`'s release pattern, which mirrors them. On the release branch the root's replace is rebased to `../third_party/X`, cli's and mlsinterop's stand, smtpproof's becomes `../../third_party/X`, and server's, sn's and sdk's `../sidecar/third_party/X` keep resolving. The root's module zip leaves the forks out either way, so a consumer of the tag links upstream go-smtp and refuses, closed. The release fixture runs over a tree that holds `third_party/`.
    - Cost: one more name in the release step and its mirror.
    - Not taken: moving the forks into `v2026/` and rewriting each nested module's replaces at release.
    - Raised by the build (MAIL-M5-02; the build's ledger, QD-920, on the fork QD-193 added).

## The build's owner questions on the sidecar core and the subprotocol (2026-11-06 to 2026-11-16)

The design-records track for §5 and §6 folded the answers below on 2026-11-16, each citing its ledger id: the owner items of those sections decided or accepted in bulk on 2026-11-06 (279-285, 295, 296), those the owner decided one at a time from 2026-11-11 to 2026-11-15, and the recommendations of 2026-11-15 that the owner's instruction of 2026-11-16 accepted, which the ledger dates 2026-11-15. A decision that groups several answers carries its latest answer's date.

279. **SSHSIGs are dropped from v0 and every milestone until a customer asks; every action's risk stays normal (option 3; the build recommended two risk levels with a classifier and an SSHSIG on high-risk decisions).**
    - Question: §16.6 added the member's SSHSIG to a high-risk approval, and nothing said what makes an action high risk or who computes it.
    - Answer: no decision needs an SSHSIG. `ApprovalDecision.sshsig` stays a reserved field, ignored wherever it is presented and never trusted; `SidecarRisk` keeps its two values and every action is normal, no policy field and no classifier raising one, so `AclRequestRule` gains no risk field. R-MCP-7 says so, and §3's approval flow, §5.4's `Risk` and §16.6's channels follow.
    - Cost: no second factor separates a public publish or a wide mailing from any other approved action until a customer asks for one.
    - Not taken: (1) two levels, normal and high, with a fixed classifier and a policy field on request rules, a high-risk decision adding the approver's SSHSIG; (2) the same with the classifier only.
    - Raised by the build (plan-MCP; the build's ledger, QD-014).

280. **An approved recipient is a (sending alias, recipient) pair with an approval record in the repo that holds that alias's mail (the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §16.5 made `mail_send` W "to approved recipients", and no section said what an approved recipient is, where the list lives, who sees it or what evidence creates an entry.
    - Answer: the record sits at `rcpt/<h>/<address>` in `mailbox:<member>` or the `group:<group>` repo, never in mailcfg, and its body `MailRecipientApproval{alias, recipient, decision, action}` holds the stored bytes of one `ApprovalDecision` on channel device or presence and of the `CanonicalAction` of kind `mail_send` listing that recipient. The daemon writes one record per recipient after that use's Outcome is done, created only if absent; a harness decision sends its one message and creates none. Every device re-verifies the embedded decision at each use under its current pin, so a file an agent wrote, or one whose approver was revoked, approves nothing. A record lasts until a person removes it with `ur mail recipients rm` on `/dev/tty` or in an app, and MCP's evs tools refuse `rcpt/`. `mail_send` is W only when every non-member recipient has a record and the run is untainted; a tainted run ignores records (§15.7, §15.10, §16.5, §16.6).
    - Cost: one small record a recipient in the mail repo, which its readers see; the first mail to each outside address needs a device or presence decision.
    - Not taken: (1) a signed mailcfg record per approved pair; (2) local per-sidecar state in the mail component, so a person approves again on each device; (3) no standing list, each send O unless an unspent multi-use decision covers it.
    - Raised by the build (plan-MCP; the build's ledger, QD-034).

281. **The safety number is 60 decimal digits over the genesis's hash and the device's identity key, shown as 12 groups of 5 (the recommendation, accepted in bulk on 2026-11-06).**
    - Question: EX5 and §5.6 show a safety number, and no section gave its bytes, length or display.
    - Answer: digest = SHA-256("urnetwork-sidecar-v1/safety-number" || 0x00 || genesis_sha256 || identity_public_key), both 32 bytes, genesis_sha256 being the SHA-256 of the Signed Genesis. The number is the digest read big-endian, mod 10^60, zero-padded to 60 digits and shown as 12 groups of 5 in three lines of 4 groups. `ur` and `SidecarApprovals` show it identically, with one vector byte-equal on every leg (§5.6's safety row, D-CORE-13, §2.8's EX5).
    - Cost: 60 digits to compare by eye or voice.
    - Not taken: (1) the hash's low 100 bits as 30 decimal digits in six groups of five; (2) 8 BIP-39 words, which reuse the recovery code's alphabet; (3) hex of the first 16 bytes.
    - Raised by the build (plan-CORE; the build's ledger, QD-039).

282. **`DefaultSidecarSettings` leaves the service urls empty, and hosts fill them from §18.9's embedded host table, the one copy of those names (the recommendation, accepted in bulk on 2026-11-06).**
    - Question: the build's hard limit keeps production hostnames out of code, and §5.4's defaults named the public service urls.
    - Answer: the defaults carry no url, so `NewSidecar` refuses until a host sets them; cli and sdk hosts fill them from §18.9's table, the data file `ur` embeds and publishes, which is the one exception to the limit. Tests stay on `.example` names (§5.4, §18.9).
    - Cost: a host that forgets to set them fails at construction.
    - Not taken: (1) the public service urls in the root's settings.go, as the design said.
    - Raised by the build (core-types; the build's ledger, QD-119).

283. **`ur` refuses to enroll beside a readable network credential by the host's state, with no signal from api (the recommendation, accepted in bulk on 2026-11-06).**
    - Question: D-TRUST-3 has `ur` refuse to enroll, and an enrolled daemon alarm, where an app's or the extension's store holds a readable network `by_jwt`, until §7.4's stage 2; nothing said how `ur` learns that the stage arrived.
    - Answer: it does not. The check is by state: `ur` refuses to enroll, and an enrolled daemon raises `credential_store` at each start and at each `SyncRefetchInterval`, while a store holds a readable network `by_jwt`, whatever the stage. A host the releases cleaned passes by itself, and a later `ur` release drops the check once the fleet has moved. No reply field, config key or other spoofable input turns it off (D-TRUST-3, §5.6, §7.4).
    - Cost: a host with an old app or extension stays refused after stage 2 until that app updates.
    - Not taken: (1) a `stage2` field in enroll's reply and `core`'s fetch, set from config; (3) dropping the host check and relying on `preview_networks` and policy.
    - Raised by the build (plan-CORE; the build's ledger, QD-120).

284. **The keychain auto-locks after 10 minutes with no request on any local socket, never while the daemon is busy (the recommendation, accepted in bulk on 2026-11-06).**
    - Question: §5.9 named an auto-lock and gave no value, no meaning of idle and no rule for daemons that are always on.
    - Answer: `AutoLockTimeout` defaults to 10 minutes. Idle means no request on any local socket (control, mcp, hook, git) for that long, and it never applies while the daemon's busy rule holds: mail, sockets or bridge on, or an indexer. Locking drops U and every R_n and enters Locked; where a key store holds U, the next local request unlocks by itself. Zero never locks, for a host to set on purpose (§5.4, §5.9).
    - Cost: a daemon that serves mail, sockets or a bridge never auto-locks.
    - Not taken: (2) locking only where the pass is the only unlock; (3) never locking by default; (4) another value, or one per host class.
    - Raised by the build (core-types; the build's ledger, QD-121).

285. **`AgentRevoke` is a local act, not a record (the recommendation, accepted in bulk on 2026-11-06).**
    - Question: §5.5 ended an agent subkey by `AgentRevoke`, and a subkey never leaves the daemon, so nothing said what a record of it would tell a reader.
    - Answer: `Sidecar.AgentRevoke(agentId)` deletes the subkey from `keychain.ur`, and the daemon signs nothing more with it. Readers bound a subkey by its certificate's `not_after_ms`, at most 30 days. A compromised daemon is a `SidecarRevoke{reason: compromise}`, and provenance from its `since_n` on reads unattributed. No proto number is reserved for a revocation record (§5.5, D-CORE-6).
    - Cost: a subkey a compromised daemon copied stays valid to readers until its certificate lapses or the daemon is revoked.
    - Not taken: (1) a sealed `AgentRevoke{agent_id}` record beside the certificate; (3) dropping agent subkeys from v1.
    - Raised by the build (plan-CORE; the build's ledger, QD-232).

286. **The sidecar adopts the `by_client_jwt` that `POST /sidecar/bind` re-mints with its `sidecar_id`, and sdk's host session takes it too.**
    - Question: bind re-mints the client token with the `sidecar_id` claim that sockets and other gates read, and neither the core nor an app's host session kept the new token, so a refresh went on from the old one.
    - Answer: `SidecarApi.Bind` returns the re-minted token beside the generation, after checking that it names the same network, client and device. Enrollment, child enrollment and pairing persist it in place of the pre-bind token, and a `restore_required` re-registration installs it. Refresh keeps the claim as presented and adds none from the binding row. sdk's host Api session implements the core's optional `SidecarTokenSourceRemint`, whose `AdoptByJwt` holds the token and sets it on the Api, refusing when the session is closed or holds none, so an app's sidecar keeps its `sidecar_id` across the host's refreshes (§5.6, §5.15, §18.7).
    - Cost: until both land, sockets denies a sidecar's authenticated `/socket/*` calls, the closed direction.
    - Not taken: refresh adding the claim from the client's binding row, a read on every refresh; a host callback on the enroll credential, a second seam for the same hand-off.
    - Raised by the build (the sockets client verifier and sdk's host services; the build's ledger, QD-797 and QD-805).

287. **A remote-mode Sidecar hears the daemon's events over a control method, `events` (option 1).**
    - Question: §18.5's listener carries every §5.4 event kind, and no §5.8 control method carried events, so a remote-mode app heard `state` alone.
    - Answer: the daemon registers a control method `events`: `{after: <cursor>, wait_ms}` answers the events past the cursor from a bounded per-daemon ring, each with its generation and kind and the ids §18.5 lists, never a secret, or `gap: true` when the ring has passed the cursor, after which the app reads `GetState`. The ring's size and the longest wait are settings fields. sdk's remote backend keeps one long-poll open on a second control session and feeds `AddEventListener` from it, and the native host adds `events` to its allow-list, so the extension hears the alarms. It is a method, not a hello mode (§5.8, §18.5).
    - Cost: a second control session an app, and a ring of events in the daemon's memory.
    - Not taken: (2) a new hello mode whose session is a one-way stream of event lines; (3) polling `status`, with the pending approvals and alarms added to what a poll reads.
    - Raised by the build (SDK-M8-02; the build's ledger, QD-821).

288. **§5.8 gains the control methods `mail.check_send`, `mail.send_result` and `mail.send` (option 1).**
    - Question: §18.5's `CheckSend`, `GetSendResult` and `Send` had no control method, so a desktop app on `ur daemon` could not send internet mail or read a send's outcome.
    - Answer: `mail.check_send` takes the draft's fields and answers the root's `SmtpSendCheck` as JSON, and `mail.send_result` takes a `send_id` and answers `SmtpSendResult`; both are reads that sign and send nothing, so neither needs §5.8's confirmation. `mail.send` goes through the daemon's gate like a submission, held for an I-8 approval (§15.10 step 1). sdk's remote backend calls each (§5.8, §18.5).
    - Cost: three more methods on the control socket.
    - Not taken: (2) no remote path, desktop apps neither checking nor following internet sends through the sdk; (3) folding the outcomes into the `mail_send` event, the check staying local.
    - Raised by the build (SDK-M9-01; the build's ledger, QD-853).

289. **The search cache keeps each kept record's wrapped object key, in slot-keyed repos the slot's block, and an ERASE hint drops every kept record whose slot key it destroys (option 1 of each question).**
    - Question: §5.9's cache keeps index files and never a key, so a search could not reopen a kept file after the round that fetched it without reading evs; in slot-keyed repos the key sits in a slot, not in the segment's header.
    - Answer: beside each kept record the cache keeps the record's file id and its wrapped object key exactly as stored, about 100 B a file: in general repos as the segment header carried it, and in slot-keyed repos (record-class repos and group inboxes) the slot's 72 B block, under fek of the slot key's generation with AAD "UR evs 1.0 object key", with that generation and the segment's, about 80 B more. A reader that holds the repo key at those generations, from `GkmClient` as any evs read does, unwraps per file and opens the record one 64 KiB frame at a time; a wrapped key is not a key, so the cache still holds none. I-EVS-13 is read as evs's storage plus a device cache that drops at the ERASE hint: the hint deletes at once every kept record whose slot key the ERASE destroys, not only the versions a CLOSURE replaced (§5.9's holds and delete rows, §11.14's keys row).
    - Cost: about 100 to 180 B a kept file; between an ERASE and its hint's arrival a device that still holds the generation's key can unwrap an erased document's kept index file.
    - Not taken: (2) keeping each fetched index file's plaintext as derived data sealed under the local search key, in place of evs's record; (3) reading evs for the segment header at search time, and in slot-keyed repos leaving shards unmatched once their round ends.
    - Raised by the build (SEARCH-M10-19 and the search cache; the build's ledger, QD-838 and QD-845).

290. **A remote-mode app's act is checked by the daemon host's own prompt when that host's authenticator holds every live presence key (option 2).**
    - Question: §5.6 runs the presence check where the key is, and a remote-mode app's two-call acts assumed the app holds the key.
    - Answer: at the hold, when every live presence key of this sidecar is one the daemon host's own authenticator holds, the first call answers no bytes and the second runs the daemon's presence prompt over the act's bytes before signing, the person's wait outside the request bound; otherwise the app's `SidecarPresenceSigner` countersigns as before. For the app's own `KeyRegister` beside a host-held live key, the app proves its new key and the daemon's prompt countersigns. sdk does not change (§5.6, §5.8).
    - Cost: the person answers a prompt on the daemon's host, not in the app.
    - Not taken: (1) as built, a two-call act always the app's to countersign, so an app beside a host-held key could not revoke, decide or add its own key; (3) the first call naming the key ids it accepts, with an sdk fallback to one confirmed call.
    - Raised by the build (CORE-M8-03; the build's ledger, QD-897).

291. **The by_jwt carries an `admin_refused` claim, and `Pair` requires it with `strict_exp` (option 3, with option 1 meanwhile; the recommendation).**
    - Question: D-CORE-7 pairs only a child client that is `strict_exp` and `admin_refused`, and `Sidecar.Pair` is handed only the child's jwt, which showed `strict_exp` alone.
    - Answer: api adds an `admin_refused` claim to the by_jwt, set from the owner row at mint as `strict_exp` and `declares_no_egress` are, additive and read by no other client. `Pair(ctx, childJwt)` requires both claims, and the jwt naming this network, before anything is sent, which makes D-CORE-7 exact for every path that receives a token it did not mint. Until the claim lands, the check of `strict_exp` alone stands, which confines the token to §7.4's allowlist with no admin route, and the app checks its own mint's `admin_refused` before handing the token over (§5.4, §5.8, D-CORE-7, §7.4).
    - Cost: one more claim in every by_jwt; the interim check rests on the app's own.
    - Not taken: (1) alone, `strict_exp` standing for both marks; (2) `Pair` taking the app's mint answer beside the jwt.
    - Raised by the build (CORE-M6-02; the build's ledger, QD-907).

292. **A compromise revocation proposes the tip as `since_n` when no entry is timed at or after the loss time, and answers REVOKE_SINCE when given neither a loss time nor a position (option 1, the recommendation, as built).**
    - Question: `PreviewDeviceRevoke` proposes `since_n` as the first entry timed at or after the loss time; nothing said what it proposes when the loss time is later than the log's newest entry, or when the person gives none.
    - Answer: where the loss time is in the past and later than the newest entry, the proposal is the tip, the largest `since_n` §7.9's verifier accepts for a revocation landing at the next position. The plan shows what that voids before anything is signed, and the person may move `since_n` earlier, never later. With no loss time and no position the call answers REVOKE_SINCE: no default is guessed, least of all the target's admission entry. `ur devices revoke <name> --compromise` with no `--since` asks on the terminal for an RFC 3339 time or a log position and fails without a terminal; a future loss time and a `since_n` past the tip stay REVOKE_SINCE (§5.4, §5.6).
    - Cost: a person must give a time or a position for every compromise revocation.
    - Not taken: (2) answering REVOKE_SINCE where no entry is timed at or after the loss, with a hint to revoke as lost; (3) defaulting to the target's admission entry, which voids everything the device ever signed.
    - Raised by the build (CORE-M2-05; the build's ledger, QD-955).

293. **§5.8's hello gains a fifth mode, `git-hook` (option 1, the recommendation, as built).**
    - Question: a mount's pre-receive and proc-receive hooks run `ur git-hook <name>`, which must reach the daemon, and §5.8's hello had no mode for it.
    - Answer: the mode's `service` is the hook's name, pre-receive or proc-receive, and it names no `repo`. After the hello the relay sends one JSON header line `{session, object_directory, alternate_object_directories}`, the session being the one the daemon set in `UR_GIT_SESSION` when it started git-receive-pack; then both sides send frames of one channel byte, a 4-byte big-endian length and the bytes: stdin and its end from the relay; stdout, stderr and the one-byte exit code from the daemon. The stream may stay open up to `ReceivePublishTimeout` (30 min). The daemon registers the mode as it does mcp and git, under §5.8's peer-uid check. It is a protocol, never a privilege (D-CORE-9): the session id grants nothing, and a relay that cannot reach the daemon exits 1, so the push is refused, never taken unhooked.
    - Cost: one more mode on the control socket.
    - Not taken: (2) carrying the hook inside the git mode under a reserved `service` value; (3) a per-session Unix socket the daemon names in `UR_GIT_SESSION`.
    - Raised by the build (EVS1-M2-35; the build's ledger, QD-959).

294. **An owner's indexer keeps its served record as one row per requester, repo and UTC day, with `Search.ServedRecordCount` as a last bound (option 2 with option 1's cap, the recommendation).**
    - Question: D-CORE-17 bounds the served record only by its 30 days, so one reader's rate set how much an owner's indexer stored.
    - Answer: the record is one row per (requester sidecar_id, repo_id, UTC day): `{requester, repo, day, count, first time, last time}`, written at page 0 once a search and naming no query. The first remote search an EvsShare reader makes in an owner-bound repo on a day adds the row, and each later one that day raises its count and moves its last time. Rows are kept `Search.ServedRecordTimeout` (30 days) by their day, so the owner's view of who read what holds exact counts in at most readers x repos x 30 rows whatever the rate; `Search.ServedRecordCount` (8,192) is a last bound on rows, the oldest days dropped first. Nothing changes on the wire (§5.9's state row, D-CORE-17, R-CORE-19).
    - Cost: the individual times inside a day are not kept.
    - Not taken: (1) the count cap alone, under which abuse drops the oldest records, the evidence of it; (3) every record in per-day sealed files, growing with the requester's rate.
    - Raised by the build (CORE-M10-02; the build's ledger, QD-961).

295. **An unsigned raise of the minimum secure version is a live denial, never stored state (the recommendation, accepted in bulk on 2026-11-06).**
    - Question: the `core` topic can raise `MinSecureVersion`, and the raise is unsigned, so a forged one could cut every peer below it for good.
    - Answer: a device applies the lesser of the floor `GET /sidecar/sync/core` currently reports and its own compiled `secure_version`, never below its compiled `MinSecureVersion`, and persists nothing. A forged floor then never refuses a peer at this device's version or newer, and it ends when the operator stops asserting it. A value above the device's own version prompts an upgrade through `ur status`. §2.8 discloses the raise under I-4 as a denial (§6.4, §5.15, §2.8's connect-4).
    - Cost: the operator can deny peers older than a device's own version for as long as it asserts the floor; a real raise does not outlive an api outage.
    - Not taken: the reading it replaces, a raised floor that only rises and persists in local state, with which one forged high floor cuts every peer pair for good.
    - Raised by the build (plan-CORE and plan-PROTO; the build's ledger, QD-032).

296. **Same-network P2P is built at M6 behind `SidecarProtocolSettings.EnablePeerP2p`, default off (the recommendation, accepted in bulk on 2026-11-06).**
    - Question: §6.18 ended relay-only for same-network pairs once C3 was tested, without saying whether P2P would then be on by default or at which milestone.
    - Answer: it is built at M6 behind the setting, default off, and pairs stay relay-only until a later owner call made on its fault schedule and measurement. Before any network turns it on, §2.8's connect rows and §2.10 say that a pair on P2P learns each other's public addresses through ICE and that relays see no frames of that pair. §6.18's line reads "able to end relay-only" (D-PROTO-10, §6.6, §6.18, §17.18).
    - Cost: every same-network byte stays relayed, and debited, until that call.
    - Not taken: (2) treating it as Later, with no code; (3) M10, beside the other v1 work.
    - Raised by the build (plan-PROTO; the build's ledger, QD-045, with the milestone settled as QD-583).

297. **Every limit is a field of a settings object, protocol and format limits included; only identifiers stay constants, and legacy constants move when the function that reads them is edited.**
    - Question: the owner asked for configuration objects for all settings and no global constants. D-PROTO-16 held protocol values such as the 4,080 B envelope as constants, and the first answer left open whether a one-line wiring change into upstream code must move the constants around it.
    - Answer: every value that sets a limit, size, count, time, interval, threshold, retry or budget is a field of its owning component's settings object, set only by that object's `Default...Settings()` constructor and read from the instance where it is used; no package-level const or var holds one, and no such literal is written into logic. Protocol and format limits are fields too: their defaults are the protocol's values, and changing one is a protocol change, never made on one side alone. Only identifiers stay named constants: enum values, proto field numbers, error, type and statement codes, version numbers, magic strings and cryptographic constants. All code this build wrote moves now; upstream code that predates it moves when a change edits the function that reads the limit, a wiring line or an added struct field moving nothing; file-wide and system-wide legacy constants, server's `model.DefaultContractExpiration` among them, move in the review phase's sweep, one track per legacy area that builds that area's settings object once; vendored third_party code stays as upstream wrote it. Tests may use literals to configure settings (§6.6's bounds, D-PROTO-16).
    - Cost: a sweep of the code already drafted; a protocol limit now looks tunable, and only the rule says it is not.
    - Not taken: keeping the protocol exception, tunables in settings and protocol and format values as named constants; the literal reading of move-on-touch, every track that touches a legacy file migrating every limit in it.
    - Raised by the owner (2026-11-11) and the build (PROTO-M4-02; the build's ledger, QD-702 and QD-958).

298. **A Service pair is keyed by its non-edge end in every namespace, and a sidecar that dials a `ur/` name holds Service while its `ur/` stream lives (option 1 of each question).**
    - Question: §6.10.1 item 3 records a pair as field `<dialer>` of `{svc_<listener>}`. For a `ur/` name the edge listens and a sidecar dials, so CreateContract would read a key under the edge; and the dialing sidecar advertised no Service, so the edge's replies got no Service contract.
    - Answer: a `ur/` Find writes field `<edge listener client_id>` of `{svc_<sidecar dialer client_id>}`, the roles swapped in the key and the ticket unchanged, so CreateContract's one Redis read is always field `<edge>` of `{svc_<sidecar>}` whichever end listens. Revocation and unlisten remove a `ur/` pair from the dialer's key; the edge's last unlisten does not reach it, so a `ur/` pair ends at its 60 min ttl. A sidecar holds Service from a `ur/` ticket's open until its last `ur/` stream ends, as a `tls/` or `smtp/` listener holds it for its lease, with one provide frame at the first hold and one at the last release, so a sidecar that sends mail through `ur/smtpedge` without receiving any works. While held, edges get Service contracts to the sidecar only for its live pairs, the inline handler admits from a Service source only stream frames, Ping, Pong and answers to the sidecar's own calls, and an edge's StreamOpen reaches only listeners the sidecar has (§6.10.1 items 2 and 3, §13.6, §2.8's sock-3).
    - Cost: a `ur/` pair outlives the edge's unlisten by up to 60 min; a dialing sidecar advertises Service while its stream lives.
    - Not taken: for the key, (2) reading the listener's key when the source is an edge, which refuses the edge's replies to a `ur/` dialer, and (3) two reads; for the hold, (2) Service whenever the mail role may send, stream or not, and (3) the edge's replies settling in another mode.
    - Raised by the build (PROTO-M5-04; the build's ledger, QD-728 and QD-849).

299. **A versions page that arrives late takes only its rises, and a reconnect ends a failed refetch's retry wait (option 2 and option 3).**
    - Question: a `versions` page api read before a resident's reset could apply after it and raise a false alarm or end a reset run; and a resync asked for during a failed refetch's backoff waited the backoff out even when the client had just reconnected.
    - Answer: the push machine counts its inputs, each reset part and hint applied, and each refetch notes the count when it starts. A page whose refetch began before an input since applied takes only its rises: a durable topic it shows lower, or an open reset run it would end, sends the client to `versions` again, one more refetch at most, and a clock topic it shows lower waits for the next page; a page begun after every applied input keeps the rules, its alarms and adopted falls included. A reconnect, the connect generation's or the long-poll generation's first successful poll after a failure, ends a pending retry wait at once and refetches; every other ask (a seq gap, an abandoned reset run, an undecodable frame, a poll's incomplete reset) is kept and served when the wait ends, and the next failure's wait goes on doubling from where it stood. No wire or format change (§6.8).
    - Cost: at most one more refetch after a late page.
    - Not taken: for the page, (1) the machine as it was, §6.8 saying a late page may alarm, and (3) holding the resident's frames while a refetch is in flight; for the wait, (1) keeping it for every ask and (2) ending it on any ask, which loses the backoff's protection against a hint storm during an outage.
    - Raised by the build (the push state machine's tests; the build's ledger, QD-905 and QD-906).

300. **A push reset that lowers a durable topic raises `head_alarm` with a fifth kind, `rollback` (option 2, the recommendation).**
    - Question: §6.8 has a reset that lowers a persisted durable version alarm, and §5.4's `SidecarHeadAlarm` had no value for it but `fork`, which means two pins that disagree.
    - Answer: `SidecarHeadAlarm` gains `rollback` beside fork, withheld, unverified and unwitnessed. A push reset that presents a durable topic (team, dns, `gkm:<group_id>`) below the version the client holds raises `head_alarm` with that kind, its Evidence the two `TopicVersion`s as protobuf bytes, the held one first, then the offered one. `Consistent()` turns false until reconciled, as for every head alarm, so inbound state still fails closed. `fork` stays reserved for two pins that disagree (§5.4, §6.4, §6.8, §18.5).
    - Cost: one more alarm kind for apps to name.
    - Not taken: (1) keeping `fork` with `TopicVersion` evidence, which shows a person a fork where api lowered a version.
    - Raised by the build (PROTO-M1-07; the build's ledger, QD-928).

301. **A companion contract seals no `WindowDelegation`; it inherits its forward contract's subject, source network and class (option 1, the recommendation, as built).**
    - Question: D-PROTO-19 and C13 had companion contracts inherit the forward contract's seals, the subject's `WindowDelegation` among them, and the signer holds those bytes nowhere and a companion request carries none.
    - Answer: the delegation is the forward contract's alone. A companion request carries none, the signer copies none and the server keeps no forward contract's delegation: no `transfer_contract` column and no Redis family, so §2.8 gains no row. Nothing is lost: §17.9's verify row admits a native flow only when the delegation's `window_client_id` is the contract's own source, and a companion's source is the replying provider, so an inherited copy would fail at any host exactly as an empty one does (D-PROTO-19, §4.6's C13, §6.10.1 items 4 and 5, §17.9's sign row).
    - Cost: none.
    - Not taken: (2) keeping each forward contract's delegation server-side, a column or a Redis family with its §2.8 row; (3) connect copying the forward contract's delegation into the companion request, a client-supplied value no receiver checks.
    - Raised by the build (PROTO-M4-02; the build's ledger, QD-957).

## The build's owner questions on networks, teams, enrollment and the authorization log (2026-11-06 to 2026-11-16)

The design-records track for §7 folded the answers below on 2026-11-16, each citing its ledger id: the owner items of that section decided or accepted in bulk on 2026-11-06 (302-306), those the owner decided one at a time from 2026-11-10 to 2026-11-15, and the recommendations of 2026-11-15 that the owner's instruction of 2026-11-16 accepted, which the ledger dates 2026-11-15. A decision that groups several answers carries its latest answer's date.

302. **Per-run cost totals go to the team record by default, and a Team turns them off with `ServiceSettings.record_cost` (option 2; the build recommended off until a Team turns them on).**
    - Question: I-20 keeps model calls in the vault and admins read actions and approvals, while the product's Team line puts cost in the ledger, and a per-run figure that names a member is monitoring-capable data.
    - Answer: per-run totals (tokens by model and reported amounts, never a model_call) go to the team record by default. `ur record cost` groups by project, client or month, never ranks people and folds groups under 5 members into `other`, which shapes the tool and is no privacy control. A Team turns it off with `ServiceSettings.record_cost`, field 8, since `mail_strict` keeps 7, signed by an Owner or Admin, and every member's `ur status` names the setting (§7.9's settings fields).
    - Cost: every Team's admins hold a per-person cost series from the first run, and works-council exposure is the product's default, so counsel reviews before RS2.
    - Not taken: (1) per-run totals to the team record only in a Team that turns them on; (3) a daily per-project sum per sidecar with no run id; (4) the vault only.
    - Raised by the build (RECORD.md's review; the build's ledger, QD-019).

303. **The team record's `RepoCreate` follows the directory's rule, and a Team can decline the ledger (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §11.12 says one team record per network, but only the directory had a filer and a refusal, and copying the directory's rule word for word makes the ledger undeclinable, since an admin device re-files a deleted one.
    - Answer: `team-create`'s first Owner device files `RepoCreate{kind team_record}` right after the directory's, and an admin device that finds a team whose access logs hold none files it. api and readers refuse a second live one in a network, and api one outside the team tier. Its admins are its creator and every config writer, as the directory's. A `RepoDelete` of it stands: only a person's /dev/tty-confirmed admin command files a new one, so a Team may decline the ledger and route as personal (§7.5, D-TEAM-28, §8.8, §11.12).
    - Cost: one more clause in D-TEAM-28 and one api check; a Team that deletes its ledger has no employer-readable record until an admin asks for one.
    - Not taken: (2) the directory's rule exactly, under which no Team can run without an employer-readable ledger; (3) only a person's command files it, which leaves the ledger off by default.
    - Raised by the build (RECORD.md's review; the build's ledger, QD-050).

304. **A zero `team_mail` reads as `indexers` (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §7.9 gives every other setting a default, while owner decision 58 says each team chooses its mail mode, and the two modes differ in who sees members' mail in transit.
    - Answer: `team_mail` is `indexers | member scopes`, indexers first, and `TEAM_MAIL_MODE_UNSPECIFIED` reads as indexers. A `tag:mail` device still needs an `IndexerSet` for mail before it registers (D-MAIL-15), so no mail flows at zero until an admin designates one, and member scopes stays an explicit choice, which turns `{mxr_}`'s scope routes on (§7.9, §15.5).
    - Cost: a team that never chooses gets designated receivers, which members' devices list, once an admin designates one.
    - Not taken: (2) member scopes as the default, which needs each scope's mx host, mailcfg and certificates before any mail arrives; (3) no default, a setup step no section describes.
    - Raised by the build (the protos review; the build's ledger, QD-117).

305. **A Team requires fail-closed hooks with the signed `ServiceSettings.record_required`, read from M6 (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: D-MCP-5's one sentence names a policy that no record carries, and a blocking hook stops a member's tools when the daemon is down, against that item's own "an outage must not stop work".
    - Answer: `ServiceSettings.record_required`, a bool, false by default, field 9, reserved at M2 and read from M6, set by an Owner or Admin and never through MCP. While it is set, `ur install-harness` writes `onFailure: block` (Claude Code) and `failClosed: true` (Cursor) on every `ur hook` entry, adds `--required` to the hook command and seals that form; `ur hook --required` exits 2 when the daemon cannot take the event. The config-hash check counts a fail-open form as a changed config, so such a run taints, and `ur status` names each fail-closed harness. Codex documents no fail-closed setting, so there the exit 2 blocks a PreToolUse only while the hook runs (§7.9's settings fields, §16.7).
    - Cost: a dead daemon stops work on Claude Code and Cursor for a team that sets it; enforcement stops at a member's own daemon, where a same-uid edit taints but cannot be prevented.
    - Not taken: (2) a key in §8.5's policy compiled into the local policy, a harness setting inside an access policy; (3) a documented local flag, which an admin can only ask for.
    - Raised by the build (plan-MCP; the build's ledger, QD-139).

306. **ur.io's OAuth consent page is in scope: owner rule 6 does not reach the issuer's consent page (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §7.8's consent row and D-TEAM-7 need the page to show the matching code and the one command, while owner rule 6 and the scope note of 2026-11-06 exclude UI and no section named the page.
    - Answer: the build changes the consent component of ur.io on mmm's `sidecar` branch to show the matching code and the one command from `authorization_details`. The page is the issuer's `authorization_endpoint` and a security control, not product UI (§7.8's `page` row).
    - Cost: a small page change in mmm and one line in the handoff's mmm row.
    - Not taken: (2) a minimal consent page served from api, a second login surface to build and secure; (3) the code in the terminal only, which drops D-TEAM-7's control against an agent driving the browser.
    - Raised by the build (plan-TEAM; the build's ledger, QD-129).

307. **`SidecarRow` carries each admission's time, `admitted_time_ms = 23` (option 2, the recommendation).**
    - Question: §7.10's cleanup list shows each listed page Worker "with its admission time", and rows carried only the admission's position, so a device that no longer retains the entry could show none.
    - Answer: `SidecarRow` gains `int64 admitted_time_ms`, field 23, the `time_ms` of the entry the admission took effect at (the admitting entry's, the completing cosign's or the tick's), set at apply and carried through bases as `admitted_at` is, 0 for the Genesis's device. Every reader computes it from the entry it applies, rows-only gates included, so rows stay equal, and the cleanup list reads it (§7.9's fence comment, §7.10, §2.8 api-7).
    - Cost: about 11 B per admission in rows, some 55 KB at 5,000, and an api-7 phrase that adds no exposure, since api already sees each entry's time and the admission's position.
    - Not taken: (1) listing positions and showing a time only where the device retains the entry, so two admin devices show one list with different detail; (3) dropping the admission time from the list.
    - Raised by the build (TEAM-M4-01; the build's ledger, QD-646).

308. **A forwarding Delegation owes Owners and Admins no authority notice (option 1, the recommendation).**
    - Question: R-TEAM-12 notifies on new credential paths, every new Delegation among them, and a forwarding Delegation (owner decision 197) is filed at each device's setup and every 90 days, thousands a quarter at team size.
    - Answer: the notice counts only Delegations that can admit or sign in. A forwarding Delegation admits nothing, and its sidecar was already admitted under an act that owed a notice of its own, so it owes none (R-TEAM-12, §7.8's Notices).
    - Cost: an owner is not told when a device of the network gains a forwarding key.
    - Not taken: (2) the notice for every Delegation, noise that buries the authority changes it exists for; (3) a notice only when a signer other than the sidecar's own member files one, which today is never.
    - Raised by the build (TEAM-M2-20; the build's ledger, QD-647).

309. **A superseded or ended forwarding Delegation's row leaves the rows once retention passes it by 4,096 positions (option 1, the recommendation).**
    - Question: a forwarding Delegation has no `not_after` and is replaced on every 90-day run, re-enrollment and pairing, so its rows accumulated without bound and a large team's bases would pass the 4 MiB rows limit.
    - Answer: the row leaves `ProjectionRows` at the first base whose retention point passes the later of its `superseded_at` and `ended_at` by 4,096 positions, one rule of the base compile over rows and positions alone, so every reader drops it alike. Past that point the replay row already refuses its Signed bytes, nothing admits under a non-live forwarding key, a `DelegationRevoke` naming a dropped id is refused as unknown, and holder sets read only live rows (§7.9's forwarding row).
    - Cost: a `DelegationRevoke` of a dropped id is refused where it once took effect and changed nothing.
    - Not taken: (2) keeping every row and filing a new forwarding Delegation only at a new client generation; (3) both as written, under which a 5,000-device team's bases pass 4 MiB within about a year.
    - Raised by the build (TEAM-M2-20; the build's ledger, QD-648).

310. **A team IdP sign-in's flow state waits in Redis under `{sso_<state>}` for 10 minutes and is taken once (option 1, the recommendation).**
    - Question: an OIDC or SAML sign-in holds a state, a nonce, a PKCE verifier and the user that began it between the redirect and the callback, and neither a Redis family nor a table held a flow.
    - Answer: a Redis key `{sso_<state>}` holds the flow as JSON, set with a 10-minute ttl and taken with GETDEL, and §2.8's api-3 names it. Nothing lasts past 10 minutes, and a lost Redis only restarts sign-ins in flight (§7.6, §7.17).
    - Cost: one Redis family and one phrase of api-3.
    - Not taken: (2) a table with a sweep, durable where durability buys nothing; (3) the flow sealed into a cookie, which still needs a store for used states and puts a verifier in the browser.
    - Raised by the build (TEAM-M2-16; the build's ledger, QD-720).

311. **The issuer accepts an edge login origin on each tlsedge port (option 1, the recommendation).**
    - Question: a members endpoint on a port other than 443 could not sign its visitors in, since the issuer took an edge origin only without a port.
    - Answer: the issuer accepts `https://<host>.<net>.<root>:<port>` for the four tlsedge ports, 443 written bare, with the redirect_uri and the audience on that origin, and checks the members publish grant for (host, port). Each port is its own origin and audience (§7.8's edge login, D-TEAM-15).
    - Cost: none beyond the wording; the grant check already takes the port.
    - Not taken: (2) a login through the host's 443 origin with sessions sealed to the host, which ties a port's audience to a 443 listener; (3) refusing `members` on ports other than 443.
    - Raised by the build (TLS-M5-19; the build's ledger, QD-723).

312. **api keeps re-seed uploads in the Redis soft-state family `{acl_<networkId>}r`, with a resumed marker (option 2, the recommendation).**
    - Question: after a site loss, devices' uploads wait until two members agree, and with several api instances two members' uploads could land on two instances and neither adopt; nothing durable said a network had resumed, so re-seed mode lasted until the operator turned it off.
    - Answer: one hash field per uploading sidecar holds its newest upload, under a ttl that is a settings field, 24 h by default, and a resumed marker field is set when the network's resume base lands. Devices send their uploads again until their network resumes, so the family is rebuildable soft state under owner decision 136, and re-seed mode ends per network at the marker (§7.8, §7.9's site loss, §2.8 api-7).
    - Cost: one Redis family and its line in api-7.
    - Not taken: (1) uploads in memory with one api instance during a restore; (3) objects on the first metadata cluster, a new object family.
    - Raised by the build (TEAM-M2-15; the build's ledger, QD-724).

313. **An `AuthKeyBundle` carries the 32-byte `delegation_id` (option 1, the recommendation).**
    - Question: the log names a Delegation by the 32-byte hash of its signed bytes, and the bundle's parser took 16 bytes, an id no verifier could match to the Delegation's row.
    - Answer: the bundle's `delegation_id` is the 32-byte id the log names, kept as bytes: one identifier for a Delegation, the one §6.9 and §10.5 use (§7.8).
    - Cost: none; no key had been minted.
    - Not taken: (2) 16 bytes in the bundle and a second lookup key for the row.
    - Raised by the build (CORE-M2-01; the build's ledger, QD-731).

314. **Rows carry every open proposal, api schedules each recovery activation by a run-once task, and a restored binding's admission filed with `self_admit` off has its own kind (the recommendation in each).**
    - Question: an `AuthorityProposal` closed at any base that folded past it, since `ProjectionRows` had no field for one; api's activation tick had no way to learn which recovery windows end; and `ProposalKind` could not say whether a restored binding's admission was filed with `self_admit` off, so its activation read the setting at the tick.
    - Answer: `ProjectionRows` gains `repeated ProposalRow proposals = 7`: each open proposal's id, statement type and statement, each signer with its position, its `not_after_ms`, a recovery-signed one's window entry and time, and its kind, compiled from the head's fold records, so api, the gates, a new device and a long-running reader hold the same S(n) after a fold. After each statement append api schedules `RunOnce("config_log_activation", proposal_id)` at the window time + 72 h for each proposal whose window moved at that entry; the task checks the row at the tip and appends an `ApiTick` naming the activation, and no periodic sweep runs. A proposal's kind is fixed at its entry, and `PROPOSAL_KIND_RESTORED_COSIGNED = 4` names a restored binding's admission filed with `self_admit` off, which activates only with one admission signer's cosign among its signers; until the value is declared, readers take `self_admit` from rows at the tick, which keeps them agreeing (§7.9's proposal, tick and self_admit rows, §2.8 api-7).
    - Cost: rows grow by open proposals only, bounded by their 7-day `not_after`; one more taskworker target; one enum value before M2's freeze.
    - Not taken: forbidding a fold past an open proposal, which holds the unfolded tail for up to 7 days; readers rebuilding proposals from fold records, which api and the gates cannot read; a periodic per-network sweep; three kinds with `self_admit` read at the tick as the rule; `self_admit` overloaded into another field.
    - Raised by the build (TEAM-M2-02, TEAM-M1-04, TEAM-M2-05; the build's ledger, QD-736, QD-745, QD-952).

315. **A base names the repos its own head change shrinks, and a removal of a holder whose access had already ended by time counts as a shrink (option 1, the recommendation, in each).**
    - Question: a base's own config head can shrink a repo's key holders, which a new device and a cold gate that start at the base cannot compute; and an entry that removed a holder whose grant had already expired left `holders_shrunk_at` unchanged, so the gate passed again a generation the expiry had closed.
    - Answer: `ProjectionHeader` gains `repeated bytes shrunk_repo_ids = 11`, the 16-byte repo ids, ascending and none twice, of the repos whose holders the base's own head change shrinks, which the writer computes from S(version-1) and S(version); a verifier present at the previous entry recomputes it and forks on a difference, and one that starts at the base takes it. Entry n, a base included, also shrinks R when it drops a holder of KeyHolders(R, n-1, t_s) from KeyHolders(R, n, t_s), t_s being the time of the entry at R's `holders_shrunk_at`, or R's creation when that is 0 (§7.9's shrink row and apply's shrunk row, §2.8 api-7).
    - Cost: a header field with its api-7 phrase, a compare at each base, and one more KeyHolders pair per repo at each touching entry; an expiry moved earlier with both ends after R's last shrink stays open, for the review phase.
    - Not taken: every policy change at a base shrinking every repo, a rotation of repos the change did not touch; rows re-compiled at each re-sign; judging each generation by its own holders, kept for the review phase; the rule as it was.
    - Raised by the build (TEAM-M2-09, TEAM-M2-17; the build's ledger, QD-746, QD-883).

316. **A sidecar signs its DPoP `iat` by api's clock (option 1, the recommendation).**
    - Question: §7.4 holds a DPoP proof to a window of ±60 s, so a sidecar whose clock is minutes off could neither renew nor exchange, while §22.8's skew row has it keep working.
    - Answer: the sidecar reads the offset between its clock and api's from its api answers, signs `iat` at its own time plus that offset, and on a refusal for `iat` refreshes the offset once and retries. The window and its replay ttl stay as they are (§7.4's proof).
    - Cost: a small client change; none on the server.
    - Not taken: (2) a server-issued DPoP nonce, a Redis family, a §2.8 row and a round trip; (3) narrowing the skew row, under which a drifted laptop cannot renew until its clock is fixed.
    - Raised by the build (TEST-M2-15; the build's ledger, QD-757).

317. **`ur daemon` runs one config follower per network it hosts, over a head reader that evs provides (option 1, the recommendation, in each).**
    - Question: no task built a network's config follower in the daemon, so the bridge and every other consumer of the verified log had no reader, and no task built the config repo's head reader over evs or each hosted network's evs and gkm clients.
    - Answer: for each network the daemon hosts, one follower is the device's one judge of §7.9's log: its projection reader over that Sidecar's api, the config repo's head reader through evs, its `authlog/` store and gkm's keys. evs provides the head reader, the file-mode read of main at a ref version, every path of the head, checked against C_v on the ref's chain (§11.8); the daemon composes each network's evs and gkm clients. Components, the bridge among them, read through the follower and build none of their own, and until the pieces are composed the follower withholds every base (§7.9's follower row).
    - Cost: two tasks, in the data and core lanes; until both land no hosted network's log is followed, the closed direction.
    - Not taken: the bridge wiring building its own follower, a second judge of one log; one core task writing the head reader over evs's read path, whose ref-version rules evs owns.
    - Raised by the build (BRIDGE-M4-16 and the daemon's composition; the build's ledger, QD-796, QD-804).

318. **A reader that starts at a base judges that base's head by descent, as api does (option 1, the recommendation).**
    - Question: a reader that starts at a base b holds no state for the authorization pins of the config repo's earlier pushes, so it could not judge their signers' writer role and withheld every anchor's head.
    - Answer: at an anchor the reader checks that the head's chain runs from C_0 to C_v and that each push's signature verifies under an identity key b's rows admit, leaving the writer role at each push's own pin unjudged; a push whose signer b's rows no longer admit is unjudgeable and withholds the head; every push after the anchor is judged in full (§7.9's anchor row).
    - Cost: a config writer removed before b, whose identity b still admits, could have a past push taken as a writer's, inside a head that b's signer, a config writer at b, signed for, and bound by the compile check from the next base on.
    - Not taken: (2) rebuilding the states from the head's fold records, a full log replay at every anchor; (3) refusing every anchor over evs; (4) the chain check alone, with no signature checked.
    - Raised by the build (the config head reader; the build's ledger, QD-814).

319. **A device with no config key applies bases rows-only, joins the config group on those states, then re-reads them in full before it stands (option 1, the recommendation).**
    - Question: a newly admitted device's follower must check config heads before it stands, and its key client takes the config repo's key only on a verified state the follower gives once it stands.
    - Answer: while the device holds no generation of the config repo, its follower applies bases as sidecar/device's posture does and hands the key client those states, which serve only to take its Welcome or wrap and open the config repo's generation keys; nothing else acts on them, no seal, commit, rotation or admission. Once it holds the key, the follower re-reads every base it applied rows-only, from its anchor, judging each head in full, and stands only when that pass agrees. The network's first device and a device restarting with its keys keep the full check from the start (§7.9's no key row, §10.7's KF2).
    - Cost: a second pass over the log since the anchor, and a window in which the key client holds a state no head check has confirmed.
    - Not taken: (2) starting at a base by its rows and reading its head by descent, which a device that cannot start at a base cannot use; (3) a first wrap staged by the admitter, a key the device opens before it can judge who rotated it.
    - Raised by the build (the daemon's composition; the build's ledger, QD-817).

320. **The genesis owner's row names SHA-256(Signed Genesis) as its admission hash (option 1, the recommendation).**
    - Question: base 1's compile gave the network's first device a row with no `admission_sha256`, while §10.4's credential names the Genesis, so every member's credential check refused the first device's leaf.
    - Answer: base 1's compile sets the genesis owner's `SidecarRow.admission_sha256` to SHA-256(Signed Genesis), so the row says what the credential carries and every check stays a byte comparison (§7.9's fence comment, §10.4).
    - Cost: one field in base 1's rows.
    - Not taken: (2) reading an empty hash on that row as the Genesis's, a special case in every reader of a row's admission hash.
    - Raised by the build (the daemon's composition; the build's ledger, QD-825).

321. **SCIM's bearer is a hashed column an Owner-only route sets, and the indexer `scim_signer` names reads its queue on a sidecar route (option 1, the recommendation, in each).**
    - Question: §7.6 gave SCIM a hashed bearer, and §2.8 named no store and §7.17 no route for it; and the indexer that `ServiceSettings.scim_signer` names (owner decision 150) could not read SCIM's queue, since `GET /network/scim-changes` is a Network route a sidecar's token cannot call.
    - Answer: `network_team.scim_token_sha256`, a nullable column in MG6, holds the SHA-256 of a bearer `ur-scim-<secret>` that `POST /network/scim-token {remove?}`, Owner-only, answers once; a new bearer replaces the old at once and `remove` turns SCIM off, and api-2 names the hash. `GET /sidecar/scim-changes`, on the strict_exp allowlist, answers only the client whose sidecar the newest projection's `scim_signer` names, with the queued removals of members outside the AdminSet by the same rows; `GET /network/scim-changes` stays the console's and `ur admin`'s (§7.4, §7.6, §7.17, §2.10).
    - Cost: one column, two routes and one allowlist line; the indexer acts on api's unsigned word, so a breached server can have it remove members outside the AdminSet, a denial that adds no reader (I-4).
    - Not taken: a derived bearer, which needs a vault resource before any team can use SCIM; an OAuth client with a `scim` scope; widening the Network route to a client token; pushing the queue in a hint, which still needs the route.
    - Raised by the build (TEAM-M6-07; the build's ledger, QD-828, QD-829).

322. **Device authorizations wait in Redis, as IdP sign-in flows do (option 1, the recommendation).**
    - Question: RFC 8628 device authorizations wait between `POST /oauth/device_authorization` and the token poll, and §2.8 named no store for them.
    - Answer: `{oauthdev_<device_code_sha256>}` holds the authorization's JSON under a ttl of its life, 10 minutes, and `{oauthuser_<user_code>}` points at it; redemption is by GETDEL, and api-11 names them (§7.8's `device` row, §7.17).
    - Cost: two Redis families and one phrase of api-11; a lost Redis restarts sign-ins in flight.
    - Not taken: (2) a Postgres table with a sweep.
    - Raised by the build (TEAM-M6-08; the build's ledger, QD-830).

323. **The auth key bearer, a key's tag ids and the admin event chain are encoded as built (option 1, the recommendation).**
    - Question: no section gave the bytes of an auth key's bearer string, of the tag ids a key record holds, or of the admin event hash chain.
    - Answer: the bearer is `ur-authkey-<id>-<secret>` with both parts in lowercase RFC 4648 base32 without padding, a key's tag ids are written as hex, and the admin event chain is `chain_sha256 = SHA-256(prev_sha256 || canonical)` over a domain string and fixed fields, each row storing its own `prev_sha256`. When every event of a network has aged out of the 400-day window, its next event starts again at seq 1 from the zero value, and an event's time never falls below the previous event's (§7.8, §7.11).
    - Cost: none in code; a fully swept chain restarts, which a reader sees because seq 1 follows a later time.
    - Not taken: (2) other encodings; (3) keeping each network's newest event past 400 days, a row that outlives api-8's published ttl.
    - Raised by the build (TEAM-M1-03, TEAM-M1-09; the build's ledger, QD-911).

324. **A member invite is the string `ur-invite-<invite_id>-<secret>` with a fixed 153-byte fragment, and a join carries an HMAC under the fragment's join secret (option 1, the recommendation).**
    - Question: §7.5 gave a member invite a fragment that pins the network and a secret that MACs the join request, and no section gave the bytes of either.
    - Answer: the string is `ur-invite-<invite_id>-<secret>[#<base64url(fragment)>]`, the bearer's parts in lowercase base32 without padding as an auth key's are, the server keeping only the secret's SHA-256. The fragment is a fixed layout, not a proto message: a version byte 1, genesis_sha256, the pin's version and chain, the inviter's sidecar_id and Ed25519 identity key, and a 32-byte join secret, 153 bytes. The join MAC is HMAC-SHA256 under that secret over a domain string, the network id, invite id, sidecar id, identity key and member id, and is refused for an ephemeral or read_only join (§7.5's invite block, §8.5's invited clause).
    - Cost: none; the fragment never reaches a server, so §2.8 gains no row.
    - Not taken: (2) a `MemberInviteFragment` message in config.proto with its fence lines.
    - Raised by the build (TEAM-M6-04; the build's ledger, QD-964).

325. **A base carries the verdict of every entry in its tail, and later verifiers take verdicts from it (option 1, the recommendation, in the form the detailed design gives it).**
    - Question: a new device that starts at base b re-judged the statements among folded_through+1..b-1 at a state it could not rebuild, so a tail statement whose rule reads what the base's head changed, or whose `at` lies below what the device holds, could get a verdict other than the long-running readers'.
    - Answer: a verdict is judged once, at the entry's position, by the verifiers present there. The base's Signed `ProjectionHeader` carries `tail_verdicts = 10`: 2 bits per entry among folded_through+1..version-1 in position order (0 refused or a BASE, 1 took effect, 2 took effect and completed a proposal, 3 never), exactly ceil(2*(version-1-folded_through)/8) bytes with padding bits 0. A new device and a rows-only verifier re-apply the tail by those bits and never re-judge it; a long-running reader and api compare the bits with their own verdicts, a reader forking and api refusing on a difference (§7.9's state, base, apply and retention rows, §2.8 api-7).
    - Cost: a header field with its api-7 phrase; a new device keeps verdicts it cannot recompute, which the base's signer and every verifier present vouch for.
    - Not taken: (2) judging tail statements on the base's rows by design, under which a later authority change could undo an earlier revocation; (3) retaining rows back to every tail statement's state.
    - Raised by the build (TEAM-M2-02; the build's ledger, QD-915).

326. **A preview refusal answers the code `not_preview` (option 1, the recommendation).**
    - Question: `POST /network/enroll` and `POST /network/auth-client` refuse a strict_exp client outside `preview_networks` with text only, and a client reads only structured codes, so `ur` could not tell a preview refusal from any other.
    - Answer: both routes answer the refusal with the code `not_preview`, and `ur` prints by the code that the network is not in the preview yet (§7.4's `preview` row, §7.8's enroll block).
    - Cost: one string on the server.
    - Not taken: (2) text only, with a generic refusal printed.
    - Raised by the build (CORE-M1-08; the build's ledger, QD-919).

327. **The log's `KeyRegister` rule never reads the attestation; the registering device refuses a failing one, and readers label keys locally (option 1, the recommendation).**
    - Question: a presence key's attestation is judged against the FIDO roots each release pins, so a log rule that refused a failing attestation would give readers on different releases different states from one log, against D-TEAM-32.
    - Answer: the log's rule checks the `KeyRegister`'s own proof, which needs no roots, and never reads `attestation`. The device about to sign refuses a key whose present attestation fails and never downgrades it to asserted. Every reader computes §16.6's label locally, at the carrying entry's time, for records and approver screens only, and shows a logged key whose attestation fails under its own roots as presence (attestation refused), neither attested nor asserted (§7.9's record bytes, §16.6).
    - Cost: a label can differ between releases; state, a key's liveness and the demand for its countersignature cannot.
    - Not taken: (2) roots the log itself pins, one more authority record and its upkeep; (3) each release's roots in the rule, accepting forks.
    - Raised by the build (MCP-M2-01; the build's ledger, QD-924).

328. **§7.4's stage 2 is turned on by a build tag, never by a config push (option 1, the recommendation, as built).**
    - Question: stage 2 must stay off until the app and extension releases ship, and nothing said whether a build tag or a `sidecar.yml` switch holds it.
    - Answer: api is built with the tag `sidecar_stage2` at M3-out, once the releases have shipped; absent the tag, stage 2 is off, so stage 1's routes and the preview gate stand. Stage 2's refusal protects the network credential from same-user agents (I-6), so it does not depend on a config file (§7.4, §23.7).
    - Cost: turning stage 2 on needs a deploy.
    - Not taken: (2) a `sidecar.yml` switch, whose mistaken push refuses shipped apps or reopens the preview limit; (3) holding the commits off the branch until the releases ship.
    - Raised by the build (TEAM-M1-07; the build's ledger, QD-933).

329. **A team's last Owner cannot delete their account until another member is Owner or the team is deleted (option 1, the recommendation).**
    - Question: an account deletion removes the user's memberships, and a team whose only Owner left would keep its network, AdminSet and subscription with no person holding a server-side role that administers it.
    - Answer: api refuses the account deletion while its user is the last Owner of a team, answering what to do first: make another member Owner, or delete the team. An Owner lost any other way is restored by a signed `AdminSet` that names another member Owner, which the server's role mirror follows (§7.5's last Owner, Q-TEAM-2's residual).
    - Cost: one more refusal on an existing route, only for a team's last Owner.
    - Not taken: (2) deleting the membership and relying on the AdminSet's mirror alone, with billing running on a team no person administers; (3) promoting another Admin automatically, a role the server would originate.
    - Raised by the build (TEAM-M6-01; the build's ledger, QD-941).

330. **Rows keep each compromise cascade's span per sidecar and each indexer designation that holds (option 1, the recommendation, in each).**
    - Question: what a sidecar signed while in a compromise cascade's set P stays void until re-signed outside P, and rows could not answer that after a fold or after a park was lifted; and `ProjectionRows` had no field for `IndexerSet` designations, so they lapsed at the first base at every reader that no longer held the entry.
    - Answer: `SidecarRow` keeps one span per compromise cascade that held the sidecar in P, `cascades = 22`: from is since_n for the revoked sidecar and, for any other, the entry that pulled it into P, and until is the revocation's entry; what the sidecar signed at a position at with from <= at < until is void at every reader. What a recovery key or a Delegation signed follows from the row that names its signer and position, so no other row carries a void marker. `ProjectionRows` gains `repeated IndexerRow indexers = 10`, one row per (sidecar_id, scope) that holds, with its signer, position and sealed services (§7.9's spans row and Indexers, §2.8 api-7).
    - Cost: about 10 B a span and one row a designation, with two phrases of api-7; the server learns nothing it does not already see as park positions, the revocation's since_n and the IndexerSet entries.
    - Not taken: a void marker on each record a cascade can void, four fields across two files; whatever a currently parked sidecar signed being void at any position, wrong both ways; readers rebuilding designations from fold records; designations ending at the next fold.
    - Raised by the build (TEAM-M2-04, TEAM-M2-07; the build's ledger, QD-947, QD-948).

331. **Only the newest active forwarding client of a sidecar's bound client is answered at the exchange (option 1, the recommendation, as built).**
    - Question: nothing in api tied a forwarding client to a Delegation, so a client minted under a forwarding Delegation that another had superseded kept exchanging tokens.
    - Answer: only the newest active forwarding child of the sidecar's current bound client speaks for it at the exchange. Every setup generates a new key set and mints a new forwarding client after filing its Delegation, so a supersession by other keys ends the old client's exchange at the new one's mint, and a repeat for the same key reissues the client (§7.4's mark, §7.8's exchange, D-TEAM-33).
    - Cost: between the Delegation's filing and the mint the old client still exchanges.
    - Not taken: (2) binding the client to its `delegation_id`, a new owner-row column, an api-4 phrase and a request field, which can replace this later; (3) leaving the removal to the sidecar, which a crash leaves undone.
    - Raised by the build (TEAM-M8-02; the build's ledger, QD-963).

## The build's owner questions on access control and sockets (2026-11-06 to 2026-11-16)

The design-records track for §8 and §9 folded the answers below on 2026-11-16, each citing its ledger id: the owner items of those sections decided or accepted in bulk on 2026-11-06 (332-335, and 336's first half), those the owner decided one at a time from 2026-11-10 to 2026-11-15, and the recommendations of 2026-11-15 that the owner's instruction of 2026-11-16 accepted, which the ledger dates 2026-11-15. A decision that groups several answers carries its latest answer's date.

332. **In an owner-bound repo the owner's later `EvsShare` lifts a config writer's standing `RepoRevoke`, and a `RepoRevoke` cannot remove the owner's consented device (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: a config writer's `RepoRevoke` stands until a config writer grants the subject again, and an owner-bound repo takes no `RepoGrant`, so nothing lifted one there; and nothing said whether a revoke could name the owner's own device.
    - Answer: in an owner-bound repo a later `EvsShare` to that subject from a consented device of the owner lifts the revoke, the fold dropping its row from `AclRepo.revokes` at that position. A `RepoRevoke` naming one of the owner's consented devices is refused, since `SidecarRevoke` and `Suspend` already remove a device (§8.5's owner consent, §8.8's RepoRevoke row).
    - Cost: an admin's revoke of a share in a member's repo can be undone by that member's device.
    - Not taken: (2) the revoke stands for good and the subject returns only under a new sidecar identity, which strands a legitimate share and gives admins a permanent lever over a member's repo; (3) a `RepoRevokeLift` statement for config writers, a new statement at M2's freeze that hands admins a say in who reads a member's repo.
    - Raised by the build (plan-ACL; the build's ledger, QD-044).

333. **Any subject of the network that the projection marks `mail_send` may deposit into a member's mailbox (option 1, narrowed, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: D-MAIL-8 delivers same-network mail by deposit, which needs one member's device to deposit into another member's mailbox, and §8.5 and §8.8 allowed no such deposit.
    - Answer: §8.5's `mailbox` deposit cell gains any subject of the network that the projection marks `mail_send`. `vault` and `secret` stay as written, and §8.8's "never in an owner-bound repo" stands for `RepoGrant`. The sender's device learns the mailbox from `mailcfg` and asks the token exchange for `repo:<id>:deposit`; the recipient's readers show the message as from a member by the push's signer (§8.5's kind defaults, §15.8, §2.8 evs-6).
    - Cost: a member can fill another member's mailbox up to §20's storage limits, as any outside sender could, and evs sees which members' devices deposit into which mailboxes.
    - Not taken: (2) an owner's consented device files `RepoGrant{role: deposit}` on its own mailbox, an exception to §8.8's "never" and a statement per mailbox; (3) a relay through a receiver, which needs a running receiver and a new carrier for the sender's signature.
    - Raised by the build (plan-MAIL; the build's ledger, QD-136).

334. **`K_sock`'s rotation overlap is kept at the gates: while the key file holds a previous key, compile writes a second target under it (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: listeners register both token paths for 10 minutes after a rotation, but rows carried only the newest paths, so gates refused every old path and the overlap protected nothing; and the key file had no path or bytes.
    - Answer: one config file, `socket/key`, holds the current key and, after a rotation, the previous key with `rotated_at_ms`. While it holds a previous key, `CompileAcl` writes a second `AclTarget` under that key beside each `sock:` target, a pure function of the head, so gates' checks do not change and readers recompile the same rows; a grant the rotating head drops is dropped on both paths. A requested grant's `sock:` entry is a literal token path and gets no second path: it works while listeners register that path and then its subject requests again. The first writer head at or after `rotated_at_ms` + 10 min clears the previous key, listeners register both paths until then by their own clock, and a lister tries the previous key while the file holds it (§8.8, §9.4, §2.8 api-7 and sock-1).
    - Cost: `sock:` targets double until the clearing head, and rows link the old and new paths for as long as they are kept, at least 30 days, not sock-1's 10 minutes.
    - Not taken: (2) no overlap at the gates, a denied dialer refetching the config once, which drops §9.4's dual registration and leaves a lagging listener unreachable; (3) gates keep the previous base's socket rows for 10 minutes, which keeps a grant the rotating head dropped alive on old paths.
    - Raised by the build (plan-SOCK; the build's ledger, QD-122).

335. **`*` and `@` address records are grant-driven: api recomputes them after each accepted delta or projection and an hourly pass reconciles (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: §12.7 gave `*` its A and AAAA "with an edge grant" while §9.4 named `FirstListen` and `LastUnlisten` DNS hooks, and nothing acted when a grant simply expired.
    - Answer: an edge grant is an active publish on `dns:<host>` in the zone, or the system publish, a network with a `mail_network` row and an approved `smtp/25/mx` listen grant. `*` has A and AAAA while the zone's set holds any host but `@`, or the system publish; `@` while the set holds `@`. After each accepted `POST /network/config/delta` or `/network/config/projection`, once the object PUT has committed, api recomputes the set and calls `model.DnsSyncEdgeRecords`, one journal write per transition, in a transaction of its own. An hourly taskworker pass over §21.6's list removes what expired and adds what a crash missed. §9.4's `FirstListen` and `LastUnlisten` stay seams with no DNS consumer (§12.7, §12.14, §9.4).
    - Cost: a removal lags its grant's expiry by up to an hour, and a network's edge use shows in DNS from its grants whether or not a listener is up.
    - Not taken: (2) listen-driven records through `FirstListen` and `LastUnlisten`, where a lease's expiry has no event and a restarting device makes `*` flap, each flap a signed write; (3) `*` and `@` present from zone creation for every network, which amends D-DNS-6 and invites connections tlsedge refuses.
    - Raised by the build (plan-DNS; the build's ledger, QD-130).

336. **`ur share add` without `--count` gives one use, and `ur share get` also reads its link from stdin (the recommendations; the count's default accepted with the build's owner items in bulk on 2026-11-06, the stdin form option 3 on 2026-11-15).**
    - Question: §9.9 stated `--expires`'s default and not `--count`'s, and the end rule had no reading for unlimited uses; and `ur share get <link> <out>` puts the share's reusable 256-bit secret in argv, `ps` and shell history.
    - Answer: an omitted `--count` means one use, `--count=n` n, and `--count=0` unlimited uses until the expiry; with `uses` 0 only a Remove or `expire_millis` ends a share. `ur share get` keeps `<link> <out>` and also accepts `-` for the link, reading it from stdin; cli/commands.go names the share link beside `ur connect --token` as a stated exception for the plain form, with its residual exposure, and cli/UI.md's row notes the `-` form (§9.9, §9.16).
    - Cost: a sharer who wants many gets must say so, and the plain form still shows the link in `ps`, /proc and history while a get runs.
    - Not taken: for the count, unlimited uses by default, which widens §9.16's leaked-link risk; for the link, (1) the plain form alone with a stated exception; (2) `ur share get <out>` reading the link from the terminal, which changes §9.9's spelling.
    - Raised by the build (the G0 re-check, SOCK-M5-14; the build's ledger, QD-241, QD-967).

337. **A sockets process answers `unavailable` for a network 5 s after evidence that the authorization log passed what it verified; with no evidence its last verified state serves (option 2, the recommendation).**
    - Question: QD-055 had the last verified projection keep serving for as long as its source failed, so a revoked `tls/` listener kept its visitors at a process cut off from api while the log moved.
    - Answer: a sockets process answers `unavailable` for a network once it has had evidence for 5 s, §8.9's target for server gates, that the log passed what it holds and it has not verified the new entries: the `{acl_<networkId>}v` event, a store answer naming a higher position, or after a resubscription a `{acl_}v` that differs from the one its state was loaded at. With no evidence the last verified state serves without limit, so an api outage changes nothing, api being the log's only writer (§8.9, §9.8).
    - Cost: a process that learns the log moved and cannot reach api refuses that network's registrations and Finds until it can.
    - Not taken: (1) the last verified state serving for as long as the source fails; (3) refusing on age alone after one missed poll, which stops every Find within 6 minutes of any api outage.
    - Raised by the build (DESIGN-DETAILS.md section 13; the build's ledger, QD-655).

338. **A `tls/` or `smtp/` Service pair lives at most 15 minutes past its listener's last accepted registration (option 2, the recommendation).**
    - Question: §9.6 wrote an edge pair to the grant's expiry, up to 24 hours, deleted on revocation, so a pair that a sweep missed or a Find rewrote authorized contracts for a revoked listener for up to a day.
    - Answer: Find writes a `tls/` or `smtp/` pair with a ttl of the lesser of the grant's remaining life and 15 min; a registration call that accepts an edge entry of the client renews its pairs, at most every 5 min a process; a removal leaves a floor that refuses a write allowed at an older position. `ur/` pairs keep §9.6's rule, their service's grant length refreshed per Find (§9.6's Edge Finds, §6.10.1, §2.8 sock-3).
    - Cost: a pair write per accepted registration interval, and a listener whose registrations stop for 15 minutes loses its edge contracts' successor.
    - Not taken: (1) the grant's expiry up to 24 h; (3) a contract-gate check of the listener's grant at CreateContract, a gate read on the contract path for platform clients, which §8.10 exempts.
    - Raised by the build (DESIGN-DETAILS.md section 13; the build's ledger, QD-656).

339. **The compile's forms stand as built: the head tables' messages, a rule's canonical form, the constant rule ids, `network:*`'s atom, what compile drops without a clock, and the engine's skew (option 1, the recommendation).**
    - Question: §8.8's compile named forms without bytes: the sealed tables' messages, what a rule's id is keyed by, ids no table holds, `network:*`, and what leaves the rows without a clock.
    - Answer: `tags` and `groups` are `ConfigAtomTable`, `rules` `ConfigRuleTable`, `labels` `ConfigLabelTable` and `resolve` `ConfigResolution`. A rule's canonical form is RFC 8785 JCS of one JSON object per rule, lists sorted, `id` and `note` left out. The implicit document's rule ids and the `tag:mail` kind rules' are constants derived by SHA-256 from fixed labels and an index. `network:*` is a derived atom of kind 4 over the one byte `*`, naming no subject until shares. An activated grant at or past the head's newest record time leaves the rows, and a member the rows no longer hold expands to nothing. `AclEngine` honors a rule until `AclEngineSettings.ClockSkew` past its expiry. The sixth reading, a route rule's via subjects among its targets, is replaced by owner decision 344 (§8.8's Placement, Atoms and Rule ids, §8.6's Direction, §7.9's paths).
    - Cost: the four byte-level forms are frozen with M2's records.
    - Not taken: (2) correcting any reading by number before M2's entry.
    - Raised by the build (ACL-M2-04; the build's ledger, QD-679).

340. **api serves gates the Client projection route's body under `/internal/gate/`, each caller class behind its own bearer (option 1, the recommendation).**
    - Question: QD-055 gave services with no database one internal read surface on api, and no task built api's end or fixed the projection route's body.
    - Answer: `GET /internal/gate/projection/<network_id>?after=<n>` answers the Client route's body, `{genesis, entries, rows, tip: {n, chain}, more}`, each message verbatim in base64, paged, from the retention point when `after` is before it, and `GET /internal/gate/rows/<network_id>/<rows_sha256>` answers the ProjectionRows bytes verbatim, which the caller holds to their hash. Both sit behind a per-caller bearer that api verifies by SHA-256 in constant time, one vault file per gate caller class, connect's first, and the lb refuses the prefix from outside. The listen-facts and over-limit routes join when sockets and quotas need them (§8.9, §19.4, §19.16).
    - Cost: one vault file per gate caller class for the operator to create and rotate.
    - Not taken: (2) folding api's end into sockets' task, which keeps connect's contract gate dark until M5; (3) giving connect read access to `proj/` and `projrows/`, which widens the metadata tier to every connect host.
    - Raised by the build (ACL-M4-01; the build's ledger, QD-680).

341. **The config repo's `AclRepo` row is the state's own, synthesized from the Genesis, and the rows gain it only at the first shrink of its key holders (option 1 of each question, the recommendations).**
    - Question: no `RepoCreate` files the config repo's row and every gate reads it; and once the row was the state's own, its `holders_shrunk_at` had nowhere to live.
    - Answer: where a state's rows hold no `AclRepo` for the network's config repo, ACL's state build adds `AclRepo{repo_id: Genesis.config_repo_id, kind: config}` with no admins and `holders_shrunk_at` 0, so the kind's defaults answer it alike at every reader, gate and api, and base 1's compile stays empty; a `RepoCreate` of kind config stays refused. The rows gain the row at the first entry that shrinks the config's key holders, `AclRepo{repo_id, kind: config, holders_shrunk_at: n}`, sorted in with the rest and advanced there afterwards like any repo's, which a base's `shrunk_repo_ids` may name; the state keeps a config row the rows hold (§8.8's Repo rows).
    - Cost: the rows' bytes change at a network's first config shrink.
    - Not taken: for the row, (2) the base compile writing it from the Genesis, which changes base 1's rows; (3) gates special-casing the config repo at each call site; for the shrink position, (2) a new header field outside the rows; (3) the state's own position, which re-keys the config group after every log entry.
    - Raised by the build (TEAM-M2-15 and the config repo row's fix; the build's ledger, QD-719, QD-762).

342. **`AclRows` carries the document's effective `evidence_default`, field 10, and every verifier checks a ruleless action's channel against it (option 1, the recommendation).**
    - Question: a verifier holding only rows could not check a decision's channel against `evidenceDefault` for an action no `requests` rule governs, so a document's narrowing held only in the daemon.
    - Answer: `AclRows` gains `repeated uint32 evidence_default = 10`, the document's effective default, all three channels where it names none, compiled at each base as each rule's list is. The daemon, every server gate and every reader check a ruleless action's channel against it in the spend check: `dns_set` and `dns_delete` at `POST /dns/records` and `bridge_expose` approvals (§8.6, §8.8's fence, §16.6, §2.8 api-7).
    - Cost: api sees which channels a network accepts by default, as each rule's row already shows for grants.
    - Not taken: (2) rows-only verifiers taking all three channels, so that a forged harness decision passes the gates where the document excluded harness; (3) a `requests` rule for every O action, a policy-grammar change.
    - Raised by the build (MCP-M3-03; the build's ledger, QD-727).

343. **A repo's folded access log keeps a removed admin's removal position and the RepoDelete's entry time and signer (option 1 of each question, the recommendations).**
    - Question: readers, evs and taskworker judge a restore's 7-day window, a shred's time and a removed admin's old right from entries that leave the log's retention, and evs's reconciler could not name a RepoDelete's signer once its entry had left.
    - Answer: `AclRepoAdminRow` gains `removed_at = 4`: a removal keeps the row, stamped with its position, until the next base's compile drops a row whose removal its retention point has passed. `AclRepoDeletionRow` gains `deleted_time_ms = 5`, the RepoDelete entry's time, and `signer = 6`, its signer. A RepoRestore's window, taskworker's shred, `AclState.RepoAdminAt` and evs's reconciler then read rows alone, on any day (§8.8's Repo rows, §2.8 api-7).
    - Cost: three additive fields before acl.proto freezes at M2, each a value the server already sees as an entry's time, position or signer.
    - Not taken: (2) judging from the retained log only and refusing beyond it, or letting `repo/`'s deleted state carry no signer; (3) evs's `repo/` object as the only judge of the window, or the reconciler applying a RepoDelete only while the log keeps its entry.
    - Raised by the build (ACL-M2-06 and its fix; the build's ledger, QD-743, QD-798).

344. **Rows carry a route rule's via subjects apart from its targets and each approved route by its ids, and grant 1 names `"via": ["autogroup:self"]` (option 1, the recommendation, for the rows; option 2 for grant 1, where the build recommended dropping `route` unless a member's own routing was meant).**
    - Question: a route rule that names no `via` routes through the advertisers its approved routes name, which rows did not hold, and a gate could not tell an exit rule's via subjects from its other targets; grant 1's `route` then granted nothing.
    - Answer: `AclRule` gains `via = 12`, a rule's via subjects apart from its targets, and `BridgeRows` gains `routes = 2`, `BridgeRouteRow{route_id, advertiser, route_rule_ids}`, written at the fold for every approved route in force and applied by every verifier in log order after a base; the state adds each advertiser to the via subjects of the no-via route rules its row names. §8.5's grant 1, and Team's starting document with it, read `{ "src": ["autogroup:member", "autogroup:untagged"], "dst": ["autogroup:self"], "via": ["autogroup:self"], "allow": ["dial", "route"] }`, so a member's devices reach each other and the prefixes their own devices' approved routes serve (§8.5, §8.8's fence and Folded grants, §17.8, §2.8 api-7).
    - Cost: api sees each approved route's advertiser and the rules it serves, and the starting document's golden rows change.
    - Not taken: for the rows, (2) refusing a `route` grant that names no `via`; (3) a no-via route grant that opens nothing; for grant 1, (1) leaving it as it was, a `route` that reads as granting and does not; (3) dropping `route` from it.
    - Raised by the build (ACL-M2-17 and the route rows' fix; the build's ledger, QD-764, QD-867).

345. **Prefix rules name only subjects an admission fixes, bind a repo's admins like every signer, and stand as built in eleven readings (option 1 of each question, the recommendations).**
    - Question: Q-EVS-3's v1 prefix rules had a record and a row but no rule for which subjects a rule may name, whether admins are exempt, or which repos, refs and pushes a set binds.
    - Answer: a rule's subject is a sidecar, a member's untagged devices, a tag, or `autogroup:sidecar`, `member`, `tagged` or `ephemeral`; a group's atom names nobody, and `ur evs rules` refuses `group:<name>` with its members' `user:` subjects to file instead. Admins are held to the rules: `ur evs rules` writes a rule for each standing admin into every set it files, and `set --as-written` files a set without them. Only a `general` repo takes a set; a set binds every shared ref and every signer, from the first push pinned at or above it; a void set leaves the one below in force with an alarm; index files, the `ur/index` and `ur/lfs` refs and admin-flagged pushes are outside the rules; a repo holds at most 256 sets for its life; a cascade voids none; a device built before M6 enforces nothing; and every number is an `AclPrefixSettings` field (§8.8's RepoPrefixRules, D-ACL-11).
    - Cost: a group's membership change needs a new set, and a set filed by other code can lock an admin out until an admin lifts the rules.
    - Not taken: for subjects, (2) any §8.4 atom judged at the push's pin, under which two devices can show different files; (3) the admin's daemon refiling at each group change; for admins, (2) exempting them, which needs each admin's spans kept in rows for the repo's life.
    - Raised by the build (DESIGN-DETAILS.md section 16; the build's ledger, QD-791, QD-792, QD-795).

346. **A share grant's CanonicalAction names the other network, and the fold writes that network's atom as the rule's source (option 1, the recommendation).**
    - Question: a share's requested grant had no way to name `network:Y` as its source in the rows, so the contract gate's share half found no rule.
    - Answer: a share grant's CanonicalAction carries the other network in `share_network_id = 40`, beside its subject, the requesting sidecar; the request rule's `network:` source is matched against it, and the fold writes the derived network atom, kind 4, as the rule's source. The admin's approval covers the network as it covers every field (§8.8's Folded grants, §8.11, §16.8's fence, §2.8 api-7).
    - Cost: a record.proto field and a fold branch before M6's freeze.
    - Not taken: (2) shares only under a standing document grant naming the network, which leaves no share without a document; (3) `network:*` naming every network a live share pin holds, which a gate that reads no config file cannot see.
    - Raised by the build (ACL-M6-03; the build's ledger, QD-820).

347. **sockets verifies Client-class tokens through `sidecarhost`'s Authenticator, a verify-only keyring and the revocation record, and the token carries a `sidecar_id` claim (option 1, the recommendation).**
    - Question: the sockets block's authenticated routes needed a Client-class verifier with no SQL, and no plan task held it.
    - Answer: `sidecarhost`'s Authenticator takes a Client-class verifier for the sockets audience over `server/session`'s verify-only by_jwt keyring, mounted from `secret_files`, and the revocation-record check: a valid record passes, a tombstone or rotation answers 401, a Redis failure answers unavailable, a miss answers unavailable with `retry_after_ms`, and a miss within 120 s of a valid check counts as valid. by_client_jwt gains the `sidecar_id` claim, re-minted by `POST /sidecar/bind` and kept by refresh. `revocation_record_enabled` is on in production before M5 (§9.8, §19.4).
    - Cost: a Redis failure fails the sockets routes closed, and a revoked client keeps at most 120 s where its record is missing.
    - Not taken: (2) the sockets track building all of it, editing files other areas own.
    - Raised by the build (SOCK-M5-07; the build's ledger, QD-848).

348. **An edge Find for a `tls/` name passes under any publish grant for the host, and the listener's front judges the audience (option 1, the recommendation).**
    - Question: the gate's edge check passed only a `public` audience, so no visitor reached a `members`, `members-device` or `link` endpoint through tlsedge.
    - Answer: an edge (`autogroup:public`) Find for a `tls/` name passes under any publish grant for the host, whatever its audience; the gate reports the audience and judges neither it nor a raw link's pin, which the listener's front does from its own evaluation. A members visitor without a session then reaches the edge login at the front, and a link URL's token is traded for its cookie (§8.10's dns publish row, §9.10).
    - Cost: tlsedge opens streams to private endpoints' fronts for any visitor, and the front's check is the only audience check.
    - Not taken: (2) public only, which leaves §13.7's private audiences with no path through tlsedge.
    - Raised by the build (TLS-M5-22; the build's ledger, QD-852).

349. **An Owner's or Admin's decision counts toward a rule's k only where the rule's approvers name it or `autogroup:dst-owner` resolves to an admin (option 1, the recommendation).**
    - Question: under the directory's default rule the directory asked the touched member's owner or sponsor alone, while the log's quorum also took an Admin's lone decision.
    - Answer: an admin's decision meets §8.6's admin clause but counts toward k only where the rule's approvers name it, `autogroup:admin` or a group the admin is in, or where `autogroup:dst-owner` resolves to an admin because no owner or sponsor stands. An Admin's lone decision activates no reach grant to another member's worker under the default rule; a rule whose approver is `autogroup:self` reaching another member's device needs the requester's owner and an admin; and an Admin who wants to grant reach alone writes a document rule (§8.6's Requests, §8.8's quorum row, D-ACL-23). It follows owner decision 180.
    - Cost: an Admin cannot approve reach to another member's worker by one decision under the default rule.
    - Not taken: (2) the directory adding `autogroup:admin` to every reach request that touches another member, which notifies every Admin device; (3) leaving the directory and the log with two eligibility sets.
    - Raised by the build (ACL-M6-05; the build's ledger, QD-863).

350. **`POST /acl/accept-invite` takes a claim by the code's hash and then a completion (option 1, the recommendation, as built).**
    - Question: the invited network had no way to read a share's target table or learn the share's id before it accepted, and a multi-use code had no mapping to shares.
    - Answer: a claim with the code's hash alone takes a use, binds the invited network to a share, the invite's own row first and then a new row of the same target table for each later claim of a multi-use code, and answers the share's id with the sharing network's sealed targets; a repeat claim answers the share the network already holds and takes no use. A completion with the share id, the sealed accept and the status stores them once. A claim binds before the invitee's preflight, so a refused preflight still holds its use and completes with a refusal status (§8.11's Invite, §17.16).
    - Cost: a failed preflight spends a use of the code.
    - Not taken: (2) a read-only peek and one accept, under which two accepters of a multi-use code plan under one share id; (3) one share row per use at invite time.
    - Raised by the build (ACL-M6-03; the build's ledger, QD-871).

351. **A deleted repo's standing admins keep the evs `admin` right alone, and the exchange mints only it (option 1, the recommendation).**
    - Question: the rights table gave a repo with an unrestored RepoDelete no right at all, so §11.12's DELETE never passed evs's guard under the real gate state.
    - Answer: a repo whose rows' newest RepoDelete stands unrestored gives its standing admins `admin` alone: no read, write or deposit, and no rule or kind-default right. The token exchange mints only `admin` for it, evs's guard honors it for DELETE, with and without now, while read and write routes stay refused, gkm's guard reads the same rights and its own recheck refuses its writes, and a RepoRestore lifts the deletion (§8.8's Repo rows, §8.10, §11.12's refused row).
    - Cost: a deleted repo's admins hold a live scope for it until its shred.
    - Not taken: (2) evs's DELETE route judging the admin from the rows beside the guard, with a token that must predate the RepoDelete; (3) leaving deletion to the reconciler's daily walk.
    - Raised by the build (the deletion row's fix; the build's ledger, QD-880).

352. **Every config writer holds `admin` on the config repo at evs and gkm (option 2, the recommendation).**
    - Question: only the Genesis's owner sidecar administered the config repo, so once that device was gone the config group could not be re-formed nor the repo re-activated short of re-seed mode.
    - Answer: every config writer, a member device of an AdminSet member that is not read_only, holds `admin` on the network's config repo at evs and gkm, and the token exchange grants `repo:<config_repo_id>:admin` to each. §7.9's bootstrap row, the Genesis's owner sidecar from base 1, is the first case of the rule. A config writer can then re-form the config group, post its ladder, and activate or re-place the repo after a restore; a config drop stays refused (§8.5's kind defaults, §7.9's exchange row).
    - Cost: every config writer holds the erase and closure rights on the config repo wherever evs lets an admin use them.
    - Not taken: (1) the bootstrap sidecar alone, as it was built; (3) the bootstrap sidecar for the first form and config writers for later forms, two rules for one right.
    - Raised by the build (the config repo row's fix; the build's ledger, QD-894).

353. **compile writes an `AclAtom` for every declared tag and group, named by a rule or not (option 1, the recommendation).**
    - Question: a tag declared in `tagOwners` that no grant or request named had no atom, so `CanApplyTag` refused its owners at admission, far from the document's save.
    - Answer: `CompileAcl` writes an atom for every tag in `tagOwners` and every group in `groups`, whether or not a rule names it, so a declared tag can be applied by a Delegation or a tagged `SidecarAdmit`, its sidecars holding what `autogroup:tagged` and the kind defaults give them (§8.8's Atoms).
    - Cost: rows hold an atom for each declared tag and group, within their 4,096-atom bound.
    - Not taken: (2) validation refusing a declared tag no rule names; (3) leaving such a tag declared and unusable.
    - Raised by the build (ACL-M2-16; the build's ledger, QD-901).

354. **`sidecarctl sockets ticket-keygen` writes the sockets ticket key file (option 1, the recommendation).**
    - Question: the plan's keygen subcommand of the sockets binary would have been an operations command outside sidecarctl.
    - Answer: `sidecarctl sockets ticket-keygen -out <file> [-in <file>]` reads the existing file if given, adds a new Ed25519 key expiring RotationInterval (30 days) plus KeyOverlap (1 day) after its creation, drops expired keys, writes the file 0600, refusing to overwrite unless `-in` names the same file, and prints no key. The operator runs it every 30 days and places the file in vault, and the block rereads it every minute (§9.8, §19.4).
    - Cost: a manual step every 30 days until it is scheduled.
    - Not taken: (2) a `keygen` subcommand of the sockets binary.
    - Raised by the build (SOCK-M5-07; the build's ledger, QD-902).

355. **AclState's twelve readings stand as built, later decisions governing where they differ (option 1, the recommendation, as built).**
    - Question: §8.4-§8.6, §8.8 and §8.12 left forms and gaps that the state had to fix: autogroup membership, targets' encodings in rows, where kind defaults live, a grant's subject, hard denies, consent's details, approver fallbacks, D-ACL-3's child clients and the ack route.
    - Answer: the readings stand as `AclState`, the consent predicate, the approver resolution and api's acl tables have them: role autogroups hold untagged subjects by role, and app devices are in `autogroup:untagged` only; a `repo_id` of sixteen zero bytes is the wildcard repo, `socket_tokens` are alternative paths of one name, and `public_name` keeps its glob; kind defaults are evaluated in the binary, never compiled into rules; a grant's subject names a sidecar, a member or an atom; an admission ends at exactly its `not_after`; consent counts a signer consented strictly before its position; `autogroup:self` with no owner or sponsor resolves to `autogroup:admin`; a child client is its own subject only when it asks for `strict_exp` itself; and an ack's body is `{version, time_ms}`. Owner decisions 344, 351, 352 and 353 govern where they changed a point (§8.4, §8.5, §8.6, §8.8's AclTarget, §8.9, §8.12, D-ACL-3).
    - Cost: the target encodings are frozen with M2's rows.
    - Not taken: (2) correcting any reading by number before M2's entry.
    - Raised by the build (ACL-M2-02; the build's ledger, QD-914).

356. **`AclState.ReapplyStatement` derives its fold inputs from the statement's body, its signers and the rebuilt rows, and judges nothing again (option 1, the recommendation).**
    - Question: re-applying a base's tail took verdict parts from a check run again, which can refuse for a reason that only a later head gives, so the fold could differ between verifiers.
    - Answer: `ReapplyStatement` takes only the verdict parts the body and signers give, the signer and an OwnerConfirm's target, and derives every other fold input from the body and the rebuilt rows it folds into: a Suspend's or Unsuspend's class and whether an Unsuspend lifts, a RepoRevoke's or RepoGrant's config-writer standing, a RepoCreate's owner and consented sidecars, a GrantRevoke's `retain_until_ms` and a GrantActivate's grant. Each is a pure function of body, signers and rebuilt rows, so a new device, a gate that started at the base and a long-running reader fold alike (§8.8's Grant chains).
    - Cost: none beyond the change.
    - Not taken: (2) keeping the fallback under which a fold follows a check that may refuse for a head-only reason.
    - Raised by the build (TEAM-M2-09; the build's ledger, QD-954).

## The build's owner questions on group keys and gkm (2026-11-06 to 2026-11-16)

The design-records track for §10 folded the answers below on 2026-11-16, each citing its ledger id: the owner items of §10 accepted in bulk on 2026-11-06 (357-359), those the owner decided one at a time from 2026-11-10 to 2026-11-15, and the recommendations of 2026-11-15 that the owner's instruction of 2026-11-16 accepted, which the ledger dates 2026-11-15. A decision that groups several answers carries its latest answer's date. QD-644, on what `Gkm.tla`'s `MembersSkipRosterCheck` twin shows, carries no number: the model and DESIGN-DETAILS.md 6.6 are the design agent's, and no section names the model, as with QD-628.

357. **A drop key lives 90 days, one setting for every kind that takes deposits, and writers renew it once under 7 days are left (option 2 with option 3's renewal, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: GenRotate's `drop_not_after_ms` had no value, which sets how long a mailbox takes mail with no reader online, and nothing renewed a drop key in a repo that only takes deposits, so a lapse closed no gate and a returning writer could find nothing to write.
    - Answer: `drop_not_after_ms` is `time_ms` + `GkmSettings.DropKeyLifetime`, 90 days, one value for every kind that takes deposits, a later value applying from the next generation. A GET of a drop key whose newest GenRotate has under 7 days left hints `pending` to the repo's writers, at most hourly per group and process, and a writer on that hint, and every writer at its hourly resync, rotates with cause SCHEDULE, with no write of its own. Members' rotation checks and the depositor rule require `time_ms` < `drop_not_after_ms` <= `time_ms` + DropKeyLifetime + 10 min, so no signer voids the backstop with a far-future value (§10.5's depositor row, §10.6's drop keys duty, §10.9's rotation checks, D-KEYS-8, D-KEYS-17, FS-23).
    - Cost: mail keeps arriving through about 60 days with every device offline at worst, 90 at best, and a rotation withheld from a depositor can reach a removed reader for up to 90 days in owner-bound groups; renewal needs a writer online.
    - Not taken: (1) 37 days, the 30-day schedule plus a week, under which about a week with every device offline stops mail with 451 and senders' retries may lapse; a lifetime with no renewal.
    - Raised by the build (plan-KEYS; the build's ledger, QD-031, QD-065).

358. **A device checks daily that gkm serves under its id only ReaderKeys it signed, raising `key_changed` for any other, and ReaderKeys take no post-quantum signature (option 2 on top of the text fix, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: an adversary that can forge Ed25519 and that the operator serves could forge a holder's ReaderKey, to which an honest rotator or hinted holder then seals RK_g with no person acting; §10.5 named only forged admissions, and nothing detected a key the device never signed.
    - Answer: §10.5 names the route, and that RK_g, which an external commit needs, rests on those signatures; §2.18's row names the forged admission or ReaderKey. Once a day, at its ReaderKey upkeep, a device GETs `/gkm/reader-key/<its own id>` and compares the key's digest with those it signed: a key it never signed raises `SidecarEvent` `key_changed` with the foreign digest, whose remedy is an active clone's, `SidecarRevoke{reason: compromise}` and a new enrollment. ReaderKey keeps its three fields, and Q-KEYS-2's residual stands (§10.5's Ladder and readerkey rows, §10.15, §5.4, §2.18).
    - Cost: one GET a day and one defined alarm; it detects a replaced key only after wraps may have been issued, and only where the operator does not hide it, but it also flags a classical clone.
    - Not taken: (1) the text fix alone, under which a forged or cloned ReaderKey raises no alarm anywhere; (3) an ML-DSA-65 signature on ReaderKeys from v0, which closes this route only, leaving admissions forgeable, adds ML-DSA keys to admissions and about 3.3 KB per ReaderKey, and pulls §10.16's Later work forward.
    - Raised by the G0 re-check (the build's ledger, QD-046).

359. **The 0x0010 gate keeps its rows and claims what they show: the draft's vectors are X-Wing's only independent evidence, and tmc/mls's comparison checks wiring (option 1, the recommendation, accepted with the build's owner items in bulk on 2026-11-06).**
    - Question: tmc/mls takes X-Wing from Go's crypto/hpke, as mls_* does, so §10.4's kem row passed by construction, and §10.4 left out the draft KATs that §22.10 has.
    - Answer: §10.4's kem row takes §22.10's first clause, the draft's X-Wing vectors passing for crypto/hpke's MLKEM768X25519, DeriveKeyPair included, and both rows say tmc/mls's comparison shares that code, so it checks wiring, not X-Wing; the artifact states that the draft's vectors are the only independent X-Wing evidence. OpenMLS stays as §22.10's required row has it, needed only if a required step has a gap, and the stacks row's tree, key schedule, framing and Welcome evidence stands (§10.4, §22.10).
    - Cost: a drift that Go and tmc/mls shared would surface only at IANA's assignment, which D-KEYS-12's migration covers.
    - Not taken: (2) OpenMLS's X-Wing KAT required for the freeze, a Rust build on the test leg that the freeze then waits on; (3) a small pure-Go X-Wing in mlsinterop/ for KATs, ours over Go's ML-KEM and only partly independent.
    - Raised by the build (plan-KEYS; the build's ledger, QD-273).

360. **The ladder's AADs take the widths as built, u64be for g and e and u8 for the cause, and gen/1 carries cause REQUEST (option 1, the recommendation).**
    - Question: §10.5 wrote the ladder's AADs as concatenations without widths, and named no cause for generation 1, which has no parent.
    - Answer: GenLink's AAD is repo_id || u64be(g) || u8(cause_g), 25 B; GenWrap's and LeafWrap's group_id || u64be(e) || u64be(g), 32 B; GroupInfo's group_id || u64be(e), 24 B. gen/1 carries cause REQUEST, and a reader refuses REMOVE there; testdata/gkm/ladder.json pins the bytes (§10.5).
    - Cost: none in code; the widths freeze with the delivery wire at M2's exit.
    - Not taken: (2) u32be for the cause, the field's width, a line of code and regenerated vectors; (3) gen/1's cause free between REQUEST and SCHEDULE, two shapes for one statement.
    - Raised by the design details (DESIGN-DETAILS.md section 6, restating keys-ladder-aad-widths; the build's ledger, QD-615).

361. **draft-ietf-mls-extensions' `last_resort` extension, type 0x000A, marks a last-resort KeyPackage (option 1, the recommendation).**
    - Question: §10.4 lists last-resort KeyPackages and named no extension or number that marks one.
    - Answer: the `last_resort` extension, type 0x000A with empty extension_data, in KeyPackage.extensions only, every leaf listing 0x000A and 0xF553 in its capabilities; a device that joined through its last-resort KeyPackage commits a path-only self-update at its first opportunity and replaces the KeyPackage at its next upkeep pass. D-KEYS-12's suite migration moves the number if the draft's does (§10.4).
    - Cost: a draft's number, which a migration would move with the suite's.
    - Not taken: (2) a private-use type beside ur_group, 0xF554, stable but read by no other stack; (3) no extension, the route or gkm's key saying which, which changes QD-526's accepted request and gkm-4's row.
    - Raised by the design details (DESIGN-DETAILS.md section 6, restating keys-m2-07-last-resort; the build's ledger, QD-616).

362. **A re-formed group's epoch 0 carries no auth pin, and epoch 1 takes its floor from `gen/<the form's generation>`'s auth (option 1, the recommendation).**
    - Question: the epoch PUT check holds each epoch's auth pin to the previous epoch's, and a re-formed group's epoch 0 carries none, so epoch 1 had no floor.
    - Answer: the check gives epoch 1 of a re-formed group the floor of `gen/<form.generation>`'s auth, which the ladder writes before the group takes any commit, wrap or claim (§10.8's wait row); no wire change (§10.6's epoch PUT check).
    - Cost: one sentence; KEYS-M2-25 had built it.
    - Not taken: (2) the form's generation's Signed GenRotate in the reform request and a ladder check, the same bytes twice; (3) epoch 0 written through the epochs route after the ladder, a special case there and a third route in deleted mode.
    - Raised by the design details (DESIGN-DETAILS.md section 6, restating keys-wire-reform-epoch-zero; the build's ledger, QD-617).

363. **Welcome pointers are keyed `gkm/welcome/<sidecar_id>/<group_id>/<n>`, and the KeyPackageRef moves into the pointer (option 1, the recommendation).**
    - Question: pointers keyed by the KeyPackageRef their Add used collided when one last-resort KeyPackage served two Adds, and the later overwrote the earlier Welcome's.
    - Answer: a pointer's key names its recipient, group and epoch, n in 20 digits, and `GkmWelcomePointer` carries `key_package_ref = 3`; a device holding several pointers for one group takes the highest n above the newest epoch it reached. One Welcome, one key. It changes the family's key form in QD-442's encoding, and §2.8's gkm-5 says the pointers' key and their ref (§10.6, gkm-5).
    - Cost: one key-form change and one field, unfrozen until M2's exit.
    - Not taken: (2) `<ref>` for one-time KeyPackages and `<ref>/<group_id>` for the last-resort one, two key forms in one family and a path-prefix pair; (3) keeping the key and overwriting, with a committer re-adding after 10 minutes, a delay per lost join that still loses the Welcome.
    - Raised by the design details (DESIGN-DETAILS.md section 6, restating keys-m2-13-last-resort-welcome-pointer; the build's ledger, QD-618).

364. **gkm answers forwarding Delegations' reader keys in batches of up to 256, `POST /gkm/delegation-keys`, beside the GET (option 1, the recommendation).**
    - Question: a config rotator read each forwarding Delegation's reader key by a GET of its own, about 3,300 requests a rotation at Team scale.
    - Answer: `POST /gkm/delegation-keys {delegation_ids, at most 256}` answers each stored key or none, in order, under the GET's scope, a reader of the network's config, as the reader-keys route does; one request and one reply message before M8's freeze. A config rotator reads through it, about 13 requests a rotation at Team scale (§10.5's step 3, §10.6's scopes, §10.14).
    - Cost: one route and two messages.
    - Not taken: (2) the GET alone, each rotator caching the keys it verified, about 4 MB of keychain per config writer, a phone's included; (3) the GET alone, issued concurrently, about 3,300 requests a rotation that §11.13's read side and the lb all see.
    - Raised by the build (KEYS-M8-01; the build's ledger, QD-637).

365. **A member device forms the group of a repo a tagged or ephemeral sidecar creates, as a config writer that reads the repo and holds its admin at gkm (option 2 of the first question, then option 3 for M2, each the recommendation).**
    - Question: KF1's epoch 0 needs its creator's leaf and an agent holds none, so a repo an agent creates had no group; and then which member device may form it when no config writer reads that repo or holds its admin scope.
    - Answer: the agent files the RepoCreate, places the repo and stays its admin (owner decision 8). gkm hints `pending` to the network's config writers for a keying repo with no GroupForm; the first to act that is a key holder of the repo and holds admin on it at gkm, which §8.5's implicit document gives every member device, runs KF1 as the group's creator, epoch 0 holding its own leaf, and wraps generation 1 to the agent, which then has evs activate the repo. Activation waits for that device, as an agent's every Add does; a repo an agent creates while no such device is online, or under a narrower ACL document that gives no member device both rights, stays keying, which leaks nothing. Revisited when Team policies can narrow member devices' evs rights (M6), the candidate being the first acting config writer filing `RepoGrant{reader}` and `RepoAdmin{add}` for itself (§10.7's KF1, §10.6's pending row, §8.8's RepoCreate). QD-659 governs QD-638's "the first member device to act".
    - Cost: a hint rule and a second device in KF1; an agent's repo waits for a member device online.
    - Not taken: for the former, (1) agents creating no repo that needs a group of its own, which changes §8.8's row and an agent's record repo; (3) a group with an empty tree, which is not RFC 9420; for its rights, (1) the acting config writer granting itself read and admin now; (2) hinting the repo's member-device readers that hold its admin instead, leaving a repo with none keying with an alarm.
    - Raised by the build (KEYS-M2-19 and KEYS-M2-32; the build's ledger, QD-638, QD-659).

366. **The MLS engine meets the phone budget by keeping the tree on disk and streaming it, and the SDK keeps bulk state on storage (option 1, the recommendation, with the owner's direction).**
    - Question: a 1,000-leaf group's join, path commit and resync measured 27 to 63 MB of heap above their baseline, three to six times the phone budget's estimate.
    - Answer: the review phase brings the engine under the budget, measured on the ios32 cell first: the ratchet tree and other large state stay on disk and stream, a path sealed and written a node at a time and the tree hashed and encoded from its on-disk sections, with one decode for a resync and a copy-on-write of the path in place of a whole-tree clone before a commit; no format or flow changes. The owner's direction: "Optimize in review. The sdk should offload to memory to storage where possible. The iso extension and apps have much more fast nvme storage available than ram." The SDK, the apps and their VPN components keep bulk state on storage and hold RAM as a working set. Until then the harness reports the peaks and fails nothing on them; if the cell still reads over budget, bounding a 32 MiB leg's roles is raised as its own question (§10.5, D-KEYS-14, §10.15).
    - Cost: engine work in the review phase; the blank-parent path's own output is 1.18 MB plus 999 encapsulations, so the estimate may still be out of reach there.
    - Not taken: (2) bounding a phone's roles, never the committer of a large blank path and never a leaf of a tree past a size, reading larger groups by wraps, a rule every committer must hold; (3) changing the claim and the iOS budget.
    - Raised by the build (KEYS-M2-23; the build's ledger, QD-641).

367. **A code-only device fetches its recovery wraps before admission and opens them once admitted (option 1, the recommendation, as built).**
    - Question: §10.8 and §7.9 said the code opens M's recovery wraps at once, before admission, but an unadmitted client reads only 8 bytes of C_g, which the wrap's AAD binds whole, and reaches no gen/ route.
    - Answer: before admission the device fetches its wraps under `recovery:<member_id>` and keeps the newest per group in its keychain; it opens them once admitted, when `gen/<g>` reaches it: the config group's first, then §7.9's anchor, then the rest. A code holder with the operator's ciphertext and gen/ objects still reads every generation wrapped to the key, so §2.10's disclosure stands (§10.8, §7.9's before-admission row).
    - Cost: none; no format or scope change.
    - Not taken: (2) the recovery read answering all of C_g, a field and a gkm-8 line, the opened key still unjudged until admission; (3) letting `recovery:<member_id>` read gen/, a scope change with the same unjudged key.
    - Raised by the build (KEYS-M2-24; the build's ledger, QD-642).

368. **A GroupForm carries its signer's auth pin, and members judge the signer at that pin (option 1, the recommendation).**
    - Question: members judged a form's signer at their newest state, which strands a lagging member once the re-former is revoked.
    - Answer: `GroupForm` gains `AuthPin auth = 5`, the signer's state when it signs. Members judge the signer by §10.6's rule at that pin where their retained log reaches it, and not at all before it, as every other judged statement is judged; gkm holds the pin to its newest state as it holds a claim's, on the chain and not ahead (§10.6, §10.8's members row, §2.8 gkm-1).
    - Cost: one field before M2's freeze and gkm-1's words.
    - Not taken: (2) a filing time gkm stamps, unsigned and movable by a server; (3) the newest state, documenting that a lagging member returns by a re-add or its recovery code.
    - Raised by the build (KEYS-M2-25; the build's ledger, QD-643).

369. **The window in which a wrapped writer, or a leaf racing a poisoned commit, seals to the generation it carried until the refusing member's REMOVE rotation reaches it is accepted (option 1, the recommendation).**
    - Question: after a compromised leaf commits a tree that holds a party dropped at the commit's own header, the members that process it refuse it, but a wrapped writer, which reads no commit, and a leaf whose seal races the commit may seal to the generation it carried until the refusing member's rotation reaches them.
    - Answer: the window stands: the commit needs a compromised leaf, which already holds that generation's key and could hand the dropped party the same content or the key itself, so the window adds no reach the attacker lacks, and the refuser's rotation ends it at once. No rule, format or model change (§10.9's window row).
    - Cost: content sealed in the window reaches the dropped party only through an attacker that could pass it on anyway.
    - Not taken: (2) a narrowing rule for the review phase, wrapped writers checking each generation's commit roster or a signed refusal notice that gkm relays, at the cost of MLS processing on agents or a new notice, and latency on rotations.
    - Raised by the orchestrator's review of DESIGN-DETAILS.md section 6 (the build's ledger, QD-695).

370. **A forwarding Delegation's reader key object is `gkm/dkey/<network_id>/<delegation_id>`, and gkm's reconciler deletes it 24 h after the Delegation's end by tracked ends and a sweep of the network's prefix (option 1 of each question, the recommendations).**
    - Question: a forwarding Delegation's row can leave the rows before the reconciler deleted its key object, so the object outlived §2.8's ttl; and a sweep after a restart could not tell which network's rows a key named only by its `delegation_id` answers to.
    - Answer: the object's key names the network the token gives at the upload and the read, an opaque id (I-13); the reconciler keeps a tracked end of a forwarding Delegation past its row's leaving the rows and deletes the object `DelegationKeyRetention`, 24 h, after the end, and now and then, and after a restart, lists one network's prefix and deletes at once any object that no forwarding row in the state's rows and no tracked end names, its row gone and its retention passed by at least 4,096 positions. A network's shred or a hold finds its key objects by the prefix, and §2.8's ttl holds at any entry rate and across restarts. This amends owner decision 202's key, `gkm/dkey/<delegation_id>`, and QD-442's path form for the family, which nothing in production held (§10.6, gkm-1).
    - Cost: a list of one network's prefix now and then.
    - Not taken: for the deletion, (2) a diff of two states' Delegations at each base, keeping the previous state per network; (3) accepting the leak, which weakens a published ttl; for the network, (2) object metadata naming it, a HEAD per unnamed object and a change to §19.6's metadata rule; (3) a marker object beside each key; (4) no sweep, an object standing until its network's shred.
    - Raised by the build (TEAM-M2-21 and the core lane's owner fixes; the build's ledger, QD-675, QD-763).

371. **gkm and taskworker's gkm reconciler read authorization through ACL's one gate cache, which a taskworker start tells of every gkm network (option 2 of the first question, option 1 of the second, the recommendations).**
    - Question: no plan built gkm's authorization state over the gate cache, for the gkm block or for taskworker's reconciler; and after a restart that cache held only networks whose log had moved since, so a quiet network's pending hints, key deletions and sweeps waited for its next entry and §2.8's ttls slipped.
    - Answer: a KEYS task builds both views in gkmservice over the gate cache's exported API: the gkm block's, a token's standing and its honored scope through ACL's scope check for the gkm audience with the answers only gkm needs (readers, writers, pins, Delegations, late holders and dropped holders), and the reconciler's, each network's moves, the networks the host holds, a network's newest state and a sidecar's network. ACL adds to the cache, as a small separate change, its network list, a sidecar-to-network index and a callback when a network's new state is installed, so a reconciler a hint wakes reads the new snapshot. Every gate check stays in ACL's one cache, and until both views land the gkm block and the reconciler fail closed. At a taskworker runtime's start the reconciler's cache is told of every network with a config log and a gkm-gated service enabled (sidecar.yml's `gkm:` networks), listed from Postgres a page at a time under the cache's load concurrency and a page rate, both settings, and a network the bounded cache evicts is told again when the reconciler next reads it (§10.6, §8.9).
    - Cost: a cold load of every gkm network at each taskworker start, spread by the page rate (§8.18's fan-out risk), and a cache sized for them all or one that cycles.
    - Not taken: for the builder, (1) ACL building gkm's state beside evs's and KEYS the reconciler's; (3) a second copy of the scope check until ACL's lands, which the one cache exists to prevent; for the networks, (2) a durable index of what the reconciler must come back to, a new family §2.8 must list; (3) waiting for each quiet network's next entry.
    - Raised by the build (KEYS-M2-17 and the gkm-auth-state track; the build's ledger, QD-718, QD-893).

372. **gkm answers whether an epoch's Welcome stands, `HEAD /gkm/groups/<id>/welcome/<n>`, so any writer leaf re-adds a joiner whose Welcome never came (option 1, the recommendation).**
    - Question: §10.6 has a writer leaf remove and re-add a joiner whose Welcome the uploader never wrote, but no leaf other than the uploader could learn that the Welcome was missing.
    - Answer: `HEAD /gkm/groups/<id>/welcome/<n>` under rw answers 200 or 404 with no body. A writer leaf that adopted an Add at epoch n asks once after `GkmSettings.WelcomeTimeout`, 10 minutes, and on a 404 removes and re-adds the joiner in one commit. It discloses nothing beyond gkm-5's Welcome objects, whose keys every reader can compute; a false 200 leaves the joiner waiting and a false 404 costs one Remove and Add (§10.6's Welcomes row, §10.14).
    - Cost: one route.
    - Not taken: (2) a flag per entry in the epochs reply, read at catch-up rather than 10 minutes later, with a §2.8 line; (3) a joiner asking by a new hint kind and route, from a device that holds no key or leaf.
    - Raised by the build (KEYS-M2-19; the build's ledger, QD-747).

373. **A network's first device draws the config group's id and RK_1 before base 1 and signs GenRotate_1 after it (option 1, the recommendation).**
    - Question: base 1 names the first config head, whose push is sealed and signed before base 1 under a generation pin, while GenRotate_1's auth pin must be past position 0 and gkm's gate holds nothing before base 1.
    - Answer: at bootstrap the first device draws the config group's id and RK_1 before base 1 and keeps them as KF1's draft; it seals and signs the first head's push with them, auth {0, A_0} and generation pin {group_id, 1, C_1}, and publishes base 1; then it signs GenRotate_1 at S(1) over that RK_1, runs the rest of KF1 and sends the push. C_g holds no pin, which makes the split sound, and every rule stands: the push's pin, every GenRotate's pin floor and gkm's gate holding nothing before base 1 (§7.9's bootstrap, §10.7's KF1).
    - Cost: a bootstrap draft at the group client, the config kind's prepare and commit at the evs client, and the bootstrap's order.
    - Not taken: (2) a config generation pinned at the genesis, a second pin exception with a holders hash that names no holder, reaching gkm before its gate holds a log; (3) base 1 naming no head, which changes the bootstrap row, api's base-1 check and every reader's base check.
    - Raised by the build (the daemon's evs and gkm clients; the build's ledger, QD-824).

374. **gkm's client reads a 502 or 504 the lb answers as no answer from gkm, never as gkm's refusal (option 1, the recommendation).**
    - Question: gkm never answers 502 or 504 itself, its routes buffering at the lb, yet its client read them as gkm's refusals.
    - Answer: a 502 or 504 whose body is not a gkm refusal is the lb's, no answer from gkm at all, an error its callers take as a transport error: KF7's fallback is taken, the Welcome watch is kept, and a write's outcome is unknown and resolved as after a lost answer, never judged refused (§10.7's KF7).
    - Cost: a few lines in the client.
    - Not taken: (2) leaving it, so a transient lb answer drops a Welcome watch, misses KF7's fallback or judges refused a write that may have applied.
    - Raised by the build (evs-502-retry; the build's ledger, QD-876).

375. **A committer that gkm refuses only because a newer generation stands takes it and commits again without alarming, and each pass starts from gkm's newest generation (option 3, with option 2 as its first step, the recommendation).**
    - Question: a wrapped rotation can move gen/ past a commit's header between the committer's read and its PUT, so gkm's epoch PUT check refused a commit whose checks had passed, and the committer alarmed `refused` on a benign race.
    - Answer: on a 403 to its own commit whose checks it passed, the committer reads gkm's generations once (`GET gen?since=` its header's); if a newer generation stands, it takes it under the rotation checks and the ladder, restages the commit with that generation in its header and commits again, as one of the pass's attempts, raising no alarm; it alarms `refused` and waits only when no newer generation explains the refusal, or when the newer one fails its checks, which raises that check's own alarm. Each pass of the pending engine also reads gkm's newest generation before its first commit. `refused` keeps its meaning, evidence against a party (§10.6's refused row, §10.9).
    - Cost: one read per pass and one on a 403.
    - Not taken: (1) keeping the alarm on the race, liveness resting on the hint or the hourly resync; (2) the per-pass read alone, which narrows the race to a rotation between that read and the PUT.
    - Raised by the build (KEYS-M2-27; the build's ledger, QD-956).

## The build's owner questions on encrypted versioned storage (2026-11-11 to 2026-11-16)

The design-records track for §11 folded the answers below on 2026-11-16, each citing its ledger id: those the owner decided one at a time from 2026-11-11 to 2026-11-15, and the recommendations of 2026-11-15 that the owner's instruction of 2026-11-16 accepted, which the ledger dates 2026-11-15. A decision that groups several answers carries its latest answer's date. §11's items the owner accepted in bulk on 2026-11-06 are defect fixes, and the rest of its items the build's readings, fills and settled items, so they went into §11 as text with no number; QD-968, which the slot origins answer, is cited under 399.

376. **A statement in parts may state no change at all, a DROP's lists may fill changeless parts after its last change, and a seal's part item may name the root's empty path (option 2 of the first question, option 1 of the others, the recommendations).**
    - Question: a git-mode push whose net change is empty but whose carried commits and history blobs pass one part (a tag over a long unheld history, or an UPDATE whose tip tree is unchanged) could not go in parts, since every statement in parts stated changes; a DROP whose lists need more parts than its changes fill had no part to carry them; and the seal record's parser refused the 52-byte part item that names the root's empty first token path, which the writer already wrote.
    - Answer: a statement in parts may state an empty change list, change_count 0 and changes_root RFC 9162's empty tree (SHA-256 of the empty string), with no changed_prefixes and every part changeless; in format 2 a DROP's parts after its last change may hold only `sections` slices of its lists, with no changes_root, joining no Merkle level, counted by part_count and bound by parts_sha256, the statement's root covering only the parts with changes, as owner decision 239 has it for spilled sections; and a seal record's part item of exactly 52 bytes (its place and changes_root) is the root's empty first path (§11.6's merkle row, §11.8's parts and batch record rows).
    - Cost: the statement shape and the seal's root for zero changed parts change before M2's freeze, and every parser and the seal check take it; the builder refuses such a push until it is built.
    - Not taken: for the empty statement, (1) pushing the history to a helper ref first and naming it as a source, and (3) keeping the local refusal; for a DROP's lists, (2) continuation parts past part_count bound by a hash in the DROP body, and (3) capping a DROP's lists to its changes' parts; for the root's item, (2) a seal record that never names the empty path.
    - Raised by the build (EVS1-M2-48, EVS1-M2-40, EVS2-M10-03; the build's ledger, QD-658, QD-661, QD-738).

377. **A push attempt judges 5d against the gate view it reads at each run of step 4, and evs takes a token's (sidecar, client) pair as §5's binding, as the exchange bound it (option 1 of each question, the recommendations).**
    - Question: a push attempt judged 5d against the gate view it bound at arrival, even when it reran steps 4 and 5 after step 7's window or a 412, against §11.8's "the newest authorization state evs holds"; and evs had no way to match a token's ur_sidecar_id to §5's binding, the authorization log carrying no client ids and evs holding no Postgres.
    - Answer: each run of step 4, the first and every rerun, reads the gate view again, and 5d judges against it, the view bound at arrival serving only 5b's identity check, at one map read a rerun; evs takes the token's (ur_sidecar_id, ur_client_id) pair as the exchange resolved it when it minted the token, checking in its own state only that ur_sidecar_id is an admitted, unrevoked sidecar of the token's network, so a rebind's old client reads for at most a token's 15 minutes and its writes meet the rev/ object every write reads (§11.8's authorization row, step 4 and 5d).
    - Cost: a map read per rerun; no lookup route, cache or log field.
    - Not taken: for the gate view, (2) keeping the bound view and refusing a rerun whose view is over 5 s old with 503; for the binding, (2) a cached lookup through api's internal route, a second assertion of api's as the token is, and (3) each sidecar's client id in SidecarRow, a format change and a server-visible column the log cannot verify.
    - Raised by the build (EVS1-M2-40, ACL-M2-11; the build's ledger, QD-660, QD-717).

378. **evs's read reply carries a directory's unfolded deltas a frame each with their proofs, ends with an error frame when it cannot encode one, and proves a prefix's delta present, every proof repeated, part level last (option 1 of the first two questions, and of the third as built, the recommendations).**
    - Question: a directory at its 448 KiB bound whose rows were still in unfolded deltas spread over a push's parts could not list in one path frame; a reader could not verify a directory delta in a walked statement whose change list was under changes_root, the reply having no place for its proof, nor tell a prefix's delta from a change of the path; and QD-681's present proof read as one proof where a push in parts needs two levels.
    - Answer: the reply carries a path's unfolded deltas past the first a frame each with its proof (`continues`), so any directory within its bound lists in any fold state within the 1 MiB + 64 KiB frame bound, and a frame evs cannot encode is logged and ends the stream with an error frame, never silently; EvsReadPathReply gains `delta_proofs = 19`, one EvsDeltaProof a delta, empty for an inline statement, and EvsAbsenceProof gains `repeated EvsMerkleProof present = 5`, part level last like every other proof, the inclusion proof of a prefix's change, which a reader takes only for a strict prefix whose change writes an entry, a delta, and refuses for the path itself or a removal (§11.6's merkle row, §11.9's reply and reader rows).
    - Cost: two fields and a frame rule before M2's freeze; no new server-visible data.
    - Not taken: for the frames, (2) folding on the read path and (3) a larger frame bound; for the proofs, (2) a proof field on EvsIndexVersion, a stored format a fold must never write, and (3) no wire change, the reader asking again for each case; for present, a single proof, which leaves a prefix's delta in a push in parts unproven and its reads refused.
    - Raised by the build (EVS1-M2-40, EVS1-M2-28; the build's ledger, QD-662, QD-681, QD-904).

379. **evs's read, refs, log and subscription routes refuse a deleted repo 409 REPO_DELETED and a shredding or shredded one 409 SHREDDING (option 1, the recommendation).**
    - Question: §11.12's refused row closes every route but restore and DELETE with now while a repo is deleted, and the read routes and subscriptions still served it.
    - Answer: those routes read repo/ from the 5 s repo cache the upload route uses and refuse as the refused row says (§11.9's request row, §11.12's refused row).
    - Cost: one cached repo/ read a request.
    - Not taken: (2) refusing only while shredding or shredded, which departs from the refused row's text.
    - Raised by the build (EVS1-M2-41; the build's ledger, QD-665).

380. **evs serves a removed path's earlier versions and earlier lives by number, the removal from the window once its marker is collected, and a folded directory's marker version as names_through + 1 (option 1 of each question, and of the last option 2, the recommendations).**
    - Question: History of a removed path repeated its removal, so §11.12's closure could not list its versions' slots; a mailcfg reader starting fresh saw only a re-created record's newest life; a reader whose walk held a removal whose marker was collected got the path plain absent, which its absence proof refused; and a removal marker had no exact path version for a directory whose newest delta was already folded.
    - Answer: a read by number serves a removed path's versions below its removal from the entry's folded versions, and a number the path holds no version at answers its newest version below it, so History walks into the removal before a creation and the life it ended, stopping with an alarm on a walk that does not descend; once a marker is collected, a window version at or below folded_through that removed the path is served as its removal; and a marker written for a directory whose newest delta is folded carries names_through + 1, an upper bound versions only skip past, EvsIndexEntry's number 6 kept for an exact names_version should M2's entry review want it (§11.7's versions and history rows, §11.9's reply row).
    - Cost: read-path work and a scan of the window statements a read already holds; no format change.
    - Not taken: for history, (2) History stopping at a removal, leaving a removed path's slots unreachable; for earlier lives, (2) mailcfg records never removed but marked deleted, and (3) accepting the newest-life limit; for the collected removal, (2) the client taking plain absent as absent and (3) leaving a writer stuck until its pin moves; for the marker, (1) a names_version field and (3) the removal's own ref version.
    - Raised by the build (MAIL-M8-02, MAIL-M7-04, TEST-M2-04, EVS1-M2-10; the build's ledger, QD-672, QD-888, QD-879, QD-930).

381. **A reader opens each sealed name and record of an unfolded version with the keys of the generation its own statement names (option 1, the recommendation).**
    - Question: a reader failed to open a file a PATH_EPOCH's tail carried, created in the source epoch by a push of a newer generation, until evs's copy had run, since it opened sealed values with the epoch's or the tail move's generation.
    - Answer: every sealed value of an unfolded version opens with the keys of its push's own generation, so every committed version stays readable across any cut-over (§11.6's tail row).
    - Cost: the read path's key choice.
    - Not taken: (2) writers never creating a name in an epoch under a newer generation while a due is batched, a write rule the design did not state.
    - Raised by the build (EVS1-M2-41; the build's ledger, QD-666).

382. **The in-house MinIO build makes a LIST whole for a key whose overwrite is in flight, and until it does, the fold's marker LIST lists twice and takes the union (option 1, the recommendation).**
    - Question: on the local stack a LIST left out a key whose overwrite was in flight with every drive online, so owner decision 226's whole LIST did not hold for keys evs rewrites in place.
    - Answer: a key an asked drive holds whose xl.meta read failed other than not-found is read again under the key's lock, or the LIST answers 503 rather than leave it out, so evs's listers decide on no LIST that drops a key; known heads and slots are still read by key (§11.13's needs row, §19.6's list row).
    - Cost: a rule in the fork with its probe as the test, and an interim double LIST at the one site found.
    - Not taken: (2) evs never deciding on a LIST of an in-place family, a change at each such site; (3) accepting the gap, which leaves markers open.
    - Raised by the build (EVS1-M2-41; the build's ledger, QD-663).

383. **evs's newest rule, and every reader of a window version's record, finds it through pidx/ once evacuation has moved its batch (option 1, the recommendation).**
    - Question: the newest rule read a window version's record from its batch, which evacuation may have deleted, while a read's statements already fell back to pidx/.
    - Answer: on an evacuated record every reader falls back to pidx/ and caches the record: the newest rule, fold, purge, collect, step 4 and the log route (§11.8's batch read row).
    - Cost: none on the store; no new head write.
    - Not taken: (2) evacuation raising folded_through before deleting a batch that holds window versions, a head write per idle ref.
    - Raised by the build (EVS1-M2-41; the build's ledger, QD-664).

384. **An ERASE's and a CLOSURE's note is EvsSealedMetadata.erasure_note: the erasure's id, a completion byte and the caller's bytes (option 2, the recommendation).**
    - Question: the erasure's sealed note, which reconcile resumes from, had no home or bytes.
    - Answer: erasure_note (8) holds the erasure id (16 B) | complete (1 B, 1 when the push ends the erasure) | the caller's bytes (a record's SealedNote, mail's documents), sealed with the push's metadata; a CLOSURE's holds its erasure id and no caller bytes; the ERASE changes nothing on the erasure ref, a creates-only push of no change, and reconcile resumes from evs's state (§11.6's Bytes, §11.12's push, rekey and reconcile rows).
    - Cost: one sealed field, written ahead of its fence by the code track.
    - Not taken: (1) the note as a creation on the erasure ref, a file per ERASE; (3) the callers' records alone, which reconcile cannot reach.
    - Raised by the build (EVS1-M2-30; the build's ledger, QD-682).

385. **A search-index diff rests only on a full entry in its own writer's files, which that writer keeps, and a roll-up promotes a carried entry into a newer bucket's shards instead of rewriting its files (option 1 of each question, the recommendations).**
    - Question: a diff could rest on a shard or another writer's sealed slot, which a merge or another device's push could take from under it, and a roll-up rewrote a newer bucket's files in place when it carried an entry that bucket held only older versions of, racing that bucket's merges.
    - Answer: a diff rests on a full entry of its document in another file of its own writer in its own bucket (a sealed slot that is not its head, or a large entry) and nothing else; the writer keeps that file while a diff of its unabsorbed slots rests on it; every push that writes a writer's file replaces that writer's head at the version read; a merge reads no head and removes no writer's file. A roll-up writes a carried version or tombstone into the shards of the newest bucket holding an entry of its document, in its own push, which replaces or creates that bucket's manifest, nothing being removed from that bucket; no all row is newer than the newest bucket entry of its key (§11.14's dependency, conflict, merges and roll-up rows, I-EVS-11, FI-20).
    - Cost: a writer's first entry of a document in a bucket is full until its head seals; a writer keeps up to 8 slots (128 KiB) a bucket past their absorption; an absorbed large entry waits for its writer's next push there or the roll-up.
    - Not taken: for bases, (2) keeping shard and sealed bases with patches for each race and (3) no diffs, some 20 to 30 times the slot bytes; for the roll-up, (2) the in-place rewrite with the newer manifest replaced in the same push and (3) merges dropping what an older bucket supersedes, which every merger must then hold.
    - Raised by the design details (DESIGN-DETAILS.md section 1; the build's ledger, QD-685, QD-686).

386. **An index entry that trails its content is held by the content pin and a push's life on the client, with an evs counter at roll-ups named as the review phase's fallback (option 1, the recommendation).**
    - Question: an index entry built late could land below a tombstone a roll-up had already dropped.
    - Answer: the builder takes its signed time, reads the index head, then each content ref's head, and drops an entry whose document that pin holds at a higher version or removed; it sends the push only within 5 min of its signed time (25 min in parts) and never resends a stored push after 429 TIME_AHEAD; a merge names no expired bucket and a roll-up only an expired one, judged at the push's signed time; hosts with the text check each live entry and backfill a missing tombstone (§11.14's companion and merges rows).
    - Cost: the accepted residual of a device whose clock ran about a week fast, stalled that long and then sent its stored bytes, which a host with the text repairs, naming the signer.
    - Not taken: (2) evs moving a head counter at every roll-up and refusing an index push built before it, kept as the fallback; (3) all keeping tombstones.
    - Raised by the design details (DESIGN-DETAILS.md section 1; the build's ledger, QD-687).

387. **A merge keeps rewriting every shard that holds an older version of a document it carries, and the lazy alternative is measured in the review phase (option 1 now, option 2 measured, the recommendation).**
    - Question: whether a merge leaves superseded rows masked until their shard is half dead, which an edited repository's merge cost argues for.
    - Answer: a bucket's shards hold one version per document (I-EVS-11) and an eraser finds a document in one shard of each partition; before M10's exit freezes the bytes the lazy alternative is measured on FS-76's corpus, since it reaches into the erasure's bounds (owner decision 146) (§11.14's merge output row).
    - Cost: the merge cost of an edited repository, accepted for now.
    - Not taken: (2) lazy superseded rows now.
    - Raised by the design details (DESIGN-DETAILS.md section 1; the build's ledger, QD-688).

388. **Fourteen readings of §11.14 stand as written (option 1, the recommendation).**
    - Question: where §11.14 left a choice, section 1 of DESIGN-DETAILS.md made fourteen readings that change no D- item.
    - Answer: as §11.14's readings row lists them: expiry at the push's signed time, absorbed slots and large entries only a diff's base, a manifest with no shard, the header coverage's order, an entry's time and bucket, a merge's tie order, the youngest shard's fill, a merge with nothing to add, a large push writing its head, the lock's renewal, a coverage-only companion push, a multi-chunk file replaced without its text, a roll-up's horizon rows, and journaled units at or below a horizon (§11.14's readings row and merges row).
    - Cost: none beyond the tasks that carry them.
    - Not taken: (2) correcting any by number.
    - Raised by the design details (DESIGN-DETAILS.md section 1; the build's ledger, QD-689).

389. **Extractor 1 defines its own decoders as rules of the index format, cuts a header at 16,384 B and reads a long delimiter or soft break as text, and stands in thirteen readings (option 1 of each question, the recommendations).**
    - Question: extractor 1 leaned on standard-library parsers whose behavior a Go release could change, held a whole header or line in memory, and left thirteen readings open where §11.14 and INDEX-FORMAT.md were silent.
    - Answer: its base64, quoted-printable, character-reference, header and whitespace rules are the format's, written in protocol/INDEX-FORMAT.md, HTML's reference table in testdata/index/conformance/entities.json, with conformance vectors holding both implementations to them; a charset label is read as bytes and the replacement encoding's labels pass as bytes; HeaderMax (16,384 B) cuts a header line and one name's joined values, and LineWindow (1,024 B) reads a longer delimiter line or soft break's blank run as text, so extraction runs in one pass in at most 150 KiB beyond the normalizer; the thirteen readings stand, each pinned by a vector (§11.14's own, charsets, html and readings rows). It replaces three sentences of QD-474's fill.
    - Cost: about 400 lines in each implementation, some 32 KB of table on the legs that index, and a header value's tail past 16 KiB unindexed.
    - Not taken: (2) the Go release as part of extractor 1's identity; (3) writing down what the library calls do today; for the bounds, (2) none and (3) four times larger.
    - Raised by the design details (DESIGN-DETAILS.md section 11; the build's ledger, QD-690, QD-691, QD-693).

390. **A remote-search body that is not its message's one deterministic encoding, or holds a field its receiver does not know, is refused (option 1, the recommendation).**
    - Question: a body could carry bytes in an unknown field or a second encoding, so the size and pad rules spoke of more than one body.
    - Answer: a receiver takes a body only with no unknown field at any depth and when marshaling the parsed message deterministically gives the same bytes, then checks pad is zeros; a failed request is INVALID and a failed reply no reply; the version is judged first, so a later version's request is UNSUPPORTED_VERSION, and a requester raises search_version to send a new field (§11.14's status row).
    - Cost: one more marshal and a comparison a body.
    - Not taken: (2) accepting whatever parses.
    - Raised by the design details (DESIGN-DETAILS.md section 11; the build's ledger, QD-692).

391. **A remote search asks the first two own search indexers at once, both kept warm from each foreground, with no hedge delay, and eleven readings of the remote search stand (option 2 of the first question, not the recommendation, and option 1 of the second).**
    - Question: §11.14 had own indexers "hedged in parallel" with no delay, and section 7 of DESIGN-DETAILS.md made eleven readings of §11.14, §18.4 and §7.9.
    - Answer: the first two own indexers are asked at once for the repos each may answer, both own pairs held warm by the foreground Hello and its keepalive, so no contract opens at a search; the first page 0 to serve a repo wins it and the other reply is dropped; Search.RemoteHedgeDelay does not exist; other members' indexers are asked one at a time as before; the readings stand, the tenth replaced by this (§11.14's order and readings rows, §18.4's remote row, D-SDK-27).
    - Cost: two exchanges and two indexers' CPU a search, and a second own pair's window floor, 512 KiB of transfer balance an hour, a foreground.
    - Not taken: (1) a second indexer asked after Search.RemoteHedgeDelay, 1 s (1.5 s metered), the recommendation; (3) no hedge.
    - Raised by the design details (DESIGN-DETAILS.md section 7; the build's ledger, QD-707, QD-711).

392. **A phone merging remote results takes each row's strongest claim by class first, and folds its own possible matches only where the indexer can be shown to have seen their push (option 1 of each question, the recommendations).**
    - Question: "the higher version wins" contradicted "the phone's own confirmed hits always stay", and a phone folded possible matches an indexer may never have seen, alarming at unequal pins.
    - Answer: a verified or confirmed claim outranks a possible one before a near one, then the higher version, then verified before confirmed, then an indexer's claim before the phone's; a local possible or near hit folds only where the index rides the content ref and the phone's pin is at or below the leg's, or its time is more than SkewGuard (40 min) below ref_time_ms, and an omission alarms only at equal pins with the field uncut and nothing uncovered (§11.14's merge row).
    - Cost: a claim verified at an older version can show above a newer possible one; a phone ahead of the indexer keeps 40 min of possible matches.
    - Not taken: for the merge, (2) the higher version always winning; for the fold, (2) the row as written and (3) each entry carrying its ref version, kept as a review-phase option.
    - Raised by the design details (DESIGN-DETAILS.md section 7; the build's ledger, QD-708, QD-709).

393. **A device searches a cached all only while it is usable, else its buckets alone until it fetches all's changed files (option 1, the recommendation).**
    - Question: §11.14's retained row kept searching a cached all older than a roll-up after the device stopped holding the rolled bucket, so a deleted document could be found again.
    - Answer: all is usable while its pin is the snapshot's or every roll-up between the pins is bridged by the rolled bucket as the roll-up read it; else the device searches its buckets, reports coverage from the oldest, and fetches all's changed files at its next window or at "search more" (§11.14's retained row).
    - Cost: a phone that loses a bridge loses its instant coverage past the buckets until that fetch.
    - Not taken: (2) the row as written.
    - Raised by the design details (DESIGN-DETAILS.md section 7; the build's ledger, QD-710).

394. **A document that alone would not fit a shard is skipped at extraction, and a layout tests its joins and removals against the shard bound (option 1 of each question, the recommendations).**
    - Question: a merge could meet a document whose row and postings passed a shard's cap in a shard of their own, and a join or a re-block after a removal could leave a shard past its cap.
    - Answer: extractor 1's D6 skips a document (no entry, a tombstone where it was indexed before) when its key set would pass KeySetMax or it alone would not fit a shard, a test every device computes at extraction; a layout joins two shards only where the joined shard encodes within the bound, and a shard a removal left past it gives up rows from its highest doc_key down, so a layout always writes (§11.14's caps and merge output rows).
    - Cost: such documents are not searchable, as documents past KeySetMax already are; the design agent amends DESIGN-DETAILS sections 1 and 11 with the exact test.
    - Not taken: for the skip, (2) a lower KeySetMax, (3) a merge writing a tombstone, (4) a shard past its cap; for the layout, (2) a rule needing no trial and (3) failing closed.
    - Raised by the build (SEARCH-M10-10) and the design details (DESIGN-DETAILS.md section 1; the build's ledger, QD-760, QD-775).

395. **An erasure re-enters an edit whose diff rests on an erased version and erases the diff with its base, and at the storage limit only those two files wait for the re-entry (option 1 of each question, the recommendations).**
    - Question: an erasure's CUT could list a version an edit's diff rested on, and at the storage limit the re-entry push that preserves the edit could be refused.
    - Answer: a diff on an erased version is erased content: the eraser composes the edit's version from the diff and its base, reading index files only, enters it full in its own head before any CLOSURE of either file, lists every slot holding such a diff, and removes it with the listed entries; a merge or roll-up composes such a diff through its listed base while the base stands, and a reader passes over one whose base is gone and listed; when evs refuses the re-entry at the limit or spent, only the diff's slot and the base's file wait with their ERASEs, the eraser retrying each turn of its allowance and at least every IndexEraseSettings.ReentryRetryInterval (10 min) (§11.14's dependency, erase and limit rows, §11.13's limit row).
    - Cost: the base stays masked from search from the CUT while it waits.
    - Not taken: for the diff, (2) re-entering from content, which an admin's phone cannot, and (3) erasing the edit too; at the limit, (2) destroying first and (3) evs taking a re-entry at the limit.
    - Raised by the design details (DESIGN-DETAILS.md section 15; the build's ledger, QD-777, QD-778).

396. **A head reader decides from a DROP's signed body alone, a DROP is held to a 256 KiB body and 1,048,576 listed values, and a head-mode device signs only a history it walked itself within 4 MiB (option 1 of each question, the recommendations).**
    - Question: whether listed_sha256 becomes a Merkle root with proofs; what bounds a DROP's body and lists, which a phone must fetch to show a version dropped; and whether a phone may sign a list it did not enumerate.
    - Answer: listed_sha256 stays a flat hash and no reader is sent a list: a head reader takes membership from the signed body, at most 257.1 KiB a drop, once, typically 1.4 KiB, and a DROP whose own list disagrees with its body is invalid to a replaying reader, taken by its body at a head reader and refused by the job either way; evs refuses a body past 262,144 B (400 INVALID) and lists past 1,048,576 values in all (409 DROP_LIST), the client cutting a larger drop into several DROP pushes at lineage boundaries, each previewed and confirmed once as one command, each counted by evs_drops_per_day; a head-mode device builds its list only by walking the path's versions through §11.9's history reads within HeadDropFetchByteCount (4 MiB), a longer history answering EVS_DROP_TOO_LARGE and naming a device that mirrors the repo, taking only map_parts from the dry run (§11.7's action, states, refused and cli rows, §11.9's reply row).
    - Cost: a phone cannot drop a path with more versions than 4 MiB holds; an old repository's recursive drop may take many pushes, whose count D-QUOTA-12's owner may later count as one.
    - Not taken: for membership, (2) a Merkle root with inclusion paths and (3) both; for bounds, (2) a Merkle root over the paths and (3) no bound; for the signer, (2) signing the dry run's list and (3) DropHistory leaving the SDK.
    - Raised by the design details (DESIGN-DETAILS.md section 10; the build's ledger, QD-699, QD-700, QD-705).

397. **A drop job marks only once evacuation's horizon has passed each drop's seen_ms by 12 min, the head cache stamps an entry with its head's written_ms, and a candidate is young until the horizon passes its LastModified + 24 h + 2 min (option 1 of each question, the recommendations).**
    - Question: TLC found two holes: a push that creates its ref, validated on a head cached up to 10 min stale after a drop committed, could land after the job's deletes; and one that adopted a receipt just under 24 h old and stalled its head write was seen by no scan.
    - Answer: the job takes its mark only once evacuation's horizon has passed each covered drop's seen_ms, the appender's clock read after the answer that showed it the commit, by 12 min (10 min of head cache, 5 s of step 7's window, the clocks and slack); the head cache stamps an entry with its committed head's own written_ms, never later than the clock; a candidate is young until the round's horizon passes its LastModified + 24 h + 2 min, owner decision 203's rule for orphans, both durations settings; I-EVS-15 and FI-27's fourth clause take those words (§11.7's action and rule rows, §11.9's cache row, §11.13's table, horizon, delete and young rows). This amends owner decision 204's 2 min.
    - Cost: a now drop's deletes start 25 h 12 min to 26 h 12 min after it, and one of a version uploaded an hour before it keeps that version's segments about 49 h after their upload; a 7-day drop is unaffected.
    - Not taken: for the cite bound, (2) step 4 reading every reuse source's head from the cluster and (3) keeping 2 min; for the young rule, (2) keeping 25 h and (3) refusing receipts for an executing job's candidates.
    - Raised by the design details (DESIGN-DETAILS.md section 10, its TLC runs; the build's ledger, QD-701, QD-703).

398. **A drop job keeps its listed versions' entry hashes for the repo's life, the drop table's entry carries the day it ended, and a dry run keeps its request and reply (option 1, the recommendation, and the build's fills ratified).**
    - Question: once the drop table forgot an executed drop at 30 days, evs could not tell a listed version, and the table's entries and a dry run's files lacked an end day and a home for its request and results.
    - Answer: the job's resolve writes its exact listed set sorted by entry hash to dropscan/ list files with a small index and a bloom filter, kept for the repo's life, so evs finds a listed version by its entry hash wherever it serves one and answers dropped, never serving an inline record of its chain; the table's entry gains ended_day (u16, a UTC day number to 2149) after preview_id, within its 128 B, an ended entry leaving 30 days after it; a dry run writes its EvsDropPreviewRequest and EvsDropPreviewReply as ask and res files, its 64 B record holding its lease and then its end (§11.8's dropscan/ row, §11.9's serve row, §11.13's table row, §2.8's evs-28).
    - Cost: 36.5 B a listed version on the segment cluster, 36.5 MiB at 2^20, outside any network's stored bytes.
    - Not taken: for the listed index, (2) drop marks everywhere and (3) dropped versions reading as missing after 30 days, against FI-27; for the fills, (2) an end time read from the job's files and (3) results inside the table.
    - Raised by the design details (DESIGN-DETAILS.md section 10) and the build (EVSB-M10-02; the build's ledger, QD-704, QD-860).

399. **Each slot object names its creating statement as its origin in object metadata, by which step 6 takes it, a retoken takes over its refused statement's slot, a deposit cites only its own push's slots, and evacuation deletes only a dead record's own slots, an interim first deleting none (option 1 of each question, the recommendations).**
    - Question: evacuation deleting the slots a dead batch record listed could destroy an honest retoken's slot or a slot a hostile record re-listed, and evs could not tell whose a slot object was.
    - Answer: evs writes each slot object's origin (push id, statement hash prefix, ref, signer sidecar, base version, path epoch, mode: at most 190 B) in object metadata at its If-None-Match create, shown to no client; step 6 takes an existing object only under its own statement's origin; a retoken meeting the slot its refused statement created (same ref and signer, a lower path epoch, uncommitted, equal bytes, no hold) deletes it by a DELETE naming its LastModified once past SlotSettleAge (2 s) and creates its own, a CLOSURE charged once across it, any other origin 409 SLOT_STALE; on a deposit ref every slot a new version names is its own push's, else 409 SLOT_UNKNOWN, recorded, so CONSUME needs no check of its own; evacuation deletes a dead record's slots only where the origin is that record's statement, behind EvacuatorSettings.DeleteDeadSlots, which stays off until one release after every process writes origins, an interim that deletes none. QD-968, on a slot a dead push listed first, is answered by these rules (§11.8's step 6, 5h and slot/ row, §11.12's deposits row, §11.13's resolve row, FI-6, FS-8).
    - Cost: leaked slots of at most 8 KiB each while the delete is off.
    - Not taken: for the origin, (2) a field of EvsSlotObject, (3) slot ids in pidx/ with a horizon GC and (4) never deleting; for the interim, (2) the full fix alone; for the retoken, (2) refusing it and rebuilding; for deposits, (2) a HEAD per consumed slot and (3) both.
    - Raised by the design details (DESIGN-DETAILS.md section 14) and the build (EVSB-M2-11; the build's ledger, QD-765, QD-766, QD-767, QD-768, QD-968).

400. **evs stores no slot body in any record: step 6 writes a push's slots before its record, and a push in parts carries its slot bodies in its seal request (the recommendations).**
    - Question: after an ERASE rewrote a slot, the record of the push that introduced it still held the slot's original body, which evs served to any reader, and a push in parts held its slot bodies inside parts that parts_sha256 covers.
    - Answer: the batch record keeps the payload with section 7, the slot bodies, emptied, as idx/ elides inline records, so the slot object is the one stored copy of each key; step 6 PUTs a push's slots, then appends its record, a crash between leaving at worst a slot no record names; a push in parts carries its slot bodies whole in its seal request (slot_bodies), outside every hash and in no part, within a format setting (1 MiB by default), a part carrying section 7 refused INVALID and a retry carrying the bodies again; FI-6 excuses the slot of an attempt that died between its slot round and its record (§11.6's payload, slices and http rows, §11.8's step 6 and seal row, §11.12's after row, FI-6, FS-8).
    - Cost: one stored field's emptying and a seal request field before format 1 freezes; DESIGN-DETAILS 14's text and its model take the order.
    - Not taken: for records, (2) stripping erased keys from stored records at each ERASE and (3) serving records emptied while storing them whole; for parts, (2) no slot-introducing push in parts, (3) per-part bodies beside each part and (4) leaving them; for the order, keeping record-then-slots.
    - Raised by the build (the record-slot-104 and push-record-no-slot-bodies fix tracks; the build's ledger, QD-806, QD-819, QD-870).

401. **A record-class slot holds a record entry's key and salt in one 104 B wrapped block (option 1, the recommendation).**
    - Question: a record entry's 32-byte salt had no place in a slot whose format held only 72-byte wrapped 32-byte keys.
    - Answer: a record-class slot's block is 24 B nonce | the entry's 32 B key and 256-bit salt sealed | 16 B tag, under fek_g with AAD "UR evs 1.0 record slot row" || repo_id || u64be(g), so key and salt die together in one ERASE, and evs takes 72 B blocks, 104 B blocks or a deposit's HPKE length, one width a slot, opening nothing (§11.6's Bytes, §11.8's slot/ row).
    - Cost: a second block width before format 1 freezes.
    - Not taken: (2) deriving the salt from the key, changing RECORD.md's sections and vectors; (3) two slot keys an entry, halving a slot's entries.
    - Raised by the build (RECORD-M2-01; the build's ledger, QD-739).

402. **POST .../reseed takes one EvsReseedRequest a call, pushes and their parts and seals and slots alike, runs the push path in a reseed mode, takes a file-mode base inside 5f's window, and takes a slot only under a re-seeded version that names it (the recommendations).**
    - Question: the reseed route had no body, no rule for which of a push's checks a re-seeded push skips, no way to carry a push in parts past the lb's 16 MiB, a file-mode ref stopping at its first push on an older base, and no way to learn which re-seeded version names a slot.
    - Answer: EvsReseedRequest carries a one-part push, one part (answered with its reseed record's place), that push's seal naming the places, one slot, or one Signed EvsReseed; evs runs steps 4 to 8 in a reseed mode writing EVS_BATCH_RESEED records per push and part, the seal an EVS_BATCH_SEAL record, every reader of a sealed push taking a reseed record where a part record would be; the mode skips the time window, TIME_STALE, the 24 h receipt rule and the quota gate, and keeps the signature at the statement's own pin, the refs table, 5h's slot rules and the chain onto the head, a file-mode push also on a base inside 5f's window as 5f and 5g judge it; a slot call carries the Signed EvsPush of the re-seeded version naming it, which must be committed with a reseed record that names the slot, else 409 SLOT_UNKNOWN; EvsReseed statements live at reseed/<repo>/<ref>, served with the head (§11.8's parts row, §11.13's re-seed row).
    - Cost: a route and message before any production re-seed; a partial loss, slots gone and heads kept, is not mended by a re-seed.
    - Not taken: for the body, (2) EvsPushRequest with a flag and a second slot route and (3) deferring to M3; for the window, (1) the head alone and (3) a sender-named version field; for parts' records, (2) PART records and (3) one joined record; for the bound, (2) a larger lb bound for the route and (3) a recorded limit; for slots, (2) any committed version and (3) evs searching for it.
    - Raised by the build (EVSB-M2-19 and the evs-reseed fix tracks; the build's ledger, QD-725, QD-815, QD-818, QD-836, QD-878).

403. **A read record keeps its entry's commit version, and a verified EvsReseed drops only the records the incident lost (option 3, with option 2's rule for older records, the recommendation).**
    - Question: after a verified EvsReseed lowered a ref's pin, the ref's read records made above the re-seeded head refused that path's surviving version.
    - Answer: a read record keeps the commit version of the entry it read; accepting a verified EvsReseed, a reader drops each of the ref's records whose entry was committed above the re-seeded head, one holding no commit version if its pin is above it, and lowers every other record's pin and the ref's path-epoch floors to the head, so exactly the lost paths show as a loss (§11.9's reader row, §11.13's re-seed row).
    - Cost: one sealed field and one reseed step.
    - Not taken: (1) records standing, which refuse a surviving version until evicted; (2) dropping every record pinned above the head.
    - Raised by the build (the re-seed fix tracks; the build's ledger, QD-816).

404. **Evacuation resolves a reseed record by its statement as it resolves a push record, the fence in place of the time clause (the recommendation).**
    - Question: §11.13 counted every reseed record committed, so a record whose push its ref's history never commits was kept, and its minute waited past the 26 h bound.
    - Answer: committed at this place keeps it, at another drops it as a duplicate, else it is pending, the ref's fence raised, and dead if still not committed on the fenced head; a reseed record lists no slot (§11.13's resolve row).
    - Cost: an evacuation rule.
    - Not taken: (2) the push's rule unchanged, a refused record waiting 64 versions; (3) appending reseed records only after commit.
    - Raised by the build (the re-seed fix tracks; the build's ledger, QD-872).

405. **A creating push carries its sealed ref name and overlay base as payload sections 15 and 16, an inline record travels only in its entry version's locator, and a push in parts lists its purge candidates at the seal (option 1 of each question, the recommendations).**
    - Question: the push that creates a ref had no way to give evs the head's sealed ref name and an overlay's base; an inline record could travel in its locator, in the payload's inline-records section or both; and a rename's removal and its target could sit in different parts, each part listing candidates the other names.
    - Answer: a push that creates its ref, or the first after a DELETE, carries section 15, the sealed ref name, and 16, the overlay base (an EvsOverlay), repeated in its sealed metadata under its signature, the name sealed under manifest with AAD "UR evs 1.0 ref name" || repo_id || ref_id; evs copies them into the head at step 7, refuses them on any other push 409 REF_MODE, and readers compare the copies, alarming on a mismatch; an inline record rides its entry version's kind-2 locator, so entry_sha256 covers it, section 3 and EvsPushPart.inline_records staying empty in format 1, refused if set; and only the seal's record lists a push in parts' purge candidates, each part's replaced versions less every segment and slot any part's versions name (§11.6's Bytes and EvsPushPart fence comment, §11.8's batch record row).
    - Cost: two payload sections; none of the fenced messages changes.
    - Not taken: for the ref name, (2) two EvsPush fields and (3) a ref-scoped file; for inline records, (2) section 3 holding them and (3) both; for candidates, (2) part and seal lists to reconcile and (3) keeping a removal and its targets in one part.
    - Raised by the build (EVS1-M2-01, EVS2-M10-04; the build's ledger, QD-734, QD-735, QD-737).

406. **A record-class stream takes a directory delta that only adds names, and its ref name spells its sidecar id as Id.String() (option 1 of each question, the recommendations).**
    - Question: a stream's creates-only rule refused the directory deltas §16.8's 2,048-entry directories need to grow, and a record stream's ref name spelled `<sidecar_id>` as 32 hex digits where every other `ur/` ref uses Id.String().
    - Answer: on a record-class stream a directory change whose delta only adds rows, with no removed token, on the directory entry's newest version, the entry staying a directory, passes 5c and readers' check, every file change staying a creation; every `ur/<sidecar_id>/…` ref, a record stream's included, spells its sidecar id as Id.String() (QD-485), ids in paths inside a repo staying 32 lowercase hex (§11.6's ref ids row, §11.8's refs table).
    - Cost: each push into a standing leaf rewrites its directory's folded entry, up to 256 KiB, as §16.8 sized.
    - Not taken: for streams, (2) no directory rows at all; for the name, (2) 32 hex digits for every `ur/` ref.
    - Raised by the build (RECORD-M3-12, RECORD-M3-01; the build's ledger, QD-722, QD-926).

407. **EvsRepo's write takes the path version its caller read, so a write is a path CAS (option 1, the recommendation).**
    - Question: a mail writer's append could overwrite a version written between its read and its push, since the push's base was what the write path read, not what the caller read.
    - Answer: a path write takes IfVersion, the version its caller read (none as before, 0 absent or removed), answering PATH_CONFLICT where it differs, so 5g's CAS spans the caller's read to the commit, and §15.7's created-only-if-absent writes take 0 (§11.20's Write, §11.8's 5g).
    - Cost: a field and a check in the client.
    - Not taken: (2) a check after the commit with a merge-back repair; (3) a lease serializing a mailbox's writers, which evs's leases cannot grant.
    - Raised by the build (MAIL-M7-06; the build's ledger, QD-721).

408. **The evs route bodies the format bytes did not list are proto3 messages as landed (the recommendation).**
    - Question: five bodies EVS1-M2-15 and EVS1-M2-16 proposed were not among plan-EVS1-format-bytes's.
    - Answer: POST .../path-epoch takes EvsPathMapRequest {path_map_sha256, part}, POST .../path-epoch/block EvsPathEpochBlockRequest {ref_id, ms}, POST and DELETE /evs/v1/subscriptions EvsSubscriptionRequest {repo_id, ref_id, path_epoch, prefixes}, and GET answers EvsSubscriptionsReply of EvsSubscription {ref_id, path_epoch, prefix, expires_ms}, application/x-protobuf; §2.8's evs-8 names each lease's expiry (§11.6's map and block rows, §11.10's lease row, §11.20's routes).
    - Cost: one design pass; connect's API document takes the protobuf bodies.
    - Not taken: (2) renaming or renumbering before M2's entry review.
    - Raised by the build (EVS1-M2-15; the build's ledger, QD-950).

409. **evs writes {evsc_<client_id>} on evs-8's row, and a lease on every ref with no prefix matches in any path epoch (option 1 of each question, the recommendations).**
    - Question: the per-client repo cap's Redis family was built before its row named it, and a whole-repo lease named main's epoch, so commits on refs in another epoch waited for the hourly resync.
    - Answer: evs-8 names {evsc_} first, then evs builds it with its cap script, run before the lease script; a `*` lease with no prefix names no token, so evs matches it for a commit on any ref of the repo, whatever its epoch, while its holder reads the repo, every other lease keeping the epoch rule (§11.6's leases row, §11.10's epochs and caps rows).
    - Cost: one branch in the match.
    - Not taken: for the family, (2) counting inside {evsl_}, which crosses slots, and (3) building it before its row; for the lease, (2) one lease per epoch and (3) the hourly resync.
    - Raised by the build (EVS1-M2-15, EVS1-M2-27; the build's ledger, QD-749, QD-953).

410. **evs's client reads a 502 or 504 that is not an evs refusal as no answer from evs, and retries (option 1, the recommendation).**
    - Question: nginx answers a streamed PUT whose upstream died 502 or 504, which evs's client read as a refusal and did not retry.
    - Answer: such an answer is the lb's, no answer from evs, and the client sends the same bytes again after ReadRetryWait until §11.8's 200, 409 or 412, so a segment PUT an lb drain cut lands once (§11.8's retry row).
    - Cost: a few lines in the client.
    - Not taken: (2) retrying only segment uploads; (3) the lb buffering segment PUTs.
    - Raised by the build (TEST-M2-15; the build's ledger, QD-758).

411. **evs's placement 409 carries REPO_PLACED and its 401 UNAUTHENTICATED, so every answer but a 200 carries a code (the recommendation).**
    - Question: the placement's "another creator placed this id" and a token that does not authenticate carried code 0.
    - Answer: two final codes join EvsRefusalCode: REPO_PLACED, 76, status 409, at PUT /evs/v1/repos/<id> when place/ names another creator, the client picking another id; and UNAUTHENTICATED, 137, status 401, among the answers that refuse nothing, for a token that does not authenticate or whose client, sidecar or member a rev/ object voids, the daemon minting a new token and retrying (§11.6's codes row, §11.8's placement row, §11.20's refusals).
    - Cost: two enum values, ahead of their code track.
    - Not taken: (2) keeping code 0 and deciding by route and status.
    - Raised by the build (EVS1-M2-07; the build's ledger, QD-927).

412. **A format rollback is a configuration of a real binary, and the purge's turn-on pass waits until its taskworker reads on (the recommendations).**
    - Question: format 1's guard for format-2 data landed with format 2's own code, so no build was FS-72's format-1 binary; and the turn-on pass could run under observe, keep everything and finish.
    - Answer: evs's and taskworker's blocks take EvsSettings.InstanceFormat from their block config, 2 from M10's release and 1 in a rollback's, so format 1's guard is reachable in any build that has it, a §19.10 row saying how and T3 running a real binary from a pinned release commit; the turn-on start reads its taskworker's purge mode and returns ErrSweepRetry for server/task's backoff until that host reads on, then queues one scan per metadata cluster, following owner decision 206 (§11.6's format row, §11.13's sweep row, §19.10, §19.11, FS-72).
    - Cost: a config field and its runbook row; a retrying task while the mode lags.
    - Not taken: for the rollback, (1) a harness from the last commits with no format-2 code and (3) the gate alone defining format 1; for the turn-on, (2) keeping it as built and (3) each repo's pass retrying.
    - Raised by the build (EVS2-M10-30, OPS-M10-01; the build's ledger, QD-854, QD-960).

413. **Each nvme run's measured price table reaches the write budget as a code change (option 3, the recommendation).**
    - Question: no path carried the nvme run's measured price table to evs's, gkm's and taskworker's budgets.
    - Answer: its rows replace the default 1 KiB and 4 KiB tables and PriceBlockByteCount's default takes the chosen block size, reviewed with D-TEST-11's report at M2's exit and before M3's pilot, defaults set only in Default...Settings(), k absorbing a constant error; a live config value can come later if production drifts past D-TEST-13's 10% (§11.13's price row, §22.8's nvme row).
    - Cost: a code change per measurement.
    - Not taken: (1) a config value reread every 60 s; (2) a file mounted per env, read at start.
    - Raised by the build (EVSB-M2-21; the build's ledger, QD-862).

414. **evs classes a path epoch's due crossing on its own verified state, immediate for every shrink until it judges from the log by each shrink's statement (the recommendation).**
    - Question: evs could not tell an immediate path epoch from a batched one, its state showing a shrink but not whose or why.
    - Answer: never by a member-checked field in GenRotate; until the log-based judgment lands, a crossing is immediate whenever the newest state shows the repo's holders shrank after the auth pin of the generation it crosses from, batched only when expiries alone passed, which fails closed; with §7.9's state at past positions, evs and clients class the entries between the two pins that shrank the holders, a member's removal, a member device's removal or revocation and a compromise retirement immediate, an agent's ordinary removal and expiries batched, any immediate one making the crossing immediate, and a party that cannot reach the earlier state or class an entry reading immediate (§11.6's due row).
    - Cost: creation blocks and maps on agent removals meanwhile.
    - Not taken: (2) GenRotate carrying the class its REMOVE covers, for members' checks to verify and evs to read.
    - Raised by the build (EVS1-M2-16; the build's ledger, QD-949).

415. **On a git-mode ref a push that breaks the prefix rules stops the ref; in file mode devices write the accepted state back unasked within bounds; a re-creating push clears a removed taint; and a repair form names what it writes over (the recommendations).**
    - Question: whether mounts skip a push that breaks the prefix rules or stop at it, whether a device writes the accepted state back unasked after ignoring a write, how a re-creating push clears a tainted path the stopped span left removed and its new tree lacks, and which sealed field names the push ids a repair writes over.
    - Answer: on a git-mode ref such a push fails the mount's check like any refused push, every mount stopping at it with evs_alarm prefix_rule naming the signer, recovered by an admin deleting the ref and pushing it again, git mode keeping one tip rule; in file mode a desktop or the daemon that mirrors the ref and may write the path writes the accepted state back unasked within AclPrefixSettings' RepairPushCount (60 an hour) and RepairByteCount (1 GiB a day) per repo and device, `ur evs repair` doing the rest; a reader keeps beside each tainted path whether the stopped span's last change there was a removal, so a re-creating push states nothing there; and EvsSealedMetadata's written_over (9) lists the push ids a repair form writes over, for display only (§11.11's prefix row, §11.6's Bytes).
    - Cost: a breaching writer's lasting answer is its revocation, which the alarm names; the repair bounds are settings, zero turning automatic repair off.
    - Not taken: for git mode, (2) skipping the push and tainting its paths; for repair, (2) never unasked and (3) names only; for the taint, (2) evs taking a removal of a removed path and (3) the two-push way round; for the field, (2) per-path lists in the sealed fields and (3) inferring it.
    - Raised by the design details (DESIGN-DETAILS.md sections 8 and 16) and the build (EVS1-M2-34, EVS1-M6-04; the build's ledger, QD-793, QD-794, QD-826, QD-833).

416. **Under prefix rules a push creating a shared ref is judged from a shared branch's tree, a filer's pin push reaches only shared branches with a tip, and evs's gate refuses a ref's creation pinned below the newest rule set (the recommendations).**
    - Question: a writer held to a prefix could create a tag or a new shared branch whose files were never checked, the filer's no-change push went to refs it could not bind, and a stale pin could create a ref under an older rule set.
    - Answer: a new shared branch is measured from its base when that is a shared branch, else from the empty tree, and a tag passes only when it tags a commit that is or was a shared branch's tip, which its push names; the filer's pin push goes only to shared branches with a tip, a deleted branch bound from the push that re-creates it and listed unbound until then; evs's gate refuses 412 GATE_CLOSED a push that creates or re-creates a ref at an auth pin below the log position of the repo's newest prefix rule set, reading the set's position, never a rule (§11.8's gate, §11.11's new refs row, D-EVS-18). It narrows owner decision 345's reading of the shared refs a set's pin push reaches.
    - Cost: one gate clause, enforced by evs as the existing fence is, so no client-checked guarantee is added.
    - Not taken: for new refs, (1) leaving them unjudged and (3) only a signer the set names for every path creating a shared ref; for the pin push, (2) a second DELETE to each deleted branch; for stale pins, (1) leaving it, (3) a readers' alarm and (4) readers refusing by clock.
    - Raised by the design details (DESIGN-DETAILS.md sections 8 and 16; the build's ledger, QD-801, QD-802, QD-803).

## The build's owner questions on DNS, the TLS edge and certificates, and the SMTP edge (2026-11-06 to 2026-11-16)

The design-records track for §12, §13 and §14 folded the answers below on 2026-11-16, each citing its ledger id: the owner-class items the owner accepted in bulk on 2026-11-06, the answers the owner decided one at a time from 2026-11-11 to 2026-11-16, and the recommendations of 2026-11-15 and 2026-11-16 that the owner's instruction of 2026-11-16 accepted. A decision that groups several answers carries its latest answer's date. The sections' other items, the defect fixes the owner accepted on 2026-11-06 and the build's readings, fills and settled items, went into §12, §13 and §14 as text with no number.

417. **dns's internal routes take one bearer per caller class, under a prefix the lb refuses from outside (option 1 of each question, the recommendations).**
    - Question: §12.8 and §13.15 marked routes internal without saying what their callers present: the dns edges on the feed, the most sensitive read in §12, every record and unlisted host; the monitors on the canary; certs on challenges, canaries and ready; each lb interface's lbmap on the custom-host map; and the abuse worker on `POST /tls/suspend`. dns.bringyour.com is a public name sidecars reach, and an edge must keep serving through a core outage (D-DNS-3).
    - Answer: one bearer per caller class, 256 random bits in one vault file per caller (`internal-dnsedge-1.yml`, `internal-dnsedge-2.yml`, `internal-monitor.yml`, `internal-monitor-outside.yml`, `internal-certs.yml` in taskworker's `secret_files` and `internal-lbmap.yml` in the lb's), each holding current and previous values so a rotation needs no downtime, read once at start; the dns API block holds only their SHA-256, in `internal-verify.yml`, compared in constant time, and each route takes only its class: the edges the journal, snapshot, reload-diff and route-probes, the site's monitor canary and canary-report, the outside monitor canary-report alone, certs acme-challenge, caa-canary and ready, and lbmap the custom-host map and its applied route, naming its interface, which the API checks against the lb inventory; every internal route moves under `/dns/internal/`, where the lb answers 403 unless the source is on the service's allow list of the site's ranges and the off-site monitor host's address, carried with W8; `POST /tls/suspend` stays a model call inside api and taskworker, its route built only once a caller outside them exists (§12.6, §12.8, §13.15, §19.4, §19.5's W8, §7.8).
    - Cost: seven vault files, one lb rule and a rotation routine; no per-interface secret, since playbook-edges.yml copies the whole vault to every edge host, and §13.4 counts an interface's report only once a dns edge's route probe of that version passes; nothing on the serving path, an edge needing neither the issuer nor Postgres to keep serving.
    - Not taken: for the dns edges and monitors, (2) a separate listener the lb never exposes and (3) mutual TLS from a private CA; for certs, lbmap and the abuse worker, (2) short-lived issuer tokens under a new `svc-` audience and (3) network position alone.
    - Raised by the build (plan-DNS and plan-TLS; the build's ledger, QD-027).

418. **An NS is running until a restore or an operator stops it, and `/dns/internal/ready` and the restore count only running NS (option 1, the recommendation).**
    - Question: §12.6 counted each running NS for ready and the restore step without saying what running is or where a stopped NS is kept; API blocks restart, so the fact must be shared and durable, and a restore that forgot a stopped NS would count its stale snapshot again.
    - Answer: a table `dns_ns(root, ns, state, stopped_time, reason)`, state running or stopped, seeded from dns.yml; running means state running, whether or not the NS answers now; the restore step writes stopped, an operator by hand through `sidecarctl dns ns stop|start` (the answer's `bringyourctl` command, in the binary where owner decision 274 puts every new operations command), and an NS leaves stopped only once it serves at or above restore_serial; ready counts only running NS, a running NS that does not answer keeping it waiting, and restoring clears once every running NS answers restore_serial; one running NS failing SOA reads for 1 h pages in business hours, since orders then wait (§12.6, §12.14, §19.8; §2.8's dns-1).
    - Cost: one table; a single NS outage holds new certificates until a person marks it stopped, for which renewal at day 30 of 45 leaves 15 days (§13.16).
    - Not taken: (2) treating a running NS that misses SOA reads for 5 minutes as stopped, so a partitioned NS a CA still reaches burns failed authorizations; (3) inferring running from the feed's long-polls, a state no restart keeps, which FS-42 needs.
    - Raised by the build (plan-DNS; the build's ledger, QD-124).

419. **§12.5's reserved block guards only the names directly below `<root>`; record owners and published hosts in a network's zone take §21.6's brand rules and §12.7's owner table (option 1, the recommendation).**
    - Question: `ScreenName` denied every label on §12.5's reserved block whatever the facts, and the record write ran it on new owners, so a network could not write `www.<label>.<root>` or `api.<label>.<root>`, the commonest user records there, while §21.6 lists only the brand rules for record owners and published hosts and §12.7 already keeps the zone's system owners from users.
    - Answer: the reserved block (www, api, app, web, status, login, admin, support, account, mail, dns, edge and the rest) guards labels, aliases and scope labels, where such a word would pass for a platform name; inside a network's own zone a record owner or published host takes §21.6's brand rules (listed brands unless the brand's domain is verified, brand plus keyword to review, word-number names kept for burners) and §12.7's owner table (b, mx, mail, mta-sts, the system `_` owners, scope labels and word-number labels stay the platform's), not the reserved block; `ScreenName` gains a way to screen a host, and the record API then allows www, api and the like in a network's zone (§12.5, §21.6).
    - Cost: a second entry point or a facts flag in `ScreenName`; published hosts follow the same rule.
    - Not taken: (2) record owners taking `ScreenName` as built, the reserved block included, so no network holds www, api or status in its own zone.
    - Raised by the build (DNS-M5-12; the build's ledger, QD-807).

420. **A downgrade withholds a custom domain's web host by a third state, `withheld`, which leaves the map while its row stays (option 1, the recommendation).**
    - Question: §20.7 withholds a custom domain's web hosts 14 days after a downgrade and D-QUOTA-6 deletes nothing, but `network_dns_custom_host.state` held only pending and active, and pending is a strong-mode host waiting for certs' walk and probe, which certs turns active on its next pass.
    - Answer: the state gains `withheld`: the downgrade's withholding sets each active TLS web host of the domain withheld, which takes it out of §13.4's custom-host map, its version raised, and tlsedge's routing, while its row, verification and CAA mode stay; a release after a renewal sets it active with map_version 0, so it re-enters the map at the next version, pending until every interface is current, as a new host is, with no re-verification and no new CAA walk; certs' result never turns a withheld host active; a strict-mode MX host is never withheld, mail hosts keeping MX, TLSA and routing; smtpedge's From-domain gate for a downgraded domain is built beside it (§12.8, §12.14; §2.8's dns-1).
    - Cost: one state value; every reader's filter (state active) is unchanged.
    - Not taken: (2) a nullable `withheld_time` column every reader filters on; (3) deleting the web hosts' rows for the customer to re-add, against D-QUOTA-6 and with a new walk and probe.
    - Raised by the build (DNS-M6-05; the build's ledger, QD-840).

421. **api's `GET /sidecar/label` answers a sidecar its own network's label and alias, allocating on first need, built as labels' server half (option 1, the recommendation).**
    - Question: the label's model half had landed and the client's table refused until a server half existed, and no task listed the route that feeds it, so `.ur`, git-remote-ur, §9.4's addresses and `network:<net>` held no real label before M5's `GET /dns/zone`.
    - Answer: `GET /sidecar/label` (Client class, sidecar-classified, so §7.4's `/sidecar/*` covers it) answers `{network_id, label, alias}` for its token's own network alone, allocating the label on first need on `dns_label`, `alias` empty while the network has none; from M5 `GET /dns/zone` feeds the client's table as well; the DNS track that landed the model half builds it as a follow-up (§12.5, §7.4).
    - Cost: one route in the shared route tables and api's sidecar-token path.
    - Not taken: (2) the TEAM or PROTO task that owns api's `/sidecar/*` routes; (3) leaving it unbuilt until M5's `GET /dns/zone`.
    - Raised by the build (DNS-M5-10; the build's ledger, QD-935).

422. **A link audience's guest link is a signed token, reusable until its grant ends (the recommendation).**
    - Question: §13.7 said a `link` audience trades "a URL token" for a cookie, and the build's reading made it 256 random bits kept in the publishing device's `tls/` state and presented once, so a link worked on one device and only through the listener that minted it.
    - Answer: a link is `TlsLinkToken { bytes grant_id = 1; string host = 2; uint64 expire_time_millis = 3; bytes nonce = 4; }` in a §6 `Signed`, `SIGNED_TLS_LINK` 0x1503, purpose `tls-link`, signed by the publishing device's identity key, `expire_time_millis` at most the grant's expires, at `https://<host>/.well-known/ur/link?t=<base64url(Signed)>`; the front verifies the signature against the projection, that the signer is the sidecar the grant names, that `grant_id` is active and that `host` equals the SNI, then sets `__Host-ur-link` (HttpOnly, Secure, SameSite=Lax, 12 h, capped by the token's expiry) holding the same token and answers 302 to `/` with `Referrer-Policy: no-referrer`; any listener of the grant honors it with no shared state, and a GrantRevoke or the grant's expiry ends every link of the grant (§13.7, §6.9, §6.11).
    - Cost: a link is a bearer until its grant ends, so ending one link alone means ending its grant.
    - Not taken: the reading's single-use random token kept in one device's `tls/` state.
    - Raised by the build (plan-TLS; the build's ledger, QD-134).

423. **taskworker lists a network's published names from ACL's own reading of its publish rules (option 1, the recommendation).**
    - Question: `model.ListTlsPublishedNames` pages a network's active publish grants for §21.6's hourly check, but nothing enumerated them: `AclState` answered `PublishGrant` for a socket the caller names, Postgres holds no table of grants, and no task said whether taskworker hosts a gate cache or asks api.
    - Answer: ACL adds a read-only `AclState.PublishedNames(now)`, every rule allowing publish grouped by host and port, `PublishGrant`'s agreement rule deciding audience and expiry and disagreeing rules listed as the closed audience; taskworker reads it through a gate cache and installs it as `model.SetTlsPublishedNamesSource`'s source, a name's label and aliases coming from `network_edge_label` and the verified domains, so the abuse check's audience and expiry are what the gates enforce, by one reading of the rules; a process with no source answers unavailable, which the hourly check treats as a failed pass (§13.9).
    - Cost: one read-only method on `AclState` and a gate cache in taskworker.
    - Not taken: (2) the source walking the newest projection's rows in server/model with a second reading of §8.4's agreement rule, which can drift from the gates'; (3) a `network_tls_published_name` table kept in step with each landed entry, a new row of metadata and an expiry no entry updates.
    - Raised by the build (TLS-M5-13 and TLS-M5-16; the build's ledger, QD-770).

424. **A Team custom-domain certificate names one host for one device, its orders paced at the server by the CA's limits held as settings and half a registered domain's limit, and its budgets replayed from two windows back (the recommendations).**
    - Question: whether the Let's Encrypt numbers section 17 of the design details assumed are right, above all that an ARI renewal counts against no limit; whether a custom-domain certificate names one custom host for one device, so that a host's devices share the exact-set limit; how much of a customer's registered-domain limit URnetwork's orders may take; and whether the budgets' replay keeps its empty start, which certified about four devices a window where the section's count was one each 34 h.
    - Answer: the numbers (a 45-day lifetime, 7 h authorization reuse, 50 certificates a registered domain in 7 days, 5 an exact name set in 7 days with one back each 34 h, 300 new orders an account in 3 h, 5 failed authorizations an hour, an ARI renewal counting against no limit) stay assumptions held as `CertsCustomSettings` defaults, which the owner corrects from the CA's rate-limits and profiles pages, no agent fetching them; if the ARI exemption is false in any part, the ceiling of about 21 certified devices a host becomes the product's stated limit; a custom-domain certificate names exactly one custom host for one device, a host's first 4 devices certified at once, one certificate kept back for a compromised key, and each further device 34 h after the one before, both settings, and a device without a certificate for a custom host is not routed that host's visitors; URnetwork's orders for a registered domain are held to a bucket of 25 new certificates, one back each 6 h 43 min (`DomainCap`, `DomainRefill`), counted before any request reaches the CA, ARI renewals outside it, a value the customer's admin sets per domain being a later product setting; the replay starts empty two windows back, at now − 2 × cap × refill (340 h for the exact set), each bucket's spends read from there and kept 15 d (`SpendRetention`), so the level is never above the truth and a refused claim's `retry_after_ms` is answered by a grant, the literal empty start standing until it is built, the closed direction (§13.8, §13.16; §2.8's cert-1).
    - Cost: waits and refused requests, never a certificate too many, where a number is wrong; N × H certificates against the registered-domain limit; a fifth device of a host waits 34 h; a claim reads twice the spend rows, which cert-1 keeps 15 d.
    - Not taken: for the numbers, (2) letting the CA's 429s correct them in the field and (3) an agent fetching the two pages; for the names, (2) one certificate a device naming every host it serves and (3) one certificate a host with a shared key; for the share, (2) all 50 and (3) a per-domain admin value now; for the replay, (1) the empty start with corrected arithmetic and (3) a per-key level row.
    - Raised by the design details (DESIGN-DETAILS.md section 17) and the build (TLS-M6-04; the build's ledger, QD-784, QD-785, QD-786, QD-990).

425. **A custom domain's account key is held by its admin's devices and the ordering desktops it is shared with, and an admin's ordering desktop changes it as soon as its holders shrink (option 1, the recommendation).**
    - Question: who may hold a custom domain's ACME account key, who may change it, and whether it is acceptable that a removed holder signs as the account until the change is sent.
    - Answer: the admin's devices and the ordering desktops the key is shared with hold it (§13.8); any holder orders; only a network admin's ordering desktop changes the key or writes the account row; the change is due the moment the repo's holders shrink or its owner leaves, and the first admin desktop online makes it within one poll, committing the new key where the remaining holders read it before the CA is asked to require it; a desktop that sees the change due and may not make it raises `tls_account_rollover_due`, and fewer than two admins' desktops seen in 7 days is a warning; the accepted risk is that a removed holder can sign as the account, revoking certificates and deactivating or taking the account, until the CA takes the key change (§13.8, §13.16).
    - Cost: the exposure from a removal to the next admin desktop's poll.
    - Not taken: (2) only admins' desktops holding the key and ordering, which leaves a team whose admins' desktops sleep with no one to order; (3) any holder changing the key, which lets a non-admin move the account row.
    - Raised by the design details (DESIGN-DETAILS.md section 17; the build's ledger, QD-787).

426. **Every custom certificate is a row a desktop claims under the account's lock, and TLS-ALPN-01 for a custom host needs its port 443 publish grant (option 1 of each question, the recommendations).**
    - Question: whether `POST /tls/cert-register` keeps a form where a desktop attests its own key with no row, lock or grant, spending the host's exact-set limit with nothing counting it; and whether an ordering desktop must hold a port 443 publish grant on a custom host's owner to answer TLS-ALPN-01 for it.
    - Answer: `POST /tls/cert-register` takes a chain only for a queued row whose account lock the caller holds, the no-row form (`TlsCertRegisterArgs` with a zero `CertId`) dropped, so a desktop's own CSR is queued by `POST /tls/cert-order` like a phone's and claimed like any row; an ordering desktop answers TLS-ALPN-01 for a custom host only where it holds an approved port 443 publish grant on the host's owner, §13.9's gate taking no exception, else it uses the customer's DNS-01 CNAME for that host or leaves the row to a desktop that holds the grant, and a row no online desktop can serve waits and raises `tls_custom_queue_stalled` after 24 h, a setting (§13.8, §13.15).
    - Cost: one more request for a desktop's own certificate; some rows wait for the right desktop or the CNAME.
    - Not taken: (2) both register forms, the second needing the first's lock, budget and resume rules; (2) an acme-only listener on any owner of the domain's hosts without the grant, an exception on the publish gate.
    - Raised by the design details (DESIGN-DETAILS.md section 17; the build's ledger, QD-788, QD-789).

427. **Section 17's eleven readings for Team custom-domain certificates stand as built (option 1, the recommendation).**
    - Question: eleven choices section 17 of the design details took where an implementer would otherwise choose.
    - Answer: custom rows have their own states (`custom_queued`, `custom_ordering`, `custom_issued`, `custom_revoking`), which no landed certs pass takes; the lock is one an account; budgets are rows of spends replayed as buckets; a desktop probes its own challenge through public DNS and the edge twice before asking the CA to validate; `ValidateListen` drops a certified or ACME name the rows do not bear out and keeps the registration; a device presents the newest installed certificate whose row is `custom_issued`, falls back to its predecessor, and for a custom name with none fails the handshake; a 429 on an ordinary order holds ordinary orders and lets ARI renewals through, and one on an ARI renewal holds everything; the plan's order is revocations, the row in flight, replacements of revoked certificates, renewals by expiry, then first certificates, the least-served host first; `GET /tls/certs?work=1` returns only accounts and waiting rows; each ordering desktop keeps the key file's last good bytes in its local secret store; a row that ends while an order is recorded for it goes to `custom_revoking`, and the account orders nothing until that order is killed at the CA or its certificate revoked (§13.8, §13.9, §13.15).
    - Cost: none beyond what is built.
    - Not taken: (2) naming readings to change.
    - Raised by the design details (DESIGN-DETAILS.md section 17; the build's ledger, QD-790).

428. **An edge block mounts the `edge` class's gate bearer, and api mints jwts for fixed clients whose ids derive from environment, host, block, slot and index (option 2 of each question, the recommendations).**
    - Question: what platform credential an edge block mounts, since it mounts no vault and so signs no jwt, and how `server.NewPlatformClientSource` turns it into K client jwts with stable ids; then, when a deploy runs a host's old and new tlsedge side by side, which of them holds the block's derived clients.
    - Answer: a per-class internal bearer in the scheme owner decisions 340 and 417 settled, a caller class `edge`, 256 random bits with current and previous values in the block's `secret_files`, read once at start, api holding only its SHA-256; a route under the internal gate prefix, `POST /internal/gate/edge-client`, taking only that class, derives the client id from (environment, host, block, slot, index) by a fixed, documented derivation, creates that client in `urnetwork-edge` on first use and answers a short-lived client jwt and the url the pool needs, refusing a host its environment's config does not name, an index at or past the block's K and a slot past the block's slot count, 2; `server.NewPlatformClientSource` asks for each of its K indexes at start and refreshes each token before it lapses, the jwt's life and the refresh point being settings, so restarts reuse client ids and the edge keeps no state; a deploy's old and new process of a block on a host hold different slots, alternating per deploy through warp's `WARP_SLOT` beside `WARP_BLOCK`, so the new process connects its own K clients while the old one drains its streams for `drain_s`, readiness counting each process's own; no network-level token sits on an lb host, and a stolen edge bearer mints only its environment's fixed edge clients, at most twice K a block and host (§13.5, §13.6, §14.9, §19.4).
    - Cost: one api route and a derivation rule; twice the clients a block and host in `urnetwork-edge`; warp hands each process its slot.
    - Not taken: for the credential, (1) the `urnetwork-edge` network's `by_jwt` on every lb host, its client ids kept in Redis, and (3) K long-lived client jwts pre-minted per host and block; for a deploy, (1) the derivation without a slot, so the new block's clients end the old one's draining streams at once, and (3) warp never running two processes of one block on a host, a deploy serving no new connections there for up to `drain_s`.
    - Raised by the build (TLS-M5-11 and TLS-M5-18; the build's ledger, QD-812, QD-873).

429. **certs' installs in api and taskworker start behind a `certs` switch, its revoke route's admins are the holders of `devices`, and cert-order asks the gate one question (option 1 of the first two questions, option 2 of the third, the recommendations).**
    - Question: no task built the installs certs runs on, so nothing it did was reachable, and only the arrival of a vault file would have stood between a release and real CA orders; §13.15 made `POST /tls/cert-revoke` "Network admin for any" on an OwnClient route, where §7.5's role gate does not run; and the gate view had no call answering whether a sidecar "holds a §8 `tls/` or `smtp/` grant" for an order that names no host.
    - Answer: a TLS task builds certs' two installs, api's (`controller.SetTlsCerts` with the engine, the Postgres store, the certs authenticator and a reader of a caller's identifier set, identity key and grant from its network's verified projection through `AclGateView`, installed when ACL's gate cache lands in api, the subject built from `AclGateView.PublishGrant` and `sidecar.TlsIdentifierSet` over the config projection's label, scope and aliases) and taskworker's (`work.SetTlsCertChains` with the engine, its DNS client, its ACME client on the account files and its hint writer, reading `certs.yml`, the account files its `account_file` names and `internal-certs.yml` from `secret_files`), both left out unless a new `certs` switch in sidecar.yml is on, which §19's gate list names, so certs fails closed through M5's Gn-out and the first real CA order is the owner's act; on `POST /tls/cert-revoke` a credential that names no client revokes any certificate of its network when it is a personal network's owner's token, a team member's token whose role holds `devices` (a role that cannot be read holding nothing) or an API key whose scopes reach `devices`, the handler passing the key's scopes to the controller, while an OAuth identity or an admin token revokes nothing there and a client token revokes its own client's certificates, since revoking a device's certificate is part of removing the device; ACL adds `AclGateView.HoldsPublicGrant(networkId, subject, now)`, true when a rule in force gives the subject publish with listen on any `tls/` name or listen on `smtp/25/mx`, which api's cert-order subject calls in the review phase, the landed reading standing until then (the view asked per name `AclState.PublishedNames` lists, each `*` as the letter `x`, a dotted Team scope host skipped until M6), every answer the gate's own, the closed direction (§13.15, §19.11).
    - Cost: one task and one gate switch; the API key's scopes passed to the controller; an ACL method in the root with its tests.
    - Not taken: for the installs, (2) installing whenever MG5 is linked and the files exist and (3) splitting them between ACL and OPS; for revoke, (2) `policy` as the permission and (3) a second, Network-class revoke route; for the order, (1) the enumeration alone, as landed, and (3) no grant beyond admission.
    - Raised by the build (TLS-M5-16, TLS-M5-17 and the certs install's track; the build's ledger, QD-846, QD-847, QD-976).

430. **certs backs a URnetwork-zone name off at a CA where its authorizations keep failing, doubling up to a day, in state that survives a restart (option 3, the recommendation).**
    - Question: Let's Encrypt pauses a name for an account after 1,152 consecutive failed authorizations, its daily refill handing one back, and M5's certs held a failing name only at 4 failures an hour, in process memory, so a name that kept failing reached the pause in about 12 days, its 429s holding LE's new orders for every other network meanwhile.
    - Answer: certs backs off a name whose authorizations keep failing at a CA, doubling up to a day as the custom hosts' failure backoff does, so the name fails at most about once a day at that CA and its run of consecutive failures stays near seven; the per-name backoff survives a restart in `network_tls_name_backoff` (§2.8's cert-1), a success resets it, and the doubling's start and cap are settings (§13.8).
    - Cost: durable per-name state with its row; a fix to a broken name takes up to a day to show.
    - Not taken: (1) no long-run bound, a paused name waiting on an operator; (2) stopping a name at a settings count below 1,152, which needs an operator as a paused one does.
    - Raised by the build (the CA numbers check of 2026-11-15; the build's ledger, QD-857).

431. **§13.7's members-device logins and the front's reach receipts take the build's nine readings (the recommendation).**
    - Question: §13.7 names a members-device statement over origin and nonce, a device step through the app or extension and a reach receipt per grant, visitor and 5 min, and gives none of them a shape.
    - Answer: (1) `TlsEdgeLogin {string origin = 1; bytes nonce = 2;}` in protocol/tls.proto, origin as the front writes it (`https://<sni>`, `:<port>` only when not 443), nonce 32 random bytes the front draws, no network_id; (2) after the ID token checks out, the callback seals `{nonce, member_id, expiry, return path}` into `__Host-ur-device-pre` (`DeviceLoginLifetime`, 10 min) and answers 302 to `/.well-known/ur/device`, whose GET answers `{origin, nonce}` and whose same-origin POST with field `s`, the base64url `Signed`, completes the login with 303 to where the visitor began; (3) the nonce leaves the pending set only once a statement verifies, a login completing once; (4) the device is `AclState.ConsentedFor(signer, member)`, not read_only, suspended or revoked; (5) `__Host-ur-session` gains the device's sidecar_id, a device session counting on a members endpoint and a members session never on a members-device endpoint, consent and membership checked on every request; (6) `Sidecar.SignTlsEdgeLogin(origin, nonce)` answers the encoded `Signed` under the sidecar's consented untagged admission, §18's `SignEdgeLogin` decoding base64url and passing the asking page's own origin; (7) a receipt's owner is the publishing sidecar's id, approver empty, `grant_id` the lowest agreeing rule_id bytewise (the header's grant_id set only for a 32-byte activated grant's id), `policy_version` the config version the grant was read at, a stream counted when its first target connection opens and its TLS bytes when it ends, windows aligned to `ReachReceiptCoalesce` from the epoch; (8) the visitor hash HMAC-SHA256(k, family ‖ the /32 or /64 prefix's address bytes)[:16], k = HKDF-SHA256 of the front's session root, salt the network_id, info `urnetwork-sidecar-v1/tls-front-reach`, stable across windows and restarts; (9) nothing new for the overlay (§13.7, §16.8).
    - Cost: none beyond what is built.
    - Not taken: naming readings to change.
    - Raised by the build (TLS-M6-06; the build's ledger, QD-882).

432. **Every ACME account key is in vault before any CA knows it, and certs rolls an account over yearly only to a next key the operator placed there (option 1, the recommendation).**
    - Question: RFC 8555 §7.3.5's key change makes the CA forget the old key at once, and certs runs in taskworker, whose `secret_files` it only reads, so a key certs made itself would be lost at a restart, and with it the account whose URI every CAA record at `<root>` pins.
    - Answer: certs never writes a key; it reads one YAML file per CA from taskworker's `secret_files` (`ca`, `private_key`, an optional `next_private_key`, `key_create_time`, `eab_key_id`, `eab_mac_key`, `contact`); once `key_create_time` is a year old, the rollover age a setting, and the file holds a `next_private_key`, `CertsAcmeClient.RolloverAccount` signs the key change with both keys and orders with the next from then on; a process restarted with both keys finds the account under whichever key the CA holds, so the operator promotes `next_private_key` to `private_key`, with a new `key_create_time`, at leisure, and the account's URI never changes; without a next key nothing rolls over and the account is reported due but not ready (`CertsAccountSet.RolloverDue`, the certs work's `rollover_due_cas`); generating the next key and placing it in vault for each CA is the operator's yearly step (§13.8, §19.10).
    - Cost: one operator step a year per CA.
    - Not taken: (2) certs making the key and writing it into vault through a new ops path, the key held only in memory meanwhile; (3) rollover only by an operator command holding both keys, the yearly duty moving wholly to a person.
    - Raised by the build (TLS-M5-15; the build's ledger, QD-942).

## Owner instructions after the v1 build (2026-11-05)

These are instructions, not design decisions, so they carry no number.

- **SDK gaps: "Design both fixes now."** The two residuals the v1 build left are designed as proposed decisions:
  - stale page Workers when `self_admit` is off (D-TEAM-29, §7.10's `stale` row);
  - revoking a lost device from an app (D-CORE-20 in §5.4 and §5.6, D-SDK-30 in §18.5).

  Their tests are FS-97 and FS-98. Independent checkers reviewed them before the rebuild.
- **Renumbered § references in DESIGN-REVIEW-RESPONSE.md:** keep them.
- **pitch5 (outside DESIGN.md):** update both session lines (:579, :640) to owner decision 170's limit, fix the five footers to cite sidecar/design/reports, and re-render the PDF.
- **Peer review of the v1 additions:** the owner arranges it with their own reviewers, as for the earlier reviews (expect DESIGN-REVIEW4*.md).
