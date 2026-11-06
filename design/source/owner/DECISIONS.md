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

## Owner instructions after the v1 build (2026-11-05)

These are instructions, not design decisions, so they carry no number.

- **SDK gaps: "Design both fixes now."** The two residuals the v1 build left are designed as proposed decisions:
  - stale page Workers when `self_admit` is off (D-TEAM-29, §7.10's `stale` row);
  - revoking a lost device from an app (D-CORE-20 in §5.4 and §5.6, D-SDK-30 in §18.5).

  Their tests are FS-97 and FS-98. Independent checkers reviewed them before the rebuild.
- **Renumbered § references in DESIGN-REVIEW-RESPONSE.md:** keep them.
- **pitch5 (outside DESIGN.md):** update both session lines (:579, :640) to owner decision 170's limit, fix the five footers to cite sidecar/design/reports, and re-render the PDF.
- **Peer review of the v1 additions:** the owner arranges it with their own reviewers, as for the earlier reviews (expect DESIGN-REVIEW4*.md).
