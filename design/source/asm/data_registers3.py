# Register data for Appendices A and B, third assembly (2026-11-04), from the section files as last edited
# (2026-11-04 05:43). Starts from data_registers2.py (loaded with runpy) and replaces the summaries of the 75
# changed and 7 new items (v3/diff.json). Scripts run under python3 -I.
#
# D: id -> decision summary (<= 20 words). Withdrawn status comes from the section label.
# Q: id -> (question <= 25 words, recommendation-or-outcome <= 15 words).
# STALE_D, STALE_Q: items whose section text lags a 2026-11-04 owner decision; the note is shown in the register
#    and the location is listed under Known gaps. Status itself is still computed from the section text.
import runpy, pathlib

_P = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_registers2.py'))
D = dict(_P['D'])
Q = dict(_P['Q'])

D.update({
# §2
'D-TRUST-3': "No sidecar ships before the P0's first stage and D-TEAM-14's 7-day expiry; no desktop sidecar before its second stage.",
'D-TRUST-5': "Membership and the communication graph are published as server-visible; team-management.html:814 and :917 change (owner decision 72).",
'D-TRUST-8': "Listeners bind all interfaces unless `--listen` narrows; off loopback, content listeners need TLS or ssh, pending Q-BRIDGE-5's residual.",
'D-TRUST-10': "I-16's witness is another reader device's hourly HeadCheck; pending Q-TRUST-9, writers in shared groups stop after 24 h without one.",
# §7
'D-TEAM-10': "Removal denies at the server at once and closes the write gate until a Remove or rotation lands.",
'D-TEAM-12': "Records freeze in v0 as Signed statements; every config-signing role's authority statement needs k of n or vetoable recovery.",
'D-TEAM-15': "Edge login issues a 60 s, nonce-bound ID token for one origin, only to members; sessions count only same-origin.",
'D-TEAM-16': "A member's consented device admits the member's untagged devices unless self_admit is off; tag owners and Delegations admit within scope.",
'D-TEAM-18': "Member devices are config leaves; agents read through X-Wing wraps, Delegation-admitted ones at once (owner decision 114).",
# §8
'D-ACL-13': "Kind defaults precede every document; owner-bound repos take readers only from the owner's consent, shares and the visible audit reader.",
'D-ACL-17': "Member devices read as leaves; other sidecars read and write every granting repo, config included, through ReaderWraps (owner decision 114).",
# §10
'D-KEYS-2': "One MLS group per evs repo, a leaf per reading member device, at most 1,000; other readers hold ReaderWraps.",
'D-KEYS-4': "Credential 0xF552 binds sidecar_id and identity key under a SidecarAdmit; only genesis is TOFU; owner-bound repos need owner consent.",
'D-KEYS-7': "Superseded by owner decision 113: any writer leaf commits the Adds and Removes that signed inputs require.",
'D-KEYS-10': "M2's exit needs 10.4's conformance plan, Go-test fuzz targets and 10.6's sizes measured; the security page discloses unaudited MLS.",
'D-KEYS-11': "Tagged, ephemeral, CI and cloud sidecars read and write through ReaderWraps; Delegations get reader keys (owner decision 114).",
'D-KEYS-13': "After a site loss, repo or network admins' devices re-seed each group from keychains under a ladder-linked GroupForm.",
'D-KEYS-14': "Groups scale by 10.6's sizes: Update interval, KF5 resync, GroupInfo on demand, daily acks and trees kept on disk.",
# §11
'D-EVS-11': "Kinds are fixed at creation; vault and mailbox readers are only consented owner devices, EvsShares and the visible audit reader.",
'D-EVS-20': "Pushes over 1 MiB or 1,024 entry writes split into at most 1,024 hashed parts; one head PUT commits them.",
'D-EVS-21': "11.13 budgets metadata-cluster operations: daily lease renewals and gkm acks, counter-led lease LISTs, per-network tier-weighted fair share.",
# §12
'D-DNS-4': "TTLs follow 12.6, short enough for ACME, failover and takedown.",
# §13
'D-TLS-2': "Ingress is 13.4's gated, probed SNI split on the shared lb addresses; port 80 only redirects.",
'D-TLS-5': "The sidecar's TLS front enforces 13.7's rules; coalescing and the shared site make the 421 and origin rules mandatory.",
'D-TLS-10': "TCP 443, 8443, 8883 and 5671 (owner decisions 68, 121); no HTTP/3 or published ECH configs; tlsedge routes on SNI.",
'D-TLS-11': "Each Team custom domain has one customer ACME account, held by its publish-grant desktops, which order for every device.",
# §15
'D-MAIL-9': "Burners launch after the owner accepts the M7 census's measured loss (SNI, DANE, TLS per ASN) and §14's probe.",
'D-MAIL-11': "Submission and IMAP bind all interfaces unless `--listen` narrows them, and off loopback require TLS before AUTH, pending Q-BRIDGE-5.",
'D-MAIL-12': "A Team direct MX names at most two mxedge-verified receivers; strict mode refuses spliced hosts; scopes receive on consented devices.",
# §16
'D-MCP-7': "No URnetwork-hosted MCP serves sidecar tools; cloud agents run `ur` in their VM (owner decision 49).",
# §19
'D-OPS-15': "Addresses and dns edge hosts follow 19.5 (owner decisions 34, 69, 71, 123, 124); nothing is dedicated to user traffic.",
'D-OPS-17': "Size the metadata tier by objects and operations measured at M2; 50% alerts on a set's budget order pools.",
# §23
'D-PHASE-3': "P0 stage 1 and D-TEAM-14 reach production log-only at M0's Gn-out; stage 2 and sdk credential rules precede M3's pilot.",
'D-PHASE-5': "Superseded by owner decision 118: no merge waits for RS1; every repo merges at each Gn-out.",
})

Q.update({
# §2
'Q-TRUST-1': ("What admission posture stops ghost members, peers and server-written grants?",
              "A customer key authority from v0, subsuming member-signed admission; residuals Q-TEAM-11, Q-ACL-10."),
'Q-TRUST-7': ("Without an ACL document, should providers refuse loopback, LAN, link-local and overlay destinations to sidecar sources?",
              "(a) no: keep allow-all and disclose it (I-10, §2.18)."),
'Q-TRUST-8': ("May product copy claim 'end-to-end encrypted' without external review?",
              "(a) yes, now, disclosing that the cryptography is not independently audited."),
'Q-TRUST-9': ("Who is D-TRUST-10's witness, and when do shared-group writers stop without one, given lone agents, weekend CI and wakes only at M8?",
              "(c) any admitted reader witnesses; alarm 24 h, stop 72 h; per-network bound."),
# §7
'Q-TEAM-6': ("How many signatures admit a sidecar or member?",
             "(a) one; AdminSet and authority-key changes need k of n; residual Q-TEAM-11."),
'Q-TEAM-10': ("May a member's own device alone admit that member's new device?",
              "(a) yes, as a scoped delta unless self_admit is off; residual Q-KEYS-14."),
# §8
'Q-ACL-1': ("[X3] Who is the policy authority?",
            "A customer key authority from v0, compiled on customers' devices; residual Q-ACL-10."),
'Q-ACL-9': ("May non-member-device sidecars (tagged, ephemeral, CI, cloud) read and write through per-generation X-Wing wraps instead of MLS leaves?",
            "(a) yes, in every granting repo, amending owner decision 60."),
'Q-ACL-10': ("Does owner decision 8's 'network admins can always grant or revoke' reach owner-bound kinds such as vaults and mailboxes?",
             "(a) no: admins revoke there and add only the visible audit reader."),
# §10
'Q-KEYS-3': ("[X12] At what granularity are MLS groups formed?",
             "Per repo; grants map onto membership; agents hold wraps (owner decision 114)."),
'Q-KEYS-5': ("What admission evidence must an MLS credential carry?",
             "A config-repo SidecarAdmit chained to genesis; members' devices may sign it (owner decision 112)."),
'Q-KEYS-9': ("[X12] Does v0 ship MLS, or per-device wraps with MLS in v1?",
             "MLS in v0 (PLAN.md:44); per-device wraps are not the v0 distributor."),
'Q-KEYS-12': ("[X12] Which header values does gkm see?",
              "Ciphertext plus group id, epoch, sizes and 10.6's sidecar-id rows; confirmed (owner decision 115)."),
'Q-KEYS-13': ("Does owner decision 7's 'only from keys allowed to grant' bind the membership committer or the change?",
              "(b) the change: any writer leaf commits what signed inputs require; residual Q-KEYS-14."),
'Q-KEYS-14': ("Only admin roles write the config repo, so who commits a self-admitted device's config-group Add, given owner decision 113's 'no change waits for an admin'?",
              "(a) the leaf that signed the admission or revocation commits it."),
# §12
'Q-DNS-4': ("Which providers serve `<root>`?",
            "None: a self-hosted dns edge, signed online, two NS at the site."),
'Q-DNS-7': ("Should one NS run outside the site before M7?",
            "(b) no: two NS at the one site; outage risk accepted."),
# §13
'Q-TLS-8': ("May names publish ports other than 443, and which?",
            "(b) a fixed list: 8443, 8883 and 5671 (owner decision 121)."),
# §16
'Q-MCP-4': ("How do cloud agents use the sidecar?",
            "(a) `ur` inside the VM over HTTP CONNECT; residual Q-TRUST-9."),
# §18
'Q-SDK-1': ("[X14] What runs the extension's sidecar?",
            "(a) a slimmed WASM Worker, HTTPS-only first; (c) native companion meanwhile; residual: size spike."),
# §19
'Q-OPS-1': ("[X13] What is the 'new file cluster' (PLAN.md:61), and where does ordering live?",
            "Two MinIO clusters at one site, store-ordered; parity and drives as recommended (owner decision 116)."),
'Q-OPS-2': ("Should small objects pack, given Y2's HDD operation load and gkm's gen/ objects on the metadata tier?",
            "(b) in v0; (a) past half the measured rate, and gen/ packing before Y2."),
'Q-OPS-8': ("How do migration groups reach server's main when M3 pilots on production?",
            "Every repo merges at each Gn-out with its groups' SQL (owner decision 118)."),
# §22
'Q-TEST-3': ("Who performs external security reviews?", "Nobody for now; 22.10's gates stand in."),
# §23
'Q-PHASE-8': ("When does sidecar go public?",
              "Now, unscrubbed (owner decisions 117, 118); every repo merges at each Gn-out."),
})

# Items whose section text lags a 2026-11-04 owner decision (Known gaps). "@@OD:N@@" links to row N.
STALE_D = {
    'D-REPO-8': "still proposed in §4.13; @@OD:117@@ withdraws it",
    'D-REPO-9': "still proposed in §4.13; @@OD:118@@ withdraws it",
    'D-SMTP-17': "still proposed in §14.11; @@OD:125@@ supersedes it",
}
STALE_Q = {
    'Q-REPO-4': "residual answered by @@OD:117@@ and @@OD:118@@; §4.14 not updated",
    'Q-SMTP-1': "residual answered by @@OD:125@@; §14.12 not updated",
    'Q-QUOTA-1': "residual answered by @@OD:122@@; §20.12 not updated",
    'Q-SMTP-6': "decided by @@OD:124@@ on 2026-11-04; §14.12 still shows it open",
}
