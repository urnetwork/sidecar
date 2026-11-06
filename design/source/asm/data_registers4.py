# Register data for Appendices A and B, fourth assembly (2026-11-04), from the section files as last edited
# (2026-11-04 10:48). Starts from data_registers3.py (loaded with runpy) and replaces the summaries of the items
# that changed since the third assembly (v4/diff.json: 185 changed, 4 new) where the change touches the summary.
# Scripts run under python3 -I.
#
# D: id -> decision summary (<= 20 words). Withdrawn status comes from the section label.
# Q: id -> (question <= 25 words, recommendation-or-outcome <= 15 words).
# STALE_D, STALE_Q: items whose section text lags an owner decision (none expected); shown with a note.
import runpy, pathlib

_P = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_registers3.py'))
D = dict(_P['D'])
Q = dict(_P['Q'])

D.update({
# §1
'D-CTX-2': "R-CTX's Owner column plus Appendix F's per-PLAN-line trace is the traceability root; section tables gain no R-CTX column.",
'D-CTX-3': "§1.7's promises are requirements as the directive and owner decisions amend them; copy follows each amendment (owner decisions 119, 120).",
# §2
'D-TRUST-3': "No sidecar before the P0's first stage and the sidecar-token 7-day expiry; no desktop sidecar before its second stage.",
'D-TRUST-8': "Bind all interfaces unless `--listen` narrows; off loopback, git over http, IMAP and submission serve only TLS (owner decision 130).",
'D-TRUST-10': "I-16's witness is any admitted reader sidecar, agents included; writers alarm at 24 h, shared-group writers stop at `witness_bound_hours`.",
# §3
'D-ARCH-1': "Notation: `<root>`, `<net>`, `<host>`, `<blabel>`, mail host `mx.<net>.<root>`; `<me>` only in PLAN quotations.",
'D-ARCH-3': "Flows F1-F10 implement the directive and owner decisions 1-135, are redrawn when one changes, and are §22.7's scenarios.",
'D-ARCH-4': "Each flow names its owner decisions; G0's check fails on unimplemented decisions, withdrawn citations or decided questions shown open.",
})

Q.update({
# §1
'Q-CTX-1': ("Must the server services be self-hostable?",
            "At the later assured stage, through `ServiceHost` interfaces; v0 ships no bundle."),
'Q-CTX-2': ("Which runtime serves browser surfaces besides the extension?",
            "The extension's sidecar.wasm in a page Worker, labeled as served code."),
'Q-CTX-3': ("What is a recURd team in URnetwork terms?",
            "A new team network plus each member's personal network."),
# §2
'Q-TRUST-1': ("What admission posture stops ghost members, peers and server-written grants?",
              "A customer key authority from v0, subsuming member-signed admission."),
'Q-TRUST-9': ("Who is D-TRUST-10's witness, and when do shared-group writers stop without one?",
              "(c) any admitted reader witnesses; shared-group writers stop at a published per-network bound."),
# §3
'Q-ARCH-8': ("What happens to repo keys when an ephemeral client is reaped?",
             "(c) a reap starts a generation not wrapped to the agent; headless sidecars deposit only."),
})

D.update({
# §4
'D-REPO-8': "Superseded by owner decision 117: no scrub, archive, filtered clone or path allowlist; the repo keeps its documents and history.",
'D-REPO-9': "Superseded by owner decision 118: no private mirrors; each `sidecar` branch uses its normal remote, merging to `main` each Gn-out.",
# §5
'D-CORE-13': "Members' devices alarm on unsigned admissions and sign `OwnerConfirm` only via `ur approve` or the app, never MCP.",
# §6
'D-PROTO-1': "One public subprotocol id, 21842, carries §6.5's envelope.",
'D-PROTO-12': "Hint writes and triggers follow §6.8, since HSET and XADD emit nothing in production and concurrent writers would lower versions.",
'D-PROTO-13': "Peer sessions pass §6.4's identity check before streams or RPC (owner decision 3).",
'D-PROTO-14': "Sidecars compare pins by scheduled HeadCheck, any admitted reader sidecar witnessing, and refuse lower or conflicting values (owner decision 129).",
# §7
'D-TEAM-12': "Records freeze as Signed statements; authority statements need k of n, a recovery key counting as one after 72 h.",
'D-TEAM-14': "Sidecar-held child and admin-refused tokens expire after 7 days under `strict_exp`, with no app release (owner decisions 103, 131).",
'D-TEAM-16': "A member's consented devices admit its untagged devices unless `self_admit` is off; admins alone add no other owner-bound reader.",
'D-TEAM-17': "One first base per network; projections rise and chain by hash; HeadCheck compares them, unwitnessed writers stopping at `witness_bound_hours`.",
'D-TEAM-18': "Member devices are config leaves and agents hold wraps; an admission's or revocation's signer commits it (owner decisions 114, 128).",
# §8
'D-ACL-7': "Requested grants activate within `maxExpiry` only on approvals over the rule's `evidence` channels (§16.6).",
# §9
'D-SOCK-2': "Use 9.4's namespaces and host forms, refusing deeper names; owner decision 40's scopes add one label.",
'D-SOCK-13': "Names outside tls/, smtp/ and ur/ reach the server only as HMAC token paths under `K_sock`, rotated on §11.6's triggers.",
# §10
'D-KEYS-4': "Credential 0xF552 binds sidecar_id and identity key under a SidecarAdmit; only genesis is TOFU; owner-bound repos add only consented readers.",
'D-KEYS-7': "Superseded by owner decisions 113 and 128: the signed statement, not an admin committer, authorizes each membership change.",
'D-KEYS-13': "After a site loss, admins' devices re-seed each group from their keychains under a ladder-linked GroupForm.",
'D-KEYS-14': "Groups scale by 10.6's sizes: Update interval, KF5 resync, GroupInfo on demand above 16 leaves, daily acks, trees on disk.",
# §11
'D-EVS-1': "Plaintext git lives only on reading sidecars; evs holds segments, index entries and signed pushes.",
'D-EVS-14': "Subscriptions are server-side token-prefix leases; hints carry only server-held fields, versioned by each repo's push sequence.",
'D-EVS-15': "Local tier: system git behind authenticating fronts plus git-remote-ur; plaintext only on loopback, TLS or ssh beyond; committer hook.",
'D-EVS-19': "Deletion is a repo/ state with a 7-day restore window, then a keys-first shred no preservation hold defers.",
# §12
'D-DNS-3': "Only 12.6's self-hosted dns edge serves `<root>`, from two NS at the site (owner decisions 69, 71, 123).",
'D-DNS-6': "System records follow 12.7, with no wildcard CNAME; an entry is one user RRset.",
'D-DNS-7': "12.7 refuses non-public addresses and listed types and owners, and caps RRsets; SRV and `*.<host>` extend own records.",
# §13
'D-TLS-6': "Every device holds its own P-256 key and certificate for its set; member scopes only on that member's consented devices.",
'D-TLS-7': "certs proxies CSRs, queues orders, puts ephemeral sidecars on GTS or ZeroSSL first, and alone writes DNS-01 in URnetwork zones.",
'D-TLS-11': "A Team custom domain's one customer ACME account is shared by its ordering desktops, which order for every device.",
# §14
'D-SMTP-5': "Header domain `<net>.<root>` with SPF -all, envelope `b.<net>.<root>`, strict DMARC, FCrDNS with HELO = PTR (owner decision 124).",
'D-SMTP-7': "Superseded by owner decisions 34 and 124: smtpedge sends from the shared lb addresses, with no IP pools.",
'D-SMTP-14': "14.7's send gate, breaker and destination caps bound Community volume; its daily recipient cap bounds every tier.",
'D-SMTP-16': "M9's gate is 14.5's soundness, speed, coverage and interop tests, in both modes, with no external audit.",
'D-SMTP-17': "Superseded by owner decision 125: the DATA-mode proof is built beside BDAT, and DATA coverage joins D-SMTP-16's gate.",
'D-SMTP-18': "Phones do not prove: they write signed outbound mail to the mailbox outbox, which a consented prover host sends.",
'D-SMTP-19': "Reports and role mail go to `rpt.bringyour.com`, whose platform listener terminates every session, SNI or not, from M5.",
'D-SMTP-20': "14.5's DATA mode proves every body octet, in 2-minute parts, within a 2 h connection (owner decision 125).",
'D-SMTP-21': "Z1 proves TLS 1.2's server Finished in-circuit, so no TLS 1.2 key is disclosed.",
# §15
'D-MAIL-2': "mxedge's router speaks only 15.4's pre-TLS dialog, refuses plaintext transactions and splices from the ClientHello.",
'D-MAIL-3': "Receivers run emersion/go-smtp with 15.5's upstreamable ServeConn, forked if declined; readers verify mail with mox over DoH.",
'D-MAIL-4': "Each receiver presents its own certificate and TLSA record for `mx.<net>.<root>`, serving every burner, and MTA-STS as a system publish.",
'D-MAIL-9': "Owner accepts the M7 census's loss before burners launch; proposed bar: under 5% of sign-up and code mail lacks SNI.",
'D-MAIL-11': "Submission and IMAP bind all interfaces unless narrowed; off loopback they speak implicit TLS only (owner decision 130).",
'D-MAIL-13': "Owner decision 135's operator list is `mail_operators.yml` in the public sidecar repo, versioned and embedded in each release.",
# §16
'D-MCP-5': "Ingest via hooks, transcript tails and scans into a sealed, pre-redacted spool; hooks fail open, but lapses taint the run.",
# §17
'D-BRIDGE-12': "The sdk exports hosted addresses, granted prefixes, aliases and an RFC 1918 block, minus local-LAN overlaps, for apps.",
'D-BRIDGE-16': "`ur bridge block` refuses blocks outside 100.64/10 and RFC 1918; readers alarm on such a head; renumbering keeps host bits.",
# §18
'D-SDK-3': "Use 18.6's seam and mirror; app devices host, serve and map nothing before C16 (M4).",
'D-SDK-6': "The browser sidecar is phased per 18.8; its Workers are member devices, the quick burner a wrapped reader.",
'D-SDK-8': "Adopt 18.10's size gates, set by 18.3's iOS headroom and 18.10's wasm sizes.",
'D-SDK-9': "Apps decide approvals, admissions, alarms and recovery vetoes through `SidecarApprovals`; control mode never signs approvals with the identity key.",
'D-SDK-12': "ur.io's hosted DeviceLocal runs no sidecar or bridge, and 18.3's hosted check marks it for §8.10's gate.",
'D-SDK-13': "The device role takes rules and names only from its BridgeState and anchored deltas (18.6).",
# §19
'D-OPS-15': "Addresses and dns edges follow 19.4 and 19.5 (owner decisions 34, 69, 71, 123, 124).",
# §20
'D-QUOTA-2': "Limits and prices come only from pro.yml, with `network_sidecar_limit` overrides; limits ship dark; a missing price withholds overage.",
'D-QUOTA-7': "Abuse limits (`sidecar_abuse:`) are separate from quotas, never sold, equal on every tier, and tightened per network by §21.",
# §21
'D-ABUSE-2': "21.5's breakers guard `<root>` and the shared addresses, with thresholds in pro.yml `sidecar_abuse:`.",
'D-ABUSE-3': "Takedown follows 21.6 and 21.8: within 1 h for confirmed public phishing, malware and paged notices; `<root>` in Search Console.",
'D-ABUSE-4': "Screening, standing and verification follow 21.6 and 21.7.",
'D-ABUSE-5': "Intake and appeals follow 21.8, report mail never touching the SNI router.",
'D-ABUSE-6': "Legal process and holds follow 21.9 (owner decisions 93, 133); a hold revives no shredded key.",
'D-ABUSE-7': "Retention, access and transparency follow §2.8, 21.10 and 21.11.",
# §23
'D-PHASE-1': "Build 23.4's milestones in dependency order, staffed as 23.5 proposes, releasing each recURd stage once its last item lands.",
'D-PHASE-2': "No code before G0; an unsettled blocker defers what it blocks; implementation findings return as Q- items.",
'D-PHASE-5': "Superseded by owner decision 118: every touched repo merges `sidecar` into `main` at each Gn-out.",
})

Q.update({
# §4
'Q-REPO-4': ("When does sidecar go public, and with which documents?",
             "Now, as it is: no scrub; nothing waits for publication (owner decisions 117, 118)."),
# §5
'Q-CORE-5': ("Is the recovery code also an MLS recovery member?",
             "No; it derives keys for recovery wraps; admin re-add restores team repos, not owner-bound ones."),
# §7
'Q-TEAM-6': ("How many signatures admit a sidecar or member?",
             "(a) one; AdminSet and authority-key changes need k of n."),
'Q-TEAM-10': ("May a member's own device alone admit that member's new device?",
              "(a) yes, as a scoped delta unless `self_admit` is off; the signer commits the Add."),
'Q-TEAM-11': ("May a recovery key sign an authority statement?",
              "(b) one signature toward k, after a 72 h veto window; personal networks recover alone."),
# §8
'Q-ACL-1': ("[X3] Who is the policy authority?",
            "A customer key authority from v0, compiled on customers' devices."),
'Q-ACL-9': ("May tagged, ephemeral, CI and cloud sidecars read and write through per-generation X-Wing wraps instead of MLS leaves?",
            "(a) yes, in every granting repo, amending owner decision 60."),
# §9
'Q-SOCK-3': ("Which relationship carries cross-network streams (X11, §20)?",
             "Service for edges; shares ride §17's IP path as FriendsAndFamily."),
# §10
'Q-KEYS-7': ("How does a member recover after losing every device?",
             "Recovery-code wraps plus admin re-add; the recovery key counts as one of k."),
'Q-KEYS-9': ("[X12] Does v0 ship MLS, or per-device wraps with MLS in v1?",
             "MLS in v0 (PLAN.md:44); agents' wraps carry its generations (owner decision 114)."),
'Q-KEYS-13': ("Does owner decision 7's 'only from keys allowed to grant' bind the membership committer or the change?",
              "(b) the change: signed inputs authorize commits (10.9); D-KEYS-7 is withdrawn."),
'Q-KEYS-14': ("Who commits the config group's membership changes, when only admins write config records?",
              "(a) also the signing leaf; recovery-admitted devices self-join by external commit."),
# §11
'Q-EVS-7': ("Does a preservation hold pause user-initiated shredding (`--now`, the 7-day timer, slot erasure)?",
            "(a) no: holds pause only server TTL sweeps and GC, if counsel confirms."),
# §14
'Q-SMTP-1': ("[X7] How is the preamble made trustworthy, and what ships before a sound proof?",
             "Nothing until D-SMTP-16's gate passes; receive-only burners; a DATA circuit always funded."),
'Q-SMTP-6': ("Which IPv4 addresses send outbound mail, under which PTR names?",
             "(a) the shared lb addresses, PTRs under bringyour.com; no IP pools."),
# §15
'Q-MAIL-13': ("What makes received mail 'validated', given that few senders set REQUIRETLS?",
              "(b) REQUIRETLS, or TLSA in our zone plus a listed enforcing operator."),
# §16
'Q-MCP-4': ("How do cloud agents use the sidecar?",
            "(a) `ur` inside the VM over HTTP CONNECT; agents witness too (owner decision 129)."),
# §17
'Q-BRIDGE-1': ("[X18] Which range carries overlay addresses, and how are they allocated?",
               "IPv4 only; a random /16 from 100.64/10, cycled or chosen within Q-BRIDGE-7's ranges."),
'Q-BRIDGE-5': ("Which bind do forwards and local listeners use?",
               "0.0.0.0/:: unless `--listen` narrows; off loopback, content listeners serve only TLS."),
'Q-BRIDGE-7': ("May a chosen overlay block lie outside 100.64/10 and RFC 1918?",
               "(b) no: only 100.64/10 or RFC 1918, narrowing owner decision 28."),
# §19
'Q-OPS-8': ("How do migration groups reach server's main when M3 pilots on production?",
            "Each group's SQL merges to main with its milestone at Gn-out (owner decision 118)."),
# §20
'Q-QUOTA-1': ("[X16] Which tier numbers, and what shape of Team price?",
              "PLAN's quotas; Team $100 for 5 seats, then $20; overage at existing rates."),
# §21
'Q-ABUSE-1': ("How far is §2.8's EX3, undetected interception of opportunistic inbound mail, narrowed?",
              "(c) per-message labels, DNS and CT watches, Team strict mode."),
'Q-ABUSE-5': ("What legal posture does URnetwork take?",
              "(a) notice unless sealed, quarterly canary, no prospective collection; holds await counsel."),
'Q-ABUSE-6': ("How do v0's review clocks run with business-hours staff?",
              "(b) business-hours review, machine actions holding; an M5 pager for emergency notices."),
# §23
'Q-PHASE-5': ("When do external reviews run?", "Moot; 22.10's gates stand in."),
'Q-PHASE-7': ("How is token expiry enforced before the first sidecar?",
              "(b) a hard 7-day expiry on sidecar-held child and admin-refused tokens only, with the P0."),
'Q-PHASE-8': ("When does sidecar go public?",
              "Now, as it is (owner decisions 117, 118); every touched repo merges at each Gn-out."),
})

# Items whose section text lags an owner decision (Known gaps). Filled from validation; none expected.
STALE_D = {}
STALE_Q = {}

Q.update({
'Q-CORE-6': ("How does one device join several networks?",
             "One daemon hosts one Sidecar per network, sharing no client or key."),
})
