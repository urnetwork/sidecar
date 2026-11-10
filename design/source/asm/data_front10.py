"""Front matter after the final meta review (2026-11-06): layered over data_front9.py. Adds owner decisions 185-191:
the presence countersignature (185, 187, 189), unlimited P0 writes outside the wear bound (186, 190), and the search
pair's accounting windows (188, 191). Adds owner decisions 192-196 from the implementation handoff: a parking
DelegationRevoke's countersignature (192), the G0 sign-off (193), the straight-through build (194), the minio fork
(195) and the branch starts (196). Adds owner decision 197 (2026-11-09): the apps' network extensions run only IP
and port forwarding, always on and self-contained, amending 87, and Android's sidecar runs only while the app is
open, amending 12. From 2026-11-10 adds the build's owner answers, 198 onward, as the design-records tracks fold
them from sidecar/DESIGN-AMENDMENTS.md: the nightly count's shard sums (198), Team subscriptions (199), the
fold's leaf places (200), gkm's owner marker (201), forwarding reader keys at gkm (202), the orphan horizon (203),
the drop job's horizon, amending 183 (204), settings in rows (205), the sweep's triggers (206), a reported URL's
path (207), the sealed abuse mailboxes (208), head readers' read records (209), the primary's physical copies (210),
the key origin served direct (211), the compromise rebind's procedure (212), no apt or yum repository in v1 (213),
the witness call outside the planes (214), forwarding's iOS executable budget and compile cap (215, 216), deciding
Q-SDK-7, the key origin's per-network databases (217), multi-use bridge approvals (218), the key origin's sign-in
hand-off (219), requested grants' sealed detail (220), promoted key-origin builds (221), wintun.dll left unbundled
(222), the ur.io/recurd page (223) and C16's latch (224)."""
import runpy, pathlib
_P9 = runpy.run_path(str(pathlib.Path(__file__).parent / 'data_front9.py'))
globals().update({k: v for k, v in _P9.items() if not k.startswith('__')})

INDEX = list(_P9['INDEX']) + [
    (185, "Presence countersignature",
     "A `compromise` SidecarRevoke, and a KeyRevoke of a presence key, carry that key's countersignature whenever "
     "the signer registered a live presence key; api and every member device verify it."),
    (186, "Write governor",
     "P0 writes are never queued or refused; FI-14's wear bound exempts them, disclosed with P0 dashboards and "
     "alarms, amending @@OD:140@@ for P0 only."),
    (187, "Presence countersignature",
     "The countersignature of @@OD:185@@ also covers revoking another device for any reason, Suspend of another "
     "device, and RecoveryVeto."),
    (188, "Q-PROTO-4",
     "The five-page promise of @@OD:176@@ holds: C19 accounts the search pair in 55-minute windows, reporting a "
     "256 KiB floor at each window's end, with a Ping a minute while foregrounded."),
    (189, "Presence countersignature",
     "The countersignature also covers SidecarAdmit, AdmissionConfirm and OwnerConfirm of untagged sidecars, "
     "AdminSet changes, MemberRevoke, RecoveryBind and RecoveryRebind."),
    (190, "Q-EVS-24",
     "After a P0 storm the other classes resume at once: the write bucket floors at zero, so P0's excess is "
     "forgiven and counted, not repaid (@@OD:186@@)."),
    (191, "Q-PROTO-4",
     "A search that finds its indexer session lost re-establishes it at once; connect-5 discloses that its contract "
     "keeps the search's time, narrowing @@OD:188@@."),
    (192, "Presence countersignature",
     "A `DelegationRevoke` that parks other devices (`since_n` > 0) also carries the countersignature: the final meta "
     "review's extension, following @@OD:187@@'s intent, ratified as written."),
    (193, "G0",
     "The owner signs G0 on 2026-11-06; the re-checks of the 21 items DESIGN-REVIEW-RESPONSE.md places at G0, the "
     "density review and RECORD.md's draft run beside M0's bootstrap, and their findings return as Q- items."),
    (194, "Build order",
     "M0-M10 build straight through in dependency order on the `sidecar` branches: each gate's local checks run and "
     "are reported, and anything needing hardware, production or people stays listed open. §23.8's freezes do not "
     "move."),
    (195, "D-OPS-20",
     "D-OPS-20's MinIO build lives in a new `urnetwork/minio` fork, a sibling checkout with its own `sidecar` branch, "
     "keeping MinIO's AGPL source in one public place; the owner creates the GitHub repo before any push."),
    (196, "Branch starts",
     "A `sidecar` branch on all repos the work touches: warp's, config's, mmm's and vault's all open at M0, so §19.11 "
     "lands W5 at M0 and W2 and W8 by M4 on warp's branch."),
    (197, "Q-SDK-2, Q-MAIL-2",
     "Every app's VPN component runs the device's IP and port forwarding and nothing else of sidecar, always on and "
     "self-contained with its own forwarding key, amending @@OD:87@@; Android's sidecar runs only while the app is "
     "open, as iOS's does, amending @@OD:12@@."),
    (198, "Stored count",
     "The nightly pass's shard jobs keep per-network sums for the night in Redis `{evsn_<night>}` (48 h); a closing "
     "job writes each network's count once every shard of every metadata cluster has reported, and a night left "
     "unfinished keeps the old count."),
    (199, "Team billing",
     "A `team_subscription` row (MG6) records each Team's Stripe subscription, customer, anchor and start, written at "
     "the first `invoice.paid` and ended at `customer.subscription.deleted`; only a live row is granted a period."),
    (200, "Path epochs",
     "The fold records each folded version's place in its statement's change list (`leaf_part`, `leaf_index`), so "
     "evs serves the proof of a version an older path epoch wrote and the reader checks the leaf names its token."),
    (201, "Group owner",
     "A group's first object is `gkm/<group_id>/owner` (repo and network), created If-None-Match from the token; "
     "every group route resolves through it, so no other repo's form can claim the group."),
    (202, "Forwarding keys",
     "A forwarding Delegation's row carries its reader key's SHA-256, and the 1,216 B key is the gkm object "
     "`gkm/dkey/<delegation_id>`, keeping 5,000-device rows near 2.2 MB under §8.8's 4 MiB."),
    (203, "Segment GC",
     "An unadopted segment goes once no batch is left from before its upload + 24 h + 2 min, 49 to 75 h, so GC "
     "raises no fence; evacuation fences a ref with no head by a placeholder head."),
    (204, "Drop history",
     "A drop job marks only once evacuation's horizon has passed each covered drop's commit by 2 min, so a `now` "
     "drop's deletions start about 25 to 26 h after it, amending @@OD:183@@'s 25-minute fence."),
    (205, "Settings in rows",
     "`self_admit` and `scim_signer` compile into `ProjectionRows.settings`, which full readers check against the "
     "head and api and the gates take, so every verifier judges a self-admission alike."),
    (206, "Versionless sweep",
     "`AbuseHoldPass` queues a hold's end pass before it deletes `hold/`, and `sidecarctl evs purge-turn-on` queues "
     "the turn-on pass in the step that sets `format2.purge: on`."),
    (207, "Abuse cases",
     "A case keeps a reported URL's path and query until its first review ends, at most its review clock; never a "
     "reporter's address or free text but an appeal's own reason."),
    (208, "Abuse mailboxes",
     "The abuse and legal-request mailboxes sit at one provider outside URnetwork's Postgres and clusters; each "
     "record is sealed to a vault-held HPKE key before it leaves api, so the provider and SES see sender, time "
     "and size."),
    (209, "Head reads",
     "Head readers keep a sealed record per path read (ref, path, entry version, pin), at most 16,384 a network, and "
     "read a recorded path from its record's pin, so the published limit is a path never read or no longer remembered."),
    (210, "D-TRUST-7",
     "The primary's physical copies count as backups: each is refreshed or destroyed within 7 d, and the 24 h edge "
     "records' partitions are UNLOGGED, so no physical copy holds them."),
    (211, "Key origin",
     "`sidecar.ur.io` is served direct, unproxied, never through Cloudflare, which terminates https://ur.io; §2.8's "
     "EX7 discloses that Cloudflare sees page requests and can alter page script."),
    (212, "Recovery rebind",
     "After a compromise rebind at r, `--compromise` lists the member's devices, clamps the rebind signer's since_n "
     "to r + 1 so the rebind stands, and revokes that signer last, by the replacement it enrolls."),
    (213, "Linux packages",
     "v1 ships no apt or yum repository: `.deb` and `.rpm` stay direct downloads through `install.sh`'s verified "
     "path, with no GPG key or repository host."),
    (214, "D-ARCH-2",
     "A checkpointer's own HTTPS call to a witness its log admin named is no URnetwork carrier: it carries a signed "
     "note and a consistency proof, never an entry, and no URnetwork server takes part."),
    (215, "Q-SDK-7",
     "Forwarding adds at most 6 MiB of stripped executable to the iOS network extension, whose signed ceiling rises "
     "from 50 MiB to 54 MiB; one implementation of the rule table stays."),
    (216, "Q-SDK-7",
     "A forwarding compile in the Apple extensions needs 5 × rows + 2 × head + 1 MiB within a 10 MiB cap and the "
     "room under a 30 MiB ceiling, about 4,300 devices; a larger network keeps its last verified state there and "
     "alarms, and no wait for a compile makes it pending."),
    (217, "Key origin storage",
     "The key origin keeps one IndexedDB database per network, `urnetwork-sidecar-v1-<network_id>`, each its own "
     "instance and root key, so the per-network Web Lock covers everything a Worker writes."),
    (218, "Bridge approvals",
     "`BridgeApproval.template_action` carries a multi-use decision's template beside each use's action, so readers "
     "check the use against it and one decision files up to its uses bridge rules."),
    (219, "Key origin sign-in",
     "The key origin signs a page Worker in by the ur.io session's hand-off: a one-time `/auth/code-create` code by "
     "postMessage, redeemed at `/auth/code-login` to mint its client, the network token then dropped."),
    (220, "Requested grants",
     "A requested `dial` or `route` grant's prefixes and ports move into its CanonicalAction's sealed "
     "`sealed_detail`, so api checks the grant by ids alone."),
    (221, "Key origin builds",
     "`sidecar.ur.io` serves only a promoted build, its loader and `sidecar.wasm` listed in the release's signed "
     "`SHA256SUMS` and the wasm's hash pinned in the loader; no browser checks them on load."),
    (222, "`ur tun` on Windows",
     "`ur tun` neither bundles nor fetches wintun.dll; it loads one beside `ur.exe` or at the app's path only once "
     "its hash and signer match the Windows app's pins."),
    (223, "ur.io/recurd",
     "A minimal real ur.io/recurd page (label, key-origin frame, sign-in, records, downloads) is built on mmm's "
     "`sidecar` branch; its visual design stays out."),
    (224, "C16",
     "C16's receive gate latches at this side's seal for M4; before M8 turns it on for app-device hosts the plaintext "
     "in flight at a seal is measured, and a visible loss moves the latch to the peer's first sealed frame within "
     "`TlsTimeout`."),
]
# Owner decision 188 amends 176's summary (the reconciler's ASM.md, 1.2).
_i176 = [r[0] for r in INDEX].index(176)
INDEX[_i176] = (176, INDEX[_i176][1],
                "Connect rounds the byte reports of phone-to-indexer search contracts up to 128 KiB, hiding up to five "
                "search pages an hour. Amended by @@OD:188@@.")
# Owner decision 197 amends 87's and 12's answers, which their rows note as 176's does.
for _n, _old_end, _note in [
        (87, "network processes hold only the keyless device role.",
         " Amended by @@OD:197@@: every app's VPN component runs the device's IP and port forwarding, self-contained "
         "with its own forwarding key, and nothing else of sidecar."),
        (12, "no hosted or TEE receiver.",
         " Amended by @@OD:197@@: Android with the VPN on is no receiver; the Android app, like the iOS app, receives "
         "only while open.")]:
    _i = [r[0] for r in INDEX].index(_n)
    assert INDEX[_i][2].endswith(_old_end), _n
    INDEX[_i] = (_n, INDEX[_i][1], INDEX[_i][2] + _note)
assert [r[0] for r in INDEX] == list(range(1, 225))
DATES = dict(_P9['DATES'])
DATES.update({185: '2026-11-05', 186: '2026-11-05', 187: '2026-11-05', 188: '2026-11-06', 189: '2026-11-06',
              190: '2026-11-06', 191: '2026-11-06', 192: '2026-11-06', 193: '2026-11-06',
              194: '2026-11-06', 195: '2026-11-06', 196: '2026-11-06', 197: '2026-11-09',
              198: '2026-11-10', 199: '2026-11-10', 200: '2026-11-10', 201: '2026-11-10', 202: '2026-11-10',
              203: '2026-11-10', 204: '2026-11-10', 205: '2026-11-10', 206: '2026-11-10', 207: '2026-11-06',
              208: '2026-11-06', 209: '2026-11-06', 210: '2026-11-06', 211: '2026-11-06', 212: '2026-11-06',
              213: '2026-11-06', 214: '2026-11-06', 215: '2026-11-10', 216: '2026-11-10', 217: '2026-11-10',
              218: '2026-11-10', 219: '2026-11-06', 220: '2026-11-06', 221: '2026-11-06', 222: '2026-11-06',
              223: '2026-11-06', 224: '2026-11-06'})
_ANCHOR = "This section lists the cross-cutting decisions"
assert _ANCHOR in _P9['DECISIONS_INTRO']
DECISIONS_INTRO = _P9['DECISIONS_INTRO'].replace(
    _ANCHOR,
    "On 2026-11-05 and 2026-11-06, with the owner's SDK fixes and the final meta review, the owner extended the "
    "presence countersignature (185, 187, 189), kept P0 writes unlimited outside the wear bound with their excess "
    "forgiven (186, 190), and kept "
    "@@OD:176@@'s five-page promise through accounting windows (188, 191). On 2026-11-06, at the implementation "
    "handoff, the owner ratified the countersignature on a `DelegationRevoke` that parks other devices (192), signed "
    "G0 (193), set M0-M10 to build straight through on the `sidecar` branches (194), gave D-OPS-20's MinIO build a "
    "fork of its own (195) and opened every touched repo's `sidecar` branch at M0 (196). On 2026-11-09, as the "
    "build planned the apps' integration, the owner put only IP and port forwarding in every app's VPN component, "
    "always on and self-contained, and ran Android's sidecar only while the app is open (197), amending "
    "@@OD:87@@ and @@OD:12@@. " + _ANCHOR)

STATUS = ("Status: draft for peer review, revised 2026-11-04 after the first peer review (see "
          "[DESIGN-REVIEW-RESPONSE.md](DESIGN-REVIEW-RESPONSE.md)), on 2026-11-05 with the v1 additions of owner "
          "decisions 150-184 (versionless objects, the search index, CLI and MCP search, the indexer, the team directory "
          "and history drops), and on 2026-11-06 after the final meta review "
          "([DESIGN-REVIEW-META.md](DESIGN-REVIEW-META.md)), with owner decisions 185-191, and at the implementation "
          "handoff, with owner decisions 192-196, on 2026-11-09 with owner decision 197, on the apps' network "
          "extensions, and from 2026-11-10 with the build's owner answers, owner decisions 198 onward, as the "
          "design-records tracks fold them. The owner signed G0 on 2026-11-06 (owner decision 193), and M0-M10 build on the `sidecar` "
          "branches (owner decision 194); nothing has shipped.")

# Implementation handoff (2026-11-06): the branch policy said the documents join the repo on the `sidecar` branch,
# but §4.3 and §4.11 put them on `main`, where they are; only code starts on `sidecar` (§4.8).
_BR_OLD = "DESIGN.md and design-research/ join it on the `sidecar` branch (§4.11)."
_BR_NEW = ("Its documents, DESIGN.md and `design/design-research/` among them, are on `main`; code starts on the "
           "`sidecar` branch (§4.11).")
assert BRANCH.count(_BR_OLD) == 1, 'branch policy text moved'
BRANCH = BRANCH.replace(_BR_OLD, _BR_NEW)

# Owner decision 196: every touched repo's branch opens at M0, so §19.11's W5 lands on warp's branch.
_BS_OLD = "- **Branch starts** (§23.4): sidecar, connect, server, sdk, build, sn and xops in M0; mmm and config in M1; vault in M2; warp in M5."
_BS_NEW = ("- **Branch starts** (§23.4): every touched repo in M0 (@@OD:196@@): sidecar, connect, server, sdk, build, sn, "
           "xops, warp, config, mmm and vault, and the `urnetwork/minio` fork (@@OD:195@@).")
assert BRANCH.count(_BS_OLD) == 1, 'branch starts moved'
BRANCH = BRANCH.replace(_BS_OLD, _BS_NEW)

# Owner decision 195: D-OPS-20's MinIO build has a repo of its own.
_SC_OLD = "through sn, warp, config, vault, build, xops and mmm."
assert SCOPE.count(_SC_OLD) == 1, 'scope text moved'
SCOPE = SCOPE.replace(_SC_OLD, "through sn, warp, config, vault, build, xops, mmm and the `urnetwork/minio` fork.")

# Id families after the final meta review: filled in from the reconciler's IDS.md before the build.
_ID_FIX = [("FI-1 to FI-27 (", "FI-1 to FI-30 ("), ("FS-1 to FS-98 (", "FS-1 to FS-125 ("),
           ("I-EVS-1 to I-EVS-15 (", "I-EVS-1 to I-EVS-17 ("),
           ("RV1-RV3 (restore invariants", "RV1-RV4 (restore invariants"),
           ("WK1-WK4 (wake invariants", "WK1-WK5 (wake invariants")]
for _a, _b in _ID_FIX:
    assert sum(_v.count(_a) for _k, _v in globals().items() if not _k.startswith('_') and isinstance(_v, str)) == 1, _a
for _k, _v in list(globals().items()):
    if not _k.startswith('_') and isinstance(_v, str):
        for _a, _b in _ID_FIX:
            _v = _v.replace(_a, _b)
        globals()[_k] = _v

# Owner decision 197 (2026-11-09): designing it raised two owner questions, Q-BRIDGE-8 and Q-SDK-7, the first open
# owner questions since owner decision 140's corrected record. The sections are written to each open one's
# recommendation, marked "(proposed; Q-...)"; assemble10.py checks OPEN_OWNER against them. Owner decisions 215 and
# 216 (2026-11-10) decide Q-SDK-7, so Q-BRIDGE-8 alone stays open.
_OPEN_OLD = "None. Every Q- item whose decider was the owner is decided. "
assert OPEN_INTRO.count(_OPEN_OLD) == 1, 'open-questions lead moved'
OPEN_INTRO = OPEN_INTRO.replace(
    _OPEN_OLD,
    "One, raised on 2026-11-09 in designing owner decision 197's forwarding: Q-BRIDGE-8 (an app device's overlay "
    "address), to whose recommendation the sections are written, marked \"(proposed; Q-BRIDGE-8)\". The other "
    "raised with it, Q-SDK-7 (forwarding's budget in the iOS network extension), was decided on 2026-11-10 "
    "(@@OD:215@@, @@OD:216@@). Every other Q- item whose decider was the owner is decided. ")
OPEN_OWNER = [
    ("Q-BRIDGE-8", "Does an app device claim its overlay address when its forwarding is set up (owner decision 197)?",
     "(a) on demand, as §17.4 says: the app's UI, the host's first map or an admin; (b) at forwarding's setup, its "
     "sidecar filing its own `BridgeAddress`",
     "(a): with no ACL document a hosted address opens the device's loopback to the network's untagged sidecars "
     "(owner decision 120), and (b) can follow by one filing",
     "nothing before M8's app hosts", "M8"),
]
for _a, _b in [("[open owner questions](#open-owner-questions) (none remain)",
                "[open owner questions](#open-owner-questions) (@@NQOWNWORD@@, raised with owner decision 197)"),
               ("and @@NQW@@ withdrawn; none is open.", "@@NQW@@ withdrawn, and @@NQOPEN@@ open for the owner.")]:
    assert HOW.count(_a) == 1, _a
    HOW = HOW.replace(_a, _b)
assert DECISIONS_INTRO.count("so no owner question is open") == 2, 'decisions lead moved'
DECISIONS_INTRO = DECISIONS_INTRO.replace("so no owner question is open", "so no owner question was then open")
_D197 = "amending @@OD:87@@ and @@OD:12@@. "
assert DECISIONS_INTRO.count(_D197) == 1
DECISIONS_INTRO = DECISIONS_INTRO.replace(
    _D197, "amending @@OD:87@@ and @@OD:12@@; designing it raised two owner questions, Q-SDK-7, which @@OD:215@@ "
    "and @@OD:216@@ decide, and Q-BRIDGE-8, open below. ")
# The build's owner answers (2026-11-06 and 2026-11-10), numbered from 198 as the design-records tracks fold them.
_D198 = "decide, and Q-BRIDGE-8, open below. "
assert DECISIONS_INTRO.count(_D198) == 1
DECISIONS_INTRO = DECISIONS_INTRO.replace(
    _D198, _D198 + "From 2026-11-10 the design-records tracks number the owner's answers to the build's questions as "
    "they fold them: the nightly count's shard sums (198), Team subscriptions (199), the fold's leaf places (200), "
    "gkm's owner marker (201), forwarding reader keys at gkm (202), the orphan horizon (203), the drop job's "
    "horizon (204), amending @@OD:183@@, settings in rows (205), the sweep's triggers (206), a reported URL's "
    "path (207), the sealed abuse mailboxes (208), head readers' read records (209), the primary's physical "
    "copies (210), the key origin served direct (211), the compromise rebind's procedure (212), no apt or yum "
    "repository in v1 (213), the witness call outside the planes (214), forwarding's iOS executable budget and "
    "compile cap (215, 216), the key origin's per-network databases (217), multi-use bridge approvals (218), the key "
    "origin's sign-in hand-off (219), requested grants' sealed detail (220), promoted key-origin builds (221), "
    "wintun.dll left unbundled (222), the ur.io/recurd page (223) and C16's latch (224). ")
# Owner decision 204 amends 183's 25-minute fence for `now` drops, which its row notes as 176's does.
_i183 = [r[0] for r in INDEX].index(183)
assert INDEX[_i183][2].endswith("`now` skips the wait."), 183
INDEX[_i183] = (183, INDEX[_i183][1], INDEX[_i183][2] + " Amended by @@OD:204@@: a `now` drop's deletions wait "
                "for evacuation's horizon, about 25 to 26 h.")
