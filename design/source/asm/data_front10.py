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
(222), the ur.io/recurd page (223), C16's latch (224), the store's DELETE that names its object (225) and its
whole LIST (226), and the path-epoch rules of 227-233 (a fold's source deletes, a map's source below the window, the
crossing creation refused, the copy's map check, the root directory, a new ref's epoch, inline leaf places), key
path prefixes (234), format 1 reading past index_epoch (235), and git and evs both ways in 236-244 (imports as
bytes, history blobs, a push's sources, changeless parts, conflict branches, one import statement per push, an
import's helper refs, overlay directories and tag refs), and the owner items of 2026-11-06 for §11 in 245-250: the
tainted bit from M3, retention without the reclaim, compaction Later, the 2 GiB file cap, SHA-1 repos and working-tree
sync and derived shares Later. Adds owner decision 251 (2026-11-15): the operator-core seam, whose Env server/core
implements for the engines, amending 19, with operator-core in the branch policy's starts and merge order and in the
scope. Adds owner decisions 252-262 (folded 2026-11-16): how the published metadata list moves (252), smtp-2's proof
parts and smtp-7 (253), cert-1's chain, revocation reason and state time (254), evs-5's ttl while the dead-slot
delete is off (255), the evs rows' words for their wire fields (256), the segment clusters' PUT reports (257), the
file clusters' readiness object (258), api-14's sign-off ids (259), the tier cache key, an OAuth client's creator and
a domain's TXT challenge (260), enrollment's attempt histories (261) and BASE records in a config head's folds (262);
and the open owner question Q-REPO-6, which owner decision 213 asked for. Adds owner decisions 263-278 (folded
2026-11-16 with §4's items): the mlswg vectors (263), release promotion (264), cli/UI.md's copy (265), proving key
sets (266), the closed source graphs (267), what a Gn-out merges (268), C20 and strict_chain (269), minio's merge
place, which the branch policy takes with the tests repo (270), X11 (271), Go 1.27.4 (272), proto fences (273),
sidecarctl in server (274), the ios_extension leg's seed rule (275), the page Worker's Id, amending 251 (276),
gomobile's legs (277) and third_party/ at release (278). Adds owner decisions 279-301 (folded 2026-11-16 with §5's
and §6's items): SSHSIGs dropped (279), approved recipients (280), the safety number (281), service urls from the
host table (282), the readable-credential check by state (283), the keychain's auto-lock (284), AgentRevoke as a
local act (285), the bind re-mint's adoption (286), the events control method (287), the mail control methods (288),
the search cache's wrapped keys (289), host-held presence keys in remote mode (290), the admin_refused claim (291),
a compromise revocation's since_n (292), the git-hook hello mode (293), the served record's daily rows (294), the
unsigned minimum-version raise (295), same-network P2P behind a setting (296), settings objects for every limit
(297), the ur/ pair's key and the dialer's Service hold (298), late versions pages and retry waits (299), the
rollback head alarm (300) and companion contracts without a WindowDelegation (301)."""
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
    (225, "Store DELETEs",
     "The in-house MinIO build refuses a DELETE carrying `x-ur-if-unmodified-ms` 412, under the key's lock, when "
     "the object it finds was stored a second or more later, so orphan GC, the nightly pass and the sweep delete "
     "only what they listed."),
    (226, "Store LISTs",
     "The in-house MinIO build answers a LIST only when it is whole: it asks every online drive of each set and "
     "answers 503 while three or more of a set's drives are offline, or one while another heals."),
    (227, "Path epochs",
     "While sources stand, a fold deletes each source copy its pushes named once the current entry holds the change, "
     "and everything below a removed directory in them, so a source holds only what still has to move."),
    (228, "Path epochs",
     "A path map's source may be any version at or below the head in its current epoch, read from the window or its "
     "log page; evs checks the tail against the window's creations, and a part's 24 h age bounds staleness."),
    (229, "Path epochs",
     "evs refuses a creation in the push whose own commit would record a blocking due, 412 PATH_EPOCH_DUE, recorded, "
     "its refusal's fence write setting the head's due fields as the commit would have."),
    (230, "Path maps",
     "The path-epoch copy hashes a committed map's parts against the head's `map_sha256` and checks their order "
     "before moving anything, alarming on a mismatch; no replaying reader downloads a map."),
    (231, "The root",
     "The root is a directory whose token path is empty in every epoch, its entry at `idx/<repo>/<ref>/<p>.e`, read "
     "with no token; a path map holds its move first and the copy moves it last."),
    (232, "Path epochs",
     "A new ref starts in the newest path epoch its creator holds, 5e taking any p from 1 to the push's generation on "
     "a ref with no head; an overlay's first push takes its base ref's current epoch."),
    (233, "Path epochs",
     "The fold records an inline change list's leaf place too, leaf_index the change's index plus 1, so evs serves "
     "every committed version of an older epoch in one round, extending @@OD:200@@."),
    (234, "Key prefixes",
     "§11.8's \"no key prefixes another\" means a path prefix, an existing key followed by `/` or the reverse, so a "
     "KeyPackage's `.claim` stands beside it."),
    (235, "Format 1",
     "Format-1 code reads past a head's index_epoch, as past window bits 4 and 5, so a format-1 device keeps reading "
     "a ref's format-1 files after an erasure's CUT."),
    (236, "Imports",
     "An imported commit travels as its bytes, and a tree that does not rebuild from its entries as its bytes beside "
     "it (`EvsSealedCommit.trees`), so an import takes every history stock git can walk; only new commits meet the "
     "strict codec."),
    (237, "History blobs",
     "A blob a git-mode push's commits name and its net change does not travels as one sealed history record in a "
     "segment the push introduces (`EvsSealedBlob`); no GC takes a segment a retained push introduced."),
    (238, "Push sources",
     "A git-mode push names up to 16 committed versions of the repo's other git-mode refs as sources, replayed "
     "first, so @@OD:81@@'s committer rule judges only the commits it carries."),
    (239, "Push parts",
     "A part may hold no change when it holds a slice of a spilled section such as sealed metadata; such parts come "
     "last, carry no changes_root, and parts_sha256 covers them."),
    (240, "Conflict branches",
     "Only settle makes a conflict branch, `ur/<sidecar_id>/conflicts/<ref>/<time>`, an owned overlay of the "
     "conflicted ref that the queue publishes and only its owner removes; 64 on a ref stop its settling."),
    (241, "Imports",
     "An EvsImport signs the commits of the one push that carries it (its tip, the carried oids' hash and count), so "
     "each push of a split import verifies alone."),
    (242, "Imports",
     "A first-parent step too large for one push makes helper refs under `ur/<sidecar_id>/import/<id>/<n>`, imports "
     "the merged side there and carries the merge commit alone, naming them as sources."),
    (243, "Overlays",
     "An overlay holds a directory whole or not at all: its first push changing a directory's names writes the whole "
     "table, so an inherited path's removal stands and listings need no evs change."),
    (244, "Tag refs",
     "A tag ref holds no path state and has no base: its one push carries no change and names as sources the refs "
     "that reach its commit, so a tag of what a branch reaches uploads nothing."),
    (245, "Taint (I-9)",
     "From M3 a push bound to a tainted run sets format 1's reserved tainted bit in its sealed provenance, and readers "
     "read such a version as untrusted, tainting the run first; a push bound to no run carries none."),
    (246, "Retention",
     "Retention stays expiry, ERASE and BASE at M6; the reclaim of expired ciphertext moves to Later beside "
     "compaction, so it stays, keyless; a deposit's version is retained until a committed CONSUME."),
    (247, "Compaction",
     "Compaction moves to Later: erased and dropped inline ciphertext and packed segments stay stored and billed for "
     "the repo's life, unreadable once their keys are gone."),
    (248, "File cap",
     "A file is capped at 2 GiB of plaintext (512 chunks) through M10, versionless files and git-lfs objects "
     "included; a larger one is refused by name before the ref moves."),
    (249, "Git object format",
     "Repos use git's SHA-1 object format only in v0, the oid's width reserved; the local tier refuses a sha256 "
     "repository, naming it, before any evs write."),
    (250, "§11.22",
     "Working-tree sync and derived shares leave v1 for Later; git users update a working tree with stock git."),
    (251, "Q-REPO-1",
     "operator-core holds the core services' interfaces and server's shared value types; its Env creates every "
     "service instance an engine holds, server/core implements it, sidecar owns its SQL, and sidecar.Id aliases "
     "operator.Id on every leg."),
    (252, "The metadata list",
     "The published list is §2.8's block plus named owner additions made ahead of a fold, and a design-records fold "
     "adds the `planned` or evidence line that a new row or §4 id needs."),
    (253, "smtp-2, smtp-7",
     "smtp-2 lists a proof per part under a named key set, with the commitments the sidecar publishes, and smtp-7 "
     "what the key set path on ur.io sees of a prover host's fetch."),
    (254, "cert-1",
     "A certificate row keeps its issued chain, a requested revocation's reason and `state_time`, and goes 30 days "
     "after expiry, revocation or failure."),
    (255, "evs-5",
     "evs-5's ttl says a dead push's own slots stay until the repo is shredded while evacuation's delete of them is "
     "off, in the release that brings slot origins."),
    (256, "evs rows",
     "The evs rows gain words for wire fields their families already hold: the CONSUME mark, a repo's creator, key "
     "generations, read pins and states, purge marks and a `pidx/` record's batch place."),
    (257, "evs-10",
     "The hdd loop sums a segment cluster's PUT rate from each evs process's 5 s report in `{nvb_<cluster>}`, not "
     "from MinIO's request metrics."),
    (258, "evs-30",
     "Each file cluster's readiness object, `sentinel/_`, written once by xops and read with each block's own "
     "credentials, has its own row."),
    (259, "api-14",
     "api-14 names the legal and engineering sign-off ids that `legal_request` keeps, staff members' opaque ids as "
     "reviewer ids are."),
    (260, "api rows",
     "api-13 names the tier's Redis cache key, api-11 an OAuth client's creating member, kept for the client's "
     "life, and api-3 a verified domain's TXT challenge."),
    (261, "Enrollment limits",
     "`POST /network/enroll` is limited per auth key and per caller address hash through 10-minute Redis attempt "
     "histories, which api-11 shows."),
    (262, "Config folds",
     "A config head's fold records include the BASE entries, each with its Signed ProjectionHeader, so the log's "
     "chain through the fold follows from the genesis and the head."),
    (263, "mlswg vectors",
     "The mlswg's 16 MLS vector files stay committed in `testdata/mls/mlswg/`, though their repository carries no "
     "license; no history is rewritten and no test fetches them."),
    (264, "Release promotion",
     "A release is promoted, not every build signed: the two holders sign a chosen release's sums offline, and "
     "ur.io publishes them with `latest.json`, which `install.sh` reads."),
    (265, "cli/UI.md",
     "A copy of the `ur` command sketch goes to `sidecar/design/UI.md`, and its spellings replace the build's own."),
    (266, "Proving key sets",
     "A prover host downloads its key set on first send from a public path on ur.io, pinned by hash in the release; "
     "none ships in the `ur` package."),
    (267, "Closed source graphs",
     "server's competition takes sidecar as an eleventh repository through new producer releases, selected by "
     "`source_graph_policy`, and sn's release gates as a fourteenth, before the first merge to `main`."),
    (268, "Gn-out merges",
     "A Gn-out merges the commit set recorded at its gate, never the tip, and every Gn-out merge of connect waits "
     "for FS-125's sweep of C19 in connect's tests."),
    (269, "C20, `strict_chain`",
     "A new connect change, `DohCache.ForwardDnssec`, lets a device fetch and validate a custom MX host's DNSSEC "
     "chain itself, which `strict_chain` requires; the validator moves from M9 to M7."),
    (270, "minio's merges",
     "The minio fork joins the warp, config, vault, xops and mmm group in the merge order, and its `master` plays "
     "`main`."),
    (271, "X11",
     "X11 joins §4.7's allowed licenses, read as MIT's text plus only its no-advertising clause, so tlshacks needs "
     "no exception."),
    (272, "Go 1.27.4",
     "Every repo moves to go1.27.4 for GO-2026-6859, server's lock following by one authorized re-pin; the "
     "competition evaluator and the perf runner stay on go1.27.3 until re-qualified."),
    (273, "Proto fences",
     "A design-records fold that writes a field into a proto fence drops that field's line from protocol's fence "
     "additions in the same commit; a fence never moves ahead of the code."),
    (274, "`sidecarctl`",
     "The one binary for every operations command this build adds lives in server/sidecarctl, where it may link "
     "server's model and the engines."),
    (275, "`ios_extension` leg",
     "The leg's seed rule stands: a file it takes wrongly is renamed and a declaration its closure needs is moved, "
     "never the rule narrowed or a tag dropped."),
    (276, "`Id` on the page Worker",
     "Amends @@OD:251@@: on the page Worker's leg `sidecar.Id` stays a twin of `operator.Id`, so the leg links no "
     "connect; `operator.Id`'s JSON decode refuses what either id refused."),
    (277, "gomobile legs",
     "§4.7's legs are sdk's table, which lists every target gomobile binds, 32-bit android/arm, the simulator and "
     "macos/amd64 among them, with gomobile's tags."),
    (278, "Release, `third_party/`",
     "The release step keeps `third_party/`, the go-smtp fork and the mox subset, at the repository's top beside "
     "`v2026/`, so every replace still resolves."),
    (279, "SSHSIGs dropped",
     "No decision needs an SSHSIG, in v0 and every milestone until a customer asks: the field stays reserved and "
     "ignored, and every action's risk stays normal."),
    (280, "Approved recipients",
     "An approved recipient is a (sending alias, recipient) pair with a `rcpt/` record in the repo that holds the "
     "alias's mail, re-verified at each use and ignored in a tainted run."),
    (281, "Safety number",
     "60 decimal digits of SHA-256 over the genesis's hash and the device's identity key, shown as 12 groups of 5."),
    (282, "Service urls",
     "`DefaultSidecarSettings` leaves the service urls empty, and hosts fill them from §18.9's embedded host table, "
     "the one copy of those names."),
    (283, "Readable credentials",
     "`ur` refuses to enroll, and an enrolled daemon alarms, beside a readable network credential by the host's "
     "state, whatever the stage; no signal turns the check off."),
    (284, "Auto-lock",
     "The keychain locks after 10 minutes with no request on any local socket, never while the daemon is busy; "
     "zero never locks."),
    (285, "`AgentRevoke`",
     "A local act, not a record: the subkey is deleted, readers bound it by its certificate's 30 days, and a "
     "compromised daemon is a `SidecarRevoke`."),
    (286, "Bind's re-minted token",
     "The sidecar adopts the `by_client_jwt` that `POST /sidecar/bind` re-mints with its `sidecar_id`, and sdk's "
     "host session takes it, so the claim survives refreshes."),
    (287, "Control `events`",
     "A remote-mode Sidecar hears every event kind by long-polling a control method `events` over a bounded ring, "
     "a gap sending it to `GetState`."),
    (288, "Mail control methods",
     "§5.8 gains `mail.check_send` and `mail.send_result`, plain reads, and `mail.send`, which goes through the "
     "daemon's gate."),
    (289, "Search cache keys",
     "The search cache keeps each kept record's wrapped object key, in slot-keyed repos the slot's block, and an "
     "ERASE hint drops every kept record whose slot key it destroys."),
    (290, "Host-held presence",
     "A remote-mode app's act runs the daemon host's own presence prompt when that host's authenticator holds "
     "every live presence key."),
    (291, "`admin_refused` claim",
     "The by_jwt carries an `admin_refused` claim, and `Pair` requires it with `strict_exp`; until it lands, "
     "`strict_exp` alone stands and the app checks its own mint."),
    (292, "Compromise `since_n`",
     "A compromise revocation proposes the tip when no entry is timed at or after the loss, and answers "
     "REVOKE_SINCE given neither a loss time nor a position."),
    (293, "`git-hook` mode",
     "§5.8's hello gains a fifth mode that relays a mount's pre-receive and proc-receive hooks to the daemon; a "
     "protocol, never a privilege."),
    (294, "Served record",
     "An owner's indexer keeps one row per requester, repo and UTC day, with a count and first and last times, "
     "for 30 days; `Search.ServedRecordCount` is a last bound."),
    (295, "Minimum-version raise",
     "An unsigned raise of the minimum secure version is a live denial a device bounds by its own compiled "
     "version and never persists."),
    (296, "Same-network P2P",
     "Built at M6 behind `SidecarProtocolSettings.EnablePeerP2p`, default off; relay-only stays until a later "
     "owner call."),
    (297, "Settings objects",
     "Every limit, protocol and format limits included, is a field of a settings object; only identifiers stay "
     "constants, and legacy constants move when the function that reads them is edited."),
    (298, "`ur/` pairs and Service",
     "A Service pair is keyed by its non-edge end in every namespace, and a sidecar dialing a `ur/` name holds "
     "Service while its `ur/` stream lives."),
    (299, "Late pages, retry waits",
     "A `versions` page that arrives late takes only its rises, and a reconnect ends a failed refetch's retry "
     "wait at once."),
    (300, "`rollback` alarm",
     "A push reset that lowers a durable topic raises `head_alarm` with a fifth kind, `rollback`, its evidence "
     "the held and offered versions."),
    (301, "Companion contracts",
     "A companion contract inherits its forward contract's subject, source network and class and seals no "
     "`WindowDelegation`."),
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
         "only while open."),
        # Owner decision 251 amends 19's: the host interfaces move to operator-core, and sidecar owns its SQL.
        (19, "owns migrations and routes, and hosts each engine.",
         " Amended by @@OD:251@@: the interfaces are operator-core's, rooted at its Env, which server/core implements; "
         "sidecar owns its SQL and migrations, which server/core runs."),
        # Owner decision 276 amends 251's alias for the page Worker's leg.
        (251, "operator.Id on every leg.",
         " Amended by @@OD:276@@: the page Worker's leg keeps a twin of it and links no connect.")]:
    _i = [r[0] for r in INDEX].index(_n)
    assert INDEX[_i][2].endswith(_old_end), _n
    INDEX[_i] = (_n, INDEX[_i][1], INDEX[_i][2] + _note)
assert [r[0] for r in INDEX] == list(range(1, 302))
DATES = dict(_P9['DATES'])
DATES.update({185: '2026-11-05', 186: '2026-11-05', 187: '2026-11-05', 188: '2026-11-06', 189: '2026-11-06',
              190: '2026-11-06', 191: '2026-11-06', 192: '2026-11-06', 193: '2026-11-06',
              194: '2026-11-06', 195: '2026-11-06', 196: '2026-11-06', 197: '2026-11-09',
              198: '2026-11-10', 199: '2026-11-10', 200: '2026-11-10', 201: '2026-11-10', 202: '2026-11-10',
              203: '2026-11-10', 204: '2026-11-10', 205: '2026-11-10', 206: '2026-11-10', 207: '2026-11-06',
              208: '2026-11-06', 209: '2026-11-06', 210: '2026-11-06', 211: '2026-11-06', 212: '2026-11-06',
              213: '2026-11-06', 214: '2026-11-06', 215: '2026-11-10', 216: '2026-11-10', 217: '2026-11-10',
              218: '2026-11-10', 219: '2026-11-06', 220: '2026-11-06', 221: '2026-11-06', 222: '2026-11-06',
              223: '2026-11-06', 224: '2026-11-06', 225: '2026-11-10', 226: '2026-11-10', 227: '2026-11-10',
              228: '2026-11-10', 229: '2026-11-10', 230: '2026-11-10', 231: '2026-11-10', 232: '2026-11-10',
              233: '2026-11-10', 234: '2026-11-10', 235: '2026-11-10', 236: '2026-11-10', 237: '2026-11-10',
              238: '2026-11-10', 239: '2026-11-10', 240: '2026-11-10', 241: '2026-11-10', 242: '2026-11-10',
              243: '2026-11-10', 244: '2026-11-10', 245: '2026-11-06', 246: '2026-11-06', 247: '2026-11-06',
              248: '2026-11-06', 249: '2026-11-06', 250: '2026-11-06', 251: '2026-11-15',
              252: '2026-11-15', 253: '2026-11-11', 254: '2026-11-12', 255: '2026-11-15', 256: '2026-11-15',
              257: '2026-11-15', 258: '2026-11-15', 259: '2026-11-15', 260: '2026-11-15', 261: '2026-11-15',
              262: '2026-11-10',
              263: '2026-11-06', 264: '2026-11-06', 265: '2026-11-06', 266: '2026-11-06', 267: '2026-11-15',
              268: '2026-11-15', 269: '2026-11-06', 270: '2026-11-06', 271: '2026-11-06', 272: '2026-11-11',
              273: '2026-11-11', 274: '2026-11-12', 275: '2026-11-15', 276: '2026-11-15', 277: '2026-11-15',
              278: '2026-11-15',
              279: '2026-11-06', 280: '2026-11-06', 281: '2026-11-06', 282: '2026-11-06', 283: '2026-11-06',
              284: '2026-11-06', 285: '2026-11-06', 286: '2026-11-13', 287: '2026-11-14', 288: '2026-11-15',
              289: '2026-11-15', 290: '2026-11-15', 291: '2026-11-15', 292: '2026-11-15', 293: '2026-11-15',
              294: '2026-11-15', 295: '2026-11-06', 296: '2026-11-06', 297: '2026-11-15', 298: '2026-11-15',
              299: '2026-11-15', 300: '2026-11-15', 301: '2026-11-15'})
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

# Owner decision 251 (2026-11-15): operator-core, a repo of its own between connect and sidecar, holds the core
# services' interfaces, so the branch policy names its branch and merge place and the scope covers it (§4.4, §4.8).
for _a, _b in [("and vault, and the `urnetwork/minio` fork (@@OD:195@@).",
                "and vault, and the `urnetwork/minio` fork (@@OD:195@@); operator-core's opened later, with its seam "
                "(@@OD:251@@)."),
               ("in the order connect, sidecar, sdk, sn, server,", "in the order connect, operator-core, sidecar, sdk, sn, server,"),
               # Owner decision 270: minio merges with the ops group, its master playing main; the tests repo's
               # branch follows build (§4.8).
               ("warp/config/vault/xops/mmm, build, re-pinning",
                "warp/config/vault/xops/mmm/minio, build, tests, re-pinning"),
               ("operator-core's opened later, with its seam (@@OD:251@@).",
                "operator-core's opened later, with its seam (@@OD:251@@), and the tests repo's, opened locally for "
                "its fixtures. In minio, `master` plays `main` (@@OD:270@@).")]:
    assert BRANCH.count(_a) == 1, _a
    BRANCH = BRANCH.replace(_a, _b)
_SC251 = "`sdk/sidecar.go`; the changes these need"
assert SCOPE.count(_SC251) == 1, 'scope text moved'
SCOPE = SCOPE.replace(_SC251, "`sdk/sidecar.go`; operator-core, the module of core-service interfaces and shared value types "
                      "that server and sidecar import (@@OD:251@@); the changes these need")

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
# 216 (2026-11-10) decide Q-SDK-7, so of those two Q-BRIDGE-8 stays open. Owner decision 213 (accepted 2026-11-06)
# asked for a Q- item on Linux updates, Q-REPO-6, which joined them on 2026-11-16 with its evidence line in check/
# (owner decision 252).
_OPEN_OLD = "None. Every Q- item whose decider was the owner is decided. "
assert OPEN_INTRO.count(_OPEN_OLD) == 1, 'open-questions lead moved'
OPEN_INTRO = OPEN_INTRO.replace(
    _OPEN_OLD,
    "Two: Q-BRIDGE-8 (an app device's overlay address), raised on 2026-11-09 in designing owner decision 197's "
    "forwarding, and Q-REPO-6 (how Linux users update without apt or yum), which owner decision 213 asked for. The "
    "sections are written to each recommendation, marked \"(proposed; Q-...)\". The other raised with owner "
    "decision 197, Q-SDK-7 (forwarding's budget in the iOS network extension), was decided on 2026-11-10 "
    "(@@OD:215@@, @@OD:216@@). Every other Q- item whose decider was the owner is decided. ")
OPEN_OWNER = [
    ("Q-BRIDGE-8", "Does an app device claim its overlay address when its forwarding is set up (owner decision 197)?",
     "(a) on demand, as §17.4 says: the app's UI, the host's first map or an admin; (b) at forwarding's setup, its "
     "sidecar filing its own `BridgeAddress`",
     "(a): with no ACL document a hosted address opens the device's loopback to the network's untagged sidecars "
     "(owner decision 120), and (b) can follow by one filing",
     "nothing before M8's app hosts", "M8"),
    ("Q-REPO-6", "How do Linux users update `ur`, now that v1 ships no apt or yum repository (owner decision 213)?",
     "(a) re-run `install.sh`'s verified path or fetch the next `.deb` or `.rpm`; (b) apt and yum repositories "
     "later, signed by a second offline two-person GPG key; (c) a self-updater checking the signed `SHA256SUMS`",
     "(a) for v1, the owner deciding at v1's exit review whether Linux users need (b)",
     "nothing before v1's channels", "M6"),
]
for _a, _b in [("[open owner questions](#open-owner-questions) (none remain)",
                "[open owner questions](#open-owner-questions) (@@NQOWNWORD@@, raised with owner decisions 197 "
                "and 213)"),
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
    "wintun.dll left unbundled (222), the ur.io/recurd page (223), C16's latch (224), the store's DELETE that "
    "names its object (225) and its whole LIST (226), a fold's source deletes (227), a map's source below the "
    "window (228), the crossing creation refused (229), the copy's map check (230), the root directory (231), a new "
    "ref's epoch (232), inline leaf places (233), extending @@OD:200@@, key path prefixes (234), format 1 reading "
    "past index_epoch (235), imports as bytes (236), history blobs (237), a push's sources (238), changeless parts "
    "(239), conflict branches (240), one import statement per push (241), an import's helper refs (242), overlay "
    "directories (243), tag refs (244), the tainted bit from M3 (245), retention without the reclaim (246), "
    "compaction Later (247), the 2 GiB file cap (248), SHA-1 repos (249) and working-tree sync and derived shares "
    "Later (250). On 2026-11-15 the owner put the core services' interfaces and server's shared value types in a new "
    "operator-core module, whose `Env` creates every service instance a hosted engine holds and server/core "
    "implements, with sidecar owning its SQL (251), amending @@OD:19@@. On 2026-11-16 the owner accepted the "
    "build's recommended decisions going forward and asked that they be recorded here; the fold of §2's that day "
    "numbers how the published metadata list moves (252), smtp-2's proof parts and smtp-7 (253), cert-1's chain, "
    "revocation reason and state time (254), evs-5's ttl while the dead-slot delete is off (255), the evs rows' "
    "words for their wire fields (256), the segment clusters' PUT reports (257), the file clusters' readiness "
    "object (258), api-14's sign-off ids (259), the tier cache key, an OAuth client's creator and a domain's TXT "
    "challenge (260), enrollment's attempt histories (261) and BASE records in a config head's folds (262), and "
    "adds the Q- item @@OD:213@@ asked for, Q-REPO-6, open below. The fold of §4's the same day numbers the "
    "repository's and the build's answers: the mlswg's vector files committed (263), releases promoted, not each "
    "build signed (264), a copy of cli/UI.md in the repository (265), proving key sets fetched from ur.io (266), "
    "the competition's and sn's source graphs taking sidecar (267), what a Gn-out merges (268), connect's C20 for "
    "`strict_chain` (269), minio's place in the merge order (270), X11 (271), Go 1.27.4 (272), how a proto fence "
    "takes a field (273), `sidecarctl` in server (274), the `ios_extension` leg's seed rule (275), the page "
    "Worker's own `Id`, amending 251 (276), gomobile's legs (277) and `third_party/` at release (278). The fold "
    "of §5's and §6's the same day numbers the core's and the subprotocol's answers: SSHSIGs dropped until a "
    "customer asks (279), approved recipients (280), the safety number (281), service urls from the host table "
    "(282), the readable-credential check by state (283), the keychain's auto-lock (284), `AgentRevoke` as a "
    "local act (285), the bind re-mint's adoption (286), the `events` control method (287), the mail control "
    "methods (288), the search cache's wrapped keys (289), host-held presence keys in remote mode (290), the "
    "`admin_refused` claim (291), a compromise revocation's `since_n` (292), the `git-hook` hello mode (293), the "
    "served record's daily rows (294), the unsigned minimum-version raise (295), same-network P2P behind a "
    "setting (296), settings objects for every limit (297), the `ur/` pair's key and the dialer's Service hold "
    "(298), late versions pages and retry waits (299), the `rollback` head alarm (300) and companion contracts "
    "without a `WindowDelegation` (301). ")
# Owner decision 204 amends 183's 25-minute fence for `now` drops, which its row notes as 176's does.
_i183 = [r[0] for r in INDEX].index(183)
assert INDEX[_i183][2].endswith("`now` skips the wait."), 183
INDEX[_i183] = (183, INDEX[_i183][1], INDEX[_i183][2] + " Amended by @@OD:204@@: a `now` drop's deletions wait "
                "for evacuation's horizon, about 25 to 26 h.")
