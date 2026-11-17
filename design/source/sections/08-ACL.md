## 8. Access control: policy, compilation, distribution, enforcement

### 8.1 Purpose and scope

This section owns the access-control model and its evaluation; X3, the customer key authority (owner decisions 3, 5-8, 110, 126); policy rows in the signed projection, grant chains and repo access logs; gate caches; enforcement points; and evs readers, with data repos' leaf seats (owner decisions 114, 144, 182). §7 owns the config repo's records, the authorization log and its read cache, the config and directory groups' `leaves` rule, members, roles, tokens and removal; §10 MLS; §11 repo kinds and drops; §16.11 the team directory; §17 bridge rules.

### 8.2 Requirements

| id | requirement | source |
|---|---|---|
| R-ACL-1 | Specify which clients, groups and networks reach a client, group, network or abstract socket | PLAN.md:74 |
| R-ACL-2 | Rules stored on the server; each client gets its rules in real time and decides locally | PLAN.md:119 |
| R-ACL-3 | One deny-by-default HuJSON policy with tags, groups, autogroups and tests; default `tag:recurd` → `autogroup:self` tcp:443 | team-management.html:813-929 |
| R-ACL-4 | Every reach grant names an approver and an expiry; one switch revokes an agent's forwards, addresses, names and mail | pitch5.html:680,729 |
| R-ACL-5 | With a policy, agents reach only granted ranges; public names authenticated by default, short-lived | pitch5.html:689,698; owner decision 120 |
| R-ACL-6 | Invite an external network to forward in; accept an invite | cli/UI.md:50-51 |
| R-ACL-7 | A breached server cannot add a reader | pitch5.html:745; team-management.html:940 |
| R-ACL-8 | No added query for networks without the feature; no PostgreSQL per packet | server/model/subscription_model.go:1727-1730; connect/CODESTYLE.md:106-107 |
| R-ACL-9 | The ACL decides evs readers, which clients verify; app devices, and untagged sidecars until a policy exists, keep today's reach | derived; owner decisions 105, 120 |
| R-ACL-10 | Tests, change audit, rollback, propagation target | team-management.html:907-929,1021-1029 |
| R-ACL-11 | Session contents stay with their author unless shared, while in a team network a run's who, what and where reach teammates by default; admins read actions, not transcripts | pitch5.html:579,640; owner decisions 126, 170 |
| R-ACL-12 | Admin keys sign policy from v0; a breached server can only deny or delay (§2.8's bound), and sees policy only as ids | owner decisions 3, 5, 72 |

### 8.3 What exists today

- No group, tag or policy table exists [R:server-identity].
- `GetProvideRelationshipDetails` returns Network iff both clients share a `network_id`, else Public, in one query (`server/model/network_client_model.go:2528-2606`). `CreateContract` resolves it at `server/controller/connect_controller.go:859`, picks the mode at `:933`, and settles companion requests as Network without an origin check (`:917-927`). A provider's reply to a Network source is not one: connect asks for it as a plain non-companion contract in the reply direction (`connect/ip.go:9393-9411`), and the subprotocol's query replies use the same helpers, so the request alone cannot tell a reply from a new dial (8.10's contract rule).
- FriendsAndFamily (`connect/protocol/transfer.proto:357`) escrows nothing (`connect_controller.go:1296`) and is never computed.
- Providers allow Network sources every destination, LAN and loopback included (`connect/ip_security.go:567`); other modes get public-only rules (`:385-390`).
- Contracts expire within 60 min (`server/model/subscription_contract_expiration.go:14`), and the contract-hole projection, a Redis pair lease, gates forwarding (`connect/CODESTYLE.md:107-110`).

### 8.4 Model

**Subjects** are sidecars (`sidecar_id`, mapped to the current client through §5's binding) and other clients (`client_id`: app devices, legacy clients); untagged children such as sdk window clients act as their nearest subject ancestor (D-ACL-3), so a sidecar's forwarding client and its window clients act as that sidecar, their tokens confined by `forward_only` (§7.4, §18.6; owner decision 197). Before expansion each is classed as a member device (untagged, not ephemeral), an ephemeral sidecar, a tagged sidecar or another client (D-ACL-19). Autogroups follow the class (owner decision 355): `autogroup:member` is the untagged sidecars, ephemeral ones included, which take reach from rules naming it while 8.6's ceiling alone limits their evs access; `autogroup:owner`, `autogroup:admin` and `autogroup:auditor` are the untagged subjects of members whose role is Owner, Owner or Admin, and Auditor, Network and IT admins being in none of them; app devices are in `autogroup:untagged` only, never `autogroup:member` (D-ACL-20's two disjoint sets); and a tagged subject takes no role autogroup. An untagged subject's atoms are its owner's user, groups and role, and its autogroups; an ephemeral subject's evs access is capped as 8.6 says; a tagged subject has no user atoms, and its §7 *sponsor* stands in: the admitting member or the one an admin's `SponsorSet` names, else `autogroup:admin` once that sponsor is removed (owner decision 83). In-daemon agents share their sidecar's grants, which the daemon may narrow (owner decision 4, §5.5).

```text
selector (src or dst unless noted)   meaning
user:<email>, group:<name>           untagged subjects
tag:<name>                           via tagOwners
sidecar:<id>                         across client generations
client:<id>                          resolved through §5's binding
role:, principal:                    Embed networks
autogroup:member|owner|admin|auditor|sidecar|tagged|network
autogroup:untagged                   untagged non-sidecars; untagged sidecars are in autogroup:member
autogroup:ephemeral                  src: untagged ephemeral sidecars
network:<net>                        as that network permits (§8.11)
autogroup:public                     src: anonymous tlsedge clients
autogroup:internet                   dst: public destinations via an exit
autogroup:self                       dst: subjects sharing the source's owner or sponsor; approver: the requester's
autogroup:sponsor                    approver
autogroup:dst-owner                  approver: the destination subject's owner, or a tagged sidecar's sponsor; for a
                                     socket, its listeners' owner or sponsor where all are one; otherwise
                                     autogroup:admin (owner decision 180); acl.proto fixes its atom at M2, when the
                                     implicit document names it (8.5); Team documents name it from M6

resource                             actions; notes (* matches within a label or segment, a bare * all of a kind)
a subject, optional ip ports         dial; its addresses too (§17)
sock:<name>                          dial, listen; this network's sockets only (others reach a listener by IP, §8.11);
                                     rows carry application names as §9.4's token paths under K_sock
                                     (owner decision 67), tls/ and smtp/ names in clear; services authorize ur/ names
ip:<cidr>, ports, via subjects       route; 0.0.0.0/0 excludes loopback and link-local
evs:<repo>                           read, write (implies read), admin (lifecycle, drops), deposit; an id or config
                                     label, never a path (X2)
dns:<host>, sock, audience,          publish, admin (zone records); <host> is @, one label or, in a v1 Team
  app_mode, link_spki_sha256         scope, <host>.<scope> (dns:*.<scope> covers one scope; Q-TLS-3); audience:
                                     members (default), members-device, link or public (owner decision 42);
                                     app_mode: http (default), or raw only under public or link, a raw link's
                                     grant pinning its client certificate's SPKI SHA-256 (§13.7)
mail:<alias>                         send, listen; checked only by clients
* (as a dst)                         any subject, application socket, ip range (exits included) or general or
                                     record repo here; outward resources (tls/ and smtp/ sockets, dns:, mail:,
                                     other networks) and §8.5's kinds must be named
```

acl.proto numbers `AclAutogroup` and `AclAction` from 1 in the order the lists above write them, 0 being unspecified (§7.9's record bytes).

**Readings.** `ParseAclPolicy` runs on every reader, so what it accepts is a format. A last segment that is exactly `*` takes every name below its prefix, at least one segment deeper, so `sock:tls/*` reaches `tls/443/blog`; this is the one place "within a label or segment" is read against its letter, and any other `*` stays inside its segment, a `tls/` or `smtp/` name's or a dns host's glob kept as written in rows (`*-preview`; 8.8's `public_name`). A bare `*` dst, `sock:*` and a glob in the first segment reach application sockets and `share/` only, never `tls/`, `smtp/` or §9.4's other reserved first segments, or the implicit document's self-approved tagged rule would reach the `tls/` names its admin-approved rule holds. `admin` on a repo implies write and read of it, within 8.6's ceiling, a read_only sidecar still getting only read; a policy grant of `admin` therefore adds a key holder, which the preview names as a reader. As an approver, `autogroup:dst-owner` reads a socket's listeners as the subjects holding `listen` on it in the state at the statement's position, never live registrations: one owner or sponsor across them names that one, otherwise `autogroup:admin`; over an atom target it expands to every standing sidecar holding the atom. `autogroup:self` of a legacy client, or of a tagged sidecar whose sponsor is gone, resolves to `autogroup:admin`, as `autogroup:sponsor` does for an untagged requester (owner decision 355). A source holds at most 4 MiB, 8.8's rows bound, and nests at most 4 deep, the schema's real depth; both are format constants, and the nesting bound runs before `encoding/json`, which recurses per level.

### 8.5 Policy document and worked examples

The policy is HuJSON in the config repo, parsed in-repo: `aclStandardizeHujson` (sidecar/acl_hujson.go) turns `//` and `/* */` comments and trailing commas into spaces, keeping byte offsets, refuses invalid UTF-8 and hands the result to `encoding/json`, on every leg, with no new module and no dependencies.yml row; a change to it counts as a format change, since every reader must parse one source alike, and §22.6's compiler fuzz target covers it. Beyond the example it has `hosts`, with Tailscale's meaning: a name for an address or CIDR, used as `ip:<name>` and resolved at parse, so an unknown name is refused; grant fields `id`, `via`, `sock`, `audience`, `app_mode`, `link_spki_sha256` (8.4) and `note`; an `approvers` count on `requests`, which subjects or a team directory request (§16.11) file, a harness `reach:` block (recurd-app.html:1743-1749) filing none until a later design (§16.7; owner decision 452); and document-level `expiresDefault` (1 h) and `evidenceDefault` (all §16.6 channels; harness only in untainted runs unless a rule names it, owner decision 142, §16.6). A `requests` rule refuses `ip`, `via`, `sock`, `audience`, `app_mode`, `link_spki_sha256` and `expires`: a rule names who may ask and who answers, and the filed request names ports, audience and expiry, so a Team narrows a rule through `dst`, `src` and `evidence`.

```hujson
{
  "groups":    { "group:eng": ["dana@acme.com", "amir@acme.com"] },
  "tagOwners": { "tag:recurd": ["group:eng"], "tag:db": ["autogroup:admin"],
                 "tag:api": ["autogroup:admin"], "tag:audit": ["autogroup:admin"] },
  "grants": [
    { "src": ["autogroup:untagged"], "dst": ["autogroup:self"], "allow": ["dial", "route"] }, // 1 laptop→phone
    { "src": ["tag:recurd"], "dst": ["evs:repo-x"], "allow": ["write"] },                     // 2
    { "src": ["group:eng"], "dst": ["sock:db"], "allow": ["dial"] },                          // 3
    { "src": ["tag:db"],    "dst": ["sock:db"], "allow": ["listen"] },
    { "src": ["network:partner-y"], "dst": ["tag:api"], "allow": ["dial"], "ip": ["tcp:443"], // 4 share over §17's
      "expires": "2026-12-31T00:00:00Z" },                                                  // IP path (owner decision 86)
    { "src": ["tag:recurd"], "dst": ["autogroup:self"], "allow": ["dial"], "ip": ["tcp:443"] },
  ],
  "requests": [ // 5: ur bridge public-tls app-preview:3000 publishes app-preview.<net>.<root> for up to
                //    24 h, approved from a device or presence key, never a harness prompt
    { "src": ["tag:recurd"], "dst": ["dns:*-preview", "sock:tls/443/*-preview"], "allow": ["publish", "listen"],
      "approver": ["autogroup:sponsor"], "maxExpiry": "24h", "evidence": ["device", "presence"] },
  ],
  "audit": { "reader": "tag:audit", "repos": ["kind:team_record", "kind:vault", "kind:mailbox"] }, // 6 Team
  "tests": [ { "src": "dana@acme.com", "accept": ["sock:db#dial"], "deny": ["evs:secrets#read"] } ],
}
```

**Grant 1 (owner decision 344).** Grant 1, and Team's starting document (`acl_team_start.hujson`) with it, reads `{ "src": ["autogroup:member", "autogroup:untagged"], "dst": ["autogroup:self"], "via": ["autogroup:self"], "allow": ["dial", "route"] }`. D-ACL-20 narrowed `autogroup:untagged` to non-sidecars, so the source names `autogroup:member` beside it, and a member's own sidecars and app devices reach each other; a rule's via subjects no longer share its targets (8.8), so `via` names `autogroup:self` and a member's devices also reach the prefixes their own devices' approved routes serve. FS-21's Team case uses peers of two members, since a member's own devices reach each other. The block above keeps its line 1 as first written until the root package's fixture of this example, which a test holds to the block byte for byte, moves with it.

**Kind defaults** come ahead of every document, evaluated in the binary from `AclRepo` rows and the state and never compiled into rules, so an admission between bases reads at once (owner decision 355); `*` never matches these kinds, which §11.12 fixes at creation. Rules add nothing to config, directory or secret repos, add only deposit to vault and mailbox, and add readers only to the last two, as to general and record repos:

| kind | read (and write where noted) | deposit |
|---|---|---|
| `config` (§7.9) | every admitted sidecar; heads from config writers (§8.8), each of which holds `admin` on it at evs and gkm, the Genesis's owner sidecar from base 1 being the first case (owner decision 352); its evs `rw` goes to config writers and its gkm `rw` to member devices that are not read_only | — |
| `directory` (one per team network, §16.11; owner decision 171) | every admitted sidecar of the team; every one that is not read_only writes only its own paths and stream, and a device KF2 parks for consent writes nothing that counts (I-EVS-14); documents neither add nor remove readers (D-ACL-24) | — |
| `vault`, `mailbox`, `secret` (owner-bound to member M; group inboxes stay general; each `secret` holds one secret, such as §13.8's ACME account key or §17.9's ShareKey, and §16.6 refuses `secret` repos to MCP's evs tools) | M's consented devices (below), which also write; their `EvsShare`s' subjects (§8.8); the `audit` reader where its block names the kind or repo | receipts from readers that do not write (§16.8); in `vault` and `mailbox` also M's other untagged subjects, the tagged subjects M sponsors, `tag:mail` mail indexers (owner decision 150); in `mailbox` also any subject of the network that the projection marks `mail_send`, for §15.8's same-network mail (D-MAIL-8; owner decision 333) |
| Team record | `autogroup:admin`, `:auditor`; no row 8.6's ceiling counts, so an ephemeral sidecar only deposits there | `autogroup:member`, tagged subjects |
| `mailcfg` | `tag:mail` mail indexers; members write the records they sign (§15.8): its writers are member devices, or, where its row names an owner (a Team scope's member), that member's consented devices | — |

A group inbox stays a `general` repo, marked at its creation: `RepoCreate`'s `inbox` is `group`, or `admin` for the network's admin address (8.8). Rotators set a marked repo's drop key as they do for a kind that takes deposits (§10.5, D-KEYS-17), and writers use §11.6's per-message slot rule for it. `ur id group-create` files its deposit grant beside the marker (§15.7); an untagged receiver in a network with no document already reaches its deposit ref through the implicit document's `autogroup:member` write on `evs:*` (§15.7). A member's deposit into another member's mailbox is bounded by §20's storage limits, and the recipient's readers show it as from a member by the push's signer; `vault` and `secret` take no such deposit, and 8.8's "never in an owner-bound repo" stands for `RepoGrant`.

**Owner consent (owner decision 126).** One admin's signature admits a device under member M (owner decision 110), but in M's owner-bound repos admins only revoke or add the audit reader; there a later `EvsShare` to the same subject from M's consented device lifts a config writer's standing `RepoRevoke`, and a `RepoRevoke` naming one of M's consented devices is refused, since `SidecarRevoke` and `Suspend` already remove a device (owner decision 332; 8.8). One predicate, which §5.6 and §7.9 cite, names M's consented devices (D-ACL-22):

```text
consented(d, M) = d's admission names member M, d is neither ephemeral nor parked by §7.9's compromise
  cascade, and one of these holds on a signature by neither a sidecar then in that cascade's set P nor a
  recovery key whose binding one signed:
  scoped     M's consented device or M's recovery key signed d's SidecarAdmit, alone or as one of k
             (§7.9, owner decision 112)
  invited    d's SidecarAdmit carries SIDECAR_CAPABILITY_INVITED, which the admitting device sets only after
             the join MAC of an invite addressed to M verifies (§7.5's invite block): §7.5's member invite,
             or the invite an admin device issues when it admits a JIT-pending member (§7.6), neither of
             which an ephemeral enrollment redeems; and d is the first admission under M in log order,
             revoked ones included, that is neither ephemeral nor read_only; a later device's bit counts for
             nothing, and readers ignore it on an ephemeral or read_only admission
  genesis    d signed the network's Genesis (the owner's first device)
  confirmed  M's consented device signed OwnerConfirm{d} (§8.8), as after an admin's admission, or the
             AdmissionConfirm{d} that lifted d's park (§7.9)
```

A signer counts for consent only if it was consented for the same member strictly before the position it signed at and the cascade does not void it there; M's recovery key is the binding in force at the admission's position; an `AdmissionConfirm` by M's consented device counts whether or not it lifted a park; a revoked device is not consented now, while what it signed before stands; and the invited clause also needs one admission signer outside every cascade (owner decision 355). Members and grantor leaves refuse other Adds and wraps there, and KF2 parks d (§10.7, §10.9). A device whose consent rested on what P signed regains M's owner-bound repos only by an `OwnerConfirm` or `AdmissionConfirm` from M's consented device outside P; an admin's `AdmissionConfirm` restores only its other access (§7.9). M's devices alarm on any admission under M that M's keys did not sign and offer to confirm it (`approval_pending`; §5.4, §18.5). Only consented devices that are not read-only (§7.9) sign M's `EvsShare`s, `OwnerConfirm`s, `RecoveryBind`s, owner-bound `RepoAdmin` adds, and DROP pushes and their cancels in M's owner-bound repos (§11.7), so admins neither drop nor cancel drops there (owner decisions 173, 183).

**Audit reader (owner decision 63; Team, v1).** Example 6's `audit` block counts only while a k-of-n `AuditOptIn` (§8.8) exists, and members see that reader in each affected reader list before it gets a key (§10.8).

The **implicit document**, versioned in the sidecar repo, serves Community and Pro networks without one; writers compile it into the projection's rules whenever `has_document` is false, so gates and clients evaluate the same rows (D-ACL-20). Team starts from grant 1, the `tag:recurd` default and the implicit document's last rule, the team directory's reach requests (D-ACL-23), which its document may narrow, give two approvers or remove (owner decision 74); the implicit document carries that rule from its M2 version, so readers of every version compile the same rows.

```hujson
{ "grants": [  // owner decision 105: untagged sidecars (autogroup:member) and app devices
               // (autogroup:untagged) keep today's reach, and providers keep allow-all LAN and
               // loopback, disclosed (owner decisions 50, 120)
    { "src": ["autogroup:member", "autogroup:untagged"], "dst": ["*"], "allow": ["*"] },
    { "src": ["autogroup:member"], "dst": ["evs:*"], "allow": ["write", "admin"] },
    { "src": ["autogroup:tagged"], "dst": ["evs:*"], "allow": ["deposit"] },
    { "src": ["autogroup:tagged"], "dst": ["autogroup:self"], "allow": ["dial"], "ip": ["tcp:443"] } ],
  "requests": [
    { "src": ["autogroup:network"], "dst": ["dns:*", "sock:tls/*", "sock:smtp/*"], "allow": ["publish", "listen"],
      "approver": ["autogroup:admin"], "maxExpiry": "7d" },                             // §13.9
    { "src": ["autogroup:tagged"], "dst": ["*", "sock:*", "evs:*", "mail:*"],
      "allow": ["dial", "route", "listen", "read", "write", "send"],
      "approver": ["autogroup:self"], "maxExpiry": "30d" },                             // owner decision 74
    { "src": ["network:*"], "dst": ["*"], "allow": ["dial", "route"],
      "approver": ["autogroup:admin"], "maxExpiry": "30d" },                            // shares (§8.11)
    { "src": ["autogroup:member", "autogroup:tagged"],                                  // the team directory's
      "dst": ["autogroup:member", "autogroup:tagged", "sock:*"], "allow": ["dial"],     // reach requests
      "approver": ["autogroup:dst-owner"], "evidence": ["device", "presence"],          // (§16.11; owner
      "maxExpiry": "30d" } ] }                                                          // decisions 179, 180)
```

An ephemeral sidecar's evs access takes 8.6's ceiling: the config's and its team directory's read, the directory's own-path writes, kind-default deposits, and grants and EvsShares that name it. A tagged ephemeral sidecar is in `autogroup:tagged`, yet gets no deposit from the implicit document's `autogroup:tagged` rule: the ceiling counts a rule only where it names the sidecar, and that rule does not. Standing publishes need a Pro or Team document; §13.9 caps the rest, and §21.7's probation is a hard deny.

### 8.6 Evaluation semantics

```text
allowed(s, a, r, t) = not hardDeny(s, a, r, t)
                      and exists g in rows(t): s in src(g), r in dst(g), a in allow(g), ports match,
                      ceiling(s, r, g)
rows(t)          = the state's AclRows: the network's document, or the implicit document when it has none
                   (has_document = false), compiled into the same rows; kind defaults, the audit block,
                   standing grants, activated requests, access-log RepoGrants and EvsShares, unexpired at t,
                   not revoked by a GrantRevoke or RepoRevoke, and no EvsShare that §7.9's cascade voids
ceiling(s, r, g) = true unless s is ephemeral and r is an evs: resource; then g names s (sidecar:<id>,
                   client:<id>, autogroup:ephemeral, or a tag s carries), is a kind default's deposit row,
                   the config kind default's read row or the directory kind default's read and own-path
                   writes, or is an EvsShare to s; so every ephemeral sidecar that hardDeny spares, never a
                   parked one, reads the config (owner decision 6) and its team's directory, and none
                   writes a config head
ports match      = for a rule with ip CIDRs or ports, each reader's check against the policy it compiles from
                   the sealed source (AclLocalPolicy); rows carry only whether a rule limits ports
                   (ports_limited, 8.8), so api and the gates check ids, and readers check a requested grant's
                   prefix against its rule
hardDeny         = unadmitted, revoked or parked sidecar (§7.9; parked by its compromise cascade or by a
                   leaked bundle's DelegationRevoke, unlike KF2's consent park) | unapproved client (§7) |
                   suspended subject | abuse halt (§21) | quota (§20)
```

- **Base.** Grants form a union over a deny base, without precedence, as in Tailscale (https://tailscale.com/docs/reference/syntax/grants); hard denies win, and no deny grants exist.
- **Direction.** The src initiates; replies are implied. Deposit implies no read, subscription, key or place in `RepoReaders`. Publish requires listen on the bound socket. Gates use server time and clients allow ±60 s of skew (`AclEngineSettings.ClockSkew`: the engine honors a rule until 60 s past its expiry by the local clock), so a daemon reserves a server-gated use only until 60 s before its `not_after` (§16.6).
- **Requests (owner decisions 74, 75, 142, 180).** A requested grant matches a `requests` rule and lasts its `expires`, else `expiresDefault` (1 h), up to `maxExpiry` (30 days by default; publishes follow §13.9). The rule's approvers approve, by default the requester's owner or sponsor; grants touching other members, shares or `autogroup:public` need an admin's decision as well, whatever the rule says (the admin clause), except that a touched member who approves as `autogroup:dst-owner` meets it for reach to a device that member owns or sponsors (owner decision 180, amending owner decision 74 for this case); two do where a Team rule's `approvers` asks. An Owner's or Admin's decision counts toward the rule's k only where the rule's approvers name it (`autogroup:admin`, or a group the admin is in) or where `autogroup:dst-owner` resolves to an admin because no owner or sponsor stands (D-ACL-23): under the directory's default rule an Admin's lone decision activates no reach grant to another member's worker, a rule whose approver is `autogroup:self` reaching another member's device needs the requester's owner and an admin, and an Admin who wants to grant reach alone writes it as a document rule (owner decision 349). Approvals are §16.8 `ApprovalDecision`s on channels the rule's `evidence` lists, or for an action no `requests` rule governs the document's `evidenceDefault`, both of which rows carry as effective lists (8.8; owner decision 342), harness evidence in a tainted run only where the rule itself names it, checked by clients, `harness_ok` and api; they activate the grant as a §7.9 delta (§8.8), whose `grant_id` the approval fixes, so a replay is refused.
- **Admission.** An admission past its `not_after` is refused at exactly that time; an untagged sidecar or app device whose member is no longer a member is unadmitted; and a hard-denied destination subject is no destination either (owner decision 355).
- **One switch.** A `Suspend` (§8.8's signers) removes a subject's atoms and activations across client generations; contracts, sockets, names, aliases, bridge rules and evs (§8.12) then refuse it, and for an agent a live Delegation admitted it also drops that Delegation's shared reader key at its position, so the next generation reaches the Delegation's other agents only by their own wraps and never the suspended one, which an `Unsuspend` returns uncovered (§10.5). Suspensions, revocations and cascade parks close open contracts, whose forwarding stops within 5 s; contracts a narrowed rule no longer allows lapse within 60 min (§8.3). A §21 suspension is server state that `hardDeny` reads, never a signed `Suspend` (I-4): it refuses contracts for sidecar subjects, shares included, names, publishing and sending, as §21's halts refuse sending, and never reaches evs or gkm, so the network's data stays readable, writable, erasable and exportable (§21.7; owner decision 531).

### 8.7 Policy authority (X3)

Owner decisions 3, 5 and 6 settle X3 (§7.9, Q-ACL-1): config writers sign the policy, every admitted sidecar evaluates it, and gates enforce its id-only projection (§8.8-§8.10). A breached server can only withhold or delay, visibly once a HeadCheck crosses the split (I-16), within §2.8's exposure bound (owner decision 129). It sees the reach graph and opaque ids, never member-chosen names, rule text or tests (owner decision 72; §2.8 api-7).

### 8.8 The policy in the config repo: rows, grant chains, saving

**Placement.** The policy source, repo labels and `K_sock` are config repo files that only config writers' heads change (owner decision 5): `policy.hujson`; the `tags` and `groups`, `rules`, `labels` and `resolve` files, which are protocol/config.proto's `ConfigAtomTable`, `ConfigRuleTable`, `ConfigLabelTable` and `ConfigResolution`, none server-visible, so none has a §2.8 row (owner decision 339); and `socket/key`, a single-record file beside `policy.hujson`, `SocketKeyFile{current_key = 1, previous_key = 2, rotated_at_ms = 3}`, its keys 32 B, with `previous_key` and `rotated_at_ms` set from a rotation until the head that clears them (§9.4), which a config writer creates with the repo (§7.9's paths). Server gates know policy only as `AclRows`, §8's part of §7.9's ProjectionRows, which the writer compiles at each base and readers recompile, alarming on a mismatch:

```proto
// sidecar/protocol/acl.proto: §8's rows inside §7.9's ProjectionRows. Ids only.
message AclRows {
  bool has_document = 1;                  // owner decisions 50, 105
  repeated AclAtom atoms = 2;             // §7.9's opaque tag and group ids -> member_ids, sidecar_ids, a
                                          // tag's owners; derived atoms for selectors no table names (Atoms)
  repeated AclRule rules = 3;             // rule_id, src atoms, targets, actions, expires; a
                                          // publish's audience, app_mode and link_spki_sha256 (8.4), the
                                          // pin in full, as a requested grant's GrantActivate shows it to
                                          // api anyway (§16.6 AD4); ports (5) reserved: bool
                                          // ports_limited = 11 says the rule has an ip port list, never
                                          // which, for 8.10's legacy rule; an activated grant's
                                          // source_rule_id = 10 (Folded grants); a route rule's via subjects
                                          // in via = 12, apart from its targets, or with no via the
                                          // advertisers whose BridgeRouteRow names the rule (§17.8; owner
                                          // decision 344); CIDRs and ports stay in each reader's
                                          // AclLocalPolicy (8.6)
  repeated AclRequestRule requests = 4;
  repeated AclRepo repos = 5;             // repo_id, kind, owner_member_id and the owner's consented
                                          // sidecar_ids (§8.5), whose consenting admission, AdmissionConfirm
                                          // and OwnerConfirm signers and positions §7.9's SidecarRow keeps;
                                          // its access log folded: repo admins, RepoGrants and EvsShares
                                          // with their expires, each with its signer sidecar_id and its
                                          // carrying entry's log position (§7.9's cascade), config writers'
                                          // standing RepoRevokes, the newest RepoDelete with any RepoRestore
                                          // of its deletion_id; the newest RepoVersioning's lock (folded from
                                          // M2, enforced from format 2); holders_shrunk_at: the newest log
                                          // position that dropped a key holder (§7.9); a removed admin's
                                          // removal position, the RepoDelete's entry time and signer, and
                                          // the prefix rule sets that took effect (Repo rows)
  bytes bridge = 6;                       // §17's id-only section
  AclAudit audit = 7;                     // owner decision 63; Team only
  repeated AclSuspension suspensions = 8; // the Suspends a fold keeps (Folded grants)
  repeated AclSpentGrant spent_grants = 9; // activated and revoked grant ids (Folded grants)
  repeated uint32 evidence_default = 10;  // the document's effective evidenceDefault, compiled at each base
                                          // as each AclRequestRule's evidence is: the ApprovalDecision.channel
                                          // values accepted for an action no requests rule names; default
                                          // all three (owner decision 342)
}
message AclRequestRule {
  bytes rule_id = 1; repeated bytes src_atoms = 2; repeated AclTarget targets = 3;
  repeated uint32 actions = 4; repeated bytes approver_atoms = 5; uint32 approvers = 6;
  int64 default_expiry_seconds = 7;       // expiresDefault: 1 h unless the document overrides it
  int64 max_expiry_seconds = 8;           // maxExpiry: 30 days unless the rule overrides it
  repeated uint32 evidence = 9;           // accepted ApprovalDecision.channel values (§16.8): the effective
                                          // list, evidenceDefault where the rule names none, else its own;
                                          // whether the rule itself names harness stays in AclLocalPolicy
}
// In a *_atoms field an autogroup is 16 bytes: fifteen zero bytes, then its AclAutogroup value, 1 to 14,
// autogroup:dst-owner (ACL_AUTOGROUP_DST_OWNER) being 14; no tag or group id takes that form.
message AclAudit {                        // a reader every member sees (owner decision 63)
  repeated bytes reader_atoms = 1; repeated uint32 repo_kinds = 2; repeated bytes repo_ids = 3;
  bytes audit_opt_in = 4;                 // the k-of-n AuditOptIn record, which api and readers verify
}
message AclTarget {                       // exactly one kind set (owner decision 355)
  bytes atom = 1; bytes sidecar_id = 2; bytes network_id = 3;
  bytes repo_id = 4;                      // sixteen zero bytes: every general or record repo (evs:*, a bare *)
  repeated bytes socket_tokens = 5;       // §9.4's token path of one socket name, 16 B a segment; several
                                          // are alternative paths of that name, newest K_sock first; while
                                          // the K_sock file holds a previous key, compile writes a second
                                          // target with the path under that key (owner decision 334)
  bool socket_prefix = 6;                 // every name strictly below the path, in whole segments; with no
                                          // token, every application and share/ socket; finer globs project
                                          // to their literal prefix
  string public_name = 7;                 // a tls/ or smtp/ socket name or a dns host, its glob kept, the two
                                          // told apart by a /, which no host holds
  reserved 8;                             // an ip target's CIDR, kept in AclLocalPolicy, never in rows
  bool mail_send = 9;
  bytes client_id = 10;                   // a client no binding names, a legacy client among them: D-ACL-5's
                                          // naming it, under an unrestricted grant
}
```

**Atoms (owner decisions 339, 353).** A tag's or group's atom id is 16 random bytes that the config's sealed `tags` and `groups` tables hold beside its name (§7.9). compile writes an `AclAtom` for every tag the document declares in `tagOwners` and every group in `groups`, whether or not a grant or request names it, and for every derived atom the policy names: `AclAtom{atom = 1, member_ids = 2, sidecar_ids = 3, tag_owner_member_ids = 4, client_ids = 5, network_ids = 6, role = 7, principal = 8}`. A tag atom's `member_ids` stays empty, its `sidecar_ids` lists the sidecars carrying it, and `tag_owner_member_ids` is its `tagOwners` expanded to member_ids at compile, which `CanApplyTag` reads and subject evaluation never does: applying a tag needs a standing member device (untagged, not ephemeral, not read_only) of a member in that list, and no consent, so a declared tag with no rule of its own can still be applied by a Delegation or a tagged `SidecarAdmit`, its sidecars holding what `autogroup:tagged` and the kind defaults give them. A selector with no table name compiles to a derived atom, id = SHA-256("urnetwork-sidecar-v1/acl-atom" || 0x00 || kind || 0x00 || value)[:16], kind one byte (1 member, 2 sidecar, 3 client, 4 network, 5 role, 6 principal), unkeyed because each value is already server-visible; `network:*` is the kind-4 atom over the one byte `*`, which names no subject until 8.11's shares. Rows name only what a writer can sign and never enumerate app clients: an app device with an owner row matches `user:`, `group:` and autogroups at the gate through `network_client_owner.member_id`, so app clients coming and going change no rows; a legacy client has no owner row and matches only `client:<id>`, `autogroup:untagged`, `autogroup:network` and `*`, D-ACL-5's "naming it" being `AclTarget.client_id` under an unrestricted grant; and `role:` and `principal:` match the identity that `getProvideRelationshipDetails`'s one query loads, never `GetClientIdentity`'s Postgres fallback, so the gate stays under §22.5's `DenyPostgresForTest`. A member that the log's rows no longer hold expands to nothing. A bare `*` dst compiles to `autogroup:network`'s atom, the socket prefix with no token and the wildcard repo, its ip ranges staying on the device.

**Rule ids (owner decision 339).** A document rule's `rule_id` is 16 random bytes held in the sealed `rules` file, keyed by the SHA-256 of the rule's canonical form: RFC 8785 JCS of one JSON object per rule, its lists sorted as strings, `id` and `note` left out and socket names in clear, a request writing its effective evidence, `expires_default` and `max_expiry`, so a change of the document's defaults is a change of meaning. An unchanged rule keeps its id across saves and `K_sock` rotations; any change of meaning makes a new id, so live grants under the old one end at that base (FS-14); identical rules compile to one; and compile refuses a rule with no row. An implicit-document rule takes the constant SHA-256("urnetwork-sidecar-v1/acl-implicit-rule" || 0x00 || u32be(index))[:16], with no table, the index counting its grants and then its requests, and 8.5's `tag:mail` kind-default rules, the only kind defaults that need the head, take SHA-256("urnetwork-sidecar-v1/acl-kind-rule" || 0x00 || u32be(i))[:16], i 0 the read and 1 the deposit. An activated grant's rule_id is its grant_id. 8.5's `id` never enters rows (8.7).

**Folded grants.** A fold keeps what the entries it drops still decide. `AclSuspension{subject = 1, suspend_id = 2, signer_class = 3, signer = 4, at = 5}`, class 1 owner or sponsor, 2 admin, 3 k of n: a fold keeps a `Suspend` until an `Unsuspend` of its own suspend_id lands, `signer_class` settles who may lift it (the statements below), and `hardDeny`, §7.9's leaves rule and `BridgeIdentity.suspended` read it. A `GrantActivate` folds to an `AclRule`: rule_id = grant_id (32 B), `source_rule_id` the CanonicalAction's rule_id, src the subject's derived atom, targets and actions from `grant_dst` and `grant_allow`, expires = `expires_millis`, and a publish's app_mode and link_spki_sha256; a share's grant, whose CanonicalAction names the other network in `share_network_id` beside its subject, the requesting sidecar, is matched by a request rule's `network:` source, the implicit document's `network:*` or a named network, and folds with that network's derived atom (kind 4) as its source, so the contract gate's share half finds the rule naming `network:Y` in X's rows (8.11; owner decision 346). compile drops the rule once `source_rule_id` names no `AclRequestRule` in this head (FS-14), once a `GrantRevoke` names it, or once its expiry is at or before the head's newest record time. A `sock:` entry in `grant_dst` holds §9.4's token path in hex, never an application name, since GrantActivate shows api the action; that path dies at the next `K_sock` rotation's end, so such a grant ends there, the closed direction, and is requested again (§9.4). `AclSpentGrant{grant_id = 1, retain_until_ms = 2}`: every activated or revoked grant_id enters `spent_grants`, with `retain_until_ms` the latest `not_after_millis` among its decisions plus 60,000 (8.6's skew); a `GrantRevoke` of an id no activation carried has no decisions to read, so it keeps 0, meaning the network's life, and since readers can verify only an admin's such revoke, these stay few; compile drops a row once `retain_until_ms` is below the newest `ConfigRecord.time_ms` in the head, never by a clock.

**Repo rows.** Every row of a repo's folded access log keeps its signer and position. A `RepoAdmin{remove}` keeps the admin's row, stamped `removed_at = 4` with the removal's position, until the next base's compile drops a row whose removal its retention point has passed, and the deletion row carries `deleted_time_ms = 5`, the RepoDelete entry's time_ms, and `signer = 6`, the RepoDelete's signer (owner decision 343). Readers, evs and taskworker then judge from rows alone, on any day: a RepoRestore within 7 days of a RepoDelete without now, taskworker's shred at 7 d 10 min after the RepoDelete's entry (§11.12), a removed admin's right at a position before its removal (`AclState.RepoAdminAt`), and evs's reconciler applying a RepoDelete after its entry left the log's retention, writing repo/'s deleted{deletion_id, time, signer} from the row. A repo whose rows' newest RepoDelete stands unrestored gives its standing admins the evs `admin` right alone: no read, write or deposit, and no rule or kind-default right; so the exchange mints only `admin` for a deleted repo, evs's guard honors it for DELETE, with and without now, while its read and write routes stay refused, gkm's guard reads the same rights and its own repo/ recheck refuses its writes, and a RepoRestore's `restored_at` lifts the deletion (§11.12's refused row; owner decision 351). `subject` in RepoGrant and EvsShare is 16 bytes naming a sidecar_id, an untagged sidecar's member, or any atom the sidecar holds; within 8.6's ceiling only its sidecar_id, a tag it carries or `autogroup:ephemeral` counts; and a config writer's standing RepoRevoke voids grants naming the revoked subject and every grant to a sidecar it names. The config repo's own row comes from no `RepoCreate`, one of kind config staying refused (owner decision 341): where a state's rows hold no `AclRepo` for the network's config repo, ACL's state build adds `AclRepo{repo_id: Genesis.config_repo_id, kind: config}` with no admins and `holders_shrunk_at` 0, so the kind's defaults answer it alike in every reader, gate and api, all of which hold the Genesis, and base 1's compile stays empty. The rows gain it only at the first entry that shrinks the config's key holders, `AclRepo{repo_id, kind: config, holders_shrunk_at: n}`, sorted in with the rest and advanced there afterwards like any repo's, which §7.9's `shrunk_repo_ids` may name; the state keeps a config row the rows hold and synthesizes one only where they hold none.

**Via subjects and route rows (owner decision 344).** A rule's via subjects ride `AclRule.via = 12`, apart from its targets, so they no longer share targets with its dial destinations, and an internet rule that names a via holds to it at every gate. A route rule that names no `via` takes as its via subjects the advertisers of the approved routes that name it: `BridgeRows.routes = 2` holds a `BridgeRouteRow{route_id = 1, advertiser = 2, route_rule_ids = 3}` for every approved route in force, written at the fold and applied by every verifier in log order after a base, as the egress mode is, and the state adds each advertiser to the via subjects of the no-via route rules its row names (§17.8). The server sees only the ids §17.8 already describes (§2.8 api-7).

**K_sock's overlap (owner decision 334).** While the `socket/key` file holds a previous key, compile writes a second `AclTarget` under that key beside each `sock:` target, a pure function of the head, so gates' `MayListen` and `MayDial` do not change and readers recompile the same rows; a grant the rotating head drops is dropped on both paths. A requested grant's `sock:` entry is a literal token path (Folded grants), so it gets no second path and works through the overlap as §9.4 says. The first writer head at or after `rotated_at_ms` + 10 min clears the previous key (§9.4). Rows therefore hold both paths until that head, which links them for as long as those rows are kept, at least 30 days (§2.8 api-7).

**Grant chains.** These statements act at once as §7.9 deltas, checked by api and readers against the state at their log position until a writer folds them in, so none waits for an admin (owner decisions 8, 74). Each opens with §7.9's `StatementHeader`, whose `at` pins the signer's state. Re-applying a base's tail judges nothing (§7.9's tail verdicts; owner decision 356): `AclState.ReapplyStatement` takes only the parts of a verdict that the statement's body and signers give, the signer and an OwnerConfirm's target, and derives every other fold input itself from the body and the rebuilt rows it folds into, never from a check run again: a Suspend's or Unsuspend's class and whether an Unsuspend lifts, a RepoRevoke's or RepoGrant's config-writer standing, a RepoCreate's owner and consented sidecars, a GrantRevoke's retain_until_ms and a GrantActivate's grant. Each is a pure function of (body, signers, rebuilt rows), so a new device, a gate that started at the base and a long-running reader fold alike, and a head change that would make the check refuse on the rebuilt rows changes no fold:

```text
statement (§6 Signed, purpose acl unless noted; ids only; in       signer
  acl.proto, which imports sidecar/protocol/bridge/auth.proto
  (§4.4), where GrantRevoke, Suspend and Unsuspend are declared,
  since sidecar/device's posture applies them between states (§17.8))
GrantActivate{header, grant_id, canonical_action, decisions}       any admitted sidecar; authority only from the
  canonical_action: the approved §16.8 CanonicalAction, whose      embedded ApprovalDecisions, each signed by an
  grant fields are rule_id, subject, grant_dst, grant_allow and    approver the requests rule names (8.6) on a
  expires_millis, and a publish's also app_mode and                channel its evidence lists, binding the
  link_spki_sha256; a dial or route grant's prefixes and ports     canonical action's hash and its subject (§16.6)
  only in its sealed_detail (owner decision 220; §17.8); a
  share's grant also share_network_id, the other network, which
  the admin's approval covers (owner decision 346)
GrantRevoke{grant_id}                                              an approver, the subject, or an admin
Suspend{subject, suspend_id}                                       an admin, or the subject's owner or sponsor;
                                                                   for an AdminSet member's device, its owner
                                                                   or k of n (§7.9); never changes AdminSet or
                                                                   its n; of another sidecar, countersigned as
                                                                   §7.9's presence row asks (owner decision
                                                                   187)
Unsuspend{subject, suspend_id}                                     the class that suspended it or a higher one
                                                                   (owner or sponsor < admin < k of n, with no
                                                                   admin class for an AdminSet member's
                                                                   device), never the subject itself; lifts
                                                                   only that suspend_id
EvsShare{repo_id, subject, expires}                                a consented device of the repo's owner (8.5),
  expires optional, defined at M2 and honored by every reader as   for owner-bound kinds
  RepoGrant's is, so a time-bound share ends with no device
  online (a reader ignoring it would widen access)
OwnerConfirm{sidecar_id}                                           a consented device of the sidecar's member
                                                                   (8.5; owner decision 126)
access log of one repo_id (owner decision 8):
RepoCreate{repo_id, kind, inbox}                                   a sidecar the kind lets create it, which
  inbox (RepoInbox: 0 none, 1 group, 2 admin) marks a group        becomes the repo's admin: general or record, a
  inbox (8.5): valid only with kind general; 2 only from a         member device (untagged, not ephemeral, not
  config writer, once a network, api and readers refusing a        read_only), or a tagged or ephemeral sidecar
  second; the marker is server-visible in the log (§2.8            only under a rule giving it admin on evs:* or
  api-7); acl.proto takes it as field 4, before M2's freeze        that repo, within 8.6's ceiling; owner-bound
                                                                   kinds, a consented device of the owner;
  a tagged or ephemeral creator's repo stays keying until a        directory, team_record and mailcfg, a config
  config writer that reads it and holds its admin forms its        writer (D-TEAM-28); config, none (§7.9's
  group (§10.7's KF1; owner decision 365), which §8.5's            bootstrap); no create action exists, so a
  implicit document always allows                                  policy cannot stop a member creating repos
RepoAdmin{repo_id, sidecar_id, add | remove}                       a repo admin or a config writer; in an
  a remove keeps the admin's row, stamped with its position        owner-bound repo an add only by a consented
  (Repo rows, above)                                               device of its owner (8.5), any of which
                                                                   may add itself (§15.7)
RepoGrant{repo_id, subject, role deposit|reader|writer, expires}   a repo admin or a config writer; never in
                                                                   an owner-bound repo (EvsShare there)
RepoRevoke{repo_id, subject}                                       a repo admin or a config writer; a config
  in an owner-bound repo, one naming a consented device of the     writer's overrides repo admins' grants and
  owner is refused, and a later EvsShare to the subject from a     stands until a config writer grants that
  consented device of the owner lifts a config writer's            subject again
  standing one, the fold dropping its row from AclRepo.revokes
  at that position (owner decision 332)
RepoDelete{repo_id, deletion_id, now}                              a repo admin, with a random deletion_id, before
                                                                   §11.12's DELETE, which requires it in evs's
                                                                   newest projection and takes deletion_id and now
                                                                   from it
RepoRestore{repo_id, deletion_id}                                  a repo admin, within 7 days of a RepoDelete
                                                                   without now, before §11.12's restore, which
                                                                   requires the matching one
RepoVersioning{repo_id, lock: locked | unlocked,                   a repo admin or a config writer; in an
  rules (sealed, optional)}; v1 (owner decision 160), see below    owner-bound repo a consented device of
                                                                   its owner (8.5)
RepoPrefixRules{repo_id, rules (sealed)}; v1 (owner decision       a repo admin or a config writer; only in a
  345), see below; SignedType 0x1111, after the row order's        general repo that is not deleted
  0x1101 to 0x110F (§6.11)
ApprovalDelivery{header, requester_sidecar_id, sealed}; SignedType the approver's device that signed the decision
  0x1110 (owner decision 447): the Signed ApprovalDecision or      or cancel it carries, after it signs
  ApprovalCancel, HPKE-XWing to the requester's ReaderKey; api
  sees its signer, requester and size, and it authorizes nothing
  (§16.8)
directory (one per team network, §16.11; owner decision 171): its admins are its creator and every config
  writer, each counted while consented (8.5) and not read_only, alone holding its admin scope (§7.8); api's
  verifier and readers refuse its RepoAdmin adds, RepoGrant, RepoRevoke and RepoVersioning and a second
  directory RepoCreate in a network, and api one outside the team tier (§20.5)
team_record (one live per team network; owner decision 303): team-create's first Owner device files its
  RepoCreate right after the directory's, and an admin device that finds a team whose access logs hold none
  files it; api's verifier and readers refuse a second live one in a network, and api one outside the team
  tier; its admins are its creator and every config writer, as the directory's; a RepoDelete of it stands,
  only a person's /dev/tty-confirmed admin command filing a new one, so a Team may decline the ledger (§7.5)
authority statement (purpose authority; §7.9's proposal and cosigns):
AuditOptIn{reader atoms, not_after} | AuditOptOut                  k of n (§7.9)

GrantActivate checks (api's projection verifier and every reader):
grant_id  SHA-256("urnetwork-sidecar-v1/grant" || approval_id || payload_sha256), fixed by the approval
match     SHA-256(canonical_action) = every decision's payload_sha256, and the action's subject = every
          decision's requester_sidecar_id
fields    the stored action sets only kind, version, scope and §16.8's server row's fields for a grant (8, 10,
          11, 28 and 29, version 4's sealed 38 and a share's 40), any other set field refusing it, so a
          requested dial or route grant shows api no prefix or port (owner decisions 220, 457)
quorum    the rule's approvers (autogroup:dst-owner resolved from grant_dst at the statement's position,
          8.4), count k, evidence and 8.6's admin clause are met, an Owner's or Admin's decision counting
          toward k only where the rule's approvers name it or dst-owner resolves to an admin (8.6; owner
          decision 349), each decision passing §16.6's spend check
refuse    a grant_id in spent_grants, in an active rule, or in an entry after folded_through, or one a
          GrantRevoke names

RepoVersioning (§11.7):
format 1  M2's acl.proto carries its id-level fields (repo_id, lock) and AclRepo's lock: format-1 code verifies
          its signer and chain, folds the lock and skips its rules, enforcing nothing; no format-1 repo holds
          versioning 1 and format-1 writers write only versioning 0, so no device stalls, forks or compiles
          other rows (D-PHASE-9); format 2 enforces the lock
lock      refuses versioning 1, not the search index's 2 (owner decision 168), and drops, never their cancels,
          in any push whose auth pin includes it (§11.7), and voids any drop still pending when evs's job would
          start (§11.13; owner decision 183); the command that files a lock offers to cancel the repo's
          pending drops
rules     replace the network's VersioningRules (§7.9) for this repo; an owner-bound repo's are sealed to that
          repo's own current generation (§10.5), which only its readers hold, the config writer folding the
          delta carrying them as an opaque blob, so no sidecar but its readers learns its path globs (owner
          decision 126); other repos' are sealed to the config's generation, as §17.8's rule bodies are; api
          and evs see only the lock; sealed_rules has §7.9's sealed-body bytes, its key drawn from the
          generation of the repo it is sealed to

RepoPrefixRules (§11.7; Q-EVS-3 (a); owner decision 345):
M2        acl.proto carries it and AclRepo's prefix_rules = 12 from M2: every verifier checks its signer, its
          repo's kind, its body's length and the repo's count of sets, and folds AclRepoPrefixRulesRow{signer
          = 1, at = 2}; nothing is enforced until M6, and a device built before M6 enforces nothing, which ur
          evs rules says at a repo's first set (D-PHASE-9)
rows      every set that took effect, in position order, for the repo's life, at most 256
          (AclPrefixSettings.SetMaxCount, as every number here is a field of AclPrefixSettings); the body
          stays in the log and the config head's fold records
sealed    a PrefixRuleSet under the repo's own generation, in §7.9's sealed-field form: rules {subject, path
          prefix in whole components, write}, sorted, at most 256 and 64 KiB; api and evs see that a set exists
subjects  a sidecar, a member's untagged devices (user:<email>), a tag, or autogroup:sidecar, member, tagged
          or ephemeral: facts an admission fixes, so a reader that holds no state at a push's pin still judges
          it and every device reaches one verdict on every version it can verify; a group's atom or a role
          names nobody, and ur evs rules refuses group:<name> with the list of its members' user: subjects to
          file instead
admins    a repo's admins are held to its rules like every signer: ur evs rules writes a rule {sidecar:<id>,
          every path} for each standing admin into every set it files, the command that adds an admin offers
          to file the set again, and set --as-written files a set without them and says which admins it
          leaves unable to write
in force  at a push's auth pin: the newest opened set at or below it; none: no restriction, so pushes pinned
          below a repo's first set are unbound; a set binds every shared ref of its repo, with no rule per
          ref, and every signer, one it does not name writing nothing; an admin lifts the rules by filing the
          one rule naming autogroup:sidecar for every path; a set binds a ref from the first push on it pinned
          at or above the set, and its filer sends a push of no change to each shared ref
verdict   every reader folds the sets at each push's auth pin; a version no rule allows is ignored and raises
          evs_alarm prefix_rule; no server checks a rule
outside   a file-mode ref's .ur-index/, the refs ur/index and ur/lfs, and pushes flagged FORCE, DELETE, BASE,
          DROP, ERASE, CUT or CLOSURE; a compromise cascade voids no rule set, and CascadePlan lists the sets
          the device filed
void      a set whose seal does not open, whose rules break the format, or whose generation was signed more
          than 1 h after its entry leaves the set below it in force and alarms, naming its filer; a later
          release's set makes a reader that cannot read it hold the repo's later versions and say `update`
```

**Access logs (owner decision 8).** A repo's access log, the ordered chain of its RepoCreate, RepoAdmin, RepoGrant, RepoRevoke, RepoDelete, RepoRestore and RepoVersioning statements, rides §7.9 deltas into config heads, which keep it for the repo's life, each statement with the log position of the entry that carried it, so a reader judges a signer's repo admin right at any position, one before its retention point included (§16.11's repo file row); readers replay it, members check Adds and Removes against it (§10.9), and, as a RepoDelete or RepoRestore precedes its §11.12 route, the log never shows a deleted repo live, so a re-seed after a site loss can refuse a repo whose log ends in a RepoDelete past 7 days or with `now` (§19.10). A DROP push rides its ref, not this log, since it changes no reader, writer or key (§11.7). A team directory's decision entry cites the `RepoGrant` or `EvsShare` it approved by hash and log position, or the `ApprovalDecision` a `GrantActivate` spends, as its request's receipt; the statements are unchanged (§16.11). Config writers, who alone write config heads, are the AdminSet members' member devices (untagged, not ephemeral; 8.4) that are not read-only, and only k of n adds one (§7.5, §7.9; owner decisions 110, 112, 128).

**Saving.** A writer's device validates, compiles, tests, previews and signs; a failing test rejects the head (https://tailscale.com/docs/reference/syntax/policy-file). The writer's device runs `tests` before signing, and readers do not rerun them at replay. The config repo's signed head history is the change audit: read-only `ur acl log` lists each head's config_version, signer and time and never runs through MCP (D-MCP-17), and a rollback is `ur acl push` of an older source, a new head at a higher version (D-ACL-9). Validation refuses unknown atoms, approver-only atoms (`autogroup:sponsor`, `autogroup:dst-owner`) outside `approver`, tags outside `tagOwners`, bad ports, overruns, `evs:` paths (X2), owner-bound readers outside the `audit` block, `evs:` grants naming the config or the directory (D-ACL-13, D-ACL-24), an `audit` block without an `AuditOptIn`, publishes past §13.9's limits, `raw` outside `public` and `link`, and a raw `link` without a pin; `network:` selectors resolve from labels or aliases, never legacy names (D-DNS-2). compile is a pure function of the head, so `user:`, `network:` and `client:` selectors resolve through the config's sealed `resolve` file (§7.9's paths), one row per selector the policy names: the writer fills it at save, a server answer being only a proposal, as §7.6 treats SCIM. For an email it uses its own invite record where it has one, else `GET /network/members`, and the preview lists each new or changed row with the member's role and devices, which the person's confirmed save signs; for a network, §12's ResolveNetworkLabel, by label or alias, the id pinned until a person saves again, so a moved alias retargets nothing (§7.12); for a client, a dual-signed `SidecarIdentityBinding` the writer verifies itself, a client with no binding staying a literal client id. Validation refuses a member_id with no live MemberRow, so a stale row fails closed until the next save; 8.4's grammar and the stored source do not change. The preview names readers a repo cannot seat (§8.12).

**Code and limits.** Pure Go `acl_*.go` in the sidecar root; `ur acl test policy.hujson` runs offline. Per-tier limits (owner decision 73) are §20.4's `acl_*` keys in `config/all/pro.yml` (`model.Pro()`). ProjectionRows hold at most 4,096 atoms and 4 MiB, and §7.9's `config_admissions` bounds subjects; validation and api's verifier refuse a head or base over a limit (`RESOURCE_EXHAUSTED`). Every tier may hold a document (owner decisions 50, 73); after a downgrade new heads must fit (§20.7).

### 8.9 Distribution: local evaluation and gate caches

**Clients.** Every admitted sidecar follows the config repo and §7's `team` hints, verifies config heads and the authorization log (§7.9) and evaluates its own rules in `AclEngine`, with no always-on compiler (owner decision 6). The engine swaps compiled state through an `atomic.Pointer`, checks without locks or allocation, and compares its auth pin (n, A_n) in HeadCheck (§6.4), which any admitted reader, agents included, may witness (owner decision 129): it refuses a lower pin, and reconciles, alarms, relays (`proven`) and stops sealing in shared groups as §6.4's auth rules say. An app's forwarding role follows them itself in its VPN component, by its forwarding Delegation's reader key, through the same engine (§18.6; owner decision 197), and between its compiles `sidecar/device`'s posture checks bases' signatures and chain only.

**Gates.** api's verifier (§7.9) keeps each network's newest base and the entries after it, which api, evs and gkm read from §7.9's verified Redis cache `{acl_<networkId>}e` when it reaches `{acl_}v` and every pin they hold, else from `proj/` on the first metadata cluster (owner decision 136); only api writes that cache, which decides nothing, and other gate services fetch from api, as only those three and taskworker reach the metadata tier (§2.8 evs-10). Each process caches them per (network, n), loading asynchronously outside packet locks on api's `INCR {acl_<networkId>}v` (class `$`, xops/redis-set-notify-keyspace-events.sh:23) after every entry it appends and on a 5-min poll; a network without a config repo costs one map miss (R-ACL-8). Gates check every entry's chain from their own pin wherever they read it, and refuse a lower n, or a second A_n at one n, with an alarm. Taskworker's gkm reconciler tells its cache of the networks §10.6's networks row names, at its runtime's start and again for one the bounded cache evicted, so a quiet network's hints, key deletions and sweeps run after a restart; gkm and the reconciler read their state through this cache (owner decision 371).

**The internal gate surface (owner decision 340).** Services with no database read rules, facts and quotas from one read surface on api under `/internal/gate/`, a prefix the lb refuses from outside. Each caller class holds its own bearer in `secret_files`, one vault file per gate caller class, connect's first, which api verifies by its SHA-256 in constant time (§19.4, §19.16). `GET /internal/gate/projection/<network_id>?after=<n>` answers the body of the Client route `GET /network/config/projection` (§7.9): `{genesis, entries, rows, tip: {n, chain}, more}`, each message verbatim in base64, paged, from the retention point when `after` is before it; `GET /internal/gate/rows/<network_id>/<rows_sha256>` answers the ProjectionRows bytes verbatim (`application/octet-stream`), which the caller holds to their hash; `GET /internal/gate/listen-facts/<network_id>` answers `network_verified`, whether a `mail_network` row exists, and each `network_tls_cert` row's name and expiry; and `GET /internal/gate/over-limit` answers §20.7's list, spent and storage-over networks apart. One encoding serves devices and gates, and gates verify entries' chain and signatures as they do from `proj/`, so api stays a carrier. A gate refreshes a network's projection on `{acl_<networkId>}v` and the 5-min poll, its facts at most every 60 s off the inline path, and the over-limit list every 5 s. A process that has never loaded them stays not ready, and a `tls/` entry with no cached facts answers `unavailable`. Other gates' reads and §20.14's quota routes join the prefix under the same rules.

**A gate behind the log (owner decision 337).** On a failed refresh a gate keeps serving what nothing contradicts: with no evidence that the log moved, the last verified projection, facts and list serve without limit, so an api outage changes nothing, api being the log's only writer. A sockets process answers `unavailable` for a network once it has had evidence for 5 s, this section's target for server gates, that the network's authorization log passed what it holds and it has not verified the new entries: the `{acl_<networkId>}v` event, a store answer naming a higher position, or after a resubscription a `{acl_}v` that differs from the one its state was loaded at (§9.8).

**Targets**, revocations included: to server gates ≤5 s; applied on connected clients p50 ≤1 s, p99 ≤5 s, measured from acks (`POST /acl/ack`) kept 7 days (§2.8). An ack's body is `{version, time_ms}`, `time_ms` used only for the delay histogram, and an ack counts only above the client's last and at or below the network's head row (owner decision 355).

### 8.10 Enforcement points

Server gates are coarse (who talks to whom, holds a name, fetches ciphertext) and read `AclRows`; clients check direction, port, socket, alias and path where access yields plaintext or a local effect. An outward action passes a server gate only under a standing grant, a request whose §7.9 delta carries the approval and whose GrantActivate signatures verify, or a decision sent with `Idempotency-Key: <effect_key>`: the gate first answers a use committed under that key from its `approval_use` row while the row lasts, and otherwise runs §16.6's spend check and consumes a use in the effect's own transaction (one row per approval and effect key, §16 D-MCP-11), so a lifted token cannot publish (I-8) and a retry past `not_after` gets its stored result; a gate keeps the decision only in memory, and `approval_use` only the approval id, use index, effect key, state, result and the decision's expiry (§2.8 api-10). Platform and ControlId clients skip the contract gate; nothing is checked per packet (connect/CODESTYLE.md:106-107).

| resource | server point: rows read | client point |
|---|---|---|
| subject dial, `ip` route | `CreateContract` (`:859`-`:933`): subjects, dial and route rules (src → via), `has_document`; a 5 s heads snapshot; subject ids on the existing query (`server/model/network_client_model.go:2544`) | stream accept (§6); the provider hook per flow (`connect/ip.go:5676,3602`; `connect/ip_icmp.go:786`) |
| `sock` | sockets (§9.10): token paths and public names | listener verifies the dialer |
| `evs` | the token exchange's `repo:<id>:deposit\|r\|rw\|admin` scopes from `AclRows` (§7.8, owner decision 2); evs and gkm honor `r`, `rw` and `admin` only for current readers and writers, and `deposit` only while its subject may deposit there (D-ACL-21), and check §11.8's gate; a deleted repo's standing admins get `admin` alone, which evs honors for §11.12's DELETE (owner decision 351), and every config writer gets `admin` on the config repo (owner decision 352); `admin` also covers DROP pushes and their cancels, in an owner-bound repo only from its owner's consented sidecar_ids (§11.7); in the team directory, as in every repo, only `admin` covers the erasing pushes, closure uploads and slot deletions §11.12's directory row lists, and only its consented, not-read-only admins get it (§7.8, §16.11) | heads only from writers (owner decision 7); every Add, Remove and wrap (§8.12) |
| `dns` publish | dns, certs, tlsedge (SNI → name → socket): publish rules; the `tls/` `ValidateListen` refuses `raw` unless the grant's audience is `public` or `link`, and a raw `link` whose grant carries no pin (§13.9); an edge (`autogroup:public`) Find for a `tls/` name passes under any publish grant for the host, whatever its audience, the gate reporting the audience and judging neither it nor a pin (§9.10; owner decision 348) | only the listener's front enforces `audience` and a raw `link`'s pin, both from its own evaluation (§13.7, §21.4) |
| `mail` | mxedge: `listen` on `sock:smtp/25/mx` (a scope's `smtp/25/mx.<scope>`); smtpedge: `mail_send`, From domain (§14.5) | receivers, local mail server: `mail:<alias>` (§15.10) |
| shares, egress | contract gate: share grants, `bridge` (§17.9) | provider: a verified `WindowDelegation` matching C13's sealed network (§17.9) |

**Contract rule** (networks with a head row), on the request's own `Companion` bit, replacing the origin-free normalization at `:917-927`: (1) a non-companion a→b with `reach(a,b)` passes, class data; (2) a non-companion without it but with `reach(b,a)` is a reply: the gate returns that verdict from memory, then `CreateContract` runs `model.CompanionOriginExists` once, with the companion path's bounded origin wait, and an origin passes as class data; (3) otherwise the witness exception below gives class `control`, else `ContractError_NoPermission`; (4) a companion a→b needs `reach(b,a)`. Step 2 precedes step 3, or a reply racing its origin would stick on a control contract. `reach` is an active dial or route grant, sockets expanding to listeners and `ip` grants to via subjects (8.8). connect is left as it is, asking for a same-network reply as a non-companion contract (8.3), and sidecar RPC replies ride this rule (§6.10.1). The gate's own decision reads no Postgres (§22.5); the origin read belongs to contract creation and runs only with a head row and only when `reach(a,b)` fails. While b's origin stands, a holds a data contract to b, so a legacy b, which checks nothing, is reachable from a for that time, as under any reply path. The gate also refuses Network contracts from §18's hosted devices (I-10), and Public ones from subjects in `exits` or `none` egress mode (`ContractError_NoPermission`). In any network, with a head row or without, `CreateContract` refuses Public contracts from declared no-egress clients, from M1 (§20.8). With a document, providers refuse LAN, loopback, link-local and overlay destinations to Network sources no rule allows (owner decision 50, §17). Witness exception: any two admitted sidecars of one network, neither revoked, parked nor suspended, get a Network contract of class `control` without a reach grant; it carries only Hello, Ping, HeadCheck and its proofs and, with a sidecar that serves remote search (Hello feature bit 0), §11.14's SEARCH and SEARCH_RESULT, which receivers enforce and the gate does not check, and providers deny IP on it (§6.4, D-PROTO-18, D-PROTO-21).

**Receivers** see window-client ids [R:connect-ip]; C13 seals the source client's stored `acl_subject_client_id` (never a request field), `source_network_id`, the contract class and the subject's `WindowDelegation` into `StoredContract` (D-PROTO-19), and receivers admit a native flow only from a verified delegation (§17.9). A **legacy** client (no `acl_enforcing`, set at mint, §7.7) is reached only through an unrestricted grant, naming it (`AclTarget.client_id`, 8.8) or a selector containing it as dst with `dial` and no `ip` ports (its rule's `ports_limited` false), `sock` or `via`; otherwise it is source-only (owner decision 106).

### 8.11 Cross-network sharing and invites

- **Consent.** X grants `network:Y` a resource with an admin's approval (owner decision 74), the grant's CanonicalAction naming Y in `share_network_id` so that X's rows hold a rule whose source is `network:Y`'s atom (8.8; owner decision 346), and Y grants its subjects `dial` on `network:X`; access is the intersection, enforced as two halves: X's provider checks X's grant against the verified source network and share (§17.9), and Y's routers and the contract gate (8.10) check Y's grant; neither sees the other's groups. X's half verifies only that a current reader of Y's config signed for the share, never Y's per-subject grant, so the unit X can check is Y's whole current reader population: a Y reader that Y's policy denies, running modified software, reaches X's granted targets only on a contract the operator mints, still within X's grant (§17.9, §2.10).
- **Invite.** `ur bridge invite` (cli/UI.md:50) files X's request with a hashed 256-bit code, `uses = --count` and a 7-day window; `accept-invite` (`:51`) files Y's, the server binds `invited_network_id`, and each activation is a delta in its network. `POST /acl/accept-invite` takes two body forms (owner decision 350). A claim, with the code's hash alone, takes a use, binds the invited network to a share, the invite's own row first and then a new row of the same target table for each later claim of a multi-use code, and answers the share's id with the sharing network's sealed targets; a repeat claim answers the share the network already holds and takes no use. A completion, with the share id, the sealed accept and the status, stores them once. A claim binds before the invitee's preflight, so a refused preflight still holds its use and completes with a refusal status, and the ShareKey's sealed body rides in the sealed accept, so `network_bridge_share` holds no column for it (§17.9). Y's approving admin creates the share's ShareKey in a `secret` repo of its own (8.5); X's approving admin's device pins it as §17.9's share pins say, in the act that files the share's GrantActivate, and the ShareKey certifies a ShareSigner per generation of Y's config, so a sidecar Y removes signs only within §17.9's bound. Both networks' tables travel under §17.9's share seal, bound to its label, both networks and the table's version; a multi-use code's accepters all hold its key, so a seal proves only a code holder, and X's approving admin is what pins one ShareKey to one share. The row is deleted once its uses run out or its window closes.
- **Contracts and data plane.** Shares ride the IP path (owner decision 86) as FriendsAndFamily toward marked sidecars, escrowed from the dialer's network (§6.10.1, Q-PROTO-3 (b), owner decision 11); §4's C18 stops providers treating those sources as Public toward private destinations, and §17's hook admits them only under a `route` or `dial` grant.

### 8.12 ACL and evs readers

- **Readers.** `RepoReaders(repo)` is the set of sidecars that 8.6's `allowed` gives read on `evs:<repo>`, from kind defaults, the audit set, rules, EvsShares and the access log, so `RepoReaders(directory)` is every admitted sidecar of the team (8.5); writers likewise, and readers accept heads only from writers (owner decision 7). The directory's `admin` needs consent and a device that is not read_only; a repo whose newest RepoDelete has no RepoRestore gives no right but its standing admins' `admin` (8.8); and the audit block counts only with a non-empty `audit_opt_in` (owner decision 355). From M6 `AclEngine.AllowPrefixWrite`, over a write's repo, ref and paths, is the writer's own refusal under 8.8's prefix rules, at the state its push pins, before anything is sent (`EVS_PREFIX_RULE`, §18.5). An expiry drops a reader at its time (§7.9's coverage); evs and gkm honor an `r`, `rw` or `admin` scope only while its subject reads or writes the repo, as the scope says, in their newest state, and a `deposit` scope only while 8.6 gives its subject deposit there, under its ceiling and hard denies, or it reads an owner-bound repo it does not write (§16.8's receipts), computed as the exchange computes the scope; gkm's drop-key route takes the same check (§7.9's tokens row).
- **Leaves, seats and wraps (owner decisions 114, 144, 182).** Member devices are MLS leaves of the repos they read, in the config and team directory groups only as §7.9's `leaves` rule entitles them; other sidecars (tagged, ephemeral, CI, cloud agents) hold §10.5's per-generation `ReaderWrap`s, the config repo's and the directory's included, and agents a live Delegation covers read its repos through the Delegation's wrap (§10.5). A group holds at most 1,000 leaves (D-KEYS-2):

```text
seats (owner decisions 144, 182; §10.9 commits)
config    §7.9's leaves rule alone decides the config leaves and their moves: the first 1,000 live member
          devices by (live_since, sidecar_id) are leaf-entitled, members accept a config Add or external join
          only of an entitled device, and the rest read by ReaderWraps, as agents do; an entitled device
          without a KeyPackage also reads by ReaderWrap, the first from its admission's signer, until it
          uploads one, no other device takes its place, and a leaf that may commit it then adds it
directory the team directory's group follows §7.9's leaves rule as the config group does, the one exception
          to data seats (owner decision 182): every admitted sidecar of the team reads it (8.5), none keyless
data      member devices stay leaves of the data repos they read, at most 1,000 a repo; a reader without a
          seat waits keyless, and the writer's preview and the console name the repo; committers fill a free
          seat with the earliest-admitted waiting member device that has a KeyPackage (KF2), members checking
          only that it reads and the 1,000 bound; a seated device keeps its leaf until a Remove, and an
          external commit that adds a leaf needs a free seat
wrapped   a wrapped config or directory member commits no Add or Remove in that group (§7.9): for an
          admission it signed, it writes the new device's first ReaderWrap at once, so that device reads with
          no admin online (owner decision 128); for a revocation, it rotates by wraps to every remaining
          holder, and the next leaf commit removes a leaf target; revoking a wrapped member device is, as for
          an agent, a new generation not wrapped to it, while a move shrinks nothing and needs no rotation
```

- **Committers (§10.9; owner decisions 113, 128).** Signed grants, admissions and revocations carry the authority: any writer leaf commits the Add or Remove one requires, as may, in the config and directory groups, the leaf that signed it; a recovery-admitted device self-joins by external commit if leaf-entitled (§7.9), else reads by its RecoveryWrap, then by wraps. Wrapped writers rotate by re-wrapping but never commit an Add or Remove; revoking an agent is a new generation not wrapped to it.
- **Removal (no server transaction, owner decision 5).** When an authorization-log entry drops a key holder, evs closes the repo's write gate (§11.8, D-EVS-18); Removes cover revoked, cascade-parked, suspended, no-longer-reading and stale sidecars and, in the config and directory groups, leaves that lost entitlement, each by its signed input (§10.9).
- **Invariant (the primary control).** A client never encrypts to an epoch or generation that a sidecar its own evaluation marks as a non-reader holds, a live Delegation's key aside, which its reaped agents and its ephemeral agents past their own `not_after` keep until it drops (§10.5's Residual; owner decision 114), committing the Remove or rotation first, and checks every Add and wrap against §7.9's admissions, §8.5's consent and the access log, so a breached server can neither admit a ghost nor grant a reader (R-ACL-7).

### 8.13 Alternatives considered

| option | pros | cons | verdict |
|---|---|---|---|
| Server-compiled policy, or a Postgres authority log beside it | one compiler; Tailnet Lock's shape | the server grants reach and readers; plaintext policy | superseded (owner decisions 3, 5, 6) |
| Every admitted sidecar an MLS leaf | one mechanism | a commit per agent join and reap; agents share the leaf cap | superseded (owner decision 114) |
| A cap of 1,000 member devices per network | config leaves only | refuses Teams past about 330 members with three devices each | rejected (owner decision 144) |
| Server-only or client-only enforcement | simple | a breach grants anything, or anyone takes names | rejected: both enforce |
| Server-checked evs prefixes or aliases | finer gates | plaintext paths and aliases | ruled out (owner directive 2026-11-03) |
| Admins add vault or mailbox readers | no owner step | silent admin reads | rejected (owner decision 126) |
| Cedar or OPA Rego | expressive | hard to compile to bitsets | rejected |

### 8.14 Decisions proposed

**D-ACL-1 (proposed).** One HuJSON source in the config repo; every sidecar compiles it, and each base's writer compiles the rows. *Why:* no server compiler (owner decision 6).

**D-ACL-2 (proposed).** Deny is the base; grants form a union; hard denies win; tier defaults are starting documents. *Why:* no precedence ambiguity.

**D-ACL-3 (proposed).** `network_client.acl_subject_client_id`, written once at creation, stays nullable until a backfill and validated CHECK (§19.7; connect/CODESTYLE.md:87-88); NULL means itself for a top-level client, else its source client's subject. Every insert writes a value, a top-level client its own id; a child client is its own subject when it asks for `strict_exp` itself and its parent has none, and otherwise takes its source's subject; a child of a legacy child keeps NULL; and the backfill names a sidecar's client by its `sidecar_identity_binding` row (owner decision 355). *Why:* identity without recursive queries.

**D-ACL-4 (proposed).** The in-memory gate checks non-companion contracts forward, passes a non-companion with only the reverse reach as a reply once contract creation finds its origin, checks companions reversed, and skips networks without a head row (8.10). *Why:* R-ACL-8; it closes the origin-free companion path, and connect asks for a same-network reply as a non-companion contract.

**D-ACL-5 (proposed).** Legacy clients are reached only through unrestricted grants, otherwise source-only (owner decision 106). *Why:* only endpoints enforce ports, and Network providers allow everything.

**D-ACL-6 (withdrawn).** Superseded by owner decisions 5 and 6: the config repo and local evaluation replace server compilation.

**D-ACL-7 (proposed).** Requested grants activate within `maxExpiry` only on approvals over the rule's `evidence` channels, harness evidence in a tainted run only where the rule names it (§16.6). *Why:* R-ACL-4, I-8, I-9, owner decisions 74, 75 and 142.

**D-ACL-8 (proposed).** One `Suspend` per subject acts at once at gates and clients, closes its contracts and, for an agent a live Delegation admitted, drops that Delegation's shared reader key (§10.5). *Why:* pitch5.html:729; a suspended agent holding a live shared key would still open what the server delivers to that key.

**D-ACL-9 (proposed).** Failing tests block a config head, and rollbacks are new heads. *Why:* R-ACL-10, I-16.

**D-ACL-10 (proposed).** Shares need two-sided consent and resolve to FriendsAndFamily toward marked sidecars, source-pays (Q-QUOTA-5 (a)). *Why:* the only non-Network mode outside the egress index.

**D-ACL-11 (proposed).** evs grants are per repo (read, write, admin, deposit), from policy or the repo's access log (owner decision 8); prefix writes follow Q-EVS-3. From M6 a general repo may carry prefix rules, which every reader enforces and no server checks (§11.7), naming only subjects an admission fixes and binding the repo's admins too (8.8; owner decision 345); separate repos remain the only boundary a server enforces, and the only one that limits reads. *Why:* the repo is the cryptographic boundary, and X2 hides paths.

**D-ACL-12 (proposed).** Mail authorization follows Q-MAIL-8 (a), split as in §8.10. *Why:* under X6 and X7 no edge sees an alias.

**D-ACL-13 (proposed).** Kind defaults precede every document; owner-bound repos add readers only as §8.5 allows, and policy never widens the config repo's writers. *Why:* R-ACL-11; owner decisions 5, 63, 110 and 126.

**D-ACL-14 (proposed).** Sidecars are subjects in `autogroup:sidecar`, named by `sidecar:<id>`; `RepoReaders` returns sidecar ids. *Why:* agents multiplex onto sidecars (D-CORE-4).

**D-ACL-15 (proposed).** Policy reaches servers only as `AclRows` in §7.9's ProjectionRows, compiled at each base and recompiled by readers; §8.8's grant chains ride the authorization log as statements. *Why:* one signed store (owner decisions 5, 6, 8, 74).

**D-ACL-16 (proposed).** Server gates evaluate only the newest verified base and the entries after it, cached per (network, n) and refreshed by `INCR {acl_<networkId>}v` and a poll. *Why:* owner decisions 5, 6 and 72; R-ACL-8.

**D-ACL-17 (proposed).** Member devices hold leaves, in the config and team directory groups by §7.9's rank (their first 1,000 live member devices) and in another data repo up to 1,000, seated earliest-admitted first, each kept until a Remove; wrapped config and directory members and all other sidecars read through §10.5's per-generation ReaderWraps (§8.12). *Why:* owner decisions 114, 144 and 182: agents cost no commit and read with no member device online, members accept config Adds by one function of the log, and no network stops at 1,000 member devices.

**D-ACL-18 (proposed).** Clients never encrypt to a non-reader (§8.12); the evs gate is D-EVS-18. *Why:* owner decisions 2 and 5 leave no server transaction for a gate.

**D-ACL-19 (proposed).** Subjects are classed before expansion (member device, ephemeral, tagged, other client), and an ephemeral sidecar's evs access takes 8.6's ceiling: the config's and its team directory's read, the directory's own-path writes, kind-default deposits, and grants and EvsShares naming it (8.4-8.6). *Why:* inheritance gave a quick burner its owner's write and admin, while every admitted sidecar reads the config and its team's directory (owner decisions 6, 171).

**D-ACL-20 (proposed).** `autogroup:untagged` is untagged non-sidecars, and writers compile the implicit document into the projection's rules whenever `has_document` is false, so gates and clients evaluate one function (8.5, 8.6). *Why:* two compilers must not publish different rows for one file.

**D-ACL-21 (proposed).** evs and gkm honor a capability (`r`, `rw`, `admin`, `deposit`) only while its subject holds that right on the repo in their newest verified state, gkm's drop-key route included (8.12; §7.9's tokens row). *Why:* a group edit or Suspend must not wait out a 15-minute token.

**D-ACL-22 (proposed).** One consent predicate, §8.5's `consented(d, M)` (scoped, invited, genesis, confirmed, each on a signature outside §7.9's parked set), which §5.6 and §7.9 cite; the invited device is M's first admission in log order that is neither ephemeral nor read-only, carrying the `invited` capability bit its admitting device set after the invite's join MAC verified, from an invite no ephemeral enrollment redeems, and a JIT member's invite comes from the admitting admin device. *Why:* three definitions left JIT members with no consented device, as an ephemeral or read-only first device would, and a stolen device's consents must stop with it.

**D-ACL-23 (proposed).** As an approver, `autogroup:dst-owner` names a request's destination's owner, a tagged sidecar's sponsor, or a socket's listeners' one owner or sponsor, else an admin. The implicit document and Team's starting document carry the directory's default rule: dial on members' devices, tagged sidecars and sockets; approver dst-owner; evidence device or presence; 30 days at most. A touched member who approves meets §8.6's admin requirement (owner decision 180), and an admin's decision counts toward the rule's k only where dst-owner resolves to an admin or the rule's approvers name one (owner decision 349). *Why:* owner decisions 74, 179 and 180: owner decision 74's admin stood in for the touched member, who here consents directly.

**D-ACL-24 (proposed).** The `directory` kind's defaults come ahead of every document, which may neither widen nor narrow them. They give every admitted sidecar of the team read, and every one that is not read_only write of its own paths and stream. §8.6's ceiling admits ephemeral sidecars to both. *Why:* owner decision 171's "members and their agents"; one fixed audience, which policy cannot quietly shrink.

**D-ACL-25 (proposed).** A drop is a repo admin's act, in an owner-bound repo only a consented, not-read-only device of its owner's; a lock refuses and voids drops. *Why:* owner decisions 126, 160, 173 and 183.

### 8.15 Open questions

**Q-ACL-1.** [X3] Who is the policy authority? **Decided by owner 2026-11-03 (owner decisions 3, 5-8, 110):** a customer key authority from v0, compiled on customers' devices, in the config repo (§7.9, §8.7); Q-TRUST-1, Q-TEAM-5 and Q-KEYS-5 follow. *Residual:* none.

**Q-ACL-2.** Cross-cutting (§2). How should team-management.html:814 and :917 describe policy? **Decided by owner 2026-11-03 (owner decision 72):** "signed under your key authority, stored encrypted in your network's config repo. URnetwork enforces an id-only projection: it sees which ids may reach which, never names or rule text," replacing both lines' false claims. *Residual:* none.

**Q-ACL-3 (withdrawn).** Merged into Q-PROTO-3 and Q-QUOTA-5, decided by owner decision 11.

**Q-ACL-4.** What do sidecars get on Community and Pro without a document? **Decided by owner 2026-11-03 (owner decision 105):** untagged sidecars act as app devices until the network writes a policy, tagged ones get §8.5's implicit tagged rules, and owner decision 120 keeps that allow-all, disclosed. *Residual:* none.

**Q-ACL-5.** How do clients without the engine take part? **Decided by owner 2026-11-03 (owner decision 106):** with a policy, legacy clients are reached only through unrestricted grants, otherwise source-only, and listed by `GET /network/clients` (§8.10, D-ACL-5). *Residual:* none.

**Q-ACL-6.** May Community networks write a policy? **Decided by owner 2026-11-03 (owner decision 73):** every tier may, within §20.4's limits (§8.8). *Residual:* none.

**Q-ACL-7.** Who approves requested grants, and for how long? **Decided by owner 2026-11-03 (owner decisions 74, 75):** §8.6's approvers, for 1 h by default and 30 days at most, a lone device's harness prompt counting unless `evidence` excludes it; owner decision 142 (2026-11-04) counts it in a tainted run only where the rule names it. *Residual:* none.

**Q-ACL-8.** Which names may server-stored policy carry? **Decided by owner 2026-11-03 (implied by owner decision 59):** moot; the rows carry ids, opaque atom ids (16 random bytes the config's sealed tables hold beside each name, §7.9), socket token paths (owner decision 67) and public names. *Residual:* none.

**Q-ACL-9.** Cross-cutting (§7, §10). May tagged, ephemeral, CI and cloud sidecars read and write through per-generation X-Wing wraps instead of MLS leaves? **Decided by owner 2026-11-04 (owner decision 114):** (a) yes, in every repo granting them access, amending owner decision 60 (§8.12). A leaf's Remove still waits for a leaf, and a reaped Delegation-admitted agent, or any holder of its reader seed, reads later generations until the Delegation's key drops (§10.5 lists when, `not_after` at the latest); a holder of the whole auth key also admits fresh agents, each with its own wraps, until the Delegation ends (§7.9's delegation row). Owner decision 144 extends config wraps to member devices past §7.9's first 1,000. *Residual:* none.

**Q-ACL-10.** Cross-cutting (§7, §10, §11). Does owner decision 8's "network admins can always grant or revoke" reach owner-bound kinds? **Decided by owner 2026-11-04 (owner decision 126):** (a) no: there admins revoke and add only owner decision 63's visible audit reader, and other readers need the member's signed consent (§8.5), keeping pitch5.html:640's "Sessions open only when the developer shares them", for session contents (owner decision 170). *Residual:* none.

**Q-ACL-11.** Who approves a member's request to reach another member's device, or a tagged sidecar? **Decided by owner 2026-11-05 (owner decision 180):** (a), the destination's owner, or a tagged sidecar's sponsor, through the approver atom `autogroup:dst-owner` in the directory's `requests` rule (8.4, 8.5); §8.6's admin clause is met when the touched member approves, amending owner decision 74 for this case; an admin stands in when the sponsor is gone, and a Team may ask for two approvers (options (b), owner and admin, and (c), an admin alone, not taken). *Residual:* none.

### 8.16 Departures from PLAN.md

- **PLAN.md:119.** Met as owner decision 5 reads it: stored rules are signed and encrypted, and every device gets the whole config in real time through evs subscriptions (owner decision 6).
- **PLAN.md:147** ("participants are leaves"): member devices are leaves, and other sidecars, like member devices past the config and directory groups' first 1,000 (§7.9), read through wraps (Q-ACL-9; owner decisions 114, 144, 182).
- **PLAN.md:74** (networks reach an abstract socket): other networks reach a listener by IP through a share (owner decision 86; Q-BRIDGE-6); application sockets are dialed only within their network (§9.4).

### 8.17 Interfaces

- **Provides:** `sidecar.ParseAclPolicy`, `sidecar.CompileAcl` → `AclRows`, and `CompileAclLocal(input *AclCompileInput) (*AclLocalPolicy, error)` on the same input, which holds what rows drop on purpose (exact socket globs, aliases, per-rule harness naming and names for previews) and is never serialized off the device; read-only `ur acl log` (8.8); `AclState` over an `AclAuthView`, which has no `Suspended`, `AclState.Suspended` answering from the rows' folded Suspends, and gives `Genesis()`, `SidecarIds()`, `CascadeVoids(signer, at)` and `Sidecar(id)` → `AclSidecar{Row, MemberId, TagIds, Ephemeral}`; `AclState.ReapplyStatement` (8.8); `AclEngine.AllowPrefixWrite` (8.12); gate checks `Reach`, `MayListen`, `MayDial`, `MayPublish`, `MaySend`, `EvsAccess` and `RepoReaders` (sidecar ids), each naming its rule or delta; `AclEngine` (`AllowInbound`, `AllowRoute`, `AllowAlias`, which checks `mail:<alias>` at receivers and the local mail server, §17's `BridgeAlias` being a share's delta and no ACL resource, `VerifyRepoMember`, `VerifyHeadSigner`); §8.5's consent rule, the `directory` kind default, and the directory's default rule with `autogroup:dst-owner` (§16.11); §8.8's grant chains and access logs, each EvsShare with its expires, signer and carrying position for §7.9's cascade, and the lock's refusal and voiding of drops (§11.7, §11.13); §8.12's data-repo seats and the directory's; the contract gate's `control` class for witnesses and its remote-search exchanges (§6.4, §11.14); `CanApplyTag` (§7).
- **Consumes:** §4 C13, C18; §5 keys, bindings; §6 `Signed`, push, HeadCheck, Hello's feature bit 0; §7 the config repo, authorization log, projection and its verified read cache, the `leaves` rule, token exchange, removal; §10 MLS; §11 the gate, lifecycle routes and the DROP push and its job (§11.7, §11.13); §13.9's `tls/` `ValidateListen`; §16 `ApprovalDecision`, the spend check, `approval_use` and §16.11's directory requests; §17.9 `WindowDelegation`; §20 limits.
- **Subprotocol messages:** none; §7's `team` hints and `evs:<repo_id>` (§6.8).
- **API routes** (`connect/api/bringyour.yml`, `route_authz.go`), Client class: `POST /acl/ack`, `POST /acl/invite`, `POST /acl/accept-invite` (8.11's claim and completion); grant chains go through §7's `POST /network/config/delta`. No route takes policy text. Internal, by a caller class's bearer: 8.9's `GET /internal/gate/projection/<network_id>`, `/rows/<network_id>/<rows_sha256>`, `/listen-facts/<network_id>` and `/over-limit`.
- **Tables** (api; migrations ≥926): `network_acl_head` (network_id, version, chain, `has_document`: the newest verified n and A_n, a second chain at the head's own version refused as a fork and counted; deleted with its network; after a Postgres restore, api advances it from verified `proj/` entries before the exchange and `CreateContract` reopen, §19.10), `network_acl_share` (code hash, uses, expiry), `network_acl_ack` (client_id, version, ack_time; 7 days); nullable `network_client.acl_subject_client_id`.
- **Services and config:** gates in `api`/`connect`, `sockets`, `evs`, `gkm`, `tlsedge`, `certs`, `dns`, `smtpedge`, `mxedge`; Redis `{acl_<networkId>}v` (48 h after its last change), with §7.9's `{acl_<networkId>}e` read only; `config/all/pro.yml`.
- **Assumptions about other sections:** §7.9 carries §8.8's statements as log entries with its `StatementHeader` and `AuditOptIn` as a k-of-n authority statement, lists `GrantRevoke`, `Suspend` and `Unsuspend` in its auth.proto, takes `OwnerConfirm` and `RecoveryBind` only from consented devices that are not read-only, and has api serve projections to gate services outside the metadata tier (§19.4). §10 follows §7.9's `leaves` rule in the config and directory groups and §8.12's data-repo seats and wraps, counts wrapped config and directory members as key holders, refuses an Add past 1,000 leaves and parks unconsented devices (KF2); §11.12's DELETE and restore require RepoDelete and RepoRestore in evs's newest projection, filed first, and take deletion_id and now from them; §7.9 designs `{acl_}e` with api its only writer, and §22.8's FS-62 loses it and serves it stale; §6.18 and §23.6 ship control contracts with M4's contract gate, and §22.8 runs FS-21's witness case then; §13.9's `ValidateListen` refuses a raw `link` whose grant carries no pin, and §2.8 api-7 lists publish rules' app modes and raw link grants' client-certificate SPKI SHA-256; §5.4 and §18.5 alarm on admissions under a member that its keys did not sign; §7.5's and §7.6's invite joins refuse an ephemeral enrollment; §7.9's SidecarRow keeps each admission's, AdmissionConfirm's and OwnerConfirm's signer and position, and its cascade lifts a park only by a signer outside P; §10.5 drops a live Delegation's key at a `Suspend` of one of its agents, and §7.9 refuses a Delegation-signed admission whose tags differ from the Delegation's; §2.10 and §22.7 cover an admin minting a device under a member, and §22.7 runs the one-definition, consent, grant-replay and seat cases, its cascade case restoring no owner-bound repo by an admin's AdmissionConfirm of a device a P member admitted; §11.7 and §11.13 check a DROP's signer against `AclRepo`'s admins and consented sidecar_ids, never refuse a cancel under a lock, and void at the job's start a drop a lock meets; §16.6 refuses DROP pushes and their cancels; §16.11 files directory requests under 8.5's directory rule, its decisions citing 8.8's receipts; §6.4's receivers accept SEARCH on a control contract only at Hello feature bit 0; FS-85 runs `autogroup:dst-owner`'s approvals, every reader refusing an admin's vault `EvsShare`, and a share's `expires` ending it with no device online; and FS-19 runs the ceiling: under an Admin in a personal network, the config read and deposits, no other repo's generation, and its config head and base refused, with no evs `rw` on the config (M2-out); Delegation-admitted, the config's next generation by its own ReaderWrap after a DelegationRevoke; tagged and in a Pro network, a read grant or vault EvsShare opening exactly its repo, its removal a shrink (M4-out); a Team network's Member and Admin runs, the team directory read with writes to its own paths only, and a member invite refusing an ephemeral enrollment (M6-out); and a quick burner's mailbox EvsShare opening exactly its repo (M8-out).

### 8.18 Risks

| risk | likelihood | impact | mitigation |
|---|---|---|---|
| `CreateContract` regression | Medium | High | one map miss without a head row; PostgreSQL tripwire test; benchmark gate |
| Gate-cache fan-out on each log entry | Medium | High | per-process caches; coalesced reloads; jitter |
| Gates run a stale or divergent projection | Medium | Medium | readers recompile rows; HeadCheck compares (n, A_n); any writer republishes |
| ACL and MLS roster drift | Medium | High | client invariant; versioned gate; drift alarms |
| A rogue or compromised admin admits a device under a member | Medium | High | §8.5's consent; KF2 parks it; the member's devices alarm |
| A data repo granted to more than 1,000 member devices seats only 1,000; the rest wait keyless | Low | Medium | the preview and console name the repo; seats fill earliest-admitted first; data-repo wraps would need the owner (owner decision 144); the team directory seats past 1,000 by wraps instead (owner decision 182) |
| Network sources reach LAN and loopback without a document, or through legacy providers | High | High | disclosed (owner decision 120); any tier may write a document (owner decision 73); unrestricted-grant rule; suspension |
| Approval fatigue | Medium | Medium | 30-day requests; standing grants; presence keys |
| A `resolve` row goes stale: a member leaves, or a network's alias moves | Medium | Low | validation refuses a member_id with no live MemberRow, so the row fails closed until the next save; a network's id stays pinned until a person saves again (§8.8's Saving) |

### 8.19 Phasing

- **v0 (§23.4):** at M2, `AclRows`, grant chains and access logs, every 8.8 statement, `GrantActivate`, `GrantRevoke`, `Suspend` and `Unsuspend` among them, being checked and folded from M2 (`RepoDelete` and `RepoRestore` included; an `EvsShare` opens an owner-bound repo only with §16.8's read receipts, D-MCP-18, and ends at its `expires`, which every reader honors from M2), acl.proto's `autogroup:dst-owner` atom, which readers evaluate from M2, as the implicit document's directory rule names it, the `directory` kind's default (8.5; D-ACL-24), compiled from the binary as every kind default is, so a device on M2-M5 code admitted to a team network computes the directory's readers, writers and erasers as M6 code does (D-PHASE-9), and `RepoVersioning`'s id-level fields and lock, folded from M2 (D-PHASE-9), local evaluation, the evs and gkm gates with current-reader scopes, member leaves by §7.9's rule and agent wraps (owner decisions 114, 144), §8.5's consent rule, the ephemeral ceiling, whose config read FS-19 gates at M2-out, policy tests, rollback and change audit; at M4, the filing flows of requested grants and suspension, the contract gate with its `control` class for witnesses, and the closing of open contracts, which C13 seals from M4 (D-PROTO-18); other gates with their services. Blocked by X8 (§6), §5's binding, §7.9's config repo and authorization log, §10's MLS, §11's `config` kind and, for window clients, §4's C13.
- **v1 (M6):** team networks (owner decision 55), with two-approver rules, scope hosts, the audit reader (owner decision 63) and config wraps for member devices past §7.9's first 1,000 (owner decision 144); the team directory itself, created with each team, its seats under §7.9's leaves rule and Team's starting document's default rule with `autogroup:dst-owner` (owner decisions 171, 180, 182); cross-network shares (Q-PROTO-3, Q-QUOTA-5, C18); peer-list filtering (`server/connect/resident.go:4826`); client-checked prefix writes (Q-EVS-3 (a); 8.8's RepoPrefixRules, §11.7).
- **v1 at M10 (owner decision 169):** `RepoVersioning` (§11.7) with storage format 2 (owner decision 163), enforcing the lock M2 folds, which also refuses and voids drops (owner decisions 173, 183); the `control` class's remote search (owner decisions 175, 178).
- **Later:** client-attested postures (team-management.html:847-850).
