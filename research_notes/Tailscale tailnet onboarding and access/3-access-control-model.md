# Tailscale Tailnet Access-Control Model (ACLs / Grants / Tags / Posture)

*Research current as of 2026-11-01. Tailscale restructured its docs from `/kb/<number>/` paths to `/docs/...` paths; both forms often still resolve. Grants reached General Availability on 2025-05-29, so as of this writing grants have been the GA-recommended model for ~17 months. Where a claim bears on what the control plane must know to enforce policy (relevant to recURd's blind-network goal), it is flagged in the Inferences sections — this is analysis, not a recURd design proposal.*

## The policy file: HuJSON format, structure, location, and editing

### Takeaway
A tailnet has exactly one policy file, written in HuJSON (JSON with comments and trailing commas), edited in the admin console JSON/visual editor, via the API, or via GitOps. It holds all access rules plus supporting definitions (tags, groups, hosts, ipsets, SSH, posture, tests). Only Owners/Admins/Network admins can edit it.

### Cited Findings
- The tailnet policy file is written in **human JSON (HuJSON)**, which permits `//` comments and trailing commas; Tailscale links its own `tailscale/hujson` library — [Policy file syntax reference](https://tailscale.com/docs/reference/syntax/policy-file). (HuJSON is Tailscale's name for the JWCC — JSON With Commas and Comments — profile; the page itself says "HuJSON," not "JWCC.")
- Top-level sections documented: `grants`, `acls`, `ssh`, `sshTests`, `tests`, `autoApprovers`, `nodeAttrs`, `postures`, `tagOwners`, `groups`, `hosts`, `ipsets`, `derpMap`, `disableIPv4`, `OneCGNATRoute`, `randomizeClientPort` — [Policy file syntax reference](https://tailscale.com/docs/reference/syntax/policy-file).
- `groups` names start with `group:` and **cannot contain other groups**; `hosts` are named aliases for an IP/CIDR (names cannot contain `@`); `ipsets` are named collections of IPs/CIDRs/hosts/autogroups/other ipsets — [Policy file syntax reference](https://tailscale.com/docs/reference/syntax/policy-file).
- The policy file is edited on the admin console **Access controls** page, which offers a **JSON editor**, a **visual policy editor**, and a **Preview rules** tab to check what a change permits — [Migrate from ACLs to grants](https://tailscale.com/docs/reference/migrate-acls-grants); [Visual policy editor](https://tailscale.com/docs/features/visual-editor).
- Editing the policy file is restricted to **Owner, Admin, or Network admin** roles — [ACL tests search summary of policy-file docs](https://tailscale.com/docs/reference/syntax/policy-file).
- The file can be managed as code via **GitOps**: Tailscale publishes the `tailscale/gitops-acl-action` GitHub Action; the default filename is `policy.hujson`; the repo should be **private** because the file contains PII such as user email addresses; a workflow runs `action: test` on PRs and `action: apply` on merges to main — [GitOps for Tailscale with GitHub Actions](https://tailscale.com/docs/integrations/github/gitops); [GitOps blog](https://tailscale.com/blog/gitops-acls).
- GitOps auth can use an **OAuth client** (`oauth-client-id` + `audience`, or + `oauth-secret`), **federated identity**, or an **API key** — [GitOps for Tailscale with GitHub Actions](https://tailscale.com/docs/integrations/github/gitops).
- To prevent direct edits in the admin console, admins can **lock the editor** on the Policy file management page; an admin can still override in an emergency via an **"Edit anyway"** option — [GitOps for Tailscale with GitHub Actions](https://tailscale.com/docs/integrations/github/gitops).
- Tailscale also documents GitOps for **GitLab CI** and **Bitbucket Pipelines**, and supports custom Actions/CI tools — [GitOps for Tailscale with GitHub Actions](https://tailscale.com/docs/integrations/github/gitops).
- The policy file is also readable/writable through the **Tailscale API** (ACL endpoint) — [Tailscale API reference](https://tailscale.com/docs/reference/tailscale-api).

### Inferences
- There is a single authoritative policy document per tailnet (not per-device config); all selectors reference entities the control plane already knows (users, groups, tags, hosts, ipsets). **recURd flag:** for the control plane to evaluate this file it must hold the mapping of identities, group memberships, and device→tag assignments — i.e., the server knows *who* and *what role* each client is, even though it need not see traffic contents.

### Gaps
- I did not fetch the exact API endpoint path/verb for reading/writing the policy file (commonly `GET`/`POST /api/v2/tailnet/{tailnet}/acl`), so I am not asserting the exact route; see the [API reference](https://tailscale.com/docs/reference/tailscale-api).

## Grants (newer model) vs legacy `acls`: what changed, syntax, migration, recommendation

### Takeaway
Grants are the recommended, GA (2025-05-29) successor to ACLs. They are a superset of ACL capability: same HuJSON file, same deny-by-default, but they merge ports+protocol into one `ip` field, drop the mandatory `action`, and add application-layer capabilities (`app`) and routing control (`via`). ACLs still work indefinitely and both can coexist, but only grants get new features.

### Cited Findings
- Grants went **GA on 2025-05-29**, announced as "Tailscale's next generation of access controls that combine network and application capabilities into a single syntax" — [Grants GA blog, dated May 29, 2025](https://tailscale.com/blog/grants-ga).
- **Grants are "feature complete" with ACLs**; "the primary difference is that grants will continue to receive new features and improvements, while ACLs will not" — [Grants vs. ACLs](https://tailscale.com/docs/reference/grants-vs-acls).
- Grants are **recommended for new tailnets and for updating existing deployments**; ACLs are suggested only for existing deployments heavily reliant on ACL syntax, tools expecting that format, or older integrations — and even then Tailscale recommends gradual migration — [Grants vs. ACLs](https://tailscale.com/docs/reference/grants-vs-acls).
- Comparison: ACLs operate "exclusively at the network layer"; grants cover network **and** application layers. ACLs have no application capabilities; grants do. ACLs are not routing-aware; grants are, via `via`. Both support device posture. ACLs require explicit `"action": "accept"`; grants imply accept — [Grants vs. ACLs](https://tailscale.com/docs/reference/grants-vs-acls).
- "You never have to update your existing rules"; "We will support our original ACL syntax forever"; ACLs and grants can be used together in the same policy — [Grants GA blog](https://tailscale.com/blog/grants-ga); coexistence also confirmed on [Grants feature page](https://tailscale.com/docs/features/access-control/grants) and [Grants vs. ACLs](https://tailscale.com/docs/reference/grants-vs-acls).
- **Field-by-field migration mapping**: `acls`→`grants`; `"action":"accept"`→removed; `src`→`src` (unchanged); `dst` with `tag:x:port`→`dst:["tag:x"]` plus `ip`; `proto`→prefixed to port in `ip` (e.g. `"tcp:443"`); `srcPosture`→unchanged; new `app` and `via` fields — [Migrate from ACLs to grants](https://tailscale.com/docs/reference/migrate-acls-grants).
- Before/after example — ACL `{"action":"accept","src":["group:eng"],"dst":["tag:web-server:443"],"proto":"tcp"}` becomes grant `{"src":["group:eng"],"dst":["tag:web-server"],"ip":["tcp:443"]}` — [Migrate from ACLs to grants](https://tailscale.com/docs/reference/migrate-acls-grants).
- Other conversions: `dst:["tag:web-server:80","tag:web-server:22"]`→`ip:["80","22"]`; `dst:["tag:database:*"]`→`ip:["*"]`; CIDR `dst:["192.0.2.0/24:22"]` + `proto:["tcp"]`→`dst:["192.0.2.0/24"]`, `ip:["tcp:22"]` — [Migrate from ACLs to grants](https://tailscale.com/docs/reference/migrate-acls-grants).
- Admin console has a **"Convert to grants"** button (Access controls → JSON editor → "Convert ACLs to grants"); it replaces the `acls` section with an equivalent `grants` section, **takes effect immediately with no confirmation dialog**, is disabled when there is no `acls` section, and changes are recorded in configuration audit logs (so it can be reverted) — [Migrate from ACLs to grants](https://tailscale.com/docs/reference/migrate-acls-grants).
- Migration caveats: **split one ACL that targets multiple tags into one grant per tag** (otherwise every port is granted to every tag); include all ports when consolidating; omit the protocol prefix if the ACL had no `proto`; check for overlapping grants; **keep SSH rules in the `ssh` section in their original format during migration** — [Migrate from ACLs to grants](https://tailscale.com/docs/reference/migrate-acls-grants).

### Inferences
- The acls→grants transition is additive and non-breaking by design; an enterprise can run mixed policy during a multi-quarter migration. The practical "recommended now" answer as of Nov 2026 is unambiguously **grants**.

### Gaps
- The migration doc does not address legacy `users`/`ports` ACL fields (older than `src`/`dst`); no conversion guidance given for those.

## Grants syntax, deny-by-default, port/protocol and app-capability scoping

### Takeaway
Each grant has `src`, `dst`, and at least one of `ip` (network) or `app` (application), plus optional `srcPosture` and `via`. Access is denied unless a grant allows it; matching grants are unioned (more specific grants add, never override). App capabilities are opaque JSON that clients enforce.

### Cited Findings
- A grant object fields: `src` (array), `dst` (array), `ip` (array), `app` (object), `srcPosture` (array, optional), `via` (array, optional). All fields except `app` are arrays. Each grant needs `src`, `dst`, and **`ip`, `app`, or both** — [Grants syntax reference](https://tailscale.com/docs/reference/syntax/grants).
- **Deny-by-default**: "Access is denied unless a grant allows it"; grants imply an `accept` action; grants "follow Tailscale's deny-by-default approach, aligned with zero trust and least privilege" — [Grants syntax reference](https://tailscale.com/docs/reference/syntax/grants); [Grants feature page](https://tailscale.com/docs/features/access-control/grants).
- **Union semantics**: when several grants match, the engine takes the **union** of their capabilities; "more specific grants add to broader ones and don't override them"; app capabilities apply only when the device already has network-level access — [Grants syntax reference](https://tailscale.com/docs/reference/syntax/grants).
- **`ip` port/protocol forms**: `*` = all ports (implies TCP, UDP, ICMP); `443` or `80-443` = port/range (implies TCP/UDP/ICMP); `tcp:443` or `tcp:80-443` = protocol + port/range; `icmp:*`, `sctp:*` = all ports for a protocol. Protocols may be named aliases (`tcp`,`udp`,`icmp`,`gre`,`esp`,`ah`,`sctp`, …) or IANA numbers 1–255 — [Grants syntax reference](https://tailscale.com/docs/reference/syntax/grants). Example: `"ip":["tcp:443","udp:53"]` — [Grants feature page](https://tailscale.com/docs/features/access-control/grants).
- If `ip` is omitted, the source has **no network-layer access** unless another rule grants it — [Grants syntax reference](https://tailscale.com/docs/reference/syntax/grants).
- **`app` capabilities**: keys use `<domainName>/<capabilityName>` (e.g. `tailscale.com/cap/tailsql`); `tailscale.com`/`tailscale.io` are reserved for Tailscale; custom capabilities should use a domain you control. Parameters are **opaque JSON** — the policy engine only validates that they are valid JSON; **clients enforce** them and the app developer documents them — [Grants syntax reference](https://tailscale.com/docs/reference/syntax/grants); [Application capabilities](https://tailscale.com/docs/features/access-control/grants/grants-app-capabilities).
- Legacy ACL protocol numbers (`proto`): `igmp`=2, `ipv4`/`ip-in-ip`=4, `tcp`=6, `egp`=8, `igp`=9, `udp`=17, `gre`=47, `esp`=50, `ah`=51, `sctp`=132; numbers 1–255 accepted; ports apply only to TCP/UDP/SCTP; clients need v1.18.2+ for `proto` — [Policy file syntax reference](https://tailscale.com/docs/reference/syntax/policy-file).

### Inferences
- **recURd flag:** The split is meaningful for a blind network — `ip` filtering is enforced in each node's packet filter (the control plane only needs identities/ports, not payload), but `app` capabilities are enforced by the *client application* reading opaque JSON the control plane merely syntax-checks. So application-layer authorization does not require the server to understand the capability's meaning, only to distribute the JSON to the right clients.

### Gaps
- None material for this question.

## Tags (`tag:`): non-human identity, tagOwners, how devices get tagged

### Takeaway
Tags give non-user devices (servers, ephemeral nodes) an identity and let policy follow a device's role. Tags are defined by their `tagOwners` entry; only owners can apply a tag. A device's identity is the union of all its tags, and tag identity and user identity are mutually exclusive.

### Cited Findings
- Tags "authenticate and identify non-user devices, such as servers and ephemeral nodes"; two purposes: give identity to non-user devices, and manage access policy by purpose; framed as "essentially service accounts, but with more flexibility" — [Group devices with tags](https://tailscale.com/docs/features/tags).
- There is no separate "tag" section: tags are defined by their owners in **`tagOwners`**. Example: `"tag:server": ["dave@example.com"]`. Owners can be **users, groups, or other tags** (e.g. `"tag:prod-2": ["tag:deployment-1"]`) — [Group devices with tags](https://tailscale.com/docs/features/tags).
- A tag with an **empty owner list** (`"tag:infrastructure": []`) is valid; its implicit owners are **Owners, Admins, and Network admins**, who can apply any tag even if not listed as owners — [Group devices with tags](https://tailscale.com/docs/features/tags).
- Tag ownership can be chained, but **applying a tag via another tag works only for direct ownership** (if `tag:a` owns `tag:b` and `tag:b` owns `tag:c`, a device authed as `tag:a` cannot receive `tag:c`). Tag names are case-insensitive, parsed lowercase — [Group devices with tags](https://tailscale.com/docs/features/tags).
- **How devices get tagged**: (1) **Auth keys** carrying pre-assigned tags, e.g. `tailscale up --auth-key=<key> --advertise-tags=tag:prod-2` (requested tags must be owned by, or exactly match, the key's tags); (2) **Admin console** → Machines → "Edit tags" (tag must already exist in policy); (3) **CLI** `--advertise-tags` on `tailscale login`/`up` (comma-separated; empty `--advertise-tags=` removes all; Linux/macOS/Windows only); (4) **API** POST to the device tags endpoint with `{"tags":["tag:foo","tag:bar"]}` — [Group devices with tags](https://tailscale.com/docs/features/tags).
- **Identity is the combination (union) of all a device's tags**, not the intersection; each tag's policy applies. A tagged device must keep **at least one tag** — [Group devices with tags](https://tailscale.com/docs/features/tags).
- **User identity and tag identity are mutually exclusive on one device**: "It's impossible for a user account identity and a tag identity to exist on the same device." Applying a tag to a user-authed device removes the user; re-authing with a user removes all tags (this is the "ownership transfer to tags" behavior) — [Group devices with tags](https://tailscale.com/docs/features/tags).
- Tags are intended **only for non-human machines**; do not tag laptops/phones. Tagged devices can SSH only to other tagged devices (not user devices) — [Group devices with tags](https://tailscale.com/docs/features/tags).
- On the receiving node, the connection's source owner is determined from the source's Tailscale IP; a tagged device's connection identity is its set of tags — [Tags search summary / Tailscale identity](https://tailscale.com/docs/concepts/tailscale-identity).

### Inferences
- **recURd flag:** Tags are the mechanism for giving *agents/non-human clients* a durable, policy-addressable identity. The control plane must store and vouch for the device→tag binding (who owns which tag, which device carries which tag) to compile per-node filters — so tag-based authorization is inherently a control-plane trust function, independent of traffic visibility.

### Gaps
- None material; "ownership transfer to tags" is documented as behavior (user identity replaced by tag) rather than a named feature.

## Groups and autogroups

### Takeaway
`group:` entries are admin-defined user lists (no nesting). Autogroups are built-in dynamic selectors for roles (`admin`, `member`, `owner`, admin sub-roles), device state (`tagged`, `shared`), relationship (`self`), and destinations (`internet`). Some autogroups are plan-gated.

### Cited Findings
- `group:<name>` = admin-defined list of users; groups **cannot contain other groups** — [Policy file syntax reference](https://tailscale.com/docs/reference/syntax/policy-file).
- **Autogroups by plan availability** — Any plan: `autogroup:internet`, `autogroup:self`, `autogroup:owner`, `autogroup:admin`, `autogroup:member`, `autogroup:tagged`, `autogroup:shared` (src only), `autogroup:nonroot` (SSH users). Standard/Premium/Enterprise: `autogroup:auditor`, `autogroup:billing-admin`, `autogroup:it-admin`, `autogroup:network-admin`. Premium/Enterprise: `localpart:*@<domain>` (SSH users). All plans (domain-based): `user:*@<domain>` (src or dst). Source-only: `autogroup:danger-all` (includes sources outside the tailnet) — [Policy file syntax reference](https://tailscale.com/docs/reference/syntax/policy-file).
- Key autogroup meanings: `autogroup:member` = all tailnet members (users, not tagged devices); `autogroup:tagged` = any tagged device; `autogroup:self` = a user's own devices (use with a `src` of a role/group/individual user); `autogroup:internet` = reach the internet through exit nodes (destination); `autogroup:shared` = devices of users who accepted a share invite — [Grants syntax reference](https://tailscale.com/docs/reference/syntax/grants); [Policy file syntax reference](https://tailscale.com/docs/reference/syntax/policy-file).
- **Legacy**: `autogroup:members` (plural) still works but is replaced by `autogroup:member`; the two cannot be used together — [Policy file syntax reference](https://tailscale.com/docs/reference/syntax/policy-file).
- Admin sub-role autogroups (`auditor`, `billing-admin`, `it-admin`, `network-admin`) usable as both `src` and `dst` — [Policy file syntax reference](https://tailscale.com/docs/reference/syntax/policy-file).

### Inferences
- `autogroup:self` is the primitive for "each user reaches only their own devices" without enumerating devices — the control plane resolves ownership at compile time. **recURd flag:** self/ownership scoping requires the server to know the user→device ownership graph.

### Gaps
- Exact additional autogroups not surfaced here (e.g. any newer ones) beyond the list above; the policy-file reference is authoritative if more exist.

## ACL/policy tests and validation; avoiding lockout

### Takeaway
`tests` (network/ACL/grant) and `sshTests` are assertions embedded in the policy file that run on every change; a failing assertion causes Tailscale to **reject** the new policy. There is no built-in "don't lock out the admin" check — that is a manual test pattern. CI (GitOps) runs the same validation before merge.

### Cited Findings
- `tests` = assertions about ACLs and network grants with fields `src`, `proto`, `accept`, `deny`; `sshTests` = assertions about SSH rules with `src`, `dst`, `accept`, `check`, `deny` — [Policy file syntax reference](https://tailscale.com/docs/reference/syntax/policy-file).
- Tests **run each time the policy file changes**; if an assertion fails, Tailscale **rejects the updated policy file with an error**; purpose is to ensure you "don't accidentally revoke important permissions or expose a critical system." A single test can assert both accept (allowed to one dst) and deny (blocked to another) — [ACL tests search summary of policy-file/acl-edit docs](https://tailscale.com/docs/reference/syntax/policy-file).
- Tests can be added in the admin console Access controls page (list destinations that should be accessible and those that should be blocked) — [ACL tests search summary](https://tailscale.com/kb/1338/acl-edit).
- In CI, the **test step sends the policy file to Tailscale to validate the policy and run all tests**; a failure prevents the merge from continuing — [GitOps for Tailscale with GitHub Actions](https://tailscale.com/docs/integrations/github/gitops).
- The admin console **Preview rules** tab lets you confirm a (migrated) policy grants expected access before saving — [Migrate from ACLs to grants](https://tailscale.com/docs/reference/migrate-acls-grants).

### Inferences
- **Lockout avoidance is a manual pattern, not a feature**: to guard against cutting off admins, write explicit `accept` tests for an admin source against key admin destinations; the test harness will then reject any edit that would break that path. (The docs describe tests generically; I found no dedicated "admin lockout" safeguard.)

### Gaps
- No source confirms an automatic safeguard that prevents an admin from removing their own access; the protection is only as good as the tests you write.

## Tailscale SSH: SSH ACLs, check mode (re-auth), session recording

### Takeaway
Tailscale SSH is governed by the policy file's `ssh` array: rules with `action: accept` or `action: check` (periodic re-auth), `src`/`dst`/`users` selectors, `checkPeriod`, and `acceptEnv`. SSH needs both a network rule (port 22) and an SSH rule. Posture via `node:os == 'js'` governs the SSH Console. tsrecorder session recording is now deprecated in favor of Tailscale PAM.

### Cited Findings
- SSH rules live in the `ssh` array. `action` is `"accept"` (admit already-authenticated tailnet users) or `"check"` (require periodic re-auth per `checkPeriod`) — [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh).
- `src`: user, group, tag, `user:*@<domain>`, or autogroup — **cannot be bare `*`**. `dst`: user, tag, or autogroup — **cannot be bare `*`**; no port (only port 22). `users`: usernames that must already exist on host, plus `autogroup:nonroot` (any non-root user) and `localpart:*@<domain>` (maps login local part to host user) — [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh).
- `checkPeriod`: applies only to `check` rules; accepts minutes/hours from **1 minute to 168 hours**; default **12 hours**; `"always"` forces re-check every connection (warned to disrupt automation like Ansible). A 2024 bug treating `"checkPeriod":"0s"` as unset was fixed (now prompts every connection) — [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh); [SSH check-mode search summary](https://tailscale.com/docs/features/tailscale-ssh).
- `acceptEnv`: allowlists env-var names clients may send via `SendEnv`/`SetEnv`; supports `*` and `?` wildcards; requires host Tailscale **v1.76.0+** — [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh).
- **Check rules are evaluated before accept rules**; if both match, the check rule applies and its `users` list alone governs access — [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh).
- Permitted connection types: user→own devices (any user incl. root); user→tagged device or shared tagged device (any user incl. root); **tagged device→tagged device** (and an SSH rule with a **tagged source cannot use `check` mode**) — [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh).
- **Default SSH policy** (unmodified tailnet): a `check` rule from `autogroup:member` to `autogroup:self`, `users` = `autogroup:nonroot` and `root`. Editing overrides this default; removing SSH rules disables Tailscale SSH — [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh).
- **Two rules required**: a network grant/ACL must allow port 22 (also used to distribute WireGuard keys), and a separate `ssh` rule must allow the SSH connection + users; default network policy allows all devices — [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh).
- Check-mode re-auth happens on the initiating device through the IdP (may trigger MFA); after re-auth a user can reach any device for the default 12h; a custom `checkPeriod` applies only to that connection's target. Policy changes removing access take effect within seconds and end existing sessions ("Access revoked") — [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh).
- **SSH Console** (web/`js`) connections are subject to posture; to allow them, posture must include `node:os == 'js'` — [Device postures and attributes](https://tailscale.com/docs/features/device-posture/postures-and-attributes).
- **Session recording (deprecation)**: the current session-recording page states Tailscale **no longer offers Tailscale SSH session recording through `tsrecorder`**; support for existing users is scheduled to **end August 2027**; Tailscale directs users to **Tailscale PAM** or Sales — [Tailscale SSH session recording](https://tailscale.com/docs/features/tailscale-ssh/tailscale-ssh-session-recording). **Conflict:** the visual-editor reference and the compliance-recording guide still describe recorder setup, where a rule names a recorder tag and, if no recorder is specified, the session is not recorded; `enforceRecorder: true` makes recording fail-closed (deny/stop sessions when recorders are unreachable), vs the default fail-open — [SSH recording search summary](https://tailscale.com/docs/use-cases/infrastructure-access/record-ssh-sessions-compliance). Treat the deprecation notice as current.

### Inferences
- **recURd flag:** SSH authorization is doubly control-plane-dependent — the server compiles both the network filter (port 22) and the SSH-specific rule, and `check` mode re-auth round-trips through the IdP/control plane. A blind-network design cannot reproduce `check`-mode re-auth without a trusted identity authority in the loop.

### Gaps
- The main SSH page does not show `srcPosture` in the `ssh` rule; posture governance of SSH is documented via the posture page (`node:os == 'js'` for Console). The policy-file reference lists `srcPosture` as an `ssh` field, so it is supported, but I did not capture an `ssh`+`srcPosture` example.

## Device posture management

### Takeaway
Postures are named sets of assertions over device attributes (built-in `node:`/`ip:`, `custom:`, and EDR/MDM integrations), defined in `postures` and referenced from rules via `srcPosture` (or tailnet-wide `defaultSrcPosture`). Posture applies only to the source. Some posture capabilities are plan-gated (geolocation Standard+; custom attributes Premium/Enterprise).

### Cited Findings
- Posture attributes are **key-value pairs** (string/number/boolean/IP) in namespaces: `node:` (host info reported by devices), `ip:` (control-plane geolocation of the device's public IP), `custom:` (set via API or OAuth provisioning), plus integration-sourced attributes. Viewable under **Attributes** on a device's Machine Details page — [Device postures and attributes](https://tailscale.com/docs/features/device-posture/postures-and-attributes).
- **Posture attributes are distinct from `nodeAttrs`**: `nodeAttrs` are flags only (e.g. `funnel`, `randomize-client-port`), not key-value pairs; `nodeAttrs` entries target devices by identity (tag/user/group/`*`) and can carry an `app` field for app-connector-style capabilities — [Device postures and attributes](https://tailscale.com/docs/features/device-posture/postures-and-attributes); [Node attributes vs. grant app capabilities](https://tailscale.com/docs/reference/node-attributes-vs-app-capabilities); [Policy file syntax reference](https://tailscale.com/docs/reference/syntax/policy-file).
- Choose `nodeAttrs` when a capability is true of the device regardless of what it connects to; choose a **grant `app` capability** when it applies only along a specific source→destination path — [Node attributes vs. grant app capabilities](https://tailscale.com/docs/reference/node-attributes-vs-app-capabilities).
- **Posture definition syntax** (object form, recommended): each posture name is prefixed `posture:`; an `assertions` array where each assertion is `attribute operator value`; optional `onFailure` with `showAlerts` (`"badge-in-console"`,`"warn-in-client"`,`"notify-in-client"`) and `endUserMessage`. A device must satisfy **every** assertion. Example: `"posture:latestApple": { "assertions": ["node:os IN ['macos','ios']", "node:tsVersion >= '1.98'"], "onFailure": {...} }` — [Device postures and attributes](https://tailscale.com/docs/features/device-posture/postures-and-attributes).
- **Operators**: `==`, `!=`, `IN`, `NOT IN`, `IS SET`, `NOT SET`; `<`,`<=`,`>=`,`>` only for numbers and version attributes (`node:osVersion`, `node:tsVersion`). If an attribute is unset, the posture does **not** match even with a negative operator — [Device postures and attributes](https://tailscale.com/docs/features/device-posture/postures-and-attributes).
- **New features (monitoring/failure alerts) are only available in the object-based syntax**, not the legacy array syntax — [Device posture search summary of postures docs](https://tailscale.com/docs/features/device-posture/postures-and-attributes).
- Named built-in attributes seen: `node:os`, `node:osVersion`, `node:tsVersion`, `node:tsAutoUpdate` (true only when Tailscale's built-in auto-update is on), `ip:publicAddress` (geolocation, **beta**; supports `IN`/`NOT IN`/`==`/`!=` with IP/CIDR/ipset) — [Device postures and attributes](https://tailscale.com/docs/features/device-posture/postures-and-attributes).
- **Referencing**: postures apply as a condition on a rule via `srcPosture`; `defaultSrcPosture` applies to rules with no posture condition and is **not additive** — a device need satisfy only one listed posture (e.g. `"defaultSrcPosture": ["posture:basicWindows","posture:basicMac","posture:basicLinux"]`). **Posture applies to `src` only, not `dst`** — [Device postures and attributes](https://tailscale.com/docs/features/device-posture/postures-and-attributes); [Grants feature page](https://tailscale.com/docs/features/access-control/grants).
- **Limitations**: posture conditions do **not** restrict traffic from shared nodes or from devices behind subnet routers (those pass if they match IP-based conditions) — [Device postures and attributes](https://tailscale.com/docs/features/device-posture/postures-and-attributes).
- **Custom attributes** set via the Tailscale API (posture attributes API, `GET /device/{deviceId}/attributes` is the referenced path) or assigned during OAuth-app provisioning; integrations named include **CrowdStrike Falcon** (docs link to a broader EDR/MDM integration list) — [Device postures and attributes](https://tailscale.com/docs/features/device-posture/postures-and-attributes).
- **Audit logging of posture**: event "Update device attribute" (target "Node changed") is logged; changes to built-in `node`/`ip` attributes are logged only if a posture references them; custom and third-party integration attribute changes are always logged — [Device postures and attributes](https://tailscale.com/docs/features/device-posture/postures-and-attributes).
- **Plan gating** — confirmed: geolocation (`ip:`) attributes require **Standard/Premium/Enterprise** — [Device postures and attributes](https://tailscale.com/docs/features/device-posture/postures-and-attributes). Per the ACL/posture feature-table summary: `nodeAttrs` on all plans; built-in posture attributes on all plans; **third-party (EDR/MDM) posture attributes require Standard+**; **custom posture attributes require Premium/Enterprise** — [Posture search summary of ACL feature table](https://tailscale.com/docs/features/device-posture/postures-and-attributes). *(These last three come from a search summary of the feature-usage-by-plan table, not a page I fetched directly — moderate confidence; verify against the live plan table.)*

### Inferences
- **recURd flag (important):** Posture enforcement requires the **control plane to collect and evaluate device attributes** — `ip:` geolocation is computed by the control plane; `node:` host info is reported by devices to the control plane; `custom:`/integration attributes are pushed to the control plane via API/EDR/MDM. The server must therefore *know a great deal about each client's device state* to gate access, even if it never sees traffic contents. A network that aims to stay blind cannot do posture gating without a trusted party holding these attributes.

### Gaps
- The posture page's full built-in attribute list (e.g. `node:tsReleaseTrack`, serial numbers, disk-encryption/compliance keys from specific integrations) was not fully captured; only the named examples above are confirmed. Exact per-attribute plan gating beyond geolocation is from a feature-table summary, not directly verified.

## Network segmentation primitives as they appear in access-control policy

### Takeaway
Subnet routers, exit nodes, app connectors, and Tailscale Services appear in policy as: destinations/routes gated by grants; `autoApprovers` for auto-approving advertised routes/exit nodes/Services; the grant `via` field (tags only) to force traffic through specific routers/connectors; `autogroup:internet` as an exit-node destination; and `svc:<name>` as a Service destination.

### Cited Findings
- **`via`** (grants) controls the routing path through exit nodes, subnet routers, or app connectors; it **accepts only tags**; routers must be accessible to the user per the policy; to allow any path, omit `via` or set `[]`/`null` — [Grants syntax reference](https://tailscale.com/docs/reference/syntax/grants).
- **`autogroup:internet`** is a destination selector meaning "use exit nodes to reach the internet" — [Grants syntax reference](https://tailscale.com/docs/reference/syntax/grants); [Grants feature page](https://tailscale.com/docs/features/access-control/grants).
- **`svc:<serviceName>`** is a destination selector for a **Tailscale Service** (grants also list `svc:web-server` as a special destination selector) — [Grants syntax reference](https://tailscale.com/docs/reference/syntax/grants); [Grants feature page](https://tailscale.com/docs/features/access-control/grants).
- **`autoApprovers`** section lets listed identities approve **subnet routes, exit nodes, and Services** without manual admin approval — [Policy file syntax reference](https://tailscale.com/docs/reference/syntax/policy-file).
- A **CIDR in `dst` controls which traffic is permitted but does not inject routes**; routes come from approved subnet routers — [Grants syntax reference](https://tailscale.com/docs/reference/syntax/grants).
- **App connectors** are expressed in `nodeAttrs.app` (the connector reaches, e.g., example.com on behalf of the tailnet regardless of which device sends traffic, so the capability describes the connector device) — [Node attributes vs. grant app capabilities](https://tailscale.com/docs/reference/node-attributes-vs-app-capabilities).

### Inferences
- Segmentation in Tailscale is enforced at the *destination/route* level in the same deny-by-default grant engine; `via` adds a routing constraint (traffic must traverse a named router tag), which is how an enterprise forces, e.g., all access to a subnet through an audited gateway.

### Gaps
- I did not fetch the dedicated `grants-via` page or the Services (`svc:`) definition page, so exact `via`/`svc:` worked examples and the Service definition schema are not captured here. Subnet-router/exit-node advertisement mechanics (CLI `--advertise-routes`/`--advertise-exit-node`) are device-side and flagged as out-of-scope (device-join).

## Enforcement architecture (how policy becomes enforced) — bears on blind-network relevance

### Takeaway
Tailscale's control (coordination) server compiles the central policy into per-node IP:port filter rules and distributes them to each client in its network map; each node enforces its own filter locally at decryption time, with the coordination server not in the data path. This is the crux of "what the server must know."

### Cited Findings
- "The control server compiles the policy into IP:port filter rules for each machine," delivered to clients via the **network map**; firewall rules specified in terms of machine tags and user groups are compiled by the control server into "a custom set of filter rules for each machine" — [How Tailscale works](https://tailscale.com/blog/how-tailscale-works).
- **Rule enforcement happens on each device directly, without further involvement from Tailscale's coordination server**; enforcement is at decryption time; if no `accept` rule exists, traffic is rejected; ACLs are deny-by-default, directional, and locally enforced — [Manage permissions using ACLs](https://tailscale.com/docs/features/access-control/acls).
- The coordination server distributes each node the **public keys of the peers it may talk to** (key distribution is separate from policy); data flows over WireGuard, so the **control plane is not in the data path** — [Key management in the Tailscale control protocol](https://tailscale.com/blog/tailscale-key-management).
- The grants policy engine likewise "sends rules to clients, which … independently check permissions without relying on the coordination server" — [Grants blog](https://tailscale.com/blog/acl-grants).

### Inferences
- **recURd flag (core):** Even though Tailscale's data plane is end-to-end encrypted (WireGuard) and the control plane is not in the data path, **the control plane must know identities, group memberships, device→tag bindings, and device posture attributes** in order to *compile* each node's filter. Access-control enforcement is thus centralized at policy-compilation time and decentralized at packet-filter time. For a design that wants the network "blind," the facts the server must hold to enforce Tailscale-grade ACLs are: user identity, role/group membership, tag ownership and assignments, approved routes/exit nodes, and (for posture gating) device attributes. The *content* of traffic is never needed by the control plane; the *metadata and identity graph* is.

### Gaps
- None material; this is well-corroborated across primary blog + ACL docs.

## Network flow logs and configuration audit logs (verifying access)

### Takeaway
Configuration audit logs (who changed what, incl. policy edits) are on by default for all plans, 90-day retention, not disableable. Network flow logs (connection metadata, never content) are Premium/Enterprise. Both can stream to SIEM/storage.

### Cited Findings
- **Configuration audit logs**: record who changed what and when; enabled by default for all tailnets; available for the most recent **90 days**; cannot be turned off; available on **all plans**; viewable on the admin console Logs page or via API (token scope **`logs:configuration:read`**) — [Configuration audit logging](https://tailscale.com/docs/features/logging/audit-logging).
- **Network flow logs**: capture connection **metadata, not traffic contents** ("Tailscale never logs the content of network traffic, and does not have access to it"); available on **Premium and Enterprise**; enabled via admin console Logs tab; API scope **`network-logs:read`** — [Network flow logs GA blog](https://tailscale.com/blog/network-flow-logs-is-generally-available); [Log streaming](https://tailscale.com/docs/features/logging/log-streaming).
- **Streaming**: both log types can stream to a SIEM/storage bucket over HTTPS; network flow logs must be enabled before adding a network-log streaming destination; private (in-tailnet) endpoints supported — [Log streaming](https://tailscale.com/docs/features/logging/log-streaming).
- Policy-relevant audit events include the "Convert to grants" action (recorded, revertible) and device attribute updates (posture) — [Migrate from ACLs to grants](https://tailscale.com/docs/reference/migrate-acls-grants); [Device postures and attributes](https://tailscale.com/docs/features/device-posture/postures-and-attributes).

### Cited Findings — conflicts on plan gating of streaming
- Streaming docs say **log streaming is Premium/Enterprise**; an older S3 blog said config-audit-log streaming is on Personal/Personal Plus/Enterprise and network-log streaming on Enterprise; the changelog says config-audit-log streaming is now available to the **Free** plan. These conflict — verify against the current pricing page — [Logging search summary](https://tailscale.com/docs/features/logging/log-streaming).

### Inferences
- **recURd flag:** Network flow logs demonstrate the metadata the control plane can reconstruct (source/dest/ports/times) without payload access — the same identity/connection metadata the enforcement model already requires. Verifying access ("did policy allow/deny X") relies on this server-visible metadata graph, not on traffic contents.

### Gaps
- Exact current plan gating for log *streaming* is contradictory across sources (see conflict above); the pricing/plan table is the authority and was not fetched.
