## 7. Networks, teams, members, enrollment, and SSO

### 7.1 Purpose and scope

This section owns the server's identity model (networks, members, roles, invitations, Team SSO, SCIM), enrollment, credentials, sponsors and names, scoped tokens, revocation objects and edge login, the admin audit log, the P0 fix against client tokens administering their network, and the config repo with its authorization log and read cache, X3's membership half (owner decisions 3, 5-8, 110, 112-114, 126-129, 136, 144, 149). §8 owns policy, gate rows and owner consent, §10 MLS and the write gate, §6 HeadCheck, §11 the `config` kind, §5 local keys, §20 counting.

### 7.2 Requirements

| id | requirement | source |
|---|---|---|
| R-TEAM-1 | No client token administers its network; sidecar-held tokens expire and renew only by ClientKey proof | server/AUTHZ1.md:3-6; D-TRUST-3; owner decision 131; Q-CORE-4 |
| R-TEAM-2 | Many users per network, no member-device cap; seven roles; free read-only seats | PLAN.md:5,363; TM:1118-1124; sidecar/design/improvements4.md:251; owner decision 144 |
| R-TEAM-3 | Invitations; one person in several networks | TM:288-292,375 |
| R-TEAM-4 | Per-network OIDC SSO, verified domains, SCIM; Team only | PLAN.md:363; TM:384-629 |
| R-TEAM-5 | User and device approval; pre-approved keys skip it | TM:477-544,775-799 |
| R-TEAM-6 | Reusable, ephemeral, pre-approved and tagged auth keys; OAuth clients; QR and MDM join | TM:648-771; RA:930 |
| R-TEAM-7 | Tags and groups as policy principals | TM:835-880 |
| R-TEAM-8 | Agent tokens ≤1 h, held by the sidecar; a sponsor the IdP can kill | FB:139; MK2:425-443 |
| R-TEAM-9 | A breached server adds no reader; admins alone add none to owner-bound repos but the audit reader | P5:745; TM:939-1012; owner decisions 3, 126 |
| R-TEAM-10 | Admin audit log, export, SIEM | TM:1021-1029 |
| R-TEAM-11 | Removal revokes a member or device everywhere, MLS included | P5:729 |
| R-TEAM-12 | New credential paths send the security notice | server/model/security_notice_api_key.go:3-7 |
| R-TEAM-13 | Released names cannot be taken over | [R:server-identity] §5 |
| R-TEAM-14 | Published names are authenticated by default | P5:698; §13.7 |

### 7.3 What exists today

| Fact | Citation | Limit |
|---|---|---|
| One `admin_user_id` per network, assumed fixed by 133 reads in 51 files; no member, role, group or tag table | server/db_migrations.go:351-360; server/session/by_jwt.go:659-700 | every client's user is the admin |
| 30-day ByJwt; with `reject_expired` off an expired token passes, a root- or session-claim one until `exp` + 60 d (`AcceptUntil`); window clients never refresh | server/session/by_jwt.go:496-502; session_state.go:15,30-48; AUTH.md:224-229; connect/ip_remote_multi_client_api.go:1023-1046 | no expiring sidecar token |
| `GET /auth/refresh` (Client) takes no proof; `POST /network/auth-client` (OwnClient) mints client tokens; payment routes take them | server/api/route_authz.go:115, :132, :192-232 | a copied token renews, mints and spends |
| OAuth: code and refresh grants, `mcp:*` scopes, ID tokens, ES256 keys apart from jwt.yml; `oauth_client` has no network | server/oauth/handlers.go:120-148; keys.go:3-13; token.go:190-223 | no client-credentials, exchange or device grant |
| 27 AppAdmin routes take client tokens except on Embed networks; code-create yields a network login, which outlives a removed API key | server/api/route_authz.go:122-131,365-394; server/session/AUTH.md:157-169, :202 | the P0 gap |
| `audit_network_event` logs only network create and delete | server/db_migrations.go:286-294 | no admin log |

### 7.4 P0: a client token never administers

**Stage 1** of owner decision 45's fix, before any sidecar ships: `refuseClientAdmin` (server/api/route_authz.go:365) also refuses child and admin-refused clients on the 27 AppAdmin and 10 OwnClientPayout routes, and a fail-closed allowlist confines `strict_exp` bearers:

```go
func refuseClientAdmin(ctx context.Context, byJwt *session.ByJwt) bool {
	return networkRefusesClientAdmin(ctx, byJwt.NetworkId) ||
		clientRefusesAdmin(ctx, byJwt.NetworkId, *byJwt.ClientId)
}
```

```text
allowlist  a strict_exp bearer reaches only:
             GET /auth/refresh and POST /network/auth-client, each with the proof below; children inherit
               both marks
             POST /network/remove-client, for its own client or children
             GET /key/<id>; POST /connect/control (connect/api.go:508)
             routes route_authz.go classifies sidecar: those §5-§21 add (/sidecar/*, /network/config/*,
               /network/enroll, /network/bridge/share/*, /acl/*, POST /approval/cancel, /tls/*, /mail/*,
               /smtp/*, /socket/*, /dns/*, GET /abuse/status) and POST /oauth/token's exchange; each route's
               own class still applies, so /smtp/appeal and /mail/direct-mx stay refused
           every other route answers 403 "A sidecar token cannot call this route." (403, so the sdk does not
           sign out): no payment, purchase, redemption, rename, account, stats, provider or extender route;
           TestSidecarTokenRoutes runs §22.7's S1-S10 and an approval cancel with the allowlist on, so a
           missing route fails a test
preview    (D-TRUST-3) until stage 2 is live in an environment, POST /network/enroll and /network/auth-client
           refuse strict_exp: true outside config/<env>/sidecar.yml's preview_networks
auth code  auth_code gains api_key_id; /auth/code-login refuses a code whose key is removed; the network token
           it mints carries the key's id, and removing the key revokes it (server/session/AUTH.md:202's gap)
```

- **Check.** `model.ClientRefusesAdmin` is true for a child (`source_client_id IS NOT NULL`), an `admin_refused` owner row, or a lookup error; no owner row means a legacy client. Both facts are immutable and cached. No shipped client sends a child token here (server/AUTHZ1.md §4), so 14 days log-only (`urnetwork_auth_child_admin_calls_total`) precede enforcement.
- **Mark.** `POST /network/enroll` and `/network/auth-client` take `admin_refused: true` and `strict_exp: true`, which `sidecar` and `sdk/sidecar.go` always send, and a marked client's children inherit both (§5). App device clients minted `admin_refused` (§18.7), and so their window clients, carry no `strict_exp`.
- **Expiry (D-TEAM-14, owner decisions 103, 131).** `strict_exp` tokens carry a 7-day `exp` and the root claim (server/session/AUTH.md:229), enforced by session's one verifier, used by every API route, the exchange and connect's transport auth, whatever `reject_expired` or `AcceptUntil` say; past `exp`, a sidecar re-enrolls under its `sidecar_id`. Window clients, which never refresh, keep today's lifetime until fleet-wide expiry follows app adoption (server/session/AUTH.md:234-238).
- **Proof (Q-CORE-4).** A `strict_exp` bearer proves its ClientKey to renew, exchange or mint:

  ```text
  where     GET /auth/refresh, POST /oauth/token's exchange, POST /network/auth-client
  proof     DPoP (RFC 9449): header {typ dpop+jwt, alg EdDSA, jwk};
            claims {jti, htm, htu, iat, ath = SHA-256(token)}
  key       the client's newest sidecar_identity_binding key (§2.8 api-5), else enroll's client_public_key;
            with none bound, refused
  replay    SET {dpop_<client_id>}<jti> 1 NX EX 120; iat within ±60 s
  sdk       Api.SetDpopSigner(func(method, url, ath string) (string, error)), installed by sdk/sidecar.go from
            the core's ClientKey before D-CORE-8's core refresher is switched off on any host; a strict_exp
            refresh without a signer is not sent (unenrolled, not proofless)
  residual  until transport auth takes the proof (later), a copied token authenticates a connect transport as
            its client until exp, at most 7 days: it receives the client's hints and can displace its resident,
            while peers refuse it at Hello for lack of the identity key
  ```
- **Stage 2**, before the first desktop sidecar and after the app and extension releases (§18.7, D-SDK-11) that stop persisting a readable network credential, `.auth_state`'s and the extension's `by_jwt` in `chrome.storage.local` (extension/src/background/index.ts:134, :201-206), which the moved routes still take: `/auth/code-create`, `/auth/add-auth`, `/auth/remove-auth`, `/auth/regenerate-seedphrase`, `/auth/generate-seedphrase` and `/auth/network-delete` become `routeAccessNetwork` (server/api/route_authz.go:122-131; sdk/api_network_credential.go:57), refusing app device tokens that same-user agents can read (owner decision 47); until then `ur` refuses to enroll beside either store (§5.6, D-TRUST-3).
- **Stage 3, the hard gate** (server/session/AUTH.md:164-169): all 27 AppAdmin routes refuse client credentials once under 1% of active app clients send them there for 14 days, or `upgrade_required` enforces SDK `bc72b109`.

### 7.5 Networks, members, roles, invitations

**Networks (owner decisions 23, 55, 59).** A team is one network whose members' sidecars are its clients, beside members' personal networks. `POST /network/team-create` (Q-TEAM-2) adds `network_team` (§20), kept for the network's life, sets `admin_user_id` to a synthetic owner-of-record and makes the caller the first Owner, so every human is removable. That Owner's bootstrapping device (7.9), after the config repo's first base, files the team directory's `RepoCreate{repo_id, kind directory}` (§8.8) and becomes its repo admin, beside every config writer; an admin device that finds a team without one files it, api and readers refuse a second, and api one outside the `team` tier (§16.11; owner decision 171; D-TEAM-28). Team routes (members, invitations, IdPs, domains, SCIM, OAuth clients, admin events and audit webhooks; 7.17) check `NetworkTierOf` (§20.5) and refuse a network outside the `team` tier with §20's `QuotaRefusal` (`upgrade`).

**Members.** `network_member.member_id`, new per join, rides in tokens and `rev/` objects, so a re-invite never revives an old token.

**Roles.** One per member, signed in the config repo (`AdminSet`, under k of n, for the table's first four, which sign config records; else `MemberAdmit`) and mirrored by the server. `routePermissionByRoute` maps the 75 Network and AppAdmin routes to permissions, unmapped ones owner-only; API keys and OAuth tokens get scopes ∩ their creator's.

| Role | May |
|---|---|
| Owner | all, including deletion, the IdP and the admin set |
| Admin | members, roles, admissions; policy, tags, groups, DNS, edge, versioning rules; keys, OAuth clients; read |
| Network admin | policy, tags, groups, DNS, edge, versioning rules; keys for owned tags; read |
| IT admin | admissions; untagged keys; read |
| Billing admin | billing, payouts; read |
| Auditor | read (settings, clients, audit) |
| Member | own devices |

**Invitations.** `POST /network/member-invite {email, role, expire_days ≤30}` stores a hashed token for a sign-in with that email; the link's fragment, never sent to the server, carries the genesis hash and authorization pin (7.9), the inviter's device key and a one-time secret MACing the join request an admin device admits; api and that device refuse an ephemeral client's join, so the invite stays unspent and the member's first device from it is never ephemeral (§8.5's invited clause). A token names one network (server/IDP.md §2); `POST /auth/network-switch` honors the target's sign-in rule.

### 7.6 SSO, domains, JIT, SCIM

- **OIDC only** (Q-TEAM-4): `network_idp` rows; code flow with PKCE S256, `state` and `nonce`; `private_key_jwt` or a vault-encrypted secret. Identity is `(idp_id, sub)`, never email (OIDC Core §5.7); just-in-time (JIT) provisioning links an existing user only after that user completes a login with its existing credential in the same flow, never by email alone (D-TEAM-23), and a team IdP authenticates only its network.
- **Domains.** TXT `_urnetwork-challenge.<domain>` (TM:601), rechecked daily, dropped after 7 failed days, one network per domain; `POST /auth/sso-discover` routes verified domains to their IdP, and SSO-required teams refuse other sign-ins.
- **JIT and SCIM** (Team v1, Q-TEAM-3). A first IdP login creates a `pending` member, since unsigned IdP data adds no reader; the admin device that admits it issues an invite to the IdP-verified email, from which the member's first device enrolls (§8.5). Without SCIM, `network_member.reauth_deadline` (7 d) bounds access after IdP disablement. SCIM 2.0 (RFC 7643/7644) at `/scim/v2/<network_id>/` takes a hashed bearer: `active=false` denies at once and queues a `MemberRevoke` (7.10); until an admin device signs it, members still encrypt to that member's devices, which the console lists, unless `ServiceSettings.scim_signer` names an admin's indexer (§3.6; owner decision 150), which signs such removals of members outside the AdminSet at once (D-TEAM-25). Group changes queue, each up to 7 days for an admin device; roles never sync (TM:450-468).

### 7.7 Clients: owners, names, tags, groups, approval

- **Owner.** `network_client_owner`, set at mint: `owner_user_id`, `member_id`, `sponsor_user_id`, `auth_key_id`, `tagged`, `ephemeral`, `admin_refused`, `strict_exp`, `acl_enforcing` (Q-ACL-5), `declares_no_egress` (§20.8), `acl_subject_client_id` (D-ACL-3), deleted with its client. A tagged client's sponsor is its admitting member until an admin's `SponsorSet` (7.9, owner decision 83), which `sponsor_user_id` mirrors.
- **Names** are DNS labels keyed on the `sidecar_id`, duplicates taking `-2`, `-3` in admission order (RA:948-971); private names derive from them (owner decision 85, §12.9). Signers and verifiers refuse reserved names and owners (§12.5, §12.7), word-number labels (§15.9) and scope labels (§13.8) as client names, and client names as publishes or scope labels.
- **Tags** (`tag:[a-z0-9-]{1,50}`), set at admission within §8's `tagOwners` so a change re-admits, and **groups** of members (`group:<name>`, or SCIM's `group:<name>@<domain>`) live in the config repo (owner decision 46). **Approval** is admission: an unadmitted client holds no grants (§8).
- **Ephemeral** clients: at the mint api inserts `network_client_lease{client_id, seen_time = now, close_sha256}` and returns the close capability once (7.8); one with no open connection is reaped once its newest disconnect and its lease's `seen_time` are both over 35 min old, so 30-36 min after its last poll and 35-36 min after its last disconnect, or at once on `POST /sidecar/close` with that capability (§18.8; Tailscale: 30-60 min, https://tailscale.com/kb/1111/ephemeral-nodes); their evs access is §8.6's ceiling, which keeps every sidecar's config read (owner decision 6).

### 7.8 Credentials and scoped tokens

| Credential | Lifetime | Acts as |
|---|---|---|
| Auth key `ur-authkey-<id>-<secret>`, plus, when pre-approved, a client-only `#<bundle>` (TM:695), the bearer hashed; also QR and MDM (TM:755-771) | 5 min to 90 d; max uses | creator, or its tags |
| OAuth client `ur-oauth-<id>` + `ur_sk_<secret>` (TM:737), for CI | until revoked | its scopes |
| API key `urn_…`, gaining scopes, expiry and creator | ≤365 d (legacy: none) | creator ∩ scopes |
| Admin token (aud = API), for `ur admin` and the console | 1 h; DPoP-bound; one command, bound by its `cmd` digest and used once (below) | member ∩ scopes |
| Service token (aud = evs, gkm, dns, certs or mail) | 15 min (owner decision 2) | the client |

```text
POST /network/enroll {auth_key, client_public_key, device_spec, declares_no_egress,
                      admission?}                                Public; limited per key and IP
  -> {by_client_jwt, client_id, approval_state, admin_refused,   no_genesis: tagged or ephemeral, before base 1
      close?}                                                    close (/network/auth-client's too): an
                                                                 ephemeral mint's capability, 128 random bits
                                                                 returned once, api keeping its SHA-256 (7.7)
ur-authkey-<id>-<secret>[#<base64url(AuthKeyBundle)>]            QR and MDM carry the same string
  <id>-<secret>  the bearer: the only auth_key enroll sends
  #<bundle>      client-only, like an invite's fragment (7.5): never sent, logged or passed to MCP; a request
                 body holding its prefix is refused before sending; redaction covers both parts
  AuthKeyBundle{version 1, genesis_sha256, head AuthPin (7.9), delegation_id, delegation_signing_seed (32 B),
                delegation_reader_seed (32 B), tag_ids}, ~200 B; the daemon signs its own SidecarAdmit with the
                Delegation's key (a scoped statement: exactly its tag_ids and, unless ephemeral, a not_after no
                earlier than the Delegation's; 7.9), keeps only the reader seed (§5.6), erases the rest; every
                other copy of the string keeps both seeds, so it admits until the Delegation ends and reads
                until its key drops (7.9's delegation row, §10.5)
POST /oauth/token  grant_type=urn:ietf:params:oauth:grant-type:token-exchange
     subject_token=<by_client_jwt>  subject_token_type=urn:ur:params:oauth:token-type:client-jwt
     resource=<service URI>  scope=<within the service's>  DPoP: <proof by the ClientKey>
  -> access token {aud, scope, proj_v (log position n, 7.9), ur_client_id, ur_subject_client_id,
                   ur_sidecar_id, member_id, act?}
     at most 64 repo: scopes, keeping the bearer under the lb's 8 KiB header line
     (warp/warpctl/config.go:1299); 300 repos cost 5 exchanges per audience per 15 min
```

- **Enrollment** creates a top-level client with owner or `tagged`, sponsor, the mark and `acl_subject_client_id` (counted by §20.8), replacing RA:930's unscoped, unexpiring `urn_` key (server/apikey/apikey.go:20-53); pre-approved keys carry the genesis hash, head and a Delegation's signing and reader seeds only in a client-only `#<bundle>` that the client splits off before any request (D-TEAM-22); the enrollment request has no field for it, and `POST /network/enroll` refuses an `auth_key` containing `#`.
- **OAuth clients** use `client_credentials` on `network_oauth_client` with scopes `devices:core`, `auth_keys`, `policy:read`, `logs:read`, `all` (TM:737-748); CI pairs `auth_keys`' ≤1 h keys with its Delegation. A Delegation's `not_after` is required, at most 90 days; CI and cloud Delegations default to 30 and are replaced, not extended.
- **`ur-cli`** is the public client of `ur login` and `ur admin` (loopback PKCE, RFC 8252, or the RFC 8628 device grant) with code-matched consent, fresh `auth_time` and one-command DPoP tokens (§5.7); v0 ships only single-use auth keys of ≤5 min (§5.6):

  ```text
  admin token  {aud api, member_id, scope, cnf.jkt (the DPoP key's thumbprint), jti, exp <= 1 h,
                cmd = base64url(SHA-256(method || 0x00 || path || 0x00 || JCS(body)))}       JCS: RFC 8785
  consent      the authorization request carries the command (RFC 9396 authorization_details), shown on the
               consent page; the token binds its digest
  api          checks DPoP's htm and htu, recomputes cmd from the request and refuses a mismatch; in the
               command's own transaction inserts admin_token_use(jti PRIMARY KEY, member_id, cmd, result,
               time); a replay of the jti returns the stored result; rows go 1 h after exp (§2.8 api-11)
  ```
- **Token exchange** (RFC 8693) checks the ClientKey's DPoP proof (RFC 9449; 7.4's proof rule, jti single-use), refuses expired subject tokens and inactive, reaped or unadmitted clients (an unadmitted client of member M may get only `recovery:<member_id>` at gkm, for M's own recovery wraps, 7.9), and never issues the API audience. evs and gkm capabilities (`scope=repo:<id>:r|rw|admin|deposit`, owner decision 2) come from §8's rows in the newest projection: a read-only sidecar gets only `r` scopes and §16.8's receipt deposit, whatever else it is; readers of an owner-bound repo who are not its writers also get `repo:<id>:deposit` for receipts (§16.8); member devices other than read-only ones get gkm `rw` on the config group (7.9's `commit`); in a team network every admitted sidecar that is not read_only gets `repo:<directory>:rw` (read_only ones `r`), and only the directory's admins, its creator and the config writers, each consented (§8.5) and not read_only, get its `admin`, which alone carries its ERASE, CUT and CLOSURE pushes, their `?closure=1` uploads and `POST .../slots/delete`, as in every repo: evs cannot see whose copies a key covers, so it checks the authority before any key mutation (§11.12, §16.11). **Re-seed mode** (§19.10): while `sidecar.yml`'s `reseed` is true and the network's log has not resumed (7.9's site loss), the exchange mints only `repo:<id>:admin`, honored only by evs's `POST /evs/v1/repos/<id>/reseed` and gkm's GroupForm, to the sidecars the restored rows list under the network's Owners and Admins, and answers other requests `restore_required`. Tokens stay in the daemon (I-7), but for §11's v1 read-only git view.
- **Keys.** Admin, service and ID tokens use disjoint ES256 key sets (`kid` prefixes `adm-`, `svc-`, `id-`), private to api's issuer, `auth.bringyour.com` (owner decisions 16, 108; server/oauth/keys.go:3-13).
- **Notices.** New credentials, IdPs, domains, Delegations and admin-set changes notify Owners and Admins; auth codes carry their `api_key_id`, so removing the key ends the code and its network token, closing server/session/AUTH.md:202's gap (7.4). Tokens are never stored (§2.8 api-11).

**Revocation objects** (owner decision 2):

```text
rev/<network_id>/<kind>/<subject_id>/_     kind: client | sidecar | member
  where  the first metadata cluster, beside place/ (owner decision 145), whatever cluster a repo is on
  write  api, on removal, deactivation, suspension or token revocation: If-None-Match to create,
         If-Match to raise not_before
  body   a JWS under api's svc- key set, which evs and gkm already hold: {subject, not_before, reason, time}
  check  evs and gkm GET the token's three subjects on each write and on streams over 60 s, cached
         <= 5 s; a token issued before not_before is void
  life   taskworker deletes it 20 min after its last write, since service tokens live 15 min; after
         a site loss api re-creates live ones from its tombstones (§19.10)
```

**Edge login** serves §13.7's `members` audience (Q-TLS-7), making the issuer an authority (§2.8 EX8).

```text
visitor  GET https://<host>.<net>.<root>/        TLS ends in the sidecar's front (§13.7)
front    no session: sets __Host-ur-pre {state, nonce, PKCE verifier}; 302 to
         <issuer>/oauth/authorize?client_id=https://<host>.<net>.<root>&scope=openid
           &redirect_uri=https://<host>.<net>.<root>/.well-known/ur/callback&nonce&state
issuer   accepts the origin only while the projection holds an active members publish grant
         for <host> in network N (§8); signs the visitor in (team IdP if required); refuses
         anyone but an active member of N
front    redeems the code: ID token {iss, aud = origin, network_id = N, nonce, exp = 60 s,
         sub = member_id (the owner's user_id in a personal network)}, id- key set
front    checks signature (issuer JWKS), aud, nonce = cookie, exp, and the member in its
         config; sets __Host-ur-session (HttpOnly, Secure, SameSite=Lax, 12 h)
front    counts that session only on same-origin requests and top-level GET or HEAD navigations
         (§13.7's Other origins row), since SameSite cannot separate networks while all of
         <root> is one site (§12.4); other requests arrive anonymous
```

### 7.9 The config repo: customer-held key authority (X3)

From v0, admin keys sign membership and policy, and clients refuse any peer or rule not derivable from signed inputs, so a breached server can only deny or delay, within §2.8's exposure bound, though its gates see the reach graph (owner decisions 3, 5-8, 72, 110).

**Repo.** One evs repo of kind `config` (§11.12) per network holds the records below, tags, groups, device names, policy (§8), bridge rules (§17), §17.9's `BridgeShareSigner` files (each accepted share's ShareSigner seed and ShareCert, which a config-writing ShareKey holder replaces per config generation) and the socket-name key (owner decision 67). Config writers, the AdminSet members' member devices that are not read_only, write its heads; every admitted sidecar, ephemeral ones included (§8.6's ceiling), reads all of it (owner decision 6) but owner-bound repos' versioning rules (below), so CI and cloud agents' sidecars hold the policy, the emails it names, the AdminSet, `K_sock` and each accepted share's ShareSigner seed, though MCP returns neither the config's contents nor a `secret` repo (§16.6); the server holds ciphertext and the authorization log.

```text
record (sidecar/protocol/config.proto; Genesis, MemberRevoke and       signer
  SidecarRevoke in bridge/auth.proto, below; §6 Signed, purpose authority)
Genesis{network_id, config_repo_id, owner member_id (user_id in a
        personal network), owner sidecar_id and key, time}            owner's first device (TOFU)
AdminSet{owners, admins, network_admins, it_admins: [member_id],       authority
         threshold k}
MemberAdmit{member_id, role: billing_admin | auditor | member}         an Owner or Admin; authority if the
  | MemberRevoke{member_id}                                              member is in the AdminSet
SidecarAdmit{network_id, sidecar_id, identity_public_key, identity_alg, an Owner, Admin or IT admin, or scoped;
             member_id | tag_ids, ephemeral, not_after (agents only),    authority for an AdminSet member's
             capabilities (bit 1 read_only)}                             device; owner-bound reads need §8.5's
  | SidecarRevoke{sidecar_id, reason: lost | reaped | removed |          consent (owner decision 126)
                  compromise, since_n}
AdmissionConfirm{sidecar_id}                                           any signer allowed to admit it
SponsorSet{sidecar_id, sponsor_member_id}                              an admin (owner decision 83)
IndexerSet{sidecar_id, scope: network | member, retire, services:      network: an Owner or Admin; member: a
           [mail, mirror, search; embed later], sealed}                consented device (§8.5) of the subject's
                                                                       member; retire: also the subject itself
RecoveryBind{member_id, xwing_public_key, ed25519_public_key,          the member's consented device (§8.5);
             prev_sha256 (the replaced binding's key hash),            authority for an AdminSet member; in
             genesis_sig (Recovery's anchor)}; RecoveryRebind{...,     the log only member_id, reason,
             reason: routine | lost | compromise} succeeds it          prev_sha256 and SHA-256 of the Ed25519
                                                                       key show, the rest sealed as rule
                                                                       bodies are (§17.8)
KeyRegister{member_id, key_id, alg (webauthn-es256 | ecdsa-p256-sha256 the member's consented, approval-capable
            | ssh-ed25519), public_key, attestation,                    device after a device or presence
            purpose (presence | sshsig), not_after}                     decision, never harness (a first
  | KeyRevoke{key_id}                                                    presence key: after a /dev/tty-
                                                                         confirmed command or in ur login),
                                                                         carrying the new key's own presence
                                                                         signature (§16.6); a presence key's
                                                                         KeyRegister or KeyRevoke from a device
                                                                         that registered a live one carries its
                                                                         countersignature (presence, below)
Delegation{pubkey, reader_xwing_public_key (§10.5), tag_ids,           owner, admin, or tag-owning network
           max_admits, not_after (required, <= 90 d; 7.8)}              admin
  | DelegationRevoke{delegation_id, since_n: 0, or for a leaked
                     bundle the position from which it parks}
ServiceSettings{team_mail: indexers | member scopes (owner             owner or admin; directory from v1
                decisions 58, 150; §15.5, §15.6); stale_leaf_days:     (M6)
                90 (§10.9's stale Removes); self_admit: on (owner
                decision 112; device-signed self-admission only);
                witness_bound_hours: 72, 24 to 168 (D-TRUST-10,
                owner decision 129); scim_signer: none | the
                sidecar_id of an admin's indexer (7.6); directory:
                {runs: auto | prompt | off (auto), workers: on |
                off (on)}, a Team's defaults for run and worker
                announcements (§16.11; owner decisions 170, 171),
                reserved in config.proto at M2}
VersioningRules{rules: [{kinds, repo_ids, path_glob,                   an Owner, Admin or Network admin
                         size_above_bytes, versioning: on | off}]}
  ordered, first match wins, an empty selector matching all and
  unmatched paths staying versioned; absent, the platform rule
  [{size_above_bytes: 64 MiB, off}]; v1, its type reserved at M2:
  format-1 readers apply nothing from it but still apply the head
  holding it (owner decision 164; §11.7)
AuthorityProposal{statement_type, statement}                           the first counted signer, or the
                                                                         recovery key
AuthorityCosign{proposal_id}                                           each further counted signer; a recovery
                                                                         key's restarts the window (Recovery)
RecoveryVeto{proposal_id}                                              an AdminSet member's admitted device,
                                                                         the subject's others included; never
                                                                         the proposed device or a read_only
                                                                         one; countersigned as presence asks
ProjectionHeader (below)                                               a config writer at S(n-1)
statements enter the authorization log as entries (below); api's ticks carry reaps and recovery activations

authority  k distinct counted signers among the newest AdminSet's n Owners and Admins (default k = 2 if n >= 3,
           else 1), an AdminSet member's existing device counting as one for its own new device
           (owner decision 112) and for revoking another of its own devices (§5.6; 7.10's stale row); each
           signs from an admitted device or with its recovery key, which counts as one of the k under the
           recovery window: a statement with a recovery-key signature, in its proposal or a cosign, is pending,
           delivering no key to the proposed device, until an api tick 72 h after the entry of its newest such
           signature, with k signatures and no valid veto (owner decision 127), so at k = 1, as in personal
           networks, a recovery key acts alone after the window; a removal's target never counts, the revoked
           device itself or a MemberRevoke's member (counted); each signer's presence key countersigns as the
           presence row asks (owner decisions 185, 187)
scoped     the member's consented device (§8.5), for its own untagged devices, at once, admitting them only
           while self_admit is on (owner decision 112) and revoking them always (7.10); its recovery key admits
           them at once, or with self_admit off on one admin's cosign (owner decisions 62, 126), either only
           through Recovery's window under a binding a void restored (owner decision 149); a tag owner's
           device, for its tags; a Delegation, which admits up to max_admits (counted in log order, rows
           keeping the count for its life) and never re-delegates, each admission carrying exactly its tag_ids
           and, unless ephemeral, a not_after no earlier than its own, until it ends (delegation, below)
commit     in the config group and the team directory's (leaves) the signer of an admission or revocation,
           or after api's reap of an uncovered ephemeral agent the device that signed its admission (7.10),
           commits what it requires even if it is no config writer: a leaf-entitled device's Add, a leaf's
           Remove and its rotation, or a wrapped reader's first wrap or rotation; a wrapped signer only wraps
           and rotates (below); a recovery-admitted, leaf-entitled device self-joins by external commit (owner
           decisions 113, 128), under a binding that takes no wrap once its ReaderWrap passes Recovery's
           anchor (restored); so no membership change waits for an admin, and in the config group the
           exchange gives member devices other than read_only ones gkm rw, while evs rw stays with config
           writers
readers    agents (tagged, ephemeral, CI, cloud) and member devices past the first 1,000 below read the config
           and the team directory by per-generation X-Wing wraps at no commit (owner decisions 114, 144, 182,
           amending 60); Delegation-admitted agents read at once by the Delegation's reader key (§10.5; 7.18),
           which also covers them in their Delegation's repos, so they hold no wraps of their own there;
           §20.4's 5,000 Team admissions count member devices and agents alike, with no member-device cap
leaves     (owner decisions 144, 182) in the config group and in the team directory's, its own MLS group
           (§16.11; D-KEYS-23), member devices (untagged, not ephemeral) that are admitted and not revoked
           (nor their member), parked or suspended rank by (live_since, sidecar_id), live_since being the
           position at which one last became so: its admission, its recovery activation, or the
           AdmissionConfirm, OwnerConfirm or Unsuspend that restored it; the first 1,000 are leaf-entitled,
           each group's MLS leaves (D-KEYS-2); the rest read each by ReaderWraps as agents do (~1.3 KB each
           per rotation) and stay leaves of their data repos, each still at most 1,000 leaves
  move     a newly live device ranks last, so one that stays live never loses entitlement; one restored before
           its Remove commits ranks last too and, if that leaves it unentitled, the next leaf commit removes it
           for lost entitlement (§10.9) as it reads on by wraps; when a leaf-entitled device stops being live,
           the first wrapped one by rank becomes leaf-entitled at that position and keeps its wraps until a
           leaf that may commit it (a writer leaf, or the revocation's signer) adds it, with the Remove or at
           its next commit; an entitled device without a KeyPackage reads by wraps until it uploads one, and no
           other device takes its place; members accept an Add or external join in either group only of a
           leaf-entitled device; rotations wrap to every holder their epoch's tree lacks, and a member device
           keeps its leaf holder identity (§10.5) while wrapped, so a move shrinks nothing
  wrapped  a wrapped device commits no Add or Remove in either group: signing an admission, it writes the new
           device's first wrap; signing a revocation, it rotates, wrapping to every remaining holder, and the
           next leaf commit removes the target (§10.5); recovered past the first 1,000, it reads by its
           RecoveryWrap, or under a binding a void restored by Recovery's ReaderWrap (restored), then wraps,
           instead of self-joining; revoking it is a new generation not wrapped to it, as for an agent (owner
           decisions 64, 114)
```

**Authority statements** (owner decision 110) need `authority`: one signature (7.5) admits or revokes only members outside the AdminSet and their devices, and no lone signer mints or removes a config-signing key, though n ≤ 2 forces k = 1 (7.18).

**Indexers** (owner decisions 150, 175, 177, 178; D-TEAM-27). A network starts with no `IndexerSet`; an indexer exists only once an Owner or Admin designates one at network scope, or a member's consented device at member scope, and every service keeps its fallback until then, a phone's "search more" downloading all and searching its own index (§3.6; owner decision 177). An `IndexerSet` designates one of §3.6's indexers, its subject a sidecar that is neither ephemeral nor read_only and, at member scope, a consented device of the signer's member; readers ignore a designation of any other subject. The newest one per (sidecar_id, scope) holds, a device designated at both scopes running their union; `retire` ends it, as does the subject's revocation, and a parked subject serves nothing until lifted. Scope `network` covers network services within the subject's access: a personal network's mail or, under `team_mail: indexers`, a Team's on a `tag:mail` device (§8.5, §15.5); mirrors of the team record, the team directory, `record` ledgers and the config on an admin's device, or of the team record on an auditor's; search upkeep of the indexes it reads outside members' own repos (§11.14), the team directory's roll-ups included; removal of revoked sidecars' directory cards and notices (§16.11). Scope `member` covers its member's own repos (owner decision 126) and, in a Team member scope (owner decision 58), that scope's mail; a Team's network mail indexers only deposit, so members' own indexers keep their mailboxes' mirrors and indexes. A personal network's designations are network scope and also cover its owner's repos. For remote search (§11.14), `search` also answers app hosts' "search more": at network scope, any member's app hosts over the team repos the subject reads; at member scope, its own member's over any repo it reads and an `EvsShare` reader's over the repo shared. So an owner-bound repo reaches only a consented device of its owner (owner decision 126), and a tagged subject, never consented, answers only team repos, the asking app naming its sponsor. No app host answers (`ur indexer add` refuses `search` there and app builds never serve it), nor a browser Worker, which is read_only or ephemeral; the subject retires the designation to stop answering. A designation grants no key, grant or read, and readers ignore a service value they do not know. It enters the log at once, api seeing its signer, subject, scope and `retire`, while `services` is sealed to the config's current generation as §17.8 seals rule bodies. `ur indexer add|rm [--services mail,mirror,search]` signs only for a /dev/tty-confirmed command or in an app's UI, never through MCP (§5.8), since an indexer's mirror and index downloads spend the transfer balance (owner decision 10), and at network scope `--services search` warns when the host has harness hooks installed, since its same-user agents could read members' queries (§2.4's TB1); `ur indexer ls` lists the network's indexers.

**Versioning rules** (owner decision 164). A network's VersioningRules set the versioning an honest writer gives each path it creates, existing paths keeping theirs (§11.7; owner decision 167); without the record the platform rule holds, versionless above 64 MiB of plaintext; Owners, Admins and Network admins write the record with `ur admin versioning`. The rules cover file-mode refs of every repo kind but config and mailcfg, never git-mode or creates-only refs, the search index's files or git-lfs's store. A repo's own rules in its RepoVersioning (§8.8) replace them for that repo; an owner-bound repo's rules are sealed to that repo's own generation, so only its readers open them, not every admitted sidecar, while the network's record and other repos' rules are sealed to the config's generation (§8.8; owner decision 126); either way the server never sees a glob. A locked repo takes no versioning off; in an owner-bound repo the owner's devices apply the rules like any writer, and the owner may lock it.

**Statements** are typed `Signed` records (§6.9's `type`, §6.11's `SignedType`) whose bodies begin with a `StatementHeader`:

```proto
// sidecar/protocol/bridge/auth.proto (§4.4), with the log's messages below
message StatementHeader {    // begins every statement that enters the authorization log
  bytes   network_id = 1;
  AuthPin at = 2;            // the signer's state when signing: on the verifier's chain, within 4,096
                             //   positions of the entry that carries it and not before the retention
                             //   point of the state that entry lands on (replay)
  bytes   nonce = 3;         // 16 random bytes
  int64   not_after_ms = 4;  // at most 7 days after signing
}
```

```text
replay      (D-TEAM-20) api and readers refuse a statement whose at is off their chain, over 4,096 positions
            old or before the retention point of the state it lands on (retention; every reader, a new device
            included, holds A_k from it, so equal pins give equal verdicts), that has expired, or whose id is
            among the last 4,096 entries; type rules close the rest: a sidecar_id is admitted once and
            tombstoned until its admission's not_after, which tagged and ephemeral admissions require; a member
            device's admission carrying one is refused, so leaves' rank depends on the log alone; GrantActivate
            is once per grant_id (§8.8); a decision activates at most its uses BridgeRoute or BridgeMap rules,
            counted by the rule id §17.8 derives from each use's effect_key (a retry adds none), and none whose
            id a BridgeWithdraw named; Suspend carries a random suspend_id that only Unsuspend{subject,
            suspend_id} lifts; revocations are idempotent
several     k-of-n and recovery-signed statements (owner decisions 110, 127, 149; D-TEAM-21): AdminSet and
            authority-key changes, an AdminSet member's admission or revocation, AuditOptIn, recovery admissions
proposal    an AuthorityProposal by the first counted signer, proposal_id = SHA-256(Signed AuthorityProposal),
            then an AuthorityCosign from each further one, each under its own header
counted     distinct member_ids among the AdminSet's Owners and Admins at the completing entry's state; a
            member's devices and its recovery key count once; neither the target device nor an AdminSet change's
            or MemberRevoke's target member counts, but an AdminSet member's existing device counts as one for
            its own new device (owner decision 112) and for revoking another of its own devices (§5.6; 7.10's
            stale row); each signer's presence key countersigns as the presence row asks; read_only devices
            never count
completion  the entry holding the k-th valid counted signature or, for a statement Recovery's window holds
            pending, the window's activation; the statement takes effect at that position, its causal identity
k = 1       a single signed statement with no recovery-key signature needs no proposal
self_admit  off: a scoped recovery admission is a proposal by the recovery key that completes on one cosign by
            an admission signer (an Owner, Admin or IT admin device), under a binding a void restored only at
            Recovery's activation
cascade     (D-TEAM-26) SidecarRevoke{reason: compromise, since_n} parks a closure P. since_n is a log position
            with no default: the signing device proposes the first entry timed at or after the loss time its
            person gives, which the person may move earlier, lists for its person and admins what P parks and
            voids, what stands (below) and each device that sealed keychain.wrap to a binding it voids (its
            member's devices live while that binding was current; Recovery's after), and signs on confirmation
            (§5.6); a record counts from the entry that carried it (a statement's own, or the base whose config
            head first holds it), never from its signer's at; in position order from since_n, P holds the
            revoked sidecar, each sidecar whose admission a sidecar then in P signed or whose park such a
            sidecar's AdmissionConfirm lifted, each whose consent (§8.5) rests only on such a sidecar's
            OwnerConfirm, a confirmation of a device then unparked and consented on other signatures adding
            none, each sidecar a recovery key admitted, alone or in a proposal, under a binding such a sidecar
            signed, each admitted under a Delegation such a sidecar signed, which is void, and, where a
            Delegation admitted the revoked sidecar, each sidecar that Delegation admitted from since_n on,
            the Delegation ending at the revocation's position (delegation); api and readers refuse the
            revocation if P would hold one of its signers; every RecoveryBind or RecoveryRebind,
            KeyRegister and EvsShare a sidecar then in P signed is void until a signer outside P signs it
            again; a void restores the newest earlier binding not void, which is no current binding until a
            signer outside P signs it again: it takes no wrap (§10.5) and no keychain seal, M's devices
            re-sealing keychain.wrap with no HPKE copy (§5.9), its admissions activate only by Recovery's
            window, and M's devices alarm; grants, approvals, suspensions and unsuspensions, access-log
            statements, SponsorSets, IndexerSets, MemberAdmits and config heads signed in P stand until revoked
lift        a parked sidecar reads, writes and witnesses nothing and is a shrink like a revocation until a
            signer outside P confirms it: an AdmissionConfirm{sidecar_id} by one allowed to admit it lifts a
            park through its admission or Delegation, and its member's OwnerConfirm one through its
            OwnerConfirm; a consent (§8.5) resting on what P signed returns only with the member's own
            AdmissionConfirm or OwnerConfirm from a consented device outside P, so an admin's AdmissionConfirm
            restores all but owner-bound reads; restored, it leaves P at that position, what it signed in P
            staying parked or void until re-signed outside P; rows keep each such record's signer and position,
            so api, evs and gkm build P as readers do; what a stolen device admitted, at any depth, or bound
            stops with it, and a legitimate device costs a confirmation
delegation  (D-TEAM-30) a Delegation ends at the first of its DelegationRevoke, its void (cascade) and a
            compromise revocation of a sidecar it admitted: from that position api and readers refuse a
            SidecarAdmit or AdmissionConfirm its key signs, as past its not_after or max_admits, and its key is
            dropped (§10.5); a DelegationRevoke with since_n > 0, for a leaked bundle, and that compromise
            revocation park each sidecar it admitted from since_n on, as the cascade parks, an AdmissionConfirm
            lifting each (lift), the rest reading on as uncovered agents, and each is a compromise retirement
            (shrink); a Suspend of one of its agents, or a revocation for lost or removed, drops only its key,
            so a copy of its auth key admits on, each later agent uncovered, until it ends (7.10's agents row)
read_only   (D-TEAM-24) page Workers are admitted read_only (§18.8); every verifier (api's, members' devices,
            gkm, evs) accepts from such a device only its own SidecarRevoke (sign-out), its own key upkeep
            under its r scopes at gkm (§10.6's scopes: its ReaderKeys, signed reader-key, its KeyPackages,
            whose credentials it signs mls-credential, and its leaf's path-only commits, resyncs and acks),
            leaving, `read` record entries and receipt deposits (§16.8), and HeadCheck replies, and refuses
            its ApprovalDecisions, admissions of any kind, OwnerConfirm, EvsShare, KeyRegister and KeyRevoke,
            IndexerSet, RecoveryBind and RecoveryRebind, every authority, acl and bridge statement, its
            ReaderWraps, DelegationWraps, GenRotates, Welcomes and group-info writes (§10.6's info row; its
            commits still carry their sealed GroupInfo at 16 leaves or fewer), evs heads, socket registrations,
            and DNS, TLS and mail writes; it is never a writer, approver, counted signer, consent signer,
            indexer, key deliverer or committer of another's Add or Remove; the exchange gives it only r
            scopes and the receipt deposit; §16.6's harness_ok counts only approval-capable devices
            (consented, not read_only)
presence    (owner decisions 185, 187; D-TEAM-32) a statement listed in covers, signed by a sidecar
            that registered a live presence key (a KeyRegister{purpose: presence} it signed, not revoked, not
            void and with its not_after after the carrying entry's time), carries that key's countersignature
            in §6.9's Signed.webauthn, and api, evs, gkm and every member device refuse it without one that
            verifies; a sidecar with none signs on its person's confirmation (D-CORE-13), and a recovery
            key's statements need none
  covers    a SidecarRevoke{reason: compromise} and a KeyRevoke of a presence key (owner decision 185); a
            KeyRegister{purpose: presence}, lest a thief register a key of its own to countersign with;
            every other SidecarRevoke of another sidecar, §7.10's stale and cleanup ones included, every
            Suspend of another sidecar and every RecoveryVeto (owner decision 187); every DelegationRevoke
            with since_n > 0, which parks other sidecars as a compromise revocation does; every SidecarAdmit,
            AdmissionConfirm and OwnerConfirm of an untagged sidecar, AdminSet change, MemberRevoke,
            RecoveryBind and RecoveryRebind, lest a thief mint a signer with no key, take over the member's
            recovery code or remove a member (owner decision 189); an AuthorityProposal carrying one of
            these, and each AuthorityCosign of such a proposal, by its own signer's key
  act       one presence check covers the m statements a device signs together, in order (1 <= m <=
            65,535): with d_i the SHA-256 of statement i's §6.9 signed bytes, root = RFC 9162's
            MTH(d_0..d_{m-1}), and the key signs, by its §16.6 profile with UV, the countersigned bytes
            "urnetwork-sidecar-v1/presence-act" || 0x00 || signer_id || u32be(m) || root, "presence-act"
            being no §6.11 purpose; each statement carries key_id, signature (with authenticator_data and
            client_data_json for webauthn-es256), m, its index and its inclusion path, so it verifies
            alone, whichever of the act's statements land and in whatever order
  verify    from its own leaf through its path to the root (RFC 9162 §2.1.3.2), then §16.6's countersign
            check over those bytes, UV set and signCount not compared, the statement's nonce and the replay
            row refusing a reuse; key_id names a key its signer registered, live at the verifying state; a
            countersignature this row does not require is ignored; the keyless device role, which parses no
            KeyRegister, applies a covered SidecarRevoke, MemberRevoke or Suspend on its identity signature,
            as a denial that its sidecar role's next state, which checks the countersignature, confirms or
            reverses (§17's device roles)
```

**Owner consent** (owner decisions 63, 126). In a member M's owner-bound repos admins revoke but add only the visible audit reader; any other reader, a device admitted under M included, must be consented under §8.5's rule. Members park other devices there; M's devices alarm on every admission under M they did not sign, and each of M's devices on every RecoveryRebind of M it did not itself sign, one another device of M signed included (§5.4's `recovery_rebind`).

**Anchor.** Invites and pre-approved keys carry `sha256(Genesis)` and the current authorization pin; sidecars refuse any other genesis or a lower pin. A `ur login` device trusts the first genesis it sees, but its admission compares a safety number covering the hash (§5.6), and a code-only recovered device, which has no admitter, accepts only a genesis its recovery key signed, checked in the config its RecoveryWrap, or under a binding a void restored its ReaderWrap, opens (Recovery's `anchor`), so only a network's first device rests on trust (§2.8 EX5). **Bootstrap** starts the authority once:

```text
who       the network's first untagged sidecar of its owner (admin_user_id's user, or a team's first Owner)
device    signs Genesis, the first config head and base 1, whose prev_chain is A_0 = SHA-256(Signed Genesis)
api       accepts base 1 only with that Genesis, as entry 1 with If-None-Match, so one genesis wins a race,
          and only if Genesis names such a sidecar
exchange  issues repo:<config_repo_id>:admin from base 1 to that sidecar alone, which creates the repo
          (§11.12), pushes the head and forms the group (§10.6); a race's loser is admitted like any device
enroll    before base 1, a tagged or ephemeral enrollment answers no_genesis
```

**Writes.** Readers, and api for bases, replay config heads from genesis, refusing a record whose signer lacks the role at its parent head; tag and group names leave sealed tables only as keyed HMACs. Scoped statements, revocations, proposals, cosigns, vetoes, confirmations, `SponsorSet`, `IndexerSet`, `KeyRegister`, `RecoveryBind`, `RecoveryRebind` and §8.8's statements enter the log at once, a proposal taking effect at its completion, and api and readers verify them against the state at their position until a writer folds them in (owner decisions 8, 74).

**Authorization log** (D-TEAM-19). One linear, hash-chained log per network orders bases and statements. Its position n, advancing on every entry, is the projection version everywhere, A_n its chain digest, and (n, A_n), the `AuthPin`, names a state for readers, gates, gkm, MLS commit headers, evs heads, tokens (`proj_v` = n), BridgeState and approvals.

```text
proj/<network_id>/<n>/_            entry n, n zero-padded to 20 digits; If-None-Match; immutable
projrows/<network_id>/<sha256>/_   a base's rows, content-addressed; If-None-Match (an equal object answers 200)
  where   the first metadata cluster, beside place/ (owner decision 145); api writes and then raises
          {acl_<networkId>}v (§8.9); api, evs and gkm read the cluster or the cache below; other gate
          services fetch from api
{acl_<networkId>}e                 the verified read cache (owner decision 136), in {acl_}v's hash tag
  holds   a hash: the newest base's position b, the tip m, the AuthEntry bytes by n of entries b..m (at most
          the newest 1,024), and the {acl_}v value it matches, rows staying on the cluster; 10 min TTL
  write   only api, never evs or gkm, in the one script that INCRs {acl_}v after each append: it adds the
          entry, raises m only upward, drops entries below a new base or past 1,024 and records the new
          {acl_}v
  read    api, evs and gkm use it only when it records {acl_}v's current value and holds every position
          they need (a hint's n, a token's proj_v, a request's pin), verifying each entry's chain from their
          own pin and its signatures as from proj/, and otherwise GET proj/; it decides nothing, so a stale
          or lost copy costs cluster reads only, and every reader refuses a lower n wherever it reads
A_n = SHA-256("urnetwork-sidecar-v1/auth-log" || u64be(n) || A_{n-1} || u32be(kind) || i64be(time_ms)
              || SHA-256(body))
```

```proto
// sidecar/protocol/bridge/auth.proto (§4.4; std and protobuf only), with StatementHeader, Genesis,
// MemberRevoke, SidecarRevoke and §8.8's Suspend, Unsuspend and GrantRevoke: what the device role verifies
// and applies (§17.8, §18.6); config.proto and acl.proto import it and never redeclare these
message AuthEntry {                  // the body of proj/<network_id>/<n>/_
  bytes  network_id = 1;
  uint64 n = 2;                      // the bootstrap base is 1; every entry adds one
  bytes  prev_chain = 3;             // A_{n-1}; A_0 = SHA-256(Signed Genesis)
  uint32 kind = 4;                   // 1 BASE, 2 STATEMENT, 3 TICK
  int64  time_ms = 5;                // api's clock when it sequenced the entry (server-asserted)
  bytes  body = 6;                   // BASE: Signed ProjectionHeader; STATEMENT: one Signed statement;
                                     // TICK: ApiTick, unsigned
}
message AuthPin { uint64 version = 1; bytes chain = 2; }     // (n, A_n), 40 B
message ProjectionHeader {           // §6 Signed, purpose authority, by a config writer at S(n-1)
  bytes  network_id = 1;
  uint64 version = 2;                // this entry's n
  bytes  prev_chain = 3;             // A_{n-1}
  uint64 folded_through = 4;         // m <= n-1: the rows compile the config head, which holds every
                                     // statement and tick up to m; the statements and ticks among
                                     // m+1..n-1 re-apply on top, a BASE there skipped
  uint64 config_version = 5; bytes config_head_sha256 = 6;
  bytes  rows_sha256 = 7; uint32 rows_byte_count = 8;   // ProjectionRows, <= 4 MiB (§8.8)
  uint32 threshold = 9;
}
message ProjectionRows {             // projrows/<network_id>/<rows_sha256>/_; for the cascade a *_signer
                                     // names a sidecar_id, a recovery key's hash or a delegation_id, and a
                                     // *_at is the position n of the entry carrying the record
  repeated MemberRow members = 1;    // member_id, role, recovery_key_sha256 (the binding in effect, windowed
                                     // while a newer one below is void), bindings newest first {key_sha256,
                                     // signer, at, reason}, kept for the membership's life
  repeated SidecarRow sidecars = 2;  // sidecar_id, admission_sha256, admission_signers (each counted one),
                                     // admitted_at, confirm_signer and confirmed_at (its newest
                                     // AdmissionConfirm), owner_confirm_signer, owner_confirmed_at,
                                     // revoked_at, parked_at, sponsor, capabilities, delegation_id,
                                     // live_since (leaves); tombstones until not_after
  repeated DelegationRow delegations = 3;   // delegation_id, signer, at, tag atoms, not_after,
                                            // key_dropped_at (§10.5), ended_at and the admissions
                                            // it has made (7.9's delegation and scoped rows)
  repeated KeyRow registered_keys = 4;      // each KeyRegister's key_id, member_id, alg, public_key,
                                            // purpose, signer, at and not_after, with its KeyRevoke's
                                            // position: what the presence row reads
  bytes  acl = 5;                    // §8.8's AclRows (acl.proto), deterministically encoded, so this file
                                     // imports nothing, each EvsShare with its signer and at; with
                                     // AclRepo.holders_shrunk_at (below); the device role reads only its
                                     // has_document (field 1)
}
message ApiTick {                    // kind TICK: api's own facts, each checked by content
  repeated bytes reaped_sidecar_ids = 1;     // ephemeral admissions only (7.10); coalesced per minute
  repeated bytes activated_proposal_ids = 2; // recovery windows that ended (Recovery)
}
```

```text
state      S(n) = the newest base b <= n, whose rows compile its config head, plus the STATEMENT and TICK
           entries among folded_through+1..b-1, re-applied in order (a BASE there is skipped, its rows
           superseded by b's), and every entry b+1..n, in order; a config head takes effect only at the base
           that names it: readers show a newer one with no base as pending and alarm after 10 min, and any
           config writer may publish its base
statement  POST /network/config/delta {Signed}: api verifies it against S(tip) (header, type rules, the
           signer's authority; else 403 with the tip, and the signer re-evaluates), PUTs tip+1, and on 412
           re-verifies against the new tip and tries the next position; replies {n, A_n}; a retry of the same
           Signed bytes found among the last 4,096 entries returns that entry's {n, A_n}: the statement id
           SHA-256(Signed) is the retry identity
base       POST /network/config/projection {Signed ProjectionHeader, rows}: accepted only if version = tip+1,
           prev_chain = A_tip, SHA-256(rows) = rows_sha256, and config_version and folded_through are each at
           least the newest base's, its config head being that base's or a descendant; api PUTs projrows, then
           the entry; if the tip moved, 409 {tip, A_tip} and the writer re-signs, re-compiling only when an
           intervening base moved the config head or the fold; folded_through may stay at its old m while
           m >= tip - 1,024, so the writer never re-compiles under a stream of statements
tick       api appends ApiTick entries at most once a minute per network
fold       once the oldest statement or tick past the newest base's folded_through is 1,024 positions behind
           the tip or 24 h old, a config writer saves a config head holding the statements and ticks
           through the tip and publishes its base, at its next start if it was offline, after a random 0-10
           min delay that another base cancels; so while any config writer runs, the unfolded tail stays
           within about 1,024 entries or a day, bounding re-application, {acl_}e's window and devices' kept
           tails (about two such spans)
limits     per network, api takes at most 60 statements a minute in bursts to 600 and 2,000 a day (20,000 on
           Team), and one base a minute and 200 a day (pro.yml, §20.4), counted in Redis {acl_<networkId>}q
           (TTL 25 h), answering 429 {retry_after_ms} beyond them; revocations of every kind, Suspend,
           BridgeWithdraw and RecoveryVeto are exempt, but one whose subject is already so, with no stronger
           reason (compromise over lost or removed, any of the three over reaped, a since_n over none, or an
           earlier since_n), answers with that entry's
           {n, A_n}; ticks and reseed uploads do not count; so each network's share of §11.13's P0 proj/ and
           projrows/ writes stays bounded, revocations' by the subjects its admissions create, though no
           cluster's sum is (owner decision 186), api reporting their bytes to the governor (§11.13)
uncertain  on a timeout or lost response, GET the position tried: the same body is success, another a loss
           (retry at the next position), 404 repeats the PUT
apply(e)   every admitted sidecar: e.n = my.n + 1 and e.prev_chain = my.A, else FORK: alarm, stop sealing
           (§6.4), keep the evidence
  BASE       the signer is a config writer at S(my.n); config_version and folded_through are each at least
             the previous base's, its config head being that base's or a descendant, so no base rolls back
             policy; the config head chains to genesis through config writers and holds, as records, exactly
             the log's statements and ticks in (the previous base's folded_through, folded_through], each by
             id with the position of the entry that carried it (a tick by its position);
             SHA-256(compile(config head)) = rows_sha256; then the STATEMENT and TICK entries among
             folded_through+1..n-1 re-apply in order, a BASE among them skipped, its rows superseded by this
             base's, each keeping the verdict it got at its own position, so a later authority change never
             undoes an earlier revocation, while effects that depend on rows, such as a GrantActivate whose
             rule the new config head deleted, follow the new rows, the same for every reader; keyless device
             roles check only the signature, prev_chain, rows_sha256 and the two versions
  STATEMENT  its header, its type's signer rule and 7.9's presence row at S(my.n); apply
  TICK       every reaped id is an ephemeral admission (7.7); every activated proposal meets the window
  my.(n, A) := (e.n, A_n)
retain     A_k for every k from api's retention point (below) on, and each base's (n, A_n) for 30 days, 40 B
           each; the previous and current bases' rows; the last 4,096 entries' statement ids (16 B each,
           64 KiB); every sidecar, phones, page Workers and agents included, its newest entries' verbatim
           bytes up to a HeadCheckProof's 64 KiB (bases as headers, §6.5) and, while it sends proven, the
           proof it verified, so any holder or relayer answers §6.4's HeadCheckProofRequest; member devices on
           §18.4's desktop and CLI hosts (ur daemon) also every entry's verbatim bytes from that point, for a
           site loss, about two fold spans (fold); a reader that cannot fetch an entry it has proof of treats
           itself as withheld
check      readers pin (n, A_n) for §6's HeadCheck, which any admitted reader, agents included, may witness;
           unwitnessed, writers in shared groups alarm at 24 h and stop at witness_bound_hours, though
           rotations, Removes and revocations never stop (I-16; D-TRUST-10, owner decision 129)
users      the exchange, §8's gates, §10's reader sets, api-10's approvals (§16.6)
retention  api keeps entries from the retention point, min(the previous base, the newest base's folded_through
           + 1), on for the network's life, deleting older entries, and rows no retained base names, 30 days
           after the newer base; a new device starts at the newest base b, verifying its signature and its
           config head's chain to genesis, not the pruned entries, chains A_k back from b's prev_chain through
           the kept entries to the retention point, so it judges every at as long-running readers do, and
           re-applies the statements and ticks among folded_through+1..b-1 as S(b) says
site loss  (§19.10) the log comes back from devices, never re-sequenced, while sidecar.yml's reseed is true
  upload     POST /network/config/reseed {entries, rows of their bases, pins} from member devices other than
             read_only ones, whose code the server serves: the verbatim run a device keeps (retain), or a
             phone's (k, A_k) pins; api checks the prev_chain links, every base's and statement's signature,
             each signer rule from the run's first base on, and agreement with the restored
             network_acl_head's (n, A_n) (§8.17); no network that row names takes a new base 1
  adopt      api adopts entries in position order from the oldest that devices of two members hold, each on
             its predecessor's digest once devices of two members hold its own, by bytes or pin (one member's
             where the run's base admits uploading devices, member devices that are not read_only, of one
             member only), so no lone compromised device fills a position with a forged TICK, a reordered
             statement or one it signs; where no bytes reach two members, the log stops before that position
  resume     an admin's device re-seeds the config repo and publishes a base at tip+1 over it; api first
             checks the newest adopted base as a new device's start does (its config head's chain to genesis)
             against that repo, discarding the adopted run if it fails; then api appends and re-derives its
             ticks, and signers re-submit statements no adopted entry holds, re-signed if expired
  after      positions and digests resume unchanged, so readers apply them without a FORK; an entry's time
             is api's own unless two members' devices forged it, and a forged activation raises
             recovery_unseen (Recovery's time row); a device whose tail passes the stop sees a FORK and keeps
             the evidence (I-16)
```

```text
shrink    entry n shrinks repo R if KeyHolders(R, n-1, t_n) is not a subset of KeyHolders(R, n, t_n) (§10.5),
          t_n its time_ms, or if it retires a holder of R's key for compromise (a SidecarRevoke or
          RecoveryRebind with reason compromise, or a DelegationRevoke with since_n > 0, signed for a
          leaked bundle), though the holder's identity may stay; identity
          (R, n, A_n); rows carry AclRepo.holders_shrunk_at, the newest such n, which writers compile into
          bases and readers, api, evs and gkm advance per entry
expiry    an authorization expiry: a holder whose RepoGrant or requested grant expires, or whose SidecarAdmit
          (an uncovered agent's) or Delegation not_after passes, at T_e, leaves at T_e with no entry; identity
          (R, T_e); a covered agent's own not_after drops no holder where it is covered: an ephemeral one
          ends as its reap would, and the scoped rule refuses a non-ephemeral one's before its Delegation's;
          like a shrink, it makes the covering generation cause REMOVE (§10.9) and is due a path epoch within
          24 h (§11.6); a ReaderKey's lapse is none: it stops deliveries to that key until the sidecar
          publishes a new one, not authorization, so it closes no gate (§10.5)
coverage  generation g of R, whose GenRotate carries auth pin (n_g, A_g) and time t_g, covers a shrink at n_r
          iff n_g >= n_r and A_g lies on the verifier's chain, and an expiry at T_e iff t_g >= T_e; §10.6's
          write gate requires a write's generation to cover both, and §11.8 enforces it at each ref's head CAS
tokens    evs and gkm honor a capability for R only while its subject reads (r) or writes (rw, admin) R in
          their newest verified state, besides rev/ objects, by a cached per-repo bitset, so a subject that a
          group edit or Suspend drops loses scope within §8.9's 5 s, not the token's 15 min
```

**Recovery** (owner decisions 3, 62, 112, 126-128, 149; D-TEAM-21). A member M's recovery key (`RecoveryBind`) admits M's new untagged device:

```text
member                    admission by the recovery key               takes effect
outside the AdminSet,     SidecarAdmit signed by its Ed25519 key      at its position; M's devices alarm (§5.4)
  self_admit on             (scoped)
outside the AdminSet,     the same as an AuthorityProposal, plus one  at the cosign; the recovery signature is
  self_admit off            cosign by an Owner, Admin or IT admin       M's consent (§8.5)
outside the AdminSet,     an AuthorityProposal of the SidecarAdmit,   at an ApiTick activation 72 h after its
  binding restored by a     plus with self_admit off one such cosign;   entry, with no counted cosign and no
  void (cascade)            a plain SidecarAdmit by the key is refused  valid veto (owner decision 149)
in the AdminSet           an AuthorityProposal plus k-1 cosigns       at an ApiTick activation 72 h after the
                                                                        entry of its newest recovery-key
                                                                        signature, with no valid veto
personal network (k = 1)  the proposal alone                          at activation, after 72 h
before      after ur login (§5.6) the device holds an unadmitted client of M; it may only read the log
admission   (GET /network/config/projection?after=), submit a recovery-signed statement (POST
            /network/config/delta) and fetch M's recovery wraps under recovery:<member_id> (aud gkm, only
            GET /gkm/recovery/<member_id>/wraps, M from the token), which the code opens at once: the window
            and veto bound the admission, not what a code holder reads, which only a compromise rebind ends
            (§2.10); the statement carries the recovery Ed25519 public key, whose hash api and readers match
            to MemberRow.recovery_key_sha256, compiled from RecoveryBind
pending     an authority statement with a recovery-key signature, in its proposal or a cosign, and any admission
            by a binding a void restored (cascade), a proposal by the table above, is pending and admits
            nothing: members refuse an Add, Welcome or wrap to its device, and it shows as recovery_window on
            admins' devices, which offer its veto (§5.6, §18.5); its window starts at p (time T_p), the entry
            of its newest recovery-key signature, so each recovery cosign restarts it; o is the proposal's entry
activation  the first ApiTick naming it with time_ms >= T_p + 72 h, once it holds k counted signatures (a
            scoped admission only its table row's cosign, if any), makes it effective at the tick's position a,
            unless a valid veto exists; admins thus always get 72 h to veto the last recovery signature, and a
            proposal whose p lands under 72 h before its not_after_ms expires unactivated
valid veto  a RecoveryVeto whose entry lies between o and a, or one a device holds (signed, or verified in
            HeadCheck) whose at.version is >= o and < a, either carrying the countersignature the presence
            row asks of its signer (owner decision 187)
voiding     between o and a, a RecoveryRebind of the subject or of any member whose recovery key signed the
            proposal or a cosign, an AdminSet change or the subject's removal; or the proposal's not_after_ms
            (7 days)
precedence  a device that held a valid veto before it applied a refuses the activation whatever the log says:
            it alarms, treats the log as forked at a and gossips the veto in HeadCheck; a veto's at is its
            signer's claim, so a device that first verifies one after applying a only alarms and offers to
            revoke the recovered device, and a veto signed late, or backdated by a compromised admin device,
            forks only devices still before a, a denial like §6.4's FORK; a device so forked applies a and the
            log after it once that log reverses a: it revokes the device a admitted for compromise from a
            since_n at or before a (the cascade parking what that device signed), or restores what a changed
            by authority with no recovery-key signature; until then it stalls its shared-group sealing
time        entry times are api's: a device applying the activation under 72 h - 10 min after it applied p
            raises recovery_unseen, and every admin device offers to revoke the recovered device; a server
            that hides p from every admin device for the whole window defeats the veto, detected on first sight
restart     the recovering device keeps its identity key, sidecar_id and proposal id in its keychain (§5.9)
            and resumes polling the log
anchor      once admitted, before any commit, wrap, sealed write or further statement, it opens the config head
            its newest verified base names, down the ladder from an RK_g matching gen/<g>'s C_g (§10.5), and
            requires the head's records to chain to a genesis whose SHA-256 its own binding's genesis_sig there
            signs under the Ed25519 key its code derives, else it raises head_alarm (fork, with that base's
            AuthPin) and acts no further; that RK_g is its config-group RecoveryWrap's, or as restored says;
            genesis_sig, that key's signature over ("urnetwork-sidecar-v1/recovery-genesis" || network_id ||
            SHA-256(Signed Genesis)), is the one input only the code produces, and only this check reads it, so
            api, which sees it sealed, and readers judge bindings alike; M's recovery public keys, which every
            config reader and rotator holds (§10.8), and the device's ReaderKey, which gkm serves, let a server
            fake either wrap but no head chaining to the genesis M signed, while a C_g match alone proves
            nothing, gkm seeing every C_g and a forged log free to admit any real rotator
  restored  under a binding that takes no wrap (cascade), in this order:
            1  pending, until the activation admits it, it reads the log and signs only its AuthorityProposal
            2  admitted, it uploads its ReaderKey but no KeyPackage until 4 passes, so it reads by wraps
               (leaves) and no Add precedes 4
            3  it fetches the late ReaderWrap of the config group's current generation that a config writer
               gives such a device (KF2), or the one a later rotation stages to it (§10.5's config row)
            4  it runs the check above from that wrap's RK_g, and only then acts as after says
after       it self-joins, revokes M's lost devices and rotates as §10.8 says, reading the config by its
            RecoveryWrap, or restored's ReaderWraps, if ranked past the first 1,000 (leaves); under a binding
            that takes no wrap only the config group's sealed GroupInfo opens to it, by that ReaderWrap's RK_g,
            so KF2 adds it to its other groups once it uploads KeyPackages, and a group whose leaves are all in
            P opens to it only through that binding's surviving wraps; it then offers
            ur keychain recovery-rotate (§5.9), M having no current binding until a device outside P signs one;
            RecoveryRebind's compromise shrinks every repo M reads, so the next rotation is cause REMOVE and
            starts a path epoch at once, while routine and lost request a rotation; old wraps are deleted in
            every case; no rebind or void reaches a keychain backup sealed before it, whose keychain.wrap the
            retired or voided code still opens (§5.9: the device's identity key, ClientKey seed, ReaderKeys and
            key cache), so after a compromise rebind or a void M revokes for compromise, and enrolls anew, each
            device whose backups may hold such a sealing, since --replace keeps its identity key (§5.5)
no code     lacking the member's consent, an admin re-add restores team repos only; short of k signers, the
            AdminSet freezes and the team starts a new network
```

### 7.10 Removal, and consistency with MLS (§10)

```text
trigger  admin: member-remove, remove-client, a page Worker's stale predecessors at its admission
         (stale) | member: own device (§5.6), a re-enrolled page Worker's stale predecessors included |
         SCIM active=false | ephemeral reap
api      tokens, keys, auth codes, listeners, publishes and certificates end, and DKIM selectors and a
         receiver's TLSA record are deleted in the same write (I-15, owner decision 36; §15.5); clients
         deactivated, each one's push-token row tombstoned in that write (§18.7); rev/ objects (7.8);
         tombstones; admin event; connect closes in <= 90 s (a denial: unsigned); each effect is
         idempotent, so after a restore §19.10 re-applies them, before the token
         exchange reopens, for every removal recorded after the main dump's snapshot
signer   an admin device, or the member's for its own devices, signs MemberRevoke or SidecarRevoke{reason}
         (authority statements for AdminSet members, 7.9), which every member sees, at log position n',
         each with its countersignature where 7.9's presence row asks;
         SCIM waits for an admin device or scim_signer (7.6); api's tick carries a reap, which the
         ephemeral admission authorizes; a member revokes another of its own devices as §5.6 says, and
         its stale page Workers as the next row does
stale    (D-TEAM-29) the device that admits a member's page Worker (§18.8), the member's consented device
         or an admin's, always an admin's with self_admit off, signs in that confirmed act, under its one
         presence check where 7.9's presence row asks (owner decision 187), SidecarRevoke{reason: removed}
         for each of that member's page Workers whose leaf,
         in every group the admitting device is a leaf of that seated it, at least one, §10.9 removed as
         stale, or that is due for that Remove (stale_leaf_days past its leaf's last change) and whose
         Remove the admitting device, a writer leaf there, commits first (§10.9's Remove row), with no
         later Add or resync (KF2, KF5); it decides at each group's current epoch, which it fetches first,
         and again before each post or retry (§5.9), dropping unposted a revocation whose Worker holds a
         leaf again, and posts the revocations before the admission, so that at config_admissions' cap
         (§20.7) the room they free counts; for an AdminSet member's Workers at k > 1 each is its own
         AuthorityProposal beside the admission's, the admitting device counting as one (7.9's counted),
         and an AdminSet device's Decide of that admission cosigns the admission and each such proposal
         after the same check in its groups (§18.5); one short of k expires at its not_after, and the
         member's next Worker admission proposes it again; an admin's device holds the member's
         owner-bound groups only through the member's own EvsShare (owner decision 126), so a Worker that
         no group it is a leaf of seated, such as one reading the config and directory by wraps (7.9's
         leaves) and no repo that device reads, is the member's: its consented device, in its own
         admission act or, after an admin's, at its OwnerConfirm of the new Worker (ur approve on /dev/tty
         included, D-CORE-13) or its answer to that admission's alarm (§5.6), revokes the same way each
         stale Worker its groups show, and offers to revoke, through §5.6's calls, the member's other page
         Workers it lists, each with its leaf's last change; in its admission act an admin's device
         revokes no Worker it did not see so removed and offers none, leaving the member's live devices
         to the member (owner decision 126); together these hold a weekly re-enroller near 14 admitted
         Workers, but a Worker no group of its admitting device seated stays admitted, one per eviction,
         until the member's consented device answers, without bound for a member with none, such as one
         with only page Workers, which §8.5 never consents, or one that never answers (7.18)
cleanup  (D-TEAM-29) from 90% of the config_admissions cap of the tier its token declares (§20.4) until
         the count falls below it, every admin device raises admissions_near_cap (§5.4) and lists, per
         member, its admitted page Workers but its newest, oldest first, each with its admission time and
         its leaf's last change where a group the device is a leaf of shows one; an admin's revoke signs
         SidecarRevoke{reason: removed} for those listed (signer row; an AdminSet member's at k > 1 as
         proposals; 7.9's presence row), so Workers no member device answers for are freed before api
         refuses an admission at the cap (§20.7); one still in use signs out and is enrolled again
agents   (D-TEAM-31) an admin's or tag owner's device revokes a tagged sidecar, and an admin's or its
         sponsor's suspends or unsuspends it (§8.8's signers), by ur admin agents revoke|suspend|unsuspend
         <name|sidecar_id> [--compromise [--since <time|position>]], confirmed on /dev/tty and never
         through MCP, each revocation or Suspend carrying the presence countersignature owner decisions
         185 and 187 require; for one a Delegation admitted, the plan names three things apart: the
         agent; the Delegation's shared reader key, which any revocation or Suspend of the agent retires,
         with the agents that then read by their own ReaderWraps and the repos that rotate; and the
         Delegation's admission authority, which every copy of its auth key keeps until the Delegation
         ends (7.9's delegation row), with its not_after and the admissions left; --compromise ends it,
         listing the agents it parks from since_n, and any other act offers ur admin delegations revoke
         <delegation_id> [--leaked --since <time|position>], which signs DelegationRevoke; ur admin
         delegations lists each Delegation's key and admission state, as the console shows them; revoking
         an auth key at api (POST /network/auth-key-revoke, or the console, which signs nothing) stops its
         bearer only, and for a pre-approved key both say that a copy of its bundle still admits and offer
         that DelegationRevoke
gate     from n', a push or deposit to a repo whose key holders n' shrank needs a generation covering it
         (7.9's coverage; §10.6, §11.8); receivers answer 451
commit   any writer leaf, the revoking device first, commits one Remove per group where a removed member
         device is a leaf; members reject a commit without the signed revocation (owner decision 113); a
         wrapped reader's revocation (an agent's, or a member device's past the config or team directory
         group's leaves) is a new generation not wrapped to it, by any writer at its next write (owner
         decisions 64, 114, 144, 182); a covered agent's reap needs none (§10.5); in the config and team
         directory groups the revoking device, or after a reap the device that signed the reaped agent's
         admission, commits these, a Remove and a rotation, even if it is no config writer, by rotation
         alone if it is wrapped (7.9's commit, owner decision 128); any leaf commits its own path-only
         update; no client encrypts to an epoch or generation a non-reader holds (§8.12), the primary
         control
cards    from n' (for a reap, its tick's position), every reader masks in the team directory the cards,
         notices and pending requests of each sidecar the removal revokes, a member's devices but not its
         tagged agents (owner decision 83); the directory's network-scope indexer, else any member device
         but a read_only one after 24 h, removes the revoked sidecars' cards and notices in one push that
         lists each (§16.11)
confirm  the revoking device shows the revocation unwitnessed until a HeadCheck peer holds its position,
         retrying every 10 min and at each start; the console alarms after 1 h (§6.4)
```

- **No committer online:** the gate refuses writes until any writer, wrapped ones included, claims a covering generation (§10.5); removed devices keep only what they could decrypt (lazy revocation, PLAN.md:47-50). No server transaction changes readers (owner decisions 5, 59).
- **Sponsors** (owner decision 83): a removed member's tagged agents keep their tags' grants and their directory cards; until an admin's `SponsorSet`, `autogroup:sponsor`, and so `autogroup:dst-owner` for them (owner decision 180), resolves to `autogroup:admin`, which their cards show as who, and their approval requests go to the team record (§8.4, §16.8, §16.11).

### 7.11 Audit log and SIEM

- **Server log.** `network_admin_event` records every admin action the server executes (per-network `seq`, actor, action, target, result, request id, hash chain; no client IP) for 400 days; Auditors and above read `GET /network/admin-events`, and HMAC-SHA256-signed SIEM webhooks retry for 24 h.
- **Server-visible fields** and TTLs: §2.8's api-1, api-3 to api-8, api-11; member, IdP, IdP-identity and webhook rows stay until removed.

### 7.12 Network names for teams

All three rename routes (server/controller/account_controller.go:13,160-256) call one `model.RenameNetwork`: §12's label rules and reserved list, the distance-1 check, 2 per day, the Admin permission, an admin event, a `network_name_reclaim` tombstone held 24 h (Q-TEAM-9), and refusal of any name in `dns_label`, label or alias, live or tombstoned (§12.5). Create and claim read tombstones; deletion writes one. Policy names networks by id, so a reclaimed name captures no grant.

### 7.13 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Every admitted sidecar a config leaf | one key path | a commit per CI join and reap; 1,000 leaves | rejected (owner decision 114) |
| Cap member devices at 1,000, or grow the config tree | no member wraps | the cap refuses Teams past ~330 members; 5,000 leaves make a 7.9-14 MB tree | rejected (owner decision 144) |
| A recovery key alone signs authority statements | a lone Owner recovers | bypasses k of n | rejected (owner decision 127) |
| Recovery keys sign only AuthorityProposals | one recovery signature per statement | admins who all lost their devices cannot reach k | rejected: a recovery cosign restarts the window (7.9) |
| ApiTick activates a restored binding's scoped admission by statement id | no proposal | a second activation list; vetoes keyed on statements too | not chosen: an AuthorityProposal reuses both (owner decision 149) |
| End a Delegation's admissions at every drop of its key | a copied bundle stops at any agent's revocation or Suspend | one CI agent's removal or Suspend stops the pipeline's enrollments until an admin re-issues its secret | rejected: its `DelegationRevoke` or a compromise revocation of one of its agents ends it (7.9's delegation row) |

### 7.14 Decisions proposed

**D-TEAM-1 (proposed).** P0 stage 1 refuses child and admin-refused tokens on all 37 routes before any sidecar, after 14 days log-only, confines `strict_exp` bearers to 7.4's route allowlist and closes AUTH.md:202. *Why:* owner decision 45.

**D-TEAM-2 (proposed).** `admin_user_id` stays immutable under a synthetic owner-of-record. *Why:* the refusal cache stays sound.

**D-TEAM-3 (proposed).** Seven roles, signed in the config repo; unmapped routes are owner-only. *Why:* fails closed.

**D-TEAM-4 (proposed).** OIDC only, keyed `(idp_id, sub)` (7.6). *Why:* blocks IdP-asserted and pre-registration takeover.

**D-TEAM-5 (proposed).** Auth keys replace `urn_` keys for `ur connect --token`; a pre-approved key's Delegation secrets ride a client-only bundle (D-TEAM-22). *Why:* scoped, expiring, revocable.

**D-TEAM-6 (proposed).** OAuth clients mint ≤1 h auth keys; CI's Delegation admits their sidecars. *Why:* the server cannot admit.

**D-TEAM-7 (proposed).** `ur-cli` tokens last 1 h, need code-matched consent and bind by DPoP to one command, whose method, path and body their `cmd` claim covers; api spends the jti in the command's transaction. *Why:* agents can drive the browser.

**D-TEAM-8 (proposed).** The exchange trades a client JWT and ClientKey proof for a 15-min, one-audience token scoped from the projection and voided by `rev/`. *Why:* owner decision 2.

**D-TEAM-9 (proposed).** Tags, groups, device names and sponsors live in the config repo. *Why:* owner decisions 46, 83.

**D-TEAM-10 (proposed).** Removal denies at the server at once, and evs refuses writes until a generation covering it is claimed (7.10). *Why:* nothing removed reads new data.

**D-TEAM-11 (proposed).** Server audit `network_admin_event`: hash-chained, no IPs, 400 days, webhook. *Why:* the server executes admin actions.

**D-TEAM-12 (proposed).** 7.9's records freeze in v0 as §6 `Signed` statements; authority statements (the four config-signing roles and their devices) need `authority`: k of n, a recovery key counting as one under the recovery window and its veto (7.9). *Why:* owner decisions 3, 5, 110, 127.

**D-TEAM-13 (proposed).** One rename function; create reads tombstones; deletion writes one. *Why:* closes three takeover paths.

**D-TEAM-14 (proposed).** Sidecar-held child and admin-refused tokens expire after 7 days under `strict_exp`, which one verifier enforces everywhere, and renew only with the ClientKey proof. *Why:* owner decisions 103, 131, with no app release.

**D-TEAM-15 (proposed).** Edge login issues members a 60 s, nonce-bound, one-origin ID token; its session counts only on same-origin requests or navigations (§13.7). *Why:* no open redirect, replay or cross-network forgery.

**D-TEAM-16 (proposed).** A member's consented devices admit its untagged devices unless `self_admit` is off, and revoke them whatever `self_admit` says; its recovery key admits them too, with one admin's cosign while `self_admit` is off; admins alone add no other reader to owner-bound repos (§8.5); tag owners and Delegations admit within scope. *Why:* owner decisions 5, 63, 112, 126.

**D-TEAM-17 (proposed).** One authorization log per network; positions rise, entries chain by hash and never fall, and HeadCheck compares (n, A_n), unwitnessed writers stopping at `witness_bound_hours`. *Why:* the server can only withhold, visibly once a HeadCheck crosses the split (owner decision 129; §2.8).

**D-TEAM-18 (proposed).** The first 1,000 live member devices by `live_since` are the leaves of the config group and of the team directory's, promoted in rank order and never demoted while live; later ones and agents hold wraps; an admission's or revocation's signer commits it there, a wrapped one by wrap or rotation (7.9). *Why:* owner decisions 114, 128, 144, 182.

**D-TEAM-19 (proposed).** One linear, hash-chained authorization log per network orders bases and statements; its position n is the projection version and (n, A_n) the pin every consumer names; api's If-None-Match PUT of `proj/<network_id>/<n>/_` linearizes it, within per-network append limits; no base lowers its config head or fold point, and a config writer folds it every 1,024 entries or 24 h; after a site loss, member devices' verbatim entries resume it unchanged, each adopted once devices of two members hold it (7.9). *Why:* bases plus delta sequence numbers commit neither content nor order, so readers could agree on different states; a re-sequenced log would fork every reader, and one device's upload could pre-empt a position.

**D-TEAM-20 (proposed).** Every log statement carries a StatementHeader (network, the signer's AuthPin, nonce, not_after ≤ 7 d), refused when off-chain, more than 4,096 positions old or before the retention point, expired or repeated; type rules close the rest (7.9). *Why:* typed signed statements still need replay rules, which every reader, a new device included, must judge alike.

**D-TEAM-21 (proposed).** k-of-n and recovery-signed statements are an AuthorityProposal plus AuthorityCosigns, counted per distinct member; an authority statement with a recovery-key signature, in its proposal or a cosign, or a scoped admission by a binding a cascade restored, stays pending, delivering no key to the proposed device, until an api tick 72 h after its newest such signature's entry with no valid RecoveryVeto, and a veto kept off the log forks only devices that held it before the activation (7.9). *Why:* owner decisions 110, 127 and 149 need a wire form, a clock and an activation path, a late recovery cosign must not skip the window, and a veto's `at` is its signer's claim.

**D-TEAM-22 (proposed).** A pre-approved auth key carries its Delegation's seeds only in a client-only `#<bundle>` split off before any request; enrollment has no field for it and api refuses an `auth_key` containing `#` (7.8). *Why:* the server must never receive admission authority or read keys.

**D-TEAM-23 (proposed).** JIT links an IdP identity to an existing user only after that user logs in with its existing credential in the same flow (7.6). *Why:* a verified-domain email alone would hand a pre-registered account to the IdP.

**D-TEAM-24 (proposed).** `SidecarAdmit.capabilities.read_only` limits a device to reading, its own sign-out, its own key upkeep (ReaderKeys, KeyPackages, its leaf's path-only commits, resyncs and acks, under the r scopes §10.6 maps), receipts and HeadCheck; it is never one of k, and never delivers a key. *Why:* a read-only browser must not carry its member's signing authority (owner decision 76's served code).

**D-TEAM-25 (proposed).** SCIM removals deny at once and are cryptographic only once an admin device, or the admin's indexer that `ServiceSettings.scim_signer` names (owner decision 150), signs the MemberRevoke (7.6). *Why:* a server queue is not a removal.

**D-TEAM-26 (proposed).** `SidecarRevoke{reason: compromise, since_n}`, `since_n` a required position, parks the closure P of what the device signed in entries from `since_n` on, and is refused if P holds one of its signers: each sidecar whose admission it or a sidecar in P signed, whose park such a sidecar's AdmissionConfirm lifted, or whose consent rests only on such a sidecar's OwnerConfirm, a confirmation of a device already unparked and consented adding none, each sidecar a recovery key admitted under a binding one of them signed, and each admitted under a Delegation one of them signed, which is void, while the Delegation that admitted the revoked sidecar, if one did, ends at the revocation, each sidecar it admitted from `since_n` joining P (D-TEAM-30); their RecoveryBinds and Rebinds, KeyRegisters and EvsShares there are void, and a binding a void restores is no current binding: it takes no wrap or keychain seal, its member's devices re-sealing, and admits only through the vetoable 72 h window, a scoped admission as an AuthorityProposal with no counted cosign (owner decision 149); each device that sealed keychain.wrap to a voided binding is listed, and revoked for compromise and enrolled anew if its backups may hold that sealing; only a signer outside P lifts a park or re-signs a voided record, and a consent resting on P's signatures returns only through the member's consented device outside P; grants, approvals and config heads signed in P stand until revoked, listed for admins (7.9); signed by a sidecar that registered a live presence key, it carries that key's countersignature (D-TEAM-32; owner decision 185). *Why:* a stolen device's admissions, and what those admit, bind or register, must not survive it; an entry position, unlike a signer's `at`, cannot be backdated; a revocation must neither freeze its own signer nor hand back a retired code, nor may a stolen device's redundant confirmations pull the devices that would revoke it into P; and a voided code must open no keychain.

**D-TEAM-27 (proposed).** A network designates its indexers (§3.6) by `IndexerSet` statements in the config repo (7.9): an Owner or Admin at network scope, a member's consented device at member scope for that member's own devices, and the subject itself to retire either; a designation names services, grants no key, grant or read, and decides only who runs a service first, so each service keeps a fallback when none is designated. A network starts with none (owner decision 177). For search, a designation also bounds which devices a phone asks, so a query reaches only designated devices (owner decisions 175, 178). *Why:* owner decisions 150 and 177; owner decision 126 leaves members' own repos to their own devices, and a duty must never widen reach.

**D-TEAM-28 (proposed).** `team-create`'s first Owner device files the directory's `RepoCreate` after the config's first base. `ServiceSettings.directory`, signed by an Owner or Admin, holds the team's defaults: for runs (auto unless set) and for workers (on). *Why:* owner decisions 170 and 171; one record holds a network's defaults (7.9).

**D-TEAM-29 (proposed).** Whichever device admits a member's page Worker, an admin's where `self_admit` is off included, signs in that act, under its one presence check where 7.9's presence row asks (owner decision 187), `SidecarRevoke{reason: removed}` for each of the member's page Workers that §10.9 removed as stale from every group it is a leaf of that seated it, at least one, and that holds a leaf in none of them, checking again before each post or retry, and for an AdminSet member at k > 1 as proposals of their own beside the admission's, which its cosigners also cosign; in its admission act an admin's device revokes or lists no other device of the member, while the member's consented device revokes the stale Workers its own groups show and offers to revoke the rest, in its own admission act or, after an admin's, at its `OwnerConfirm` or admission-alarm answer (7.10's `stale` row); from 90% of `config_admissions` every admin device lists each member's page Workers but its newest for an admin to revoke (7.10's `cleanup` row). *Why:* with `self_admit` off no member device admits, so a weekly re-enroller's evicted Workers would pile up toward Team's 5,000 `config_admissions` (§20.4); a stale-removed Worker has had no leaf change for 90 days and holds no leaf in that group, an admin's device sees the member's owner-bound groups only through the member's own share, and revoking a live device in an admission act stays the member's choice (owner decision 126); and a member with no device that answers, such as one with only page Workers, would reach the cap unseen, while an admin may revoke a member's device (owner decision 126), so admins see the pile and free it first.

**D-TEAM-30 (proposed).** A Delegation admits only sidecars carrying exactly its tag_ids and, unless ephemeral, a `not_after` no earlier than its own, up to `max_admits`, which rows count for its life; it ends at its `DelegationRevoke`, its void or a compromise revocation of a sidecar it admitted, after which api and every reader refuse an admission its key signs; a `DelegationRevoke` with `since_n`, and that compromise revocation, park the sidecars it admitted from `since_n` on as the cascade parks, the rest reading on as uncovered agents; a `Suspend`, or a lost or removed revocation, of one of its agents drops only its key (7.9's delegation row, §10.5). *Why:* a covered agent must read exactly what its Delegation's key opens; every copy of a reusable auth key holds the signing seed, which an honest daemon's erasure cannot reach and a colluding operator's fresh client cannot stop, so a leak needs a customer-signed end with a positional park; ending admissions at every key drop would stop a CI pipeline's enrollments at one agent's removal.

**D-TEAM-31 (proposed).** A tagged sidecar's revocation or `Suspend` shows a plan that names the agent, its Delegation's shared reader key and that Delegation's admission authority apart, with the agents and repos each reaches; `--compromise` ends the Delegation, any other act offers `ur admin delegations revoke`, and revoking an auth key at api alone says that a copy of its bundle still admits (7.10's agents row). *Why:* the three are separate capabilities, a person stopping a leaked key must see which one each act ends, and only the customer-signed end stops a copied bundle.

**D-TEAM-32 (proposed).** A `SidecarRevoke{reason: compromise}`, a presence key's `KeyRegister` or `KeyRevoke`, any other `SidecarRevoke` or `Suspend` of another sidecar, a `DelegationRevoke` with `since_n` > 0 and a `RecoveryVeto`, a `SidecarAdmit`, `AdmissionConfirm` or `OwnerConfirm` of an untagged sidecar, an AdminSet change, a `MemberRevoke`, a `RecoveryBind` or `RecoveryRebind`, and an `AuthorityProposal` carrying one or an `AuthorityCosign` of it, signed by a sidecar that registered a live presence key, carry that key's countersignature in §6.9's `Signed.webauthn`, which api, evs, gkm and every member device verify, each statement alone by its inclusion path to the act's Merkle root, UV required; a sidecar with none signs on its person's confirmation (D-CORE-13) (7.9's presence row). *Why:* owner decisions 185 and 187: a presence check that only the signing device ran was skipped by modified software on a stolen unlocked device, which could then lock the member out; one prompt must still cover an act of several statements that land separately; without the `KeyRegister` rule a thief would register a key of its own to countersign with; and without the admission, confirmation and binding rules it would admit a device with no key, or rebind the member's recovery code, and act from there (owner decision 189).

### 7.15 Open questions

**Q-TEAM-1.** How far does the P0 go? **Decided by owner 2026-11-03 (owner decision 45):** three stages, the last a hard gate (7.4). *Residual:* none.

**Q-TEAM-2.** Convert personal networks? **Decided by owner 2026-11-03 (owner decision 55):** (a) no; new team networks only. *Residual:* none.

**Q-TEAM-3.** Is SCIM in Team v1? **Decided by owner 2026-11-03 (owner decision 56):** (a) yes. *Residual:* none.

**Q-TEAM-4.** OIDC or SAML? **Decided by owner 2026-11-03 (owner decision 46):** (a) OIDC; SAML-only customers broker through an OIDC IdP. *Residual:* none.

**Q-TEAM-5.** Is the key authority opt-in? **Decided by owner 2026-11-03 (owner decisions 3, 45):** no; enforced from v0, member-signed admission subsumed. *Residual:* none.

**Q-TEAM-6.** How many signatures admit? **Decided by owner 2026-11-03 (owner decision 110):** (a) one; AdminSet and authority-key changes need k of n. *Residual:* none.

**Q-TEAM-7.** Cross-cutting (§2). Does the server hold the member directory? **Decided by owner 2026-11-03 (owner decision 46):** only users, emails and roles (§2.8 api-3). *Residual:* none.

**Q-TEAM-8.** Do a departing member's tagged agents leave? **Decided by owner 2026-11-03 (owner decision 83):** (b) no; they keep their tags' grants under `SponsorSet` (7.10). *Residual:* none.

**Q-TEAM-9.** How long is a released name held? **Decided by owner 2026-11-03 (implied by owner decision 83):** (a) 24 h. *Residual:* none.

**Q-TEAM-10.** Cross-cutting (§5.6, §10.4). May a member's own device alone admit that member's new device? **Decided by owner 2026-11-04 (owner decision 112):** (a) yes, as a scoped statement unless `self_admit` is off; an AdminSet member's new device still needs k of n, its existing device counting as one. It subsumes §10's DeviceAdmit; the signer commits the config group's Add or, if wrapped, a first wrap (owner decisions 128, 144). *Residual:* none.

**Q-TEAM-11.** Cross-cutting (§5.9, §10.8). May a recovery key sign an authority statement? **Decided by owner 2026-11-04 (owner decision 127):** (b) as one signature toward k, after a 72 h window any admin device may veto. Teams with k > 1 still need other signers (owner decision 110); a personal network (k = 1) recovers alone after the window. *Residual:* §2.10's row for an operator colluding with a recovery-code thief: the window bounds admission, not reads, so the code opens its recovery wraps at once until a compromise rebind, and keychain backups sealed to a code before its rebind or void stay open to it (7.9).

### 7.16 Departures from PLAN.md

- **PLAN.md:119**, met in part (§8.16): stored rules are signed and encrypted, and every device reads the whole config (owner decisions 5, 6, 72).
- **PLAN.md:147** ("participants are leaves"): member devices are leaves; agents, and member devices past the first 1,000 of the config group and the team directory's, hold wraps there (Q-ACL-9, Q-KEYS-15, Q-KEYS-16; owner decisions 114, 144, 182).

### 7.17 Interfaces

- **Provides:** `ClientRefusesAdmin`, the `strict_exp` allowlist, preview gate, expiry and proof, roles; 7.9's records (VersioningRules for §11.7 included), log, `AuthPin`, causal identities, leaf rule, presence countersignature rule (owner decisions 185, 187), verifier, read cache and site-loss resumption (§2, §6, §8-§11, §13, §16-§19); `rev/` objects; 7.7's attributes; removal events; token exchange; enrollment, auth-key bundles and `ur-cli` (§5); edge login (§13); audit events; `IndexerSet` and `ur indexer add|rm|ls` (§3.6, §5.8, §11.13, §11.14, §15.5, §15.6, §16.8, §18.5; owner decision 150), with the Indexers paragraph's remote-search scope rule (§11.14, §18.4; owner decisions 175, 177, 178); the team directory's creation and `ServiceSettings.directory` (§16.11; D-TEAM-28).
- **Consumes:** §8 (policy, gate rows, `GrantActivate`, `Suspend`, consent, `OwnerConfirm`, `tagOwners`, `autogroup:sponsor`, `autogroup:dst-owner`, the ephemeral ceiling); §6 (push, `HeadCheck`, `Signed.type`); §10 (config and directory groups, key holders, wraps, the write gate); §11 (kind `config`, the head CAS); §5 (`sidecar_id`, binding, recovery key); §13.7 (cookies); §16 (presence and SSH keys, receipts, §16.11's directory); §18.8 (page Workers, the poll lease); §19.10 (re-seed mode); §20 (Team, `NetworkTierOf`, seats, `config_admissions`).
- **Subprotocol messages:** service 0x12, topic `team` (§6.11): `MembershipChanged`, `ApprovalRequested`, `AuthorityHeadChanged` (config head or log entry); 7.9's records are §6.11's 0x12xx `SignedType`s.
- **API routes:** all in connect/api/bringyour.yml (new 403 `RolePermissionRefused`), route_authz.go and sdk/api_network_credential.go:57.

  ```text
  Network, role-gated  POST /network/team-create; GET /network/members; POST /network/member-invite|member-remove;
                       POST /auth/network-switch; POST /network/idp; POST /network/domain-add|domain-verify|
                       domain-remove; GET|POST /network/auth-keys|oauth-clients; POST /network/auth-key-revoke|
                       oauth-client-revoke|audit-webhook; GET /network/admin-events|scim-changes;
                       GET /network/clients gains acl_enforcing (owner decision 106); POST /account/api-key
                       gains scopes and expiry
  Public               POST /network/enroll; POST /network/member-invite-accept; POST /auth/sso-discover;
                       GET /auth/sso/callback; /scim/v2/<network_id>/...; POST /oauth/device_authorization;
                       three new /oauth/token grants; published origins at /oauth/authorize
  Client               GET /network/config/projection?after=; POST /network/config/projection|delta;
                       POST /network/config/reseed (member devices but read_only ones, reseed only; 7.9);
                       GET /auth/refresh and POST /network/auth-client gain DPoP for strict_exp bearers (7.4)
  ```
- **Tables:** owner `api`; migrations 926+, before code; new columns on large tables nullable.

  ```text
  new      network_client_owner, network_team, network_member, network_invite, network_idp,
           network_idp_identity, network_domain, network_auth_key, network_oauth_client,
           network_scim_change, network_admin_event, network_audit_webhook, admin_token_use
  altered  account_api_key, auth_code (api_key_id)
  ```
- **Services and config:** `api` (log sequencer and verifier, gate cache, `rev/` writer, the only writer of `{acl_<networkId>}e` and of the append limiter's `{acl_<networkId>}q`, Redis `{dpop_<client_id>}` jtis for 120 s); `server/oauth` (grants, key sets, edge login); `taskworker` (rechecks, expiries, the reaper, `rev/` deletion, webhooks); `pro.yml` via `Pro()`; `config/<env>/sidecar.yml`'s `preview_networks` (7.4) and `reseed` (7.8, 7.9); vault (IdP secrets, OAuth keys); sidecar repo (`protocol/config.proto`; `protocol/bridge/auth.proto` for the log and what the device role verifies; verifier; `git-credential-ur`).
- **Assumptions about other sections:** §10 follows 7.9's leaves, wraps, `commit` (a reap's admission signer included) and coverage, in the team directory's group as in the config group, §10.5's key holders and rotation wraps treating that group's wrapped member devices as the config group's (D-KEYS-23), makes a generation covering an authorization expiry cause REMOVE, lets no read_only device claim `gen/`, sign a wrap or write GroupInfo while taking its own ReaderKeys, KeyPackages, path-only commits, resyncs and acks under r (§10.6's scopes), parks owner-bound Adds lacking §8.5's consent, removes a restored config leaf that lost entitlement, reads recovery bindings from the config and wraps to none that a void restored until re-signed, giving a device such a binding admitted, once activated, KF2's late ReaderWrap of the config group's current generation and a staged one at each later rotation while the tree lacks it, from which it anchors (7.9's `restored`) before it self-joins the config group, KF2 adding it to its other groups; §11.6 dates path epochs for those expiries; §4.4 and §6.11 place `auth.proto`'s messages (`ApiTick`, `ProjectionRows` with its rows, and `Suspend`, `Unsuspend` and `GrantRevoke`, which §8.8 declares there) in `protocol/bridge`, beside §6.9's `Signed`, whose `webauthn` field carries 7.9's presence countersignature, which §16.6's countersign row checks, §5.6 and §18.5 produce, and §17's device role leaves to its sidecar role (owner decisions 185, 187); §17.8 derives a decision-carrying rule's id from its effect_key; §5.4 and §18.5 alarm on admissions under a member its own keys did not sign, on each RecoveryRebind of it the device did not itself sign (`recovery_rebind`, offering to revoke the signer for compromise) and on a veto first verified after its activation, and §18.5's deny signs `RecoveryVeto`; §5.6, §5.9, §10.8 and §2.8 EX5 cite 7.9's recovery `anchor`, its `restored` order (a ReaderWrap, not an Add, under a binding a void restored) and §5.4's `head_alarm` (fork) on failure, §5.6 the cascade's `since_n`, §5.6's `recovery_window` and §18.5's veto cover a restored binding's admission proposal, and §5.9 re-seals `keychain.wrap` whenever the cascade changes the member's current binding, with no HPKE copy while none is current, and applies 7.9's backup rule to each device that sealed to a voided binding; §18.7, §18.15 and D-SDK-11 schedule the extension release that stops persisting `by_jwt` before stage 2, which §23.7 and D-PHASE-3 list inside M3's gate; §18.8 reaps by 7.7's 35 min threshold and lease row, and §6.18 and §18.17 phase the close capability and `POST /sidecar/close` with that row (MG1, M1); §18.4 states 7.9's device retention; D-TRUST-10 and §2.8 take `witness_bound_hours`, and §2.8's rows add `strict_exp`, the log and `{dpop_}`, api-4 each ephemeral client's lease (`seen_time`, at most once per 300 s) and its close capability's SHA-256, and api-7 `live_since`, `parked_at`, the signers and positions the cascade reads (AdmissionConfirms' included), recovery bindings as ids with the rest sealed, `{acl_}q` and 7.9's retention point as its ttl, while §8.8's AclRows keep each EvsShare's signer and position; §11.13 prices `proj/` and `rev/` writes as never-shed P0 within 7.9's append limits, which §20.4 carries in pro.yml; §11 and §19 keep `proj/`, `projrows/` and `rev/` on the first metadata cluster (owner decision 145); §8.9, §2.8 api-7 and §19.7 cite 7.9's `{acl_}e`, and FS-62 loses it; §19.10 resumes the log as 7.9's site loss says, I-16 names that beside EvsReseed, and FS-41 sees no FORK, refuses one member's forged TICK and resumes a Team whose other members hold only read_only page Workers from one member's uploads; FS-14 tests a stale re-signed base (api refuses it, readers FORK), a new device starting after the 30-day retention at a base folded below the previous one, a GrantActivate whose rule a new config head deleted, and a statement whose at predates the retention point after two quick bases, refused by api and every reader, a new device included; §22.7 and FS-16 test a late recovery cosign, a rebind of a cosigning code's member voiding its proposal and a veto backdated after an activation (devices past it only alarm; those before it fork until a compromise revocation of the recovered device), and a code-only recovery served a forged genesis that admits the real rotators, or a RecoveryWrap forged from M's recovery public keys (it alarms and seals nothing); §22.7's cascade case also an admission under a Delegation the device signed, a rebound key K' admitting E and E admitting F before the revocation (both parked), the revoked device's OwnerConfirm of an admin-admitted device, its only consent (parked), and of one consented otherwise (not parked), a personal network revoking its first device from a device that device admitted (refused at since_n 0, accepted at the loss position), a voided compromise rebind (the code it retired admits only through the window and gets no wrap), an admin's AdmissionConfirm of a device a parked device self-admitted (no owner-bound read until the member's own confirmation), and the restored code of a Team member whose only device was stolen (a plain SidecarAdmit refused; its proposal shown in `recovery_window` and, unvetoed, activating 72 h on with no counted cosign; the device then anchoring from the config ReaderWrap a config writer gives it, a forged one raising `head_alarm` (fork), reading the config, self-joining and offering recovery-rotate) and, in the K' case, M's device that sealed to K' re-sealing at the void and listed for compromise revocation; FS-17 a phone holder; FS-19 an ephemeral client's refused join from a member invite; and §22.7's approval suite a cancel under the allowlist; §20.4 allows Team 5,000 `config_admissions`, with no member-device cap; §2.8's api-7 shows each `IndexerSet`'s signer, subject, scope and `retire`, its services sealed, and §15.5 keeps an undesignated `tag:mail` device off the mail listener under `team_mail: indexers`; §8.8 and §11.12 refuse a second `directory` RepoCreate in a network, api also one outside the `team` tier (7.5), and §16.11 takes `ServiceSettings.directory` as the team's defaults and 7.10's `cards` row; §11.14 and §18.4 apply the Indexers paragraph's remote-search scope, and §8.8 and §11.7 seal an owner-bound repo's RepoVersioning rules to its own generation, which every reader of that repo holds; §10.5 takes a Delegation's reach from 7.9's scoped tag rule, drops its key at a Suspend of one of its agents and at its end (the delegation row), and counts an ephemeral covered agent's own not_after as no drop; §2.6, §2.10 and §2.18 disclose the split between the shared key and the admission authority; §22.7's suites, FS-18 and FS-102 test 7.9's delegation row and 7.10's agents row.

### 7.18 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| A missed `admin_user_id` read lets a member act as owner | Medium | High | classify the 133 reads; fail closed |
| A reusable auth key leaks: its reader seed reads later generations, past reaps, until its Delegation's key drops, and its signing seed admits fresh agents, which read by their own wraps, until the Delegation ends | Medium | High | expiry, uses, `max_admits`, which rows count for the Delegation's life; `not_after` ≤ 90 d, 30 d for CI; a `Suspend` or any non-reap revocation of one of its agents drops the key (§10.5); `DelegationRevoke`, whose `since_n` parks a leak's admissions, or a compromise revocation of one of its agents ends the Delegation; the revoke plan names the agent, the key and the admission authority apart (7.10) |
| A `Suspend`, or a lost or removed revocation, of one CI agent drops its Delegation's shared key, so the Delegation's later agents read only once a holder wraps to them | Medium | Low | the plan lists the agents and repos the drop reaches; the console replaces the Delegation as at a CI secret rotation (§10.5) |
| An agent drives `ur-cli` through the user's browser | Medium | High | consent code, `auth_time`, DPoP |
| Strict expiry strands an offline sidecar | Medium | Medium | early refresh; re-enrollment keeps the `sidecar_id` |
| A team loses its admin keys | Medium | High | k of n; recovery keys (owner decision 127) |
| n ≤ 2 forces k = 1: either admin alone can remove the other or change the AdminSet | Medium | High | the console recommends n ≥ 3; AdminSet notices (7.8) |
| An admin's leaked recovery code signs authority statements, alone at k = 1 | Low | Critical | the 72 h window from the newest recovery signature, a late cosign included, on every member device; any admin device vetoes; a `RecoveryRebind` of the code's member voids every pending proposal the code signed or cosigned; a server hiding that signature from every admin device defeats the veto, detected on first sight |
| A stolen recovery code admits a device under a non-admin member at once | Low | High | the member's devices alarm (owner decision 126); `RecoveryRebind` |
| A compromised AdminSet device gossips a veto backdated before a recovery activation | Low | Medium | devices that applied the activation only alarm; those still before it fork until the log reverses it, by a compromise revocation of the recovered device, whose member then recovers again; admins revoke the vetoing device (7.9) |
| An admin admits a device as a new member's first, consented under §8.5 or JIT | Low | High | the member's real device, parked, alarms; admins re-invite the member |
| SCIM deprovisioning waits for an admin's signature | Medium | Medium | server denial at once; the console's unsigned-removal list; `scim_signer` on an admin's indexer |
| No admin device online to sign a member's revocation, or no admitting device online after a reap | Medium | Medium | server denial; own-device revocations commit at once (owner decision 128); the gate refuses writes (412) |
| A designated indexer stays offline, so its services wait on their fallbacks, and a Team's mail on sender retries | Medium | Medium | per-service fallbacks (§3.6); two mail indexers (§15.6); `ur status` lists each indexer's services and newest sign of life |
| An admin designates its own device as a network-scope search indexer to collect members' queries | Low | High | no designation by default (owner decision 177); own indexers first, and other members' owner-bound repos never reach it (owner decision 126); the app names the answering member before the first query and again when it changes; a per-device `own` or `off` mode (§18.4); designations are signed and listed in every config and `ur indexer ls`; one other member's device at a time (§11.14) |
| After a site loss, one compromised member device pre-empts log positions with a forged TICK (any time_ms), a reordered statement or one it signs, forking every longer tail, or a device's longer tail goes unuploaded | Low | High | uploads only from member devices in reseed mode, matched to the restored `network_acl_head`; api adopts an entry only once devices of two members hold its digest, and checks the newest adopted base against the re-seeded config repo; a forged activation raises `recovery_unseen`; a device whose tail passes the stop sees a FORK and keeps the evidence (7.9) |
| A compromised device spends its network's daily append limit, delaying admissions and approvals | Low | Medium | revocations, Suspend and vetoes are exempt, so admins revoke it at once; 429s carry `retry_after_ms`, and the day's budget refills within 24 h (7.9) |
| A thief holding a member's unlocked device that registered no presence key, or who knows its passcode or its security key's PIN, signs what 7.9's presence row covers on a confirmation alone | Low | High | `ur login` and the apps offer a platform presence key (owner decision 142), after which every such statement needs its countersignature (owner decisions 185, 187, 189); every member device sees each revocation and offers to revoke its signer; disclosed (§2.10) |
| A device's only presence key, a security key, is lost, so the device signs nothing 7.9's presence row covers, a new key's `KeyRegister` included, until another device of its member revokes that key or its `not_after` passes | Low | Medium | `ur keys rm` from another of the member's devices, countersigned by that device's own presence key, which a device with none first registers (§16.6's register and remove rows); a second key registered while the first works; a member with no other device admits one by its recovery code (§5.9), since the lost key also blocks this device's admissions (owner decision 189) |
| A member whose devices are all page Workers, which §8.5 never consents, or one that never answers its alarms after an admin's device admits its Worker (always so with `self_admit` off), keeps each Worker that no group of the admitting device seated, one admission per eviction toward `config_admissions` (7.10's `stale` row; §20.4) | Low | Medium | admins' devices revoke every Worker they saw stale-removed (D-TEAM-29); the member's next `OwnerConfirm` or alarm answer frees the rest; from 90% of the cap every admin device lists each member's page Workers but its newest for an admin to revoke (7.10's `cleanup` row), so none waits for the cap's refusal; FS-97 |

### 7.19 Phasing

- **P0, before any sidecar:** stage 1 (D-TEAM-1, with 7.4's allowlist and auth-code fix), D-TEAM-14 and its proof.
- **v0, personal networks (§23 M1-M2):** auth keys and their bundles, enrollment, token exchange, `rev/` objects, key sets, `ur-cli`'s auth-key scope, ephemeral reaping with its lease and close capability (MG1), API-key scopes, rename unification; the enforced config repo (M2; owner decisions 3, 5): the authorization log with its read cache, append limits, fold cadence and site-loss resumption, k-of-n verifier and proposals, the presence countersignature rule (owner decisions 185, 187), recovery window, consent rule, read-only admissions, compromise cascade, Delegation ends and their parks (7.9's delegation row) with the CLI's agent and Delegation revoke plans (7.10's agents row), committers and recovery path, and `IndexerSet` (owner decision 150), tested though personal networks have n = 1; config.proto reserves `ServiceSettings.directory` (D-TEAM-28).
- **With §13's v0:** edge login.
- **v1, Team (M6):** members, roles, invitations, switching, OIDC, domains, JIT, SCIM and `scim_signer`, OAuth clients, full `ur-cli` admin, audit log, multi-admin teams, and config wraps for member devices past the first 1,000 (owner decision 144); the team directory, created with the team, its group under 7.9's leaves rule, and `ServiceSettings.directory` (owner decisions 170, 171, 182).
- **v1, every network (§23's M10, with storage format 2; owner decision 169):** `VersioningRules` (§11.7), its type reserved at M2 with 7.9's records, and `IndexerSet`'s `search` service, which includes answering remote searches (§11.14; owner decisions 157, 163, 164, 175, 178).
- **On app migration:** stage 3 (7.4).
- **Blocking:** the `admin_user_id` audit blocks members; stage 1 and D-TEAM-14 block the first sidecar, stage 2 the first desktop sidecar; token exchange and `rev/` block evs (§11); the config repo needs §10 and §11 and blocks §8's gates, and its records and log freeze at M2 (§23.8).
