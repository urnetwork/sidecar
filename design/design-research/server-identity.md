# Fact sheet: server identity, networks, clients, auth, tiers and quotas

Scope: the base for the sidecar's network/team client management, access control and usage limits.
Snapshot: server `5bb504212`, connect `49f285f1`, sdk `d0c609ee`, config `909e0ec` (all 2026-11-03).
Paths are relative to `/Users/brien/urnetwork`. "inference:" marks reasoning; everything else is cited.
Where a design note and the code disagree, the code is reported and the note is flagged. The message repo
and connect/MESSAGEREVIEW.md were ignored. No vault secret, key or certificate file was opened.

## 1. Summary

1. Identity is Network → exactly one admin User → Clients. `network.admin_user_id` is the only link from a network to a person. Token state checks, every sign-in path, API-key lookup and the `user_id` of every client token resolve through it (`server/session/by_jwt.go:659-666`, `:678-700`, `:960-1003`; `server/apikey/apikey.go:31-34`; `server/model/auth_model.go:424`). No member, team, role, group, tag or policy table exists.
2. Two credential kinds: the network credential (a `by_jwt` without `client_id`, or a `urn_` API key) and the client token (`by_client_jwt`, with `client_id`/`device_id`). JWTs carry `aud=[urnetwork:api, urnetwork:connect]` and live 30 days. API keys never expire and have no scopes or user (`server/session/by_jwt.go:62-67,157-168`; `server/session/client_session.go:236-254`; `server/db_migrations.go:2872-2885`).
3. AUTHZ1 is enforced per route class in `server/api/route_authz.go`. The 27 AppAdmin routes still accept client tokens on ordinary (non-Embed) networks. One of them, `/auth/code-create`, returns an auth code that logs in as the network, so a leaked sidecar client token can escalate to a network credential (`server/api/route_authz.go:122`; `server/model/auth_model.go:1838-1851`; `server/AUTHZ1.md:54,160-187`).
4. `network_name` rules: trim, lowercase, space→`-`, 5–50 bytes, `[a-z0-9-]`. There is no reserved list and no hyphen-position rule. Names can be renamed through three paths with inconsistent rules, and a name is free again the moment its network is deleted. Not every name is a CA-issuable DNS label, and some valid names collide with live `*.ur.network` infrastructure hosts (`server/model/network_model.go:178-206`).
5. Who can reach whom today: clients of the same network use Network provide mode, which is free and creates no escrow. Clients of different networks use Public mode, paid from the payer's escrow. `FriendsAndFamily` is defined, and its contracts skip escrow, but the server never resolves a relationship to it. The Embed `isolated` ACL group hides a client from the peer list but does not block contracts (`server/model/network_client_model.go:2258-2333`; `server/controller/connect_controller.go:847-934,1234-1246`).
6. Tiers are binary: a network is Pro iff it holds an in-window `transfer_balance` row with `pro=true`. `config/all/pro.yml` defines only `free` (2 concurrent top-level clients, 30 GiB/day) and `pro` (1000 clients, 10 TiB/month). Concurrent-client enforcement was switched on 2026-11-03 (`server/model/pro_model.go:18-22`; `config/all/pro.yml:54-57,86-100`).
7. The transfer balance is a byte ledger. Its only debit paths are contract settlement: escrow draws balances in `end_time` order, and the debit journal is keyed by `contract_id`. There is no service-usage debit and no metered (post-paid) billing (`server/model/subscription_model.go:1688-1830`; `server/db_transfer_debit_journal.go:7-16`).
8. A reusable quota pipeline exists: the Embed per-client data caps. Usage goes into Redis 30 s blocks, the `RollupClientDataUsage` task drains them, an in-memory capped snapshot refreshes every 5 s, and the refusal happens inside `createTransferEscrowInTx` (`server/model/network_client_data_cap_model.go:52-72,808,850,942`).
9. Scoped tokens exist only for MCP. An OAuth 2.1 authorization server signs 1 h audience-bound access tokens with keys disjoint from the ByJwt keys. Its scopes are `mcp:read` and `mcp:fetch`, and it supports only the `authorization_code` and `refresh_token` grants: there is no token exchange (`server/oauth/oauth.go:28-60`; `server/oauth/token.go:31-130`; `server/oauth/handlers.go:120-148`).
10. Latest migration is **version 925**: an AST count of the `migrations` slice, whose last element is at `server/db_migrations.go:11311`. Migrations are append-only and identity-hashed (`server/db_migration_catalog.go:13-34`). Ids are ULID-shaped `connect.Id` values with non-crypto entropy (`connect/id.go:17-77`).

## 2. Facts with citations

### 2.1 Data model

- `network(network_id uuid PK, network_name varchar(256) UNIQUE, admin_user_id uuid)` (`server/db_migrations.go:351-360`). Later columns: `create_time` (:1720), `guest_upgrade_network_id` (:1728), `leaderboard_public` (:1847), `contains_profanity` (:1940), `product_updates_sync` (:2480), `points_leaderboard_public`, `emoji_tag` (:6833-6836). `admin_user_id` has an index but no unique constraint (:361).
- `network_user(user_id PK, user_name varchar(128), auth_type, user_auth UNIQUE, …)` is commented `// FIXME add network_id` (`server/db_migrations.go:376-392`). Sign-in methods live in `network_user_auth_sso` / `_password` / `_wallet` / `_seedphrase`, keyed by `user_id` (:2131-2170). Every login query joins `network ON network.admin_user_id = network_user.user_id` (`server/model/auth_model.go:424,751,979,1175,1699`).
- `network_client(client_id PK, network_id, active, description varchar(256), create_time, auth_time)` (`server/db_migrations.go:551-561`), with later `device_id` (:1250), `source_client_id` (child lineage, :2109-2111), `principal varchar(256)` (:3296), `deactivate_time` (:3481) and `contract_time` (:4518). There is **no user column**.
- `device(device_id PK, network_id, device_name varchar(256), device_spec)` (`server/db_migrations.go:1260-1268`). A child client reuses its parent's `device_id` (`server/model/network_client_model.go:700-729`).
- The code comment "A client is always tied to a user" (`server/session/by_jwt.go:124-130`) does not match the code. `LoadByJwtFromClientId` builds a client token from `network.admin_user_id` (`:960-1003`), so a client's "user" is always the admin. The code wins.
- Guests: the `guest_mode` claim is deprecated and false on new tokens (`server/session/by_jwt.go:141-142`). lag.dev guest networks are recorded in the `lag_guest` table (`server/db_migrations.go:10220`) and named `lag-<uuid>` (`server/model/lag_guest_model.go:39-41`). Their tokens are refused off the two lag routes and on connect (`server/session/AUTH.md:28-38`).
- Cross-network device sharing tables exist: `device_share(source_network_id, guest_network_id, client_id, confirmed)` and `device_adopt(owner_network_id, owner_user_id, client_id, …)` (`server/db_migrations.go:1313-1356`). grep finds them only in `server/model/device_association_model.go`. inference: they play no part in contract authorization.

### 2.2 network_name: exact constraints and DNS fitness

- `ValidateNetworkName` (`server/model/network_model.go:178-206`):
  - applies `TrimSpace` and `ToLower`, then replaces `" "` with `"-"` (the comment says underscores; the code uses `-`);
  - requires 5–50 bytes;
  - accepts only `a-z`, `0-9` and `-`.
- The rule landed 2026-02-27 (`git log -S`: commit `7bb89d828`). No migration normalizes older names (searched `server/db_migrations.go` and `db_migrations_code.go`). inference: names from before that date may hold uppercase, spaces or Unicode, up to 256 characters.
- Uniqueness is the case-sensitive DB constraint `network_network_name_key` (`server/model/network_model.go:1318`). Network create and `POST /network/user/update` also refuse a name within distance 1 of any indexed name (`networkNameSearch().AnyAround(…, 1)`, :98, :1397). `/account/change-name` and `/account/claim-name` check only the exact name and the reclaim cooldown (`server/controller/account_controller.go:205-256`).
- There is no reserved-name list. Profanity is flagged in `contains_profanity` but not refused (`server/model/network_model.go:411`).
- Three rename paths, each with different rules:
  - `POST /network/user/update` (Network class) calls `model.NetworkUpdate`. It checks fuzzy and exact matches but has no rate limit and writes no cooldown for the old name (`server/model/network_model.go:1429-1481`).
  - `POST /account/change-name` (AppAdmin) is limited to 2 per day and writes a 24 h `network_name_reclaim` row for the old name (`server/controller/account_controller.go:13,160-172`; `server/model/account_action_rate_limit.go:52-53`).
  - `POST /account/claim-name` (AppAdmin) is limited to 2 per day and writes no cooldown.

  Seedphrase-only users can neither change nor claim a name (`server/controller/account_controller.go:261`).
- Network create never reads `network_name_reclaim`: no reference exists in `server/model/network_model.go` or `auth_model.go`. `RemoveNetwork` deletes the `network` row (`server/model/account_model.go:379`). inference: a released or deleted name can be registered by a new network immediately.
- Generated names: seedphrase signups get `word-word-NN` from the BIP-39 word list (`server/model/util.go:41-60`, used at `server/model/network_model.go:278`); lag guests get `lag-<36-char uuid>`.
- Fit as a DNS label:
  - 50 bytes fits the 63-octet label limit.
  - Let's Encrypt's Boulder rejects labels that start or end with `-`. It also rejects labels with `--` in positions 3–4 unless they begin with `xn` and decode to NFC punycode (`policy/pa.go`, https://raw.githubusercontent.com/letsencrypt/boulder/main/policy/pa.go). `ValidateNetworkName` accepts all of these. inference: some valid network names cannot get public certificates, and valid `xn--` names display as Unicode, which allows homographs.
- Collisions with infrastructure:
  - Live hosts already use labels that are valid network names: `main-lb`, `main-api`, `main-app`, `main-connect`, `main-web` (`xops/lb/main/nginx.conf/by-us-fmt-5-edge-0.bringyour.com-eno2.conf:184,572,1026,1116,1197`), `gossip` (`connect/EXTENDER.md:884`) and `connect` (`sdk/network_space_test.go:143`).
  - Wildcards are also in use: `*.connect.ur.network` (xops) and `*.proxy.prod.ur.network` (`server/.autobeam/manifests/httpproxy/certificate.yaml:8`).
  - The connect TLS allow-list includes `**.ur.network` (`config/main/tls.yml:3-7`).
  - The API spec already describes names as subdomains: "a network name is a globally unique subnet (xyz.ur.network)" (`connect/api/bringyour.yml:25`).
- `ur.network` is **not** on the Public Suffix List (checked against the list version dated 2026-10-31, https://publicsuffix.org/list/public_suffix_list.dat).
- Let's Encrypt limits: 50 certificates per registered domain per 7 days (an override form exists), 300 new orders per account per 3 h, and 5 duplicate certificates per 7 days (https://letsencrypt.org/docs/rate-limits/, updated 2026-08-05). inference: every `<me>.ur.network` certificate draws on one bucket of 50 per week.

### 2.3 Roles, principal, ACL groups, names (what exists)

- Roles and principal live in `network_client_role(client_id, role varchar(128))` and `network_client.principal`. They are "assigned at creation and immutable after" and carry "no meaning to the network". Each client has at most 32 roles. Only a network session with a real auth method may set them; otherwise they are inherited, for example from an auth code (`server/db_migrations.go:3284-3307`; `server/model/network_client_model.go:53-55,198-206,274-310`). They travel in the JWT (`server/session/by_jwt.go:144-147`) and in the peer list (`server/model/peer_model.go:49-58`).
- The ACL group is stored in `network_client_acl_group(client_id PK, network_id, acl_group varchar(32))`. Its only values are `default` and `isolated`, and it applies to top-level clients only. It is set with the network credential and only on Embed-enabled networks. An isolated client is not listed, gets no peer list and is not counted by the peer valve, but still counts toward client limits (`server/model/network_client_acl_group_model.go:12-43,104-120`; `server/db_migrations.go:9824-9839`).
- Client "names" are free text: `network_client.description` and `device.device_name` (256 characters each, the latter renamable). `/device/set-name` is OwnClient (`server/model/network_client_model.go:2064-2082`; `server/api/route_authz.go:244`).

### 2.4 Tokens and credentials

- ByJwt claims (`server/session/by_jwt.go:132-168`):
  - UR claims: `network_id`, `network_name`, `user_id`, `create_time` (the lineage time), `device_id`, `client_id`, `session_id`, `root_client_id`, `guest_mode`, `pro`, `roles`, `principal`, `lag_guest`;
  - registered claims: `iss=urnetwork:byjwt`, `sub=user_id`, `aud=[urnetwork:api, urnetwork:connect]`, `exp=+30d` (:62), `nbf`, `iat`, `jti`.
- Tokens are signed with the vault `jwt.yml` domain TLS keys, using the newest ECDSA key that is at least 2 h old, and carry a `kid` (`server/session/AUTH.md:53-56`).
- Verification order: signature; registered claims, gated by `auth.yml` `reject_missing_expiration` and `reject_expired` (both false per `server/session/AUTH.md:224-230`); session horizon; Redis session marker; then `ValidateByJwtState`, a single DB read (`server/session/by_jwt.go:468-545`, `:550-700`). That read checks:
  - the network exists and the token's user is its admin;
  - `create_time` is not before `credential_change_time`;
  - for a client token, the client is active, the device matches and the lineage holds.

  IDP.md §3 says ByJwt parsing validates no registered claims. The code now checks iss, aud and sub whenever they are present, and exp under its gate (`server/session/by_jwt.go:503-532` against `server/IDP.md:55-60`). The code wins.
- The connect transport requires `aud=urnetwork:connect` and a client token. An authorization lease re-checks it every 60 s and retires it after 90 s (`server/connect/transport.go:1692`; `server/connect/transport_authentication.go:38-57`; `server/session/authorization_lease.go:24-25`).
- API keys (`server/session/client_session.go:23-24,236-254`; `server/model/account_api_key_model.go:242-249`; `server/db_migrations.go:2872-2885`):
  - format: `urn_` plus 52 base32hex characters, from 32 random bytes;
  - storage: SHA-256 hex in `account_api_key(api_key_id, network_id, api_key, name varchar(128), create_time)`;
  - a request with a key authenticates as `NewByJwt(network_id, admin_user_id, …, pro=false)` and skips `ValidateByJwtState`.
- Refresh: `GET /auth/refresh` takes client tokens only and `POST /auth/network-refresh` takes network tokens only. Both keep the presented `create_time` (`server/session/AUTH.md:171-192`).
  - The SDK refreshes a client token at 40–50% of its lifetime (`sdk/device_token_manager.go:267-290`).
  - `connect.BringYourApi` has no refresh method (`connect/api.go:36-601`).
- Auth codes (`server/model/auth_model.go:1804-1830`): at most 24 h and 100 uses, at most 500 active per network, made of 512 random bytes. Logging in with one returns a network token. The client-token refusal in `AuthCodeCreate` is commented out (:1838-1851).
- OAuth / IDP (`server/IDP.md:14-48`):
  - issuer `auth.bringyour.com`, authorization page `ur.io/authorize`, resource `https://mcp.bringyour.com` (`server/mcp/auth.go:42`);
  - access tokens: 1 h, ES256, audience-bound; refresh tokens: 90 d sliding, opaque, rotated (`server/oauth/oauth.go:28-36`);
  - `AccessTokenClaims` holds `scope`, `network_id`, `client_id` (the OAuth client id), `principal` and `roles` (`server/oauth/token.go:31-42`);
  - `VerifyAccessToken` requires an audience (:98-130);
  - grants are `authorization_code` and `refresh_token` only (`server/oauth/handlers.go:120-148`);
  - MCP refuses ByJwts and API keys and turns a verified access token into an unsigned in-memory ByJwt (`server/mcp/auth.go:1-30`).
- SSO is consumer Apple or Google id tokens posted to `/auth/login`. The audience must match vault `apple.yml`/`google.yml` `client_id`, and `email_verified` is required (`server/session/sso_jwt.go:14-87`). `config/main/sso.yml` holds only `web_connect.redirect_url` (read at `server/controller/auth_controller.go:23-26`). There is no per-network or enterprise IdP, no SAML and no SCIM.

### 2.5 Route classes (AUTHZ1)

- The classes are Public, Client, OwnClient, OwnClientPayout, AppAdmin and Network (`server/api/route_authz.go:20-50`).
  - Counts at HEAD: Public 138, Client 51, Network 47, AppAdmin 27, OwnClient 5, OwnClientPayout 10.
  - `server/session/AUTH.md:116` (dated 2026-10-13) says 241 routes. The code wins.
  - An unclassified route is treated as Network (:352-357).
- `applyRouteAccess` (`server/api/route_authz.go:374-392`) adds the gates:
  - Network routes get `router.RefuseClientCredentials(…, RefuseEveryClientCredential)`;
  - AppAdmin and OwnClientPayout routes refuse a client token only when `model.NetworkRefusesClientAdmin` is true, that is when Embed was ever enabled or the network has an Embed client allowance (`server/model/network_client_admin_model.go:21-27`);
  - every route except the two lag routes gets the lag-guest gate;
  - every non-Public route gets `RefuseIntendedNetworkMismatch`, which answers 412 on an `X-UR-Intended-Network-Id` mismatch (`server/session/intended_network.go:23,106`).
- The refusal is a 403 so that it does not log the user out (`server/AUTHZ1.md:96-105`). The "hard gate", making AppAdmin routes Network everywhere, is pending (`server/session/AUTH.md:163-169`).
- Own-client limits (`server/model/network_client_model.go:360-380`): a client token creates only its own children and reissues or removes only itself and its children. A foreign id answers "Client does not exist."
- New routes must pass `TestEveryRouteIsClassified` (route_authz), `TestSpecRoutesImplemented` (every route documented in `connect/api/bringyour.yml`) and, for AppAdmin or Network routes, the sdk's `TestApiAdminRoutesMatchTheServer` (`server/api/spec_conformance_test.go:11-24`; `sdk/api_network_credential.go:57`).

### 2.6 Client creation and limits

- `POST /network/auth-client` (`server/model/network_client_model.go:188-250`):
  - request: `client_id?`, `source_client_id?`, `description`, `device_spec`, `roles?`, `principal?`, `proxy_config?`, `provide_intent?`, `time_zone?`, `locale?`;
  - response: `by_client_jwt`, `client_id`, `error{client_limit_exceeded, upgrade_required, message}`, `proxy_config_result`;
  - the handler first settles an inline x402 `X-PAYMENT`, and answers 402 with payment terms when an upgrade is required (`server/api/handlers/network_client_handlers.go:22-36`; `server/controller/x402_controller.go:849-905`).
- `POST /network/register-client-v1` (Network class) is the idempotent variant. Its schema is `urnetwork-client-registration-v1`, with `registration_id` and `scope_sha256`, and it stores the minting `user_id` (`server/model/network_client_registration.go:24-31,120-125,274`; `server/CLIENT-REGISTRATION.md:1-11`).
- Client limits:
  - Active top-level clients are capped at `LimitTopLevelClientIdsPerNetwork=100`, overridable up to 10,000,000 per network through `network_top_level_client_limit`. The cap applies only while `Pro().EnforceConcurrentClients` is on (`server/model/network_client_model.go:51,652-675`; `server/model/network_client_limit_model.go:13-28`).
  - Concurrent connected top-level clients are capped per tier (free 2, pro 1000), both at creation and at connection activation (`server/model/network_client_model.go:502-512`; `server/model/peer_model.go:1510-1561`). Over the limit, the connection is closed with code 4001 (`server/connect/provider_intent.go:52`).
  - Child clients and provider-intent installs never count.
  - `LimitClientIdsPerNetwork=100000` is never referenced. inference: nothing caps child creation.
- Lifecycle:
  - A top-level client idle for 30 days (no auth, no connect, no live connection) is deactivated, then hard-deleted 30 days later (`server/model/network_client_model.go:3905-3925,3982-4030`).
  - A child's connect refreshes its direct parent's `auth_time` (:3456-3500).
  - The comment saying client ids are "never revoked" (:81-84) is contradicted by this reaper. The code wins.

### 2.7 Reachability today

- `GetProvideRelationshipDetails` returns Network mode for the same client or the same network, and Public otherwise (`server/model/network_client_model.go:2258-2333`).
- `CreateContract` requires the destination to advertise the resolved mode, or Stream as a fallback, and answers NoPermission otherwise (`server/controller/connect_controller.go:847,915-934`; `resolveNonCompanionProvideMode` at :734).
- Payer: Network and FriendsAndFamily contracts escrow nothing, a companion contract is paid by its destination, and every other contract by its source (:1234-1246,1332-1350).
- `FriendsAndFamily = 2` exists in `connect/protocol/transfer.proto:354-361` and `server/model/network_client_model.go:76`, but no relationship resolution produces it (grep).
- The peer registry is Redis per network, with dirty-counter polling. Pubsub was dropped after it melted Redis on 2026-07-15 (`server/model/peer_model.go:25-36`). Categories are Client, Proxy, Provider and Isolated (:59-75). `GET /network/peers` is Client class (`server/api/route_authz.go:159`).
- Precedent for a service that runs as a client: hosted proxy devices run on hosted-session tokens of the network's own clients, minted by `session.MintHostedSession` (`server/session/session_mint.go:152-191`).

### 2.8 Tiers, balance, charging

- Pro entitlement (`server/model/pro_model.go:15-55,164-217`):
  - a network is Pro iff it holds an in-window `transfer_balance.pro=true`;
  - the answer is cached 60 s in Redis and 5 s in process, and `UpdateProNetwork` refreshes it after a commit;
  - data codes write `pro=false` (`config/all/pro.yml:210-217`).

  `server/PRO_ENFORCEMENT_PLAN.md:9,20` describes Pro as any paid balance, says `by_jwt.go:516` hardcodes `pro=false`, and places `pro.yml` under `config/main`. The code has the `pro` column, `LoadByJwtFromClientId` computes `pro` (`server/session/by_jwt.go:968-976`), and the file is `config/all/pro.yml`. The code wins.
- Plan config: `ProConfig.Tier(pro bool)` is binary (`server/model/pro.go:454`). SOCKS and WireGuard are Pro-only, but `enforce_features: false` (`config/all/pro.yml:63,90-95`). The `pro.yml` comment that exempts public providers (:43-44) is superseded by provider intent (`server/PRO_ENFORCEMENT_PLAN.md:78-90`).
- `subscription_renewal(network_id, subscription_type varchar(32), start_time, end_time, …)` has only the type `supporter`. Markets are apple, google, stripe, solana, manual, x402, monero and zcash (`server/db_migrations.go:1687-1697`; `server/model/subscription_model.go:5695-5712`).
- `transfer_balance` holds `balance_id`, `network_id`, `start_time`, `end_time`, `start_balance_byte_count`, `balance_byte_count`, net revenue columns, generated `paid` and `active`, `pro` and `grant_kind` (`server/db_migrations.go:742-754,1653-1656,3385-3393,9578`; struct at `server/model/subscription_model.go:293-316`).
- Charging:
  - `createTransferEscrowInTx` sorts the payer's balances by `end_time`, then `start_time`, and refuses with "Insufficient balance (n)." (`server/model/subscription_model.go:1688-1830`).
  - Debits happen only in settlement code (`server/model/subscription_transfer_debit.go:267`; `subscription_contract_scheduled_close.go:279`; `subscription_model.go:4170`).
  - The debit journal's primary key is `(balance_id, contract_id)`, with no foreign key (`server/db_transfer_debit_journal.go:3-16`).
- Grant tasks: `RefreshFreeTransferBalances`, `RefreshProTransferBalances` and `RefreshReferralTransferBalances` (`server/controller/subscription_controller.go:2156-2330`). grep finds no metered-billing code.

### 2.9 Quota and rate-limit mechanisms

- Account action budgets: `CheckAndRecordAccountActionRateLimit` counts `network_user_action_attempt` rows over a trailing window and keeps them 48 h. It can be keyed by user, client or address hash (`server/model/account_action_rate_limit.go:15-20,199-300`).
- `rateLimitError` becomes a 429 with `Retry-After` (`server/model/rate_limit_error.go:9-22`; `server/router/handler_utils.go:604-609`).
- `CheckIpRateLimitAttempt` is Redis-backed (`server/ip_ratelimit.go:331`), and `TokenBucket` is in-process (`server/token_bucket.go:11`).
- Also available: the data-cap pipeline (§1.8), the client-allowance override (§2.6) and the connected count from the peer registry.

### 2.10 x402

- SKUs are `pro_1month`, `data_1tib` and `data_10tib`. Amounts come from `pro.yml` and prices from vault `x402.yml`. The feature is inert unless `x402.yml` is enabled; it settles to Stripe deposit addresses through the CDP facilitator, using the `X-PAYMENT` retry header (`server/controller/x402_controller.go:24-62,88-212`).
- Settlement calls the same grant seams as the other payment rails (`server/PRO_ENFORCEMENT_PLAN.md:7,38-43`).
- List prices: data at $3 per TiB or $20 per 10 TiB; Pro at $5 a month or $40 a year, and $0.5 or $4 on the regional tier (`config/all/pro.yml:104-107,173-176,218-224`).

### 2.11 API conventions

- Routes are declared as `router.NewRoute(method, regexPattern, handler)` and `NewStreamingRoute` inside `routesWithReservedAttemptUpload`. Path parameters come from `router.GetPathValues`. The list ends with `return applyRouteAccess(append(routes, oauth.Routes()...))` (`server/api/api.go:22-52,441`; `server/router/router.go:49-65,221`).
- Handlers in `server/api/handlers` wrap model or controller functions (`server/router/handler_utils.go:165-553`):
  - `WrapRequireAuth`, and `WrapRequireClient`, which guarantees a `ClientId`;
  - `WrapWithInputRequireAuth` and `WrapWithInputRequireClient`;
  - `WrapNoAuth`, `WrapOptionalAuth` and `WrapWithInputNoAuth`.

  JSON request bodies are capped at 16 MiB (:42).
- Errors (`server/router/handler_utils.go:27-36,154-163,555-632`):
  - an error string that starts with `NNN ` sets the HTTP status;
  - a failed authentication answers 401 "Not authorized.", and a dependency outage answers 503;
  - most refusals answer HTTP 200 with `{"error":{"message"}}`, the "auth-client house style" (`server/EMBED1.md:71-72`);
  - plain-text error bodies are the default unless a route documents otherwise (`connect/api/bringyour.yml:39-40`).
- Ids: `server.Id` wraps `connect.Id`, a 16-byte ULID-shaped value: a 48-bit millisecond timestamp plus 80 bits of monotonic `math/rand` entropy. Its text form is the 36-character lowercase UUID, and 32-hex is also parsed (`server/id.go:14-23`; `connect/id.go:17-77,149-171`). inference: ids are guessable and must never serve as secrets.

### 2.12 Migrations

- To add one, append to `migrations []any` in `server/db_migrations.go` with `newSqlMigration`, `newOnlineSqlMigration` or `newRestartableOnlineSqlMigration` (both require an `auditSql` twin) or `newCodeMigration`. Larger DDL goes in a constant in `server/<name>_schema.go`.
  - The version is the slice index plus 1. HEAD holds 925 entries (AST count).
  - Each migration's identity is hashed with SHA-256 into `migration_catalog` and verified at startup (`server/db_migrations.go:24-121,170-233`; `server/db_migration_catalog.go:13-34`).
  - Style: varchar, never ENUM, and fully qualified column names (`server/db_migrations.go:232-233`).
  - Owner rule: a migration is applied only after merge, pull and push (`server/EMBED1.md:3-6`).

### 2.13 Module facts

- `server/go.mod` requires both connect and sdk through `replace ../connect` and `replace ../sdk` (`server/go.mod:48,51,213-227`).
- `connect/go.mod` replaces glog (`../glog`), sctp (`./sctp`) and gvisor (`../gvisor`) (`connect/go.mod:98-102`). inference: the sidecar module must mirror these, because replace directives are not transitive.
- `connect.BringYourApi` already offers `AuthLogin`, `AuthCodeLogin`, `AuthNetworkClientSyncWithCtx`, `RemoveNetworkClientSync`, `FindProviders2` and `ConnectControl` (`connect/api.go:36,278`).

### 2.14 Answers to the four questions (inference unless cited)

**(a) Multiple users per network, roles, SSO, groups and tags.**
1. Add `network_member(network_id, user_id, role, status, invited_by, …)` and keep `admin_user_id` as the immutable owner of record. The refusal cache and the revocation record both assume `admin_user_id` never changes (`server/session/state_refusal_cache.go:8-14`; `server/session/revocation_record.go:14`).
2. Make both `ValidateByJwtState` queries (`server/session/by_jwt.go:659-666,678-700`), the revocation record and the session-operation actor check (`server/session/session_operation.go:187`) accept active members.
3. Record which user created each client, either in a new `network_client.user_id` column or by reusing `network_client_registration.user_id`. Then mint client tokens for that user (`server/session/by_jwt.go:960-1003`), and deactivate a member's clients when the member is removed.
4. Add a network choice to every sign-in path; today each one joins on the admin (`server/model/auth_model.go:424…`). The IDP already binds the network at authorization time (`server/IDP.md:33-48`).
5. Add a role gate next to `RefuseClientCredentials`. Today's classes check only the credential kind.
6. Give API keys a creator and scopes, or keep them owner-only.
7. Review the other admin-keyed paths: `RemoveNetwork` deletes only the admin's sign-in rows (`server/model/account_model.go:295-379`), and security notices go to the admin.
8. Team SSO: add a per-network OIDC/SAML connection, domain verification, just-in-time membership with a default role, and SCIM 2.0 (https://www.rfc-editor.org/rfc/rfc7644). Deprovisioning revokes the member's sessions and deactivates their clients.
9. Add mutable `network_client_tag` and `network_group`/`network_group_member` tables. They are separate from roles, which are immutable. Follow the Tailscale model: tags are identities for non-human devices, and `tagOwners` decide who may apply them (https://tailscale.com/kb/1068/tags). Positioning wants free read-only seats (`sidecar/improvements4.md:251`) and signed membership so that a breached server cannot add a reader (`sidecar/improvements4.md:229`).

**(b) Where to store, compile and authorize an access-control policy.**
- Store: in server Postgres, a versioned `network_access_policy` table plus a history table for audit.
- Compile: a pure-Go parser, validator and compiler in the sidecar repo (owner rule). The server imports it to validate on write and to compile. Clients import the same package for local enforcement of the bridge rules.
- Distribute: a Redis per-network version counter that readers poll, as the peer registry does, rather than pubsub. Push each client the compiled slice that affects it over the subprotocol.
- Decide (server-authoritative), at these points:
  - in `controller.CreateContract`, between `getProvideRelationshipDetails` (:847) and `resolveNonCompanionProvideMode` (:921);
  - at abstract-socket accept;
  - at the TLS and SMTP edges;
  - when filtering `/network/peers`.
- Keep it in memory: contract creation is a hotspot (`server/model/subscription_model.go:1727-1730`). Use an in-process snapshot like the data-cap snapshot, so a network with no policy adds no query.
- Cross-network grants need a mode other than Public. If they map to FriendsAndFamily, the traffic becomes free, because that mode creates no escrow.

**(c) How a sidecar client should authenticate.**
- Today a client token works on any new api route wrapped with `WrapRequireClient`, and on connect. But it is a 30-day bearer token: it can buy through x402 (Client class) and, on ordinary networks, can escalate through the AppAdmin routes.
- Recommendation:
  - Make the sidecar a child client of the device's client. Children do not count against the free tier's 2 concurrent clients, and the child's connect keeps the parent from idling out.
  - Keep that token out of the harness.
  - For HTTP services such as git over HTTPS, DNS and TLS, add an RFC 8693 token-exchange grant (https://www.rfc-editor.org/rfc/rfc8693) to the existing authorization server: subject token = client JWT, resource = the service URI, plus scopes. Mint with `oauth.MintAccessToken` and verify with `oauth.VerifyAccessToken(token, aud)`, which needs no DB read. Add a UR client-id claim, because `AccessTokenClaims.ClientId` is the OAuth client id.
  - Git 2.46+ credential helpers can return `authtype=Bearer` with `credential` and `password_expiry_utc` (https://git-scm.com/docs/git-credential; 2.46 release notes, https://www.kernel.org/pub/software/scm/git/docs/RelNotes/2.46.0.adoc).
  - A stdio MCP server "SHOULD NOT" use the OAuth flow and must not pass tokens through (https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).
  - Subprotocol traffic is already authenticated by the connect transport.
  - Mark sidecar clients so that admin routes refuse them on every network.

**(d) Quotas.**
- Limits: add per-tier fields to `proTierYaml` (`storage_bytes`, `emails_per_day`, `dns_entries`, `tls_endpoints`) and a `team` tier. `Tier(pro bool)` then has to take a tier, and Team needs its own entitlement source.
- DNS entries and TLS endpoints: count rows inside the create transaction, under a per-network lock (the pattern of `LockSessionLifecycle` and `countNetworkActiveTopLevelClients … LIMIT n+1`).
- Emails per day: a per (network, UTC day) Redis counter, or an account-action budget, answering 429 with `Retry-After`. An abuse report sets a one-day halt flag.
- Storage bytes: a gauge the storage service updates on every commit, reconciled offline. `MeasureBlobUsageAtPrefix` lists every object, so it is launch and preflight only (`server/blob.go:263-278`).
- Charging: a new service-usage debit journal and worker, modeled on `transfer_debit_journal` and `FlushTransferDebits`, that draws balances in `end_time` order and feeds the usage tables for caps. Service usage has to be priced in byte-equivalents. If services ran as hosted clients inside the user's network, their traffic would be Network mode and would never be charged.
- Delivery of refusals: 402 with x402 terms for agents (the `WriteX402UpgradeRequired` pattern), and the `upgrade_required` code for apps.

## 3. Constraints the design must respect

1. The sidecar imports connect only. It cannot use `server.Db`, `session.*` or `model.*`, so service code in the sidecar repo must receive auth, quota and storage implementations from server through interfaces (PLAN.md:7).
2. Every DB change is a server migration appended at version ≥926. Published migrations are identity-hashed, so any schema constant exported by the sidecar is frozen once released (`server/db_migration_catalog.go:13-34`).
3. A client token must never administer the network. New admin routes are Network class, unclassified routes default to Network, and 403 is the refusal code, never 401 (`server/api/route_authz.go:352-357`; `server/AUTHZ1.md:96-105`).
4. Keep `network.admin_user_id`, `network_client.network_id`, `device_id` and `source_client_id` immutable, and never reactivate a client. The refusal cache depends on all of these (`server/session/state_refusal_cache.go:8-14`).
5. OAuth signing keys must stay disjoint from the `jwt.yml` keys, and every resource server must name its audience when verifying (`server/IDP.md:52-75`).
6. Contract creation is a hotspot: new checks need an in-memory snapshot and must add no query for networks that lack the feature (`server/model/subscription_model.go:1727-1730`).
7. Network names are mutable and reclaimable. DNS zones, socket names, email and certificates should key on `network_id` (inference from §2.2).
8. Free tier: 2 concurrent top-level clients, enforced since 2026-11-03. A sidecar that runs as a top-level client takes one of the two slots (`config/all/pro.yml:54-57,87`).
9. Top-level clients idle for 30 days are deactivated and reaped. Durable references such as git identity, policy or MLS leaves cannot rely on a raw client id alone (`server/model/network_client_model.go:3905-3925`).
10. New routes must be documented in `connect/api/bringyour.yml`, classified in route_authz, and added to the sdk admin table (§2.5).
11. Postgres style: varchar rather than ENUM, and fully qualified columns. Fan-out uses Redis counters with polling, not pubsub (`server/model/peer_model.go:32-36`).
12. The transfer balance is in bytes and Pro is binary. Every new limit needs a byte price or a new entitlement model.

## 4. Reusable pieces

- Session and auth (`session` package):
  - functions: `ParseByJwtForAudience`, `ValidateByJwtState`, `ValidateByJwtStateInTx`, `ByJwtNamesClientUnverified`, `LoadByJwtFromClientId`, `MintHostedSession`, `LockSessionLifecycle`, `CheckIntendedNetwork`;
  - types and constants: `ByJwt.Client()` and `ByJwt.Renew()`, `ClientSession.ApiKeyAuthenticated`, `ByJwtAudienceApi/Connect`.
- Routing: `router.NewRoute`, `NewStreamingRoute`, `GetPathValues`, `RefuseClientCredentials`, `RefuseEveryClientCredential`, `RefuseIntendedNetworkMismatch`, and the `Wrap*` family (§2.11); `RaiseHttpError` with the `NNN message` convention; `api.applyRouteAccess` and `routeAccessByRoute`.
- Clients:
  - creation and identity: `model.AuthNetworkClient`, `AuthNetworkClientFromParent`, `RegisterNetworkClient`, `validateClientIdentityArgs`;
  - lookup and limits: `GetNetworkClient`, `GetProvideRelationshipDetails`, `GetProvideModes`, `NetworkConcurrentClientsExceeded`, `CanConnectNetworkPeer`, `networkTopLevelClientLimitInTx`, `countNetworkActiveTopLevelClients`;
  - Embed controls: `NetworkRefusesClientAdmin`, `NetworkEmbedEnabled` (with its 30 s cache), `SetNetworkClientAclGroup`.
- Plans and balances: `model.Pro()`, `ProConfig.Tier`, `IsProNetwork`, `IsProFresh`, `UpdateProNetwork`, `NetworkFeatureAllowed`, `AddTransferBalanceInTx`, `GetActiveTransferBalances`, `createTransferEscrowInTx`, `FlushTransferDebits`.
- Quotas and rate limits: `RecordClientDataUsage`, `RollupClientDataUsage`, `clientDataCapEscrowError`, `CheckAndRecordAccountActionRateLimit`, `rateLimitError`, `server.CheckIpRateLimitAttempt`, `server.TokenBucket`.
- Payments: `controller.X402PaymentRequiredFor`, `WriteX402PaymentRequired`, `X402SettleInlineUpgrade`.
- OAuth: `oauth.MintAccessToken`, `VerifyAccessToken`, `ParseScope`, `HasScope`, `Issuer`.
- Network names: `model.ValidateNetworkName`, `FindNetworkByName`, `NetworkNameTx`, `RaiseNetworkNameWrite`, `IndexNetworkNameInTx`.
- Ids: `server.NewId` and `connect.NewId`, with `ParseId`.
- Storage, DNS and TLS: `server.MeasureBlobUsageAtPrefix`; Route 53 DNS publishing and DNS-01 ACME in `server/taskworker/work/extender_dns_publish.go` and `extender_measurement_acme.go`.
- Client side: `connect.NewBringYourApi`, `SetByJwt`, `AuthNetworkClientSyncWithCtx`, `AuthCodeLoginSync`; the sdk refresh scheduler in `sdk/device_token_manager.go` (sdk only).

## 5. Gaps, risks, surprises

1. **Client-token escalation.** On ordinary networks, `/auth/code-create` (AppAdmin) mints a network-login code from a client token. A sidecar token that an agent can read is effectively an admin credential until the hard gate lands (`server/model/auth_model.go:1838-1851`).
2. **Name takeover.** Deletion frees a name at once, and network create ignores the 24 h reclaim. `/network/user/update` renames without any cooldown. DNS zones, email and certificates bound to names can be hijacked (§2.2).
3. **Infrastructure collision.** `connect`, `gossip`, `main-api` and similar labels are valid network names, and `*.connect.ur.network` is already a wildcard host (§2.2).
4. **Certificate and PSL limits.** `ur.network` is not on the PSL, so all user certificates share the 50 per week per registered domain limit. Without a PSL entry, user subdomains are also same-site with `api.ur.network`.
5. **Non-issuable names.** Hyphen-edge and `??--` names are valid network names, and names from before 2026-02-27 were never validated.
6. **Isolation is not access control.** The isolated ACL group does not block contracts, and FriendsAndFamily exists in the enum but nothing produces it.
7. **No charge path for services.** Network-mode contracts are free and unmetered, and nothing debits a balance outside settlement.
8. **No Team entitlement.** `pro` is a boolean; there is no team plan, seat or metered-overage billing.
9. **Missing pieces for the sidecar.** The OAuth authorization server lacks token exchange, there is no per-network IdP, and API keys have no scope or creator.
10. **Doc drift.** AUTHZ1 and IDP cite `jwt/by_jwt.go`, which is now `session/by_jwt.go`. IDP.md §3 claim validation, PRO_ENFORCEMENT_PLAN's IsPro and `config/main/pro.yml`, and the AUTH.md route counts are all stale.

## 6. Open questions for the owner

1. Should zones be `<network_id>`-based with the name as an alias, and what tombstone period should a released name carry once it has DNS, email or certificates?
2. May we add a reserved-name list, retroactively refuse hyphen-edge and `??--` names, and run a census of legacy names that fail `^[a-z0-9]([a-z0-9-]{0,48}[a-z0-9])?$`?
3. Should `ur.network` user zones go on the PSL private section, or move to a separate apex?
4. Should sidecar clients be marked so that AppAdmin routes refuse them now, ahead of the hard gate?
5. Team identity: keep `admin_user_id` as the immutable owner and add members? Which roles, and is a viewer seat free?
6. Should cross-network policy grants be free (FriendsAndFamily, no escrow) or payer-escrowed?
7. How should storage, email, DNS and TLS usage be priced in transfer-balance bytes, and is Team overage post-paid through Stripe meters?
8. Is RFC 8693 token exchange on `auth.bringyour.com` acceptable as the sidecar's scoped-token path?
