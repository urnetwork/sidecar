# Tailscale device/client onboarding and join experience (end to end)

_Scope: how a new device/client joins a tailnet and how easy each path is, from one human running one command to enterprise mass-enrollment. Focus = join mechanics and UX. SSO/identity internals and ACL syntax are covered by other researchers. All URLs accessed 2026-11-01; findings reflect Tailscale KB/docs as of that date. Tailscale has two overlapping doc trees live simultaneously — legacy `tailscale.com/kb/NNNN/...` and newer `tailscale.com/docs/...` — and some articles note beta/alpha status; flagged where seen._

## Key Question 1 — The interactive join (`tailscale up`, browser/SSO flow, registration, naming, MagicDNS): how many steps to a working client?

### Takeaway
A brand-new tailnet is a 6-step wizard (account + first device + second device); adding one more client to an *existing* tailnet is effectively 3 user actions — install, run `tailscale up`, complete SSO in the browser — after which the device auto-registers unless device approval is on. The "login" is an SSO identity-provider flow surfaced via a one-time login URL, not an email magic-link.

### Cited Findings
- The official quickstart ("Create a tailnet") is **6 numbered steps**: (1) go to tailscale.com / install the client; (2) log in with an SSO identity provider; (3) choose Business or Personal use; (4) on "Let's add your first device," select OS and authenticate the client with the same SSO credentials — "once authenticated, the device appears in the browser window"; (5) "add a second device" by selecting its OS and copying a link to send to it; (6) select "Take me home" to open the admin console — [Tailscale quickstart](https://tailscale.com/docs/how-to/quickstart).
- `tailscale up` "connects the device to Tailscale and authenticates if needed"; running it with no flags connects the device — [CLI reference](https://tailscale.com/kb/1080/cli).
- `tailscale login` logs in and adds the device to the tailnet; `--qr` generates a QR code "for the web login URL" (implying `up`/`login` surface a web login URL the user opens) — [CLI reference](https://tailscale.com/kb/1080/cli).
- Device naming: each device gets a unique name generated from its OS hostname, shown on the Machines page and renamable there; `--hostname=<name>` overrides the OS hostname and also changes the MagicDNS name — [CLI reference](https://tailscale.com/kb/1080/cli); [Quickstart](https://tailscale.com/docs/how-to/quickstart).
- Each device is assigned a unique `100.x.y.z` Tailscale IP — [Quickstart](https://tailscale.com/docs/how-to/quickstart).
- MagicDNS is **enabled by default** for tailnets created on/after **October 20, 2022**; older tailnets enable it on the DNS page. It auto-registers DNS names so devices are reachable by machine name (e.g. `monitoring.yak-bebop.ts.net`), and search domains are added so `ping monitoring` works — [MagicDNS KB](https://tailscale.com/kb/1081/magicdns).
- The legacy `.beta.tailscale.net` name format stopped being supported on **September 13, 2024**; names now use `<machine>.<tailnet>.ts.net` — [MagicDNS KB](https://tailscale.com/kb/1081/magicdns).
- `tailscale status` shows Tailscale IP, machine name, owner email, OS, and connection status (`active`/`idle`/`-`) — [CLI reference](https://tailscale.com/kb/1080/cli).

### Inferences
- "Steps to a working client" depends on starting point: ~3 interactive actions to add a client to an existing tailnet (install → `tailscale up` → click through SSO), vs. the 6-step wizard for a first-time tailnet, vs. a single non-interactive command with an auth key (see Q2).
- The browser flow is SSO (identity-provider) auth reached through a one-time login URL, not an email magic-link; "magic-link" semantics in Tailscale apply to invite/share links (Q5), not to device login.
- **Control-plane dependency flag (recURd relevance):** registration, device naming/MagicDNS records, and the login URL are all brokered by the coordination server — the control plane learns of and names every device and holds the registration state.

### Gaps
- The quickstart page does not itself show `tailscale up` or describe the automatic browser launch per-OS; exact per-platform first-run screens (GUI auto-opens browser vs. CLI prints "To authenticate, visit: …") were not captured verbatim from a single primary page.

## Key Question 2 — Auth keys (types, creation, use, limits, caveats)

### Takeaway
Auth keys let a device register without a browser, enabling one-command headless joins (`tailscale up --auth-key=<key>`). Keys come in one-off vs. reusable flavors with optional ephemeral / pre-approved / tagged settings and a 1–90-day validity; reusable keys are explicitly called "very dangerous if stolen." Tailscale now recommends OAuth clients + API as the programmatic alternative.

### Cited Findings
- Auth keys ("pre-authentication keys") register nodes without web sign-in; suited to containers, IoT, IaC (Terraform), and iOS/Android. A key authenticates the device **as the user who generated it**; if the key has tags, the device takes on the tags' identity — [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).
- **One-off** keys connect a device once and are revoked automatically after use; **reusable** keys connect multiple devices. "Reusable keys are very dangerous if stolen" — store in a dedicated key vault — [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).
- **Expiry:** validity is selectable **1 to 90 days inclusive**; if unspecified, the key expires at the max of **90 days**. There is no documented way to extend a key — you "generate a new key." Devices authorized by an expired key stay authorized until their *node key* expires — [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).
- **Device settings set at generation:** *Ephemeral* (device auto-removed after going offline; for containers/Lambda); *Pre-approved* (auto-authorizes when device approval is enabled — option only appears if approval is on); *Tags* (optional toggle — a key can be created without a tag) — [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).
- **Create (admin console):** must be Owner/Admin/IT admin/Network admin → Settings > Keys → "Generate auth key" → fill form → "Generate key." Keys are **case-sensitive** — [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).
- **Create (programmatic):** the page recommends an OAuth client + Tailscale API rather than a direct documented "create key" call — [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).
- **Use (CLI):** `sudo tailscale up --auth-key=<key>` supplies the key and skips interactive login (note: flag is `--auth-key`, documented under `tailscale login`; some docs write `--authkey`) — [Auth keys KB](https://tailscale.com/kb/1085/auth-keys); [CLI reference](https://tailscale.com/kb/1080/cli).
- **Use (mobile):** in the app's sign-in screen menu select "Use an auth key," paste, confirm; admins can push keys to managed devices via the `AuthKey` MDM policy — [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).
- **Revocation:** admin role required; you can revoke only your own keys; revoking does **not** deauthorize already-joined nodes (delete them on the Machines page) — [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).
- **Tailnet Lock:** keys can be pre-signed only via `tailscale lock sign` — [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).
- Pre-approved keys bypass manual approval **only** when device approval is enabled for the tailnet — [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).

### Inferences
- No documented cap on number of keys (page is silent), so key-count is unlikely to be an onboarding bottleneck.
- The security model centers on the key being a bearer secret that maps a new device to a user/tag identity; one-off + short TTL + tags is the recommended low-risk headless pattern.
- **Control-plane dependency flag (recURd relevance):** the coordination server mints and stores the auth key and validates it at registration time; the device presents a key the control plane issued and recognizes. Pre-approval and tag assignment are also control-plane-held state.

### Gaps
- No primary-sourced maximum key count or per-plan key limits found.

## Key Question 3 — OAuth clients for automation/CI (minting auth keys with scopes/tags)

### Takeaway
OAuth clients are the recommended long-lived automation credential: a client ID + secret (created on the "Trust credentials" page) that exchange for a 1-hour API token and mint short-lived, tag-bound auth keys on demand via the API, so no 90-day key sits in CI. They require tags and never expire themselves.

### Cited Findings
- OAuth client = ongoing API access via OAuth 2.0 client-credentials; exchanges client ID+secret at `https://api.tailscale.com/api/v2/oauth/token` for an access token scoped to the client — [OAuth clients KB](https://tailscale.com/kb/1215/oauth-clients).
- Scopes named on the page: `dns:read`; `devices:core` (read/write device list, authorize/remove machines, manage tags); `auth_keys` (needed to generate auth keys and to register nodes with `tailscale up --auth-key`); `all`; `devices` (in example response) — [OAuth clients KB](https://tailscale.com/kb/1215/oauth-clients).
- Minting keys: with `auth_keys` scope the client calls `POST /api/v2/tailnet/:tailnet/keys` for a fresh key each time, replacing a long-lived key; regular auth keys expire after 90 days and one-off keys expire once used — [OAuth clients KB](https://tailscale.com/kb/1215/oauth-clients).
- **Tags required:** creating a client with `auth_keys` requires selecting one or more tags, and minted keys must use those tags; OAuth-registered devices are **tag-owned, not user-tied**. For multiple tags, use a `tag:...-tag-owner` that owns the others — [OAuth clients KB](https://tailscale.com/kb/1215/oauth-clients).
- **Lifetimes:** API access tokens expire after **1 hour** (not changeable); OAuth clients themselves are not documented to expire and keep working even after the creator loses tailnet access — [OAuth clients KB](https://tailscale.com/kb/1215/oauth-clients).
- When registering with an OAuth secret, the `ephemeral` parameter defaults to **true**; URL-style params are `ephemeral`, `preauthorized`, `baseURL` — [OAuth clients KB](https://tailscale.com/kb/1215/oauth-clients).
- **Create:** Trust credentials page → "Credential" → "OAuth" → choose Read/Write per operation → Generate → copy client ID + secret (secret shown once) — [OAuth clients KB](https://tailscale.com/kb/1215/oauth-clients).
- **CI examples:** `tailscale up --auth-key=${OAUTH_CLIENT_SECRET} --advertise-tags=tag:ci`; or the `get-authkey` utility (needs Go 1.23+): set `TS_API_CLIENT_ID`/`TS_API_CLIENT_SECRET` then `go run tailscale.com/cmd/get-authkey@latest -tags tag:development`. Client libraries exist for Go, Node, PHP, Ruby, Rust — [OAuth clients KB](https://tailscale.com/kb/1215/oauth-clients).

### Inferences
- OAuth clients are the designed answer to "don't paste a 90-day reusable key into CI": CI holds a non-expiring client secret and mints a disposable tagged key per run.
- **Control-plane dependency flag (recURd relevance):** the OAuth secret authorizes the control plane to mint keys and bind tag identities server-side; the coordination server is the key-minting authority and holds the scope/tag grants.

### Gaps
- Full scope catalog is not on this page (it points to "Trust credentials" docs); exact current scope list beyond those named was not fully enumerated.

## Key Question 4 — Device approval, device/key expiry, re-auth cadence and UX

### Takeaway
Device approval (all plans) hard-gates a new device — it can't pass traffic until an admin clicks Approve on the Machines page, unless it used a pre-approved key. Separately, node keys expire by default at 180 days (6 months), after which the device goes offline until the user re-authenticates (`tailscale up --force-reauth`); tagged devices have expiry disabled by default, and there is no documented advance-warning notification.

### Cited Findings
- **Device approval** is available on **all plans**; Owner/Admin/IT admin enables it on the Device management page. An unapproved device shows "awaiting approval" and **cannot send or receive traffic** until approved — [Device approval KB](https://tailscale.com/kb/1099/device-approval).
- Approving: Machines page → device shows a **"Needs approval"** badge → open device menu → **Approve**; connects immediately, no restart/toggle needed. A device shared by multiple users / used for multiple nodes needs approval only once — [Device approval KB](https://tailscale.com/kb/1099/device-approval).
- Pre-approved auth keys auto-approve (option appears only when approval is enabled), bypassing the manual step — [Device approval KB](https://tailscale.com/kb/1099/device-approval); [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).
- Automation: set a `nodeNeedsApproval` webhook, verify against your criteria, then approve/revoke via the device authorization API with `{"authorized": true}` / `{"authorized": false}` — [Device approval KB](https://tailscale.com/kb/1099/device-approval).
- **Node/machine key expiry:** new domains default to **180 days**; admins can set a custom period **1–180 days** on the Device management page (Key Expiry section → Save). The change applies only to devices that log in after saving — [Key expiry KB](https://tailscale.com/kb/1028/key-expiry).
- At expiry, "connections to and from the endpoint stop working"; the page describes **no advance warning/notification** — [Key expiry KB](https://tailscale.com/kb/1028/key-expiry).
- **Re-auth UX:** run `tailscale up --force-reauth` (with `sudo` if needed); do not run over remote SSH/RDP without a fallback, as it may drop the connection. If an auth URL is already started, a "Reauthorize machine" option replaces the extend option. Admins can "Temporarily extend key" by **30 minutes**; owner must re-auth or disable expiry within that window — [Key expiry KB](https://tailscale.com/kb/1028/key-expiry).
- **Disable/enable expiry per device:** Machines page → row menu → "Disable Key Expiry"/"Enable Key Expiry" (available on all plans) — [Key expiry KB](https://tailscale.com/kb/1028/key-expiry).
- **Tagged devices:** when a tag is first applied and the device authenticates, key expiry is **disabled by default** — [Key expiry KB](https://tailscale.com/kb/1028/key-expiry); [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).
- Admin console browser sessions expire after 30 days (separate from key expiry) — [Key expiry KB](https://tailscale.com/kb/1028/key-expiry).

### Inferences
- Re-authentication cadence for user devices is ~every 6 months by default; servers typically avoid it by being tagged (expiry off). This is the main recurring onboarding-maintenance cost.
- The lack of documented pre-expiry notification is a known friction point (device silently drops at the 180-day mark).
- **Control-plane dependency flag (recURd relevance):** approval state and key-expiry enforcement live in the coordination server — a new device's ability to pass traffic is a control-plane decision, and expiry forces periodic re-contact with the control plane. Pre-approved keys move that decision to key-mint time but still require the control plane to hold it.

### Gaps
- One internal wording nuance: the key-expiry page says "180 days" and also "6 months by default" (≈equivalent); no true contradiction, but phrasing is loose.

## Key Question 5 — Invites: user invites, node/device sharing, share links, admin-console "Add device"

### Takeaway
Three distinct "invite" flows exist, all from the admin console and all on every plan: (a) invite a *user* to your tailnet (email or role-bound invite link); (b) *share a single node* with an external user (email or single-use/reusable share link, recipient must own a tailnet); (c) "Add device" on the Machines page (OS picker + download, or client-device/QR). Invite and share links are single-use magic links by default and expire after 30 days.

### Cited Findings
- **Invite a user (any email domain):** Users page → "Invite external users" → add emails → pick one role (applies to all addresses in the invite). Available on **all plans**; unused invites expire after **30 days** — [Invite any user (docs)](https://tailscale.com/docs/features/sharing/how-to/invite-any-user); [Invite users (blog)](https://tailscale.com/blog/invite-users).
- **Invite link (role-bound):** Copy invite link tab → select role → "Generate & copy invite link" — [Invite any user (docs)](https://tailscale.com/docs/features/sharing/how-to/invite-any-user).
- **Team invites (custom domain only):** can batch-invite multiple same-domain addresses; unused team invites expire **90 days** after last welcome invite; GitHub accounts lack emails so can't be invited — [Invite team members (docs)](https://tailscale.com/docs/features/sharing/how-to/invite-team-members).
- Manage invites: filter Users page by `status:invited`; resend/delete via the user's menu; if user approval is enabled, invited users must be approved before joining — [Invite any user (docs)](https://tailscale.com/docs/features/sharing/how-to/invite-any-user).
- **Node/device sharing:** share one machine with an external user without exposing it publicly; recipient sees only that machine. Share by **email** (single-use invite link; recipient need not own that email) or **copy invite link** (single-use by default; "Reusable link" can be accepted up to **1,000 times** — "treat links like passwords"). Unused invite links expire after **30 days** — [Sharing KB](https://tailscale.com/kb/1084/sharing).
- Share recipient must be an **Owner/Admin/IT admin of a tailnet** (i.e., needs their own account + tailnet). Shared machines appear under the sharer's name, are reachable only by FQDN (`<host>.<tailnet>.ts.net`), are quarantined by default (inbound only unless mutual share + rules), and **tagged machines can't be shared** — [Sharing KB](https://tailscale.com/kb/1084/sharing).
- Sharing is on **all plans**. Admin steps: Machines → machine menu → Share → "Share by email" or "Copy invite link." Link-based sharing is **beta**; declarative node sharing is **alpha** — [Sharing KB](https://tailscale.com/kb/1084/sharing).
- **"Add device" in console:** Machines page → "Add device" → choose OS → "Download Tailscale"; or "Add device" → "Client device." New devices authenticate and are added automatically unless device approval is enabled — [Add a device (docs)](https://tailscale.com/docs/features/access-control/device-management/how-to/set-up); [Device add KB](https://tailscale.com/kb/1316/device-add).

### Inferences
- Node sharing is deliberately higher-friction than inviting a user: the recipient must already run their own tailnet, which raises the bar for casual cross-org sharing but keeps identity boundaries clean.
- **Control-plane dependency flag (recURd relevance):** the coordination server brokers all invites/shares — it generates and holds the single-use/reusable magic links, tracks acceptance, and stitches a shared node into the recipient's view. Sharing is a control-plane-mediated grant.

### Gaps
- Sharing page is silent on whether shared machines count toward device limits.

## Key Question 6 — Mass/enterprise enrollment (MDM/Intune/Jamf, pre-set config, unattended/headless, containers, Kubernetes operator, GitOps)

### Takeaway
Enterprise enrollment scales via three complementary mechanisms: MDM to push the client + policies (incl. a pre-set `AuthKey`) to managed fleets; auth keys / OAuth clients for headless and container joins; and the Kubernetes operator / Terraform provider for infrastructure. MDM policies are GA since Feb 2024 but gated to Premium/Enterprise; everything else (keys, OAuth, operator, Terraform) is available broadly.

### Cited Findings
- **MDM GA:** Tailscale MDM policies reached general availability on **February 12, 2024**, for **Premium and Enterprise** customers. Policies can keep Tailscale always running, force auto-updates, force an exit node (full or split tunnel), hide menu options, and restrict corporate devices from personal tailnets. Windows reads policies from the registry; macOS/iOS/tvOS read them from the user defaults DB via configuration profiles — [MDM GA (blog)](https://tailscale.com/blog/mdm-ga).
- Supported MDM tooling includes **Microsoft Intune, Jamf, Kandji (Iru), JumpCloud, SimpleMDM**; Tailscale publishes per-platform and per-tool guides — [MDM guides](https://tailscale.com/docs/integrations/mdm); [macOS MDM KB](https://tailscale.com/kb/1286/macos-mdm); [iOS MDM KB](https://tailscale.com/kb/1380/ios-mdm).
- macOS MDM can **pre-approve the VPN configuration** (no first-launch prompt) and add a system-extension policy to allow the extension by default; standalone vs. App Store variants use different bundle identifiers; system-scope payloads can only be deployed by an MDM server — [MDM search synthesis / macOS MDM KB](https://tailscale.com/kb/1286/macos-mdm).
- iOS/tvOS: MDM policies take effect **only if the app was installed through MDM**; a hand-installed `.mobileconfig` cannot deploy policies; managed apps use AppConfig — [MDM guides](https://tailscale.com/docs/integrations/mdm).
- Admins can push an auth key to managed devices via the **`AuthKey` MDM policy**, enabling zero-touch join — [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).
- **Unattended/headless:** On **Linux**, Tailscale runs as the system service and is available even when no user is logged in (headless servers need no extra setup). On **Windows**, enable "Run Unattended" (tray → Preferences, or `tailscale up --unattended=true`) so the service runs under the system account; elevated permissions may be required. **macOS has no run-as-system/unattended mode yet** — [Run unattended KB](https://tailscale.com/kb/1088/run-unattended); [CLI reference](https://tailscale.com/kb/1080/cli) (`--unattended` is Windows-only).
- **Containers (Docker):** use the `tailscale/tailscale` image; join with `TS_AUTHKEY` (an auth key, or an OAuth client secret — then supply the tag via `--advertise-tags` in `TS_EXTRA_ARGS`); `TS_STATE_DIR` persists state (mount as a volume, else each restart creates a new node, example `/var/lib/tailscale`); `TS_EXTRA_ARGS` passes `tailscale up` flags (e.g. `--advertise-exit-node --ssh --accept-routes`); `TS_TAILSCALED_EXTRA_ARGS` passes daemon flags — [Docker KB](https://tailscale.com/kb/1282/docker); [Docker configuration parameters](https://tailscale.com/docs/features/containers/docker/docker-params); [Docker guide (blog)](https://tailscale.com/blog/docker-tailscale-guide).
- **Kubernetes operator:** setup = define tags in access controls (e.g. `tag:k8s-operator` owning `tag:k8s`), create an OAuth client on the Trust credentials page with **write scope for General/Services, Devices/Core, and Keys/Auth Keys**, each with `tag:k8s-operator`, then install via **Helm** (`helm upgrade --install tailscale-operator tailscale/tailscale-operator` with OAuth values) or static manifests. **Workload identity federation** can replace OAuth secrets. The operator runs ingress/egress proxies, an API-server proxy, and Connector-based subnet routers/exit nodes as tailnet devices — [Install operator (docs)](https://tailscale.com/docs/kubernetes-operator/install-operator); [Operator quickstart](https://tailscale.com/docs/kubernetes-operator/quickstart); [Operator overview KB](https://tailscale.com/kb/1236/kubernetes-operator).
- **GitOps / IaC:** the official **Terraform provider** (`tailscale_key` resource) creates auth keys with reusable/ephemeral/pre-authorized/tagged settings; the provider authenticates with an API key or OAuth client ID+secret and requires specifying the tailnet — [Terraform provider KB](https://tailscale.com/kb/1210/terraform-provider); [Terraform provider repo](https://github.com/tailscale/terraform-provider-tailscale).

### Inferences
- The "zero-touch" enterprise path is MDM-push-client + MDM-push-`AuthKey` (+ pre-approved/tagged key) → device joins with no user interaction; this is the closest Tailscale gets to enrolling thousands of machines automatically.
- Terraform device-recreation is a known rough edge: a recreated server leaves a stale device record holding the hostname; the community workaround is API-delete-by-hostname before recreate, plus single-use short-TTL keys (the key lands in plaintext cloud-config) — [Terraform provider issue #232](https://github.com/tailscale/terraform-provider-tailscale/issues/232). (Anecdotal / GitHub issue; may predate current provider.)
- **Control-plane dependency flag (recURd relevance):** every mass-enrollment path still routes device identity through the coordination server — the operator/Terraform/MDM all ultimately present control-plane-issued keys/OAuth secrets, and the control server mints keys, assigns tags, and records each node.

### Gaps
- "GitOps-style device management" in Tailscale is mostly policy-file-as-code (ACLs — out of scope here) plus Terraform + alpha "declarative node sharing"; no primary doc describes a full declarative *device-enrollment* GitOps workflow beyond Terraform.
- Exact current Terraform provider version and whether the device-cleanup gap is fixed were not verified against the Terraform Registry.

## Key Question 7 — Cross-platform onboarding specifics

### Takeaway
Onboarding effort differs sharply by platform: Linux is the easiest headless (system service, `--auth-key` one-liner); Windows needs explicit "Run Unattended" for server use; macOS needs system-extension/VPN approval (pre-approvable only via MDM) and has no unattended mode; iOS/Android add "Use an auth key" and QR; tvOS/Android TV use QR or an on-screen code entered in the console.

### Cited Findings
- **Linux:** runs as the system service, available with no user logged in; join headless with `sudo tailscale up --auth-key=<key>` — [Run unattended KB](https://tailscale.com/kb/1088/run-unattended); [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).
- **Windows:** reads MDM policies from the registry; "Run Unattended" needed for server/reboot persistence (`tailscale up --unattended=true`); `--unattended` is Windows-only — [MDM GA (blog)](https://tailscale.com/blog/mdm-ga); [CLI reference](https://tailscale.com/kb/1080/cli).
- **macOS:** App Store vs. standalone variants differ in bundle IDs; MDM can pre-approve the VPN config (skips first-launch prompt) and auto-allow the system extension; **no run-as-system/unattended mode yet** — [macOS MDM KB](https://tailscale.com/kb/1286/macos-mdm); [Run unattended KB](https://tailscale.com/kb/1088/run-unattended).
- **iOS/tvOS:** MDM policies only apply when the app was installed via MDM; hand-installed `.mobileconfig` can't deploy policies; use AppConfig — [MDM guides](https://tailscale.com/docs/integrations/mdm).
- **Mobile (iOS/Android):** sign-in screen menu → "Use an auth key" → paste → confirm — [Auth keys KB](https://tailscale.com/kb/1085/auth-keys).
- **tvOS/Apple TV:** QR code appears automatically on first connection attempt — [QR device-add KB](https://tailscale.com/kb/1336/device-add-qr-code).
- **Android TV / headless TV devices:** client generates an alphanumeric code entered in the admin console for automatic authentication — [Add device (search synthesis)](https://tailscale.com/docs/features/access-control/device-management/how-to/set-up).
- **Containers:** see Q6 (`TS_AUTHKEY`, `TS_STATE_DIR`, `TS_EXTRA_ARGS`) — [Docker configuration parameters](https://tailscale.com/docs/features/containers/docker/docker-params).

### Inferences
- The macOS system-extension + VPN-profile approval is the platform-specific friction that MDM exists to erase; without MDM, a macOS user must click through OS security prompts.
- Headless devices without a keyboard/browser (TVs, servers) are explicitly served by two patterns: auth keys (servers/containers) and QR/on-screen-code (TVs).

### Gaps
- Did not capture exact Android (phone) first-run screens beyond the "Use an auth key" option.

## Key Question 8 — QR codes, magic links, one-click flows

### Takeaway
Tailscale's lowest-friction interactive join is the QR flow: the device shows a QR (automatically on Apple TV), you scan it with a trusted phone, authenticate there via SSO, and the device logs in automatically — no credentials typed on the target device. "Magic-link" behavior is in the single-use email invite/share links, not in device login; the nearest thing to one-click is an MDM-pushed `AuthKey` (zero-touch) or an auth-key one-liner.

### Cited Findings
- **QR device-add flow:** (1) install client on the device; (2) its login page shows a "QR code" link (auto on Apple TV); (3) scan with a trusted phone/tablet — opens the Tailscale login page in a browser (scanning device needn't have the app); (4) authenticate via your identity provider (pick tailnet if multiple); (5) the new device logs in automatically; (6) approve if device approval is on — [QR device-add KB](https://tailscale.com/kb/1336/device-add-qr-code).
- `tailscale up`/`login --qr` generates a QR code for the web login URL (CLI path to the same flow) — [CLI reference](https://tailscale.com/kb/1080/cli).
- Invite and share links are single-use magic links by default (reusable share links accepted up to 1,000 times), expiring after 30 days — [Sharing KB](https://tailscale.com/kb/1084/sharing); [Invite any user (docs)](https://tailscale.com/docs/features/sharing/how-to/invite-any-user).
- Near-one-click aspects Tailscale highlights: QR auto-displays on Apple TV; auth happens on the phone (nothing typed on the target); device logs in automatically after auth — [QR device-add KB](https://tailscale.com/kb/1336/device-add-qr-code).

### Inferences
- The QR + MDM-`AuthKey` combinations are Tailscale's answer to "one-click": QR removes typing credentials on constrained devices; MDM-pushed keys remove interaction entirely for managed fleets.
- **Control-plane dependency flag (recURd relevance):** the QR encodes a control-plane login URL and the whole handshake completes against the coordination server; one-click still means one-click-to-the-control-plane.

### Gaps
- The QR KB page does not itself document the Android-TV alphanumeric-code variant (found only via the Add-device search synthesis); exact per-TV-platform wording not fully confirmed from one primary page.

## Key Question 9 — Onboarding friction (what breaks or confuses users)

### Takeaway
Community reports cluster around a few recurring issues: silent login failures (button does nothing, spinner hangs), platform/IdP-specific breakage (notably Windows + GitHub sign-in), self-hosted/NAS TLS prerequisites, and custom-login-server (Headscale) flows needing the CLI. Notably, Tailscale's own designers have called the onboarding "the most horrible onboarding experience we've ever done," while third parties still rate it low-friction for non-technical users. All of this is anecdotal/forum-level.

### Cited Findings
- A Tailscale podcast guest said internal designers see the onboarding as "the most horrible onboarding experience we've ever done. There's so many things we can improve still" — [SCW podcast w/ Avery Pennarun & Brad Fitzpatrick](https://www.buzzsprout.com/1822302/9890092-tailscale-with-avery-pennarun-brad-fitzpatrick). (Anecdotal, self-reported.)
- Windows + GitHub sign-in: a user was repeatedly bounced back to a login page asking for an email; the suggested `mygithubuserid@github` format just returned the login page — [Tailscale forum](https://forum.tailscale.com/t/first-time-login-with-github-fails/4355). (Anecdotal forum.)
- A Windows client on corporate guest WiFi "just didn't work" with no warning — [GitHub issue #14126](https://github.com/tailscale/tailscale/issues/14126). (Anecdotal issue.)
- Silent/stalled logins: after a client update "nothing happens after pressing the login button"; another app "hangs on the login with spinning wheel" — [Umbrel community](https://community.umbrel.com/t/tailscale-failed-to-login-error/21338). (Anecdotal.)
- Self-hosted/NAS: enabling SSL/TLS resolved a login failure for an Unraid user (login failed immediately on click until TLS was enabled) — [search synthesis of forum/NAS reports](https://tailscale.com/kb/1080/cli). (Anecdotal; consolidated from NAS community threads.)
- Custom login servers (Headscale): on macOS/iOS/Android the default browser login must be interrupted; on Windows, logging into a custom control server requires the command line — [search synthesis of Headscale guides]. (Anecdotal / third-party.)
- Windows reboot: a fresh Windows Server 2019 install had "no tailscale connectivity until I login again" despite unattended expectations — [GitHub issue #3186](https://github.com/tailscale/tailscale/issues/3186). (Anecdotal.)
- Windows unattended wording: a GitHub issue flags that the GUI message ("runs as the current user") conflicts with the docs ("runs as the system") — [GitHub issue #14826](https://github.com/tailscale/tailscale/issues/14826). (Anecdotal; documentation inconsistency.)
- Counterpoint — one first-run reviewer found stumbling points "very minor" and typical of being new — [lethain.com "trying tailscale"](https://lethain.com/trying-tailscale/). (Anecdotal.)

### Inferences
- The dominant documented friction is interactive-login fragility (silent failures, IdP edge cases, GUI/service account confusion on Windows) — which is exactly why the ecosystem leans on auth keys/OAuth/MDM to bypass the browser flow for anything at scale.
- Re-auth-at-180-days with no advance notification (Q4) is a latent friction source that compounds the login-fragility problem for long-lived user devices.
- **Control-plane dependency flag (recURd relevance):** most friction is concentrated in the browser↔control-plane SSO handshake; the headless paths that avoid it still depend on the control plane holding a key — the friction moves rather than disappearing.

### Gaps
- No systematic/quantitative friction data (e.g., support-ticket categories, drop-off rates) found; all evidence is scattered forum/issue anecdotes spanning multiple versions and years. Direct Reddit threads did not surface in search.
- Could not confirm whether specific reported bugs (e.g., Windows reboot reconnection) are fixed in current client versions.
