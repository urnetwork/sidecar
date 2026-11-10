## 18. SDK, apps, and extension integration

### 18.1 Purpose and scope

This section owns `sdk/sidecar.go` and its binding gates, host services, wakes, search on devices (policy, conditions, background windows and `SidecarSearch`), remote search's requester side on app hosts (its modes, notice and states, and how apps see failover and merge), the team directory's app surface (`SidecarDirectory`, access-request approvals), the drop-history calls, the forwarding role that every app's VPN component runs (owner decision 197) with its setup, keys and seam `deviceBridge` and its posture, per-platform placement (with §5, X10), the browser sidecar and its key origin (X14), cloud hosts and their allow-list, and size budgets. §17 owns the bridge engine, §7.9 and §8 admissions and the projection, §5 the gate, pairing and alarms, §11.14 the search index, its read path and remote search's wire, eligibility, failover and merge, §16.11 the directory, §11.7 and §11.13 the drop, §16 approvals, §19 the push sender; app UI is out of scope (owner rule 6).

### 18.2 Requirements

| id | requirement | source |
|---|---|---|
| R-SDK-1 | An sdk `Sidecar` struct exposes the key controls | PLAN.md:28 |
| R-SDK-2 | Apps use it directly; the extension runs it as a background web worker | PLAN.md:28 |
| R-SDK-3 | Device integration (ip addr, port forward) via abstractions the Sidecar implements | PLAN.md:31 |
| R-SDK-4 | Bindings link only the sidecar core, never `mcp/` or `cli/` | PLAN.md:7 |
| R-SDK-5 | gobind types only; exports pass mobileexports, the C ABI and js | x/mobile bind/gen.go:480-512 |
| R-SDK-6 | iOS extension within its executable ceiling, 52,428,800 B today and raised only by a reviewed budget (Q-SDK-7), and a 32 MiB Go soft limit | sdk/build/check_apple_size.sh:9; apple/app/extension/TunnelMemoryBounds.swift:139,143 |
| R-SDK-7 | No server holds keys or plaintext | CONVENTIONS §0 |
| R-SDK-8 | Quick burner: "Must log in, runs a new DeviceRemote in browser" | cli/UI.md:160-164 |
| R-SDK-9 | With no connected remote, "start a local device that listens" | cli/UI.md:67 |
| R-SDK-10 | Runs in cloud-agent environments, behind a published host list | sidecar/design/market2.md:537; owner decision 49 |
| R-SDK-11 | The sdk Api owns the JWT and its refresh | sdk/device_token_manager.go:20-27 |
| R-SDK-12 | Apps approve outward actions, admit devices, act on admission alarms, veto recovery windows | §2 I-4, I-8; owner decisions 112, 126, 127, 149 |
| R-SDK-13 | Every host that searches a repo keeps its two latest buckets synced (phones' team directory aside, 18.4); desktops and indexers keep all in the background; phones fetch it at "search more" for repos no designated indexer answers, browser tabs at "search more", both also in the background on Wi-Fi while charging; each device can override | owner decisions 154, 177, 178 |
| R-SDK-14 | Once its network designates an indexer that may answer, an app host's "search more" asks it for verified hits by default instead of downloading all; with none designated, the default, the phone downloads and searches its own index; per device `on`, `own` or `off`; another member's device only after the app names that member | owner decisions 175, 177, 178 |

### 18.3 What exists today

- **Bindings.** gomobile binds only `github.com/urnetwork/sdk` (sdk/build/Makefile:101, :150, :160), plus an `ios_extension` binding (:155); Android output passes `mobileexports` (:118; sdk/build/cmd/mobileexports/main.go:128-137). The signed extension had 4,690,096 B of headroom on 2026-11-02 (sdk/build/APPLE_EXTENSION_MEMORY_BUDGET.md); sdk.wasm is 74,965,628 B (2026-10-31).
- **Auth.** The Api owns the token, its refresh (sdk/device_token_manager.go:20-27; sdk/api.go:364, :3672) and the network credential (:203-207), which `.auth_state` keeps beside the device client token in a 0600 file (sdk/local_state_auth.go:31-35; sdk/local_state.go:22). A confirmed 401 reaches `AddAuthLogoutEventListener` with its generation, which `IsAuthLogoutCurrent` checks (sdk/api_auth_logout_event.go:11-39), and cause `session_revoked` only for a session the server confirms revoked (sdk/api_auth_logout_cause.go:31).
- **Extension.** Its background script (extension/manifest.config.ts:35-43) keeps a network `by_jwt` in `chrome.storage.local`, written on SSO login, an external `SET_JWT` and the ur.io bridge's `SETUP` and `REFRESH_JWT` (src/background/index.ts:134, :201-206; src/bridge/background.ts:502-508, :560-565); its sdk.wasm serves only the popup (src/utils/sdk-wasm.ts:1-10).
- **connect.** In-band auth exists (connect/transport.go:2556-2600; server/connect/transport.go:1507-1552), but without `CheckOrigin` (:1597-1601) cross-origin browser upgrades fail (gorilla/websocket@v1.5.3/server.go:89-99). Proxies are SOCKS5 only (connect/net.go:333-363). `Client.Send` takes a per-frame ack callback (connect/transfer.go:4228-4235).
- **Apps, hosted devices.** The iOS app has `aps-environment` (apple/app/network/network.entitlements:5-6); no server code sends APNs or FCM. ur.io's hosted DeviceLocal (server/proxy/proxy_device.go:1302) sets `HostedIncompatible` (:1483; sdk/device_local.go:893-910); the server knows it by its `proxy_device_config` row (server/db_migrations.go:2777) or as that client's child (server/model/network_client_retired_hosted.go:2-6).

### 18.4 Roles, placement, identity

Two roles (owner decisions 87, 197). The forwarding role is all of sidecar that runs in an app's VPN component (Apple's network extension on iOS and macOS, Android's VPN service, the Windows and Linux app services): the device's IP and port forwarding, that is §17's overlay address, port forwards into the device, routes to other devices' subnets and its own advertised subnet, with no sidecar-subprotocol peer. It is `sidecar/device` with the root's forwarding files (D-SDK-20, 18.10), and it is self-contained (18.6): its own forwarding keys, its sidecar's forwarding Delegation in the authorization log (§7.9), forwarding clients it refreshes itself, and its own reading of the config repo, from which it compiles its rules, so it never waits on the app. It runs whenever the VPN component runs, and no setting turns it off. The sidecar role is the full `sidecar.Sidecar` (§5) on its own Required client: a child in the device client's network (server/model/network_client_model.go:374-394), top-level in any other (owner decision 23); on app hosts it runs only while the app is open, as iOS suspends it, OS-granted windows and wakes aside (18.7), on Android too (owner decision 197). A CLI host has no forwarding role: its daemon runs §17's bridge in process under its own identity key (§17.10).

| Host | Forwarding role | Sidecar role | Client (X10) | Secrets | Budget |
|---|---|---|---|---|---|
| iOS | network extension; 18.10's budget (proposed; Q-SDK-7) | app, while open | child | keychain group `network.ur.sidecar`; forwarding's keys in the extension's own (§5.9) | 32 MiB |
| Android | VPN service | app, while open (owner decision 197) | child | AndroidKeyStore; `noBackupFilesDir`; forwarding's under its own alias and files (§5.9) | 16 MiB, added |
| Desktop apps | network extension (macOS), `urnetworkd` (Linux), app service (Windows) | `ur daemon`; app in remote mode | child after §5.8's pairing | §5.9 | 128 MiB; 192 MiB designated for search (§5.4) |
| CLI, cloud VM | none | `ur daemon` | top-level, §20.8 (cloud: tagged, ephemeral, by ReaderWraps) | §5.9 | 128 MiB; 192 MiB designated for search (§5.4) |
| Extension, ur.io pages | none | Worker (18.8) | top-level, declared no-egress (§20.8) | non-extractable WebCrypto key and IndexedDB, in 18.8's key origin (quick burner: memory) | 64 MiB heap above wasm data |

Phones mirror `mailcfg`, `vault/` and `i/` in full and head-read `m/` (§11.13), and keep MLS trees on disk, one loaded at a time (≤2.83 MB at 1,000 leaves; D-KEYS-14). Of §7.9's authorization log, every sidecar, phones, page Workers and agents included, keeps the digests A_k, its newest entries' bytes up to a `HeadCheckProof`'s 64 KiB (bases as headers) and, while it sends `proven`, the proof it verified, so any witness answers §6.4's `HeadCheckProofRequest`; member devices running `ur daemon` (desktop and CLI hosts) also keep every entry from api's retention point, which a site loss resumes from (§19.10). A config writer folds once the unfolded tail spans 1,024 entries or 24 h, at its next start if it was offline (§7.9's fold), so while one runs, kept tails stay within about 2,048 entries and a new device, a page Worker included, re-applies at most about 1,024. Marks: fg, foreground; VPN, whenever the app's VPN component runs (owner decision 197); awake, Firefox event page alive; outbox, D-SMTP-18; C4, §4's browser carrier.

| Feature | iOS app | Android | Desktop daemon | Extension: Chrome / Firefox |
|---|---|---|---|---|
| evs, mail read, burner logins | fg | fg | yes | yes / awake |
| Search: buckets; all | fg; Wi-Fi while charging; "search more" asks a designated indexer (fg), else downloads | fg; the same | yes; background | yes / awake; "search more" |
| Mail send | fg, outbox | fg, outbox | yes (§14) | outbox |
| Socket dial | fg | fg | yes | C4 |
| Listen: mail, sockets, TLS | fg | fg | yes | no |
| Approvals, admissions, alarms (18.5) | fg | fg | app or `ur approve` (for other sidecars); presence key | alarms only |
| Forwarding (§17): routes and forwards out / hosting | VPN, links after §22.9 / VPN, after C16 | VPN / VPN, after C16 | the app's VPN component, else `ur tun` / likewise, after C16 on an app's; `ur bridge` | no |

iOS suspends backgrounded apps (https://developer.apple.com/documentation/backgroundtasks), and Android's sidecar role now runs only while the app is open, whether or not the VPN runs, OS-granted windows and wakes aside, as on iOS (owner decision 197), so Android 15's 6 h daily cap on `dataSync` without a VPN [R:sdk-clients] no longer bears on it; forwarding alone runs in the background, in the VPN component.

**Search (R-SDK-13, R-SDK-14; D-SDK-21, D-SDK-25 to D-SDK-28).** §11.14's read path, and on app hosts its remote search, run on each host by this policy:

```text
modes       how all is kept: background | wifi_charging | on_demand | never; buckets are always synced with
            the repo on any host that searches it, phones' team directory aside (directory, below)
defaults    desktop ur daemon and indexers    background: all at each roll-up and rewrite (§11.14)
            ephemeral CLI hosts (CI, cloud)   on_demand: buckets at the first search, all only for scope all
                                              (owner decision 154's per-device override: an in-memory cache
                                              would re-download all at every start)
            iOS and Android apps              wifi_charging, plus on_demand at "search more" for repos no
                                              designated indexer answers (remote, below)
            ur.io page Worker                 wifi_charging while a tab is open (browsers, below), plus on_demand
                                              at "search more"
            quick burner                      buckets in memory, at its first search; never all
            extension Worker (Later)          on_demand
override    per device, for one repo or every repo: SetPolicy (18.5), the key origin's search policy request
            (18.8) or, on a daemon, §16.10's ur search sync --policy over its default Search.AllPolicy (§5.4);
            sealed in §5.9's non-derived search state, which cache eviction keeps, never in the config repo;
            app hosts and the page Worker's main set Search.AllPolicy and Search.MemoryByteCount over
            DefaultSidecarSettings() per host class, as sdk narrows connect's defaults for mobile
            (applyMobileLowMemoryClientSettings, sdk/mobile_memory_policy.go:332)
windows     wifi_charging syncs all in an OS-granted window (18.7), or while a foreground app or an open tab is
            on an unmetered link and charging, and there runs the merges and roll-ups §11.14 assigns the
            device: a roll-up only while it holds all within its cap, stopping at a window's budget, else a
            capable writer runs it; Low Power Mode or power saving pauses it
conditions  hosts report unmetered, charging and low power (18.7); a condition not yet reported, or one the
            browser hides, counts as metered and not charging; ur daemon hosts report none and count as
            unmetered; the Go core reads no platform API
browsers    the key-origin frame reports what its browser exposes: unmetered when navigator.connection.type is
            wifi or ethernet (Chromium on Android and ChromeOS), charging from getBattery() (Chromium); Safari
            and Firefox expose neither and desktop browsers no network type
            (https://github.com/mdn/browser-compat-data, 2026-11-05), so their tabs fetch all only at "search
            more" (owner decision 154's per-device override of its Wi-Fi-while-charging fetch, which these
            browsers give no signal to apply), or, once the person turns on "keep in this browser", whenever
            a ur.io tab is open
metered     a "search more" whose missing all exceeds 25 MiB on a metered link waits, reporting
            waiting=metered and the byte count, until the host repeats it with AllowMetered; under 25 MiB it
            proceeds
caps        phones keep all only below 256 MiB per network and 10% of free space, else on_demand, and evict
            all shards unused for 30 days; the page Worker keeps 128 MiB per network; a "search more" past a
            cap searches each all shard as it lands and keeps the youngest within the cap; desktops and
            indexers keep §5.9's Search.CacheByteCount (4 GiB by default; 16 GiB on a daemon designated for
            search, which evicts no all of a repo it serves while under it)
remote      app hosts only (owner decisions 175, 177, 178): at "search more" a repo goes to an online
            designated search indexer that §11.14's eligibility lets answer it, this member's own first, then
            one other member's device at a time; the core splits, fails over and merges by §11.14 and reports
            its states and "verified by" labels (18.5); a repo none answers, every repo while none is
            designated (the default) and every repo in off mode take the fallback: all by sync position, under
            metered and caps, with possible matches; keystrokes never leave the device; remote-mode Sidecars
            and browser Workers never ask; an app host sets Hello feature bit 1, in Hello and HelloResult,
            toward each search indexer its mode (on or own) lets it ask, and none in off mode, which marks the
            pair for C19's windows (§6.10, §6.11, §4.6)
  setting   per device and network: on (default), own (this member's indexers only), off (the fallback only);
            kept with the notice answers in §5.9's non-derived search state, never in the config repo, never
            set through MCP; "reset notices" clears the answers
  notice    before the first request to another member's device, the app names that member (a tagged
            device: its sponsor), the device and the repos: "Search more asks <device> (<member>) to search
            <repos> for you. That device sees the words you search for there, never your own mail or notes.
            [Search] [Only my devices]"; until it is answered those repos are searched on the phone; Search
            continues, so the mode stays on; Only my devices sets own; shown once per answering member, each
            new one asked anew; never for own indexers, so never in a personal network or one with none
            designated
directory   the team directory (§16.11; owner decisions 171, 177): phones fetch its current announcements
            (cards from its format 2, announce entries before) only while a List holds the view open (18.5),
            at most 8 MiB a metered session (§5.4's Directory settings), in an order no filter or query
            changes, and search them on the device; past the cap List reports partial coverage with
            waiting=metered and the bytes left, continuing on an unmetered link or when the host repeats it
            with AllowMetered; "search more" asks a designated indexer that reads it, fetching buckets and all
            only for the fallback (remote, above), so phones keep no directory buckets synced; phones lease
            notices for their member's targets and each own pending request's notice path (18.7); ur daemon
            hosts sync cards every 15 min while serving a harness session in the network, at each view or
            search (coalesced to 30 s), else hourly, with the moved streams 64 to a read (§11.9), reproduce
            index heads from the cards they fetch (§11.14) and keep all by Search.AllPolicy
```

```text
targets     warm, from the cache: phone app: buckets p50 <= 50 ms and p95 <= 150 ms, a cached five-year all
            p50 <= 150 ms and p95 <= 500 ms, working set <= 4 MiB a search; desktop: <= 10 ms and <= 50 ms, a
            verified page of 50 <= 200 ms, a 64 MiB decoded-shard cache; page Worker: <= 100 ms (p95 300 ms)
            and <= 300 ms (p95 1 s), <= 8 MiB, yielding every 50 ms; each working set holds the search's
            frames, lists and pending candidates beside the process's 256 KiB of version-table pages (§5.9),
            whatever the buckets hold, and a host sets DaemonSearchCount so its searches fit
            Search.MemoryByteCount; cold, a "search more" downloading all keeps §16.10's cold contract, a
            shard's hits within 300 ms of its landing on phones and page Workers; §22 measures them on
            surrogate phones (owner decision 100) and in Safari's wasm engine
remote      tap to the first remote page, pre-warmed, on an indexer's warm cache of five years of mail at 100
            a day: Wi-Fi p50 <= 300 ms and p95 <= 1 s, each later page <= 250 ms and <= 800 ms; LTE p50
            <= 500 ms and p95 <= 1.5 s, later pages <= 400 ms and <= 1.2 s; cold (no contract or Hello in
            10 min) adds <= 500 ms and <= 1.5 s, a failover Search.RemoteTimeout (3 s unmetered, 5 s
            metered); §22.8's remote row measures them on T3 with real relays and netem, on surrogates from
            the later of M10's and M8's exits
```

### 18.5 `sdk/sidecar.go`

```go
// sdk/sidecar*.go: bound types only; no sidecar-package value crosses.
type SidecarKeyStore interface { // app-implemented, gobind-safe: a host never throws across it (D-SDK-15)
	PutSecret(name string, valueBase64 string) int32 // SidecarKeyStoreOk | SidecarKeyStoreLocked | SidecarKeyStoreFailed
	GetSecret(name string) *SidecarSecret            // never nil
	DeleteSecret(name string) int32                  // Ok (deleted or absent) | Locked | Failed
}
type SidecarSecret struct { // json in the C ABI and js
	Status      int32  // SidecarSecretPresent | SidecarSecretAbsent | SidecarSecretLocked | SidecarSecretFailed
	ValueBase64 string // set only when Present
}
type SidecarPresenceSigner interface { // app-implemented: a Secure Enclave or platform FIDO key, per §16.6's profiles; nil: another device approves
	GetAttestation() string                       // public key and attestation, registered per §16.6
	SignWithPresence(messageBase64 string) string // after a presence check with UV over the message (webauthn-es256: its
	                                              // SHA-256 as the challenge), base64 of §6.9's WebAuthnEvidence: key_id
	                                              // and DER signature, with authenticator_data and client_data_json for
	                                              // webauthn-es256; "" if refused
}
type SidecarSettings struct { // json in the C ABI and js
	Instance, StateDir    string      // StateDir "" on js: IndexedDB
	Components            *StringList // "evs", "mail", "sockets", "bridge", "tls" (§5.4); an app lists no "bridge",
	                                  // since forwarding is its VPN component's, always on (18.4)
	MemoryBudgetByteCount int64
}
type Sidecar struct{ /* stateLock; local *sidecar.Sidecar or remote §5.8 client; the extension's Worker and native host serve it too */ }
func NewSidecarLocal(networkSpace *NetworkSpace, keyStore SidecarKeyStore, presenceSigner SidecarPresenceSigner, settings *SidecarSettings) (*Sidecar, error)
func NewSidecarRemote(presenceSigner SidecarPresenceSigner, settings *SidecarSettings) (*Sidecar, error) // `ur daemon` control mode (§5.8)
func (self *Sidecar) EnrollWithDevice(device Device, callback SidecarResultCallback) // child, admin_refused and strict_exp (§7.4);
                                                                                  // remote: §5.8's pairing; then runs forwarding's setup for its VPN component (18.6)
func (self *Sidecar) Unlock(passphrase string, callback SidecarResultCallback)       // local only; "": key-store wrap, called once the store unlocks;
                                                                                  // remote: refused, the daemon unlocks (§5.9)
func (self *Sidecar) GetState() string       // locked|unenrolled|offline|online|revoked (State, below)
func (self *Sidecar) GetStateReason() string // unenrolled: expired|refused|parent_lost|session_ended|keystore_lost; revoked: signed
func (self *Sidecar) AddEventListener(listener SidecarEventListener) Sub // §5.4's SidecarEvent kinds: state,
	// approval_pending, member_added, member_removed, key_changed, refused, admission_alarm, recovery_rebind,
	// recovery_window, recovery_unseen, head_alarm (§6.4: fork, withheld, unverified or unwitnessed, with both
	// pins), access_request, access_decided {request_id, outcome} and directory_erasure {repo_id, outcome} (§16.11),
	// history_drop {repo_id, drop_id, state, not_before_ms}, admissions_near_cap (admin devices, §7.10's cleanup
	// list), mail_send {send_id} (§14.5),
	// search_alarm {mismatch or omission, indexer, repo}, index_mismatch and index_malformed (§11.14), erasure
	// {repo_id, SidecarErasure: fenced|rewriting|waiting|done|stalled, objects and bytes left, next try, finish}
	// (§5.4, §11.12, §11.13's wait); each carries the repo, ref and path its kind names
func (self *Sidecar) SetPushToken(platform string, token string, callback SidecarResultCallback) // "apns"|"fcm"; "" deletes
func (self *Sidecar) SignEdgeLogin(origin string, nonceBase64 string, callback SidecarResultCallback) // §13.7 members-device; v1 (M6)
func (self *Sidecar) GetSidecarId() *Id
func (self *Sidecar) GetEvs() *SidecarEvs   // nil unless registered
func (self *Sidecar) GetMail() *SidecarMail // plus §15.9's burner, vault and one-time-code methods
func (self *Sidecar) GetSockets() *SidecarSockets
func (self *Sidecar) GetApprovals() *SidecarApprovals
func (self *Sidecar) GetSearch() *SidecarSearch // nil unless evs is registered; 18.4's search policy
func (self *Sidecar) GetDirectory() *SidecarDirectory // nil outside a team network (§16.11)
func (self *Sidecar) Close()
func (self *SidecarEvs) CreateRepo(kind string, displayName string, private bool, callback SidecarResultCallback) // §11.12;
	// the result names its repo_id; in a team network a general or record repo is announced at creation unless
	// private, which writes the private marker instead (owner decision 181)
func (self *SidecarEvs) ReadHead(repoId *Id, path string, callback SidecarBytesCallback) // §11; tokens derived and decrypted here;
	// a versionless file replaced mid-read is read again from the new head (§11.7)
func (self *SidecarEvs) ReadVersion(repoId *Id, path string, version int64, callback SidecarBytesCallback) // an older
	// version: EVS_DROPPED from its drop's not_before unless the drop is cancelled or refused, readable with that
	// time while drop_pending (§11.9); a drop never takes the head
func (self *SidecarEvs) History(repoId *Id, path string, callback SidecarHistoryCallback) // each version's time, signer,
	// versioning and state: kept | collected | drop_pending | dropped (§11.7, §11.9)
func (self *SidecarEvs) Write(repoId *Id, path string, data []byte, versioning string, callback SidecarResultCallback) // ≤1 MiB;
	// file-mode refs only; versioning "", "on" or "off" ("" keeps the path's, a new path's from its rules: §11.7;
	// owner decision 167); a versionless path's 409 is surfaced, never retried by rebasing (§11.7);
	// EVS_GIT_REF on a git-mode ref (§11.7)
func (self *SidecarEvs) AddRepoChangeListener(repoId *Id, listener SidecarRepoChangeListener) Sub
// Drop history (§11.7, §11.13; owner decisions 173, 183): a preview, drop or cancel only by a repo admin, in an
// owner-bound repo only its owner's consented devices that are not read_only (owner decision 126), each a person's
// act in the app's UI; the Drops listing by any reader (§11.20)
func (self *SidecarEvs) DropHistoryPreview(repoId *Id, path string, follow bool, callback SidecarDropPreviewCallback)
	// the server's mandatory dry run: versions, bytes freed, shared and kept inline, dates, list_match, preview_id
func (self *SidecarEvs) DropHistory(repoId *Id, previewId *Id, confirmPath string, now bool, callback SidecarResultCallback)
	// confirmPath: the name the person typed, refused unless it is the previewed path; now skips the 7-day window
	// behind a second confirmation; repo admins' devices then raise history_drop with its cancel
func (self *SidecarEvs) CancelDrop(repoId *Id, dropId *Id, callback SidecarResultCallback) // any repo admin (owner-bound:
	// the owner's consented device) until 60 s before not_before
func (self *SidecarEvs) Drops(repoId *Id, callback SidecarDropsCallback) // each drop's state, not_before and listed
	// paths, up to 1,024 lineages, named as this device names them (I-13); a drop a hold defers reads done, as
	// everywhere (owner decision 184)
func (self *SidecarEvs) Erasures(repoId *Id, callback SidecarErasuresCallback) // each erasure the repo's erasure
	// sets list or this device runs, as a SidecarErasure (§5.4): any reader sees fenced, done or stalled, and the
	// eraser's device, or one that may finish it (§11.12's reconcile row), also its rekey objects and bytes left,
	// its next try and its finish by §11.13's wait row, so an app shows one message's erasure across a UTC day
	// and a restart
func (self *SidecarMail) GetAliases() *SidecarAliasList
func (self *SidecarMail) Send(draft *SidecarDraft, callback SidecarResultCallback) // internet mail: §14's outbox unless this host proves;
	// the result names its send_id, whose outcomes GetSendResult reads and the mail_send event announces
func (self *SidecarMail) CheckSend(draft *SidecarDraft, callback SidecarSendCheckCallback) // for the composer, per recipient
	// domain: mode (bdat|data|unknown), encoded bytes, the DATA cap, expected delay and ok|too_large|unknown (§14.5)
func (self *SidecarMail) GetSendResult(sendId *Id, callback SidecarSendResultCallback) // per recipient domain:
	// sent|queued|deferred|too_large|refused|tls_refused|failed, with bytes and cap, retry_after_ms or the MX's code
func (self *SidecarMail) SetReceiverEnabled(enabled bool, callback SidecarResultCallback) // remote mode: its daemon, an
	// always-on receiver; in a personal network or a member scope, enabling files that device's IndexerSet for mail and
	// disabling retires it (§15.6, §7.9); local mode answers refused, as app hosts receive only while open (owner decision 197)
func (self *SidecarMail) GetReceiverCoverage() string // indexer|foreground-only|none, with Coverage's copy (below; §15.9)
func (self *SidecarSockets) Dial(address string, timeoutMillis int64) (*Socket, error) // §9
func (self *SidecarSockets) Listen(address string, weight int32) (*SidecarSocketListener, error)
func (self *SidecarSocketListener) Accept(timeoutMillis int64) (*Socket, error) // worker thread
func (self *SidecarApprovals) GetPending() *SidecarApprovalList // §16.8 requests; admissions this device may sign (§5.6);
                                                                 // admission alarms, parked devices included; recovery_rebind
                                                                 // alarms; on AdminSet devices, recovery windows: §7.9's
                                                                 // recovery-signed authority statements and admissions by a
                                                                 // binding its cascade restored (owner decisions 127, 149);
                                                                 // recovery_unseen, where this device may revoke the
                                                                 // recovered device; access_request: §16.11's requests
                                                                 // this member approves (owner decisions 179, 180); on
                                                                 // AdminSet devices, another AdminSet member's device
                                                                 // revocation proposal this device may cosign (§5.6);
                                                                 // on admin devices, admissions_near_cap's cleanup list
                                                                 // (§7.10's cleanup row)
func (self *SidecarApprovals) AddPendingListener(listener SidecarApprovalListener) Sub
func (self *SidecarApprovals) Decide(approvalId *Id, decision string, callback SidecarResultCallback) // single use (§16.8):
	// request: approve|deny, an ApprovalDecision (§16.6); admission: approve signs the SidecarAdmit (§5.6), with one
	// presence check over the act where §7.9's presence row asks (owner decisions 187, 189), and for
	// a page Worker, in the same act, SidecarRevoke{removed} of each of its member's page Workers §7.10's stale row
	// lets this device revoke, an admin's included (D-TEAM-29), on the member's own device listing its other page
	// Workers to revoke through RevokeDevice, and for an AdminSet member's admission proposal its AuthorityCosign
	// and one for each stale-revocation proposal filed with it that passes that row's check; admission alarm:
	// approve signs OwnerConfirm{sidecar_id} for a parked device, revoke revokes that device (below), deny dismisses
	// it, a parked device staying parked (§2.10), and each answer for a page Worker an admin admitted also signs
	// §7.10's stale revocations this device sees and lists the member's other page Workers to revoke through
	// RevokeDevice; revocation proposal (AdminSet devices): approve signs §7.9's AuthorityCosign once the person
	// reviews §5.6's plan, which this device derives, with §5.6's approval, deny dismisses it; recovery window
	// (AdminSet devices, either kind): deny signs §7.9's RecoveryVeto naming it, countersigned as §7.9's presence
	// row asks (owner decision 187); recovery_rebind: not me signs a SidecarRevoke for compromise of the rebind's
	// signer from a since_n at or before the rebind, and I did this runs §5.9's compromise procedure, each listed
	// device's since_n clamped past the rebind for its signer, which goes last (owner decision 212);
	// recovery_unseen: revoke signs a SidecarRevoke for compromise of the recovered device from a since_n at or
	// before its activation; each once the person confirms §7.9's cascade list (what P parks and voids, what
	// stands, and each device that sealed to a binding it voids, to revoke for compromise and enroll anew if its
	// backups may hold that sealing, §5.9); deny dismisses it; a revoke answer naming a device of this member runs
	// through RevokeDevice's rules (§5.6's plan, approval, Suspend and codes), for compromise from the since_n its
	// alarm fixes, an admission alarm's at that admission; access_request: approve signs §16.11's grant (a
	// RepoGrant, an owner's EvsShare, or for reach an ApprovalDecision on channel device or presence), the decision
	// entry and the notice's rewrite, deny its decision entry and the notice's rewrite to denied, both by §16.11's
	// resumable protocol, finished after a crash from the device's ledger; admissions_near_cap (admin devices,
	// §7.10's cleanup row): revoke signs SidecarRevoke{removed} of each listed page Worker, an AdminSet member's
	// at k > 1 as proposals, under §7.9's presence row, deny dismisses it until the count rises. The signer of an
	// admission or revocation then commits what it requires in the config group and a team's directory group: an
	// Add or the new device's first wrap, a Remove and its rotation; a wrapped signer, not among §7.9's 1,000
	// leaf-entitled devices, only wraps and rotations (§7.9's commit; owner decisions 128, 144, 182)
// Revoking another of this member's devices (§5.6; D-SDK-30): a person's act in the app's UI, never MCP; a
// remote-mode Sidecar forwards each call to its daemon over §5.8's control channel, where, under Presence,
// RevokeDevice first returns the act's countersigned bytes (§7.9's presence row), which the app signs by
// SignWithPresence and sends back in a second call before the daemon signs anything
func (self *SidecarApprovals) GetDevices() *SidecarDeviceList // this member's admitted devices, this one first
func (self *SidecarApprovals) PreviewRevokeDevice(sidecarId *Id, reason string, lostAtMillis int64, sinceN int64,
	callback SidecarRevokePlanCallback) // §5.6's plan; reason lost | compromise; sinceN 0: the proposed position
func (self *SidecarApprovals) RevokeDevice(planId *Id, revokeKeys *SidecarRevokeItemList, callback SidecarResultCallback)
	// after the plan's copy (below) and the person's confirmation: SignWithPresence over the act's bytes where
	// Presence, then §5.6's statements, each with its countersignature (owner decisions 185, 187); revokeKeys:
	// the plan's key items the person left selected; the result names
	// the entry, or authority_pending:<proposal_id> while other AdminSet devices' cosigns are due; refusals carry
	// §5.6's REVOKE_ codes
type SidecarDevice struct { // json in the C ABI and js; §5.4's MemberDevice
	SidecarId        *Id
	Name             string // its config device name
	This             bool   // this device: Sign out, never Revoke
	ReadOnly         bool   // a page Worker
	Ephemeral        bool   // a quick burner
	State            string // live | pending | parked | stale | revoked (§5.4)
	AdmittedMillis   int64
	LastChangeMillis int64 // 0: none seen
}
type SidecarRevokePlan struct { // json in the C ABI and js; §5.4's DeviceRevokePlan
	PlanId      *Id
	SidecarId   *Id
	Name        string
	Reason      string                 // lost | compromise
	SinceN      int64                  // compromise: where P starts
	SinceMillis int64                  // its entry's time
	Items       *SidecarRevokeItemList // §5.4's DeviceRevokeItem rows: park | void | stands | reseal | key
	Signatures  int32                  // 1, or k for an AdminSet member's device
	Presence    bool                   // RevokeDevice runs SignWithPresence
}
type SidecarRevokeItem struct { // json in the C ABI and js
	Effect, Kind, Name string
	Id                 []byte // §5.4's: 16 bytes, a recovery_binding's 32-byte key hash or a key's key_id
	Position           int64
}
type SidecarRevokePlanCallback connect.ApiCallback[*SidecarRevokePlan]
type SidecarSearchQuery struct { // json in the C ABI and js
	Text         string  // §11.14's query: terms AND; "quoted" phrases; -term drops only confirmed containment
	RepoIds      *IdList // empty: every repo this sidecar reads with its index on
	Scope        string  // "cached" (default: buckets and any cached all) | "latest" | "all" ("search more")
	SinceMillis  int64   // 0: unbounded; a range inside the buckets never needs all
	UntilMillis  int64
	Fuzzy        bool   // near hits even when 3 or more exact hits exist
	AllowMetered bool   // "all" may download past 25 MiB on a metered link
	Remote       string // "" (the network's mode, 18.4) | "off": this search stays on the device
	PageSize     int32  // default 50
}
type SidecarSearchHit struct { // json in the C ABI and js
	RepoId     *Id
	Path       string
	Version    int64
	TimeMillis int64
	Title      string // subject or title
	From       string // sender, or the writer's label
	Snippet    string // verified hits: around the match; mail: i/'s snippet; else ""
	State      string // verified | confirmed | possible | near | unmatched (a local possible or near hit an
	                  // indexer's checked span disproved, which apps fold into one "not matched by" row, §11.14)
	Partition  string // latest | all
	Correction string // near: the corrected term
	By         string // "": this device | the answering indexer's config device name ("verified by")
}
type SidecarSearchProgress struct { // json in the C ABI and js
	Searched, Total                  int32 // partitions
	FetchByteCount, FetchedByteCount int64
	Uncovered                        int32           // recent changes not yet searchable
	Waiting                          string          // "" | metered | offline | update
	CoveredFromMillis                int64           // the oldest time this search covered
	Remote                           string          // "" | notice | asking | answered | partial | fallback | off
	RemoteBy                         *SidecarIndexer // the indexer asked, or the one a notice names
	FallbackReason                   string          // "" | none | offline | busy | refused | unreachable | off | notice
}
type SidecarSearchStatus struct { // json in the C ABI and js
	IndexOn, FormatSupported                 bool
	Policy                                   string // background | wifi_charging | on_demand | never
	Remote                                   string // this network's mode: on | own | off
	LatestFromMillis, AllCachedThroughMillis int64  // 0: all not cached
	AllCachedByteCount, AllMissingByteCount  int64
	Uncovered                                int32
}
type SidecarIndexer struct { // json in the C ABI and js
	SidecarId     *Id
	Name          string  // its config device name
	MemberId      *Id     // its member, or a tagged device's sponsor
	Member        string
	Own           bool    // a device of this member
	State         string  // online | unreachable | busy | unknown
	Acknowledged  bool    // another member's: the person answered its notice
	ServedRepoIds *IdList // repos it answered in the last 24 h
}
type SidecarSearchListener interface { // app-implemented; called on a Go thread
	SearchPage(hits *SidecarSearchHitList, progress *SidecarSearchProgress, done bool) // replaces the last page
}
func (self *SidecarSearch) Search(query *SidecarSearchQuery, listener SidecarSearchListener) *SidecarSearchHandle
func (self *SidecarSearchHandle) More(pageSize int32) // the next page
func (self *SidecarSearchHandle) Cancel() // local: no Cancel reaches an indexer, whose cursor a newer search supersedes
func (self *SidecarSearch) GetStatus(repoId *Id) *SidecarSearchStatus
func (self *SidecarSearch) SetPolicy(repoId *Id, policy string, callback SidecarResultCallback) // nil repoId: every repo; "" restores the host default
func (self *SidecarSearch) SetConditions(unmetered bool, charging bool, lowPower bool) // the app, on each change (18.7)
func (self *SidecarSearch) RunBackgroundSync(budgetMillis int64, callback SidecarResultCallback) // an OS window; stops at the budget, resumable
func (self *SidecarSearch) DropCache(repoId *Id, callback SidecarResultCallback)
func (self *SidecarSearch) GetIndexers() *SidecarIndexerList // indexers that may answer this device, own first
func (self *SidecarSearch) SetRemote(mode string, callback SidecarResultCallback) // on | own | off, this network's
func (self *SidecarSearch) AcknowledgeIndexer(memberId *Id, allow bool, callback SidecarResultCallback) // a notice's
	// answer: allow false sets own; a nil memberId clears every answer ("reset notices")
func (self *SidecarDirectory) List(filter *SidecarDirectoryFilter, listener SidecarDirectoryListener) Sub // while one is
	// open the view is open, the only time a phone fetches announcements (18.4); past the metered cap its listener
	// reports partial coverage (sidecars fetched and left, bytes left, waiting=metered), and AllowMetered on the filter
	// continues from where it stopped
func (self *SidecarDirectory) Get(announcementId *Id) *SidecarAnnouncement // attested and identifier fields; prose as
	// untrusted text for people
func (self *SidecarDirectory) SetRuns(projectKey string, value string, callback SidecarResultCallback) // this member's
	// claims, auto | prompt | off, per project ("": its default; owner decision 170)
func (self *SidecarDirectory) SetWorker(enabled bool, callback SidecarResultCallback) // this sidecar's worker item
func (self *SidecarDirectory) Request(request *SidecarAccessRequest, callback SidecarResultCallback) // a repo, a
	// worker's announced services (owner decision 179) or a socket, with role, expiry and reason; filed by this person
func (self *SidecarDirectory) GetRequests(view string) *SidecarAccessRequestList // "mine" | "incoming"
func (self *SidecarDirectory) AnnounceRepo(repoId *Id, announcement *SidecarRepoAnnouncement, callback SidecarResultCallback)
	// a repo admin; an owner-bound repo only on its owner's consented device; writes or replaces its item
func (self *SidecarDirectory) RevokeRepo(repoId *Id, callback SidecarResultCallback) // the same signers: the private
	// marker over the announcement at once, and an erasure_request that the directory's erasure runner completes;
	// the result reads hidden, and SidecarEvent directory_erasure names a request still pending past 24 h (owner
	// decision 181)
type SidecarResultCallback connect.ApiCallback[*SidecarResult] // one terminal result (sdk/api.go:950)
// Go only; gobind skips, mobileexports names each.
func (self *Sidecar) Core() *sidecar.Sidecar
func (self *SidecarSockets) ListenContext(ctx context.Context, address string) (net.Listener, error)
```

Rules: `*Id`, `*Time` or `int64` milliseconds, `[]byte` for byte strings that are not 16-byte ids, as `ProviderIdentity.PublicKey` binds (sdk/post_quantum_identity.go:29), `int32`/`int64` counts, `exportedList[T]` lists (sdk/gomobile.go:10-71), no NSObject names (`Description`, `Hash`) or basic-type aliases (golang/go#71827), every export under `trace` (sdk/trace.go:12, :54), since a crossing panic exits the app.

- **Gate.** Outward calls (§5.4's list) pass `Sidecar.Authorize` on both backends and return `pending` with an approval id (synchronously, `approval_pending:<id>`) until a grant or decision exists.
- **Search (D-SDK-22, D-SDK-26).** Apps only render: the core assembles partitions, masks, confirms and ranks, and chooses indexers, asks, merges and labels (§11.14); hits carry their state and possible matches are labeled; apps render the notice, the remote states and "verified by `<device>`" (18.4); a remote-mode `Sidecar` forwards these calls to the daemon (18.7) and never asks an indexer.
- **Approvals** (owner decisions 112, 126-128, 149, 179, 180). `Decide` signs what each kind requires; admissions and `OwnerConfirm`s follow a safety-number check, never through MCP (D-CORE-13), and only the member's consented devices that are not `read_only` (§7.9, §8.5) sign its scoped admissions, `OwnerConfirm`s and owner-bound `EvsShare`s; an access request reaches the approver §16.11 names for its target. The host's own requests need the `SidecarPresenceSigner`, as does every act §7.9's presence row covers wherever this device registered a live presence key, its evidence becoming the countersignature each of the act's statements carries (§5.6; owner decisions 185, 187); a remote-mode or `ur approve` decision signs `device` evidence only for another sidecar's request (§16.6).
- **Device revocation (D-SDK-30).** `GetDevices` lists the member's devices from the config and the groups this device holds; `PreviewRevokeDevice` returns §5.6's plan; `RevokeDevice` signs it only on a host approval-capable for the member (§16.6) and not suspended (§5.6's caller), after `SignWithPresence` over the act's countersigned bytes wherever the plan's `Presence` is set, its evidence the countersignature that api and every member device check on each statement (owner decisions 185, 187), an empty signature answering `REVOKE_CANCELLED`. The revoked device keeps only what it could already decrypt, and its leaves and keys go as §5.6's `effects` row says. Apps show this copy:

```text
devices     GetDevices' rows: this device first as "This device", with Sign out in place of Revoke,
            then each other device by name with "Last active <LastChangeMillis>", marked "Paused"
            (parked), "Inactive" (stale) or "Being revoked: waiting for another admin" (pending)
ask         "Revoke <name>? Last active <time>."  [It's lost]  [Someone may have used it]  [Cancel]
lost        "<name> will get nothing new from this network and can't act for you. It keeps what it had
            already downloaded. Choose this if it was wiped or broken, or is locked and nobody used
            it."
compromise  "When did you last have <name>?" [date and time]; then the plan: "Devices <name> added
            since then are paused until you confirm them: <devices>. Keys, auth keys, shares and
            recovery codes it set up since then stop working: <items>. Access and approvals it granted
            stay until you revoke them: <items>." Each reseal row: "<device> may hold a backup <name>
            could open: revoke it too and set it up again."
keys        with Presence: "Also remove these keys <name> registered:", each checked, "Uncheck a
            security key you still have"; without it: "Keys <name> registered stay until you remove
            them on a device that asks for your fingerprint, face or security key."
confirm     with Presence, the platform's prompt, "Revoke <name>"; else the app's own confirmation
pending     Signatures > 1: "Another admin must approve. Until then <name> is paused and gets
            nothing new."
cosign      Decide's revocation proposal: "<member> asks from <device> to revoke their <name>.", the
            plan, then "Approve" with the platform's prompt where Presence; while another pending
            proposal of <member>'s names <device>: "<member>'s devices asked to revoke each other.
            Check with <member> before you approve either."
done        "<name> is revoked. Your other devices are changing the keys to everything it could read;
            what it already downloaded stays on it."; with items that joined after the preview:
            "Also paused or stopped since you checked: <items>."
refusals    REVOKE_PARKS_SELF: "<name> added or confirmed this device after <time>, so revoking it
            from here would pause this device too. Pick a later time if you still had <name> then,
            choose It's lost, or revoke it from another device."; REVOKE_STALE: "Something changed.
            Check the list again.", with the new plan; REVOKE_REFUSED: "The network didn't accept
            this, so nothing changed."; UNAVAILABLE: "Can't reach URnetwork, so nothing changed."
```
- **Key store (D-SDK-15).** Statuses follow §5.9's store states (D-CORE-15): only Absent, for a network with no recorded `sidecar_id`, creates a root key.
- **Coverage (owner decisions 12, 125, 150).** `GetReceiverCoverage`'s values and copy:

```text
indexer          an IndexerSet designates a mail indexer for this user's mail (§7.9, §15.6)
foreground-only  receivers, but no mail indexer: "A phone alone cannot reliably receive mail: an indexer, an
                 always-on device (a desktop ur daemon, a NAS or VPS), is needed; time-sensitive codes may
                 not arrive" (owner decisions 12, 197)
none             no receiver; CreateBurner shows foreground-only's copy (§15.9)
every value      says nothing of sending: outbound size limits are CheckSend's and GetSendResult's
```

- **Send capability (D-SDK-31; owner decision 125).** `CheckSend` runs as the person composes, and `GetSendResult` and `mail_send` follow the send, from the outbox too (§14.5). Their copy:

```text
compose     too_large: "<domain> accepts messages only up to <cap> from your devices, and this one
            is <size>. Send <domain> a smaller message; your other recipients aren't affected.";
            unknown, over the cap: "If <domain>'s mail server is an older kind, it accepts only up
            to <cap>, and this message is <size>."; data mode under the cap: "Sending to <domain>
            takes about <delay>."
results     sent; queued: "Waiting for one of your computers to send it."; deferred: "Sending
            again at <time>."; too_large: compose's copy; refused: "<domain> refused it (<code>).";
            tls_refused: §14.4's TL4 refusal; failed: "Couldn't send to <domain>."
never       an indexer, receiver or coverage setting: those are inbound (GetReceiverCoverage)
```

| Gate | Change |
|---|---|
| mobileexports | A `mobileSidecarGoOnlyIds` map; names avoid `Proxy`, an `Rpc` suffix and a `DeviceRemote` prefix, whose broad rules hide lost methods |
| C ABI | Nine handle types, `SidecarSearch`, `SidecarSearchHandle` and `SidecarDirectory` included, join `behavioralTypes` (sdk/cgo/gen/gen.go:48), Go-only members `skipMethods` (:182), `SidecarSettings` `jsonParamDefaults` (:158); `SidecarSecret`, `SidecarIndexer`, `SidecarDevice`, `SidecarRevokePlan`, `SidecarRevokeItem`, `SidecarSendCheck` and `SidecarSendResult` cross as JSON, as data structs do (:15), and `SidecarIndexerList`, `SidecarDeviceList`, `SidecarRevokeItemList` and `SidecarSendDomainList` as JSON arrays, as lists do (:178); listeners and app interfaces cross as function pointers |
| js | The extension Worker's main (18.8) and `gen_types.go` types, the device revocation's among them, where `PreviewRevokeDevice` and `RevokeDevice` answer `REVOKE_NOT_CAPABLE` while the extension is alarms-only (18.4); the page Worker links no sdk (18.10), and its key origin offers no revocation, since it is read_only (18.8); `ur native-host` relays no call that §5.8 signs only on confirmation, §5.6's revocation included, answering `REVOKE_NOT_CAPABLE` itself |

**State (D-SDK-14).** Both backends, by client generation (§5.6):

```text
reasons     unenrolled: expired | refused | parent_lost | session_ended | keystore_lost; revoked: signed
confirmed 401 for generation g    -> unenrolled(session_ended if its cause is session_revoked, else refused),
                                     only if IsAuthLogoutCurrent(g) at the transition; identity, keys,
                                     admission and pins kept
strict_exp passed unrefreshed     -> unenrolled(expired)
parent client removed or reaped   -> unenrolled(parent_lost)
a core revocation hint, or a bind -> fetch the config: revoked(signed) only if a SidecarRevoke{sidecar_id}
  refused with sidecar_revoked       verifies against it, else unenrolled(refused) and an alarm
re-enrollment (EnrollWithDevice,  -> offline, binding generation n+1 under the same sidecar_id
  ur login)
generations every event names its generation; one of an older generation is dropped
```

### 18.6 Device abstractions and the DeviceRemote mirror

```go
// sdk/device_sidecar.go: unexported, so connect and netip types reach no binding.
// device.Bridge (sidecar/device) satisfies it; nil keeps today's behavior.
type deviceBridge interface {
	Route(packet []byte) connect.UserNatClient // a link, a reject client, or nil for the default route; lock- and allocation-free
	EgressHook() connect.EgressHook            // §4 C5, §17.6: pass, map or deny per flow
	Routes() []netip.Prefix                    // the block if chosen in RFC 1918 (owner decision 132), hosted addresses,
	                                           // granted prefixes and aliases, minus every local /32 the physical path
	                                           // needs (interfaces, gateways, resolvers), never the whole block; with
	                                           // those unknown, per-peer /32s instead of the block (§17.4, D-BRIDGE-12)
	LocalZone() connect.LocalZone              // §12.9's private names from the state's Names and NameZones; nil before a state
	SetPending(pending *bridge.Pending) error  // legacy -> pending, at forwarding's setup (Setup, below)
	SetState(state *bridge.BridgeState) error  // §17.8, from the forwarding role's own compile (Following); versions only rise
	ApplyDeltas(objects [][]byte) error        // projection deltas, verified offline against the state's anchor (§8.9)
	Status() device.BridgeStatus
	AddChangeCallback(callback func()) func()
}
// bridge is sidecar/protocol/bridge (D-SDK-20). BridgeState (§17.8) carries compiled rules, names, identities and
// share keys (§17.9), its AuthPin and the anchor; in an app the forwarding role produces Pending and states in the
// VPN component's own process (Following, below), and none crosses the device RPC. DeviceLocal also implements
// §17.10's BridgeHost (NewBridgeLink), in sidecar/device, minting each link's window clients under its forwarding
// client and signing their delegations with its forwarding key (Signing, below).
func (self *DeviceLocal) GetBridgeRoutes() *BridgeRouteList // bound, for the tun owner in its process (18.15), with its listener
func (self *DeviceLocal) SetBridgeLocalAddresses(addresses *StringList) // bound: the tun owner's interface, gateway and
	// resolver addresses from the platform's routes and DNS settings, on each path change, since
	// connect.LocalIpv4Networks sees only interface subnets, or nil where enumeration is restricted
	// (connect/tun.go:490-495); until set, Routes() exports per-peer /32s
// Device, so DeviceLocal and DeviceRemote: GetBridgeStatus() *BridgeStatus, AddBridgeStatusChangeListener(listener) Sub
```

- **Lifecycle.** Past legacy, `DeviceLocal` builds `device.Bridge` on its provider client and rebuilds it with the client, like subprotocols (sdk/device_local_subprotocol.go:95-110), at §17.5-§17.6's call sites (sdk/device_local.go:5696, :5789, :6340-6345). On each change it re-reads hook and routes and passes `LocalZone()` to C14's `UpgradeMux.SetLocalZone` beside `SetBlocker` (:5315; owner decision 85).
- **Setup (D-SDK-32; owner decision 197).** The sidecar role's one act for its VPN component, in each network it has joined: in process on Android, over the device RPC to the iOS extension, and from `ur daemon` through the desktop app paired per §5.8 to the macOS extension or the Windows or Linux app service; never through MCP. After it the forwarding role holds everything it needs, and the app's absence stops nothing:

```text
when        each new client generation of the sidecar S (enrollment, re-enrollment, pairing; 18.5's State), and
            any run of the app 90 days or more after the last setup; after a DelegationRevoke of S's forwarding
            Delegation by any signer but S (§7.9), only when S's person confirms in the app's UI
keys        the VPN component generates, and never exports, a forwarding key (Ed25519), a forwarding reader key
            (X-Wing) and its forwarding client's ClientKey; only their public halves cross
delegate    S signs its forwarding Delegation {pubkey, reader_xwing_public_key, forward: S, and in its device
            client D's network D as host_client_id and host_client_public_key} (§7.9's forwarding row), which
            supersedes S's earlier one, and writes its first DelegationWrap of the config's current generation
            (§10.5's dwraps)
mint        S mints its forwarding client F: POST /network/auth-client {source_client_id: S's client,
            admin_refused, strict_exp, forward_only, the VPN component's client public key} with S's DPoP proof;
            F and its window clients act as S (D-ACL-3), and forward_only confines their tokens (§7.4, §7.8)
hand off    F's token, the Delegation's id and Pending {network_id, genesis_sha256, sidecar_id, identity public
            key} reach the VPN component; no key of S does
after       the VPN component refreshes F by its own DPoP proofs (§7.4), follows and compiles (Following) and
            signs (Signing); a forwarding client left unrefreshed 7 days, its VPN component off that long, lapses
            with no grace (D-TEAM-14), and forwarding stays pending until the app's next run mints another
```

- **Following (owner decision 197).** The forwarding role takes rule changes directly, with one compiler and follower shared with the daemon (18.10):

```text
pushes      team hints reach the VPN component on its device client D in D's network (21842 registered for
            pushes only, D-PROTO-8; D minted acl_enforcing, Rules below), and in any other network by §6.8's
            long-poll on F
follow      it fetches the authorization log (GET /network/config/projection?after=) and config heads with F's
            config-read token (§7.8), opens each config generation by its DelegationWrap (§10.5), and runs the
            forwarding leg's follower, AclEngine and §17.8's compiler for S off the packet path, within §8.9's
            targets, so a new rule, grant, block or revocation applies while the app sleeps
witness     while the sidecar role runs, it sends its witnessed AuthPin (§6.4) as a hint: the forwarding role
            fetches and verifies up to it, and a pin off its chain raises head_alarm through the status mirror;
            between the app's runs its view is unwitnessed (§17.17)
```

Its posture is one state machine with §17.8's engine (D-SDK-13, D-BRIDGE-18):

```text
posture      per network, persisted in the VPN component's own store, sealed under forwarding's local key (§5.9):
             iOS and macOS, the extension's container, never the app group; Android, the VPN service's files;
             Windows and Linux, the app service's state directory
legacy       no sidecar has set up forwarding here: nil deviceBridge, today's behavior
pending      setup handed it Pending{network_id, anchor, sidecar_id, identity key}: every Network source is denied
             loopback, LAN, link-local, overlay and served-prefix destinations and every exit; the block deny
             stands; maps and hosted addresses refuse
enforcing    a state its own compile verified, and the anchored deltas after it, re-verified offline against the
             anchor and restored before the first packet on every start; {doc}: §17.6's rules; {nodoc}: owner
             decisions 50, 105 and 120's allow-all, entered only on a verified base above the persisted
             document_seen_at latch (the newest pin at which has_document was true)
stored       the anchor, the newest verified AuthPin, the signed base header and rows, the statements since,
             document_seen_at, and the config generations and compiled state its last compile used
transitions  legacy -> pending -> enforcing{doc|nodoc}; back to legacy only on this sidecar's own sign-out
             (its SidecarRevoke), which wipes the stored state and forwarding's keys
never        an unverified projection, one that does not chain, a lower version or an unsigned has_document
             changes the posture; one that fails to verify leaves it unchanged and alarms
DP1          after a device's first verified state, no restart, delay or unsigned response lowers enforcement
so           an unverified projection is never read; a verified no-document state keeps owner decisions 50,
             105 and 120's allow-all
```

- **Signing (D-SDK-13, D-SDK-32).** The forwarding role signs its own links' delegations, so no link waits on the app:

```text
sign     per window client a link builds (§17.9's sign), the VPN component signs its WindowDelegation with the
         forwarding key: subject S, signer_id the forwarding Delegation's delegation_id (§6.9), not_after_ms at
         most the window client's strict_exp, which F's children inherit; on a share link, with the share's
         current BridgeShareSigner, read from the config, while its ShareCert is unexpired (§17.9); the window
         clients are F's children, so C13 seals S's client as their subject
only     the forwarding key signs nothing but S's WindowDelegations (§7.9's forwarding row); targets check
         every flow against their own state (§17.9's use), so it gains no reach S lacks
host     in D's network, the device's hosted address, maps and served prefixes run on D's sdk provider once
         C16 lands (D-SDK-3), which S's forwarding Delegation names, so senders link to D and check its key
         (§17.9's target); in any other network an app device hosts nothing
```

- **Rules.** An sdk mints its device client `acl_enforcing` (§7.7) only after its forwarding role leaves legacy, so its resident publishes `team` hints to it (§6.8); earlier or older-sdk clients stay legacy until the app re-mints them (owner decision 106), its sidecar re-enrolling (18.5's State). `checkDeviceSubprotocolId` (sdk/device_local_subprotocol.go:85-93) also refuses 21842-21851 to apps.
- **Mirror.** Bridge status and forwarding's setup calls (the keys' public halves out, the hand-off in, the witness hint) are additive, like network peers (sdk/device_rpc.go:6202-6232, :12100-12135, :14388), each listed in its method table (sdk/device_rpc_methods.go:18, :234): an older peer answers unlisted methods as unknown (:9-18), so `DeviceRpcVersion` stays 3 (:7677). No other sidecar-role API crosses the device RPC, and no key: forwarding's keys never leave the VPN component, and S's never enter it.

### 18.7 Host services the sdk injects

| Service | sdk host | Into §5.4's `SidecarHost` |
|---|---|---|
| JWT, refresh | an Api session holding only the child token (sdk/api.go:182-192), `strict_exp` for 7 days (owner decision 131); `StartJwtRefresh` at 40-50% of lifetime; refresh carries a DPoP proof from a signer sdk/sidecar.go installs (`Api.SetDpopSigner`, Go only, from the core's ClientKey), and none is sent without one | `TokenSource()`; D-CORE-8's refresher off once the signer is installed |
| Logout | `AddAuthLogoutEventListener` (confirmed 401, with its generation; `IsAuthLogoutCurrent` at the transition) | `Unenrolled` with a reason; `Revoked` only on a verified `SidecarRevoke` (D-SDK-14) |
| State, secrets | `StateDir` or IndexedDB; the app's `SidecarKeyStore` | `Store()`, re-sealing tokens on refresh; `KeyStore()` |
| Conditions, background windows | the app's `SetConditions` on each change, and its OS window calling `RunBackgroundSync` (below) | the search engine's sync windows (D-SDK-23) |

**Network credential (I-6; owner decision 45).** Same-user agents read `.auth_state` and the extension's `chrome.storage.local` (18.3), so two releases precede §7.4's stage 2 (M3): the desktop app's stops persisting `by_jwt` once the device client exists, re-authenticates for admin actions, seals `.auth_state` in an app-only OS keystore where one exists, and mints device clients `admin_refused`; the extension's stops persisting `by_jwt` in `chrome.storage.local` at each of 18.3's four writes, re-authenticating where it needs one.

**Search windows (D-SDK-23, D-SDK-27).**

```text
window      iOS: a BGProcessingTaskRequest with requiresExternalPower and requiresNetworkConnectivity
            (https://developer.apple.com/documentation/backgroundtasks/bgprocessingtaskrequest), which cannot
            require an unmetered path, under the processing background mode and a permitted identifier the app
            adds (its Info.plist lists only fetch and network.ur.update-tunnel:
            apple/app/URnetwork-Info.plist:17-20, :96-99); Android: WorkManager periodic work with
            setRequiresCharging(true) and NetworkType.UNMETERED
            (https://developer.android.com/reference/androidx/work/Constraints.Builder); each calls
            RunBackgroundSync(budget), which does 18.4's window work while the reported conditions allow it,
            stops at the budget and resumes next time
conditions  SetConditions(unmetered, charging, lowPower) on each change: iOS NWPathMonitor (unmetered =
            neither isExpensive nor isConstrained), UIDevice batteryState, ProcessInfo
            isLowPowerModeEnabled; Android NET_CAPABILITY_NOT_METERED, BatteryManager.isCharging,
            PowerManager.isPowerSaveMode
foreground  an app host with remote search on opens or reuses the Network contract with its first-choice own
            search indexer at each foreground and sends §6.4's Hello with feature bit 1 (§6.11) unless its
            session there lives (a Pong within 120 s), running HeadCheck where due, its hourly round
            counting that indexer among its own-device picks; while in the foreground it sends that indexer
            §6.10's keepalive Ping each minute, so a search's contract opens at a foreground or a window's
            end, not at the search unless it fails over or finds the session lost, when its Hello
            re-establishes the session at once (owner decision 191); a HelloResult or Pong within 3 s
            marks it online for 10 min; another member's indexer is warmed only once its notice is
            answered, and then kept alike
control     a remote-mode Sidecar forwards Search, GetStatus and SetPolicy over §5.8's control channel to
            the daemon as a stream, asking for untrusted hits' text, since a person reads them (§5.8), so the
            desktop app and the extension's native host use the daemon's cache and policy; it never asks an
            indexer, its daemon holding all: GetIndexers lists none, and SetRemote and AcknowledgeIndexer
            answer refused
```

**Wake pushes (owner decisions 17, 88; D-SDK-16).** Apps call `SetPushToken` at every launch, posting `{platform, token}` to `POST /sidecar/push-token`; the server keeps one per client in `sidecar_push_token`, with a revision that each change raises, projected as `tok` below in revision order (step 0, WK5). The queue and the sentinels aside, every key below sits in the client's slot `{scp_<C>}`, and no command spans two slots:

```text
{scp_<C>}live    EX 90; its publisher (§6.8) refreshes it every 30 s
{scp_<C>}tok     api's projection of sidecar_push_token's {platform, token} at the revision tokrev holds;
                 absent while the row is a tombstone (no token); written only by step 0's apply script
{scp_<C>}tokrev  the newest revision of C's row applied to tok, a decimal string; no TTL
{scp_<C>}ack     the highest hint stream id C's connect stack acked; EX 3600; written only while tok exists
{wakeq_<shard>}  16 streams in their own slots: {c, t, v, h, hint_millis, due_millis}, MAXLEN ~10000
{tokgen_<n>}     16,384 sentinels, one per hash slot (n the least integer whose tag hashes to it), each holding
                 the run_id of the master that served the slot at its last reconcile (step 5); like tok and
                 tokrev, no TTL, so volatile-ttl never evicts them
                 (xops/main/ansible/templates/redis/redis.conf.j2:1184)
0 token    a change to C's sidecar_push_token row (a POST, an empty POST, a vendor rejection, C's removal)
           raises its rev by one in the statement that makes it, a removal leaving a tombstone (no
           platform or token) and a new row's rev starting at its insert's time in milliseconds, above any
           rev a lost row of C reached before a Postgres restore (§19.10), as rows change far less than
           once a millisecond; its writer reads t0, the TIME of the master serving {scp_<C>}, before the
           transaction, commits, then runs the apply script on {scp_<C>}: EXPIRED when that master's TIME
           is over 60 s past t0; STALE when tokrev > rev; nothing written when tokrev = rev; else SET
           tokrev and SET tok, or DEL tok for a tombstone; an EXPIRED or failed apply rereads t0 and the
           row and applies again, at most 3 times; a POST equal to the row commits nothing and applies the
           row as it stands; revisions stay far below 2^53, so the script compares them exactly
1 hint     §6.8's one EVALSHA on {scp_<C>}: HSET ver if higher; XADD hint -> h; INCR n; return {h, tok, live}
2 enqueue  after the script, the owning service, only if tok and the topic is mail, team, evs or core, XADDs
           to {wakeq_<hash(C) mod 16>}: due now if forced or live is absent, else now + 15 s (a deferred
           check); forced: §15.6's router on a receiver miss, and POST /sidecar/wake (§6), which writes a core
           hint; an XADD error is retried 3 times within 1 s, then counted
           (urnetwork_wake_enqueue_dropped_total) and dropped, the hint state untouched
3 ack      the publisher sends each coalesced PushHint batch with connect's frame ack (18.3) and, on the ack,
           raises {scp_<C>}ack to its h
4 send     §19.4's push sender reads each stream through one consumer group, holds entries in a heap by
           due_millis and at due MGETs ack, tok and tokrev: ack >= h or no tok drops the entry; otherwise
           it wakes under §19.4's per-client coalescing (one wake per 10 s) and vendor caps, then XACKs; a
           crash before XACK redelivers through XAUTOCLAIM after 30 s idle; entries over 60 s old are dropped;
           a vendor 410 or UNREGISTERED tombstones the row only while its rev equals the tokrev read with
           that token, so it never removes a newer registration (step 0)
5 loss     taskworker's pass, every 60 s, compares each sentinel with the run_id (INFO; random per process
           start, https://github.com/redis/redis/blob/8.10.0/src/server.c initServerConfig) of the master
           CLUSTER SHARDS shows serving its slot; with no replicas, a master that comes back empty or from
           its last RDB dump, its only persistence (xops/main/ansible/templates/redis/redis.conf.j2:453,
           :1420; xops/main/ansible/REDIS.md:140-141), or that newly serves a slot leaves the sentinel
           absent or naming another run_id; each such slot is reconciled at the first pass at least 90 s
           after the pass that found it, if the same master still serves it: read t0; list the slot's tok
           and tokrev keys (CLUSTER GETKEYSINSLOT); then read its rows by sidecar_push_token.slot and apply
           each (step 0); DEL tok and tokrev of each listed client that has no row, a row being committed
           before any key of its client exists; then SET the sentinel; every apply begun before that
           master took the slot has expired by then, §19.6's chrony holding masters' clocks within 50 ms,
           and later ones are ordered by its tokrev; one master's slots take about 2 s per million tokens,
           all 16,384 about 50 s, at 20,000 writes/s, after the 90 s (FS-36: one master killed, one
           restarted from an older dump)
6 sweep    the same pass applies every row changed since 2 min before the last completed pass began, so an
           apply lost with a killed api lands within about 2 min with no app launch, and deletes each row
           24 h after its client's removal, after DELing its tok and tokrev (FS-120)
WK1  no script or MULTI spans two hash slots: a CROSSSLOT lint, and a 3-master cluster in T3
WK2  a wake-class hint to a token holder yields a vendor submission by due plus the sender's lag, unless
     the client's stack acked a stream id >= h, coalescing folds it into a later wake, a vendor cap
     applies, or the wake is lost: its enqueue dropped after step 2's retries (counted by
     urnetwork_wake_enqueue_dropped_total) or with a service killed after the script (uncounted), its
     entry older than 60 s or lost with its master, or its tok absent until step 5 reconciles the slot
WK3  losing a wake-queue entry never changes hint state
WK4  wake payloads carry a topic class and a version only (owner decision 88)
WK5  while the slot's sentinel names its serving master, tok moves only up its row's revisions: an
     apply lands only above tokrev and within 60 s of its t0, so once a change commits, tok equals the
     newest row (absent for a tombstone) as soon as that change's apply, a retry or step 6 lands, or
     step 5 reconciles a slot whose master changed, and no older token or removed one returns; until
     that reconcile, at least 90 s after the pass that found the new master, tok may hold an older or
     removed token, from an older dump or an apply begun before that master took the slot
```

- **Resync.** The app resyncs over HTTPS (§6.8); no wake event outlives §6's hourly key (§2.8 api-6, ext-8).
- **Best effort.** Apple asks for at most two or three background pushes an hour (https://developer.apple.com/documentation/usernotifications/pushing-background-updates-to-your-app); FCM may demote silent ones (https://firebase.google.com/docs/cloud-messaging/android/message-priority).

```text
APNs  apns-push-type background, apns-priority 5   {"aps":{"content-available":1},"t":"mail","v":42}
FCM   data message, priority high                  {"data":{"t":"mail","v":"42"}}
      t: mail | team | evs | core (§6.8's topic with any id stripped); v: that topic's version; never an id
```

- **Directory notices (D-SDK-28).** From M8 a phone leases the team directory's `q/<target>/` prefixes for the targets its member approves, and the notice path of each of its own pending requests (§16.11, §11.10), so a decision, a denial's included, rewrites a notice the phone leases. Their hints are `evs:<repo_id>` hints like any lease's (§6.8), so they are wake-class: a request or its decision wakes the phone under topic class `evs`, naming no directory, target or request.

### 18.8 The browser sidecar (X14): the extension and ur.io pages

```text
ur.io:     page, labeled as served code (§2.8 EX7) -> iframe https://sidecar.ur.io/v1/ (key origin)
             -> Worker: sidecar.wasm; the quick burner memory-only
Chrome:    extension page -port urnetwork-sidecar-v1-> service worker (relay; mints client; alarms)
             -> offscreen document (reason WORKERS; alarms re-create it) -> Worker: sidecar.wasm (IndexedDB, WebCrypto)
Firefox:   event page -> Worker: sidecar.wasm; both unload when idle (MDN)
meanwhile: connectNative -> `ur native-host` (stdio) -> `ur daemon` control mode (§5.8)
carrier:   first HTTPS-only: §6 long-poll, §10, §11 (config repo too) | later wss H1 + in-band protocol.Auth (§4 C4)
```

- **Phasing (owner decisions 15, 26, 76).** HTTPS-only needs neither C4 nor C17, so the page Worker, on 18.10's `sidecar_http` leg, serves ur.io/recurd from RS1 (M4) and the team console from RS2 (M6).
- **Carrier.** C4's `GOOS=js` WebSocket carrier, templated on sdk/device_rpc_platform_js.go, needs the server to admit `chrome-extension://` ids, the `moz-extension:` scheme (per-install UUID origins, https://bugzilla.mozilla.org/show_bug.cgi?id=1372288) and the key origin `https://sidecar.ur.io`, safe since auth is a bearer frame.
- **Identity (owner decisions 112, 114, 126, 144).** Each Worker but the quick burner is an untagged member device, admitted per §5.6 with the member's consent (§8.5) and counted in `config_admissions` (§20.4). The page Worker reads records, receipts and the config's names, tags, groups and policy (owner decisions 46, 67); it is admitted `read_only` (§7.9), so every verifier refuses what it signs but its sign-out `SidecarRevoke`, its own ReaderKeys, KeyPackages and leaf's MLS maintenance under its r scopes (§10.6), read receipts and HeadCheck replies, and it is never approval-capable (§16.6) or a key deliverer. The extension's service worker, or on ur.io the key origin, mints one `admin_refused`, `strict_exp` top-level client declaring no egress (§20.8), re-minted under its `sidecar_id` after expiry (§5.5); the Worker gets only its token, never listens, and serves only its own pages. `nativeMessaging`, which warns of "cooperating native applications", stays optional (Firefox 87+, https://bugzil.la/1630415).
- **Key origin (D-SDK-18).** ur.io pages frame it and message it by exact origin:

```text
pages       https://ur.io/recurd, the console and the quick tools render views and hold no sidecar key, sidecar
            token or wrapped secret, though ur.io's account panel keeps a network byJwt in localStorage while a
            member is signed in on that browser; the team console shows the directory, and the drops of the repos it reads with
            their states and the device command; it files no request or decision and never dry-runs, signs
            or cancels a drop (read_only, admin_refused; D-SDK-29)
key origin  https://sidecar.ur.io/v1/, served direct from the lb, never through Cloudflare, which terminates
            https://ur.io (§2.8 EX7, §19.5's W10; owner decision 211), serves only the signed loader and
            sidecar.wasm, under CSP default-src
            'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 18.9's hosts; frame-ancestors
            https://ur.io; its Worker holds IndexedDB, the non-extractable WebCrypto root key and its token
messages    postMessage, accepted only when event.origin is exactly https://ur.io in production (per-env
            lists; never localhost or http:); requests name an operation (list, read view, record view,
            directory view, drop states, search, search more, search cancel, search status, search policy,
            sign-out); replies carry plaintext views only, search hits as display fields and states;
            GetSecret's strings never leave the Worker
storage     same-site with ur.io, so not partitioned in first-party use (§22.9's reload test checks it); the
            search cache is its own IndexedDB store, written only by the lock holder (D-SDK-24); a browser
            clears an origin's storage bucket in its entirety (https://storage.spec.whatwg.org/, §7), the
            keychain, MLS state and token with the cache: under storage pressure unless the bucket is
            persistent, and in Safari after seven days of Safari use without user interaction on the site,
            Home Screen web apps keeping their own count
            (https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/); so the frame calls
            navigator.storage.persist(), which Safari grants by heuristics such as a Home Screen web app
            (https://webkit.org/blog/14403/updates-to-storage-policy/, 2023-08-10), and the page tells the
            person what an eviction costs: the next Worker enrolls anew (admission, below)
instance    one Worker per network (§22.9's two-tab case), as §5.8's flock keeps one daemon: a Worker opens
            a network's state only while it holds the Web Lock urnetwork-sidecar-<network_id> (exclusive,
            scoped like IndexedDB to the storage bucket: https://w3c.github.io/web-locks/), so only the
            holder loads the keychain, MLS state and token, refreshes, commits and writes; every other Worker
            loads no state and relays its page's requests, and the views back, over a BroadcastChannel of
            that name; the lock frees with the holder's Worker (its tab closed, reloaded, crashed or
            discarded), and the next waiter reloads from IndexedDB, relayed requests retrying; Chrome 133+
            does not freeze a tab whose lock blocks another
            (https://developer.chrome.com/blog/freezing-on-energy-saver, 2025-01-20); the frame refuses to
            start without locks (before Chrome 69, Firefox 96, Safari 15.4), while a SharedWorker would need
            Chrome 148 on Android (https://github.com/mdn/browser-compat-data, 2026-11-05); quick burners,
            memory-only, take none
extension   (Later) its Worker accepts only its own extension pages' ports, never a content-script relay,
            and takes the same lock
admission   a page Worker or quick burner needs a consented device of its member online to admit it (§5.6),
            and the quick burner also to sign its EvsShare; with self_admit off, an admin admits a page
            Worker, which stays parked in owner-bound repos until OwnerConfirm; a Worker enrolling after an
            eviction is a new sidecar_id, adding a config_admissions entry (§20.4); the device admitting it,
            an admin's included, revokes that member's page Workers §10.9 removed as stale from every
            group it is a leaf of that seated it, at least one, and the member's consented device, in its
            admission or else at its OwnerConfirm or admission alarm, revokes those its groups show and
            offers to revoke the others (§7.10's stale row; D-TEAM-29), so evictions pile up only as that
            row bounds, and from 90% of the cap admins' devices list the rest to revoke (§7.10's cleanup)
leaves      each page Worker is a read_only MLS leaf of each group it reads, within D-KEYS-2's 1,000 per
            group; in the config and directory groups, unless §7.9's rank makes it one of the 1,000
            leaf-entitled, it reads by wraps (owner decisions 144, 182); sign-out removes it, and an unused
            or evicted one goes by §10.9's stale-leaf Removes, 90 days after its leaf last changed
disclosed   script running in https://ur.io (served code, Cloudflare's altered page script, an XSS, an
            extension with page access) can request views while it runs, never the Worker's key or token, so
            that access ends with it; it can also take the account panel's network byJwt from localStorage
            while a member is signed in on that browser, which reaches network-credential routes, but a client
            minted with it gets no admission, key or plaintext without a consented device (§5.6, §7.9; §2.4,
            §2.10)
```

- **Quick burner (Q-SDK-4).** An ephemeral sidecar: a memory-only keychain (§5.6) on an `ephemeral` client (§7.7), never a genesis signer, reading the member's mailbox by ReaderWraps through an `EvsShare` (§8.8, §15.7) that the consented device admitting it signs, and reaped 30-36 min after its last poll (the lease below, §7.10); with no consented device of its member online, the page waits. It searches the mailbox's two buckets in memory only and never fetches all.
- **Lease (D-SDK-17).** No resident measures an HTTPS-only host's disconnect, so its polls carry its liveness, in a narrow table rather than `network_client.auth_time`, whose every write updates that table's ~10 indexes, so `ConnectNetworkClient` refreshes it at most hourly (server/model/network_client_model.go:3625-3634):

```text
lease        network_client_lease(client_id PK, seen_time, close_sha256 unique): one row per ephemeral
             client, inserted at its mint (§7.7); a GET /sidecar/sync/poll whose SET {scp_<C>}hb 1 NX EX
             300 sets, or errs, writes seen_time = now, so at most once per 300 s while Redis answers
reap         taskworker's ephemeral job, every 60 s, reaps (§7.10) each ephemeral client with no open
             connection whose seen_time and newest connection disconnect_time, if any, are both over 35
             min old, probing each lease row past 35 min by network_client_connection's (client_id,
             connect_time) index (server/db_migrations.go:3149-3152; closed rows live 8 h,
             server/taskworker/work/network_client_work.go:93): 30-36 min after the last poll, 35-36 min
             after the last disconnect, so an agent connected for hours survives any disconnect under 35 min
close        §7.8's enroll and auth-client responses return an ephemeral client's 128-bit close capability
             once, api keeping only its SHA-256 (§7.7); the key-origin document, not the Worker, holds it
             and on pagehide sends navigator.sendBeacon(POST /sidecar/close) with it as a text/plain body,
             since sendBeacon sets no Authorization header and Workers lack it; the Public route (§6.16)
             reaps the client whose close_sha256 matches at once; best effort, the lease bounding the rest
generations  each poll authenticates its own client_id; a reaped or revoked client's polls get 401 and
             write nothing, so no old generation keeps a replacement alive
suspended    a tab suspended over 36 min is reaped; on resume its polls get 401 and the page offers
             re-enrollment, since a memory-only keychain cannot rejoin
cost         one narrow-row write per ephemeral page per 5 min (about 33/s for 10,000 pages) and one
             index probe per lease row past 35 min per run; auth_time keeps its hourly refresh
```

### 18.9 Headless and cloud agents

| Rung | Carrier | Needs | Gives |
|---|---|---|---|
| 1 | H1 wss direct | egress to the platform host | everything |
| 2 | H1 via HTTP CONNECT (`HTTPS_PROXY`) | §4 C8 (M4), including API dials | everything |
| 3 | HTTPS-only | the required hosts below | evs, records, long-poll; no streams, sockets or mail send |

Owner decision 49 runs `ur` in the VM on rung 2, as a desktop daemon without mail receipt. `ur` embeds its allow-list and the issuer SPKIs of its hosts, `ur status` probes each entry, and mmm publishes the list at `https://ur.io/recurd/hosts/v1.json`, versioned by path:

```text
host                          tcp  need
api.bringyour.com             443  required: enrollment, /sidecar, /acl, /tls, /mail, long-poll (§6)
auth.bringyour.com            443  required: login, token exchange (§7.8; server/IDP.md:18)
evs.bringyour.com             443  required: storage (§11)
gkm.bringyour.com             443  required: MLS (§10)
connect.bringyour.com         443  rungs 1-2: RPC, streams, sockets, mail, bridge; UDP 443 (H3) optional
sockets.bringyour.com         443  with sockets (§9)
dns.bringyour.com             443  with records or TLSA (§12.8)
api.certspotter.com, crt.sh   443  with tls: the CT watch (§13)
ur.io                         443  optional: install.sh, the release key, this list
```

Claude Code cloud adds secrets at its proxy (https://code.claude.com/docs/en/cloud-environments), so the proxy may see bearer tokens, never Required-mode traffic or repo content; `ur status` reports interception (§2.4), a chain ending outside those SPKIs, without blocking it. Offline agent phases spool (§16.9).

### 18.10 Build and size

- **Imports.** sdk imports the sidecar root and `protocol` in sidecar-role files, and in forwarding files `sidecar/device`, `protocol/bridge` and the root's forwarding files, by a new rule on sdk/dependency_boundary_test.go's legs (:80-92); §4.7's `make check` fails the `ios_extension` leg if its root files leave the forwarding list below or it registers a `protocol` descriptor outside it (D-SDK-20).
- **Forwarding leg (owner decision 197; D-SDK-20).** Every VPN component runs forwarding and no other sidecar code: Apple's extensions link only forwarding, as the `ios_extension` leg, and the Windows and Linux app services the same file list, while Android's VPN service runs in the app's own binding, where the sidecar role's code is present but runs only while the app is open (18.4):

```text
kept        the every-leg types and SidecarApi; the forwarding client's DPoP refresh (§7.4); the authorization
            log's follower and config verification (§7.9); DelegationWrap unwrap, X-Wing and the key ladder
            (§10.5); evs head reads of the config repo (§11); AclEngine (§8); §17.8's statements and compiler;
            forwarding's signer; protocol's config, acl, evs and gkm descriptors; sidecar/device; protocol/bridge
excluded    every other root file, under !ios_extension as connect-facing ones carry !sidecar_http: mls_,
            mail_, smtp_, tls_, dns_, socket_, search_, record_, directory_, indexer_ and the subprotocol but
            push hints; evs writes and every repo but config; approvals, enrollment and recovery; mcp/, cli/
            and every <svc>service
make size   from M4 the leg adds at most 4 MiB of executable over today's binding, and the signed iOS
            extension's ceiling rises from 50 MiB to 54 MiB (proposed; Q-SDK-7)
memory      forwarding's Go heap at most 4 MiB steady and 8 MiB while compiling, inside the iOS tunnel's 28 MiB
            target and 32 MiB soft limit (sdk/build/APPLE_EXTENSION_MEMORY_BUDGET.md): rows stream, never held
            whole, and a compile that would pass the bound leaves the last verified state in force and raises
            bridge_alarm (proposed; Q-SDK-7); measured on surrogates only (owner decision 100)
```
- **Pruning.** No `net/rpc`, templates or dynamic reflect lookups (sdk/build/mobile_method_pruning_test.go:27); the worker needs protobuf v1.36.12, the first that keeps pruning (sdk/build/go.mod:98; sdk/js/go.mod:97 has v1.36.11), and sidecar generates with v1.36.11 (§6).
- **Tags.** sdk's sidecar-role files carry `!ios_extension`, and §5.10's Keychain tag keeps gomobile's darwin slices (sdk/dependency_boundary_test.go:91) on the app's `SidecarKeyStore`.
- **iOS.** From M4, §4's `make size` holds the `ios_extension` leg to the forwarding leg's budget above (proposed; Q-SDK-7; D-SDK-20); memory is measured on surrogates only (owner decision 100).
- **wasm (D-SDK-19).** A connect-only js/wasm main is already 55.0 MB unstripped (53.2 MB stripped; 2026-11-03), since Go links every imported package's `init` functions and initialized variables, connect's IP stack included (42 gVisor packages, §4.6). The page Worker's `sidecar.wasm` therefore links no connect package; the Q-SDK-1 spike before M4's entry decides C17 for the extension only (owner decision 22):

```text
leg         js/wasm, -tags sidecar_http, main sdk/js/cmd/sidecarwasm, importing only the sidecar root and
            protocol (not sdk); its entry type is sidecar.Sidecar from this leg's NewSidecar, with no
            components and a SidecarHost of Store over IndexedDB, KeyStore over the WebCrypto key and a
            nil TokenSource, so §5.6's sidecarTokenManager refreshes (§5.4)
excluded    the root's connect-dependent files (client generations and SidecarEnv, Subprotocol and
            streams, remote search's search_remote_*.go, sockets dial and listen, bridge, tls and smtp
            listeners) and the engine host
            interfaces (host_*.go), since no server engine (§4.4) runs in the page Worker, each //go:build
            !sidecar_http; only they name a connect type, connect.Id included, or the root's Subprotocol
kept        identity, keychain, config verification and ACL evaluation, mls_ and the key ladder, evs head
            reads and writes over HTTPS, records and approval views, search (x/text normalization, about 0.6
            MB unstripped; no zstd), the long-poll, and the token path over SidecarApi: POST /sidecar/bind,
            GET /auth/refresh with a DPoP proof that crypto/ed25519 signs by the ClientKey (§7.4), and the
            token exchange for evs and gkm (§7.8)
types       §5.4's every-leg types: the root's Id ([16]byte), Logger, MonitorValue and CallbackList, and
            the net/http SidecarApi (bearer plus DPoP signer), so its events, actions, binding and Sign
            link here; connect-facing files convert at that boundary
make check  from M1: this leg's go list -deps holds no github.com/urnetwork/connect package and no gVisor
gate        41,943,040 B unstripped (owner decision 22's goal), measured from M2; estimated 13-21 MB (Go's
            js runtime, net/http's fetch transport, protobuf, crypto/hpke, mls_, search)
threads     js/wasm runs one thread: MLS and X-Wing are pure Go in the Worker, and an operation over 50 ms
            yields between steps, so a long-poll's fetch and page requests interleave
C17         no longer gates the page Worker; it stays for the extension's streaming Worker (C4, Later)
miss        if the leg still exceeds the goal at M4's entry, RS1 ships it under today's 74,965,628 B sdk.wasm
            gate, a size ur.io already serves, and Gn-in records the slip; never a hosted sidecar
```

### 18.11 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Full sidecar in network processes | always on | iOS: 4,690,096 B headroom, 32 MiB shared, jetsam kills the VPN; desktop: root, LocalSystem or sandboxed processes (apple/app/app.xcodeproj/project.pbxproj:1291) hold content | rejected (owner decisions 87, 197) |
| The keyless device role: the app compiles the rules and signs each link's delegation | no key or config reader in the tunnel; a 1 MiB budget | new rules and new links wait for the app, and a sleeping app stalls links | not taken (owner decision 197) |
| A forwarding sidecar of its own in the VPN component, admitted as a device | hosts verify as today | two sidecars per app device in policy, `ur devices` and admissions; filings signed for a sidecar the app does not hold; with self_admit off an admin admits every phone's | rejected: a forwarding Delegation of the device's own sidecar (D-SDK-32) |
| A second, minimal follower, policy evaluator and compiler in `sidecar/device` | keeps the tunnel near 1 MiB | two implementations of security-critical rules to keep equal | not chosen (proposed; Q-SDK-7) |
| A forwarding Delegation that expires within 90 days, as an auth key's | bounds a copied forwarding key with no revocation | forwarding stops where the app has not run for 90 days | rejected: it ends with its sidecar, its revocation or a newer one (owner decision 197) |
| Forwarding in the root package, linked whole | no new package | links every root `init` and `protocol` descriptor into the jetsam-bound tunnel | rejected: `sidecar/device` with the listed root files (Q-SDK-5; D-SDK-20) |
| Hosted sidecar like ProxyDevice | no install | keys and plaintext on servers | ruled out (owner directive 2026-11-03; owner decision 26) |
| No browser sidecar before M8 | smaller M4 | ur.io/recurd and the console decrypt nothing (owner decisions 15, 46) | rejected (18.8) |
| Keys in the `https://ur.io` origin | no frame or messages | any ur.io XSS uses the key and takes the token | rejected (D-SDK-18) |
| Poll lease in `network_client.auth_time` | no new table | non-HOT writes over ~10 indexes at 12 times server's hourly cadence; a reap keyed on it revokes a long-connected agent within 60 s of a blip | rejected (D-SDK-17) |
| Phones keep all in the background on any network | older results at once | tens to hundreds of MB over cellular, and battery | rejected (D-SDK-21) |
| Browser tabs missing a condition prefetch all on a guessed Wi-Fi and charging state | parity with phones | Safari and Firefox expose no battery state, and desktop browsers no network type (MDN); a wrong guess spends cellular data | rejected (D-SDK-21) |
| Phones download all at "search more" only for the fallback, asking a designated indexer first | no first download of ~110-165 MB for a five-year mailbox; verified hits | relays see when each search and page runs; the indexer's holder sees the words | chosen once an indexer is designated (D-SDK-26; owner decisions 175, 178) |
| Hedging requests to other members' indexers | lower tail latency | the query reaches more devices | rejected: hedged only among own indexers (D-SDK-27) |
| Other members' indexers by default, with no notice | owner decision 175's literal default | silent cross-member disclosure of search intent | rejected: one notice per answering member (D-SDK-26) |

### 18.12 Decisions proposed

**D-SDK-1 (proposed).** Two roles (18.4): the sidecar role in the app or `ur daemon`, and in every app's VPN component only forwarding, which holds its own forwarding key and nothing else of sidecar. *Why:* owner decisions 4, 87, 197; tunnel budgets.

**D-SDK-2 (proposed).** One `sdk.Sidecar` with local and remote backends and 18.5's gates. *Why:* PLAN.md:28 within gobind limits.

**D-SDK-3 (proposed).** 18.6's seam, setup and mirror; app devices host, serve and map nothing before C16 (M4; D-BRIDGE-5), and then only on the device client's sdk provider, in that client's network. *Why:* Go types stay off bindings; the Opportunistic device client (sdk/device_local_provider.go:258) may reply in plaintext; the device client exists only in its own network.

**D-SDK-4 (proposed).** The sdk Api session owns the token and injects 18.7's services. *Why:* one refresh per process.

**D-SDK-5 (proposed).** 18.4's budgets are carved out of each process limit. *Why:* message pools and the soft limit are process-wide (sdk/sdk.go:554-571).

**D-SDK-6 (proposed).** The browser sidecar is phased per 18.8; its Workers are member devices, the page Worker admitted `read_only`, and the quick burner a wrapped reader. *Why:* owner decisions 15, 26, 76, 114.

**D-SDK-7 (proposed).** Cloud hosts climb 18.9's rungs against its host list. *Why:* owner decision 49; connect proxies only over SOCKS5.

**D-SDK-8 (proposed).** Adopt 18.10's gates. *Why:* 18.3's iOS headroom and 18.10's wasm sizes.

**D-SDK-9 (proposed).** Apps decide approvals, admissions, alarms and recovery vetoes through `SidecarApprovals`; control mode signs `approval` only as `device` evidence for another sidecar's request, after the person confirms at the host. *Why:* I-4, I-8; owner decisions 112, 126, 127, 149.

**D-SDK-10 (proposed).** Wakes carry only a topic class and version (18.7), from M8. *Why:* owner decision 88; §2.8 ext-8.

**D-SDK-11 (proposed).** The desktop app and extension releases adopt 18.7's credential rules before §7.4's stage 2 (M3). *Why:* I-6; owner decision 45; same-user agents read both stores.

**D-SDK-12 (proposed).** ur.io's hosted DeviceLocal runs no sidecar or bridge, and 18.3's hosted check marks it for §8.10's gate. *Why:* I-10.

**D-SDK-13 (proposed).** The forwarding role takes rules and names only from the `BridgeState` its own compile of the verified config produces and the anchored deltas after it, persists its posture (legacy, pending, enforcing), restoring enforcing state before the first packet, and signs each window client's `WindowDelegation` itself, with its forwarding key or a share's current `BridgeShareSigner` (18.6). *Why:* owner decisions 3, 85, 197; forwarding must never wait on the app, a restart plus an unsigned `has_document = false` must not reopen a LAN, and §17.9's hosts admit only delegated window clients.

**D-SDK-14 (proposed).** Transport rejections are generation-bound and map to Unenrolled with a reason; only a verified `SidecarRevoke` maps to Revoked. *Why:* a lost or expired client is not a revocation (D-CORE-8), and a stale callback must not end a new pairing.

**D-SDK-15 (proposed).** `SidecarKeyStore` returns status codes and a `SidecarSecret` struct (18.5). *Why:* gobind carries no error type, and a crossing panic exits the app.

**D-SDK-16 (proposed).** Wakes follow 18.7: a slot-local script, a separate enqueue for token holders, client acks from connect's frame ack, a deferred check while live, and per-slot sentinels that reconcile a restarted master's tokens. Token projections follow each row's revision: every change, a removal's tombstone included, raises it in Postgres; a slot-local script applies a revision only above `tokrev` and within 60 s of the TIME its writer read before the transaction; a slot whose master changed is reconciled 90 s after the pass that found it; and each pass re-applies the rows changed since the last one. *Why:* Redis Cluster refuses cross-slot transactions, a stale live marker must not drop the only wake, and masters have no replicas and restart from their last RDB dump; a post-commit SET lands in no order that a Postgres commit or row lock sets, so an older POST's SET could replace a newer token or revive a removed one until the next launch (meta review F15).

**D-SDK-17 (proposed).** An ephemeral client's polls refresh its narrow `network_client_lease` row at most once per 5 min; it is reaped only with no open connection once that lease and its newest disconnect are both over 35 min old, 30-36 min after the later, and an unload beacon closes it early by a 128-bit capability (18.8). *Why:* no resident measures an HTTPS-only host's disconnect; `auth_time` refreshes hourly over `network_client`'s ~10 indexes, so a reap keyed on it revokes connected agents on any blip; `sendBeacon` sets no Authorization header, and the token stays in the Worker.

**D-SDK-18 (proposed).** Browser keys, tokens and the Worker live in a key origin that ur.io pages frame and message by exact origin, one Worker per network under a Web Lock. *Why:* one shared origin would let any ur.io XSS take the key, and two tabs' Workers over one IndexedDB would race refreshes, commits and keychain writes.

**D-SDK-19 (proposed).** The page Worker builds the root with `-tags sidecar_http`, linking no connect package: connect-facing and engine host (`host_*.go`) files are `!sidecar_http`, and the rest, token path included, use only §5.4's root types and `SidecarApi`. *Why:* importing connect links its IP stack, putting the 40 MB goal out of reach without C17.

**D-SDK-20 (proposed).** The forwarding role is `sidecar/device`, importing connect and `sidecar/protocol/bridge` only, with the root's forwarding files, the only root files the `ios_extension` leg links, whose file and descriptor lists `make check` holds (18.10). *Why:* owner decision 197 puts the config follower and compiler in the VPN component, and only an allow-list keeps every other root init and descriptor out of the jetsam-bound tunnel.

**D-SDK-21 (proposed).** Every host that searches a repo keeps its two latest buckets synced, phones' team directory aside (D-SDK-28). Desktops and indexers keep all in the background; phones fetch it at "search more" for repos no designated indexer answers and browser tabs at "search more", both also on Wi-Fi while charging, phones in OS windows, and tabs while open only where their browser reports both conditions; ephemeral agents fetch it only at "search more"; each device may override per repo, within 18.4's caps. A condition an app or browser has not reported counts as metered and not charging. *Why:* owner decisions 154, 177 and 178; 154's per-device override covers browsers, since Safari and Firefox report neither condition and desktop browsers no network type, and ephemeral agents, whose in-memory caches would re-download all at every start; only OS windows let a backgrounded phone download tens to hundreds of MB.

**D-SDK-22 (proposed).** Apps search through `SidecarSearch` (18.5): one call streams replacing pages of hits labeled verified, confirmed, possible, near or unmatched, each naming the indexer that verified it if one did, with progress that names the bytes to fetch, any metered wait and the remote state. *Why:* gobind's limits; one implementation of masking and ranking on every host.

**D-SDK-23 (proposed).** Hosts report network and power conditions, apps through `SetConditions` and browsers through the key-origin frame, and apps grant background time through `RunBackgroundSync`; the Go core reads no platform API. *Why:* none is portable across gomobile, the C ABI and js, and the OS decides when a backgrounded app may run.

**D-SDK-24 (proposed).** The page Worker links the search engine and keeps its search cache in its own IndexedDB store, written only by the Web Lock holder; pages receive hit views only, and the quick burner searches its buckets in memory and never fetches all. *Why:* owner decision 76's one browser runtime; eviction and Safari's 7-day rule make the cache disposable by design.

**D-SDK-25 (proposed).** Search meets 18.4's warm targets and §16.10's cold contract on phones, desktops and the page Worker, each search's masks inside its working set; §22 measures them on surrogate phones (owner decision 100) and in Safari's wasm engine before M10's exit (owner decision 169), and the remote targets on surrogates from the later of M10's and M8's exits. *Why:* the research left decryption rates on phones and in Safari's wasm unmeasured; a cold download's first hit depends on where the match lies, so only its progress, arrival and completion can be bounded.

**D-SDK-26 (proposed).** Where its network designates a search indexer that may answer, none being designated by default (owner decision 177), app hosts ask it at "search more" by default. The mode is per device and network: `on` (own indexers, then other members' that §11.14 allows, each new answering member only after the app's notice), `own` or `off`, kept in §5.9's non-derived search state, never in the config repo. Keystrokes search only the phone, and a repo none answers falls back to owner decision 155's download. *Why:* owner decisions 175 and 178; the notice and the setting make a member's disclosure of team-repo queries known and reversible without changing that default.

**D-SDK-27 (proposed).** At foreground, an app host with remote search on sends Hello, with feature bit 1, to its first-choice own search indexer, which its hourly HeadCheck round counts among its own-device picks, unless its session there lives, and while in the foreground keeps that pair's §6.10 window with a Ping a minute, so no "search more" needs a new contract or Hello. It waits `Search.RemoteTimeout` (3 s unmetered, 5 s metered) before the next indexer, hedges only among own indexers, and skips a failed one for 2 min. *Why:* the contracts a search rides then open at foregrounds and window ends, not at the search unless it fails over or finds its session lost (owner decision 191), so connect's stored rows and reports keep owner decision 176's promise (owner decision 188); the first page saves 0.5-1.5 s; and no query reaches more devices than it must. The keepalive costs one small frame each way a minute while the app is in the foreground.

**D-SDK-28 (proposed).** Apps reach the team directory through `SidecarDirectory`, create private repos and announce or revoke repo announcements (owner decision 181), and decide access requests through `SidecarApprovals`. Phones fetch announcements only while the view is open, ask a designated indexer at "search more", else fetch buckets and all, and lease notices for their member's targets and their own requests' notice paths, so every decision wakes its requester; past the metered cap a view shows partial coverage it can continue. *Why:* owner decisions 170, 171 and 181; approvers and requesters in the apps need wakes, and a phone cannot follow a team's cards.

**D-SDK-29 (proposed).** Drop history in the apps is admin-only, behind the server's dry run and a typed name, and on an owner-bound repo only on its owner's consented devices. *Why:* owner decisions 126 and 173; an irreversible deletion takes a person's deliberate act.

**D-SDK-30 (proposed).** Apps list the member's devices and revoke another of them through `SidecarApprovals`' `GetDevices`, `PreviewRevokeDevice` and `RevokeDevice` (18.5), bound types under gomobile and JSON in the C ABI and js, which wrap §5.4's calls under §5.6's rules: the plan's copy before the person confirms, `SignWithPresence` wherever the plan sets `Presence`, in remote mode over the act's bytes the daemon's first call returns (§5.8), its evidence the countersignature every verifier checks (owner decisions 185, 187), `authority_pending:<proposal_id>` while an AdminSet member's revocation, its target suspended, awaits other AdminSet devices' cosigns through `Decide`, and `REVOKE_NOT_CAPABLE` on hosts that are not approval-capable, the extension's alarms-only hosts among them, whose `ur native-host` relays none of these calls. *Why:* §5.6's app path had no bound call, `Decide` answering only pending items and `Core()` being Go-only; gobind's limits; and the binding must neither bypass §5.6's approval nor give a read_only or alarms-only host a signing path (§16.6).

**D-SDK-31 (proposed).** Apps check and follow internet sends through `SidecarMail`: before Send, `CheckSend` gives each recipient domain's mode, the message's encoded bytes, the DATA cap, the expected delay and a predicted outcome; after it, `GetSendResult` and the `mail_send` event give each domain's outcome, with 18.5's copy; `GetReceiverCoverage` speaks only of receiving. *Why:* owner decision 125 keeps the DATA cap, so a person needs the size, the cap and the one domain it stops, at composition or before MAIL, and an inbound API cannot explain an outbound limit (meta review K04).

**D-SDK-32 (proposed).** Forwarding is authorized by a forwarding Delegation the sidecar signs for keys its VPN component generated and never exports, and runs on forwarding clients the sidecar mints as its `forward_only` children, which the VPN component refreshes itself; the forwarding key signs only that sidecar's `WindowDelegation`s, and the Delegation ends with the sidecar, its `DelegationRevoke` or a newer one (18.6, §7.9). *Why:* owner decision 197's self-contained forwarding keeps the device one subject in policy, `ur devices` and admissions, and reuses the Delegation's signer path, reader wraps, rows, revocation and cascade.

### 18.13 Open questions

**Q-SDK-1.** [X14] What runs the extension's sidecar? **Decided by owner 2026-11-03 (owner decision 26):** (a), a slimmed `sidecar.wasm` Worker, HTTPS-only first, and meanwhile (c), the native companion to a desktop `ur daemon`; never a hosted sidecar (18.8). *Residual:* 18.10's size spike, which decides C17 for the extension's streaming Worker only (owner decision 22); pages use the `sidecar_http` leg (D-SDK-19).

**Q-SDK-2.** Where does the sidecar run beside a network process (PLAN.md:28, :31)? **Decided by owner 2026-11-03 (owner decision 87):** (a), in the iOS app and the desktop `ur daemon`; network processes stay keyless (D-SDK-1). **Amended by owner 2026-11-09 (owner decision 197):** every app's VPN component (Apple's network extension on iOS and macOS, Android's VPN service, the Windows and Linux app services) runs the device's IP and port forwarding and nothing else of sidecar: its overlay address, port forwards into it, routes to other devices' subnets and its own advertised subnet, always on whenever the component runs, with no setting that turns it off, and self-contained, with its own forwarding key, taking rule changes directly so it never waits on the app (18.4, 18.6; D-SDK-32). Owner decision 87 holds for everything else, and on Android the sidecar role runs only while the app is open, as on iOS. *Residual:* Q-SDK-7, forwarding's budget in the iOS extension.

**Q-SDK-3.** Do phones get wake pushes? **Decided by owner 2026-11-03 (owner decision 88):** (b), content-free APNs and FCM wakes from the first app hosts (M8; 18.7). *Residual:* none.

**Q-SDK-4.** How does the ur.io quick burner run (cli/UI.md:164)? **Decided by owner 2026-11-03 (owner decision 76):** (b), an ephemeral, labeled wasm sidecar in the page (18.8; Q-CTX-2). *Residual:* none.

**Q-SDK-5.** Cross-cutting (D-REPO-2). Where does the iOS device role's code live? Even with engines in `<svc>service` packages (owner decision 104), a root-package device role links every root init and `protocol` descriptor into the iOS extension. **Closed by peer review 2026-11-04:** (b) now. The device role is the leaf package `sidecar/device`, importing only connect and a generated `sidecar/protocol/bridge` (D-SDK-20); the root never imports it, and the iOS extension links neither the root nor `protocol`. Conditions: `protocol/bridge` imports only std and protobuf (owner decision 52's test); `make check` fails the ios_extension leg if its deps include the sidecar root or `sidecar/protocol`; `make size`'s 1 MiB gate stays and passes at M4; §2.10 gains the routing-integrity row; §17.10's `sidecar.Bridge` becomes `device.Bridge`. Owner decision 197 then put the config follower and compiler in every VPN component, so the extension links `sidecar/device` with the root's forwarding files and `protocol`'s config, acl, evs and gkm descriptors under 18.10's allow-list, the root still never importing `device/`, and the size gate follows Q-SDK-7. *Residual:* none.

**Q-SDK-6.** May a phone or browser ask one of its network's indexers to search all and return verified hits, instead of downloading all and showing possible matches? **Decided by owner 2026-11-05 (owner decisions 175, 177, 178):** (c), amended: in v1 a phone's "search more" asks one of its network's designated indexers that reads the repo end to end over the sidecar subprotocol (Required mode) and gets verified hits, an owner-bound repo only on its owner's consented device, replies padded to 16 KiB steps (§11.14's remote search, with 18.4's notice and setting); a network has no indexer by default, so by default a phone downloads all and shows possible matches (owner decision 155), as it does whenever none is online (options (a), never, and (b), later and opt-in, not taken). Browser tabs, whose Workers carry no connect client, keep the download (18.17's Later). *Residual:* none; connect's byte reports are owner decision 176 (§6's Q-PROTO-4).

**Q-SDK-7.** Cross-cutting (§4.7, §22.9). What budget does forwarding get in the iOS network extension, now that owner decision 197 has it follow the config repo and compile its own rules there? *Options:* (a) the `ios_extension` leg links the root's forwarding files (18.10) and adds at most 4 MiB of executable, the signed extension's ceiling rising from 50 MiB to 54 MiB, with forwarding's Go heap at most 4 MiB steady and 8 MiB while compiling inside the tunnel's 28 MiB target, all measured on surrogates (owner decision 100); (b) keep `make size`'s 1 MiB by writing a second, minimal config follower, policy evaluator and compiler in `sidecar/device`, two implementations of security-critical rules to keep equal; (c) on iOS alone the app compiles and signs as the keyless role did, which would need owner decision 197's point 3 amended. *Recommendation:* (a): one implementation, and the extension's executable ceiling is an artifact ceiling the owner has raised by review before (sdk/build/APPLE_EXTENSION_MEMORY_BUDGET.md), while runtime memory stays inside today's targets; 18.10 and §4.7 are written to it (proposed; Q-SDK-7). *Blocks:* the `ios_extension` leg's `make size` value and §4.7's leg rule from M4, and iOS forwarding at M8. *Decider:* owner.

### 18.14 Departures from PLAN.md

- **PLAN.md:13 ("all service code goes in the root").** The forwarding role's packet side is the leaf package `sidecar/device`, which apps' VPN components link with only the root's forwarding files, as §4.15 records (Q-SDK-5, closed by peer review; D-SDK-20; owner decision 197).
- **PLAN.md:28 ("in the background ... as a web worker").** The extension's Worker follows ur.io's page Worker (M4) and its native companion (M8); Firefox's is session-scoped (Q-SDK-1).
- **PLAN.md:28 ("used directly by the apps").** Desktop apps use the `ur daemon`; iOS runs the sidecar in the app, not the tunnel, and every app's VPN component runs only forwarding (Q-SDK-2; owner decisions 87, 197).
- **PLAN.md:31 ("initial goal", abstractions "that the Sidecar struct implements").** `device.Bridge`, not the whole `Sidecar`, implements `deviceBridge` (Q-SDK-2, Q-SDK-5), and sdk exposure arrives at M8, after M4's dark seams (Q-PHASE-1).

### 18.15 Interfaces

- **Provides:** the `sdk.Sidecar` API, gates, state reasons and approval kinds, a revocation proposal's cosign included; the member's device list and revocation (`GetDevices`, `PreviewRevokeDevice`, `RevokeDevice`) with its copy; `SidecarSearch`, the search policy, conditions and windows, remote search's requester side (modes, notice, `GetIndexers`, the foreground Hello, merged states) and the key origin's search operations; `SidecarDirectory`, `CreateRepo`'s `private` and access-request approvals; the drop calls and `History`'s states; the send check and results (`CheckSend`, `GetSendResult`, `mail_send`) with their copy; `deviceBridge`, forwarding's setup (its keys, the forwarding Delegation, the forwarding client and the hand-off), its following, compile and signing in the VPN component, posture, zone and local addresses, `BridgeHost` in `DeviceLocal`, bridge status; the forwarding leg's file and descriptor lists; the hosted mark; the browser sidecar, its key origin, the poll lease, the ephemeral reap predicate and the close capability, and the native host; the wake dispatch and payload; 18.4's per-host log retention (§5.9, §7.9); 18.9's host list; the `sidecar_http` leg; edge-login signatures (§13.7).
- **Consumes:** §4 (C4, C5, C8, C14, C16, C17, `make check`'s legs, `make size`); §7.9's forwarding Delegation, §7.4's `forward_only` mark, §7.8's config-read exchange and §10.5's forwarding key holder (owner decision 197); §5 (gate, alarms, control mode, pairing, `SidecarHost`, every-leg types, `SidecarApi` and `sidecarTokenManager`, store states, §5.4's device revocation calls); §6 (the hint script's `tok` and `live`, `PollResponse`, `POST /sidecar/close`, `HeadCheckProof`'s 64 KiB); §7 (marks, P0 stages and DPoP, the ephemeral mint and its `close`, the exchange, admissions, `read_only`, the leaves rule, the log's fold and retention, recovery windows and `RecoveryVeto`, projection, the reaper); §8.5, §8.9; §9-§11; §12.9; §14-§17; §19; §20.8; §11.14's search engine and remote search, §5.9's index cache and non-derived search state; §16.11's directory; §11.7's and §11.13's drop.
- **Subprotocol messages:** `SearchRequest` (`SEARCH`, 0x1404) and `SearchReply` (`SEARCH_RESULT`, 0x1405) (§6.11, §11.14): app hosts send requests to designated indexers and take replies, as requesters only, never serving (M10).
- **API routes:** `POST /sidecar/push-token {platform: apns|fcm, token}` (Client; sets or, when empty, deletes the caller's wake token; M8).
- **Tables:** `sidecar_push_token(client_id, platform, token, rev, update_time, removed_time, slot)` (api; migration ≥926, §19's MG8; `rev`, 18.7's revision; `slot`, the hash slot of `{scp_<C>}`, indexed for 18.7's reconcile, and `update_time` for its sweep; a removal keeps the row as a tombstone without platform or token; no foreign key: each path that removes a client tombstones its row and sets `removed_time` in that transaction, and 18.7's sweep deletes the row 24 h later); `network_client_lease(client_id, seen_time, close_sha256)` (api; MG1, with the auth keys that mint the first ephemeral clients; read by the reaper; deleted with its client; 18.8); Redis `{scp_<C>}live` and `{scp_<C>}ack` (publishers), `{scp_<C>}tok` and `{scp_<C>}tokrev` (the token projection and its revision, which api, the push sender and taskworker change only through 18.7's apply script), `{tokgen_<n>}` (taskworker's 16,384 per-slot sentinels) and `{wakeq_<shard>}` (owning services, evs included, write; the push sender reads; 18.7); `{scp_<C>}hb` (api, the poll lease; 18.8).
- **Services and config:** `CheckOrigin` on connect's H1 upgrader (18.3); `https://ur.io` and the key origin `https://sidecar.ur.io` in `cors_origins` (warp/services/services.go:676) for api (auth included), evs and gkm; the key origin's loader, CSP and frame-ancestors, the page Worker, its label and `hosts/v1.json` (mmm); extension `offscreen` and optional `nativeMessaging`; native-host manifests for URnetwork's extension ids only; APNs and FCM credentials (§19).
- **App work this design assumes (out of scope; external releases, §23):** running forwarding in every VPN component (Apple's network extension on iOS and macOS, Android's VPN service, the Windows and Linux app services) whenever it runs, with no setting that turns it off, its keys and state in the stores §5.9 names, and Android's VPN service in a process of its own (owner decision 197); `GetBridgeRoutes`, a chosen RFC 1918 block included (owner decision 132), lifted from §17.3's tun exclusions (Windows: WFP permits; Linux: the complement set), and `SetBridgeLocalAddresses` from the platform's routes and DNS settings; 18.4-18.7's seams (receiver, the composer's send check and results, autofill, push, approvals, alarms, presence key, §5.8's pairing); re-minting the device client after its forwarding role's first state (18.6); for search, 18.7's OS windows and conditions, the metered prompt with its byte count, labels for possible matches, 18.4's notice and setting, the indexer list and "verified by" labels; the directory view and access-request approvals; the drop dialog and pending drops' cancel (18.5); and, as prerequisites of §7.4's stage 2 (M3), 18.7's credential rules: the desktop app release and the extension release that stop persisting `by_jwt`.
- **Assumptions about other sections:** §14 sends the extension's outbox mail as it does phones'; §6.8's hint script returns `tok` and `live` for 18.7's enqueue; §16.6 defines approval-capable hosts and the presence profiles; §5.6's `recovery_window` and §7.9's `RecoveryVeto` cover an admission by a binding the cascade restored as they do a recovery-signed authority statement, and §7.9's cascade list names each device that sealed to a binding it voids (owner decision 149); §17.10's `BridgeHost` and `BridgeStatus` live in `sidecar/device`, which D-SDK-20's tunnel may import; §5.8's control mode carries a remote-mode app's forwarding setup (18.6) to its daemon, which signs the forwarding Delegation and mints the forwarding client for that app alone; §17.4 carves the local addresses `SetBridgeLocalAddresses` passes; §7.7's ephemeral mint inserts the lease row and §7.8's responses return its `close` once, §7.10's ephemeral job applies 18.8's predicate, §6.16's poll writes only the lease, never `network_client`, and §6.18 phases `POST /sidecar/close` with it (M1); §19.7 lists `network_client_lease` in MG1; §7.9's fold bounds the log tails 18.4 keeps, and FS-17's phone holder answers a `HeadCheckProofRequest` from them; §22.7's Redis-write assertion admits the `{wakeq_}` entries evs writes (18.7); §19.4's token row defers to 18.7's steps 0, 5 and 6, and its sender tombstones a token on a vendor 410 only while the row still holds the revision it read; FS-36 kills one master and restarts one from an older dump, and expects a count only for step 2's failed XADDs, and FS-120 delays applies past later commits; each path that removes a client (§7.10) tombstones its token row in that transaction; §19.10's api step raises every row's rev by 2^32 after a Postgres restore; §22.9's Browsers row opens two tabs on one network (18.8's instance rule); §5.8's control mode carries `Search` streams, status and policy calls to the daemon (18.7) and returns untrusted hits' text to a caller that asks for it; §6.4's control contracts carry SEARCH where reach does not (D-PROTO-21); §11.14 owns remote search's eligibility, failover and merge and cites 18.4's notice; §16.11 defines the directory, its notices and their `q/` leases; §5.4 carries the new event kinds and fields and the `Directory` and remote-search settings, and §5.9 keeps 18.4's overrides, modes and notice answers in its non-derived search state; §5.4's `Devices`, `PreviewDeviceRevoke` and `RevokeDevice` carry §5.6's rules and `REVOKE_` codes, and §5.8's control mode carries a remote-mode app's revocation calls and presence evidence to its daemon, the first call returning the act's countersigned bytes under Presence (D-SDK-30), and §7.9's presence row and §6.9 define the countersignature that `SignWithPresence`'s evidence becomes (owner decisions 185, 187).

### 18.16 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `sidecar.wasm` misses its goal or starts slowly | High | High | `sidecar_http` leg from M1; spike before M4; C17 only for the extension |
| An iOS tunnel jetsam regression reaches users unmeasured, now that forwarding compiles there (owner decision 197) | High | High | `make size` from M4; surrogates (owner decision 100); the forwarding leg's file list and budget (D-SDK-20; proposed; Q-SDK-7); a compile past its bound keeps the last state and alarms |
| A compromised VPN component forwards as its sidecar and reads the config until its forwarding Delegation ends | Low | Medium | the forwarding key signs only that sidecar's delegations, and its client is `forward_only` (D-SDK-32); no mail, evs data, MLS, identity or recovery key there; `DelegationRevoke` or the sidecar's revocation (§2.10) |
| Android's VPN service shares the app's process, so a compromise there reaches the sidecar role while the app is open | Medium | High | app work runs the service in a process of its own (18.15); forwarding's keys under their own alias and files (§5.9) |
| Phone-only burner users miss mail, as wakes are throttled or dropped | High | High | owner decision 12's copy via `GetReceiverCoverage`; mail indexers (owner decision 150); 18.7's deferred check (WK2) and per-slot reconcile; token projections in revision order, swept each pass (WK5) |
| Installed apps or the extension leave admin credentials agent-readable | Medium | Critical | D-SDK-11; §7.4's stages (owner decision 45) |
| An XSS or extension in ur.io reads decrypted views while it runs | Medium | High | key origin, exact-origin messages, CSP (D-SDK-18); disclosed (§2.10) |
| A rarely opened page Worker resyncs each group it reads before showing records (KF5; stale Removes after 90 days), or finds itself revoked once a newer Worker's admitting device saw those Removes (§7.10's stale row) | Medium | Low | KF5's resync by external commit; re-enrollment through a consented device, or with self_admit off an admin's; sign-out revokes it |
| Phone users take possible matches for matches | Medium | Medium | labels; trigram-overlap ranking; confirmation on open (D-SDK-22); a designated indexer's verified hits where one is online (owner decision 178) |
| No indexer is designated, so phones download all | High (the default, owner decision 177) | Medium | owner decision 155's model; the app's indexer prompt names remote search; `ur indexer add --services search` |
| Members accept the notice without weighing it, and their team-repo words reach a team indexer's holder | Medium | Medium | own indexers first; the notice names the member, the device and the repos; per-device `own` and `off`; owner-bound repos never (D-SDK-26) |
| An indexer is offline when needed | Medium | Low | the foreground Hello; own failover; a fallback no worse than the default (D-SDK-27) |
| Remote search misses 18.4's targets on distant or congested links | Medium | Low | local buckets answer first; §22.8's netem runs; one step a reply |
| Search misses 18.4's targets on mid-range phones or in Safari's wasm | Medium | Medium | §22's gate on surrogates (owner decision 100); buckets answer first (D-SDK-25) |
| A phone's all partition crowds its storage | Low | Medium | 18.4's 256 MiB and 10% caps; 30-day eviction |
| Safari's 7-day storage cap deletes an occasional user's page Worker, keychain and token included | Medium | Low | re-enrollment through a consented device; persistent storage where granted; stale leaves removed after 90 days (18.8) |

### 18.17 Phasing

- **v0, CLI hosts (M1-M4):** §5.17's daemon; 18.8's lease, reap predicate and close capability, with `POST /sidecar/close`, for §7's first ephemeral clients (MG1, M1); 18.7's credential rules, in the desktop app and extension releases, before §7.4's stage 2 (M3); M4's dark seam, posture, zone call and id refusal in `sidecar/device`, with the forwarding leg's file and descriptor rule; 18.9's host list with C8 (M4); `make size` from M4, at Q-SDK-7's budget.
- **v0, ur.io (M4, RS1):** ur.io/recurd's `read_only` page Worker in its key origin (18.8), on the `sidecar_http` leg (import rule from M1, size measured from M2) within 18.10's gate or miss rule.
- **v1 (M6, RS2):** the team console on that Worker, with the directory's read-only views; `SignEdgeLogin` for §13's `members-device`; the directory's seams (`SidecarDirectory`, `CreateRepo`'s `private`, access-request approvals; §16.11's announce entries), in app hosts from M8; after M8, §17.9's egress spec on app devices.
- **v0, app hosts (M8, BS1):** Android and iOS local mode; desktop remote mode with §5.8's pairing; forwarding in every app's VPN component (owner decision 197): its keys, setup, forwarding Delegation and forwarding clients, its own following, compile and signing, posture and private names on app paths, hosting after C16 in the device client's network, iOS links after §22.9; Android's sidecar role only while the app is open; `SidecarApprovals` and alarms (owner decision 126), with the member's device list and revocation and, in team networks, revocation proposals' cosigns (D-SDK-30); wakes (owner decision 88), directory notices' included, and the directory view's policy; the receiver and coverage APIs and the indexer prompt; from M9, the send check and results (§14.5); the quick tools; the native companion (owner decision 26).
- **v1, M10 (owner decision 169):** 18.4's search policy and targets, `SidecarSearch`, conditions and 18.7's windows on app hosts, and remote search's requester side (modes, notice, `GetIndexers`, the foreground Hello and §6.10's keepalive), at the later of M10's and M8's exits, in team networks at the later of those and M6's (§23); the page Worker's search operations, conditions and cache; the quick burner's in-memory buckets; remote mode's search stream; with format 2 (§11.7), `Write`'s versioning argument, the drop calls, `History`'s states and `EVS_DROPPED` (owner decisions 173, 183) and the console's drop view, and the directory's cards and index with phones' directory "search more".
- **Later:** the extension's own Worker, Firefox session mode, browser streams (C4), C17 for the extension's streaming Worker if the spike needs it; browser Workers and ephemeral CLI hosts as remote-search requesters, browsers after C4.
- **Blocking:** §7.4's stage 1 blocks every host, stage 2 the first desktop sidecar beside the app or the extension (owner decision 45); the page Worker ships within the `sidecar_http` leg's gate or, at M4's entry, its miss rule (18.10); C16, device hosting; Q-SDK-7, the `ios_extension` leg's budget and iOS forwarding.
