# Fact sheet: the SDK and client apps as sidecar hosts

Researched 2026-11-03, read-only. Paths are relative to `/Users/brien/urnetwork`. "inference:" marks a conclusion no code or doc states. Where docs and code disagree, the code wins and the disagreement is noted. The message repo and `connect/MESSAGEREVIEW.md` were not used.

## 1. Summary

1. **The sdk has four binding surfaces, each with its own build gate.** One Go package ships as:
   - gomobile builds: an Android `.aar` and two Apple xcframeworks, one for the app and one for the extension.
   - a generated cgo C ABI with C++/Python/Java/C#/Rust/Ruby wrappers, used by the Windows and Linux apps.
   - hand-written `syscall/js` bindings for WASM.
   - plain Go, for embedders such as `server/proxy`.

   A new `sdk/sidecar.go` has to pass every one of these gates (`sdk/build/Makefile:23,93-170`, `sdk/cgo/README.md:3-20`, `sdk/js/Makefile:69-70`).
2. **gobind binds a short list of types.** It accepts bool, int, int8, uint8, int16, int32, int64, float32, float64, string, `[]byte`, error, and pointers to named types or named interfaces, but only from packages that are themselves being bound. It does not accept uint16/32/64, other slices, maps or func parameters (`.gomodcache/golang.org/x/mobile@v0.0.0-20260820023541-8e8303b9da6c/bind/gen.go:451-512`). The build binds only `github.com/urnetwork/sdk` (`sdk/build/Makefile:101,150`). So types from the `sidecar` package cannot reach the apps directly, and the sdk `Sidecar` must wrap everything in sdk-local types.
3. **Every native platform except Android splits the UI process from the network process.** Each pair talks over the device RPC, with `DeviceRemote` calling `DeviceLocal` over mutual-TLS (mTLS) on loopback:
   - iOS and macOS: app and packet-tunnel extension.
   - Linux: GUI and the root daemon `urnetworkd`.
   - Windows: tray app and a LocalSystem service.

   Android runs `DeviceLocal` inside the app process (`android/app/app/src/main/AndroidManifest.xml:257-277`, `DeviceManager.kt:399-412`).
4. **On iOS, the only long-running process that can reach the network is the packet-tunnel extension.** Its limits:
   - About 50 MiB per the code comment. Apple does not document the limit.
   - A 32 MiB Go soft limit and a 32 MiB device target.
   - Its signed binary is 47.7 MiB against a 50 MiB ceiling, leaving 4,690,096 bytes of headroom (`sdk/build/APPLE_EXTENSION_MEMORY_BUDGET.md:71-80`).
5. **A sidecar cannot run a second connect client under the device's client id.** The server keeps one resident per client id, and the instance must match (`server/model/network_client_resident_model.go:62-68`). The sidecar has two options:
   - Share the `DeviceLocal`'s provider client in the same process.
   - Mint a child client. A client token can do this with `SourceClientId`, and child clients are exempt from the concurrent-client limit (`server/model/network_client_model.go:361-378,502`).
6. **Subprotocols are the existing messaging seam, with two limits.**
   - What exists: `DeviceLocal.EnableSubprotocol`, `SendSubprotocolBytes` and `QuerySubprotocols`, for ids of 1024 and up. Registrations are re-attached when the client is replaced (`sdk/device_local_subprotocol.go:15-26,318-361`).
   - The control id can neither send nor receive subprotocol frames (`connect/SUBPROTOCOL.md` §8.6, `connect/subprotocol.go:997`).
   - Registering a receive listener on a reserved id (below 1024) goes through unexported connect functions (`connect/subprotocol.go:545,558`). An external `sidecar` module therefore cannot listen on a reserved id unless connect exports something.
7. **No browser context runs a `DeviceLocal` or a connect client today.**
   - The ur.io page runs the WASM `DeviceRemote` (about 75 MB) against a hosted `DeviceLocal` in `server/proxy`.
   - The extension's service worker never loads WASM. It only relays opaque device-rpc frames to `wss://api.<proxyHost>/device-rpc` (`extension/src/utils/sdk-wasm.ts:8`, `extension/src/bridge/device-rpc.ts:1-5,121-137`).
8. **connect's platform transport cannot run in a browser.** It uses gorilla websocket with a custom TLS dialer and sends `Authorization` and `X-UR-*` headers on the upgrade (`connect/net_http.go:3058-3064`, `connect/transport.go:2516-2524`), and a browser `WebSocket` cannot set headers. Under js/wasm only two things work: HTTP through `fetch`, and WebRTC through the browser (`connect/net_http_platform_js.go:12-28`, `connect/transport_p2p_webrtc_pc_js.go:17-19`).
9. **Running in an MV3 extension adds three constraints.**
   - Chrome service workers stop after 30 s idle or 5 min on one event. WebSocket traffic resets the idle timer from Chrome 116, and a native-messaging port keeps the worker alive from Chrome 105.
   - A service worker cannot start Workers. An offscreen document with reason `WORKERS` is the documented route.
   - Firefox event pages unload "after a few seconds".

   On the sdk side, the loader injects a `<script>` tag (`sdk/js/src/loader.ts:66`), which does not work in a worker. Go WASM is single-threaded.
10. **Nothing in the device routes by destination to a client, or rewrites ports.** The existing routing seams are:
    - `RouteOverride{Local,Pin}`, matched by host or subnet but with no client target.
    - `ConnectLocationId.ClientId`, which sends the whole tunnel's egress through one peer.
    - the `connect.UserNatClient` send seam.
    - `SecurityPolicy`, which can only drop, allow or flag.

    Both mobile apps also exclude RFC1918 ranges from the tunnel (`apple/app/extension/PacketTunnelProvider.swift:1797-1806`, `android/.../MainService.kt:755-758`).

## 2. Facts with citations

### 2.1 Answer (a): where the sidecar can run

| Host | Process and binding | Lifetime | Memory | Network | Notes |
|---|---|---|---|---|---|
| CLI/daemon on macOS, Linux, Windows (recURd beside a harness) | A plain Go binary from `sidecar/cli` (PLAN.md:19-21), with no sdk linked | Spawned by the harness over stdio MCP. inference: it lives as long as the harness session | Desktop-class | Raw TCP, UDP and QUIC | Must have its own client id (fact 5). inference: it cannot use `DeviceRemote` to reach the local VPN daemon, because that would mean linking sdk. Linux exposes `DeviceLocal` on 127.0.0.1:12025 with mTLS, plus `/run/urnetwork/control.sock` checked with SO_PEERCRED (`linux/README.md:20-23`). Windows uses mTLS ws plus a named pipe (`windows/README.md:49-55`). |
| macOS app | App process (`URnetworkSdk.xcframework`, `DeviceRemote`) and the tunnel. The tunnel is an app extension in App Store builds and a system extension (`packet-tunnel-provider-systemextension`) in Developer ID builds (`apple/app/extension/extension-macOS-sysext.entitlements:23`) | The tunnel runs while the VPN is up. The launch helper only reopens the app at login (`apple/app/URnetworkLaunchHelper/main.swift`) | Device target 128/256 MiB, process budget 384/768 MiB, by host-RAM tier (`apple/app/extension/TunnelMemoryBounds.swift:138-145`) | Full | — |
| iOS app | App process (`DeviceRemote`) and the packet tunnel (`URnetworkExtensionSdk`, `DeviceLocal`) | inference: the app is suspended in the background. The tunnel lives while the VPN is connected | Tunnel: about 50 MiB ("the memory limit in the PacketTunnelProvider is 50mib on iOS", `PacketTunnelProvider.swift:375-376`). Apple's DTS staff say the limit is not documented ([forum 73148](https://developer.apple.com/forums/thread/73148?page=2), [106377](https://developer.apple.com/forums/thread/106377)). Go soft limit 32 MiB and device target 32 MiB (`TunnelMemoryBounds.swift:139,143`) | The tunnel has full access | The extension binding drops the view controllers (`sdk/view_controller_extension.go:1-29`) |
| Android app | One process. `MainService` is a VpnService foreground service (`foregroundServiceType="systemExempted"`) with no `android:process` attribute (`AndroidManifest.xml:257-277`) | While the VPN or app is up. If the sidecar runs on its own after the VPN stops, a `dataSync` foreground service is capped at 6 h per 24 h on Android 15 ([Android FGS timeout](https://developer.android.com/develop/background-work/services/fgs/timeout)) | Process limit is min(¾·memoryClass, 64 MiB). Device target is min(64 MiB, that limit) (`MainApplication.kt:109-113,1118-1119`, `DeviceManager.kt:93-103`) | Full | Can share the Go runtime and the provider client |
| Linux and Windows apps | GUI (unprivileged) and the daemon or service (root or LocalSystem), both through the cgo C ABI and C++ wrapper | The daemon is always on (systemd `Type=notify` / Windows service) | Same 8 GiB host bar as macOS (`TunnelMemoryBounds.swift:147-148`) | Full | — |
| Browser extension | Chrome: MV3 service worker. Firefox: event page (`extension/manifest.config.ts:35-43`) | Short-lived (see §2.9) | inference: the WASM heap only grows | HTTP through fetch, WebSocket, and WebRTC through the browser. No raw TCP or UDP | No Go runs in the background today |
| ur.io page (`mmm/ur.io/react`) | WASM `DeviceRemote` through the extension transport (`src/app/device/wasmLoader.js:28-46`) | Tab lifetime | — | fetch and WebSocket | Controls a hosted device only |
| Hosted, in `server` | `server/proxy` builds `sdk.NewPlatformDeviceLocal` (`server/proxy/proxy_device.go:1268`). The server already imports the sdk (`server/go.mod:51,219`) | Idle-reaped after 90 min by default and re-created when its egress dies (`sdk/js/PLAN.md:81-83`) | Server-class | Full | `AllowProvider=false` (`sdk/device_local.go:1588`), so it has no provider client and no subprotocols (`sdk/README.md:66`) |
| Headless cloud agent | The CLI inside the agent VM | Session or VM lifetime | VM | Claude Code cloud: Ubuntu 24.04 x86_64. All outbound traffic goes through an HTTP/HTTPS security proxy. Access level is None, Trusted (an allowlist, the default), Full or Custom ([cloud environments](https://code.claude.com/docs/en/cloud-environments)). Codex cloud: internet is off by default during the agent phase, and when on it can be limited by allowlist and by HTTP method ([Codex internet access](https://learn.chatgpt.com/docs/cloud/internet-access)) | connect dials only through SOCKS5 proxies (`connect/net.go:333-363`). No platform or API dial uses `ProxyFromEnvironment`; the only use is the diagnostic `connect/transfer_contract_work_capture.go:256` |

### 2.2 How the sdk is bound today

- **Android.** `gomobile bind -target android/arm64,android/arm,android/amd64 -androidapi 24 -tags sdk_mobile_bind -javapkg com.bringyour ... github.com/urnetwork/sdk` (`sdk/build/Makefile:93-101`). Afterwards, `go run ./cmd/mobileexports` fails the build on any `// skipped` declaration it does not allow (`Makefile:118`, `build/cmd/mobileexports/main.go:1-3,186-235`).
- **Apple.** Two bindings for ios/arm64, iossimulator/arm64, macos/arm64 and macos/amd64 at iOS 16.0: a full one, and one tagged `sdk_mobile_bind,ios_extension`. The build sets `GOFIPS140=off` and then runs `check_apple_size.sh` (`Makefile:129-170`).
- **`//gomobile:noexport` does nothing.** The directive is not in the pinned x/mobile source; grepping `.gomodcache/golang.org/x/mobile@v0.0.0-20260820023541-8e8303b9da6c` finds no match. Members are actually excluded in one of two ways. Either their type is unsupported, so gobind emits `// skipped ...` (`bind/genjava.go:294-325`) and `mobileexports` must allow it. Or a build tag removes them, for example `//go:build !sdk_mobile_bind` on `sdk/proxy_device.go:1` and `sdk/subprotocol_rpc_remote.go:1`.
- **C ABI.** Generated by `sdk/cgo/gen/gen.go`:
  - Behavioral objects cross as `uint64` handles; data structs, slices and maps cross as JSON (`gen.go:12-21`).
  - `[]byte` crosses as pointer plus length, and callbacks as a function pointer plus `user_data`.
  - Each new behavioral type must be added to `behavioralTypes` (`gen.go:48+`).
  - Callbacks fire on arbitrary threads (`sdk/cgo/README.md:23-45`, "abi contract").
  - Any change to the header means regenerating the five language packages (`sdk/cgo/README.md`, "regenerating").
- **JS.** A separate module, `github.com/urnetwork/sdk/js`, with hand-written wrappers per type (`sdk/js/main.go`, for example `jsDevice` and `jsProxyDevice`) and TypeScript types generated by `gen_types.go`. The WASM is built unstripped with `CGO_ENABLED=0 GOOS=js GOARCH=wasm go build -ldflags "-X ...Version"` (`sdk/js/Makefile:69-70`). The artifact is 74,965,628 bytes (`sdk/js/wasm/sdk.wasm`, built 2026-10-31). The loader comment says "~40 MB" (`loader.ts:34`); the artifact is the correct figure.
- **Modules.** Four modules each `replace` connect, `pion/sctp`, glog, goidenticons and gvisor with sibling paths: `sdk/go.mod`, `sdk/build/go.mod:104-114`, `sdk/js/go.mod:103-113` and `sdk/cgo/go.mod:103-113`. `sdk/build/go.mod:98` pins protobuf v1.36.12 for method pruning; the root module uses v1.36.11 (`sdk/go.mod:22`). connect replaces glog, `./sctp` and gvisor (`connect/go.mod:98-102`).

### 2.3 gomobile type and naming rules

- **Supported types** are listed above (`bind/gen.go:480-512`). A signature with any unsupported parameter or result is skipped whole (`gen.go:460-479`). A pointer or interface is accepted only when its package is in `AllPkg` (`validPkg`, `gen.go:451-458`).
- **Results.** Zero, one or two results, and if two, the second must be `error`. "Exceptions and panics are not yet supported": a panic crossing the boundary exits the program. Byte slices "are passed by reference, and support mutation". Proxy objects can form reference cycles that leak ([gobind docs](https://pkg.go.dev/golang.org/x/mobile/cmd/gobind)).
- **sdk conventions:**
  - Structs are exported through pointers. `Id` is `*Id` and carries `IdStr` for equals/hashCode (`sdk/sdk.go:31-43,739-743`).
  - Lists are concrete types built on the generic `exportedList[T]` (`gomobile.go:10-71`; `StringList` at `:73`) because "arrays of structs are not exportable".
  - `*Time` crosses as Unix milliseconds (`gomobile.go:497-556`).
  - Exported names use Get*/Set* (`sdk.go:43`).
  - A map crosses one entry at a time (`device_local_subprotocol.go:305-307`).
- **Generics.** They can be used internally, but the bound surface uses named instantiations, for example `type AuthNetworkClientCallback connect.ApiCallback[*AuthNetworkClientResult]` (`sdk/api.go:950`).
- **Aliases.** Do not use an alias of a basic type for a const, a struct field or an interface-method type ([golang/go#71827](https://github.com/golang/go/issues/71827)). This is enforced by `build/cmd/mobileexports/type_alias_test.go:20-60`.
- **Name collisions.** Avoid names that clash with NSObject; `DeviceDescription` is used instead of `Description` (`sdk/api.go:955-958`).
- **`context.Context`.** It is unsupported. Go-only variants whose names contain `SyncWithContext` are allowed automatically (`mobileexports/main.go:153`); any other variant must be added to the allowlist (`main.go:17-100`).
- **Size gate.** Mobile bindings must not link `net/rpc`, `html/template` or `text/template`. They also must not call `reflect` `Method`/`MethodByName` with a name the linker can't read, because that turns pruning off and costs about 7 MiB (`sdk/build/mobile_method_pruning_test.go:12-60`, `APPLE_EXTENSION_MEMORY_BUDGET.md:87-112`). `check_apple_size.sh` fails any artifact that has lost pruning.
  - Checked: the non-test code of the MCP go-sdk v1.7.0 and its jsonschema-go and uritemplate dependencies imports none of these (grep of `.gomodcache`).

### 2.4 Listener, callback and Sub patterns

- `type Sub interface{ Close() }`, created with `newSub(func())` (`sdk/sub.go:3-19`). Every listener is registered with `AddXListener(listener) Sub` (`sdk/device.go:541+`).
- Listeners live in `connect.CallbackList[T]` and are each called through `connect.HandleError` (`device_local_subprotocol.go:135-148`). A listener called inline "must not block", and it receives its own copy of the bytes (`:28-32`).
- Async API calls take the form `Api.X(args, XCallback)` and deliver exactly one terminal result. A panic becomes an error (`sdk/api.go:92-132`; `trace.go:12-60` holds the recover wrappers). The README's `errors.go` does not exist in the sdk root; `trace.go` does this job.
- **Browser.** `BrowserStateOnly` exists because "Browser JavaScript callbacks cannot synchronously wait for a websocket response". Getters read a cache and mutations are queued (`sdk/device_rpc.go:90-97`). Go's docs say a blocking `js.FuncOf` callback "will cause an immediate deadlock" with fetch, and that `syscall/js` "is EXPERIMENTAL" ([syscall/js](https://pkg.go.dev/syscall/js)).

### 2.5 The view-controller pattern

- `ViewController{Close, Start, Stop}`. `ViewControllerManager` is embedded in `DeviceLocal` and `DeviceRemote` and provides `OpenXViewController()` and `CloseViewController` (`sdk/view_controller.go:11-120`).
- A controller holds a ctx and cancel, a `stateLock`, `CallbackList`s and a `Device` (example: `feedback_view_controller.go:28-60`).
- Constructors that work from an Api alone (`NewXViewControllerWithApi(ctx, api)`) are Go/JS only (`mobileexports/main.go:31-51`).
- The `ios_extension` build drops the controllers (`view_controller_extension.go`). This build split removed 2.729 MiB from the archive (`APPLE_EXTENSION_MEMORY_BUDGET.md:124-126`).

### 2.6 Device abstractions a Sidecar could implement or attach to

1. **Provider client: the device's identity on the network.** Built by `connect.NewClient(providerCtx, clientId, clientOob, clientSettings)` with `ClientAuth{ByJwt, InstanceId, AppVersion}` (`sdk/device_local_provider.go:293-306`). Subprotocols "follow the device's own client" (`device_local.go:2004-2007`). The accessor `providerClientSnapshot()` is unexported (`device_local.go:3006`).
2. **Device subprotocol API.** `EnableSubprotocol(int32, SubprotocolListener) (Sub, error)`, `DisableSubprotocol`, `EnabledSubprotocols() *IntList`, `SendSubprotocolBytes(int32, *Id, []byte) bool`, `QuerySubprotocols(*Id, int64, SubprotocolsQueryCallback)`, `SubprotocolStats()` (`device_local_subprotocol.go:318-356`). Ids below 1024 are refused (`:85-93`).
3. **Subprotocol over device RPC** (Go/JS only): `DeviceRemote.OpenSubprotocolContext(ctx, id) (*RemoteSubprotocol, error)` with `Receive`, `Send` and `Query`. It polls every 20 ms (`subprotocol_rpc_remote.go:30-142`). Limits are 65,535 bytes per message, 64 queued messages and 1 MiB per subscription (`subprotocol_rpc.go:12-15`). It is served by `DeviceLocalRpc.Subprotocol` (`device_rpc_methods.go:224`).
4. **Device RPC.** Uses the net/rpc protocol through the sdk's own client and server, with gob. Only methods listed in the table are served (`device_rpc.go:26-50`, `device_rpc_methods.go:1-15`). The default address is 127.0.0.1:12025 (`device_rpc.go:174`). TLS is configured with `SetRpcServer(serverPem, clientCertPem, hostPort)` (`device_local.go:6128`) and `GenerateDeviceRpcKeyMaterial()` (`device_rpc_transport.go:651`).
5. **Sockets.** `Device` has `Dial`, `DialContext` and `DialTls`, all outbound. "Server sockets, listeners ... are future work" (`sdk/SOCKET.md:7,27-40`).
6. **Userspace stack.** `connect.CreateTun(ctx, *TunSettings) (*Tun, error)` with `ListenTCP`, `ListenUDP`, `DialContext`, `Read` and `Write` over gVisor (`connect/tun.go:1-6,855-863,1335-1389`).
7. **Route overrides.** `BlockActionOverride{OverrideId, Hosts, AppIds, BlockOverride, RouteOverride{Local, Pin}}`, where a host is a name, wildcard, IP or subnet (`sdk/device.go:199-233`, `connect/ip_block_action.go:33-66`). Overrides are converted in `connectBlockActionOverrides`, which forces Local=false on hosted devices (`device_local.go:6856-6888`), and persisted as `.block_action_overrides` (`local_state.go:569-583`).
8. **Peer egress.** `ConnectLocationId.ClientId` ("a direct connection to another device", `sdk/sdk.go:1076-1090`) and `ProviderSpec.ClientId` (`api.go:1395-1400`).
9. **Packet send seam.** `SendPacket` reads the atomic `deviceLocalSendRoute{upgradeMux, remoteUserNatClient, routeLocal, provider}` (`device_local.go:5598-5741`). `connect.UserNatClient` is `SendPacket/Close/Shuffle/SecurityPolicyStats/SetLocalSecurityBypass` (`connect/ip.go:199-209`).
10. **Packet policy.** `SetClientSecurityPolicyGenerator` and `SetProviderSecurityPolicyGenerator`, Go-only (`device_local.go:2590-2607`), over `connect.SecurityPolicy.InspectEgress/InspectIngress(provideMode, *IpPath, payload)`. The only results are Drop, Allow and Incident, so it cannot rewrite (`connect/ip_security.go:34-61`).
11. **TUN addresses.**
    - IPv4 is a random 10.x.y.h/24 because `UseExperimentalTunnelAddress` defaults to true (`device_local.go:441-444,1850-1861,2229-2235`).
    - IPv6 is a random /64 inside `fd00:7572:6e65::/48` (`tunnel_address_ipv6.go:22-60`).
    - Neither address is stable per client.
    - Apple excludes 10/8, 172.16/12 and 192.168/16 from the tunnel (`PacketTunnelProvider.swift:1802-1806`), and on IPv6 it excludes link-local, ULA, multicast and loopback (`:1809-1822`, `TunnelIpv6Routes.swift`). Android excludes the same RFC1918 ranges (`MainService.kt:756-758`).
12. **Peers.** `NetworkPeer{ClientId, ProvideEnabled, Principal, Roles, DeviceSpec, DeviceName}` (`sdk/device.go:435-447`).
13. **Identity key.** `connect.ClientKeyManager` holds a long-lived Ed25519 key whose private half "never leaves" the process. Its public half is published, and anyone can read it from `/key/<client_id>` without authentication (`connect/transfer_key.go:16-30`, `connect/api.go:540-560`). The seed is persisted as `DeviceLocalKeyMaterial.clientKeySeed` (`sdk/device_local_key_material.go:11-38`).

### 2.7 Authentication and persistence

- **LocalState.** Lives in `<storage>/.by`, with files at mode 0600 (`sdk/local_state.go:22,201-205`). Auth is one envelope, `.auth_state`, holding `{by_jwt` (the network/admin credential), `by_client_jwt` (the client credential) and `instance_id}` (`local_state_auth.go:15-37`).
- **JWT claims.** The client reads `client_id` and `network_id` without verifying them (`device_local.go:6211-6225`, `device_local_key_material.go:149-167`).
- **Token refresh.** The sdk `Api` owns the bearer token and its refresh schedule, for apps and headless users alike (`device_token_manager.go:20-27`). Refresh calls GET `/auth/refresh` (`api.go:3672`). connect has no refresh call. `connect.BringYourApi` offers AuthNetworkClient, AuthCodeLogin, GetClientKey and FindProviders2 (`connect/api.go:20-601`).
- **Key material.** A plain JSON file, `.device_local_key_material`, scoped to its network. It is not stored in the Keychain (`local_state_key_material.go:24-60`, `device_local_key_material.go:11-22`). It is saved explicitly with `DeviceLocal.SaveKeyMaterial()` (`device_local_key_save.go:16-82`). The iOS tunnel saves it from its own process (`apple/app/extension/TunnelDeviceKeyPersistence.swift:25-36`).
- **Precedent for a secure store implemented by the app.** `BittensorLocalKeyStore` (`AddKey/KeyPhrase/KeyAddress/DeleteKey/ReadNote/WriteNote`). Its comment says it is backed by the Keychain on Apple and "readable only by this app, not its extensions", and that each method returns one value "since that is what the c abi carries" (`sdk/bittensor_local_key_flow.go:188-208`). Windows stores the equivalent as a per-user file protected with DPAPI (`windows/README.md`, payout key paragraph).
- **Apple storage split.**
  - The app and the extension each build a NetworkSpaceManager on their own `.documentDirectory` (`DeviceManager.swift:1294-1304`, `PacketTunnelProvider.swift:576-580`).
  - "the extension seeds from its own local state" (`PacketTunnelProvider.swift:666-683`).
  - The network space JSON, the per-session RPC PEMs and `rpc_listen_hostport` reach the extension through `providerConfiguration` (`:481-517`).
  - Both targets share the app group `group.network.ur` and the keychain group `network.ur.tunnel-credentials`. Only the app has `network.ur.bittensor-key` (`extension/extension.entitlements:7,23`, `network/network.entitlements:9,33-34`).
- **Extension storage.** `by_jwt` lives in `chrome.storage.local` (`extension/src/background/index.ts:169`).
- **Child clients.** The server says "a client token creates only children of its own client", and a top-level client needs the network credential. Only top-level clients without provide intent count against the concurrent limit (`server/model/network_client_model.go:361-378,495-503`). The sdk args are `ClientId`, `SourceClientId`, `Roles`, `Principal`, `ProvideIntent` (`sdk/api.go:952-990`).
- **Residents.** There is one resident per client, and a lookup succeeds only when the instance id matches (`server/model/network_client_resident_model.go:62-68`). inference: two processes on one client id would keep replacing each other's resident.

### 2.8 Memory and size budgets

| Item | Value | Source |
|---|---|---|
| iOS tunnel jetsam | About 50 MiB, not documented by Apple | `PacketTunnelProvider.swift:375-376`; Apple forum threads in §2.1 |
| iOS Go soft limit and device target | 32 MiB / 32 MiB | `TunnelMemoryBounds.swift:139,143`. The budget doc's 20 MiB "Per-DeviceLocal target" (`APPLE_EXTENSION_MEMORY_BUDGET.md:16`) is older; the code value is current |
| Measured iOS footprint | 20.9 MiB `phys_footprint` peak (2026-08-15) | `APPLE_EXTENSION_MEMORY_BUDGET.md:11-16` |
| Signed iOS extension binary | 47,738,704 bytes against a 52,428,800-byte ceiling | `APPLE_EXTENSION_MEMORY_BUDGET.md:71-80`, `check_apple_size.sh:9` |
| iOS SDK archives | Full: 84,756,160 bytes against a 96 MiB ceiling. Extension: 78,977,376 bytes against 92 MiB | same, and `check_apple_size.sh:7-8` |
| Process-wide settings | `SetMemoryLimit` sizes connect's global message pools and `debug.SetMemoryLimit` for the whole process (`sdk/sdk.go:554-571`). GC percent is 25 on Android and iOS (`sdk.go:63,72-79`) | — |
| Android | Process min(¾·memoryClass, 64 MiB); device target up to 64 MiB | `MainApplication.kt:109-113`, `DeviceManager.kt:93-103` |
| FIPS | Off in the extension. Turning it on could add a 32 MiB scratch area | `APPLE_EXTENSION_MEMORY_BUDGET.md:128-133` |

### 2.9 Browser and extension

- **Architecture as built (2026-07-10).** The browser `DeviceRemote` connects directly to `wss://<proxyHost>/device-rpc?proxy=<signed proxy id>`, served next to the hosted `DeviceLocal` in `server/proxy` (`sdk/js/PLAN.md:3-33,58-67`). ur.io uses `createExtensionDeviceRemote({apiUrl, platformUrl, byJwt, instanceId, transport})` (`mmm/ur.io/react/src/app/device/wasmLoader.js:28-46`).
- **The extension as a relay.** It accepts Port `urnetwork-device-rpc-v1` from allowed origins and opens the WebSocket itself. The URL and credential stay inside the extension. It sends a keepalive every 20 s, accepts frames up to 3 MiB, and allows 8 connections per port (`extension/src/bridge/device-rpc.ts:16-18,121-137,164-386`, `bridge/protocol.ts:26-60`).
- **Where the WASM loads.** Only the popup loads it, for location grouping and the license list. "The service worker never loads it" (`extension/src/utils/sdk-wasm.ts:3-11`).
- **Manifest.**
  - MV3 with `minimum_chrome_version: "116"` ("Device RPC lives in the extension service worker", `manifest.config.ts:15-18`). Firefox needs at least 128 (`:114`).
  - Permissions: proxy, storage, alarms, tabs, identity (`:44`).
  - Chrome host permissions cover only `api.bringyour.com` and `api-v4.bringyour.com` (`:90-92`).
  - CSP adds `'wasm-unsafe-eval'` (`:97-99`). Chrome says the extension-pages policy "applies to page and worker contexts" ([CSP](https://developer.chrome.com/docs/extensions/reference/manifest/content-security-policy)).
  - Firefox builds turn the background into scripts (`extension/README.md:116`).
  - The extension uses no offscreen document, Worker, `connectNative` or IndexedDB (grep of `src`).
- **Chrome service-worker lifecycle** ([lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle), undated):
  - The worker stops after 30 s idle, after 5 min on one event, or when a fetch takes more than 30 s.
  - WebSocket traffic resets the timer from Chrome 116. `connectNative` keeps the worker alive from 105.
  - Messages from an offscreen document reset the timer from 109.
- **Offscreen documents** ([offscreen](https://developer.chrome.com/docs/extensions/reference/api/offscreen)): the reason `WORKERS` "needs to spawn workers". An extension may have only one open at a time, and only the `runtime` API is available inside it. Only `AUDIO_PLAYBACK` has a lifetime limit. Available from Chrome 109.
- **Workers from a service worker** are not available. [w3c/ServiceWorker#1529](https://github.com/w3c/ServiceWorker/issues/1529), "allow service workers to created nested dedicated workers", is still open ([2025-02 comment](https://lists.w3.org/Archives/Public/public-webapps-github/2025Feb/0117.html)). The Chromium team added `WORKERS` "to spawn a worker from an offscreen document" ([chromium-extensions, 2023-03-08](https://groups.google.com/a/chromium.org/g/chromium-extensions/c/K6ddzhaWX0I)).
- **Firefox.** It does not support `background.service_worker`; MV3 background scripts run as event pages with a `window` and the DOM. They "unload after a few seconds of inactivity". Message ports "cannot prevent an event page from shutting down", and DOM timers stop when the page idles ([manifest background](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background), [background scripts](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Background_scripts)).
- **Storage.** `chrome.storage.local` holds 10 MB without `unlimitedStorage`; `storage.session` holds 10 MB in memory; service workers cannot use `localStorage` ([storage](https://developer.chrome.com/docs/extensions/reference/api/storage)).
- **Permission changes.** An update adding a warning permission disables the extension "until the user accepts" ([permission warnings](https://developer.chrome.com/docs/extensions/develop/concepts/permission-warnings)).
- **Native messaging.** Length-prefixed JSON; host-to-extension messages at most 1 MB, extension-to-host at most 64 MiB; one host process per `connectNative` port; host manifests per user or system-wide on Windows, macOS and Linux ([native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)).
- **Go WASM.**
  - `GOOS=js` uses `wasm_exec.js`. `GOOS=wasip1` arrived in Go 1.21, and net/http becomes fetch ([Go wiki](https://go.dev/wiki/WebAssembly)).
  - Go 1.24 added `go:wasmexport` and wasip1 `-buildmode=c-shared` reactors ([Go 1.24](https://go.dev/doc/go1.24)).
  - js/wasm has no threads and no preemption ([runtime/lock_js.go](https://go.googlesource.com/go/+/0941fc3/src/runtime/lock_js.go), [golang/go#71134](https://github.com/golang/go/issues/71134), [#28631](https://golang.org/issue/28631)).
  - `WebAssembly.Memory` documents only `grow()` ([MDN](https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/JavaScript_interface/Memory)). inference: the heap never shrinks.
- **The sdk loader in a browser** appends a `<script>` element for `wasm_exec.js` (`sdk/js/src/loader.ts:64-72`), which needs a `document`.
- **connect under js/wasm.**
  - connect never imports `syscall/js` (grep).
  - Each strategy request is a single fetch (`net_http_platform_js.go:12-28,74-95`), and `NewAccountHost` already runs the API from WASM without a device (`sdk/js/account_host.go:13-24`).
  - The platform transport uses gorilla websocket (`net_http.go:3058-3064`, `ClientStrategy.WsDialContext` at `:2223`), and its upgrade sends `Authorization: Bearer`, `X-UR-AppVersion`, `X-UR-InstanceId` and `X-UR-TransportVersion` (`transport.go:2516-2524`).
  - A browser `WebSocket` "cannot set request headers" (`sdk/js/PLAN.md:72-74`).
  - The sdk's own browser WebSocket adapter exists only for device RPC (`sdk/device_rpc_platform_js.go:20-95`, `device_rpc_extension_js.go:18-72`).

### 2.10 Answer (b): the sdk integration seam, as the code stands

- **Dependency direction fits.** server already imports sdk (`server/go.mod:51,219`), so sdk → sidecar → connect has no cycle while sidecar imports neither (PLAN.md:7).
- **Three ways to attach.** inference: options, not decisions.
  1. **In the same process as a `DeviceLocal`:** the Android app, the Apple tunnel, the Linux and Windows daemons. This reuses the provider client, with the same attach-and-re-attach pattern subprotocols use (`device_local_subprotocol.go:95-110,358-361`). It needs a new hook in the sdk, because `providerClientSnapshot` is unexported.
  2. **Standalone with its own child client:** the iOS app process, desktop GUIs, the CLI, the cloud. It mints the client with `AuthNetworkClient{SourceClientId: deviceClientId}` (§2.7).
  3. **Remote, in the style of `DeviceRemote`:** new methods in `DeviceLocalRpc` plus table entries (`device_rpc_methods.go:1-15`) and a version check (`RpcVersion`, `device_rpc.go:113-119`). This matches how every split platform already works, but the mobile bindings exclude the existing remote-subprotocol type (`subprotocol_rpc_remote.go:1`).
- **Services the sdk would supply to sidecar core**, because connect lacks them: the JWT and its refresh (sdk `Api`), a persistent directory (LocalState `.by`), a secure secret store implemented by the app (the `BittensorLocalKeyStore` pattern), and logging (`connect.Logger`).
- **How the device would consume sidecar rules (bridge and port forward).** Candidates are a new `RouteOverride` target, or a wrapper around `connect.UserNatClient` in `deviceLocalSendRoute`. Server-to-client rule pushes must come from a peer client and not from ControlId (§1 fact 6).

## 3. Constraints the design must respect

1. **Bound API types.** The bound sdk API may use only gobind types (§2.3). Use int32/int64 for ids and counts, because uint16 (as in `connect.SubprotocolId`) is unsupported. Use `*Id` and `*Time`, wrapper lists, and listener interfaces returning `Sub`. No maps, no func parameters, no contexts, no generics, no values from the `sidecar` package.
2. **Every new exported symbol needs four things:** an allowlist entry in `mobileexports` or a clean bind, a classification in cgo `behavioralTypes` (or valid JSON), hand-written JS wrappers with TypeScript types, and a regenerated C header and language packages.
3. **What the sdk may import from sidecar.** Only sidecar core packages, never `sidecar/mcp` or `sidecar/cli`. None of it may link `net/rpc`, `html/template` or `text/template`, or call reflect method lookup with a dynamic name. protobuf must stay at v1.36.12 or below where `sdk/build` resolves it.
4. **iOS extension budget.** Anything that runs in the iOS extension shares the ~50 MiB jetsam limit, the 32 MiB Go soft limit and the 4.69 MB binary headroom. App-only code must be tagged `!ios_extension`.
5. **Pools and heap.** connect's message pools and the soft limit are process-wide (`sdk.go:554-571`), so storage and git code must stream instead of buffering whole files or packs.
6. **One connect client per client id.** The sidecar either shares the device's provider client or owns a child client id (§2.7).
7. **Subprotocol ids.** Sidecar subprotocols must use ids ≥1024 through the existing API, or connect must export reserved-id registration. Server-originated events cannot come from ControlId.
8. **The browser cannot run connect's platform transport** without a new WebSocket transport plus auth that does not rely on headers. API calls through fetch do work.
9. **Extension background code must survive termination** at any moment (30 s idle in Chrome, seconds in Firefox) and rebuild from storage. It cannot spawn Workers from the service worker, and it cannot use the sdk loader as written.
10. **JS-facing methods must be async.** Nothing may block inside `js.FuncOf` (§2.4).
11. **Keys and processes on Apple.** Keys used by the app process cannot rely on the extension's `.device_local_key_material` (separate containers). The shared keychain group and the app group are the only places both processes can see.
12. **Overlay addresses for the bridge must reach the tunnel.** RFC1918 and ULA are excluded on the mobile tunnels today (§2.6 item 11).

## 4. Reusable pieces

- **Subprotocols:** `DeviceLocal.EnableSubprotocol / DisableSubprotocol / EnabledSubprotocols / SendSubprotocolBytes / QuerySubprotocols / SubprotocolStats`, `SubprotocolListener`, `SubprotocolsQueryCallback`, `SubprotocolReservedLimit` (`sdk/device_local_subprotocol.go`). In connect: `Client.AddSubprotocolRawCallback`, `RegisterSubprotocol[T]`, `SendSubprotocol[T]`, `SendSubprotocolBytes`, `QuerySubprotocols`, `ProtoCodec[T]`, `RetainSubprotocolBytes` (`connect/subprotocol.go:540-1000`).
- **Remote subprotocol:** `DeviceRemote.OpenSubprotocolContext` and `RemoteSubprotocol.Receive/Send/Query/Close` (Go/JS).
- **Gomobile surface primitives:** `exportedList[T]`, the `XList` wrappers, `Id` (`NewId`, `ParseId`), `Time`, `Sub`/`newSub` (`sdk/gomobile.go`, `sdk/sub.go`). Panic-safe wrappers: `trace`, `traceWithReturnError` (`sdk/trace.go`).
- **Callbacks:** `connect.CallbackList[T]`, `connect.HandleError`, `connect.ApiCallback[R]` (`connect/net_http.go:3310`).
- **API:** `connect.BringYourApi` (`AuthNetworkClientSyncWithCtx`, `GetClientKey`, `AuthCodeLogin`) and `connect.ClientStrategy`, which works under js/wasm. In the sdk: `Api.AuthNetworkClient`, `RefreshJwt`, `AddJwtRefreshListener`, `AddAuthLogoutListener`.
- **Identity:** `connect.ClientKeyManager` (`Seed/PublicKey/Sign`), `/key/<client_id>`, `DeviceLocalKeyMaterial`, `LocalState.LoadDeviceLocalKeyMaterial`, `DeviceLocal.SaveKeyMaterial`.
- **Device RPC:** `NewDeviceRemoteWithDefaults`, `DeviceLocal.SetRpcServer`, `GenerateDeviceRpcKeyMaterial`, `NewExtensionDeviceRemote(networkSpace, byJwt, instanceId, transport js.Value)` (`sdk/device_rpc_extension_js.go:46-72`), `NewPlatformDeviceRemote` (`sdk/device_rpc.go:480-508`).
- **Networking:** `Device.DialContext/DialTls`, `connect.CreateTun` plus `Tun.ListenTCP/ListenUDP`, `connect.ProxySettings` (SOCKS5).
- **Routing and policy:** `BlockActionOverride` and `RouteOverride` (sdk and connect), `connect.UserNatClient`, `connect.SecurityPolicy`, `DeviceLocal.SetClientSecurityPolicyGenerator` and `SetProviderSecurityPolicyGenerator`.
- **Secure store pattern:** `BittensorLocalKeyStore` (an interface the app implements).
- **Extension:** `DeviceRpcBridgeService` and the bridge protocol (`extension/src/bridge/*`), `chromeStorageAdapter`.
- **MCP:** `github.com/modelcontextprotocol/go-sdk` v1.7.0, already used by `server/mcp` (`server/go.mod:30`).

## 5. Gaps, risks and surprises

1. The iOS tunnel has 4.69 MB of binary headroom and about 50 MiB of runtime memory. An MLS library, a git implementation and protobufs in the extension could break the ceiling. Running only in the app means no background.
2. Burner-email receive on iOS needs something reachable. inference: a local SMTP server (PLAN.md:102-104) runs only while the app is foreground or the VPN is on, so mobile needs edge-side queueing or a hosted sidecar.
3. No connect client can run in a browser today (§2.9). A sidecar worker in the extension needs three things: a new connect transport over browser `WebSocket`, an auth change on the server, and a loader that works in a worker.
4. Chrome cannot start a Worker from the service worker. Firefox's background is a DOM event page that unloads within seconds. inference: the two browsers need different background designs (Firefox support for `chrome.offscreen` was not checked).
5. sdk.wasm is about 75 MB and unstripped. inference: start-up and memory cost each time the extension is woken.
6. `//gomobile:noexport` does nothing in the pinned x/mobile. It only documents intent.
7. There is no per-destination client routing or port mapping. Subnet matching exists only inside `BlockActionOverride`, and there is no prefix-table type in connect (grep). The mobile tunnels exclude RFC1918 and ULA.
8. Cloud agent sandboxes allow only HTTP/HTTPS through a proxy, or block the internet by default. connect supports SOCKS5 proxies only, and the H3/QUIC transports need UDP.
9. Hosted devices have no provider client, so they cannot do subprotocols or peer messaging (`sdk/README.md:66`). A hosted sidecar would need its own client.
10. Docs that disagree with the code:
    - The budget doc says the iOS device target is 20 MiB; the code sets 32 MiB.
    - The loader comment says the WASM is "~40 MB"; it is 75 MB.
    - The js PLAN.md says Go networking is "runtime-inert", but connect now uses fetch for HTTP.
    - `sdk.go:32` still names a `client` package.
    - The README mentions `errors.go`, which does not exist.

## 6. Open questions for the owner

1. Which process is the canonical sidecar on iOS: the tunnel, which is always on but has a tight budget, or the app, which has headroom but stops in the background? Is a hosted sidecar acceptable as the always-on mailbox?
2. Should a sidecar on a device share that device's client id (in process) or always be a child client? Child clients inherit identity and are exempt from concurrent limits.
3. May connect export reserved-id subprotocol registration and a browser WebSocket transport, or must those also live in the sidecar repo?
4. For the extension: should the sidecar be a native companion over native messaging, a remote sidecar hosted in server (like `ProxyDevice`), or a real WASM client (which needs the transport and auth work)?
5. Should the bridge use a non-RFC1918 overlay range (for example 100.64/10) so the apps need no route changes, or will the apps add included routes per subnet?
6. Where do MLS private keys live on each platform: plain LocalState files like today, or a secure store implemented by the app, and is that store shared between the app and the extension?
7. Is a sidecar API through the cgo C ABI for Windows and Linux in scope for v1, or only gomobile and JS?
8. For cloud agents, which UR domains and protocols can the user be expected to allowlist, and is an HTTPS-only transport through the sandbox proxy required?
