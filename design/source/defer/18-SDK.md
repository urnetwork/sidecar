### sdk-extension-worker: The extension's own Worker
Stage: Later
- **Deferred:** The browser extension running the sidecar itself as a web worker, with its streams (owner decision 26; R-CTX-5, R-ARCH-4; §5.17, §18.4, §18.8, §18.17, §22.17, §23.4). §22's rows for it wait with it.
- **Why:** Owner decision 26: HTTPS-only first, and connect streams follow C4. The extension's Worker also waits on §18.10's size spike and C17.
- **Launch instead:** The extension uses a desktop `ur daemon` over native messaging, `ur native-host`, where one exists; without one it is alarms-only. ur.io pages use the read-only page Worker.
- **Lost:** An extension with no desktop daemon beside it has no sidecar: no vault, no approvals of its own, and `PreviewRevokeDevice` and `RevokeDevice` answer `REVOKE_NOT_CAPABLE`.
- **Dark in code:** On js, `NewSidecarLocal` answers unsupported and `NewSidecarRemote` runs over a host-supplied `ur native-host` port (sdk/sidecar.go, sdk/sidecar_types_js.go). `ur native-host` relays no call that §5.8 signs only on confirmation.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** C4, and C17 if the spike asks for it; a Worker main within `sidecar.wasm`'s size gate; the rule that the Worker accepts only its own extension pages' ports; and §22's extension rows.

### sdk-firefox-session-mode: Firefox session mode
Stage: Later
- **Deferred:** Firefox session mode, named in §18.17's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row. On Firefox the extension runs in an event page, and both it and its Worker unload when idle (§18.8).
- **Launch instead:** §18.4's feature table gives what the extension does on Firefox, with the mark "awake" for what needs the event page alive.
- **Lost:** DESIGN.md does not say.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design that says what the mode is, with the extension's own Worker.

### sdk-remote-search-requesters: Browser Workers and ephemeral CLI hosts as remote-search requesters
Stage: Later
- **Deferred:** Asking a designated indexer to search from a browser Worker or an ephemeral CLI host (§5.4's requester methods; §18.13's Q-SDK-6; §18.17). Browsers also wait on C4.
- **Why:** Remote search's requester side is on app hosts only (owner decision 175). A browser tab's Worker carries no connect client.
- **Launch instead:** A browser tab downloads the index and searches locally, as a phone does when no indexer is online (owner decision 155).
- **Lost:** A browser tab or a short-lived CLI host pays the index download before it can search.
- **Dark in code:** Nothing is built. The requester methods exist for app hosts only (§5.4).
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** C4 for browsers, then the requester's Hello and policy on those hosts, with no keepalive (owner decision 609).

### sdk-v1: §18's v1 set
Stage: v1 (M6, M10)
- **Deferred:** §18.17's v1 rows. At M6 (RS2): the team console on the page Worker, with the directory's read-only views; the `sdk.Sidecar` shell with `SignEdgeLogin`; the directory's seams. At M10 (owner decision 169): the search policy and targets, `SidecarSearch`, windows on app hosts and remote search's requester side; the page Worker's search; `Write`'s versioning argument, the drop calls and `History`'s states (owner decisions 173, 183).
- **Why:** Team ships at M6 and format 2 with search at M10.
- **Launch instead:** v0: CLI hosts through M1-M4, the ur.io/recurd page at M4 (RS1), app hosts at M8 (BS1).
- **Lost:** Until M6: the team console. Until M10: search and drops in the SDK.
- **Dark in code:** Built in the same run on the `sidecar` branches; the `sdk.Sidecar` shell lands dark at M6.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: each ships when its milestone's gate passes (§23.6).
