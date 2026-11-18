### repo-c4-browser-carrier: C4, the browser WebSocket carrier
Stage: Later
- **Deferred:** C4 of §4.6's connect changes: a `GOOS=js` WebSocket H1 carrier with in-band auth and an Origin allowlist (owner decisions 22 and 26; §18.8). With it wait browser streams, socket dials from a browser (§18.4), HeadCheck replies from `read_only` page Workers (§7.9, §18.8; QD-227) and the extension's own Worker.
- **Why:** Owner decision 26 runs the browser HTTPS-only first, and connect streams follow C4. The page Worker needs no connect client for what it serves at RS1 and RS2.
- **Launch instead:** The page Worker runs on the `sidecar_http` leg, HTTPS-only, over §6's long-poll (§18.8, §18.10). Where a desktop `ur daemon` exists, the extension uses it through `ur native-host`.
- **Lost:** No stream or socket dial from a browser. A page Worker runs no HeadCheck, so a page's view is unwitnessed and shows no `witnessed_at` (§7.9's read_only row).
- **Dark in code:** Nothing is built. `make check`'s X9 rule holds C4 as `later` and fails when a js carrier over a browser WebSocket appears in connect (sidecar/check/x9_test.go).
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** C4 on connect's `sidecar` branch, templated on sdk/device_rpc_platform_js.go; the server admits `chrome-extension://` ids, the `moz-extension:` scheme and the key origin; the X9 row moves to a milestone. Then HeadCheck for read_only Workers and the extension's Worker follow.

### repo-c17-js-connect-build: C17, a js connect build without gVisor
Stage: Later, decided after §18's spike
- **Deferred:** C17 of §4.6: a `js` connect build without gVisor or the IP stack, for the extension's streaming Worker only (owner decision 22; Q-REPO-2's residual; Q-SDK-1; D-SDK-19).
- **Why:** A connect-only js/wasm main imports 42 gVisor packages, which puts `sidecar.wasm`'s size goal out of reach. The page Worker no longer needs C17, since it links no connect client, so only the extension's streaming Worker would, and that Worker waits on C4.
- **Launch instead:** The page Worker is built `-tags sidecar_http` and links no connect client, engine or IP stack (§18.10).
- **Lost:** Nothing beyond what C4's entry lists.
- **Dark in code:** Nothing is built. `make check`'s X9 rule fails when connect gains a gVisor-free js build that §4.6 has not decided (sidecar/check/x9_test.go).
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** §18.10's size spike gives the figures; the owner decides C17 on them; the change then lands in connect with C4.

### repo-c7-logical-lanes: C7, caller lane keys and logical lanes
Stage: Later
- **Deferred:** C7 of §4.6, a caller lane key for non-IP sends (connect/transfer_logical_lane.go), and with it §6's explicit lanes per stream (owner decision 22; §6.12's alternatives; §6.18).
- **Why:** §4.6: `TransferKey` lanes suffice. §6's alternatives row adds that explicit lanes are off by default in connect and starve without floors.
- **Launch instead:** Streams share connect's `TransferKey` lanes. D-PROTO-4's review reopens the question if a stall is measured.
- **Lost:** One stream's backlog can delay another on the same lane.
- **Dark in code:** Nothing is built. `make check`'s X9 rule fails when a caller lane key appears on connect's send options (sidecar/check/x9_test.go).
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A measured cross-stream stall, then C7 in connect with floors for each lane, and §6's stream rules for choosing a lane.

### repo-apt-yum-repositories: apt and yum repositories
Stage: Open, decided at v1's exit review
- **Deferred:** apt and yum repositories for `ur` (owner decision 213; Q-REPO-6's option (b)).
- **Why:** Owner decision 213 ships no apt or yum repository. Q-REPO-6 asks how Linux users then update, and its recommendation is to let the owner decide at v1's exit review whether they need repositories.
- **Launch instead:** `.deb` and `.rpm` are direct downloads, and `install.sh` checks the offline key's signature. A Linux host updates when someone re-runs `install.sh` or fetches the next package. Homebrew and winget come with v1.
- **Lost:** `apt upgrade` and `dnf upgrade` never reach `ur`, so no update arrives on a Linux host without someone acting.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** The owner's answer to Q-REPO-6. Option (b) needs a second offline two-person GPG key, signing at promotion, and repository trees under ur.io/recurd.

### repo-v1: §4's v1 set
Stage: v1 (M6, M7, M10)
- **Deferred:** §4.18's v1 row: connect change C18 at M6; C20 at M7 (owner decision 269); C19's window accounting at M10 (owner decisions 176, 188); Homebrew and winget packages.
- **Why:** Each belongs to a v1 milestone: cross-network shares and Team at M6, strict-mode mail at M7, storage format 2 and search at M10 (owner decisions 55, 163, 169).
- **Launch instead:** v0 uses the connect changes of M1-M5 (§4.6) and ships `ur` through `install.sh` and direct packages.
- **Lost:** Until those milestones: cross-network shares, `strict_chain`, and remote search's accounting.
- **Dark in code:** Built in the same run on the `sidecar` branches. C19 blocks M10's Gn-out and C20 blocks M7's `strict_chain` (§4.18's Blocking row).
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: each ships when its milestone's gate passes (§23.6).
