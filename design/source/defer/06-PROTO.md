### proto-stream-resume: Stream resume
Stage: Later
- **Deferred:** Resuming a broken stream where it stopped, named in §6.18's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row.
- **Launch instead:** A stream that fails resets with TRANSFER_FAILED and its caller opens a new one. The stream's offsets leave room for a later resume (§6's errors rule).
- **Lost:** A long transfer that breaks starts again from its beginning at the stream layer.
- **Dark in code:** Nothing is built. The offsets in the stream frames are the seam.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for which side keeps what, for how long, and how a resumed stream is authorized again, then additive wire fields.

### proto-hybrid-only-tls-groups: Hybrid-only TLS groups
Stage: Later
- **Deferred:** Offering and accepting only hybrid key-exchange groups in TLS, named in §6.18's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row.
- **Launch instead:** TLS 1.2 and 1.3 with X25519MLKEM768 offered first (§13's versions row), so a peer that supports the hybrid group uses it and one that does not still connects.
- **Lost:** A connection to a peer without the hybrid group has no post-quantum key exchange.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A measurement of which peers lack the group, an owner decision on refusing them, and a settings field for the group list.

### proto-peer-p2p: Same-network P2P, turned on
Stage: Built at M6, off until an owner call
- **Deferred:** Ending relay-only for same-network sidecar pairs (owner decision 296; D-PROTO-10; §6.6, §6.18, §17.18; QD-045, QD-583).
- **Why:** Owner decision 296 builds P2P at M6 and leaves it off until the owner calls it on its fault schedule and measurement.
- **Launch instead:** Every same-network pair stays relay-only.
- **Lost:** Every same-network byte is relayed, and debited, until that call.
- **Dark in code:** `SidecarProtocolSettings.EnablePeerP2p`, default false (sidecar/envelope_settings.go, sidecar/rpc_subprotocol.go).
- **Held:** Nothing.
- **To bring back:** §22's P2P fault schedule and measurement pass; §2.8's connect rows and §2.10 say that a pair on P2P learns each other's public addresses through ICE and that relays see no frames of that pair; the owner calls it; a network turns the setting on.

### proto-v1: §6's v1 set
Stage: v1 (M6, M10)
- **Deferred:** §6.18's v1 rows. At M6: FriendsAndFamily shares with C18, and same-network P2P built behind its switch. At M10 (owner decision 169): the SEARCH pair, Hello's feature bits 0 and 1, the control class's acceptance of SEARCH, and C19's window accounting with the app hosts' keepalive (owner decisions 176, 188).
- **Why:** Shares belong to M6 and remote search to M10 (owner decisions 86, 163, 169, 175).
- **Launch instead:** v0's wire is M1's and M2's, with M4's seals and control contracts and M5's streams; it freezes at M2, and M10's bytes are additive to it.
- **Lost:** Until M6 and M10: cross-network shares and remote search.
- **Dark in code:** Built in the same run on the `sidecar` branches. M10's bytes freeze at M10's Gn-out.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: each ships when its milestone's gate passes (§23.6).
