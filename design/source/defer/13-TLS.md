### tls-ech-split-mode: ECH in split mode
Stage: Later
- **Deferred:** Encrypted ClientHello at the edge, in split mode, so the name a visitor asks for is hidden on the path (§2.19, §13.17; D-TLS-10).
- **Why:** D-TLS-10: ECH routing needs split mode, which Go's TLS server lacks.
- **Launch instead:** tlsedge routes on the cleartext SNI, publishes no ECH configs and ignores GREASE ECH (§13.5). §2.8 lists the SNI and the whole ClientHello among what the lb and tlsedge see.
- **Lost:** The host name of every TLS connection to the edge is visible to the network path, as well as to the edge.
- **Dark in code:** Nothing is built. The ClientHello parser reads ECH presence only (sidecar/tlsedgeservice).
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** Split-mode ECH in the TLS stack tlsedge uses, a design for the public name and key rotation, HTTPS records to publish the configs (§12's entry), and new §2.8 words.

### tls-h3-edge: HTTP/3 on the edge's UDP 443
Stage: Later
- **Deferred:** h3 on edge UDP 443 (§13.17; D-TLS-10).
- **Why:** D-TLS-10: a QUIC connection's SNI cannot be preread while connect owns UDP 443.
- **Launch instead:** TCP 443, 8443, 8883 and 5671. The front serves no HTTP/3 and strips upstream `Alt-Svc` h3 entries (§13.7).
- **Lost:** No HTTP/3 to a published name.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A way to split UDP 443 between connect's transport and the edge by QUIC's SNI, then QUIC in tlsedge's connection path and its metering.

### tls-anycast: Anycast for the edge
Stage: Later
- **Deferred:** Anycast addresses for the edge, named in §13.17's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row. There is one lb site today (§9.17).
- **Launch instead:** The edge shares the existing lb addresses through the SNI split on TCP 443 (§13.4; owner decision 34).
- **Lost:** Nothing while there is one site.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A second site and address space to announce, which is an operations and provider change before it is a design one.

### tls-v1: §13's v1 set
Stage: v1 (M6)
- **Deferred:** §13.17's v1 paragraph: Team custom domains, with §12's custom-host-add, the split's custom-host map and strong-mode CAA checks (FS-32, FS-35, FS-122); Team scopes; affinity; `members-device`; overlay access for members by §17's maps and grants, with M6's `ur tun` on macOS and Windows; publish reach receipts (§16).
- **Why:** They are Team items (owner decision 55).
- **Launch instead:** v0 at M5: the SNI split with an empty custom-host map, tlsedge and Service contracts, certificates under `<root>`, the front with `members` login, desktop `ur bridge public-tls`, and the CT watch.
- **Lost:** Until M6: a Team's own domains and member-device access.
- **Dark in code:** Built in the same run on the `sidecar` branches.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: it ships when M6's gate passes (§23.6).
