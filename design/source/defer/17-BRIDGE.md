### bridge-l3-delivery: L3 delivery
Stage: Later
- **Deferred:** Delivering IP packets at layer 3 between sidecars, named in §17.18's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row. D-BRIDGE-1 reuses connect's client-to-provider NAT path, so targets need no tun or root.
- **Launch instead:** The provider's NAT path: sender routing, a per-flow provider decision, one hop (§17.5, §17.6).
- **Lost:** What a routed path gives over a NAT one: the sender's own address at the destination, and protocols that do not cross NAT.
- **Dark in code:** Nothing is built.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for a routed path with a tun on both ends, and how §17.8's rules apply to it.

### bridge-multi-hop-maps: Multi-hop maps
Stage: Later
- **Deferred:** Port maps and routes that cross more than one sidecar, named in §17.18's Later row. It has no D- item, task or FS row.
- **Why:** DESIGN.md gives no reason beyond the Later row. D-BRIDGE-1 keeps the path to one hop.
- **Launch instead:** One hop. A provider never dials another host's block address for a flow it received (§17.6's rule 2).
- **Lost:** A destination behind a second sidecar is not reachable through the first.
- **Dark in code:** Nothing is built. The provider hook denies a block address not hosted on the device.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** A design for who authorizes each hop and how loops are refused.

### bridge-ipv6-subnet-routes: IPv6 subnet routes
Stage: Later
- **Deferred:** Advertising and routing IPv6 subnets (§17.18; §23.4).
- **Why:** The overlay is IPv4 only: one IPv4 /16 per network and no IPv6 overlay (§17.4; owner decision 28).
- **Launch instead:** IPv4 subnet routes. Private names answer NODATA for AAAA (the plan's BRIDGE-M4-14).
- **Lost:** An IPv6-only subnet behind a sidecar cannot be reached.
- **Dark in code:** Nothing is built. The route statements are IPv4.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** An address plan for IPv6 in the overlay, new statement fields, and the conflict and HA rules of §17.7 for them.

### bridge-v1: §17's v1 set
Stage: v1 (M6)
- **Deferred:** §17.18's v1 row: cross-network shares through C18, with ShareKeys, per-generation ShareSigners and the preflight; `ur tun` on macOS and Windows; P2P, built at M6 behind `EnablePeerP2p` and off until an owner call (owner decision 296).
- **Why:** Shares and the other platforms' tun belong to M6 (owner decision 86).
- **Launch instead:** v0 at M4, same network, Linux and WSL2 first; at M8, forwarding in every app's VPN component (owner decision 197).
- **Lost:** Until M6: sharing across networks, and `ur tun` on macOS and Windows.
- **Dark in code:** Built in the same run on the `sidecar` branches. P2P's switch has its own entry under §6.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: it ships when M6's gate passes (§23.6).
