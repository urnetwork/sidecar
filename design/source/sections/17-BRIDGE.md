## 17. IP addresses, subnet routing, and port forwarding

### 17.1 Purpose and scope

This section owns PLAN.md's bridge (PLAN.md:113-119): the overlay address plan (X18, owner decisions 28, 132), subnet routing, provider port mapping, bridge rules, their engine and states, native IP principals (`WindowDelegation`), cross-network shares (owner decision 86, C18), service discovery across hosts (17.7.1; owner decision 778), the connect changes, `BridgeHost`, `ur tun` and `ur bridge`. §7.9 owns the config repo and authorization log; §8 policy, grants, shares and gates; §12 names; §13 `public-tls`; §18 the sdk seam, the forwarding role's setup in apps' VPN components (owner decision 197) and app work; §20 billing.

### 17.2 Requirements

| id | requirement | source |
|---|---|---|
| R-BRIDGE-1 | A destination in a client's subnet goes to that client, not the default route | PLAN.md:115 |
| R-BRIDGE-2 | Providers rewrite destination ip:port by port mappings for same-network packets | PLAN.md:117 |
| R-BRIDGE-3 | Rules stored on the server, pushed in real time, decided locally | PLAN.md:119; owner decisions 5, 6 |
| R-BRIDGE-4 | The sdk device gains "ip addr, port forward" through Sidecar-implemented abstractions | PLAN.md:31 |
| R-BRIDGE-5 | A permanent private address per agent and service, plus routed subnets; Linux and WSL2 first | sidecar/design/pitch5.html:687, :894 |
| R-BRIDGE-6 | A forward is a grant (one agent, port and window, approved), encrypted between sidecars | sidecar/design/pitch5.html:680-681 |
| R-BRIDGE-7 | With a policy, agents reach only granted ranges and exit only through customer exits | sidecar/design/pitch5.html:689; owner decision 120 |
| R-BRIDGE-8 | `ur tun`, `ur bridge` and the BRIDGE notes; listeners bind 0.0.0.0/:: unless `--listen` narrows them | cli/UI.md:11, :42-52, :104-122; owner decision 84 |
| R-BRIDGE-9 | No locks, I/O or PostgreSQL per packet; every delivery path carries the decision; fail closed | connect/CODESTYLE.md:98, :106 |
| R-BRIDGE-10 | With an ACL document, only rules open a provider's loopback, LAN, link-local or overlay addresses; its own daemon listeners never open, and unverified policy state opens nothing private | §2 I-10; owner decisions 50, 105, 120 |
| R-BRIDGE-11 | Forwarding unlimited on every tier: no count caps; bytes count | PLAN.md:353, :359; owner decisions 10, 66 |
| R-BRIDGE-12 | Bridge flows are Required at both ends and come from principals the customer signed; outward bridge actions need an I-8 approval | owner directive; owner decision 3; §2 I-3, I-4, I-8 |
| R-BRIDGE-13 | A /16 per network that admins cycle or choose; private names in v0; cross-network forwards on the IP path, aliased and isolated | owner decisions 28, 85, 86, 132 |
| R-BRIDGE-14 | A service mDNS finds on one host's link is discoverable from the network's other hosts that may reach it, and reachable from them: Xcode on one host finds and reaches an iPhone on another's LAN; raw mDNS is never reflected and rule 5 stands | owner decision 778 |

### 17.3 What exists today

| Piece | Fact | Citation |
|---|---|---|
| Sender | One lock-free `sendRoute` load per packet or burst, sdk sockets included, then the mux, a multi client or the local NAT; a destination change rebuilds the multi client, dropping every flow; `NetworkPeer` sends everything to one peer. Window clients (a multi client's per-provider children) show providers their own ids, form no session without `PostQuantumEncryption`, force P2P in Network mode unless overridden, and keep TCP/25 local | sdk/device_local.go:5666-5683, :4984-4995, :5286-5302; sdk/socket.go:141; connect/ip_remote_multi_client_api.go:1033-1038; connect/ip_remote_multi_client.go:1643-1649, :3205-3220, :6718-6725 |
| Provider | Flows open at three points (17.6). The sdk provider is Opportunistic: plaintext until a session forms, or forever. Network sources reach anything, LAN and loopback included; every other mode, FriendsAndFamily included, is Public at both ends: public unicast only, else an Incident calling `ReportAbuse`; RFC 1918 is not public, but 100.64/10 is | connect/ip.go:10416-10421, :10449-10451; sdk/device_local_provider.go:258; connect/transfer_encrypt.go:477-483; connect/ip_security.go:385-390, :567-576, :892-908; connect/ip_remote_multi_client.go:6704 |
| Apps | All four capture 0/0 and exclude RFC 1918 and fc00::/7 | apple/app/extension/PacketTunnelProvider.swift:1797-1806; android/.../MainService.kt:755-758; windows/app/src/Service/NetPolicy.h:79-83; linux/app/src/Tunnel.hpp:508-510 |

Missing: overlay addresses, destination routing, port mapping, per-port provider checks, private egress for shares, and a customer-vouched principal: contracts are HMACed under a provider secret the platform holds (connect/protocol/transfer.proto:375-379, :563-567).

### 17.4 Address plan (X18)

| Item | Value |
|---|---|
| Block | One IPv4 /16 per network, at random from 100.64.0.0/10 (owner decision 28) except 100.64.0.0/16 (likeliest in use) and 100.100.0.0/16 (Tailscale's 100.100.100.100); no IPv6 overlay |
| Enclaves | an enclave claims one address per incarnation, a `BridgeAddress` /32 in the block that `ur enclave ls` shows, and its private name follows the running incarnation through the overlay resolver, so people and rules use the name (owner decision 737; DESIGN-COMPUTE.md §11.8) |
| First block | Drawn at the network's bootstrap into its first config head; a head that holds none, an older network's or one bootstrapped before the bridge shipped, gets one from any config writer's next head; until then `ur tun ip` reports no block and files nothing. Every head carries the block forward; a reader keeps a byte-identical record it holds without judging its signer again, and once that signer no longer stands any Owner's or Admin's config writer's next head re-signs the record, keeping its prefix, previous prefix and drain, so a revoked first device costs no reader its block, a reader holding none taking it from that head on (§7.9's Writes; owner decision 698) |
| Cycle or choose | An admin re-rolls it or picks a /16 in 100.64.0.0/10 or RFC 1918 only (owner decision 132; D-BRIDGE-16); hosts keep their host bits while the old block drains (17.8) |
| Uniqueness | None across networks; a device whose networks share a block (owner decision 23) routes it only to the first-joined one, warning in `ur status` and a `SidecarEvent` until an admin cycles one |
| Host address | A random free /32 of the lower /17 outside `<block>.0.0/24`, which holds services (the resolver at `<block>.0.53`, the IPv6 translator at `<block>.0.46`, 17.5, and the source `<block>.0.1` that C5's `Deliver` gives a flow whose source holds no overlay address, §4.6); once that is full, the highest free /32 of the upper /17, whose bottom aliases fill first-fit (17.9); never x.y.z.0 or x.y.z.255; a chosen address (`ur tun ip <ip>`) must lie in the lower /17 |
| Binding | The §5 `sidecar_id` (an agent's own only under its own OS user, container or VM, §5.5); it survives re-enrollment and the reaper; on an app, its VPN component's forwarding role hosts it (17.10; owner decision 197) |
| Assignment | On demand (`ur tun ip`, the app's UI, the host's first map, an admin), never by an app's forwarding setup, which files no `BridgeAddress` of its own (owner decision 484); the first claim in log order wins (17.8) |
| Release | On revocation or removal, then a 30-day tombstone (I-14) |

Addresses avoid connect's tun ranges, 10.a.b.0/24 and 169.254/16 (sdk/device_local.go:1851-1861; connect/tun.go:387-399, :533-551). Where a local route overlaps the block, as a CGNAT carrier address can, the device routes overlay peers by their /32s and carves out of the router's table and every exported route each local /32 its physical path needs: interface addresses, gateways and system resolvers, from the platform's routes and DNS settings (§18.6's `SetBridgeLocalAddresses`), since `connect.LocalIpv4Networks` sees only interface subnets, or nil where enumeration is restricted (connect/tun.go:490-495). The block is never dropped wholesale; until those /32s are known, the export holds per-peer /32s instead of the block. If a carved /32 is an assigned overlay address, `ur status` warns and an admin cycles the block (D-BRIDGE-16). Under `ur tun`'s `exits`, where the default route rides the tun, each carved address the host reaches only by its default route keeps the host's own route, an off-link resolver's above all, IPv6 ones included (17.11; owner decision 480).

### 17.5 Data path and the router

The bridge adds a sender lookup (PLAN.md:115) and a provider decision (PLAN.md:117) to connect's client-to-provider NAT path (D-BRIDGE-1).

```text
sender (app tun | ur tun | userspace connect.Tun)      target (sidecar-owned, Required)
  sendPacket / sendPacketsWithPolicy                     ClientReceive -> principal -> policy
    deviceBridge.Route --link--> multi client(target) ==> LocalUserNat flow -> EgressHook (C5, C18)
      | default | reject: RST or ICMP into the tun          pass | map | deny -> real socket
    UpgradeMux -> default multi client
```

- **Insertion.** After `route := self.sendRoute.Load()` (sdk/device_local.go:5766, :5859; :2440 is a read-only check, no send path), before the mux, so bridged :53 and :80 are never claimed. `deviceLocalSendRoute` gains §18.6's `deviceBridge` (`device.Bridge`, 17.10): nil costs one check, `Route` one atomic load plus `BridgeTable.Classify` and, where an entry offers a choice, one pin probe, two for TCP while it holds 5-tuple pins. Every send path passes here (connect/CODESTYLE.md:98); the CLI runs the same table over `ur tun` or a userspace `connect.Tun`.
- **Batches.** A burst splits in place (a 64-entry stack array) into per-link batches, keeping flow order; an all-default burst passes unchanged.
- **Classify.** A fixed-offset destination read, then an immutable longest-prefix lookup in an in-repo table in `device/`, the prefixes flattened at build time into sorted disjoint ranges searched by binary search, at 0 allocs/op: ≤50 ns at 1,000 prefixes (§22 gate). Unassigned block addresses answer unreachable; carved local /32s (17.4) take the default route, which under `ur tun`'s `exits` hands each back to the host's own route (17.11; owner decision 480).
- **HA and pins** (D-BRIDGE-7, D-BRIDGE-9). A weighted rendezvous hash of (source, destination, protocol), fragment-safe, picks among an entry's advertisers, and pins keep a live pair on its link across edits, since TCP cannot change exit mid-flow (connect/ip_remote_multi_client.go:6593-6597):

```text
pins     the sender's lock-free table: 8,192 slots on desktop, 1,024 on mobile
key      the pair (source, destination, protocol), in every fragment's header, so a pair's flows and
         fragments share one pin and one link; only a TCP connection under a 5-tuple pin (syn) leaves its
         pair's link, and connect's multi clients forward only reassembled UDP, dropping fragmented TCP,
         since TCP uses MSS (connect/ip_remote_multi_client.go:6679, :6848-6850, :6875)
record   only where an entry offers a choice, two or more advertisers or links with draining ones
         included; overlay /32s and one-advertiser routes otherwise have one link and need none; one
         atomic store per pair per second
lookup   a TCP segment's 5-tuple pin, then its pair's pin, while its link still serves the entry; else
         the window; else the hash, pinned where the entry offers a choice and a slot is free
full     no free slot: the pair routes by the hash unpinned; nothing is refused (owner decision 66)
window   an entry that offered no choice (one advertiser and one link, so no pins) and now offers one pins
         a pinless pair at first sight to the pre-change link for 600 s after the change, 5 min for UDP and
         ICMP, while that link remains in the entry, draining included: live flows stay while it serves
         them, and new UDP and ICMP pairs, which cannot be told from live ones, follow it
syn      a TCP SYN of a pair the window would pin, or pinned to a draining link, takes the hash over the
         entry's undrained links under a 5-tuple pin instead, so new connections take the new rule at once
         (with no such link or free slot, it follows its pair)
idle     a pin ends when its pair or connection idles out on its link: 600 s for TCP, 5 min otherwise,
         the link's idles (connect/ip_remote_multi_client.go:210-213); hosts hold bridge flows as long
         through C5's per-flow IdleTimeout (17.6), raising for them alone connect's NAT idles: TCP 300 s
         (connect/ip.go:510), UDP 60 s (:446) or, in the targetless provider profile, 300 s (:578, :711),
         ICMP 60 s (connect/ip_icmp.go:157); a NAT at its flow caps still evicts an approximately least
         recently active flow (`applyLruMapLimit`, connect/ip.go:11751)
kept     an edit that leaves a pair's link serving it (an advertiser joining, a weight change, another
         link's health) keeps its pin until it idles out
removed  a withdraw, retarget, address or block change, or a link rebuild, leaves the old advertiser or
         link in the entry, draining: it serves its pinned pairs, and every pair while nothing else
         remains, TCP pins for max(drain_seconds, 600 s) and others for max(drain_seconds, 5 min), a
         rebuilt link's until its strict_exp, then leaves
health   a refusal, that is a CreateContract refusal, a failed ContractDestinationCheck or no sealed session
         within 3 s of the link's first send, never a target's TCP RST, marks a link down for 30 s; a down
         link takes no new pairs while another advertiser of the entry is up, and keeps its pins
```

- **Links** (Q-BRIDGE-2). One multi client per target, built by `BridgeHost` (17.10): fixed `ProviderSpec{ClientId}`, `FixedWindowSize: 1`, `PostQuantumEncryption` (Required), `OverrideAllowDirect=false` until C3 (D-PROTO-10), `EnableIcmp`, never `DefaultMultiClientSettings`' six-client window; each window client carries the subject's `WindowDelegation` (17.9). Window clients are the subject's children, or on an app its forwarding client's, which act as the subject (17.10), so they expire unrefreshed at §7.4's 7-day `strict_exp`, and links rebuild after 6 days, draining under the pins above. Same-network links run Network mode, share links FriendsAndFamily, carrying private destinations only inside their aliases (17.9). Relayed bytes are debited (§20.6). Links idle-close after 600 s, as long as a TCP pin, and survive default-route rebuilds. `device.Bridge.Route` answers TCP to destination port 25 on any link entry with the reject client, through the rejects bucket below, so bridged TCP/25 never enters a link, whose multi client would hand it to its own local NAT to dial on the sender's physical network (`sendSmtpLocal`, connect/ip_remote_multi_client.go:6649, :6843); TCP/25 on the default route is untouched. Until C16 only sidecar-owned Required clients are targets (D-BRIDGE-5), so replies are sealed too.
- **Memory.** A window client carries a full client graph (connect/ip_remote_multi_client.go:217-222), so a device short of its §18.4 budget closes its least recently used idle link; the iOS tunnel runs none until §22.9 measures one (owner decision 100).
- **Rejects.** A TCP RST or ICMP administratively prohibited (v4 3/13, v6 1/1) enters the tun through a per-source token bucket (20/s, burst 40), since connect writes policy resets unthrottled (connect/ip_smtp_policy.go:847-864). Under `exits` an IPv6 packet, which no exit carries, is answered here too, counted per family beside the rejects' own counts, so a dual-stack source hears at once and falls back to IPv4 (owner decision 482).
- **IPv6 to discovered instances** (owner decision 778). Apple documents Xcode's device connections as needing IPv6, and the overlay carries IPv4 alone, so each instance the advertising proxy registers takes an IPv6 address too (17.7.1): its IPv4 address in the low 32 bits of a /96 inside a ULA /48 the device draws at random once (RFC 4193, in RFC 6052's layout), which `ur tun` routes into the tun, the tun holding one other address of that /48 as its own IPv6 source. The router translates a packet to that /96 statelessly into IPv4 (RFC 7915) before it classifies it, its destination the embedded address and its source `<block>.0.46`, the services address kept for it (17.4), and translates a reply to `<block>.0.46` back the same way, to the tun's own IPv6 address, so the host's own IPv4 flows to that address never mix with translated ones. Checksums are rewritten and ICMP errors translated as RFC 7915 says; a translated packet leaves 20 bytes smaller, TCP's MSS keeps replies within the tun's MTU, and a UDP reply that would exceed it once translated is dropped, which QUIC's path MTU discovery absorbs (RFC 9000 §14). Every client the translator serves sends from `<block>.0.46`, so where a host's `Deliver` writes such a flow into its tun (17.6), the flow takes `<block>.0.1` and a port the NAT allocates, as a source that holds no overlay address does (§4.6), and two viewers' flows never share a 5-tuple there. Every other IPv6 packet still meets the rejects row.

### 17.6 Provider hook and port mapping

C5 (§4) gives `LocalUserNatSettings` an `EgressHook`, called once per flow before the dial: at the TCP dial (connect/ip.go:5740), the UDP open (:3589) and ICMP egress (connect/ip_icmp.go:782), which every lane uses (connect/ip_provider_reliable_ingress.go:158-191). Replies are rebuilt from the flow (connect/ip.go:4075-4077, :7289-7291), so a map is DNAT with no checksum or return-path rewrite.

```go
// connect (C5, with C13's seals, C15's key and receive gate, which window clients set on, and C18's switch);
// a nil hook keeps today's behavior
type EgressFlow struct {
	Source        TransferPath
	ProvideMode   protocol.ProvideMode
	ContractClass protocol.ContractClass // C13: the sealed contract class; unset when the contract sealed none
	SourceSubject Id               // C13: the sealed source subject, a consistency check only
	SourceNetwork Id               // C13: the sealed source network, in every mode (D-PROTO-19)
	Principal     *BridgePrincipal // the verified WindowDelegation's subject and network (17.9); nil: none
	                               // (not Peer.Principal, the contract signer's string)
	Sealed        bool             // the source peer had a sealed session (EncryptionEventSealed,
	                               // connect/transfer_encrypt.go:520) when the flow opened
	Protocol      IpProtocol
	From, To      netip.AddrPort
}
type BridgePrincipal struct {
	Subject, Network, ShareId Id // ShareId is zero on a same-network link
	NotAfter                  time.Time
}
type EgressDecision struct {
	Verdict          EgressVerdict  // Pass | Map | Deny (an RST for TCP, unreachable for UDP and a silent drop
	                                // for an ICMP echo; never an Incident)
	Target           netip.AddrPort // Map; port 0 keeps the port
	RuleTag          uint64         // names a (subject, rule) pair, so CloseFlows can end a subject's flows:
	                                // the first 8 bytes of SHA-256(subject_id (16 B) || rule_id), big-endian,
	                                // rules 4 and 7 taking one byte, the rule number, as their rule_id, and
	                                // rule 3 that byte, 0x03, then the hosted address's 4 bytes, one tag per
	                                // hosted address (owner decision 483), and a share's flows the share_id
	                                // as subject with 0x53 then the target's index, u32be, as rule_id
	                                // (17.9), so the engine enumerates a subject's or a rule's tags without
	                                // tracking flows
	PolicyGeneration uint64         // the published policy the decision used
	IdleTimeout      time.Duration  // this flow's NAT idle in place of the NAT-wide one; 0 keeps the NAT's
}
type EgressHook interface {
	// once per contract a source presents, in its first flow's sequence before the dial, from the peer's
	// C13 seals and C15 key; connect keeps the answer on that source's flows until the contract ends
	VerifyPrincipal(source TransferPath, peer Peer) *BridgePrincipal
	ResolveEgress(flow *EgressFlow) EgressDecision // inline, non-blocking
	PolicyGeneration() uint64                       // the published generation, one atomic load
	// C18: true hands FriendsAndFamily flows to private destinations to ResolveEgress
	// instead of the public-only rules (connect/ip_security.go:574-576)
	FriendsAndFamilyEgress() bool
}
// RST to the source and close the socket of every flow registered with ruleTag below the published
// generation, dials in progress included
func (self *LocalUserNat) CloseFlows(ruleTag uint64) int
// LocalUserNatSettings holds the initial hook; this additive atomic setter swaps it on a running NAT, as
// legacy -> pending does (17.8), and installing a non-nil hook cancels every live flow that holds no registered
// decision, so nothing opened before the hook outlives it
func (self *LocalUserNat) SetEgressHook(hook EgressHook)
// optional: SetEgressHook hands a hook that implements it each NAT it is installed on, outside every lock, so
// device.Bridge, which holds no NAT, keeps the closer and calls CloseFlows after each policy swap; unbind runs
// when the hook leaves that NAT
type EgressHookBinder interface{ BindFlowCloser(closer EgressFlowCloser) (unbind func()) }
type EgressFlowCloser interface{ CloseFlows(ruleTag uint64) int } // LocalUserNat
// C18's source half: MultiClientSettings (connect/ip_remote_multi_client.go:578) gains
// SharePrivateDestinations []netip.Prefix, which egressRelationship's callers (:6826, :7000, :7367) admit
```

```text
C5's contract (D-BRIDGE-21; TCP, UDP and ICMP)
register  ResolveEgress returns {verdict, target, rule tag, policy generation, idle}; LocalUserNat records
          them on the flow's sequence before it starts the dial (TCP), opens the socket (UDP) or sends
          (ICMP), each under the sequence's context (connect/ip.go:5740, :3589)
publish   a revocation first swaps in the new policy (an atomic pointer swap, generation g+1), then calls
          CloseFlows(rule tag), which cancels every flow registered with that tag at a generation <= g, a flow
          whose dial is in progress included (its sequence context ends)
recheck   a flow whose dial completes re-reads the published generation before it sends the SYN-ACK or
          forwards a first byte; a newer one re-resolves the flow, and only the same verdict and target keep
          it: anything else, a Map to another target included, closes it as a Deny; one atomic load per
          flow, no lock on the packet path
udp       a NAT with a hook runs each UDP sequence's own socket loop, its sharedSocketLifecycle off, so
          openSocket and the hook run outside udpSend's buffer mutex (connect/ip.go's initSequence); §22.9's
          Memory row re-measures that per-flow cost on constrained provider profiles at M8
```

`device.BridgeEgressPolicy` implements the hook from the host's verified state (17.8):

```text
at an sdk provider, any mode but Network   -> Pass   // Public and FriendsAndFamily among them: today's
  and Service                                        // public-only rules follow
Service                                    -> Deny   // no IP (§6.10.1)
at a host, any mode but Network and        -> Deny   // None, Public, Stream, PublicStream and any later
  FriendsAndFamily                                   // value (D-PROTO-6)
contract class control or unset            -> Deny   // D-PROTO-18: no IP on control contracts; it binds Network
                                                     // and a host's FriendsAndFamily flows, never the pass row
no verified principal (17.9), or its       -> Deny   // D-BRIDGE-17; sdk providers skip it until C16
  subject or share revoked or suspended here
not Sealed                                 -> Deny   // hosts are Required (D-PROTO-6)
FriendsAndFamily at a host (17.9)          -> C18 on and To in an alias A_i of the principal's share ? To = T_i,
                                              then rules 0-3 (3 by grant only) and 6 under the share grant : Deny
0 one of this device's daemon listeners    -> Deny   // D-BRIDGE-19, document or not
1 map(To, protocol, port)                  -> AllowDial(subject, host, port) ? Map(target) : Deny
2 a block address not hosted here          -> Deny   // one hop; never dial another host's address
3 a hosted address                         -> (no document and untagged) or AllowDial(subject, host, port)
                                              ? Map(127.0.0.1:port), never a daemon listener : Deny
4 no ACL document, untagged source         -> Pass   // today's allow-all, disclosed (owner decisions 50, 105, 120)
5 loopback, link-local, multicast, unspecified -> Deny   // mDNS too: 17.7.1 carries discovery as records
6 a served prefix                          -> AllowRoute(subject, prefix, port) ? Pass or Map(remap) : Deny
7 public unicast                           -> AllowExit(subject, host) ? Pass : Deny
8                                          -> Deny   // LAN without a route rule
subject: the principal's (at an sdk provider before C16, C13's sealed subject, resolved through the compiled
client_ids of 17.9's verify row: a sealed subject in no row is an other client (§8.4), untagged for rule 4 as
owner decision 105 keeps for app devices, and under a document holds only autogroup:untagged's rows, which
BridgeRules carries as untagged = 10, the dial, route and exit rows of a subject with no sidecar_id,
member_id or client_ids that the compiler fills from §8.5's expansion (owner decision 477));
"no document" means a verified enforcing{nodoc} state (17.8); idle: a Pass or Map of a flow with a principal
sets IdleTimeout to 600 s for TCP and 5 min otherwise (17.5), and every other flow keeps its NAT's;
AllowDial, AllowRoute and AllowExit read the per-subject rows the compiler expands into BridgeRules (17.8),
never AclEngine, whose AllowRoute serves the compiler and ur bridge's previews
```

- **Maps** match the destination as sent: `:5432` → `127.0.0.1:5432` on a hosted address, or `:8000` → `192.168.1.20:8000` ("client:port → ip:port"); ranges map by offset; ICMP echo follows rule 3, through connect's unix ICMP egress (connect/ip_icmp_egress_unix.go), whose datagram sockets on darwin each receive every echo reply the host receives, so there each flow's echo identifier is drawn at random per process (crypto/rand), skipping any a live flow of the process holds, and a reply is kept only for a sequence number the flow sent and has not yet seen answered, so two processes echoing to one address, two providers on one Mac among them, never take each other's replies (owner decision 674). A map never targets another client's overlay address, the daemon's own listeners or a §13.7 control panel.
- **Own listeners** (D-BRIDGE-19). Rule 0 matches the daemon's local API, MCP, git, IMAP and submission listeners on loopback and every local address, since they bind all interfaces by default (owner decision 84); the state lists them (17.8), and the control channel is a socket or pipe, never a port (I-17).
- **Exposed prefixes.** An address in one of this host's exposed prefixes (17.7) is never dialed as sent: rule 2 does not count it another host's, and whichever rule passes it, 1 for a map whose target it is, a listeners map's included, 4 for an untagged source with no document or 6 under `AllowRoute`, maps it back to its served prefix, host bits kept, so such a map dials the served address, as a shared device's /32 needs (17.7.1; owner decision 778).
- **No document.** Rules 3-4 apply owner decisions 50, 105 and 120: untagged sources keep today's reach, minus rule 0, the hosted address standing for loopback, and tagged ones get §8.5's implicit rules, so R-BRIDGE-7 holds for tagged agents, and for all once a policy exists; product copy and §2.18 disclose this (I-10).
- **Listeners** (owner decisions 770, 771, 774; DESIGN-COMPUTE.md §26.7). Under the `listeners` feature (§7.9), rules 1 and 3 also admit a flow whose source a `listener:` grant (§8.4) names when its protocol and port are in the host's own last-published set, never rule 0's listeners, a forward, a port a narrower socket also binds or a share's source, a removal taking effect when the next scan of the OS's socket tables sees it, before the next publish; each such flow is tagged by rule id `0x4C`, protocol and port, so a hide closes it, whether `ur listeners` or `ur bridge discovery` writes it into the host's one hide set (17.7.1), and delivered through `ur tun` by C5's fourth verdict, `Deliver` (§4.6), which writes its packets into the host's tun instead of dialing, from the source's overlay address, or from `<block>.0.1` and a port the NAT allocates for a source that holds none or that sends from 17.5's translator address `<block>.0.46`, so two viewers' translated flows never meet there (owner decision 778), or else to a non-loopback address of the host, never `127.0.0.1`. The implicit document's `autogroup:tagged` to `listener:*` admits only while the network's acknowledgment of `listeners:publish` stands (§8.5). A listeners flow under rule 1 goes to its map's target, as every map's does, an exposed address's served one (above).
- **sdk exit NAT** (`ensureRemoteUserNatProviderWithLock`, sdk/device_local.go:6421). The hook goes on that NAT, `remoteUserNatProviderLocalUserNat`, alone: the provider's own `localUserNat` stays hookless, since it carries this device's own `routeLocal` flows (:5788, :5895), which are no provider source. Until C16 the sdk installs the policy without the principal and Sealed rows and rules 1-3 and 6, since an Opportunistic provider's sources may be plaintext: Network sources keep the public exit their rules allow and, with a document, lose LAN, loopback and overlay reach.
- **C6a.** 100.64/10 becomes non-public, as IANA lists it (RFC 6598; https://www.iana.org/assignments/iana-ipv4-special-registry/, updated 2025-10-09), so public exits refuse overlay traffic. Behind `CfaaSecurityPolicySettings.DropSharedAddressSpace`, false by default, providers shadow-count it for a release, and a later one drops it as `SecurityPolicyReasonSharedAddressSpace`, not as an Incident: a check of its own beside `isPublicUnicast`, which stays as it is, since that branch returns an Incident (connect/ip_security.go:574).

### 17.7 Subnets: advertisement, conflicts, HA

- **Advertising.** `ur bridge expose <ranges>` files a `BridgeRoute` delta (17.8). As in Tailscale, approval is separate from access ([R:connect-ip] §2.10): a standing grant in a config head or an I-8 approval (§16.6) activates it; §8 `route` grants decide who uses it. A route rule that names no `ip:` destination and no `autogroup:internet` reaches the prefixes §8.4's readings give it, so Team's grant 1 reaches the prefixes a member's own devices' approved routes serve: the compile gives such a rule an entry and a route row for each served prefix whole, exits staying an internet or /0 rule's alone; an activated grant with no local detail stays closed (owner decision 220); the filer names such a rule in a route's `route_rule_ids`, and a standing grant covers a route, by the same reading; and `AclEngine.AllowRoute` answers `ur bridge`'s previews by it too, refusing an address outside those prefixes (owner decision 575).
- **Overlap** (D-BRIDGE-8). The longest prefix wins. An identical prefix is an HA replica (same `site_id`) or a remap, an exposed prefix from the block, allocated as aliases are, first fit and aligned from the upper /17's bottom in one space with them (17.9), that the advertiser maps back keeping host bits.
- **Sender conflicts.** The sdk drops and reports exposed subnet-route prefixes overlapping `connect.LocalIpv4Networks()` (connect/tun.go:490-531), so the local LAN wins until a remap or block change; where it returns nil, only 17.4's carve keeps the physical path's /32s. The overlay block follows that carve rule instead. The block and approved prefixes join `RandomLocalIpv4`'s avoid list.
- **HA.** When no link to an advertiser of the most specific prefix can carry a packet (17.5), the router answers unreachable, never falling back to a broader prefix or the default route, which could reach another network reusing the addresses.

#### 17.7.1 Service discovery across hosts (DNS-SD)

mDNS (RFC 6762) is link-local multicast to 224.0.0.251 and ff02::fb on UDP 5353, and never leaves its link: the bridge routes unicast IP one hop (17.5), and the hook denies multicast (rule 5) and another host's address (rule 2), so no link carries it, and rule 5 stays as it is. Owner decision 778 makes a service that mDNS finds on one host's link discoverable on the network's other hosts that may reach it, as DNS-SD (RFC 6763) in unicast records. Each `ur daemon` host is a Discovery Proxy (RFC 8766) for its own services, those it announces by mDNS and, with DESIGN-COMPUTE.md's listeners, the entries its listeners list holds (17.11), and for the LAN devices its person shares. It answers each other host's watch, over §6's RPC and never as DNS over the overlay, which rule 0 refuses at a daemon's own listeners (D-BRIDGE-19), with the records that host may reach. The watching host's resolver answers them as unicast DNS-SD in the network's zone (§12.9.1), and its advertising proxy registers them for its own apps in `local.`, where Xcode and every multicast-only app browse. No host reflects raw mDNS to another, as Avahi's reflector does.

```text
gather    the Discovery Proxy: ur daemon on Linux, macOS and Windows, while it publishes anything (its own
          services, unless its person turned them off, or a shared device) and a watch or its person's own view
          is open, so the LAN is queried on demand (RFC 8766 §1)
links     each interface that is up, multicast-capable and not point-to-point: never loopback, ur tun's link or
          another tun
how       macOS: mDNSResponder's DNS-SD API (DNSServiceBrowse, DNSServiceResolve and DNSServiceGetAddrInfo on each
          such interface's index), called through purego as §5.10's keychain is; Linux and Windows: the
          sidecar's own querier, UDP 5353 shared with the platform's responder, sending RFC 6762 §5.2's
          continuous queries with §7.1's known answers, at most QueryRate (20 a second; RFC 8766 §9.3) on an
          interface
types     the effective list (below), each type browsed by name; never every type that _services._dns-sd._udp
          enumerates
keeps     per instance: its name (one label of UTF-8, at most 63 octets, no control character; RFC 6763 §4.1.1),
          service and subtypes, port, TXT (at most TxtByteCount, 1,300 B; RFC 6763 §6.2), its target's host
          label, that host's IPv4 addresses and each record's RFC 6762 §10 TTL
own       an instance whose target is this host, one its own mDNS announces or one of its listed entries (listed,
          below): published at the host's overlay address (17.4), port unchanged, only while the host holds an
          address, which discovery never claims, so discovery opens no host's loopback (owner decision 484's
          reasoning); a viewer reaches it as the hook passes that viewer's flow, as on any of the host's ports:
          under 17.6's listeners rule, for a port of the host's listed set, by Deliver or at a non-loopback address
          of the host, never 127.0.0.1; rule 3 maps to 127.0.0.1 only a flow the listeners rule does not admit and
          rule 3's own grants do, an admin's dial on the host's port or the no-document rule for an untagged
          source (owner decisions 105, 120), as DESIGN-COMPUTE.md §26.7 keeps it
listed    with DESIGN-COMPUTE.md's listeners (M13a), each socket and map entry of a ur daemon host's listed set
          (17.6, 17.11) whose type is known and in the effective list (below): the type its person set,
          ur listeners label <port>[/udp] --type <service>|none, none withholding the entry, else its port's:
          22 _ssh._tcp; 80, 3000, 5173, 8000, 8080 and 8888 _http._tcp; 443 and 8443 _https._tcp; 445 _smb._tcp;
          548 _afpovertcp._tcp; 631 _ipp._tcp; 2049 _nfs._tcp; 3389 _rdp._tcp; 5900 _rfb._tcp; 9100
          _pdl-datastream._tcp; it becomes an own instance named "<description> :<port>", cut to fit 63 octets,
          with an empty TXT (RFC 6763 §6.1), at the host's overlay address and the entry's port; none where the
          host's own mDNS already announces that protocol and port; only the host's watch answers it, to each
          viewer by its hook, and the listeners repo never carries it; a clash takes the names rule (Q-BRIDGE-11);
          an enclave is such a host, its ur daemon running in enclave mode (DESIGN-COMPUTE.md §11.10), so its
          listed entries take names as any host's, answered by its own watch and filtered by its own hook, while
          it gathers no LAN and shares no device
shared    an instance whose target is a LAN device its person shared (share, below): published at the address
          the device's route serves, an exposed prefix's with the host bits kept (17.7), else the device's own;
          where no route serves it and one of this host's maps targets the instance, at the host's overlay
          address and the map's port (rule 1)
never     a device not shared; an address that no served prefix or map of this host reaches; a link-local
          address (169.254/16, fe80::/10; RFC 8766 §5.5.2); IPv6, which the overlay does not carry; an instance
          found on a point-to-point link, at an overlay, exposed or alias address, or registered by this host's
          own advertising proxy; an instance or entry the host's hide set holds (Hiding, below)
```

A shared device's global or ULA IPv6 addresses join its records once [IPv6 subnet routes](DESIGN-DEFER.md#bridge-ipv6-subnet-routes) exist; a link-local one never does. Watches and the records they carry:

```text
watch     DNS_SD_WATCH (0x1B02) and DNS_SD_WATCH_RESULT (0x1B03), §12.9.1's messages: peer RPC on the pair's
          Network contract of class data, never control, so a viewer asks only a host that §8.10's reach(viewer,
          host) admits, by a dial on it or a route through it; the listeners' live ask, LISTENERS, stays apart, on
          the control class (Listeners and discovery, below)
viewer    a ur daemon that runs ur tun or the advertising proxy watches each host of its network that its own
          evaluation of the rows reaches, by a dial on the host's address or a route through it, its own
          member's hosts first, at most WatchHostCount (64) at once; a host answering serving = false, which publishes nothing, is asked again
          after NotServingRetryInterval (1 h)
call      the host answers DnsSdWatch{since, hold_ms} at once when its view for this viewer differs from since,
          else when it changes or at hold_ms, at most WatchHoldTimeout (50 s, under §6.6's 55 s); the viewer
          calls again at once, so a change reaches it within a round trip
answer    the host's published instances whose address, protocol and port its hook would pass with the viewer as
          the source, by 17.6's rules in order and the hook's own code: rule 3, and the listeners rule within it,
          for its own services and listed entries, 1 for a map, a listed one included, 4 or 6 for a shared device;
          at most InstanceCount (256) and AnswerByteCount (64 KiB), truncated past them; a share's source holds no
          Network contract with the host, so it watches nothing (17.9)
checks    the viewer keeps an instance only at an address its host serves by the config, the host's overlay /32
          or a prefix or exposed prefix of a route it advertises (17.8), and only where its own router sends that
          address to the host, a LAN prefix of its own winning (17.7); it drops the rest, counting them in
          ur bridge devices
lost      a host whose watch has failed for HostLossTimeout (90 s), an instance its host drops, a TTL that runs
          out, or a compile whose rows no longer reach it: the viewer withdraws the instance from its resolver
          and its advertising proxy at once
```

Each limit named in this subsection is a field of `BridgeDiscoverySettings`, its default as given (owner decision 297).

**Who sees what.** A host answers each viewer with what its own hook would let that viewer reach, so the policy decides who sees each record, at the point that decides reach, and discovery opens nothing: a viewer sees a shared device only where §8's `route` lets it reach the device's address through its host, and a host's own service or listed entry only where `dial`, a `listener:` grant (§8.4) or the no-document rule for an untagged source reaches that port (owner decisions 105, 120, 770). The listeners list differs by design: every admitted sidecar reads every published entry, whatever it may reach, each badged for its viewer, the list being the network's (owner decision 770; 17.11), while a DNS-SD name follows each viewer's reach, since a Bonjour browser offers to connect to every name it lists; so a listed entry's name reaches a viewer only in its host's answer to that viewer's watch, never through the `listeners` repo. A viewer that reaches nothing on a host holds no contract that carries a watch (§8.10). URnetwork's servers see a watch as any RPC between two sidecars: Required-mode ciphertext with its size and timing at the relays, and the pair's data contracts in api's rows (§2.8's connect-1 and connect-2), so no metadata row is added. Names and TXT are their host's words, never trusted, and no MCP tool reads them, `listeners_list` (§16.5) included, which reads the `listeners` repo alone.

**Listeners and discovery.** The listeners (17.11) and discovery are two views, which divide plainly. The listeners list (DESIGN-COMPUTE.md §26) is what each device listens on, found in its OS's socket tables and its own bridge state, published to the `listeners` repo for every admitted sidecar and refreshed by `LISTENERS`: `ur listeners` and `Listeners()` (§18.5) show it, the document's `listeners` block (§7.9) says who publishes it, and `listeners:publish` discloses it. Discovery is DNS-SD: what hosts announce by mDNS and the LAN devices their persons share, which the mDNS gatherer above finds, and the Bonjour names listed entries take, all of which each host's watch answers per viewer: `ur bridge devices` and `GetDiscovery` (§18.5) show it, the document's `discovery` block (§8.5) sets its types beyond or short of the default list, for LAN devices and listed entries alike, and the own-services notice below discloses what a host announces by mDNS. A listed entry crosses into discovery as an own instance (`listed`, above), and nothing crosses back: the gatherer lists no socket, and the listing reads no mDNS. `LISTENERS` and the watch stay two RPCs (§6.11): the listeners list is the whole network's (owner decision 770), entries a viewer may not reach included, and a person's own-view and hidden entries for that person's devices, so a viewer that reaches nothing on a host still refreshes it over the control class, while a watch answers only what its viewer may reach; a DNS-SD instance has no field for an entry's kind, bind, description source, end or `shared` mark; and one list answered two ways could disagree.

**Sharing a device.** A LAN device is published only by its person's act on its host, since its name and model belong to whoever uses it:

```text
share     ur bridge share <device> on the device's host, a Confirm daemon method bridge.share beside
          bridge.activate (from control with the person's confirmation, never MCP; §5.8): <device> is a LAN host
          the host's own view lists, by its mDNS host name; the confirmation shows the disclosure below, then
route     a served prefix of this host that covers the device's IPv4 address serves it as it is; otherwise the
          host files a BridgeRoute for that /32 with an exposed /32 from the upper /17, allocated first fit as
          17.9's aliases are, an `expose` under §16.6's approval (I-8), and publishes once the route is in
          force, so every viewer reaches the device at a block address no LAN of its own holds
keep      the share sits in the host's own sealed settings, by host name, in no statement and at no server
moves     within a served prefix, the records follow the device's new address in the next answer; out of a /32
          share's route, by a new lease or another Wi-Fi network, the host stops publishing the device and
          withdraws the route (BridgeWithdraw, drain), since another device may take the address, and asks its
          person to share again: a new /32 under a new approval, or at once under a standing grant that covers
          it (17.7); a device unseen for ShareRouteAbsentTimeout (7 d) loses its /32 route and keeps its share;
          a connection to the old address ends, and a client reconnects once its browse shows the new one
unshare   ur bridge unshare <device>: no longer published, and a /32 route its share filed is withdrawn
```

**Types** (Q-BRIDGE-10). A host gathers and publishes only the types of the effective list, so the network is not shown every device's every service:

```text
default types, versioned in the sidecar repo as §12.5's reserved list is
apple devices  _remotepairing._tcp (a paired iPhone's or iPad's CoreDevice endpoint, iOS 17 and later);
               _remotepairing-manual-pairing._tcp (an Apple TV or Vision Pro pairing by the code it shows);
               _apple-mobdev2._tcp (Wi-Fi sync and debugging before iOS 17); _device-info._tcp (a model)
remote access  _ssh._tcp _sftp-ssh._tcp _rfb._tcp _rdp._tcp
files          _smb._tcp _afpovertcp._tcp _nfs._tcp _webdav._tcp _webdavs._tcp
print, scan    _ipp._tcp _ipps._tcp _pdl-datastream._tcp _printer._tcp _uscan._tcp _uscans._tcp
web            _http._tcp _https._tcp
per network    the ACL document's discovery block, {"discovery": {"allow": [...], "deny": [...]}}, adds and
               removes service names, each _<name>._tcp or _udp of letters, digits and hyphens (RFC 6763 §7);
               a name past 15 characters, as two of Apple's are, browses in local. alone (mDNSResponder's
               DNSCommon.c), so only the advertising proxy carries it; with no document, the default list
```

**The advertising proxy** (draft-ietf-dnssd-advertising-proxy's role, on the viewer's own machine alone):

```text
macOS     for each instance the viewer keeps, ur daemon, through purego and on one DNSServiceCreateConnection,
          calls DNSServiceRegisterRecord for its target's A record and for an AAAA record at its translated
          address (17.5), and DNSServiceRegister for the instance (type, port, host = that target, TXT unchanged,
          so a client's own check of it, CoreDevice's of its authTag among them, still holds), all on
          kDNSServiceInterfaceIndexLocalOnly, the instance with kDNSServiceFlagsNoAutoRename; mDNSResponder
          never probes a LocalOnly record or sends one on any interface, and only this machine's browsers find
          it (dns_sd.h; mDNSResponder's mDNSCore/mDNS.c), so Xcode and every app browsing local. see the
          instance, and the host's LAN sees nothing
target    <label>.<client-name>.local: the device's own host label under its host's client name, never a name
          a LAN host holds, since a unique LocalOnly address record hides that name's other answers on the
          machine
names     an instance keeps its own name unless one of that name and type is in view on this machine, from its
          LAN, its own services or another host's answer; then it, and each same-named remote one, takes
          `<name> (<client-name>)`, cut to fit 63 octets; a local instance that appears later takes its name
          back at once; one whose name, type and host label match a local instance's is the same device on
          this LAN, and is not registered (Q-BRIDGE-11)
linux     ur tun's link alone: a TUN device is multicast-capable (Linux's drivers/net/tun.c), systemd-resolved
          runs mDNS on it once ur tun sets the link's MulticastDNS, and Avahi from 0.9 uses any multicast
          interface (Avahi's commit 2b6bccca); the bridge hands the proxy the mDNS packets that reach the tun
          from the host's own address, and the proxy answers there with the same A and AAAA records, from
          <block>.0.53 with RFC 6762 §10's TTLs, sends goodbyes at withdrawal, and sends nothing to a LAN
          interface; where Avahi's reflector is on, which would repeat its answers onto the LAN, it stays off,
          and ur bridge devices says why
withdraw  at once when the viewer drops the instance: DNSServiceRefDeallocate, which sends nothing on the wire for
          a LocalOnly record, or a goodbye on the tun link
loops     registrations stay on the machine; the gatherer skips LocalOnly answers, point-to-point links and every
          overlay, exposed or alias address; a host publishes only what its gatherer found on its LAN and its own
          services, never what a watch brought: nothing learned from the network goes back into it
default   on wherever ur daemon runs on macOS or Linux and the device can send into the overlay, by ur tun or the
          macOS app's VPN component (17.11); ur bridge discovery proxy off turns it off (Q-BRIDGE-9)
```

[The advertising proxy on Windows, and discovery in the apps](DESIGN-DEFER.md#bridge-discovery-other-platforms), are Later: Windows' DNS-SD API browses `.local` names alone and documents no registration scoped to the machine (learn.microsoft.com's `DNS_SERVICE_BROWSE_REQUEST`, `DnsServiceRegister`); Android's NsdManager browses `local.` alone and runs no mDNS on a VPN service's tun, whose interface Android brings up without the multicast flag (AOSP's MdnsSocketProvider.java and com_android_server_connectivity_Vpn.cpp); and on iOS, raw multicast needs Apple's `com.apple.developer.networking.multicast` entitlement (developer.apple.com). A Windows desktop still gathers and shares, and its `ur tun` resolver answers §12.9.1's names; an app's VPN component owns those names and answers each NODATA (§12.9.1).

**As built** (mdns-service-discovery, sidecar 85e6afc5 to d605f71e, where this subsection is silent). A watch served, or the person's own view asked, keeps the gatherer querying for `GatherDemandTimeout` (2 min), so a viewer calling again within a hold keeps it running. macOS gathers no subtypes, since DNS-SD browses a subtype only by its name and none is named to browse, and the Linux and Windows querier keeps those a responder announces. A viewer calls a host again no sooner than `WatchMinInterval` (1 s) after its last call to it began, so a host that answers every watch at once is asked at most once a second, while a held watch, which answers at a change, is called again at once; each call is bounded by `WatchCallTimeout` (55 s, §6.6's call bound), and a failed one is asked again after `WatchRetryInterval` (2 s), doubling to `WatchRetryMaxInterval` (30 s), under `HostLossTimeout`. A listed entry's instance carries `ListedTtl` (120 s; DESIGN-COMPUTE.md §26.8), renewed with each answer while it stays listed; a host shares at most `ShareCount` (64) devices and keeps at most `HideCount` (1,024) hides; and it judges its shares for a move or an absence every `ShareUpkeepInterval` (1 min) beside the gatherer's own reports, a share's absence counting only while the gatherer runs. On macOS a target whose address moves has its LocalOnly record removed and registered again, since a LocalOnly lookup never hears `DNSServiceUpdateRecord`, and a paired network whose app VPN component routes its block counts as a way into the overlay, though the instances seen through it take no AAAA record, the app's translator not being the daemon's. On Linux the proxy answers a type that a name it owns does not hold, an AAAA while the translator is off among them, with an NSEC (RFC 6762 §6.1), and a legacy query from another port with its id and TTLs of at most 10 s (RFC 6762 §6.7), and announces a new record twice, 1 s apart (RFC 6762 §8.3); it answers mDNS over IPv4 to 224.0.0.251 from `<block>.0.53` and, while the translator is on, over IPv6 to ff02::fb from `<block>.0.53`'s address in the translator's /96, which the host routes into the tun by the /96's route and reverse-path filters such as firewalld's pass, never from the tun's own address of the /48, which the host's mDNS stack would take for its own echo and drop, as systemd-resolved does (owner decision 805; built by discovery-proxy-ipv6-mdns, sidecar 5aa5a01c). Its NSEC, legacy and known-answer rules hold on both families, announcements and goodbyes go to both groups, and each family's messages split within its own bound, IPv6's 1,232 B beside IPv4's 1,252 B, under the tun's 1,280 B MTU; with the translator off the proxy holds no IPv6 address and leaves an IPv6 query unanswered. `ur tun` hands the proxy the IPv6 queries the host sends from the translator's own address or a link-local one, and the rest to the bridge as before. `ur tun` keeps one ULA /48 for each network it carries, drawn once and kept in that network's sealed local state beside its choices (17.5).

**Disclosure and opt-out** (Q-BRIDGE-9). Two notices cover a host's own names, each its own share of them: discovery's for the services the host announces by mDNS, and `listeners:publish` for its listed entries'. A host publishes the services it announces by mDNS from the release that ships discovery, and tells its person at `ur daemon`'s first start after it, in `ur status` and `ur bridge devices` until seen, `ur bridge devices` showing it counting as seen, and once in the desktop app: "This computer's services that it announces on its own network (file sharing, screen sharing, SSH, printers it shares) show by name, with this computer's name, on the devices of your URnetwork network whose policy lets them reach those services. `ur bridge discovery off` stops it; `ur bridge discovery hide` hides one, from the Listeners section too." `listeners:publish` discloses the Bonjour names listed entries take with the list itself, and its text gains a line saying so (§2.8; DESIGN-COMPUTE.md §26.6), so an entry takes no name before its device publishes its list. Sharing a LAN device shows, before its approval: "Sharing `<name>` (`<model>`) lets the devices of your network that its policy lets reach it see its name, its model and the services it offers, with their ports, and connect to it through this computer at `<address>`. Devices on this computer's network that you do not share stay unseen." Each device keeps its own switch, and a share ends by `unshare`.

**Hiding** (one set with the listeners'). A host keeps one hide set, in its own sealed settings, which `ur bridge discovery hide` and `ur listeners hide` both write and both views honor. What lies at the host's overlay address is keyed by protocol and port, so one hide takes a listed entry, its Bonjour name and an own service its mDNS announces on that port alike; anything else, a shared device's instance, is keyed by instance; and a device its person hides whole (`ur listeners hide --device`) publishes no instance at its overlay address, its own and listed ones, while a LAN device it shares is hidden by that instance's own hide or by ending the share (DESIGN-COMPUTE.md §26.6). A hidden listed entry also leaves the listeners rule, its flows closed by rule tag `0x4C` (17.6), and a hidden instance leaves each watch's next answer. `unhide`, by either command, reopens what the hide closed, so it is a §5.8 Confirm method, the person's own act on /dev/tty or in the app's UI, never MCP. `ur bridge discovery off` withholds only the Bonjour names of the host's own services and listed entries, and says that the Listeners section still lists the entries.

**Xcode on another host** (owner decision 778's use case). Person P runs `ur daemon` on host A, whose LAN holds P's iPhone, and on macOS host B, with `ur tun`. Once, with the iPhone at B, P pairs it with B's Mac as Apple requires: on iOS 17 to 26 by cable, Developer Mode on, the iPhone unlocked and Trust tapped, since only an Apple TV or Vision Pro pairs over a network by a code it shows (developer.apple.com's "Pairing your devices with Xcode"); on iOS 27 also by Xcode's Device Hub on a network the two share, since that pairing has the iPhone find the Mac on its own link, and discovery never advertises onto a LAN. Then, on A, P shares the iPhone: no served prefix covers it there, so A files its /32 under an exposed /32, which P approves. B's daemon watches A, which answers with the iPhone's `_remotepairing._tcp` instance at the exposed address, since grant 1, or a network's allow-all, lets B route there. B's advertising proxy registers it LocalOnly, its TXT unchanged, and Xcode, which finds devices by Bonjour alone (Apple's DTS, developer.apple.com/forums/thread/805833), lists it; a client tells its own device by the TXT's authTag, checked against its pairing records (pymobiledevice3's misc/understanding_idevice_protocol_layers.md). Xcode connects to the instance's port, verifies the pairing, then asks the iPhone for a tunnel, TCP or, before iOS 18.2, QUIC, on a port the iPhone picks for that connection on the same address (pymobiledevice3's and go-ios's clients; Apple documents none of it): the /32 route carries every port and protocol, so no per-port map is needed, unless an admin narrows the route's ports, which the device's line in `ur bridge devices` names. Apple's DTS states that Xcode's device connections require IPv6 and rely on link-local traffic, with no IPv4 option (developer.apple.com/forums/thread/798547), and the iPhone accepts its tunnel from routable addresses, IPv4 over a VPN included (pymobiledevice3's pull 2207); whether Xcode takes the routable ULA address of 17.5's translator is undocumented, and §22.7's S8 run on a real Xcode and iPhone before M6's exit decides it. The design gives reach and discovery alone; pairing stays the person's act, at the devices, as on one LAN.

**What the use case rests on** (owner decision 778; recorded for the implementer at the owner's request, 2026-11-24). Two conditions hold it, and the second is its main risk:

1. **Pairing.** On iOS 17 to 26 an iPhone first pairs with each Mac by cable and shows no code; only an Apple TV or Vision Pro pairs over a network by a code it shows; pairing over a network the two share arrives with Xcode on iOS 27. So B's Mac must have paired with the iPhone by cable once, or both must be on iOS 27.
2. **IPv6.** Apple's DTS says Xcode's device connections "require IPv6 and rely on IPv6 link-local traffic", and the overlay carries IPv4 alone. 17.5's translator gives each remote device a routable ULA IPv6 address, and no one has documented whether Xcode accepts such an address in place of a link-local one. §22.7's S8 run on a real Xcode and iPhone before M6's exit decides it, and 17.17's risk row names the fallback.

### 17.8 Rules in the config repo, delivery, engine, disposition

```text
statement (sidecar/protocol/bridge/bridge.proto; §6.9 Signed,             signer; carried in
  purpose bridge, SignedType 0x1901-0x1907 in row order; a delta
  begins with auth.proto's StatementHeader, §7.9; §4.4)
BridgeBlock{ipv4_prefix, previous_prefix, drain_until}                    an admin; a head, carried and kept
                                                                            (17.4; owner decisions 28, 132, 698)
BridgeAddress{sidecar_id, ipv4}                                           the sidecar or an admin; a delta
BridgeRoute{route_id, advertiser, prefixes, exposed_prefix, site_id,      the advertiser; a delta, active once
            weight, kind subnet|exit, drain_seconds, approval}              approved (17.7)
BridgeMap{map_id, host, match_prefix, protocol, ports, target,            the host; a delta, active once
          target_port, expires, drain_seconds, approval}                    approved (17.7)
BridgeEgress{subject, mode auto|exits|none; sealed: exit sidecar_ids      an admin, owner or sponsor; a delta
             or tag_id and require_default_egress, none under auto or
             none}
BridgeAlias{share_id, target_index, alias_prefix, host sidecar_id,        the accepting sidecar; a delta (17.9)
            host identity key}
BridgeWithdraw{rule_id, reset|drain}                                      the rule's signer or an admin; ids only
approval  none under a standing grant (17.7), or the I-8 decisions and this use's CanonicalAction (§16.8),
          which readers verify as §8.8 does a GrantActivate's, the signer being every decision's requester,
          holding the body to the action the person saw: a route's prefixes inside its cidrs, an exit needing
          0.0.0.0/0, a map's target port and expiry to the action's where it sets them, and the statement type
          to the action's shape, a map void under an action naming cidrs and a route void under one naming a
          target port or an expiry (owner decision 705);
          under a multi-use decision also template_action, the template every decision's payload_sha256
          hashes, which this use's action must match (ActionMatchesTemplate), so one decision files up to
          its uses rules, the ledger's count binding them; with it unset the single-use reading stands
          (owner decision 218)
rule id   route_id or map_id: under a decision, SHA-256("urnetwork-sidecar-v1/bridge-rule" || effect_key),
          the use's §16.6 ledger key, which readers recompute, so a retry or restart files one id; under a
          standing grant, 32 random bytes; a filing of a held id may change only weight, site_id and
          drain_seconds and activates nothing; readers refuse an id a BridgeWithdraw named and a decision's
          ids past its uses (§7.9); a fold freezes each bridge statement's body-level verdict into the config
          head's bridge ledger (bridge/ledger/, Ledger below; owner decision 473), which keeps a withdrawn id,
          with its approval_id, until its decision's not_after, and a void one (Unformed generations, below)
          for the network's life (DESIGN-DETAILS.md section 12)
```

The statements' bytes, a delta's `StatementHeader` first and its sealed part in its `*Body` (Placement, below), with the messages and lists they use:

```proto
// sidecar/protocol/bridge/bridge.proto: the table's statements, a delta's header first, then the fields api sees
// in the order the table writes them, and a sealed_body opening to its *Body for the rest
message BridgeBlock {                     // a head's record, with no header; a reader keeps a carried one it
                                          // holds byte for byte unjudged, and an admin's next head re-signs one
                                          // whose signer no longer stands (17.4; owner decision 698)
  BridgeIpv4Prefix ipv4_prefix = 1;
  BridgeIpv4Prefix previous_prefix = 2;
  int64 drain_until = 3;
}
message BridgeAddress { StatementHeader header = 1; bytes sidecar_id = 2; bytes sealed_body = 3; }
message BridgeAddressBody { fixed32 ipv4 = 1; }
message BridgeRoute {
  StatementHeader header = 1;
  bytes route_id = 2;                     // the rule id below
  bytes advertiser = 3;
  repeated bytes route_rule_ids = 4;      // the §8 route rules it serves (17.7; owner decision 344)
  bytes sealed_body = 5;                  // BridgeRouteBody
}
message BridgeRouteBody {
  repeated BridgeIpv4Prefix prefixes = 1;
  BridgeIpv4Prefix exposed_prefix = 2;
  bytes site_id = 3;
  uint32 weight = 4;
  BridgeRouteKind kind = 5;
  uint32 drain_seconds = 6;
  BridgeApproval approval = 7;
}
message BridgeMap {
  StatementHeader header = 1;
  bytes map_id = 2;                       // the rule id below
  bytes host = 3;
  int64 expires = 4;
  bytes sealed_body = 5;                  // BridgeMapBody
}
message BridgeMapBody {
  BridgeIpv4Prefix match_prefix = 1;
  uint32 protocol = 2;                    // the IP protocol number
  repeated BridgePortRange ports = 3;
  bytes target = 4;                       // the address, 4 or 16 B
  uint32 target_port = 5;
  uint32 drain_seconds = 6;
  BridgeApproval approval = 7;
}
message BridgeEgress {
  StatementHeader header = 1;
  bytes subject = 2;
  bytes sealed_body = 3;                  // BridgeEgressBody, under exits only
  BridgeEgressMode mode = 4;              // in the clear (Placement)
}
message BridgeEgressBody {
  reserved 1; reserved "mode";            // the mode, which BridgeEgress carries in the clear
  repeated bytes exit_sidecar_ids = 2;    // or exit_tag_id
  bytes exit_tag_id = 3;
  bool require_default_egress = 4;        // the subject's devices keep default egress on (17.11's lock; owner
                                          // decision 607)
}
message BridgeAlias { StatementHeader header = 1; bytes sealed_body = 2; }   // only its header shows
message BridgeAliasBody {
  bytes share_id = 1;
  uint32 target_index = 2;
  BridgeIpv4Prefix alias_prefix = 3;
  bytes host = 4;                         // T_i's host's sidecar_id, in the sharing network
  bytes host_identity_public_key = 5;     // that host's identity key, from the target table (17.9's Y's pin)
  bytes sharing_network_id = 6;
  uint32 drain_seconds = 7;               // a release's drain: 300 s when 0, 3,600 s at most
  bool release = 8;                       // ends this share's alias for target_index
}
message BridgeWithdraw { StatementHeader header = 1; bytes rule_id = 2; BridgeWithdrawMode mode = 3; }
message BridgeApproval {                  // the approval row
  bytes canonical_action = 1;             // this use's CanonicalAction as stored, whose effect_key derives the id
  repeated Signed decisions = 2;
  bytes template_action = 3;              // a multi-use decision's template (owner decision 218)
}
message BridgeIpv4Prefix { fixed32 address = 1; uint32 length = 2; }
message BridgePortRange { uint32 first = 1; uint32 last = 2; }
enum BridgeRouteKind {
  BRIDGE_ROUTE_KIND_UNSPECIFIED = 0; BRIDGE_ROUTE_KIND_SUBNET = 1; BRIDGE_ROUTE_KIND_EXIT = 2;
}
enum BridgeEgressMode {
  BRIDGE_EGRESS_MODE_UNSPECIFIED = 0; BRIDGE_EGRESS_MODE_AUTO = 1; BRIDGE_EGRESS_MODE_EXITS = 2;
  BRIDGE_EGRESS_MODE_NONE = 3;
}
enum BridgeWithdrawMode {
  BRIDGE_WITHDRAW_MODE_UNSPECIFIED = 0; BRIDGE_WITHDRAW_MODE_RESET = 1; BRIDGE_WITHDRAW_MODE_DRAIN = 2;
}
```

- **Placement** (owner decision 5). Admin-signed heads carry the block, standing rules and 17.9's `BridgeShareSigner` files; sidecars file statements about themselves, and owners or sponsors about their subjects, as deltas entering §7.9's authorization log, verified at their position until a writer folds them in. Rule bodies are sealed to the config's current key generation (§10) in §7.9's sealed-body bytes, each delta but `BridgeWithdraw` opening to its `*Body` message and `BridgeAlias` showing only its header, with `expires` and `drain_until` int64 milliseconds since the epoch and an IPv4 prefix a `BridgeIpv4Prefix{fixed32 address, uint32 length}`, so §8.12's invariant and D-TRUST-10's witness stop can delay them; a bodiless `BridgeWithdraw` never waits, nor does a `BridgeEgress` of mode `none` or `auto`, whose `sealed_body` is empty. Only ids show (kind, signer, subject, rule id, expiry, an egress statement's mode and, for an approved route, the advertiser and the `route` rules it serves), which readers check; gates and api apply each egress entry's mode in log order over `BridgeRows.egress`, as §8.9's entries after a base, and rows carry the same value at the fold. A requested `dial` or `route` grant keeps only ids in the clear too: its CanonicalAction's `rule_id`, `subject`, `grant_allow`, `expires_millis` and a subject-only `grant_dst`, while its prefixes and ports, `cidrs`, `target_port` and any `ip:` or port text in `grant_dst`, ride in `sealed_detail`, sealed as rule bodies are, under a raised version; `payload_sha256` still covers the stored bytes, so api's `match` checks ids only, and approvers and readers open the detail to render and enforce it, while a publish keeps its clear fields, which are public anyway (owner decision 220; §8.8, §16.8). A writer's save opens it too: its policy's `ip:` tests count the prefixes and ports of each activated route grant the head keeps, and one whose detail the writer lacks fails a deny test as indeterminate, naming the grant (§8.8's Saving; owner decision 679). Gates see only §8's reach rules between sidecar ids and `BridgeRows`' egress modes (§8.10), never prefixes, addresses, ports, maps or aliases (§2.8, api-12).
- **Ledger** (owner decision 473). A sealed body is judged by every reader that holds its generation, on the state its entry lands on, a base's tail on that base's rows with the tail re-applied (§7.9), as a signer already is; when a writer folds a statement it freezes the verdict it holds into the config head's bridge ledger, files of rows by kind: `bridge/ledger/addresses` with their tombstones, `bridge/ledger/rules/<xx>` shards by rule id with each rule's body and disposition, `bridge/ledger/egress` and `bridge/ledger/aliases`, and `bridge/ledger/manifest` holding their hashes. Every full reader standing under the previous base computes the same files and forks on a difference, and a device that starts at the base, a VPN component included, takes them, so no reader re-opens a folded statement and a compile does not grow with the log. They are ciphertext at evs, so no §2.8 row: about 600 KB at 5,000 devices. Writers fold through their tip whenever a bridge statement is unfolded, so the one case that differs from a verdict at the entry's own position, a head landing within seconds of an approved filing whose policy disqualifies that approval, turns the verdict at every reader alike and fails closed, and the requester files again under a new decision.
- **Unformed generations** (owner decision 478). A body sealed to a generation gkm does not name is pending. A config writer whose whole read of gkm's generation listing, made inside the plan, names G as the newest while it holds keys 1 to G freezes a body sealed above G void (Refused, no such generation) once the entry at its tip is `UnformedVoidWait` (24 h) past the filing's own entry in log time, and folds past it; every reader that holds keys refuses, void and with no alarm, a body whose generation's GenRotate is signed more than `GenerationFormGrace` (1 h) after the entry that carries it, so a generation claimed after the void changes no reader's verdict and no device forks; a checker never voids and, lacking the generation, takes the head's rows unchecked. Both are `BridgeLedgerSettings` fields, the wait raised to a floor of the grace plus 30 min. A member device that keeps filing such bodies can hold the fold while it files, an accepted bound: the writer's `config_key_waiting` line names the filer on every plan, and revoking the filer, a statement that needs no base, ends it one wait after its last filing, as a network can shorten by lowering the wait. The id level and the rows are unchanged, and no server sees anything new.
- **Engine.** The compiler (`bridge_*.go`, §5) reads the config (owner decision 6) as a pure function of the state at a pin, the head that pin's base names, the unfolded bridge statements with their verdicts, the generation keys and the host: it opens the unfolded bodies, reads the head's ledger files once each without holding them, expands §8's reach into per-subject rows (§8.9's enumerators) and returns a `BridgeState` whose bytes are equal at every reader given equal inputs, within §8.9's latency targets; it runs off the packet path, in the sidecar role on a daemon and in an app's VPN component in the forwarding role, which reads the config by its forwarding Delegation's reader key (owner decision 197; 17.10); `device.Bridge` (17.10) applies it and later verified log entries, manages links, and swaps table and hook atomically. Every change takes one order: the evidence is committed, the policy is published at the next generation, then `CloseFlows` runs for each rule tag the new policy no longer admits; a denial is held at its own log position until a state at or past it, so a compile that captured an earlier position and finishes later removes none; and after a start, and at each new client generation, the hook is in the NAT's settings before the NAT exists (DESIGN-DETAILS.md section 12). At a daemon's start, and at each new client generation, the bridge provider is built only after every entry above the restored state that the `ConfigClient` holds has been replayed to the bridge, and a compile at the tip has run if one can, from local stores alone, since the `ConfigClient` stores an entry before any entry callback runs; a client store behind the posture's pin waits for the follow to reach it, with `bridge_alarm` after 30 s, so a host whose config store lagged its posture at a crash serves no bridge flow until it reaches api again, and nothing a restart does lowers enforcement; an app's VPN component, which has no resident judge, is unchanged (owner decision 474). Before its first verified state it is pending and denies every private destination and exit; it persists its last verified state and never lowers it on unsigned input:

```text
states (D-BRIDGE-18), per network; §18.6's forwarding role runs the same machine as its posture
legacy                no sidecar of the network has enrolled, or on an app set up its forwarding, on this
                      device: no hook, today's behavior
pending               an anchor and no verified state: Network-source flows to loopback, LAN, link-local,
                      overlay and served prefixes, and every exit, are denied; the block deny stands; maps and
                      hosted addresses refuse
enforcing{doc}        a verified state whose rows have has_document = true: 17.6's rules
enforcing{nodoc}      a verified state with has_document = false: owner decisions 50, 105 and 120's allow-all
persist               the anchor, the newest verified AuthPin, the signed base header and rows, the entries
                      since, the latch document_seen_at (the newest pin with has_document = true) and each
                      served share's newest verified ShareCert (17.9); on restart they re-verify offline
                      against the anchor and the pinned ShareKeys, and the state applies before the first
                      packet; in an app's forwarding role they are sealed under forwarding's root key and the
                      highest pin committed is also kept in the key store, a store below it being pending
                      (§18.6's posture; DESIGN-DETAILS.md section 4)
legacy -> pending     the sidecar enrolls, or on an app sets up its forwarding (§18.6), with
                      Pending{network_id, genesis_sha256, sidecar_id, identity_public_key}, on an app with
                      the forwarding Delegation its keys are named in (forward_delegation_id), stored with the
                      anchor; a later Pending for the same network and anchor, as after an admin's revocation
                      and a new enrollment, replaces the stored id and key and changes no state
pending -> enforcing  the first state verified against the anchor
doc -> nodoc          only a verified base above document_seen_at whose rows say has_document = false
any -> legacy         only this sidecar's own sign-out, which wipes the stored state: a Signed SidecarRevoke
                      whose sidecar_id and signer_id both equal the stored sidecar_id, whose header.network_id
                      is the stored network and whose signature verifies under the stored identity key, a
                      chained delta in enforcing and, with no pin to chain from in pending, taken alone by
                      ApplyDeltas; another sidecar's sign-out or an admin's revocation of this one lowers nothing
never                 an unsigned has_document, a projection that does not chain, or a lower pin changes the
                      state; one that fails to verify leaves it and alarms
```

- **Forwarding roles** (owner decisions 87, 197). An app's VPN component compiles its own `BridgeState` from the config it reads by its forwarding Delegation's reader key, with `Pending` from forwarding's setup (§18.6), its `Names` feeding C14's zone (§12.9). The compile's judge is §7.9's rows-only verifier, as api's: the forwarding role checks a head against the base that names it and does not re-compile rows from it, which the app's sidecar role, a full reader, does whenever it runs (§18.6's witness). Between compiles its posture applies as denials the log's `SidecarRevoke`, `MemberRevoke`, `Suspend`, `GrantRevoke`, `BridgeWithdraw` and `DelegationRevoke` entries and a newer forwarding Delegation's supersession, each on its signer's identity key in the rows it holds, verified against the anchor (§7.9) with `protocol/bridge`'s types alone, a `SidecarRevoke`, `MemberRevoke` or `Suspend` that §7.9's presence row covers on its identity signature as a denial that the next compile, which checks the countersignature, confirms or reverses (owner decisions 185, 187, 189), and it lifts nothing: an `Unsuspend` and every opening take effect at the next compile. A statement that could narrow reach and that it cannot check waits for the next compile, the last compiled state staying in force: the component never goes pending for it, and raises `bridge_alarm` with the statement's age once it has waited 10 minutes, again at doubling intervals (20 minutes, 40 minutes and so on) up to once a day while the condition lasts and at once whenever a further such statement becomes overdue, the condition staying in the posture's status until a compile clears it, so a revocation the posture cannot check does not apply on a device that cannot compile, an accepted cost (owner decisions 216, 487; DESIGN-DETAILS.md section 4). It holds the denials in its overlay, which goes to the component's sealed store in the review phase and until then, past its bound, makes the posture's decision pending rather than stop applying them (§18.6's posture; owner decision 485). So rules and revocations apply whether or not the app runs. A base whose signer the rows the posture holds do not name, as a config writer admitted after them, is followed by its chain and waits for a compile, the denials after it still applying; under a compiled state the posture takes that signer's key from the state's `base_signer_identity_public_key`, the key the judge verified the base under (17.9's `BridgeState`; owner decision 696). A compile opens the config's generations by DelegationWraps to the forwarding reader key, listed in the group the config repo's newest GroupForm makes, which the role follows only along a chain of verified forms, none re-forming below a generation it holds (§10.8's re-form). Every generation a compile wants and has not opened, whether or not gkm lists it, raises `config_key_waiting` once it has waited `KeyWaitAlarmInterval` (10 minutes), and again each interval while it waits, its detail naming the cause: no wrap yet, no such generation listed, forms that do not lead on, a listing stopped short, or a failed read; and a listed GenRotate that conflicts with a generation the role holds, or breaks its chain by `parent_commitment`, opens nothing and raises `head_alarm` (fork), the compile's pin its evidence (DESIGN-DETAILS.md section 4; owner decision 716).
- **Limits.** None per network (owner decision 66); the block bounds addresses at 64,770.

```proto
message BridgeRows {                      // bridge.proto; acl.proto's AclRows.bridge (§8)
  repeated BridgeEgressRow egress = 1;    // subject (sidecar_id or opaque atom), mode; ids only
  repeated BridgeRouteRow routes = 2;     // each approved route in force by its ids: route_id, advertiser and
                                          // the route rules it serves, written at the fold and applied by every
                                          // verifier in log order after a base, as the egress mode is; a route
                                          // rule with no via takes those advertisers as its via subjects
                                          // (§8.8; owner decision 344)
}
message BridgeEgressRow { bytes subject = 1; BridgeEgressMode mode = 2; }   // a sidecar_id or opaque atom
message BridgeRouteRow {                  // never a prefix, site, weight or kind
  bytes route_id = 1;                     // the route's rule id, 32 B
  bytes advertiser = 2;                   // the sidecar_id that filed it
  repeated bytes route_rule_ids = 3;      // the §8 route rules it serves: a policy rule's 16 B, a grant's 32
}
```

```proto
// sidecar/protocol/bridge/bridge.proto (§4.4; std and protobuf only), importing auth.proto (§7.9) and
// signed.proto (§6.9): the compiler's view of this host for device.Bridge, in process, a daemon's sidecar role
// or an app's forwarding role compiling it (§18.6); auth only rises, and verified entries apply on top
message BridgeState {
  AuthPin auth = 1;                        // auth.proto's (n, A_n), the newest verified state; ApplyDeltas chains from it
  bytes genesis_sha256 = 2;                // the anchor (§7.9)
  bool has_document = 3;                   // that state's rows: enforcing{doc} or enforcing{nodoc}
  bytes rules = 4;                         // a marshalled BridgeRules, declared in bridge.proto with its row
                                           // messages: this device's compiled block, routes, maps and hook
                                           // rules; only in process or over the device RPC, so no §2.8 row
  map<string, fixed32> names = 5;          // client name -> overlay IPv4 (§7.7, 17.4), versioned with rules
  repeated string name_zones = 6;          // <net>.<root>, and the alias zone where one is chosen (§12.9)
  repeated BridgeIdentity identities = 7;  // the subjects its rules let reach this host (17.9), ~64 B each
  repeated BridgeShareKey share_keys = 8;  // the shares this host serves (17.9)
  repeated string daemon_listeners = 9;    // rule 0 (17.6): the daemon's listener binds, host:port
  bytes base_signer_identity_public_key = 10;  // the Ed25519 key, 32 B, the judge verified the newest base at or
                                           // below auth under, its signer's identity key at S(b-1), which the
                                           // posture tries for that signer under this state past the rows'
                                           // writers and the identities (DESIGN-DETAILS.md section 4, 4.2.5);
                                           // empty before base 1, or where the compile holds no entry of the
                                           // base, which fails closed (owner decision 696)
}
message BridgeIdentity { bytes sidecar_id = 1; bytes identity_public_key = 2; uint64 admitted_at = 3;
                         bool revoked = 4; bool suspended = 5;
  bytes forward_delegation_id = 6;         // the subject's forwarding Delegation live at the state, 32 B;
                                           // empty for none (§7.9's forwarding row)
  bytes forward_public_key = 7;            // its Ed25519 key, 32 B, under which a delegation whose 32-byte
                                           // signer_id is that Delegation's id verifies (17.9's verify)
}
message BridgeShareKey { bytes share_id = 1; bytes public_key = 2; }   // the pinned ShareKey, Ed25519
message Pending {                         // legacy -> pending
  bytes network_id = 1;
  bytes genesis_sha256 = 2;
  bytes sidecar_id = 3;                   // this sidecar's, which the sign-out edge above checks
  bytes identity_public_key = 4;          // its identity key, Ed25519, under which that SidecarRevoke verifies
  bytes forward_delegation_id = 5;        // on an app, the forwarding Delegation this component's keys are
                                          // named in (§18.6's setup; owner decision 197)
}
```

**Disposition** (D-BRIDGE-7):

| Change | Sender | Provider |
|---|---|---|
| Revocation (revoked or expired grant, the subject's `SidecarRevoke` or suspension, rejected route, `--reset`) | Reset at once: pins to a revoked advertiser drop, and an entry left with no advertiser answers its packets with an RST or prohibited reply for 600 s, then leaves | `CloseFlows` after the policy swap, dials in progress included (17.6) |
| Edit (withdraw, retarget, advertiser or health change, new address or block) | Drain under 17.5's pins: while the table has room no live pair leaves a link that still serves it, and a removed advertiser or old address drains as 17.5's `removed` row sets (`drain_seconds` 300 s by default, 3,600 s at most); new pairs take the new rule, as do new TCP connections of pairs pinned to a draining link, but new UDP and ICMP pairs follow the pre-change link through 17.5's window; a full table refuses nothing | A removed route or old address stays compiled, draining and admitting flows, for max(`drain_seconds`, 600 s), and a retargeted map keeps only the flows it opened; then the engine drops it, swaps the policy and runs `CloseFlows` on its tags, for an old hosted address that address's alone (17.6's `RuleTag`), so flows opened to the host's new address during the drain live on, while a `GrantRevoke` still ends the subject's flows under every rule the grant reached (owner decision 483) |

**After sleep or a clock step** (owner decision 789). `device.Bridge` acts on a rule's lapse, a map's or reach row's `expires`, a drain's end at max(`drain_until`, `draining_since` + 600 s) or the previous block's `previous_block_drain_until`, by publishing again at that wall-clock time and running `CloseFlows` on the tags that lapsed; its wait is a runtime timer, which stops while the system sleeps (`mach_absolute_time` on darwin, `CLOCK_MONOTONIC` on linux), so a device that slept past a lapse, or whose clock stepped forward, would keep that rule's earlier flows open past it, though `ResolveEgress`, which reads the wall clock, refuses new ones at once and revocations publish at once. `Bridge.CheckClock()` publishes at now, as run's timer does, and the platform layers call it when the device wakes and when its clock changes: `NEPacketTunnelProvider.wake()` on Apple's network extensions, `ACTION_TIME_CHANGED` and the screen-on and idle-exit broadcasts on Android, the power-resume notification on Windows and logind's resume signal on Linux. A desktop, which has no one wake signal Go reads portably, also caps run's wait at `BridgeSettings.ClockCheckInterval`, so it is late by at most that interval after it wakes; phones take no cap and add no periodic wakeups. So an expiry resets at once after sleep within one wake. It is built (bridge-wall-clock-wake, sidecar 0d6e6227, 1522911f, ef1c7b2a; sdk b07f4eb7): `ClockCheckInterval` is 30 s in `DefaultBridgeSettings` and 0 in `MobileBridgeSettings`, which iOS's and Android's bridges take, a negative one refused and a capped wait short of its time only reading the clock again; it caps the link manager's wait too, which a check also runs at now, as for a replaced link's drain to its window clients' `strict_exp`, and a link counts its age on the wall clock alone, so its rebuild before those clients expire follows the wall clock. ur daemon watches for its host's resume for its life, logind's `PrepareForSleep(false)` on the system bus on Linux and powrprof's suspend-resume notification on Windows, and checks every bridge it holds at each; where neither is to be had, on macOS, which tells no process of a resume, the cap covers the host. The sdk's `DeviceLocal.CheckClock`, `urnet_device_local_check_clock` in the C ABI, hands every bridge the device holds a check from any thread, the apps' calls to it coming with the app phase.

**The core's own ends** (owner decision 798). The sidecar core waits on the same kind of timer for wall-clock ends of its own: a `tls/` or `smtp/` stream's reset at its ticket's `grant_expire_time_millis` (§9.6's step 7), a daemon forward's close at its grant's expiry (17.9), a `ur share`'s end at its `expire_millis` (§9.9), and the forwarding role's next follow, compile and posture's overdue-alarm point (§18.10's memory row). Each owner takes the seam: a check, safe from any goroutine and never blocking, arms each wait again from the wall clock, the end fixed where it was admitted, and ends at once what lapsed. `SocketComponent.CheckClock` resets each listener's lapsed streams with `RST_REVOKED`, and `Sidecar.CheckClock` reaches it as it reaches every component that keeps a clock (`SidecarClockComponent`); `DaemonBridges.CheckClock` closes the lapsed forwards; `DaemonSockets.CheckClock` ends each hosted network's lapsed shares, resetting their streams, deleting their records and unlistening their names; and `Forwarder.CheckClock` does the point the device slept past, raising `narrowing_overdue` once for the newest, and arms the next. ur daemon calls the core's checks beside its bridges' at each resume, and alone every `ClockCheckInterval`, the interval its bridges cap their own waits by; the VPN component's `DeviceLocal.CheckClock` reaches each forwarding role's `Forwarder` and the role's refresh of its forwarding client (§18.6), which a desktop's role also checks every interval and a phone's never. Revocations still act at once, each edge refuses new work by the wall clock, and relative waits, timeouts and refreshes, stay as they are. It is built (core-wall-clock-wake, sidecar 4eca0452, e1cc7a97, a3b7cc46; sdk d5781686, eff09887). An app's own sidecar role, whose `tls/` and `smtp/` listeners run while the app is open (§13.17), takes a call of its own (owner decision 803): the sdk's `Sidecar.CheckClock()`, never blocking, calls the core's `Sidecar.CheckClock`, bound through gomobile and the C ABI (`urnet_sidecar_check_clock`) as `DeviceLocal.CheckClock` is, and the app calls it when it comes to the foreground and at a clock change, `NSSystemClockDidChange` or `ACTION_TIME_CHANGED`, beside its VPN component's `DeviceLocal.CheckClock`. Decided ahead of its code, which fix track sdk-sidecar-check-clock builds in the sdk, the apps' calls coming with the app phase; until then a new stream is still refused at its end, by its ticket's expiry at admission.

### 17.9 ACL, identity, egress, cross-network shares (C18)

- **Permissions** (§8.4): `route` on `ip:<cidr>`, `dial` on the subject for hosted addresses and maps, `autogroup:internet` via the exit, and per forward a requested grant (port, `expires`, 1 h by default; owner decision 74). §8's contract gate checks pairs, and the hook each flow by the principal a verified `WindowDelegation` names, checked against C13's seal (D-PROTO-19). `forward`, `expose`, `egress` and `invite` are outward actions under `Sidecar.Authorize` (§5, I-8) at every entry point, whose deltas carry the approval (§8.6), in a tainted run only by I-9's evidence (owner decision 142). Own-resource filings sign from any mode, MCP included (§5.8, §16.6): `bridge_forward` files a `GrantActivate` from its decision and returns its grant_id; `bridge_expose` a `BridgeRoute` or `BridgeMap` under a standing grant or its decision, a map preceded by this host's own `BridgeAddress` where the log holds none for it (17.4), and returns 17.8's rule id; `bridge_close(grant_id | rule_id)` a `GrantRevoke` of a forward's grant whose subject it is, or a `BridgeWithdraw` of this sidecar's own rule; `block`, `egress`, `invite`, `accept-invite` and `activate` sign only as D-CORE-13 allows.
- **Principals** (D-BRIDGE-17). C13's seal is the operator's statement, so a host admits a native flow only from a window client a customer key vouches for:

```proto
// bridge.proto; §6.9 Signed, purpose window-delegation, SignedType 0x1908; by the subject's
// identity key, the key of its live forwarding Delegation (owner decision 197; §7.9), or, on a share
// link, the ShareSigner its share_cert names (share signers, below)
message WindowDelegation {
  bytes network_id = 1;                // the source network
  bytes subject_sidecar_id = 2;
  bytes window_client_id = 3;
  bytes window_client_public_key = 4;  // the window client's ClientKey public key
  bytes target_sidecar_id = 5;         // the host this link reaches
  int64 not_after_ms = 6;              // at most the window client's strict_exp (§7.4)
  bytes share_id = 7;                  // set for a cross-network share
  bytes share_cert = 8;                // with share_id: the Signed ShareCert below
}
message ShareCert {                    // §6.9 Signed, purpose window-delegation, SignedType 0x1909, by the ShareKey
  bytes share_id = 1;
  uint64 config_generation = 2;        // g, the source network's config generation (§10.5)
  bytes signer_public_key = 3;         // g's ShareSigner, Ed25519
  int64 not_after_ms = 4;              // at most 7 days after signing
}
message BridgeShareSigner {            // Y's config file per accepted share; sidecar roles only, not in BridgeState
  bytes share_id = 1;
  uint64 config_generation = 2;        // g, as in share_cert
  bytes signer_seed = 3;               // g's ShareSigner: a fresh 32-byte Ed25519 seed
  bytes share_cert = 4;                // its Signed ShareCert
}
message BridgeShareGrant {             // X's config file bridge/share-grant/<share_id hex> (share pins, below)
  bytes share_id = 1;
  bytes grant_id = 2;                  // the share's GrantActivate; the file counts only while that grant is live
  bytes share_public_key = 3;          // Y's ShareKey, Ed25519
  bytes target_table_sha256 = 4;       // of the sealed target table as network_bridge_share stores it
  bytes table_key = 5;                 // K
  bytes accepting_network_id = 6;      // Y
  bytes alias_table_sha256 = 7;        // of the BridgeShareAccept X's approving admin opened
  uint64 target_table_version = 8;
  uint64 alias_table_version = 9;
}
```

```text
sign     BridgeHost gets one per window client it builds, signed by the subject's identity key where the
         sidecar role builds the link (a daemon), by its forwarding key in an app's VPN component (§18.6),
         or on a share link by a ShareSigner (share signers, below), and passes it in CreateContract; the
         contract signer copies it unchanged into StoredContract (C13); a companion contract's request
         carries none and its contract seals none, the delegation being the forward contract's alone
         (D-PROTO-19; owner decision 301)
verify   once per contract, before the first flow's dial: the signature, by the subject's identity key
         pinned through its SidecarAdmit and neither revoked nor suspended at this state, by the key of the
         subject's forwarding Delegation live at this state (§7.9's forwarding row: forward names the
         subject, and it is neither superseded, revoked nor void; a 32-byte signer_id is its delegation_id,
         verified only under that subject's BridgeIdentity.forward_public_key, never by trying keys), which
         the host denies again from the entry that revokes or supersedes it (§17.8's forwarding roles), or by
         a ShareSigner that share signers
         admit; window_client_id = the contract's source; window_client_public_key = the
         sealed session's peer key (C15); target_sidecar_id = this host; not_after_ms ahead; network_id =
         C13's sealed network; C13's sealed subject is among subject_sidecar_id's client_ids in the compiled
         rules, one map lookup, else deny: its current bound client and every id the compiler bound to it
         in the last 7 days, the longest a window client lives (§7.4), each binding verified against the
         subject's pinned identity key off the packet path; off that path the compiler looks a denied id up
         (GET /sidecar/identity?client_id=, §5.15) and adds it at its next compile if its binding names that
         subject, so an older generation's window client recovers on its next contract, alarming only if it
         names another sidecar or none; a share link skips this clause, keeping the signature, ShareCert and
         network_id checks
use      the principal {subject, network, share, not_after} rides that source's flows; the hook rechecks the
         subject, or a share's grant, against the state per flow (one lookup), so a SidecarRevoke, Suspend
         or share revocation denies it and CloseFlows ends its flows, and not_after_ms lapses it; a source
         without one is never passed by rule 4
target   the sender's link admits a contract only if destination_client_public_key is the target's current
         SidecarIdentityBinding client key, verified against its pinned identity key
         (GET /sidecar/identity/<sidecar_id>, cached per link), or for an app host the device client key its
         live forwarding Delegation names, which its identity key signed (§18.6's host row); on a share link
         the identity key is the one Y's BridgeAlias pinned for T_i's host (share pins, below)
cost     ~200 B (~350 B with a ShareCert) and one Ed25519 verification (~50 µs) per contract per link, and
         one per new ShareCert
```

- **Egress spec.** A subject's default route goes to an approved exit, or nowhere (app devices: `NetworkPeer` with `PostQuantumEncryption`, v1, §18); §8.10's gate refuses Public contracts under `exits` or `none`. Under `exits` that holds for IPv6, which no exit carries: `ur tun` takes the host's IPv6 default route too and the bridge answers IPv6 there through 17.5's rejects row, so a dual-stack host falls back to IPv4 and IPv6-only destinations are unreachable (owner decision 482), while each carved address the host reaches only by its default route keeps the host's own route in either family (17.11; owner decision 480).
- **Shares** (owner decision 86). X's `ur bridge invite` files §8.11's admin-approved share (a `route` or `dial` grant to `network:Y`) with a 256-bit code and seals its targets T_i (index, host `sidecar_id`, ports or prefix, and the host's identity public key) under K, which the code derives and the server, holding the code's hash, cannot (share seal, below). Y's `accept-invite`, approved by a Y admin, first claims the share by the code's hash, which binds Y to it and answers the share's id with X's sealed targets, then runs the preflight below, aliases each target with an equal-length A_i in Y's block (`BridgeAlias` deltas, each copying its T_i's host identity key, so Y's routers pin the host from Y's own signed log), reports `active` only once its own ledger shows each alias in force, planning again at the new tip if a concurrent accept took a block, and returns the aliases sealed under K with the accept's status, in a completion stored once (§8.11; owner decision 350): the accepting side's one sealed column holds a `BridgeShareAccept{aliases, share_key, shortfall}`, each field one seal under its own label, an active share carrying the aliases and the ShareKey and either refusal the shortfall alone, so the server still sees one opaque value (owner decision 475). Y routes A_i over a share link to T_i's host (resolved through §5's binding log), whose hook maps A_i to T_i, keeping host bits. Y's approving admin device also generates the share's Ed25519 ShareKey, which certifies a ShareSigner per generation of Y's config (share signers, below); its public key, sealed under K, reaches X, whose approving admin's device pins it, with K, in a `BridgeShareGrant` config file in the act that files the share's GrantActivate, `ur bridge activate` (share pins, below), and X's host verifies the `WindowDelegation`s those signers sign, while Y's routers and the contract gate (§8.10) enforce Y's grants: §8.11's intersection is these points. X's host checks the share and that the signer is one every current Y config reader holds, never Y's per-subject grant, so the intersection holds against a modified Y reader or a compromised operator, not both together: on an operator-minted contract, any current Y reader, one Y's policy denies included, reaches X's granted targets, within X's grant (17.12, 17.17). A target table never changes: other targets are another share. An alias ends by a `BridgeAlias` release from its signer or an admin, which drains it (DESIGN-DETAILS.md section 12).

```text
share seal (§8.11; api-9's tables)
K          HKDF-SHA256(code, salt x_network_id, info "urnetwork-sidecar-v1/bridge-share"), 32 B
sealed     nonce (24 random B a seal) || XChaCha20-Poly1305(K, nonce, body, ad), with ad =
           "urnetwork-sidecar-v1/bridge-share/" || label || 0x00 || x_network_id || y_network_id ||
           u64be(version): y_network_id is 16 zero bytes for targets, which X seals before any accept, and
           version is the table version network_bridge_share stores
labels     targets: BridgeShareTargets, each T_i's index, host sidecar_id, ports or prefix and host identity
           public key; aliases: BridgeShareAliases, each A_i by index with its host bits (the low 16 bits)
           and length; share-key: the ShareKey's public key; shortfall: refused_no_space's figures; proto3
           bodies in protocol/bridge, each padded by a bytes pad field to a multiple of 256 B
accept     the accept's seals ride together as BridgeShareAccept{aliases, share_key, shortfall}, the value of
           the accepting side's sealed column, whose whole SHA-256 X's pin names (owner decision 475)
open       a failed open refuses the share and alarms, with no fallback
holders    a multi-use code's accepters all hold K, so a seal proves only a code holder; X's approving admin
           is what pins one ShareKey to one share (share pins)
```

```proto
// sidecar/protocol/bridge/bridge.proto: the share seal's bodies, each sealed under K with its label and padded by
// pad to a multiple of 256 B, and the accepting side's sealed column
message BridgeShareTargets { repeated BridgeShareTarget targets = 1; bytes pad = 15; }   // label targets
message BridgeShareTarget {
  uint32 index = 1;                    // from 0, dense
  bytes host_sidecar_id = 2;
  bytes host_identity_public_key = 3;  // what Y's BridgeAlias copies (share pins)
  BridgeIpv4Prefix prefix = 4;         // a hosted address as a /32, or a served prefix
  uint32 protocol = 5;                 // 0 every protocol; 6 or 17 with ports
  repeated BridgePortRange ports = 6;
}
message BridgeShareAliases { repeated BridgeShareAlias aliases = 1; bytes pad = 15; }   // label aliases
message BridgeShareAlias {
  uint32 index = 1;
  uint32 alias_host_bits = 2;          // A_i's low 16 bits, since Y's block is not X's to know
  uint32 length = 3;                   // its target's
}
message BridgeShareKeyBody { bytes share_public_key = 1; bytes pad = 15; }   // label share-key
message BridgeShareShortfall {         // label shortfall: refused_no_space's figures
  uint32 index = 1;                    // the first target that found no room
  uint32 length = 2;                   // its prefix length
  uint32 free_address_count = 3;       // the upper /17's free addresses at the preflight
  uint32 largest_free_length = 4;      // the shortest prefix length with an aligned free block; 33 for none
  bytes pad = 15;
}
message BridgeShareAccept {            // the accepting side's sealed column, whose SHA-256 X's pin names
  bytes aliases = 1;                   // the sealed BridgeShareAliases; empty on a refusal
  bytes share_key = 2;                 // the sealed BridgeShareKeyBody; empty on a refusal
  bytes shortfall = 3;                 // the sealed BridgeShareShortfall, under refused_no_space alone
}
```

```text
share pins
X's pin    the config file bridge/share-grant/<share_id hex>, a BridgeShareGrant{share_id = 1, grant_id = 2,
           share_public_key = 3, target_table_sha256 = 4, table_key = 5, accepting_network_id = 6,
           alias_table_sha256 = 7, target_table_version = 8, alias_table_version = 9} that X's approving
           admin's device writes in a head in the act that files the GrantActivate it names, a config file as
           BridgeShareSigner is (§7.9): the accepting network's id and each table's hash and version, the
           alias table being the BridgeShareAccept that admin opened, so the ShareKey it saw is pinned with
           the aliases, and a host compiles the share only from tables that hash to them (owner decision
           475); table_key is K, which X's hosts need to open Y's alias table and map A_i to T_i; the
           compiler fills BridgeState.share_keys only from a file whose grant_id is a live grant
match      X's host matches a destination's low 16 bits against an alias's host bits and length, since Y's
           block is not X's to know and a block change in Y keeps them; if Y re-aliases a share, X's admin
           activates again (owner decision 475)
activate   ur bridge activate <share_id>, a Confirm daemon method bridge.activate beside bridge.invite and
           bridge.accept_invite (from control with the person's confirmation, never MCP; §5.8), shows Y's
           network, each target with its alias, the ShareKey's fingerprint and both tables' hashes, asks on
           /dev/tty, then activates on that preview, refusing anything that changed since; it stays apart
           from the invite, since another admin may approve (owner decision 475)
Y's pin    each T_i carries its host's identity public key, which Y's approving device copies into the
           BridgeAlias body, so Y's routers pin the host from Y's own signed log and the target row checks
           the host's binding against that key
```

```text
preflight  (D-BRIDGE-20) on Y's approving device before any BridgeAlias, since the server sees no prefix
size       aliases live in the upper /17 (17.4), so a target wider than /17 is refused_too_large
space      each A_i is a free aligned block of its target's length in the upper /17, overlapping no alias,
           exposed prefix (17.7) or host /32 spilled there, a /32 alias avoiding x.y.z.0 and x.y.z.255;
           none free: refused_no_space, the shortfall sealed under K
allocate   first fit from the upper /17's bottom, aligned, in one space with exposed prefixes, while spilled
           hosts take its top; overlapping /24 requests get disjoint blocks; a draining alias keeps its
           block until its drain ends
status     network_bridge_share.accept_status: active | refused_too_large | refused_no_space
```

```text
X: targets T_i, sealed under K --> server (§8.11 share; network_bridge_share) <-- Y: aliases A_i, ShareKey, sealed under K
X's host hook: FriendsAndFamily from Y, To in A_i -> T_i      Y's routers: A_i -> share link to T_i's host
```

```text
share signers (D-BRIDGE-17)
ShareKey     an owner-bound `secret` of Y's approving admin (§11.12), as §13.8 keeps an account key, never in
             the config, so it reaches only §8.5's readers of that secret; it signs only ShareCerts
ShareSigner  at accept, and whenever a ShareKey holder that writes the config sees a newer generation g of
             Y's config (§10.5), the holder replaces the share's BridgeShareSigner {share_id, g, a fresh seed,
             its ShareCert} in a config head at g, unless it already names g, and replaces it again, with a
             fresh seed and cert at g, when the cert has under 3 days left, unprompted as §7.9's folds are:
             every cert certifies a seed of its own, so one seed rides one file, in a head sealed at the
             generation its cert names, and a renewal that §10.6's gate refuses is dropped and made again at
             the new generation (DESIGN-DETAILS.md section 12); §10.6's write gate takes a write at g only
             while g covers the config's holders_shrunk_at, so a sidecar that has stopped reading Y's config
             gets no later signer or cert; a ShareSigner signs only share-link WindowDelegations
file         a BridgeShareSigner is a config file, not a statement, with no Signed or SignedType of its own:
             only config writers' heads change it, as with K_sock (§8.8), and their signatures cover it; a writer
             without the ShareKey cannot certify, so X refuses its signer; a Y sidecar signs with one only
             while its share_id, g and seed's public key match its cert
keys         the ShareKey and ShareSigners, Ed25519, sign §6.9 Signeds in the sidecar role's bridge_*.go,
             beside §5.4's identity-key Sign: signer_id = share_id, key_id = SHA-256 of the signing public key;
             verifiers require signer_id = the body's share_id and resolve key_id, a ShareCert's to the
             share's pinned BridgeShareKey and a share delegation's to its ShareCert's signer_public_key
sign         a Y subject signs with the share's current BridgeShareSigner while its cert is unexpired; when
             that file changes, the compiler that reads it, a daemon's sidecar role or an app's forwarding role
             (§18.6), has BridgeHost re-sign each share link's delegations, which their next contracts carry
admit        X's host requires the ShareCert to verify under the pinned ShareKey with the delegation's
             share_id, not_after_ms ahead and at most 7 days away (§8.6's 60 s skew), and g at least the
             share's newest verified generation, which it raises and keeps in 17.8's persisted state, then the
             delegation under signer_public_key; the principal's not_after is the earlier not_after_ms; a g
             above the share's newest is committed to the persisted posture store before the contract that
             carried it is admitted: one commit per share per rotation of Y, a few milliseconds in that
             contract's VerifyPrincipal sequence before the dial, never a packet's, a flow's or a later
             contract's (R-BRIDGE-9), so a removed sidecar stays refused after a host restart (owner decision
             476)
bound        a sidecar Y removed is admitted on new contracts until a later generation's ShareCert reaches the
             host in any Y delegation, at most 7 days after its removal reaches evs, and those it opened run
             to their end (at most 60 min, server/model/subscription_contract_expiration.go:14); with no
             renewal for 7 days the share lapses for everyone; a reaped Delegation-admitted agent signs while
             it reads Y's config (§10.5); a removed holder device, or a holder member leaving the AdminSet, can
             certify until X revokes the share, so Y's devices raise a SidecarEvent naming it, and X re-invites
```

- **Isolation.** Only sidecar-owned Required hosts holding a share grant turn `FriendsAndFamilyEgress()` on; sdk providers never do. The principal's verified share and network, never an address, select the aliases, which resolve only to that share's targets through maps, dialable hosted addresses and served prefixes: never rule 4, rule 0's listeners, unmapped loopback, another host's address or an exit (owner decision 11). NAT state is per source path and 5-tuple (connect/ip.go:2072-2098), so foreign flows share no entry with local ones; replies carry the alias back unrewritten. Foreign flows are shed first under NAT pressure. Reach events name the source network (§16).

**Enclaves' egress** (owner decisions 737, 739; DESIGN-COMPUTE.md §11.8). An enclave's network is its sidecar's, set by `ur`: default egress on, to its mode's destination, `auto`, `exits` or `none`, the mode its subject's `BridgeEgress` statement, which its sponsor files with `ur enclave egress`, an `egress_change` action; at create the network's mode for `tag:enclave` where a policy sets one, else `auto`, and a network that requires default egress for `tag:enclave` holds it on (owner decision 607). Default egress off, `direct`, sends traffic out the provider's own network from the miner's address, allowed only by `enclave_egress_direct`, an outward action each time, recorded. Inside the VM the enclave's init installs fail-closed nftables rules: no inbound on the host interface but replies, outbound only the daemon's own marked transport and, under `direct` alone, everything else, so no process routes around the tun and agents cannot change them; outbound TCP 25 is refused in every mode.

### 17.10 Placement, sdk seams, apps, hosts

| Repo | Change |
|---|---|
| connect (X9) | §4.6's C5, C6a, C13 and C14 (M4), C15's key (M1), C16 before app devices host, C18 for shares (M6); not C6b, since providers terminate flows without a tun; and, default off, an egress mark on Linux for `ur tun`'s exits (17.11): egress_linux.go's `SetEgressMark` sets SO_MARK at every dial site connect's egress machinery covers, which egress_dial_sites_test.go audits, and the extender carrier's socket (`openExtenderPacketConn`, which the alt api path and the QUIC and DNS carriers share) and the provider's ICMP egress off Windows join that machinery, so the mark, and on Windows the interface pin, reach them (owner decision 479) |
| sidecar | Root `bridge_*.go`: statements, the compiler that builds `BridgeState`, forwards, and forwarding's setup and signer, the compiler and signer also linked into apps' VPN components among the root's forwarding files (§18.10). `device/` (`device.Bridge`, D-SDK-20): table, pins, links, `BridgeEgressPolicy`, principals, aliases, routes, the per-link resolver and zone with §12.9.1's DNS-SD answers, 17.5's IPv6 translator, and 17.8's states, importing connect and `protocol/bridge` only; the root holds 17.7.1's watches and shares, and `cli/` its gatherer and advertising proxy, macOS's through purego. `cli/` wires `device.Bridge` to the root's state producer for `ur tun` and `ur bridge` and holds `ur tun`'s OS tun (`golang.zx2c4.com/wireguard/tun`, MIT) and the userspace stack, out of every sdk binding (Q-SDK-5); on Windows `ur tun` neither bundles nor fetches wintun.dll: it loads one beside `ur.exe` or at the installed app's path only once its SHA-256 and Authenticode signer match windows/app/tools/fetch-deps.ps1's pins (0.14.1), since it runs elevated, and otherwise prints where to get it, so the release zip holds no DLL (owner decision 222); the SHA-256 is the DLL's, exact per architecture, which the owner records beside the zip's pin from a Windows run of that script (`$WintunDllSha256Amd64`, `$WintunDllSha256Arm64`) and `ur tun` carries, beside WinVerifyTrust and the script's signer thumbprint, refusing every DLL until they are recorded (owner decision 481) |
| sdk | Both insertion points and the exit-NAT hook through §18.6's `deviceBridge`; `DeviceLocal` implements `BridgeHost`; route export (§18); in every app's VPN component, forwarding's following, compile and signing on its forwarding client (owner decision 197; §18.6) |
| server | No rule tables; `network_bridge_share`; gates read `BridgeRows`; the forwarding client's `forward_only` mark (§7.4) |
| apps | Out of scope (owner rule 6): running forwarding in every VPN component, always on, and applying exported routes, a chosen block included, are §18's app work |

```go
// device (sidecar/device); implemented by sdk DeviceLocal and the CLI host, which own the client generators
type BridgeHost interface {
	// one link per target (Q-BRIDGE-2); shareAliases is nil for a same-network link (ProvideMode_Network),
	// and for a share link (FriendsAndFamily) lists the aliases C18's source half may carry; sign returns
	// the Signed WindowDelegation for each window client the link builds, not_after_ms at most notAfter, the
	// client's strict_exp (§7.4), and on a share link the host calls it again for each live one when its
	// compile finds a new BridgeShareSigner, for its later contracts (17.9)
	NewBridgeLink(ctx context.Context, target connect.Id, subject connect.Id, shareAliases []netip.Prefix,
		sign func(windowClientId connect.Id, windowClientPublicKey []byte, notAfter time.Time) ([]byte, error),
	) (connect.UserNatClient, error)
}
```

**Device abstractions (PLAN.md:31).** `device.Bridge` satisfies §18.6's `deviceBridge`, `BridgeEgressPolicy` being its hook. In every app it runs in the VPN component as the forwarding role, with the root's compiler and its own forwarding key, whenever that component runs, with no setting that turns it off and no wait on the app (owner decision 197); under `ur tun` the daemon runs it, through `cli/`. On apps, sending, that is routes to other devices' addresses and subnets, forwards out and exits, needs no C16, since its links are Required window clients to sidecar-owned hosts or C16 ones; hosting, that is the device's own address, maps into it and its advertised subnet, waits for C16 on the device client's sdk provider, in that client's network only (D-BRIDGE-5, §18.6's host row).

### 17.11 cli/UI.md mapping

| Command or UI note | Meaning (v0 unless noted) |
|---|---|
| `ur tun` | OS tun `ur-<instance>` with the block and granted prefixes; the default routes, IPv6's too, only with default egress on and an egress destination, `--default-egress` and `--route-local` setting the person's two choices (below; owner decision 606); yields to an app bridge |
| `ur tun ip [<ip>\|auto]`; "client assign local ip" | Show or claim the address |
| `ur bridge`; "show all ips", "show all hostname:port" | Run the bridge; list addresses, private names, rules, forwards |
| `ur bridge expose <ranges>`; "client forward ip subnet" | Advertise subnets (a route) |
| `ur bridge expose :<port>[=<ip>:<port>]` (added); "client:port → ip:port" | Map this client's port |
| `ur bridge forward client:port[:local ip]:local port`; "client:port → client:port" | Listen on all interfaces unless `--listen` narrows it (owner decision 84); dial over the userspace stack under a §8 grant |
| `ur bridge egress auto\|<exit>\|tag:<t>\|none [--require-default-egress]` (added); "client egress spec" | The default route; under exits alone, `--require-default-egress` has the subject's devices keep default egress on (below; owner decision 607) |
| `ur bridge block [cycle\|<cidr>]` (added; admins) | Re-roll or choose the block (17.4; owner decisions 28, 132) |
| `ur bridge invite`, `accept-invite` | Cross-network port and subnet shares (17.9), v1 |
| `ur bridge activate <share_id>` (added; the sharing network's approving admin) | Show an accepted share and activate it (17.9's share pins; owner decision 475), v1 |
| `ur bridge devices [--json]` (added) | This host's LAN devices that discovery finds, shared or not, and the instances this device sees from the network's hosts, each with its address and why any is withheld (17.7.1), v1 |
| `ur bridge share <device>`, `unshare <device>` (added) | Publish a LAN device to the network's hosts that may reach it, filing its /32 route where none serves it, confirmed on /dev/tty (17.7.1; owner decision 778), v1 |
| `ur bridge discovery on\|off`, `hide\|unhide <instance>`, `proxy on\|off` (added) | Publish Bonjour names for this device's own services and listed entries or not, the Listeners section listing the entries still; hide one, in the hide set `ur listeners hide` also writes, `unhide` confirmed on /dev/tty (§5.8); and run the advertising proxy or not (17.7.1), v1 |

Without an active grant, these commands print the approval prompt and wait (§16.6); `forward` warns that it serves every host reaching the listener. `ur bridge public-tls` is §13's.

```text
ur tun's default routes (owner decisions 479, 480, 482, 606, 607)
choice   (owner decision 606) two per-network settings of the device that ur tun sets and shows: default
         egress, on unless the person turns it off, whether the host's default traffic goes to the egress
         destination through the tun; and route local traffic, on by default as the sdk's DefaultRouteLocal is,
         its counterpart of the sdk's routeLocal; with default egress on, ur tun takes the default routes, both
         families, by the rows below when the client has an egress destination: under exits an exit of the
         network it can use, under auto the connect client's destination; with no destination and route local
         traffic on, default traffic stays on the host's own default routes and the tun carries only the block,
         the granted prefixes and private names, and with route local traffic off the tun still takes them and
         refuses that traffic, failing closed; with default egress off, default traffic stays on the host's
         routes in every mode; a change of either setting, or a destination that comes or goes, re-applies the
         routes without restarting the tun; the egress mode stays the admin's policy for traffic that enters
         URnetwork (§8.10)
lock     (owner decision 607) under exits, a network's admin, owner or sponsor may require default egress on,
         in the BridgeEgress statement's exits body, sealed with it (require_default_egress, 17.8), so servers
         learn nothing new; a device whose network requires it keeps default egress on for that network, and
         ur tun shows the lock and refuses --default-egress=off, naming the requirement; with no exit, route
         local traffic still decides; ur bridge egress files it through an egress_change action whose
         require_default_egress = 41 its approval shows and binds (§16.8)
linux    the daemon's own transport stays off the tun by fwmark policy routing: its sockets carry connect's
         egress mark M (17.10), and ur tun puts the default route in its own table T with wg-quick's rules,
         not fwmark M lookup T and lookup main suppress_prefixlength 0, carving nothing by the platform's
         addresses; SO_MARK needs CAP_NET_ADMIN, which ur tun already requires; until connect's mark lands,
         ur tun installs no default route under exits and says so
strict   where rp_filter is strict (1) on all or on the interface of the main table's default route, ur tun
         holds the exits, putting nothing on, and says so with the fix (rp_filter 2, systemd's default),
         trying again at each sync; ur changes no host security setting, firewall rule or global sysctl a
         person did not choose, and wg-quick's src_valid_mark and connmark recipe is a later task of its own
carve    each carved address (17.4) the host reaches only by its default route keeps the host's own route:
         a throw route in T on Linux; on macOS and Windows, where the exits ride IPv4's halves (0.0.0.0/1,
         128.0.0.0/1), a host route through the default route's gateway and interface, as wg-quick on macOS
         and WireGuard for Windows route an endpoint's /32, an address an on-link or local route reaches
         taking none; the routes follow the carve and the default route at each sync and leave with the
         exits, adding nothing by the platform's addresses, so the host's own DNS to an off-link resolver
         leaves outside the exits, as the carve already accepts for apps
ipv6     ::/0 goes through the tun too, with IPv6 copies of the two rules on Linux and the platforms'
         equivalents beside the IPv4 halves on macOS and Windows, and the bridge rejects IPv6 there (17.5);
         the carve's off-link IPv6 addresses take IPv6 throws, or IPv6 host routes through the IPv6 default
         route's gateway, as IPv4's do; the daemon's own IPv6 sockets keep the mark, so its traffic leaves
         by the host's route
```

**Listeners** (owner decision 770; DESIGN-COMPUTE.md §26.4-§26.6). The bridge also lists its host's listeners, from its OS's socket tables and its own state, publishes them to the network's `listeners` repo and answers `LISTENERS`, and `ur listeners` sits beside `ur bridge`; on an app the sidecar role publishes the forwards its VPN component reports. On a `ur daemon` host each listed `socket` and `map` entry of a known type also takes a Bonjour name, an own instance of 17.7.1's discovery that only its host's watch answers, per viewer; `ur listeners label <port>[/udp] --type <service>|none` sets that type, and `ur listeners hide` writes the hide set `ur bridge discovery hide` writes (owner decision 778). 17.7.1's **Listeners and discovery** says how the two divide, `ur listeners` and `Listeners()` beside `ur bridge devices` and `GetDiscovery`.

### 17.12 Alternatives considered

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Routing inside the multi client (a `RouteOverride`) | One place | After the mux; per-packet evaluation; reaches the IpAssoc cluster (connect/ip_remote_multi_client.go:7384-7395) | Rejected |
| Per-packet rewrite: in `clientReceiveAdmitted`, or of aliases at the sender | Any protocol; no alias table at hosts | Port-aware rewrite both ways, a copy per packet (connect/ip.go:10316-10335) | Rejected: the hook maps once per flow |
| Cross-network forwards over §9 streams | No foreign packets in provider NATs | No subnet invites; a second data plane | Not chosen (owner decision 86) |
| App devices as targets now (Opportunistic) | Phones and app desktops host at once | Replies can cross relays in plaintext (connect/transfer_encrypt.go:477-483) | Ruled out by the owner directive until C16 |
| Trust C13's sealed subject at hosts | No signature per contract | The platform holds the HMAC key: a breached server mints any subject | Rejected (D-BRIDGE-17) |
| One ShareKey every Y reader holds, rotated on removals and re-pinned at X from Y's update | No admin key or renewal | A removed sidecar holds the old key, so it signs a successor of its own, which the operator can deliver first | Rejected: an admin's ShareKey certifies per-generation signers (17.9) |
| X verifies Y's per-subject grant: a ShareKey-signed list of Y's granted subjects with their identity keys at each change to Y's grants, each delegation signed by its subject's own key | The intersection holds against a modified Y reader and a colluding operator together | The ShareKey holder re-certifies at every change to Y's grants; X pins a list per change and learns who in Y may reach it; delegations lose the per-generation signer that spares X Y's identity log | Not chosen: Y's current config readers, with Y's routers and the contract gate, are the unit for Y's half, disclosed (17.9, §8.11; meta review CC-05) |
| Bootstrap from the unverified projection's `has_document` | Opens at once after a restart | A forged `has_document = false` reopens a LAN | Rejected (D-BRIDGE-18) |
| A pin per 5-tuple flow, a full table refusing; or the pre-edit table for TCP non-SYN segments through a drain | Exact per flow; no pair state | 1,024 slots holding UDP 5 min cap a phone near 3.4 new flows/s; a new connection's SYN and later segments split across links, and a provider drops a non-SYN segment it has no flow for (connect/ip.go:4659-4687) | Rejected: pair pins where an entry offers a choice (17.5) |
| Reflecting raw mDNS between hosts, as Avahi's reflector does | Every app and type works unchanged | Needs an exception to rule 5; shows every LAN device's name network-wide; loops and storms; carries LAN addresses that other hosts often cannot reach | Rejected (owner decision 778) |
| A Discovery Proxy each host serves as DNS over the overlay (RFC 8766 as written) | Standard clients query it directly | Rule 0 refuses the daemon's own listeners over the overlay (D-BRIDGE-19) | Rejected: the watch over §6's RPC (17.7.1) |
| Per-viewer DNS-SD records as files in a network-wide evs repo, each host writing what every viewer may reach | Works while the host is offline | A repo's readers are fixed by its kind, never by each viewer's reach, so every reader would hold every record, a shared device's name included, unless each host wrote a file per viewer and sealed it again at every compile and LAN change; evs keeps when each LAN changes | Not chosen: each host answers each viewer's watch by its hook (D-BRIDGE-22). The `listeners` repo suits the listeners list, the network's whole list for every admitted sidecar by owner decision 770, each entry badged for its viewer; a DNS-SD name is an offer to connect, which a Bonjour browser makes for every name it lists, so it follows reach |
| Every LAN device published, or every type `_services._dns-sd._udp` enumerates | No act needed; nothing missed | Other people's devices named network-wide; casting, AirPlay and HomeKit types useless off their link | Rejected (Q-BRIDGE-9, Q-BRIDGE-10) |
| A port map per advertised service | No route | Xcode's tunnel uses a port the iPhone picks per connection | Rejected for devices: a /32 route (17.7.1) |
| Listed entries under one generic type, `_ur-listener._tcp` | Every listed entry shows, whatever it serves | No Bonjour client browses that type, so Finder, Xcode and print dialogs find nothing new, and a name says nothing of what it serves | Rejected: the person's label or the port's curated type (17.7.1), as DESIGN-COMPUTE.md §26 answers it |
| One RPC for both: the watch carrying the listeners list, or `LISTENERS` the DNS-SD view | One message pair | The listeners list is the whole network's, so it rides the control class without reach, while a watch answers only what reach admits; an instance has no field for an entry's kind, bind, description source, end or `shared` mark; one list answered two ways could disagree | Rejected: two pairs (17.7.1, §6.11) |

### 17.13 Decisions proposed

**D-BRIDGE-1 (proposed).** The bridge reuses connect's client-to-provider NAT path: sender routing, a per-flow provider decision, one hop. *Why:* PLAN.md:115-117; targets need no tun or root.

**D-BRIDGE-2 (proposed).** The router sits before the mux behind `deviceBridge` (17.5); the CLI shares it. *Why:* all device egress passes there.

**D-BRIDGE-3 (proposed).** Fail closed: the block is a deny backstop; providers serve only sealed flows, never dial another host's address and, with an ACL document, open private destinations only by rule. *Why:* R-BRIDGE-10, R-BRIDGE-12.

**D-BRIDGE-4 (proposed).** The C5 hook applies 17.6's order, relying on C6a, C13, C15 and, for shares, C18 (17.10). *Why:* once per flow; a nil hook changes nothing.

**D-BRIDGE-5 (proposed).** Links run Required to a fixed target with one window client, relay-only until C3, never count-capped; targets are sidecar-owned until C16, after which an app device hosts on its device client's sdk provider, in that client's network only. *Why:* D-PROTO-6, D-PROTO-10; owner decisions 66, 197.

**D-BRIDGE-6 (proposed).** Bridge rules are signed config-repo statements, sidecars' own as sealed deltas in the authorization log; gates see only reach rules and `BridgeRows`, applying an egress statement's clear mode in log order, and a requested grant's prefixes and ports ride sealed in its CanonicalAction (owner decision 220). A fold freezes each statement's body-level verdict, judged on the state its entry lands on, into the config head's bridge ledger, which every full reader standing there checks, and a body sealed above every formed generation is frozen void after `UnformedVoidWait` (17.8; owner decisions 473, 478). *Why:* owner decision 5; no prefixes, addresses or ports reach the server (I-4); every reader at one pin must hold one ledger, and a compile must not grow with the log.

**D-BRIDGE-7 (proposed).** Revocations reset both ends at once. Edits move no live pair off a link that still serves it while the pin table has room, and drain a removed advertiser or address for max(`drain_seconds`, 600 s) for TCP and max(`drain_seconds`, 5 min) otherwise. New pairs take the new rule, as do new TCP connections of pairs pinned to a draining link, but for 5 min after an entry first offers a choice new UDP and ICMP pairs, which cannot be told from live ones, follow the pre-change link. Pins key on the rendezvous pair, exist only where an entry offers a choice, and a full table leaves a pair unpinned, refusing nothing (17.5). *Why:* revocation is a security event; an edit should not break live TCP; owner decision 66 allows overload protection, not count caps.

**D-BRIDGE-8 (proposed).** An identical advertisement is an approved HA replica or remap; nesting is allowed; other overlaps are refused. *Why:* LAN prefixes repeat across sites.

**D-BRIDGE-9 (proposed).** HA is active-active by weighted rendezvous over healthy advertisers; a down mark removes a link from the hash only while another advertiser is up, and moves no pin. *Why:* NAT keeps flows symmetric; nothing waits on the server; one timed-out connect must not cut a route's live flows.

**D-BRIDGE-10 (proposed).** A forward listens on 0.0.0.0/:: unless `--listen` narrows it, under a requested grant, disclosed as LAN-exposed. *Why:* owner decision 84; D-TRUST-8.

**D-BRIDGE-11 (proposed).** Hosted devices (sdk/device_local.go:893-910), URnetwork-run WireGuard proxy clients, the extension worker and isolated clients (server/connect/resident.go:4790-4793) never route, host or serve. *Why:* I-10; js has no raw sockets.

**D-BRIDGE-12 (proposed).** The sdk exports hosted addresses, granted prefixes, aliases and an RFC 1918 block, minus every local /32 the physical path needs (interfaces, gateways, system resolvers), and per-peer /32s instead of the block while those are unknown, for apps to capture. *Why:* apps exclude RFC 1918, Apple's overlap semantics are undocumented ([R:connect-ip] §2.6), and a captured carrier resolver black-holes DNS.

**D-BRIDGE-13 (proposed).** 17.9's egress spec sets a subject's default route, enforced at §8.10's gate. *Why:* R-BRIDGE-7 must survive a compromised agent sidecar.

**D-BRIDGE-14 (proposed).** C18 reaches the hook only on sidecar-owned Required hosts holding a share grant, which map foreign flows by the principal's verified share and network to that share's targets only (17.9). *Why:* owner decision 86; isolation must not rest on addresses.

**D-BRIDGE-15 (proposed).** The accepting network aliases shared hosts and prefixes in its own block; both tables travel sealed under the invite code's key. *Why:* blocks and LANs repeat across networks; the server learns no addresses.

**D-BRIDGE-16 (proposed).** `ur bridge block` refuses a block outside 100.64/10 and RFC 1918, readers keep the previous block and alarm on a head carrying one, and renumbering keeps host bits; an overlap no carve resolves (17.4) is fixed by cycling, readers keeping the previous block until a head carries a valid one. *Why:* owner decision 132; a CLI check binds no other signing tool.

**D-BRIDGE-17 (proposed).** A host admits a native IP flow only from a window client whose customer-signed `WindowDelegation` it verified against the subject's pinned identity key, the key of the subject's live forwarding Delegation (owner decision 197) or, on a share link, a ShareSigner of the source network's newest certified config generation, which the share's pinned ShareKey, kept in the approving admin's `secret`, certifies for at most 7 days, each cert certifying a fresh seed, the host committing a raised generation before it admits (owner decision 476); C13's seal serves only as a consistency check (17.9). *Why:* C13's seal is the operator's statement, and a sidecar its network removes must stop signing within a bound, which no key every reader keeps allows.

**D-BRIDGE-18 (proposed).** Only a verified state opens a private destination: the engine and the forwarding role run 17.8's legacy, pending and enforcing states, persisted, never lowered by unsigned input (§18.6), and a daemon's start replays every judged denial before its provider is built (owner decision 474). *Why:* a restart plus a forged `has_document = false` must not reopen a LAN, nor a restart drop a denial only a judge could decide.

**D-BRIDGE-19 (proposed).** A provider never dials its own daemon listeners, document or not (17.6's rule 0). *Why:* owner decision 120 opens LAN and loopback destinations, not the sidecar's own control and content plane.

**D-BRIDGE-20 (proposed).** Hosts draw from the lower /17 and aliases fill the upper /17 first-fit (17.4), so a share is refused, before any flow and with its reason in `accept_status`, only when it is wider than /17 or the upper /17 has no aligned room for it (17.9). *Why:* a /16 cannot alias a /8 or itself, and random host /32s across the whole block leave few free aligned blocks (about 5 free /24s among 1,000 hosts).

**D-BRIDGE-21 (proposed).** A revocation swaps the provider's policy before `CloseFlows`, and a flow registers its rule and policy generation before its dial and re-checks it before its first byte (17.6); the engine's order is commit, publish, close, with every denial held at its own log position (17.8's engine). *Why:* a dial can outlast the reset that should have ended it.

**D-BRIDGE-22 (proposed).** Service discovery crosses hosts as DNS-SD records each `ur daemon` host gathers from its own link and answers to each other host's watch, over §6's RPC on a data-class contract, with the instances its hook would let that viewer reach; no mDNS packet crosses a link, and no server stores a record (17.7.1; owner decision 778). *Why:* the policy decides who sees what at the point that decides reach; rule 0 refuses DNS at the daemon over the overlay, and rule 5 stands.

**D-BRIDGE-23 (proposed).** A host publishes its own services, those its mDNS announces and its listed entries of a known type, at its overlay address, and only the LAN devices its person shares, at the address their route serves, never a link-local address, IPv6 or an address it does not serve; viewers keep only addresses their host serves by the config (17.7.1). *Why:* discovery opens no reach, other people's devices are named only by their person's act, and no host can point viewers elsewhere.

**D-BRIDGE-24 (proposed).** Sharing a LAN device gives it a /32 route under an exposed /32, approved as an `expose`, unless a served prefix already covers it; a move out of that route withdraws it, and a new address takes a new approval (17.7.1). *Why:* a device's debugging tunnel uses ports it picks per connection, and an address the device leaves can pass to another device.

**D-BRIDGE-25 (proposed).** The advertising proxy registers each instance a viewer keeps on the viewer's own machine alone, LocalOnly in mDNSResponder on macOS and on `ur tun`'s link on Linux, under a target name no LAN host holds, and a host never publishes what a watch brought (17.7.1). *Why:* multicast-only apps, Xcode among them, browse `local.`; nothing may reach the viewer's LAN or loop back into the network.

**D-BRIDGE-26 (proposed).** `ur tun` gives each instance the advertising proxy registers an IPv6 address that embeds its IPv4 one in a ULA /96 of the device's own, translated statelessly at the sender (RFC 7915) to and from `<block>.0.46`, which a host's `Deliver` takes as a source that holds no overlay address, giving each such flow `<block>.0.1` and a port of its own; no other IPv6 enters the overlay (17.5, 17.6). *Why:* Apple documents Xcode's device connections as IPv6 alone, and the overlay carries IPv4 alone; every viewer's translated flows share one source address, which a host's tun would mix.

**D-BRIDGE-27 (proposed).** With DESIGN-COMPUTE.md's listeners, a `ur daemon` host, an enclave's included, publishes each `socket` and `map` entry of its listed set whose type its person's label or its port gives, in the effective list, as an own instance named `<description> :<port>`, which only its watch answers, per viewer by its hook, and the `listeners` repo never carries; one hide set, keyed by protocol and port at the host's overlay address, else by instance, serves `ur listeners` and discovery alike, `unhide` a Confirm method; `LISTENERS` stays on the control class and the watch on the data class (17.7.1; owner decisions 770, 778). *Why:* a Bonjour browser offers to connect to every name it lists, so names follow each viewer's reach, while the listeners list is the whole network's; one hide must hide a service from both views; a DNS-SD instance cannot carry an entry's kind, bind, description source, end or `shared` mark.

### 17.14 Open questions

**Q-BRIDGE-1.** [X18] Which range carries overlay addresses? **Decided by owner 2026-11-03 (owner decision 28):** IPv4 only, a random /16 per network from 100.64.0.0/10 after C6a, which admins may cycle or replace (17.4). *Residual:* none; Q-BRIDGE-7 bounds the choice.

**Q-BRIDGE-2.** How do links reach targets? **Closed by peer review 2026-11-04:** (c). One `BridgeHost` link per target, as a fixed `ProviderSpec{ClientId}` multi client with window size 1 (`FixedWindowSize: 1`), `PostQuantumEncryption` Required, `OverrideAllowDirect=false` until C3, and `EnableIcmp`; not `DefaultMultiClientSettings`, whose six-client quality window (connect/ip_remote_multi_client.go:217-234) is the wrong default and six times the memory. Each window client carries the subject's customer-signed `WindowDelegation` into C13's seal, which the provider verifies (D-BRIDGE-17). Option (b), a link on the subject's own client, is adopted only where §22.9 measures per-target memory over §18.4's iOS budget and the new framing passes fragment, reply-filter and lifecycle tests; the iOS tunnel is the first candidate and runs no link until measured (owner decision 100). *Residual:* none.

**Q-BRIDGE-3.** Should upgraded providers refuse private destinations to Network sources unless a rule allows them? **Decided by owner 2026-11-03 (owner decision 50):** only with an ACL document; without one, untagged sidecars keep today's reach (17.6 rules 3-4; owner decision 105), which owner decision 120 keeps and discloses (Q-TRUST-7). *Residual:* none.

**Q-BRIDGE-4.** Do overlay addresses get private names? **Decided by owner 2026-11-03 (owner decision 85):** yes, in v0: `<client-name>.<net>.<root>` from the config repo, answered on the device by C14 or `ur tun`'s resolver, never forwarded or published (§12.9). *Residual:* none.

**Q-BRIDGE-5.** Which bind do forwards and local listeners use? **Decided by owner 2026-11-03 (owner decision 84):** 0.0.0.0/:: unless `--listen` narrows it (cli/UI.md:11), forwards disclosed as LAN-exposed (D-TRUST-8). **Decided by owner 2026-11-04 (owner decision 130):** off loopback, git over http, IMAP and SMTP submission serve only TLS, git also ssh, and plaintext stays on 127.0.0.1 and ::1 (I-17); port forwards, which carry the user's own protocol, are unaffected. *Residual:* none.

**Q-BRIDGE-6.** Cross-cutting (§8, §9). Which data plane carries forwards and invites? **Decided by owner 2026-11-03 (owner decision 86):** the IP path for all, cross-network included, with C18 (17.9). *Residual:* none.

**Q-BRIDGE-7.** Cross-cutting (§18). May a chosen block lie outside 100.64/10 and RFC 1918? **Decided by owner 2026-11-04 (owner decision 132):** (b), no: only 100.64.0.0/10, 10/8, 172.16/12 or 192.168/16, narrowing owner decision 28's "any /16" (D-BRIDGE-16). Public exits refuse RFC 1918 today (connect/ip_security.go:897) and 100.64/10 after C6a, so overlay traffic never reaches the internet; any /16, or adding 198.18.0.0/15, was not chosen. *Residual:* none.

**Q-BRIDGE-8.** Cross-cutting (§18). Does an app device claim its overlay address when its forwarding is set up? Owner decision 197 makes the device's overlay address part of its always-on forwarding, while 17.4 assigns one on demand. **Decided by owner 2026-11-15 (owner decision 484):** (a), on demand, as 17.4 says: in the app's UI, by the host's first map, or by an admin. Forwarding's setup files no `BridgeAddress` of its own, and the address it names among the VPN component's forwarding is the one the device holds once it has claimed it, so no app device's loopback opens to the network's untagged sidecars (17.6's rule 3 with no ACL document; owner decision 120) because its forwarding was set up; (b), filing at setup, can follow later with one statement at the next setup, and hosting waits for C16 either way. *Residual:* none.

**Q-BRIDGE-9.** Is service discovery on by default for a host's own services, for its LAN's devices, and for the advertising proxy, each separately? **Decided by owner 2026-11-24 (owner decision 778):** (a), the recommendation, under the owner's standing acceptance of recommended options: a host's own services are published from the release, its person told first and able to turn them off or hide one, since they are named only to devices the policy already lets reach them; a LAN device is published only once its person shares it, since its name and model belong to whoever uses it; and the advertising proxy runs wherever the device can send into the overlay, since Xcode's use case needs it without a step (17.7.1). (b), everything off until the person turns each on, and (c), (a) with every LAN device published as found, were not taken. *Residual:* none.

**Q-BRIDGE-10.** Which service types does a host gather and publish? **Decided by owner 2026-11-24 (owner decision 778):** (b), the recommendation, under the owner's standing acceptance of recommended options: a curated default list, versioned in the sidecar repo and covering Apple's device types, which a network's ACL document widens with an allow list and trims with a deny list (17.7.1). (a), every type that `_services._dns-sd._udp` enumerates less a deny list, would name casting, AirPlay, HomeKit and companion devices network-wide, though none works off its link; (c), only the types a network's admins list, would leave every network without Xcode's types until an admin writes a policy. *Residual:* none.

**Q-BRIDGE-11.** How does the advertising proxy name a remote instance whose name and type are already in view on the machine? **Decided by owner 2026-11-24 (owner decision 778):** (a), the recommendation, under the owner's standing acceptance of recommended options: a remote instance keeps its own name where nothing in view has it, else takes `<name> (<client-name>)`; a local instance always wins its name, and the same device seen on the machine's own LAN is not registered again (17.7.1), so a remote instance never passes for a local one, and a client that keys on an instance's name finds it unchanged. (b), every remote instance renamed `<name> (<client-name>)`, would rename every remote device on every host. *Residual:* none.

### 17.15 Departures from PLAN.md

- **PLAN.md:117** ("from same network"): owner decision 86 extends maps to cross-network shares (Q-BRIDGE-6).
- **PLAN.md:353 with :359.** Relayed bridge bytes count (owner decision 10); P2P bytes after C3 do not (§20, Q-QUOTA-6).
- **PLAN.md:31.** `device.Bridge`, not the whole `Sidecar`, implements the device abstractions (17.10; Q-SDK-2).
- **cli/UI.md, not PLAN.md:** the added `expose :<port>`, `egress` and `block` forms (17.11).

### 17.16 Interfaces

- **Provides:** `device.Bridge`, `device.BridgeEgressPolicy`, `device.BridgeHost`, `BridgeStatus`; the compiler and forwarding's signer, which apps' VPN components link (§18.6, §18.10); `protocol/bridge/bridge.proto`'s `BridgeState`, `BridgeIdentity`, `BridgeShareKey`, `Pending`, `BridgeRows`, `WindowDelegation`, `ShareCert`, `BridgeShareSigner`, share pins' `BridgeShareGrant`, the share seal's `BridgeShareTargets`, `BridgeShareAliases` and `BridgeShareAccept`, the config head's bridge ledger (`BridgeLedgerManifest`, `BridgeLedgerAddresses`, `BridgeLedgerRules`, `BridgeLedgerEgressSpecs` and `BridgeLedgerAliases` under `bridge/ledger/`), and 17.8's statements; 17.8's states, route export, reach events (§16), the `ur tun` resolver (§12.9), `ur bridge activate` and `ur tun`'s exits routes (17.11); 17.7.1's discovery: each `ur daemon` host's gathering and its answers to watches, a viewer's view, which §12.9.1's names answer, sharing a LAN device, the advertising proxy, listed entries' Bonjour names, the hide set it shares with `ur listeners`, `BridgeDiscoverySettings` and `ur bridge devices`, `share` and `discovery` (owner decision 778).
- **Consumes:** §7.9's config repo, authorization log (`AuthPin`, entries, `StatementHeader`), deltas and `team` hints, and its forwarding Delegations (owner decision 197); §7.4's `strict_exp`; §8 grant chains, `AclEngine`, approvals, suspension, contract gate, shares; §10's generations; §11.12's `secret` kind; §6 `Signed` and §6.11's `SignedType`, Required, §6.10.1; §5 identities, the binding log, `GET /sidecar/identity/<sidecar_id>`, `Sidecar.Authorize`, `SidecarEvent`; §16.6's decisions and `effect_key`; §12.9; §18 `deviceBridge`, forwarding's setup and the device RPC's status mirror; §20.6 debits; §4 C5, C6a, C13, C14, C15, C16, C18.
- **Subprotocol messages:** none for rules, which ride the config repo (§6.11's MessageType 0x19 holds only DESIGN-COMPUTE.md's `LISTENERS` and `LISTENERS_RESULT`, 0x1901 and 0x1902, the listeners' live ask the bridge answers, 17.11; owner decision 770); 17.7.1's watches are §12.9.1's `DNS_SD_WATCH` and `DNS_SD_WATCH_RESULT` (0x1B02, 0x1B03), on data-class contracts. `Signed` types 0x1901-0x1909 are 17.8's statements, `WindowDelegation` and `ShareCert`; `BridgeShareSigner`, a config file, takes none (17.9).
- **API routes:** statements through §7's `POST /network/config/delta`; shares through §8's `POST /acl/invite` and `POST /acl/accept-invite`, which carry the sealed tables, the accept status included, the accept in §8.11's two forms, a claim that answers the share's id with the sealed targets and a completion that stores the sealed accept and the status once (owner decision 350); `GET|PUT /network/bridge/share/<share_id>` (Client, a sidecar of either network: read both tables, or replace its own at a higher version).
- **Tables:** `network_bridge_share` (api): share_id, both network ids, sealed target and alias tables, versions, `accept_status enum{active, refused_too_large, refused_no_space}`; kept until revoked.
- **Services and config:** no new service and no `sidecar_abuse:` caps; sdk flag `EnableBridge` and §19's `bridge` gate, which keep the bridge dark until its release (§19.11) and are no setting: released, an app's forwarding runs whenever its VPN component runs (owner decision 197); `ur tun` needs CAP_NET_ADMIN or root.
- **Assumptions about other sections:** §7.9 carries 17.8's statements as log entries, its type rule bounding a decision's bridge rules by 17.8's rule ids; §7.9's config head holds `bridge/ledger/` and `bridge/share-grant/`, its writer folds the ledger at each base that folds a bridge statement and through its tip while one is unfolded, and its head check compares the ledger (owner decision 473); the daemon's `ConfigClient` stores an entry before any entry callback runs (owner decision 474); §8 enumerates for the compiler the rules by which one subject reaches another (§8.9); a §5.8 Confirm method, `bridge.activate`, runs 17.9's activation (owner decision 475); §16.6's step 5 has a bridge component whose Lookup finds that id in the authorization log, AU1 counts those rules, `bridge_expose` returns the id, and `bridge_close` takes it or a forward's grant_id (§16.5); `sidecar/device` parses only `protocol/bridge`'s auth.proto (§7.9: `AuthPin`, `AuthEntry`, `ProjectionHeader`, `StatementHeader`, `Genesis`, `SidecarRevoke`, `MemberRevoke`, `ForwardScope`, and §8.8's `Suspend`, `Unsuspend` and `GrantRevoke`) and signed.proto (§6.9: `Signed`, `WebAuthnEvidence`, `SignedType`), which `config.proto` and `acl.proto` import (§4.4), reading the fields of config.proto's `Delegation` and `DelegationRevoke` its overlay needs by their numbers (DESIGN-DETAILS.md section 4); §5.8 and §16.6 sign 17.9's own-resource filings, a host's own `BridgeAddress` among them, from any mode, and other bridge statements only for a /dev/tty-confirmed `ur` command or in an app's UI; §18.6's setup gives an app's VPN component its forwarding Delegation, forwarding clients and `Pending`, after which its forwarding role compiles 17.8's states itself, persists them as its posture and signs its links' delegations with its forwarding key or a share's ShareSigner, and `DeviceLocal` takes the physical path's /32s; §7.9 defines the forwarding Delegation, its signer, what its key signs and its ends, §6.9 that key's `signer_id`, and §7.4 the forwarding client's `forward_only` mark; §2.8 lists `network_bridge_share` with its accept status and C13's delegation with a share's ShareCert, §2.10 17.9's share-signer bound, and §2.6 and §7.9 the ShareKey's custody and the `BridgeShareSigner` seeds every Y config reader, agents included, holds; §6.9's Signers and §5.5's identity-key rule (D-CORE-6) admit 17.9's two share keys; §22 tests D-BRIDGE-16 to D-BRIDGE-21: §22.5's §17 row; §22.7's S8, its actions suite and its assert block's bridge clauses (17.5's pins, aliases, private names, the no-document rules, MCP's own-resource bridge filings); FS-38, with its share signers in the M6-out run with C18; FS-56's dial fence, no byte reaching a target after its flow's revocation (D-BRIDGE-21); and §22.9's Browsers row (the CGNAT carve) and Memory row (mobile churn past a full table, the link cell's NAT at C5's per-flow idles) (owner decision 551). For 17.7.1 (owner decision 778): §12.9.1 answers a viewer's discovery view as DNS-SD names in `ur tun`'s resolver and owns the names on app paths; §6.11 numbers the watch; §8.5's document takes the `discovery` block; §8.10's contract rule admits a watch where `reach` does; §16.6 approves a share's /32 route as any `expose`; §5.8's confirmation carries `ur bridge share` and `unhide`; DESIGN-COMPUTE.md §26's listeners give each listed entry its `--type` label, publish the listed set the watch reads and write the hide set discovery shares, and its `Deliver` takes `<block>.0.46` as a source that holds no overlay address (§4.6); and §22 tests it (§22.5's §17 row, §22.7's S8).

### 17.17 Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Without an ACL document, untagged sidecars reach every provider's LAN and loopback (owner decisions 50, 105) | High | High | Accepted and disclosed (owner decision 120; §2.18); never the provider's own daemon listeners (D-BRIDGE-19); every tier may write a document (owner decision 73) |
| Providers not yet on C5 let Network sources reach everything | High | High | D-ACL-5's legacy rule; only enforcing clients advertise or host |
| Before C16, sdk providers apply rules 4 and 7 to C13's operator-asserted subject | Low | Medium | With a document, private destinations stay denied whatever the subject; D-BRIDGE-17 there from C16 |
| Foreign flows probe or exhaust a host's NAT (C18) | Medium | High | 17.9's isolation; per-source NAT state; foreign-first shedding; §22 tests |
| A sidecar the source network removed keeps signing share delegations that operator-made contracts carry: a ShareSigner until a later ShareCert reaches the host (at most 7 days), a reaped Delegation-admitted agent while it reads that config, a removed ShareKey holder until the share is revoked | Low | Medium | 17.9's per-generation ShareSigners under 7-day ShareCerts; the ShareKey only in the approving admin's `secret`; a `SidecarEvent` on a holder's removal, then a new invite |
| A current reader of the source network's config that its policy denies, running modified software, reaches a share's targets on a contract the operator mints, since X's host checks the network, the share and the signer, never Y's per-subject grant | Low | Medium | It needs a modified Y device and a colluding or compelled operator; X's grant still bounds targets, ports and expiry; the honest gate refuses the contract; Y removes the reader (17.9, 17.12; §8.11) |
| A forward on all interfaces serves the LAN and every local user (owner decision 84) | High | Medium | Disclosure; `--listen`; grant expiry; the Host check |
| The block clashes with Tailscale, CGNAT or, if chosen in RFC 1918, a LAN | Medium | Medium | Cycling or choosing the block; /32 peer routes and carved interface, gateway and resolver /32s, or per-peer /32s while those are unknown (17.4); the local LAN wins (17.7); §22.9's CGNAT fixture |
| A full pin table leaves pairs unpinned, so an edit can move their live flows | Low | Medium | One pin per pair, only where an entry offers a choice; nothing refused (owner decision 66); `ur bridge` counts unpinned pairs; §22.9's mobile churn case |
| After an uncovered agent's reap, new bridge deltas wait for a config rotation (§8.12) by a config writer or the agent's admitting device, a wrapped one by rotation alone (§7.10; owner decisions 128, 144) | Medium | Medium | No admin needed (owner decision 128); covered agents' reaps need none (§10.5); withdrawals never wait; `ur bridge` shows the wait |
| A tun's overlay address leaks in WebRTC (libwebrtc's 100.64/10 handling is unverified) | Unknown | Low | `ur tun ip auto` refuses behind `BridgeComponentSettings.AutoAddressEnabled`, false, until §22.9's Browsers check shows no ICE candidate in the overlay block; an explicit address and an admin's assignment work |
| Links, or forwarding's compile, do not fit the iOS tunnel | High | Medium | No iOS links until §22 measures; Q-BRIDGE-2's own-client links; the compile cap of owner decision 216, measured to admit about 4,300 devices' rows at the tunnel's connected baseline and 770 to 1,440 under provider load, a network past it keeping its last verified state on that device and alarming; links fail closed meanwhile |
| A revocation the posture cannot check does not apply on a device that cannot compile | Low | High | Accepted by the owner (owner decision 216): forwarding never drops for it; `bridge_alarm` on the schedule 17.8's forwarding roles give, the condition in the status throughout (owner decision 487); denials the posture can check apply at once; the review phase's storage-backed compile removes the memory cap as a cause (owner decision 366; DESIGN-DETAILS.md section 4) |
| Between the app's runs an app's forwarding role follows the log unwitnessed, so an operator that withholds a revocation from it keeps a revoked subject reaching that device | Low | Medium | the sidecar role's witnessed pin at each run (§18.6); daemon hosts witness by HeadCheck (§6.4); it needs a malicious operator, and the subject's own revocation still ends it at every other device |
| A base that leaves a bridge filing unfolded and changes the policy its approval was judged by turns that filing's verdict at every reader | Low | Low | writers fold through their tip whenever a bridge statement is unfolded, so only a filing in the seconds between a head's writing and its base's acceptance is exposed; it fails closed alike at every reader, and the requester files again (17.8; owner decision 473) |
| A standing member device keeps filing bridge bodies sealed to generations that never form, holding the config fold | Low | Medium | each is void at the fold `UnformedVoidWait` (24 h) after its entry; while they keep coming, bases past the tail cap wait up to that long at a time; the writer's `config_key_waiting` line names the filer on every plan, and revoking it, which needs no base, ends the hold one wait after its last filing (17.8; owner decision 478) |
| Under `exits`, a Linux host with a strict reverse path filter keeps its own route instead of the exits until a person loosens the filter | Low | Low | `ur tun` holds the exits, putting nothing on, and says how (rp_filter 2); `ur` changes no host security setting a person did not choose (17.11; owner decision 479) |
| A shared device's /32 route outlives its address: another LAN device takes the address while the shared one is away, and the network's devices that may route there reach it | Low | Medium | The host withdraws the route when it sees the device move, and after 7 days unseen; the share's confirmation advises a fixed lease for the device (17.7.1) |
| A host's own service names, or a shared device's name and model, say more about a person than its owner meant | Medium | Low | Told at the first publish and shown at each share; named only to devices the policy lets reach them; `ur bridge discovery off`, `hide` and `unshare` (17.7.1; Q-BRIDGE-9) |
| A compromised or modified host advertises misleading names, or the name of a service a viewer knows locally | Medium | Medium | Addresses held to what the host serves by the config; a local instance wins its name and a remote one carries its host's name on a clash (Q-BRIDGE-11); a paired device's pair-verify; names and TXT shown as the host's words, read by no model (17.7.1) |
| An admin narrows a shared device's route to some ports, so Xcode reaches the pairing port but not the tunnel's picked one | Medium | Low | `ur bridge devices` names the narrowing on the device's line; a device's debugging needs its route's every port (17.7.1) |
| Avahi's reflector, turned on by someone, would repeat the Linux proxy's answers onto the LAN | Low | Medium | The Linux proxy stays off while Avahi's reflector is on, and says why (17.7.1) |
| Xcode connects to a device only at a link-local IPv6 address, as Apple's DTS describes its connections, so it lists the shared iPhone but does not reach it at the translator's ULA address | Medium | High | §22.7's S8 run on a real Xcode and iPhone before M6's exit decides; if it fails, the translator also takes a link-local address on `ur tun`'s own link, which no LAN shares, and the proxy registers the device there on that interface, a change §17.7.1 and 17.5 make before M6's exit; other clients, pymobiledevice3's among them, already reach the iPhone at a routable address |

### 17.18 Phasing

- **v0, M4 (same network; Linux and WSL2 first):** C5 with its dial fence, C6a, C13 with `WindowDelegation`s, C14; statements in the config repo and 17.8's states, the rule table and the compile of `BridgeRows` landing at M2 with §7.9's records, though nothing files a bridge statement until M4; router, hook (rule 0 included), userspace stack; `ur tun` on Linux, its default route under `exits` once connect's egress mark lands (owner decision 479); private names via `ur tun`'s resolver and C14's seam, dark on app paths; forwards, expose and egress under I-8 approvals; HA, pins, dispositions, block changes and the CGNAT carve; sidecar-owned hosts; the sdk insertion behind `EnableBridge`. Blocked by §7.9's config repo and authorization log (M2), §8's grant chains and gates, and C13.
- **v0, M8** (with §18's app hosts): forwarding in every app's VPN component, with its own keys, compile and signing (owner decision 197): sending from M8, hosting after C16 in the device client's network, once M8's entry has measured the plaintext an Opportunistic peer has in flight at C16's latch (owner decision 224), iOS links after §22.9's measurement, private names on app paths.
- **v1:** cross-network shares through C18, with ShareKeys, per-generation ShareSigners and the preflight, and `ur tun` on macOS and Windows (M6); service discovery across hosts (17.7.1; owner decision 778) at M6 with them: gathering on `ur daemon` on Linux, macOS and Windows, watches, sharing, §12.9.1's names in `ur tun`'s resolver and the advertising proxy on macOS and Linux, Xcode's use case passing §22.7's S8 on a real iPhone before M6's exit, and, with DESIGN-COMPUTE.md's listeners at M13a (§23.4), listed entries' Bonjour names, the hide set the two share and `Deliver`'s `<block>.0.1` for a translated source; P2P after C3, built at M6 behind §6.6's `EnablePeerP2p` and off until [a later owner call](DESIGN-DEFER.md#proto-peer-p2p) (owner decision 296).
- **Later:** [L3 delivery](DESIGN-DEFER.md#bridge-l3-delivery), [multi-hop maps](DESIGN-DEFER.md#bridge-multi-hop-maps), [IPv6 subnet routes](DESIGN-DEFER.md#bridge-ipv6-subnet-routes), [the advertising proxy on Windows, and discovery in the apps](DESIGN-DEFER.md#bridge-discovery-other-platforms).
- **Deferred:** DESIGN-DEFER.md holds an entry for each Later item, linked above, and for [this section's v1 set](DESIGN-DEFER.md#bridge-v1) (owner decision 587).
