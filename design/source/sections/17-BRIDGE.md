## 17. IP addresses, subnet routing, and port forwarding

### 17.1 Purpose and scope

This section owns PLAN.md's bridge (PLAN.md:113-119): the overlay address plan (X18, owner decisions 28, 132), subnet routing, provider port mapping, bridge rules, their engine and states, native IP principals (`WindowDelegation`), cross-network shares (owner decision 86, C18), the connect changes, `BridgeHost`, `ur tun` and `ur bridge`. §7.9 owns the config repo and authorization log; §8 policy, grants, shares and gates; §12 names; §13 `public-tls`; §18 the sdk seam, the forwarding role's setup in apps' VPN components (owner decision 197) and app work; §20 billing.

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
| First block | Drawn at the network's bootstrap into its first config head; a head that holds none, an older network's or one bootstrapped before the bridge shipped, gets one from any config writer's next head; until then `ur tun ip` reports no block and files nothing |
| Cycle or choose | An admin re-rolls it or picks a /16 in 100.64.0.0/10 or RFC 1918 only (owner decision 132; D-BRIDGE-16); hosts keep their host bits while the old block drains (17.8) |
| Uniqueness | None across networks; a device whose networks share a block (owner decision 23) routes it only to the first-joined one, warning in `ur status` and a `SidecarEvent` until an admin cycles one |
| Host address | A random free /32 of the lower /17 outside `<block>.0.0/24`, which holds services (the resolver at `<block>.0.53`); once that is full, the highest free /32 of the upper /17, whose bottom aliases fill first-fit (17.9); never x.y.z.0 or x.y.z.255; a chosen address (`ur tun ip <ip>`) must lie in the lower /17 |
| Binding | The §5 `sidecar_id` (an agent's own only under its own OS user, container or VM, §5.5); it survives re-enrollment and the reaper; on an app, its VPN component's forwarding role hosts it (17.10; owner decision 197) |
| Assignment | On demand (`ur tun ip`, the app's UI, the host's first map, an admin; proposed; Q-BRIDGE-8); the first claim in log order wins (17.8) |
| Release | On revocation or removal, then a 30-day tombstone (I-14) |

Addresses avoid connect's tun ranges, 10.a.b.0/24 and 169.254/16 (sdk/device_local.go:1851-1861; connect/tun.go:387-399, :533-551). Where a local route overlaps the block, as a CGNAT carrier address can, the device routes overlay peers by their /32s and carves out of the router's table and every exported route each local /32 its physical path needs: interface addresses, gateways and system resolvers, from the platform's routes and DNS settings (§18.6's `SetBridgeLocalAddresses`), since `connect.LocalIpv4Networks` sees only interface subnets, or nil where enumeration is restricted (connect/tun.go:490-495). The block is never dropped wholesale; until those /32s are known, the export holds per-peer /32s instead of the block. If a carved /32 is an assigned overlay address, `ur status` warns and an admin cycles the block (D-BRIDGE-16).

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
- **Classify.** A fixed-offset destination read, then an immutable longest-prefix lookup (bart v0.30.0, MIT, 2026-09-21, https://pkg.go.dev/github.com/gaissmai/bart, at 0 allocs/op, else in-repo): ≤50 ns at 1,000 prefixes (§22 gate). Unassigned block addresses answer unreachable; carved local /32s (17.4) take the default route.
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
- **Rejects.** A TCP RST or ICMP administratively prohibited (v4 3/13, v6 1/1) enters the tun through a per-source token bucket (20/s, burst 40), since connect writes policy resets unthrottled (connect/ip_smtp_policy.go:847-864).

### 17.6 Provider hook and port mapping

C5 (§4) gives `LocalUserNatSettings` an `EgressHook`, called once per flow before the dial: at the TCP dial (connect/ip.go:5740), the UDP open (:3589) and ICMP egress (connect/ip_icmp.go:782), which every lane uses (connect/ip_provider_reliable_ingress.go:158-191). Replies are rebuilt from the flow (connect/ip.go:4075-4077, :7289-7291), so a map is DNAT with no checksum or return-path rewrite.

```go
// connect (C5, with C13's seals, C15's key and C18's switch); a nil hook keeps today's behavior
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
	                                // rules 3, 4 and 7 taking one byte, the rule number, as their rule_id, so
	                                // the engine enumerates a subject's or a rule's tags without tracking flows
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
5 loopback, link-local, multicast, unspecified -> Deny
6 a served prefix                          -> AllowRoute(subject, prefix, port) ? Pass or Map(remap) : Deny
7 public unicast                           -> AllowExit(subject, host) ? Pass : Deny
8                                          -> Deny   // LAN without a route rule
subject: the principal's (at an sdk provider before C16, C13's sealed subject, resolved through the compiled
client_ids of 17.9's verify row: a sealed subject in no row is an other client (§8.4), untagged for rule 4 as
owner decision 105 keeps for app devices, and under a document holds only autogroup:untagged's rows);
"no document" means a verified enforcing{nodoc} state (17.8); idle: a Pass or Map of a flow with a principal
sets IdleTimeout to 600 s for TCP and 5 min otherwise (17.5), and every other flow keeps its NAT's;
AllowDial, AllowRoute and AllowExit read the per-subject rows the compiler expands into BridgeRules (17.8),
never AclEngine, whose AllowRoute serves the compiler and ur bridge's previews
```

- **Maps** match the destination as sent: `:5432` → `127.0.0.1:5432` on a hosted address, or `:8000` → `192.168.1.20:8000` ("client:port → ip:port"); ranges map by offset; ICMP echo follows rule 3. A map never targets another client's overlay address, the daemon's own listeners or a §13.7 control panel.
- **Own listeners** (D-BRIDGE-19). Rule 0 matches the daemon's local API, MCP, git, IMAP and submission listeners on loopback and every local address, since they bind all interfaces by default (owner decision 84); the state lists them (17.8), and the control channel is a socket or pipe, never a port (I-17).
- **No document.** Rules 3-4 apply owner decisions 50, 105 and 120: untagged sources keep today's reach, minus rule 0, the hosted address standing for loopback, and tagged ones get §8.5's implicit rules, so R-BRIDGE-7 holds for tagged agents, and for all once a policy exists; product copy and §2.18 disclose this (I-10).
- **sdk exit NAT** (`ensureRemoteUserNatProviderWithLock`, sdk/device_local.go:6421). The hook goes on that NAT, `remoteUserNatProviderLocalUserNat`, alone: the provider's own `localUserNat` stays hookless, since it carries this device's own `routeLocal` flows (:5788, :5895), which are no provider source. Until C16 the sdk installs the policy without the principal and Sealed rows and rules 1-3 and 6, since an Opportunistic provider's sources may be plaintext: Network sources keep the public exit their rules allow and, with a document, lose LAN, loopback and overlay reach.
- **C6a.** 100.64/10 becomes non-public, as IANA lists it (RFC 6598; https://www.iana.org/assignments/iana-ipv4-special-registry/, updated 2025-10-09), so public exits refuse overlay traffic. Behind `CfaaSecurityPolicySettings.DropSharedAddressSpace`, false by default, providers shadow-count it for a release, and a later one drops it as `SecurityPolicyReasonSharedAddressSpace`, not as an Incident: a check of its own beside `isPublicUnicast`, which stays as it is, since that branch returns an Incident (connect/ip_security.go:574).

### 17.7 Subnets: advertisement, conflicts, HA

- **Advertising.** `ur bridge expose <ranges>` files a `BridgeRoute` delta (17.8). As in Tailscale, approval is separate from access ([R:connect-ip] §2.10): a standing grant in a config head or an I-8 approval (§16.6) activates it; §8 `route` grants decide who uses it.
- **Overlap** (D-BRIDGE-8). The longest prefix wins. An identical prefix is an HA replica (same `site_id`) or a remap, an exposed prefix from the block, allocated as aliases are, first fit and aligned from the upper /17's bottom in one space with them (17.9), that the advertiser maps back keeping host bits.
- **Sender conflicts.** The sdk drops and reports exposed subnet-route prefixes overlapping `connect.LocalIpv4Networks()` (connect/tun.go:490-531), so the local LAN wins until a remap or block change; where it returns nil, only 17.4's carve keeps the physical path's /32s. The overlay block follows that carve rule instead. The block and approved prefixes join `RandomLocalIpv4`'s avoid list.
- **HA.** When no link to an advertiser of the most specific prefix can carry a packet (17.5), the router answers unreachable, never falling back to a broader prefix or the default route, which could reach another network reusing the addresses.

### 17.8 Rules in the config repo, delivery, engine, disposition

```text
statement (sidecar/protocol/bridge/bridge.proto; §6.9 Signed,             signer; carried in
  purpose bridge, SignedType 0x1901-0x1907 in row order; a delta
  begins with auth.proto's StatementHeader, §7.9; §4.4)
BridgeBlock{ipv4_prefix, previous_prefix, drain_until}                    an admin; a head (owner decisions 28, 132)
BridgeAddress{sidecar_id, ipv4}                                           the sidecar or an admin; a delta
BridgeRoute{route_id, advertiser, prefixes, exposed_prefix, site_id,      the advertiser; a delta, active once
            weight, kind subnet|exit, drain_seconds, approval}              approved (17.7)
BridgeMap{map_id, host, match_prefix, protocol, ports, target,            the host; a delta, active once
          target_port, expires, drain_seconds, approval}                    approved (17.7)
BridgeEgress{subject, mode auto|exits|none; sealed: exit sidecar_ids      an admin, owner or sponsor; a delta
             or tag_id, none under auto or none}
BridgeAlias{share_id, target_index, alias_prefix, host sidecar_id,        the accepting sidecar; a delta (17.9)
            host identity key}
BridgeWithdraw{rule_id, reset|drain}                                      the rule's signer or an admin; ids only
approval  none under a standing grant (17.7), or the I-8 decisions and this use's CanonicalAction (§16.8),
          which readers verify as §8.8 does a GrantActivate's, the signer being every decision's requester;
          under a multi-use decision also template_action, the template every decision's payload_sha256
          hashes, which this use's action must match (ActionMatchesTemplate), so one decision files up to
          its uses rules, the ledger's count binding them; with it unset the single-use reading stands
          (owner decision 218)
rule id   route_id or map_id: under a decision, SHA-256("urnetwork-sidecar-v1/bridge-rule" || effect_key),
          the use's §16.6 ledger key, which readers recompute, so a retry or restart files one id; under a
          standing grant, 32 random bytes; a filing of a held id may change only weight, site_id and
          drain_seconds and activates nothing; readers refuse an id a BridgeWithdraw named and a decision's
          ids past its uses (§7.9); a fold keeps a withdrawn id, with its approval_id, until its decision's
          not_after
```

- **Placement** (owner decision 5). Admin-signed heads carry the block, standing rules and 17.9's `BridgeShareSigner` files; sidecars file statements about themselves, and owners or sponsors about their subjects, as deltas entering §7.9's authorization log, verified at their position until a writer folds them in. Rule bodies are sealed to the config's current key generation (§10), so §8.12's invariant and D-TRUST-10's witness stop can delay them; a bodiless `BridgeWithdraw` never waits, nor does a `BridgeEgress` of mode `none` or `auto`, whose `sealed_body` is empty. Only ids show (kind, signer, subject, rule id, expiry, an egress statement's mode and, for an approved route, the advertiser and the `route` rules it serves), which readers check; gates and api apply each egress entry's mode in log order over `BridgeRows.egress`, as §8.9's entries after a base, and rows carry the same value at the fold. A requested `dial` or `route` grant keeps only ids in the clear too: its CanonicalAction's `rule_id`, `subject`, `grant_allow`, `expires_millis` and a subject-only `grant_dst`, while its prefixes and ports, `cidrs`, `target_port` and any `ip:` or port text in `grant_dst`, ride in `sealed_detail`, sealed as rule bodies are, under a raised version; `payload_sha256` still covers the stored bytes, so api's `match` checks ids only, and approvers and readers open the detail to render and enforce it, while a publish keeps its clear fields, which are public anyway (owner decision 220; §8.8, §16.8). Gates see only §8's reach rules between sidecar ids and `BridgeRows`' egress modes (§8.10), never prefixes, addresses, ports, maps or aliases (§2.8, api-12).
- **Engine.** The compiler (`bridge_*.go`, §5) reads the config (owner decision 6), verifies statements against §7.9's admissions and §8's grants within §8.9's latency targets, and compiles a `BridgeState` off the packet path: in the sidecar role on a daemon, and in an app's VPN component in the forwarding role, which reads the config by its forwarding Delegation's reader key (owner decision 197; 17.10); `device.Bridge` (17.10) applies it and later verified log entries, manages links, and swaps table and hook atomically. Before its first verified state it is pending and denies every private destination and exit; it persists its last verified state and never lowers it on unsigned input:

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
                      packet
legacy -> pending     the sidecar enrolls, or on an app sets up its forwarding (§18.6), with
                      Pending{network_id, genesis_sha256, sidecar_id, identity_public_key}, stored with the
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

- **Forwarding roles** (owner decisions 87, 197). An app's VPN component compiles its own `BridgeState` from the config it reads by its forwarding Delegation's reader key, with `Pending` from forwarding's setup (§18.6), its `Names` feeding C14's zone (§12.9); between compiles its posture applies the log's `SidecarRevoke`, `MemberRevoke`, `Suspend`, `Unsuspend`, `GrantRevoke` and `BridgeWithdraw` entries, verified against the anchor (§7.9) with `protocol/bridge`'s types alone, a `SidecarRevoke`, `MemberRevoke` or `Suspend` that §7.9's presence row covers on its identity signature as a denial that the next compile, which checks the countersignature, confirms or reverses (owner decisions 185, 187, 189). So rules and revocations apply whether or not the app runs.
- **Limits.** None per network (owner decision 66); the block bounds addresses at 64,770.

```proto
message BridgeRows {                      // bridge.proto; acl.proto's AclRows.bridge (§8)
  repeated BridgeEgressRow egress = 1;    // subject (sidecar_id or keyed atom), mode; ids only
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
}
message BridgeIdentity { bytes sidecar_id = 1; bytes identity_public_key = 2; uint64 admitted_at = 3;
                         bool revoked = 4; bool suspended = 5; }
message BridgeShareKey { bytes share_id = 1; bytes public_key = 2; }   // the pinned ShareKey, Ed25519
message Pending { bytes network_id = 1; bytes genesis_sha256 = 2; }  // legacy -> pending
// bridge.proto also declares Pending's sidecar_id = 3 and identity_public_key = 4, which the sign-out edge above
// checks; they join this fence in one change with protocol's fence test, whose additions list holds them now
```

**Disposition** (D-BRIDGE-7):

| Change | Sender | Provider |
|---|---|---|
| Revocation (revoked or expired grant, the subject's `SidecarRevoke` or suspension, rejected route, `--reset`) | Reset at once: pins to a revoked advertiser drop, and an entry left with no advertiser answers its packets with an RST or prohibited reply for 600 s, then leaves | `CloseFlows` after the policy swap, dials in progress included (17.6) |
| Edit (withdraw, retarget, advertiser or health change, new address or block) | Drain under 17.5's pins: while the table has room no live pair leaves a link that still serves it, and a removed advertiser or old address drains as 17.5's `removed` row sets (`drain_seconds` 300 s by default, 3,600 s at most); new pairs take the new rule, as do new TCP connections of pairs pinned to a draining link, but new UDP and ICMP pairs follow the pre-change link through 17.5's window; a full table refuses nothing | A removed route or old address stays compiled, draining and admitting flows, for max(`drain_seconds`, 600 s), and a retargeted map keeps only the flows it opened; then the engine drops it, swaps the policy and runs `CloseFlows` on its tags |

### 17.9 ACL, identity, egress, cross-network shares (C18)

- **Permissions** (§8.4): `route` on `ip:<cidr>`, `dial` on the subject for hosted addresses and maps, `autogroup:internet` via the exit, and per forward a requested grant (port, `expires`, 1 h by default; owner decision 74). §8's contract gate checks pairs, and the hook each flow by the principal a verified `WindowDelegation` names, checked against C13's seal (D-PROTO-19). `forward`, `expose`, `egress` and `invite` are outward actions under `Sidecar.Authorize` (§5, I-8) at every entry point, whose deltas carry the approval (§8.6), in a tainted run only by I-9's evidence (owner decision 142). Own-resource filings sign from any mode, MCP included (§5.8, §16.6): `bridge_forward` files a `GrantActivate` from its decision and returns its grant_id; `bridge_expose` a `BridgeRoute` or `BridgeMap` under a standing grant or its decision, a map preceded by this host's own `BridgeAddress` where the log holds none for it (17.4), and returns 17.8's rule id; `bridge_close(grant_id | rule_id)` a `GrantRevoke` of a forward's grant whose subject it is, or a `BridgeWithdraw` of this sidecar's own rule; `block`, `egress`, `invite` and `accept-invite` sign only for a `ur` command confirmed on /dev/tty or in an app's UI.
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
// share pins' BridgeShareGrant (below) joins this fence when bridge.proto declares it
```

```text
sign     BridgeHost gets one per window client it builds, signed by the subject's identity key where the
         sidecar role builds the link (a daemon), by its forwarding key in an app's VPN component (§18.6),
         or on a share link by a ShareSigner (share signers, below), and passes it in CreateContract; the
         contract signer copies it unchanged into StoredContract (C13)
verify   once per contract, before the first flow's dial: the signature, by the subject's identity key
         pinned through its SidecarAdmit and neither revoked nor suspended at this state, by the key of the
         subject's forwarding Delegation live at this state (§7.9's forwarding row: forward names the
         subject, and it is neither superseded, revoked nor void), or by a ShareSigner that share signers
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

- **Egress spec.** A subject's default route goes to an approved exit, or nowhere (app devices: `NetworkPeer` with `PostQuantumEncryption`, v1, §18); §8.10's gate refuses Public contracts under `exits` or `none`.
- **Shares** (owner decision 86). X's `ur bridge invite` files §8.11's admin-approved share (a `route` or `dial` grant to `network:Y`) with a 256-bit code and seals its targets T_i (index, host `sidecar_id`, ports or prefix, and the host's identity public key) under K, which the code derives and the server, holding the code's hash, cannot (share seal, below). Y's `accept-invite`, approved by a Y admin, runs the preflight below, aliases each target with an equal-length A_i in Y's block (`BridgeAlias` deltas, each copying its T_i's host identity key, so Y's routers pin the host from Y's own signed log) and returns the aliases sealed under K. Y routes A_i over a share link to T_i's host (resolved through §5's binding log), whose hook maps A_i to T_i, keeping host bits. Y's approving admin device also generates the share's Ed25519 ShareKey, which certifies a ShareSigner per generation of Y's config (share signers, below); its public key, sealed under K, reaches X, whose approving admin's device pins it, with K, in a `BridgeShareGrant` config file in the act that files the share's GrantActivate (share pins, below), and X's host verifies the `WindowDelegation`s those signers sign, while Y's routers and the contract gate (§8.10) enforce Y's grants: §8.11's intersection is these points. X's host checks the share and that the signer is one every current Y config reader holds, never Y's per-subject grant, so the intersection holds against a modified Y reader or a compromised operator, not both together: on an operator-minted contract, any current Y reader, one Y's policy denies included, reaches X's granted targets, within X's grant (17.12, 17.17).

```text
share seal (§8.11; api-9's tables)
K          HKDF-SHA256(code, salt x_network_id, info "urnetwork-sidecar-v1/bridge-share"), 32 B
sealed     nonce (24 random B a seal) || XChaCha20-Poly1305(K, nonce, body, ad), with ad =
           "urnetwork-sidecar-v1/bridge-share/" || label || 0x00 || x_network_id || y_network_id ||
           u64be(version): y_network_id is 16 zero bytes for targets, which X seals before any accept, and
           version is the table version network_bridge_share stores
labels     targets: BridgeShareTargets, each T_i's index, host sidecar_id, ports or prefix and host identity
           public key; aliases: BridgeShareAliases, each A_i by index; share-key: the ShareKey's public key;
           shortfall: refused_no_space's figures; proto3 bodies in protocol/bridge, each padded by a bytes pad
           field to a multiple of 256 B
open       a failed open refuses the share and alarms, with no fallback
holders    a multi-use code's accepters all hold K, so a seal proves only a code holder; X's approving admin
           is what pins one ShareKey to one share (share pins)
```

```text
share pins
X's pin    the config file bridge/share-grant/<share_id hex>, a BridgeShareGrant{share_id, grant_id,
           share_public_key, target_table_sha256, table_key} that X's approving admin's device writes in a
           head in the act that files the GrantActivate it names, a config file as BridgeShareSigner is
           (§7.9); table_key is K, which X's hosts need to open Y's alias table and map A_i to T_i; the
           compiler fills BridgeState.share_keys only from a file whose grant_id is a live grant
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
             its ShareCert} in a config head at g, unless it already names g, and re-certifies g when the cert
             has under 3 days left, unprompted as §7.9's folds are; §10.6's write gate takes a write at g only
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
             delegation under signer_public_key; the principal's not_after is the earlier not_after_ms
bound        a sidecar Y removed is admitted on new contracts until a later generation's ShareCert reaches the
             host in any Y delegation, at most 7 days after its removal reaches evs, and those it opened run
             to their end (at most 60 min, server/model/subscription_contract_expiration.go:14); with no
             renewal for 7 days the share lapses for everyone; a reaped Delegation-admitted agent signs while
             it reads Y's config (§10.5); a removed holder device, or a holder member leaving the AdminSet, can
             certify until X revokes the share, so Y's devices raise a SidecarEvent naming it, and X re-invites
```

- **Isolation.** Only sidecar-owned Required hosts holding a share grant turn `FriendsAndFamilyEgress()` on; sdk providers never do. The principal's verified share and network, never an address, select the aliases, which resolve only to that share's targets through maps, dialable hosted addresses and served prefixes: never rule 4, rule 0's listeners, unmapped loopback, another host's address or an exit (owner decision 11). NAT state is per source path and 5-tuple (connect/ip.go:2072-2098), so foreign flows share no entry with local ones; replies carry the alias back unrewritten. Foreign flows are shed first under NAT pressure. Reach events name the source network (§16).

### 17.10 Placement, sdk seams, apps, hosts

| Repo | Change |
|---|---|
| connect (X9) | §4.6's C5, C6a, C13 and C14 (M4), C15's key (M1), C16 before app devices host, C18 for shares (M6); not C6b, since providers terminate flows without a tun |
| sidecar | Root `bridge_*.go`: statements, the compiler that builds `BridgeState`, forwards, and forwarding's setup and signer, the compiler and signer also linked into apps' VPN components among the root's forwarding files (§18.10). `device/` (`device.Bridge`, D-SDK-20): table, pins, links, `BridgeEgressPolicy`, principals, aliases, routes, the per-link resolver and zone, and 17.8's states, importing connect and `protocol/bridge` only. `cli/` wires `device.Bridge` to the root's state producer for `ur tun` and `ur bridge` and holds `ur tun`'s OS tun (`golang.zx2c4.com/wireguard/tun`, MIT) and the userspace stack, out of every sdk binding (Q-SDK-5); on Windows `ur tun` neither bundles nor fetches wintun.dll: it loads one beside `ur.exe` or at the installed app's path only once its SHA-256 and Authenticode signer match windows/app/tools/fetch-deps.ps1's pins (0.14.1), since it runs elevated, and otherwise prints where to get it, so the release zip holds no DLL (owner decision 222) |
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
| `ur tun` | OS tun `ur-<instance>` with the block and granted prefixes; the default route only under `exits`; yields to an app bridge |
| `ur tun ip [<ip>\|auto]`; "client assign local ip" | Show or claim the address |
| `ur bridge`; "show all ips", "show all hostname:port" | Run the bridge; list addresses, private names, rules, forwards |
| `ur bridge expose <ranges>`; "client forward ip subnet" | Advertise subnets (a route) |
| `ur bridge expose :<port>[=<ip>:<port>]` (added); "client:port → ip:port" | Map this client's port |
| `ur bridge forward client:port[:local ip]:local port`; "client:port → client:port" | Listen on all interfaces unless `--listen` narrows it (owner decision 84); dial over the userspace stack under a §8 grant |
| `ur bridge egress auto\|<exit>\|tag:<t>\|none` (added); "client egress spec" | The default route |
| `ur bridge block [cycle\|<cidr>]` (added; admins) | Re-roll or choose the block (17.4; owner decisions 28, 132) |
| `ur bridge invite`, `accept-invite` | Cross-network port and subnet shares (17.9), v1 |

Without an active grant, these commands print the approval prompt and wait (§16.6); `forward` warns that it serves every host reaching the listener. `ur bridge public-tls` is §13's.

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

### 17.13 Decisions proposed

**D-BRIDGE-1 (proposed).** The bridge reuses connect's client-to-provider NAT path: sender routing, a per-flow provider decision, one hop. *Why:* PLAN.md:115-117; targets need no tun or root.

**D-BRIDGE-2 (proposed).** The router sits before the mux behind `deviceBridge` (17.5); the CLI shares it. *Why:* all device egress passes there.

**D-BRIDGE-3 (proposed).** Fail closed: the block is a deny backstop; providers serve only sealed flows, never dial another host's address and, with an ACL document, open private destinations only by rule. *Why:* R-BRIDGE-10, R-BRIDGE-12.

**D-BRIDGE-4 (proposed).** The C5 hook applies 17.6's order, relying on C6a, C13, C15 and, for shares, C18 (17.10). *Why:* once per flow; a nil hook changes nothing.

**D-BRIDGE-5 (proposed).** Links run Required to a fixed target with one window client, relay-only until C3, never count-capped; targets are sidecar-owned until C16, after which an app device hosts on its device client's sdk provider, in that client's network only. *Why:* D-PROTO-6, D-PROTO-10; owner decisions 66, 197.

**D-BRIDGE-6 (proposed).** Bridge rules are signed config-repo statements, sidecars' own as sealed deltas in the authorization log; gates see only reach rules and `BridgeRows`, applying an egress statement's clear mode in log order, and a requested grant's prefixes and ports ride sealed in its CanonicalAction (owner decision 220). *Why:* owner decision 5; no prefixes, addresses or ports reach the server (I-4).

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

**D-BRIDGE-17 (proposed).** A host admits a native IP flow only from a window client whose customer-signed `WindowDelegation` it verified against the subject's pinned identity key, the key of the subject's live forwarding Delegation (owner decision 197) or, on a share link, a ShareSigner of the source network's newest certified config generation, which the share's pinned ShareKey, kept in the approving admin's `secret`, certifies for at most 7 days; C13's seal serves only as a consistency check (17.9). *Why:* C13's seal is the operator's statement, and a sidecar its network removes must stop signing within a bound, which no key every reader keeps allows.

**D-BRIDGE-18 (proposed).** Only a verified state opens a private destination: the engine and the forwarding role run 17.8's legacy, pending and enforcing states, persisted, never lowered by unsigned input (§18.6). *Why:* a restart plus a forged `has_document = false` must not reopen a LAN.

**D-BRIDGE-19 (proposed).** A provider never dials its own daemon listeners, document or not (17.6's rule 0). *Why:* owner decision 120 opens LAN and loopback destinations, not the sidecar's own control and content plane.

**D-BRIDGE-20 (proposed).** Hosts draw from the lower /17 and aliases fill the upper /17 first-fit (17.4), so a share is refused, before any flow and with its reason in `accept_status`, only when it is wider than /17 or the upper /17 has no aligned room for it (17.9). *Why:* a /16 cannot alias a /8 or itself, and random host /32s across the whole block leave few free aligned blocks (about 5 free /24s among 1,000 hosts).

**D-BRIDGE-21 (proposed).** A revocation swaps the provider's policy before `CloseFlows`, and a flow registers its rule and policy generation before its dial and re-checks it before its first byte (17.6). *Why:* a dial can outlast the reset that should have ended it.

### 17.14 Open questions

**Q-BRIDGE-1.** [X18] Which range carries overlay addresses? **Decided by owner 2026-11-03 (owner decision 28):** IPv4 only, a random /16 per network from 100.64.0.0/10 after C6a, which admins may cycle or replace (17.4). *Residual:* none; Q-BRIDGE-7 bounds the choice.

**Q-BRIDGE-2.** How do links reach targets? **Closed by peer review 2026-11-04:** (c). One `BridgeHost` link per target, as a fixed `ProviderSpec{ClientId}` multi client with window size 1 (`FixedWindowSize: 1`), `PostQuantumEncryption` Required, `OverrideAllowDirect=false` until C3, and `EnableIcmp`; not `DefaultMultiClientSettings`, whose six-client quality window (connect/ip_remote_multi_client.go:217-234) is the wrong default and six times the memory. Each window client carries the subject's customer-signed `WindowDelegation` into C13's seal, which the provider verifies (D-BRIDGE-17). Option (b), a link on the subject's own client, is adopted only where §22.9 measures per-target memory over §18.4's iOS budget and the new framing passes fragment, reply-filter and lifecycle tests; the iOS tunnel is the first candidate and runs no link until measured (owner decision 100). *Residual:* none.

**Q-BRIDGE-3.** Should upgraded providers refuse private destinations to Network sources unless a rule allows them? **Decided by owner 2026-11-03 (owner decision 50):** only with an ACL document; without one, untagged sidecars keep today's reach (17.6 rules 3-4; owner decision 105), which owner decision 120 keeps and discloses (Q-TRUST-7). *Residual:* none.

**Q-BRIDGE-4.** Do overlay addresses get private names? **Decided by owner 2026-11-03 (owner decision 85):** yes, in v0: `<client-name>.<net>.<root>` from the config repo, answered on the device by C14 or `ur tun`'s resolver, never forwarded or published (§12.9). *Residual:* none.

**Q-BRIDGE-5.** Which bind do forwards and local listeners use? **Decided by owner 2026-11-03 (owner decision 84):** 0.0.0.0/:: unless `--listen` narrows it (cli/UI.md:11), forwards disclosed as LAN-exposed (D-TRUST-8). **Decided by owner 2026-11-04 (owner decision 130):** off loopback, git over http, IMAP and SMTP submission serve only TLS, git also ssh, and plaintext stays on 127.0.0.1 and ::1 (I-17); port forwards, which carry the user's own protocol, are unaffected. *Residual:* none.

**Q-BRIDGE-6.** Cross-cutting (§8, §9). Which data plane carries forwards and invites? **Decided by owner 2026-11-03 (owner decision 86):** the IP path for all, cross-network included, with C18 (17.9). *Residual:* none.

**Q-BRIDGE-7.** Cross-cutting (§18). May a chosen block lie outside 100.64/10 and RFC 1918? **Decided by owner 2026-11-04 (owner decision 132):** (b), no: only 100.64.0.0/10, 10/8, 172.16/12 or 192.168/16, narrowing owner decision 28's "any /16" (D-BRIDGE-16). Public exits refuse RFC 1918 today (connect/ip_security.go:897) and 100.64/10 after C6a, so overlay traffic never reaches the internet; any /16, or adding 198.18.0.0/15, was not chosen. *Residual:* none.

**Q-BRIDGE-8.** Cross-cutting (§18). Does an app device claim its overlay address when its forwarding is set up? Owner decision 197 makes the device's overlay address part of its always-on forwarding, while 17.4 assigns one on demand. *Options:* (a) on demand, as 17.4 says: in the app's UI, by the host's first map, or by an admin; (b) at forwarding's setup the sidecar role files its own `BridgeAddress`, so every app device is addressable once C16 lets it host. *Recommendation:* (a): with no ACL document, a hosted address opens the device's loopback to the network's untagged sidecars (17.6's rule 3; owner decision 120), a reach the owner did not ask for, and (b) can follow by one filing at any later setup; 17.4 is written to it (proposed; Q-BRIDGE-8). *Blocks:* nothing before M8's app hosts. *Decider:* owner.

### 17.15 Departures from PLAN.md

- **PLAN.md:117** ("from same network"): owner decision 86 extends maps to cross-network shares (Q-BRIDGE-6).
- **PLAN.md:353 with :359.** Relayed bridge bytes count (owner decision 10); P2P bytes after C3 do not (§20, Q-QUOTA-6).
- **PLAN.md:31.** `device.Bridge`, not the whole `Sidecar`, implements the device abstractions (17.10; Q-SDK-2).
- **cli/UI.md, not PLAN.md:** the added `expose :<port>`, `egress` and `block` forms (17.11).

### 17.16 Interfaces

- **Provides:** `device.Bridge`, `device.BridgeEgressPolicy`, `device.BridgeHost`, `BridgeStatus`; the compiler and forwarding's signer, which apps' VPN components link (§18.6, §18.10); `protocol/bridge/bridge.proto`'s `BridgeState`, `BridgeIdentity`, `BridgeShareKey`, `Pending`, `BridgeRows`, `WindowDelegation`, `ShareCert`, `BridgeShareSigner`, share pins' `BridgeShareGrant`, the share seal's `BridgeShareTargets` and `BridgeShareAliases`, and 17.8's statements; 17.8's states, route export, reach events (§16), the `ur tun` resolver (§12.9).
- **Consumes:** §7.9's config repo, authorization log (`AuthPin`, entries, `StatementHeader`), deltas and `team` hints, and its forwarding Delegations (owner decision 197); §7.4's `strict_exp`; §8 grant chains, `AclEngine`, approvals, suspension, contract gate, shares; §10's generations; §11.12's `secret` kind; §6 `Signed` and §6.11's `SignedType`, Required, §6.10.1; §5 identities, the binding log, `GET /sidecar/identity/<sidecar_id>`, `Sidecar.Authorize`, `SidecarEvent`; §16.6's decisions and `effect_key`; §12.9; §18 `deviceBridge`, forwarding's setup and the device RPC's status mirror; §20.6 debits; §4 C5, C6a, C13, C14, C15, C16, C18.
- **Subprotocol messages:** none; rules ride the config repo (§6.11 leaves MessageType 0x19 unused). `Signed` types 0x1901-0x1909 are 17.8's statements, `WindowDelegation` and `ShareCert`; `BridgeShareSigner`, a config file, takes none (17.9).
- **API routes:** statements through §7's `POST /network/config/delta`; shares through §8's `POST /acl/invite` and `POST /acl/accept-invite`, which carry the sealed tables, the accept status included; `GET|PUT /network/bridge/share/<share_id>` (Client, a sidecar of either network: read both tables, or replace its own at a higher version).
- **Tables:** `network_bridge_share` (api): share_id, both network ids, sealed target and alias tables, versions, `accept_status enum{active, refused_too_large, refused_no_space}`; kept until revoked.
- **Services and config:** no new service and no `sidecar_abuse:` caps; sdk flag `EnableBridge` and §19's `bridge` gate, which keep the bridge dark until its release (§19.11) and are no setting: released, an app's forwarding runs whenever its VPN component runs (owner decision 197); `ur tun` needs CAP_NET_ADMIN or root.
- **Assumptions about other sections:** §7.9 carries 17.8's statements as log entries, its type rule bounding a decision's bridge rules by 17.8's rule ids; §16.6's step 5 has a bridge component whose Lookup finds that id in the authorization log, AU1 counts those rules, `bridge_expose` returns the id, and `bridge_close` takes it or a forward's grant_id (§16.5); `sidecar/device` parses only `protocol/bridge`'s auth.proto (§7.9: `AuthPin`, `AuthEntry`, `ProjectionHeader`, `StatementHeader`, `Genesis`, `SidecarRevoke`, `MemberRevoke`, and §8.8's `Suspend`, `Unsuspend` and `GrantRevoke`) and signed.proto (§6.9: `Signed`, `WebAuthnEvidence`, `SignedType`), which `config.proto` and `acl.proto` import (§4.4); §5.8 and §16.6 sign 17.9's own-resource filings, a host's own `BridgeAddress` among them, from any mode, and other bridge statements only for a /dev/tty-confirmed `ur` command or in an app's UI; §18.6's setup gives an app's VPN component its forwarding Delegation, forwarding clients and `Pending`, after which its forwarding role compiles 17.8's states itself, persists them as its posture and signs its links' delegations with its forwarding key or a share's ShareSigner, and `DeviceLocal` takes the physical path's /32s; §7.9 defines the forwarding Delegation, its signer, what its key signs and its ends, §6.9 that key's `signer_id`, and §7.4 the forwarding client's `forward_only` mark; §2.8 lists `network_bridge_share` with its accept status and C13's delegation with a share's ShareCert, §2.10 17.9's share-signer bound, and §2.6 and §7.9 the ShareKey's custody and the `BridgeShareSigner` seeds every Y config reader, agents included, holds; §6.9's Signers and §5.5's identity-key rule (D-CORE-6) admit 17.9's two share keys; §22 states the dial fence as an invariant (no byte reaches a target after its flow's revocation; D-BRIDGE-21), which FS-56 tests, and tests D-BRIDGE-16 to D-BRIDGE-21, aliases, the no-document rules, the CGNAT carve, private names, MCP's own-resource bridge filings (a host's first map with its `BridgeAddress`) and the refusal of any other (§16.6), a `BridgeAddress` naming another sidecar_id or a second one for an addressed host included, share signers in FS-38's M6-out run with C18 (a ShareSigner-signed delegation passes; a ShareCert below the host's newest verified generation, expired, over 7 days out or not signed by the pinned ShareKey is refused, after a host restart from 17.8's persisted state too; a sidecar Y removed is refused new contracts once a later generation's ShareCert reaches the host, at most 7 days after its removal; with no renewal for 7 days the share lapses), and 17.5's pins: a TCP flow idle 300-600 s keeps its link across a withdraw, a long-lived flow across an advertiser join, and a one-advertiser retarget's live flows through the drain, while a new pair's TCP connection takes the new rule at once and new UDP and ICMP pairs follow the pre-change link for 5 min; a fragmented UDP datagram stays on one link; mobile churn past a full table (§22.9); and §22.9's link cell holds an app-device host's NAT at C5's per-flow idles.

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
| A tun's overlay address leaks in WebRTC (libwebrtc's 100.64/10 handling is unverified) | Unknown | Low | A §22 test before `auto` assigns one |
| Links, or forwarding's compile, do not fit the iOS tunnel | High | Medium | No iOS links until §22 measures; Q-BRIDGE-2's own-client links; the compile cap of owner decision 216, a network past it keeping its last verified state on that device and alarming; links fail closed meanwhile |
| Between the app's runs an app's forwarding role follows the log unwitnessed, so an operator that withholds a revocation from it keeps a revoked subject reaching that device | Low | Medium | the sidecar role's witnessed pin at each run (§18.6); daemon hosts witness by HeadCheck (§6.4); it needs a malicious operator, and the subject's own revocation still ends it at every other device |

### 17.18 Phasing

- **v0, M4 (same network; Linux and WSL2 first):** C5 with its dial fence, C6a, C13 with `WindowDelegation`s, C14; statements in the config repo and 17.8's states, the rule table and the compile of `BridgeRows` landing at M2 with §7.9's records, though nothing files a bridge statement until M4; router, hook (rule 0 included), userspace stack; `ur tun` on Linux; private names via `ur tun`'s resolver and C14's seam, dark on app paths; forwards, expose and egress under I-8 approvals; HA, pins, dispositions, block changes and the CGNAT carve; sidecar-owned hosts; the sdk insertion behind `EnableBridge`. Blocked by §7.9's config repo and authorization log (M2), §8's grant chains and gates, and C13.
- **v0, M8** (with §18's app hosts): forwarding in every app's VPN component, with its own keys, compile and signing (owner decision 197): sending from M8, hosting after C16 in the device client's network, once M8's entry has measured the plaintext an Opportunistic peer has in flight at C16's latch (owner decision 224), iOS links after §22.9's measurement, private names on app paths.
- **v1:** cross-network shares through C18, with ShareKeys, per-generation ShareSigners and the preflight, and `ur tun` on macOS and Windows (M6); P2P after C3 (§6).
- **Later:** L3 delivery, multi-hop maps, IPv6 subnet routes.
