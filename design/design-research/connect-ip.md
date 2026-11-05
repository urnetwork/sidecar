# Fact sheet: the connect/SDK IP data path as the substrate for "IP Address and Port Forward (bridge)"

Scope: the bridge section of the plan (sidecar/PLAN.md:113-119): subnets associated with a client, destination ip:port remapping when IP-providing for the same network, and rules stored on the server and pushed to clients in real time. Code was read at connect `49f285f1` and sdk `eb552288` (HEAD, 2026-11-03). Paths are relative to /Users/brien/urnetwork. Where a comment and the code disagree, the code is treated as correct.

## 1. Summary

1. Today a packet goes: OS tun → `DeviceLocal.sendPacket` (a lock-free route snapshot) → `UpgradeMux` (which claims :53, :80 and :853) → `RemoteUserNatMultiClient` (security policy, block-action overrides, picks a window client for each flow) → the provider's `RemoteUserNatProvider` (relationship taken from the contract) → `LocalUserNat` (a user-space NAT that opens real sockets) → internet. The NAT builds every return packet from the flow's original identity (sdk/device_local.go:5674-5743; connect/ip_remote_multi_client.go:6659-6831; connect/ip.go:10107-10443, 4075-4109).
2. Nothing routes by destination to a chosen client today. The "default route" is the whole multi client, and changing it rebuilds the multi client and drops every flow (sdk/device_local.go:4984-5031). The nearest per-destination mechanism is `BlockActionOverride`/`RouteOverride{Local,Pin}`, a compiled matcher swapped in atomically (connect/ip_block_action.go:33-69, 668-673).
3. The best place for subnet routing is the SDK's `DeviceLocal.sendPacket` and `sendPacketsWithPolicy`, before the UpgradeMux (sdk/device_local.go:5696, 5789). It would add an immutable longest-prefix table next to `deviceLocalSendRoute`. The batch path has to be split per destination.
4. The best place for port mapping is the provider's `LocalUserNat` at dial time: the TCP dial (connect/ip.go:5670-5677), the UDP dial (3597-3603) and ICMP egress (connect/ip_icmp.go:786). Because the NAT synthesizes replies from the original flow path, changing only the dial target gives DNAT with no checksum rewriting and no return-path rewriting. It runs once per flow, not once per packet.
5. Same-network trust comes from the platform-signed contract: `Peer.ProvideMode` (connect/transfer.go:17291) plus the sealed `roles`/`principal` (connect/protocol/transfer.proto:631-637). For Network sources the provider policy allows every destination, including LAN and loopback (connect/ip_security.go:567-569). There is no per-port or per-destination ACL.
6. No client has an overlay or virtual IP. The device tun is a random 10.a.b.h/24 by default or comes from the 169.254/16 pool, with IPv6 a random address in fd00:7572:6e65::/48 (sdk/device_local.go:1851-1876; sdk/tunnel_address_ipv6.go:25). The only durable per-client address pool is the server's WireGuard `proxy_client_ipv4` (server/model/network_client_proxy_model.go:1096-1180).
7. All four app platforms exclude RFC1918, and fc00::/7 for IPv6, from the tun (apple/app/extension/PacketTunnelProvider.swift:1802-1806; android/app/app/src/main/java/com/bringyour/network/MainService.kt:754-758; windows/app/src/Service/NetPolicy.h:80-82; linux/app/src/Tunnel.hpp:575). Peer LAN subnets never reach the SDK unless the apps add more-specific routes.
8. A real-time push precedent exists. The server Resident sends `NetworkPeersReset` and then `NetworkPeersUpdate` control frames from ControlId, which need no contract. They are driven by Redis keyspace events with a version-counter poll as backstop (server/connect/resident.go:4783-4857; connect/transfer_contract_manager.go:686-697). Peer subprotocol messages need a contract, and ControlId is barred from subprotocols (connect/subprotocol.go:902-905).
9. On userspace TCP: `connect.Tun` (gVisor) dials and listens only on its own address, with no promiscuous or spoofing mode (connect/tun.go:253-312, 1335-1355). The provider side needs no tun at all, because `LocalUserNat` terminates TCP itself. A tun-less sidecar can be assembled from exported connect pieces.
10. Module constraints: sidecar can use only exported connect symbols. It must repeat connect's `replace` lines for gvisor, glog and sctp (connect/go.mod:98-102). connect cannot import sidecar, so any provider-side hook has to be a type defined in connect.

## 2. Facts by topic

### 2.1 Client send path (device tun to exit)
- Entry points are `SendPacket`, `SendPacketNoCopy`, `SendPacketBatch` and `SendPacketsNoCopy` (sdk/device_local.go:5598-5653). Single packets go to `sendPacket` (5674) and bursts to `sendPacketsWithPolicy` (5755). SDK sockets go through the same path (`OpenSocket`: private `connect.Tun` → `sendPacketsNoCopy`, sdk/socket.go:112-141; sdk/SOCKET.md:70-80).
- Routing reads `deviceLocalSendRoute{remoteUserNatClient, upgradeMux, routeLocal, provider}` with one atomic load and no lock. It is rebuilt under `stateLock` by `updateSendRouteWithLock` (sdk/device_local.go:1167-1173, 5655-5672, 5696). Order: mux → remote client → local NAT → drop (5698-5742). Every device packet carries `source=SourceId(clientId)` and `ProvideMode_Network` (5692, 5703).
- The batch path loads the route once and gives the whole burst to one route (sdk/device_local.go:5789-5838). The mobile packet-pressure gate runs before routing (5675-5691, 5764).
- `UpgradeMux` (connect/ip_mux_upgrade.go:3-7) claims UDP and TCP :53 to *any* destination whenever a resolver is configured (1008-1019). It passes TCP/80 through or blocks it (1020-1021, 1097-1102), refuses TCP/853 only toward the DNS stand-in, and reads the SNI on TCP/443 (981-1001).
- `RemoteUserNatMultiClient.sendPacketWithPolicy` (connect/ip_remote_multi_client.go:6659-6831) does, in order: fragment gate (6666-6689); relationship (6691); ICMP gate, off by default (6698-6704); TCP/25 sent to its own local NAT (6708-6713); SMTP guard (6714-6724); policy inspection (6725); block-action decision (6750-6756); `securityRoute` (6763); then block, local (6787-6795) or remote with a pin (6799-6830). Batches are grouped per exact flow (7097-7102), and the same decisions run per group in `sendPacketGroup` (7165, 7202, 7237).
- `egressRelationship` is Network only when both the source and the client are Network (connect/ip_security.go:385-390). For Network the policy allows everything (567-569). Otherwise a non-public destination is an Incident (574-576), which is always blocked and cannot be overridden (connect/ip_block_action.go:603-606). `isPublicUnicast` uses Go's `IsPrivate`, which covers only RFC1918 and RFC4193, plus loopback, link-local, multicast, unspecified and some IPv6 reserved ranges (connect/ip_security.go:892-908; https://pkg.go.dev/net#IP.IsPrivate). **100.64.0.0/10 passes as public.** The blocklist generator also subtracts 100.64/10 from the blocklist, on the false assumption that the egress path already refuses it (connect/security/main.go:115-126).
- `RemoteUserNatClient` takes a single destination set (connect/ip.go:10570-10792). It uses a random per-5-tuple `pathTable` whose map is never evicted ("TODO clean up", 11017-11080). By its own comment it is a test fixture, not a production path (10746-10755).

### 2.2 How the default route is chosen and changed
- `SetDestination`, `SetConnectLocation` and `Reconnect` all go through `applyDestination`. It keeps the live multi client only if the spec fingerprint and the transport are unchanged (sdk/device_local.go:4984-4992). Otherwise it closes the mux and the client and builds new ones (5030-5031, 5296-5309), which drops every flow.
- `ApiMultiClientGenerator` discovers providers for each spec and excludes the device itself (sdk/device_local.go:5131-5194). Every window client is a new network client with `SourceClientId` set to the device (connect/ip_remote_multi_client_api.go:1026-1027). **A provider therefore sees a window client id, not the device's client id.**
- `sendUpdate` binds each Ip4Path or Ip6Path to a window channel under `stateLock`, using domain or app affinity and DNS hints (connect/ip_remote_multi_client.go:5245-5374). `Shuffle` acts on the windows (10610-10617). `RemoveProvider` drops a provider and excludes it from rediscovery (10630-10643).
- "Network peer" destination: `ConnectLocation.NetworkPeer` (sdk/sdk.go:999-1003) builds the multi client with `ProvideMode_Network` (sdk/device_local.go:5052-5062, 5287-5302). That forces direct P2P (connect/ip_remote_multi_client.go:3191-3201) and sets the network window flag (2908). This is today's only way to route through one's own device, and it takes the whole default route, not a subnet.

### 2.3 Provider (exit) path
- The provider is a `RemoteUserNatProvider` on the device's provider client (connect/ip.go:7848-7982). It exists when the provide mode is not None (sdk/device_local.go:4727-4731, 6325-6415). Its exit NAT is a separate `LocalUserNat` whose sockets use `ProviderDialContextSettings` (sdk/device_local.go:863-870, 4650-4678, 6340-6345). The route-local NAT is a different instance (sdk/device_local_provider.go:278-286).
- Ingress runs `ClientReceive` → `clientReceiveAdmitted` (connect/ip.go:10090-10443). `provideMode := peer.ProvideMode` (10122) comes from the receive contract (connect/transfer.go:17291). Then: parse (10253), SMTP guard (10260-10304), and reverse-policy inspection (10307-10313), which for Network resolves to the allow-all rule (connect/ip_security.go:830-843, 567-569). Packets are grouped per flow and handed to `localUserNat.sendTransferPacketsWithTimeout(...,0,...)` (10358-10431).
- Reliable-lane TCP also passes through `clientReceiveAdmitted`, then `queueReliablePacket` → `enterNat` → `enterTcp` (connect/ip_provider_reliable_ingress.go:50-73, 158-191; connect/ip.go:1965-1975). That makes `clientReceiveAdmitted` the single ingress chokepoint.
- `LocalUserNat` dispatches in `runSendShard.handleIpPacket` (connect/ip.go:1616-1957). The default is one shard (741-744). Flow buffers are keyed by `{source, srcIp, srcPort, dstIp, dstPort}` (2072-2109).
  - TCP dials upstream before it sends the SYN+ACK, using `DialContext(ctx,"tcp",IpPath().DestinationHostPort())` (5655-5679). A failed dial becomes a RST or an unreachable sent back to the source (5680-5719).
  - UDP opens one connected socket per flow (3595-3634).
  - ICMP calls `newIcmpEgress(ctx, ver, destinationIp, ...)` directly, *not* through DialContext (connect/ip_icmp.go:782-786).
- Replies are built from the stored flow identity (`StreamState`/`ConnectionState`, connect/ip.go:3971-4036, 4075-4109).
- Dial hook: `ConnectSettings.DialContext` delegates to `DialContextSettings.DialContext` when that is set (connect/net.go:219-231, 248-249). The hook sees only `(ctx, network, addr)`.
- Precedents:
  - A per-flow context value read at dial time: `providerEgressTarget.dialContext` (connect/ip_egress_realism.go:84-136).
  - In-memory termination of a reserved destination range: synthetic speed for 198.18/15 and 2001:2::/48 (connect/ip.go:5661-5668; connect/ip_synthetic_speed.go:45-57).
  - Per-source teardown across all protocol buffers: source retirement (connect/ip.go:159-161, 933-1015, 1643-1652).

### 2.4 Provide modes and "exit for own network only"
- Protocol modes are None, Network, FriendsAndFamily, Public, Stream and PublicStream (connect/protocol/transfer.proto:354-361). The device mode Network enables only Network contracts (sdk/device_local.go:4733-4746).
- Control modes (sdk/device_local.go:3446-3466, 5397-5406):
  - auto: Public while connected, Network while idle;
  - always;
  - network, the "private provider";
  - manual;
  - never, which is also the default for a device without a provider (1840-1843).
- The server computes Network if both clients share a `network_id` and Public otherwise. It does not compute a FriendsAndFamily relationship (server/model/network_client_model.go:2258-2345). If the destination's modes do not match the relationship, contract creation is rejected with `provide_mode_unavailable` (server/controller/connect_controller.go:595-614, 909-925).
- Network contracts seal the source's `roles` and `principal` (connect/protocol/transfer.proto:631-637), exposed as `Peer.Roles`/`Peer.Principal` (connect/transfer.go:608-611). Server ACL groups are only `default` and `isolated` (server/model/network_client_acl_group_model.go:11-31).
- inference: any same-network source, including a hand-built connect client, can make a Network provider dial its LAN or 127.0.0.1. Nothing in connect restricts this beyond the contract relationship (ip_security.go:567-569 together with ip.go:5673).

### 2.5 Address plan and DNS interception
- Device tun IPv4: when `UseExperimentalTunnelAddress` is set (the default, sdk/device_local.go:444), the address is `RandomLocalIpv4(LocalIpv4Networks())`, the lowest free 10.a.b.0/24 with host 2..254. Otherwise it comes from connect's 169.254/16 pool (sdk/device_local.go:1851-1876; connect/tun.go:526-551). Apple assigns it with mask /24 (apple/app/extension/PacketTunnelProvider.swift:1796).
  - The Windows and Linux comments mention 169.254.2.1 (windows/app/src/Service/NetPolicy.h:52; connect/egress_resolver_linux.go:350), but both apps read `device.tunnelLocalAddress()` (windows/app/src/Service/TunnelController.cpp:1105; linux/app/src/daemon/TunnelHost.cpp:985). Code wins.
- Device tun IPv6: a random interface id and subnet id in fd00:7572:6e65::/48, prefix /64 (sdk/tunnel_address_ipv6.go:25-55).
- gVisor `Tun` addresses (connect/tun.go:387-404, 477-488): IPv4 from 169.254/16; IPv6 from fd75:726e:6574::/96, inside the /64. They are process-unique, and peers cannot know them.
- DNS stand-ins: 65.49.70.65 and 2001:db8::65:49:70:65 (connect/net_http_doh.go:329, 337).
- DNS has local-answer branches in `handleDns`: resolver.arpa NODATA and blocker answers (connect/ip_mux_upgrade.go:1622-1680). There is no hook for a local zone.
- The server WireGuard proxy holds durable peer addresses from a shuffled `proxy_client_ipv4` pool of 10M RFC1918 addresses that avoids common subnets (server/model/network_client_proxy_model.go:1096-1180). It rewrites them to a per-device 169.254 address on the way out (server/proxy/proxy_device.go:1369-1374, 1818-1852).

### 2.6 OS routes in the apps
- iOS/macOS: included route 0.0.0.0/0; excluded 10/8, 172.16/12 and 192.168/16; IPv6 excludes fe80::/10, fc00::/7, ff00::/8 and ::1 (apple/app/extension/PacketTunnelProvider.swift:1797-1821; apple/app/extension/TunnelIpv6Routes.swift:30-35). Settings are re-applied by a deduplicated plan (apple/app/extension/PacketTunnelProvider.swift:1985-2030).
- Android 13 and later: `addRoute 0/0` plus `excludeRoute` of the same three RFC1918 ranges (android/app/app/src/main/java/com/bringyour/network/MainService.kt:754-758). Windows and Linux have the same exclusions (windows/app/src/Service/NetPolicy.h:45-82; linux/app/src/Tunnel.hpp:510, 575).
- Android documentation (https://developer.android.com/reference/android/net/VpnService.Builder, API 33): "If multiple routes match the packet destination, route with the longest prefix takes precedence." Changing parameters means calling `establish()` again, which is a seamless handover to a new fd.
- Apple documents `includedRoutes` and `excludedRoutes` but not how they resolve when they overlap (https://developer.apple.com/documentation/networkextension/neipv4settings; DTS reply in Mar/Apr 2021 at https://developer.apple.com/forums/thread/677054: "routes ... added in the order that you add them").

### 2.7 Userspace TCP/IP (gVisor and connect's own NAT)
- `connect.Tun` uses a private gVisor stack with one NIC and a default route per family (connect/tun.go:1-14, 863-981). It exposes `DialContext`, `DialResolvedContext`, `ListenTCP` and `ListenUDP`, which bind only to its own address (1335-1406). `newTunStack` does not set promiscuous mode, spoofing or forwarders (253-312), and connect, sdk and server/proxy never call `NewForwarder`, `SetPromiscuousMode` or `SetSpoofing`.
- connect uses the gvisor fork at ../gvisor through `replace` (connect/go.mod:102). In that fork, `SetPromiscuousMode` is at gvisor/pkg/tcpip/stack/stack.go:1834, `SetSpoofing` ("allowing endpoints to bind to any address") at 1849-1851, and `tcp.NewForwarder` at gvisor/pkg/tcpip/transport/tcp/forwarder.go:42-47.
- `IpMux` is a Tun-backed stage that sends upstream to a UserNat and returns packets for its own address back into the Tun (connect/ip_mux.go:1-17, 108-146).
  - The UpgradeMux shows the full DNAT pattern: it rewrites a DNS-over-TCP destination to the Tun address (`rewriteDnsTcpAddress`, connect/ip_mux_upgrade.go:867-945) and restores the source in `onPump` (950-971).
  - That helper is TCP-only and address-only. `RewriteIpv4Source/Destination` (RFC 1624) is IPv4-only and also address-only (connect/ip_nat_rewrite.go:1-19, 71-80). Neither rewrites ports.
- The tun-less template already exists: server/proxy wires a `connect.Tun` to a DeviceLocal (`ReadBatch` → send; receive → `WriteBatch`; `tun.DialContext` for HTTP/SOCKS) (server/proxy/proxy_device.go:1333, 1550-1609, 1924). connectctl shows a client built only from connect (`NewClientStrategyWithDefaults`, `NewBringYourApi`, `NewApiOutOfBandControlWithApi`, `NewClientWithDefaults`; connect/connectctl/main.go:602-641).
- inference: "expose a local port" needs no tun on the exposing side. Its `RemoteUserNatProvider` plus `LocalUserNat` already terminate a peer's TCP in user space and dial real sockets. "Dial into a peer subnet" without an OS tun is `connect.Tun.DialContext` → a Network-mode UserNatClient aimed at the target, the same shape as the SDK sockets.
- Prior art: Tailscale netstack (BSD-3, https://github.com/tailscale/tailscale/blob/main/wgengine/netstack/netstack.go) calls `SetPromiscuousMode(nic,true)`, uses `tcp.NewForwarder` and `udp.NewForwarder`, adds subnet addresses to the NIC on demand, and rewrites its own service IP to loopback before dialing.

### 2.8 Real-time delivery to a device
- Peers precedent:
  - The client `PeerManager` handles `NetworkPeersReset` followed by `NetworkPeersUpdate` (full list on connect, then diffs) as top-level control frames (connect/transfer_peer_manager.go:30-36, 228-293; connect/protocol/transfer.proto:428-454).
  - The server Resident registers a `NetworkPeerListener` for top-level client-category peers only; proxy and isolated clients get none (server/connect/resident.go:4783-4805). It sends frames from control with `sendListenerFrame` (4819-4857).
  - Live deltas come from one per-exchange Redis keyspace subscriber (server/connect/key_event_subscriber.go:62-73). The listener polls the per-network version counter as a backstop (server/model/peer_model.go:2191-2196).
- Contracts: ControlId traffic needs no contract (connect/transfer_contract_manager.go:686-697). Peer messages do, and the server rejects a contract when the destination does not provide the relationship's mode (connect_controller.go:917-925).
- Subprotocols:
  - Sending to ControlId is refused (connect/subprotocol.go:902-905; connect/SUBPROTOCOL.md:372-373).
  - Client dispatch does not check the source (connect/transfer.go:4262-4271; connect/subprotocol.go:590-652). inference: a Subprotocol frame from control would be delivered, but that contradicts the documented rule.
  - The SDK attaches subprotocols to the device's own top-level client (sdk/device_local_subprotocol.go:15-26).

### 2.9 Rule machinery that already exists
- `blockActionMatcher` compiles exact hosts, wildcards, addresses and prefixes. Prefixes are a linear slice scanned on every uncached decision (connect/ip_block_action.go:467-527, 638-643).
- Decisions are cached per destination and extended over the destination's IpAssoc *cluster* (connect/ip_remote_multi_client.go:7338-7419, 7384-7395).
- `SetBlockActionOverrides` swaps the matcher atomically, bumps a version and clears the cache (7447-7458). The SDK applies new overrides to the live multi client (sdk/device_local.go:7212-7213) and re-applies them after a rebuild (5375).
- inference: an override change takes effect for the next packet of an already established flow, so it is not flow-preserving. The code comments say a TCP flow cannot move mid-connection (connect/ip_remote_multi_client.go:6577-6594).
- userwireguard (a wireguard-go fork) ships the WireGuard AllowedIPs radix trie (userwireguard/device/allowedips.go:191, 207).
- bart v0.30.0 (2026-09-21, MIT, https://pkg.go.dev/github.com/gaissmai/bart) provides `Lookup`, `Contains` and `LookupPrefixLPM`, plus `InsertPersist`, `DeletePersist` and `ModifyPersist`. Readers can use immutable snapshots without a lock.

### 2.10 External prior art (dated)
- Tailscale assigns 100.64.0.0/10, the address is stable per device, and it warns of conflicts with other VPNs using the same space (https://tailscale.com/kb/1015/100.x-addresses, validated 2026-01-12).
- RFC 6598 (Apr 2012) reserves that block for service-provider use (https://www.rfc-editor.org/rfc/rfc6598). ULA space is defined in RFC 4193 (https://www.rfc-editor.org/rfc/rfc4193).
- Tailscale subnet routers (https://tailscale.com/kb/1019/subnets, validated 2026-09-29):
  - route approval is separate from access rules;
  - SNAT is on by default;
  - the longest prefix wins, with "no fall back to a less-specific route" when the more-specific router goes offline.
- Tailscale 4via6 encodes a site id plus the IPv4 address in fd7a:115c:a1e0:b1a::/64 to handle overlapping subnets (https://tailscale.com/kb/1201/4via6-subnets, validated 2026-10-05).

### 2.11 Answers to (a), (b) and (c)
**(a) Insertion points**
- Subnet routing, on the sending device:
  - `DeviceLocal.sendPacket` after `route := self.sendRoute.Load()` (sdk/device_local.go:5696), and `sendPacketsWithPolicy` after line 5789, which must split the burst per destination. Both come before the mux, so bridged :53 and :80 flows are not claimed.
  - Peek the destination at fixed offsets (IPv4 [16:20], IPv6 [24:40]), use a nil-table fast path, and do an allocation-free longest-prefix lookup. Send matches to a Network-mode UserNatClient for the target. Its receive side is wired to `DeviceLocal.receive` and `receivePackets` (4235-4269).
  - Alternative, in connect: a `RouteOverride` that names a client, inside `sendPacketWithPolicy` and `sendPacketGroup` (ip_remote_multi_client.go:6763, 7237). That inherits cluster extension and per-packet re-evaluation (2.9), and the default multi client's Public relationship turns private destinations into Incidents (2.1).
- Port mapping, on the providing device:
  - Preferred: a per-flow resolve at `TcpSequence` (connect/ip.go:5670-5677), `UdpSequence.openSocket` (3597-3603) and ICMP (connect/ip_icmp.go:786). The hook receives source, provideMode and IpPath and returns *pass*, *map(addrPort)* or *deny*. Deny reuses the RST path (5700-5717).
  - Alternative: packet NAT in `clientReceiveAdmitted` after an Allow verdict (connect/ip.go:10316-10335). This needs a port-aware rewrite in both directions, a copy instead of `MessagePoolShareReadOnly`, and a reverse rewrite on the return path.
- Hot paths that must not slow down: `DeviceLocal.sendPacket` and `sendPacketsWithPolicy`; `UpgradeMux.onSend`; the multi-client send functions; `clientReceiveAdmitted` (a shared callback that must never block, connect/CODESTYLE.md:117-121); `runSendShard.handleIpPacket`; and `DeviceLocal.receive`. Dials happen once per flow and are not hot.

**(b) What changes where.** The user request is that the new pieces live in the sidecar repo.
- **sidecar** holds:
  - the rule model and protobufs (`sidecar/protocol`);
  - the compiled immutable route and port-map tables;
  - a versioned apply engine with flow pins;
  - the push subscriber;
  - the bridge router and port mapper, implementing the SDK and connect interfaces;
  - the CLI's userspace composition (`connect.Tun` with a UserNatClient for egress, and `LocalUserNat` with `RemoteUserNatProvider` for exposing ports).
- **connect**, minimal and generic:
  - the per-flow egress-target hook type on `LocalUserNatSettings`, or a flow-identity context value passed into `DialContextSettings`, because connect cannot import sidecar;
  - optional exports (a policy-reset helper, a port-aware rewrite);
  - a push carrier if control frames are chosen (2.8).
- **sdk** (which imports sidecar):
  - the call sites from (a);
  - the bridge client lifecycle;
  - installing the hook on the exit NAT (sdk/device_local.go:6340-6345);
  - exporting included routes plus a change listener so the apps can re-apply routes;
  - `Device` and DeviceRemote RPC surface only for UI (sdk/device_rpc.go:239-243).
- **server** (which imports sidecar): rule storage, per-client fan-out, ACL and virtual address allocation.

**(c) Real-time updates without disrupting flows**
- Delivery: the Resident pattern (reset plus diff, a version counter, a corrective poll, no contract), sent per client by the Resident that holds the client's transports.
- Apply:
  - Compile off the packet path and swap an `atomic.Pointer`. This follows `sendRoute` and `blockActionState`, and bart's `...Persist` methods fit.
  - Pin existing flows to their route by tuple, so table changes affect new flows only.
  - On revocation, send a TCP RST or ICMP unreachable to the local app.
  - Move a target make-before-break: start the new target client first and let old flows drain.
  - On the provider, a dial-time mapping already affects new flows only. Revoking a mapping needs a new per-mapping flow kill; source retirement covers only a whole source.
- OS routes:
  - Pre-route one fixed overlay block so virtual subnets change without OS churn.
  - Real LAN routes mean re-running `establish()` on Android and `setTunnelNetworkSettings` on Apple.

## 3. Constraints the design must respect
1. The packet path does no I/O, no PostgreSQL and no blocking in shared callbacks (connect/CODESTYLE.md:106-107, 117-131). Rule lookups are in-memory, lock-free snapshots.
2. Every delivery path must carry the decision (CODESTYLE.md:98): single, batch and native sends; SDK sockets; the reliable provider lane.
3. TCP flows cannot change exit mid-connection (connect/ip_remote_multi_client.go:6577-6594). Updates must pin flows.
4. The bridge must run under a Network relationship on both ends. The default Public multi client blocks private destinations as Incidents (connect/ip_security.go:385-390, 574-576).
5. A bridge target must provide at least Network (sdk/device_local.go:4742-4746). Devices set to `never` reject Network contracts.
6. Port mapping applies only to `peer.ProvideMode==Network` sources (sidecar/PLAN.md:117). A destination-only remap is safe from public sources only when the mapped range is inside Go's `IsPrivate`; 100.64/10 is not.
7. An unmapped virtual or overlay address must fail closed at the provider and at the public multi client. It must never be dialed onto a real network.
8. The overlay range must avoid 169.254/16, fd75:726e:6574::/64, fd00:7572:6e65::/48, the tun's own 10.a.b.0/24, 198.18/15, 2001:2::/48 and the DNS stand-ins.
9. Apps exclude RFC1918 and fc00::/7, so routes must be exported for the apps to add.
10. sidecar can use only exported connect API, must replicate connect's `replace` directives (connect/go.mod:98-102; sdk/go.mod:107-115), and must not import sdk or server.
11. Hosted or proxy devices get no peer-listener pushes (server/connect/resident.go:4783-4787) and are `HostedIncompatible` (sdk/device_local.go:5242-5245).
12. New `Device` methods need DeviceRemote RPC entries (sdk/device_rpc_methods.go).

## 4. Reusable pieces (exact names)
- connect types: `UserNatClient`, `UserNatBatchClient`, `UserNatNativeBatchClient`, `ReceivePacketFunction`, `ReceivePacketsFunction`, `SourceId` (connect/ip.go:62-86, 199-223; connect/ip_native_ingress.go:14-17).
- `NewRemoteUserNatMultiClient(ctx, generator, receive, ProvideMode_Network, settings)` with fixed `ProviderSpec{ClientId}`, which gives direct P2P. Also `NewRemoteUserNatClient` (fixture-grade).
- `TryNewLocalUserNat`, `TryNewRemoteUserNatProviderWithPacketStats`, `LocalUserNatSettings.{Tcp,Udp}BufferSettings.DialContextSettings`, and `DialContextSettings{DialContext}` (connect/net.go:219-231).
- `CreateTunWithResolver`, `Tun.DialContext/ListenTCP/ListenUDP/ReadBatch/WriteBatch`, and `NewIpMux`.
- `ParseIpPath`, `ParseIpPathWithPayload`, `IpPath`, `RewriteIpv4Source/Destination`, `MessagePoolCopy/Return/ShareReadOnly`.
- `TakeLocalIpv4Address`, `LocalIpv6Prefix`, `RandomLocalIpv4` (connect/tun.go).
- Subprotocol API: `RegisterSubprotocol`, `ProtoCodec`, `SendSubprotocol*`, `Client.AddSubprotocolRawCallback`, plus SDK `EnableSubprotocol` and `SendSubprotocolBytes`.
- Peers: `Client.NetworkPeers()`, `PeerManager().PeersMonitor()`, SDK `GetNetworkPeers` and `AddNetworkPeersChangeListener` (sdk/device_local.go:8271-8300).
- Patterns to copy: `deviceLocalSendRoute` with `updateSendRouteWithLock`; `blockActionState` with `SetBlockActionOverrides`; the Resident listener plus `sendListenerFrame`; `providerEgressTarget.dialContext`; the synthetic-speed bypass.
- External: bart `Table` with `Lookup` and `InsertPersist`; userwireguard `AllowedIPs` (MIT and BSD lineage).

## 5. Gaps, risks, surprises
- No overlay or virtual IP and no per-client address registry exist. Tun addresses are random and only meaningful locally (2.5).
- 100.64.0.0/10 counts as public unicast in connect and is removed from the blocklist. A Tailscale-style CGNAT overlay would leak to public exits if no bridge rule matched (connect/ip_security.go:892-908; connect/security/main.go:115-126).
- Overlapping LANs are common (192.168.1.0/24), and the device's own 10.a.b.0/24 tun subnet can collide with a peer LAN. Prefix-to-prefix remapping at the provider, done with the same dial hook, is the likely way out.
- Network peers can already make each other's providers dial loopback and LAN, with no per-port ACL (2.4).
- A provider sees window-client ids, not device ids (2.2). Per-device ACLs need `principal`/`roles` or the device's provider client to be the sender.
- ICMP egress bypasses DialContext (connect/ip_icmp.go:786), and multi-client ICMP is off by default.
- Apple does not document how included and excluded routes resolve when they overlap. Android route changes re-run `establish()` (2.6).
- Subprotocol pushes from control break the documented rule. Peer pushes need contracts and provide modes (2.8).
- Override changes are not flow-preserving, and block-action matches extend over the IpAssoc cluster. Both are wrong semantics for subnet routes (2.9).
- The extension runs a hosted proxy device that gets no peer pushes. Under js connect has no raw sockets, so the extension cannot provide or expose ports (inference from the `*_js.go` set and sdk/device_rpc_extension_js.go:41-60).

## 6. Open questions for the owner
1. Does "routed through a device" mean only the sending device's tun path, or also multi-hop (a provider forwarding into a third client's subnet)?
2. Should there be an overlay range for per-client virtual IPs? If so, which one (RFC1918 or ULA versus 100.64/10), and does it map to `<name>.<me>.ur.network` through split DNS in the mux?
3. Push carrier: new top-level control messages in connect, or allowing sidecar Subprotocol frames from ControlId through the Resident?
4. Should port-map ACLs key on network membership only, or on `principal`/`roles`, or on device identity (which needs the device's provider client as sender instead of window clients)?
5. Is a connect change acceptable for the per-flow egress-target hook, or must DNAT be limited to what a `DialContextSettings` wrapper can do?
6. On a rule removal or change, should active flows be reset immediately or allowed to drain?
7. Must bridge targets on `never` or Public provide modes be supported, or does the bridge require the "network" private-provider mode?
8. Are hosted, extension and isolated clients in scope as bridge sources or targets?
