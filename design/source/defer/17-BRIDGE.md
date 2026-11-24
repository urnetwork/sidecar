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

### bridge-discovery-other-platforms: The advertising proxy on Windows, and discovery in the apps
Stage: Later
- **Deferred:** §17.7.1's advertising proxy on Windows, and gathering, sharing, watching and the advertising proxy in the apps, named in §17.18's Later row and §17.7.1 (owner decision 778).
- **Why:** Windows' DNS-SD API browses `.local` names alone and documents no registration scoped to the machine (learn.microsoft.com's `DNS_SERVICE_BROWSE_REQUEST` and `DnsServiceRegister`). Android's NsdManager browses `local.` alone and runs no mDNS on a VPN service's tun, which Android brings up without the multicast flag (AOSP's MdnsSocketProvider.java and com_android_server_connectivity_Vpn.cpp). On iOS, raw multicast needs Apple's `com.apple.developer.networking.multicast` entitlement, and Bonjour browsing needs local network access, which a packet tunnel provider has but its container app may not (Apple's TN3179). App devices host only after C16, and Android's sidecar role runs only while the app is open (owner decision 197).
- **Launch instead:** `ur daemon` gathers, shares and watches on Linux, macOS and Windows, and runs the advertising proxy on macOS and Linux; a Windows desktop answers §12.9.1's names under `ur tun`; an app's VPN component owns those names and answers each NODATA (§12.9.1).
- **Lost:** On Windows, apps that browse only multicast do not see the network's instances; a phone neither publishes the devices on its own LAN nor shows the network's.
- **Dark in code:** Nothing is built for these platforms.
- **Held:** Nothing: no task or track waits on it.
- **To bring back:** For Windows, a registration the DNS Client keeps on the machine, or a responder on `ur tun`'s adapter if the system's mDNS uses it, each measured; for iOS, a LocalOnly registration from the app process or the entitlement; for Android, a path NsdManager uses, which a VPN service's tun does not give; and for the apps, the sidecar role's view handed to the VPN component (DESIGN-DEFER.md's dns-service-discovery-app-paths entry).

### bridge-v1: §17's v1 set
Stage: v1 (M6)
- **Deferred:** §17.18's v1 row: cross-network shares through C18, with ShareKeys, per-generation ShareSigners and the preflight; `ur tun` on macOS and Windows; service discovery across hosts, with sharing, watches, the advertising proxy on macOS and Linux and its IPv6 translator (§17.7.1; owner decision 778); P2P, built at M6 behind `EnablePeerP2p` and off until an owner call (owner decision 296).
- **Why:** Shares and the other platforms' tun belong to M6 (owner decision 86).
- **Launch instead:** v0 at M4, same network, Linux and WSL2 first; at M8, forwarding in every app's VPN component (owner decision 197).
- **Lost:** Until M6: sharing across networks, `ur tun` on macOS and Windows, and finding a device on another host's LAN.
- **Dark in code:** Built in the same run on the `sidecar` branches. P2P's switch has its own entry under §6.
- **Held:** Nothing.
- **To bring back:** Nothing to bring back: it ships when M6's gate passes (§23.6).
