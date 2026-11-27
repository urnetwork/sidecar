# Zero-trust networking, tunnels and developer edge tools sold to teams: pricing, vendor visibility and agent positioning (state as of 26 November 2026)

Scope and conventions:
- **Dates.** Pricing pages marked "checked 26 Nov 2026" were fetched on that date. Older material is labeled with its own date.
- **Reused material.** Items marked "earlier note" come from local research notes written 31 Oct to 1 Nov 2026, which cite primary pages accessed then:
  - `research_notes/Tailscale tailnet onboarding and access/` (Tailscale SSO, SCIM, roles, device approval, auth keys, control plane, Headscale)
  - `research_notes/Top sidecar overlap tools/reach_usage.md`
  - `research_notes/User gaps in top tools/tunnel_user_gaps.md`
  - `research_notes/Sidecar positioning and market gaps/incumbent_bundling.md`
  - `research_notes/Agent work record gaps and features/record_feature_benchmark.md`
  - `research_notes/Sidecar pitch4 differentiation directions/L1-1.06…`, `L1-1.07…` and `L1-1.10…`

  Tailscale onboarding (SSO, SCIM, roles, device approval, auth keys) is **not** redone here.
- **Search summaries.** "(search summary)" means the fact came from a search-engine summary of the linked page, not from a page fetched in full. Treat it as moderate confidence.
- **Three visibility layers, kept apart throughout:**
  - (a) data-plane encryption between devices;
  - (b) what the control or coordination plane stores and sees;
  - (c) where TLS terminates for public ingress.

  Vendor-terminated TLS is never called end-to-end here.

---

## 1. Which tools would a team weigh against a CLI that gives every device and agent a private IP, port forwarding, a public TLS edge, storage and email, with roles and the team's own IdP?

### Takeaway
No incumbent ships that whole bundle with vendor-blind transport.
- **Cloudflare** is the only vendor that sells every piece:
  - Mesh private IPs (launched 14 Apr 2026)
  - Tunnel
  - Email Routing and Email Service
  - Artifacts storage
  - Access with your IdP
  - AI Gateway and MCP portals

  Every piece runs through Cloudflare's edge, which can inspect the traffic.
- **Tailscale** is the strongest neutral mesh. It offers private IPs, Serve and Funnel, tsidp, the Aperture AI gateway, roles and SCIM, but no storage or email.
- **The 2026 entrant to watch is doxx.net.** It opened an "Agentic Defined Networking" public beta in Oct 2026, with a reported $38M a16z Series A, per-network IP space and DNS root, native MCP, and strong privacy claims.

### Cited Findings

#### Capability map (who covers which piece of the bundle)
- **Tailscale.**
  - Mesh with private IPs (WireGuard).
  - **Serve** publishes a local port only inside the tailnet on an HTTPS `*.ts.net` name, with identity headers.
  - **Funnel** is the public path. It is beta, TLS-only, limited to ports 443, 8443 and 10000 and to tailnet DNS names, with non-configurable bandwidth limits (earlier note; docs validated 20 Jan 2026). — [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve); [Tailscale Funnel](https://tailscale.com/kb/1223/funnel)
  - **Aperture** is its AI gateway, sold as a "platform extension" with no price on the pricing page, and "can be used without Tailscale" (checked 26 Nov 2026). — [Tailscale pricing](https://tailscale.com/pricing)
  - **tsidp** is a lightweight OIDC/OAuth server inside the tailnet. Its docs (last validated 10 Mar 2026) pitch it for MCP servers in private AI deployments (search summary). — [tsidp docs](https://tailscale.com/docs/features/tsidp)
  - No storage or email product was found.
- **Cloudflare.**
  - **Mesh** (14 Apr 2026): every enrolled device and node gets a private Mesh IP, CIDR routes allow subnet routing, and Workers and Durable Objects reach the network through Workers VPC bindings. Mesh replaces WARP Connector ("Mesh node"), and the WARP client is now the "Cloudflare One Client". — [Cloudflare blog, Mesh](https://blog.cloudflare.com/mesh/); [Cloudflare changelog, Mesh](https://developers.cloudflare.com/changelog/post/2026-04-14-cloudflare-mesh/)
  - **Tunnel**: Cloudflare's own docs (modified 18 Nov 2026) now say "Cloudflare Mesh is the default connector for private access and private networks", and point public-hostname publishing to Tunnel. — [Cloudflare Tunnel docs](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)
  - **Email**: Email Routing forwards inbound mail. Email Service sending went to public beta on 16 Apr 2026 for "any application and any agent", with an Agents SDK `onEmail` hook (earlier note). — [Cloudflare blog, Email for agents](https://blog.cloudflare.com/email-for-agents/)
  - **Storage**: Artifacts, "a Git-compatible storage primitive", opened to Workers Paid customers on 1 Oct 2026 (earlier note). — [Cloudflare blog, Artifacts](https://blog.cloudflare.com/next-git-platform-on-cloudflare/)
  - **MCP server portals** went GA on 24 Sep 2026 (earlier note). — [Cloudflare changelog, MCP portals GA](https://developers.cloudflare.com/changelog/post/2026-09-24-mcp-portals-ga/)
- **ngrok.**
  - Ingress, not a mesh: HTTP/S, TCP and TLS endpoints.
  - Traffic Policy (auth, IP rules, mTLS).
  - Private "internal" endpoints published via `forward-internal` (earlier note).
  - An **AI Gateway** at `gateway.ngrok.ai`.
  - A hosted **ngrok MCP server** that can now create AI Gateway configs (changelog 17 Nov 2026).
  - Sources: [ngrok pricing](https://ngrok.com/pricing); [ngrok AI Gateway docs](https://ngrok.com/docs/ai-gateway/); [ngrok changelog, MCP write tools](https://ngrok.com/changelog/ai-gateway-mcp-write-tools); [Using ngrok as your MCP gateway](https://ngrok.com/docs/using-ngrok-with/using-mcp)
- **NetBird.**
  - WireGuard mesh (open source; server AGPL since Aug 2025, per earlier note).
  - A **built-in reverse proxy** in the management server (v0.65, March 2026 newsletter) that exposes internal services publicly "with optional SSO, PIN, or password authentication".
  - An `expose` command for ephemeral public URLs (v0.66).
  - **Agent Network**, an LLM-access proxy for agents (docs updated 4 Sep 2026).
  - An MCP server for managing config.
  - Sources: [NetBird March 2026 newsletter](https://www.netbird.io/knowledge-hub/2026-march-newsletter) (search summary); [How Agent Network works](https://docs.netbird.io/agent-network/how-it-works); [NetBird MCP server](https://docs.netbird.io/manage/mcp-server)
- **Twingate.** ZTNA client plus connectors (no public ingress product found). **Identity Firewall**, now "Twingate Privileged Access Management" (blog byline 13 Nov 2025), adds just-in-time access, session replay, and per-command and per-query logging for SSH and Kubernetes. — [Twingate blog, Identity Firewall](https://twingate.com/blog/identity-firewall)
- **ZeroTier.** Layer-2-style virtual networks. Enterprise offers self-hosted and air-gapped controllers. **ZeroTier Quantum** launched at RSAC in March 2026 as a "quantum-secure networking platform". — [ZeroTier pricing](https://www.zerotier.com/pricing/); [BusinessWire, ZeroTier Quantum](https://www.businesswire.com/news/home/20260322114599/en/RSAC-2026-ZeroTier-Launches-ZeroTier-Quantum-the-Worlds-First-End-to-End-Quantum-Secure-Networking-Platform)
- **Teleport.**
  - Identity-aware access proxy for SSH, Kubernetes, databases, apps and MCP.
  - **Agentic Identity Framework** (announced late Jan 2026).
  - **Beams**, a "trusted runtime" for agents in Firecracker microVMs: announced 19 Mar 2026, GA 10 Nov 2026 (search summary).
  - Sources: [Teleport Agentic Identity Framework](https://goteleport.com/platform/agentic-identity-framework/); [Teleport Beams press release](https://goteleport.com/about/newsroom/press-releases/teleport-launches-beams-trusted-agent-runtimes-for-infrastructure/); [Cloud Native Now, Beams GA](https://cloudnativenow.com/uncategorized/teleport-beams-trusted-runtime-for-ai-agents-reaches-general-availability/)
- **Pomerium.**
  - Identity-aware reverse proxy. "Every plan uses a self-hosted data plane to handle application traffic in your environment".
  - Managed control plane (Zero) or self-hosted (Enterprise).
  - MCP server access and MCP tool access control on all plans (checked 26 Nov 2026).
  - Source: [Pomerium pricing](https://www.pomerium.com/pricing)
- **Defined Networking (managed Nebula).** Nebula overlay with a managed lighthouse that "acts as a relay by default", priced per host. — [Defined pricing](https://www.defined.net/pricing/)
- **Headscale.** Self-hosted reimplementation of Tailscale's control server: BSD-3, one tailnet, "not enterprise software", latest v0.29.3 as of 1 Nov 2026 (earlier note). — [Headscale FAQ](https://headscale.net/stable/about/faq/); [Headscale features](https://headscale.net/stable/about/features/)
- **Netmaker.** WireGuard mesh with egress and ingress gateways, relays and a remote-access client. Offered as self-hosted community, Pro/Team/Business, and SaaS. — [Netmaker pricing](https://www.netmaker.io/pricing)
- **Pangolin (Fossorial, YC S25).**
  - Tunneled reverse proxy with identity, plus a VPN client for "private resources".
  - Cloud or self-hosted (CE under AGPLv3, EE under a commercial license).
  - Added a "private HTTPS" edge-terminated mode on 27 May 2026.
  - Sources: [Pangolin pricing](https://pangolin.net/pricing); [Pangolin blog, peer-to-edge-peer](https://pangolin.net/news/building-a-peer-to-edge-peer-reverse-proxy)
- **OpenZiti, NetFoundry and zrok.**
  - OpenZiti is an open-source overlay.
  - zrok offers public and private shares (Apache 2.0; hosted free tier at zrok.io).
  - NetFoundry launched **MCP and LLM gateways** on 2 Jun 2026.
  - Sources: [zrok pricing](https://zrok.io/pricing/) (search summary); [NetFoundry press release, MCP and LLM gateways](https://netfoundry.io/press-release/netfoundry-launches-enterprise-class-mcp-and-llm-gateways-bringing-zero-trust-to-ai-deployments/)
- **2026 entrant: doxx.net (Barrett Lyon, founder of Prolexic).**
  - "Agentic Defined Networking" public beta, opened around 1–5 Oct 2026. Users and agents build private networks "with their own IP space and DNS root".
  - Agents can lease public IPs and set firewall policy, through a "full network API with native MCP support".
  - Funding: $38M Series A led by a16z.
  - Source: [Help Net Security, 5 Oct 2026](https://helpnetsecurity.com/2026/10/05/doxx-net-agentic-defined-networking-platform)
- **Other 2026 names checked.**
  - Outerlimit raised a $16M pre-seed for a "zero trust security layer for autonomous AI agents" (agent authorization, not connectivity; secondary source). — [Pulse 2.0](https://pulse2.com/outerlimit-raises-16-million-pre-seed/)
  - Firezone, a WireGuard ZTNA, remains a peer; its pricing is in §2.
- **Context from the earlier note: Microsoft dev tunnels.**
  - Still "public preview", "not recommended for production".
  - TLS is terminated at the Azure relay with a Microsoft CA certificate.
  - Private by default, scoped to the creating account (earlier note, page checked 31 Oct 2026).
  - Sources: [What are dev tunnels?](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview); [Dev tunnels security](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/security)

#### Matrix-ready summary (sources are in the rows above and in §2–§4)
| Vendor | Private IP mesh for devices/agents | Port forwarding / public ingress | Public TLS edge default | Storage | Email | Model router / AI gateway | Own IdP + roles |
|---|---|---|---|---|---|---|---|
| Tailscale | Yes (WireGuard) | Serve (tailnet), Funnel (public, beta) | Funnel: node terminates TLS, relays do not decrypt | No | No | Aperture (GA 26 Aug 2026) | Yes; SCIM and advanced roles on Standard |
| Cloudflare | Mesh (14 Apr 2026), via Cloudflare edge | Tunnel, Quick Tunnels | Cloudflare edge terminates TLS | Artifacts, R2 | Email Routing; Email Service (beta) | AI Gateway; MCP portals | Yes (Access) |
| ngrok | No (ingress only; internal endpoints) | Yes | ngrok cloud terminates for HTTPS; agent/upstream termination optional | No | No | AI Gateway | SSO/RBAC is a paid add-on |
| NetBird | Yes (WireGuard) | Reverse proxy (v0.65, 2026) | Not documented in pages read | No | No | Agent Network LLM proxy | Enterprise IdP and SCIM on Team |
| Twingate | ZTNA (client to connector) | No public ingress found | n/a | No | No | No (PAM product) | Yes; Okta/Entra on Business |
| ZeroTier | Yes | No managed public ingress found | n/a | No | No | No | OIDC SSO on Essential+ |
| Teleport | No (access proxy) | App access through proxy | Teleport proxy | No | No | LLM controls in framework; Beams | Yes |
| Pomerium | No (reverse proxy) | Yes (self-hosted data plane) | Customer's own Pomerium | No | No | MCP gateway | Yes |
| Defined (Nebula) | Yes | No | n/a | No | No | No | SSO on Free |
| Headscale | Yes (self-hosted control) | No (no Funnel equivalent documented) | n/a | No | No | No | OIDC login only |
| Netmaker | Yes | Ingress gateways | Not documented | No | No | No | SSO on Team; SCIM on Enterprise |
| Pangolin | VPN client to private resources | Yes (core product) | Cloud broker by default; "private HTTPS" mode at site | No | No | No | Yes on Team |
| zrok / NetFoundry | OpenZiti overlay | zrok public and private shares | zrok frontend terminates public shares | No (zrok "drives" not checked) | No | NetFoundry LLM and MCP gateways | NetFoundry enterprise |
| doxx.net | Yes (own IP space and DNS root) | Agents lease public IPs | Not documented | Not documented | Not documented | Not documented | Not documented |

### Inferences
- **The closest functional overlap is Cloudflare.** Mesh, Tunnel, Email Service, Artifacts, Access, AI Gateway and MCP portals cover all the listed jobs, but each runs through an edge that terminates TLS and can inspect traffic. The defensible contrast is vendor blindness, not feature count.
- **Tailscale overlaps on reach, identity and the model router (Aperture), but not on storage or email.**
- **Tailscale Funnel is the nearest existing analog to "a TLS edge that routes by SNI and never holds TLS keys".** The relays pass TLS through and the node terminates it. Funnel is still beta, limited to three ports, and serves only `ts.net` names: no custom domains were found for Funnel.
- **doxx.net is the competitor most likely to copy the same framing** ("agents get what humans get", private IP space, privacy-first) with heavy funding. Its pricing, ingress, storage and email story are undocumented so far, and it should be tracked.

### Gaps
- No pricing, plan or ingress documentation was found for doxx.net.
- Whether zrok's hosted service includes storage ("drives") as a team feature was not checked.
- Firezone's current official prices did not render (see §2).
- Cloudflare Mesh's per-plan limits beyond "free for up to 50 nodes and 50 users" were not found.

---

## 2. Pricing: free tiers, team and business per-seat prices, minimums, tier gating (SSO, SCIM, custom domains, RBAC/ACLs, device posture, audit logs), and 2025–2026 changes with user reaction

### Takeaway
- **First paid team tiers cluster at $4–9 per user per month.** Pangolin $4, Twingate $5, NetBird €6, Cloudflare $7, Pomerium $7 annual or $9 monthly, Tailscale $8.
- **Second tiers run $9–18.** Pangolin $9, Twingate $10, NetBird €12, Tailscale $18.
- **The free tiers undercut any paid three-seat plan** but are often non-commercial: Tailscale Personal (6 users), ZeroTier Personal and Twingate Home are non-commercial. Cloudflare (50 users), Twingate Starter (5), NetBird (5) and Pangolin (5) state no such restriction.
- **SCIM and enterprise IdP now sit in the first paid tier at Tailscale, NetBird and Pangolin.** Flow logs and SIEM streaming sit in the second tier.
- **ngrok is the outlier.** It charges $10 per user for SSO/RBAC plus $15 per user for SCIM and audit logs, on every user.
- **The big 2026 change was Tailscale's "Pricing v4" (8 Apr 2026).** It moved business plans from active-user billing to seat billing, with Standard at $8 (up from roughly $6 on Starter), and drew small-team complaints on Hacker News.
- **ZeroTier cut new free accounts from 25 to 10 devices,** with forum pushback.

### Cited Findings

#### Price table (checked 26 Nov 2026 unless noted)
| Vendor | Free tier | Team / entry paid | Business / second tier | Enterprise | Billing unit and notes |
|---|---|---|---|---|---|
| Tailscale | Personal $0: up to 6 users, unlimited user devices, 50 tagged resources "to start", 1,000 ephemeral min/mo, **non-commercial use only** | Standard **$8/user/mo**, unlimited users, 10 ACL groups | Premium **$18/user/mo**, 300 ACL groups, 10,000 ephemeral min/mo | Custom, annual invoice | Seats billed at start of month; cannot drop below occupied seats; extra tagged resources $1/mo each — [Tailscale pricing](https://tailscale.com/pricing) |
| ngrok | Free $0: 1 user, $5 one-time credit, 3 online endpoints, 1 GB out, 20k HTTP/S requests, 3 MAU, 24 h inspector | Hobbyist $10/mo ($8/mo annual), 1 user | Pay-as-you-go **$20/mo base incl. 3 users, then $5/user**, plus usage | Min spend **$10,000/yr** | Usage: $0.02/endpoint-hour, $0.01 per custom-domain active hour, $0.27/domain/hour for BYO certs, $0.10/GB after 5 GB — [ngrok pricing](https://ngrok.com/pricing) |
| Cloudflare Zero Trust | Free $0 "forever", **50 users**, logs up to 24 h | Pay-as-you-go **$7/user/mo**, no user limit, logs up to 30 days | — | Contract: custom annual per-user price, logs up to 6 months, Logpush | [Cloudflare SASE/Zero Trust plans](https://www.cloudflare.com/plans/sase-zero-trust.md). The .md page fetched shows only "/user/month". A search summary attributes "(paid annually)" to Cloudflare's own listing, while CostBench says $7 either way ([CostBench](https://costbench.com/software/business-vpn/cloudflare-zero-trust/)). The billing period is unresolved |
| Cloudflare Mesh | Free for up to 50 nodes and 50 users on any account | Included with Cloudflare One plans | — | — | [Cloudflare blog, Mesh](https://blog.cloudflare.com/mesh/) (14 Apr 2026; modified 15 Jul 2026) |
| Twingate | Starter free, up to 5 users (1 admin) | Teams **$5/user/mo**, up to 100 users, "Yearly -15%" | Business **$10/user/mo**, up to 500 users | Custom | The table also shows "$12 user / mo" for both tiers, unlabeled (monthly vs yearly split unclear). Home $15/mo for up to 7 users, non-commercial — [Twingate pricing](https://www.twingate.com/pricing) |
| NetBird (cloud) | €0: 5 users, 100 machines | Team **€6/user/mo**, unlimited users, "100 machines + 10 per user", extra machines €0.50/mo | Business **€12/user/mo** | Custom | "We charge only for active users and machines that connected or logged in at least once during the billing period" — [NetBird pricing](https://netbird.io/pricing) |
| ZeroTier | Personal free: 10 devices, 1 network, 1 admin, non-commercial | Essential **$18/mo** incl. 10 devices, then $2/device, 5 admins, 10 networks | Scale **$179/mo** incl. 100 devices, then $1.80/device, 10 admins | Custom (500+ devices; self-hosted and air-gapped), plus "Quantum" | Device-based, not per user. Accounts created after 5 Nov 2025 use "New Central" — [ZeroTier pricing](https://www.zerotier.com/pricing/) |
| Pomerium | Zero Personal free: 1 cluster, 10 routes, 5 policies, 1 custom domain, 1 admin, 2 service accounts | Zero Business **$9/user/mo monthly or $7 annual** (MAU), 20 service accounts | — | Custom, self-hosted control plane | [Pomerium pricing](https://www.pomerium.com/pricing) |
| Defined (Nebula) | Free up to **100 hosts**, 2 routes | Pro **$1/host/mo**, unlimited hosts | — | Quote | Per enrolled host; own lighthouses and relays are billable — [Defined pricing](https://www.defined.net/pricing/) |
| Pangolin (cloud) | Basic free: 5 users, 5 sites, 5 machine clients | Team **$4/user/mo** (50 users, 25 machine clients) | Business **$9/user/mo** (250 users, 100 machine clients) | Custom | Self-hosted EE: $15/user/yr + $7/site/yr, free under $100K revenue; CE free under AGPLv3 — [Pangolin pricing](https://pangolin.net/pricing) |
| Netmaker | Community $0 (self-hosted, Apache 2.0) | Team "starting" **$2 per active connection/mo**; "Professional" $99/mo in another table | Business "starting" $4 per active connection/mo | Custom | Page is internally inconsistent; SaaS is usage-based per device — [Netmaker pricing](https://www.netmaker.io/pricing) |
| Teleport | Community Edition (license terms not on page) | — | — | Usage-based | "Pay only for what you use: active users and protected resources"; no dollar prices — [Teleport pricing](https://goteleport.com/pricing/) |
| zrok / NetFoundry | zrok $0/mo; "credit card only needed to remove interstitial pages" | NetFoundry sales | — | NetFoundry custom; 30-day trial | [zrok pricing](https://zrok.io/pricing/) (search summary); [NetFoundry pricing](https://netfoundry.io/pricing/) (search summary) |
| Firezone | Starter free | Team ≈ **$5/user/mo** ($4.16 annual) **(unverified)** | — | Custom | The official page rendered no prices. The figures come from Vercel preview mirrors — [Firezone pricing](https://www.firezone.dev/pricing); [preview mirror](https://firezone-blzw9rqbv-firezone.vercel.app/pricing) |

#### What each tier gates
- **Tailscale (checked 26 Nov 2026).**
  - SCIM is "available to all paid plans".
  - "Advanced user roles" are on Standard.
  - MDM/EDR/XDR posture integrations: Standard and above.
  - Basic posture (OS, client version): all plans.
  - Configuration audit logs: all plans.
  - **Log streaming and network flow logs: Premium and above.**
  - "Custom tailnet subdomains": Enterprise.
  - Advanced Tailscale SSH (for example non-default check-mode length): Premium.
  - SSH session recording is sold in the Privileged Access Management extension "through sales".
  - Limits on ACL groups, multiple tailnets, tagged and ephemeral resources are "not currently enforced".
  - Source: [Tailscale pricing](https://tailscale.com/pricing)
  - Tailnet Lock is "available on the Personal and Enterprise plans" (earlier note, doc validated 2 Dec 2025). — [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock)
- **ngrok (checked 26 Nov 2026).**
  - SSO/RBAC: "$10 per user/month (applied to all users)".
  - "Identity & Access Governance Suite" (SCIM, account-wide IP restrictions, audit logs): "$15 per user/month (for all users; requires the SSO/RBAC add-on)".
  - Bring-your-own domains: Pay-as-you-go only.
  - Wildcard domains: Pay-as-you-go.
  - End-to-end TLS: "Contact sales".
  - Mutual TLS: "Via Traffic Policy".
  - Traffic log export: $0.25 per 2k events.
  - Dedicated agent connect IPs: "$900 per month per region".
  - Source: [ngrok pricing](https://ngrok.com/pricing)
- **Cloudflare (checked 26 Nov 2026).**
  - ZTNA, SWG, the device client and the connector are on all plans.
  - Remote Browser Isolation is an add-on.
  - CASB is limited to 2 read-only API integrations on Free and Pay-as-you-go.
  - DLP has "limited predefined profiles" except on Contract.
  - Logpush is mentioned only under Contract.
  - Source: [Cloudflare SASE/Zero Trust plans](https://www.cloudflare.com/plans/sase-zero-trust.md)
  - Admin logs are retained 18 months on all plans, and Access request logs 24 h on Free (earlier note, page updated 15 Oct 2026). — [Zero Trust logs](https://developers.cloudflare.com/cloudflare-one/insights/logs/)
- **Twingate (checked 26 Nov 2026).**
  - Teams: "SSO via Google Workspace".
  - Business: "SSO via Okta, Entra ID, and more" and "User provisioning & management via IdP".
  - Device posture: Home, Teams and Business; Business adds endpoint integrations.
  - DNS filtering: add-on on Business and Enterprise.
  - Service accounts: Home and Business, **not Teams**.
  - Exit networks: Home, Business and Enterprise.
  - Source: [Twingate pricing](https://www.twingate.com/pricing)
- **NetBird (checked 26 Nov 2026).**
  - Free: social SSO only.
  - Team: "SSO & MFA with enterprise IdP", "IdP provisioning (SCIM)", "Audit events logging".
  - Business: "Device posture checks", "Connection traffic events logging", "Audit & traffic events streaming", "MDM & EDR device controls".
  - Source: [NetBird pricing](https://netbird.io/pricing)
- **ZeroTier (checked 26 Nov 2026).**
  - OIDC SSO: Essential, Scale and Enterprise (not Personal).
  - Logs: 30 days on Essential and Scale, 90 days on Enterprise.
  - Custom flow rules: Scale.
  - Self-hosted and air-gapped: Enterprise.
  - No SCIM is mentioned.
  - Source: [ZeroTier pricing](https://www.zerotier.com/pricing/)
- **Pomerium (checked 26 Nov 2026).**
  - On every plan: SSO, access and admin audit logs, configuration history, the policy language, MCP server access and MCP tool access control.
  - Enterprise only: device posture, session recording, RBAC (delegated admin), Rego and directory sync.
  - Source: [Pomerium pricing](https://www.pomerium.com/pricing)
- **Pangolin (checked 26 Nov 2026).**
  - Team: SSO, multiple roles, audit logging, posture, self-hosted relay nodes and custom DNS.
  - Business: SSO auto-provisioning, device approvals, advanced SSH and multi-org.
  - Enterprise: SIEM log streaming.
  - Source: [Pangolin pricing](https://pangolin.net/pricing)
- **Netmaker (checked 26 Nov 2026).**
  - Team: SSO (Google, GitHub, Microsoft, custom OIDC).
  - Business: audit logging, posture checks and device approvals.
  - Enterprise: SCIM, traffic logs and SIEM.
  - Source: [Netmaker pricing](https://www.netmaker.io/pricing)
- **Defined (checked 26 Nov 2026).**
  - SSO is listed on Free.
  - Users are "Unlimited, via SSO using your identity provider".
  - SCIM, RBAC and audit logs are not mentioned.
  - Source: [Defined pricing](https://www.defined.net/pricing/)
- **Teleport (pricing guide revision 6 Jan 2026, earlier note).**
  - Usage-based on "monthly active users and Teleport Protected Resources".
  - A protected resource includes any "MCP server, git repository, or a machine or workload identity".
  - Enterprise lists "Session recordings and structured audit logs for every session and request".
  - Source: [Teleport pricing guide (PDF)](https://goteleport.com/_uploads/Teleport_Pricing_Guide_Rev_Jan_6_2026_c706e2abf0.pdf)

#### How machines and agents are billed (relevant to "every agent gets an IP")
- **Tailscale.** User devices are free and unlimited. Tagged resources (servers, agents, app connectors): 50 on Personal, then $1/mo each, and they "do not automatically increase or decrease with usage". Ephemeral nodes draw on a minute pool; after more than 4 hours one counts as a tagged resource. — [Tailscale pricing](https://tailscale.com/pricing)
- **NetBird.** "100 machines + 10 per user", then €0.50 per machine per month. — [NetBird pricing](https://netbird.io/pricing)
- **Pangolin.** Machine clients: 5, 25 or 100 by cloud tier. Self-hosted EE charges $7/yr per machine client beyond 25. — [Pangolin pricing](https://pangolin.net/pricing)
- **Pomerium.** Service accounts: 2 on Personal, 20 on Business. — [Pomerium pricing](https://www.pomerium.com/pricing)
- **Defined and ZeroTier** bill per host or device. — [Defined pricing](https://www.defined.net/pricing/); [ZeroTier pricing](https://www.zerotier.com/pricing/)
- **Teleport** meters MCP servers and machine or workload identities as protected resources (earlier note). — [Teleport pricing guide](https://goteleport.com/_uploads/Teleport_Pricing_Guide_Rev_Jan_6_2026_c706e2abf0.pdf)
- **Cloudflare Mesh**: free up to 50 nodes. — [Cloudflare blog, Mesh](https://blog.cloudflare.com/mesh/)

#### 2025–2026 pricing changes and reaction
- **Tailscale Pricing v4 (8 Apr 2026).**
  - What changed:
    - "Starter becomes Standard".
    - Business plans move to seat-based pricing ("For these plans, for this product, seat-based pricing is the better fit").
    - Personal Plus is retired, and Personal "now supports up to six users".
    - SCIM, device posture, user-management APIs and webhooks go self-serve.
  - Stated reasons: predictable bills, procurement comparability, and accounting.
  - Migration: "Your current plan will keep working, at the same price, for at least another 12 months."
  - Source: [Tailscale blog, Pricing v4](https://tailscale.com/blog/pricing-v4)
  - Tailscale's post on X: "Paid plans move to seat-based pricing … Standard is now $8". — [Tailscale on X](https://x.com/Tailscale/status/2041903744179200095)
- **Tailscale's own FAQ admits the increase.** Moving from Starter to Standard "slightly increased the price per seat". After the first year, legacy Starter and Team move to Standard, and legacy Premium and Business to Premium. "Moving to a new plan is a one-way change." — [Tailscale pricing](https://tailscale.com/pricing)
- **Old price, secondary sources.**
  - Old Starter was "roughly $6–7 per active user", modeled at about $6.50.
  - By that blog's own math at 90% utilization, 50 seats go from about $293/mo to $400 (Standard), and 100 seats from about $585 to $800.
  - The publisher sells a self-hosted PaaS, so the bias favors self-hosting.
  - Source: [bex.co, 9 Jul 2026](https://bex.co/blog/2026/07/09/tailscale-pricing-v4-border0-headscale)
- **Hacker News reaction** to "Tailscale's Pricing v4" (35 points, 29 comments). — [HN 47691281](https://news.ycombinator.com/item?id=47691281)
  - Tenkuru: an 8-person startup paying $6–12/month says "that jumps to $64 a month", since only about half the team is active in a month. Also: "I'm personally thrilled that the free plan now includes 6 seats, which is perfect for my home setup".
  - packetlost: "We might need to drop our Tailscale usage because of this."
  - pepemon: "Introducing billing for ephemeral nodes and tagged resources behind an opaque "Contact Sales" wall"; "I've already added an "Evaluate Netbird" to our team's backlog"; describes the pattern as "embed yourself as a deep infrastructure dependency".
  - drcongo: "I would _love_ to give you guys money, you just won't let me."
  - noodlesUK: "I also think capping Tailscale SSH to 5 devices on the standard plan kneecaps the value." This is a user claim, not checked against docs.
  - ts-samlinville (Tailscale product): "We do intend to allow Personal users to pay for additional tagged devices".
- **ZeroTier free-tier cut.**
  - New free sign-ups get 10 devices, down from 25; existing free users keep their entitlements, and a staff forum reply confirms legacy accounts keep "25 free devices".
  - Users called the 2024 move to Essential "a bit of bait and switch".
  - The 2024 Essential was described as a flat $5 plus $2 per extra device. The page today lists Essential at $18/mo with 10 devices, and the date of that later change was not found.
  - Sources (search summary): [ZeroTier Essential announcement](https://www.zerotier.com/?p=3556); [ZeroTier forum, 10 to 25 devices](https://discuss.zerotier.com/t/can-i-increase-device-from-10-to-25-as-like-previously/23892); [ZeroTier forum, Essential feedback](https://discuss.zerotier.com/t/essential-plan-feedback/22318); [ZeroTier forum, blocked after new pricing](https://discuss.zerotier.com/t/blocked-out-of-the-dashboard-after-new-pricing-model/22030)
- **NetBird license change (4 Aug 2025, earlier note).**
  - Moved management, relay and signal from BSD-3 to AGPLv3. "All client applications remain under BSD-3".
  - HN thread: 88 points, 78 comments. One user: "I actually made the jump from tailscale -> netbird last month."
  - Source: [HN 44813110](https://news.ycombinator.com/item?id=44813110)
- **Pangolin license change.** Moved to dual licensing (AGPLv3 plus the Fossorial Commercial License) with a new Enterprise Edition (date not captured). — [Linuxiac](https://linuxiac.com/pangolin-reverse-proxy-moves-to-dual-licensing-with-new-enterprise-edition/) (search summary)

### Inferences
- **Against the planned Team plan (about $10/mo for the first 3 seats, then $10/seat):**
  - Three seats at $10 is cheaper than Tailscale Standard ($24) and ngrok Pay-as-you-go ($20 + usage), and similar to Twingate Teams ($15).
  - Free tiers undercut it for teams of up to 5 (Twingate, NetBird, Pangolin), up to 6 non-commercial (Tailscale), or up to 50 (Cloudflare).
  - From seat 4, $10/seat is above every first-tier mesh or ZTNA price here ($4–8) and at the level of second tiers (Twingate Business $10, Pangolin Business $9). Storage, email, the TLS edge and the model router have to carry that premium.
- **Example ngrok bill, my own arithmetic from the listed rates.** A 10-person team with SSO and audit logs pays $20 + 7×$5 + 10×$10 + 10×$15 = **$305/mo before usage**. ngrok's "SSO tax" is the steepest in the set.
- **Market norm for gating.** SSO and SCIM in the first paid tier, flow logs, streaming and posture integrations in the second. Holding SCIM back would look unusual next to Tailscale, NetBird and Pangolin.
- **Seat billing versus active billing is a live pain point.** NetBird and Pomerium bill only active users or MAU; Tailscale moved away from that and drew the clearest complaints. Billing only active seats, and never metering agents, is a defensible contrast. Tailscale meters tagged resources at $1/mo beyond 50, and NetBird charges €0.50 per machine.

### Gaps
- Twingate's monthly versus annual prices: the page shows both "$5/$12" and "$10/$12" without labels.
- Cloudflare's billing period for the $7 tier: monthly versus annual conflicts across pages.
- Firezone's official prices.
- Teleport dollar prices and Community Edition license terms: neither is on the pricing page.
- Netmaker's real price, given the inconsistent page.
- Aperture prices: the pricing page says nothing. A six-user free tier was reported in an earlier search but is unconfirmed.
- The tagged-resource allowances on Standard and Premium were not captured.
- No Reddit threads were opened: the login wall noted in earlier rounds still applies.

---

## 3. What can the vendor see? (data-plane encryption, control-plane visibility, TLS termination at public ingress, traffic and DNS logging)

### Takeaway
- **Data plane.** Mesh products (Tailscale, NetBird, ZeroTier, Nebula, Netmaker, Headscale, OpenZiti) encrypt device-to-device traffic with keys generated on the device. Their relays cannot decrypt.
- **Control plane.** Every managed control plane in the set holds the team's identities, device graph, public keys and full access policy in the clear and resolves policy itself. Defined holds the CA key and says it "is technically capable of issuing a certificate for a new host in your network". Tailscale's Tailnet Lock only blocks node injection.
- **Public ingress.** Vendor-edge TLS termination (plaintext at the vendor) is the default at Cloudflare (even with Keyless SSL), ngrok HTTPS endpoints, zrok public shares and Pangolin Cloud's standard mode. Passthrough exists at Tailscale Funnel (the node terminates TLS) and ngrok agent or upstream termination. Pangolin's 2026 "private HTTPS" mode ends TLS at the customer's site, but the control plane issues and pushes the certificates.
- **Gateways and Cloudflare Mesh.** Every AI or MCP gateway reads prompts by design. Cloudflare Mesh sends all traffic through Cloudflare's edge with Gateway inspection.

### Cited Findings

#### Tailscale (mesh, control plane, Funnel and Serve, Aperture)
- **Data plane.**
  - "Private keys are generated on each device and never leave it." "All device public keys are stored on the coordination server."
  - "Tailscale doesn't route any traffic through the coordination service."
  - The coordination server distributes "routing configurations and access control policies to clients" and keeps a registry of all devices.
  - Earlier note, accessed 1 Nov 2026.
  - Sources: [Control and data planes](https://tailscale.com/docs/concepts/control-data-planes); [How Tailscale works](https://tailscale.com/blog/how-tailscale-works)
- **DERP relays.** "it's impossible for a DERP server to decrypt your traffic" (earlier note). — [DERP servers](https://tailscale.com/kb/1232/derp)
- **Control-plane exposure.** The control plane necessarily holds every node's public key, identity-to-device mappings and auth tokens, the complete ACL policy (it decides which peer keys each node receives), endpoint metadata and posture data. This synthesis is from the earlier note's reading of the docs above.
- **Tailnet Lock** stops the coordination server from injecting nodes: without it, "If Tailscale were malicious … Tailscale could send or receive traffic to your existing nodes in plaintext". It does not hide metadata (earlier note). — [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock)
- **Logs.**
  - Network flow logs capture connection metadata. "Tailscale never logs the content of network traffic, and does not have access to it" (Premium/Enterprise; earlier note). — [Network flow logs GA](https://tailscale.com/blog/network-flow-logs-is-generally-available)
  - Configuration audit logs are on all plans, kept 90 days, and cannot be disabled (earlier note). — [Audit logging](https://tailscale.com/kb/1203/audit-logging)
- **Funnel TLS.** Relay servers do not decrypt the proxied stream, and the node terminates TLS. There is no visitor login wall (earlier note; docs validated 20 Jan 2026). — [Tailscale Funnel](https://tailscale.com/kb/1223/funnel)
- **Funnel ingress depends on the control plane.** A Tailscale engineer on GitHub (14 Sep 2026): if a node's control connection drops, "control immediately removes it as an ingress target" (earlier note). — [tailscale/tailscale#20739](https://github.com/tailscale/tailscale/issues/20739)
- **Aperture (AI gateway) sees full content by design.**
  - Request capture includes the "full body" and headers; response capture the "full response body".
  - Each record carries "the login name and device ID".
  - Captures can be purged, and retention can go "all the way down to zero" (earlier notes).
  - Sources: [How Aperture works](https://tailscale.com/docs/aperture/how-aperture-works.md); [Tailscale blog, Aperture audit, 30 Jun 2026](https://tailscale.com/blog/aperture-audit-AI-agents)
  - The privacy page describes a "managed" gateway that is a node on the customer's tailnet, with database backups that Tailscale support can restore during a 7-day grace period. That implies Tailscale operates the storage (earlier note). — [Aperture privacy and data retention](https://tailscale.com/docs/aperture/privacy-and-data-retention)
- **Aperture passes model traffic through Vercel.**
  - Aperture is built on **Vercel AI Gateway and Vercel Sandbox**: "we built our identity and connectivity layer on top".
  - "The AI Gateway itself retains no data". A `zeroDataRetention` flag restricts routing to ZDR providers.
  - "No key is ever issued to the agent."
  - Source: [Vercel, 11 Sep 2026](https://vercel.com/blog/how-tailscale-built-a-customer-facing-model-router-on-ai-gateway)
- **PAM (beta).** Recordings are "generally saved and stored in Tailscale-managed storage", with S3 on Premium (earlier note, post dated 26 Oct 2026). — [Tailscale blog, PAM](https://tailscale.com/blog/what-is-tailscale-pam)

#### ngrok
- **Default termination.**
  - "All HTTPS endpoints terminate TLS at ngrok's cloud service." Traffic is "re-encrypted before they are transmitted over a Secure Tunnel to an agent".
  - The alternatives are agent termination ("configure the ngrok agent to terminate TLS connections for you") or upstream termination. In those modes "the ngrok cloud service can not see the payloads that transfer through your endpoints".
  - Source: [ngrok TLS termination](https://ngrok.com/docs/universal-gateway/tls-termination)
- **The pricing page lists end-to-end TLS as "Contact sales"** on Pay-as-you-go, while the docs describe agent and upstream termination as configuration. The commercial gate is unclear. — [ngrok pricing](https://ngrok.com/pricing)
- **Inspection and retention.**
  - Traffic Inspector keeps request data for 24 h on Free, 72 h on Hobbyist and Pay-as-you-go, and up to 90 days with an add-on.
  - "Inspection is only supported for HTTP endpoints. TCP and TLS endpoints don't support inspection" (earlier note).
  - Source: [Traffic Inspector](https://ngrok.com/docs/obs/traffic-inspection)
- **AI Gateway.** It "Receives your request with your access key at `gateway.ngrok.ai`" and forwards it. The page says nothing about what is logged or retained. — [ngrok AI Gateway](https://ngrok.com/docs/ai-gateway/)

#### Cloudflare
- **Mesh routes everything through Cloudflare.**
  - All Mesh traffic transits Cloudflare's network: "the Cloudflare edge is the path".
  - Gateway policies, DNS filtering, traffic inspection, DLP and device posture apply automatically. The post does not say where traffic is decrypted.
  - Source: [Cloudflare blog, Mesh](https://blog.cloudflare.com/mesh/)
- **Tunnel.**
  - The `cloudflared`-to-edge leg uses TLS 1.3 with post-quantum encryption by default (search summary). — [Tunnel cipher suites](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/cipher-suites)
  - For public hostnames, visitor TLS ends at Cloudflare's edge, and Cloudflare handles each request unencrypted before forwarding it (third-party guide). — [SSD Nodes, Is Cloudflare Tunnel secure](https://www.ssdnodes.com/learn/is-cloudflare-tunnel-secure)
  - Even when customers keep keys with Keyless SSL, "Keyless SSL requires that Cloudflare decrypt, inspect, and re-encrypt traffic for transmission back to a customer's origin" (search summary). — [Cloudflare Keyless SSL](https://www.cloudflare.com/keyless-ssl/)
- **Device client and Gateway.**
  - The client's default "Traffic and DNS mode" "Routes device traffic (by default, all ports and protocols) and DNS queries through Cloudflare for filtering, inspection, and policy enforcement". — [Cloudflare One Client](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/) (search summary)
  - "By default, Gateway logs all events, including DNS queries and HTTP requests that are allowed and not a risk." Admins can disable this or log only blocks, but "Logpush data is unaffected." — [Gateway logs](https://developers.cloudflare.com/cloudflare-one/insights/logs/gateway-logs) (search summary)
  - HTTPS inspection requires a Cloudflare root certificate on each client. "With proxy and TLS decryption turned on, Cloudflare will log all traffic sent through Gateway." — [TLS decryption](https://developers.cloudflare.com/cloudflare-one/traffic-policies/http-policies/tls-decryption/) (search summary)
- **MCP server portals.** Access logs "tool, prompt, and resource activity", and Gateway routing adds HTTP logging and DLP scanning (earlier note). — [MCP portals GA](https://developers.cloudflare.com/changelog/post/2026-09-24-mcp-portals-ga/)
- **Email Routing.**
  - Marketing claim: "Email Routing is 100% private; Cloudflare will not store or access email content." The launch post says Cloudflare "doesn't look into, queue, or store emails at any point".
  - The same product pages advertise phishing detection, which requires reading message content. That is a tension the pages do not explain (search summary).
  - Sources: [Cloudflare Email Routing](https://www.cloudflare.com/products/email-routing); [Introducing Email Routing](https://blog.cloudflare.com/introducing-email-routing/)
  - The postmaster docs (modified 30 Oct 2026) say nothing about storage or retention. — [Email Routing postmaster](https://developers.cloudflare.com/email-routing/postmaster/)
- **Quick Tunnels.** "Anyone with the URL can access your local service". The email gate "requires an interactive browser session" (earlier note, page updated 30 Sep 2026). — [Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)

#### Twingate
- **Relays.** For traffic through a Relay, "Twingate has no ability to decrypt such data". Client-to-Connector traffic is "end-to-end encrypted over a certificate-pinned TLS tunnel" with a session key generated by the Client. "Relays do not store any traffic or network-identifiable information" (search summary).
- **DNS.** "DNS lookups for protected Resources are always resolved locally". For FQDN resources the Connector does local resolution (search summary).
- **Controller.** It authenticates users and authorizes Connectors, and "no single component can independently make a decision to allow traffic" (search summary).
- **Sources:** [Encryption in Twingate](https://www.twingate.com/docs/how-encryption-works-in-twingate); [Understanding relays](https://www.twingate.com/docs/understanding-relays); [How Twingate works](https://www.twingate.com/docs/architecture-overview)
- **PAM (Identity Firewall)** advertises session replay and per-command and per-query logging. The blog does not say which component sees the session content or where it is stored. — [Twingate blog, Identity Firewall](https://twingate.com/blog/identity-firewall)

#### NetBird
- **Agent Network (docs updated 4 Sep 2026).**
  - The proxy peer "terminates the request", resolves identity, enforces policy, injects the provider key and forwards upstream.
  - It reads the request body and will "capture the prompt if prompt collection is enabled".
  - Usage (identity, provider, model, tokens, cost) is "retained indefinitely". Access logs, with prompts and completions if capture is on, have configurable retention and optional PII redaction.
  - Internal resources bypass the proxy over direct peer-to-peer WireGuard.
  - "The tunnel is the credential."
  - Source: [How Agent Network works](https://docs.netbird.io/agent-network/how-it-works)
- **Reverse proxy.** The built-in reverse proxy in the management server exposes services publicly (v0.65, March 2026). Where public TLS terminates was not documented in the pages read. — [NetBird March 2026 newsletter](https://www.netbird.io/knowledge-hub/2026-march-newsletter) (search summary)

#### Defined Networking (managed Nebula)
- **Keys.** "the private key for each host is generated locally and never leaves the host". Session keys are derived between endpoints, so Defined "does not hold the material required to decrypt your application traffic".
- **CA.** Defined holds the CA private key (operations backed by AWS KMS) and "is technically capable of issuing a certificate for a new host in your network", which it calls "inherent to any managed-PKI model".
- **Exit.** Customers can export configs, create their own CA and run Nebula without Defined's cloud.
- All three points are search summaries.
- **Sources:** [Defined security whitepaper](https://www.defined.net/security/whitepaper/); [Defined architecture docs](https://docs.defined.net/architecture/); [Defined security](https://www.defined.net/security/)
- **Relay.** The managed lighthouse "acts as a relay by default". — [Defined pricing](https://www.defined.net/pricing/)

#### Pomerium, Teleport, Headscale
- **Pomerium.** The data plane is self-hosted on every plan. With Zero, the managed control plane "receives configuration and operational data". — [Pomerium pricing](https://www.pomerium.com/pricing) MCP tool calls are logged "with the method, tool name, and parameters". — [Pomerium MCP docs](https://www.pomerium.com/docs/capabilities/mcp) (search summary)
- **Teleport.**
  - Enterprise records "Session recordings and structured audit logs for every session and request" (earlier note). — [Teleport pricing guide](https://goteleport.com/_uploads/Teleport_Pricing_Guide_Rev_Jan_6_2026_c706e2abf0.pdf)
  - Beams log "every agent action" (press release). — [Teleport Beams press release](https://goteleport.com/about/newsroom/press-releases/teleport-launches-beams-trusted-agent-runtimes-for-infrastructure/)
- **Headscale.** You run the control server yourself. No Tailnet-Lock equivalent is documented (inference from absence, earlier note). — [Headscale features](https://headscale.net/stable/about/features/)

#### Pangolin, zrok and NetFoundry, doxx.net
- **Pangolin (27 May 2026).**
  - Pangolin calls the standard model a "server-terminated, cloud-based reverse proxy" that acts as "a mandatory man-in-the-middle decrypting your SSL".
  - Its new private HTTPS mode: "SSL terminates at the edge", and "The HTTPS traffic travels over a blind transport layer and decrypts all the way down at the local network edge".
  - But the control plane issues and manages the certificates and pushes them to site connectors, and sites send logs and analytics back to the cloud.
  - Source: [Pangolin blog, peer-to-edge-peer](https://pangolin.net/news/building-a-peer-to-edge-peer-reverse-proxy)
  - Cloud reverse-proxy and relayed client traffic "passes through Pangolin Cloud servers". — [Pangolin pricing](https://pangolin.net/pricing)
- **zrok.**
  - For public shares, NetFoundry's public reverse proxy "terminates TLS … just like Tunnel/Funnel". This is an OpenZiti community post; its date was not checked, and the comparison to Funnel is the poster's.
  - Private shares stay on the OpenZiti overlay, which "employs end-to-end encryption".
  - Sources (search summary): [OpenZiti forum, E2E TLS termination](https://openziti.discourse.group/t/e2e-tls-termination/4611); [zrok README](https://github.com/openziti/zrok)
- **NetFoundry gateways (2 Jun 2026).** Connections are "end-to-end encrypted". The LLM Gateway's PII, content-safety and prompt-injection guardrails imply that it reads prompts, though the release does not say so. — [NetFoundry press release](https://netfoundry.io/press-release/netfoundry-launches-enterprise-class-mcp-and-llm-gateways-bringing-zero-trust-to-ai-deployments/)
- **doxx.net (claims only).**
  - Peer-to-peer calls, chat and file transfers are "end-to-end encrypted" with "no communications server in the middle".
  - Onion routing means "no single point knows both who a user is and what they're doing".
  - The CEO says the network was built so it "never can" know what users do.
  - None of this is independently verified. — [Help Net Security](https://helpnetsecurity.com/2026/10/05/doxx-net-agentic-defined-networking-platform)

### Inferences
- **No vendor here sells a managed control plane that cannot read team policy.**
  - Tailscale, NetBird, Twingate, ZeroTier, Defined, Pangolin, Pomerium Zero and Cloudflare all evaluate or distribute policy in the clear.
  - The only route to "the vendor cannot see the policy" today is self-hosting: Headscale, self-hosted NetBird, Pomerium Enterprise, OpenZiti, Defined export.
  - A blind control plane is a real gap in the market, not a feature parity item.
- **Even "keys stay on device" vendors keep an admission backdoor in the control plane.** Defined can issue host certs, and Tailscale can inject nodes unless Tailnet Lock is on. A comparison should mention both.
- **Cloudflare Mesh is not a peer-to-peer mesh.** It is a private-IP overlay whose packets all transit Cloudflare's inspection stack. "Private IPs for agents" alone will not separate a product from Cloudflare; the encryption boundary will.
- **Ingress with an edge that never holds TLS keys is rare.**
  - Tailscale Funnel is the only managed product found that passes TLS through by default. It is beta, three ports, `ts.net` names only.
  - ngrok supports it as an option.
  - Pangolin's version still has the vendor issuing the certificates.
- **Every agent-era product launched in 2026 reads the prompt or tool call by design:** Aperture, ngrok AI Gateway, NetBird Agent Network, NetFoundry LLM Gateway, Cloudflare MCP portals, Pomerium MCP, Teleport Beams.
- **Aperture adds a third party, Vercel, to the model path.** A model router that routes without reading content would be a clear contrast.

### Gaps
- ZeroTier's data-plane encryption and what ZeroTier Central sees were not re-verified in this pass.
- Netmaker's server visibility was not checked.
- Where NetBird's reverse proxy terminates TLS was not checked.
- Whether Cloudflare Spectrum offers TLS passthrough was not found.
- The CT-log exposure of `ts.net` hostnames under Tailscale HTTPS/Funnel was not re-checked.
- Whether Tailscale clients upload diagnostic logs by default was not re-checked.
- Twingate PAM's session-recording path and storage are undocumented in what was read.
- Where Aperture's gateway node physically runs (Tailscale-run versus customer-run) was described as "experimenting with multiple deployment options" in an earlier note; not resolved.

---

## 4. Agent positioning in 2026: MCP gateways, agent access to private resources, identity for non-human workloads, AI gateways (with vendor messaging)

### Takeaway
Every major vendor now pitches some combination of:
- agents as first-class identities ("no key is ever issued to the agent", "the tunnel is the credential");
- an MCP gateway;
- an AI or LLM gateway with logging.

The leaders are:
- **Tailscale:** Aperture GA, MCP endpoints, agents as tailnet nodes, a sovereign-AI push.
- **Cloudflare:** Mesh "to secure the AI agent lifecycle", MCP portals GA, email for agents.
- **Teleport:** Agentic Identity Framework and Beams GA on 10 Nov 2026.

NetBird (Agent Network), ngrok (AI Gateway plus an MCP server that configures it), Pomerium (MCP gateway on every plan) and NetFoundry (MCP and LLM gateways) follow. Twingate says MCP and A2A support is planned. No agent product was found for ZeroTier, Defined, Headscale, Netmaker or Pangolin.

### Cited Findings

#### Tailscale
- **Aperture timeline.**
  - Private alpha: 27 Jan 2026. — [Tailscale blog, Aperture private alpha](https://tailscale.com/blog/aperture-private-alpha) (search result)
  - Self-serve: 23 Mar 2026. — [Tailscale blog, Aperture self-serve](https://tailscale.com/blog/aperture-self-serve) (search result)
  - GA: 26 Aug 2026. — [Tailscale blog, Aperture GA](https://tailscale.com/blog/aperture-ga)
- **What the GA release adds:**
  - token purchasing inside Aperture;
  - "Two MCP endpoints, Tailscale and Tailscale SSH, for adding nodes and accessing them from agents";
  - Projects;
  - default tool permissions.

  Users approve each machine before Aperture can add it to the tailnet. — [Tailscale blog, Aperture GA](https://tailscale.com/blog/aperture-ga)
- **Aperture messaging:**
  - "you don’t need to choose between ease of use, identity-aware networking, and robust safety when using agentic AI"
  - "Unified AI governance for AI agents and users."

  Source: [Tailscale blog, Aperture GA](https://tailscale.com/blog/aperture-ga)
- **Pricing page.** It lists "Secure AI Agent Connectivity" as a solution, and says Aperture covers "tool-call control and session logs". — [Tailscale pricing](https://tailscale.com/pricing)
- **Agents as nodes (30 Sep 2026, earlier note).**
  - Meta's Muse agent joins the user's tailnet "as its own node so grants and tags apply".
  - It "requires explicit confirmation the first time it connects to any tailnet device".
  - "a skill for coding agents" is in alpha.

  Source: [Tailscale blog, Muse](https://tailscale.com/blog/meta-muse-ai-agent-tailscale)
- **Sovereign AI (13 Oct 2026, earlier note).** "Tailscale is making a multi-million-dollar, multi-year investment in sovereign AI". — [Tailscale blog, sovereign AI](https://tailscale.com/blog/sovereign-ai-patricia-prewitt)
- **Codex Cloud.** Blog title, 6 Oct 2026: "Codex Cloud shipped with Tailscale support. Nobody told us." (earlier note). — [Tailscale blog RSS](https://tailscale.com/blog/index.xml)
- **tsidp for MCP.**
  - Pitched for MCP servers in private AI deployments.
  - The repo's MCP-gateway example uses Dynamic Client Registration (RFC 7591) and Token Exchange (RFC 8693).
  - The repo is labeled experimental.

  Sources (search summary): [tsidp docs](https://tailscale.com/docs/features/tsidp); [tsidp MCP gateway example](https://raw.githubusercontent.com/tailscale/tsidp/HEAD/examples/mcp-gateway/README.md); [Tailscale blog, DCR for MCP](https://tailscale.com/blog/dynamic-client-registration-dcr-for-mcp-ai)
- **CEO, 21 Jul 2026.** "Tailscale is, almost by accident, the tool of choice for a lot of AIs and AI agents that are running around now". On a land grab: "Given the interest in Tailscale right now and the AI revolution in progress, doing a bit of a land grab is worth it." — [BetaKit](https://betakit.com/tailscale-catches-ai-tailwinds-as-it-nears-40000-paid-business-customers/)

#### Cloudflare
- **Mesh (14 Apr 2026) messaging:**
  - "The clients are no longer just humans or services."
  - "agents need to reach private resources, but the tools for doing that were built for humans, not autonomous software."
  - "You don't need a new technology paradigm to secure agentic workloads."

  The post also says agents do not yet have distinct identities visible to Gateway policies. Per-agent identity (principal, sponsor, scope) is planned. — [Cloudflare blog, Mesh](https://blog.cloudflare.com/mesh/)
- **Press release title:** "Cloudflare launches Mesh to secure the AI agent lifecycle". — [Cloudflare press release, 14 Apr 2026](https://www.cloudflare.com/press/press-releases/2026/cloudflare-launches-mesh-to-secure-the-ai-agent-lifecycle/)
- **Agents Week (13 Apr 2026):** Sandboxes GA, Artifacts, the Think framework (earlier note). — [Cloudflare press release, Agents Week](https://www.cloudflare.com/press/press-releases/2026/cloudflare-expands-its-agent-cloud-to-power-the-next-generation-of-agents/)
- **Email for agents (16 Apr 2026):** Email Service sending in public beta for "any application and any agent", with per-address agent instances (earlier note). — [Cloudflare blog, Email for agents](https://blog.cloudflare.com/email-for-agents/)
- **MCP server portals GA (24 Sep 2026):** "one endpoint for approved Model Context Protocol (MCP) servers", "service token authentication for autonomous agents", Logpush (earlier note). — [MCP portals GA](https://developers.cloudflare.com/changelog/post/2026-09-24-mcp-portals-ga/)
- **Birthday Week (5 Oct 2026):** "Introducing cf: the agentic CLI", "Protected Quick Tunnels", "Cloudflare OS", Containers "rebuilt to scale agent sandboxes" (earlier note). — [Cloudflare Birthday Week 2026 wrap-up](https://blog.cloudflare.com/birthday-week-2026-wrap-up/)

#### ngrok
- **AI Gateway.**
  - One endpoint to hosted and local models (OpenAI, Anthropic, Google, DeepSeek, xAI, Ollama, vLLM), with access control and failover.
  - Billed in credits: "No subscription plan required to get started".

  Source: [ngrok AI Gateway](https://ngrok.com/docs/ai-gateway/)
- **June 2026 change.** The dashboard moved to `app.ngrok.ai`. A Traffic Policy with the `ai-gateway` action now fails validation (`ERR_NGROK_3820`), so LLM traffic must go to `gateway.ngrok.ai` (search summary). — [ngrok AI Gateway changelog](https://ngrok.com/docs/ai-gateway/changelog)
- **17 Nov 2026.** The hosted ngrok MCP server (`https://mcp.ngrok.com/mcp`) can create and modify AI Gateway configs, so an agent can set up "a virtual model, a restricted key, and calling code from one prompt" (search summary). — [ngrok changelog, MCP write tools](https://ngrok.com/changelog/ai-gateway-mcp-write-tools); [ngrok MCP server docs](https://ngrok.com/docs/mcp-server)
- **ngrok as MCP gateway.** Private internal endpoints are published via `forward-internal` (earlier note, page dated 21 Sep 2026). — [Using ngrok as your MCP gateway](https://ngrok.com/docs/using-ngrok-with/using-mcp)

#### Teleport
- **Agentic Identity Framework (late Jan 2026).**
  - "cryptographic identity, ephemeral privileges, access guardrails, auditability, and real-time enforcement".
  - An MCP proxy "with authorization and visibility" and MCP server discovery.
  - Built on MCP and SPIFFE "to reduce vendor lock-in".
  - LLM controls: rate limits, budgets, routing, prompt and response tracking.

  Sources (search summary): [Teleport Agentic Identity Framework](https://goteleport.com/platform/agentic-identity-framework/); [Teleport press release](https://goteleport.com/about/newsroom/press-releases/teleport-introduces-agentic-identity-framework/)
- **Beams.**
  - Announced 19 Mar 2026, MVP 30 Apr 2026, GA 10 Nov 2026 at KubeCon NA.
  - Each agent runs in an isolated Firecracker VM with "delegated identity", connects "without secrets", and every action is logged.
  - Quotes: "The biggest blocker to agentic AI in the enterprise is friction introduced by security and IAM"; "every agent has the identity, access controls, and audit trail it needs".

  Sources: [Teleport Beams press release](https://goteleport.com/about/newsroom/press-releases/teleport-launches-beams-trusted-agent-runtimes-for-infrastructure/); [Cloud Native Now, Beams GA](https://cloudnativenow.com/uncategorized/teleport-beams-trusted-runtime-for-ai-agents-reaches-general-availability/) (search summary); [Help Net Security, 19 Mar 2026](https://www.helpnetsecurity.com/2026/03/19/teleport-announced-beams/)

#### NetBird, Pomerium, NetFoundry, Twingate
- **NetBird Agent Network.**
  - An access-control layer for agents reaching LLM APIs through one proxy endpoint, which can front LiteLLM, Portkey or Cloudflare AI Gateway.
  - "The tunnel is the credential."
  - The sidebar labels it "New". A search summary of the docs says "currently in beta".

  Sources: [How Agent Network works](https://docs.netbird.io/agent-network/how-it-works); [What is NetBird Agent Network?](https://docs.netbird.io/agent-network) (search summary)
- **NetBird MCP server.** A separate server for changing NetBird config, off by default on self-hosted. — [NetBird MCP server](https://docs.netbird.io/manage/mcp-server) (search summary)
- **Pomerium.**
  - Acts as "a secure gateway between MCP clients and servers, handling OAuth 2.1 flows with upstream services so you don't need to implement OAuth in your MCP server" (changelog).
  - Logs every tool call with parameters.
  - MCP is on every plan, including free Zero Personal.

  Sources: [Pomerium changelog, experimental MCP support](https://www.pomerium.com/changelog/experimental-mcp-support) (search summary); [Pomerium MCP docs](https://www.pomerium.com/docs/capabilities/mcp); [Pomerium pricing](https://www.pomerium.com/pricing)
- **NetFoundry (2 Jun 2026).**
  - MCP Gateway: aggregation, tool namespacing, permission filtering, RBAC.
  - LLM Gateway: OpenAI-compatible; semantic routing; guardrails; per-identity budgets; on-prem and air-gapped.
  - Quotes: "Every AI agent, MCP server, and LLM endpoint in a NetFoundry enclave receives its own cryptographic identity."; "There is no reachable surface for agents to misuse or attackers to exploit."
  - A2A network is "not yet available".

  Source: [NetFoundry press release](https://netfoundry.io/press-release/netfoundry-launches-enterprise-class-mcp-and-llm-gateways-bringing-zero-trust-to-ai-deployments/)
- **Twingate.**
  - Identity Firewall / PAM (13 Nov 2025): "It extends the same Zero Trust principles to AI agents that you apply to human users", "with planned support for emerging standards like the Model Context Protocol (MCP) and Agent-to-Agent (A2A) communication".
  - Starter includes it for up to 5 resources at no cost.

  Source: [Twingate blog, Identity Firewall](https://twingate.com/blog/identity-firewall)
- **Twingate agentic workflows page.** Least-privilege access for agents and service accounts with no standing credentials, and headless CLI setups for agents and CI. — [Twingate agentic workflows](https://www.twingate.com/product/agentic-workflows) (search summary)
- **Twingate blog argument.** MCP servers should not be reachable from the open internet. — [Twingate blog, AI gateway access](https://www.twingate.com/blog/ai-gateway-access) (search summary)

#### No agent story found, and the new entrant
- **ZeroTier.** No agent-specific product found. 2026 news is ZeroTier Quantum (RSAC, Mar 2026) and an award release framing identity-based networking for a world of AI agents (search summary). — [BusinessWire, ZeroTier Quantum](https://www.businesswire.com/news/home/20260322114599/en/RSAC-2026-ZeroTier-Launches-ZeroTier-Quantum-the-Worlds-First-End-to-End-Quantum-Secure-Networking-Platform); [ZeroTier award release](https://www.zerotier.com/news/zerotier-named-cybersecurity-solution-of-the-year-2026-by-the-cyber-security-review/)
- **Defined, Headscale, Netmaker, Pangolin.** No agent or MCP features on their pricing pages. — [Defined pricing](https://www.defined.net/pricing/); [Netmaker pricing](https://www.netmaker.io/pricing); [Pangolin pricing](https://pangolin.net/pricing)
- **doxx.net.**
  - Quotes: "Agents on doxx.net get what humans get"; "No other network treats people and their agents as peers on infrastructure one company owns end to end."
  - Agents get "their own network identity, private channels to their humans and each other".
  - Claims more than 38 million threats blocked in closed beta since Dec 2025.

  Source: [Help Net Security](https://helpnetsecurity.com/2026/10/05/doxx-net-agentic-defined-networking-platform)

### Inferences
- **The 2026 consensus has three parts:**
  - give the agent a network identity rather than a key;
  - put a gateway in front of models and MCP;
  - log everything at that gateway.

  The product under evaluation already matches the first, with per-role address ranges and agents as devices.
- **The differentiator is doing the second and third without the operator reading content.** Every incumbent's agent product depends on reading content: Aperture captures full bodies, Cloudflare portals log prompt activity and run DLP, NetBird captures prompts on request, NetFoundry's guardrails read prompts.
- **Copy should avoid saying "agent identity" as if it were unique.** Tailscale (agents as nodes, first-connect approval), NetBird ("the tunnel is the credential"), Teleport (delegated identity) and NetFoundry (a cryptographic identity per agent) all say it.
- **Cloudflare publicly admits a gap** (no per-agent identity in Gateway yet), and Twingate's MCP support is still "planned". Both are short-lived openings.

### Gaps
- Aperture pricing and hosting model.
- Pricing for Cloudflare MCP portals, Teleport Beams and NetFoundry gateways.
- An exact launch date for NetBird Agent Network.
- doxx.net product docs (ingress, pricing, storage, email).
- No Pangolin or ZeroTier agent roadmap statement was found.

---

## 5. Adoption signals (customers, users, funding, revenue claims) and 2026 outages, incidents and advisories

### Takeaway
- **Tailscale is the scale leader among neutral vendors:**
  - about 40,000 paid business customers and 2 million MAU (Jul 2026);
  - a 2025 Series C at about $1.5B USD;
  - its first acquisition (Border0, Mar 2026).
- **NetBird raised a $10M Series A** (Jan 2026).
- **doxx.net raised a reported $38M from a16z** (Oct 2026).
- **ngrok's last public round is still 2022.**
- **Reliability.** Tailscale had a string of short coordination-server incidents in 2026 (longest about 4 h). Cloudflare had a 20 Feb 2026 BGP outage (official postmortem) and a 20 Oct 2026 Zero Trust disruption (about 3 h 14 m, per status aggregators). Teleport's last critical advisory found is CVE-2025-49825 (June 2025).

### Cited Findings

#### Adoption and funding
- **Tailscale (BetaKit, 21 Jul 2026).**
  - "on the cusp of surpassing 40,000 paid business clients", twice the November count.
  - "two million monthly active users"; "now 300-person".
  - On track to double sales in 2026.
  - Most firms added in the past eight months use it "as part of their AI infrastructure stack" (onboarding survey).
  - Named customers include Cohere, Lovable, Mistral, Duolingo, Instacart, Microsoft, Nvidia, SAP and Telus.

  Source: [BetaKit](https://betakit.com/tailscale-catches-ai-tailwinds-as-it-nears-40000-paid-business-customers/)
- **Tailscale Series C.**
  - $160M USD in Apr 2025 at about $1.5B. — [SiliconANGLE, 8 Apr 2025](https://siliconangle.com/2025/04/08/networking-startup-tailscale-raises-160m-1-5b-valuation/)
  - BetaKit reports it as "$230-million CAD" at "$2-billion" (CAD). — [BetaKit, Series C](https://betakit.com/corporate-vpn-startup-tailscale-secures-230-million-cad-series-c-on-back-of-surprising-growth/)
  - Revenue is undisclosed.
- **Tailscale acquired Border0** (privileged access management) on 17 Mar 2026, its first acquisition. Border0's seven-person Vancouver team joined. This is a secondary source citing Tailscale's announcement and BetaKit. — [bex.co](https://bex.co/blog/2026/07/09/tailscale-pricing-v4-border0-headscale)
- **ngrok.** $50M Series A led by Lightspeed (Dec 2022). The 2022 release says "more than 5 million developers". No 2026 round or revenue was found. **This dates from 2022.** — [ngrok press release](https://ngrok.com/press-releases/ngrok-raises-50m-for-ingress-as-a-service)
- **NetBird.** $10M Series A (reported as €8.5M) led by Pace Capital with Nauta, InReach and Antler, on 13 Jan 2026. A €4M seed followed in 2024 (search summary). — [Tech.eu, 13 Jan 2026](https://tech.eu/2026/01/13/netbird-announces-10m-series-a-to-expand-open-source-vpn-alternative/)
- **Teleport.** Beams runs on the "Teleport Infrastructure Identity Platform", which the company says is "in production at more than 700 enterprises" (vendor claim, search summary). — [SiliconANGLE](https://siliconangle.com/?p=853497)
- **Pangolin.**
  - YC Summer 2025 batch.
  - Company says it closed a "$4.7M seed round" (Chemistry, YC, BLAST, 468 Capital and others). One aggregator reports only $500K, so the sources conflict.
  - 10,000 GitHub stars on 19 Jun 2025.
  - **This dates from 2025.**

  Source: [Pangolin blog, seed round](https://pangolin.net/news/seed-round) (search summary)
- **doxx.net.**
  - $38M Series A led by a16z, with Animo Ventures and Focal.vc; a16z partner Joel De La Garza joins the board.
  - A Dealroom-linked report says $24.6M, which conflicts.

  Sources: [Help Net Security](https://helpnetsecurity.com/2026/10/05/doxx-net-agentic-defined-networking-platform); [a16z](https://a16z.com/announcement/investing-in-doxxnet/); [Dealroom](https://dealroom.co/news/158848-doxx-net-lands-38m-series-a-for-agentic-networking/) (search summary)
- **Weak open-source signals (earlier notes).**
  - GitHub API on 31 Oct 2026: `cloudflare/cloudflared` 16,361 stars; `openziti/zrok` 4,797; `fatedier/frp` 110,353.
  - Docker Hub pulls: `headscale/headscale` 6.7M; `netbirdio/management` 1.5M.

  Sources: [cloudflare/cloudflared](https://github.com/cloudflare/cloudflared); [openziti/zrok](https://github.com/openziti/zrok); [Docker Hub API](https://hub.docker.com/v2/repositories/vaultwarden/server/) (the earlier note's query base)

#### Outages, incidents, advisories
- **Tailscale coordination server, 2026.**
  - 9 Apr: about 1.1 h of slow responses affecting connectivity and logins (official status page). — [Tailscale status, 9 Apr 2026](https://status.tailscale.com/incidents/01KNSQAEMDVVFAEKYE9Z7DK9N7)
  - From the isdown.app aggregator (search summary; individual pages not opened):
    - 16 Jul: about 4 h of elevated errors.
    - 17 and 19 Aug: about 1.9 h and 2.4 h, including the admin console.
    - 1 Oct: 48 min of sign-in 500s.
    - Shorter events on 13 Jan, 27 Jan, 11 Feb, 26 Feb, 1 Mar, 11 Mar, 7 May, 3 Aug and 24 Aug.
    - Source: [isdown, Tailscale outage history](https://isdown.app/status/tailscale/outage-history?page=3)
  - Tailscale's own docs: while coordination is down, "existing connections and cached policies keep working", but devices cannot make new connections or get policy updates (earlier note). — [Coordination server down](https://tailscale.com/docs/reference/coordination-server-down)
- **Tailscale Funnel regression.**
  - Client 1.102.1 broke public Funnel ingress while status still showed "on". The fix shipped in 1.102.2 the same day (4 Aug 2026).
  - On 18 Aug a user reported the macOS App Store build still on 1.102.1 (earlier note).

  Source: [tailscale/tailscale#20739](https://github.com/tailscale/tailscale/issues/20739)
- **Cloudflare, 20 Feb 2026.** Official postmortem: a subset of Bring Your Own IP customers had their routes withdrawn via BGP. A secondary outlet gives a different cause; prefer the official account. — [Cloudflare blog, outage 20 Feb 2026](https://blog.cloudflare.com/cloudflare-outage-february-20-2026/); [WebProNews](https://www.webpronews.com/how-a-single-misconfigured-rule-took-down-15-of-cloudflares-global-network-for-90-minutes/)
- **Cloudflare, 20 Oct 2026.** About 3 h 14 m of disruption from 03:20 UTC affecting Zero Trust connectivity, Access logins, Secure Web Gateway and the dashboard (status-page summaries via an aggregator; no root-cause post found). — [isdown, Cloudflare Zero Trust incident](https://isdown.app/status/cloudflare/incidents/672477-cloudflare-zero-trust-connectivity); [Cloudflare status](https://www.cloudflarestatus.com/)
- **Cloudflare Quick Tunnels (Oct 2026, earlier note).** On cloudflared 2026.10.0, `--allowed-mail` sessions expired about 5 seconds after the one-time-PIN login. Users: "effectively unusable". — [cloudflare/cloudflared#1752](https://github.com/cloudflare/cloudflared/issues/1752)
- **Teleport.**
  - CVE-2025-49825: SSH authentication bypass, CVSS 9.8, June 2025; Teleport Cloud not affected. **This dates from 2025.** — [SecurityWeek](https://www.securityweek.com/critical-authentication-bypass-flaw-patched-in-teleport/); [OSV](https://osv.dev/vulnerability/GHSA-8cqv-pj7f-pwpc)
  - 2026 CVEs appear in downstream Teleport 18 packages (CVE-2026-23831, CVE-2026-22703, CVE-2026-42501) with unconfirmed severity. — [Snyk](https://security.snyk.io/vuln/SNYK-CHAINGUARDLATEST-TELEPORT18-16638014) (search summary)

### Inferences
- **Tailscale's 2026 is a land grab driven by AI.** Paid customers doubled in about eight months, and the CEO cites agents recommending and deploying the product. Expect aggressive agent features and fast pricing tweaks.
- **Small-team buyers have shown they will evaluate NetBird or Headscale when prices move.**
- **Centralized control planes fail visibly**: Tailscale's coordination incidents, Funnel ingress tied to the control connection, Cloudflare's multi-hour Zero Trust disruption. Any new control plane will be judged the same way, so publishing degraded-mode behavior (what keeps working when control is down) is table stakes, as Tailscale does.

### Gaps
- Funding for Twingate, ZeroTier, Defined, Netmaker and Pomerium, and customer counts for all vendors except Tailscale, were not researched in this pass.
- Cloudflare's public-company revenue for Zero Trust was not researched.
- No official root-cause posts were found for Tailscale's 2026 incidents or Cloudflare's 20 Oct 2026 incident.
- No 2026 Tailscale security bulletins were checked.

---

## 6. User complaints relevant to privacy, lock-in, pricing or reliability

### Takeaway
2025–2026 complaints cluster on four themes:
- **Pricing surprises:** Tailscale's seat billing and the opaque "Contact Sales" wall for tagged and ephemeral resources; ZeroTier's free-device cut; ngrok's free-plan interstitial.
- **Reliability of public paths:** Funnel ports and the 1.102.1 regression; Cloudflare's quick-tunnel email gate.
- **Lock-in:** "embed yourself as a deep infrastructure dependency".
- **License shifts:** NetBird's AGPL move, Pangolin's dual license.

Privacy complaints in the threads opened were rare. Users mostly worry about cost and lock-in, while vendors' own docs reveal the visibility issues.

### Cited Findings
- **Tailscale, pricing and lock-in (HN, Apr 2026).** "that jumps to $64 a month" (Tenkuru); "We might need to drop our Tailscale usage because of this." (packetlost); "behind an opaque "Contact Sales" wall" and "embed yourself as a deep infrastructure dependency" (pepemon); "I would _love_ to give you guys money, you just won't let me." (drcongo). — [HN 47691281](https://news.ycombinator.com/item?id=47691281)
- **Tailscale Funnel ports (open issue; comments from 2024 to 2026, earlier note).** `--https=9443` prints "Funnel on" but "requests from the outside will time out". A Tailscale engineer (31 Jul 2026) said the CLI should use `CheckFunnelPort` and does not. — [tailscale/tailscale#10742](https://github.com/tailscale/tailscale/issues/10742) Users also hit the three-port limit in TCP mode: "even less than three ports are really insufficient". — [tailscale/tailscale#14625](https://github.com/tailscale/tailscale/issues/14625)
- **Tailscale Funnel regression (Aug 2026, earlier note).** `funnel status` "reports ‘on’ even when the actual public path is completely broken". — [tailscale/tailscale#20739](https://github.com/tailscale/tailscale/issues/20739)
- **ngrok free interstitial (Feb 2026, earlier note).**
  - Breaks MCP widget asset loading in Claude.ai.
  - An Anthropic staffer replied: "We recommend using cloudflared instead of ngrok for local MCP development. It's free, has no interstitial pages, and requires no extra headers."
  - The issue was closed as not planned.

  Source: [anthropics/claude-ai-mcp#53](https://github.com/anthropics/claude-ai-mcp/issues/53)
- **Cloudflare quick-tunnel email gate (Oct 2026, earlier note).** "In practice the protected site cannot be used." One user: "So much wasted time and retyping of my email address every damn time." — [cloudflare/cloudflared#1752](https://github.com/cloudflare/cloudflared/issues/1752)
- **ZeroTier free-tier cut.** Forum users pushed back on 25 dropping to 10 devices. One said "stuff just stopped working" after hitting a limit without warning; earlier critics called the Essential move "a bit of bait and switch" (search summary). — [ZeroTier forum, blocked after new pricing](https://discuss.zerotier.com/t/blocked-out-of-the-dashboard-after-new-pricing-model/22030); [ZeroTier forum, Essential feedback](https://discuss.zerotier.com/t/essential-plan-feedback/22318)
- **NetBird AGPL move (Aug 2025, earlier note).** HN commenters raised the CLA as a relicensing risk. One commenter had moved from Tailscale to NetBird. — [HN 44813110](https://news.ycombinator.com/item?id=44813110)
- **A competitor's privacy framing of Cloudflare Tunnel.** Pangolin's own blog (May 2026) calls cloud-terminated reverse proxies "a mandatory man-in-the-middle decrypting your SSL". This is a vendor argument, not a user complaint. — [Pangolin blog](https://pangolin.net/news/building-a-peer-to-edge-peer-reverse-proxy)
- **Headscale self-hosting caveats (secondary, a self-hosting vendor's blog).** "practical ceiling near 300 devices"; no session recording, no native SSO console, community-only support. — [bex.co](https://bex.co/blog/2026/07/09/tailscale-pricing-v4-border0-headscale)

### Inferences
- **The most persuasive buyer-side message is pricing predictability without an agent tax.** That means flat seats, no per-agent or per-tagged-device meter, and no "Contact Sales" wall for machine counts. Privacy is the architectural differentiator, but users rarely complain about it unprompted.
- **Reliability complaints focus on public ingress that looks healthy while broken.** A TLS edge that reports real reachability, and supports any port and custom domains, addresses the most-cited Funnel and quick-tunnel failures.
- **License-trust wariness is real.** NetBird's CLA debate and Pangolin's dual license show it. A dated commitment on licensing of the client and relay code would pre-empt it.

### Gaps
- Reddit threads were not opened (login wall).
- No complaint threads were found for Twingate, Pomerium, Defined, Netmaker, NetFoundry or zrok in 2025–2026; none was searched in depth.
- No user discussion of Aperture's dependence on Vercel or its prompt capture was found.
- No user reaction to Cloudflare Mesh's traffic routing through its edge was found.
