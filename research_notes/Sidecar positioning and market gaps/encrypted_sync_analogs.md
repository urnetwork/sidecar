# Encrypted sync analogs: precedents for E2EE, real-time, git-compatible team storage and userspace private networking (state as of 31 October 2026)

Conventions used in these notes:
- "[GitHub API, 2026-10-31]" means star counts, last-push dates and release dates were pulled from the GitHub REST API on 31 Oct 2026. Stars are only a rough proxy for adoption.
- "[search excerpt; page not opened]" means the fact comes from a search-engine summary of that URL, not from a fetch of the page. Treat it as less reliable than an opened page.
- "Vendor claim" marks statements made by a company about itself.
- Pages that failed to load are noted inline, and nothing was filled in from memory.

---

## 1. Keybase: what it offered, adoption, what happened after Zoom bought it (2020 to 2026), and lessons for an encrypted git + team identity + messaging bundle

### Takeaway
Keybase built almost exactly the bundle URnetwork is designing (E2EE git, cryptographic teams with key rotation, E2EE chat, an encrypted filesystem), gave it all away free with a reported ~200k to 400k users, and was acquired by Zoom on 7 May 2020, mainly for its crypto team, to fix Zoom's own E2EE problem. The app has run in low-key maintenance mode since: the client still ships small releases in 2026 (v6.6.3 on 2026-06-03, commits through 2026-10-30), but I found no product investment or roadmap.

### Cited Findings
**What Keybase offered**
- Keybase launched 14 Feb 2014. Its creators are listed as Chris Coyne, Max Krohn and others. Features: identity proofs that link social accounts to keys; E2EE chat (launched Feb 2017); KBFS, "free cloud storage of up to 250 GB" split into public, private and team folders, with paid plans "planned" but no upgrades available; encrypted git (Oct 2017); teams (Sept 2017); Stellar wallets (Sept 2019) — [Wikipedia: Keybase](https://en.wikipedia.org/wiki/Keybase) (secondary).
- Teams (blog post, 18 Sep 2017):
  - "Teams get chats and channels." Encrypted team files live in `/keybase/team/`. Subteams inherit admin control, and roles separate writers from admins.
  - On removal: "The Keybase app takes care of all the crazy stuff, such as rotating keys when Alice later boots Carter."
  - Server visibility was stated explicitly: "Keybase servers do know team memberships: team names, users, and roles." "Keybase servers cannot read the contents of chats or files or even know the names of chat channels or files." "At no point does Keybase have any private keys for any file or chat data."
  - Pricing: "We think someday if teams take off, we'll charge for larger teams", and "there is no upsell on message history."
  - Source: [Keybase blog, Introducing Keybase Teams](https://keybase.io/blog/introducing-keybase-teams).
- Encrypted git (blog post, 4 Oct 2017):
  - An open-source `keybase://` git remote helper built on go-git. "It is end-to-end encrypted." "Even your repository names and branch names are encrypted." "Everything is signed."
  - Servers can see team membership, who pushes and fetches, which devices are used, and opaque repo IDs.
  - Free, with a 100 GB cap for personal repos plus 100 GB per team.
  - Limits: "No pull requests, no wiki, no issue tracking." "Your work is only as safe as your endpoints."
  - The post explains that storing a bare repo directly in KBFS could cause conflicts, so the helper uses locking in git instead.
  - Source: [Keybase blog, Encrypted git for everyone](https://keybase.io/blog/encrypted-git-for-everyone).

**Adoption figures (all old and weakly sourced)**
- The Wikipedia infobox lists 407,163 users as of 2019-08-22, flagged "citation needed" — [Wikipedia: Keybase](https://en.wikipedia.org/wiki/Keybase).
- A Stellar Development Foundation post said "Keybase has about 200,000 users and is growing fast". The date was not visible to me (likely 2018 to 2019) — [Stellar blog](https://stellar.org/blog/keybase-and-stellar-partnership) [search excerpt; page not opened].
- The acquisition announcement gives no Keybase user numbers. Its only figure is about Zoom ("Hundreds of millions of participants") — [Keybase blog, Keybase joins Zoom](https://keybase.io/blog/keybase-joins-zoom).

**Zoom acquisition and aftermath**
- 7 May 2020: "Today we're announcing that Zoom acquired Keybase." "Initially, our single top priority is helping to make Zoom even more secure." "There are no specific plans for the Keybase app yet." "Ultimately Keybase's future is in Zoom's hands." "if anything changes about Keybase's availability, our users will get plenty of notice." No deal terms or monetization plans were disclosed — [Keybase blog](https://keybase.io/blog/keybase-joins-zoom).
- Zoom's press release, cited by Wikipedia (title only; not opened), was headlined "Zoom acquires Keybase and announces goal of developing the most broadly used enterprise end-to-end encryption offering" — [Zoom blog](https://blog.zoom.us/wordpress/2020/05/07/zoom-acquires-keybase-and-announces-goal-of-developing-the-most-broadly-used-enterprise-end-to-end-encryption-offering/).
- Context: on 9 Nov 2020 the FTC alleged that Zoom had touted "end-to-end, 256-bit encryption" since at least 2016 while "Zoom maintained the cryptographic keys that could allow Zoom to access the content of its customers' meetings." The settlement required a security program, a ban on misrepresentation, and biennial independent assessments — [FTC press release](https://www.ftc.gov/news-events/news/press-releases/2020/11/ftc-requires-zoom-enhance-its-security-practices-part-settlement).
- User reaction: Decrypt ran the headline "Keybase users revolt following Zoom acquisition" (May 2020; article not opened) — [Decrypt](https://decrypt.co/28121/keybase-users-revolt-following-zoom-acquisition).

**Status through 2026, with conflicting sources**
- Wikipedia: "Since the acquisition, development has stopped, but the service has been kept functional." This has no inline citation — [Wikipedia: Keybase](https://en.wikipedia.org/wiki/Keybase).
- GitHub partly contradicts this. keybase/client released v6.6.0 (2026-03-06), v6.6.2 (2026-04-08) and v6.6.3 (2026-06-03, marked "Latest"). The notes mention multi-account push notifications, account switching, audio attachments, "Git default branch handling", Emoji 16 and HEIC avatars. Earlier, v6.3.1 added chat, file and repo archiving. Commits continue through 2026-10-30, e.g. "bump rpc module with better context cancellation handling". The repo has 9,266 stars — [keybase/client releases](https://github.com/keybase/client/releases) [GitHub API, 2026-10-31].
- The standalone keybase/kbfs repo is archived (last push 2019-02-12) — [GitHub keybase/kbfs](https://github.com/keybase/kbfs) [GitHub API, 2026-10-31].

**Comparable precedent: Skiff**
- Skiff offered E2EE mail, calendar, pages and drive. Notion acquired it in Feb 2024, and Skiff discontinued its services with roughly six months for users to migrate; accounts were not converted to Notion accounts — [Reclaim The Net](https://reclaimthenet.org/private-email-and-documents-company-skiff-is-shutting-down-after-notion-acquisition); [AlternativeTo](https://alternativeto.net/news/2024/2/notion-acquires-the-privacy-focused-platform-skiff-ending-its-services-within-6-months/) [search excerpts; pages not opened].
- Gigazine reported that Skiff had 2 million users in Nov 2023 — [Gigazine](https://gigazine.net/gsc_news/en/20240214-notion-acquired-skiff) [search excerpt].

### Inferences
- **The bundle is buildable; the business was the problem.** A small team shipped E2EE git, teams with key rotation, chat and a filesystem on one signed identity layer. Everything was free, with large quotas (250 GB KBFS, 100 GB of git per team), and charging was deferred to "someday". The exit was an acqui-hire to fix the acquirer's E2EE credibility, not a scale-up. A new entrant should put a paid wedge (team admin, audit, seats) in the product from day one.
- **Acquisitions strand E2EE data.** With Keybase and Skiff, users' encrypted data lived on a vendor-hosted service whose fate the acquirer controlled. A git-native design softens this: data stays in ordinary git repos that can be cloned and kept in the clear locally, with a documented export path.
- **Keybase set a good bar for claim hygiene.** It listed exactly which metadata its servers could see (membership, push and fetch events, devices, opaque repo IDs). URnetwork should publish the same kind of list for the sidecar, relays and TLS edge.
- **Keybase did not put git's mutable state on its real-time filesystem.** It used locking because a bare repo in KBFS could conflict. This bears directly on the sidecar sketch of "each directory is a git server" backed by real-time encrypted storage (see section 6).
- **"Maintenance mode for six years" is itself a signal.** Zoom kept Keybase running and patched but did not grow it. Without a business reason, an acquirer of an E2EE collaboration tool is more likely to freeze or shut it than to invest.

### Gaps
- No official Keybase user or MAU numbers after 2019. The acquisition price is undisclosed.
- No 2021 to 2026 Zoom or Keybase statement about the app's future turned up in searches. I did not verify whether new sign-ups, the Stellar wallet or KBFS quotas still work in 2026; release notes still mention Stellar IDs in v6.3.1.
- I did not open the Keybase NCC Group audit or the "Keybase and the chaos of crypto" essay, which covers the Stellar airdrop.

---

## 2. Analogs: what each does, how widely it is used, how it makes money, and whether it positioned for AI agents in 2025 to 2026

### Takeaway
The networking side is commoditizing fast and has explicitly positioned for agents in 2026:
- Iroh 1.0 shipped 2026-06-15, with agent and LLM use cases.
- Tailscale calls itself "the missing network identity layer for AI agents"; its Aperture AI gateway went GA 2026-08-26.
- NetFoundry (OpenZiti, zrok) launched MCP and LLM gateways in June 2026.

On the storage side, the agent-positioned product (Dolt, "the Database for Agents") is not E2EE. The E2EE sync products (classic Jazz, Automerge with Keyhive) are not agent-positioned or are still alpha. Radicle's private repos are unencrypted and flagged "unfit for use today". Jazz's 2026 relational rewrite no longer foregrounds E2EE.

### Cited Findings

#### Summary table (as of 31 Oct 2026; sources in the per-product bullets below)
| Product | What it is | Stored-data E2EE? | Adoption proxy | Business model | Agent positioning 2025 to 2026 |
|---|---|---|---|---|---|
| Radicle | P2P git forge (issues and patches as git objects) | No. Private repos "not encrypted at rest", and the docs warn they are "unfit for use today" | 270 stars on GitHub mirror; ">40" seed nodes at 1.0 (Sept 2024) | Radworks treasury governed by the RAD token; grants | None found |
| Iroh (n0) | P2P QUIC, "dial keys not IPs", NAT traversal, relays | Transport only (authenticated QUIC); iroh-docs is a separate, niche repo | 12.9k stars; vendor claims "millions of devices" | Open-source library plus paid "iroh services" (hosted relays, Pro plan) | Yes: Mesh LLM (Jul 2026); Block's Buzz (Sept 2026) |
| Jazz (Garden Computing) | Local-first sync DB | Classic: yes (group read keys). New relational Jazz: E2EE not mentioned; read policies applied server-side | Classic 2.5k stars; new repo 221 stars (v2 alpha) | Open-source server plus usage-priced Jazz Cloud | Light ("People and agents now edit the same data...") |
| Automerge / Ink & Switch | CRDT library; research on version control and E2EE access control | Keyhive/ARK E2EE is in alpha | Automerge 6.7k stars; keyhive 269 stars | Research lab; NLnet project page for Keyhive | None found |
| Dolt (DoltHub) | Version-controlled SQL with git semantics | No E2EE found | 24.8k stars | Open-source DB plus commercial DoltHub, Hosted Dolt, DoltLab | Strong: slogan changed to "Dolt is the Database for Agents" (2026) |
| git-crypt | Transparent encryption of chosen files in git | Partial (file contents only) | ~10k stars | Volunteer OSS | None |
| git-remote-gcrypt | Remote helper that encrypts a whole git remote | Yes (packs and manifest) | ~1k stars | Volunteer OSS | None |
| SOPS | Secrets-file encryption tool | n/a (secrets files) | 23.6k stars | OSS (governance not verified) | None found |
| Syncthing | P2P continuous file sync | Not examined this round | 89.9k stars | Foundation and donations, plus Kastelo commercial support | None found |
| zrok / OpenZiti (NetFoundry) | Public and private sharing over a zero-trust overlay | Transport ("securely and privately transported") | zrok 4.8k stars; ziti 4.5k stars | OSS plus NetFoundry SaaS and commercial gateways | Yes: MCP and LLM gateways (Jun 2026) |
| tsnet (Tailscale) | Tailscale embedded in a Go program, userspace TCP/IP | Transport (WireGuard-based) | tailscale 38.4k stars; $160M Series C (Apr 2025) | SaaS | Yes: agent identity; Aperture GA (Aug 2026) |
| Holepunch / Pear | P2P app runtime behind the Keet messenger | Not specified on the Pear launch page | pear 439 stars; hypercore 2.9k stars | Tether-backed; no revenue model stated | Indirectly, via Tether's QVAC local-AI SDK |

#### Radicle (P2P git, identities, private repos)
- Radicle 1.0.0 was released 10 Sep 2024. It describes itself as a "peer-to-peer, local-first code collaboration stack built on Git". Issues, patches and code review are stored as Collaborative Objects inside the repo. Identity is based on public keys. It has built-in Tor support, and the release cited more than 40 seed nodes "freely replicating user content". Planned work at the time included native CI/CD, multi-device support and a desktop app. radicle.xyz now redirects to radicle.dev — [Radicle 1.0.0 announcement](https://radicle.dev/2024/09/10/radicle-1.0.0).
- Private repositories, per the user guide:
  - Such a repo is "only visible and accessible to explicitly authorized peers", controlled by an allow list of DIDs.
  - "Private repositories are not encrypted at rest", so any allow-listed node can read the contents.
  - "While private repositories are supported in Radicle, severe security vulnerabilities make them unfit for use today."
  - Unpublishing "won't delete historic repository data from public seed nodes or other peers".
  - "Radicle's codebase hasn't yet undergone formal security audits."
  - Transport between nodes is encrypted with ChaCha20-Poly1305.
  - Source: [Radicle user guide](https://radicle.dev/guides/user).
- Adoption proxies: the radicle-dev/heartwood GitHub mirror has 270 stars, and its latest tag is releases/1.10.3 — [GitHub radicle-dev/heartwood](https://github.com/radicle-dev/heartwood) [GitHub API, 2026-10-31]. No user counts found.
- Funding [search excerpts; pages not opened]:
  - Radworks is a treasury governed by RAD tokenholders, with about 50M RAD allocated to the community treasury — [RAD token docs](https://docs.radworks.org/community/rad-token).
  - Grants typically run from 2,000 to 50,000 USDC or RAD — [Radworks grant program](https://docs.radworks.org/community/grant-program).
  - 430,289.60 USDC had been "transferred to the Foundation ... to fund Radicle Protocol development" as of 19 Aug 2025 — [Radworks forum](https://community.radworks.org/t/foundation-to-oversee-development-of-radicle-protocol-and-radworks-app/3646/2).
- AI-agent positioning: none found in the sources reviewed.

#### Iroh / n0 (P2P QUIC with hole punching; iroh-docs)
- "Iroh 1.0 - Dial Keys, not IPs" was posted 15 Jun 2026 by b5. Contents:
  - Features: QUIC multipath, QUIC NAT traversal, public relays (open-source relay binaries), a local-first mode that works without internet, custom transports (BLE, WiFi Aware, Tor; LoRa under construction), WASM in the browser, and official Python, Node.js, Swift and Kotlin bindings.
  - Stability: wire changes come only with major versions. 0.35 relays are supported through 31 Dec 2026.
  - Vendor claims: public relays saw "more than 200 million endpoints created, in the last 30 days alone"; iroh is "running on millions of devices today"; "95% of data transferred in a connection" goes direct.
  - Listed use cases include "LLM training" and "agent communication".
  - Source: [iroh blog, v1](https://www.iroh.computer/blog/v1).
- Blog timeline:
  - Monetization: "iroh services" (hosted relays) was introduced 2025-10-09. Managed relays became authenticated by default (2026-07-30). A Pro plan with a shared authenticated relay arrived 2026-09-08, and "iroh-services 2.0" on 2026-10-02.
  - Privacy features: post-quantum key exchange (2026-05-19) and blinded address lookup (2026-10-13).
  - Customer story: Paycode connected toll-booth payment terminals (2026-03-26).
  - Agent work: "Mesh LLM: distributed AI computing on iroh" (2026-07-11) and "Buzz" (2026-09-22).
  - Source: [iroh blog index](https://www.iroh.computer/blog).
- Buzz (22 Sep 2026): "Block is building Buzz", a community platform where people and AI agents collaborate in shared channels. Its MeshLLM feature pools members' spare compute behind a local OpenAI-compatible endpoint over iroh's authenticated QUIC. The post mentions Goose's optional `roam` feature for agent-to-agent communication and names "more agent-to-agent communication over iroh" as the next step. It does not describe sharing memory or files between agents — [iroh blog, Buzz](https://www.iroh.computer/blog/buzz-agent-workspaces).
- Adoption proxies:
  - n0-computer/iroh has 12,891 stars; v1.4.1 shipped 2026-10-22.
  - n0-computer/iroh-docs ("Multi-dimensional key-value documents with an efficient synchronization protocol") is a separate repo with 76 stars; v0.100.0 shipped 2026-05-27. It is not mentioned in the 1.0 post.
  - Sources: [GitHub iroh](https://github.com/n0-computer/iroh); [GitHub iroh-docs](https://github.com/n0-computer/iroh-docs) [GitHub API, 2026-10-31].

#### Jazz (E2EE real-time sync with groups and permissions)
- Classic Jazz docs:
  - "Your data is always encrypted, even on Jazz Cloud servers." "Groups use a shared 'read key' for encrypting data".
  - "When someone is removed from a Group, the read key rotates and gets revealed to all remaining members." "removed members can't read new data, but existing data they already had access to remains readable to them."
  - Primitives: Ed25519 signatures, XSalsa20 encryption, BLAKE3 hashing.
  - Source: [classic Jazz docs, encryption](https://classic.jazz.tools/docs/react/reference/encryption).
- Repo split [GitHub API, 2026-10-31]:
  - garden-co/classic-jazz (created 2023-08-15) has 2,538 stars and is still pushed (2026-10-26).
  - The new garden-co/jazz repo was created 2026-01-04 and has 221 stars. It is described as "A local-first relational database for the browser, React Native and your backend", and its latest release is v2.0.0-alpha.59 (2026-10-04).
  - Sources: [GitHub garden-co/jazz](https://github.com/garden-co/jazz); [GitHub garden-co/classic-jazz](https://github.com/garden-co/classic-jazz).
- Current homepage (Oct 2026):
  - "Jazz is a relational database built on real-time sync." "Jazz is eventually consistent by default", with optional globally consistent transactions.
  - Row-level security and per-query auth are tied to JWT claims; "Jazz applies read policies together with each query, so unauthorized rows never leave the cloud." It also offers branches and edit history.
  - "People and agents now edit the same data at a much higher rate"; "agents & jobs" appear among supported runtimes; an `llms.txt` is linked.
  - Pricing: the server is open source and free to self-host. Jazz Cloud costs $0.039/hr for a 2 GB instance, $0.45/GB-month for storage and $0.09/GB for egress, with a free allowance.
  - © 2026 Garden Computing.
  - Source: [jazz.tools](https://jazz.tools/).
- The current docs landing page does not mention E2EE and links separately to "classic Jazz docs" — [jazz.tools/docs](https://jazz.tools/docs).
- A third-party database directory lists the new Jazz as a relational DBMS that syncs local SQLite with server-side SQLite. It gives the former name as "Groove" and the start year as 2026 — [dbdb.io](https://dbdb.io/db/jazz) [search excerpt].

#### Automerge and Ink & Switch local-first work (Upwelling, Patchwork, Keyhive)
- automerge/automerge has 6,701 stars; js/automerge-3.5.0 shipped 2026-09-16 — [GitHub automerge](https://github.com/automerge/automerge) [GitHub API, 2026-10-31].
- Upwelling (March 2023; McKelvey, Jenson, Wagner, Cook, Kleppmann) combines real-time editing with drafts, layers and a merged "stack". Details in section 6 — [Ink & Switch, Upwelling](https://www.inkandswitch.com/upwelling/).
- Patchwork explores "universal version control" for documents: lightweight branches, diff visualization, and a chat-like history interface, extended beyond prose to drawings and spreadsheets. Its spin-off Jacquard applies the ideas to scientific papers — [Patchwork notebook, 2024 version control](https://www.inkandswitch.com/patchwork/notebook/2024-version-control/) [search excerpt]. The current notebook index (2026 entries such as "Local-First Task Framework", April 2026) shows no AI-specific entries — [Patchwork notebook](https://www.inkandswitch.com/patchwork/notebook/).
- Keyhive is local-first access control plus E2EE. It uses BeeKEM, "a variant of TreeKEM", for E2EE groups "on the order of thousands of members", and beelay-core, described as auth-enabled sync over E2EE data — [Keyhive lab notebook](https://www.inkandswitch.com/keyhive/notebook/) [search excerpt]. An NLnet project page exists — [NLnet Keyhive](https://nlnet.nl/project/Keyhive/) [search excerpt]. inkandswitch/keyhive has 269 stars; keyhive-wasm/0.6.0 shipped 2026-10-29 — [GitHub keyhive](https://github.com/inkandswitch/keyhive) [GitHub API, 2026-10-31].
- ARK (Automerge Repo Keyhive) API guide:
  - "@automerge/automerge-repo-keyhive is still in alpha."
  - Relay access "lets it move ciphertext without being able to read the document."
  - `repo.create` "silently creates an unprotected document, with no access control or encryption".
  - "There is currently no key backup or recovery mechanism."
  - Source: [Automerge ARK API guide](https://automerge.org/docs/keyhive/ark-api-guide/).
- Business model: no Automerge revenue model found (see Gaps). AI-agent positioning: none found.

#### Dolt (version-controlled SQL)
- DoltHub blog, 5 Jun 2026 (Nick Tobey): "Somewhat recently we changed our slogan." The old slogan was "Dolt is Git for Data"; the new one is "Dolt is the Database for Agents". "recently many of our users have use cases related to Agentic AI." The post gives no usage figures — [DoltHub blog, Our AI policy](https://www.dolthub.com/blog/2026-06-05-our-ai-policy/).
- Other 2026 DoltHub posts [search excerpts; not opened]:
  - April 2026 credits Gas Town with a spike in Dolt usage — [DoltHub blog](https://dolthub.com/blog/2026-04-16-two-weeks-in-gastown/).
  - March 2026 says Dolt is the persistence layer for Beads and that Gas Town struggled beyond four concurrent agents without it — [DoltHub blog](https://www.dolthub.com/blog/2026-03-13-multi-agent-persistence/).
  - August 2026 asks how to build products for agents and notes that an earlier Dolt MCP server exists — [DoltHub blog](https://dolthub.com/blog/2026-08-27-how-do-you-build-products-for-agents).
- Vendor marketing says each agent works on its own branch and only what works gets merged — [aidatabase.dolthub.com](https://aidatabase.dolthub.com/) [search excerpt]. The /multiagent subpage returned 404 when fetched.
- dolthub/dolt has 24,787 stars; v2.6.2 shipped 2026-10-31 — [GitHub dolt](https://github.com/dolthub/dolt) [GitHub API, 2026-10-31].
- Business model: a third-party listing says Dolt is Apache-2.0, while DoltHub hosting, DoltLab and Hosted Dolt are commercial offerings — [dev.co listing](https://dev.co/databases/open-source/dolt) [search excerpt].
- None of the sources reviewed claims E2EE for Dolt.

#### git-crypt, git-remote-gcrypt, SOPS
- git-crypt:
  - Encrypts only files marked in `.gitattributes`, using AES-256-CTR with a deterministic synthetic IV.
  - "git-crypt does not encrypt file names, commit messages, symlink targets, gitlinks, or other metadata."
  - "git-crypt does not support revoking access to an encrypted repository which was previously granted."
  - It is not recommended for whole-repo encryption; the README points to git-remote-gcrypt instead.
  - Status: pre-1.0, about 10k stars, v0.8.0 released 2025-09-23/24.
  - Sources: [GitHub AGWA/git-crypt](https://github.com/AGWA/git-crypt); [GitHub API, 2026-10-31].
- git-remote-gcrypt:
  - A GnuPG-based remote helper. Packfiles are encrypted with random keys, and an encrypted, signed manifest holds refs and pack keys. The manifest is re-encrypted on each push to the current participant list.
  - "Every git push effectively has `--force`."
  - The sftp and git-URL backends upload "the entire repository history with each push".
  - "Each pushing user must have the public keys of all collaborators and correct participant config."
  - Maintained by Sean Whitton since 2016; about 1k stars; last push 2026-08-15.
  - Sources: [GitHub spwhitton/git-remote-gcrypt](https://github.com/spwhitton/git-remote-gcrypt); [GitHub API, 2026-10-31].
- SOPS: getsops/sops ("Simple and flexible tool for managing secrets") has 23,576 stars; v3.13.3 shipped 2026-07-23 — [GitHub getsops/sops](https://github.com/getsops/sops) [GitHub API, 2026-10-31]. Mechanism and governance were not re-verified this round.
- None of the three has AI-agent positioning; all are volunteer or community open source with no vendor revenue model found.

#### Syncthing
- syncthing/syncthing ("Open Source Continuous File Synchronization") has 89,944 stars; v2.1.7 shipped 2026-10-21 — [GitHub syncthing](https://github.com/syncthing/syncthing) [GitHub API, 2026-10-31].
- The usage-statistics page data.syncthing.net redirects to mon.syncthing.net, which returned a Grafana load error. No usage numbers were retrieved.
- Business model [search excerpts]:
  - The Syncthing Foundation is a Swedish non-profit that pays for infrastructure from donations — [Syncthing Foundation](https://syncthing.net/foundation/); [Donations](https://syncthing.net/donations).
  - Kastelo provides commercial support and development resources. A developer forum post says donations run "somewhat below hosting costs" and Kastelo covers the difference — [Syncthing forum](https://forum.syncthing.net/t/how-is-the-current-funding-level/8828).
- AI-agent positioning: none found.

#### zrok / OpenZiti (NetFoundry)
- zrok:
  - "zrok provides private or public, instant, secure tunneling of applications from anywhere."
  - Private shares go only to other zrok users, and "all communication is securely and privately transported between zrok clients". The homepage does not explicitly claim E2EE.
  - "Brought to you by NetFoundry and built on OpenZiti". zrok.io is "a public service instance operated by NetFoundry using the same code base that is available to self-hosted environments."
  - No AI or MCP mention on the homepage.
  - Source: [zrok.io](https://zrok.io/).
- openziti/zrok has 4,797 stars (v2.0.9 on 2026-10-31); openziti/ziti has 4,464 stars — [GitHub zrok](https://github.com/openziti/zrok); [GitHub ziti](https://github.com/openziti/ziti) [GitHub API, 2026-10-31].
- NetFoundry press release (dateline 2 Jun 2026, published 3 Jun 2026):
  - Launched MCP and LLM gateways as part of "AI Enclave".
  - Each agent, MCP server and LLM endpoint gets "its own cryptographic identity". Agents are "not given access to any API keys, service accounts or shared secrets". Connections "remain end-to-end encrypted" (vendor claim).
  - The gateways are commercial ("Our commercial MCP and LLM Gateways"), and OpenZiti is open source.
  - Vendor claim: NetFoundry "secures billions of sessions".
  - Source: [NetFoundry press release](https://netfoundry.io/press-release/netfoundry-launches-enterprise-class-mcp-and-llm-gateways-bringing-zero-trust-to-ai-deployments/).
- An OpenZiti post describes ziti-mcp-server, which gives AI agents access to the Ziti Management API — [OpenZiti blog](https://blog.openziti.io/what-is-ziti-mcp-server-openzitis-full-management-api-for-ai-agents) [search excerpt].

#### tsnet (userspace Tailscale)
- "tsnet is a library that lets you embed Tailscale inside a Go program." "tsnet uses a userspace TCP/IP networking stack." Each `tsnet.Server` becomes its own device on the tailnet. The KB page is Go-only — [Tailscale KB, tsnet](https://tailscale.com/kb/1244/tsnet).
- The tailscale/tailscale repo description is "The easiest, most secure way to use WireGuard and 2FA"; it has 38,426 stars and v1.104.4 shipped 2026-10-28 — [GitHub tailscale](https://github.com/tailscale/tailscale) [GitHub API, 2026-10-31].
- Agent positioning (undated page, © 2026; vendor claims) — [Tailscale use case: secure AI agent connectivity](https://tailscale.com/use-cases/secure-ai-agent-connectivity):
  - "The missing network identity layer for AI agents."
  - "every agent has built-in identity and Tailscale embedded directly in its binary."
  - "MCP servers become nodes and authenticated network endpoints."
  - Aperture is "Unified AI governance for AI agents and users."
  - A 2026 Forrester TEI study cites 213% ROI.
- Aperture GA (26 Aug 2026) — [Tailscale blog, Aperture GA](https://tailscale.com/blog/aperture-ga):
  - An AI gateway that started as an LLM proxy so agents don't hold API keys. It now adds cost controls, hooks, guardrails, logging, an MCP and API proxy, and per-project tool permissions.
  - "a clear audit trail, because all of your agent's actions are logged."
  - "Each new Aperture instance comes with some initial tokens included."
  - The post does not state what content is logged or who can read the logs.
- Funding: Series C of about $160M on 8 Apr 2025, led by Accel. The CEO told BetaKit the post-money valuation was $1.45B; other trackers say about $1.5B or about $2B CAD — [BetaKit](https://betakit.com/corporate-vpn-startup-tailscale-secures-230-million-cad-series-c-on-back-of-surprising-growth/) [search excerpt].

#### Holepunch / Pear
- Pear Runtime was announced 13 Feb 2024 as "the first open-source, interoperable peer-to-peer live data protocol". Holepunch built Keet on it and is "Tether-backed". The launch page promises "zero server infrastructure costs, ever", gives no adoption numbers, describes no specific encryption method, and states no revenue model — [pears.com announcement](https://pears.com/news/holepunch-unveils-groundbreaking-open-source-peer-to-peer-app-development-platform-pear-runtime/).
- holepunchto/pear has 439 stars (v3.6.0 on 2026-10-15); holepunchto/hypercore ("a secure, distributed append-only log") has 2,926 stars — [GitHub pear](https://github.com/holepunchto/pear); [GitHub hypercore](https://github.com/holepunchto/hypercore) [GitHub API, 2026-10-31].
- AI angle, Tether's QVAC [secondary; search excerpts]:
  - An open-source SDK for local AI that uses Holepunch P2P for model distribution and delegated inference. Tether's CEO described Keet with QVAC as offering local translation and transcription — [Decrypt](https://decrypt.co/363809/bitcoin-ethereum-metaverse-tokens-sink-further-after-holiday-crypto-rally?amp=1); [Forklog](https://forklog.com/en/tether-unveils-sdk-for-ai-deployment-on-any-device/amp).
  - A Korean blog dates the QVAC SDK release to 9 Apr 2026 (unverified) — [wikidocs](https://wikidocs.net/blog/@jaehong/11186/).

### Inferences
- **Networking competitors are agent-positioned and audit-heavy.** URnetwork's planned port forwarding, TLS edge, auth and audit features overlap with Tailscale (tsnet plus Aperture), NetFoundry (zrok/OpenZiti plus MCP and LLM gateways) and iroh (P2P transport plus hosted relays). All three now sell agent identity, keep secrets away from agents, and log at a gateway. None claims that the gateway cannot see what it logs, so "private networking plus admin audit" is not by itself a differentiator.
- **The storage gap from earlier rounds still holds.** Agent-positioned versioned storage (Dolt) is not E2EE, and E2EE sync (classic Jazz, Automerge with ARK, git-remote-gcrypt) is not agent-positioned or is pre-production.
- **Jazz may be a cautionary signal (unconfirmed).** Its 2026 rewrite into a relational database with server-applied read policies ("unauthorized rows never leave the cloud") and no E2EE mention suggests that a leading E2EE-sync startup chose server-side queries and permissions over client-side encryption for its next product. Garden Computing has not, in what I read, said why.
- **Monetization patterns.** The dominant model is an open-source core plus a hosted relay or sync service (iroh services, Jazz Cloud, zrok.io/NetFoundry, Tailscale SaaS). Alternatives are token-treasury funding (Radicle), patron funding (Holepunch via Tether) and a foundation plus a consulting firm (Syncthing via Kastelo). Only Tailscale shows large venture funding in what I found.

### Gaps
- n0's funding and revenue; Holepunch's revenue; Keet and Pear user counts; Radicle active-user numbers; Syncthing usage numbers (the stats page failed to load).
- SOPS internals and CNCF status were not verified. Syncthing's "untrusted/encrypted device" capability was not examined.
- Jazz 2's E2EE status was not explicitly confirmed or denied by Garden Computing.
- Automerge's funding model; Dolt and Tailscale revenue.

---

## 3. Does any 2026 product offer E2EE, real-time sync with a git-compatible interface for teams, and for agents?

### Takeaway
I found no established product that combines all of these as of 31 Oct 2026. The nearest pieces are scattered:
- Keybase encrypted git: E2EE, teams, git, maintained in 2026, but not real-time and not agent-positioned.
- git-remote-gcrypt and a 2026 prototype, git-remote-e2ee: E2EE git, but push/pull only.
- Classic Jazz and Automerge with ARK: E2EE real-time sync, but not git, and ARK is alpha.
- Radicle: git plus identity, but its private repos are unencrypted and "unfit for use today".
- Dolt: git semantics and agent-positioned, but not E2EE.

A handful of very early agent-memory projects attempt E2EE team sync.

### Cited Findings
- An extended search for E2EE git, real-time sync, teams and agents in 2026 surfaced only early-stage projects [search excerpts; not verified]:
  - A proposal for P2P agent memory sync across machines and teams using iroh and a team content key (repo about 11 days old) — [DevCat issue #12](https://github.com/devileya/DevCat/issues/12).
  - A PR that E2E-encrypts team board, memory and docs; it notes "a removed member keeps what they already received" — [Dispatch PR #167](https://github.com/wsoule/dispatch/pull/167).
  - Per-team-key agent memory sharing at version 0.1.0 — [MemBridge](https://github.com/MembridgeAi/membridge/releases).
  - AES-256-GCM encrypted GitHub sync for agent memory — [ContextGO](https://pypi.org/project/contextgo/0.13.0/).
  - Shared live agent sessions over an E2EE relay that explicitly does not sync the git remote — [AgentsRoom](https://agentsroom.dev/features/remote-fleet).
- git-remote-e2ee (opened):
  - "Git your host can't read." It keeps "file contents and Git metadata (paths, refs, authors, messages) confidential". Update times, sizes and a padded device count remain visible.
  - Each device has its own key with read, write or admin roles. Each push uses a fresh random key wrapped per device. "An administrator can revoke one device without rewriting history", and a revoked device keeps what it already read.
  - Concurrent pushes are resolved by rejecting the loser. It is pull/push only, not real-time, and does not mention AI agents.
  - "Status: prototype", "repository format is unstable"; 1 star, 93 commits.
  - Source: [GitHub combinatrix-ai/git-remote-e2ee](https://github.com/combinatrix-ai/git-remote-e2ee).
- Keybase's encrypted git remains in a maintained client (v6.6.2, 2026-04-08, "Git default branch handling") but is not real-time — [keybase/client releases](https://github.com/keybase/client/releases); [Keybase encrypted git](https://keybase.io/blog/encrypted-git-for-everyone).
- Radicle private repos are "not encrypted at rest" and "unfit for use today" — [Radicle user guide](https://radicle.dev/guides/user).
- ARK (Automerge E2EE) "is still in alpha" — [ARK guide](https://automerge.org/docs/keyhive/ark-api-guide/).
- Dolt markets itself as "the Database for Agents" with branch-per-agent workflows, with no E2EE claim — [DoltHub blog](https://www.dolthub.com/blog/2026-06-05-our-ai-policy/).

### Inferences
- The combination still looks open as of 31 Oct 2026. Three 2026 movements may close it from different sides:
  - E2EE CRDT stacks maturing (Keyhive/ARK; keyhive-wasm 0.6.0 on 2026-10-29).
  - Networking vendors adding agent identity and audit (Tailscale, NetFoundry, iroh).
  - Many small agent-memory projects reinventing team-key E2EE.
- The most defensible positioning is probably not "first E2EE git". Keybase did that in 2017. It is more likely E2EE team memory that works for any agent harness and plugs into existing git tooling, with verifiable claims.

### Gaps
- The search was not exhaustive. Closed-source enterprise products and startups without public repos may exist.
- The early-stage GitHub projects were seen only via search excerpts, except git-remote-e2ee.

---

## 4. Trade-off: E2EE versus server-side search, indexing and LLM processing

### Takeaway
Anything a server must read (search, indexing, spam filtering, LLM summarization) breaks E2EE unless it runs on an endpoint or inside an attested trusted execution environment (TEE). The 2024 to 2026 consensus from academics and from Meta and Signal leadership is to prefer endpoint-local processing; to treat TEEs as weaker but auditable; and to treat agents with broad endpoint access as the new threat to E2EE.

### Cited Findings
- Knodel et al., "How To Think About End-To-End Encryption and AI" (arXiv 2412.20231, Dec 2024; NYU and Cornell) [search excerpt; PDF not opened] — [arXiv](https://arxiv.org/abs/2412.20231); [IACR ePrint 2024/2086](https://eprint.iacr.org/2024/2086):
  - Training shared models on E2EE content is incompatible with E2EE.
  - AI processing of E2EE content may be compatible only if it prioritizes endpoint-local processing.
  - The paper discusses TEEs and FHE, defaults and consent.
- WhatsApp Private Processing (Meta Engineering, 29 Apr 2025) — [Meta Engineering](https://engineering.fb.com/2025/04/29/security/whatsapp-private-processing-ai-tools/):
  - Design: AI requests go to a confidential VM (a TEE) via OHTTP relays with anonymous credentials and RA-TLS attestation. It "does not retain access to messages after the session is completed".
  - Meta concedes that "vulnerability researchers have repeatedly demonstrated the ability to bypass TEE guarantees" and that logs leaving the CVM could leak information.
  - Promised transparency: published CVM binaries, a third-party log of binary digests, source for attestation verification, bug bounty and a white paper. These are described as forthcoming.
- Confer, Moxie Marlinspike's "end-to-end encryption for AI chats", launched around Jan 2026 and relies on a TEE. Reports say Marlinspike announced (March 2026) that Confer's technology would be integrated into Meta AI; not confirmed from a primary source [secondary; search excerpts] — [heise](https://heise.de/-11143673); [SC World](https://www.scworld.com/brief/signal-founder-launches-confer-an-encrypted-ai-chat-alternative).
- Signal president Meredith Whittaker argues that agents with OS-level access bypass E2EE in practice: SXSW, March 2025; an "existential threat" in Fortune, 27 Nov 2025; "perilous" per Bloomberg, 20 Jan 2026 [secondary; search excerpts] — [Fortune](https://fortune.com/2025/11/27/ai-agents-are-an-existential-threat-to-secure-messaging-signals-president-whittaker-says); [Bloomberg](https://www.bloomberg.com/news/articles/2026-01-20/ai-agents-perilous-for-secure-apps-such-as-signal-whittaker); [TechRadar](https://www.techradar.com/pro/security/agentic-ai-has-profound-issues-with-security-and-privacy-signal-president-says).
- Element's E2EE compliance search and export works through a privileged client: "Audit Bot can be configured to write all decrypted events in all rooms to an S3-compatible storage of your choice" — [Element docs, Audit Bot](https://ems-docs.element.io/books/element-cloud-documentation/page/audit-bot).
- New Jazz evaluates permissions server-side ("Jazz applies read policies together with each query, so unauthorized rows never leave the cloud") — [jazz.tools](https://jazz.tools/).
- Tailscale's Aperture logs "all of your agent's actions" at a gateway it runs, and does not state what content is logged — [Tailscale blog](https://tailscale.com/blog/aperture-ga).

### Inferences
- **The sidecar is an endpoint.** By the Knodel framing, local indexing and search inside each member's sidecar is compatible with E2EE.
- **Plaintext leaves the boundary when agents call cloud models.** Once a harness (Claude Code, Codex, Cursor, Copilot) sends sidecar content to a hosted model, that content is outside the E2EE boundary. Any honest claim must say something like "encrypted in storage and between members' devices; agents you run, and the model providers they call, see plaintext." This is the Whittaker critique applied to the sidecar's own users.
- **Server-side team features force a choice.** Cross-team server search, server-side LLM summarization of the shared inbox, and spam or malware scanning would each need either (a) a TEE with published binaries and attestation, which is the Meta and Confer model with its acknowledged TEE weaknesses, or (b) removal of the feature or a move to the endpoints.
- **Email arrives in plaintext.** Inbound email to an "agent inbox" arrives at the receiving mail server as ordinary SMTP. It can only be encrypted after receipt, so an E2EE claim for email would be weaker than for member-to-member content. This is general technical reasoning, not sourced this round; Proton's "zero-access" handling of inbound mail is the analog to check.

### Gaps
- Apple Private Cloud Compute, Google Workspace client-side encryption and Proton Lumo were not examined.
- The Knodel paper was not read in full.
- Confer's technical design was not verified from confer.to.

---

## 5. Trade-off: E2EE versus admin audit and compliance access (Wire, Element/Matrix, Proton for Business, Tresorit, Signal-like tools)

### Takeaway
Credible E2EE products give admins content access only by adding a visible, cryptographically real reader:
- Wire adds a consented legal-hold device.
- Element adds a visible AuditBot member that holds keys.
- Proton escrows non-private users' keys under an admin-held organization key, with an opt-out "private user" status.

Separately, they offer metadata-only activity logs (Tresorit). The cautionary case is TeleMessage. It marketed E2EE "through to the corporate archive", silently shipped plaintext to its own archive server, and was breached in May 2025.

### Cited Findings
- **Wire legal hold** [search excerpts. The docs page docs.wire.com/latest/.../legalhold.html returned 404 and the support article returned 403 when fetched]:
  - Only team admins enable it, and the user must accept.
  - A legal-hold device joins the user's MLS or Proteus client list, so it decrypts like any other device.
  - Other users see a red dot on the held user's profile.
  - Held conversations are retained on the backend.
  - Sources: [Wire developer docs, legal hold](https://docs.wire.com/developer/reference/team/legalhold.html); [Wire support, What is legal hold?](https://support.wire.com/hc/en-us/articles/360002018278-What-is-legal-hold); [Wire blog](https://wire.com/en/blog/balancing-privacy-and-compliance-with-legalhold).
- **Element (Matrix) Audit Bot** — [Element docs, Audit Bot](https://ems-docs.element.io/books/element-cloud-documentation/page/audit-bot):
  - Opened page: "The use of Audit Bot is visible to your users. The service account cannot be hidden." "Audit Bot is able to read encrypted messages to allow you to read or store all messages." "Audit Bot joins all rooms and spaces created by your users." "Audit Bot also joins Direct Message rooms created by your users." "Audit Bot does not join rooms created by users on others servers." "Messages from the past are not exported retrospectively." It is available only on the Element Enterprise Cloud plan.
  - Element marketing says it is an enterprise add-on at about $1 per monthly active user, and that DMs can be excluded. This may conflict with the docs above or be a configuration option — [Element AuditBot PDF](https://static.element.io/pdfs/auditbot.pdf); [Element auditing](https://element.io/server-suite/auditing) [search excerpts].
- **Proton for Business** [search excerpts of Proton support pages; not opened]:
  - "By default, all users are non-private, which means any organization administrator can access their data." Admins cannot read private users' data, and a private user's lost password cannot be admin-reset.
  - The organization key is held only by org admins, so "administrators are able to read the emails of all users of an organization unless the user is explicitly designated as a private user." Proton recommends changing the organization key when an admin leaves.
  - Sources disagree on whether private users can be converted back to non-private.
  - Sources: [Proton: private users](https://proton.me/support/private-users); [Proton: user roles](https://proton.me/support/user-roles); [Proton: organization key](https://proton.me/support/organization-key).
- **Tresorit** [search excerpts; the support article returned 403 when fetched]: by default admins cannot see tresor contents. They can see usage stats, devices, policies and billing; per-tresor activity logs (who accessed what and when) can be exported to CSV — [Tresorit support](https://support.tresorit.com/hc/en-us/articles/216113797); [Tom's Guide review](https://tomsguide.com/reviews/tresorit-review).
- **Signal-like tools: TeleMessage TM SGNL**:
  - Marketing archived on 1 May 2025 promised "End-to-End encryption from the mobile phone through to the corporate archive."
  - Source-code analysis (6 May 2025) found "TM SGNL sends the plaintext, already decrypted versions of chat logs to the archive server", hosted on public AWS. The author wrote: "they designed their archiving system to not be end-to-end encrypted, and that they lie about it."
  - Timeline: 404 Media reported its use by Mike Waltz on 1 May 2025. The hack was reported on 4 May, and TeleMessage suspended service on 5 May after a second breach. The analysis covered Android code only.
  - Source: [Micah Lee](https://micahflee.com/despite-misleading-marketing-israeli-company-telemessage-used-by-trump-officials-can-access-plaintext-chat-logs/).
  - Follow-up reporting covers 410 GB of heap dumps published by DDoSecrets (19 May 2025 update) and a reachable `/management/heapdump` endpoint [search excerpts] — [Micah Lee: hacked](https://micahflee.com/the-signal-clone-the-trump-admin-uses-was-hacked/); [Micah Lee: 20 minutes](https://micahflee.com/how-the-knock-off-signal-app-used-by-trump-officials-got-hacked-in-20-minutes/).
- **Agent-era networking audit is gateway-visible, not E2EE**:
  - Tailscale Aperture: "a clear audit trail, because all of your agent's actions are logged" — [Tailscale blog](https://tailscale.com/blog/aperture-ga).
  - NetFoundry: per-agent cryptographic identities, with "Denied tools are removed from the registry entirely" — [NetFoundry press release](https://netfoundry.io/press-release/netfoundry-launches-enterprise-class-mcp-and-llm-gateways-bringing-zero-trust-to-ai-deployments/).
- **Keybase model**: admins control membership; the server sees "team names, users, and roles" but not content — [Keybase blog](https://keybase.io/blog/introducing-keybase-teams).

### Inferences
- **There are four defensible patterns, and URnetwork should pick explicitly:**
  - (a) A metadata-only audit trail: membership changes, link creation and redemption, device enrollment, commit hashes pushed, by which agent identity. Clients should sign it so the server cannot forge it.
  - (b) Content audit via a visible audit member that is a real, displayed group member (Element).
  - (c) Consented legal hold via an extra device (Wire).
  - (d) Org-key escrow with a "private member" opt-out (Proton).
- **"E2EE plus audit view" is credible if the audit path is visible.** It must be cryptographically explicit and disclosed to members. A server-side or vendor-side plaintext copy described as E2EE is the TeleMessage failure mode and invites the same exposure.
- **Agent gateways that log prompts or tool calls are a separate plaintext tier.** If the sidecar ships an Aperture-like log, its privacy claim must be scoped separately from the storage claim.

### Gaps
- Signal itself offers no admin or eDiscovery features. This is widely known but I did not fetch a primary source this round.
- Wire and Tresorit primary pages could not be loaded (404/403); details rely on search excerpts.
- Element AuditBot pricing comes from a PDF not opened.
- Microsoft Purview, Google Vault with client-side encryption, and Slack EKM were not examined.

---

## 6. Trade-off: real-time CRDT semantics versus git merge semantics

### Takeaway
CRDTs give continuous, automatic convergence, but they resolve conflicts syntactically and expose every keystroke, which the Ink & Switch work calls the "fishbowl effect". Git gives explicit, reviewable units (commits, branches, merges) and surfaces conflicts to humans. The research consensus (Upwelling, Patchwork) is to layer git-like drafts and branches on top of real-time CRDTs. Every E2EE git precedent also shows that mutable refs need serialization: locking (Keybase), reject-the-loser (git-remote-e2ee), or force-push risk (git-remote-gcrypt).

### Cited Findings
- **Upwelling** (Ink & Switch, March 2023) — [Ink & Switch, Upwelling](https://www.inkandswitch.com/upwelling/):
  - Real-time co-editing creates the "fishbowl effect"; "Writers don't want first drafts visible to the editor."
  - "Asynchronous collaboration allows a writer to accumulate a set of proposed changes and share them all in one batch, as opposed to sharing edits keystroke by keystroke."
  - Design: drafts (layers) are real-time among their authors and merge into a linear "stack"; "there should be no dependence between one draft and another".
  - Automerge resolves syntactic conflicts simplistically, so humans must still review semantic conflicts.
  - Limits: "there is no way to excise names or information that may have appeared in earlier drafts". Git itself is hard for writers to adopt.
- **Patchwork** (2024 onward) adds lightweight branches, diff visualization and history views to Automerge-style documents, extended beyond prose ("universal version control") — [Patchwork notebook](https://www.inkandswitch.com/patchwork/notebook/2024-version-control/) [search excerpt].
- **Keybase encrypted git**: a bare repo stored directly in KBFS could cause conflicts, so the helper uses "locking" in git — [Keybase blog](https://keybase.io/blog/encrypted-git-for-everyone).
- **git-remote-gcrypt**: "Every git push effectively has `--force`", and users are advised to pull before pushing; the `gcrypt.require-explicit-force-push` option guards this — [GitHub git-remote-gcrypt](https://github.com/spwhitton/git-remote-gcrypt).
- **git-remote-e2ee**: concurrent pushes are handled by rejecting the loser, with automatic retry planned — [GitHub git-remote-e2ee](https://github.com/combinatrix-ai/git-remote-e2ee).
- **New Jazz**: "eventually consistent by default", with opt-in globally consistent transactions, plus "branches and edit history" — [jazz.tools](https://jazz.tools/).
- **Dolt** (vendor claim): one branch per agent, "merge only what works", with automatic conflict detection — [aidatabase.dolthub.com](https://aidatabase.dolthub.com/) [search excerpt].
- **iroh-docs** is "Multi-dimensional key-value documents with an efficient synchronization protocol", i.e. a key-value sync model, not git — [GitHub iroh-docs](https://github.com/n0-computer/iroh-docs).

### Inferences
- **Real-time sync of git objects should be straightforward; refs are the hard part.** Git's object store is content-addressed and append-only, which behaves like a grow-only set, so syncing it in real time and encrypted should be simple. The difficulty is refs (branch pointers). These need compare-and-swap or locking (the Keybase and git-remote-e2ee approach) or per-writer ref namespaces with explicit merges. This is my reasoning and should be validated.
- **Agents fit git semantics.** Agents produce large, fast, sometimes wrong edits, which is the Dolt branch-per-agent argument and the Upwelling "batch and review" argument. Plausible sidecar semantics: real-time sync of each agent's or member's working branch, with explicit, reviewable merges into shared branches. The audit trail then becomes the commit and merge log.
- **Append-only history conflicts with erasure.** Upwelling's "no way to excise" limitation applies to any signed, append-only E2EE history. Leaked secrets or personal data in shared agent memory would need rewrite tooling and re-encryption.

### Gaps
- No quantitative comparison (latency, storage growth) of CRDT history versus git packs under E2EE was found.
- How Radicle reconciles per-peer refs was not verified this round.

---

## 7. Trade-off: team key management (MLS, key rotation on member removal)

### Takeaway
Across every system examined, removal is forward-only. A removed member loses access to new content after a key rotation or epoch change, but keeps whatever they already decrypted. History is rarely re-encrypted. MLS (RFC 9420, July 2023) is the standard for efficient group key agreement with forward secrecy and post-compromise security up to "thousands" of members. Ink & Switch's BeeKEM adapts TreeKEM to local-first, concurrent settings. Simpler tools (git-crypt) cannot revoke at all, and several new tools lack key recovery.

### Cited Findings
- **MLS (RFC 9420, July 2023)** — [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html):
  - It provides "efficient asynchronous group key establishment with forward secrecy (FS) and post-compromise security (PCS) for groups in size ranging from two to thousands."
  - Removal is a Remove proposal plus a Commit. "This new entropy is added to the epoch secret for the new epoch so that it is not known to the removed member."
  - Access-control policy (who may remove whom) is left to the application.
- **Keyhive** uses BeeKEM, a TreeKEM variant, for local-first E2EE groups of "thousands of members" — [Keyhive notebook](https://www.inkandswitch.com/keyhive/notebook/) [search excerpt]. ARK documents key rotation when a member is added; it offers `revokeMemberFromDoc` but does not document rotation on revoke; and "There is currently no key backup or recovery mechanism" — [ARK guide](https://automerge.org/docs/keyhive/ark-api-guide/).
- **Classic Jazz**: "When someone is removed from a Group, the read key rotates"; "existing data they already had access to remains readable to them" — [classic Jazz docs](https://classic.jazz.tools/docs/react/reference/encryption).
- **Keybase teams**: "rotating keys when Alice later boots Carter"; resetting an account "cryptographically kicks you off all your teams" — [Keybase blog](https://keybase.io/blog/introducing-keybase-teams).
- **git-crypt**: "does not support revoking access to an encrypted repository which was previously granted" — [GitHub git-crypt](https://github.com/AGWA/git-crypt).
- **git-remote-gcrypt**: the manifest is re-encrypted to the current participants on each push, and every pusher must hold all collaborators' public keys. The README does not say whether old packs are re-encrypted — [GitHub git-remote-gcrypt](https://github.com/spwhitton/git-remote-gcrypt).
- **git-remote-e2ee**: a per-push random key is wrapped per device, so "An administrator can revoke one device without rewriting history"; revoked devices keep what they read; losing every key means losing the data; M-of-N admin approval is planned — [GitHub git-remote-e2ee](https://github.com/combinatrix-ai/git-remote-e2ee).
- **Proton**: change the organization key if an admin leaves or is compromised [search excerpt] — [Proton: organization key](https://proton.me/support/organization-key).
- **Wire**: the legal-hold device is added to the user's MLS or Proteus client list, which shows Wire running MLS alongside its older Proteus protocol [search excerpt] — [Wire developer docs](https://docs.wire.com/developer/reference/team/legalhold.html).

### Inferences
- **Share links are bearer capabilities.** The sidecar's "count-limited share links" let anyone holding an unredeemed link join. Each redemption should bind to a device or agent key and enter the group through a signed membership operation (MLS Add/Commit or equivalent). Removal must trigger an epoch change, and the audit trail should record both.
- **Agents complicate membership.** If every agent harness instance is a group member with its own key, which seems the cleanest way to attribute actions, membership churn will be high. MLS or TreeKEM-style log-cost updates matter more than in human-only teams.
- **Recovery and zero knowledge conflict.** Enterprise buyers will ask for key recovery, which ARK and git-remote-e2ee lack. Proton's org-key escrow for non-private users shows what that costs: admins can then read content. That should be a disclosed, per-member setting, not a hidden default.

### Gaps
- Keybase's per-team-key and KBFS lazy rekeying specifics were not retrieved; the sigchain doc does not describe them.
- RFC 9420's detailed FS/PCS analysis (section 16.6) was not read.
- Matrix Megolm rotation behavior was not examined.

---

## 8. Which privacy claims buyers and reviewers scrutinize ("end-to-end encrypted", "zero-knowledge", "customer-held keys"), and what evidence they expect

### Takeaway
In 2020 to 2026, regulators and academics attacked the gap between E2EE or "zero-knowledge" marketing and the actual threat model:
- The FTC acted against Zoom (2020).
- ETH Zurich showed malicious-server attacks on E2EE cloud storage (CCS 2024) and on "zero knowledge" password managers (USENIX Security 2026).
- Source-code review exposed TeleMessage (2025).

Reviewers expect E2EE to hold against a malicious server; open-source clients; independent audits of the full client; disclosure of what metadata leaks; and, for server-side processing, published, attestable binaries.

### Cited Findings
- **FTC vs. Zoom (9 Nov 2020)**: false "end-to-end, 256-bit encryption" claims while Zoom held keys. The settlement bars misrepresentation and requires biennial independent assessments — [FTC](https://www.ftc.gov/news-events/news/press-releases/2020/11/ftc-requires-zoom-enhance-its-security-practices-part-settlement).
- **ETH Zurich, "End-to-End Encrypted Cloud Storage in the Wild: A Broken Ecosystem"** (Hofmann and Truong; ACM CCS 2024; ePrint 2024/1616, Oct 2024) — [IACR ePrint 2024/1616](https://eprint.iacr.org/2024/1616):
  - Analyzed Sync, pCloud, Icedrive, Seafile and Tresorit "in the setting of a malicious server". These companies "cumulatively have over 22 million users". "We unveil severe cryptographic vulnerabilities in four of them."
  - "Our attacks invalidate the marketing claims made by the providers of these systems", including file injection, tampering and "direct access to the content of the files".
  - Tresorit's CEO called "largely broken" an overstatement — [Tresorit blog](https://tresorit.com/blog/addressing-the-state-of-end-to-end-encrypted-cloud-storage-insights-from-tresorits-ceo-2) [search excerpt].
- **ETH Zurich and USI, "Zero Knowledge (About) Encryption: A Comparative Security Analysis of Three Cloud-based Password Managers"** (Scarlata, Torrisi, Backendal, Paterson; USENIX Security 2026; ePrint 2026/058) [search excerpts; not opened] — [USENIX](https://www.usenix.org/conference/usenixsecurity26/presentation/scarlata); [ePrint 2026/058](https://eprint.iacr.org/2026/058):
  - Under a fully malicious server: 12 attacks on Bitwarden, 7 on LastPass and 6 on Dashlane; most allow password recovery.
  - Attack totals differ between the USI release (27) and secondary coverage (25).
- **TeleMessage**: its "End-to-End encryption ... through to the corporate archive" claim was disproven by reading the Android source — [Micah Lee](https://micahflee.com/despite-misleading-marketing-israeli-company-telemessage-used-by-trump-officials-can-access-plaintext-chat-logs/).
- **Privacy Guides cloud-storage criteria**:
  - Minimum: "Must enforce E2EE." Best case: "Clients should be open source." "Clients should be audited in their entirety by an independent third party."
  - The page does not list reproducible builds.
  - Recommended providers: Proton Drive, Tresorit and Peergos. Tresorit stays recommended despite the ETH paper.
  - Source: [Privacy Guides: Cloud storage](https://www.privacyguides.org/en/cloud/).
- **Meta's evidence package for TEE-based "private" AI**: published CVM binary images, a third-party log of binary digests, open-sourced attestation-verification code, bug bounty and a white paper (promised) — [Meta Engineering](https://engineering.fb.com/2025/04/29/security/whatsapp-private-processing-ai-tools/).
- **Self-disclosure examples**:
  - Radicle: "Radicle's codebase hasn't yet undergone formal security audits", and private repos are "unfit for use today" — [Radicle user guide](https://radicle.dev/guides/user).
  - Keybase listed the metadata its servers see — [Keybase blog](https://keybase.io/blog/encrypted-git-for-everyone).
  - git-remote-e2ee lists what the host can still see: times, sizes and a padded device count — [GitHub git-remote-e2ee](https://github.com/combinatrix-ai/git-remote-e2ee).
- **Careful versus broad wording in networking**:
  - zrok says "securely and privately transported between zrok clients" and does not explicitly claim E2EE — [zrok.io](https://zrok.io/).
  - NetFoundry says connections "remain end-to-end encrypted" (vendor claim; in an overlay network this means between overlay endpoints) — [NetFoundry press release](https://netfoundry.io/press-release/netfoundry-launches-enterprise-class-mcp-and-llm-gateways-bringing-zero-trust-to-ai-deployments/).
  - Classic Jazz says "Your data is always encrypted, even on Jazz Cloud servers" without using the term "end-to-end" — [classic Jazz docs](https://classic.jazz.tools/docs/react/reference/encryption).

### Inferences
- **"Zero-knowledge" is now the riskiest term.** The 2026 ETH and USI paper title mocks it. Reviewers test it against a malicious server, including key-distribution, sharing and recovery flows, not just ciphertext at rest. "End-to-end encrypted" is defensible only with a published threat model, a metadata list and an account of how keys are distributed and verified. "Customer-held keys" invites the question of who holds the organization key, which is the Proton non-private-user model.
- **The evidence a new entrant should plan for:**
  - (1) An open-source sidecar, since it is the endpoint.
  - (2) An independent audit of client and protocol before marketing E2EE.
  - (3) A written malicious-server threat model and metadata disclosure.
  - (4) A visible, cryptographically explicit audit-member design rather than a silent archive copy.
  - (5) Reproducible or published builds plus attestation if any TEE processing is offered.
  - Reproducible builds are a plus but not a universal reviewer requirement; Privacy Guides' cloud criteria omit them.
- **The TLS edge must be scoped.** URnetwork's "public TLS edge" must be scoped separately in claims. An edge that terminates TLS sees plaintext for that traffic; only TLS passthrough, i.e. SNI routing to a sidecar holding the certificate key, keeps content end-to-end. This is general technical reasoning, not sourced this round.

### Gaps
- "Customer-held keys" programs (Google Workspace client-side encryption, Microsoft Double Key Encryption, Slack EKM, Zep CMK) were not examined this round.
- Primary sources for reviewer expectations on reproducible builds (e.g., Signal or F-Droid policies) were not fetched.
- The 2026 password-manager paper was not opened, and vendor rebuttals (Bitwarden, Keeper) were not read.
