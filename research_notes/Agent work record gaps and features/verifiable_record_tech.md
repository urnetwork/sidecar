# Verifiable, selectively disclosable and erasable records of AI-agent work: standards, maturity and adoption (as of 31 October 2026)

Source conventions: IETF statuses come from the datatracker JSON (`/doc/<name>/doc.json`) and API, read on 31 Oct 2026. GitHub facts come from the GitHub API or raw files. Claims marked **[search summary]** were seen only in a search engine's summary of the page, not opened directly. Everything else was opened.

## 1. Transparency logs: Rekor v2, Trillian/Tessera, C2SP tlog specs, CT, witnesses, SCITT/SCRAPI

### Takeaway
Tile-based transparency logs are production-grade and a small team can host one in 2026. Tessera reached v1.0 in September 2025, Rekor v2 went GA in October 2025 and has a POSIX build, and Sunlight and the static CT API are used for Certificate Transparency. The IETF SCITT architecture and COSE Receipts became RFCs on 30 June 2026 (RFC 9943 and RFC 9942), and SCRAPI is in the RFC Editor queue. A team can run its own log of hashes and let anyone verify inclusion and append-only consistency without seeing any content. The public witness (cosigning) network is still experimental, with "Production: Not available yet", so independent cosigning today means staging witnesses, witnesses run by customers or auditors, or other anchors.

### Cited Findings
**Sigstore Rekor (v1 and v2)**
- Rekor v2 GA was announced on 10 Oct 2025. The backend moves "to a tile-backed transparency log implementation" built on Tessera, with GCP, AWS, MySQL and POSIX storage. — [Sigstore blog: Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/)
- Each shard has its own URL. The current one is `https://log2025-1.rekor.sigstore.dev`, and clients "MUST NOT hardcode this URL". — [Sigstore blog: Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/)
- Client support:
  - Cosign v2.6.0 added v2 upload and verification; the post recommends "Cosign v3.0.1+ or v2.6.0+".
  - The Go, Python and Java clients are supported.
  - "Support for JavaScript and Ruby will follow."
  - — [Sigstore blog: Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/)
- On witnessing, the GA post says Rekor v2 will integrate "witnessing directly into Rekor... This will be implemented soon." A search turned up no 2026 Sigstore post confirming that it shipped. — [Sigstore blog: Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/); [Sigstore blog index](https://blog.sigstore.dev/)
- Rekor v1 "will continue to run in parallel". Freezing it to new uploads "will be announced one year in advance". — [Sigstore blog: Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/)
- Rekor v1 still gets releases: v1.5.5 shipped on 21 Oct 2026. — [sigstore/rekor releases](https://github.com/sigstore/rekor/releases)
- rekor-tiles (Rekor v2) is at v2.4.1 (30 Oct 2026). Its README lists four binaries:
  - `rekor-server-gcp`
  - `rekor-server-aws`
  - `rekor-server-posix` ("lightweight, no cloud dependencies")
  - `rekor-server-gcpcloudsql`
  - — [sigstore/rekor-tiles](https://github.com/sigstore/rekor-tiles)
- gitsign has a `rekorVersion` setting marked "(Experimental)". Its default is 1, and 2 selects the Rekor v2 / rekor-tiles API. — [sigstore/gitsign README](https://github.com/sigstore/gitsign)

**Trillian and Tessera**
- Tessera describes itself as a "Go library for building tile-based transparency logs (tlogs)". v1.0.0 shipped on 22 Sep 2025 and the latest release is v1.0.4 (16 Jul 2026). — [transparency-dev/tessera releases](https://github.com/transparency-dev/tessera/releases)
- Trillian is still maintained: v1.8.0 shipped on 21 Sep 2026. — [google/trillian releases](https://github.com/google/trillian/releases)

**C2SP tlog specifications**
- The C2SP repository holds these specs: signed-note, tlog-checkpoint, tlog-cosignature, tlog-tiles, tlog-witness, tlog-proof, tlog-policy, tlog-mirror, static-ct-api and mtc-tlog. Each file is an "editor's copy" with a stable reference at c2sp.org. — [C2SP repo](https://github.com/C2SP/C2SP)
- tlog-checkpoint: "A checkpoint is a signed note where the body is precisely formatted for use in transparency log applications." — [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint)
- tlog-tiles: "an efficient HTTP API to fetch the signed checkpoint, Merkle Tree hashes, and entries of a transparency log containing arbitrary entries." — [c2sp.org/tlog-tiles](https://c2sp.org/tlog-tiles)
- tlog-cosignature: "Log clients can verify a quorum of cosignatures to prevent split-view attacks before trusting an inclusion proof." — [c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature)
- tlog-witness: "a synchronous HTTP-based protocol to obtain cosignatures from transparency log witnesses." — [c2sp.org/tlog-witness](https://c2sp.org/tlog-witness)
- tlog-proof: "a textual format for an offline-verifiable proof that some data has been logged to a transparency log and that its inclusion has been observed by some number of witnesses." — [c2sp.org/tlog-proof](https://c2sp.org/tlog-proof)

**Witness / cosigning networks**
- witness-network.org calls itself "a community service that brings logs and witnesses together" and is labelled "experimental / work-in-progress". A community maintainer must approve each log or witness; applicants send their motivation and public key. Witnesses cosign only "if the new log state only contains appended entries." — [witness-network.org](https://witness-network.org/)
- The witness tables say "Production: Not available yet." Staging witnesses are run by:
  - GDB Security
  - Geomys
  - IPng Networks GmbH
  - Markovian Protocol
  - Mullvad VPN AB
  - TrustFabric
  - The tables warn that it "is a work-in-progress service". — [witness-tables.md](https://github.com/transparency-dev/witness-network/blob/main/site/content/witness-tables.md)
- The testing log list is "an experimental list... only meant for dev/testing. Expect breakage." It has 13 logs, including:
  - CT staging logs (`arche2025h1/h2`, `arche2026h1.staging.ct.transparency.dev`);
  - several Sigsum logs, one run by Mullvad;
  - `vindex.gopherwatch.org`;
  - `keyserver.geomys.org`.
  - The staging lists are load-test lists (10 qps / 4k logs and 100 qps / 40k logs). The repo README status is "Work in progress."
  - — [lists/testing/log-list.1](https://github.com/transparency-dev/witness-network/blob/main/lists/testing/log-list.1); [witness-network repo](https://github.com/transparency-dev/witness-network)
- Sigsum is designed to resist an attacker who controls "the signer's secret key and distribution infrastructure", "the public log, including its hosting infrastructure and secret key", and "a threshold of so called witnesses that call out if a log fails." — [sigsum.org](https://www.sigsum.org/)

**Certificate Transparency**
- RFC 6962 (Experimental, 6 Jun 2013) and RFC 9162 CT v2.0 (Experimental, 10 Dec 2021). — [RFC 6962](https://datatracker.ietf.org/doc/rfc6962/); [RFC 9162](https://datatracker.ietf.org/doc/rfc9162/)
- Chrome's CT policy accepted static-ct-api (tiled) logs in a "validation phase" that required at least one SCT from an RFC 6962 log. Chrome said it expected to move to a policy "agnostic to API specification". **[search summary]** — [Chrome ct-policy post](https://groups.google.com/a/chromium.org/g/ct-policy/c/HBFZHG0TCsY/m/HAaVRK6MAAAJ)
- Let's Encrypt wrote in June 2025 that "the major browsers that enforce CT have now permitted Static CT API logs to apply for inclusion". **[search summary]** — [Let's Encrypt: a year of Sunlight](https://letsencrypt.org/2025/06/11/reflections-on-a-year-of-sunlight.html)
- Sunlight, a static-CT implementation, released v0.10.2 on 28 Oct 2026. — [FiloSottile/sunlight](https://github.com/FiloSottile/sunlight)

**SCITT and SCRAPI (IETF)**
- RFC 9943, "An Architecture for Trustworthy and Transparent Digital Supply Chains", was published on 30 Jun 2026 as a Proposed Standard. It defines "an architecture for single-issuer signed statement transparency". — [RFC 9943 (datatracker)](https://datatracker.ietf.org/doc/rfc9943/); [rfc-editor](https://www.rfc-editor.org/rfc/rfc9943.html)
- RFC 9942, COSE Receipts, was published on 30 Jun 2026 as a Proposed Standard. Receipts "prove properties of a Verifiable Data Structure... such as minimal disclosure, transparency, and non-equivocation", and the RFC provides "CBOR encodings for Merkle inclusion and consistency proofs". — [RFC 9942](https://datatracker.ietf.org/doc/rfc9942/)
- RFC 9995, COSE Hash Envelope, was published on 14 Jul 2026 as a Proposed Standard. It marks a payload as a hash output, so "access to the original payload is not required for signature validation". — [RFC 9995](https://datatracker.ietf.org/doc/rfc9995/)
- SCRAPI (draft-ietf-scitt-scrapi-11, 26 Jun 2026) has IESG state "RFC Ed Queue" and RFC Editor state "In Progress". It specifies the "REST API... needed for an interoperable implementation of a SCITT Transparency Service". — [draft-ietf-scitt-scrapi](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/)
- Receipt profiles:
  - draft-ietf-scitt-receipts-ccf-profile-06 (WG draft, 22 Oct 2026);
  - draft-bryce-cose-receipts-mmr-profile-03 (individual draft, 19 Sep 2026). It covers Merkle Mountain Ranges "designed for high throughput, ease of replication and compatibility with commodity cloud storage".
  - — [CCF profile](https://datatracker.ietf.org/doc/draft-ietf-scitt-receipts-ccf-profile/); [MMR profile](https://datatracker.ietf.org/doc/draft-bryce-cose-receipts-mmr-profile/)
- 38 Internet-Drafts with "scitt" in the name were updated in 2026. — [datatracker API query](https://datatracker.ietf.org/api/v1/doc/document/?name__contains=scitt&type=draft&time__gte=2026-01-01)
- IETF 127 runs 14–20 Nov 2026 in San Francisco. The SCITT WG session is on 19 Nov at 00:30 UTC. — [IETF 127 agenda](https://datatracker.ietf.org/meeting/127/agenda)
- Microsoft's Azure Code Transparency client is "based on a managed service that complies with a draft SCITT RFC". It stores COSE envelopes in a Merkle tree, issues signed inclusion proofs as receipts, and its .NET package is still prerelease (1.0.0-beta.12). **[search summary]** — [Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/overview/azure/security.codetransparency-readme?view=azure-dotnet-preview); [NuGet](https://www.nuget.org/packages/Azure.Security.CodeTransparency/1.0.0-beta.12)
- A Microsoft Tech Community snippet says "MST [Microsoft Signing Transparency] now generally available", built "to align with the emerging IETF SCITT standard". I saw no date and could not open the primary post. **[search summary]** — [Tech Community tag page](https://techcommunity.microsoft.com/tag/microsoft%20azure%20attestation)

**Other production transparency logs (precedents)**
- Google's Android Binary Transparency logs are "Append only", "Cryptographically assured" through Merkle trees, and publicly auditable. Google has launched four: Pixel Firmware Transparency, Google System APK Code Transparency, Google Product Application Transparency and Android Mainline Modules Transparency. The page was last updated on 3 Sep 2026. — [Android Binary Transparency overview](https://developers.google.com/android/binary_transparency/overview)
- The Google System APK log is a tile-based Merkle tree whose checkpoint and leaves are published at fixed URLs. **[search summary]** — [Google System APK log details](https://developers.google.com/android/binary_transparency/google1p/log_details)
- Russ Cox's tlog design gives inclusion proofs of length O(lg N) and consistency proofs that an older log is a prefix of the newer one. **[search summary]** — [research.swtch.com/tlog](https://research.swtch.com/tlog)

### Inferences
- **Can a team run its own log?** Yes, and cheaply. Tessera v1.x or `rekor-server-posix` can run next to, or behind, a URnetwork-hosted relay. The log leaves would be hashes (or COSE Hash Envelopes) of signed entries. Clients verify inclusion against a signed checkpoint and verify append-only behaviour with consistency proofs. Neither check needs the content, which stays in the encrypted git store. This is the standard RFC 9162 / C2SP model.
- **Can clients verify without trusting URnetwork?** Only if the log signing key is not held solely by URnetwork, or if independent witnesses cosign the checkpoints. Otherwise URnetwork, as operator, could show different views (equivocate) to different parties. The cosignature spec exists to stop exactly that split view.
  - The C2SP witness protocol is stable and implemented, but the community network has no production tier. A credible v1 would publish checkpoints to staging witnesses and let customers or their auditors run a witness. A third-party Merkle root anchor, such as a public Rekor entry or URnetwork's own on-chain root commitments, would add a further check.
  - A privacy-network company (Mullvad) already operates a staging witness. URnetwork could plausibly operate one as well.
- **Privacy leak of public anchoring.** Even a hash-only checkpoint reveals tree size over time, that is, activity volume and timing. Per-team logs that publish checkpoints in batches on a schedule reduce this.
- **SCITT fit.** RFC 9943 is single-issuer "signed statement transparency". An agent-record entry maps cleanly to a SCITT Signed Statement, and RFC 9942 Receipts give an interoperable proof format. URnetwork does not need to run a public SCITT Transparency Service. Emitting COSE_Sign1 statements with Hash Envelope payloads and RFC 9942 receipts from its own Tessera log would make the record "SCITT-compatible" for export.
- **URnetwork's existing Merkle code is not a drop-in.** It is a sorted-leaf keccak set commitment for EVM verification, described in section 8. An append-only agent log needs RFC 9162-style ordered trees with consistency proofs, which is what Tessera provides.

| Item | Status (31 Oct 2026) | Feature for a private agent record | Agent product use found |
|---|---|---|---|
| Rekor v2 (rekor-tiles) | GA 10 Oct 2025; v2.4.1; witnessing "soon" | Public timestamped anchor for checkpoints or approvals; self-hostable private instance | None for agent records (GitHub uses Sigstore for build attestations, see section 2) |
| Tessera / Trillian | Tessera v1.0 (Sep 2025); Trillian v1.8.0 | The team's own append-only log of entry hashes | None found |
| C2SP tlog-checkpoint/tiles/witness/cosignature/proof | Stable community specs (editor's copies, versioned refs) | Offline-verifiable inclusion proofs; split-view protection | None found |
| Witness network | Experimental; staging only, "Production: Not available yet" | Third-party cosigning of checkpoints | None found |
| CT (RFC 6962/9162, static-ct-api) | Experimental RFCs; static-ct-api logs accepted by browsers | Design precedent only | n/a |
| SCITT RFC 9943, COSE Receipts RFC 9942, Hash Envelope RFC 9995 | RFCs (Jun–Jul 2026) | Standard statement and receipt formats for export | Only individual-draft profiles for agents (sections 6 and 8) |
| SCRAPI | RFC Editor queue | Standard REST API if URnetwork ever runs a Transparency Service | None found |

### Gaps
- I found no 2026 confirmation that Rekor v2's integrated witnessing has shipped.
- I found no date for a production witness-network tier.
- I did not verify the current Chrome CT log policy (whether it is now API-agnostic) on the official policy page.
- The GA status and date of Microsoft Signing Transparency and Azure Code Transparency are unverified; the primary posts were not opened.
- I did not check whether Sigstore's public Rekor usage policy welcomes non-software records, such as hashes of agent-record checkpoints.
- I found nothing on the 2026 status of DataTrails as a commercial SCITT service.

## 2. Signed provenance and attestations (gitsign, SSH signing, bots/agents on GitHub, in-toto, SLSA, trusted publishing, artifact attestations, agent-specific predicates)

### Takeaway
Commit signing (SSH, GPG, S/MIME) is mature on GitHub, and Copilot's cloud agent has signed all its commits, shown as "Verified", since 3 Apr 2026. gitsign gives keyless signatures tied to an OIDC or SPIFFE identity, but GitHub still shows gitsign commits as unverified. The in-toto attestation framework (v1.2.0, March 2026), SLSA v1.2 (with a Source track), npm and PyPI trusted publishing, and GitHub artifact attestations are mature for build provenance. No in-toto predicate for agent sessions or agent changes has been merged. As of 31 Oct 2026 there is a cluster of open PRs and issues, plus one IETF individual draft that defines an in-toto predicate for agent authorization records.

### Cited Findings
**Commit signing**
- GitHub docs: "Using GPG, SSH, or S/MIME, you can sign tags and commits locally. These tags or commits are marked as verified". They also say "SSH signatures are the simplest to generate." — [GitHub Docs: commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
- GitHub stores a persistent verification record with a `verified_at` timestamp. Once a commit is verified it stays verified even if the key is later revoked or expires: "GitHub will not re-verify previously signed commits." — [GitHub Docs: commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
- On bots: "Organizations and GitHub Apps that require commit signing can use bots to sign commits." Verification "will only work if the request is verified and authenticated as the GitHub App or bot and contains no custom author information, custom committer information, and no custom signature information". GitHub signs web-interface commits with its `web-flow` GPG key. — [GitHub Docs: commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
- **gitsign** v0.18.0 shipped on 20 Oct 2026. — [sigstore/gitsign releases](https://github.com/sigstore/gitsign/releases)
- gitsign uses "keyless Sigstore to sign Git commits with your own GitHub / OIDC identity". Its token providers include `device` (headless), `spiffe`, `github-actions`, `google-workload-identity` and `buildkite-agent`. — [gitsign README](https://github.com/sigstore/gitsign)
- gitsign FAQ: "GitHub doesn't recognize Gitsign signatures as verified at the moment". The reasons given are that the Sigstore CA root is not in GitHub's trust root, and that ephemeral certificates need Rekor-based verification. — [gitsign README FAQ](https://github.com/sigstore/gitsign#why-doesnt-github-show-commits-as-verified)

**Agents and signing on GitHub**
- On 3 Apr 2026, GitHub said Copilot cloud agent "now signs every commit it makes". The commits show as Verified, and the agent can now work in repositories with "Require signed commits". The entry does not name the signing key and says nothing about attestations, provenance, session logs or links to session records. — [GitHub changelog, 2026-04-03](https://github.blog/changelog/2026-04-03-copilot-cloud-agent-signs-its-commits/)
- Earlier, Copilot coding agent commits were unsigned and that blocked merges. — [GitHub community discussion #175965](https://github.com/orgs/community/discussions/175965) **[search summary]**
- Claude Code has no native commit signing. Three GitHub issues were closed as "not planned":
  - #7711, "Support commit signing to work with GitHub Vigilant Mode" (closed 13 Jan 2026).
  - #80551, "cryptographic attestation that a git commit (or other action) was taken by a Claude agent" (opened 23 Jul 2026, closed 4 Sep 2026). It states "There is currently no mechanism for Claude Code to sign git commits".
  - #83257, which reports that the Claude Code on the web sandbox "configures SSH commit signing but ships an empty signing key — commits silently unsigned" (closed 7 Sep 2026).
  - — [anthropics/claude-code #7711](https://github.com/anthropics/claude-code/issues/7711); [#80551](https://github.com/anthropics/claude-code/issues/80551); [#83257](https://github.com/anthropics/claude-code/issues/83257)

**in-toto, SLSA, trusted publishing, artifact attestations**
- The in-toto Attestation Framework released v1.2.0 on 18 Mar 2026. — [in-toto/attestation releases](https://github.com/in-toto/attestation/releases)
- The registered predicates are cyclonedx, link, provenance, reference, release, runtime-trace, scai, spdx (and spdx2/spdx3), svr, test-result, vsa and vuln. None is agent-specific. — [in-toto predicates directory](https://github.com/in-toto/attestation/tree/main/spec/predicates)
- slsa.dev/spec presents SLSA **v1.2** with "Status: Approved". It has a **Source Track** (Producing source, Verifying source, Assessing source control systems, Example controls). v1.1 and a Working Draft are also listed, without dates. — [slsa.dev/spec](https://slsa.dev/spec/)
- npm trusted publishing with OIDC went GA on 31 Jul 2025:
  - provenance is published by default;
  - it needs npm CLI v11.5.1+;
  - it works with GitHub Actions and GitLab CI/CD;
  - provenance is not generated for private repositories.
  - **[search summary]** — [GitHub changelog 2025-07-31](https://github.blog/changelog/2025-07-31-npm-trusted-publishing-with-oidc-is-generally-available/); [npm docs: trusted publishers](https://docs.npmjs.com/trusted-publishers)
- PEP 740 (index support for digital attestations) has "Status: Final" (resolution 17 Jul 2024). PyPI documents attestations, including a "PyPI Publish Attestation (v1)". — [PEP 740](https://peps.python.org/pep-0740/); [PyPI docs: attestations](https://docs.pypi.org/attestations/)
- GitHub Artifact Attestations went GA on 25 Jun 2024. — [GitHub changelog](https://github.blog/changelog/2024-06-25-artifact-attestations-is-generally-available/)
- How GitHub Artifact Attestations work:
  - The client "writes out an in-toto statement which binds the subject to a predicate", seals it "in a DSSE signing envelope", and wraps it "as a Sigstore bundle".
  - Public repositories use the Sigstore Public Good Fulcio and land on Rekor.
  - Private repositories use "GitHub's internal instance of Fulcio", and "no information is written to public ledgers or logs".
  - — [GitHub blog: Artifact Attestations](https://github.blog/security/supply-chain-security/introducing-artifact-attestations-now-in-public-beta/)

**2025–2026 work on attestations for AI-agent-produced changes (none merged)**
- in-toto/attestation **PR #588**, "Add AI Agent Action predicate type (v0.1)", was opened on 19 Aug 2026 and is still open. It targets tool invocations "as observed by protocol intermediaries (gateways, proxies, audit sidecars)" and argues that "Application logs are insufficient for auditing because the entity writing the log is the same entity whose behavior needs verification." — [in-toto/attestation#588](https://github.com/in-toto/attestation/pull/588)
- in-toto/attestation **issue #600**, "Proposal: Agentic process evidence" (29 Sep 2026, open), proposes a session- or process-level record keyed to a git commit. Per discussion on #604, it would cover which harness, agent, model and tools ran, plus session logs, policy context and human accountability. — [in-toto/attestation#600](https://github.com/in-toto/attestation/issues/600); [#604](https://github.com/in-toto/attestation/issues/604)
- Other open in-toto proposals:
  - #601, #602 and #603: "AI Change Provenance", "AI Change Authorship" and "AI Change Review" predicates (29 Sep 2026).
  - #604: "AI code-generation provenance with per-range human/AI attribution", the OpenFab Generation Predicate (30 Sep 2026).
  - #554: "agent-decision/v0.1".
  - #609: "Agentic process evidence predicate".
  - #552: "agent-threat-scan".
  - — [in-toto/attestation issues and PRs matching "agent"](https://github.com/in-toto/attestation/pulls?q=agent)
- draft-gilda-audit-agent-audit-record-03 (29 Oct 2026, individual) defines a record format for agent authorization decisions as "one in-toto predicate type, signed inside a DSSE envelope". It is "offered as a data model for the audit records the proposed AUDIT working group would specify". — [draft-gilda-audit-agent-audit-record](https://datatracker.ietf.org/doc/draft-gilda-audit-agent-audit-record/)

### Inferences
- **What this enables for a private agent record.**
  - Each run can end with an in-toto Statement in a DSSE envelope, the same format GitHub Artifact Attestations use. Its subjects would be the git commit or tree digests the run produced. Its predicate would hold the run summary: the record's entry hashes, the approval digests, and the principal and sponsor IDs.
  - The agent principal's key signs the statement, and the record log carries it.
  - Any in-toto or Sigstore verifier can check it without URnetwork's software.
- **Human approvals should be signed by the human's own key.** That can be an SSH key already registered on GitHub (simplest and widely verifiable) or a gitsign/OIDC certificate. "A human approved X" then becomes a signature anyone can check, not a claim made by the sidecar.
- **GitHub "Verified" for agent commits** is currently available only:
  - through GitHub-held keys (Copilot cloud agent, GitHub Apps via API, web-flow);
  - or with GPG/SSH/S/MIME keys uploaded to an account.
  - Per-agent SSH keys on a machine or bot account would show Verified. gitsign keyless signatures would not.
- **The agent-predicate space is fragmented and unmerged.** At least eight in-toto proposals are open, and none is accepted. A small company can credibly help consolidate (for example #588 plus #600) rather than invent another predicate.

| Item | Status | Feature for a private agent record | Agent product use found |
|---|---|---|---|
| SSH/GPG commit signing | GA (GitHub verifies; persistent verification) | Agent principals or human sponsors sign commits | Copilot cloud agent signs (GitHub key); Claude Code does not |
| gitsign | v0.18.0; not "Verified" on GitHub | Keyless signatures bound to OIDC/SPIFFE identity, logged in Rekor | None found |
| in-toto Attestation Framework | v1.2.0 (Mar 2026); no agent predicate merged | Portable per-run attestation | Proposals only (#588, #600, #601–604) |
| SLSA | v1.2 Approved, with Source track | Source-track controls could describe "agent-authored change reviewed by human" | None found |
| npm / PyPI trusted publishing + provenance | GA (npm Jul 2025); PEP 740 Final | Precedent for OIDC-bound, keyless provenance | n/a |
| GitHub Artifact Attestations | GA Jun 2024 | Precedent: private-repo attestations without public logs | Builds only, not agent sessions |

### Gaps
- I could not confirm the dates for SLSA v1.1 and v1.2; slsa.dev/spec gives none.
- I could not find which key signs Copilot cloud agent commits, or whether GitHub links signatures to session logs.
- I found no official statement on commit signing for Codex cloud or Cursor cloud agents.
- I did not open Anthropic's own docs on signing in Claude Code on the web; only the issue reports cite them.
- Whether GitHub plans to verify Sigstore/gitsign signatures is unknown.

## 3. Delegation and agent-identity standards (WIMSE, RFC 8693, RFC 9396, IETF/OpenID AI-agent work, XAA / MCP Enterprise-Managed Authorization, SPIFFE/SPIRE, VC 2.0, SD-JWT VC)

### Takeaway
The delegation primitives are stable RFCs: Token Exchange (RFC 8693, 2020) and Rich Authorization Requests (RFC 9396, 2023). Above them:
- ID-JAG (draft-06) is shipped as Okta Cross App Access and as MCP's stable Enterprise-Managed Authorization extension (2026-07-28).
- OAuth Identity Chaining is in the RFC Editor queue.
- IETF agent-identity work is concentrating in WIMSE. draft-ietf-wimse-aims-00 (Sept 2026) is authored by Defakto, AWS, Zscaler, Ping, OpenAI and Okta.

W3C VC 2.0 is a Recommendation (May 2025), SD-JWT is RFC 9901 (Nov 2025), SD-JWT VC is in IESG Evaluation, and SPIFFE/SPIRE are CNCF graduated. The sidecar should consume these: record delegation-chain evidence and token identifiers in each entry. It should not define its own scheme.

### Cited Findings
**IETF base specs**
- RFC 8693, OAuth 2.0 Token Exchange: Proposed Standard, 15 Jan 2020. — [RFC 8693](https://datatracker.ietf.org/doc/rfc8693/)
- RFC 9396, OAuth 2.0 Rich Authorization Requests: Proposed Standard, 30 May 2023. — [RFC 9396](https://datatracker.ietf.org/doc/rfc9396/)
- RFC 9421, HTTP Message Signatures: Proposed Standard, 14 Feb 2024. — [RFC 9421](https://datatracker.ietf.org/doc/rfc9421/)
- RFC 9420, MLS: Proposed Standard, 18 Jul 2023. — [RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)

**OAuth WG drafts**
- draft-ietf-oauth-identity-chaining-17 (19 Jul 2026) is in the "RFC Ed Queue". — [identity-chaining](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/)
- draft-ietf-oauth-identity-assertion-authz-grant-06 (ID-JAG, 31 Oct 2026) is a WG draft. — [ID-JAG](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)
- draft-ietf-oauth-transaction-tokens-11 (30 Jul 2026) is a WG draft. — [Transaction Tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/)
- draft-ietf-oauth-v2-1-17 (31 Oct 2026). — [OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)

**Agent-specific OAuth drafts (all individual)**
- draft-oauth-transaction-tokens-for-agents-06 (Apr 2026). — [datatracker](https://datatracker.ietf.org/doc/draft-oauth-transaction-tokens-for-agents/)
- draft-mishra-oauth-agent-grants-02 (30 Aug 2026), "OAuth Profile for Delegated AI Agent Authorization". — [datatracker](https://datatracker.ietf.org/doc/draft-mishra-oauth-agent-grants/)
- draft-niyikiza-oauth-attenuating-agent-tokens-02 (27 Oct 2026). — [datatracker](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/)
- draft-chen-oauth-rar-agent-extensions-01 (23 Oct 2026), "Policy, Lifecycle, and Intent Extensions for OAuth Rich Authorization Requests". — [datatracker](https://datatracker.ietf.org/doc/draft-chen-oauth-rar-agent-extensions/)
- draft-mcguinness-oauth-actor-receipts-01 (9 Oct 2026). Each receipt is "a signed JSON Web Token (JWT) attesting which issuer added an actor hop", and receipts form "a hash-linked chain". — [datatracker](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-actor-receipts/)
- draft-oauth-ai-agents-on-behalf-of-user-02 (Aug 2025) has **expired**. — [datatracker](https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/)
- draft-agnihotri-oauth-agent-impl-status-02, "Implementation Status of OAuth Identity Chaining and Transaction Tokens" (Jun 2026). — [datatracker](https://datatracker.ietf.org/doc/draft-agnihotri-oauth-agent-impl-status/)

**WIMSE**
- draft-ietf-wimse-arch-08 (6 Jul 2026) is a WG draft. — [wimse-arch](https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/)
- draft-ietf-wimse-http-signature-08 (Oct 2026) has IESG state "Publication Requested". — [wimse-http-signature](https://datatracker.ietf.org/doc/draft-ietf-wimse-http-signature/)
- Other WIMSE WG drafts:
  - draft-ietf-wimse-workload-creds-03 (30 Oct 2026);
  - draft-ietf-wimse-wpt-02 (27 Aug 2026);
  - draft-ietf-wimse-identifier-04;
  - draft-ietf-wimse-mutual-tls-03;
  - draft-ietf-wimse-workload-identity-practices-08.
  - draft-ietf-wimse-s2s-protocol has been "Replaced" by these.
  - — [WIMSE documents](https://datatracker.ietf.org/wg/wimse/documents/)
- **draft-ietf-wimse-aims-00**, "AI Identity Management System" (15 Sep 2026), replaces draft-klrc-aiagent-auth. Its authors are Kasselman (Defakto), Lombardo (AWS), Rosomakho (Zscaler), Campbell (Ping), Nick Steele (OpenAI) and Parecki (Okta). The abstract says: "Rather than defining new protocols, this document describes how existing and widely deployed standards can be applied or extended". — [draft-ietf-wimse-aims](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/); [replacement relation](https://datatracker.ietf.org/api/v1/doc/relateddocument/?target__name=draft-klrc-aiagent-auth)
- draft-ni-wimse-ai-agent-identity-04 (28 Oct 2026, Huawei and others) discusses "cryptographically binding an AI agent identity to an accountable user or organization". — [datatracker](https://datatracker.ietf.org/doc/draft-ni-wimse-ai-agent-identity/)
- WIMSE meets twice at IETF 127: 18 Nov 22:00 UTC, and 19 Nov 22:00 UTC as a "Joint session with OAUTH". — [IETF 127 agenda](https://datatracker.ietf.org/meeting/127/agenda)

**Other IETF agent groups and draft volume**
- New agent groups:
  - **agentproto** ("Agent Communication Protocols", ART area) is an active WG, with a session on 16 Nov 2026.
  - **dawn** ("Discovery of Agents With Names") is an active WG.
  - The DMSC and CATALIST BoFs have concluded.
  - — [IETF group API](https://datatracker.ietf.org/api/v1/group/group/?name__icontains=agent&format=json); [IETF 127 agenda](https://datatracker.ietf.org/meeting/127/agenda)
- 298 Internet-Drafts with "agent" in the name were updated in 2026. Some are non-AI uses. — [datatracker API query](https://datatracker.ietf.org/api/v1/doc/document/?name__contains=agent&type=draft&time__gte=2026-01-01)
- Web Bot Auth: the IETF **webbotauth** WG adopted draft-ietf-webbotauth-httpsig-protocol-01 (29 Oct 2026), "HTTP Message Signatures for automated traffic". — [datatracker](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/)

**OpenID Foundation and W3C**
- The OpenID Foundation published its whitepaper "Identity Management for Agentic AI" on **7 Oct 2025**. It was written by the Artificial Intelligence Identity Management Community Group. — [OIDF whitepaper post](https://openid.net/new-whitepaper-tackles-ai-agent-identity-challenges/)
- About the AIIM Community Group:
  - It is chaired by Atul Tulshibagwale (CrowdStrike) and Jeff Lombardo (AWS) and is open to the public under a participation agreement.
  - It defers protocol work to OIDF working groups.
  - It responded to NIST's RFI on AI agent security (NIST-2025-0035) in March 2026.
  - **[search summary]** — [AIIM CG](https://openid.net/cg/artificial-intelligence-identity-management-community-group/); [OIDF response to NIST](https://openid.net/oidf-responds-to-nist-on-ai-agent-security/)
- draft-sharif-openid-agent-identity-02 (21 Oct 2026), "OpenID Connect Agent Identity Claims for Autonomous AI Agents", is an individual I-D, not an OIDF specification. — [datatracker](https://datatracker.ietf.org/doc/draft-sharif-openid-agent-identity/)
- W3C proposed an "Agent Identity Registry Protocol Community Group" on 24 Apr 2026. It names OIDF AIIM, the W3C CCG, DIF and IETF WIMSE as coordination partners. **[search summary]** — [W3C CG proposal](https://www.w3.org/community/blog/2026/04/24/proposed-group-agent-identity-registry-protocol-community-group/)

**Cross App Access / MCP Enterprise-Managed Authorization (EMA)**
- The extension identifier is `io.modelcontextprotocol/enterprise-managed-authorization`. Its spec lives at `ext-auth/specification/stable/enterprise-managed-authorization/2026-07-28`. The client exchanges the ID token for an **ID-JAG** from the enterprise IdP, then trades that for an access token from the MCP server's authorization server. One stated use case is "an auditable authorization trail for all MCP server access". — [MCP EMA extension](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization)
- Documented implementers:
  - Okta (Available): issuing is included in Okta SSO, "capped at 250 ID-JAGs per user per resource app per month. Higher volume requires Okta for AI Agents".
  - Ping (PingFederate 13.1+), Descope, Athenz, Janssen (targets draft rev 04) and ThunderID: Available for issuing and accepting.
  - Stytch and AuthPlane: Available for accepting.
  - Keycloak: Experimental (26.7.0, rev 01).
  - Auth0, WorkOS and Scalekit: Early access.
  - Cloudflare `workers-oauth-provider` (experimental) and FastMCP 4.0 (beta) accept ID-JAGs.
  - "Implementations track different draft revisions".
  - — [MCP EMA extension](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization)
- The MCP extension support matrix, as fetched, showed no text entries for Enterprise Auth for any listed client, including Claude Code, VS Code Copilot, Cursor and ChatGPT. The cells may hold icons that did not render, so client support is unverified. — [MCP extension client matrix](https://modelcontextprotocol.io/extensions/client-matrix)

**SPIFFE/SPIRE and credentials**
- "SPIFFE is a graduated project" of the CNCF, and so is SPIRE. — [spiffe/spiffe README](https://github.com/spiffe/spiffe); [spiffe/spire README](https://github.com/spiffe/spire)
- gitsign can obtain signing identity from a `spiffe` token provider. — [gitsign README](https://github.com/sigstore/gitsign)
- W3C Verifiable Credentials Data Model 2.0 became a W3C Recommendation on 15 May 2025, as did VC Data Integrity 1.0. — [VC DM 2.0](https://www.w3.org/TR/vc-data-model-2.0/); [VC Data Integrity](https://www.w3.org/TR/vc-data-integrity/)
- SD-JWT is RFC 9901 (Proposed Standard, 20 Nov 2025). SD-JWT VC (draft-ietf-oauth-sd-jwt-vc-23, 31 Oct 2026) is in "IESG Evaluation". — [RFC 9901](https://datatracker.ietf.org/doc/rfc9901/); [SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
- draft-nandakumar-agent-sd-jwt-02 (3 Sep 2026), "SD Agent: Selective Disclosure for Agent Discovery and Identity Management", is an individual draft. — [datatracker](https://datatracker.ietf.org/doc/draft-nandakumar-agent-sd-jwt/)
- Cloudflare's "signed agents" class uses Web Bot Auth / RFC 9421 signatures. The first cohort includes ChatGPT agent, Goose, Browserbase and Anchor Browser. **[search summary]** — [Cloudflare blog: signed agents](https://blog.cloudflare.com/signed-agents/)

### Inferences
| Item | Status | Feature for a private agent record | Agent product use found |
|---|---|---|---|
| RFC 8693 Token Exchange (`act` chains) | RFC (2020) | Record the actor chain (sponsor → agent → sub-agent) as evidence in each entry | Underlies ID-JAG issuing (Athenz, Descope, Ping) |
| RFC 9396 RAR | RFC (2023) | `authorization_details` as the structured "approved action" object a human signs | No agent product evidence found |
| ID-JAG / XAA / MCP EMA | ID-JAG draft-06; EMA "stable" (2026-07-28); Okta GA | Record which IdP policy decision authorized an MCP server call (ID-JAG `jti`, issuer, subject) | Okta, Ping, Descope and others; client support unverified |
| OAuth Identity Chaining / Transaction Tokens | RFC Ed Queue / WG draft | Cross-domain call chains; transaction IDs to correlate entries | None found |
| WIMSE (arch, creds, http-signature, AIMS) | WG drafts; http-signature "Publication Requested"; AIMS -00 | Per-agent workload credentials, plus a vocabulary for per-agent principals and the "accountable user" | None found in agent products |
| SPIFFE/SPIRE | CNCF graduated | Agent workload identity for keyless signing (gitsign `spiffe`) | None found for coding agents |
| VC 2.0 / SD-JWT VC | W3C Rec / IESG Evaluation | A "delegation credential" from sponsoring human to agent principal, selectively disclosable to a client | None found |
| OIDF AIIM | Whitepaper (Oct 2025); no protocol | Vocabulary and threat model | n/a |

- The sidecar does not need to be an identity provider. Its entries should carry identifiers it can later prove: the sponsor's key fingerprint, the agent principal key, ID-JAG and token `jti`s, and the RAR object hash. An auditor can then tie each entry to an IdP-issued authorization without the sidecar issuing tokens.
- Delegation is the most crowded area: hundreds of 2026 agent drafts, many of them about identity. The major vendors (Okta, Ping, AWS, OpenAI) are writing in WIMSE and OAuth. Contributions from a 1–10 person company are likelier to land as implementation reports or as audit-record requirements (section 8) than as new identity protocols.

### Gaps
- I could not verify which MCP clients (Claude Code, Codex, Cursor, VS Code) implement EMA; the matrix rendered without entries.
- I found no 2026 OIDF AIIM deliverable beyond the NIST response, and none was verified directly.
- I found no adoption data for SD-JWT VC or VC 2.0 in agent delegation.
- I did not open Microsoft Entra Agent ID material here; see the separate positioning notes.

## 4. Selective disclosure and privacy-preserving audit (Merkle proofs, redactable signatures, SD-JWT, BBS, ZK; key transparency, Keybase, binary transparency)

### Takeaway
In 2026 the mature, standard way to "prove a fact without revealing the content" combines two pieces:
- salted-hash commitments inside signed entries, as in SD-JWT (RFC 9901, Nov 2025), with SD-CWT as its CBOR sibling in AD Evaluation;
- Merkle inclusion and consistency proofs (RFC 9162 trees, COSE Receipts RFC 9942).

BBS (CFRG draft-14; W3C BBS cryptosuite still a Candidate Recommendation Draft) and JSON Web Proofs remain drafts. I found no standardized redactable-signature scheme. ZK proofs are practical and audited for narrow credential checks (Google's longfellow-zk), but general ZK proofs over audit logs remain research. Key transparency shows that privacy-preserving third-party audit works at scale: WhatsApp AKD (2023), Apple Contact Key Verification (2023), and Cloudflare as WhatsApp's external auditor since Sept 2024. The IETF KEYTRANS documents are not yet RFCs.

### Cited Findings
**Selective disclosure standards**
- SD-JWT: RFC 9901, Proposed Standard, 20 Nov 2025. — [RFC 9901](https://datatracker.ietf.org/doc/rfc9901/)
- SD-CWT: draft-ietf-spice-sd-cwt-09 (30 Oct 2026), IESG state "AD Evaluation". — [SD-CWT](https://datatracker.ietf.org/doc/draft-ietf-spice-sd-cwt/)
- BBS: draft-irtf-cfrg-bbs-signatures-14 (29 Oct 2026), a CFRG research-group document with intended status Informational. It is not an RFC. — [BBS draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)
- JSON Web Proof: draft-ietf-jose-json-web-proof-14 (20 Jul 2026), a WG draft. — [JWP](https://datatracker.ietf.org/doc/draft-ietf-jose-json-web-proof/)
- W3C "Data Integrity BBS Cryptosuites" is a "W3C Candidate Recommendation Draft 10 September 2026". — [vc-di-bbs](https://www.w3.org/TR/vc-di-bbs/)
- COSE Receipts (RFC 9942) cover Merkle inclusion and consistency proofs and name "minimal disclosure" as a target property. — [RFC 9942](https://datatracker.ietf.org/doc/rfc9942/)

**Agent-specific selective-disclosure profiles (individual drafts)**
- draft-mih-scitt-agent-action-capsule-sel-disc-00 (19 Jun 2026) profiles "salted-hash commitments, decoy digests, and disclosed [salt, name, value] triples". It follows "the SD-JWT selective-disclosure model (RFC 9901)" with JCS canonicalization. — [datatracker](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule-sel-disc/)
- draft-ruvalcaba-nhe-audit-00 (13 Aug 2026, Saluca LLC) describes a "Tamper-Evident, Content-Optional Audit Chain". It has a "prove-without-exposing mode in which a verifier confirms that an event occurred, with the attested metadata, without the event's content being disclosed". — [datatracker](https://datatracker.ietf.org/doc/draft-ruvalcaba-nhe-audit/)
- draft-emirdag-scitt-ai-agent-execution-01 (12 Oct 2026, Veridic Inc.) defines "a redaction receipt mechanism for privacy-preserving evidence custody". It uses "an independent Evidence Custodian as Transparency Service". — [datatracker](https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/)

**Zero-knowledge proofs: practicality**
- Google open-sourced the **longfellow-zk** libraries on 3 Jul 2025 for privacy-preserving age assurance (proving "over 18" without revealing other data). **[search summary]** — [Google blog](https://blog.google/technology/safety-security/opening-up-zero-knowledge-proof-technology-to-promote-privacy-in-age-assurance/)
- The longfellow-zk authors presented at the IETF 124 CFRG session. They reported completed security reviews, including one by Trail of Bits, and said the EU age-verification specification would include the ZKP "as an experimental feature". **[search summary]** — [IETF 124 CFRG slides](https://datatracker.ietf.org/meeting/124/materials/slides-124-cfrg-longfellow-zk-01)
- A 2017 "CT with privacy" paper proves log misbehaviour in zero knowledge, with proofs of about 330 KB, about 5 s to generate and about 3 s to verify; the cost was judged acceptable only because the check is rare. **[search summary]** — [arXiv 1703.02209](https://arxiv.org/pdf/1703.02209)
- An MCP pre-SEP proposed "verifiable tool results (Verifiable MCP) — ZK proofs / TEE attestations attached to `tools/call` results". It was closed on 22 Sep 2026 and moved to working-group discussion. — [MCP issue #3354](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3354)

**Key transparency precedents**
- WhatsApp, 13 Apr 2023: WhatsApp published the open-source Auditable Key Directory (AKD). The server "maintains an append-only AKD of public keys mapped to user accounts" alongside "a publicly available, privacy-preserving audit record for anyone to verify". — [Meta Engineering](https://engineering.fb.com/2023/04/13/security/whatsapp-key-transparency/)
- Cloudflare became WhatsApp's external AKD auditor, announced 24 Sep 2024 and using its Plexi tool. It validates each epoch and publishes signatures. "The proof verification and signatures stored do not contain personally identifiable information". Results are on dash.key-transparency.cloudflare.com. **[search summary]** — [Cloudflare blog](https://blog.cloudflare.com/key-transparency); [Business Wire](https://www.businesswire.com/news/home/20240924561957/en/Cloudflare-Helps-Secure-the-Worlds-Most-Popular-Messaging-Applications)
- Apple iMessage Contact Key Verification (2023) works as follows:
  - KT "uses a verifiable log-backed map data structure", following CONIKS.
  - The map is indexed by a VRF output "to maintain user privacy".
  - It issues "Signed Mutation Timestamps (SMTs), which are auditable promises to make changes to the map".
  - Devices verify log consistency themselves, and Messages "gossips log hashes — by including them in the encrypted part of a small percentage of messages" to detect split views.
  - — [Apple Security blog](https://security.apple.com/blog/imessage-contact-key-verification/)
- IETF KEYTRANS: draft-ietf-keytrans-architecture-10 (7 Oct 2026) is "Waiting for AD Go-Ahead" with intended status Informational. draft-ietf-keytrans-protocol-05 (6 Jul 2026) is a WG draft. KEYTRANS meets at IETF 127 on 18 Nov at 19:30 UTC. — [KT architecture](https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/); [KT protocol](https://datatracker.ietf.org/doc/draft-ietf-keytrans-protocol/); [IETF 127 agenda](https://datatracker.ietf.org/meeting/127/agenda)

**Keybase and binary transparency**
- Keybase: "Every public announcement you make on Keybase is now verifiably signed by Keybase and hashed into the Stellar blockchain." "Since 20 Jan 2020, Keybase has been regularly pushing its Merkle Root into the Stellar blockchain". "Thanks to Stellar, we are unforkable." Keybase previously anchored to Bitcoin. — [Keybase Book: Stellar](https://book.keybase.io/docs/server/stellar); [Keybase Book: Bitcoin](https://book.keybase.io/docs/server/merkle-root-in-bitcoin-blockchain)
- Keybase's merkle/root API returns the root and the server's signature over it. **[search summary]** — [Keybase API](https://keybase.io/docs/api/1.0/call/merkle/root)
- Google Binary Transparency: see section 1. — [Android Binary Transparency](https://developers.google.com/android/binary_transparency/overview)

### Inferences
- **"Prove a human approved an action without revealing content" is buildable from RFC-grade parts.**
  - Each approval entry commits to its fields as SD-JWT-style salted digests: action type, repository, commit hash, approver ID, time, policy and RAR object hash.
  - The approver signs the entry with their own key.
  - The entry's hash sits in the team's Merkle log under a witnessed checkpoint.
  - To prove the approval to a client, the team discloses the chosen fields and salts, the approver signature, the inclusion proof, and the cosigned checkpoint.
  - The client learns "this person approved this commit under this policy at this time, and it was logged before checkpoint N". It learns nothing about the code, beyond the commit hash, which is a commitment and not the code.
- **Hiding the number and shape of fields** needs decoy digests, which SD-JWT and draft-mih both use. Low-entropy fields must be salted; the EDPB likewise rejects unsalted hashes (section 5).
- **Unlinkability across presentations (BBS) is unnecessary** for a team proving facts to its own client. The disclosed record is meant to be attributable, so BBS would be over-engineering here.
- **Key-transparency lessons that transfer:**
  - publish privacy-preserving commitments, not data;
  - let an independent auditor verify each epoch, as Cloudflare does for WhatsApp;
  - verify consistency in the client;
  - gossip or anchor heads to defeat split views, as Apple and Keybase do.
  - A full verifiable map (VRF-indexed, CONIKS/AKD-style) only becomes relevant if URnetwork publishes a directory of agent principal keys that outsiders must look up. That is a later-stage feature.

| Item | Status | Feature for a private agent record | Agent product use found |
|---|---|---|---|
| Merkle inclusion/consistency (RFC 9162; COSE Receipts) | RFCs | Prove an entry exists and the log is append-only without revealing other entries | None found |
| SD-JWT (RFC 9901) / SD-CWT | RFC / AD Evaluation | Per-field disclosure of approvals and metadata | Individual agent drafts only |
| BBS / JWP | CFRG draft-14 / JOSE draft-14; W3C CRD | Unlinkable, multi-show disclosure | None |
| Redactable signatures | No standard found | Redact parts of a signed entry | None |
| ZK over logs | Research; longfellow-zk practical for credentials only | Prove predicates, e.g. "every deploy had an approval", without disclosure | MCP pre-SEP only (closed) |
| Key transparency (AKD, CKV, KEYTRANS) | Deployed at scale; KEYTRANS not RFC | Third-party auditor model; agent key directory | n/a |

### Gaps
- I found no production deployment of ZK proofs over audit logs, and no 2026 benchmarks for log-predicate ZK.
- I did not assess redactable-signature libraries; I found no IETF or W3C work item for them.
- The KEYTRANS RFC timeline is unknown.
- The Cloudflare and Plexi details are from search summaries.

## 5. Erasure with intact tamper-evidence (crypto-shredding, GDPR/EDPB/ICO, pitfalls)

### Takeaway
The EDPB's final blockchain guidelines (Guidelines 02/2025, **version 2.0, adopted 7 July 2026**) describe three ways to keep an integrity structure intact while allowing erasure:
- delete the decryption key;
- delete the secret key or salt behind a keyed or salted hash;
- delete the data and witness behind a "perfectly hiding" commitment.

The EDPB does not treat crypto-shredding as equal to deletion. Encrypted data "is still personal data", hashes count as personal data until the salt or key is gone, encryption is "overtaken by time", and erasure must be designed in and "effective". I found no regulator text that simply "accepts crypto-shredding as erasure". For the sidecar, the defensible design is a hash chain or Merkle log over **salted commitments** (or over ciphertext). Each entry gets its own content key and salt, stored only with the content. Deleting both leaves digests that still verify the chain but can no longer be linked to the person.

### Cited Findings
**EDPB Guidelines 02/2025 on blockchain**
- Version 2.0 was adopted on 7 Jul 2026. Version 1.1, adopted 8 Apr 2025, was the consultation draft. The EDPB also published a track-changes file and a consultation report. — [EDPB Guidelines 02/2025 v2.0 (PDF)](https://www.edpb.europa.eu/system/files/2026-07/edpb_guidelines_202502_blockchain_v2_en.pdf); [EDPB consultation page](https://www.edpb.europa.eu/our-work-tools/documents/public-consultations/2025/guidelines-022025-processing-personal-data_en)
- The passages below appear in both v1.1 and v2.0. I checked the v2.0 text.
- On encryption: "upon deletion of this decryption key, the encrypted data will be unintelligible, at least until the algorithm is broken, the decryption techniques advance sufficiently... or if the key had already been compromised or leaked." "The EDPB recalls that encrypted personal data is still personal data and encryption does not remove the need for GDPR compliance." "even state-of-the-art encryption perfectly implemented will be overtaken by time if the blockchain is retained indefinitely." — [EDPB v2.0](https://www.edpb.europa.eu/system/files/2026-07/edpb_guidelines_202502_blockchain_v2_en.pdf)
- On salted or keyed hashes: "the hash will also be considered personal data". "after deletion of the secret key or salt, the hash should not be linkable to the original data, provided that the algorithm has not been broken, the keys have not been compromised or leaked, and the salt was not leaked or poorly chosen." "the use of unsalted or unkeyed hashes should, in general, not be considered sufficient". — [EDPB v2.0](https://www.edpb.europa.eu/system/files/2026-07/edpb_guidelines_202502_blockchain_v2_en.pdf)
- On commitments: "If the commitment has been computed using a perfectly hiding state-of-the art scheme, then once the original data and its witness are deleted, the commitment persisting in the blockchain is useless. It will be neither possible to recover nor to recognise the original personal data." — [EDPB v2.0](https://www.edpb.europa.eu/system/files/2026-07/edpb_guidelines_202502_blockchain_v2_en.pdf)
- On integrity after erasure: when off-chain data is modified so subjects are no longer identifiable, the "'anonymised transaction' would have lost all its semantics, but still exists to allow the verification of integrity for other, remaining transactions." — [EDPB v2.0](https://www.edpb.europa.eu/system/files/2026-07/edpb_guidelines_202502_blockchain_v2_en.pdf)
- General principles:
  - "technical impossibility cannot be invoked to justify non-compliance".
  - "Whichever approach to storage limitation is chosen, it must be effective."
  - "Deletion requires governance and traceability measures" (citing GDPR Recital 66 and the AEPD technical note).
  - "the EDPB recommends looking at other tools if the strong integrity property of blockchains is not needed."
  - — [EDPB v2.0](https://www.edpb.europa.eu/system/files/2026-07/edpb_guidelines_202502_blockchain_v2_en.pdf)
- The EDPB recommends storing data "in a form which is primarily intended to function as a proof of existence (e.g. by use of a pointer, a cryptographic commitment or a hash generated from a keyed hash function...)" with the data needed to verify the proof kept off-chain. — [EDPB v2.0](https://www.edpb.europa.eu/system/files/2026-07/edpb_guidelines_202502_blockchain_v2_en.pdf)
- The EDPB cites the Spanish DPA's technical note "Proof of concept Blockchain and the right to erasure". — [AEPD technical note (PDF)](https://www.aepd.es/guias/Tech-note-blockchain.pdf)

**Other regulators**
- ICO: secondary commentary says the ICO accepts backups that cannot be overwritten immediately if the data is put "beyond use". I did not open the ICO's backup-specific text. **[search summary]** — [ICO right to erasure](https://ico.org.uk/for-organisations/guide-to-dp/guide-to-the-uk-gdpr/individual-rights/right-to-erasure)
- A law-firm summary reports that the Danish DPA requires deletion from backups where technically possible and that the CNIL does not require backup deletion. **[search summary, unverified]** — [Hall Booth Smith](https://hallboothsmith.com/?p=11767)
- A secondary blog says the EDPB published a coordinated-enforcement report on erasure in Feb 2026. **[search summary, unverified]**

**Engineering practice and pitfalls**
- Crypto-shredding is a known event-sourcing pattern: encrypt personal data under per-subject keys and "throw away the key". — [Verraes, 2019](https://verraes.net/2019/05/eventsourcing-patterns-throw-away-the-key/)
- Vendors warn that erasure holds only if the key is destroyed and "there is no copy of it", so backups, replicas and escrow must be covered. KEK/DEK wrapping is the common structure, and the ciphertext still occupies storage. **[search summary]** — [Seald](https://prod.discovery.seald.io/blog/data-destruction-using-crypto-shredding); [Conduktor](https://conduktor.io/blog/gdpr-kafka-right-to-erasure); [AxonIQ](https://www.axoniq.io/blog/protect-sensitive-data-in-an-event-sourced-application)
- Forum commentary says some practitioners consider crypto-shredding "insufficient in Germany". This is anecdotal. **[search summary]** — [AxonIQ forum](https://discuss.axoniq.io/t/crypto-shredding-and-gdpr-with-axon-framework/5987)
- Agent-record drafts already target this property:
  - draft-ruvalcaba-nhe-audit-00: "Content storage is optional and its retention is configurable independently of the chain, so content may be redacted without destroying the chain's integrity". — [datatracker](https://datatracker.ietf.org/doc/draft-ruvalcaba-nhe-audit/)
  - draft-emirdag-scitt-ai-agent-execution-01 defines "redaction receipts". — [datatracker](https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/)
- Product practice: Tailscale Aperture lets customers "reduce your capture log retention all the way down to zero" and "export logs to S3-compatible storage". Admin viewing of other users' logs is itself recorded. — [Tailscale blog, 30 Jun 2026](https://tailscale.com/blog/aperture-audit-AI-agents)

### Inferences
**A design that matches the EDPB's three patterns**
1. Each record entry stores only:
   - metadata;
   - a commitment `C = H(salt ‖ canonical(content))` with a 256-bit random salt, or a hash of the ciphertext;
   - a pointer into the encrypted git store.
2. Each content blob is encrypted under its own data key (DEK). The DEK and the salt are stored only inside the encrypted blob's envelope, wrapped by the MLS-derived group key. They are never stored in the log.
3. Erasure works like this:
   - delete the DEK and salt everywhere, including caches, every member device and the audit member or escrow copy;
   - optionally delete the ciphertext;
   - append an "erasure" entry that references the erased entry's ID and the legal basis, which gives the governance and traceability trail the EDPB asks for.
   - The chain and the Merkle proofs still verify, because they cover `C`, which no longer links to anything.

**Pitfalls**
- **Hashing plaintext** of short or guessable content, such as approval text, file paths or emails, is reversible by brute force. Always salt or key. The EDPB says unsalted hashes are insufficient.
- **Metadata is personal data too.** Approver identity, timestamps and repository names can identify a person. Prefer pseudonymous principal IDs that resolve through an erasable directory entry.
- **Key copies.** MLS group secrets, per-device caches, backups and a disclosed escrow or "visible audit member" all hold key material. A shred is complete only if every holder deletes. That is hard to prove, so the record should log the escrow holder's acknowledgment of the shred.
- **Git semantics.** Git objects persist in packfiles, reflogs, clones and forks. Per-entry DEKs avoid history rewrites: the encrypted blob may remain, but it becomes unintelligible. The EDPB still treats that as personal data until it is unintelligible "at least until the algorithm is broken", so deleting the ciphertext where feasible is better.
- **Public anchors.** Witnessed or public checkpoints contain only tree heads (hashes of hashes). They are far from personal data, but the EDPB's caution about hashes means the leaf commitments must be salted.
- **Legal positioning.** No regulator text found says crypto-shredding equals erasure. The defensible claim is "erasure by deletion of keys and salts, designed to the EDPB's commitment/salted-hash pattern", backed by counsel, not "GDPR-certified erasure".

### Gaps
- I did not open the ICO's text on "beyond use" or encryption keys.
- I found no explicit DPA decision accepting or rejecting crypto-shredding.
- I did not verify the EDPB's Feb 2026 coordinated-enforcement report on erasure.
- I did not review the v2.0 track changes in full. I spot-checked that the key passages persist, but the 5.2 numbering and footnotes differ between versions.

## 6. Telemetry and record formats (OpenTelemetry GenAI, harness telemetry, Agent Trace, AAIF and IETF work, MCP 2026-07-28)

### Takeaway
- The OpenTelemetry GenAI conventions are all still "Development". That includes agent spans and MCP spans. In May 2026 they moved to a separate `semantic-conventions-genai` repo, which had no tagged release by 31 Oct 2026.
- Claude Code, Codex and Cursor all export OpenTelemetry, but mostly under vendor names (`claude_code.*`, `cursor.*`). Content export is redacted or opt-in, and none offers integrity protection. Only Claude Code exports traces (beta), and Cursor says it "doesn't send traces".
- Agent Trace is a v0.1.0 "RFC" (January 2026) with no signatures, and its canonical GitHub repo returns 404.
- I found no AAIF activity-log format.
- The MCP 2026-07-28 revision deprecated MCP's Logging feature in favour of stderr and OpenTelemetry, and documented trace-context propagation. It added nothing on audit or provenance, and maintainers redirected receipt proposals to working groups.
- The real standards activity on agent audit records is at the IETF. An **AUDIT BoF** (WG-forming) meets at IETF 127 on 17 Nov 2026. Its inputs include a CDDL/COSE "Verifiable Agent Conversation Records" draft and a vCon agent-session profile.

### Cited Findings
**OpenTelemetry GenAI semantic conventions**
- The GenAI pages in the main semantic-conventions repo now read "Moved: Generative AI semantic conventions" and point to `open-telemetry/semantic-conventions-genai`. The main repo's latest release is v1.44.0 (4 Aug 2026). — [semconv gen-ai agent spans (moved notice)](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/gen-ai/gen-ai-agent-spans.md); [semconv releases](https://github.com/open-telemetry/semantic-conventions/releases)
- `semantic-conventions-genai` was created on 5 May 2026 and has no GitHub releases. Its CHANGELOG has only an "Unreleased" section. — [semantic-conventions-genai](https://github.com/open-telemetry/semantic-conventions-genai); [CHANGELOG](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/CHANGELOG.md)
- "Semantic Conventions for GenAI agent and framework spans" has **Status: Development**. It defines `create_agent` and `invoke_agent` spans and attributes such as `gen_ai.agent.id`, `gen_ai.agent.name` and `gen_ai.agent.version`, all Development. — [gen-ai-agent-spans.md](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md)
- The MCP semantic conventions also have **Status: Development**. Attributes include `mcp.method.name`, `mcp.session.id`, `mcp.protocol.version` and `mcp.resource.uri`. "MCP tool call execution spans are compatible with GenAI execute_tool spans." — [mcp.md](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/mcp.md)
- Open work in the GenAI repo:
  - #437, "MCP: align semantic conventions with protocol 2026-07-28" (5 Aug 2026).
  - PR #291, "add agent authorization observability attributes" (15 Jun 2026).
  - PR #445, agent lifecycle events for async and long-running executions.
  - PR #650, trigger type and event attributes.
  - — [#437](https://github.com/open-telemetry/semantic-conventions-genai/issues/437); [#291](https://github.com/open-telemetry/semantic-conventions-genai/pull/291); [#445](https://github.com/open-telemetry/semantic-conventions-genai/pull/445); [#650](https://github.com/open-telemetry/semantic-conventions-genai/pull/650)

**Harness telemetry**
- Claude Code:
  - It exports metrics, logs/events and traces. Traces are beta and "off by default", enabled with `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1`.
  - Names are `claude_code.*`. Some span attributes follow GenAI conventions (`gen_ai.system`, `gen_ai.request.model`, `gen_ai.response.id`, `gen_ai.tool.call.id`).
  - The `claude_code.tool_decision` event records `decision` (accept or reject) and a `source`: config, hook, user_permanent, user_temporary, user_abort or user_reject.
  - Prompts, responses and tool details are redacted unless opted in (`OTEL_LOG_USER_PROMPTS`, `OTEL_LOG_TOOL_DETAILS` and others).
  - I read only the first 100k characters of the page.
  - — [Claude Code monitoring docs](https://code.claude.com/docs/en/monitoring-usage)
- Codex added OpenTelemetry **log events** in PR #2103, merged 29 Sep 2025. They cover "outbound API requests, streamed responses, user input, tool-approval decisions, and the result of every tool invocation. Export is disabled by default". — [openai/codex PR #2103](https://github.com/openai/codex/pull/2103)
- Codex's `log_user_prompt` defaults to false, and a trace exporter is configurable under `[otel]`. **[search summary, third-party guides]** — [OneUptime guide](https://oneuptime.com/docs/en/telemetry/openai-codex); [Daniel Vaughan blog](https://codex.danielvaughan.com/2026/04/16/codex-cli-opentelemetry-observability-tracing-agent-sessions/)
- Cursor:
  - "OpenTelemetry Export is available on the Enterprise plan". It covers metrics and logs only: "Cursor doesn't send traces".
  - Names are `cursor.*`, with scope `cursor.telemetry` 0.1.0.
  - Conversation content is off by default. When enabled, it covers only Cloud Agents and Grok Bot.
  - Logs are delivered "at-least-once", so consumers should dedupe on `cursor.event.id`.
  - It has no signing or integrity features.
  - — [Cursor OTel export docs](https://cursor.com/docs/enterprise/opentelemetry-export)

**Agent Trace and git-native formats**
- Agent Trace:
  - It is "an open specification for tracking AI-generated code", **version 0.1.0, status RFC, January 2026**.
  - Contributors listed: Amp, Amplitude, Cline, Cloudflare, Cognition, git-ai, Jules, OpenCode, Tapes and Vercel. These are contributors, not confirmed adopters.
  - Ranges can carry a `content_hash` "for position-independent tracking".
  - It defines no signatures, and storage is "implementation-defined".
  - — [agent-trace.dev](https://agent-trace.dev/)
- The canonical repo, `github.com/cursor/agent-trace`, returns HTTP 404 from the GitHub API on 31 Oct 2026. — [GitHub API: cursor/agent-trace](https://api.github.com/repos/cursor/agent-trace)
- git-ai uses the "Git AI standard" v3.0.0 in Git Notes. Its "Attestation Section" maps line ranges to sessions using hash-derived keys, such as `"h_" + SHA256("<author_identity>")[0..14]`. The spec defines no cryptographic signatures. — [Git AI standard v3.0.0](https://github.com/git-ai-project/git-ai/blob/main/specs/git_ai_standard_v3.0.0.md); [git-ai README](https://github.com/git-ai-project/git-ai)

**Linux Foundation / AAIF**
- The Agentic AI Foundation launched on 9 Dec 2025 with MCP, goose and AGENTS.md. agentgateway reportedly became a hosted project in June 2026 and A2A in August 2026. I found no AAIF agent activity-log format; agentgateway advertises metrics, tracing and access logging. **[search summary]** — [The Register](https://www.theregister.com/2025/12/09/linux_foundation_agentic_ai_foundation/); [aaif.io](https://aaif.io/)
- AGNTCY, a separate Linux Foundation project, has an "Observability & Evaluation" working group. **[search summary]** — [Linux Foundation: AGNTCY](https://www.linuxfoundation.org/press/linux-foundation-welcomes-the-agntcy-project-to-standardize-open-multi-agent-system-infrastructure-and-break-down-ai-agent-silos)

**MCP 2026-07-28**
- The 2026-07-28 spec was released on 28 Jul 2026; its RC was on 29 May 2026. — [modelcontextprotocol releases](https://github.com/modelcontextprotocol/modelcontextprotocol/releases)
- Changelog items relevant to a record:
  - It deprecates "the Roots, Sampling, and Logging features (SEP-2577)" and advises: "log to `stderr` (stdio) or use OpenTelemetry instead of Logging".
  - It documents "OpenTelemetry trace context propagation conventions for `_meta` keys (`traceparent`, `tracestate`, `baggage`)" (SEP-414).
  - MCP is now stateless. "Clients SHOULD identify themselves on each request (`io.modelcontextprotocol/clientInfo`), and servers SHOULD identify themselves in each result's `_meta`" (SEP-2575).
  - Protocol-level sessions and `Mcp-Session-Id` are removed (SEP-2567).
  - It adds an `extensions` capability field.
  - No audit, provenance or signing item appears.
  - — [MCP 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- Proposals in the MCP repo:
  - "[Proposal] Verifiable tamper evident receipts for tool calls" (#3471) was closed on 31 Oct 2026. A maintainer replied: "Please start with relevant working and interest groups in Discord before opening a SEP".
  - The ZK/TEE "Verifiable MCP" pre-SEP (#3354) was closed and moved to a working group.
  - "SEP-2624: Interceptors" is open (22 Apr 2026). It defines a primitive so context operations can be "intercepted, validated, and transformed" and cites "a sprawling landscape of sidecars, proxies".
  - "SEP: Mandatory tool definition integrity" (#3452) and "SEP-1766: Digest-Pinned Tool Versioning" were closed.
  - — [#3471](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3471); [#3354](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3354); [SEP-2624](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2624); [#3452](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3452); [SEP-1766](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1766)

**IETF agent audit and record formats**
- The **AUDIT BoF** ("Agent Use of Delegation and Interaction Traceability") is in the Security Area. The AD is Christopher Inacio, the group is "Not chartered yet", and the list is audit@ietf.org. — [IETF AUDIT group](https://datatracker.ietf.org/group/audit/about/)
- The BoF session is on **17 Nov 2026 at 17:00 UTC** (90 minutes) at IETF 127 in San Francisco. — [IETF 127 agenda](https://datatracker.ietf.org/meeting/127/agenda)
- The BoF request is marked "WG forming". Its scope:
  - "An architectural concept"; "Common data models for audit records"; "Propagation of audit context across interactions (user, agents, subagents, tools)".
  - Integration with OAuth, HTTP, and attestation and transparency frameworks.
  - Profiles for RATS and SCITT, an HTTP context header, OAuth token context, and a profile of vCon's Verifiable Agent Conversation Records.
  - Out of scope: auditing the model, its training data or inference.
  - Proponents: Mirja Kühlewind (Ericsson, editor), Henk Birkholz and Pam Dingle (Microsoft). Proposed chair: Yaroslav Rosomakho.
  - It references a side meeting at IETF 126.
  - — [AUDIT BoF request](https://datatracker.ietf.org/doc/bofreq-kuhlewind-audit-agent-use-of-delegation-and-interaction-traceability/)
- draft-kuehlewind-audit-architecture-01 (7 Sep 2026; Kühlewind and Birkholz) covers "distributed audit record generation, propagation of audit context, optional attestation, and additional logging for transparency". — [datatracker](https://datatracker.ietf.org/doc/draft-kuehlewind-audit-architecture/)
- draft-birkholz-verifiable-agent-conversations-01 (31 Aug 2026; Birkholz, Heldt and Orie Steele):
  - It defines "a data format for verifiable agent conversation records using CDDL, with representations in both JSON and CBOR".
  - It covers "session metadata, message exchanges, tool invocations, reasoning traces, and system events".
  - "COSE is used as the signing method to allow for native interoperability in SCITT Transparency Services".
  - — [datatracker](https://datatracker.ietf.org/doc/draft-birkholz-verifiable-agent-conversations/)
- draft-howe-vcon-agent-session-00 (20 May 2026) is a vCon "agent_session" extension. It carries "prompts, tool invocations, tool results, reasoning, and file or artifact provenance", with the trace conforming to the VAC CDDL. — [datatracker](https://datatracker.ietf.org/doc/draft-howe-vcon-agent-session/)
- draft-sharif-agent-audit-trail-09 (26 Oct 2026) is a JSON logging format "linked via tamper-evident hash chaining using SHA-256 per RFC 8785, with optional ECDSA signatures". It maps to the EU AI Act, "whose application dates were staged into 2027-2028 by Regulation (EU) 2026/1744". — [datatracker](https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/)
- Draft volume: in 2026, 42 Internet-Drafts with "receipt" in the name and 15 with "audit" in the name were updated. Many are agent-related; examples include draft-sahu-agent-action-receipts ("Signed, Hash-Chained Action Receipts for AI Agents") and draft-noa-scitt-ai-agent-receipt. — [datatracker API: receipt](https://datatracker.ietf.org/api/v1/doc/document/?name__contains=receipt&type=draft&time__gte=2026-01-01); [datatracker API: audit](https://datatracker.ietf.org/api/v1/doc/document/?name__contains=audit&type=draft&time__gte=2026-01-01)

### Inferences
- **OpenTelemetry is an export channel, not the record of truth.** It has no integrity or signing, delivery is at-least-once or at-most-once, and content is redacted by default.
  - The sidecar should emit GenAI-compatible attribute names where they exist (`gen_ai.agent.id`, `gen_ai.tool.name`, `mcp.method.name`). That makes its entries joinable with harness telemetry.
  - It should also propagate `traceparent` through MCP `_meta`, as SEP-414 provides, so each entry links to the harness trace.
- **MCP 2026-07-28 helps a stdio sidecar's record.** Per-request `clientInfo` gives harness identity on every call. Deprecating MCP Logging pushes logs towards OpenTelemetry, which a verifiable record can complement but not replace. Removing `Mcp-Session-Id` means the sidecar must define its own run and session IDs.
- **Agent Trace is a weak base:** v0.1.0, no signatures, and the repo is unavailable. The IETF Birkholz/Steele VACR format (CDDL, JSON/CBOR, COSE, SCITT-ready) is the likeliest future interop target, because the AUDIT BoF plans to profile it.
- **No harness signs its telemetry or transcripts.** A signed, chained record therefore fills a real gap, but URnetwork must ingest data the harness gives it. Hooks and the MCP traffic the sidecar observes are the evidence sources.

### Gaps
- I could not open Codex's official observability docs on developers.openai.com. Trace-export details come from third-party guides.
- No timeline exists for GenAI conventions reaching Stable.
- I found no AAIF working group on activity logs, and the AGNTCY observability schema was not examined.
- MCP Security and Enterprise interest-group agendas are on Discord and were not examined.
- I read only part of the Claude Code monitoring page (100k of 173k characters).

## 7. Current use: do agent products sign, attest, or make records third-party verifiable?

### Takeaway
None of the agent products I checked makes its record of agent work verifiable by a third party through signatures over the session record, a transparency log or witnesses.
- **GitHub comes closest on signing.** Copilot cloud agent commits have been signed and Verified since 3 Apr 2026, and GitHub runs Sigstore-based artifact attestations, but for builds, not agent sessions.
- **Microsoft has the richest agent audit schema.** Purview records carry AgentId, accessed resources and model details. Microsoft separately runs a SCITT-aligned signing-transparency ledger for software, but I found no evidence that the two are connected.
- Claude Code declined native commit signing and attestation requests.
- Cursor and Codex export OpenTelemetry without integrity.
- Entire and git-ai keep records in git without cryptographic signatures.
- Tailscale Aperture and Coder offer audit logs without described tamper-evidence.
- Cloudflare signs agent identity on HTTP requests, which is not a record.

The designs closest to URnetwork's are not products. They are IETF individual drafts, such as a "content-optional audit chain", and an open in-toto PR aimed at "audit sidecars".

### Cited Findings
- **GitHub Copilot.** Copilot cloud agent "now signs every commit it makes", and the commits show as Verified (3 Apr 2026). The entry says nothing on attestations or session records. — [GitHub changelog](https://github.blog/changelog/2026-04-03-copilot-cloud-agent-signs-its-commits/)
- **GitHub Artifact Attestations** use in-toto, DSSE and Sigstore bundles, with Rekor for public repos and a private Fulcio for private repos. — [GitHub blog](https://github.blog/security/supply-chain-security/introducing-artifact-attestations-now-in-public-beta/)
- **Claude Code**:
  - There is no native commit signing; requests for signing and for "cryptographic attestation that a git commit... was taken by a Claude agent" were closed as not planned.
  - The web sandbox shipped an empty signing key (#83257).
  - Its OpenTelemetry export is redacted by default and unsigned.
  - — [#80551](https://github.com/anthropics/claude-code/issues/80551); [#83257](https://github.com/anthropics/claude-code/issues/83257); [monitoring docs](https://code.claude.com/docs/en/monitoring-usage)
- **Codex** has OpenTelemetry log events, disabled by default. I found no evidence of signing or attestation. — [openai/codex PR #2103](https://github.com/openai/codex/pull/2103)
- **Cursor**:
  - OpenTelemetry export has metrics and logs, no traces, and no integrity features.
  - Agent Trace has no signatures, and its repo returns 404.
  - The only signed-commit hit was a user forum thread about an agent hanging on signing.
  - — [Cursor OTel docs](https://cursor.com/docs/enterprise/opentelemetry-export); [agent-trace.dev](https://agent-trace.dev/); [Cursor forum](https://forum.cursor.com/t/cursor-agent-signed-commits/119822) **[search summary]**
- **Entire.** The README's only integrity mention is "Installs from a Git host are verified against the release's `checksums.txt`" for plugins. Companion research reports that session transcripts are pushed to git as checkpoint refs, redaction is "best effort", and the README does not mention encryption. — [entireio/cli README](https://github.com/entireio/cli)
- **git-ai.** Its Git Notes "attestations" are line-to-session mappings with hash-derived keys, not signatures. — [Git AI standard v3.0.0](https://github.com/git-ai-project/git-ai/blob/main/specs/git_ai_standard_v3.0.0.md)
- **Cloudflare**:
  - Its "signed agents" class verifies Web Bot Auth / RFC 9421 HTTP signatures from agents such as ChatGPT agent and Goose. **[search summary]**
  - It audits WhatsApp's key transparency log as a third party, publishing signatures without PII. **[search summary]**
  - — [Cloudflare signed agents](https://blog.cloudflare.com/signed-agents/); [Cloudflare key transparency](https://blog.cloudflare.com/key-transparency)
- **Tailscale Aperture.** Retention can go "all the way down to zero", logs can be exported to S3-compatible storage, and admin access to other users' logs "is recorded". No signing, hashing or tamper-evidence is described. — [Tailscale blog, 30 Jun 2026](https://tailscale.com/blog/aperture-audit-AI-agents)
- **Coder.** AI Governance is "included with a Premium license". It covers the AI Gateway, an "LLM gateway to audit AI sessions, central MCP server management, and policy enforcement", and the Agent Firewall, "Process-level firewalls for agents". No signing or tamper-evidence is described. — [Coder docs: AI Governance](https://coder.com/docs/ai-coder/ai-governance)
- Coder renamed AI Bridge to AI Gateway and Agent Boundaries to Agent Firewall in April 2026, after GA in v2.30 (February 2026). **[search summary]** — [Coder changelog 2.30](https://coder.com/changelog/coder-2-30)
- **Microsoft Purview / Agent 365**:
  - Purview Audit logs Copilot and AI app interactions with `AgentId`, `AgentName`, `AgentVersion`, `AccessedResources` (including Action, PolicyDetails and `XPIADetected`), `Messages` (IDs, `JailbreakDetected`) and `ModelTransparencyDetails`.
  - Logs for non-Microsoft AI apps are pay-as-you-go and "retains... for 180 days".
  - The page says nothing on immutability, signing or third-party verification. It was updated on 26 Aug 2026.
  - — [Microsoft Learn: Audit logs for Copilot and AI applications](https://learn.microsoft.com/en-us/purview/audit-copilot)
- Microsoft's SCITT-aligned transparency ledger (MST / Azure Code Transparency) is described in section 1. **[search summary]**
- **Spec-level designs closest to URnetwork's:**
  - draft-ruvalcaba-nhe-audit-00, a content-optional, hash-linked audit chain with "prove-without-exposing" verification.
  - draft-emirdag-scitt-ai-agent-execution-01 (Veridic), a SCITT profile with hash-chain integrity, "sequence completeness", redaction receipts and EU AI Act mappings.
  - draft-mih-scitt-agent-action-capsule-05 (Action State Group), digest-committed per-action capsules with "an honest human-in-the-loop flag".
  - draft-noa-scitt-ai-agent-receipt-01 (NordenSoft).
  - draft-bailey-scitt-agent-session-receipt-00 (WhiteMagic Labs), session-level receipts "with an explicit head commitment that detects local hash-chain truncation and whole-store rollback".
  - — [ruvalcaba](https://datatracker.ietf.org/doc/draft-ruvalcaba-nhe-audit/); [emirdag](https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/); [mih](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/); [noa](https://datatracker.ietf.org/doc/draft-noa-scitt-ai-agent-receipt/); [bailey](https://datatracker.ietf.org/doc/draft-bailey-scitt-agent-session-receipt/)
- in-toto PR #588 explicitly targets "gateways, proxies, audit sidecars". — [in-toto/attestation#588](https://github.com/in-toto/attestation/pull/588)

### Inferences
- **Who comes closest:**
  1. GitHub, which has signed agent commits plus attestation infrastructure. But GitHub holds the keys, the session record is not attested, and the approach is GitHub-only.
  2. Microsoft, which has a rich agent audit schema plus a separate SCITT ledger. These are not combined, the audit is tenant-internal, and the vendor can read it.
  3. Small vendors writing IETF agent-receipt drafts. I could not verify product maturity.
- Nobody found offers "verifiable without trusting the vendor" plus "private from the vendor" for agent work across harnesses. That combination is open territory.
- Product precedent for "access to the record is itself recorded": Aperture logs admin viewing of other users' logs. URnetwork's "visible audit member" could go further by logging membership and key-escrow events in the verifiable log itself, as Apple's KT does for device keys.

### Gaps
- Codex cloud and Cursor cloud commit signing remain unconfirmed.
- I did not review Entire's hosted docs for signing or encryption.
- I did not check Agent 365-specific audit records or whether Purview audit is immutable.
- I found no Tailscale Aperture docs on log integrity.
- I could not determine whether any of the drafting startups (Veridic, Action State Group, NordenSoft, WhiteMagic Labs, Saluca, CyberSecAI, Tersign) ship products.

## 8. Judgment: credible differentiators vs over-engineering, and where URnetwork could contribute

### Takeaway
URnetwork can credibly claim two things using mature, standard pieces:
- **"Verifiable without trusting us"**, with these parts:
  - per-principal signatures;
  - an RFC 9162 / C2SP tile log run with Tessera;
  - witness cosignatures under C2SP;
  - an open-source verifier;
  - exports as COSE/SCITT statements and in-toto/DSSE.
- **"Prove it to your client without showing them your code"**: SD-JWT-style salted-commitment disclosures (RFC 9901) of signed approvals, plus Merkle inclusion proofs.

Erasure via per-entry keys and salts follows the EDPB's own patterns. Over-engineering for a 1–10 person company:
- BBS, general ZK, redactable signatures;
- running a public SCITT Transparency Service or verifiable map;
- TEE attestation;
- making blockchain anchoring the primary trust anchor.

The best venue to contribute is the new IETF AUDIT BoF (17 Nov 2026), followed by in-toto predicate consolidation, the C2SP / witness-network community and the OTel GenAI SIG. I found no evidence of the claimed IETF 124 presentation.

### Cited Findings
- **Limits of what records prove.** draft-zhang-audit-record-limits-00 (Tersign, 27 Oct 2026) states: "Each mechanism establishes a narrower fact than it is often taken to establish". It covers independence of signers or observers, "the completeness of a set of records", time, and verifier reports. It "defines independence by control rather than by key or process separation". — [draft-zhang-audit-record-limits](https://datatracker.ietf.org/doc/draft-zhang-audit-record-limits/)
- **The self-report problem.** in-toto #588: "Application logs are insufficient for auditing because the entity writing the log is the same entity whose behavior needs verification." — [in-toto/attestation#588](https://github.com/in-toto/attestation/pull/588)
- **Crowding.** 42 Internet-Drafts with "receipt" in the name and 15 with "audit" were updated in 2026, many agent-related. — [datatracker API: receipt](https://datatracker.ietf.org/api/v1/doc/document/?name__contains=receipt&type=draft&time__gte=2026-01-01); [datatracker API: audit](https://datatracker.ietf.org/api/v1/doc/document/?name__contains=audit&type=draft&time__gte=2026-01-01)
- **MCP gatekeeping.** A receipts proposal opened directly as a GitHub issue was redirected: "Please start with relevant working and interest groups in Discord before opening a SEP". SEP workflow was formalized in SEP-1850. — [MCP #3471](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3471); [MCP 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- **IETF venues at IETF 127** (14–20 Nov 2026, San Francisco):
  - AUDIT BoF (17 Nov);
  - SCITT (19 Nov 00:30 UTC);
  - WIMSE (18 and 19 Nov, the second joint with OAUTH);
  - KEYTRANS (18 Nov);
  - agentproto (16 Nov).
  - — [IETF 127 agenda](https://datatracker.ietf.org/meeting/127/agenda)
- **The AUDIT BoF is WG-forming.** Its deliverables include audit-record data models and SCITT/RATS profiles. — [AUDIT BoF request](https://datatracker.ietf.org/doc/bofreq-kuhlewind-audit-agent-use-of-delegation-and-interaction-traceability/)
- **Open participation:**
  - The OIDF AIIM CG is "open to the public" under a participation agreement. **[search summary]** — [AIIM CG](https://openid.net/cg/artificial-intelligence-identity-management-community-group/)
  - The witness network accepts new logs and witnesses with maintainer approval. — [witness-network.org](https://witness-network.org/)
  - in-toto takes predicate proposals through issues and PRs, guided by new_predicate_guidelines.md. — [in-toto/attestation#604](https://github.com/in-toto/attestation/issues/604)
- **URnetwork's existing Merkle code.** The `urnetwork/sdk` package `sn/merkle` "implements the OpenZeppelin-compatible keccak256 Merkle tree shared by the UR subnet server (payout roots), the ops CLI, and the validator (effort roots). Roots built here are committed on-chain". It works like this:
  - Leaves are double-keccak hashed.
  - Internal nodes are hashed as "sorted pair" (commutative).
  - "Sort the leaf hashes in ascending lexicographic byte order" before building the tree.
  - A separate `ledger_sum_tree.go` uses 0x00/0x01 leaf/node domain separation.
  - `trail_leaf.go` commits validator "trail" leaves that carry Ed25519 signatures for on-chain disputes.
  - — [sdk/sn/merkle/merkle.go](https://github.com/urnetwork/sdk/blob/main/sn/merkle/merkle.go); [ledger_sum_tree.go](https://github.com/urnetwork/sdk/blob/main/sn/merkle/ledger_sum_tree.go); [trail_leaf.go](https://github.com/urnetwork/sdk/blob/main/sn/merkle/trail_leaf.go)
- **IETF 124 claim (Montreal, 1–7 Nov 2025):**
  - Searching all IETF 124 slide titles for "urnetwork", "bringyour", "ur network", "dvpn", "decentralized vpn", "vpn", "decentrali", "p2p" and "peer-to-peer" found no URnetwork or BringYour deck. The decentralization talks found were by others or untitled by company: DINRG, PEARG, and MLS "Decentralized MLS".
  - No Internet-Draft abstract mentions URnetwork or BringYour.
  - The IETF 124 hackathon wiki has no mention.
  - The meeting-materials HTML page returned an empty response, and the side-meetings wiki is JavaScript-rendered and could not be searched.
  - — [datatracker slides API (meeting 124)](https://datatracker.ietf.org/api/v1/doc/document/?type=slides&name__startswith=slides-124&title__icontains=urnetwork); [IETF 124 hackathon wiki](https://wiki.ietf.org/en/meeting/124/hackathon); [meeting dates](https://datatracker.ietf.org/api/v1/meeting/meeting/?number__in=124,125,126,127)

### Inferences
**What "verifiable without trusting us" can honestly mean.** With the stack below, a client or auditor can independently verify five things:
- Each entry was signed by the stated agent principal or human sponsor key.
- Entries were not altered or reordered after logging (hash chain plus Merkle consistency).
- The team was not shown a different history from its auditor (witness cosignatures on checkpoints).
- An entry existed by a certain time (witnessed checkpoint time, or an external anchor).
- Erased entries still verify as erased commitments.

It **cannot** prove the following:
- That the agent did nothing unlogged. Completeness is limited to what the harness routed through the sidecar.
- That the content is truthful. The record holds what the harness reported.
- That signers were independent of the team. The draft-zhang distinctions apply.

Marketing should name these limits. A cross-harness record observed by a separate process is a stronger position than self-reporting, and in-toto #588 makes the same argument. But the harness launches the sidecar, so it is not fully independent.

**Recommended standard pieces (mature enough to ship in 2026)**

| Feature | Standard pieces (status) | Verdict for a 1–10 person team |
|---|---|---|
| Signed, hash-chained, metadata-only entries per principal | COSE_Sign1 or DSSE/in-toto Statement v1 (in-toto v1.2.0); Ed25519 keys held on client devices | **Build (table stakes).** Every competing draft does this, so it is not a differentiator alone |
| Team-owned Merkle log + signed checkpoints | RFC 9162 tree; C2SP tlog-checkpoint/tlog-tiles; Tessera v1.0 (POSIX) | **Build.** Mature, cheap, self-hostable; the core of "verifiable without trusting us" |
| Independent cosigning | C2SP tlog-witness/cosignature; witness network staging only | **Build the hook, partner for witnesses.** Publish checkpoints to staging witnesses, ship a witness that customers or auditors can run, and consider running one (Mullvad does) |
| Hash-only payloads + standard receipts for export | RFC 9995 Hash Envelope; RFC 9942 COSE Receipts; RFC 9943 SCITT | **Adopt the formats; don't run a public Transparency Service** (SCRAPI not yet RFC) |
| Signed human approvals | SSH signatures (GitHub-verifiable) or gitsign/OIDC certificates | **Build. Strongest single differentiator.** It turns "who approved it" from a claim into a signature |
| Prove approval to a client without code | SD-JWT model (RFC 9901) salted digests + decoys; Merkle inclusion proof; witnessed checkpoint | **Build (credible).** Standard pieces, small code |
| Delegation evidence | RFC 8693 actor chains, ID-JAG `jti` and issuer, RAR objects; WIMSE AIMS vocabulary | **Consume and record; don't define** |
| GDPR erasure with intact chain | Per-entry DEK + 256-bit salt commitments; erasure entries; EDPB v2.0 patterns | **Build, with counsel.** Claim "designed to EDPB's commitment pattern", not "certified erasure" |
| Per-run attestation export | in-toto Statement + DSSE, with an agent predicate (unmerged PRs #588/#600) | **Build as export; help standardize** |
| OTel export | GenAI semconv (Development) + SEP-414 trace context | **Build as interop, not integrity** |
| Unlinkable disclosure (BBS), JWP | Drafts (CFRG -14; W3C CRD) | **Over-engineering now.** Revisit if BBS reaches RFC |
| ZK proofs over the log | Research; ZK practical only for credentials (longfellow-zk) | **Over-engineering** |
| Redactable signatures | No standard | **Over-engineering** |
| Verifiable map / KT for agent key directory | KEYTRANS drafts; AKD/CKV designs | **Later.** Only if outsiders must look up agent keys at scale |
| TEE / RATS attestation of the sidecar | RFC 9334 architecture; agent EAT drafts | **Over-engineering for v1** |
| Blockchain anchoring as primary trust | Keybase precedent; URnetwork already commits roots on-chain | **Optional secondary anchor only.** Witnesses are more standard; the EDPB discourages chains where integrity can be had otherwise |

**Notes on fit with URnetwork's design**
- **Keep the existing Merkle code for the subnet; use Tessera for the record.** The SDK's OpenZeppelin tree sorts leaves and uses commutative pair hashing. That suits an on-chain set membership proof but has no ordering and no RFC 9162 consistency proofs. Reusing it would make the record non-interoperable with the C2SP, SCITT and COSE Receipts verifiers.
- The team's Merkle and on-chain experience lowers the cost of a checkpoint anchor. The subnet contracts could optionally commit agent-log checkpoint hashes, but treat that as a secondary anchor.
- **"Private from us, complete for your admins" must be verifiable too.** Log every MLS membership change, escrow-key creation and use, and admin decryption request as signed entries. Then "the vendor cannot read it" and "admins can" are both auditable claims, not policy promises.
- **Public checkpoints leak activity volume.** Default to per-team logs with batched, scheduled checkpoints.

**Standards bodies where a 1–10 person company could plausibly contribute (ranked)**
1. **IETF AUDIT BoF and the likely WG** (17 Nov 2026; audit@ietf.org). It is on-topic for cross-harness agent records: audit-context propagation, record data models and SCITT profiles. The most valuable input would be an implementation report or interop test vectors for a "content-optional, erasable, witnessed" record, not another format. Per IETF norms, participation is open and individual.
2. **in-toto attestation** (CNCF). Help consolidate the open agent predicates (#588 "audit sidecars" plus #600 "agentic process evidence") into one predicate URnetwork can emit. This has a low barrier and visible impact.
3. **C2SP / witness network.** Register the record log format as a witnessed log type, or operate a witness, as Mullvad does. This is cheap and builds "verifiable without trusting us" credibility.
4. **OTel GenAI SIG** (`semantic-conventions-genai`). Contribute agent-approval and authorization attributes (PR #291 is related) and the MCP 2026-07-28 alignment (#437).
5. **MCP working and interest groups (Discord) before any SEP.** This is the route for provenance and audit extensions, for example via SEP-2624 interceptors.
6. **WIMSE/OAuth** (AIMS document) and the **OIDF AIIM CG.** These are possible, but identity is dominated by large vendors, so audit-record requirements would be the useful contribution.

- **IETF 124 claim.** I found no evidence. If the company presented, it was not under a slide title containing its name, and not in an I-D. Avoid citing it externally until it is substantiated. A real presentation at the IETF 127 AUDIT BoF or a later meeting would be verifiable and more valuable.

### Gaps
- The AUDIT BoF outcome (WG formation, charter text, adopted drafts) will not be known until after 17 Nov 2026.
- It is unknown whether the witness network will accept small, private per-team logs, or how log lists are scoped.
- I made no cost or performance estimates for running Tessera per team, or for witness cosigning frequency.
- I did not verify that the IETF 124 presentation exists, for example in side meetings or in sessions where slides lack the company name.
- I did not obtain legal confirmation that the per-entry key and salt erasure design satisfies GDPR Art. 17 in the target markets.
