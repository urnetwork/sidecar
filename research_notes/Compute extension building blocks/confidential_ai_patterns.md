# Confidential AI production architectures: trust, attestation binding, transparency, unlinkability, statelessness, keys and admitted limits (state as of 2026-11-23)

Research notes for the sidecar compute extension: routing inference to TEE-backed third-party providers, and renting TEE VMs that run an agent harness. Bracketed dates give the source's publication or update date. "[live]" means undated live documentation read on 2026-11-23. "(possibly superseded)" marks material older than a newer source on the same system. "(search snippet)" marks a fact seen only in a search-result summary, not in a fetched primary page; treat those as lower confidence.

## 1. How does the client verify the server before sending data (evidence, verifier, where verification runs, how measurements are published and pinned, how updates and rotations are handled)?

### Takeaway
The strongest production designs (Apple PCC, Meta Private Processing, Tinfoil) run the verifier on the client. They pin vendor roots and minimum TCB levels in client code, and accept a server only if its hardware-rooted measurements appear in a public append-only log. Apple goes furthest. It projects every measured value into a release record whose digest must be in its own Merkle log, keeps a separate logged ledger of the physical machines it trusts, and has Google's firmware updates approved by Apple's log. Google Private AI Compute is the outlier. As of its September 2026 brief, servers are attested Google-side and issued keys, and client-side verification is still listed as future work. Brave and Phala sit in the middle: Brave's server-side "oracle" does the checking today, and Phala attests only its gateway.

### Cited Findings

#### Status snapshot (November 2026)
- [live] Apple PCC now "serves requests from two node platforms, Apple silicon and Google Cloud," and both must present "attested measurements that match a release recorded in the public transparency log" — [Apple PCC Security Guide](https://security.apple.com/documentation/private-cloud-compute)
- [2026-06-08] Apple announced PCC's extension to Google Cloud (Intel TDX CPUs, NVIDIA confidential-computing GPUs, Google Titan) for "agentic tool-use and complex reasoning." Protections would be "gradually ramping towards the complete set of protections throughout the summer preview period" — [Apple: Expanding PCC](https://security.apple.com/blog/expanding-pcc)
- [live] PCC releases 6A375/6AX1661 are "the first PCC on Google Cloud release in production, serving requests at the launch of the 27.0 operating systems" — [PCC Release Notes](https://security.apple.com/documentation/private-cloud-compute/releasenotes)
- [2026-06-11] Google: Apple PCC on Google Cloud uses Intel TDX, NVIDIA Blackwell confidential computing and Titan, and the two companies built "an open-source host stack specifically to support PCC's transparency" — [Google Cloud blog](https://cloud.google.com/blog/products/identity-security/powering-the-next-era-of-confidential-ai/)
- [2025-11] Google announced Private AI Compute (press) — [The Register](https://www.theregister.com/2025/11/12/google_touts_private_ai_compute/). [2026-09] The technical brief "Google Private AI Compute: Enabled with Secure Server-Side Memory" adds a persistent per-user memory layer — [Google PAC technical brief, Sept 2026](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf); [Google DeepMind blog, 2026-09-23](https://deepmind.google/blog/advancing-private-ai-compute-with-secure-server-side-memory/)
- Meta Private Processing white paper: V1 2025-06-10, V2 2026-03-16, V3 2026-10-20 — [Meta Private Processing white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper). The Trail of Bits audit write-up is dated 2026-04-07 — [Trail of Bits](https://blog.trailofbits.com/2026/04/07/what-we-learned-about-tee-security-from-auditing-whatsapps-private-inference/)
- [2025-08-14] NVIDIA Secure AI white paper v1.3 (Blackwell update) — [NVIDIA WP-12554-001 v1.3](https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf). Vera Rubin NVL72 rack-scale confidential computing ("third generation," one security domain of 72 GPUs and 36 CPUs) was announced at CES 2026 (search snippet; vendor and press claims) — [NVIDIA CC page](https://nvidia.com/en-us/data-center/solutions/confidential-computing); [VentureBeat](https://venturebeat.com/security/nvidia-rubin-rack-scale-encryption-enterprise-ai-security)
- Tinfoil launched Containers on 2026-03-10 (deploy your own image into an enclave) and Bunkers on 2026-11-19 (a confidential, always-running sandbox for agents, experiments and interactive work) — [Tinfoil blog index](https://tinfoil.sh/blog)
- Edgeless Privatemode runs AI workers on NVIDIA H100 or B200 in confidential VMs at Scaleway and Lyceum, with the Contrast Coordinator as attestation service — [Privatemode/Continuum architecture docs](https://docs.edgeless.systems/continuum/architecture/overview)
- dstack (Phala): Intel TDX is the "production TEE path." AMD SEV-SNP is "new and experimental." AWS EC2 NitroTPM and GCP TDX paths also exist — [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md)
- [2026-08-12] NEAR AI Cloud added Intel Trust Authority attestation tokens — [NEAR AI blog](https://near.ai/blog/near-ai-cloud-integrates-intel-trust-authority). [2026-11-09] NEAR disclosed an SGLang RCE breach — [CSA research note, 2026-11-11](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/11/CSA_research_note_near_ai_sglang_confidential_inference_breach_20261111-csa-styled.pdf)
- [2026-10-15] Brave Leo added end-to-end encrypted chats over OHTTP to NEAR AI TEEs (TDX plus NVIDIA GPUs), for the GLM 5.3 Flash model only — [Brave blog](https://brave.com/blog/browser-ai-e2ee/)
- Azure: the confidential inferencing deep dive [2024-09-24, v4.0 updated 2025-12-16] — [Azure deep dive](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-confidential-inferencing-technical-deep-dive/4253150). Microsoft's product overview still lists confidential inferencing only for Azure OpenAI Whisper on NCCadsH100v5 (search snippet) — [Azure product overview](https://learn.microsoft.com/azure/confidential-computing/overview-azure-products)
- [2025-06-18] Anthropic/Pattern Labs, "Confidential Inference via Trusted Virtual Machines," is a research sketch: "we're working on a system based on this design," with no production claim — [Anthropic](https://www.anthropic.com/research/confidential-inference-trusted-vms)
- [2026-08-19, updated 2026-09-22] OpenAI's page describes "Private Safety Processing" for zero-data-retention customers, with content encrypted under customer-controlled keys. It contains no TEE, attestation or hardware details — [OpenAI](https://openai.com/index/offering-zero-data-retention-for-frontier-models/). A DevDay 2026 "Private Intelligence" confidential-computing offering appears only in secondary coverage, which says the models, endpoints and hardware are unspecified (search snippet; unverified) — [VentureBeat](https://venturebeat.com/ai/openais-new-private-intelligence-targets-a-growing-enterprise-concern-who-can-see-your-ai-data/)
- [2025-11] Confident Security open-sourced OpenPCC, a PCC-inspired framework with a Go client, an OHTTP gateway and a third-party relay — [OpenPCC GitHub](https://github.com/openpcc/openpcc); [Axios](https://axios.com/2025/11/05/openpcc-encryption-ai-mcp-data). An arXiv paper (2026-06) prototypes it on TDX plus H100 (search snippet) — [arXiv 2606.11145](https://arxiv.org/html/2606.11145v1)

#### Apple PCC: what the device checks
- The device or proxy node sends user data only after node validation: "cryptographic proof of the node's identity, bound to the boot chain's measurements, checked against the append-only transparency log" [live] — [PCC: Google Cloud Node Attestation](https://security.apple.com/documentation/private-cloud-compute/googlecloudnodeattestation)
- Apple silicon nodes [live]: the Secure Enclave (SEP) signs a structure that contains the hardware attestation, the public half of the SEP-protected request key, sealed-register state and an anti-replay digest. The bundle adds Image4 manifests for every cryptex, the node's DCIK certificate, and log inclusion proofs for both the software release and the DCIK certificate — [PCC: Apple Silicon Node Attestation](https://security.apple.com/documentation/private-cloud-compute/applesiliconnodeattestation)
- Google Cloud nodes collect three kinds of evidence [live]:
  - an Intel TDX quote (MRTD plus RTMRs covering firmware, boot loader and container launch);
  - a Titan TPM2 quote over the BMC firmware, BIOS and host kernel;
  - NVIDIA SPDM `GET_MEASUREMENTS` transcripts with a fresh anti-replay value, carried in the VM's RTMR event log "so GPU trust is bound to the same CPU attestation."

  Source: [PCC: Google Cloud Node Attestation](https://security.apple.com/documentation/private-cloud-compute/googlecloudnodeattestation)
- The verifier rejects a Google Cloud node unless all of the following hold [live]:
  - TD attributes are "debug off, migratable off, key-locker off, perf-mon off…", the quoting enclave is not in debug mode, and UEFI debug is off;
  - a single measured Unified Kernel Image is the sole EFI application;
  - the container image digest is logged, and a production node has no runtime-configuration override;
  - the expected number of GPUs is present and every GPU reports identical driver and VBIOS measurements;
  - the Titan warm-reset counter is exactly `2`, which defeats a BMC that warm-resets the CPU into staged BIOS code.

  Source: [PCC: Google Cloud Node Attestation](https://security.apple.com/documentation/private-cloud-compute/googlecloudnodeattestation)
- Multi-vendor roots [live]: "For any component an attacker could abuse to exfiltrate user data, PCC therefore roots the software attestation in at least two separate roots of trust from independent vendors." Intel TDX and Titan cover the software that handles user data. GPU firmware rests on NVIDIA alone "because a GPU cannot reach the network or move data off the machine on its own" — [PCC: Google Cloud Roots of Trust](https://security.apple.com/documentation/private-cloud-compute/googlecloudrootsoftrust)
- Hardware ledger [live]: a Device Identity Manifest binds the Titan DeviceID certificate digest, the Intel platform instance ID (PIID) and each GPU's SPDM identity. An issuing service outside the node certifies the manifest and logs it, so "a node therefore cannot certify its own hardware." A node's attestation is trusted only if its hardware is a logged fleet member — [PCC: Google Cloud Roots of Trust](https://security.apple.com/documentation/private-cloud-compute/googlecloudrootsoftrust)
- Measurement pinning by projection [live]:
  - Releases are ASN.1 `ReleaseV2` records, split into a "firmware release" (Titan, BMC, BIOS, TDX module/SVN, NVIDIA VBIOS/driver) and a "software release" (host, guest and key-protection VM UKI/OVMF digests, container image digest, quoting-enclave identity).
  - "No field in either structure is compared against a reference value on its own. A verifier projects the values it reads… into the release structure, digests the encoded result, and checks that digest for inclusion in the log." A rolled-back `teeTcbSvn` therefore matches no entry.

  Source: [PCC: Google Cloud Software Transparency](https://security.apple.com/documentation/private-cloud-compute/googlecloudsoftwaretransparency)
- How updates are approved [live]:
  - Google builds the hardware TCB, but "Apple approves a firmware update by publishing its reference measurements to the transparency log… an unapproved firmware update prevents the node from accepting requests."
  - Apple gets advance maintenance notifications. OS updates ship as complete new images. The whole host restarts to pick up new versions.

  Source: [PCC: Google Cloud Software Transparency](https://security.apple.com/documentation/private-cloud-compute/googlecloudsoftwaretransparency)
- Apple builds each firmware release from "Google's software bill of materials (SBOM)… and NVIDIA's reference integrity manifests (RIMs)," so "a device therefore accepts a firmware state only once Apple has recorded it in the log" [live] — [PCC: Google Cloud Node Attestation](https://security.apple.com/documentation/private-cloud-compute/googlecloudnodeattestation)
- Transparency-log hygiene [live]:
  - The log is a Merkle tree and append-only.
  - To resist split-view attacks, "connections to the Apple Transparency Service route through third-party MASQUE proxies. The client hard-codes the top-level domains of these proxies."
  - At least daily milestones are published. Clients verify consistency proofs, and a device alerts the user only if an inconsistency is not resolved within 7 days.

  Source: [PCC: Release Transparency](https://security.apple.com/documentation/private-cloud-compute/releasetransparency)
- [2024-06-10, possibly superseded on details] Production images are published "within 90 days of inclusion in the log, or after relevant software updates are available, whichever is sooner." A signed release "cannot be removed without detection" — [Apple Security blog 2024](https://security.apple.com/blog/private-cloud-compute/)
- Research access [live]:
  - The Virtual Research Environment boots PCC software on an Apple-silicon Mac, virtualizing the SEP. A "research" variant relaxes iBoot, kernel and TXM policy.
  - Google Cloud nodes cannot be emulated, so "full-fidelity research therefore runs against real Google Cloud infrastructure."
  - [2026-06-08] Live research-mode nodes are promised via the Apple Security Bounty.

  Sources: [PCC VRE](https://security.apple.com/documentation/private-cloud-compute/virtualresearchenvironment); [PCC Research Variant](https://security.apple.com/documentation/private-cloud-compute/vreresearchvariant); [PCC Google Cloud Research Environment](https://security.apple.com/documentation/private-cloud-compute/googlecloudresearch); [Expanding PCC](https://security.apple.com/blog/expanding-pcc)
- Known gap [live]: devices, proxy nodes and ensemble leaders validate the DCA CA signature on node certificates "but don't yet enforce the presence of transparency inclusion proofs" — [PCC Release Notes](https://security.apple.com/documentation/private-cloud-compute/releasenotes)
- [2026-06-08] Devices "will only trust PCC software that is cryptographically approved by Apple" — [Expanding PCC](https://security.apple.com/blog/expanding-pcc)

#### Google Private AI Compute
- [2026-09] Clients establish trust "through validating the endpoint server's identity… on remote attestation and cryptographic key validation, along with a secure session protocol." "Upon successful hardware and software attestation, server instances… are provisioned with a cryptographic key. Clients verify this key before transmitting any data" — [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)
- [2026-09] System attestation is "measured from the first mutable code to the OS via the Titan security chip," combined with TEEs. Binary digests are "published to a ledger," and critical components are available for third-party audit — [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)
- [2026-09] Future work, stated by Google:
  - "Client-side attestation verification": "Moving from Google-asserted compliance toward client-side cryptographic verification, enabling user devices to independently validate server attestation evidence and endorsed binary identities."
  - Evolving the ledger into a log "observed and co-signed by independent third parties."
  - Broader reproducible builds.

  Source: [Google PAC brief §05](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)
- [2026-09-23] Google says it is publishing "a tamper-proof public record of our server software" and that devices "will be able to verify" it (future tense) — [DeepMind blog](https://deepmind.google/blog/advancing-private-ai-compute-with-secure-server-side-memory/)
- [2025-11-08] NCC Group's 2025 review covered attestation and encryption between front-end services and model serving. It excluded the AMD SEV-SNP platform itself and the phone apps (search snippet) — [NCC Group report](https://www.fox-it.com/media/cbuhuhuu/ncc_group_google_e025353p_report_2025-11-08_v14.pdf)
- [2026-09] Users can inspect Private AI Compute network requests in "Network Logs on supported Pixel and Android devices" — [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)

#### Meta Private Processing (WhatsApp)
- [2026-10-20] Clients hardcode:
  - the AMD Root Key (ARK);
  - CRLs for the ASK certificates;
  - "Minimum TCB… version numbers";
  - trusted guest and platform policy;
  - the "Artifact transparency provider's public signing-key."

  Source: [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)
- [2026-10-20] Clients check an RA-TLS certificate (extension OID 1.3.6.1.4.1.40981.2.2.20):
  - the certificate is self-signed and properly formed;
  - the hash of its public key is in the SEV-SNP report data;
  - the nonce matches;
  - transparency proofs verify under a "service-specific policy" and are not revoked;
  - the VCEK→ASK→ARK chain is valid;
  - guest and platform meet policy.

  Source: [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)
- [2026-10-20] "Most restrictive policy": each client request carries a timestamp, SEV-SNP TCB values and trusted transparency keys. The service uses "the max timestamp and TCB values of the two," so a stale server policy cannot weaken a client's — [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)
- [2026-10-20] Transparency and expiry:
  - Digests go to a third-party log, currently Cloudflare. The white paper notes: "This is not a Merkle-tree-based transparency ledger but a simple log maintained by a third party."
  - The revocation list "is published every 3 hours, and each signature expires every 24 hours."
  - Expiry is set per namespace: ML models "on the order of months," the CVM base image "on the order of weeks," with weekly CVM releases.

  Source: [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)
- [2026-10-20] Auditable artifacts are binaries, revocation lists and "authorized host identities." Models and system prompts stay private, and embargoed fixes are released "typically within a 90 day timeframe" — [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)
- [2026-04-07] After the audit (finding TOB-WAPI-8), patch levels are validated against VCEK certificate X.509 extensions, and the client enforces minimums set in its source code — [Trail of Bits](https://blog.trailofbits.com/2026/04/07/what-we-learned-about-tee-security-from-auditing-whatsapps-private-inference/)
- The bug bounty offers researchers a remote attestation endpoint to check the build hash and policy of deployed TEEs (search snippet) — [Meta bug bounty: Private Processing](https://bugbounty.meta.com/payout-guidelines/private-processing/)

#### Tinfoil
- [live] The SDK fetches the attestation document, verifies the AMD certificate chain, checks the Sigstore bundle against Sigstore's trust anchor, compares measurement predicates to runtime measurements, then opens TLS and matches the server key to the attested key. It fails closed on mismatch — [Tinfoil attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture)
- [live] The build is a CVM image described as byte-for-byte reproducible from pinned inputs (pinned OVMF from tinfoilsh/edk2, kernel, initrd).
  - The SHA256 of `tinfoil-config.yml` sits on the kernel command line, linking the config to the measurement.
  - A GitHub action builds on release tags and publishes a keyless-signed Sigstore bundle to Rekor.
  - Model weights are not CPU-measured. They are verified with dm-verity against a root hash pinned in the config.

  Source: [Tinfoil attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture)
- [live] Helper proxies for the attestation bundle, GitHub and the AMD KDS are untrusted: "A proxy can withhold material but cannot forge it" — [Tinfoil attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture)
- The Go verifier supports AMD SEV-SNP and Intel TDX, with "a secure HTTP client that attests automatically" (search snippet) — [tinfoilsh/verifier on pkg.go.dev](https://pkg.go.dev/github.com/tinfoilsh/verifier@v0.10.15)
- [2026-03-10] Containers: the client SDK verifies the attestation report on every connection, and a response is returned "only if attestation verification succeeds." Each Git tag creates a Sigstore record. Clients check the public transparency log rather than a Tinfoil-operated service, and the application need not be open source — [Tinfoil Containers](https://tinfoil.sh/blog/2026-03-10-tinfoil-containers)

#### Edgeless (Privatemode, Contrast) and Confidential Containers
- [live] The Privatemode client, either the JS SDK or a local proxy, "Verifies the integrity and authenticity of the service before any inference communication begins." It relies on "independent cryptographic certificates and hardware-enforced signatures," plus public source code and reproducible builds — [Privatemode architecture](https://docs.edgeless.systems/continuum/architecture/overview)
- [2026-08-06] GitLab describes the Privatemode proxy checking enclave evidence against known-good values before sending (search snippet) — [GitLab blog](https://about.gitlab.com/blog/confidential-ai-for-gitlab-self-hosted/)
- [live, v1.26] Contrast: the CLI verifies the Coordinator using reference values embedded at build time, and "the CLI effectively serves as the root of trust for the deployment." The Coordinator verifies each pod's launch measurement and initdata hash against the manifest — [Contrast attestation overview](https://docs.edgeless.systems/contrast/architecture/attestation/overview)
- [2025-12-19] CoCo Trustee splits the verifier into a Key Broker Service (KBS), an Attestation Service (AS) and a Reference Value Provider Service (RVPS). "Trustee should be deployed in a trusted environment" — [CoCo attestation docs](https://confidentialcontainers.org/docs/attestation/)

#### Phala dstack and RedPill, NEAR AI, Brave
- [live] dstack: verify the TDX quote with dcap-qvl. MRTD and RTMR0–2 are precomputed from the image. RTMR3 is checked by replaying the event log (compose-hash, init-script-hash, gpu-policy-hash, instance-id, key-provider) — [dstack TDX attestation guide](https://github.com/Dstack-TEE/dstack/blob/master/docs/attestation-tdx.md)
- [live] dstack trusts `os_image_hash` only after the quote is verified and MRTD/RTMR0–2 are recomputed from the image. "Downstream authorization systems can then compare that trusted value against an allowlist or governance contract" — [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md)
- [live] Phala Confidential AI (used by RedPill):
  - `GET /v1/aci/attestation?nonce=<64 hex>`;
  - `report_data` = SHA-256 of `{"keyset_digest":…,"nonce":…,"purpose":"aci.report_data.v1"}`;
  - compare compose-hash against an independently obtained, authenticated allowlist; `source_provenance` is "not a trust root";
  - the report describes the Phala gateway, not each upstream model's execution environment;
  - "A valid hardware quote alone does not verify a particular response."

  Source: [Phala verify attestation](https://docs.phala.com/phala-cloud/confidential-ai/verify/verify-attestation)
- [2026-08-12] NEAR AI Cloud returns a hardware-signed attestation with each request and publishes raw evidence. Intel Trust Authority, an independent verifier running in SGX, issues "an attestation token: a signed JWT carrying its verdict." NEAR says "The chain of trust no longer terminates at the infrastructure operator" — [NEAR AI blog](https://near.ai/blog/near-ai-cloud-integrates-intel-trust-authority)
- [2026-10-15] Brave Leo:
  - Today the open-source Brave AI Gateway fetches the TEE's live attestation and checks it against approvals from Brave's verification oracle. It re-checks before relaying each message, using a verification no more than an hour old, and the browser relies on that check. Browser-side verification is planned.
  - The oracle rebuilds NEAR-authored images from source. The third-party model runtime is not rebuilt; it is pinned by a hardware-attested deployment log.

  Source: [Brave blog](https://brave.com/blog/browser-ai-e2ee/)

#### Microsoft Azure
- [2024-09-24, v4.0 2025-12-16]:
  - Clients fetch the current HPKE public key together with attestation and transparency evidence. "Clients verify this evidence before sending their HPKE-sealed inference request."
  - The ledger records container hashes and policies, with optional SBOM, source and CI pointers. "All claims registered on the ledger will be digitally signed."
  - Receipts come back with completions.
  - GPU evidence is SPDM, checked against NVIDIA RIMs and OCSP.

  Source: [Azure deep dive](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-confidential-inferencing-technical-deep-dive/4253150)

#### NVIDIA GPU evidence
- [live] Blackwell evidence is the SPDM 1.1 `GET_MEASUREMENTS` transcript: VBIOS and driver measurement blocks, a signature from the attestation identity key, and a certificate chain to NVIDIA's CA with a serial-bearing SAN. "A verifier that doesn't use NVIDIA's attestation SDK parses these fields itself" — [PCC: Google Cloud Node Attestation](https://security.apple.com/documentation/private-cloud-compute/googlecloudnodeattestation)
- [live] dstack checks GPUs with `nvattest` against NVIDIA RIMs and the revocation service, "or NRAS when a deployment selects remote verification" — [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md)
- NVIDIA R595 TRD1 notes: in full CC-on modes, the driver accepts no workloads until the Attestation SDK or the user sets a GPU-Ready bit (search snippet) — [NVIDIA R595 TRD1 release notes](https://docs.nvidia.com/confidential-computing/release-notes/r595-trd1)

### Inferences
- A sidecar Go client can copy the Tinfoil and Apple shape directly:
  - embed vendor roots (AMD ARK, Intel SGX/TDX root, NVIDIA device root) and minimum TCB values in client code;
  - fetch evidence through untrusted proxies (URnetwork servers can carry it);
  - verify on the device;
  - accept only measurements included in a log that the provider does not control;
  - fail closed.
- Server-side "oracle" verification (Brave today, Google today) is exactly the trust in operator servers that sidecar's E2EE rule forbids. It is acceptable only if the oracle is itself an attested enclave the device verified, which is the Apple proxy-node and Tinfoil router pattern in §2.
- Apple's projection method fits a fleet of heterogeneous Bittensor providers well. Map whatever evidence a provider presents (TDX/SNP quote plus GPU SPDM) into a canonical release record. Accept it only if that record's digest is in a sidecar-controlled log. Providers then cannot slip in a one-off firmware or TCB state.
- Apple's hardware ledger and Meta's "authorized host identities" are the closest precedents for pinning which physical machines a third-party operator may use. This matters more for Bittensor providers, who hold physical access, than for hyperscalers (see §6).

### Gaps
- The Apple Security Guide pages are undated. The OS 27.0 launch date that put PCC on Google Cloud into production is not stated in the sources; it is presumably fall 2026.
- No source says exactly what Google PAC devices verify today. The brief calls client-side verification future work, but also says clients "verify this key."
- No 2026 Azure status update was found, so it is unclear whether confidential inferencing grew beyond Whisper or added Blackwell confidential GPU VMs.
- No OpenAI technical white paper on confidential inference was found.
- Microsoft's open-source attested-OHTTP client and server repositories were not verified in this pass.

## 2. How is the attestation bound to the encrypted channel, and who terminates TLS?

### Takeaway
There are two production patterns. The first is to encrypt to an attested key, so the outer TLS is irrelevant: Apple HPKE-wraps a per-request data key to each validated node's key; Azure and Brave seal requests to an OHTTP/HPKE key whose private half exists only in an attested TEE; Tinfoil offers EHBP. The second terminates TLS inside the TEE with a fresh, client-nonced attestation that binds the TLS public key (Meta RA-TLS, Tinfoil, Contrast, dstack, Phala). Gateways and load balancers never terminate the inner channel. Missing freshness and binding are the most common audit findings. GPU evidence must be bound inside the CPU TEE's measured log, because NVIDIA reports alone are not bound to a particular CVM.

### Cited Findings

#### Apple PCC
- [live] Request flow:
  - The device generates a per-request Data Encryption Key (DEK) and encrypts the body with it.
  - For each node whose attestation it validated, it wraps the DEK with HPKE "as defined in the Oblivious HTTP specification" to that node's Request Encryption Key (REK).
  - The node uses the HPKE envelope to derive a response key, "so the client knows which node sent the response data."
  - The result is "an end-to-end encrypted, bidirectional tunnel, cryptographically tied to the REK and the node attestation."
  - Only small routing metadata travels outside the tunnel, protected by OHTTP.

  Source: [PCC: Attested Request Handling](https://security.apple.com/documentation/private-cloud-compute/requesthandling)
- [live] `cb_attestationd` creates the REK inside the SEP, which never releases it. The key is bound "to the OS instance and to the node's Software Sealed Registers," so it "becomes inaccessible if the measurements change." Request handlers hold only a reference to it. On expiry "the node deletes its private half, so nothing can decrypt a request encrypted to a retired key" — [PCC: On-Node Request Termination](https://security.apple.com/documentation/private-cloud-compute/requesttermination)
- [live] Anti-replay: "CloudBoard rejects a request if a node has already accepted its key material" ("single-execution semantics"), which blocks a gateway from replaying a request to many nodes to mount side channels — [PCC threat model](https://security.apple.com/documentation/private-cloud-compute/attacks)
- [live] Google Cloud nodes:
  - Requests are encrypted to an attested KEM key held in a separate Key Protection Service VM.
  - Spatial binding: the same Intel PIID must appear in both TDX quotes and in a TPM PCR.
  - Temporal binding: `REPORTDATA = SHA512(label ‖ SHA512(challenge ‖ SHA512(extra_data)))`, with `challenge = SHA256(attested_metadata)`. The challenge also "covers the certificate-transparency log head the node witnessed," so evidence age is bounded by a log timestamp, not one the node chose.

  Source: [PCC: Google Cloud Node Attestation](https://security.apple.com/documentation/private-cloud-compute/googlecloudnodeattestation)
- [live] Multi-turn agent sessions keep a persistent connection. "Each new turn reuses the cryptographic tunnel that was negotiated for the first turn" — [PCC: Multi-Turn Agent](https://security.apple.com/documentation/private-cloud-compute/multiturnagent)
- [live] Transitive trust:
  - Proxy nodes, such as PCC Agent nodes, validate worker-node attestations "on behalf of the user's device — verifying the same attestation properties as the user's device."
  - Workers are checked against the "trusted log revision" the device committed to when it accepted the proxy. Consistency or fresh inclusion proofs bridge revision differences.
  - A `customerProxy` policy ensures that clients unable to verify proxy attestations reject these nodes.

  Source: [PCC: Transitive Trust](https://security.apple.com/documentation/private-cloud-compute/transitivetrust)

#### Google Private AI Compute
- [2026-09] "The client establishes a Noise encryption connection with a frontend server and establishes mutual attestation of auditable binaries over that connection." The frontend then uses ALTS channels to inference and TPU model servers. Connections use "bi-directional attestation," and "The overall trust… is established by transitive trust between these servers" — [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)

#### Meta Private Processing
- [2026-10-20] For each received request, the in-CVM Attestation Agent:
  - generates a P-256 keypair;
  - puts digests of the public key and the attestation bundle into SEV-SNP report data;
  - returns a self-signed X.509 certificate carrying the finalized bundle.

  The TLS 1.3 session is forwarded through load balancers to the agent inside the target CVM. "The RA-TLS session can carry the user's requests directly or be used to establish a shared secret from which any protocol can derive its own keys," for example SRTP or message keys. OHTTP wraps the whole exchange. Source: [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)
- [2026-04-07] Audit finding TOB-WAPI-7: attestation reports "could be saved and replayed indefinitely." The fix puts the TLS `client_random` nonce into every report. Trail of Bits recommends attesting over a value derived from the handshake transcript, citing the IETF draft "Remote Attestation with Exported Authenticators" — [Trail of Bits](https://blog.trailofbits.com/2026/04/07/what-we-learned-about-tee-security-from-auditing-whatsapps-private-inference/)

#### Tinfoil
- [live] TLS terminates inside the CVM with a "non-exportable private key that never leaves enclave memory." The client compares the TLS key with the attested key — [Tinfoil attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture)
- [live] EHBP is for clients that cannot pin certificates, such as browsers, or when an intermediary sits in the path. Bodies are encrypted to the attested HPKE key (RFC 9180). Headers stay in the clear for routing, and a proxy server can add API keys and handle auth without seeing plaintext bodies — [Tinfoil attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture)
- [live] Chained enclaves:
  - The client verifies the confidential model router.
  - The router verifies each model enclave against a fixed model-to-repository mapping compiled into its binary, and pins each enclave's TLS key.
  - "The Tinfoil Backend supplies only the list of enclave hostnames."
  - The router re-checks periodically and whenever a TLS key changes, and stops routing to enclaves whose attestation has expired.

  Source: [Tinfoil attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture)

#### Contrast, dstack, Phala
- [live, v1.26] Contrast `REPORTDATA` holds a hash of the CVM's public key and a nonce, which gives freshness and binds attestation to a TLS session — [Contrast attestation overview](https://docs.edgeless.systems/contrast/architecture/attestation/overview)
- [live] dstack provides "Zero Trust HTTPS (TLS terminates in TEE)." The Gateway terminates TLS at the edge and provisions ACME certificates automatically, and "All internal communication uses RA-TLS for mutual attestation" — [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md); [dstack README](https://github.com/Dstack-TEE/dstack)
- [live] Phala ACI: clients pin hostname-validated TLS to the SPKI listed in the attested keyset (`tls_public_keys`). The keyset digest and nonce are bound through `report_data` — [Phala verify attestation](https://docs.phala.com/phala-cloud/confidential-ai/verify/verify-attestation)

#### Azure, Brave, Anthropic
- [v4.0 2025-12-16] Azure: the OHTTP gateway runs inside the TEE and decrypts requests. The KMS releases the HPKE private key, wrapped under an attested vTPM key, only after the gateway presents a Microsoft Azure Attestation token that satisfies the key release policy — [Azure deep dive](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-confidential-inferencing-technical-deep-dive/4253150)
- [2026-10-15] Brave:
  - For each request the browser creates an ephemeral X25519 key and runs ECDH against the TEE's key, then HKDF-SHA256 and AES-128-GCM (Chromium's OHTTP).
  - Each turn gets a new one-time key and re-encrypts the whole history. The encryption key is "supplied only after the TEE passes verification."
  - Decryption happens in NEAR's TDX `cloud-api` gateway enclave.
  - The oracle records a signing key only if it is bound into a verified hardware attestation, and the TEE's encryption key must carry a signature from an approved signing key.

  Source: [Brave blog](https://brave.com/blog/browser-ai-e2ee/)
- [2025-06-18] Anthropic's sketch: the request is encrypted before reaching Anthropic, but the API server decrypts, processes and re-encrypts it. Cleartext exists in the API server and the trusted loader, so it is not end-to-end to the accelerator — [Anthropic](https://www.anthropic.com/research/confidential-inference-trusted-vms)

#### GPU-to-CPU binding (NVIDIA)
- [2025-08-14] CPU–GPU traffic is encrypted with bounce buffers, or by TDISP/IDE "when coupled with a compatible CPU, Blackwell GPU, and supported firmware and driver releases." Session keys sit "in key slots that cannot be accessed by the hypervisor" and are "destroyed when a VM is torn down or a GPU is reset" — [NVIDIA WP v1.3](https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf)
- TEE.fail: NVIDIA attestation reports are not bound to a specific CVM or CPU, so attestations from other devices can be "borrowed" — [TEE.fail](https://tee.fail/)
- [live] dstack: "dstack also cannot rule out a live relay/cuckoo attack to a genuine remote GPU: current Hopper/Blackwell deployments do not provide a CPU-TEE-verifiable TEE-I/O/TDISP device binding." The GPU event is "not a lifetime or physical co-location guarantee" — [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md)
- [live] Apple's mitigation: GPU SPDM transcripts are embedded in the TDX-attested event log, all GPUs must report identical measurements, and each GPU's SPDM identity must match the logged hardware ledger entry — [PCC: Google Cloud Node Attestation](https://security.apple.com/documentation/private-cloud-compute/googlecloudnodeattestation); [PCC: Google Cloud Roots of Trust](https://security.apple.com/documentation/private-cloud-compute/googlecloudrootsoftrust)
- [live, v1.26] Contrast's guidance on relay attacks: accept evidence only from expected machines, by listing machine identifiers in the manifest (PIID for TDX, HWID for SEV-SNP) or by trusting the entire network path — [Contrast attestation overview](https://docs.edgeless.systems/contrast/architecture/attestation/overview)

### Inferences
- Sidecar's relayed inference should use encrypt-to-attested-key (HPKE/OHTTP-style, as Apple, Azure, Brave and Tinfoil EHBP do). URnetwork servers then carry only ciphertext plus routing headers. A browser extension cannot pin TLS certificates, which is exactly the EHBP case.
- No surveyed system documents SSH host-key attestation. By analogy with Meta and Contrast, an enclave's SSH host key would be generated in the TEE, and its hash plus a client nonce placed in `report_data`. The Trail of Bits recommendation suggests binding instead to the SSH exchange hash or session ID, which plays the role of a TLS exporter, so a relayed attestation cannot be reused on another connection.
- On provider hardware, GPU binding should mirror Apple and dstack: GPU evidence inside the CPU-attested event log, a fresh nonce at boot, an identical-measurement check across GPUs, and ideally GPU serials allowlisted per provider. TDISP binding is not available to verify on current deployments.

### Gaps
- Neither Tinfoil Bunkers nor dstack explains how an SSH host key is bound to attestation. Bunkers says only that "Bunkers verify this end-to-end before you connect."
- The text of the IETF "Remote Attestation with Exported Authenticators" draft was not reviewed.
- How Google binds Noise-session keys to attestation is not specified in the brief.

## 3. How do they keep the operator from targeting a specific user (OHTTP, anonymous credentials, identity-blind load balancers), and how do they meter or bill without identifying content?

### Takeaway
Every consumer-scale system (Apple, Google, Meta, Brave) separates authentication from inference. A separate service turns device or account credentials into unlinkable single-use tokens: RSA blind signatures/Privacy Pass at Apple, Anonymous Tokens at Google, ACS at Meta, unlinkable tokens at Brave. Requests travel through a third-party OHTTP relay so the gateway never sees the source IP. Apple and Meta also stop the operator from serving per-user keys by publishing OHTTP and token key configurations, in a transparency log (Apple) or through a third-party CDN with a signature key hardcoded in the client (Meta). Variable-cost metering is handled by Apple's cost tokens returned inside the encrypted response and refunded as anonymous tokens. B2B systems (Azure, Tinfoil, Phala) bill by API key and token counts and do not claim unlinkability. Persistent per-user state cannot be non-targetable; Google says so explicitly.

### Cited Findings

#### Apple PCC
- [live] Tokens:
  - The client authenticates to the Token Granting Service, which checks eligibility and the rate limit, then issues a batch of One-Time Tokens built with "RSA Blind Signatures, as detailed in RFC 9474 and used in Privacy Pass (RFC 9578)."
  - Redemption is "cryptographically unlinkable" to issuance.
  - From iOS/macOS 27 the separate PCC Identity Service is folded into the Token Granting Service.

  Source: [PCC: Anonymous Request Routing](https://security.apple.com/documentation/private-cloud-compute/requestflow)
- [live] Transport:
  - Chunked OHTTP; the client encrypts with HPKE to the Oblivious Gateway's key.
  - Clients "randomly select among multiple Oblivious Relays (ORs) operated by distinct third parties, currently Cloudflare and Fastly," over HTTP/3.
  - Separate Privacy Pass tokens, signed by different keys, go to the relay and to the gateway.
  - The OHTTP key configuration and the token keys "are published to the transparency log, and clients confirm that the keys they receive have been recorded," so "only one set of keys is in use in a given time period."

  Source: [PCC: Anonymous Request Routing](https://security.apple.com/documentation/private-cloud-compute/requestflow)
- [live] Cost feedback (iOS/macOS 27):
  - The node returns a signed JWT "cost token" inside the encrypted response. It carries "only the cost information, token issuer metadata, and bucketed timestamps."
  - The client later submits accumulated tokens over OHTTP to a Cost Aggregation Service.
  - That service refunds Private Access Token "denominations," which the client spends when requesting new token batches.

  Source: [PCC: Anonymous Request Routing](https://security.apple.com/documentation/private-cloud-compute/requestflow)
- Known issue [live]: "The keys that sign Cost feedback are not yet published to the Release Transparency" — [PCC Release Notes](https://security.apple.com/documentation/private-cloud-compute/releasenotes)
- [live] Node selection: the gateway "assembles the candidate set without any identifying information about the user or device." The device "caps how many candidate attestations it uses regardless of how many the PCC Gateway offers, and a configuration PCC supplies can only lower that cap." After an external tool call exposes content, the request "opts into stronger protection" for later node selections — [PCC: Non-Targetability](https://security.apple.com/documentation/private-cloud-compute/nontargetability)
- [live] Residual: "A user who is highly distinguishable by those properties might be subject to a semi-targeted attack" — [PCC: Non-Targetability](https://security.apple.com/documentation/private-cloud-compute/nontargetability)
- [2024-06-10, possibly superseded] Steering traffic would need both the relay and the load balancer compromised, and node selection is "statistically auditable" — [Apple Security blog 2024](https://security.apple.com/blog/private-cloud-compute/)
- [live] External tool calls carry `tenant_info` (bundle ID, feature ID, device model and OS version, test-device group) but "no information identifying the source device or user." A trace ID correlates the tool calls of one request — [PCC: Tool Gateway Protocol appendix](https://security.apple.com/documentation/private-cloud-compute/appendix_toolcalling)

#### Google Private AI Compute
- [2026-09] "IP blinding relays which are operated by third-parties… tunnel all traffic." Authentication is isolated from inference "using Anonymous Tokens": "Device authentication and rate limiting are handled by a separate server, which exchanges device credentials for an anonymous, cacheable token… A user's identity never travels with their data on the inference path" — [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)
- [2026-09] Memory: "a request must reach the user's store, so the system must resolve a stable per-user identifier. Consequently, the stateful system does not claim network-level non-targetability. Instead, targeting a specific user's memory yields only opaque ciphertext" — [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)

#### Meta Private Processing
- [2026-10-20] The relay strips the IP. Meta's OHTTP gateway decrypts the HPKE layer, validates the ACS token and selects a CVM. ACS credentials "can be used a finite number of times." The RA-TLS target is "chosen by a load balancer while it has no knowledge of the user" — [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)
- [2026-10-20] ACS and OHTTP key configurations are distributed through a third-party CDN (currently Fastly) "to prevent Meta from being able to target specific users." The configuration "is signed with a Meta-owned key, and that signing key is hardcoded on the client" — [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)
- [2026-10-20] Named threat scenarios include "Targeted routing attacks," "User de-anonymization side-channel attacks" and "ACS de-anonymization attacks" — [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)

#### Brave, Azure, Tinfoil, OpenPCC
- [2026-10-15] Brave runs the relay, which sees IP addresses but not content. NEAR's gateway and inference TEEs see content but not IP addresses. Leo needs no account and does not log IPs, and Premium subscriptions are validated with unlinkable tokens so payment details cannot be tied to conversations — [Brave blog](https://brave.com/blog/browser-ai-e2ee/)
- [v4.0 2025-12-16] Azure: there is an optional "OHTTP proxy outside of Azure." Enterprises can run their own proxy to "inject a tenant level authentication token." Billing needs "the size (but not the content) of the completions" — [Azure deep dive](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-confidential-inferencing-technical-deep-dive/4253150)
- [live] Tinfoil's router sends usage records to its backend (token counts, model, timestamp, API key, request IDs, route, serving enclave). They contain no prompt or response text, but they are linked to the account. Billing and backend code are closed source — [Tinfoil attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture)
- [2025-05-10] Tinfoil on OHTTP: it "only protects who sent the data, not the data itself"; after decryption "the actual content… is fully exposed to the receiving server" — [Tinfoil: Oblivious Is Not Always Private](https://tinfoil.sh/blog/2025-05-10-ohttp)
- [2026-07-14] Tinfoil prompt-cache routing key: `hash(cache_salt || tinfoil_routing_secret || message_prefix)`, using a secret only Tinfoil holds, so neither the user nor Tinfoil alone can pick a replica — [Tinfoil secure prompt caching](https://tinfoil.sh/blog/2026-07-14-secure-prompt-caching)
- [live] OpenPCC expects deployments to "operate an OHTTP Gateway and configure clients use an OHTTP Relay, operated by a third party." Its repository has an `anonpay/` component, which the README does not describe — [OpenPCC GitHub](https://github.com/openpcc/openpcc)

### Inferences
- URnetwork's own network could act as the OHTTP relay, provided it never also runs the gateway or any attested key holder. Apple uses two independent relay operators; Brave relays while NEAR's TEE decrypts.
- For paid inference, Apple's blind-signature token batches plus encrypted cost tokens show how to meter variable token costs without per-request identity. The provider (a Bittensor miner) would see only an anonymous token and a ciphertext.
- Rentable enclaves are persistent, addressable per-user VMs, so by Google's own reasoning they cannot be non-targetable. Their protection must come from attestation, encryption and hardware allowlisting, and the product should say so plainly.
- Key configurations (OHTTP keys, token-issuer keys, enclave attestation keys) should be published in a log or through a third party, so a malicious operator cannot fingerprint one user with unique keys. Apple and Meta both do this.

### Gaps
- The Google Anonymous Tokens and Meta ACS protocol internals were not extracted beyond the cited summaries.
- Meta's mitigations for the named de-anonymization threats were not fully extracted from the white paper's threat table.
- OpenPCC's anonymous payment design (`anonpay/`) and white paper were not read.

## 4. What happens to logs, crash dumps, debugging access, and state (stateless designs versus persistent disks sealed to measurements)?

### Takeaway
Production inference services are stateless by construction:
- no persistent writable storage, or storage encrypted with a per-boot key held only in memory;
- per-request processes for parsing untrusted input, plus periodic recycling of shared runtimes;
- no shell or SSH in production images. Debug images with SSH exist but have different measurements that clients never accept;
- telemetry restricted to allowlists enforced in a measured daemon, with Apple adding differential-privacy-style thresholds for content-dependent metrics.

State across turns or sessions is kept under keys the user's device supplies or holds: Apple's encrypted KV cache, Google's per-user memory, Meta's client-sent history. The new rentable-sandbox products (Tinfoil Bunkers, dstack CVMs) do keep persistent disks, and both document integrity and rollback weaknesses.

### Cited Findings

#### Apple PCC
- [2024-06-10] "the system doesn't even include a general-purpose logging mechanism," and only "pre-specified, structured, and audited logs and metrics can leave the node." PCC nodes "cannot enable Developer Mode and do not include the tools needed by debugging workflows" — [Apple Security blog 2024](https://security.apple.com/blog/private-cloud-compute/)
- [live] Management and observability on Apple silicon:
  - "A specialist team audits each change to the metrics, log lines, and traces." Rules are scoped to each component's exposure to user data.
  - `splunkloggingd` forwards only allowlisted log lines, keyed by Mach-O image plus format string. Log persistence is off.
  - `cloudmetricsd` enforces the metric allowlist "in the daemon rather than in the emitting process, so a compromised component cannot bypass it."
  - Crash reports get partial or full redaction. "A maximum of three partially redacted logs is reported from each node per hour," emitted for 20% of crashes. Panic logs are forwarded without extra redaction.
  - Diagnostics go only through rate-limited interfaces exposed to the BMC. Rate limits on stack-trace capture bound side-channel bandwidth.

  Source: [PCC: Management and Observability](https://security.apple.com/documentation/private-cloud-compute/management)
- [live] Content-dependent metrics, such as recitation-prevention blocks, use "in-node aggregation." Export waits for a minimum time window and a per-bucket event minimum, with Laplace noise on both the count and the threshold — [PCC: Management and Observability](https://security.apple.com/documentation/private-cloud-compute/management)
- [live] Fixed bug: "the number of recitation prevention blocks could be logged and made accessible to Apple" — [PCC Release Notes](https://security.apple.com/documentation/private-cloud-compute/releasenotes)
- [live] A Google Cloud node uses audited allowlists in off-the-shelf telemetry components. "A node does not currently collect crash reports" — [PCC: Management and Observability](https://security.apple.com/documentation/private-cloud-compute/management)
- [live] Google Cloud hardened versus debug images:
  - In hardened images, "OpenSSH is not installed" on the host or either VM, serial consoles are detached, and the GPU is locked in CC mode with NVLink encryption.
  - "The host powers off as soon as the Workload VM terminates."
  - Debug images add SSH, operator login and crash tooling, but "Apple publishes production measurements for the hardened images only… so a node booted from a debug image can't decrypt user requests."

  Source: [PCC: Google Cloud Debug and Hardened Images](https://security.apple.com/documentation/private-cloud-compute/appendix_googleclouddebugandhardenedimages)
- [live] No state across reboots:
  - Apple silicon: "Ephemeral Data Mode… randomizes the data volume's encryption keys on every boot."
  - Google Cloud: "The one… file system is encrypted under a key the node generates at boot and holds only in memory."
  - "a node keeps no log that survives a reboot."

  Source: [PCC: Stateless Computation](https://security.apple.com/documentation/private-cloud-compute/statelesscomputation)
- [live] Runtime isolation and recycling:
  - Request parsing runs in a per-request, socket-activated `tie-cloud-app` container.
  - The shared inference runtime is recycled on a jittered security timeout. Weights and the system-prompt prefix cache survive recycling in `tie-model-owner`.
  - Streamed deltas are padded "so that its serialized size falls into one of a fixed set of buckets."

  Source: [PCC: Google Cloud Stateless Inference](https://security.apple.com/documentation/private-cloud-compute/googlecloudstatelessinference)
- [live] Cross-turn state: "PCC retains no encryption keys for cached state between turns: the user's device supplies the keys with each turn's request." On Google Cloud nodes the encrypted per-user KV cache sits in a cache store with time-to-live (TTL) eviction — [PCC: Multi-Turn Agent](https://security.apple.com/documentation/private-cloud-compute/multiturnagent); [PCC: Google Cloud Stateless Inference](https://security.apple.com/documentation/private-cloud-compute/googlecloudstatelessinference)

#### Google Private AI Compute
- [2026-09] "Granular egress policies… across diverse channels such as monitoring, data logs, or core dumps… with a default of no egress." There is "Zero shell access on hardened TPU platform" and no human access "even in 'break glass' emergency scenarios." Analytics go through confidential federated analytics, so only DP aggregates are visible — [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)
- [2026-09] Secure server-side memory:
  - A per-user "memory Oak Server" database runs inside a TEE, written in Rust on the open-source Oak Containers runtime.
  - Records are "encrypted with per-user keys that are never visible outside the Trusted Computing Base."
  - Key release is attestation-gated. Records are decrypted only in volatile enclave RAM, then the session commits new memories re-encrypted and "wipe[s] all volatile prompt context."

  Source: [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)
- [2026-09-23] The blog says keys are "held exclusively on your personal devices," with "per-user databases shielded by device-derived encryption keys." Its diagrams show a KEK, a DEK and a wrapped DEK. The brief instead says the keys are "bound to the user" and "only ever available in plaintext inside an attested TEE" — [DeepMind blog](https://deepmind.google/blog/advancing-private-ai-compute-with-secure-server-side-memory/); [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)

#### Meta Private Processing
- [2026-10-20] The orchestrator has "no database access," and "conversational history is sent to the orchestrator from the client with every request." The predictor "turns off persistent KV Cache" — [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)
- [2026-10-20] Logging: during the "setup phase," from CVM launch until the TLS keypair is generated and linked to the attestation report, "logs can be exported without restriction," and "once completed, the CVM cannot revert to this phase." Afterwards rsyslog routes logs through an `omprog` exporter that applies allowlist filters, and unfiltered `omfile` logs stay inside the TEE — [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)
- [2025-04-29] Remote shell access is prohibited, including from the host, and users are promised an in-app log of requests — [Meta engineering blog](https://engineering.fb.com/2025/04/29/security/whatsapp-private-processing-ai-tools/)

#### NVIDIA, Azure, OpenAI
- [2025-08-14] GPU "performance counters are disabled in full CC-On mode." A "CC-DevTools" mode re-enables them while keeping encryption paths on — [NVIDIA WP v1.3](https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf)
- [v4.0 2025-12-16] Azure: prompts are "not stored, logged, or used for any other purpose such as debugging or training." The filesystem is read-only under dm-verity, with a RAM-disk for scratch — [Azure deep dive](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-confidential-inferencing-technical-deep-dive/4253150)
- [2026-08-19] OpenAI ZDR does not retain prompts or responses, except that images flagged for potential CSAM "will continue to be retained for manual review" — [OpenAI](https://openai.com/index/offering-zero-data-retention-for-frontier-models/)

#### Tinfoil (inference, Containers, Bunkers)
- [live] Inference CVMs have read-only disks and a boot-time ramdisk. Opt-in encrypted volumes become writable only after the customer's key is provided, and they are "not protected against replay of older sectors or restoration of an older copy of the disk" — [Tinfoil attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture)
- [2026-03-10] Containers: "There is no SSH access into the enclave." A debug mode runs in an isolated enclave environment — [Tinfoil Containers](https://tinfoil.sh/blog/2026-03-10-tinfoil-containers)
- [2026-11-19] Bunkers have persistent volumes. They use dm-crypt and dm-integrity directly ("initialize them with fixed values") instead of LUKS, because LUKS metadata can be altered by the host, and randomized IVs in AES-XTS against ciphertext-correlation side channels. The Perimeter's activity log is "very hard to tamper with" — [Tinfoil Bunkers](https://tinfoil.sh/blog/2026-11-19-introducing-tinfoil-bunkers)
- [2026-07-14] Prompt caches live only in GPU VRAM, never on disk, with no explicit expiry — [Tinfoil secure prompt caching](https://tinfoil.sh/blog/2026-07-14-secure-prompt-caching)

#### dstack, Contrast, NEAR
- [live] dstack storage: "the LUKS2 volume carries no authentication tag." ext4 data is not checksummed. "An infrastructure operator can withhold, delete, replace, or restore an earlier valid encrypted disk image," so applications "must anchor a monotonic version" for rollback resistance — [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md)
- [live] dstack development modes, such as KMS `auth_api.type = "dev"`, are visible in measurements or contract state. "Production verifiers should reject deployments that use these development settings." A switch that skipped attestation entirely was "removed rather than documented" — [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md)
- [archived 2026-06-26] NEAR's private-ml-sdk ships a `dstack-nvidia-dev-*` image variant that includes SSH, alongside production images — [nearai/private-ml-sdk](https://github.com/nearai/private-ml-sdk)
- [live] Contrast secure persistence: a LUKS volume whose key is derived from the workload secret. Cloud persistent volumes are treated as untrusted — [Contrast secrets](https://docs.edgeless.systems/contrast/architecture/secrets)
- [2026-11-11] In the NEAR breach the attacker "obtained API keys for two Cloud customers that had been written to logs" — [CSA research note](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/11/CSA_research_note_near_ai_sglang_confidential_inference_breach_20261111-csa-styled.pdf)

### Inferences
- Sidecar enclaves break the PCC-style stateless rule by design: a persistent Debian VM with full tools. The closest proven patterns are:
  - disk keys that only the user's device can supply or unwrap (Apple turn keys, Google device-derived keys);
  - dm-integrity plus dm-crypt with fixed metadata, not host-editable LUKS headers (Tinfoil Bunkers);
  - a monotonic version anchored outside the host to stop rollback (dstack).
- The bundled SSH should be the user's own access path, with keys only the user holds, as in Tinfoil Bunkers' passkey-wrapped keys. It should not be an operator debug path. Any operator debug image should carry distinct measurements that sidecar clients never accept, following Apple's hardened-versus-debug split.
- Enclave telemetry to URnetwork should be allowlisted and enforced by a measured daemon outside the agent's control (Apple `cloudmetricsd`). The NEAR incident shows that credentials logged inside the TEE leak through ordinary logs.

### Gaps
- How Google PAC and Meta handle crash dumps beyond "default no egress" and log filtering is not described.
- Tinfoil Bunkers does not describe disk key custody, sealing or rollback protection.
- Who holds Google's memory KEK (device versus attested TEE) is ambiguous between the brief and the blog.

## 5. How are secrets provisioned into the TEE (key brokers, KMS bound to attestation, sealing), and how does a TEE prove its identity to other services (TLS certs or SSH keys issued after attestation)?

### Takeaway
Three provisioning patterns recur:
- **Key generated in the TEE, never exported, its public half attested.** Apple's SEP-held request key and Key Protection Service VM, Meta's per-request RA-TLS key, Tinfoil's TLS key.
- **Attestation-gated KMS or key broker.** Azure's KMS and Microsoft Azure Attestation, Anthropic's keyserver, CoCo Trustee, Contrast Coordinator, dstack KMS with on-chain policy, Google's memory key release, and Confidential Space or Intel Trust Authority tokens feeding a cloud KMS.
- **A CA that issues identities only after attestation.** Contrast's mesh CA, Google's workload credentials and ALTS, dstack's KMS-signed RA-TLS certificates and ACME at the gateway, and Constellation's SSH CA derived from a cluster secret.

Rentable sandbox products add credential-proxy patterns: Tinfoil Bunkers gives the agent placeholder credentials and swaps in real ones at an attested egress proxy.

### Cited Findings

#### Apple PCC
- [live] Apple silicon: the request key lives in the SEP, bound to sealed registers (see §2). The node identity is a DCIK certificate "issued through the PCC Certificate ceremony process" by the Data Center Attestation CA — [PCC: Apple Silicon Node Attestation](https://security.apple.com/documentation/private-cloud-compute/applesiliconnodeattestation)
- [live] Google Cloud nodes, Key Protection Service:
  - The KEM private key "lives in a dedicated confidential VM" and is held by a Rust module backed by `memfd_secret`. The module copies a key into ordinary memory only for the duration of one decapsulation, then zeroes that copy.
  - Each KEM key is tied to a binding HPKE key generated by the Workload VM. "There is no operation that returns a decapsulated secret in the clear."
  - The verifier checks both VMs' attestations and confirms the binding keys are equal.
  - Keys have lifespans measured on the CVM's monotonic clock.
  - Apple notes the binding "does not provide forward secrecy."

  Source: [PCC: Google Cloud Node Attestation](https://security.apple.com/documentation/private-cloud-compute/googlecloudnodeattestation)
- [live] Hardware identity certificates come from an external issuing service. `CPAgent` "retrieves the issued certificate… refreshing it on a fixed interval" — [PCC: Google Cloud Roots of Trust](https://security.apple.com/documentation/private-cloud-compute/googlecloudrootsoftrust)
- [live] Fixed bug: "A secure-configuration value that selects whether a delegation-eligible tool runs in an isolated Delegated tool calls or locally on the PCC Agent is now attested. Previously, this value was read without attestation" — [PCC Release Notes](https://security.apple.com/documentation/private-cloud-compute/releasenotes)

#### Google
- [2026-09] "Workload credentials are provisioned only upon successful validation of the node's attestation against internal reference values. Failure of validation prevents connection establishment." Memory keys: "an enclave that does not present valid attestation evidence matching an endorsed memory binary cannot obtain the keys" — [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)
- [live] Confidential Space:
  - The verifier, Google Cloud Attestation or Intel Trust Authority, returns attestation results "in the form of identity tokens."
  - Data owners create a workload identity pool provider with attribute conditions. Protected resources, for example Cloud KMS keys, are accessible only when verification passes.
  - Operators have no access to the data and cannot change the workload code or execution environment.
  - Testing uses "a debug version of the Confidential Space image."

  Source: [Confidential Space overview](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/confidential-space-overview)

#### Azure, Anthropic, NEAR
- [v4.0 2025-12-16] Azure's "confidential, transparent KMS… generates and periodically rotates OHTTP keys." The gateway presents an MAA token, and if it satisfies the key release policy it receives the HPKE private key "wrapped under an attested vTPM key." "All changes to the key release policies will be recorded in a transparency ledger." dm-verity root hash and container policy are extended into vTPM PCRs that the KMS checks — [Azure deep dive](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-confidential-inferencing-technical-deep-dive/4253150)
- [2025-06-18] Anthropic's design:
  - A TPM measures boot.
  - A keyserver checks this proof and releases decryption keys only to attested recipients.
  - A secure CI server signs loader programs after multi-engineer review.
  - Third-party keyservers are under exploration.

  Source: [Anthropic](https://www.anthropic.com/research/confidential-inference-trusted-vms)
- [2026-08-12] Intel Trust Authority tokens let downstream systems gate actions; for example, a key management service can release decryption keys only against a valid token — [NEAR AI blog](https://near.ai/blog/near-ai-cloud-integrates-intel-trust-authority)

#### Edgeless Contrast, Privatemode, Constellation; CoCo
- Contrast certificates (search snippet):
  - The Coordinator "is verifier for all workloads… and issues certificates as attestation result" (root, intermediate and mesh CA).
  - The Coordinator rotates the intermediate private key on every manifest update, so "Any change to the manifest requires a new rollout of the services."
  - Workload certificates last one year.

  Source: [Contrast certificates](https://docs.edgeless.systems/contrast/architecture/certificates)
- [live] Contrast secrets:
  - On first start the Coordinator generates a random seed and derives the CA and manifest-history keys from it with HKDF. The seed is returned encrypted to a "seed share owner" key, for recovery.
  - Workload secrets are "deterministically derived from the secret seed and a workload secret ID," "stable across manifest updates and Coordinator recovery."
  - A Vault-compatible transit API is authenticated by mesh certificate.

  Source: [Contrast secrets](https://docs.edgeless.systems/contrast/architecture/secrets)
- [live] Privatemode:
  - The Coordinator provides credentials bound to attestation for key exchange.
  - A Secret Service agrees a prompt encryption key with each client through an attested key exchange, stores each key for a limited time, and releases it only to verified GenAI workers.
  - Worker components: an attestation agent that attests the GPU and marks it ready, an encryption proxy, and read-only integrity-checked weight disks.

  Source: [Privatemode architecture](https://docs.edgeless.systems/continuum/architecture/overview)
- Constellation emergency SSH (repo mirror and commit; search snippet):
  - The master secret derives an Ed25519 SSH CA via HKDF. Nodes' OpenSSH trusts the CA, and `constellation ssh` signs a user's public key with a 24-hour certificate (implemented around March 2025).
  - Stated requirement: "Access must be encrypted end-to-end to protect from CSP snooping."
  - Open points: workers lack the master secret, so the CA must be distributed at join. SSH host certificates were suggested.

  Sources: [Constellation RFC 016 (mirror)](https://git.hackliberty.org/Git-Mirrors/constellation/blame/tag/v2.19.0/rfc/016-node-access.md); [Constellation commit](https://github.com/edgelesssys/constellation/commit/68035cd90bfd07e5ffab1cd81b87ee768baa9ded)
- [2025-12-19] CoCo: the guest Attestation Agent attests to the KBS, the Confidential Data Hub requests resources, and the KBS validates evidence through the AS using RVPS reference values — [CoCo attestation docs](https://confidentialcontainers.org/docs/attestation/)

#### dstack and Phala
- [live] dstack KMS:
  - It runs in its own TEE, verifies TDX quotes before releasing keys, and "Enforces authorization policies defined in on-chain smart contracts — operators cannot bypass these checks."
  - It "Derives deterministic keys bound to each app's attested identity."
  - The KMS root CA public-key hash is extended as the `key-provider` event, binding a workload to one KMS.

  Sources: [dstack README](https://github.com/Dstack-TEE/dstack); [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md)
- [live] dstack identity:
  - "App key release and KMS key handover require verified caller attestation from the RA-TLS client certificate."
  - "Certificate signing verifies the CSR signature and the attestation embedded in the CSR before signing."
  - The TPM key provider "seals its seed to the runtime register (PCR14 on GCP and AWS)."
  - The GPU gate "runs before the app keys are requested, and a failed gate stops the boot before any key is released."

  Source: [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md)
- [live] dstack's limits: "Encrypted environment variables prevent the host from reading your secrets. However, the host can replace encrypted values," so use a pattern like `LAUNCH_TOKEN`. "All keys derive from the KMS root key… a TEE compromise could expose the root key," and an MPC KMS is in development — [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md)
- [archived 2026-06-26] In NEAR's private-ml-sdk, "the KMS is not secure for production use" in the default configuration. The local key provider's keys derive from the SGX sealing key on the provider host and are not resilient to CPU microcode updates — [nearai/private-ml-sdk](https://github.com/nearai/private-ml-sdk)
- [live] Phala's attested workload keyset carries `tls_public_keys` and receipt-signing keys. Responses carry Ed25519 receipts whose request and response hashes must match the bytes sent and received (receipt detail is a search snippet) — [Phala verify attestation](https://docs.phala.com/phala-cloud/confidential-ai/verify/verify-attestation); [Phala verify signature](https://docs.phala.com/phala-cloud/confidential-ai/verify/verify-signature)

#### Tinfoil (Containers, Bunkers)
- [2026-03-10] Containers declare secrets by name in `tinfoil-config.yml`. The injection mechanism is not described — [Tinfoil Containers](https://tinfoil.sh/blog/2026-03-10-tinfoil-containers)
- [2026-11-19] Bunkers:
  - SSH keys are generated by the Tinfoil Terminal site: "we generate new SSH keys, and encrypt them under your PRF passkey" (a system key or a YubiKey). A CLI mode "keeps the private key completely under custody of your ssh-agent."
  - The owner's key hash is bound into the per-enclave config, so "one bunker should never be able to impersonate another."
  - Agents get placeholder credentials. The Perimeter, a separate CVM on physically separate hosts, swaps in real credentials on outbound requests and "If a credential is attempted to be used in an unexpected place, it instantly gets rejected." It covers more than 100 APIs and MCP servers plus SSH, IMAP and Postgres, with Rego policies.

  Source: [Tinfoil Bunkers](https://tinfoil.sh/blog/2026-11-19-introducing-tinfoil-bunkers)

### Inferences
- For sidecar enclaves, three options for SSH host identity are documented elsewhere:
  - (a) a host key generated in the TEE whose hash goes into report data with a client nonce (Meta, Contrast);
  - (b) an attested CA enclave that issues SSH host certificates after attestation (Contrast mesh CA, dstack CSR signing). The client must then verify the CA enclave itself, and Contrast notes the verifying CLI becomes the root of trust;
  - (c) a user-held CA (Constellation emergency SSH).

  Binding the owner's key hash into the measured config (Bunkers) prevents enclave swapping.
- On Bittensor provider hardware, where the operator has physical access, an attestation-gated KMS should not run on the same provider's machines, and release should be conditioned on hardware identity allowlists. This follows Apple's ledger and Contrast's PIID/HWID guidance and is informed by TEE.fail (§6).
- The Bunkers Perimeter pattern fits sidecar's agent harness directly. Real API keys, including keys for the agent's own inference calls, stay outside the agent's reach in a separate attested egress component.

### Gaps
- No primary source describes attestation-bound SSH host keys in production. Tinfoil Bunkers omits the mechanism.
- The Constellation details come from a repository mirror and commit pages, not the current official docs.
- Contrast manifest-history verification and the Coordinator recovery steps were not documented on the pages read.

## 6. What do they explicitly exclude from the threat model, or admit they do not protect (physical attacks, side channels, the model provider, the software inside)?

### Takeaway
Hardware vendors exclude sophisticated physical attacks (NVIDIA, Intel, AMD), and TEE.fail (S&P'26, disclosed October 2025) showed a sub-$1,000 DDR5 interposer that forges Intel TDX quotes and lets a dstack host fake TDX and NVIDIA attestations. Hyperscaler-hosted designs answer with physical security, single tenancy, multi-vendor roots and hardware ledgers (Apple), or CPU allowlists (Meta). Every system admits:
- attestation proves identity, not correctness (NEAR's 2026 SGLang breach inside the confidential environment);
- side channels and streaming traffic analysis remain;
- abuse detection conflicts with privacy;
- model weights and runtimes are often not reproducible or public.

### Cited Findings

#### Vendors and hardware attacks
- [2025-08-14] NVIDIA in-scope threats: "Software attacks, Basic physical attacks, Software rollback attacks, Cryptographical attacks, Data rollback and replay attacks." Out of scope: "Sophisticated physical attacks, Denial of service attacks." A stated goal is that "interposers on buses such as PCIe and DDR memory cannot leak data or code" — [NVIDIA WP v1.3](https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf)
- [2025-08-14] Hopper Protected PCIe is limited to 8-GPU HGX systems, and "data traffic between GPUs over NVLINK remains unencrypted." Blackwell multi-GPU passthrough encrypts NVLink for up to eight GPUs — [NVIDIA WP v1.3](https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf)
- [live] Apple on Blackwell: "model weights and activations sit in high-bandwidth memory that the GPUs isolate from the host but don't encrypt" — [PCC: Google Cloud Node Architecture](https://security.apple.com/documentation/private-cloud-compute/googlecloudnodearchitecture)
- TEE.fail (Chuang, Seto, Berrios, van Schaik, Garman, Genkin; IEEE S&P'26; Intel security announcement 2025-10-28; AMD bulletin AMD-SB-3040):
  - The FAQ says "it should cost you under $1000" to build a similar setup.
  - It recovers Intel's per-CPU provisioning certification key, so forged TDX and SGX quotes are "cryptographically indistinguishable from legitimate ones." A forged quote with bogus measurements passes Intel DCAP verification at the UpToDate level.
  - The SEV-SNP attack works even with Ciphertext Hiding enabled.
  - Demonstrations: BuilderNet; dstack, where a malicious provider could run a workload in a non-confidential VM while forging TDX and NVIDIA attestations; and Secret Network.
  - Intel says interposer attacks "are considered out of the threat model for Intel SGX and TDX," AMD "does not plan to publish any updates to their SEV-SNP firmware," and NVIDIA says "there are no mitigations from the Nvidia CC side."
  - Advice: know which servers you trust and where they are located; do not trust an attestation report without knowing the machine's location.

  Source: [TEE.fail](https://tee.fail/)

#### Apple PCC
- [live] Residual risk: "Software vulnerabilities… one zero-day could reach many nodes at once," and "Hardware subversion… Non-targetability and per-node key custody confine such a node to the requests routed to it" — [PCC threat model](https://security.apple.com/documentation/private-cloud-compute/attacks)
- [live] Open challenges Apple names:
  - "Full-stack confidential computing… Most confidential computing deployments attest only the guest VM, leaving the host unmeasured."
  - Supply chain: "Proprietary firmware binaries, non-reproducible vendor builds, and encrypted microcode limit independent verification."
  - "Traffic analysis of streaming inference."
  - "Abuse detection without surveillance."

  Source: [PCC threat model](https://security.apple.com/documentation/private-cloud-compute/attacks)
- [live] Traditional CVM limits that Apple rejects: "A single vendor's root of trust" and "Side channels out of scope." It mitigates them with bare-metal sole tenancy and dual Titan plus TDX quotes — [PCC: Google Cloud Node Architecture](https://security.apple.com/documentation/private-cloud-compute/googlecloudnodearchitecture)
- [live] Outside the attested set: NICs, PCIe switches and GPU baseboard management, "verified, by Google rather than by Apple" out-of-band. Smart-NIC and PCIe-retimer firmware is "treated as untrusted," with the IOMMU limiting DMA — [PCC: Google Cloud Roots of Trust](https://security.apple.com/documentation/private-cloud-compute/googlecloudrootsoftrust); [PCC: Google Cloud Software Transparency](https://security.apple.com/documentation/private-cloud-compute/googlecloudsoftwaretransparency)
- [live] Model cryptexes are "Codeless cryptexes whose contents are not published," listed as a research target for "data-only attacks" — [PCC VRE](https://security.apple.com/documentation/private-cloud-compute/virtualresearchenvironment)
- [live] Known issue: a script-execution policy identifies Python interpreters by process name, so "a caller can alter its invocation path to avoid policy enforcement" — [PCC Release Notes](https://security.apple.com/documentation/private-cloud-compute/releasenotes)
- [2024-06-10, possibly superseded] The threat model includes a sophisticated attacker with physical access who may subvert some hardware security properties and extract data actively being processed. The defense is economic and probabilistic: a hardened supply chain makes such attacks "prohibitively expensive and likely to be discovered" — [Apple Security blog 2024](https://security.apple.com/blog/private-cloud-compute/)

#### Google and Meta
- [2026-09] Google relies on "best-in-class, multi-layered physical security." TPUs are "comparable to a typical TEE," not a standard TEE. Memory gives up network non-targetability, and client-side verification is future work — [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)
- [2026-10-20] Meta: "vulnerability researchers have demonstrated the ability to bypass TEE guarantees under certain circumstances directly from a host"; "defending against physical access introduces significant complexity"; vendor or PKI compromise is listed as a threat. Prompt injection is acknowledged; Meta says features "do not share any data with anyone else" — [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)
- [2026-10-20] Meta web search: the model forms a query that is "sent in plaintext to Meta infrastructure outside of the TEE" and on to search providers. It is optional, unlinked from identity, and shown in the transparency report — [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)
- [2026-04-07] Trail of Bits found 28 issues, 8 of them high severity. 16 were fixed, 4 partially addressed, and 8 low or informational issues were left as is. On physical attacks, SEV-SNP's threat model does not fully cover advanced attacks; Meta added controls restricting which CPUs are trusted. Fully reproducible CVM images remain hard to achieve — [Trail of Bits](https://blog.trailofbits.com/2026/04/07/what-we-learned-about-tee-security-from-auditing-whatsapps-private-inference/)
- [2025-08] The audit report lists "GPU LLMs do not verify NVIDIA GPU attestation" among its findings (search snippet; remediation status unknown) — [2025-08 security review PDF](https://cyberinsider.com/wp-content/uploads/2026/04/2025-08-meta-whatsapp-privateprocessing-securityreview.pdf)

#### Confidential AI providers
- [live] dstack:
  - "Side-channel attacks… are researched actively."
  - "dstack protects the execution environment, not your application code."
  - Operators "can still deny service."
  - Storage gives no freshness or integrity guarantee.
  - The GPU check is a boot-time statement, with relays possible.
  - On SEV-SNP, the GPU event "is not remotely bound."
  - NitroTPM attestations carry no TCB status.

  Source: [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md)
- [2026-11-11] NEAR AI breach:
  - An SGLang RCE gave the attacker code execution on one inference server, and the attacker "could have observed user requests processed on that server on November 8, including requests submitted in confidential mode."
  - NEAR's own report: "Confidential computing protects data from the operator and the host. It does not protect against a vulnerability in the software running inside the environment."
  - About 100 users' names and emails were exposed, plus data from 18 legacy agents "that ran outside the confidential computing environment."
  - The same research note catalogs SGLang deserialization RCEs (pickle and ZeroMQ, dill, torch.load) throughout 2026.

  Sources: [CSA research note](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/11/CSA_research_note_near_ai_sglang_confidential_inference_breach_20261111-csa-styled.pdf); [The Block](https://theblock.co/news/defi/2026-11-10-near-ai-security-breach-437002)
- [2026-10-15] Brave: browser-side verification is not built yet. Open weights alone cannot rule out malicious weight changes, and the model runtime is not rebuilt. The verification chain depends on Intel, NVIDIA, dstack, Sigstore, GitHub, Hugging Face and public DNS — [Brave blog](https://brave.com/blog/browser-ai-e2ee/)
- [v4.0 2025-12-16] Azure accepts benign side effects (billing, health probes, KV and L3 caching) and says it is researching their risks. Where OpenAI models run proprietary inference code, protection falls back to sandbox properties — [Azure deep dive](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-confidential-inferencing-technical-deep-dive/4253150)
- [2025-06-18] Anthropic: the API server's security is "beyond the scope." Accelerators lack full confidential computing. Physical and hypervisor security rely on compute providers — [Anthropic](https://www.anthropic.com/research/confidential-inference-trusted-vms)
- [live] Tinfoil trusts the AMD, Intel and NVIDIA roots, and its billing backend is closed source — [Tinfoil attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture). [2026-11-19] Bunkers: "access pattern correlation is not covered" — [Tinfoil Bunkers](https://tinfoil.sh/blog/2026-11-19-introducing-tinfoil-bunkers). [2026-07-14] Shared caches leak through timing, and operator-chosen salts fail against a malicious operator — [Tinfoil secure prompt caching](https://tinfoil.sh/blog/2026-07-14-secure-prompt-caching)
- [live] Contrast: the "seed share owner can decrypt data encrypted with secrets derived from the workload secret." A leaked seed means "the deployment should be considered compromised" — [Contrast secrets](https://docs.edgeless.systems/contrast/architecture/secrets)

#### Agent runtimes in TEEs (state of the art)
- Production agent-in-TEE systems found:
  - [live] Apple PCC Agent: production, server-side tool calling.
  - [2026-09] Google PAC memory for "agentic" experiences.
  - [2026-11-19] Tinfoil Bunkers: rentable sandboxes with SSH.
  - [2026-03-10] Tinfoil Containers.
  - [live] dstack CVMs, which run docker-compose apps.

  Sources: [PCC Agent](https://security.apple.com/documentation/private-cloud-compute/pccagent); [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf); [Tinfoil Bunkers](https://tinfoil.sh/blog/2026-11-19-introducing-tinfoil-bunkers); [Tinfoil Containers](https://tinfoil.sh/blog/2026-03-10-tinfoil-containers); [dstack README](https://github.com/Dstack-TEE/dstack)
- [live] PCC Agent:
  - Tools the agent does not implement go "to the user's device to execute locally."
  - Delegated tools run on separate attested worker nodes for "security isolation."
  - External tools go through a single tool gateway outside the boundary, using an MCP-like JSON-RPC over gRPC with "tool enumeration… not supported."
  - Each external call is logged and streamed end-to-end encrypted to the device's Apple Intelligence Report (`outboundCalls`).

  Source: [PCC Agent](https://security.apple.com/documentation/private-cloud-compute/pccagent)
- Research only:
  - [2025-12, v2 2025-12-13] Omega runs many agents in one CVM with nested isolation, "differential attestation" and supervised external interactions, on SEV-SNP plus H100 — [arXiv 2512.05951](https://arxiv.org/abs/2512.05951)
  - AgenTEE (EuroMLSys'26, Arm CCA) runs mutually attesting agent, LLM and app CVMs on edge devices (search snippet) — [AgenTEE](https://www.cs.dartmouth.edu/dfk/research/abdollahi-agentee/index.html)
  - A May 2026 survey lists compound attestation for multi-hop agent chains as an open problem (search snippet) — [arXiv 2605.03213](https://arxiv.org/abs/2605.03213)

### Inferences
- Bittensor TEE providers are exactly the "malicious operator with physical access" that Intel, AMD and NVIDIA exclude, and TEE.fail demonstrated the attack against dstack-style deployments. The sidecar design should therefore:
  - treat provider attestations as weaker than hyperscaler ones;
  - consider per-provider hardware-ID allowlists, as Meta restricts trusted CPUs and Apple keeps a hardware ledger;
  - keep high-value secrets, such as user disk keys and long-lived credentials, out of provider-hosted TEEs where possible.
- The NEAR breach shows that the agent harness and the inference engine inside a sidecar enclave are the main attack surface. Mitigations that already exist: per-request isolation and recycling (Apple), no credentials in logs, a separate key-holding VM (Apple Key Protection Service) and an egress credential proxy (Tinfoil Perimeter).

### Gaps
- The DDRop write-interposer attack, said to forge TDX attestation, appeared only in a secondary search summary and was not verified against a primary source.
- No source quantified how much of the Bittensor TEE provider fleet runs in physically secured hyperscaler data centers versus self-hosted machines. That is out of scope for this note.
- Whether Meta's predictor now verifies GPU attestation, the August 2025 finding, was not confirmed.

## 7. Which patterns recur across these systems, and which pitfalls does each system call out?

### Takeaway
Eleven patterns are shared by at least two independent production systems. The pitfalls cluster around unmeasured inputs, missing freshness, TCB levels self-reported by the platform rather than taken from the vendor certificate, unbound GPU evidence, host-editable storage metadata, logs, and bugs inside the attested software.

### Cited Findings

#### Recurring patterns
1. **The client verifies first and fails closed, with vendor roots and minimum TCBs pinned in client code.** Apple, Meta and Tinfoil — [PCC: Google Cloud Node Attestation](https://security.apple.com/documentation/private-cloud-compute/googlecloudnodeattestation); [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper); [Tinfoil attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture)
2. **A public append-only log of measurements, checked by inclusion proof on the client, with split-view protection and key configurations logged too.** Apple (Merkle log, MASQUE proxies, OHTTP and token keys logged), Meta (third-party log, 3-hour revocation lists, 24-hour signatures), Tinfoil (Sigstore/Rekor), Azure (signed ledger), Google (ledger, witnessed log planned) — [PCC: Release Transparency](https://security.apple.com/documentation/private-cloud-compute/releasetransparency); [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper); [Tinfoil attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture); [Azure deep dive](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-confidential-inferencing-technical-deep-dive/4253150); [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)
3. **Reproducible, published images plus researcher environments, with debug images measured separately and never accepted.** Apple (VRE, Google Cloud research environment, debug versus hardened images), Meta (auditable artifacts), Tinfoil, dstack, Google memory server (open source) — [PCC VRE](https://security.apple.com/documentation/private-cloud-compute/virtualresearchenvironment); [PCC: Google Cloud Debug and Hardened Images](https://security.apple.com/documentation/private-cloud-compute/appendix_googleclouddebugandhardenedimages); [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md); [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)
4. **Measure everything that is loaded.** Config hash on the kernel command line, weights by dm-verity root hash, compose-hash and init scripts in RTMR3, container policy in a vTPM PCR, ACPI tables signed — [Tinfoil attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture); [dstack TDX attestation guide](https://github.com/Dstack-TEE/dstack/blob/master/docs/attestation-tdx.md); [Azure deep dive](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-confidential-inferencing-technical-deep-dive/4253150); [Trail of Bits](https://blog.trailofbits.com/2026/04/07/what-we-learned-about-tee-security-from-auditing-whatsapps-private-inference/)
5. **Encrypt to an attested key, or terminate TLS inside the TEE with the key bound in report data plus a client nonce.** Intermediaries see only ciphertext — [PCC: Attested Request Handling](https://security.apple.com/documentation/private-cloud-compute/requesthandling); [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper); [Contrast attestation overview](https://docs.edgeless.systems/contrast/architecture/attestation/overview); [Brave blog](https://brave.com/blog/browser-ai-e2ee/)
6. **Non-targetability stack.** Third-party OHTTP relays, unlinkable tokens from a separate issuer, an identity-blind gateway that offers candidate nodes, a client-capped candidate count, and logged key configurations — [PCC: Anonymous Request Routing](https://security.apple.com/documentation/private-cloud-compute/requestflow); [PCC: Non-Targetability](https://security.apple.com/documentation/private-cloud-compute/nontargetability); [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf); [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)
7. **Stateless by default; state only under user-held or user-supplied keys.** Ephemeral boot keys, per-request processes, recycling, device-supplied turn keys, per-user memory keys — [PCC: Stateless Computation](https://security.apple.com/documentation/private-cloud-compute/statelesscomputation); [PCC: Multi-Turn Agent](https://security.apple.com/documentation/private-cloud-compute/multiturnagent); [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)
8. **No privileged runtime access.** No SSH or shell in production, allowlisted telemetry enforced in a measured daemon, redacted and rate-limited crash data, no break-glass — [PCC: Management and Observability](https://security.apple.com/documentation/private-cloud-compute/management); [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf); [Meta engineering blog](https://engineering.fb.com/2025/04/29/security/whatsapp-private-processing-ai-tools/); [Tinfoil Containers](https://tinfoil.sh/blog/2026-03-10-tinfoil-containers)
9. **Attestation-gated key release, and identities issued only after attestation.** KMS or key broker, CA, workload credentials — [Azure deep dive](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-confidential-inferencing-technical-deep-dive/4253150); [Contrast secrets](https://docs.edgeless.systems/contrast/architecture/secrets); [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md); [Confidential Space overview](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/confidential-space-overview); [Anthropic](https://www.anthropic.com/research/confidential-inference-trusted-vms)
10. **Transitive trust through attested intermediaries.** Apple proxy nodes verify workers against the device's log revision; the Tinfoil router verifies model enclaves; Google uses mutually attested ALTS chains — [PCC: Transitive Trust](https://security.apple.com/documentation/private-cloud-compute/transitivetrust); [Tinfoil attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture); [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf)
11. **User-visible transparency of what left the boundary.** Apple Intelligence Report `outboundCalls`, Meta's in-app report and visible search terms, Pixel Network Logs, Azure receipts — [PCC Agent](https://security.apple.com/documentation/private-cloud-compute/pccagent); [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper); [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf); [Azure deep dive](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-confidential-inferencing-technical-deep-dive/4253150)

#### Pitfalls each system calls out
- **Apple PCC:**
  - certificate-log inclusion not yet enforced;
  - interpreter policy bypassable by path;
  - an unattested config value could have moved a tool out of isolation (fixed);
  - a content-dependent metric (recitation-block count) leaked (fixed);
  - cost-token signing keys not yet logged;
  - Google Cloud preview "ramping";
  - streaming traffic analysis, supply-chain opacity, and abuse detection are open problems;
  - HBM is unencrypted on Blackwell.

  Sources: [PCC Release Notes](https://security.apple.com/documentation/private-cloud-compute/releasenotes); [PCC threat model](https://security.apple.com/documentation/private-cloud-compute/attacks); [PCC: Google Cloud Node Architecture](https://security.apple.com/documentation/private-cloud-compute/googlecloudnodearchitecture)
- **Google PAC:** clients do not yet verify attestation themselves; the ledger is not yet independently witnessed; stateful memory gives up network non-targetability; TPUs are "comparable to" a TEE rather than one; the 2025 audit excluded SEV-SNP and the apps (search snippet) — [Google PAC brief](https://services.google.com/fh/files/misc/private_ai_compute_technical_brief.pdf); [NCC Group report](https://www.fox-it.com/media/cbuhuhuu/ncc_group_google_e025353p_report_2025-11-08_v14.pdf)
- **Meta Private Processing:**
  - unmeasured environment variables: with an injected `LD_PRELOAD`, "The attestation would still verify as valid";
  - unmeasured ACPI tables;
  - TCB level taken from the report instead of the VCEK certificate;
  - no freshness, so reports were replayable;
  - physical attacks;
  - reproducibility;
  - the transparency log is not a Merkle tree;
  - models and system prompts are private;
  - web search queries leave the TEE in plaintext;
  - setup-phase logs "can be exported without restriction."

  Sources: [Trail of Bits](https://blog.trailofbits.com/2026/04/07/what-we-learned-about-tee-security-from-auditing-whatsapps-private-inference/); [Meta white paper V3](https://ai.meta.com/static-resource/private-processing-technical-whitepaper)
- **NVIDIA:**
  - sophisticated physical attacks and DoS are out of scope;
  - Hopper NVLink is unencrypted;
  - DevTools mode re-enables performance counters, a side-channel avenue;
  - GPU reports are not bound to a CVM, so relays are possible;
  - TDISP binding cannot be verified on current deployments.

  Sources: [NVIDIA WP v1.3](https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf); [TEE.fail](https://tee.fail/); [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md)
- **Tinfoil:**
  - encrypted volumes have no rollback protection;
  - OHTTP hides who, not what;
  - shared prompt caches leak via timing, and operator-chosen salts are insufficient;
  - Bunkers do not cover access-pattern correlation;
  - LUKS headers are host-alterable, hence raw dm-crypt plus dm-integrity;
  - billing and backend are closed and see API keys.

  Sources: [Tinfoil attestation architecture](https://docs.tinfoil.sh/verification/attestation-architecture); [Tinfoil: Oblivious Is Not Always Private](https://tinfoil.sh/blog/2025-05-10-ohttp); [Tinfoil secure prompt caching](https://tinfoil.sh/blog/2026-07-14-secure-prompt-caching); [Tinfoil Bunkers](https://tinfoil.sh/blog/2026-11-19-introducing-tinfoil-bunkers)
- **Edgeless Contrast and Privatemode:** the CLI is the root of trust; relay attacks require pinning PIID or HWID; the seed-share owner can decrypt; a lost seed means lost data; manifest changes rotate the mesh CA and force rollouts; AES-GCM nonce limits apply to the transit engine — [Contrast attestation overview](https://docs.edgeless.systems/contrast/architecture/attestation/overview); [Contrast secrets](https://docs.edgeless.systems/contrast/architecture/secrets); [Contrast certificates](https://docs.edgeless.systems/contrast/architecture/certificates)
- **CoCo Trustee:** the key broker and attestation service must themselves run in a trusted environment — [CoCo attestation docs](https://confidentialcontainers.org/docs/attestation/)
- **dstack and Phala:**
  - attestation is not correctness;
  - the host can swap encrypted environment variables;
  - `pre_launch_script` is not a launch gate;
  - the KMS root key is a single point of failure;
  - disks lack integrity and rollback protection;
  - GPU checks are boot-time only;
  - SEV-SNP lacks a runtime register for GPU binding;
  - development switches must be rejected by verifiers;
  - Phala's gateway attestation does not cover upstream model enclaves;
  - a quote does not verify a response, so verify receipts;
  - TEE.fail forged TDX and NVIDIA attestations against dstack.

  Sources: [dstack security model](https://github.com/Dstack-TEE/dstack/blob/master/docs/security/security-model.md); [Phala verify attestation](https://docs.phala.com/phala-cloud/confidential-ai/verify/verify-attestation); [TEE.fail](https://tee.fail/)
- **NEAR AI:** an RCE in the inference engine inside the confidential environment; API keys written to logs; legacy agents outside the TEE; the SDK's local KMS is not for production; Intel Trust Authority moves the trust anchor to Intel — [CSA research note](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/11/CSA_research_note_near_ai_sglang_confidential_inference_breach_20261111-csa-styled.pdf); [nearai/private-ml-sdk](https://github.com/nearai/private-ml-sdk); [NEAR AI blog](https://near.ai/blog/near-ai-cloud-integrates-intel-trust-authority)
- **Brave:** verification is server-side today; the model runtime is not rebuilt; open weights do not prove integrity; there is a long dependency chain — [Brave blog](https://brave.com/blog/browser-ai-e2ee/)
- **Azure:** accepted side effects (billing, probes, KV and L3 caching); proprietary inference code is only sandboxed; public coverage remains Whisper-only (search snippet) — [Azure deep dive](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-confidential-inferencing-technical-deep-dive/4253150); [Azure product overview](https://learn.microsoft.com/azure/confidential-computing/overview-azure-products)
- **Anthropic:** the API server handles cleartext; accelerators lack confidential computing; providers are trusted for physical and hypervisor security — [Anthropic](https://www.anthropic.com/research/confidential-inference-trusted-vms)
- **OpenAI:** its public ZDR "Private Safety Processing" is not a TEE design; no confidential-inference technical detail was published as of the 2026-09-22 update — [OpenAI](https://openai.com/index/offering-zero-data-retention-for-frontier-models/)

### Inferences
- The patterns that matter most for sidecar's two features:
  - **TEE-routed inference:** 1, 2, 5, 6, 9 and 10, plus Apple's projection-to-release-digest method for heterogeneous providers.
  - **Rentable agent enclaves:** 3, 4, 8 and 9, plus:
    - Tinfoil Bunkers' owner-key-in-config binding and egress credential proxy;
    - Apple PCC Agent's rule of keeping tools inside the boundary by default and logging every boundary crossing to the user;
    - dstack and Tinfoil's documented storage caveats.
- The most transferable pitfall checklist for a sidecar verifier is Trail of Bits' list: measure every loaded input; take TCB levels from the vendor certificate, not the report; require a fresh nonce bound to the channel; test negatively. Add dstack's GPU-binding and storage caveats, and TEE.fail's physical-location warning for operator-hosted hardware.

### Gaps
- No public production system was found that combines all four of rentable per-user TEE VMs, attested SSH, client-held disk keys, and operator-blind networking. Tinfoil Bunkers (2026-11-19) is the closest, but its key-binding and storage-key details are unpublished.
- Microsoft's open-source attested-OHTTP client and server, OpenPCC's white paper and anonymous-payment design, and Google's anonymous-token protocol were not read and may hold further reusable components.
