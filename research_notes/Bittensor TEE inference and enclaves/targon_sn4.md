# Targon (Bittensor SN4, Manifold Labs): TEE inference and confidential VMs, state as of 2026-11-23

Labels on each finding: **[live]** = my own request to a public endpoint on 2026-11-23 (about 07:25 UTC); **[doc]** = Targon or Manifold documentation; **[code]** = public source code; **[mkt]** = marketing page, blog, or X post (a claim, not proof); **[3rd]** = independent or secondary source. Anything dated before mid-2026 is marked "(possibly superseded)". X post dates were decoded from the post IDs.

## 1. What does Targon offer today, on which hardware, which parts run in a TEE, and can a client insist on a TEE?

### Takeaway
As of November 2026 Targon is a GPU/CPU cloud, not an inference API. It sells confidential VMs (`type=vm`, Intel TDX GPU VMs and AMD SEV CPU and B300 VMs, all flagged `cc_enabled: true`), plus bare metal and sandboxes, which are **not** confidential. The old OpenAI-compatible inference API at `api.targon.com/v1` answers **HTTP 410 Gone**. TEE-ness depends on product type: every `vm` SKU is confidential and nothing else is. Nothing a client can check cryptographically enforces it, because Targon exposes no attestation to customers.

### Cited Findings
- **Product line today [mkt, 2026-11-23]:** the targon.com homepage lists Virtual Machines ("On-demand GPU and CPU VMs with SSH access", up to eight GPUs per VM), Bare Metal, Sandboxes, Reserved Capacity (through sales), and "Confidential VMs" that run inside Intel TDX trust domains. It states "Bare metal servers are not confidential." It does not mention serverless or an inference API. — [targon.com](https://targon.com/)
- **Docs framing [doc]:** "Virtual Machines: Confidential GPU VMs with Intel TDX and direct SSH"; "Bare Metal: Dedicated physical servers by region with direct SSH"; "Sandboxes: Short-lived isolated environments with terminal and desktop access." — [docs.targon.com](https://docs.targon.com/)
- **VM = full VM, not a container [doc]:** a VM is "a full VM running on the Targon Virtual Machine (TVM) platform—not a container"; Intel TDX encrypts it and "NVIDIA PCIe Confidentiality" protects GPU work. **VMs are beta**: the page warns of "potential data loss" and says VMs may be out of stock. — [VM guide](https://docs.targon.com/guides/virtual-machines)
- **Live inventory, TEE flag per SKU [live]:** `GET https://api.targon.com/tha/v3/inventory` (no auth needed) returns 17 SKUs. All 12 `type: "vm"` SKUs have `spec.cc_enabled: true`. The 3 sandbox SKUs have `cc_enabled: false`. The 2 bare-metal SKUs have `cc_enabled: null`. GPU VMs report `cpu_vendor: INTEL`, except `b300-xlarge-amd`. CPU-only VMs are `cpu-*-amd` with `cpu_model: EPYC-v4`. — [api.targon.com/tha/v3/inventory](https://api.targon.com/tha/v3/inventory)
- **Hardware behind the VMs [live]:** miner "auctions" on `tower.targon.com/api/v2/auctions` name the confidential compute classes: `TDX-VM-NVIDIA-{H100,H200,B200,B300,RTX6000B}`, `SEV-VM-NVIDIA-B300`, `SEV-VM-CPU`, `SEV-CPU-AMD-EPYC-V4`, and `TDX-{HOPPER,BLACKWELL}-NVIDIA-*`. — [tower auctions](https://tower.targon.com/api/v2/auctions)
- **Supported provider hardware [doc/code, repo docs updated 2026-11-09]:** TargonOS installs only on these profiles. Intel TDX: `h100-8x-intel`, `h200-8x-intel`, `b200-8x-intel`, `b300-8x-intel`, `rtxp6000b-8x-intel`, and `cpu-intel` (no GPU, at least 477 GiB RAM and 48 threads). AMD SEV-SNP: `b300-8x-amd`, `rtxp6000b-8x-amd`, `cpu-amd`. GPU profiles need exactly 8 GPUs, a TPM 2.0, and the TEE enabled in BIOS. — [miner.md](https://github.com/manifold-inc/targon/blob/main/docs/miner/miner.md), [installing-targonos.md](https://github.com/manifold-inc/targon/blob/main/docs/miner/installing-targonos.md)
- **AMD support is new [code]:** repo commits "add hardware profiles" (2026-09-23) and "update docs; add amd profile" (2026-10-16). — [manifold-inc/targon commits](https://github.com/manifold-inc/targon/commits/main)
- **GPU TEE mode [doc]:** the Manifold/Intel whitepaper says GPUs run in NVIDIA Protected PCIe (PPCIe) mode and are passed through to the CVM, with NVIDIA nvtrust attestation every interval. — [Intel whitepaper](https://www.manifold.inc/releases/intel-whitepaper)
- **What PPCIe protects [3rd, NVIDIA docs]:** host-to-GPU transfers use an encrypted bounce buffer over PCIe, but "GPU-GPU communications over the NVLink or NVSwitch interconnect are not encrypted". PPCIe supports only the configuration where all eight GPUs and four NVSwitches pass through to one VM. Single-GPU "SPT" CC mode passes one GPU to each CVM. — [NVIDIA PPCIe intro](https://docs.nvidia.com/attestation/attestation-client-tools-ppcie/latest/ppcie_introduction.html), [NVIDIA CC r590 release notes](https://docs.nvidia.com/confidential-computing/release-notes/r590-trd1.md), [arXiv 2507.02770](https://arxiv.org/pdf/2507.02770)
- **Timeline:**
  - 2025-03-31: TVM architecture announced as Targon v6. — [X @manifoldlabs](https://x.com/manifoldlabs/status/1906786140579058096), [Targon v6](https://www.manifold.inc/releases/targon-v6) (possibly superseded)
  - 2025-10-28: "Secure Targon Compute" launched, renting H200 GPU and CPU nodes secured by TVM. 2025-10-31: Ubuntu image. 2025-11-04: persistent volumes. — [iq.wiki, last edited 2026-07-18](https://iq.wiki/wiki/targon) [3rd]
  - 2025-12-10: TVM "released", "powered by NVIDA PPCIe, Intel TDX Encryption, and AMD SEV Encryption" [mkt]. — [X @manifoldlabs](https://x.com/manifoldlabs/status/1998812954125545695)
  - 2026-03-23: joint whitepaper with Intel. — [X @TargonCompute](https://x.com/TargonCompute/status/2036151401684856896)
  - Sept 2026: Bare Metal and Sandboxes added. — [subnetalpha.ai](https://subnetalpha.ai/subnet/targon/) [3rd]
  - 2026-11-11: SDK v4.0.0 removed the `rental`, `storage`, and `serverless` inventory types and the Rental and Volume APIs. — [targon-sdk CHANGELOG](https://github.com/manifold-inc/targon-sdk/blob/main/CHANGELOG.md)
- **Earlier containers-vs-VMs framing, now superseded [mkt, ~March 2026]:** the TargonOS post said TVM (Intel TDX, "Enterprise" tier) "provisions containers rather than full virtual machines". It described TargonOS ("Community" tier, TPM-based, consumer GPUs allowed, "does not match TDX-level guarantees") as provisioning "fully encrypted virtual machines" with root and dedicated IPs. — [TargonOS post](https://www.manifold.inc/releases/targon-os). By 2026-11 the miner docs say TargonOS "replaces the previous provisioning flow (manual host OS preparation + the TVM installer)" and requires TDX or SEV-SNP **and** a TPM. — [miner.md](https://github.com/manifold-inc/targon/blob/main/docs/miner/miner.md)
- **Inference API gone [live]:** `GET https://api.targon.com/v1/models` and `POST https://api.targon.com/v1/chat/completions` both return `HTTP/2 410` with an empty body. The new control-plane API identifies itself as `{"name":"Targon Hub API - (Carnage)","version":"v4.4.0","buildDate":"2026-11-06..."}`. — [api.targon.com/v1/models](https://api.targon.com/v1/models), [api.targon.com/tha/v3/version](https://api.targon.com/tha/v3/version)
- **When the API went away [3rd]:** a latency monitor reports "the API host answers HTTP 410 Gone from 4 of 4 regions". Its earliest retained history (2026-08-24 18:53 UTC) already shows only 410s, and it lists "no shutdown notice from Targon … on record". — [llmlatency.dev/provider/targon](https://llmlatency.dev/provider/targon)
- **Conflicting secondary sources** still describe Targon as an inference API at `https://api.targon.com/v1`. — [api-evangelist/targon](https://github.com/api-evangelist/targon), [opentao.ai](https://opentao.ai/beginner/subnets/4-targon/). The live probes contradict them.
- **Hard failure on attestation (design claim) [doc]:** the system "is designed to halt VM launch if attestation fails, leaving the disk encrypted"; the homepage says "If attestation fails, the disk stays encrypted." — [Intel whitepaper](https://www.manifold.inc/releases/intel-whitepaper), [targon.com](https://targon.com/)
- **No confidentiality switch in the API [doc]:** the workload create body has `type` (`SANDBOX`/`VM`/`BM`), `image`, `resource_name`, `ports`, `ssh_keys`, `vm_config`, and so on, but no confidential/TDX flag and no attestation fields. — [Workloads API](https://docs.targon.com/api/workloads)

### Inferences
- A client can make "TEE or nothing" a hard rule only by policy: create only `type: VM` workloads whose `resource_name` has `cc_enabled: true` in inventory, and never fall back to `BM` or `SANDBOX`. The proof is Targon's API saying so, not evidence the client checks.
- Since the 2026-11-11 SDK release dropped "serverless", Targon's only route to TEE inference is renting a confidential GPU VM and running your own inference server (vLLM, SGLang) inside it.
- The TEE model has two layers. Per-node CPU TEE (TDX or SEV-SNP) plus per-GPU NVIDIA CC. On 8-GPU nodes in PPCIe mode, GPU-to-GPU NVLink traffic is plaintext, so the security assumes the HGX baseboard is physically trusted.

### Gaps
- No official notice of when or why the `api.targon.com/v1` inference API was retired (sometime before 2026-08-24).
- Not documented: how the 1-GPU "small" VMs (SHARED network) are carved from 8-GPU nodes (SPT CC mode per GPU, or PPCIe with something nested). The answer decides which GPU protection mode a small VM gets.
- Whether the AMD CPU VMs use full SEV-SNP. Only the "SEV" auction names and the `cpu-amd` SEV-SNP hardware profile suggest it.

## 2. What can a remote client verify by itself, and who sees plaintext at each hop?

### Takeaway
A Targon customer cannot verify anything themselves today. There is no customer-facing attestation endpoint. Expected measurements are not published. The only verifier is Manifold's closed `tower.targon.com`, and in the whitepaper design Targon's KBS holds each VM's disk key. Customer-side verification was listed as "future work" in March 2026. Targon's design keeps the **miner host** out of the trust boundary, but **Manifold/Targon (KBS, tower, image builder, control plane) stays inside it**. Nothing in the report data binds a TLS key or a customer key.

### Cited Findings
- **Customer verification is future work [doc, ~2026-03-23]:** "Future work will explore a user-facing approach for independently verifying the confidential execution state of CVMs." — [Intel whitepaper](https://www.manifold.inc/releases/intel-whitepaper)
- **No attestation in the customer API [doc, 2026-11]:** the Workloads API page has no attestation endpoints or fields, and no confidential/TDX flags. — [Workloads API](https://docs.targon.com/api/workloads). The VM guide has no attestation section. — [VM guide](https://docs.targon.com/guides/virtual-machines)
- **The only customer "verify" call [doc/code]:** `POST /tha/v3/orgs/{org_slug}/workloads/verify` with `{"uid","digest"}` returns `{"verified": bool}`, which "reports whether digest matches the SHA-256 of the workload image". Targon's server computes this answer; it is not hardware evidence. — [Workloads API](https://docs.targon.com/api/workloads), [targon-sdk libs/go/workload.go](https://github.com/manifold-inc/targon-sdk/blob/main/libs/go/workload.go)
- **Boot and key-release flow [doc, whitepaper ~2026-03]:**
  1. Targon clones a golden Ubuntu 24.04 + NVIDIA image and encrypts it with a random per-VM disk key. The pipeline precomputes the expected TDX boot-chain measurement and stores it in the KBS with the key.
  2. At early boot, a "Manifold Attestation Agent" in the initramfs collects TDX measurement registers and makes a quote.
  3. The quote goes to the Targon KBS, which forwards it to Intel Trust Authority (ITA). ITA returns a signed JWT.
  4. The KBS checks the JWT, the measurements, and the embedded NVIDIA report, then releases the key, bound to the agent and CVM instance.
  5. Validators do not call ITA themselves; they relay packages to the KBS.
  6. The NVIDIA attestation report and node metadata are embedded in the TDX quote's user-data field ("unified attestation").
  7. Validators issue a nonce for each re-attestation, about every 72 minutes.
  8. The KBS records the source IP at first attestation; if it changes, "the existing CVM becomes permanently inaccessible."
  — [Intel whitepaper](https://www.manifold.inc/releases/intel-whitepaper)
- **Whitepaper threat model [doc]:** the adversary has full physical and OS/hypervisor control and can see all network traffic. Trusted: TDX, NVIDIA CC, and ITA. "No trust is placed in providers, host OS or hypervisor, validators, or network transport." Out of scope: side channels outside vendor threat models, denial of service, and compromise of ITA or NVIDIA root keys. Physical attacks such as TEE.fail are not discussed. — [Intel whitepaper](https://www.manifold.inc/releases/intel-whitepaper)
- **Evidence endpoint on nodes [code, repo HEAD 2026-11-09]:** validators call `POST http://{nodeIP}:8980/api/v1/evidence` (fallback port 8080) over **plain HTTP**, body `{"nonce": ...}`, with Epistula headers signed by a Bittensor hotkey. The response is:
  - `quote`
  - `user_data`: `gpu_cards`, `cpu_cards`, `node_type`, `attestation.gpu_remote{attestation_result,token,valid}`, `attestation.switch_remote{...}`, `auction_name`, `nonce`, `cvm_id`, `quote_type`, `ram_bytes`, `storage_bytes`, `version`
  - optional `tpm{ak_pub_hex, quote_hex, quote_signature_hex, pcrs_hex}`

  — [internal/attest/cvm/cvm.go](https://github.com/manifold-inc/targon/blob/main/internal/attest/cvm/cvm.go), [internal/attest/types.go](https://github.com/manifold-inc/targon/blob/main/internal/attest/types.go)
- **Validators do not verify quotes locally [code]:** the validator checks only that `nonce` equals `user_data.nonce`. It then POSTs `{"attestation":..., "ip_address":...}` to `https://tower.targon.com/api/v1/verify-attestation`, or to `/api/v2/verify-attestation` when TPM evidence is present and version is 2, and accepts tower's `{valid, error}`. `TowerURL = "https://tower.targon.com"` is hard-coded. The `sn4 attest --ip/--uid` CLI ("Manually attest a miner or ip address") uses the same tower path. — [cvm.go](https://github.com/manifold-inc/targon/blob/main/internal/attest/cvm/cvm.go), [consts.go](https://github.com/manifold-inc/targon/blob/main/internal/validator/setup/consts.go), [cli/attest/root.go](https://github.com/manifold-inc/targon/blob/main/internal/cli/attest/root.go)
- **GPU attestation verifier [code]:** `manifold-inc/targon-nvidia-attest` is a Python FastAPI `/attest` service that wraps NVIDIA's `nv_attestation_sdk`. It does remote verification against NVIDIA NRAS (`https://nras.attestation.nvidia.com/v3/attest/gpu` and `/v3/attest/switch`), with OCSP and RIM services, a nonce, and JWT policies (`gpu_remote_policy.json`, `switch_remote_policy.json`). No license file; last push 2026-01-09. — [targon-nvidia-attest](https://github.com/manifold-inc/targon-nvidia-attest)
- **Host hardening by providers [doc]:** the TDX BIOS settings Targon requires include `Memory Integrity → Disable`, TME-MT on, SGX on, and a non-zero TDX key split. The installer checks hardware against `tower.targon.com`, verifies minisign signatures, and says these endpoints "are pinned inside the signed installer and cannot be pointed elsewhere". — [installing-targonos.md](https://github.com/manifold-inc/targon/blob/main/docs/miner/installing-targonos.md)
- **Independent assessment [3rd, 2026-10-21]:** pragma.vision rates Targon "Watch". Claimed 55 vs verified 35. Findings:
  - "Selected tenant attestations work, but physical tampering can undermine TDX protection and trusted measurements."
  - Guest attestation does not establish the host memory-integrity mode.
  - Signed workload commitments do not prove the declared code ran.
  - NVSwitch falls outside the published GPU attestation.
  - Fabricated benchmark figures were retracted.

  Recommendation: "constrained use". — [pragma.vision](https://pragma.vision/observe/targon-sn4). Conflict: the Targon code does request NVSwitch attestation (`switch_remote`) — [types.go](https://github.com/manifold-inc/targon/blob/main/internal/attest/types.go). NVIDIA confirms NVLink/NVSwitch traffic is unencrypted in PPCIe mode — [NVIDIA r590 notes](https://docs.nvidia.com/confidential-computing/release-notes/r590-trd1.md).
- **Physical-attack context [3rd, Oct 2025]:** TEE.fail uses a DDR5 bus interposer costing under $1,000. It extracted keys from Intel's Provisioning Certification Enclave, which breaks SGX/TDX attestation, and forged TDX attestations. It also passed NVIDIA CC attestation while running workloads with no TEE protection. Intel and AMD treat physical attacks as out of scope. — [The Hacker News](https://thehackernews.com/2025/10/new-teefail-side-channel-attack.html), [SecurityWeek](https://www.securityweek.com/new-attack-targets-ddr5-memory-to-steal-keys-from-intel-and-amd-tees), [Georgia Tech](https://scp.cc.gatech.edu/external-news/teefail-breaking-trusted-execution-environments-ddr5-memory-bus-interposition)
- **Marketing claims [mkt]:** host OS, hypervisor, and machine owner are "outside the trust boundary" — [targon.com](https://targon.com/). The host operator "can't see your data, your model weights, or your code"; "Even a compromised host kernel cannot read memory" — [TargonOS post](https://www.manifold.inc/releases/targon-os).

### Inferences
Hop-by-hop plaintext visibility for a Targon confidential VM. This table is my synthesis; the sources are the findings above.

| Hop | What that party can see | Basis |
|---|---|---|
| Client → `api.targon.com` (HTTPS control plane) | Targon sees account, org, SSH **public** keys, image choice, ports, hostname, billing. No workload data. | API docs |
| Targon platform (image builder, KBS, tower, ITA client) | Builds the VM image, holds the per-VM disk key and expected measurements, and alone decides attestation validity. So Manifold can technically decrypt or alter disks it keyed. **Trusted party.** | whitepaper, code |
| Validator (third party) | Attestation metadata only: node IP, GPU/CPU IDs, nonce, tokens. No workload data. Uses plain HTTP to nodes; integrity relies on quote signatures plus nonce. | code |
| Miner host OS / hypervisor | Cannot read VM memory (TDX/SEV-SNP) or disk (LUKS, key released only after attestation). **Sees every network packet of the VM**, plus timing and volume. | whitepaper; TEE.fail limits this against physical attackers |
| Miner network / uplink | All VM ingress and egress. Plaintext unless the workload encrypts it (SSH, TLS, WireGuard). | VM guide: public IP is the node's |
| SSH session | Ends at sshd inside the VM (user `ubuntu`). The host sees ciphertext. The SSH host key is **not** tied to attestation, so the first connect is trust-on-first-use against a host that controls the network. | VM guide; no customer attestation |
| Inside the TEE (CVM) | Plaintext; customer workload and keys. | — |
| CPU ↔ GPU (PCIe) | Encrypted bounce buffers in CC/PPCIe mode; GPU memory protected. | NVIDIA docs |
| GPU ↔ GPU (NVLink/NVSwitch, 8-GPU VMs) | **Plaintext** in PPCIe mode; the baseboard is assumed physically trusted. | NVIDIA docs |
| Physical attacker with DIMM access (the miner) | Out of Targon's and Intel/AMD's threat model; TEE.fail-class attacks have forged TDX quotes. TDX hosts run with Memory Integrity disabled. | TEE.fail, BIOS doc |

- Nothing found binds a TLS public key or a customer encryption key into the report data. The whitepaper and code bind only the validator nonce, NVIDIA report, and node metadata (`cvm_id`, auction, cards). So no attested end-to-end channel from a client to the VM is documented.
- A URnetwork client could get partial independent assurance in two ways. (a) Generate its own TDX or SEV-SNP report from inside the VM if the guest exposes `/sys/kernel/config/tsm/report` or `/dev/tdx_guest`/`/dev/sev-guest` and the host runs a quote service. (b) Bind its own SSH or TLS key into that report's data. Neither is documented by Targon, and without published reference measurements the client could prove only "some TDX VM", not "Targon's unmodified image".
- Anyone holding a Bittensor hotkey can technically fetch a node's raw evidence (the `sn4 attest` path). But it covers the node's agent CVM (`cvm_id`), not a specific customer VM, and the miner may restrict callers by stake (the miner config has `min_stake` "required for validators to get nodes").

### Gaps
- No published reference values: MRTD/RTMRs, SEV-SNP launch digests, or VM image hashes. The KBS and tower source code is not public.
- Whether a customer VM can produce its own TDX/SNP quote, and whether its quote is the same "unified" node quote validators see.
- How SSH keys are injected into the encrypted VM (cloud-init from Targon's control plane?). This matters because it gives Targon a path to add access.
- Exactly what the tower v2 (TPM) verification checks; how often customer VMs (as opposed to nodes) are re-attested; what happens to a running VM when attestation fails mid-life.

## 3. Can a Targon confidential VM serve as a URnetwork "enclave" (Debian, root/SSH, IP, egress control, storage, lifecycle, provisioning, prices)?

### Takeaway
Partly. You get a long-running confidential VM (TDX GPU VMs, or SEV CPU-only VMs from **$0.15/h**) with SSH and a public IP, managed by REST API, CLI, and Go/Python SDKs. But the evidence shows **Ubuntu-only pre-built images** (no Debian, no BYO image), a non-root `ubuntu` login, and SSH on a non-22 port. The IP is the **miner node's IP**: per-port forwards in SHARED mode, 1:1 minus reserved ports in PASSTHROUGH mode. There are no documented egress controls, IPv6, persistent volumes (removed 2026-11-11), snapshots, or stop/start. The product is "beta" with a "potential data loss" warning. It fails URnetwork's "Debian VM" requirement as documented. Customer-controlled egress is possible only by tunnelling from inside the VM.

### Cited Findings
- **Provisioning (REST) [doc]:** `POST https://api.targon.com/tha/v3/orgs/{org_slug}/workloads` with `Authorization: Bearer <token>`. Body example: `{"name", "type":"VM", "image", "resource_name":"h200-small", "ssh_keys":[...], "vm_config":{"hostname":...}}`. List images with `GET .../workloads/vm-images`; check stock with `GET https://api.targon.com/tha/v3/inventory?type=vm&gpu=true`. — [VM guide](https://docs.targon.com/guides/virtual-machines)
- **Full workload endpoint set [doc]:**
  - create `POST .../workloads`, list `GET`, get `GET .../{uid}`, update `PATCH`, delete `DELETE` (204)
  - `POST .../{uid}/deploy`; `POST .../{uid}/suspend` (not for VM or BM); `POST .../{uid}/reboot` (VM only)
  - `GET .../{uid}/state`, `/events`, `/logs`
  - `GET .../vm-images`, `GET .../bm-images`, `POST .../verify`
  - `PUT|DELETE .../{uid}/ssh-keys/{ssh_key_uid}`
  - Tokens are personal access tokens or org service tokens. Lifecycle states: `registered, provisioning, running, error, suspended, stopped, deleted`. Name ≤32 characters, lowercase alphanumeric and hyphens; `ports` 1024–65535 with `TCP|UDP|SCTP` and `PROXIED|DIRECT`; `experiments` keys `reserved-gpu`, `persistent-workload` (config-gated).

  — [Workloads API](https://docs.targon.com/api/workloads)
- **SDK/CLI [code, v4.0.0 2026-11-11]:** typed VM, Bare Metal, and Sandbox services in Go and Python (TypeScript has Sandbox only). `Create` = register + deploy + optional wait. "VMs are created with SSH keys and an optional hostname; there is no VM password." "Rental and Volume APIs are unavailable in v4 and have no current replacement." CLI: `brew tap manifold-inc/tap && brew install targon`, `targon auth login`. — [targon-sdk README](https://github.com/manifold-inc/targon-sdk), [CHANGELOG](https://github.com/manifold-inc/targon-sdk/blob/main/CHANGELOG.md)
- **Images: Ubuntu only in evidence [doc/code]:** the dashboard offers "pre-configured" images only. SDK examples use `Image: "ubuntu-24.04"`, CLI examples `--image ubuntu-24.04-noble`. The image type has `name, display_name, os_family, description`. The whitepaper's pipeline clones "a golden Ubuntu 24.04 image with NVIDIA drivers". — [VM guide](https://docs.targon.com/guides/virtual-machines), [targon-sdk libs/go/README.md](https://github.com/manifold-inc/targon-sdk/tree/main/libs/go), [CLI README](https://github.com/manifold-inc/targon-sdk/tree/main/cli), [Intel whitepaper](https://www.manifold.inc/releases/intel-whitepaper). `vm-images` needs an org token (unauthenticated call → `401 MISSING_API_TOKEN`) [live], so I could not list the full catalogue.
- **SSH and root [doc]:** `ssh -p <SSH_PORT> ubuntu@<PUBLIC_IP>` (example `ssh -p 4022 ubuntu@203.0.113.42`). The port is per-VM and is not 22. "The user is always `ubuntu`"; the page does not mention root or sudo. — [VM guide](https://docs.targon.com/guides/virtual-machines). Secondary and marketing sources say "root SSH access" [3rd](https://subnetalpha.ai/subnet/targon/) and "root access" [mkt](https://www.manifold.inc/releases/targon-os).
- **Networking [doc]:** "Each VM has a public IP address." **Shared network**: add ports under Edit → Exposed Ports, TCP or UDP, "direct routing". **Passthrough network**: ports map 1:1 to the VM except `22, 4050, 5001, 8081, 8980, 8981, 9899`. Nothing on IPv6, firewall, or egress controls. — [VM guide](https://docs.targon.com/guides/virtual-machines). Response fields: `state.public_ip`, `state.ssh_port`, `state.urls[]`, `resource.network_mode`. — [Workloads API](https://docs.targon.com/api/workloads). The Go SDK says VM ports may be "1-65535 except 22", TCP or UDP, and "VM ports are direct forwards, so routing is not sent", which conflicts with the API page's 1024–65535 range. — [libs/go/vm.go](https://github.com/manifold-inc/targon-sdk/blob/main/libs/go/vm.go)
- **Network mode per SKU [live]:** 1-GPU and small/medium/large CPU VMs are `SHARED`; 8-GPU `*-xlarge` and `cpu-xlarge-amd` are `PASSTHROUGH`. — [inventory](https://api.targon.com/tha/v3/inventory)
- **Node IP is the miner's [doc/code]:** providers set the node's uplink (DHCP/static/bond/VLAN via `targon.net.*`) — [installing-targonos.md](https://github.com/manifold-inc/targon/blob/main/docs/miner/installing-targonos.md). Validators fetch evidence from `http://{nodeIP}:8980` — [cvm.go](https://github.com/manifold-inc/targon/blob/main/internal/attest/cvm/cvm.go). Port 8980 is on the passthrough reserved list.
- **Storage [doc/code]:** per-SKU disk only (e.g. 320 GiB on 1-GPU VMs). Volumes existed from 2025-11-04 ([iq.wiki](https://iq.wiki/wiki/targon), possibly superseded) but were removed from the SDK on 2026-11-11 with "no current v4 replacement" ([CHANGELOG](https://github.com/manifold-inc/targon-sdk/blob/main/CHANGELOG.md)). The API docs list no volume endpoints ([Workloads API](https://docs.targon.com/api/workloads)). TargonOS says disks and keys "are destroyed when a VM is deleted" ([TargonOS post](https://www.manifold.inc/releases/targon-os)).
- **Lifecycle [doc]:** start at create, reboot ("Active connections are interrupted"), and delete ("cannot be undone"). Stop and snapshot are not mentioned; suspend is not allowed for VMs. — [VM guide](https://docs.targon.com/guides/virtual-machines), [Workloads API](https://docs.targon.com/api/workloads)
- **Live confidential VM catalogue and prices [live, 2026-11-23 07:25 UTC]** (`cost_per_hour` in USD per VM; all `cc_enabled: true`):

| SKU | GPU | vCPU | RAM | Disk | Net | $/h | In stock |
|---|---|---|---|---|---|---|---|
| cpu-small-amd | none (EPYC-v4) | 4 | ~52 GiB | 384 GiB | SHARED | 0.15 | 54 |
| cpu-medium-amd | none | 8 | ~105 GiB | 768 GiB | SHARED | 0.30 | 27 |
| cpu-large-amd | none | 16 | ~210 GiB | 1,536 GiB | SHARED | 0.60 | 13 |
| cpu-xlarge-amd | none | 32 | ~419 GiB | 3,072 GiB | PASSTHROUGH | 1.00 | 6 |
| rtx6000b-small | 1× RTX PRO 6000B | 32 | ~125 GiB | 320 GiB | SHARED | 1.69 | 6 |
| h100-small | 1× H100 | 12 | ~171 GiB | 320 GiB | SHARED | 3.09 | 7 |
| h200-small | 1× H200 | 16 | ~171 GiB | 320 GiB | SHARED | 4.00 | 8 |
| h100-xlarge | 8× H100 | 96 | ~1,367 GiB | 2,560 GiB | PASSTHROUGH | 24.72 | 0 |
| h200-xlarge | 8× H200 | 128 | ~1,367 GiB | 2,560 GiB | PASSTHROUGH | 32.00 | 1 |
| b200-xlarge | 8× B200 | 160 | 1,536 GiB | 16 TiB | PASSTHROUGH | 52.00 | 0 |
| b300-xlarge-amd | 8× B300 (AMD host) | 96 | 2,560 GiB | 16 TiB | PASSTHROUGH | 55.20 | 0 |
| b300-xlarge | 8× B300 | 160 | 2,560 GiB | 16 TiB | PASSTHROUGH | 68.00 | 0 |

  Not confidential, for comparison: sandboxes $0.045–0.175/h; bare metal `bm-a4-rtx4090` (4× RTX 4090) $2.40/h and `bm-a5-h100-sxm` (8× H100) $25.20/h, both region `aus` (Austin). — [api.targon.com/tha/v3/inventory](https://api.targon.com/tha/v3/inventory)
- **Shape names in docs [doc]:** `cpu-small`…`cpu-xlarge`, `h200-small/large/xlarge`, and H100/B200/B300/RTX6000B/RTX4090 families; check with `targon inventory --type vm --gpu`. — [Compute resources](https://docs.targon.com/guides/compute-resources). The live inventory uses `-amd` suffixes and shows only `small` and `xlarge` GPU shapes.

### Inferences
- **Fit against the enclave requirement:**
  - Confidential VM, SSH, long-running: **yes**.
  - Debian: **no evidence**; Ubuntu 24.04 only, no BYO image path.
  - Customer-controlled IP and default egress: **no at the platform level**. The IP is the miner node's, and the miner's network carries all traffic. Inside the VM, a root-capable user could set the default route through a WireGuard or URnetwork tunnel. That controls *where* traffic exits, but the host still sees the encrypted tunnel's metadata.
  - Root: **probably via sudo on Ubuntu cloud images**, but undocumented.
- **IP stability is weak:** the KBS binds a node to its first-attestation IP, and a 1-GPU or CPU VM shares the node IP with port forwards. URnetwork could not put a VM behind its own address. IPv4 ports must be requested ahead of time (SHARED), or are 1:1 with reserved holes (PASSTHROUGH).
- **Durability:** with no volumes, no snapshots, a beta data-loss warning, and keys destroyed on delete, state must be replicated off the VM.

### Gaps
- The full `vm-images` catalogue (needs a token), especially any non-Ubuntu `os_family` or custom-image path.
- Whether `ubuntu` has passwordless sudo; whether IPv6 exists; whether outbound ports are filtered; whether the provider's network can be pinned to a region (VMs have no `region` field, BM has `aus`/`dal`).
- Quotas or limits per org (number of VMs, ports per VM), and VM uptime/eviction terms (e.g. what happens when a miner deregisters).

## 4. Inference API: what exists now (endpoints, features, limits)?

### Takeaway
None on Targon. `api.targon.com/v1/*` returns 410 Gone, Targon is no longer an OpenRouter provider, and "serverless" was removed from the SDK. Manifold's separate brand **Sybil** (`api.sybil.com/v1`) documents OpenAI-style completions, chat completions, models, and Responses endpoints. It markets "confidential secure compute on Targon" but exposes no attestation, and its API returned 503 "no available server" when probed on 2026-11-23.

### Cited Findings
- **Targon API retired [live]:** `/v1/models` and `/v1/chat/completions` on `api.targon.com` → HTTP 410 (2026-11-23). — [api.targon.com/v1/models](https://api.targon.com/v1/models). Third-party monitor: 410 from 4 of 4 regions since at least 2026-08-24. — [llmlatency.dev](https://llmlatency.dev/provider/targon)
- **Not on OpenRouter [live]:** `openrouter.ai/api/v1/providers` lists 123 providers and none matches "targon" (2026-11-23); `openrouter.ai/provider/targon` returns 404. — [OpenRouter providers API](https://openrouter.ai/api/v1/providers), [openrouter.ai/provider/targon](https://openrouter.ai/provider/targon). Historical: pydantic-ai still lists `targon` among known OpenRouter provider names (possibly superseded). — [pydantic-ai docs](https://ai.pydantic.dev/api/models/openrouter/)
- **Serverless removed [code]:** SDK v4.0.0 (2026-11-11) "Removed the `rental`, `storage`, and `serverless` inventory types"; SDK 1.0.0 (2026-04-18) had added "config/container deployment support for v2 workload-backed serverless resources" (superseded). — [CHANGELOG](https://github.com/manifold-inc/targon-sdk/blob/main/CHANGELOG.md)
- **Historical usage claim [3rd, Oct 2025, possibly superseded]:** Targon processed "millions of daily requests for partners like Dippy". — [subnetalpha.ai](https://subnetalpha.ai/subnet/targon/)
- **Sybil [mkt/doc]:** "Single API, Access All Open-Source LLMs"; models deployed on "Confidential Compute on Targon"; "LLM's are run on confidential secure compute"; no attestation mentioned — [sybil.com](https://sybil.com/). Docs list Completions (`/api/completions`), Chat Completions, Models, and Responses ("structured response formats and streaming"); no Anthropic Messages endpoint; no TEE, logging, or retention text — [docs.sybil.com](https://docs.sybil.com/). Base URL `https://api.sybil.com/v1`, `Authorization: Bearer $SYBIL_API_KEY`, example `POST /v1/chat/completions` with model `mistral-large` — [Getting started](https://docs.sybil.com/guides/getting-started).
- **Sybil API status [live]:** `GET https://api.sybil.com/v1/models` → 503 `no available server` (2026-11-23, single probe). — [api.sybil.com/v1/models](https://api.sybil.com/v1/models)

### Inferences
- For URnetwork's "all inference in a TEE" rule, Targon is only a **confidential GPU host**. URnetwork would run and operate the inference stack itself inside rented VMs, along with any attested TLS or E2EE layer (Q2 shows Targon provides none).
- Sybil does not meet the rule as documented. It gives no attestation, no customer-visible TEE evidence, and TLS terminates at Sybil's API by default. Its availability is also uncertain.

### Gaps
- Tool calling, structured output, context lengths, rate limits, and sub-keys for Sybil (not on the pages fetched); whether Sybil's 503 was transient.
- What the retired Targon inference API offered (models, TLS termination, any TEE claim per request); no primary source found.

## 5. Pricing and payment (fiat, TAO, alpha, Gamma), deposit mechanics, refunds, usage reports, and terms/privacy

### Takeaway
Targon bills from a prepaid **USD credit balance** per organization. Each org also has an **SS58 (Bittensor-format) wallet address**, and the site uses **Stripe Checkout** for card payments. Secondary sources say TAO and alpha deposits are accepted and routed to a buyback wallet. Deposit minimums, confirmation times, crypto conversion rates, refunds, and invoices are not publicly documented; billing pages sit behind sign-in. **No evidence that Targon accepts Gamma yet**: it was named among the seven intended initial Gamma issuers (late Sept 2026), but its 2026-11-11 SDK, API docs, and validator code have no Gamma support. The ToS (dated 2025-07-10) promises no training on customer data without consent. It also allows suspension "without notice", gives no SLA, limits use to "personal or internal business purposes", and lists "sensitive personal data" among prohibited content.

### Cited Findings
- **Credits and wallet API [doc]:** `GET /tha/v3/orgs/{org_slug}/credits` returns `credits` ("Current credit balance.") and `currency` (example `"USD"`). `GET /tha/v3/orgs/{org_slug}/wallet` returns `address`, an "SS58-encoded wallet address". Orgs carry `billing_email` and an integer `overage` ("Overage allowance."). — [Organizations API](https://docs.targon.com/api/orgs)
- **CLI [code]:** `targon org credits`, `targon org wallet`, and `targon whoami` show the wallet, credits, and profile. Credits display in USD, turning yellow under $25. "wallet, and credits are organization-bound." — [targon-sdk cli](https://github.com/manifold-inc/targon-sdk/tree/main/cli), [README](https://github.com/manifold-inc/targon-sdk)
- **Card via Stripe [live]:** the public targon.com JavaScript stores a `stripe_pending_checkout` session and recognizes `checkout.stripe.com` / `pay.stripe.com` redirects. `/pricing` and `/billing` redirect to `/sign-in`. — [targon.com](https://targon.com/)
- **TAO and alpha deposits [3rd]:**
  - Oct 2025 session summary: payments "TAO/fiat today", stablecoins planned (possibly superseded).
  - "auto top-off of customer credits" delivered May 2026.
  - Oct 2026 summary: "TAO and alpha deposits for Targon credits flow to the project's buyback wallet."
  - Revenue buybacks: about $100K/month in July 2025, >2,000 TAO of SN4 alpha in May 2026, >550 TAO in Aug 2026.

  — [subnetalpha.ai](https://subnetalpha.ai/subnet/targon/). The stats site has "Revenue" and "Buybacks" pages — [stats.targon.com](https://stats.targon.com/).
- **Gamma, Targon's side [3rd]:** Const (OpenTensor) named Chutes, Engy, GM, Lium, Targon, Hippius, and Affine as initial Gamma issuers at the Exploit Summit on Sept 28, 2026. — [Startup Fortune](https://startupfortune.com/bittensor-unveils-gamma-tokens-to-let-ai-subnets-pay-each-other/), [A Bittensor Journey, Sept 2026](https://www.abittensorjourney.com/p/navigating-bittensor-september-2026). Gamma PR reported merged on 2026-11-05 — [X @mentatminds](https://x.com/mentatminds/status/2118370933345792319), [subtensor PR #3300](https://github.com/RaoFoundation/subtensor/pull/3300). Reported as not on by default; each subnet's owner key must accept it — [KuCoin explainer](https://www.kucoin.com/news/insight/TAO/6abd088638a264000791e5ef). A Targon page about a year old said "gamma tokens" were planned "in the coming months" — [subnetalpha.ai](https://subnetalpha.ai/subnet/targon/).
- **No Gamma in Targon's code or docs [code/doc, checked 2026-11-23]:** `gamma` does not appear in `manifold-inc/targon` or `manifold-inc/targon-sdk` (v4.0.0, 2026-11-11), and the Organizations API has only `wallet` and `credits`. — [targon](https://github.com/manifold-inc/targon), [targon-sdk](https://github.com/manifold-inc/targon-sdk), [Organizations API](https://docs.targon.com/api/orgs)
- **Pricing [live]:** per-VM hourly `cost_per_hour` (table in Q3), e.g. H200 $4.00/GPU-h (1×) or $32/h (8×); confidential CPU VMs from $0.15/h. The inventory page column reads "Price / hr / GPU". — [inventory API](https://api.targon.com/tha/v3/inventory), [targon.com/inventory](https://targon.com/inventory). Reserved capacity is "arranged with our team" (no public price). — [targon.com/inventory](https://targon.com/inventory)
- **Supply-side prices, for context [live]:** miner payouts are set per card-hour by auction (USD cents): `TDX-VM-NVIDIA-H200` target 290 / max 450; `TDX-VM-NVIDIA-B300` 650/975; `SEV-VM-CPU` 10/20. "Any emissions not allocated to auctions are burned." — [tower auctions](https://tower.targon.com/api/v2/auctions), [miner.md](https://github.com/manifold-inc/targon/blob/main/docs/miner/miner.md)
- **Terms of Service [doc, dated "7/10/25 July 10, 2025", possibly superseded but still live 2026-11-23]:**
  - Entity "Manifold Labs, Inc., a Texas Corporation"; Texas law.
  - "We will not use any data you submit through the Services to train or improve" models without "explicit prior consent".
  - "Targon reserves the right to suspend or terminate your access to the Services at our discretion, without notice."
  - Services "as is" and "as available"; "does not guarantee uninterrupted, error-free service"; no SLA.
  - License "for personal or internal business purposes".
  - Prohibited content includes "sensitive personal data, financial or medical information".
  - No payment, refund, or crypto clauses.

  — [targon.com/terms](https://targon.com/terms). The repo's TERMS.md (for miners and validators) says "You retain all rights and ownership of your data." — [TERMS.md](https://github.com/manifold-inc/targon/blob/main/TERMS.md)
- **Privacy Policy [doc, "July 10, 2025"]:**
  - Collects account data, IP addresses, browser and OS, and payment details via third parties ("we do not retain financial information").
  - "Certain log data and usage records may be retained for a reasonable period."
  - Does "not use your Personal Data for training" models without consent.
  - Shares with vendors and with "its parent company, Manifold Labs, Inc."
  - Prompts, outputs, VM contents, crypto wallets, miners/validators, and data location are not addressed.

  — [targon.com/privacy](https://targon.com/privacy)
- **Sybil billing (separate product) [doc]:** USD balance; "Add Credits" through a Stripe checkout page; saved cards; prepaid or postpaid plans; dashboard shows spend and request count; no crypto mentioned. — [Sybil billing](https://docs.sybil.com/guides/billing)

### Inferences
- The SS58 org wallet strongly suggests TAO (and possibly alpha) deposits go to a per-org address and are credited in USD. A Gamma integration would most naturally become another way to fund the same USD credit balance. Today URnetwork would have to pay by card (Stripe) or TAO/alpha to keep a Targon org funded.
- The "personal or internal business purposes" license and "sensitive personal data" exclusion conflict with URnetwork reselling Targon VMs or inference to end users who send private data. A written enterprise or reseller agreement would be needed.

### Gaps
- Deposit mechanics: which token(s) the SS58 address accepts (TAO only, or also SN4 alpha); minimum deposit; confirmations or crediting delay; exchange-rate source; any crypto discount or surcharge.
- Refunds, invoices/receipts, tax handling, usage-report exports, and per-workload billing granularity (per second, minute, or hour). None found publicly; billing is behind sign-in.
- Whether Targon has enabled, or announced a date for, Gamma acceptance after the 2026-11-05 merge. No Targon statement found.
- Enterprise or reseller terms, and any DPA (none public).

## 6. Reliability, scale, incidents, cheating history, and hardware locations

### Takeaway
Live network stats show a **small, concentrated supply**: 4 active miners, 312 GPUs, and 11 CPU nodes on 2026-11-23, with two miners holding about 90% of GPUs. 8-GPU confidential SKUs were mostly out of stock. VMs are beta. No status page or incident history was found. The inference API disappeared without a public notice. An independent reviewer rates readiness "Watch" and notes retracted benchmark claims. Bare-metal regions are Austin and Dallas; VM locations are undisclosed.

### Cited Findings
- **Network snapshot [live, asOf 2026-11-23T06:24:08Z, block 9,567,579, TAO $175]:**
  - 4 miners: UID 156 (160 GPUs: 136 B300-TDX + 24 B300-SEV; weight 0.659), UID 7 (120 GPUs + 11 CPU nodes: 104 H200, 8 RTX6000B, 8 B200, 11 SEV CPU; weight 0.272), UID 32 (24 H100; 0.059), UID 162 (8 RTX6000B; 0.010).
  - Totals: 312 GPUs, 11 CPU nodes; network `payoutRate` 1,142.6 (USD/h per the page label).
  - History starts 2025-10-29.

  — [stats.targon.com tRPC statistics.getSnapshot](https://stats.targon.com/api/trpc/statistics.getSnapshot), [stats.targon.com](https://stats.targon.com/)
- **Per-type counts vs auction targets [live]:** B300-TDX 136/128, H200-TDX 104/128, B300-SEV 24/80, H100-TDX 24/240, RTX6000B-TDX 16/32, CPU-SEV 11/15, B200-TDX 8/64. — [stats snapshot](https://stats.targon.com/api/trpc/statistics.getSnapshot)
- **Customer stock [live]:** h200-xlarge 1; b200/b300/h100-xlarge 0; small GPU VMs 6–8; CPU VMs 6–54. — [inventory](https://api.targon.com/tha/v3/inventory)
- **Conflicting scale claims:**
  - "Operating 1,000+ GPUs and CPUs… 99% upti[me]" (community X post, 2026-03-13). — [X @bittingthembits](https://x.com/bittingthembits/status/2032473344751063343) [3rd, unverified]
  - "over $70 million worth of NVIDIA-certified hardware" (July 2025 session, possibly superseded). — [subnetalpha.ai](https://subnetalpha.ai/subnet/targon/)
  - Bittensor.ai shows 10 validators and 3 miners, OpenTAO 247/256 miners with 5 earning (dates unclear). — [bittensor.ai](https://bittensor.ai/subnets/4), [opentao.ai](https://opentao.ai/beginner/subnets/4-targon/)
- **Locations [live/3rd]:** `GET /tha/v3/region` → `aus` (Austin, US) and `dal` (Dallas, US); both BM SKUs are `aus`. — [api.targon.com/tha/v3/region](https://api.targon.com/tha/v3/region). Manifold Labs is in Austin, Texas — [subnetalpha.ai](https://subnetalpha.ai/subnet/targon/).
- **Beta and availability caveats [doc]:** VMs beta, "potential data loss", "may be out of stock". — [VM guide](https://docs.targon.com/guides/virtual-machines)
- **Unannounced shutdown [3rd]:** the inference API went 410 with "no shutdown notice from Targon … on record". — [llmlatency.dev](https://llmlatency.dev/provider/targon)
- **Independent readiness review [3rd, 2026-10-21]:** "Watch" band, unchanged across revisions on 2026-07-19, 09-22, and 10-01. Notes "published performance claims include a retraction" / "fabricated benchmark figures were retracted". — [pragma.vision](https://pragma.vision/observe/targon-sn4)
- **Validator setup [doc]:** validators run inside a TVM CPU VM on an AMD SEV-SNP server (suggested: Latitude `m4.metal.medium`, Ubuntu 26.04), installed from the `tvm/install` binary with `--service-url http://tvm.targon.com`. — [validator.md](https://github.com/manifold-inc/targon/blob/main/docs/validator/validator.md)
- **Why TEE (official framing) [doc, ~2025-03-31, possibly superseded]:** the v6 page cites privacy and security needs and keeping models confidential. It does **not** mention miner cheating. — [Targon v6](https://www.manifold.inc/releases/targon-v6). The 2026 whitepaper framing is "We needed to run trusted workloads on untrusted host machines". — [X @TargonCompute](https://x.com/TargonCompute/status/2036151401684856896)
- **Scrutiny [3rd]:** a May 2025 Token Metrics report criticized a lack of transparency about the team, GitHub, and roadmap (possibly superseded). — [iq.wiki](https://iq.wiki/wiki/targon)

### Inferences
- Concentration risk is high. If one miner (UID 156) leaves, more than half the GPU supply goes with it, and the B300 confidential SKUs depend on it. For an "enclave" product, capacity and continuity cannot be assumed without reserved capacity or a contract.
- Because miners are paid from emissions per live card and customer revenue funds alpha buybacks, supply follows the auction targets set by Manifold, not customer demand directly.

### Gaps
- Documented miner cheating or exploit cases, and the specific pre-TEE verification failures that motivated TVM: none found in primary sources.
- Any public status page, incident log, or SLA history; which benchmark claims were retracted.
- Physical locations, data-centre operators, and physical-security controls for confidential-VM nodes (pragma.vision flags this as the main blocker).

## 7. Open-source repositories

### Takeaway
The public code is the miner/validator relay (Go, MIT) and client SDKs and CLI (Apache-2.0), plus an NVIDIA attestation wrapper with no license. The components that decide trust are not public: TargonOS (shipped as signed binaries), the TVM installer (a stripped ELF binary committed to the MIT repo), the KBS, the tower verifier, and the image pipeline.

### Cited Findings
- **Org repos [live via GitHub API, 2026-11-23]:**

| Repo | Language | License | Stars | Last push | Notes |
|---|---|---|---|---|---|
| homebrew-tap | Ruby | Apache-2.0 | 0 | 2026-11-20 | CLI tap |
| targon-sdk | Python, Go, TS, Rust CLI | Apache-2.0 | 4 | 2026-11-20 | "Python SDK for building and deploying serverless applications on the Targon platform." |
| targon | Go | MIT | 72 | 2026-11-09 | "A library for building subnets with the manifold reward stack" |
| targon-o11y | Go | none | 0 | 2026-10-08 | |
| targon-nvidia-attest | Python | none | 0 | 2026-01-09 | |
| targon-oracle | Go | MIT | 0 | 2025-06-04 | |
| nvtrust (fork) | – | Apache-2.0 | 0 | 2025-04-23 | |
| host-verification | – | NOASSERTION | 2 | 2025-04-11 | |
| others | – | – | – | – | manifold-sdk, periscope (LLM load testing), epistula-examples, vesta, wallet-monitor, taoxyz-wallet, ablx, hone-api/dashboard, openclaw |

  — [github.com/manifold-inc](https://github.com/manifold-inc)
- **`targon` contents [code]:** Go 98.8 KB, Python 2.5 KB. Directories `cmd/{miner,sn4,validator}`, `internal/attest/{cvm,nonce}`, `internal/validator/...`, `internal/tower/tower.go`, `docs/{miner,validator,sn4}`, `weights-api/`. `tvm/install` is an 8.2 MB "ELF 64-bit LSB pie executable, x86-64 … stripped". About 2,026 commits; no releases. README calls Targon "The Confidential Decentralized AI Cloud" and lists "AMD SEV-SNP integration" as roadmap. — [manifold-inc/targon](https://github.com/manifold-inc/targon)
- **TargonOS distribution [doc]:** release 13.1.0 at `releases.targon.com` (ISO, iPXE UKI, netboot bundle), with `SHA256SUMS` and per-artifact minisign signatures checked against "its baked-in release key". — [installing-targonos.md](https://github.com/manifold-inc/targon/blob/main/docs/miner/installing-targonos.md)
- **SDK v4.0.0 [code, 2026-11-11]:** Go module `github.com/manifold-inc/targon-sdk/libs/go/v4`, PyPI `targon-sdk`, npm `@targon/sdk`, crates.io `targon-sdk`. Includes a sandbox cookbook (create/exec/files/fork/freeze). — [targon-sdk](https://github.com/manifold-inc/targon-sdk)

### Inferences
- URnetwork could reuse the Go SDK (Apache-2.0) to provision VMs from the sidecar's backend. No open-source code verifies a Targon VM's attestation end to end, so URnetwork would have to write and own any such verifier, and it would still lack reference measurements.

### Gaps
- Source for TargonOS, the KBS, the tower verifier (`/api/v1|v2/verify-attestation`), the attestation agent in the VM initramfs, and the VM image build. None found public; no reproducible-build or measurement-publication process found.
