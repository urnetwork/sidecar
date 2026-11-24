# SayGM (SN28) confidential `-tee` tier: what a client can verify end to end, hop by hop (state as of 2026-11-23)

Scope: whether a person's device can verify SayGM's `-tee` path to URnetwork's bar. The bar is device-side verification of the TEE, before anything is sent, from evidence bound to a nonce the device chose and to a key or TLS session that ends inside the TEE, with no hop outside a TEE seeing plaintext.

Method:
- "Live" means this researcher ran the request on 2026-11-23 between 17:59 and 18:15 UTC, as free unauthenticated GETs.
- "Verified by this researcher" means a full Intel DCAP check, done in Python with `cryptography` 44.0.2 against collateral fetched live from Intel PCS. It covered the PCK chain to Intel's published root, the QE report signature, the attestation-key binding, the quote signature, the signed TCB Info and QE Identity, both CRLs, TCB-level matching, and the TDX module identity. It also included an RTMR0–3 replay from the event log and recomputation of the REPORTDATA bindings.
- No paid call was made, and no account was created.

## 1. The gateway attestation at `GET /attestation/info`: exact fields, what REPORTDATA binds, whether a client can tie its TLS session or a key to the attested gateway, and an independent check of the live quote

### Takeaway
The live quote is genuine and current, and a client can check it fully on its own:
- Intel TDX quote v4, chaining to Intel's root.
- TCB `UpToDate` for platform, TDX module and QE (TCB evaluation data number 20).
- Debug off; the production `dstack-0.5.15` OS; RTMR0–3 replay exactly from the event log.

REPORTDATA binds `SHA-512(gateway_pubkey ‖ base64-decoded nonce)`. The nonce is base64, so a client that hashes a hex nonce's raw bytes gets a false mismatch.

`gateway_pubkey` is a 32-byte identity key (Ed25519 by every indication), not the TLS key. No API lets a client encrypt to it. The earlier gap is nonetheless closed: a client *can* tie its TLS session to the attested CVM. `api.saygm.com` is a dstack-ingress deployment behind Phala's TLS-passthrough gateway. Its `/evidences/` bundle carries a second, static quote from the *same CVM instance* (identical MRTD, MRCONFIGID and RTMR0–3, including the instance-id). That quote binds the Let's Encrypt account and the certificate, and a CAA record pins issuance to that account. The served TLS certificate is the attested one (same serial, same SPKI), so the session ends inside the attested gateway. Caveats:
- the TLS key is bound by a static, non-nonce quote;
- the DNS owner (SayGM) can briefly lift the CAA pin;
- the compose behind the attested hash is not published.

### Cited Findings
**The endpoint and its contract**
- OpenAPI contract:
  - "Public, unauthenticated endpoint. Supply a fresh base64 nonce of 16–64 decoded bytes; the response echoes it in a nonce-bound attestation record."
  - The `nonce` query parameter is "Fresh base64-encoded nonce; decoded length must be 16–64 bytes."
  - Responses:
    - 400: "Missing or malformed query fields return text; invalid decoded nonce values return JSON".
    - 429: "Attestation request capacity or frequency limit reached".
    - 500: "The attestation record could not be validated".
    - 503: "The attestation provider is unavailable or timed out".

  — [SayGM OpenAPI](https://saygm.com/openapi.json)
- Schema `AttestationInfo`, with `additionalProperties: false`. All of these fields are required:
  - `schema_version` (const `"2"`), `gateway_id`, `gateway_pubkey` (base64), `tee_platform` (const `"intel-tdx"`);
  - `app_id`, `compose_hash`, `os_image_hash`, `instance_id`, `tcb_info`;
  - `quote`, `event_log` (string), `vm_config` (string or null), `report_data` (base64), `nonce` (base64), `issued_at`;
  - `verification_status` (enum `not_checked`, `verified`, `failed`), `verified_at`, `verified_tcb_status`, `verified_tcb_date`;
  - `event_log_verified`, `os_image_verified`, `policy_accepted` (boolean), `verification_failure_reason`, `policy_failure_reason`.

  — [SayGM OpenAPI](https://saygm.com/openapi.json)
- [live, 17:59:56 UTC] Response 200, 13,420 bytes, served by `server: nginx/1.27.4`, with `cache-control: no-store`, `access-control-allow-origin: *` and an `x-gm-request-id`. Live values:
  - identity: `schema_version` `"2"` (a string), `gateway_id` `gw-mainnet-1`, `gateway_pubkey` `duH/rhjI8AP2L/W+knVu5QfYkylTmlQXlH6wc96+3RA=` (32 bytes), `tee_platform` `intel-tdx`;
  - app: `app_id` `3c97764f8f3e6e450f31240ffcd0a28c17dc00db`, `compose_hash` `9fd0e3f14c92d4fea71254063c63956eb3c39c9617346a21ab27b0fcb4f6fc52`, `os_image_hash` `4597735f1a38ad8ec9f781356b88737fc052062deb7c9aaa4be89bf1b35643ca`, `instance_id` `bc672ebb6c74ad97351bd5b0db523a89f44f2626`;
  - `tcb_info` `{status: null, tcb_date: null}`;
  - verification fields: `verification_status` `not_checked`, `policy_accepted` false, every `verified_*` field null.

  — [api.saygm.com/attestation/info](https://api.saygm.com/attestation/info)
- [live] Rate limits and errors:
  - 3 of 8 calls made about 0.6 s apart (18:02:10–18:02:14 UTC) returned `{"error":{"code":"attestation_rate_limited"}}`.
  - A call without a nonce returned 400 `Failed to deserialize query string: missing field 'nonce'`.

  — [api.saygm.com/attestation/info](https://api.saygm.com/attestation/info)

**REPORTDATA binding**
- SayGM documents `report_data = SHA‑512(gateway_pubkey ‖ nonce)` with this recipe:
  - `NONCE=$(openssl rand -base64 32)`;
  - `(jq -r .gateway_pubkey attestation.json | openssl base64 -d -A; printf %s "$NONCE" | openssl base64 -d -A) | openssl dgst -sha512 -binary | openssl base64 -A`.

  Both inputs are base64-decoded. "A match shows the quote was made for your nonce and names this key; step 3 checks Intel's signature on it." — [saygm.com/privacy](https://saygm.com/privacy)
- [live, verified by this researcher] Recomputation:
  - The request sent a 64-character hex nonce. The server base64-decoded it to 48 bytes.
  - `SHA-512(raw 32-byte gateway_pubkey ‖ base64-decode(nonce))` equals both the JSON `report_data` and the quote's REPORTDATA.
  - Hashing the hex string's raw bytes, the ASCII hex, or the base64 pubkey text does **not** match. Neither do dstack's `app-data:` prefix variants.

  — [api.saygm.com/attestation/info](https://api.saygm.com/attestation/info)
- The miner image's attestation server implements the same contract. It cites `gm/docs/contracts/gateway-attestation-info.md`: `report_data = SHA-512(pubkey || caller_nonce)`, with "Both sides … decoded from base64 by callers". "The gm gateway's attestation surface uses the identical helper — the two services stay byte-for-byte consistent." — [gm-miner attestd/src/report_data.rs](https://github.com/taostat/gm-miner/blob/main/attestd/src/report_data.rs); [attestd/src/info.rs](https://github.com/taostat/gm-miner/blob/main/attestd/src/info.rs)
- What `gateway_pubkey` is: the miner's twin key is described as follows. "ed25519 keypair bootstrap, TEE-bound in production … The pubkey is published in `GET /attestation/info` and bound into the TDX quote's `report_data`". It is "derived from a dstack-KMS sealed key via the guest agent's `get_key` endpoint … only for this `app_id` + `compose_hash`". "This mirrors the gm gateway's `gateway/src/attestation/keypair.rs`." — [gm-miner attestd/src/keypair.rs](https://github.com/taostat/gm-miner/blob/main/attestd/src/keypair.rs). SayGM: "The gateway identity is also used by SayGM's accounting and validation pipeline." — [SayGM docs: TEE attestation](https://docs.saygm.com/security/attestation/)

**The quote itself (live, verified by this researcher)**
- Header and body values:
  - quote v4, 5,010 bytes, attestation key type 2 (ECDSA P-256), TEE type 0x81 (TDX), QE vendor id `939a7233f79c4ca9940a0db3957f0607` (Intel);
  - `TEE_TCB_SVN` `0b010500…`, `MRSIGNERSEAM` all zero, `SEAMATTRIBUTES` 0;
  - `TDATTRIBUTES` = bit 28 only: DEBUG 0, `SEPT_VE_DISABLE` 1, PKS/KL/PERFMON 0; `XFAM` 0x207;
  - `MRTD` `20038376b145055508e1a8538a864857e8180f989ea8aac4954d432c494872aa48e6946b381fe6bb28d8b9e703ed65d3`;
  - `RTMR0` `027b610a…d11d1ba7`, `RTMR1` `786417fa…bf6f86ec`, `RTMR2` `255b32bf…9296ffae`, `RTMR3` `cf23cca2…bc8ae6d3`;
  - `MRCONFIGID` = `0x01 ‖ compose_hash ‖ zero padding`; `MROWNER` and `MROWNERCONFIG` zero.

  — [api.saygm.com/attestation/info](https://api.saygm.com/attestation/info)
- PCK certificate (embedded, certification data type 6 wrapping type 5): leaf "Intel SGX PCK Certificate", issuer "Intel SGX PCK Platform CA". FMSPC `20a06f000000`, PCE ID `0000`, SGX-type field 1, PCESVN 13, CPUSVN components `[5,5,2,2,5,255,0,2,0…]`. — [api.saygm.com/attestation/info](https://api.saygm.com/attestation/info)
- Signature chain: all of these passed.
  - The embedded root equals Intel's published "Intel SGX Root CA" (SHA-256 `44a0196b…74d3`), and the chain verifies leaf → Platform CA → root.
  - The QE report signature verifies under the PCK key. QE REPORTDATA = SHA-256(attestation key ‖ QE auth data), padded with zeros. The quote signature verifies under the attestation key.

  — [Intel SGX root certificate](https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem)
- Collateral and TCB status: all of these passed.
  - TDX TCB Info for FMSPC `20a06f000000`: v3, issued 2026-11-23T16:56:03Z, next update 2026-12-23, evaluation data number 20. Its signature verifies, and its signer chains to Intel's root.
  - Matched platform level: **UpToDate**, tcbDate 2025-08-13, no advisories. TDX module identity `TDX_01`: MRSIGNER and attributes match, **UpToDate**.
  - TD_QE identity v2: signature valid, MRSIGNER, ISVPRODID, MISCSELECT and attributes match, QE ISVSVN 6 → **UpToDate**.
  - The PCK Platform CA CRL and the root CRL both have valid signatures and are current. The leaf, the Platform CA and the TCB signer are not revoked.

  — [Intel PCS TCB Info](https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=20a06f000000); [Intel PCS QE Identity](https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity); [Intel PCK CRL (platform)](https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=pem); [Intel root CRL](https://certificates.trustedservices.intel.com/IntelSGXRootCA.der)
- Collateral anomaly [live]: `certificates.trustedservices.intel.com/IntelSGXRootCA.der` now serves a 294-byte **CRL**, not the certificate. The CRL is issued by Intel SGX Root CA, with thisUpdate 2026-02-26, nextUpdate 2027-02-26 and Last-Modified 2026-09-30. The root certificate is at `Intel_SGX_Provisioning_Certification_RootCA.pem`. The earlier notes called the `.der` URL the "Root CA cert". — [IntelSGXRootCA.der](https://certificates.trustedservices.intel.com/IntelSGXRootCA.der); earlier: [tee_attestation_verification.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/tee_attestation_verification.md>)
- Event log: 30 events, 13 for RTMR0, 5 for RTMR1, 2 for RTMR2 and 10 for RTMR3.
  - Boot events carry digests but empty `event` and `event_payload`.
  - The RTMR3 events carry names and payloads but empty digests: `system-preparing`, `app-id`, `compose-hash`, `instance-id`, `boot-mr-done`, `mr-kms` (`beb00fed…f48c`), `os-image-hash`, `key-provider`, `storage-fs` (`zfs`) and `system-ready`.
  - `key-provider` is `{"name":"kms","id":<DER P-256 SubjectPublicKeyInfo 3059…f844ee>}`.
  - Replaying RTMR0–3 reproduces the quote exactly. For RTMR3 each digest is recomputed as SHA-384(event_type u32 LE ‖ ":" ‖ name ‖ ":" ‖ payload).

  — [api.saygm.com/attestation/info](https://api.saygm.com/attestation/info) (verified by this researcher)
- `vm_config` is `{"os_image_hash":"4597735f…","cpu_count":2,"memory_size":4294967296,"qemu_version":"8.2.2","pci_hole64_size":0,"hugepages":false,"num_gpus":0,"num_nvswitches":0,"hotplug_off":false,"image":"dstack-0.5.15","host_share_mode":"9p","ovmf_variant":"pre202505","spec_version":1}`. The gateway is a 2-vCPU, 4 GiB CVM with no GPU. — [api.saygm.com/attestation/info](https://api.saygm.com/attestation/info)
- Phala's meta-dstack v0.5.15 release (2026-11-16) lists `dstack-0.5.15` = `4597735f1a38ad8ec9f781356b88737fc052062deb7c9aaa4be89bf1b35643ca`, so the gateway runs the **production** image. The dev variant `dstack-dev-0.5.15` is `432b8a1e…aebd`. The release adds the guest side of 0.6.5's "KMS-enforced launch tickets". — [meta-dstack v0.5.15](https://github.com/Dstack-TEE/meta-dstack/releases/tag/v0.5.15)
- Phala's register convention: RTMR3 = app-id, compose-hash, instance-id and key-provider. dstack-mr computes MRTD and RTMR0–2 from the image plus the VM shape. — [Phala attestation fields](https://docs.phala.com/phala-cloud/attestation/attestation-fields); [Phala: verify the platform](https://docs.phala.com/phala-cloud/attestation/verify-the-platform)

**TLS: the certificate is not `gateway_pubkey`, but it can be tied to the attested CVM**
- [live] TLS 1.3 to `api.saygm.com` presents leaf `CN=api.saygm.com`:
  - issued by Let's Encrypt `YE1` (chain YE1 → Root YE → ISRG Root X2);
  - serial `05C1E66E327DF493733F954BE5DC4247441B`, valid 2026-11-16 06:22 to 2027-02-14;
  - a P-256 key with SPKI SHA-256 `a58f285b…dee37e`.

  Its key is unrelated to the 32-byte `gateway_pubkey`. — [api.saygm.com](https://api.saygm.com/attestation/info)
- [live DNS]:
  - `api.saygm.com` is a CNAME to `_.dstack-pha1-prod9.phala.network` (66.220.6.109).
  - `_dstack-app-address.api.saygm.com` TXT = `"3c97764f8f3e6e450f31240ffcd0a28c17dc00db:443"`, which equals the attested `app_id`.
  - CAA at `api.saygm.com` = `0 issue "letsencrypt.org;validationmethods=dns-01;accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/3533020186"`. `saygm.com` has no CAA.

  — [Google DoH: CAA](https://dns.google/resolve?name=api.saygm.com&type=CAA); [Google DoH: TXT](https://dns.google/resolve?name=_dstack-app-address.api.saygm.com&type=TXT)
- SayGM says "HTTPS for api.saygm.com terminates inside the enclave" and "The confidential VM runs on Phala Cloud with dstack". — [saygm.com/privacy](https://saygm.com/privacy)
- [live] `https://api.saygm.com/evidences/` lists four files, all dated 23-Nov-2026 15:57:
  - `acme-account.json` (80 B, `{"body": {}, "uri": "https://acme-v02.api.letsencrypt.org/acme/acct/3533020186"}`);
  - `cert-api.saygm.com.pem` (4,796 B);
  - `quote.json` (15,977 B: hex quote, event log, report_data, vm_config);
  - `sha256sum.txt` (173 B).

  — [api.saygm.com/evidences/](https://api.saygm.com/evidences/)
- [live, verified by this researcher] Evidence checks:
  - `sha256sum.txt`'s hashes of both files match.
  - `quote.json` passes the same full DCAP check (UpToDate, debug off). Its REPORTDATA = SHA-256(`sha256sum.txt`) ‖ 32 zero bytes.
  - Its MRTD, MRCONFIGID and RTMR0–3 are **byte-identical** to the nonce-bound `/attestation/info` quote's, so the instance-id `bc672ebb…` is the same.
  - The certificate in the evidence has the **same serial and SPKI** as the live TLS leaf.
  - The ACME account URI equals the CAA `accounturi`.

  — [evidences/quote.json](https://api.saygm.com/evidences/quote.json); [evidences/sha256sum.txt](https://api.saygm.com/evidences/sha256sum.txt); [evidences/cert-api.saygm.com.pem](https://api.saygm.com/evidences/cert-api.saygm.com.pem)
- Phala's dstack-ingress README defines this chain and its limits:
  - report_data "is the SHA-256 of `sha256sum.txt` followed by 32 zero bytes … That is all it covers: no nonce, no timestamp, no TLS key, nothing about the connection".
  - The verifier must check (1) the quote is genuine; (2) "It is your app" (app_id, compose_hash, a known os_image_hash); (3) the files are the attested ones; (4) "The connection uses the attested certificate … Otherwise a man in the middle can serve its own certificate and relay the real `/evidences`"; (5) the CAA `accounturi` pin.
  - "The account key never leaves the CVM, so while these records are in place only the CVM can obtain a certificate". "whoever controls the DNS zone can remove the pin, get a certificate and put it back. Monitor Certificate Transparency logs".
  - The current README describes an HAProxy-based ingress. SayGM's server header and directory listing are nginx.

  — [dstack-ingress README](https://github.com/Dstack-TEE/dstack-examples/tree/main/custom-domain/dstack-ingress)

**History**
- Observations of the gateway's identity over the day:
  - The homepage panel showed gateway `gw-mainnet-2` at 07:27 UTC.
  - `gw-mainnet-1` answered at 17:05 UTC (earlier notes) and in all 6 successful calls here.
  - The panel read "gw-mainnet-1 … Last verified 23/11/2026, 18:09:41 UTC".

  — [other_subnets_survey.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/other_subnets_survey.md>); [all_inference_providers.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/all_inference_providers.md>); [saygm.com](https://saygm.com/)

### Inferences
- **What a device can establish for the gateway hop today, all locally:**
  - Freshness: a fresh nonce bound with `gateway_pubkey`.
  - Genuine, current hardware: genuine TDX at current TCB with debug off.
  - The workload: app `3c97764f…`, running compose `9fd0e3f1…` (in both MRCONFIGID and RTMR3) on dstack's production 0.5.15 OS with a KMS key provider.
  - The TLS key: the TLS certificate its session uses belongs to that same live instance. This needs a second, static quote matched to the fresh one by identical registers, plus a check that the live certificate's SPKI equals the attested one.

  Together these meet "TLS session that ends inside the TEE" for the **gateway** only. They do not reach the model (§3).
- The TLS binding is RA-TLS-like (a key bound once, by a static quote). Per the SEAT and CVE-2026-33697 analysis in the earlier notes, whoever extracts that key can relay. With Phala's custody, that would take a physical attack on Phala's host.
- The nonce-bound quote binds `gateway_pubkey`, a signing identity, not the TLS key. A one-quote design would put the TLS SPKI (or a TLS exporter) into the nonce-bound REPORTDATA.
- **Implementation pitfall for URnetwork's verifier:** send the nonce as standard base64, and hash the *decoded* bytes. The server accepts hex text and silently base64-decodes it.
- The `verification_status`/`verified_*`/`policy_accepted` fields are unsigned, and they are empty for a client-chosen nonce. The homepage "TEE attestation verified" panel is SayGM's registry verdict, served through Cloudflare (`saygm.com` resolves to Cloudflare). Neither is evidence a device can rely on; only its own DCAP check is.
- The gateway was redeployed or restarted today: the evidence files were written at 15:57 UTC, and the id changed from `gw-mainnet-2` (07:27) to `gw-mainnet-1`. A device must therefore expect `instance_id`, and perhaps `gateway_pubkey`, to change across redeploys, and re-verify per connection or session. `compose_hash` changes only when SayGM changes the workload.
- The `SGX-type` field value 1 corresponds, per Intel's PCK certificate profile, to "Scalable" without integrity. That would mean TDX's logical-integrity mode, which DDRop-class attacks target. This is an inference; the spec text was not re-read here.

### Gaps
- MRTD and RTMR0–2 were replayed but **not recomputed** from the `dstack-0.5.15` image with `dstack-mr` (it needs the image download and the tool). The OS identity rests on the event log's `os-image-hash` entry, which matches Phala's published production hash, and on SayGM's panel claim ("OS verification: Measurements matched").
- crt.sh returned 502, so no Certificate Transparency check was done for `api.saygm.com` certificates outside the evidence.
- Whether more than one gateway instance sits behind `api.saygm.com` at once is unknown; only `gw-mainnet-1` was seen in this session. Also unknown: whether the TLS key is dstack-ingress's deterministic, KMS-derived key (stable SPKI across renewals) or a certbot key.
- The meaning of the `mr-kms` event, and which KMS root `3059…f844ee` is, were not established. It could be Phala's cloud KMS or an on-chain DstackKms; this also matters for §2.

## 2. Does SayGM publish the gateway's measurements and code (open source, reproducible builds), so that a client can pin what reads plaintext inside the gateway?

### Takeaway
No for the gateway:
- Its code is in a private `gm` repository.
- Its `app-compose.json` (what `compose_hash` hashes) is not published anywhere found.
- SayGM publishes no approved-hash list for the gateway.

A device can pin `compose_hash` and `os_image_hash` (trust on first use, or SayGM's say-so) and detect changes. It cannot learn what code reads plaintext. Only the OS layer is reviewable, because it is Phala's published, reproducibly built dstack image.

The miner side is open source (Apache-2.0), with a public compose template. Its builds are "partially reproducible": deterministic Rust binaries, but not bit-for-bit Docker layers. The registry's approved miner image list is also not public.

### Cited Findings
- SayGM's verification criteria include "The measured workload matches an approved SayGM image". "The lower-level attestation verification interface is still being prepared for general buyer use. This page documents the trust model without asking users to depend on an unstable verification command." — [SayGM docs: TEE attestation](https://docs.saygm.com/security/attestation/)
- "When the gateway boots, dstack records measurements of the OS image and the exact container configuration into the TDX hardware … A valid quote shows … which OS image and container configuration it is running". Step 3 points to "the dstack verifier in Phala's platform verification guide". — [saygm.com/privacy](https://saygm.com/privacy)
- The homepage panel shows only truncated hashes:
  - "OS measurement 4597735f…5643ca"; "Workload measurement 9fd0e3f1…f6fc52";
  - "TDX quote: Signature verified"; "OS verification: Measurements matched"; "Gateway identity: Verified";
  - "A verifier outside the gateway checks hardware-signed evidence."

  — [saygm.com](https://saygm.com/)
- [live, GitHub API] The `taostat` organization has no public gateway or registry repository. `taostat/gm`, `taostat/gm-gateway`, `taostat/gm-registry` and `taostat/saygm` return 404. Public SN28 repos: `gm-miner` (pushed 2026-11-23), `gm-validator`, `gm-mcp`, `saygm-cookbook`, `saygm-desktop`. — [GitHub: taostat repos](https://api.github.com/orgs/taostat/repos?per_page=100&sort=pushed)
- The miner code refers to private paths in that repo: `gm/docs/contracts/gateway-attestation-info.md`, `gateway/src/attestation/keypair.rs`, `gateway/src/pipeline/retry.rs` and `registry/src/gm_registry/attestation/`. — [attestd/src/report_data.rs](https://github.com/taostat/gm-miner/blob/main/attestd/src/report_data.rs); [attestd/src/keypair.rs](https://github.com/taostat/gm-miner/blob/main/attestd/src/keypair.rs); [attestd/src/gateway_contract.rs](https://github.com/taostat/gm-miner/blob/main/attestd/src/gateway_contract.rs)
- [live] Places a compose or measurement list could be published were each checked; none publishes one:

  | Place | Result |
  |---|---|
  | `registry.saygm.com` (behind Cloudflare) | 404 for `/`, `/openapi.json`, `/v1/image-versions`, `/v1/images`, `/v1/gateways`, `/v1/workers` and similar; 200 only on `/healthz` |
  | Phala Trust Center page for the app | 503 "Under construction" |
  | Phala Cloud's app API | 401 "Not authenticated" |
  | The dstack public sysinfo host `<app_id>-8090.dstack-pha1-prod9.phala.network` | no connection |

  — [registry.saygm.com/healthz](https://registry.saygm.com/healthz); [Phala Trust Center](https://trust.phala.com/app/3c97764f8f3e6e450f31240ffcd0a28c17dc00db); [Phala Cloud API](https://cloud-api.phala.network/api/v1/apps/3c97764f8f3e6e450f31240ffcd0a28c17dc00db)
- [live] On Ethereum mainnet, the `app_id` address `0x3c97…00db` is not a contract (`is_contract: false`, no logs), so it is not an Ethereum DstackApp. The Base explorer was behind a Cloudflare challenge. — [eth.blockscout.com](https://eth.blockscout.com/api/v2/addresses/0x3c97764f8f3e6e450f31240ffcd0a28c17dc00db)
- The OS layer is public and reproducible:
  - The production `dstack-0.5.15` hash is published.
  - The release notes say a new `os_image_hash` "must be whitelisted in your KMS / `DstackKms` contract before CVMs can boot with it".
  - dstack's OS is built reproducibly (Yocto), and dstack-mr recomputes MRTD/RTMR0–2.

  — [meta-dstack v0.5.15](https://github.com/Dstack-TEE/meta-dstack/releases/tag/v0.5.15); [Phala: verify the platform](https://docs.phala.com/phala-cloud/attestation/verify-the-platform)
- Miner side:
  - `gm-miner` is Apache-2.0.
  - "Partially reproducible. The Rust binaries inside the image are deterministic given the same toolchain … The Docker layer structure is *not* bit-for-bit reproducible". "the **compose-hash** … is the primary measurement". "The registry's image versioning tracks compose-hash + os-image-hash (per `registry.proto`)".
  - "Operators can verify the measurement by re-running the build and comparing compose-hashes."

  — [gm-miner LICENSE](https://github.com/taostat/gm-miner/blob/main/LICENSE); [gm-miner docs/reproducibility.md](https://github.com/taostat/gm-miner/blob/main/docs/reproducibility.md)
- Miner deployment: "the CLI selects the approved image for its own release". "Deploy creates a Phala Cloud CVM, verifies the deployed image hashes against the registry's approved versions, and registers the worker". New CVMs use "`dstack-0.6.5` OS image, manifest v3, and an ephemeral data disk". — [gm-miner README](https://github.com/taostat/gm-miner)

### Inferences
- For URnetwork's E4 ("the provider publishes the measurements its images produce … with enough of the build to review"), SayGM's gateway **fails**. The compose is measured and pinnable, but neither its content nor its code is reviewable.
- Pinning `9fd0e3f1…` gives change detection only. SayGM can deploy a new compose at will; the evidence then shows a new hash, but a device cannot judge whether the new code is benign. No public, append-only log of approved gateway hashes was found. With Phala's on-chain KMS, a DstackApp contract would provide one, but the gateway's app id is not an Ethereum contract and Base could not be checked.
- The gateway therefore counts as provider code inside the boundary (URnetwork's AP shape), whatever its measurement status. And the device cannot see the downstream hops at all (§3).

### Gaps
- Whether SayGM's gateway app is governed by an on-chain allowlist (a DstackApp on Base) or by Phala's cloud KMS was not determined, because the Base explorer was blocked.
- Whether SayGM would publish `app-compose.json` or the gateway source on request is unknown.
- No public listing of the registry's approved miner or gateway image versions was found.

## 3. The `-tee` path after the gateway: route, who sees plaintext, whether the gateway verifies the miner CVM and the model TEE, and what (if anything) a client can see

### Takeaway
A `-tee` request travels: device → SayGM gateway CVM (TDX, Phala `prod9`; plaintext) → RA-TLS → an anonymous miner's CVM (TDX on Phala Cloud; plaintext) → the model TEE. The model TEE is reached in one of three ways:
- **Chutes**, ML-KEM E2E to an instance the miner admitted on nonce-bound TDX, GPU and pinned-measurement evidence;
- **KubeTEE**, attested TLS to `llm.kubetee.ai`, with **no** reference-measurement pinning in the miner's verifier;
- **NEAR AI Cloud**, attested TLS plus NRAS.

So plaintext exists in three TEEs. The model TEE is verified by the *miner's* open-source code; the miner CVM is verified by SayGM's closed gateway and registry. **The client sees none of it:**
- no route evidence, no signed statement, no public log;
- no per-response evidence;
- no propagation of the client's nonce.

`gateway_provider` in the catalog names the model maker, not the TEE host.

### Cited Findings
**Catalog and routing as a client sees it**
- [live] `/v1/models` lists 67 models, 11 of them confidential (`tier: confidential`, `confidential: true`): `deepseek-v3.2-tee`, `deepseek-v4-flash-0731-tee`, `gemma-4-31b-turbo-tee`, `glm-5.1-tee`, `glm-5.2-tee`, `glm-5.3-flash-tee`, `kimi-k2.6-tee`, `kimi-k3-tee`, `qwen3.5-397b-a17b-tee`, `qwen3.6-27b-tee` and `qwen3.8-27b-tee`. Their `gateway_provider` values are `deepseek`, `google`, `zai`, `moonshot` and `qwen`, i.e. the model makers. — [api.saygm.com/v1/models](https://api.saygm.com/v1/models)
- SayGM says "The `gateway_provider` field names the upstream service that receives the request when the route leaves the gateway", and "The `confidential` field is true only when inference runs in a TEE." — [saygm.com/privacy](https://saygm.com/privacy); [SayGM docs: privacy model](https://docs.saygm.com/security/privacy/)
- Buyers can restrict providers with `X-GM-Providers`; names include `kubetee`, `chutes`, `near` and `deepinfra`. Messages responses carry `x-gm-model-served` (`provider:model`). — [SayGM docs: routing](https://docs.saygm.com/api/routing/); [SayGM docs: Anthropic](https://docs.saygm.com/api/anthropic/) (via [all_inference_providers.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/all_inference_providers.md>))
- [live] The OpenAPI's paths are `/chat/completions`, `/responses`, `/credits`, `/messages`, `/v1beta/models/{modelAndAction}`, `/models`, `/models/{model}`, `/images/generations`, `/videos…`, `/messages/count_tokens`, `/guard/preview` and `/attestation/info`. The words "evidence" and "signature" appear nowhere in it. — [SayGM OpenAPI](https://saygm.com/openapi.json)

**Hop 1: the gateway**
- "API requests through the OpenAI, Anthropic and Gemini-compatible endpoints are decrypted and handled inside that enclave. Guardrails and routing run there too." — [saygm.com/privacy](https://saygm.com/privacy)

**Hop 2: gateway → miner CVM**
- The miner's data plane uses dstack RA-TLS:
  - The guest agent generates "a fresh P-256 key pair (random per call …)" and takes a quote with `report_data = SHA-512("ratls-cert:" || pubkey_der)`. It embeds the quote and event log in the leaf under OID `1.3.6.1.4.1.62397.1.8`.
  - "On connecting to the miner's `:8080` the gateway must, once per connection: 1. Parse the leaf cert … 2. Verify the quote with `dcap-qvl` — the same audited path the registry control loop already uses. 3. Recompute `SHA-512("ratls-cert:" || leaf_spki_der)` … 4. Replay the event log to RTMR3 and confirm the `compose_hash` maps to an approved `ImageVersion`."

  — [gm-miner attestd/src/ratls.rs](https://github.com/taostat/gm-miner/blob/main/attestd/src/ratls.rs)
- How the miner is reached: "the data plane MUST be reached through the dstack gateway's TLS-passthrough URL — the `s`-suffix form `https://<app-id>-8080s.<node>.phala.network`. The default `-8080` … has the dstack gateway terminate TLS at the edge". "`gmcli deploy` registers the `-8080s` passthrough URL with the registry".
- The gateway authenticates to the miner with a shared secret, not attestation. "GM_NODE_SECRET is the node secret (Mechanism 1 …): `gmcli deploy` generates it … and registers it with the registry. Envoy's inbound Lua filter enforces it as the `x-gm-node-key` header."
- The registry's attestation enforcement rejects a compose hash outside the approved versions.

  — [gm-miner dstack/docker-compose.yaml](https://github.com/taostat/gm-miner/blob/main/dstack/docker-compose.yaml)
- Miner CVMs run on the operator's own Phala Cloud account, with the registry-attested sizes `tdx.small` (1 vCPU/2 GiB) and `tdx.medium` (2 vCPU/4 GiB), so no GPU. "Your provider API keys … are baked into the miner container at deploy time and stay inside the TEE — gm never sees them." `gmcli worker list` shows each worker's "last attestation". — [gm-miner README](https://github.com/taostat/gm-miner)

**Hop 3: miner CVM → model TEE, by route**
- Route table for current `-tee` products, from the miner's sourcing doc:

  | Route | Serves |
  |---|---|
  | Chutes `-TEE` chutes on `llm.chutes.ai` | qwen3.5-397b-a17b-tee, qwen3.6-27b-tee, deepseek-v3.2-tee, deepseek-v4-flash-0731-tee, gemma-4-31b-turbo-tee, kimi-k2.6-tee, kimi-k3-tee, glm-5.1-tee, glm-5.2-tee |
  | KubeTEE (`llm.kubetee.ai`) | glm-5.2-tee, glm-5.3-tee, glm-5.3-flash-tee, deepseek-v4.1-flash(-1017)-tee, kimi-k3-tee, kimi-k3.1-pro-tee, mimo-v2.6-pro-ultraspeed-tee |
  | NEAR (`*.completions.near.ai`) | qwen3.8-27b-tee, glm-5.3-flash-tee |

  "One model can have several such routes and none of them is canonical." — [gm-miner docs/sourcing.md](https://github.com/taostat/gm-miner/blob/main/docs/sourcing.md); [gm-miner README](https://github.com/taostat/gm-miner)
- **Chutes:**
  - The verifier "fetches Chutes' signed evidence for the instances Chutes offers under a fresh nonce" and admits an instance when:
    - "its Intel TDX quote verifies at `UpToDate` TCB with the debug bit clear";
    - "the quote's `report_data` binds that nonce to the instance's end-to-end encryption key, and binds the key of the certificate that signed the evidence";
    - "its MRTD and runtime RTMR0-3 match a VM release Chutes publishes, from the measurement list compiled into this image";
    - "NVIDIA's attestation service verifies its GPUs under the same nonce".
  - "Each request is then encrypted end to end to an admitted instance's key … the response is released only after it authenticates". "Admissions are reused for up to 15 minutes".
  - Exception: "`-TEE` requests the gateway marks with `x-gm-ordinary: 1` because they serve a non-confidential product, use the direct HTTPS path to `llm.chutes.ai`."

  The compiled references are `attestd/references/chutes/measurements-2026-11-09.json` (e.g. "8xh200 [10.2.1]", RTMR3 zero). — [gm-miner docs/sourcing.md](https://github.com/taostat/gm-miner/blob/main/docs/sourcing.md); [measurements-2026-11-09.json](https://github.com/taostat/gm-miner/blob/main/attestd/references/chutes/measurements-2026-11-09.json)
- **KubeTEE:**
  - Each pooled TLS 1.3 connection is attested before use. Required:
    - the nonce echoed;
    - a `kubetee.attestation.v1` keyset naming the connection's serving key;
    - `report_data` = SHA-256 of the binding statement, zero-padded;
    - DCAP `UpToDate`, debug off;
    - the event log replaying to RTMR0–3;
    - the TLS key signing the nonce.
  - Connections are reused for 10 minutes or 100 requests. The verifier "logs the replica's pod name and measured registers (MRTD, MRCONFIGID, RTMR0-3)".
  - The module header lists the same checks, with no comparison against reference measurements. In the evidence code, `Measurements` is returned and logged, not matched.
  - The miner strips `x-kubetee-*` and `x-litellm-*` response headers.

  — [gm-miner docs/sourcing.md](https://github.com/taostat/gm-miner/blob/main/docs/sourcing.md); [kubetee_verify/mod.rs](https://github.com/taostat/gm-miner/blob/main/attestd/src/kubetee_verify/mod.rs); [kubetee_verify/evidence.rs](https://github.com/taostat/gm-miner/blob/main/attestd/src/kubetee_verify/evidence.rs)
- KubeTEE's own plaintext path is "Traefik TLS passthrough into an in-guest terminator, then attestation-gated TLS to model backends". — [KubeTEE README](https://github.com/KubeTEE-AI/kubetee-subnet) (via [other_subnets_survey.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/other_subnets_survey.md>))
- **NEAR:** "A new TLS connection receives nonce-bound evidence, and the verifier validates its Intel TDX quote, exact model id, live TLS public-key fingerprint, and compose measurement binding. A positive NVIDIA NRAS verdict is required". Connections are reused for 10 minutes or 100 requests. — [gm-miner docs/sourcing.md](https://github.com/taostat/gm-miner/blob/main/docs/sourcing.md)

**Who else checks**
- The gm validators do not verify evidence: "the validator treats the published artifact set as authoritative and does not re-derive cost or re-verify hashes or signatures. It only computes the weight vector." — [gm-validator README](https://github.com/taostat/gm-validator)
- SayGM's registry "requests fresh evidence with its own nonce and checks: 1 Quote signature 2 TCB status 3 OS measurements 4 Gateway identity". This is the *gateway's* evidence. — [saygm.com/privacy](https://saygm.com/privacy)

### Inferences
- **Plaintext holders on a `-tee` request:**
  - All routes: SayGM's gateway CVM (incl. opt-in guardrails), then the miner's CVM.
  - Chutes: plus the Chutes TEE instance, including Chutes' unmeasured serving code (RTMR3 = 0). Chutes' API sees ciphertext.
  - KubeTEE: plus KubeTEE's in-guest terminator and its backend pods.
  - NEAR: plus the NEAR model TEE.
  - Phala's dstack edges see ciphertext only, because both ingress hops are TLS passthrough.
- **Does the gateway verify?**
  - The miner CVM: yes per the miner repo's contract (RA-TLS per connection, plus the registry's DCAP loop). The gateway code is private, so this is SayGM's stated design, not something a client or this researcher can confirm.
  - The model TEE: no. The miner's image verifies it, and the gateway trusts the registry-approved miner image to do so.
  - Classification: the gateway alone decides whether a `-TEE` route request is "ordinary", a plaintext path to Chutes' API.
- **Client visibility is nil:**
  - The client's nonce reaches only `/attestation/info`.
  - Internal model evidence is per admission or connection (up to 15 or 10 minutes), never per request, and never bound to the client's nonce.
  - No response carries route or model-TEE evidence.
  - `x-gm-model-served` and any `X-GM-Providers` restriction (e.g. `chutes` to force the E2E route) are the gateway's word. Under btauth, `X-GM-Providers` is also an unsigned header (earlier notes).
- **The KubeTEE route is the weakest:** without pinned MRTD/RTMR references, any genuine, current, debug-off TDX VM that holds a keyset KubeTEE bound would pass. That leaves KubeTEE fully trusted for what runs. Inference from the published doc and code.
- SayGM's copy overstates the path. "your prompt is decrypted only within the enclave that runs the model" contradicts its own statement that the gateway decrypts requests, and the miner code shows a second decryption in the miner CVM. All three are TEEs, but not one.

### Gaps
- The gateway's actual RA-TLS verification, its approved-miner policy, and when it sets `x-gm-ordinary` are in private code.
- Which route the gateway picks per `-tee` model, and which routes the registry currently admits, are not public. Only miners see them, via `gmcli sources`.
- KubeTEE's backend-pod attestation (behind its terminator) and NEAR's "compose measurement binding" (pinned to published values or not) were not verified here.
- Whether `x-gm-model-served` is returned on OpenAI- and Gemini-shaped responses was not checked; a paid call would be needed.

## 4. Is there an end-to-end mode (client encrypts to a key inside the model's TEE; gateway carries only ciphertext)? If not, has SayGM announced one?

### Takeaway
No. Every request is TLS to the gateway, which decrypts it. The only E2E encryption in SayGM's system is the miner CVM's ML-KEM encryption to Chutes instances, which happens after two TEEs have read the plaintext. No client-side E2E mode is documented or announced. SayGM's "end to end" wording means "sealed in TEEs throughout", not client-held encryption.

### Cited Findings
- No E2E or evidence path exists among the OpenAPI's 14 paths (listed in §3). — [SayGM OpenAPI](https://saygm.com/openapi.json)
- "API requests … are decrypted and handled inside that enclave [the gateway]." — [saygm.com/privacy](https://saygm.com/privacy)
- SayGM's "end to end" claims:
  - "Confidential models: Your prompt stays inside the enclave, end to end. Open-weight models served inside a TEE, so your prompt is decrypted only within the enclave that runs the model." — [saygm.com/privacy](https://saygm.com/privacy); [saygm.com](https://saygm.com/)
  - "so inference itself runs sealed and the prompt stays inside the enclave end-to-end". — [saygm.com/llms.txt](https://saygm.com/llms.txt)
- The miner, not the client, does E2E to Chutes: "Each request is then encrypted end to end to an admitted instance's key and sent through Chutes' encrypted invocation endpoint". — [gm-miner docs/sourcing.md](https://github.com/taostat/gm-miner/blob/main/docs/sourcing.md)
- On a "lower-level attestation verification interface": "still being prepared for general buyer use". — [SayGM docs: TEE attestation](https://docs.saygm.com/security/attestation/)
- June 2026 roadmap items were "Attested Logs", BYOK, Teams and "Pay with Alpha"; there was no client E2E. — [TAO Daily, 2026-06-13](https://taodaily.io/gm-wants-to-be-bittensors-private-door-to-every-frontier-model/) (via [other_subnets_survey.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/other_subnets_survey.md>))

### Inferences
- The building blocks for an E2E pass-through already exist in SayGM's open miner code: Chutes evidence admission plus an ML-KEM-768 client. A pass-through would move that code to the device (URnetwork's sidecar), with the gateway and miner forwarding ciphertext and the chute and instance headers. See §6.

### Gaps
- No SayGM-specific source on client-side E2E plans was found. A general web search on 2026-11-23 ("SayGM confidential models end-to-end encryption attestation tee") returned only unrelated confidential-inference papers.
- SayGM's Discord and announcement channels were not searched; plans could exist there.

## 5. Who is in the trust boundary for a `-tee` request: SayGM (T34 Corporation FZCO, Dubai), miners, Phala, Chutes and KubeTEE (and NEAR)

### Takeaway
A device that verifies everything SayGM exposes still trusts all of these:
- **SayGM:** its closed gateway code, which it can redeploy; its registry, which approves miners and holds their node secrets; its DNS (the CAA pin); and its route choices.
- **Miners:** anonymous, but confined to registry-approved, open-source images on Phala Cloud.
- **Phala:** the dstack OS, the KMS that derives app keys, the hosts in its data centers, and its edge.
- **Intel.**
- **The model TEE operator:** Chutes (unmeasured serving code; its anonymous GPU miners' physical access), KubeTEE (no pinned measurements), or NEAR AI.

Only Intel and the gateway's measurements are checkable by the device today.

### Cited Findings
- **SayGM (T34 Corporation FZCO):**
  - The operator is "T34 Corporation FZCO, Dubai World Trade Centre Authority trade licence L-3102", under UAE law with Dubai courts. — [SayGM terms](https://saygm.com/terms) (via [all_inference_providers.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/all_inference_providers.md>))
  - The gateway and registry code is private (§2).
  - The registry holds every miner's node secret ("registers it with the registry"). — [gm-miner dstack/docker-compose.yaml](https://github.com/taostat/gm-miner/blob/main/dstack/docker-compose.yaml)
  - "The gm-operated epoch-finalizer is the single source of truth for per-record cost derivation". — [gm-validator README](https://github.com/taostat/gm-validator)
  - [live] `saygm.com`, `account.saygm.com`, `registry.saygm.com` and `docs.saygm.com` resolve to Cloudflare addresses (104.21.2.20, 172.67.128.151) with no CAA. Only `api.saygm.com` is TEE-terminated. — [Google DoH: account.saygm.com](https://dns.google/resolve?name=account.saygm.com&type=A)
- **Miners:**
  - Each runs its own Phala Cloud account and CVM, holds upstream API keys inside it, and chooses which upstream (Chutes, KubeTEE, NEAR) its worker serves. "A single worker can serve only one route per model." — [gm-miner README](https://github.com/taostat/gm-miner)
  - Miners use their own Chutes keys. Chutes' terms bar handing keys to end users (§3.3) and require a written agreement for standalone resale (§9.3). — [chutes_sn64.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/chutes_sn64.md>)
- **Phala:**
  - The gateway CVM runs on Phala Cloud `prod9` (CNAME `_.dstack-pha1-prod9.phala.network`). Its RTMR3 names a KMS key provider (`{"name":"kms",…}`). Miner CVMs use "the registry's default Phala KMS contract". — [api.saygm.com/attestation/info](https://api.saygm.com/attestation/info); [gm-miner README](https://github.com/taostat/gm-miner)
  - dstack's KMS derives app keys, including the gateway and miner identity keys ("derived from a dstack-KMS sealed key"). — [attestd/src/keypair.rs](https://github.com/taostat/gm-miner/blob/main/attestd/src/keypair.rs)
  - Phala is a Proof of Cloud Alliance member, and TEE.fail showed forged dstack attestation by a malicious provider with physical access. — [tee_attestation_verification.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/tee_attestation_verification.md>)
- **Chutes:** "AP for inference … the tenant image and serving code are Chutes' and unmeasured (RTMR3 = 0), and Chutes' platform releases the disk key". — [DESIGN-COMPUTE.md](</Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md>)
- **KubeTEE:** "KubeTEE AI LTD", two contributors, owner-run control plane; the miner's verifier pins no measurements (§3). — [other_subnets_survey.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/other_subnets_survey.md>); [kubetee_verify/mod.rs](https://github.com/taostat/gm-miner/blob/main/attestd/src/kubetee_verify/mod.rs)
- **NEAR AI:** an SGLang RCE was reported 2026-11-09, and "an 18-agent legacy deployment outside the TEE" was found. — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-confidential-ai-inference-tee-limits-20261/) (via [tee_attestation_verification.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/tee_attestation_verification.md>))
- **Let's Encrypt and the DNS operator:** the TLS-to-TEE binding holds "while these [CAA] records are in place". — [dstack-ingress README](https://github.com/Dstack-TEE/dstack-examples/tree/main/custom-domain/dstack-ingress)

### Inferences
- **What each party could do:**
  - SayGM could deploy a gateway compose that logs prompts. A pinning device would see a new `compose_hash` but could not tell what it does. SayGM could also approve a miner image that skips model-TEE checks, or mark `-tee` requests "ordinary".
  - Phala, or whoever has physical access to the gateway's and miners' hosts, sits where TEE.fail-class attacks apply.
  - Chutes, KubeTEE or NEAR read plaintext in their serving stack.
  - The anonymous miner is the party best contained: approved image, Phala-hosted, no physical access. This is an inference; no source states Phala excludes self-hosted dstack nodes for miners.
- Composite label rule (inference): a chain is no stronger than its weakest plaintext hop. Even a fully verifiable SayGM chain would inherit the AP label of Chutes, or worse for KubeTEE.

### Gaps
- Whether Phala's KMS for SayGM's gateway is Phala's cloud KMS or an on-chain DstackKms; this decides who can authorize a new gateway compose.
- Who physically hosts Phala `prod9`, and whether its chips are in a Proof of Cloud registry.
- SayGM publishes no DPA or contract text on miner data handling beyond its terms and privacy page.

## 6. What SayGM would need to add to meet a client-verified bar, at AP or A1

### Takeaway
**Today SayGM's `-tee` tier should be labeled "none" under URnetwork's rule.** The device can verify the gateway TEE and tie its TLS session to it. It cannot verify the miner CVM or the model TEE. The device is never handed a key that ends in the model's TEE. And the gateway, which reads plaintext, runs unpublished code. It meets E1 but fails E2–E4 at the model hop.

The shortest route to **AP** is an E2E pass-through: the device verifies Chutes' instance evidence and encrypts to the instance key itself, while SayGM's gateway and its miner forward ciphertext. That yields the same AP as Chutes direct (Chutes trusted; SayGM and miners outside), and it could be paid in gamma via btauth.

**A1** is not reachable through SayGM's current upstreams, because Chutes' serving code is unmeasured and KubeTEE's measurements are unpinned. A1 would also need SayGM's own plaintext-handling code to be public, reproducible and pinned.

### Cited Findings
- URnetwork's labels:
  - A1 `tee`: "E1-E4 hold, and every piece of code inside the TEE that handles plaintext is measured and pinned, so the provider cannot change what reads a request without changing the evidence".
  - AP `tee-platform`: "E1-E4 hold for the provider's base image, but the provider's own unmeasured code … or a key service it runs sits inside the boundary".
  - E2 Evidence: "the device fetches a CPU quote and, for GPUs, NVIDIA SPDM evidence, bound to a 32-byte nonce the device chose".
  - E3 End to end: "the key the device encrypts to is generated inside the TEE and bound in the quote's report data; the provider's gateway, validators and load balancers carry ciphertext".
  - E4 Measurements: "the provider publishes the measurements its images produce … with enough of the build to review".

  — [DESIGN-COMPUTE.md](</Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md>)
- What would move Chutes itself to A1: "the chute's image digest and serving code bound into the evidence (its issue #75 …), single-tenant VMs or a per-tenant key, and a disk key released by measurement". — [DESIGN-COMPUTE.md](</Users/brien/urnetwork/sidecar/DESIGN-COMPUTE.md>)
- Chutes' E2E interface:
  - `GET /chutes/{id}/evidence?nonce=` works anonymously. `/e2e/instances/{chute_id}` needs an API key and returns instance keys and single-use nonces. `POST /e2e/invoke` takes `X-Chute-Id`, `X-Instance-Id` and `X-E2E-Nonce`; there is also an `X-E2EE-Usage-Passthrough` header.
  - The binding is `REPORTDATA[0:32] = SHA256(nonce_hex ‖ e2e_pubkey_b64)`.
  - Relaying evidence without the instance keys leaves the client unable to check it (teep's NanoGPT note).

  — [chutes_sn64.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/chutes_sn64.md>)
- Binding guidance: a static key bound in REPORTDATA is relay-prone once that key is extracted. Bind to a TLS exporter or handshake, or use HPKE to an attested key. — [tee_attestation_verification.md](</Users/brien/urnetwork/sidecar/research_notes/Bittensor TEE inference and enclaves/tee_attestation_verification.md>)
- SayGM's miner already implements Chutes admission (DCAP, pinned MRTD/RTMR, NRAS, nonce-to-E2E-key binding) and ML-KEM E2E. — [gm-miner docs/sourcing.md](https://github.com/taostat/gm-miner/blob/main/docs/sourcing.md)

### Inferences
**For AP, either path (recommendation: path A first).**

Path A, E2E pass-through for Chutes `-TEE` routes. SayGM would add:
1. A per-model endpoint returning the chute id and the live instances' `e2e_pubkey`s with single-use E2E nonces, proxied with the miner's Chutes key. The device fetches nonce-bound evidence itself from `api.chutes.ai/chutes/{id}/evidence` (anonymous) or through SayGM, verifies it, and pins the chute id per model (E2, E4).
2. An opaque-body invoke route. The device's ML-KEM ciphertext plus the `X-Chute-Id`, `X-Instance-Id` and `X-E2E-Nonce` headers pass unchanged through the gateway and the miner to `/e2e/invoke`, and the encrypted stream comes back (E3: the gateway and miners carry ciphertext).
3. Billing from Chutes' plaintext usage summary (`X-E2EE-Usage-Passthrough`), since the gateway can no longer count tokens.
4. A refusal to downgrade: no `x-gm-ordinary` path on this route.

Result: the label equals Chutes direct (AP), with SayGM, its miners and Phala outside the boundary. A side benefit (inference): a gamma-payable relay for Chutes, which itself takes no gamma. Contract risk remains on miners reselling Chutes access (Chutes §9.3).

Path B, a verifiable chain of TEEs; plaintext stays in SayGM's TEEs. SayGM would add:
1. Gateway publication: the gateway's `app-compose.json` and source, or at least digest-pinned images with a reproducible build. An append-only record of authorized gateway compose hashes, e.g. a DstackApp allowlist on-chain or Sigstore/Rekor (E4).
2. Session binding: the TLS SPKI, or better a TLS-exporter value, in the *nonce-bound* REPORTDATA, instead of relying on the static `/evidences/` quote.
3. Per-response route evidence, signed by the quote-bound `gateway_pubkey` and bound to the client's nonce or request id. It would carry: the miner worker's RA-TLS quote, compose hash and instance; the model TEE's evidence the miner admitted (Chutes instance id, quote, GPU evidence), with the miner's admission nonce *derived from* the client's nonce; and an explicit "confidential, not ordinary" flag.
4. Public, signed lists of approved miner images and of KubeTEE or NEAR reference measurements, and actual MRTD/RTMR pinning in the KubeTEE verifier.

Even then the label is **AP at best**: SayGM's own code inside the chain is trusted, and Chutes' serving code is unmeasured. Path B is more work for SayGM and weaker for URnetwork than Path A.

**For A1,** everything above, plus:
- every plaintext-handling component reviewable and pinned: the gateway, the miner image (bit-for-bit reproducible, which the miner doc says it is not), and the model TEE's serving code;
- a model TEE operator that measures its serving stack. None qualifies today: Chutes issue #75 is open, KubeTEE is unpinned, and NEAR's binding was unverified here.

Realistically this is not reachable through SayGM until an upstream reaches A1. A2 would further need custody evidence, e.g. Proof of Cloud entries for each hop's PPID or chip ID.

**Interim guidance for URnetwork (recommendation):**
- List SayGM `-tee` as "none".
- It may still be preferable to frontier or `open` routes as "operator-sealed by SayGM's claim", but this must not be displayed as a TEE label.
- The gateway's own attestation is worth verifying anyway when the device uses SayGM: it protects against URnetwork's network and Phala's edge reading traffic. It does not protect against SayGM.

### Gaps
- Whether SayGM is willing to build an E2E pass-through, and whether Chutes' terms let miners relay E2E for SayGM's buyers, needs direct contact with both.
- Whether Chutes' `/e2e/instances` nonces can be fetched by one party (SayGM or the miner) and used by another (the device) was not tested. The E2E post's 60–75 s nonce lifetimes suggest it can work if relayed promptly.
