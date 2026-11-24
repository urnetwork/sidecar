# Local go-tdx-guest subset

This directory holds seven packages of `github.com/google/go-tdx-guest` at
`v0.3.2-0.20261123220626-a4ee4f4ee52a`, main's commit a4ee4f4e of 2026-11-23
(module zip `h1:jUvjNncAAS1qxnHGPgQLfMA2MMBnYDKbFFRdNsUnRXU=`, fetched through
proxy.golang.org and checked against Go's checksum database), and what their
own tests read. DESIGN-COMPUTE.md §5.3 builds the TDX verifier on it, vendored
and pinned (Appendix D's §4.5 and §4.7 row), and CARCH-M11-02 vendors it so
ATTEST-M14-01 only imports it (CONTRACTS C-28). The module path stays
`github.com/google/go-tdx-guest`, so a module replaces it here.

The pin is main, not a tag: the design's research read main on 2026-11-23, and
the one tag, v0.3.1 of 2024-02-16, reads no version 5 quote, where §5.3 checks
quotes v4 and v5. go-tdx-guest is Apache-2.0, in `LICENSE`, Copyright Google
LLC. Nothing here is changed: each kept file is as published.

## What is kept

The verifier ATTEST-M14-01 imports and every package it imports:

- `abi`: quote v4 and v5 and DICE-signed quote parsing, with its tests;
- `pcs`: Intel PCS's collateral types, with its tests;
- `proto/tdx` and `proto/checkconfig`, with `proto/tdx.proto`,
  `proto/checkconfig.proto` and `proto/doc.go`, their sources;
- `verify`: the signature chain, the collateral checks and Intel's SGX root in
  `trusted_root.pem`, with its tests;
- `verify/trust`: the getter interfaces the collateral client implements, with
  its tests;
- `validate`: the policy checks over a verified quote's body, with its tests.

What those tests read:

- `testing`: the mocks and test cases `verify`'s tests use;
- `testing/testdata`: sample quotes (v4, v5 and DICE), a TD report, Intel PCS
  responses (TCB info v4 and v5, QE identity), the PCK and root CRLs, and the
  CCEL quote its embed names. ATTEST-M14-01's sample-quote tests read these too;
- `client/linuxabi`: the TDX guest ABI's types, which `testing` imports; it
  opens no device.

## What is not

`client` (the guest's `/dev/tdx_guest` and configfs-tsm quote providers),
`testing/client`, `rtmr` (CCEL event-log replay, which reaches go-configfs-tsm
and go-eventlog; ATTEST-M14-01 replays RTMR3 from the profile's events itself,
§11.7), `gce` (GCE metadata and provenance), `verify/dice` (a DICE root nothing
kept imports), `tools/`, `README.md`, `CONTRIBUTING.md`, `.github/` and
`.goreleaser.yml`.

At this commit no kept package imports go-sev-guest: only `tools/check` does,
for its command line. CARCH-M11-02's plan line reads the verifier as reaching
go-sev-guest's trust package; at this version it does not, so the two trees
stand apart, and `../go-sev-guest` is ATTEST-M14-02's SEV-SNP verifier alone.

`go.mod` is upstream's, tidied over the kept packages: it requires cbor
v2.9.6, go-cmp v0.6.0 (tests only), logger v1.1.1, go-cose v1.1.0, multierr
v1.11.0, x/crypto v0.17.0 and protobuf v1.34.2, with float16 v0.8.4 and x/sys
v0.19.0 indirect, all at upstream's versions, and no longer go-configfs-tsm,
go-eventlog, go-sev-guest or go-tpm. A consumer's graph selects its own newer
x/crypto, x/sys and protobuf over these.

## Network

`verify`'s default getter fetches Intel PCS collateral with `net/http`
(`trust.SimpleHTTPSGetter`, `trust.RetryHTTPSGetter`). §5.3 and §5.7 fetch
collateral only through the collateral cache, so ATTEST-M14-01 passes its
`AttestCollateralClient` as the getter and never leaves the default in place.

## Checked here

- `go vet ./...` and `go test ./...` in this directory pass: `abi`, `pcs`,
  `validate`, `verify` and `verify/trust`. The tests read `testing/testdata`
  through recording getters and dial nothing.

## Who replaces it

Go does not inherit a replace, so each module that links sidecar's root repeats
one, as for `../go-smtp` and `../mox`: `./third_party/go-tdx-guest` in
`sidecar/go.mod`; `../third_party/go-tdx-guest` in `sidecar/cli`,
`sidecar/smtpproof` and `sidecar/mlsinterop`; `../sidecar/third_party/go-tdx-guest`
in server, sn and sdk; and `../../sidecar/third_party/go-tdx-guest` in sdk's
`build`, `cgo` and `js`. sidecar's `require_compute.go` keeps the require in
each of them until ATTEST-M14-01 imports `verify`. The release step leaves
`third_party/` beside `v2026/` (QD-920) and rebases the root's replace, as for
go-smtp and mox. Upstream's API is a superset of this subset's, so a build
without the replace resolves upstream at the same version.

To move the pin, take the new version through the proxy, copy the same
packages, tidy and rerun the tests here, and update this file, its
`dependencies.yml` row, its NOTICE entry and the require in every module above.
