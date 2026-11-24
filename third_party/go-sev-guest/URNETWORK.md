# Local go-sev-guest subset

This directory holds seven packages of `github.com/google/go-sev-guest` at
`v0.15.1-0.20261120002523-d591100d9985`, main's commit d591100d of 2026-11-20
(module zip `h1:M9lFahd3jw1/A8Zm8Fl+uO1LNLTsOdgIdd/jBgRPgxk=`, fetched through
proxy.golang.org and checked against Go's checksum database), and what their
kept tests read. DESIGN-COMPUTE.md §5.3 builds the SEV-SNP verifier on it,
vendored and pinned (Appendix D's §4.5 and §4.7 row), and CARCH-M11-02 vendors
it so ATTEST-M14-02 only imports it (CONTRACTS C-28). The module path stays
`github.com/google/go-sev-guest`, so a module replaces it here.

The pin is main as the design's research read it on 2026-11-23 (the AMD
SEV-SNP ABI up to revision 1.58); the newest tag is v0.15.0 of 2026-06-09.
go-sev-guest is Apache-2.0, in `LICENSE`, Copyright Google LLC. Nothing here
is changed: each kept file is as published, and two test files are left out
(below).

## What is kept

The verifier ATTEST-M14-02 imports and every package it imports:

- `abi`: the attestation report, its certificate table and the CPUID family
  checks (`cpuid_amd64.s` included), with its tests and fuzz corpus;
- `kds`: AMD KDS's URLs and the VCEK and VLEK certificate extensions, with its
  tests;
- `proto/sevsnp` and `proto/check`, with `proto/sevsnp.proto`,
  `proto/check.proto` and `proto/doc.go`, their sources;
- `verify`: the VCEK or VLEK, ASK and ARK chain and the report's signature;
- `verify/trust`: the getter interfaces and AMD's embedded ARK and ASK
  certificates for Milan, Genoa and Turin, VCEK and VLEK, with its tests;
- `validate`: the policy checks over a verified report.

What the kept tests read:

- `verify/testdata`: a sample report and VCEK certificates;
- `testing`: fake certificate chains, a fake KDS and test cases, with its tests;
- `testing/data`: the test-only signing keys upstream publishes for those fake
  chains, which sign test certificates and nothing else;
- `proto/fakekds`, with `proto/fakekds.proto`, which `testing` imports;
- `client/linuxabi`: the SEV guest ABI's types, which `testing` imports; it
  opens no device.

## What is not

`client` (the guest's `/dev/sev-guest` and configfs-tsm report providers),
`testing/client`, `tools/`, `README.md`, `INSTALL.md`, `LIMITATIONS.md`,
`CONTRIBUTING.md`, `.github/`, `.gitignore` and `.goreleaser.yaml`. Two test
files go with `client`: `verify/verify_test.go` and `validate/validate_test.go`
drive a fake `/dev/sev-guest` through `client` and `testing/client`, so they
cannot build here; ATTEST-M14-02's own tests carry the verifier's coverage,
over sample reports and `computetest.FakeTeeEvidence`'s.

`go.mod` is upstream's, tidied over the kept packages: it requires go-cmp
v0.5.7 (tests only), logger v1.1.1, uuid v1.6.0, multierr v1.11.0, x/crypto
v0.17.0, x/sys v0.15.0 and protobuf v1.33.0, with x/xerrors indirect, all at
upstream's versions, and no longer golang/protobuf or go-configfs-tsm. A
consumer's graph selects its own newer x/crypto, x/sys and protobuf over these.

## Network

`verify`'s default getter fetches certificates from AMD's KDS with
`net/http`. §5.3 and §5.7 fetch them only through the collateral cache, so
ATTEST-M14-02 passes its `AttestCollateralClient` as the getter and never
leaves the default in place.

## Checked here

- `go vet ./...` and `go test ./...` in this directory pass: `abi`, `kds`,
  `testing` and `verify/trust`. The tests dial nothing.

## Who replaces it

The same modules as `../go-tdx-guest`, with the same paths ending in
`third_party/go-sev-guest`, and for the same reason: Go does not inherit a
replace. sidecar's `require_compute.go` keeps the require in each of them until
ATTEST-M14-02 imports `verify`. The release step leaves `third_party/` beside
`v2026/` (QD-920) and rebases the root's replace, as for go-smtp and mox.
Upstream's API is a superset of this subset's, so a build without the replace
resolves upstream at the same version.

To move the pin, take the new version through the proxy, copy the same
packages, tidy and rerun the tests here, and update this file, its
`dependencies.yml` row, its NOTICE entry and the require in every module above.
