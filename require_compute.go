//go:build tools

// Holds the modules compute adds (DESIGN-COMPUTE.md Appendix D's §4.5 and §4.7 row, and the owner's QD-1254) in the
// graph of every module that builds this package, ahead of the tasks that import them (CARCH-M11-02, CONTRACTS C-28).
// go mod tidy reads every build tag, so each import keeps its module's require here and in every module that builds
// the root: cli, smtpproof and mlsinterop, server, sn and sdk's four. No build sets the tag, so this file links none of
// them, and dependencies.yml keeps each planned until a leg links it. Each line names the package its first importing
// task reads, so the requires already hold what that package needs; once a shipped file imports one, its line here
// says nothing more and the review phase prunes it.
package sidecar

import (
	// drand's beacon signatures over BLS12-381 (ATTEST-M15-03, §5.6)
	_ "github.com/cloudflare/circl/sign/bls"
	// the enclave SSH server's shell sessions (§12.4)
	_ "github.com/creack/pty"
	// the search signer's EIP-712 signatures (§21.5)
	_ "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	// LiteRT-LM's and ONNX Runtime's C libraries without cgo, in the local engine and the safety classifier (§6.5, §27.5)
	_ "github.com/ebitengine/purego"
	// calendars (§23.7)
	_ "github.com/emersion/go-ical"
	_ "github.com/emersion/go-webdav/caldav"
	// SEV-SNP reports, through third_party/go-sev-guest (ATTEST-M14-02, §5.3)
	_ "github.com/google/go-sev-guest/validate"
	_ "github.com/google/go-sev-guest/verify"
	// TDX quotes, through third_party/go-tdx-guest (ATTEST-M14-01, §5.3)
	_ "github.com/google/go-tdx-guest/validate"
	_ "github.com/google/go-tdx-guest/verify"
	// SVSM's vTPM quotes and credential activation (ENC-M14-07, §11.7)
	_ "github.com/google/go-tpm/tpm2"
	// the evidence tunnel (ATTEST-M14-03, §5.7)
	_ "github.com/gorilla/websocket"
	// the enclave SSH server's sftp subsystem (§12.4)
	_ "github.com/pkg/sftp"
	// NVIDIA's reference integrity manifests (ATTEST-M15-02, §5.3)
	_ "github.com/russellhaering/goxmldsig"
	// the gateway's re-encoding of oversized WebP images (§8.5)
	_ "golang.org/x/image/webp"
)
