// §22.7's actions row's fixtures (MCP-M3-26; D-MCP-17, I-7, X1) and the parts of CC4 that MCP work reaches, which
// mcp's actions suite and S9 (scenario_s9_test.go) run on:
//
//   - a fixture ACME account key, as certs keeps one in a network's secret repo (§13.8): a fresh P-256 key whose
//     PKCS#8 DER and PEM are reported to the privacy capture as secrets, so every scan looks for them, raw and in
//     every encoding §22.7 names;
//   - the statements §16.6 says no MCP path signs, whatever a tool claims of its own resources: BridgeBlock,
//     BridgeEgress, Suspend, EvsShare, OwnerConfirm and the access log's, each repo statement §8.8 folds into a repo's
//     access log;
//   - McpCc4: what CC4 names for MCP work, each MCP result, the environment, each hook's answer and the daemon's log,
//     kept on one PrivacyCapture, and under sidecar_testhooks every key testHookSecret reports while it is open.
//
// Every value is synthetic. Safe for concurrent use.

package sidecartest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A fixture ACME account key: its PKCS#8 DER and its PEM.
type FixtureAcmeAccountKey struct {
	Der []byte
	Pem []byte
}

// A fresh fixture key, its DER and its PEM reported to capture as secrets.
func NewFixtureAcmeAccountKey(capture *PrivacyCapture) (*FixtureAcmeAccountKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	capture.AddSecret("acme_account_key", der)
	capture.AddSecret("acme_account_key_pem", encoded)
	return &FixtureAcmeAccountKey{Der: der, Pem: encoded}, nil
}

// The statements no MCP path may sign (§16.6's refused table; D-MCP-17).
func McpRefusedStatements() []bridge.SignedType {
	return []bridge.SignedType{
		bridge.SignedType_SIGNED_BRIDGE_BLOCK,
		bridge.SignedType_SIGNED_BRIDGE_EGRESS,
		bridge.SignedType_SIGNED_SUSPEND,
		bridge.SignedType_SIGNED_EVS_SHARE,
		bridge.SignedType_SIGNED_OWNER_CONFIRM,
		// the access log's (§8.8): what a repo's log folds
		bridge.SignedType_SIGNED_REPO_CREATE,
		bridge.SignedType_SIGNED_REPO_ADMIN,
		bridge.SignedType_SIGNED_REPO_GRANT,
		bridge.SignedType_SIGNED_REPO_REVOKE,
		bridge.SignedType_SIGNED_REPO_DELETE,
		bridge.SignedType_SIGNED_REPO_RESTORE,
		bridge.SignedType_SIGNED_REPO_VERSIONING,
		bridge.SignedType_SIGNED_AUDIT_OPT_IN,
		bridge.SignedType_SIGNED_AUDIT_OPT_OUT,
		bridge.SignedType_SIGNED_REPO_PREFIX_RULES,
	}
}

// CC4 for MCP work on one capture. See the file header.
type McpCc4 struct {
	Capture *PrivacyCapture
	remove  func()
}

// A capture of what CC4 names for MCP work: the process's environment now, and under sidecar_testhooks every key
// testHookSecret reports until Close. Fails while another installation of the hooks stands.
func NewMcpCc4() (*McpCc4, error) {
	capture := NewPrivacyCapture()
	self := &McpCc4{Capture: capture, remove: func() {}}
	capture.AddEnvironment("process", os.Environ())
	if HooksLinked {
		remove, err := InstallTestHooks(func(kind string, secret []byte) {
			capture.AddSecret(kind, secret)
		}, nil)
		if err != nil {
			return nil, err
		}
		self.remove = remove
	}
	return self, nil
}

// The daemon's log, its every line kept.
func (self *McpCc4) Log(source string) sidecar.Logger {
	return self.Capture.Logger(source)
}

// One MCP result, as the session got it.
func (self *McpCc4) Result(source string, body []byte) {
	self.Capture.Add(PrivacyClassMcp, source, body)
}

// What a hook answered its harness: its stdout and its error's text.
func (self *McpCc4) Hook(source string, body []byte) {
	self.Capture.Add(PrivacyClassHook, source, body)
}

// Every finding over what was kept: a canary or a secret where CC4 may hold none.
func (self *McpCc4) Scan() []*PrivacyFinding {
	return self.Capture.Scan()
}

// Takes the hooks off.
func (self *McpCc4) Close() {
	self.remove()
}
