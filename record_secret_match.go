//go:build !ios_extension

// Sidecar.SecretMatcher (I-7, R-MCP-9): what no tool result may carry. MCP's tool framework refuses a result that
// matches, and its errors never echo an input that does (mcp/tool.go). A SecretMatcher matches two things:
//
//	credentials  the values the daemon holds that grant something: the client's bearer token (by_jwt), the identity
//	             key's and the ClientKey's seeds and their Ed25519 private keys, each raw, as hex in either case and
//	             as base64 in the standard and URL alphabets, padded and not
//	token forms  every rule of the redactor's (record_redact_rules.go), PII aside, which is no credential: the shapes a
//	             leaked token of any service takes, the daemon's own or not
//
// A credential shorter than SecretMatchSettings.CredentialMinByteCount (settings_mcp.go) is skipped, so a short or empty value never
// matches everything. A match reports the class that matched, "credential" or the redactor's rule, and its offset,
// never the bytes.
//
// The keys are read where they are made, so each read reaches testHookSecret (identity_keys.go, api_token_manager.go),
// and a matcher holds copies of them in memory for its life: build one per call, or per credential change. A
// SecretMatcher is immutable and safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// The class a credential's match reports.
const SecretMatchCredential = "credential"

// Where a secret is in a text: the class that matched and its offset, never its bytes.
type SecretMatch struct {
	// SecretMatchCredential, or a redactor rule's id.
	Class string
	// Bytes from the text's start.
	Offset int
}

// The matcher: each credential's encodings, and the redactor's rules.
type SecretMatcher struct {
	forms [][]byte
}

// A matcher of credentials, each copied in all its encodings. settings nil is the defaults.
func NewSecretMatcher(credentials [][]byte, settings *SecretMatchSettings) *SecretMatcher {
	if settings == nil {
		settings = DefaultSecretMatchSettings()
	}
	self := &SecretMatcher{}
	add := func(form []byte) {
		if len(form) == 0 || len(form) < settings.CredentialMinByteCount {
			return
		}
		for _, existing := range self.forms {
			if bytes.Equal(existing, form) {
				return
			}
		}
		self.forms = append(self.forms, bytes.Clone(form))
	}
	for _, credential := range credentials {
		if len(credential) < settings.CredentialMinByteCount {
			continue
		}
		add(credential)
		lowerHex := hex.EncodeToString(credential)
		add([]byte(lowerHex))
		add(bytes.ToUpper([]byte(lowerHex)))
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			add([]byte(encoding.EncodeToString(credential)))
		}
	}
	return self
}

// The first secret in text, by offset, nil for none: a credential in any encoding, or a token a redactor rule finds.
func (self *SecretMatcher) Match(text []byte) *SecretMatch {
	var first *SecretMatch
	note := func(class string, offset int) {
		if first == nil || offset < first.Offset {
			first = &SecretMatch{Class: class, Offset: offset}
		}
	}
	if self != nil {
		for _, form := range self.forms {
			if offset := bytes.Index(text, form); 0 <= offset {
				note(SecretMatchCredential, offset)
			}
		}
	}
	matches, _ := findRedactMatches(text, false)
	for _, match := range matches {
		note(match.Rule, match.Start)
	}
	return first
}

// Whether text holds a secret.
func (self *SecretMatcher) Matches(text []byte) bool {
	return self.Match(text) != nil
}

// How many encoded forms the matcher holds: for a test, never their bytes.
func (self *SecretMatcher) FormCount() int {
	if self == nil {
		return 0
	}
	return len(self.forms)
}

// The credentials this sidecar holds now, as a matcher (I-7): its bearer token and its keys, read from the network's
// keychain. ErrSidecarStoreLocked's error while Locked and ErrSidecarNoIdentity before enrollment, so a caller that
// cannot build one refuses rather than answers unchecked. A sidecar holding a key but no token matches the keys.
func (self *Sidecar) SecretMatcher() (*SecretMatcher, error) {
	var state SidecarState
	var secrets SidecarSecrets
	var settings *SecretMatchSettings
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state = self.lifecycle.state
		secrets = self.coreSecrets
		settings = self.settings.Mcp.SecretMatch
	}()
	if state == SidecarStateLocked {
		return nil, fmt.Errorf("secret matcher: %w", ErrSidecarStoreLocked)
	}
	if secrets == nil {
		return nil, fmt.Errorf("secret matcher: %w", ErrSidecarNoIdentity)
	}
	credentials := [][]byte{}
	defer func() {
		for _, credential := range credentials {
			clear(credential)
		}
	}()
	record, err := loadSidecarIdentity(secrets)
	if err != nil {
		return nil, fmt.Errorf("secret matcher: %w", err)
	}
	defer record.keys.erase()
	for _, seed := range [][]byte{record.keys.identitySeed, record.keys.clientKeySeed} {
		if len(seed) != ed25519.SeedSize {
			continue
		}
		credentials = append(credentials, bytes.Clone(seed), []byte(ed25519.NewKeyFromSeed(seed)))
	}
	byJwt, err := loadSidecarByJwt(secrets)
	switch {
	case err == nil:
		credentials = append(credentials, []byte(byJwt))
	case !errors.Is(err, ErrSidecarStoreAbsent):
		return nil, fmt.Errorf("secret matcher: %w", err)
	}
	return NewSecretMatcher(credentials, settings), nil
}
