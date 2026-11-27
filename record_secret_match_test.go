//go:build !ios_extension

// Sidecar.SecretMatcher (I-7): each credential matches raw, as hex in either case and as base64 in both alphabets,
// padded and not; a value under the settings' bound and ordinary text match nothing; the redactor's token forms match
// with no credential; a match names its class and offset, never the bytes; and on every leg the connect identity seed
// and every reader key a keychain keeps are credentials, a reader key the keychain cannot give failing the read.
// record_secret_match_sidecar_test.go holds a sidecar's own matcher, and record_secret_match_connect_test.go a connect
// leg's connect identity.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A GitHub token shape the redactor's github-pat rule finds: synthetic, mixed characters for its entropy bound.
const testSecretMatchToken = "ghp_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"

// Each encoding a leaked credential is likely to take, as NewSecretMatcher lists them: raw, hex in either case, and
// base64 in the standard and URL alphabets, padded and not.
func testSecretMatchForms(credential []byte) map[string]string {
	lowerHex := hex.EncodeToString(credential)
	return map[string]string{
		"raw":            string(credential),
		"hex":            lowerHex,
		"upper hex":      strings.ToUpper(lowerHex),
		"base64":         base64.StdEncoding.EncodeToString(credential),
		"raw base64":     base64.RawStdEncoding.EncodeToString(credential),
		"url base64":     base64.URLEncoding.EncodeToString(credential),
		"raw url base64": base64.RawURLEncoding.EncodeToString(credential),
	}
}

// The matcher catches credential in each of its forms as a credential: inside a tool result's text, at its offset, and
// inside an error's text, as MCP checks both (mcp/tool.go), and in a result's JSON, which carries bytes as base64.
func testSecretMatchCaught(t *testing.T, matcher *SecretMatcher, name string, credential []byte) {
	t.Helper()
	prefix := "a tool result with "
	for form, encoded := range testSecretMatchForms(credential) {
		text := []byte(prefix + encoded + " in it")
		if match := matcher.Match(text); match == nil || match.Class != SecretMatchCredential || match.Offset != len(prefix) {
			t.Errorf("%s, %s, in a result: %+v", name, form, match)
		}
		toolErr := fmt.Errorf("the call failed on %s", encoded)
		if match := matcher.Match([]byte(toolErr.Error())); match == nil || match.Class != SecretMatchCredential {
			t.Errorf("%s, %s, in an error: %+v", name, form, match)
		}
	}
	result, err := json.Marshal(map[string]any{"result": credential})
	if err != nil {
		t.Fatal(err)
	}
	if match := matcher.Match(result); match == nil || match.Class != SecretMatchCredential {
		t.Errorf("%s, in a result's json: %+v", name, match)
	}
}

// No form of a public value matches as a credential: each text is the form alone, so a credential holding it would
// match at its start, before any redactor rule could.
func testSecretMatchNotCaught(t *testing.T, matcher *SecretMatcher, name string, public []byte) {
	t.Helper()
	for form, encoded := range testSecretMatchForms(public) {
		if match := matcher.Match([]byte(encoded)); match != nil && match.Class == SecretMatchCredential {
			t.Errorf("%s, %s, matched as a credential", name, form)
		}
	}
}

// The reader keys a network's keychain keeps (§5.9's keychain.ur), each made as its maker makes it: enrollment's first
// ReaderKey and a Delegation's reader seed in the core's namespace, and the generations gkm's upkeep keeps under its
// own, by upkeep's ReaderKey step on a clock the test moves.
type testSecretMatchReaderKeys struct {
	upkeep *GkmUpkeep
	api    *gkmTestUpkeepApi
	clock  *gkmTestClock
	// enrollment's first ReaderKey (identity_enroll.go)
	firstSeed []byte
	// a pre-approved key's Delegation reader seed (identity_admission.go)
	delegationSeed []byte
}

// Keeps enrollment's first ReaderKey and a Delegation's reader seed in secrets, the core's namespace of networkId's
// keychain in instance, and an upkeep on that keychain's gkm namespace, as GkmUpkeepArgs gives the daemon's, which
// keeps no generation until keep runs its step. The upkeep runs no loop, so nothing is left to end.
func newTestSecretMatchReaderKeys(t *testing.T, instance *SidecarInstance, networkId Id, secrets SidecarSecrets) *testSecretMatchReaderKeys {
	t.Helper()
	firstSeed, err := newSidecarReaderKeySeed(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.Put(sidecarReaderKeyRecordName, firstSeed); err != nil {
		t.Fatal(err)
	}
	delegationSeed := make([]byte, authKeySeedByteCount)
	rand.Read(delegationSeed)
	if err := keepDelegationReaderKey(secrets, &AuthKeyBundle{DelegationReaderSeed: bytes.Clone(delegationSeed)}); err != nil {
		t.Fatal(err)
	}
	_, identityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sidecarId := NewId()
	keys := &testSecretMatchReaderKeys{
		api:            &gkmTestUpkeepApi{},
		clock:          newGkmTestClock(),
		firstSeed:      firstSeed,
		delegationSeed: delegationSeed,
	}
	keys.upkeep, err = newGkmUpkeep(context.Background(), &GkmUpkeepArgs{
		SidecarId: sidecarId,
		Api:       keys.api,
		Sign: func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
			return &bridge.Signed{
				Body:      bytes.Clone(body),
				SignerId:  sidecarId.Bytes(),
				Signature: ed25519.Sign(identityKey, bridge.SignedBytes(purpose, signedType, body)),
				Type:      uint32(signedType),
			}, nil
		},
		Secrets: instance.secrets(networkId, gkmUpkeepSecretsNamespace),
		Clock:   keys.clock,
		Log:     NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// Moves the clock by advance and runs upkeep's ReaderKey step at its now, as a pass does: a fresh generation once the
// current one is 6 days old, and each one 30 days past its not_after erased.
func (self *testSecretMatchReaderKeys) keep(t *testing.T, advance time.Duration) {
	t.Helper()
	self.clock.Advance(advance)
	if err := self.upkeep.keepReaderKey(context.Background(), self.clock.Now()); err != nil {
		t.Fatal(err)
	}
}

// The newest generation's seed, read back as upkeep opens it (ReaderPrivateKey), which is its private key's bytes, and
// what is public of it: its X-Wing public key and the signed ReaderKey upkeep uploaded.
func (self *testSecretMatchReaderKeys) newest(t *testing.T) (seed []byte, publicKey []byte, signed *bridge.Signed) {
	t.Helper()
	uploads := self.api.readerKeys
	if len(uploads) == 0 {
		t.Fatal("upkeep keeps no generation")
	}
	signed = uploads[len(uploads)-1]
	digest, _ := gkmTestReaderKeyOf(t, signed)
	privateKey, err := self.upkeep.ReaderPrivateKey(digest)
	if err != nil {
		t.Fatal(err)
	}
	seed, err = privateKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return seed, privateKey.PublicKey().Bytes(), signed
}

// credentials holds exactly want, in any order.
func testSecretMatchSameSet(t *testing.T, credentials [][]byte, want [][]byte) {
	t.Helper()
	if len(credentials) != len(want) {
		t.Fatalf("%d credentials, want %d", len(credentials), len(want))
	}
	for i, wanted := range want {
		found := false
		for _, credential := range credentials {
			found = found || bytes.Equal(credential, wanted)
		}
		if !found {
			t.Errorf("credential %d of want is missing", i)
		}
	}
}

// A keychain view that reaches no other namespace of its keychain, as any SidecarSecrets but keychainSecrets.
type testSecretMatchOneNamespace struct {
	SidecarSecrets
}

// A keychain view failing the read of one name, or every list, with err, in its own namespace and in each it reaches.
type testSecretMatchFailingSecrets struct {
	SidecarSecrets
	failName string
	failList bool
	err      error
}

func (self *testSecretMatchFailingSecrets) Get(name string) ([]byte, error) {
	if name == self.failName {
		return nil, self.err
	}
	return self.SidecarSecrets.Get(name)
}

func (self *testSecretMatchFailingSecrets) List(prefix string) ([]string, error) {
	if self.failList {
		return nil, self.err
	}
	return self.SidecarSecrets.List(prefix)
}

func (self *testSecretMatchFailingSecrets) keychainNamespace(namespace string) SidecarSecrets {
	namespaces, ok := self.SidecarSecrets.(sidecarKeychainNamespaces)
	if !ok {
		return nil
	}
	failing := *self
	failing.SidecarSecrets = namespaces.keychainNamespace(namespace)
	return &failing
}

// Each encoding of a credential matches inside ordinary text, at its offset.
func TestSecretMatcherMatchesEveryEncoding(t *testing.T) {
	credential := []byte("a synthetic credential of forty bytes!!!")
	matcher := NewSecretMatcher([][]byte{credential}, nil)
	forms := testSecretMatchForms(credential)
	for name, form := range forms {
		text := []byte("prefix " + form + " suffix")
		match := matcher.Match(text)
		if match == nil || match.Class != SecretMatchCredential || match.Offset != len("prefix ") {
			t.Errorf("%s: %+v", name, match)
		}
	}
	if matcher.Matches([]byte("nothing secret here, just words and 1234567890abcdef")) {
		t.Error("ordinary text matched")
	}
}

// A credential under CredentialMinByteCount is skipped, so a short value never matches everything.
func TestSecretMatcherSkipsShortCredentials(t *testing.T) {
	settings := DefaultSecretMatchSettings()
	short := []byte("abc")
	matcher := NewSecretMatcher([][]byte{short, nil}, settings)
	if matcher.FormCount() != 0 || matcher.Matches([]byte("abcabcabc")) {
		t.Errorf("a short credential matched, %d forms", matcher.FormCount())
	}
	settings.CredentialMinByteCount = 2
	if !NewSecretMatcher([][]byte{short}, settings).Matches([]byte("xabcx")) {
		t.Error("a credential at the bound did not match")
	}
}

// The redactor's token forms match with no credential at all, and name their rule; PII is no credential.
func TestSecretMatcherFindsTokenForms(t *testing.T) {
	var none *SecretMatcher
	match := none.Match([]byte("token=" + testSecretMatchToken))
	if match == nil || match.Class != "github-pat" || match.Offset != len("token=") {
		t.Errorf("the token: %+v", match)
	}
	if NewSecretMatcher(nil, nil).Matches([]byte("mail alice@example.com about it")) {
		t.Error("an address matched as a credential")
	}
}

// The connect identity seed a keychain keeps is a credential on every leg, matched in each encoding once kept; a
// keychain keeping none lists nothing.
func TestConnectIdentityCredentialsHoldTheKeptSeed(t *testing.T) {
	_, secrets := newIdentityTestSecrets(t, NewId())
	if credentials, err := loadSidecarConnectIdentityCredentials(secrets); err != nil || len(credentials) != 0 {
		t.Fatalf("a keychain keeping no connect identity listed %d credentials, %v", len(credentials), err)
	}
	seed, err := newSidecarConnectIdentitySeed(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := &SidecarIdentity{NetworkId: NewId(), SidecarId: NewId(), ClientId: NewId(), Generation: 1}
	if err := persistSidecarConnectIdentitySeed(secrets, identity, seed); err != nil {
		t.Fatal(err)
	}
	credentials, err := loadSidecarConnectIdentityCredentials(secrets)
	if err != nil {
		t.Fatal(err)
	}
	matcher := NewSecretMatcher(credentials, nil)
	for name, form := range map[string]string{
		"raw":            string(seed),
		"upper hex":      strings.ToUpper(hex.EncodeToString(seed)),
		"base64":         base64.StdEncoding.EncodeToString(seed),
		"raw url base64": base64.RawURLEncoding.EncodeToString(seed),
	} {
		text := []byte("the seed " + form + " here")
		if match := matcher.Match(text); match == nil || match.Class != SecretMatchCredential || match.Offset != len("the seed ") {
			t.Errorf("the seed, %s: %+v", name, match)
		}
	}
}

// Every reader key a keychain keeps is listed, its seed whole, which is its private key's bytes, and nothing else:
// enrollment's first ReaderKey and a Delegation's reader seed from the core's namespace, and each generation gkm's
// upkeep keeps, a lapsed one, a replaced one and the current one, until upkeep erases it 30 days past its not_after; a
// keychain keeping none lists nothing. On every leg.
func TestReaderKeyCredentialsHoldEveryKeptSeed(t *testing.T) {
	networkId := NewId()
	instance, secrets := newIdentityTestSecrets(t, networkId)
	if credentials, err := loadSidecarReaderKeyCredentials(secrets, nil); err != nil || len(credentials) != 0 {
		t.Fatalf("a keychain keeping no reader key listed %d credentials, %v", len(credentials), err)
	}
	keys := newTestSecretMatchReaderKeys(t, instance, networkId, secrets)
	// generations on days 0, 6 and 12: on day 12 the first has lapsed and the second is replaced, both still kept
	generationSeeds := [][]byte{}
	for _, advance := range []time.Duration{0, 6 * 24 * time.Hour, 6 * 24 * time.Hour} {
		keys.keep(t, advance)
		seed, _, _ := keys.newest(t)
		generationSeeds = append(generationSeeds, seed)
	}
	credentials, err := loadSidecarReaderKeyCredentials(secrets, nil)
	if err != nil {
		t.Fatal(err)
	}
	testSecretMatchSameSet(t, credentials, append([][]byte{keys.firstSeed, keys.delegationSeed}, generationSeeds...))

	// day 37 is 30 days past the first generation's not_after: upkeep erases it as it keeps a fourth
	keys.keep(t, 25*24*time.Hour)
	fourthSeed, _, _ := keys.newest(t)
	credentials, err = loadSidecarReaderKeyCredentials(secrets, nil)
	if err != nil {
		t.Fatal(err)
	}
	testSecretMatchSameSet(t, credentials, [][]byte{keys.firstSeed, keys.delegationSeed, generationSeeds[1], generationSeeds[2], fourthSeed})
}

// A reader key the keychain keeps but cannot give fails the read, so no matcher is built without it: a read the keychain
// fails, of a core record, of gkm's list or of a generation's record, is the keychain's error as it is, the seeds read
// before it returned beside it for the caller to clear; a view reaching no gkm namespace is
// errSidecarReaderKeysUnreachable; and a generation's record that does not decode is errSidecarReaderKeyRecordFormat,
// repeating none of the record. On every leg.
func TestReaderKeyCredentialsFailClosed(t *testing.T) {
	networkId := NewId()
	instance, secrets := newIdentityTestSecrets(t, networkId)
	keys := newTestSecretMatchReaderKeys(t, instance, networkId, secrets)
	keys.keep(t, 0)
	gkmSecrets := instance.secrets(networkId, gkmUpkeepSecretsNamespace)
	names, err := gkmSecrets.List(gkmUpkeepReaderKeyPrefix)
	if err != nil || len(names) != 1 {
		t.Fatalf("upkeep keeps %d generations, %v", len(names), err)
	}

	for _, c := range []struct {
		name     string
		failName string
		failList bool
		err      error
		// the seeds read before the failure
		readCount int
	}{
		{name: "enrollment's first ReaderKey", failName: sidecarReaderKeyRecordName, err: ErrSidecarStoreFailed, readCount: 0},
		{name: "a Delegation's reader seed", failName: sidecarDelegationReaderKeyRecordName, err: ErrSidecarStoreLocked, readCount: 1},
		{name: "gkm's list", failList: true, err: ErrSidecarStoreLocked, readCount: 2},
		{name: "a generation's record", failName: names[0], err: ErrSidecarStoreFailed, readCount: 2},
	} {
		failing := &testSecretMatchFailingSecrets{SidecarSecrets: secrets, failName: c.failName, failList: c.failList, err: c.err}
		credentials, err := loadSidecarReaderKeyCredentials(failing, nil)
		if !errors.Is(err, c.err) || len(credentials) != c.readCount {
			t.Errorf("%s failing: %d read, %v", c.name, len(credentials), err)
		}
	}

	credentials, err := loadSidecarReaderKeyCredentials(&testSecretMatchOneNamespace{SidecarSecrets: secrets}, nil)
	if !errors.Is(err, errSidecarReaderKeysUnreachable) || !errors.Is(err, ErrSidecarStoreFailed) || len(credentials) != 2 {
		t.Errorf("a view reaching no gkm namespace: %d read, %v", len(credentials), err)
	}

	damaged := []byte("synthetic damage, no ReaderKey record of upkeep's")
	if err := gkmSecrets.Put(gkmReaderKeyRecordName(make([]byte, 32)), damaged); err != nil {
		t.Fatal(err)
	}
	_, err = loadSidecarReaderKeyCredentials(secrets, nil)
	if !errors.Is(err, errSidecarReaderKeyRecordFormat) || !errors.Is(err, ErrSidecarStoreFailed) {
		t.Fatalf("a record that does not decode: %v", err)
	}
	if strings.Contains(err.Error(), string(damaged)) || strings.Contains(err.Error(), hex.EncodeToString(damaged)) {
		t.Error("the error repeats the record")
	}
}
