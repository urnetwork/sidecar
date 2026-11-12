// MCP-M3-09's CLI half on fakes: a CTAP2 authenticator in memory behind presence_fido.go's provider, its keys
// registering and asserting in the bytes the root's per-use profile verifies, its refusals failing closed; the CBOR
// codec's canonical form and its refusals; and ur keys add-presence, rm and ls, each signing only on a yes on the
// terminal through a Confirm method, with ur login's offer.

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A CTAP2 authenticator in memory on CTAPHID: one ES256 credential it makes on demand, flags and a forced status a test
// sets, keepalives before each answer.
type testFidoDevice struct {
	t        testing.TB
	settings *urFidoSettings

	stateLock    sync.Mutex
	key          *ecdsa.PrivateKey
	credentialId []byte
	flags        byte
	// a CTAP2 status each CBOR answer carries instead of ok, 0 for none
	status     byte
	keepalives int
	channelId  uint32
	signCount  uint32
	// the request coming in, and the reports going out
	command   byte
	channel   uint32
	length    int
	request   []byte
	sequence  byte
	responses [][]byte
	// what it saw: the client data hashes asked to sign, in order
	signedHashes [][]byte
}

func newTestFidoDevice(t testing.TB) *testFidoDevice {
	return &testFidoDevice{t: t, settings: defaultUrFidoSettings(), flags: urFidoFlagUserPresent | urFidoFlagUserVerified, keepalives: 2, channelId: 0x01020304}
}

func (self *testFidoDevice) Write(report []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(report) != self.settings.ReportByteCount {
		self.t.Fatalf("a report of %d bytes", len(report))
	}
	channel := binary.BigEndian.Uint32(report)
	if report[4]&0x80 != 0 {
		self.command = report[4]
		self.channel = channel
		self.length = int(binary.BigEndian.Uint16(report[5:]))
		self.request = append([]byte{}, report[7:min(len(report), 7+self.length)]...)
		self.sequence = 0
	} else {
		if channel != self.channel || report[4] != self.sequence {
			self.t.Fatalf("continuation %d on %#x", report[4], channel)
		}
		self.sequence += 1
		self.request = append(self.request, report[5:min(len(report), 5+self.length-len(self.request))]...)
	}
	if len(self.request) < self.length {
		return nil
	}
	self.answerWithLock()
	return nil
}

// Queues the answer to the request just completed.
func (self *testFidoDevice) answerWithLock() {
	switch self.command {
	case urFidoCommandInit:
		answer := append(append([]byte{}, self.request...), 0, 0, 0, 0, 2, 1, 0, 0, 0x04)
		binary.BigEndian.PutUint32(answer[len(self.request):], self.channelId)
		self.queueWithLock(self.channel, urFidoCommandInit, answer)
	case urFidoCommandCbor:
		for range self.keepalives {
			keepalive := make([]byte, self.settings.ReportByteCount)
			binary.BigEndian.PutUint32(keepalive, self.channel)
			keepalive[4] = urFidoCommandKeepalive
			binary.BigEndian.PutUint16(keepalive[5:], 1)
			keepalive[7] = 2
			self.responses = append(self.responses, keepalive)
		}
		self.queueWithLock(self.channel, urFidoCommandCbor, self.ctapWithLock(self.request[0], self.request[1:]))
	default:
		self.t.Fatalf("command %#x", self.command)
	}
}

// One CTAP2 command's answer: status and CBOR.
func (self *testFidoDevice) ctapWithLock(command byte, encoded []byte) []byte {
	if self.status != 0 {
		return []byte{self.status}
	}
	value, _, err := urCborRead(encoded, self.settings.CborDepthCount)
	if err != nil {
		self.t.Fatal(err)
	}
	request := value.(map[any]any)
	rpIdHash := sha256.Sum256([]byte(urPresenceRpId))
	switch command {
	case urFidoMakeCredential:
		if request[int64(2)].(map[any]any)["id"] != urPresenceRpId || request[int64(7)].(map[any]any)["uv"] != true {
			self.t.Fatalf("a makeCredential: %+v", request)
		}
		self.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			self.t.Fatal(err)
		}
		self.credentialId = make([]byte, 80)
		rand.Read(self.credentialId)
		point, err := self.key.PublicKey.Bytes()
		if err != nil {
			self.t.Fatal(err)
		}
		coseKey, err := urCborAppend(nil, urCborMap{
			{Key: int64(1), Value: urFidoCoseKeyTypeEc2}, {Key: int64(3), Value: urFidoCoseEs256}, {Key: int64(-1), Value: urFidoCoseCurveP256},
			{Key: int64(-2), Value: point[1:33]}, {Key: int64(-3), Value: point[33:]},
		})
		if err != nil {
			self.t.Fatal(err)
		}
		authenticatorData := append(append(rpIdHash[:], self.flags|urFidoFlagAttested), 0, 0, 0, 0)
		authenticatorData = append(authenticatorData, make([]byte, 16)...)
		authenticatorData = binary.BigEndian.AppendUint16(authenticatorData, uint16(len(self.credentialId)))
		authenticatorData = append(append(authenticatorData, self.credentialId...), coseKey...)
		answer, err := urCborAppend([]byte{urFidoStatusOk}, urCborMap{
			{Key: int64(1), Value: "none"}, {Key: int64(2), Value: authenticatorData}, {Key: int64(3), Value: urCborMap{}},
		})
		if err != nil {
			self.t.Fatal(err)
		}
		return answer
	case urFidoGetAssertion:
		allowed := request[int64(3)].([]any)[0].(map[any]any)["id"].([]byte)
		if self.key == nil || !bytes.Equal(allowed, self.credentialId) {
			return []byte{urFidoStatusNoCredential}
		}
		clientDataHash := request[int64(2)].([]byte)
		self.signedHashes = append(self.signedHashes, append([]byte{}, clientDataHash...))
		self.signCount += 1
		authenticatorData := binary.BigEndian.AppendUint32(append(rpIdHash[:], self.flags), self.signCount)
		digest := sha256.Sum256(append(append([]byte{}, authenticatorData...), clientDataHash...))
		signature, err := ecdsa.SignASN1(rand.Reader, self.key, digest[:])
		if err != nil {
			self.t.Fatal(err)
		}
		answer, err := urCborAppend([]byte{urFidoStatusOk}, urCborMap{
			{Key: int64(1), Value: urCborMap{{Key: "id", Value: self.credentialId}, {Key: "type", Value: "public-key"}}},
			{Key: int64(2), Value: authenticatorData}, {Key: int64(3), Value: signature},
		})
		if err != nil {
			self.t.Fatal(err)
		}
		return answer
	}
	self.t.Fatalf("CTAP2 command %#x", command)
	return nil
}

// Splits an answer into an init packet and continuations.
func (self *testFidoDevice) queueWithLock(channel uint32, command byte, answer []byte) {
	report := make([]byte, self.settings.ReportByteCount)
	binary.BigEndian.PutUint32(report, channel)
	report[4] = command
	binary.BigEndian.PutUint16(report[5:], uint16(len(answer)))
	sent := copy(report[7:], answer)
	self.responses = append(self.responses, report)
	for sequence := byte(0); sent < len(answer); sequence += 1 {
		report = make([]byte, self.settings.ReportByteCount)
		binary.BigEndian.PutUint32(report, channel)
		report[4] = sequence
		sent += copy(report[5:], answer[sent:])
		self.responses = append(self.responses, report)
	}
}

func (self *testFidoDevice) Read(ctx context.Context) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.responses) == 0 {
		return nil, errors.New("the test device has nothing to answer")
	}
	report := self.responses[0]
	self.responses = self.responses[1:]
	return report, nil
}

func (self *testFidoDevice) Close() error {
	return nil
}

// A provider over device, its credentials in a test directory.
func newTestFidoProvider(t *testing.T, device *testFidoDevice) *urFidoProvider {
	return newUrFidoProvider(t.TempDir(), func() ([]urFidoDevice, error) {
		return []urFidoDevice{device}, nil
	}, defaultUrFidoSettings(), sidecar.NewNoopLogger())
}

// A security key registers and asserts in the bytes §16.6's per-use profile verifies: the key's SEC 1 point, an
// assertion over a statement's signed bytes passing VerifyPresenceUse, its counter rising, over CTAPHID continuations
// and keepalives; and the provider holds the key by its id across a fresh provider on the same directory.
func TestFidoRegisterAndAssertVerify(t *testing.T) {
	device := newTestFidoDevice(t)
	provider := newTestFidoProvider(t, device)
	handle, err := provider.Register(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if handle.Alg != bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 || len(handle.PublicKey) != 65 || len(handle.KeyId) != 16 || !provider.Holds(handle.KeyId) {
		t.Fatalf("the handle: %+v", handle)
	}
	row := &bridge.KeyRow{KeyId: handle.KeyId, Alg: handle.Alg, PublicKey: handle.PublicKey, Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE}
	body := []byte("a decision's body, as signed")
	for range 2 {
		evidence, err := provider.Assert(t.Context(), handle.KeyId, bridge.SignedBytes(sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, body))
		if err != nil {
			t.Fatal(err)
		}
		signed := &bridge.Signed{
			Body: body, KeyId: evidence.GetKeyId(), Signature: evidence.GetSignature(), Type: uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION),
			Webauthn: &bridge.WebAuthnEvidence{AuthenticatorData: evidence.GetAuthenticatorData(), ClientDataJson: evidence.GetClientDataJson()},
		}
		if err := sidecar.VerifyPresenceUse(signed, sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, row, nil); err != nil {
			t.Fatalf("the assertion does not verify: %v", err)
		}
	}
	reopened := newUrFidoProvider(provider.directory, provider.devices, defaultUrFidoSettings(), sidecar.NewNoopLogger())
	if !reopened.Holds(handle.KeyId) || reopened.Holds([]byte("another key")) {
		t.Error("the credentials file does not hold its key, or holds another")
	}
	if err := reopened.Remove(handle.KeyId); err != nil || reopened.Holds(handle.KeyId) {
		t.Errorf("removal: %v", err)
	}
	if _, err := reopened.Assert(t.Context(), handle.KeyId, body); !errors.Is(err, sidecar.ErrPresenceNoKey) {
		t.Errorf("an assertion of a removed key: %v", err)
	}
}

// An authenticator that verifies no user, or verifies one only by a PIN, which CTAP2's clientPIN would need, registers
// and signs nothing; a device that holds no such credential is passed over.
func TestFidoRefusesWithoutUserVerification(t *testing.T) {
	device := newTestFidoDevice(t)
	device.flags = urFidoFlagUserPresent
	if _, err := newTestFidoProvider(t, device).Register(t.Context()); !errors.Is(err, errUrFidoUnverified) {
		t.Errorf("no UV at registration: %v", err)
	}
	pinOnly := newTestFidoDevice(t)
	pinOnly.status = 0x36
	if _, err := newTestFidoProvider(t, pinOnly).Register(t.Context()); !errors.Is(err, errUrFido) {
		t.Errorf("a PIN-only key: %v", err)
	}
	verifying := newTestFidoDevice(t)
	provider := newTestFidoProvider(t, verifying)
	handle, err := provider.Register(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	verifying.stateLock.Lock()
	verifying.flags = urFidoFlagUserPresent
	verifying.stateLock.Unlock()
	if _, err := provider.Assert(t.Context(), handle.KeyId, []byte("m")); !errors.Is(err, errUrFidoUnverified) {
		t.Errorf("no UV at assertion: %v", err)
	}
	other := newTestFidoDevice(t)
	provider.devices = func() ([]urFidoDevice, error) { return []urFidoDevice{other}, nil }
	if _, err := provider.Assert(t.Context(), handle.KeyId, []byte("m")); !errors.Is(err, sidecar.ErrPresenceNoKey) {
		t.Errorf("a device without the credential: %v", err)
	}
	none := newUrFidoProvider(t.TempDir(), func() ([]urFidoDevice, error) { return nil, nil }, defaultUrFidoSettings(), sidecar.NewNoopLogger())
	if _, err := none.Register(t.Context()); !errors.Is(err, sidecar.ErrPresenceUnavailable) {
		t.Errorf("no device: %v", err)
	}
}

// CTAP2's canonical CBOR: map keys ordered by major type, then length, then bytes; shortest heads; a round trip; and
// the reader refusing what CTAP2 has no form for.
func TestFidoCborCanonical(t *testing.T) {
	encoded, err := urCborAppend(nil, urCborMap{
		{Key: "type", Value: "public-key"}, {Key: int64(-1), Value: int64(1)}, {Key: int64(1000), Value: true},
		{Key: int64(1), Value: []byte{1, 2}}, {Key: "id", Value: []any{int64(-7), false}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("a5" + "0142" + "0102" + "1903e8" + "f5" + "20" + "01" + "626964" + "8226f4" + "6474797065" + "6a7075626c69632d6b6579")
	if !bytes.Equal(encoded, want) {
		t.Errorf("encoded %x, want %x", encoded, want)
	}
	value, rest, err := urCborRead(encoded, 4)
	if err != nil || len(rest) != 0 {
		t.Fatal(err)
	}
	decoded := value.(map[any]any)
	if decoded["type"] != "public-key" || decoded[int64(-1)] != int64(1) || decoded[int64(1000)] != true ||
		!bytes.Equal(decoded[int64(1)].([]byte), []byte{1, 2}) || decoded["id"].([]any)[0] != int64(-7) {
		t.Errorf("decoded %+v", decoded)
	}
	for name, bad := range map[string]string{
		"indefinite": "5f", "float": "f93c00", "duplicate key": "a201010102", "short": "43010203"[:6], "tag": "c101",
		"deep": "818181818101",
	} {
		data, _ := hex.DecodeString(bad)
		if _, _, err := urCborRead(data, 4); err == nil {
			t.Errorf("%s read", name)
		}
	}
	if _, err := urCborAppend(nil, urCborMap{{Key: int64(1), Value: 1}}); err == nil {
		t.Error("an int value encoded")
	}
}

// A HID report descriptor declares FIDO by Usage Page (long) 0xF1D0, and no other page reads as it.
func TestFidoReportDescriptor(t *testing.T) {
	fido := []byte{0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01}
	keyboard := []byte{0x05, 0x01, 0x09, 0x06, 0xa1, 0x01}
	if !urFidoReportDescriptor(fido) || urFidoReportDescriptor(keyboard) {
		t.Error("the FIDO usage page")
	}
}

// A daemon target hosting presence keys, as a test sets them.
type testUrPresenceKeysTarget struct {
	testUrDaemonTarget
	stateLock     sync.Mutex
	keys          []*sidecar.SidecarPresenceKey
	authenticator bool
	added         int
	removed       [][]byte
	// what addPresenceKey answers, nil to add
	addErr error
}

func (self *testUrPresenceKeysTarget) presenceKeys() ([]*sidecar.SidecarPresenceKey, bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.keys, self.authenticator, nil
}

func (self *testUrPresenceKeysTarget) addPresenceKey(ctx context.Context) (*sidecar.SidecarPresenceKey, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.addErr != nil {
		return nil, self.addErr
	}
	self.added += 1
	key := &sidecar.SidecarPresenceKey{KeyId: []byte{0xaa, byte(self.added)}, Alg: bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256, Held: true, NotAfter: time.Now()}
	self.keys = append(self.keys, key)
	return key, nil
}

func (self *testUrPresenceKeysTarget) removeKey(ctx context.Context, keyId []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.removed = append(self.removed, keyId)
	return nil
}

// FS-124's CLI cases: ur keys add-presence and ur keys rm sign only on a yes on the terminal, nothing on a no, and refuse
// with no terminal, never reading stdin; ur keys ls lists the keys; a failed or refused registration exits failed.
func TestKeysAddPresenceAndRemoveOnTheTerminal(t *testing.T) {
	target := &testUrPresenceKeysTarget{authenticator: true}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	cli.stdin = strings.NewReader("y\n")
	if code := cli.main(context.Background(), []string{"ur", "keys", "add-presence"}); code != urExitFailed || target.added != 0 {
		t.Fatalf("no terminal: exit %d, %d added", code, target.added)
	}
	if !strings.Contains(stderr.String(), "terminal") {
		t.Errorf("stderr %q", stderr.String())
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "keys", "add-presence"}); code != urExitOk || target.added != 0 {
		t.Fatalf("a no: exit %d, %d added", code, target.added)
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "keys", "add-presence"}); code != urExitOk || target.added != 1 {
		t.Fatalf("a yes: exit %d, %d added", code, target.added)
	}
	if code := cli.main(context.Background(), []string{"ur", "keys", "ls"}); code != urExitOk || !strings.Contains(stdout.String(), "aa01  KEY_ALG_ECDSA_P256_SHA256") {
		t.Errorf("the list: exit %d: %s", code, stdout.String())
	}
	if code := cli.main(context.Background(), []string{"ur", "keys", "rm", "aa01"}); code != urExitOk || len(target.removed) != 1 || !bytes.Equal(target.removed[0], []byte{0xaa, 0x01}) {
		t.Errorf("a removal: exit %d, %x", code, target.removed)
	}
	if code := cli.main(context.Background(), []string{"ur", "keys", "rm", "not-hex"}); code != urExitFailed {
		t.Errorf("a removal of no key id: exit %d", code)
	}
	target.addErr = sidecar.ErrSidecarActPresence
	if code := cli.main(context.Background(), []string{"ur", "keys", "add-presence"}); code != urExitFailed {
		t.Errorf("a refused prompt: exit %d", code)
	}
}

// keys.add_presence and keys.remove are Confirm methods, so no mcp or hook session, nor an unconfirmed call, reaches
// them; keys.list is not.
func TestKeysPresenceMethodsAreConfirmOnly(t *testing.T) {
	methods := urKeysPresenceMethods(&testUrPresenceKeysTarget{})
	if len(methods) != 3 {
		t.Fatalf("%d methods", len(methods))
	}
	for _, method := range methods {
		if method.Confirm != (method.Name != urMethodKeysList) {
			t.Errorf("%s: Confirm %v", method.Name, method.Confirm)
		}
	}
}

// ur login's offer: asked only where the host has an authenticator and holds no key of the member, and a yes
// registers one; with no terminal nothing is asked and the login still succeeds.
func TestLoginOffersAPresenceKey(t *testing.T) {
	target := &testUrPresenceKeysTarget{authenticator: true}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, _ := newTestUrCli(daemon.socketPath)
	if err := urOfferPresenceKey(context.Background(), cli); err != nil || target.added != 0 {
		t.Fatalf("no terminal: %v, %d added", err, target.added)
	}
	tty := &testTty{lines: []string{"y"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if err := urOfferPresenceKey(context.Background(), cli); err != nil || target.added != 1 {
		t.Fatalf("a yes: %v, %d added", err, target.added)
	}
	tty = &testTty{lines: []string{"y"}}
	if err := urOfferPresenceKey(context.Background(), cli); err != nil || target.added != 1 || tty.written.Len() != 0 {
		t.Errorf("offered again with a key held: %d added, %q", target.added, tty.written.String())
	}
	target.authenticator = false
	target.keys = nil
	if err := urOfferPresenceKey(context.Background(), cli); err != nil || target.added != 1 {
		t.Errorf("offered with no authenticator: %v, %d added", err, target.added)
	}
}
