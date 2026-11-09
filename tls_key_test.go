//go:build !sidecar_http

package sidecar

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

// A clock a test moves by hand. Nothing here waits on it, so After and AfterFunc never fire.
type tlsTestClock struct {
	stateLock sync.Mutex
	current   time.Time
}

func newTlsTestClock() *tlsTestClock {
	return &tlsTestClock{current: time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC)}
}

func (self *tlsTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.current
}

func (self *tlsTestClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

func (self *tlsTestClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

func (self *tlsTestClock) advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.current = self.current.Add(by)
}

// An unlocked instance holding testNetworkId's keychain, its medium and key store for a restart, and the keychain's tls
// namespace.
func newTlsTestSecrets(t *testing.T) (*SidecarInstance, SidecarStoreBackend, *fakeKeyStore, SidecarSecrets) {
	t.Helper()
	backend := NewSidecarMemoryBackend()
	keyStore := newFakeKeyStore()
	instance := newInstanceOn(t, backend, keyStore)
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	enrollTestNetwork(t, instance, testNetworkId)
	return instance, backend, keyStore, instance.secrets(testNetworkId, tlsSecretsNamespace)
}

// The private scalar of key, for a test that looks for it where it must not be.
func tlsTestScalar(t *testing.T, key *TlsDeviceKey) []byte {
	t.Helper()
	scalar, err := key.privateKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return scalar
}

func TestDefaultSidecarTlsSettingsMatchDesign(t *testing.T) {
	want := SidecarTlsSettings{
		// §13.8: rotated every 180 days
		KeyRotationInterval: 180 * 24 * time.Hour,
		SelfSignedLifetime:  30 * 24 * time.Hour,
		SelfSignedBackdate:  1 * time.Hour,
	}
	if settings := DefaultSidecarSettings(); !reflect.DeepEqual(*settings.Tls, want) {
		t.Errorf("tls settings %+v, want %+v", *settings.Tls, want)
	}
	if DefaultSidecarTlsSettings() == DefaultSidecarTlsSettings() {
		t.Error("two calls share one value")
	}
}

func TestTlsDeviceKeyIsAP256Signer(t *testing.T) {
	_, _, _, secrets := newTlsTestSecrets(t)
	keys, err := loadOrCreateTlsDeviceKeys(secrets, newTlsTestClock().Now())
	if err != nil {
		t.Fatal(err)
	}
	key := keys.current
	publicKey, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		t.Fatalf("public key %T", key.Public())
	}
	var signer crypto.Signer = key
	digest := sha256.Sum256([]byte("synthetic signing input"))
	signature, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		t.Error("the signature does not verify under the key's public half")
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.Spki(), spki) || key.SpkiSha256() != sha256.Sum256(spki) {
		t.Error("the SPKI is not the public key's")
	}
	// Spki hands out a copy
	key.Spki()[0] ^= 0xff
	if !bytes.Equal(key.Spki(), spki) {
		t.Error("Spki shares its bytes")
	}
	// the public half handed out is a copy, so nothing reaches the key through it
	publicKey.X = nil
	if key.Public().(*ecdsa.PublicKey).X == nil {
		t.Error("Public shares the key's own public half")
	}
	if key.Reason() != TlsKeyRotationNone {
		t.Errorf("a first key's reason %d", key.Reason())
	}
}

// No method of TlsDeviceKey answers its private half, in any form (§13.8: never exported).
func TestTlsDeviceKeyHasNoMethodAnsweringItsPrivateKey(t *testing.T) {
	// crypto.PrivateKey is any, as crypto.PublicKey is, so Public's dynamic type is checked in
	// TestTlsDeviceKeyIsAP256Signer instead
	refused := []reflect.Type{
		reflect.TypeFor[*ecdsa.PrivateKey](),
		reflect.TypeFor[ecdsa.PrivateKey](),
	}
	keyType := reflect.TypeFor[*TlsDeviceKey]()
	for i := 0; i < keyType.NumMethod(); i += 1 {
		method := keyType.Method(i)
		for j := 0; j < method.Type.NumOut(); j += 1 {
			for _, refusedType := range refused {
				if method.Type.Out(j) == refusedType {
					t.Errorf("%s answers a %s", method.Name, refusedType)
				}
			}
		}
	}
	want := []string{"CreateTime", "Public", "Reason", "Sign", "Spki", "SpkiSha256"}
	got := []string{}
	for i := 0; i < keyType.NumMethod(); i += 1 {
		got = append(got, keyType.Method(i).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("methods %v, want %v: a new one must not answer the private key", got, want)
	}
}

// The key is made once and read back the same after the instance closes and opens again on the same medium (§5.9).
func TestTlsDeviceKeySurvivesARestart(t *testing.T) {
	instance, backend, keyStore, secrets := newTlsTestSecrets(t)
	clock := newTlsTestClock()
	made, err := loadOrCreateTlsDeviceKeys(secrets, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Hour)
	again, err := loadOrCreateTlsDeviceKeys(secrets, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if again.current.SpkiSha256() != made.current.SpkiSha256() || !again.current.CreateTime().Equal(made.current.CreateTime()) {
		t.Fatal("a second call made another key")
	}
	instance.Close()

	reopened := newInstanceOn(t, backend, keyStore)
	if err := reopened.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Hour)
	restarted, err := loadOrCreateTlsDeviceKeys(reopened.secrets(testNetworkId, tlsSecretsNamespace), clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if restarted.current.SpkiSha256() != made.current.SpkiSha256() {
		t.Error("the key did not survive the restart")
	}
	if !restarted.current.CreateTime().Equal(newTlsTestClock().Now()) {
		t.Errorf("create time %v", restarted.current.CreateTime())
	}
	if restarted.pending != nil {
		t.Error("a pending key appeared")
	}
}

// The keychain holds the key sealed, and nothing on the medium holds its scalar in the clear: not keychain.ur, not a
// component's store (§13.8's trap: never a component file or the evs mirror).
func TestTlsDeviceKeyNeverReachesTheMediumInTheClear(t *testing.T) {
	instance, backend, _, secrets := newTlsTestSecrets(t)
	keys, err := rotateTlsDeviceKey(secrets, newTlsTestClock().Now(), TlsKeyRotationRequest)
	if err != nil {
		t.Fatal(err)
	}
	writeStoreFile(t, storeOf(t, instance, testNetworkId, tlsSecretsNamespace), "certificate", []byte("synthetic chain"))
	for _, key := range []*TlsDeviceKey{keys.current, keys.pending} {
		scalar := tlsTestScalar(t, key)
		for path, content := range backendSnapshot(t, backend) {
			if bytes.Contains(content, scalar) {
				t.Errorf("%s holds a device key's scalar", path)
			}
		}
	}
}

// §13.8's 180 days, at the boundary: not due a moment before, due at it and after.
func TestTlsKeyRotationDueAtExactly180Days(t *testing.T) {
	settings := DefaultSidecarTlsSettings()
	_, _, _, secrets := newTlsTestSecrets(t)
	clock := newTlsTestClock()
	keys, err := loadOrCreateTlsDeviceKeys(secrets, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	made := keys.current.CreateTime()
	for _, row := range []struct {
		after time.Duration
		due   bool
	}{
		{after: 0, due: false},
		{after: 179 * 24 * time.Hour, due: false},
		{after: 180*24*time.Hour - time.Nanosecond, due: false},
		{after: 180*24*time.Hour - time.Millisecond, due: false},
		{after: 180 * 24 * time.Hour, due: true},
		{after: 180*24*time.Hour + time.Nanosecond, due: true},
		{after: 365 * 24 * time.Hour, due: true},
	} {
		if due := TlsKeyRotationDue(keys.current, made.Add(row.after), settings); due != row.due {
			t.Errorf("%v after creation: due %t, want %t", row.after, due, row.due)
		}
	}
	// a key's time survives the record to the millisecond, so the boundary does not move across a restart
	reloaded, err := loadTlsDeviceKeys(secrets)
	if err != nil {
		t.Fatal(err)
	}
	if !TlsKeyRotationDue(reloaded.current, made.Add(180*24*time.Hour), settings) ||
		TlsKeyRotationDue(reloaded.current, made.Add(180*24*time.Hour-time.Nanosecond), settings) {
		t.Error("the boundary moved across the record")
	}
	// the interval is a setting
	short := DefaultSidecarTlsSettings()
	short.KeyRotationInterval = time.Hour
	if !TlsKeyRotationDue(keys.current, made.Add(time.Hour), short) {
		t.Error("KeyRotationInterval is not read")
	}
}

// A rotation sets a pending successor and leaves the current key serving; a second request answers the same
// successor; only that successor's promotion swaps them, in one write that drops the old key.
func TestTlsDeviceKeyRotationKeepsTheOldKeyUntilPromotion(t *testing.T) {
	_, _, _, secrets := newTlsTestSecrets(t)
	clock := newTlsTestClock()
	first, err := loadOrCreateTlsDeviceKeys(secrets, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(24 * time.Hour)
	rotated, err := rotateTlsDeviceKey(secrets, clock.Now(), TlsKeyRotationSuspicion)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.current.SpkiSha256() != first.current.SpkiSha256() {
		t.Fatal("a rotation replaced the current key before its successor's certificate installed")
	}
	if rotated.pending == nil || rotated.pending.SpkiSha256() == first.current.SpkiSha256() {
		t.Fatal("no new pending key")
	}
	if rotated.pending.Reason() != TlsKeyRotationSuspicion || !rotated.pending.CreateTime().Equal(clock.Now()) {
		t.Errorf("pending key reason %d made %v", rotated.pending.Reason(), rotated.pending.CreateTime())
	}

	clock.advance(time.Hour)
	again, err := rotateTlsDeviceKey(secrets, clock.Now(), TlsKeyRotationRequest)
	if err != nil {
		t.Fatal(err)
	}
	if again.pending.SpkiSha256() != rotated.pending.SpkiSha256() || again.pending.Reason() != TlsKeyRotationSuspicion {
		t.Error("a second request replaced the pending key")
	}

	// the pending state is in the keychain, not only in memory
	stored, err := loadTlsDeviceKeys(secrets)
	if err != nil {
		t.Fatal(err)
	}
	if stored.current.SpkiSha256() != first.current.SpkiSha256() || stored.pending == nil ||
		stored.pending.SpkiSha256() != rotated.pending.SpkiSha256() {
		t.Fatal("the record does not hold the pair")
	}

	// a promotion naming the current key, or any other, changes nothing
	if _, err := promoteTlsDeviceKey(secrets, first.current.SpkiSha256()); !errors.Is(err, ErrTlsDeviceKeyNotPending) {
		t.Errorf("promoting the current key: %v", err)
	}
	if _, err := promoteTlsDeviceKey(secrets, sha256.Sum256([]byte("synthetic other key"))); !errors.Is(err, ErrTlsDeviceKeyNotPending) {
		t.Errorf("promoting another key: %v", err)
	}
	unchanged, err := loadTlsDeviceKeys(secrets)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.current.SpkiSha256() != first.current.SpkiSha256() || unchanged.pending == nil {
		t.Fatal("a refused promotion changed the record")
	}

	promoted, err := promoteTlsDeviceKey(secrets, rotated.pending.SpkiSha256())
	if err != nil {
		t.Fatal(err)
	}
	if promoted.current.SpkiSha256() != rotated.pending.SpkiSha256() || promoted.pending != nil {
		t.Fatal("the promotion did not swap the keys")
	}
	stored, err = loadTlsDeviceKeys(secrets)
	if err != nil {
		t.Fatal(err)
	}
	if stored.current.SpkiSha256() != rotated.pending.SpkiSha256() || stored.pending != nil {
		t.Fatal("the swap is not in the keychain")
	}
	if _, err := promoteTlsDeviceKey(secrets, rotated.pending.SpkiSha256()); !errors.Is(err, ErrTlsDeviceKeyNotPending) {
		t.Errorf("a second promotion: %v", err)
	}
	if _, err := rotateTlsDeviceKey(secrets, clock.Now(), TlsKeyRotationNone); !errors.Is(err, ErrTlsKeyRotationReason) {
		t.Errorf("a rotation with no reason: %v", err)
	}
	if _, err := rotateTlsDeviceKey(secrets, clock.Now(), TlsKeyRotationReason(9)); !errors.Is(err, ErrTlsKeyRotationReason) {
		t.Errorf("a rotation with an unknown reason: %v", err)
	}
}

// Only absence makes a key: a locked keychain answers locked and writes nothing, and a record that does not decode is
// a failure that nothing overwrites (D-CORE-15).
func TestTlsDeviceKeyIsMadeOnlyWhenAbsent(t *testing.T) {
	instance, backend, _, secrets := newTlsTestSecrets(t)
	clock := newTlsTestClock()

	instance.Lock()
	before := backendSnapshot(t, backend)
	if _, err := loadOrCreateTlsDeviceKeys(secrets, clock.Now()); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Fatalf("locked: %v", err)
	}
	if _, err := rotateTlsDeviceKey(secrets, clock.Now(), TlsKeyRotationRequest); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Fatalf("locked rotation: %v", err)
	}
	requireSameBackend(t, before, backend)
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}

	if err := secrets.Put(tlsDeviceKeyRecordName, []byte("synthetic garbage")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateTlsDeviceKeys(secrets, clock.Now()); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Fatalf("garbage: %v", err)
	}
	if _, err := rotateTlsDeviceKey(secrets, clock.Now(), TlsKeyRotationRequest); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Fatalf("garbage rotation: %v", err)
	}
	kept, err := secrets.Get(tlsDeviceKeyRecordName)
	if err != nil || !bytes.Equal(kept, []byte("synthetic garbage")) {
		t.Fatal("a failed record was overwritten")
	}
}

// Every truncation of a record, a byte past its end, and each field out of range decodes as a failure.
func TestTlsDeviceKeyRecordRefusesWhatIsNotOne(t *testing.T) {
	_, _, _, secrets := newTlsTestSecrets(t)
	keys, err := rotateTlsDeviceKey(secrets, newTlsTestClock().Now(), TlsKeyRotationScheduled)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := keys.encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeTlsDeviceKeys(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.current.SpkiSha256() != keys.current.SpkiSha256() || decoded.pending.SpkiSha256() != keys.pending.SpkiSha256() ||
		decoded.pending.Reason() != TlsKeyRotationScheduled {
		t.Fatal("the record does not round-trip")
	}
	for length := 0; length < len(encoded); length += 1 {
		if _, err := decodeTlsDeviceKeys(encoded[:length]); !errors.Is(err, errTlsDeviceKeyFormat) {
			t.Fatalf("%d bytes: %v", length, err)
		}
	}
	if _, err := decodeTlsDeviceKeys(append(bytes.Clone(encoded), 0)); !errors.Is(err, errTlsDeviceKeyFormat) {
		t.Errorf("a trailing byte: %v", err)
	}
	// offsets: magic 4, version 1, then the current entry's time 8, reason 1 and scalar 32, then the flag
	flagOffset := len(tlsDeviceKeyRecordMagic) + 1 + 8 + 1 + tlsDeviceKeyScalarSize
	for _, mutation := range []struct {
		name   string
		mutate func(record []byte)
	}{
		{name: "magic", mutate: func(record []byte) { record[0] = 'X' }},
		{name: "version", mutate: func(record []byte) { record[4] = 2 }},
		{name: "zero time", mutate: func(record []byte) { clear(record[5:13]) }},
		{name: "reason", mutate: func(record []byte) { record[13] = 9 }},
		{name: "zero scalar", mutate: func(record []byte) { clear(record[14 : 14+tlsDeviceKeyScalarSize]) }},
		{name: "scalar past the order", mutate: func(record []byte) {
			for i := 14; i < 14+tlsDeviceKeyScalarSize; i += 1 {
				record[i] = 0xff
			}
		}},
		{name: "flag", mutate: func(record []byte) { record[flagOffset] = 2 }},
	} {
		record := bytes.Clone(encoded)
		mutation.mutate(record)
		if _, err := decodeTlsDeviceKeys(record); !errors.Is(err, errTlsDeviceKeyFormat) {
			t.Errorf("%s: %v", mutation.name, err)
		}
	}
	// a flag saying none follows, with an entry after it, is a trailing tail
	noPending := bytes.Clone(encoded)
	noPending[flagOffset] = 0
	if _, err := decodeTlsDeviceKeys(noPending); !errors.Is(err, errTlsDeviceKeyFormat) {
		t.Errorf("an entry after a flag of none: %v", err)
	}
	// and the failure wraps the store's, so no caller reads it as absence
	if !errors.Is(errTlsDeviceKeyFormat, ErrSidecarStoreFailed) || errors.Is(errTlsDeviceKeyFormat, ErrSidecarStoreAbsent) {
		t.Error("the format error is not a store failure")
	}
}

// Two first calls at once make one key: the state's lock serializes the record's read and write.
func TestTlsDeviceKeyConcurrentFirstCallsMakeOneKey(t *testing.T) {
	_, _, _, secrets := newTlsTestSecrets(t)
	state := newTlsDeviceState(DefaultSidecarTlsSettings())
	now := newTlsTestClock().Now()
	const callCount = 8
	spkiHashes := make(chan [sha256.Size]byte, callCount)
	var wait sync.WaitGroup
	for range callCount {
		wait.Add(1)
		go func() {
			defer wait.Done()
			keys, err := state.keys(secrets, now)
			if err != nil {
				t.Error(err)
				return
			}
			spkiHashes <- keys.current.SpkiSha256()
		}()
	}
	wait.Wait()
	close(spkiHashes)
	seen := map[[sha256.Size]byte]bool{}
	for spkiHash := range spkiHashes {
		seen[spkiHash] = true
	}
	if len(seen) != 1 {
		t.Errorf("%d keys made", len(seen))
	}
}
