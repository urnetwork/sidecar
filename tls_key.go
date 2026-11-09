//go:build !sidecar_http

// §13.8's device TLS key (R-TLS-4, D-TLS-6): one P-256 key per device and network, made on this device and sealed in
// the network's keychain.ur under the tls component's namespace (§5.9), so it never reaches evs, a component's store
// or a server (I-1). The keychain holds the key; the tls component's store holds only certificates (TLS-M5-18).
//
// One record, device-key, holds the current key and the pending successor a rotation set, so one keychain write moves
// both: a kill leaves the old pair or the new one, never a successor without the key it replaces. A rotation on
// suspicion or request, or once TlsKeyRotationDue answers true, sets the pending key; the current key keeps serving
// until the successor's certificate installs (TLS-M5-18), which promotes it.
//
// TlsDeviceKey is a crypto.Signer that also gives out its SPKI. No method answers the private key, so the key leaves
// only as signatures. Every key reaches testHookSecret where it is made and where it is read back. Errors name no
// key, name or value (I-7, I-13).
//
// The record functions read, decide and write without a lock of their own: a caller that may race another holds one
// across the call, as tlsDeviceState does.
//
// Off the sidecar_http leg: a page Worker runs no tls component (§18.10).

package sidecar

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// The tls component's namespace of keychain.ur (§5.9): its component name, so the tls component's SidecarEnv.Secrets
// and Sidecar.TlsDeviceCertificate reach the same records.
const tlsSecretsNamespace = "tls"

// The record holding the current device key and its pending successor.
const tlsDeviceKeyRecordName = "device-key"

// The record's format values: magic, version, the current key's entry, a byte saying whether a pending entry follows,
// then that entry. An entry is the key's creation time in Unix milliseconds, the reason it was made and its P-256
// scalar, integers big endian.
const (
	tlsDeviceKeyRecordMagic   = "URTK"
	tlsDeviceKeyRecordVersion = 1
	tlsDeviceKeyScalarSize    = 32
)

var (
	// The device-key record does not decode. As any value failing decoding, a failure and never absence (D-CORE-15),
	// so nothing is made in its place.
	errTlsDeviceKeyFormat = fmt.Errorf("%w: the tls device key record does not decode", ErrSidecarStoreFailed)
	// A promotion named a key that is not the pending one: none is pending, or another is.
	ErrTlsDeviceKeyNotPending = errors.New("tls device key is not the pending one")
	// A rotation reason that is not one a successor can carry.
	ErrTlsKeyRotationReason = errors.New("tls key rotation reason refused")
)

// Why a device key was made (§13.8): the network's first, or a rotation's successor. It rides with the key, so
// whoever swaps it in knows how to retire its predecessor: keyCompromise after suspicion, superseded otherwise.
type TlsKeyRotationReason uint8

const (
	// The network's first key on this device.
	TlsKeyRotationNone TlsKeyRotationReason = 0
	// TlsKeyRotationDue answered true.
	TlsKeyRotationScheduled TlsKeyRotationReason = 1
	// A suspected compromise: the predecessor's certificate is revoked with keyCompromise (§13.8).
	TlsKeyRotationSuspicion TlsKeyRotationReason = 2
	// A person asked.
	TlsKeyRotationRequest TlsKeyRotationReason = 3
)

// Whether reason is one a key can carry.
func (self TlsKeyRotationReason) valid() bool {
	return self <= TlsKeyRotationRequest
}

// One device's TLS key for one network (§13.8). A crypto.Signer, so crypto/tls and crypto/x509 take it as a
// certificate's PrivateKey; nothing answers the private key itself. Immutable, and safe for concurrent use.
type TlsDeviceKey struct {
	privateKey *ecdsa.PrivateKey
	createTime time.Time
	reason     TlsKeyRotationReason
	// DER SubjectPublicKeyInfo
	spki []byte
}

// The public half, a *ecdsa.PublicKey on P-256, as crypto.Signer answers it. A copy, sharing nothing with the key.
func (self *TlsDeviceKey) Public() crypto.PublicKey {
	publicKey := self.privateKey.PublicKey
	return &publicKey
}

// Signs digest, as crypto.Signer does: an ASN.1 ECDSA signature.
func (self *TlsDeviceKey) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return self.privateKey.Sign(random, digest, opts)
}

// A copy of the key's DER SubjectPublicKeyInfo: what a CSR carries, a TLSA 3 1 1 record hashes, and an attestation's
// spki_sha256 covers.
func (self *TlsDeviceKey) Spki() []byte {
	return bytes.Clone(self.spki)
}

// SHA-256 of the SPKI, as TlsKeyAttestation.spki_sha256 and a link pin carry it.
func (self *TlsDeviceKey) SpkiSha256() [sha256.Size]byte {
	return sha256.Sum256(self.spki)
}

// When this device made the key, on the Sidecar's clock, to the millisecond.
func (self *TlsDeviceKey) CreateTime() time.Time {
	return self.createTime
}

// Why the key was made.
func (self *TlsDeviceKey) Reason() TlsKeyRotationReason {
	return self.reason
}

// Whether key is due for rotation at now: at or past settings.KeyRotationInterval, 180 days, from its making
// (§13.8). A due key keeps serving until its successor's certificate installs.
func TlsKeyRotationDue(key *TlsDeviceKey, now time.Time, settings *SidecarTlsSettings) bool {
	return !now.Before(key.createTime.Add(settings.KeyRotationInterval))
}

// A device's keys for one network as the keychain holds them: the key serving now and the successor a rotation set,
// nil when none is pending.
type tlsDeviceKeys struct {
	current *TlsDeviceKey
	pending *TlsDeviceKey
}

// A new P-256 key, made at now for reason, reported to the privacy harness. Since Go 1.26 GenerateKey draws from the
// system's secure source whatever reader it is given.
func newTlsDeviceKey(now time.Time, reason TlsKeyRotationReason) (*TlsDeviceKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return nil, fmt.Errorf("no tls key: %w", err)
	}
	scalar, err := privateKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("no tls key: %w", err)
	}
	// the scalar is the key: a private key that leaks holds these bytes
	testHookSecret("tls_device_key", scalar)
	clear(scalar)
	return newTlsDeviceKeyOf(privateKey, time.UnixMilli(now.UnixMilli()), reason)
}

// The TlsDeviceKey holding privateKey.
func newTlsDeviceKeyOf(privateKey *ecdsa.PrivateKey, createTime time.Time, reason TlsKeyRotationReason) (*TlsDeviceKey, error) {
	spki, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("no tls key: %w", err)
	}
	return &TlsDeviceKey{privateKey: privateKey, createTime: createTime, reason: reason, spki: spki}, nil
}

// Appends key's entry.
func appendTlsDeviceKeyEntry(encoded []byte, key *TlsDeviceKey) ([]byte, error) {
	scalar, err := key.privateKey.Bytes()
	if err != nil {
		return nil, err
	}
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(key.createTime.UnixMilli()))
	encoded = append(encoded, byte(key.reason))
	encoded = append(encoded, scalar...)
	clear(scalar)
	return encoded, nil
}

// The record's bytes, which the caller zeroes once written.
func (self *tlsDeviceKeys) encode() ([]byte, error) {
	encoded := make([]byte, 0, len(tlsDeviceKeyRecordMagic)+1+2*(8+1+tlsDeviceKeyScalarSize)+1)
	encoded = append(encoded, tlsDeviceKeyRecordMagic...)
	encoded = append(encoded, tlsDeviceKeyRecordVersion)
	encoded, err := appendTlsDeviceKeyEntry(encoded, self.current)
	if err != nil {
		clear(encoded)
		return nil, err
	}
	if self.pending == nil {
		return append(encoded, 0), nil
	}
	encoded = append(encoded, 1)
	encoded, err = appendTlsDeviceKeyEntry(encoded, self.pending)
	if err != nil {
		clear(encoded)
		return nil, err
	}
	return encoded, nil
}

// Reads one entry, reporting its key to the privacy harness, or errTlsDeviceKeyFormat.
func takeTlsDeviceKeyEntry(cursor *wrapCursor) (*TlsDeviceKey, error) {
	createTimeMillis := cursor.takeUint64()
	reason := TlsKeyRotationReason(cursor.takeUint8())
	scalar := cursor.take(tlsDeviceKeyScalarSize)
	if cursor.failed || !reason.valid() || createTimeMillis == 0 || 1<<62 < createTimeMillis {
		return nil, errTlsDeviceKeyFormat
	}
	scalar = bytes.Clone(scalar)
	defer clear(scalar)
	testHookSecret("tls_device_key", scalar)
	privateKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		return nil, errTlsDeviceKeyFormat
	}
	key, err := newTlsDeviceKeyOf(privateKey, time.UnixMilli(int64(createTimeMillis)), reason)
	if err != nil {
		return nil, errTlsDeviceKeyFormat
	}
	return key, nil
}

// Exactly one record of this version: the current key, and a pending one only if its flag says so. Anything else is
// errTlsDeviceKeyFormat, which never repeats the bytes.
func decodeTlsDeviceKeys(encoded []byte) (*tlsDeviceKeys, error) {
	cursor := &wrapCursor{remaining: encoded}
	magic := cursor.take(len(tlsDeviceKeyRecordMagic))
	version := cursor.takeUint8()
	if cursor.failed || string(magic) != tlsDeviceKeyRecordMagic || version != tlsDeviceKeyRecordVersion {
		return nil, errTlsDeviceKeyFormat
	}
	current, err := takeTlsDeviceKeyEntry(cursor)
	if err != nil {
		return nil, err
	}
	keys := &tlsDeviceKeys{current: current}
	switch cursor.takeUint8() {
	case 0:
	case 1:
		keys.pending, err = takeTlsDeviceKeyEntry(cursor)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errTlsDeviceKeyFormat
	}
	if cursor.failed || !cursor.finished() {
		return nil, errTlsDeviceKeyFormat
	}
	return keys, nil
}

// Writes keys as the record, in one keychain write.
func putTlsDeviceKeys(secrets SidecarSecrets, keys *tlsDeviceKeys) error {
	encoded, err := keys.encode()
	if err != nil {
		return err
	}
	defer clear(encoded)
	testHookBarrier("tls.device_key_put.before", "")
	err = secrets.Put(tlsDeviceKeyRecordName, encoded)
	testHookBarrier("tls.device_key_put.after", "")
	return err
}

// The keys secrets holds, nil with ErrSidecarStoreAbsent when there are none, the keychain's ErrSidecarStoreLocked
// while it is locked, and ErrSidecarStoreFailed for a record that does not decode.
func loadTlsDeviceKeys(secrets SidecarSecrets) (*tlsDeviceKeys, error) {
	encoded, err := secrets.Get(tlsDeviceKeyRecordName)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	return decodeTlsDeviceKeys(encoded)
}

// The keys secrets holds, making and sealing the network's first key, made at now, when the keychain answers that it
// holds none. Only absence makes one: a locked or failed keychain answers its error, and nothing is written over what
// may be there (D-CORE-15).
func loadOrCreateTlsDeviceKeys(secrets SidecarSecrets, now time.Time) (*tlsDeviceKeys, error) {
	keys, err := loadTlsDeviceKeys(secrets)
	if !errors.Is(err, ErrSidecarStoreAbsent) {
		return keys, err
	}
	current, err := newTlsDeviceKey(now, TlsKeyRotationNone)
	if err != nil {
		return nil, err
	}
	keys = &tlsDeviceKeys{current: current}
	if err := putTlsDeviceKeys(secrets, keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// Sets a pending successor made at now for reason, unless one is pending already, which it answers unchanged: one
// order at a time, and a second request needs nothing the first does not give. The current key keeps serving.
func rotateTlsDeviceKey(secrets SidecarSecrets, now time.Time, reason TlsKeyRotationReason) (*tlsDeviceKeys, error) {
	if reason == TlsKeyRotationNone || !reason.valid() {
		return nil, ErrTlsKeyRotationReason
	}
	keys, err := loadOrCreateTlsDeviceKeys(secrets, now)
	if err != nil || keys.pending != nil {
		return keys, err
	}
	pending, err := newTlsDeviceKey(now, reason)
	if err != nil {
		return nil, err
	}
	rotated := &tlsDeviceKeys{current: keys.current, pending: pending}
	if err := putTlsDeviceKeys(secrets, rotated); err != nil {
		return nil, err
	}
	return rotated, nil
}

// Makes the pending key whose SPKI hashes to spkiSha256 the current one, dropping the key it replaces, in one write:
// what TLS-M5-18 calls once that key's certificate has installed. Any other key answers ErrTlsDeviceKeyNotPending and
// changes nothing.
func promoteTlsDeviceKey(secrets SidecarSecrets, spkiSha256 [sha256.Size]byte) (*tlsDeviceKeys, error) {
	keys, err := loadTlsDeviceKeys(secrets)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, ErrTlsDeviceKeyNotPending
	}
	if err != nil {
		return nil, err
	}
	if keys.pending == nil || keys.pending.SpkiSha256() != spkiSha256 {
		return nil, ErrTlsDeviceKeyNotPending
	}
	promoted := &tlsDeviceKeys{current: keys.pending}
	if err := putTlsDeviceKeys(secrets, promoted); err != nil {
		return nil, err
	}
	return promoted, nil
}
