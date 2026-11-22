//go:build !ios_extension

// The connect identity a client generation keeps (§5.5, §5.9): the seed its client's sequence certificate and provide
// secret keys derive from (sidecar_new_connect.go), in the network's keychain.ur beside the identity record, under the
// client id and generation it was drawn for. A daemon restarted under its kept generation comes back under the same
// client id, and a peer that served it holds its send sequence to that id and the contracts on it, each HMAC'd with the
// client's provide key for the contract's mode and committed to the client's sequence certificate. A client that drew
// fresh material refuses every one of them, and the peer's answers wait on its AckTimeout, connect's 60 s: connect's
// contract manager keeps its keys for the process's life because without them "the client will have to time out the
// send sequence and flush its pending contracts". The sdk keeps all three across an app's restarts for that reason
// (sdk/device_local_key_material.go), the ClientKey seed being the identity record's here already, and edges derive
// theirs from a seed of their block's (host_edge_identity.go, QD-1174).
//
// A generation's first start draws one seed, 32 random bytes, and keeps it before the client opens, so nothing of the
// client reaches a peer under material the keychain does not hold; every later start of the generation reads it back.
// A record of another generation's, as a new generation finds its predecessor's, gives way to a new seed, so a new
// client never presents an earlier client's material. A record that fails decoding is §5.9's Failed, never absent, and
// nothing here overwrites it (D-CORE-15). The seed never leaves the keychain: it reaches testHookSecret where it is drawn
// or read and is never logged (I-7). Of what derives from it only the provide keys leave the device, to the platform, as
// every client's do, since the platform signs contracts to the client with them. Only a leg whose generations run a
// connect client keeps one (sidecarLeg.keepsConnectIdentity).
//
// Nothing here names a connect type, so it builds on every leg the core's identity does.

package sidecar

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The record of the current generation's connect identity seed, in the core's namespace beside the identity record.
const sidecarConnectIdentityRecordName = "connect_identity"

// The record's format values: magic, version, then the client id and generation it was drawn for and the seed,
// integers big endian.
const (
	sidecarConnectIdentityRecordMagic   = "URCI"
	sidecarConnectIdentityRecordVersion = 1
)

// The record does not decode. As any value failing decoding, this is a failure and never absence (D-CORE-15).
var errSidecarConnectIdentityFormat = fmt.Errorf("%w: the connect identity record does not decode", ErrSidecarStoreFailed)

// What keychain.ur keeps of one generation's connect identity.
type sidecarConnectIdentityRecord struct {
	clientId   Id
	generation int64
	seed       []byte
}

// The record's bytes.
func (self *sidecarConnectIdentityRecord) encode() []byte {
	encoded := make([]byte, 0, len(sidecarConnectIdentityRecordMagic)+1+len(self.clientId)+8+len(self.seed))
	encoded = append(encoded, sidecarConnectIdentityRecordMagic...)
	encoded = append(encoded, sidecarConnectIdentityRecordVersion)
	encoded = append(encoded, self.clientId[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(self.generation))
	return append(encoded, self.seed...)
}

// Exactly one record of this version with a client id, a positive generation and a whole seed, or
// errSidecarConnectIdentityFormat, which never repeats the bytes.
func decodeSidecarConnectIdentityRecord(encoded []byte) (*sidecarConnectIdentityRecord, error) {
	cursor := &wrapCursor{remaining: encoded}
	magic := cursor.take(len(sidecarConnectIdentityRecordMagic))
	version := cursor.takeUint8()
	clientIdBytes := cursor.take(len(Id{}))
	generation := int64(cursor.takeUint64())
	seed := cursor.take(sidecarConnectIdentitySeedByteCount)
	if !cursor.finished() || string(magic) != sidecarConnectIdentityRecordMagic ||
		version != sidecarConnectIdentityRecordVersion || generation < 1 {
		return nil, errSidecarConnectIdentityFormat
	}
	clientId, err := IdFromBytes(clientIdBytes)
	if err != nil || clientId == (Id{}) {
		return nil, errSidecarConnectIdentityFormat
	}
	record := &sidecarConnectIdentityRecord{clientId: clientId, generation: generation, seed: bytes.Clone(seed)}
	testHookSecret("connect_identity_seed", record.seed)
	return record, nil
}

// The seed secrets keeps for identity's generation: nil when it keeps none or another generation's, the keychain's own
// errors as they are, and errSidecarConnectIdentityFormat for a record that does not decode. The caller clears the
// seed.
func loadSidecarConnectIdentitySeed(secrets SidecarSecrets, identity *SidecarIdentity) ([]byte, error) {
	encoded, err := secrets.Get(sidecarConnectIdentityRecordName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	record, err := decodeSidecarConnectIdentityRecord(encoded)
	if err != nil {
		return nil, err
	}
	if record.clientId != identity.ClientId || record.generation != identity.Generation {
		// a predecessor's, which this generation's first start replaces
		clear(record.seed)
		return nil, nil
	}
	return record.seed, nil
}

// A new seed from random, reported to the privacy harness.
func newSidecarConnectIdentitySeed(random io.Reader) ([]byte, error) {
	seed := make([]byte, sidecarConnectIdentitySeedByteCount)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, fmt.Errorf("no randomness for a connect identity: %w", err)
	}
	// the seed is every key of the identity: a derived key or a seed that leaks holds what these bytes derive
	testHookSecret("connect_identity_seed", seed)
	return seed, nil
}

// Keeps seed in secrets as identity's generation's, in place of whatever generation's was there. A write has reached
// the disk when this returns nil.
func persistSidecarConnectIdentitySeed(secrets SidecarSecrets, identity *SidecarIdentity, seed []byte) error {
	record := &sidecarConnectIdentityRecord{clientId: identity.ClientId, generation: identity.Generation, seed: seed}
	encoded := record.encode()
	defer clear(encoded)
	testHookBarrier("identity.connect_identity.persist.before", identity.SidecarId.String())
	err := secrets.Put(sidecarConnectIdentityRecordName, encoded)
	testHookBarrier("identity.connect_identity.persist.after", identity.SidecarId.String())
	return err
}
