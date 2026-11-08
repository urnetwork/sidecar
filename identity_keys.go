// The sidecar's own keys (§5.5, D-CORE-5, D-CORE-6): its Ed25519 identity key (owner decision 44), durable for
// the sidecar_id's life, and the ClientKey seed of its current client generation, the 32 bytes
// connect.ClientSettings.ClientKeySeed takes. The identity key signs every statement; the ClientKey signs only the
// identity binding and §7.4's DPoP proofs. A compromised identity key means a SidecarRevoke and a new sidecar_id,
// so nothing here rotates one.
//
// Both live only in the network's keychain.ur (§5.9), in one record of the core's namespace, with the ids and the
// newest binding, so one write of keychain.ur moves all of it at once: a kill leaves the old generation or the new
// one, never a ClientKey without its binding. A key is made in memory first, since enrollment persists nothing
// until api confirms admin_refused (D-CORE-7), and every key reaches testHookSecret where it is made or read.
//
// Nothing here names a connect type, so it builds on every leg.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The keychain namespace of the core's own records (§5.9's keychain.ur).
const sidecarCoreSecretsNamespace = "core"

// The record holding the identity, its keys and the newest binding.
const sidecarIdentityRecordName = "identity"

// The identity record's format values: magic, version, then network, sidecar and client ids, the generation, the
// identity seed, the ClientKey seed, and the binding with its length, integers big endian.
const (
	sidecarIdentityRecordMagic   = "URID"
	sidecarIdentityRecordVersion = 1
	// Far past any binding, which is about 250 bytes, so the bound only stops a decoder reading garbage whole.
	sidecarIdentityMaxBindingByteCount = 64 * 1024
)

var (
	// The keychain holds no identity for this network: it has not enrolled.
	ErrSidecarNoIdentity = errors.New("no sidecar identity")
	// The identity record does not decode. As any value failing decoding, this is a failure and never absence
	// (D-CORE-15).
	errSidecarIdentityFormat = fmt.Errorf("%w: the identity record does not decode", ErrSidecarStoreFailed)
)

// Who this sidecar is: its ids, its current client generation and the public halves of its keys. It never holds a
// private key, so it may go anywhere an id may.
type SidecarIdentity struct {
	NetworkId Id
	SidecarId Id
	// The current generation's client.
	ClientId Id
	// The bound client generation (§5.5), 1 for a sidecar_id's first.
	Generation int64
	// The identity key's Ed25519 public half.
	IdentityPublicKey []byte
	// The current ClientKey's Ed25519 public half.
	ClientPublicKey []byte
}

// A copy sharing no slice.
func (self *SidecarIdentity) clone() *SidecarIdentity {
	clone := *self
	clone.IdentityPublicKey = bytes.Clone(self.IdentityPublicKey)
	clone.ClientPublicKey = bytes.Clone(self.ClientPublicKey)
	return &clone
}

// The identity key and the ClientKey of one client generation, as seeds, in memory. Erase zeroes both. Not safe
// for concurrent use.
type sidecarIdentityKeys struct {
	identitySeed  []byte
	clientKeySeed []byte
}

// Fresh keys for a new sidecar: a new identity key and its first ClientKey, drawn from random.
func newSidecarIdentityKeys(random io.Reader) (*sidecarIdentityKeys, error) {
	identitySeed, err := newSidecarKeySeed(random, "identity_key")
	if err != nil {
		return nil, err
	}
	clientKeySeed, err := newSidecarKeySeed(random, "ClientKey")
	if err != nil {
		clear(identitySeed)
		return nil, err
	}
	return &sidecarIdentityKeys{identitySeed: identitySeed, clientKeySeed: clientKeySeed}, nil
}

// The same identity key with a new ClientKey, for generation n+1: re-enrollment, pairing, fallback (§5.5, §5.8).
func (self *sidecarIdentityKeys) withNewClientKey(random io.Reader) (*sidecarIdentityKeys, error) {
	clientKeySeed, err := newSidecarKeySeed(random, "ClientKey")
	if err != nil {
		return nil, err
	}
	return &sidecarIdentityKeys{identitySeed: bytes.Clone(self.identitySeed), clientKeySeed: clientKeySeed}, nil
}

// A new Ed25519 seed from random, reported to the privacy harness as the key kind names it.
func newSidecarKeySeed(random io.Reader, kind string) ([]byte, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, fmt.Errorf("no randomness for a key: %w", err)
	}
	// the seed is the key: a private key or a seed that leaks holds these bytes
	testHookSecret(kind, seed)
	return seed, nil
}

// The identity key's public half.
func (self *sidecarIdentityKeys) identityPublicKey() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(self.identitySeed).Public().(ed25519.PublicKey)
}

// The ClientKey's public half, which POST /network/enroll sends as client_public_key.
func (self *sidecarIdentityKeys) clientPublicKey() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(self.clientKeySeed).Public().(ed25519.PublicKey)
}

// A copy of the ClientKey seed, for connect.ClientSettings.ClientKeySeed and newDpopSigner. The caller zeroes it
// once used.
func (self *sidecarIdentityKeys) clientKeySeedCopy() []byte {
	return bytes.Clone(self.clientKeySeed)
}

// Zeroes both seeds.
func (self *sidecarIdentityKeys) erase() {
	clear(self.identitySeed)
	clear(self.clientKeySeed)
}

// What the core keeps in keychain.ur for one network: the identity, its keys and the newest binding.
type sidecarIdentityRecord struct {
	identity *SidecarIdentity
	keys     *sidecarIdentityKeys
	// The newest marshalled SignedSidecarIdentityBinding, which a restore_required refresh posts again (§5.6).
	binding []byte
}

// The record's bytes. The public keys are not stored: they follow from the seeds.
func (self *sidecarIdentityRecord) encode() []byte {
	encoded := make([]byte, 0, len(sidecarIdentityRecordMagic)+1+3*16+8+2*ed25519.SeedSize+4+len(self.binding))
	encoded = append(encoded, sidecarIdentityRecordMagic...)
	encoded = append(encoded, sidecarIdentityRecordVersion)
	encoded = append(encoded, self.identity.NetworkId[:]...)
	encoded = append(encoded, self.identity.SidecarId[:]...)
	encoded = append(encoded, self.identity.ClientId[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(self.identity.Generation))
	encoded = append(encoded, self.keys.identitySeed...)
	encoded = append(encoded, self.keys.clientKeySeed...)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(self.binding)))
	return append(encoded, self.binding...)
}

// Exactly one record of this version with every id set, a positive generation and a binding, or
// errSidecarIdentityFormat, which never repeats the bytes.
func decodeSidecarIdentityRecord(encoded []byte) (*sidecarIdentityRecord, error) {
	cursor := &wrapCursor{remaining: encoded}
	magic := cursor.take(len(sidecarIdentityRecordMagic))
	version := cursor.takeUint8()
	networkIdBytes := cursor.take(16)
	sidecarIdBytes := cursor.take(16)
	clientIdBytes := cursor.take(16)
	generation := cursor.takeUint64()
	identitySeed := cursor.take(ed25519.SeedSize)
	clientKeySeed := cursor.take(ed25519.SeedSize)
	bindingByteCount := cursor.takeUint32()
	if cursor.failed || string(magic) != sidecarIdentityRecordMagic || version != sidecarIdentityRecordVersion ||
		bindingByteCount == 0 || sidecarIdentityMaxBindingByteCount < bindingByteCount {
		return nil, errSidecarIdentityFormat
	}
	binding := cursor.take(int(bindingByteCount))
	if !cursor.finished() || generation < 1 || 1<<62 < generation {
		return nil, errSidecarIdentityFormat
	}
	ids := [3]Id{}
	for i, idBytes := range [][]byte{networkIdBytes, sidecarIdBytes, clientIdBytes} {
		id, err := IdFromBytes(idBytes)
		if err != nil || id == (Id{}) {
			return nil, errSidecarIdentityFormat
		}
		ids[i] = id
	}
	keys := &sidecarIdentityKeys{identitySeed: bytes.Clone(identitySeed), clientKeySeed: bytes.Clone(clientKeySeed)}
	testHookSecret("identity_key", keys.identitySeed)
	testHookSecret("ClientKey", keys.clientKeySeed)
	return &sidecarIdentityRecord{
		identity: &SidecarIdentity{
			NetworkId:         ids[0],
			SidecarId:         ids[1],
			ClientId:          ids[2],
			Generation:        int64(generation),
			IdentityPublicKey: keys.identityPublicKey(),
			ClientPublicKey:   keys.clientPublicKey(),
		},
		keys:    keys,
		binding: bytes.Clone(binding),
	}, nil
}

// Writes the identity, its keys and the newest binding to secrets, the core's namespace of the network's keychain,
// in one write: enrollment's persist after api confirms admin_refused, and each new generation's (D-CORE-7). The
// binding must verify and name the same ids, generation and keys, so the record never holds a pair that does not
// match.
func persistSidecarIdentity(secrets SidecarSecrets, keys *sidecarIdentityKeys, signedBinding []byte) (*SidecarIdentity, error) {
	binding, err := VerifySidecarIdentityBinding(signedBinding)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(binding.IdentityPublicKey, keys.identityPublicKey()) ||
		!bytes.Equal(binding.ClientPublicKey, keys.clientPublicKey()) {
		return nil, fmt.Errorf("%w: the binding names other keys", ErrSidecarBindingInvalid)
	}
	record := &sidecarIdentityRecord{
		identity: &SidecarIdentity{
			NetworkId:         binding.NetworkId,
			SidecarId:         binding.SidecarId,
			ClientId:          binding.ClientId,
			Generation:        binding.Generation,
			IdentityPublicKey: binding.IdentityPublicKey,
			ClientPublicKey:   binding.ClientPublicKey,
		},
		keys:    keys,
		binding: signedBinding,
	}
	encoded := record.encode()
	defer clear(encoded)
	testHookBarrier("identity.persist.before", binding.SidecarId.String())
	err = secrets.Put(sidecarIdentityRecordName, encoded)
	testHookBarrier("identity.persist.after", binding.SidecarId.String())
	if err != nil {
		return nil, err
	}
	return record.identity.clone(), nil
}

// The identity record secrets holds: ErrSidecarNoIdentity when there is none, the keychain's ErrSidecarStoreLocked
// while it is locked, and ErrSidecarStoreFailed for one that does not decode. The caller erases its keys once done.
func loadSidecarIdentity(secrets SidecarSecrets) (*sidecarIdentityRecord, error) {
	encoded, err := secrets.Get(sidecarIdentityRecordName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, ErrSidecarNoIdentity
	}
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	return decodeSidecarIdentityRecord(encoded)
}
