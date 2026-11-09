//go:build !sidecar_http

// Where Hello's identity check finds the key a peer's sidecar_id must hold (§6.4, D-PROTO-13). M1's
// source is first use per sidecar_id (§2.8 EX6): the first verified binding for a sidecar_id pins its
// identity key, durably, before Hello answers, and every later binding for it must name that key. From
// M2 the pin is the peer's SidecarAdmit in the config (rpc_admission.go), the source a Subprotocol runs
// on whenever its env carries Admissions, and these first-use pins are dropped as each sidecar_id is
// checked against its admission, since EX6 ends there.
//
// The pin is the identity key, never the client key: each re-pair binds generation n+1 under the same
// identity key on a new client (§5.8), so the client key changes and the identity key does not. A pin
// also keeps the highest generation seen, so a binding below it is refused: a replayed older generation
// cannot stand in for the newer one.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	// The binding's identity key is not the one its sidecar_id is pinned to (D-PROTO-13): key_changed.
	errHelloPinMismatch = errors.New("hello: identity key differs from the pin")
	// The binding's generation is below the highest this sidecar_id has shown.
	errHelloGenerationBelow = errors.New("hello: generation below the highest seen")
)

// What Hello asks of a pin: whether a verified binding's identity key and generation may stand for its
// sidecar_id, recording a first use and a higher generation durably before it answers. The answer is the
// peer's admission as this side's verified state holds it, nil under M1's first-use pins, which know of
// none. ctx bounds what the source may wait for, an admission source's one catch-up of the config. Safe
// for concurrent use.
type identityPinSource interface {
	checkPin(ctx context.Context, sidecarId Id, identityPublicKey []byte, generation int64) (*identityPinAdmission, error)
}

// A peer's admission as an admission source read it.
type identityPinAdmission struct {
	admission *AclSidecar
	// the position n of the state it was read at, or an older one: read before the admission, so a
	// state that moved between the two reads is read again at the next recheck, never skipped
	stateVersion uint64
}

// One sidecar_id's pin as stored: its identity key and the highest generation seen.
type identityPin struct {
	identityPublicKey [ed25519.PublicKeySize]byte
	generation        int64
}

// The pin file's form: a magic and version byte, the 32-byte key, then the generation, big endian.
const (
	identityPinMagic     = "URPIN"
	identityPinVersion   = 1
	identityPinByteCount = len(identityPinMagic) + 1 + ed25519.PublicKeySize + 8
)

// The pin's file bytes.
func (self *identityPin) encode() []byte {
	encoded := make([]byte, 0, identityPinByteCount)
	encoded = append(encoded, identityPinMagic...)
	encoded = append(encoded, identityPinVersion)
	encoded = append(encoded, self.identityPublicKey[:]...)
	return binary.BigEndian.AppendUint64(encoded, uint64(self.generation))
}

// The pin a file holds, or ErrSidecarStoreFailed for bytes of any other form.
func decodeIdentityPin(encoded []byte) (*identityPin, error) {
	if len(encoded) != identityPinByteCount || string(encoded[:len(identityPinMagic)]) != identityPinMagic || encoded[len(identityPinMagic)] != identityPinVersion {
		return nil, fmt.Errorf("%w: a pin file of another form", ErrSidecarStoreFailed)
	}
	pin := &identityPin{}
	keyStart := len(identityPinMagic) + 1
	copy(pin.identityPublicKey[:], encoded[keyStart:keyStart+ed25519.PublicKeySize])
	pin.generation = int64(binary.BigEndian.Uint64(encoded[keyStart+ed25519.PublicKeySize:]))
	if pin.generation < 1 {
		return nil, fmt.Errorf("%w: a pin below generation 1", ErrSidecarStoreFailed)
	}
	return pin, nil
}

// M1's identityPinSource: first use per sidecar_id, in the Subprotocol's sealed store, one file a
// sidecar_id under pins/. A read or write that fails refuses the binding, so a store fault never reads as
// a first use.
type firstUseIdentityPins struct {
	store SidecarStore

	// Serializes each check's read and write, so two first uses of one sidecar_id cannot both pin. It is
	// held across the store's I/O, which is why it is its own lock and never stateLock: nothing a packet
	// or frame path needs waits on it, and a Hello is rare, once per peer per HelloCacheTimeout.
	pinLock sync.Mutex
	// what the store holds, read once per sidecar_id and written with it
	sidecarIdPins map[Id]*identityPin
}

// Pins kept in store, read as each sidecar_id first shows.
func newFirstUseIdentityPins(store SidecarStore) *firstUseIdentityPins {
	return &firstUseIdentityPins{
		store:         store,
		sidecarIdPins: map[Id]*identityPin{},
	}
}

// The file a sidecar_id's pin is kept in.
func identityPinName(sidecarId Id) string {
	return "pins/" + sidecarId.String()
}

// The stored pin, nil when the store holds none. Called with pinLock held.
func (self *firstUseIdentityPins) loadWithLock(sidecarId Id) (*identityPin, error) {
	if pin, ok := self.sidecarIdPins[sidecarId]; ok {
		return pin, nil
	}
	reader, err := self.store.Open(identityPinName(sidecarId))
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	encoded, err := io.ReadAll(io.LimitReader(reader, int64(identityPinByteCount)+1))
	if err != nil {
		return nil, err
	}
	pin, err := decodeIdentityPin(encoded)
	if err != nil {
		return nil, err
	}
	self.sidecarIdPins[sidecarId] = pin
	return pin, nil
}

// Writes pin durably, then keeps it. Called with pinLock held.
func (self *firstUseIdentityPins) storeWithLock(sidecarId Id, pin *identityPin) error {
	testHookBarrier("rpc.hello_pin.before", sidecarId.String())
	defer testHookBarrier("rpc.hello_pin.after", sidecarId.String())
	writer, err := self.store.Create(identityPinName(sidecarId))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(pin.encode()); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	self.sidecarIdPins[sidecarId] = pin
	return nil
}

// See identityPinSource. The first binding for a sidecar_id pins it; a later one must name the pinned
// key and no lower generation, and a higher generation is recorded before this answers. First use knows
// no admission, so the answer's admission is always nil.
func (self *firstUseIdentityPins) checkPin(ctx context.Context, sidecarId Id, identityPublicKey []byte, generation int64) (*identityPinAdmission, error) {
	if len(identityPublicKey) != ed25519.PublicKeySize || generation < 1 {
		return nil, errHelloPinMismatch
	}
	self.pinLock.Lock()
	defer self.pinLock.Unlock()
	pin, err := self.loadWithLock(sidecarId)
	if err != nil {
		return nil, err
	}
	if pin == nil {
		pin = &identityPin{generation: generation}
		copy(pin.identityPublicKey[:], identityPublicKey)
		return nil, self.storeWithLock(sidecarId, pin)
	}
	if !bytes.Equal(pin.identityPublicKey[:], identityPublicKey) {
		return nil, errHelloPinMismatch
	}
	if generation < pin.generation {
		return nil, errHelloGenerationBelow
	}
	if pin.generation < generation {
		raised := &identityPin{identityPublicKey: pin.identityPublicKey, generation: generation}
		return nil, self.storeWithLock(sidecarId, raised)
	}
	return nil, nil
}
