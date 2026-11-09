// The keys each actor held, as testHookSecret hands them over (TEST-M2-01): what fault's StoreView opens as a
// reader opens it, and nothing more. A secret belongs to the actor whose goroutine created, derived or unwrapped
// it, as the barrier driver knows its actors' goroutines; one from a goroutine no actor runs, a test's own setup
// or an oracle's derivation among them, belongs to "". Without sidecar_testhooks no hook reaches this, so every
// reader holds nothing and every open fails closed.
//
// Safe for concurrent use: hooks fire from any goroutine.

package sidecartest

import (
	"bytes"
	"maps"
	"slices"
	"sync"
)

type HeldSecrets struct {
	stateLock sync.Mutex
	// by actor, then by kind, each secret once
	actorKindSecrets map[string]map[string][][]byte
}

func NewHeldSecrets() *HeldSecrets {
	return &HeldSecrets{actorKindSecrets: map[string]map[string][][]byte{}}
}

// Records that actor held secret of kind, a copy, once.
func (self *HeldSecrets) Add(actor string, kind string, secret []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kindSecrets := self.actorKindSecrets[actor]
	if kindSecrets == nil {
		kindSecrets = map[string][][]byte{}
		self.actorKindSecrets[actor] = kindSecrets
	}
	for _, held := range kindSecrets[kind] {
		if bytes.Equal(held, secret) {
			return
		}
	}
	kindSecrets[kind] = append(kindSecrets[kind], bytes.Clone(secret))
}

// Copies of every secret of kind that actor held, in the order first held.
func (self *HeldSecrets) Secrets(actor string, kind string) [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	secrets := [][]byte{}
	for _, held := range self.actorKindSecrets[actor][kind] {
		secrets = append(secrets, bytes.Clone(held))
	}
	return secrets
}

// Every actor that held anything, "" among them when unattributed code did.
func (self *HeldSecrets) Actors() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Sorted(maps.Keys(self.actorKindSecrets))
}
