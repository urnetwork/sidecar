// The keys §11.6's format takes from one generation of a repo's key (§10.5): K_path_p, which keys tokens of path
// epoch p; K_ref, from RK_1 for the repo's life, which keys ref ids; manifest_g, which seals record headers, entry
// fields, push metadata and names; and fek_g, which wraps object keys. Each is derived once, through
// EvsRepoKey.DeriveKey, whose HKDF hooks it under its §10.5 name, and then kept, so a token path of 32 components
// or a segment of many records costs one derivation per purpose, never one per use.
//
// A deposit's writer holds none of these: it seals under K_dep, from its deposit's own object key
// (plan-EVS1-format-bytes#5), which takes manifest's place, so EvsManifestKey carries either.
//
// These live in the client's memory only: no server receives or derives one (I-1), and nothing here logs a key.
// Each type is immutable once made, so it is safe for concurrent use.

package sidecar

import (
	"errors"
	"fmt"
)

// The width of every key the format derives or draws: K_path, K_ref, manifest, fek, K_dep and object keys.
const evsKeyByteCount = 32

// A key the format needs that its holder does not have, or one of the wrong shape.
var ErrEvsKeyMissing = errors.New("evs key missing")

// K_path_p = HKDF-SHA256(RK_p, salt repo_id, info "UR evs 1.0 path" || u64be(p)): the key of path epoch p's tokens,
// p being the generation that derives it (§11.6's path epochs).
type EvsPathKey struct {
	repoId Id
	epoch  uint64
	key    []byte
}

// Path epoch p's key from generation p of the repo's key.
func NewEvsPathKey(repoKey *EvsRepoKey) (*EvsPathKey, error) {
	key, err := repoKey.DeriveKey(EvsKeyPurposePath, nil)
	if err != nil {
		return nil, err
	}
	return &EvsPathKey{repoId: repoKey.RepoId(), epoch: repoKey.Generation(), key: key}, nil
}

// The repo whose tokens it keys.
func (self *EvsPathKey) RepoId() Id {
	return self.repoId
}

// p, the path epoch it keys.
func (self *EvsPathKey) Epoch() uint64 {
	return self.epoch
}

// ErrEvsKeyMissing unless this holds a key, which only NewEvsPathKey makes.
func (self *EvsPathKey) checkHeld() error {
	if self == nil || len(self.key) != evsKeyByteCount {
		return fmt.Errorf("%w: no path key", ErrEvsKeyMissing)
	}
	return nil
}

// K_ref = HKDF-SHA256(RK_1, salt repo_id, info "UR evs 1.0 ref" || u64be(1)), the same at every generation, so
// any reader derives head/<repo>/<ref> for a name it holds (§11.6's ref ids, D-KEYS-22).
type EvsRefKey struct {
	repoId Id
	key    []byte
}

// K_ref from a key whose ladder has reached RK_1, at any generation. A key that has not is ErrGkmKeyMissing.
func NewEvsRefKey(repoKey *EvsRepoKey) (*EvsRefKey, error) {
	key, err := repoKey.DeriveKey(EvsKeyPurposeRef, nil)
	if err != nil {
		return nil, err
	}
	return &EvsRefKey{repoId: repoKey.RepoId(), key: key}, nil
}

// The repo whose ref ids it keys.
func (self *EvsRefKey) RepoId() Id {
	return self.repoId
}

// ErrEvsKeyMissing unless this holds a key, which only NewEvsRefKey makes.
func (self *EvsRefKey) checkHeld() error {
	if self == nil || len(self.key) != evsKeyByteCount {
		return fmt.Errorf("%w: no ref key", ErrEvsKeyMissing)
	}
	return nil
}

// What seals a record header, an entry's sealed_fields, a push's sealed metadata and a name: manifest_g of
// generation g, or on a deposit ref the deposit's K_dep, which takes manifest's place under the same layouts and
// AADs (plan-EVS1-format-bytes#5). generation is the g each AAD names.
type EvsManifestKey struct {
	repoId     Id
	generation uint64
	deposit    bool
	key        []byte
}

// manifest_g from generation g of the repo's key.
func NewEvsManifestKey(repoKey *EvsRepoKey) (*EvsManifestKey, error) {
	key, err := repoKey.DeriveKey(EvsKeyPurposeManifest, nil)
	if err != nil {
		return nil, err
	}
	return &EvsManifestKey{repoId: repoKey.RepoId(), generation: repoKey.Generation(), key: key}, nil
}

// The repo it seals for.
func (self *EvsManifestKey) RepoId() Id {
	return self.repoId
}

// The g its AADs name.
func (self *EvsManifestKey) Generation() uint64 {
	return self.generation
}

// Whether it is a deposit's K_dep rather than manifest_g.
func (self *EvsManifestKey) Deposit() bool {
	return self.deposit
}

// ErrEvsKeyMissing unless this holds a key, which only its constructors make.
func (self *EvsManifestKey) checkHeld() error {
	if self == nil || len(self.key) != evsKeyByteCount {
		return fmt.Errorf("%w: no manifest key", ErrEvsKeyMissing)
	}
	return nil
}

// fek_g, which wraps object keys under generation g: a segment's or inline chain's wrapped-key block, and a slot's
// keys outside deposits (§11.6's object key row, plan-EVS1-format-bytes#2).
type EvsFekKey struct {
	repoId     Id
	generation uint64
	key        []byte
}

// fek_g from generation g of the repo's key.
func NewEvsFekKey(repoKey *EvsRepoKey) (*EvsFekKey, error) {
	key, err := repoKey.DeriveKey(EvsKeyPurposeFek, nil)
	if err != nil {
		return nil, err
	}
	return &EvsFekKey{repoId: repoKey.RepoId(), generation: repoKey.Generation(), key: key}, nil
}

// The repo it wraps for.
func (self *EvsFekKey) RepoId() Id {
	return self.repoId
}

// g.
func (self *EvsFekKey) Generation() uint64 {
	return self.generation
}

// ErrEvsKeyMissing unless this holds a key, which only NewEvsFekKey makes.
func (self *EvsFekKey) checkHeld() error {
	if self == nil || len(self.key) != evsKeyByteCount {
		return fmt.Errorf("%w: no fek key", ErrEvsKeyMissing)
	}
	return nil
}
