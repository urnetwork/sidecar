// §7.9's log as fixtures, for gkm's client to read through sidecar.GkmAuthView until TEAM's ConfigState implements
// it (TEAM-M2-02). Each position is a state a test writes: the ProjectionRows it compiles to, whose AclRows give
// Repo, and what §8.6's evaluation and the admissions would give, which no fixture can compute: identity keys,
// readers and writers. Positions chain as the real log does, each A_n hashing the one before, so At and OnChain
// see a fork the way a reader would; the chain values are this fake's own, not AuthChainDigest's.
//
// Safe for concurrent use. A view never changes once appended.

package sidecartest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One position's state, as a test writes it.
type FakeGkmAuthFixture struct {
	// The rows it compiles to. Nil: none, so Repo answers nil.
	Rows *bridge.ProjectionRows
	// Each admitted sidecar's identity key.
	IdentityKeys map[sidecar.Id][]byte
	// RepoReaders, by repo.
	RepoReaders map[sidecar.Id][]sidecar.Id
	// The writers, by repo.
	RepoWriters map[sidecar.Id][]sidecar.Id
}

// A copy that shares nothing the test may change later.
func (self *FakeGkmAuthFixture) clone() *FakeGkmAuthFixture {
	cloned := &FakeGkmAuthFixture{
		IdentityKeys: map[sidecar.Id][]byte{},
		RepoReaders:  map[sidecar.Id][]sidecar.Id{},
		RepoWriters:  map[sidecar.Id][]sidecar.Id{},
	}
	if self == nil {
		return cloned
	}
	if self.Rows != nil {
		cloned.Rows = proto.Clone(self.Rows).(*bridge.ProjectionRows)
	}
	for sidecarId, identityKey := range self.IdentityKeys {
		cloned.IdentityKeys[sidecarId] = bytes.Clone(identityKey)
	}
	for repoId, readers := range self.RepoReaders {
		cloned.RepoReaders[repoId] = slices.Clone(readers)
	}
	for repoId, writers := range self.RepoWriters {
		cloned.RepoWriters[repoId] = slices.Clone(writers)
	}
	return cloned
}

// A chain of fixture states, positions 1 on.
type FakeGkmAuthLog struct {
	stateLock sync.Mutex
	views     []*FakeGkmAuthView
	// the oldest position a reader retains (§7.9's retain row)
	retainedFrom uint64
}

func NewFakeGkmAuthLog() *FakeGkmAuthLog {
	return &FakeGkmAuthLog{retainedFrom: 1}
}

// A_0, which the first position hashes.
func fakeGkmAuthGenesisChain() []byte {
	chain := sha256.Sum256([]byte("fake gkm auth log genesis"))
	return chain[:]
}

// A_n from A_{n-1}, n and the position's own rows.
func fakeGkmAuthChain(previousChain []byte, version uint64, rowsBytes []byte) []byte {
	hasher := sha256.New()
	hasher.Write(previousChain)
	hasher.Write(binary.BigEndian.AppendUint64(nil, version))
	hasher.Write(rowsBytes)
	return hasher.Sum(nil)
}

// Appends the next position with the fixture's state, and returns its view.
func (self *FakeGkmAuthLog) Append(fixture *FakeGkmAuthFixture) *FakeGkmAuthView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	previousChain := fakeGkmAuthGenesisChain()
	if 0 < len(self.views) {
		previousChain = self.views[len(self.views)-1].pin.GetChain()
	}
	cloned := fixture.clone()
	rowsBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(cloned.Rows)
	if err != nil {
		panic(fmt.Sprintf("fake auth log: rows: %v", err))
	}
	version := uint64(len(self.views)) + 1
	view := &FakeGkmAuthView{
		log:     self,
		pin:     &bridge.AuthPin{Version: version, Chain: fakeGkmAuthChain(previousChain, version, rowsBytes)},
		fixture: cloned,
		acl:     &protocol.AclRows{},
	}
	if cloned.Rows != nil {
		if err := proto.Unmarshal(cloned.Rows.GetAcl(), view.acl); err != nil {
			panic(fmt.Sprintf("fake auth log: AclRows: %v", err))
		}
	}
	self.views = append(self.views, view)
	return view
}

// The newest position, or nil before the first.
func (self *FakeGkmAuthLog) Tip() *FakeGkmAuthView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.views) == 0 {
		return nil
	}
	return self.views[len(self.views)-1]
}

// Retains positions from version on, as a reader past its retention point does: At refuses an earlier pin as
// ErrGkmAuthNotRetained and OnChain says false for one.
func (self *FakeGkmAuthLog) Retain(version uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.retainedFrom = version
}

// A pin on no chain of this log, a fork's, at version.
func FakeGkmForkPin(version uint64) *bridge.AuthPin {
	chain := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("fake gkm auth fork"), version))
	return &bridge.AuthPin{Version: version, Chain: chain[:]}
}

// One position of a FakeGkmAuthLog.
type FakeGkmAuthView struct {
	log     *FakeGkmAuthLog
	pin     *bridge.AuthPin
	fixture *FakeGkmAuthFixture
	acl     *protocol.AclRows
}

func (self *FakeGkmAuthView) Pin() *bridge.AuthPin {
	return proto.Clone(self.pin).(*bridge.AuthPin)
}

// The view at pin, by this view's own chain.
func (self *FakeGkmAuthView) At(pin *bridge.AuthPin) (sidecar.GkmAuthView, error) {
	if pin == nil || pin.GetVersion() == 0 {
		return nil, fmt.Errorf("%w: no pin", sidecar.ErrGkmAuthOffChain)
	}
	if self.pin.GetVersion() < pin.GetVersion() {
		return nil, sidecar.ErrGkmAuthAhead
	}
	self.log.stateLock.Lock()
	defer self.log.stateLock.Unlock()
	if pin.GetVersion() < self.log.retainedFrom {
		return nil, sidecar.ErrGkmAuthNotRetained
	}
	view := self.log.views[pin.GetVersion()-1]
	if !bytes.Equal(view.pin.GetChain(), pin.GetChain()) {
		return nil, sidecar.ErrGkmAuthOffChain
	}
	return view, nil
}

func (self *FakeGkmAuthView) OnChain(pin *bridge.AuthPin) bool {
	_, err := self.At(pin)
	return err == nil
}

func (self *FakeGkmAuthView) IdentityKey(sidecarId sidecar.Id) []byte {
	return bytes.Clone(self.fixture.IdentityKeys[sidecarId])
}

func (self *FakeGkmAuthView) Repo(repoId sidecar.Id) *protocol.AclRepo {
	for _, repo := range self.acl.GetRepos() {
		if bytes.Equal(repo.GetRepoId(), repoId.Bytes()) {
			return proto.Clone(repo).(*protocol.AclRepo)
		}
	}
	return nil
}

func (self *FakeGkmAuthView) RepoReaders(repoId sidecar.Id) []sidecar.Id {
	return slices.Clone(self.fixture.RepoReaders[repoId])
}

func (self *FakeGkmAuthView) RepoWriters(repoId sidecar.Id) []sidecar.Id {
	return slices.Clone(self.fixture.RepoWriters[repoId])
}

// A fixture's rows for repos with these holders_shrunk_at, the one AclRows field gkm's client reads here, and kinds.
func FakeGkmAuthRows(repos ...*protocol.AclRepo) *bridge.ProjectionRows {
	acl, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.AclRows{Repos: repos})
	if err != nil {
		panic(fmt.Sprintf("fake auth rows: %v", err))
	}
	return &bridge.ProjectionRows{Acl: acl}
}
