// §6.4's HeadCheck sources in memory (the root's rpc_headcheck_sources.go), so PROTO-M2-03's transport
// and every HeadCheck schedule run before TEAM-M2-10, KEYS-M2-23, EVS1-M2-23 and CORE-M2-01 land them
// for real.
//
// FakeHeadCheckApi is one network's authorization log as api holds it: TICK entries chained by
// bridge.AuthChainDigest, which it can withhold from any device past a position, as a server that
// splits its readers does, and fork after a position, as one that serves two histories does. Each
// device's FakeHeadCheckAuth keeps its own verbatim entries and digests, fetches from an api, serves a
// HeadCheckProof from its newest entries within its retain bytes (HeadCheckMaxProofByteCount on every
// sidecar, phones included, as §7.9's retain row has it) and checks a peer's proof by its chain.
// FakeHeadCheckHeads holds a device's generation, epoch and ref pins with what the store holds past
// them, and FakeHeadCheckPeers its view of who is admitted, revoked, parked or suspended.
//
// What the fakes do not keep: signatures, since a fake log holds only ticks, which are unsigned, so a
// proof is checked by its chain alone (ConfigClient's VerifyAuthProof checks §7.9's verify row); bases
// and their rows; §7.9's precedence rule, as HoldVeto only records what it is handed; and the real
// sources' forward reads, which FakeHeadCheckHeads answers from what a test sets as the store's truth.
//
// Safe for concurrent use. A device's fake never holds its lock while it calls its api.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a fake's fetch or forward read refuses with when what it was served does not chain onto what it
// holds: the fork a real source refuses and reports.
var ErrFakeHeadCheckFork = errors.New("fake head check source: served a fork")

// One network's authorization log as api holds it.
type FakeHeadCheckApi struct {
	networkId sidecar.Id
	// what distinguishes this history's ticks from another's after a fork
	branch string

	stateLock sync.Mutex
	// entry n at index n-1, verbatim
	entries [][]byte
	// A_n at index n, A_0 the network's genesis digest
	chains [][]byte
	// for each device api withholds from, the last position it serves it
	withheldAfter map[sidecar.Id]uint64
}

// A log holding only its genesis, whose digest is synthetic and fixed by the network id.
func NewFakeHeadCheckApi(networkId sidecar.Id) *FakeHeadCheckApi {
	genesis := sha256.Sum256(append([]byte("urnetwork-sidecar-test/head-check-genesis/"), networkId.Bytes()...))
	return &FakeHeadCheckApi{
		networkId:     networkId,
		branch:        "main",
		chains:        [][]byte{genesis[:]},
		withheldAfter: map[sidecar.Id]uint64{},
	}
}

// The network.
func (self *FakeHeadCheckApi) NetworkId() sidecar.Id {
	return self.networkId
}

// Sequences count ticks and answers the new tip.
func (self *FakeHeadCheckApi) Append(count int) *bridge.AuthPin {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for range count {
		n := uint64(len(self.entries) + 1)
		prevChain := self.chains[n-1]
		body := fmt.Appendf(nil, "fake tick %s %d", self.branch, n)
		chain, err := bridge.AuthChainDigest(n, prevChain, bridge.AuthEntryKindTick, int64(n), body)
		if err != nil {
			panic(err)
		}
		entry := &bridge.AuthEntry{
			NetworkId: self.networkId.Bytes(),
			N:         n,
			PrevChain: bytes.Clone(prevChain),
			Kind:      bridge.AuthEntryKindTick,
			TimeMs:    int64(n),
			Body:      body,
		}
		entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
		if err != nil {
			panic(err)
		}
		self.entries = append(self.entries, entryBytes)
		self.chains = append(self.chains, chain[:])
	}
	return self.pinWithLock(uint64(len(self.entries)))
}

// (version, A_version) as api holds it, nil past its tip.
func (self *FakeHeadCheckApi) Pin(version uint64) *bridge.AuthPin {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pinWithLock(version)
}

// The pin at version, nil past the tip.
func (self *FakeHeadCheckApi) pinWithLock(version uint64) *bridge.AuthPin {
	if uint64(len(self.entries)) < version {
		return nil
	}
	return &bridge.AuthPin{Version: version, Chain: bytes.Clone(self.chains[version])}
}

// The newest pin.
func (self *FakeHeadCheckApi) Tip() *bridge.AuthPin {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pinWithLock(uint64(len(self.entries)))
}

// From now on serves the device nothing past position after, until Serve.
func (self *FakeHeadCheckApi) Withhold(sidecarId sidecar.Id, after uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.withheldAfter[sidecarId] = after
}

// Ends Withhold for the device.
func (self *FakeHeadCheckApi) Serve(sidecarId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.withheldAfter, sidecarId)
}

// A second history sharing this one's entries through position at and diverging after it, as a server
// serving two views would. Withholding does not carry over.
func (self *FakeHeadCheckApi) Fork(at uint64, branch string) *FakeHeadCheckApi {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	at = min(at, uint64(len(self.entries)))
	fork := &FakeHeadCheckApi{
		networkId:     self.networkId,
		branch:        branch,
		withheldAfter: map[sidecar.Id]uint64{},
	}
	for _, entryBytes := range self.entries[:at] {
		fork.entries = append(fork.entries, bytes.Clone(entryBytes))
	}
	for _, chain := range self.chains[:at+1] {
		fork.chains = append(fork.chains, bytes.Clone(chain))
	}
	return fork
}

// The entries after position after that api serves sidecarId, verbatim: through its tip, or through
// where it withholds.
func (self *FakeHeadCheckApi) entriesFor(sidecarId sidecar.Id, after uint64) [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	through := uint64(len(self.entries))
	if withheldAfter, withheld := self.withheldAfter[sidecarId]; withheld {
		through = min(through, withheldAfter)
	}
	entries := [][]byte{}
	for n := after + 1; n <= through; n += 1 {
		entries = append(entries, bytes.Clone(self.entries[n-1]))
	}
	return entries
}

// Every entry through version, verbatim, whatever api withholds: what a holder that saw them before a
// split keeps.
func (self *FakeHeadCheckApi) entriesThrough(version uint64) [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entries := [][]byte{}
	for n := uint64(1); n <= min(version, uint64(len(self.entries))); n += 1 {
		entries = append(entries, bytes.Clone(self.entries[n-1]))
	}
	return entries
}

// One device's view of the authorization log: a sidecar.HeadCheckAuthSource.
type FakeHeadCheckAuth struct {
	sidecarId sidecar.Id
	api       *FakeHeadCheckApi

	stateLock sync.Mutex
	// the position before the first entry kept
	keptFrom uint64
	// entry keptFrom+1 at index 0, through the pin
	entries [][]byte
	// A_k for each k from keptFrom through the pin
	chains map[uint64][]byte
	pin    *bridge.AuthPin
	// the newest entries' bytes a proof serves from
	retainByteCount int
	vetoes          [][]byte
	heldVetoes      [][]byte
}

// A device at api's genesis, keeping every entry it applies, serving proofs from its newest
// HeadCheckMaxProofByteCount of them.
func NewFakeHeadCheckAuth(sidecarId sidecar.Id, api *FakeHeadCheckApi) *FakeHeadCheckAuth {
	genesis := api.Pin(0)
	return &FakeHeadCheckAuth{
		sidecarId:       sidecarId,
		api:             api,
		chains:          map[uint64][]byte{0: genesis.GetChain()},
		pin:             genesis,
		retainByteCount: sidecar.HeadCheckMaxProofByteCount,
	}
}

// What its proofs serve from: fewer bytes model a holder whose kept entries reach back less far.
func (self *FakeHeadCheckAuth) SetRetainByteCount(retainByteCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.retainByteCount = retainByteCount
}

// Applies entries after the pin from api, through version, whatever api withholds: a device that saw
// them before a split.
func (self *FakeHeadCheckAuth) ReachFromApi(version uint64) error {
	pin := self.Pin()
	entries := self.api.entriesThrough(version)
	if uint64(len(entries)) <= pin.GetVersion() {
		return nil
	}
	return self.apply(pin, entries[pin.GetVersion():])
}

// Drops the entries and digests before position keptFrom, as a device whose retention point moved.
func (self *FakeHeadCheckAuth) Forget(keptFrom uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if keptFrom <= self.keptFrom || self.pin.GetVersion() < keptFrom {
		return
	}
	self.entries = self.entries[keptFrom-self.keptFrom:]
	for k := self.keptFrom; k < keptFrom; k += 1 {
		delete(self.chains, k)
	}
	self.keptFrom = keptFrom
}

// Applies entries onto pin, refusing at the first that does not chain onto it. pin is what the caller
// read; a pin that moved meanwhile applies only what still follows it.
func (self *FakeHeadCheckAuth) apply(pin *bridge.AuthPin, entries [][]byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, entryBytes := range entries {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return err
		}
		if entry.GetN() <= self.pin.GetVersion() {
			continue
		}
		if entry.GetN() != self.pin.GetVersion()+1 || !bytes.Equal(entry.GetPrevChain(), self.pin.GetChain()) {
			return ErrFakeHeadCheckFork
		}
		chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
		if err != nil {
			return err
		}
		self.entries = append(self.entries, bytes.Clone(entryBytes))
		self.chains[entry.GetN()] = chain[:]
		self.pin = &bridge.AuthPin{Version: entry.GetN(), Chain: chain[:]}
	}
	return nil
}

// The vetoes its HeadCheck carries.
func (self *FakeHeadCheckAuth) SetVetoes(vetoes [][]byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.vetoes = slices.Clone(vetoes)
}

// What HoldVeto was handed, in order.
func (self *FakeHeadCheckAuth) HeldVetoes() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.heldVetoes)
}

// A copy of the pin.
func (self *FakeHeadCheckAuth) Pin() *bridge.AuthPin {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return proto.CloneOf(self.pin)
}

// A kept digest.
func (self *FakeHeadCheckAuth) ChainAt(version uint64) ([]byte, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	chain, kept := self.chains[version]
	return bytes.Clone(chain), kept
}

// The vetoes set.
func (self *FakeHeadCheckAuth) Vetoes() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.vetoes)
}

// Applies what api serves this device after its pin, its whole tip unless it withholds. A history that
// does not chain onto the pin answers ErrFakeHeadCheckFork, having applied what did.
func (self *FakeHeadCheckAuth) FetchAuth(ctx context.Context, through *bridge.AuthPin) error {
	pin := self.Pin()
	return self.apply(pin, self.api.entriesFor(self.sidecarId, pin.GetVersion()))
}

// Checks that entries chain from the pin to through, and applies nothing.
func (self *FakeHeadCheckAuth) VerifyAuthProof(ctx context.Context, entries [][]byte, through *bridge.AuthPin) error {
	at := self.Pin()
	for _, entryBytes := range entries {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return fmt.Errorf("%w: %w", sidecar.ErrHeadCheckProofInvalid, err)
		}
		if !bytes.Equal(entry.GetNetworkId(), self.api.networkId.Bytes()) || entry.GetN() != at.GetVersion()+1 ||
			!bytes.Equal(entry.GetPrevChain(), at.GetChain()) {
			return sidecar.ErrHeadCheckProofInvalid
		}
		chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
		if err != nil {
			return fmt.Errorf("%w: %w", sidecar.ErrHeadCheckProofInvalid, err)
		}
		at = &bridge.AuthPin{Version: entry.GetN(), Chain: chain[:]}
	}
	if at.GetVersion() != through.GetVersion() || !bytes.Equal(at.GetChain(), through.GetChain()) {
		return sidecar.ErrHeadCheckProofInvalid
	}
	return nil
}

// The entries after position after through the pin, if they lie within its newest retain bytes;
// ErrHeadCheckProofNotFound if its kept entries do not reach back that far within them.
func (self *FakeHeadCheckAuth) AuthProof(after uint64) ([][]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.pin.GetVersion() <= after {
		return [][]byte{}, nil
	}
	if after < self.keptFrom {
		return nil, sidecar.ErrHeadCheckProofNotFound
	}
	entries := self.entries[after-self.keptFrom:]
	byteCount := 0
	for _, entryBytes := range entries {
		byteCount += len(entryBytes)
	}
	if self.retainByteCount < byteCount {
		return nil, sidecar.ErrHeadCheckProofNotFound
	}
	proof := make([][]byte, 0, len(entries))
	for _, entryBytes := range entries {
		proof = append(proof, bytes.Clone(entryBytes))
	}
	return proof, nil
}

// Records the veto; an empty one is refused.
func (self *FakeHeadCheckAuth) HoldVeto(ctx context.Context, signedVeto []byte) error {
	if len(signedVeto) == 0 {
		return errors.New("fake head check source: empty veto")
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.heldVetoes = append(self.heldVetoes, bytes.Clone(signedVeto))
	return nil
}

// One device's generation, epoch and ref pins, with what the store holds past them for its forward
// reads: a sidecar.HeadCheckGenSource, HeadCheckGroupSource and HeadCheckRefSource. Every pin is shared
// with every peer.
type FakeHeadCheckHeads struct {
	stateLock sync.Mutex
	gens      map[sidecar.Id]*protocol.GenHead
	groups    map[sidecar.Id]*protocol.GroupHead
	refs      map[[2]sidecar.Id]sidecar.HeadCheckRef
	// what gen/ and the refs' statements hold, by group and generation, and by ref and version
	storeGens map[sidecar.Id]map[uint64]*protocol.GenHead
	storeRefs map[[2]sidecar.Id]map[uint64]*protocol.RefHead
}

// No pins.
func NewFakeHeadCheckHeads() *FakeHeadCheckHeads {
	return &FakeHeadCheckHeads{
		gens:      map[sidecar.Id]*protocol.GenHead{},
		groups:    map[sidecar.Id]*protocol.GroupHead{},
		refs:      map[[2]sidecar.Id]sidecar.HeadCheckRef{},
		storeGens: map[sidecar.Id]map[uint64]*protocol.GenHead{},
		storeRefs: map[[2]sidecar.Id]map[uint64]*protocol.RefHead{},
	}
}

// Pins a generation, replacing the group's pin.
func (self *FakeHeadCheckHeads) SetGen(gen *protocol.GenHead) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.gens[sidecar.Id(gen.GetGroupId())] = proto.CloneOf(gen)
}

// Pins an epoch, replacing the group's pin.
func (self *FakeHeadCheckHeads) SetGroup(group *protocol.GroupHead) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.groups[sidecar.Id(group.GetGroupId())] = proto.CloneOf(group)
}

// Pins a ref, whose repo seals under groupId, replacing the ref's pin.
func (self *FakeHeadCheckHeads) SetRef(ref *protocol.RefHead, groupId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refs[[2]sidecar.Id{sidecar.Id(ref.GetRepoId()), sidecar.Id(ref.GetRefId())}] = sidecar.HeadCheckRef{Head: proto.CloneOf(ref), GroupId: groupId}
}

// What gen/ holds at gen's generation, which a forward read compares.
func (self *FakeHeadCheckHeads) StoreGen(gen *protocol.GenHead) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	groupId := sidecar.Id(gen.GetGroupId())
	if self.storeGens[groupId] == nil {
		self.storeGens[groupId] = map[uint64]*protocol.GenHead{}
	}
	self.storeGens[groupId][gen.GetGeneration()] = proto.CloneOf(gen)
}

// What the ref's statements come to at ref's version, which a forward read compares.
func (self *FakeHeadCheckHeads) StoreRef(ref *protocol.RefHead) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	refKey := [2]sidecar.Id{sidecar.Id(ref.GetRepoId()), sidecar.Id(ref.GetRefId())}
	if self.storeRefs[refKey] == nil {
		self.storeRefs[refKey] = map[uint64]*protocol.RefHead{}
	}
	self.storeRefs[refKey][ref.GetVersion()] = proto.CloneOf(ref)
}

// Every generation pin, by group id.
func (self *FakeHeadCheckHeads) GenHeads(peerSidecarId sidecar.Id) []*protocol.GenHead {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	gens := []*protocol.GenHead{}
	for _, gen := range self.gens {
		gens = append(gens, proto.CloneOf(gen))
	}
	slices.SortFunc(gens, func(a *protocol.GenHead, b *protocol.GenHead) int {
		return bytes.Compare(a.GetGroupId(), b.GetGroupId())
	})
	return gens
}

// One generation pin.
func (self *FakeHeadCheckHeads) GenHead(groupId sidecar.Id) (*protocol.GenHead, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	gen, held := self.gens[groupId]
	if !held {
		return nil, false
	}
	return proto.CloneOf(gen), true
}

// Reached, and pinned, when the store holds through's commitment at its generation; forked when it
// holds another; unserved when it holds none.
func (self *FakeHeadCheckHeads) CatchUpGen(ctx context.Context, through *protocol.GenHead) (sidecar.HeadCheckCatchUp, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	stored, served := self.storeGens[sidecar.Id(through.GetGroupId())][through.GetGeneration()]
	switch {
	case !served:
		return sidecar.HeadCheckCatchUpUnserved, nil
	case !bytes.Equal(stored.GetCommitment(), through.GetCommitment()):
		return sidecar.HeadCheckCatchUpForked, nil
	}
	self.gens[sidecar.Id(through.GetGroupId())] = proto.CloneOf(stored)
	return sidecar.HeadCheckCaughtUp, nil
}

// Every epoch pin, by group id.
func (self *FakeHeadCheckHeads) GroupHeads(peerSidecarId sidecar.Id) []*protocol.GroupHead {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	groups := []*protocol.GroupHead{}
	for _, group := range self.groups {
		groups = append(groups, proto.CloneOf(group))
	}
	slices.SortFunc(groups, func(a *protocol.GroupHead, b *protocol.GroupHead) int {
		return bytes.Compare(a.GetGroupId(), b.GetGroupId())
	})
	return groups
}

// One epoch pin.
func (self *FakeHeadCheckHeads) GroupHead(groupId sidecar.Id) (*protocol.GroupHead, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	group, held := self.groups[groupId]
	if !held {
		return nil, false
	}
	return proto.CloneOf(group), true
}

// Every ref pin, by repo and ref id.
func (self *FakeHeadCheckHeads) RefHeads(peerSidecarId sidecar.Id) []*protocol.RefHead {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	refs := []*protocol.RefHead{}
	for _, ref := range self.refs {
		refs = append(refs, proto.CloneOf(ref.Head))
	}
	slices.SortFunc(refs, func(a *protocol.RefHead, b *protocol.RefHead) int {
		return bytes.Compare(append(slices.Clone(a.GetRepoId()), a.GetRefId()...), append(slices.Clone(b.GetRepoId()), b.GetRefId()...))
	})
	return refs
}

// One ref pin.
func (self *FakeHeadCheckHeads) RefHead(repoId sidecar.Id, refId sidecar.Id) (sidecar.HeadCheckRef, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ref, held := self.refs[[2]sidecar.Id{repoId, refId}]
	if !held {
		return sidecar.HeadCheckRef{}, false
	}
	return sidecar.HeadCheckRef{Head: proto.CloneOf(ref.Head), GroupId: ref.GroupId}, true
}

// As CatchUpGen, for a ref's chain at through's version.
func (self *FakeHeadCheckHeads) CatchUpRef(ctx context.Context, through *protocol.RefHead) (sidecar.HeadCheckCatchUp, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	refKey := [2]sidecar.Id{sidecar.Id(through.GetRepoId()), sidecar.Id(through.GetRefId())}
	stored, served := self.storeRefs[refKey][through.GetVersion()]
	switch {
	case !served:
		return sidecar.HeadCheckCatchUpUnserved, nil
	case !bytes.Equal(stored.GetChain(), through.GetChain()):
		return sidecar.HeadCheckCatchUpForked, nil
	}
	if ref, held := self.refs[refKey]; held {
		self.refs[refKey] = sidecar.HeadCheckRef{Head: proto.CloneOf(stored), GroupId: ref.GroupId}
	}
	return sidecar.HeadCheckCaughtUp, nil
}

// One device's view of who stands: a sidecar.HeadCheckPeerState.
type FakeHeadCheckPeers struct {
	stateLock sync.Mutex
	peers     map[sidecar.Id]sidecar.HeadCheckPeer
}

// No one admitted.
func NewFakeHeadCheckPeers() *FakeHeadCheckPeers {
	return &FakeHeadCheckPeers{peers: map[sidecar.Id]sidecar.HeadCheckPeer{}}
}

// Admits each, standing.
func (self *FakeHeadCheckPeers) Admit(sidecarIds ...sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, sidecarId := range sidecarIds {
		self.peers[sidecarId] = sidecar.HeadCheckPeer{Admitted: true}
	}
}

// Sets how the state holds the sidecar.
func (self *FakeHeadCheckPeers) Set(sidecarId sidecar.Id, peer sidecar.HeadCheckPeer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.peers[sidecarId] = peer
}

// The peer as set, or one no admission names.
func (self *FakeHeadCheckPeers) HeadCheckPeer(sidecarId sidecar.Id) sidecar.HeadCheckPeer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.peers[sidecarId]
}

// One device's sources, together.
type FakeHeadCheckDevice struct {
	Auth  *FakeHeadCheckAuth
	Heads *FakeHeadCheckHeads
	Peers *FakeHeadCheckPeers
}

// A device at api's genesis with no other pins and no one admitted.
func NewFakeHeadCheckDevice(sidecarId sidecar.Id, api *FakeHeadCheckApi) *FakeHeadCheckDevice {
	return &FakeHeadCheckDevice{
		Auth:  NewFakeHeadCheckAuth(sidecarId, api),
		Heads: NewFakeHeadCheckHeads(),
		Peers: NewFakeHeadCheckPeers(),
	}
}

// The sources HeadCheck reads, all five set.
func (self *FakeHeadCheckDevice) Sources() *sidecar.HeadCheckSources {
	return &sidecar.HeadCheckSources{Auth: self.Auth, Gens: self.Heads, Groups: self.Heads, Refs: self.Heads, Peers: self.Peers}
}

var (
	_ sidecar.HeadCheckAuthSource  = (*FakeHeadCheckAuth)(nil)
	_ sidecar.HeadCheckGenSource   = (*FakeHeadCheckHeads)(nil)
	_ sidecar.HeadCheckGroupSource = (*FakeHeadCheckHeads)(nil)
	_ sidecar.HeadCheckRefSource   = (*FakeHeadCheckHeads)(nil)
	_ sidecar.HeadCheckPeerState   = (*FakeHeadCheckPeers)(nil)
)
