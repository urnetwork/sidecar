// §7.9's log and §8's evaluation as fixtures, for the record to read through sidecar.RecordAuthView until TEAM's
// ConfigState and ACL's AclState implement it, and §16.6's run files as a map, for sidecar.RecordRunView until
// MCP-M3-04's Sidecar.RunTainted fills it.
//
// Each position of a FakeRecordAuth is a state a test writes: who is admitted under which key, member and sponsor,
// who reads, writes and deposits each repo, whose deposits are receipts alone, who is consented, who a compromise
// revocation voids, and which logs exist. Positions chain as the real log does, each A_n hashing the one before, so
// At sees a fork the way a reader would; the chain values are this fake's own, not AuthChainDigest's. A view never
// changes once appended, and everything here is safe for concurrent use.

package sidecartest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One repo's rights at a position, as a test writes them.
type FakeRecordRepoAuth struct {
	Readers []sidecar.Id
	Writers []sidecar.Id
	// Devices of the repo's admins (§8.6).
	Admins     []sidecar.Id
	Depositors []sidecar.Id
	// Depositors whose deposits are read receipts alone (§11.12).
	ReceiptOnly []sidecar.Id
	// Consented devices of the repo's owner (§8.5).
	Consented []sidecar.Id
}

// One position's state, as a test writes it. A nil map answers no.
type FakeRecordAuthFixture struct {
	IdentityKeys map[sidecar.Id][]byte
	// The member of each untagged sidecar.
	Members map[sidecar.Id]sidecar.Id
	// The sponsor of each tagged sidecar that has one.
	Sponsors map[sidecar.Id]sidecar.Id
	Repos    map[sidecar.Id]*FakeRecordRepoAuth
	// Each compromise revocation's since_n, by sidecar.
	CompromisedSince map[sidecar.Id]uint64
	// Nil reads as a personal network with no team logs.
	Logs *sidecar.RecordLogIds
	// Each member's vault.
	Vaults map[sidecar.Id]sidecar.Id
	// The time_ms of the entry that made this position, which RightEnded answers.
	TimeMillis int64
}

// A deep copy, so a test changing its fixture later changes no appended view.
func (self *FakeRecordAuthFixture) clone() *FakeRecordAuthFixture {
	cloned := &FakeRecordAuthFixture{
		IdentityKeys:     map[sidecar.Id][]byte{},
		Members:          map[sidecar.Id]sidecar.Id{},
		Sponsors:         map[sidecar.Id]sidecar.Id{},
		Repos:            map[sidecar.Id]*FakeRecordRepoAuth{},
		CompromisedSince: map[sidecar.Id]uint64{},
		Logs:             &sidecar.RecordLogIds{},
		Vaults:           map[sidecar.Id]sidecar.Id{},
	}
	if self == nil {
		return cloned
	}
	for sidecarId, key := range self.IdentityKeys {
		cloned.IdentityKeys[sidecarId] = bytes.Clone(key)
	}
	for sidecarId, memberId := range self.Members {
		cloned.Members[sidecarId] = memberId
	}
	for sidecarId, sponsorId := range self.Sponsors {
		cloned.Sponsors[sidecarId] = sponsorId
	}
	for repoId, repo := range self.Repos {
		if repo == nil {
			continue
		}
		cloned.Repos[repoId] = &FakeRecordRepoAuth{
			Readers:     slices.Clone(repo.Readers),
			Writers:     slices.Clone(repo.Writers),
			Admins:      slices.Clone(repo.Admins),
			Depositors:  slices.Clone(repo.Depositors),
			ReceiptOnly: slices.Clone(repo.ReceiptOnly),
			Consented:   slices.Clone(repo.Consented),
		}
	}
	for sidecarId, since := range self.CompromisedSince {
		cloned.CompromisedSince[sidecarId] = since
	}
	if self.Logs != nil {
		cloned.Logs.Team = self.Logs.Team
		if self.Logs.TeamRecordId != nil {
			teamRecordId := *self.Logs.TeamRecordId
			cloned.Logs.TeamRecordId = &teamRecordId
		}
		if self.Logs.DirectoryId != nil {
			directoryId := *self.Logs.DirectoryId
			cloned.Logs.DirectoryId = &directoryId
		}
	}
	for memberId, vaultId := range self.Vaults {
		cloned.Vaults[memberId] = vaultId
	}
	cloned.TimeMillis = self.TimeMillis
	return cloned
}

// The log's positions, from 1. Safe for concurrent use.
type FakeRecordAuth struct {
	stateLock sync.Mutex
	views     []*fakeRecordAuthView
	// the first position a view still retains; earlier pins read as not retained
	retainedFrom uint64
}

func NewFakeRecordAuth() *FakeRecordAuth {
	return &FakeRecordAuth{retainedFrom: 1}
}

// Appends the next position and returns its view. The fixture is copied.
func (self *FakeRecordAuth) Append(fixture *FakeRecordAuthFixture) sidecar.RecordAuthView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	previous := make([]byte, sha256.Size)
	if len(self.views) > 0 {
		previous = self.views[len(self.views)-1].pin.GetChain()
	}
	version := uint64(len(self.views) + 1)
	chain := sha256.Sum256(binary.BigEndian.AppendUint64(slices.Clone(previous), version))
	view := &fakeRecordAuthView{
		auth:    self,
		pin:     &bridge.AuthPin{Version: version, Chain: chain[:]},
		fixture: fixture.clone(),
	}
	self.views = append(self.views, view)
	return view
}

// The newest position's view, nil before the first.
func (self *FakeRecordAuth) Tip() sidecar.RecordAuthView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.views) == 0 {
		return nil
	}
	return self.views[len(self.views)-1]
}

// Drops what every view retains below version, as §7.9's retain row lets a reader: At answers
// ErrRecordAuthNotRetained for an earlier pin.
func (self *FakeRecordAuth) RetainFrom(version uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.retainedFrom = max(self.retainedFrom, version)
}

// One position. Its pin and fixture never change.
type fakeRecordAuthView struct {
	auth    *FakeRecordAuth
	pin     *bridge.AuthPin
	fixture *FakeRecordAuthFixture
}

func (self *fakeRecordAuthView) Pin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: self.pin.GetVersion(), Chain: bytes.Clone(self.pin.GetChain())}
}

func (self *fakeRecordAuthView) At(pin *bridge.AuthPin) (sidecar.RecordAuthView, error) {
	if pin == nil || self.pin.GetVersion() < pin.GetVersion() {
		return nil, sidecar.ErrRecordAuthAhead
	}
	self.auth.stateLock.Lock()
	defer self.auth.stateLock.Unlock()
	if pin.GetVersion() < self.auth.retainedFrom {
		return nil, sidecar.ErrRecordAuthNotRetained
	}
	view := self.auth.views[pin.GetVersion()-1]
	if !bytes.Equal(view.pin.GetChain(), pin.GetChain()) {
		return nil, sidecar.ErrRecordAuthOffChain
	}
	return view, nil
}

func (self *fakeRecordAuthView) AtPosition(version uint64) (sidecar.RecordAuthView, error) {
	if version == 0 || self.pin.GetVersion() < version {
		return nil, sidecar.ErrRecordAuthAhead
	}
	self.auth.stateLock.Lock()
	defer self.auth.stateLock.Unlock()
	if version < self.auth.retainedFrom {
		return nil, sidecar.ErrRecordAuthNotRetained
	}
	return self.auth.views[version-1], nil
}

// The first position after after, up to this one, at which the sidecar neither writes nor deposits repo while it did
// at after.
func (self *fakeRecordAuthView) RightEnded(repoId sidecar.Id, sidecarId sidecar.Id, after uint64) (int64, bool) {
	self.auth.stateLock.Lock()
	defer self.auth.stateLock.Unlock()
	holds := func(view *fakeRecordAuthView) bool {
		return view.Writes(repoId, sidecarId) || view.Deposits(repoId, sidecarId)
	}
	if after == 0 || self.pin.GetVersion() < after || !holds(self.auth.views[after-1]) {
		return 0, false
	}
	for version := after + 1; version <= self.pin.GetVersion(); version += 1 {
		view := self.auth.views[version-1]
		if !holds(view) {
			return view.fixture.TimeMillis, true
		}
	}
	return 0, false
}

func (self *fakeRecordAuthView) IdentityKey(sidecarId sidecar.Id) []byte {
	return bytes.Clone(self.fixture.IdentityKeys[sidecarId])
}

func (self *fakeRecordAuthView) Member(sidecarId sidecar.Id) (sidecar.Id, bool) {
	memberId, ok := self.fixture.Members[sidecarId]
	return memberId, ok
}

func (self *fakeRecordAuthView) Sponsor(sidecarId sidecar.Id) (sidecar.Id, bool) {
	sponsorId, ok := self.fixture.Sponsors[sidecarId]
	return sponsorId, ok
}

// The repo's rights, or none.
func (self *fakeRecordAuthView) repo(repoId sidecar.Id) *FakeRecordRepoAuth {
	if repo := self.fixture.Repos[repoId]; repo != nil {
		return repo
	}
	return &FakeRecordRepoAuth{}
}

func (self *fakeRecordAuthView) Consented(repoId sidecar.Id, sidecarId sidecar.Id) bool {
	return slices.Contains(self.repo(repoId).Consented, sidecarId)
}

func (self *fakeRecordAuthView) Reads(repoId sidecar.Id, sidecarId sidecar.Id) bool {
	return slices.Contains(self.repo(repoId).Readers, sidecarId)
}

func (self *fakeRecordAuthView) Writes(repoId sidecar.Id, sidecarId sidecar.Id) bool {
	return slices.Contains(self.repo(repoId).Writers, sidecarId)
}

func (self *fakeRecordAuthView) Admins(repoId sidecar.Id, sidecarId sidecar.Id) bool {
	return slices.Contains(self.repo(repoId).Admins, sidecarId)
}

func (self *fakeRecordAuthView) Deposits(repoId sidecar.Id, sidecarId sidecar.Id) bool {
	return slices.Contains(self.repo(repoId).Depositors, sidecarId)
}

func (self *fakeRecordAuthView) ReceiptOnly(repoId sidecar.Id, sidecarId sidecar.Id) bool {
	return slices.Contains(self.repo(repoId).ReceiptOnly, sidecarId)
}

func (self *fakeRecordAuthView) CompromisedSince(sidecarId sidecar.Id) (uint64, bool) {
	since, ok := self.fixture.CompromisedSince[sidecarId]
	return since, ok
}

func (self *fakeRecordAuthView) Logs() *sidecar.RecordLogIds {
	logs := &sidecar.RecordLogIds{Team: self.fixture.Logs.Team}
	if self.fixture.Logs.TeamRecordId != nil {
		teamRecordId := *self.fixture.Logs.TeamRecordId
		logs.TeamRecordId = &teamRecordId
	}
	if self.fixture.Logs.DirectoryId != nil {
		directoryId := *self.fixture.Logs.DirectoryId
		logs.DirectoryId = &directoryId
	}
	return logs
}

func (self *fakeRecordAuthView) Vault(memberId sidecar.Id) (sidecar.Id, bool) {
	vaultId, ok := self.fixture.Vaults[memberId]
	return vaultId, ok
}

// §16.6's run files as a test drives them: a run starts untainted, may turn tainted and never back, and may lose its
// file, after which it reads tainted, as a run with no readable file does (D-MCP-16). Safe for concurrent use.
type FakeRunView struct {
	stateLock sync.Mutex
	// each run with a readable file, and whether it is tainted
	runTainted map[sidecar.Id]bool
	// every run ever tainted, which no later write clears
	everTainted map[sidecar.Id]bool
}

func NewFakeRunView() *FakeRunView {
	return &FakeRunView{runTainted: map[sidecar.Id]bool{}, everTainted: map[sidecar.Id]bool{}}
}

// Writes a run's file, untainted unless it was ever tainted.
func (self *FakeRunView) StartRun(runId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.runTainted[runId] = self.everTainted[runId]
}

// Taints a run, for good.
func (self *FakeRunView) Taint(runId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.runTainted[runId] = true
	self.everTainted[runId] = true
}

// Removes a run's file, as a deleted or unreadable one: the run reads tainted from then on.
func (self *FakeRunView) LoseRun(runId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.runTainted, runId)
}

// Tainted unless the run has a readable file that is not.
func (self *FakeRunView) RunTainted(runId sidecar.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	tainted, ok := self.runTainted[runId]
	return !ok || tainted
}
