//go:build !ios_extension && !sidecar_http

// SKILL-M11-02's test world: a member's agents repo and agent repos as evs serves them, each version signed by the
// device that wrote it at the world's clock, the judgments of a network of the test's own, and a client per device.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One version of a path.
type testAgentsVersion struct {
	version uint64
	pushId  Id
	signer  Id
	time    time.Time
	removed bool
	created bool
	data    []byte
}

// One repo's paths, each path's versions oldest first.
type testAgentsRepo struct {
	world  *testAgentCardsWorld
	repoId Id
	paths  map[string][]*testAgentsVersion
}

// The newest version of a path, nil for none.
func (self *testAgentsRepo) newest(path string) *testAgentsVersion {
	versions := self.paths[path]
	if len(versions) == 0 {
		return nil
	}
	return versions[len(versions)-1]
}

// Appends a version signed by signer: data, or a removal for nil.
func (self *testAgentsRepo) put(signer Id, path string, data []byte) uint64 {
	newest := self.newest(path)
	version := uint64(1)
	if newest != nil {
		version = newest.version + 1
	}
	self.paths[path] = append(self.paths[path], &testAgentsVersion{
		version: version, pushId: NewId(), signer: signer, time: self.world.clock.Now(), removed: data == nil,
		created: newest == nil || newest.removed, data: bytes.Clone(data),
	})
	return version
}

// The repo as one device reaches it: what it writes is signed by that device.
type testAgentsRepoAs struct {
	repo   *testAgentsRepo
	signer Id
}

func (self *testAgentsRepoAs) History(ctx context.Context, args *EvsReadArgs) (*EvsHistory, error) {
	self.repo.world.stateLock.Lock()
	defer self.repo.world.stateLock.Unlock()
	versions := self.repo.paths[args.Path]
	if len(versions) == 0 {
		return nil, ErrEvsPathAbsent
	}
	history := &EvsHistory{Path: args.Path, HeadVersion: versions[len(versions)-1].version, Whole: true}
	for i := len(versions) - 1; 0 <= i; i -= 1 {
		version := versions[i]
		history.Versions = append(history.Versions, &EvsHistoryVersion{
			Version: version.version, PushId: version.pushId, SignerSidecarId: version.signer, Time: version.time,
			Removed: version.removed, Created: version.created,
		})
		if args.NewestLife && version.created {
			break
		}
	}
	return history, nil
}

func (self *testAgentsRepoAs) ReadHead(ctx context.Context, args *EvsReadArgs, out io.Writer) (*EvsFileInfo, error) {
	version := func() *testAgentsVersion {
		self.repo.world.stateLock.Lock()
		defer self.repo.world.stateLock.Unlock()
		for _, version := range self.repo.paths[args.Path] {
			if (args.Version == 0 && version == self.repo.newest(args.Path)) || version.version == args.Version {
				return version
			}
		}
		return nil
	}()
	if version == nil || version.removed {
		return nil, ErrEvsPathAbsent
	}
	if _, err := out.Write(version.data); err != nil {
		return nil, err
	}
	return &EvsFileInfo{Path: args.Path, Version: version.version, SignerSidecarId: version.signer, Time: version.time,
		Size: uint64(len(version.data)), Provenance: &EvsPushProvenance{State: EvsProvenanceUnattributed}}, nil
}

func (self *testAgentsRepoAs) WritePaths(ctx context.Context, args *EvsWritePathsArgs) (*EvsWritePathsResult, error) {
	if hook := self.repo.world.takeBeforeWrite(); hook != nil {
		hook()
	}
	self.repo.world.stateLock.Lock()
	defer self.repo.world.stateLock.Unlock()
	if self.repo.world.writeRefused[self.signer] {
		return nil, ErrEvsWriteInvalid
	}
	result := &EvsWritePathsResult{}
	for _, write := range args.Writes {
		newest := self.repo.newest(write.Path)
		standing := uint64(0)
		if newest != nil && !newest.removed {
			standing = newest.version
		}
		if write.IfVersion != nil && *write.IfVersion != standing {
			return nil, newEvsPlannedConflict([]string{write.Path}, nil)
		}
	}
	for _, write := range args.Writes {
		var data []byte
		if !write.Remove {
			data = make([]byte, write.Content.Size())
			if _, err := write.Content.ReadAt(data, 0); err != nil && err != io.EOF {
				return nil, err
			}
		}
		result.PathVersions = append(result.PathVersions, self.repo.put(self.signer, write.Path, data))
	}
	self.repo.world.writeCount += 1
	return result, nil
}

func (self *testAgentsRepoAs) List(ctx context.Context, args *EvsReadArgs) (*EvsListing, error) {
	self.repo.world.stateLock.Lock()
	defer self.repo.world.stateLock.Unlock()
	listing := &EvsListing{Path: args.Path}
	prefix := args.Path + "/"
	for path := range self.repo.paths {
		name, found := strings.CutPrefix(path, prefix)
		if !found || strings.Contains(name, "/") || self.repo.newest(path).removed {
			continue
		}
		listing.Entries = append(listing.Entries, &EvsListEntry{Name: []byte(name), Kind: protocol.EvsEntryKind_EVS_ENTRY_FILE})
	}
	if len(listing.Entries) == 0 {
		return nil, ErrEvsPathAbsent
	}
	slices.SortFunc(listing.Entries, func(a *EvsListEntry, b *EvsListEntry) int { return bytes.Compare(a.Name, b.Name) })
	return listing, nil
}

// The world's clock, which moves only when the test sets it.
type testAgentCardsClock struct {
	stateLock sync.Mutex
	now       time.Time
}

func (self *testAgentCardsClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *testAgentCardsClock) Set(at time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = at
}

func (self *testAgentCardsClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

func (self *testAgentCardsClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

// The judgments of the world's network.
type testAgentsAuthority struct {
	world *testAgentCardsWorld
}

func (self *testAgentsAuthority) MemberOf(sidecarId Id) (Id, bool) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	memberId, found := self.world.members[sidecarId]
	return memberId, found
}

func (self *testAgentsAuthority) UntaggedConsented(sidecarId Id, memberId Id) bool {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	return self.world.consented[sidecarId] && self.world.members[sidecarId] == memberId
}

func (self *testAgentsAuthority) AgentsRepo(memberId Id) (Id, bool) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	repoId, found := self.world.agentsRepos[memberId]
	return repoId, found
}

func (self *testAgentsAuthority) MemberAgentRepo(memberId Id, repoId Id) bool {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	owner, found := self.world.agentRepos[repoId]
	return found && owner == memberId
}

func (self *testAgentsAuthority) MemberAgentRepoLabeled(memberId Id, repoId Id, labelMac []byte) bool {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	owner, found := self.world.agentRepos[repoId]
	return found && owner == memberId && len(labelMac) == AgentRepoLabelMacByteCount && bytes.Equal(self.world.agentRepoLabels[repoId], labelMac)
}

func (self *testAgentsAuthority) AgentReposOn() bool {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	return self.world.featureOn
}

// A member's devices, a tagged sidecar it sponsors, another member's device, and the repos they reach.
type testAgentCardsWorld struct {
	t        *testing.T
	ctx      context.Context
	clock    *testAgentCardsClock
	settings *SkillSettings

	member      Id
	laptop      Id
	phone       Id
	cloud       Id
	otherMember Id
	otherDevice Id

	stateLock   sync.Mutex
	featureOn   bool
	members     map[Id]Id
	consented   map[Id]bool
	agentsRepos map[Id]Id
	agentRepos  map[Id]Id
	repos       map[Id]*testAgentsRepo
	created     []protocol.RepoKind
	// each agent repo's keyed label as its RepoCreate filed it, and the network's K_label, nil where none derives
	agentRepoLabels map[Id][]byte
	labelKey        *AgentRepoLabelKey
	writeRefused    map[Id]bool
	writeCount      int
	beforeWrite     func()
	// each device's agent ids by label, as its keychain keeps them
	agentIds map[Id]map[string]Id
	revoked  map[Id]bool
	alarms   []*RecordAlarm
}

func newTestAgentCardsWorld(t *testing.T) *testAgentCardsWorld {
	world := &testAgentCardsWorld{
		t:            t,
		ctx:          context.Background(),
		clock:        &testAgentCardsClock{now: time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)},
		settings:     DefaultSkillSettings(),
		member:       testConfigId("agents member"),
		laptop:       testConfigId("agents laptop"),
		phone:        testConfigId("agents phone"),
		cloud:        testConfigId("agents cloud agent"),
		otherMember:  testConfigId("agents other member"),
		otherDevice:  testConfigId("agents other device"),
		featureOn:    true,
		agentsRepos:  map[Id]Id{},
		agentRepos:   map[Id]Id{},
		repos:        map[Id]*testAgentsRepo{},
		writeRefused: map[Id]bool{},
		agentIds:     map[Id]map[string]Id{},
		revoked:      map[Id]bool{},
	}
	world.members = map[Id]Id{world.laptop: world.member, world.phone: world.member, world.cloud: world.member, world.otherDevice: world.otherMember}
	world.consented = map[Id]bool{world.laptop: true, world.phone: true, world.otherDevice: true}
	world.agentRepoLabels = map[Id][]byte{}
	labelKey, err := newAgentRepoLabelKey(testConfigId("agents network"), bytes.Repeat([]byte{0x5a}, agentRepoLabelKeyByteCount))
	if err != nil {
		t.Fatal(err)
	}
	world.labelKey = labelKey
	return world
}

// The hook the next write runs first, cleared as it is taken.
func (self *testAgentCardsWorld) takeBeforeWrite() func() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	hook := self.beforeWrite
	self.beforeWrite = nil
	return hook
}

// A repo the world holds, made where none is.
func (self *testAgentCardsWorld) repo(repoId Id) *testAgentsRepo {
	repo := self.repos[repoId]
	if repo == nil {
		repo = &testAgentsRepo{world: self, repoId: repoId, paths: map[string][]*testAgentsVersion{}}
		self.repos[repoId] = repo
	}
	return repo
}

// The member's agents repo, nil before one stands.
func (self *testAgentCardsWorld) agentsRepo() *testAgentsRepo {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	repoId, found := self.agentsRepos[self.member]
	if !found {
		return nil
	}
	return self.repo(repoId)
}

// A client acting as sidecarId.
func (self *testAgentCardsWorld) client(sidecarId Id) *AgentsClient {
	self.t.Helper()
	client, err := NewAgentsClient(&AgentsClientArgs{
		Self:      func() (Id, error) { return sidecarId, nil },
		Authority: func() (AgentsAuthority, error) { return &testAgentsAuthority{world: self}, nil },
		Repo: func(repoId Id) AgentsRepoAccess {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return &testAgentsRepoAs{repo: self.repo(repoId), signer: sidecarId}
		},
		CreateRepo: func(ctx context.Context, args *EvsCreateRepoArgs) (Id, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if !aclRepoLabelMacFits(args.Kind, args.LabelMac) {
				return Id{}, fmt.Errorf("%w: a label of %d bytes on a %s repo", errInvalidSettings, len(args.LabelMac), args.Kind)
			}
			repoId := NewId()
			memberId := self.members[sidecarId]
			self.created = append(self.created, args.Kind)
			switch args.Kind {
			case protocol.RepoKind_REPO_KIND_AGENTS:
				if _, found := self.agentsRepos[memberId]; !found {
					self.agentsRepos[memberId] = repoId
				}
			case protocol.RepoKind_REPO_KIND_AGENT:
				self.agentRepos[repoId] = memberId
				self.agentRepoLabels[repoId] = bytes.Clone(args.LabelMac)
			}
			self.repo(repoId)
			return repoId, nil
		},
		LabelKey: func(ctx context.Context) (*AgentRepoLabelKey, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.labelKey == nil {
				return nil, ErrAgentRepoLabelKey
			}
			return self.labelKey, nil
		},
		AgentId: func(label string) (Id, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			labels := self.agentIds[sidecarId]
			if labels == nil {
				labels = map[string]Id{}
				self.agentIds[sidecarId] = labels
			}
			if agentId, found := labels[label]; found && !self.revoked[agentId] {
				return agentId, nil
			}
			agentId := NewId()
			labels[label] = agentId
			return agentId, nil
		},
		AgentRevoked: func(agentId Id) (bool, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.revoked[agentId], nil
		},
		HostName: func(sidecarId Id) string { return "host of " + sidecarId.String()[:8] },
		FeatureCheck: func() error {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if !self.featureOn {
				return &AuthFeatureRequiredError{Feature: AuthFeatureAgentRepos, AdminMemberIds: []Id{self.member}, Err: ErrAuthFeatureOff}
			}
			return nil
		},
		Alarm: func(alarm *RecordAlarm) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.alarms = append(self.alarms, alarm)
		},
		Clock:    self.clock,
		Settings: self.settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return client
}

// Writes a card at name in the member's agents repo as signer, past every rule, as a sidecar of the member that rewrites
// another's path does.
func (self *testAgentCardsWorld) forge(signer Id, card *AgentCard) {
	self.t.Helper()
	data, err := EncodeAgentCard(card, self.settings)
	if err != nil {
		self.t.Fatal(err)
	}
	repo := self.agentsRepo()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	repo.put(signer, AgentCardPath(card.Name), data)
}

// The alarms raised so far.
func (self *testAgentCardsWorld) alarmCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.alarms)
}
