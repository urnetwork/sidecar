// The world ACL-M2-16's schedules and privacy test run on (§22.5's §8 row, FS-14's and FS-19's acl cases, FS-62's gate
// case, §22.7's policy canaries): §22.7's admission world, AdmissionNet, with ACL's own compile as its tier's
// AclCompile, so every base compiles the network's real policy, the implicit document when it has none (D-ACL-20),
// every full reader compiles it again to check the base, and every gate takes the rows. What this file adds to
// AdmissionNet:
//
//	SaveAclPolicy     §8.8's Saving on the writer's device: PlanAclSave over its config head and the state at the
//	                  tip, then the head saved with its base, as ur acl push does once a person confirms the preview
//	ReaderStates      every reader standing at the tip, the reference first, so a decision is asked of each and must
//	                  come out alike (EveryAcl)
//	ForkedReader      a full reader or a gate restored at the newest base, which a schedule then serves an entry
//	                  api never sequenced, as a server forking its readers serves one of them (FS-14)
//	ForkedFollower    a device follower, TEAM-M2-10's ConfigClient, reading a server's view of its own: api's
//	                  entries through the tip, then once Fork serves one, an entry api never sequenced; the auth
//	                  source a device's HeadCheck compares, so a schedule connects two such views (FS-14), and
//	                  Follower, one reading api's own, for the honest twin
//	AclConfigRowView  a reader's state with the config repo's AclRepo row that every option of question
//	                  team-m2-15-config-repo-acl-row gives it: no compile writes that row yet, so the config's read,
//	                  its key holders and its head signers are judged on this view until the question is answered,
//	                  and the rows themselves refuse every config scope, the closed direction
//
// Nothing here sleeps or reads a clock of its own: the admission world's FakeClock is the only time. Nothing creates,
// derives or unwraps a key but the fixed test keys the admission world derives from labels.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// ACL's compile (ACL-M2-04's CompileAcl over the head and the log's rows, as acl_compile.go registers it), as
// AdmissionTier.AclCompile takes it.
func AclAdmissionCompile(head *sidecar.ConfigHead, rows *sidecar.ConfigCompileRows) (*protocol.AclRows, error) {
	input, err := sidecar.NewAclCompileInput(head, rows)
	if err != nil {
		return nil, err
	}
	return sidecar.CompileAcl(input)
}

// §8.8's Saving on the writer's device: plans source over the writer's config head and the reference's state at the
// tip, which the writer's follower stands at, then saves the planned head with its base. resolver nil resolves the
// document's selectors from the head's own rows alone. Fails the row on a document the writer may not save or a test
// that fails. The plan, and the base's pin.
func (self *AdmissionNet) SaveAclPolicy(source []byte, resolver sidecar.AclSaveResolver) (*sidecar.AclSavePlan, *bridge.AuthPin) {
	self.t.Helper()
	var plan *sidecar.AclSavePlan
	pin := self.SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		planned, err := sidecar.PlanAclSave(self.ctx, &sidecar.AclSaveInput{
			Policy:   source,
			Head:     head,
			State:    self.State(),
			Resolver: resolver,
			Now:      self.clock.Now(),
		})
		if err != nil {
			return nil, err
		}
		if err := planned.Tests.Err(); err != nil {
			return nil, err
		}
		plan = planned
		return planned.Head, nil
	})
	return plan, pin
}

// What a save resolves a document's user: selectors by, as the writer's invite records and GET /network/members do
// (plan-ACL-selector-resolution): each email's member. No network or client resolves.
type AclSaveMembers map[string]sidecar.Id

func (self AclSaveMembers) ResolveMember(ctx context.Context, email string) (sidecar.Id, bool, error) {
	memberId, found := self[email]
	return memberId, found, nil
}

func (self AclSaveMembers) ResolveNetwork(ctx context.Context, text string) (sidecar.Id, bool, error) {
	return sidecar.Id{}, false, nil
}

func (self AclSaveMembers) ResolveClient(ctx context.Context, clientId sidecar.Id) (sidecar.Id, bool, error) {
	return sidecar.Id{}, false, nil
}

var _ sidecar.AclSaveResolver = AclSaveMembers(nil)

// The atom id a saved head's tags table holds for a tag, its name without "tag:", false for none.
func AclTagAtom(plan *sidecar.AclSavePlan, name string) (sidecar.Id, bool) {
	return aclTableAtom(plan, sidecar.ConfigHeadTagsPath, name)
}

// The atom id a saved head's groups table holds for a group, its name without "group:", false for none.
func AclGroupAtom(plan *sidecar.AclSavePlan, name string) (sidecar.Id, bool) {
	return aclTableAtom(plan, sidecar.ConfigHeadGroupsPath, name)
}

func aclTableAtom(plan *sidecar.AclSavePlan, path string, name string) (sidecar.Id, bool) {
	if plan == nil || plan.Head == nil {
		return sidecar.Id{}, false
	}
	table := &protocol.ConfigAtomTable{}
	if err := proto.Unmarshal(plan.Head.File(path), table); err != nil {
		return sidecar.Id{}, false
	}
	for _, atom := range table.GetAtoms() {
		if atom.GetName() == name {
			atomId, err := sidecar.IdFromBytes(atom.GetAtomId())
			return atomId, err == nil
		}
	}
	return sidecar.Id{}, false
}

// One verifier standing at the tip: its name, and its state.
type AdmissionReaderState struct {
	Name   string
	Config *sidecar.ConfigState
}

// Every verifier the world runs that stands, not forked: the reference first, then each new device and gate by their
// start, and the writer's follower once it stands at the tip.
func (self *AdmissionNet) ReaderStates() []*AdmissionReaderState {
	self.t.Helper()
	states := []*AdmissionReaderState{}
	for _, reader := range self.everyReader() {
		if reader.fork == nil {
			states = append(states, &AdmissionReaderState{Name: reader.name, Config: reader.log.State()})
		}
	}
	if self.follower != nil && self.follower.Fork() == nil {
		if state := self.follower.State(); state != nil && proto.Equal(state.Pin(), self.Tip()) {
			states = append(states, &AdmissionReaderState{Name: "the writer's follower", Config: state})
		}
	}
	return states
}

// Runs check on every reader's state and acl part at the tip, failing the row with the reader's name at the first
// error: what every verifier must answer alike, whichever kind it is.
func (self *AdmissionNet) EveryAcl(check func(state *sidecar.ConfigState, acl *sidecar.AclState) error) {
	self.t.Helper()
	for _, reader := range self.ReaderStates() {
		acl, err := reader.Config.Acl()
		if err != nil {
			self.t.Fatalf("%s's acl state at %d: %v", reader.Name, reader.Config.Pin().GetVersion(), err)
		}
		if err := check(reader.Config, acl); err != nil {
			self.t.Fatalf("%s at %d: %v", reader.Name, reader.Config.Pin().GetVersion(), err)
		}
	}
}

// The entry api served at position n, verbatim; nil for a position the world has not read.
func (self *AdmissionNet) Entry(n uint64) []byte {
	return bytes.Clone(self.entries[n])
}

// A verifier restored at the newest base from the entries at its retention point through the tip, as §7.9's retention
// row starts one that holds nothing else: a full reader, or with rowsOnly a gate. A schedule serves it what api never
// sequenced, so the world does not apply its entries.
func (self *AdmissionNet) ForkedReader(rowsOnly bool) *sidecar.ConfigLog {
	self.t.Helper()
	base := self.State().Base().GetVersion()
	if base == 0 {
		self.t.Fatal("no base to restore a reader at")
	}
	retained := &sidecar.ConfigRetained{SignedGenesis: self.signedGenesis, Rows: map[[sha256.Size]byte][]byte{}}
	point := self.State().RetentionPoint()
	for k := point; k <= self.applied; k += 1 {
		entryBytes, found := self.entries[k]
		if !found {
			self.t.Fatalf("no entry at %d, inside the retention from %d", k, point)
		}
		retained.Entries = append(retained.Entries, entryBytes)
	}
	var log *sidecar.ConfigLog
	var err error
	if rowsOnly {
		log, err = sidecar.RestoreConfigLogRowsOnly(admissionLogSettings(), retained, self.rowsOnlySource(), nil)
	} else {
		log, err = sidecar.RestoreConfigLog(admissionLogSettings(), retained, admissionHeadSource{net: self})
	}
	if err != nil {
		self.t.Fatalf("a reader restored at base %d: %v", base, err)
	}
	if !proto.Equal(log.Pin(), self.Tip()) {
		self.t.Fatalf("a reader restored at base %d stands at %d, the tip %d", base, log.Pin().GetVersion(), self.applied)
	}
	return log
}

// A device follower a server forks (FS-14): a ConfigClient on the world's clock and context reading a view of its
// own, api's entries through the tip n it was made at and, once Fork serves one, an entry at n+1 api never sequenced,
// as a server serving its readers two views serves each its own. It is no reader the world compares; it ends with the
// world.
type AdmissionForkedFollower struct {
	// TEAM-M2-10's device follower: what a device's HeadCheck compares as its auth source.
	Client *sidecar.ConfigClient
	net    *AdmissionNet
	// api's tip when the follower was made, where its view parts from api's, and its pin
	n    uint64
	nPin *bridge.AuthPin

	stateLock sync.Mutex
	// the entry at n+1 and (n+1, A_{n+1}), nil until Fork
	entry []byte
	pin   *bridge.AuthPin
}

// A follower standing at the tip, read from api's entries: what a server shows it until Fork. Fails the row unless
// it reaches the tip.
func (self *AdmissionNet) ForkedFollower() *AdmissionForkedFollower {
	self.t.Helper()
	follower := &AdmissionForkedFollower{net: self, n: self.applied, nPin: proto.CloneOf(self.Tip())}
	follower.Client = self.followerOf(follower)
	return follower
}

// A device follower of api's own projection, an honest server's view, standing at the tip: a ConfigClient on the
// world's clock and context, which a forked follower's twin compares. It is no reader the world compares; it ends
// with the world. Fails the row unless it reaches the tip.
func (self *AdmissionNet) Follower() *sidecar.ConfigClient {
	self.t.Helper()
	return self.followerOf(self.projection())
}

// A ConfigClient on projection, waited for until it stands at the tip.
func (self *AdmissionNet) followerOf(projection sidecar.ConfigProjectionReader) *sidecar.ConfigClient {
	self.t.Helper()
	clientSettings := sidecar.DefaultConfigClientSettings()
	clientSettings.Log = sidecar.NewNoopLogger()
	clientSettings.LogSettings = admissionLogSettings()
	client, err := sidecar.NewConfigClient(self.ctx, &sidecar.ConfigClientArgs{
		NetworkId:    self.networkId,
		GenesisChain: self.genesisChain,
		Projection:   projection,
		Heads:        self.heads,
		Clock:        self.clock,
		Settings:     clientSettings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := client.WaitFor(self.ctx, self.applied); err != nil {
		self.t.Fatalf("a follower at %d: %v", self.applied, err)
	}
	if !proto.Equal(client.Pin(), self.Tip()) {
		self.t.Fatalf("a follower stands at %d, not the tip %d", client.Pin().GetVersion(), self.applied)
	}
	return client
}

// Serves entryBytes at n+1 from now on, the server's view for this follower, and waits for the follower to apply
// it: (n+1, A_{n+1}), where it then stands. Fails the row unless the entry chains onto the tip and the follower takes
// it without a fork.
func (self *AdmissionForkedFollower) Fork(entryBytes []byte) *bridge.AuthPin {
	net := self.net
	net.t.Helper()
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		net.t.Fatal(err)
	}
	if entry.GetN() != self.n+1 || !bytes.Equal(entry.GetPrevChain(), self.nPin.GetChain()) {
		net.t.Fatalf("a fork's entry at %d does not chain onto the tip %d", entry.GetN(), self.n)
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		net.t.Fatal(err)
	}
	pin := &bridge.AuthPin{Version: entry.GetN(), Chain: bytes.Clone(chain[:])}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.entry = bytes.Clone(entryBytes)
		self.pin = proto.CloneOf(pin)
	}()
	if _, err := self.Client.WaitFor(net.ctx, self.n+1); err != nil {
		net.t.Fatalf("a forked follower served its entry at %d: %v", self.n+1, err)
	}
	if !proto.Equal(self.Client.Pin(), pin) || self.Client.Fork() != nil {
		net.t.Fatalf("a forked follower stands at %d, forked %t, not on its entry at %d", self.Client.Pin().GetVersion(),
			self.Client.Fork() != nil, self.n+1)
	}
	return pin
}

// The view's GET /network/config/projection: api's entries after after through n, a page api serves past n cut
// there, then the fork's entry once served, which is the view's tip.
func (self *AdmissionForkedFollower) ReadConfigProjection(ctx context.Context, after uint64) (*sidecar.ConfigProjection, error) {
	entry, pin := func() ([]byte, *bridge.AuthPin) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.entry, self.pin
	}()
	tip := self.nPin
	if entry != nil {
		tip = pin
	}
	if self.n < after {
		return &sidecar.ConfigProjection{Tip: proto.CloneOf(tip)}, nil
	}
	projection, err := self.net.api.ReadConfigProjection(ctx, self.net.networkId, after)
	if err != nil {
		return nil, err
	}
	for i, entryBytes := range projection.Entries {
		served := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, served); err != nil {
			return nil, err
		}
		if self.n < served.GetN() {
			projection.Entries = projection.Entries[:i]
			projection.More = false
			break
		}
	}
	if projection.More {
		return projection, nil
	}
	if entry != nil {
		projection.Entries = append(projection.Entries, bytes.Clone(entry))
	}
	projection.Tip = proto.CloneOf(tip)
	return projection, nil
}

var _ sidecar.ConfigProjectionReader = (*AdmissionForkedFollower)(nil)

// The AuthEntry a server would sequence at the tip's next position for a statement, chained onto the tip, at the
// clock's time: an entry api may never have appended.
func (self *AdmissionNet) NextEntry(signedBytes []byte) []byte {
	self.t.Helper()
	return self.marshal(&bridge.AuthEntry{
		NetworkId: self.networkId.Bytes(),
		N:         self.applied + 1,
		PrevChain: bytes.Clone(self.Tip().GetChain()),
		Kind:      bridge.AuthEntryKindStatement,
		TimeMs:    self.clock.Now().UnixMilli(),
		Body:      signedBytes,
	})
}

// The AuthEntry a server would sequence at position n for a statement, chained onto A_{n-1} as the reference holds it,
// at the clock's time: a second entry at a position api may have filled, for a view the server forks there.
func (self *AdmissionNet) ForkEntryAt(n uint64, signedBytes []byte) []byte {
	self.t.Helper()
	if n == 0 || self.applied+1 < n {
		self.t.Fatalf("no position %d to fork at, the tip %d", n, self.applied)
	}
	return self.marshal(&bridge.AuthEntry{
		NetworkId: self.networkId.Bytes(),
		N:         n,
		PrevChain: bytes.Clone(self.VerdictAt(n - 1).Pin.GetChain()),
		Kind:      bridge.AuthEntryKindStatement,
		TimeMs:    self.clock.Now().UnixMilli(),
		Body:      signedBytes,
	})
}

// Serves one entry to a verifier ForkedReader restored: its verdict, or the fork it refuses the entry as.
func (self *AdmissionNet) ServeEntry(log *sidecar.ConfigLog, entryBytes []byte) (sidecar.ConfigVerdict, error) {
	if log.RowsOnly() {
		verdicts, err := log.ApplyRun([][]byte{entryBytes}, self.rowsOnlySource())
		if err != nil {
			return sidecar.ConfigVerdict{}, err
		}
		if len(verdicts) != 1 {
			return sidecar.ConfigVerdict{}, fmt.Errorf("a run of one entry gave %d verdicts", len(verdicts))
		}
		return verdicts[0], nil
	}
	return log.Apply(entryBytes, admissionHeadSource{net: self})
}

// A KeyRegister of key as a presence key of device's member, signed by device's identity key, as its Signed's bytes and
// not posted: what RegisterPresenceKey posts for a device that holds no live key yet, for a schedule that serves it to a
// reader api never sequenced it for.
func (self *AdmissionNet) PresenceKeyRegister(device *AdmissionDevice, key *FixturePresenceKey) []byte {
	self.t.Helper()
	body, err := key.RegisterBody(&protocol.KeyRegister{
		Header:   self.Header(),
		MemberId: device.MemberId.Bytes(),
		NotAfter: self.clock.Now().Add(30 * 24 * time.Hour).UnixMilli(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	purpose, _ := sidecar.ConfigStatementPurpose(bridge.SignedType_SIGNED_KEY_REGISTER)
	return self.marshal(&bridge.Signed{
		Body:      body,
		SignerId:  device.SidecarId.Bytes(),
		Signature: ed25519.Sign(device.Key, bridge.SignedBytes(purpose, bridge.SignedType_SIGNED_KEY_REGISTER, body)),
		Type:      uint32(bridge.SignedType_SIGNED_KEY_REGISTER),
	})
}

// The config repo's id, the Genesis's.
func (self *AdmissionNet) ConfigRepoId() sidecar.Id {
	return self.configRepoId
}

// A reader's state with the config repo's AclRepo row added where its rows hold none: kind config, no owner, no
// admins and no access log, the row every option of question team-m2-15-config-repo-acl-row gives (an AclState that
// synthesizes it, a compile that writes it, or gates that special-case the Genesis's id), so §8.5's config kind
// default answers through it. Every other question goes to the state. Built once; immutable.
type AclConfigRowView struct {
	*sidecar.ConfigState
	configRepoId sidecar.Id
	acl          *sidecar.AclState
}

// The view over state. An error when the state's rows do not build.
func NewAclConfigRowView(state *sidecar.ConfigState) (*AclConfigRowView, error) {
	acl, err := state.Acl()
	if err != nil {
		return nil, err
	}
	configRepoId, err := sidecar.IdFromBytes(state.Genesis().GetConfigRepoId())
	if err != nil {
		return nil, fmt.Errorf("the genesis names no config repo: %w", err)
	}
	rows := proto.Clone(acl.Rows()).(*protocol.AclRows)
	if acl.Repo(configRepoId) == nil {
		rows.Repos = append(rows.Repos, &protocol.AclRepo{RepoId: configRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_CONFIG})
		slices.SortFunc(rows.Repos, func(a *protocol.AclRepo, b *protocol.AclRepo) int {
			return bytes.Compare(a.GetRepoId(), b.GetRepoId())
		})
	}
	withRow, err := sidecar.NewAclState(rows, state)
	if err != nil {
		return nil, err
	}
	return &AclConfigRowView{ConfigState: state, configRepoId: configRepoId, acl: withRow}, nil
}

// The acl part with the config's row.
func (self *AclConfigRowView) Acl() *sidecar.AclState {
	return self.acl
}

// GkmAuthView's, from the acl part with the config's row.
func (self *AclConfigRowView) Repo(repoId sidecar.Id) *protocol.AclRepo {
	return self.acl.Repo(repoId)
}

func (self *AclConfigRowView) RepoReaders(repoId sidecar.Id) []sidecar.Id {
	return self.acl.RepoReaders(repoId, time.UnixMilli(self.TimeMs()))
}

func (self *AclConfigRowView) RepoWriters(repoId sidecar.Id) []sidecar.Id {
	return self.acl.RepoWriters(repoId, time.UnixMilli(self.TimeMs()))
}

func (self *AclConfigRowView) RepoReadersAt(repoId sidecar.Id, at time.Time) []sidecar.Id {
	return self.acl.RepoReaders(repoId, at)
}

var _ sidecar.GkmAuthView = (*AclConfigRowView)(nil)

// Whether holders hold a sidecar under one of kinds.
func AclHolds(holders sidecar.GkmHolders, sidecarId sidecar.Id, kinds ...sidecar.GkmHolderKind) bool {
	return slices.ContainsFunc(kinds, func(kind sidecar.GkmHolderKind) bool {
		return holders.Contains(kind, sidecarId.Bytes())
	})
}

// A document whose every name is a canary (§22.7's policy canaries; §8.7, owner decision 72), saved on a network's
// writer: what no store may hold in any form, and the saved plan, whose head does hold them.
type AclCanaryPolicy struct {
	// a tag and a group hold 50 bytes at most, so each is a canary's first 40 characters behind a letter, forbidden
	// in every form; a repo label, a socket segment, a note and a comment hold a whole canary text
	Tag, Group, Label, Socket, Note, Comment string
	// K_sock, which the head carries beside the policy (§8.8's Placement) and the capture looks for as a secret
	SocketKey []byte
	// the member the document's group names, its consented device, and the repo the label names
	MemberDevice *AdmissionDevice
	RepoId       sidecar.Id
	Plan         *sidecar.AclSavePlan
}

// Saves on the network's writer a document whose policy text, tags, groups, repo labels and socket names are canaries
// of capture, with the head's labels file and K_sock, then admits one more member and folds, so the log holds
// statements and bases after it. Fails the row unless the document compiles to what it says.
func (self *AdmissionNet) SaveAclCanaryPolicy(capture *PrivacyCapture) *AclCanaryPolicy {
	self.t.Helper()
	policy := &AclCanaryPolicy{
		Tag:       "t" + capture.CanaryText("acl tag")[:40],
		Group:     "g" + capture.CanaryText("acl group")[:40],
		Label:     capture.CanaryText("acl repo label"),
		Socket:    capture.CanaryText("acl socket name"),
		Note:      capture.CanaryText("acl policy note"),
		Comment:   capture.CanaryText("acl policy comment"),
		SocketKey: bytes.Repeat([]byte{0x6b}, 32),
	}
	capture.Forbid("acl tag", []byte(policy.Tag))
	capture.Forbid("acl group", []byte(policy.Group))
	capture.AddSecret("acl K_sock", policy.SocketKey)

	memberId, first := self.ConsentedMember("m")
	policy.MemberDevice = first
	policy.RepoId = self.Id("labelled repo")
	self.MustLand(self.Sign(first, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: self.Header(), RepoId: policy.RepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
	}))
	labels := self.marshal(&protocol.ConfigLabelTable{Labels: []*protocol.ConfigRepoLabel{{Label: policy.Label, RepoId: policy.RepoId.Bytes()}}})
	socketKeyFile := self.marshal(&protocol.SocketKeyFile{CurrentKey: policy.SocketKey})
	self.SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		head, err := head.WithFile(sidecar.ConfigHeadLabelsPath, labels)
		if err != nil {
			return nil, err
		}
		return head.WithFile(sidecar.ConfigHeadSocketKeyPath, socketKeyFile)
	})
	source := fmt.Sprintf(`{
		// %s
		"groups": { "group:%s": ["m@acme.example"] },
		"tagOwners": { "tag:%s": ["group:%s"] },
		"grants": [
			{ "src": ["group:%s"], "dst": ["evs:%s"], "allow": ["write"], "note": "%s" },
			{ "src": ["group:%s"], "dst": ["sock:%s"], "allow": ["dial"] },
			{ "src": ["tag:%s"], "dst": ["sock:%s"], "allow": ["listen"] },
			{ "src": ["autogroup:member"], "dst": ["autogroup:self"], "allow": ["dial", "route"] },
		],
	}`, policy.Comment, policy.Group, policy.Tag, policy.Group, policy.Group, policy.Label, policy.Note, policy.Group,
		policy.Socket, policy.Tag, policy.Socket)
	policy.Plan, _ = self.SaveAclPolicy([]byte(source), AclSaveMembers{"m@acme.example": memberId})
	if len(policy.Plan.Rows.GetRules()) < 4 {
		self.t.Fatalf("the canary document compiled to %d rules", len(policy.Plan.Rows.GetRules()))
	}
	acl, err := self.State().Acl()
	if err != nil {
		self.t.Fatal(err)
	}
	if rights := acl.EvsAccess(sidecar.AclSidecarSubject(first.SidecarId), policy.RepoId, sidecar.AclTokenAudienceEvs, self.clock.Now()).Rights; !rights.Has(sidecar.AclEvsWrite) {
		self.t.Fatalf("the group's write on the labelled repo: %04b", rights)
	}
	saved := policy.Source()
	for _, name := range []string{policy.Tag, policy.Group, policy.Label, policy.Socket, policy.Note, policy.Comment} {
		if !bytes.Contains(saved, []byte(name)) {
			self.t.Fatalf("the saved policy does not name %q", name)
		}
	}
	self.AdmitMember(self.Owner(), "after the canary policy", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	self.Fold(true)
	return policy
}

// The saved head's policy file, where the canaries stand.
func (self *AclCanaryPolicy) Source() []byte {
	return self.Plan.Head.File(sidecar.ConfigHeadPolicyPath)
}
