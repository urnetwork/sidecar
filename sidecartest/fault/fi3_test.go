package fault

// FI-3's oracle (fi3.go) on T2, in fi1_test.go's hand world: pushes built with the format's own builders under the
// pins a test chooses, committed through evsservice.HeadStore past 5d, or written over it where the head store itself
// refuses (a fallen pin), and the authorization states named as a projection would deliver them. Each mutant is
// caught at its commit beside the twin the gate's window or a covering generation lets through. fi3_world_test.go
// reads FS-3's twins clean on the evs world.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

type fi3World struct {
	*fiHandWorld
	main sidecar.Id
	// each generation's key, from gen/1, which the hand world wrote
	keys map[uint64]*sidecar.EvsRepoKey
}

func newFi3World(t *testing.T) *fi3World {
	hand := newFiHandWorld(t)
	return &fi3World{fiHandWorld: hand, main: sidecar.NewId(), keys: map[uint64]*sidecar.EvsRepoKey{1: hand.repoKey}}
}

// A step's action appending the next authorization state, which shrinks the repo's holders there when shrink, and
// naming it as current, as a projection's delivery does.
func (self *fi3World) advance(shrink bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		rows := proto.Clone(self.fixture.Rows).(*bridge.ProjectionRows)
		acl := &protocol.AclRows{}
		if err := proto.Unmarshal(rows.GetAcl(), acl); err != nil {
			return err
		}
		position := self.view.Pin().GetVersion() + 1
		for _, repo := range acl.GetRepos() {
			if shrink && bytes.Equal(repo.GetRepoId(), self.repoId.Bytes()) {
				repo.HoldersShrunkAt = position
			}
		}
		aclBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(acl)
		if err != nil {
			return err
		}
		rows.Acl = aclBytes
		fixture := *self.fixture
		fixture.Rows = rows
		self.fixture = &fixture
		self.view = self.log.Append(self.fixture)
		SetAuthorizationView(net, self.networkId, self.view)
		return nil
	}
}

// A step's action writing gen/<g> for the next generation under the current state, the key kept for pushes under it.
func (self *fi3World) rotate(ctx context.Context, net *Net) error {
	newest := uint64(len(self.keys))
	holders := sha256.Sum256([]byte(fmt.Sprintf("fi3 holders %d", newest+1)))
	key, rotate, err := self.keys[newest].NextGeneration(&sidecar.GkmGenerationArgs{
		Cause: sidecar.GkmCauseRemove, Auth: self.view.Pin(), Time: net.Clock().Now(), HoldersSha256: holders[:],
	})
	if err != nil {
		return err
	}
	generationBytes, err := StoreViewFixtureGeneration(rotate)
	if err != nil {
		return err
	}
	if _, err := self.cluster.PutIfNoneMatch(ctx, sidecar.GkmGenerationPath(self.groupId, newest+1), generationBytes, nil); err != nil {
		return err
	}
	self.keys[newest+1] = key
	return nil
}

// What a hand push pins, beyond what the head holds.
type fi3Pins struct {
	// the auth pin, nil the current state's
	auth *bridge.AuthPin
	// the generation, 0 the newest
	generation uint64
	// the path epoch, 0 the first
	epoch uint64
	// write the head past HeadStore's own rules, as a store that took any write would
	raw bool
}

// A step's action committing a push on main creating a fresh file under pins, past every check evs would run.
func (self *fi3World) push(pins fi3Pins) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		chains := self.chains[self.main]
		if chains == nil {
			chains = [][32]byte{sidecar.EvsChainStart(self.repoId, self.main)}
			self.chains[self.main] = chains
		}
		base := uint64(len(chains) - 1)
		auth := pins.auth
		if auth == nil {
			auth = self.view.Pin()
		}
		generation := pins.generation
		if generation == 0 {
			generation = uint64(len(self.keys))
		}
		epoch := max(1, pins.epoch)
		pushId := sidecar.NewId()
		entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsEntryVersion{
			Version: base + 1, PushId: pushId.Bytes(), BaseVersion: base, TimeMs: net.Clock().Now().UnixMilli(),
			Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096, SealedFields: []byte("sealed fields"),
			Chain: []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline record")}},
		})
		if err != nil {
			return err
		}
		built, err := sidecar.NewEvsStatementBuilder(self.admin.Sign).Build(&sidecar.EvsPushPlan{
			RepoId: self.repoId, RefId: self.main, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
			PushId: pushId, BaseVersion: base, BaseChain: chains[base],
			Generation: generation, GroupId: self.groupId, GenerationCommitment: self.keys[generation].Commitment(), PathEpoch: epoch,
			Auth: auth, SignerSidecarId: self.admin.SidecarId, ClientId: sidecar.NewId(),
			TimeMs: net.Clock().Now().UnixMilli(), SealedMetadata: []byte("sealed metadata"),
			Changes: []*sidecar.EvsPlannedChange{{TokenPath: sidecar.EvsTokenPath{sidecar.NewEvsRandomToken()}, EntryVersion: entryBytes}},
		})
		if err != nil {
			return err
		}
		push := &fiHandPush{refId: self.main, statement: built.Statement, payload: built.Payload, signerId: self.admin.SidecarId}
		if err := self.writeRecord(ctx, push); err != nil {
			return err
		}
		if !pins.raw {
			return self.commit(ctx, push)
		}
		return self.commitRaw(ctx, push)
	}
}

// Step 7 written straight to the store, as commit builds it, past HeadStore's refusal of a falling pin.
func (self *fi3World) commitRaw(ctx context.Context, push *fiHandPush) error {
	prior, err := self.heads.ReadCluster(ctx, self.cluster, self.repoId, push.refId)
	if err != nil {
		return err
	}
	chains := self.chains[push.refId]
	version := uint64(len(chains))
	chain := sidecar.EvsChainNext(chains[version-1], sidecar.Id(push.statement.Push.GetPushId()), push.statement.Sha256)
	statementPush := push.statement.Push
	next := evsservice.CloneEvsHead(prior.Head)
	next.Version, next.Chain, next.PushId = version, chain[:], statementPush.GetPushId()
	next.Generation, next.GenerationCommitment, next.Auth = statementPush.GetGeneration(), statementPush.GetGenerationCommitment(), statementPush.GetAuth()
	entry := sidecar.NewEvsWindowEntry(push.statement.Sha256, statementPush, []sidecar.EvsTokenPath{push.statement.Changes[0].TokenPath}, nil, true, push.place)
	next.Window = append(bytes.Clone(next.GetWindow()), entry.Encode()...)
	headBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(next)
	if err != nil {
		return err
	}
	if _, err := self.cluster.PutIfMatch(ctx, evsservice.HeadKey(self.repoId, push.refId), prior.Etag, headBytes, nil); err != nil {
		return err
	}
	self.chains[push.refId] = append(chains, chain)
	return nil
}

func fi3Checks() []Invariant {
	return []Invariant{FI(3)}
}

// Commits under the state current at each CAS, a rotation after a shrink, and a commit under the new generation past
// the window: clean at every step.
func TestFi3ReadsCommitsUnderTheCurrentStateClean(t *testing.T) {
	world := newFi3World(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.push(fi3Pins{})},
		{Actor: "api", Action: world.advance(false)},
		{Actor: "writerA", Action: world.push(fi3Pins{})},
		{Actor: "api", Action: world.advance(true)},
		{Actor: "writerA", Action: world.rotate},
		{Actor: "clock", Advance: 10 * time.Minute},
		{Actor: "writerA", Action: world.push(fi3Pins{})},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi3-current", Steps: steps, Check: fi3Checks()}, world.net))
}

// A push committing under generation 1 more than §10.6's window after a shrink that excludes it: caught at its CAS.
func TestFi3CatchesACommitPastTheGateWindowOnAnExcludedGeneration(t *testing.T) {
	result := fi3ShrinkRun(t, 6*time.Minute)
	fiRequireViolation(t, result, 4, "FI-3", "generation 1, which the state named at", "excludes, past §10.6's window", "does not cover holders_shrunk_at 3")
}

// Its twin: the same commit inside the window, a push validated before the shrink landing within §11.8's bound.
func TestFi3TakesACommitInsideTheGateWindow(t *testing.T) {
	fiRequirePass(t, fi3ShrinkRun(t, time.Minute))
}

// Two states, a shrink at the third, the clock moved by after, and a push under generation 1, which the shrink
// excludes, at the head's pin.
func fi3ShrinkRun(t *testing.T, after time.Duration) *Result {
	world := newFi3World(t)
	var validated *bridge.AuthPin
	steps := []*Step{
		{Actor: "writerA", Action: world.push(fi3Pins{})},
		{Actor: "api", Action: world.advance(false)},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			// the pin a push validated before the shrink carries
			validated = world.view.Pin()
			return world.advance(true)(ctx, net)
		}},
		{Actor: "clock", Advance: after},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			return world.push(fi3Pins{auth: validated, generation: 1})(ctx, net)
		}},
	}
	return Run(t.Context(), &Schedule{Id: "fi3-gate", Steps: steps, Check: fi3Checks()}, world.net)
}

// A push naming path epoch 2 on a ref at epoch 1, with no PATH_EPOCH: caught.
func TestFi3CatchesAStalePathEpochAtTheCas(t *testing.T) {
	world := newFi3World(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.push(fi3Pins{})},
		{Actor: "writerA", Action: world.push(fi3Pins{epoch: 2})},
	}
	result := Run(t.Context(), &Schedule{Id: "fi3-epoch", Steps: steps, Check: fi3Checks()}, world.net)
	fiRequireViolation(t, result, 1, "FI-3", "path epoch 2 at its CAS, the ref's current 1: a stale path epoch")
}

// A retry of a push validated under an older pin, landing after a commit that raised the head's pin, as a store that
// took any write would let it: caught as a pin that fell.
func TestFi3CatchesARetryReusingAFallenPin(t *testing.T) {
	world := newFi3World(t)
	var old *bridge.AuthPin
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			old = world.view.Pin()
			return world.push(fi3Pins{})(ctx, net)
		}},
		{Actor: "api", Action: world.advance(false)},
		{Actor: "writerB", Action: world.push(fi3Pins{})},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			return world.push(fi3Pins{auth: old, raw: true})(ctx, net)
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi3-fallen-pin", Steps: steps, Check: fi3Checks()}, world.net)
	fiRequireViolation(t, result, 3, "FI-3", "auth pin 1 below the head's 2: a pin fell")
}

// A push pinning a chain the network's log never held: caught as off the chain current at its CAS.
func TestFi3CatchesAPinOffTheChain(t *testing.T) {
	world := newFi3World(t)
	forked := sha256.Sum256([]byte("a forked chain"))
	steps := []*Step{
		{Actor: "writerA", Action: world.push(fi3Pins{})},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			return world.push(fi3Pins{auth: &bridge.AuthPin{Version: 1, Chain: forked[:]}, raw: true})(ctx, net)
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi3-fork", Steps: steps, Check: fi3Checks()}, world.net)
	fiRequireViolation(t, result, 1, "FI-3", "off the authorization chain current at its CAS")
}

// A commit past §11.12's phase-1 window after repo/ left active: caught. Its twin inside the window is clean.
func TestFi3CatchesACommitPastTheLifecycleWindow(t *testing.T) {
	result := fi3LifecycleRun(t, 30*time.Second)
	fiRequireViolation(t, result, 3, "FI-3", "after repo/ left active, past §11.12's 20s")
}

func TestFi3TakesACommitInsideTheLifecycleWindow(t *testing.T) {
	fiRequirePass(t, fi3LifecycleRun(t, 10*time.Second))
}

func fi3LifecycleRun(t *testing.T, after time.Duration) *Result {
	world := newFi3World(t)
	fi2 := &fi2World{fiHandWorld: world.fiHandWorld, main: world.main}
	steps := []*Step{
		{Actor: "writerA", Action: world.push(fi3Pins{})},
		{Actor: "evs3", Action: fi2.repoState(protocol.EvsRepoState_EVS_REPO_DELETED)},
		{Actor: "clock", Advance: after},
		{Actor: "evs1", Action: world.push(fi3Pins{})},
	}
	return Run(t.Context(), &Schedule{Id: "fi3-lifecycle", Steps: steps, Check: fi3Checks()}, world.net)
}

// A Net no schedule named an authorization state on: FI-3 fails closed at the first commit rather than judging it.
func TestFi3FailsClosedWithNoStateNamed(t *testing.T) {
	world := newFi3World(t)
	// a second network's repo/ makes the repo one no state is named for
	other := sidecar.NewId()
	steps := []*Step{
		{Actor: "evs", Action: func(ctx context.Context, net *Net) error {
			object, err := world.cluster.Get(ctx, sidecar.EvsRepoObjectKey(world.repoId))
			if err != nil {
				return err
			}
			body := new(bytes.Buffer)
			_, err = body.ReadFrom(object.Body)
			object.Body.Close()
			if err != nil {
				return err
			}
			repo := &protocol.EvsRepoObject{}
			if err := proto.Unmarshal(body.Bytes(), repo); err != nil {
				return err
			}
			repo.NetworkId = other.Bytes()
			repoBytes, err := proto.Marshal(repo)
			if err != nil {
				return err
			}
			_, err = world.cluster.PutIfMatch(ctx, sidecar.EvsRepoObjectKey(world.repoId), object.Etag, repoBytes, nil)
			return err
		}},
		{Actor: "writerA", Action: world.push(fi3Pins{})},
	}
	result := Run(t.Context(), &Schedule{Id: "fi3-no-state", Steps: steps, Check: fi3Checks()}, world.net)
	fiRequireViolation(t, result, 1, "FI-3", "no authorization state is named for network")
}
