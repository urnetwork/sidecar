//go:build !sidecar_http

// The flows' world: the member checks' world with a fake clock, the fake gkm every device's api shares, and for each
// device a GkmGroupClient over its own keychain, holding generation 1 and, for a leaf, epoch 1, as a join leaves a
// device.

package sidecar_test

import (
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One device's side of the flows.
type gkmFlowDevice struct {
	*gkmWorldDevice
	world   *gkmFlowWorld
	client  *sidecar.GkmGroupClient
	secrets *gkmFakeSecrets
	api     *gkmFakeApi
	// its ReaderKeys' private keys, by the digest of the public key
	readerPrivateKeys map[string]hpke.PrivateKey
	readerKeySha256   []byte
	alarms            []*sidecar.GkmAlarm
}

type gkmFlowWorld struct {
	*gkmCommitWorld
	ctx   context.Context
	clock *sidecartest.FakeClock
	store *gkmFakeStore
	flows map[*gkmWorldDevice]*gkmFlowDevice
	// what each member's RecoveryBind publishes; a member absent here has no readable recovery key
	recoveryKeys map[sidecar.Id]*sidecar.GkmRecoveryKey
	// the jitter every client draws
	jitter time.Duration
	// epoch 1's header, encoded
	headerBytes []byte
}

// A world with the commit world's devices admitted and granted at the log's first position, and no group yet: what
// KF1 starts from.
func newGkmBareFlowWorld(t *testing.T, kind protocol.RepoKind) *gkmFlowWorld {
	commitWorld := &gkmCommitWorld{gkmWorld: newGkmWorld(t, kind)}
	commitWorld.a = commitWorld.admit("a")
	commitWorld.b = commitWorld.admit("b")
	commitWorld.c = commitWorld.admit("c")
	commitWorld.p = commitWorld.admit("p")
	commitWorld.p.row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	commitWorld.x = commitWorld.admit("x")
	commitWorld.grant(true, commitWorld.a, commitWorld.b)
	commitWorld.grant(false, commitWorld.c, commitWorld.p, commitWorld.x)
	commitWorld.first = commitWorld.state()
	world := &gkmFlowWorld{
		gkmCommitWorld: commitWorld,
		ctx:            context.Background(),
		clock:          sidecartest.NewFakeClock(commitWorld.now),
		flows:          map[*gkmWorldDevice]*gkmFlowDevice{},
		recoveryKeys:   map[sidecar.Id]*sidecar.GkmRecoveryKey{},
	}
	world.store = newGkmFakeStore(t, world.clock)
	for _, device := range world.devices {
		world.flow(device)
	}
	return world
}

// The commit world at epoch 1 and generation 1, as gkm holds it and as every device holds it.
func newGkmFlowWorld(t *testing.T, kind protocol.RepoKind) *gkmFlowWorld {
	commitWorld := newGkmCommitWorld(t, kind)
	world := &gkmFlowWorld{
		gkmCommitWorld: commitWorld,
		ctx:            context.Background(),
		clock:          sidecartest.NewFakeClock(commitWorld.now),
		flows:          map[*gkmWorldDevice]*gkmFlowDevice{},
		recoveryKeys:   map[sidecar.Id]*sidecar.GkmRecoveryKey{},
	}
	world.store = newGkmFakeStore(t, world.clock)
	world.headerBytes = gkmWorldHeader(t, 1, world.first.Pin())
	// gkm's side of the group: its owner, its form, gen/1, and epochs 0 and 1
	world.store.groupOwnerRepoIds[world.groupId] = world.repoId
	formBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GroupForm{RepoId: world.repoId.Bytes(), GroupId: world.groupId.Bytes(), Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	form, err := world.a.signer.Sign("group-form", bridge.SignedType_SIGNED_GROUP_FORM, formBody, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.store.repoForms[world.repoId] = []*bridge.Signed{form}
	world.store.groupGenerations[world.groupId] = []*bridge.Signed{world.gen1.signed}
	world.store.groupEpochs[world.groupId] = []*protocol.GkmEpochObject{
		{Header: world.header, Uploader: world.a.id.Bytes(), GroupInfoGeneration: 1},
		{Header: world.header, Uploader: world.a.id.Bytes(), GroupInfoGeneration: 1},
	}
	for _, device := range world.devices {
		world.flow(device)
	}
	return world
}

// Moves the clock, and the world's own reading of it.
func (self *gkmFlowWorld) advance(timeout time.Duration) {
	self.clock.Advance(timeout)
	self.now = self.clock.Now()
}

// A fresh ReaderKey of a device, published at gkm, its private key kept.
func (self *gkmFlowDevice) publishReaderKey() {
	self.world.t.Helper()
	signed, privateKey := self.world.readerKey(self.gkmWorldDevice)
	keySha256 := sha256.Sum256(privateKey.PublicKey().Bytes())
	self.readerPrivateKeys[string(keySha256[:])] = privateKey
	self.readerKeySha256 = keySha256[:]
	self.world.store.readerKeys[self.id] = signed
}

// A client for a device over secrets, as a restart builds one: the same keychain, nothing else kept.
func (self *gkmFlowDevice) restart() {
	self.world.t.Helper()
	world := self.world
	args := &sidecar.GkmGroupClientArgs{
		SidecarId: self.id,
		Api:       self.api,
		Sign:      self.signer.Sign,
		Secrets:   self.secrets,
		ReaderPrivateKey: func(keySha256 []byte) (hpke.PrivateKey, error) {
			privateKey, ok := self.readerPrivateKeys[string(keySha256)]
			if !ok {
				return nil, sidecar.ErrGkmKeyMissing
			}
			return privateKey, nil
		},
		ReaderKeySha256: func() []byte { return self.readerKeySha256 },
		RecoveryKey: func(memberId sidecar.Id) (*sidecar.GkmRecoveryKey, error) {
			return world.recoveryKeys[memberId], nil
		},
		ReaderRepoIds: func() []sidecar.Id { return []sidecar.Id{world.repoId} },
		Alarm:         func(alarm *sidecar.GkmAlarm) { self.alarms = append(self.alarms, alarm) },
		Jitter:        func(max time.Duration) time.Duration { return min(world.jitter, max) },
		Clock:         world.clock,
	}
	if len(self.row.GetTagIds()) == 0 {
		args.Mls = self.mls
	}
	client, err := sidecar.NewGkmGroupClient(args)
	if err != nil {
		world.t.Fatal(err)
	}
	self.client = client
	if tip := world.log.Tip(); tip != nil {
		client.AuthAdvanced(tip)
	}
}

// A device's flows, made at first use: its api, keychain, ReaderKey and client, holding generation 1 if it reads
// the repo and epoch 1 if it is a leaf.
func (self *gkmFlowWorld) flow(device *gkmWorldDevice) *gkmFlowDevice {
	self.t.Helper()
	if flow, ok := self.flows[device]; ok {
		return flow
	}
	flow := &gkmFlowDevice{
		gkmWorldDevice:    device,
		world:             self,
		secrets:           newGkmFakeSecrets(),
		api:               self.store.api(device.label, device.id),
		readerPrivateKeys: map[string]hpke.PrivateKey{},
	}
	self.flows[device] = flow
	flow.publishReaderKey()
	flow.restart()
	return flow
}

// Gives a device generation 1 as a join or a first wrap would, and epoch 1 if it is a leaf.
func (self *gkmFlowWorld) hold(device *gkmWorldDevice, generations ...*gkmWorldGeneration) *gkmFlowDevice {
	self.t.Helper()
	flow := self.flow(device)
	for _, generation := range generations {
		if err := flow.client.TestHoldGeneration(self.repoId, self.groupId, generation.generation, generation.key); err != nil {
			self.t.Fatal(err)
		}
	}
	if device.group != nil {
		if err := flow.client.TestHoldEpoch(self.repoId, device.group, self.headerBytes); err != nil {
			self.t.Fatal(err)
		}
	}
	return flow
}

// Every device that reads the repo holds generation 1.
func (self *gkmFlowWorld) holdAll() {
	self.t.Helper()
	for _, device := range self.devices {
		if device.group != nil {
			self.hold(device, self.gen1)
		}
	}
}

// Appends the world as the log's next position and gives it to every client but those named, which stay behind.
func (self *gkmFlowWorld) stateFor(behind ...*gkmWorldDevice) *sidecartest.FakeGkmAuthView {
	self.t.Helper()
	view := self.state()
	for device, flow := range self.flows {
		stale := false
		for _, other := range behind {
			stale = stale || other == device
		}
		if !stale {
			flow.client.AuthAdvanced(view)
		}
	}
	return view
}

// gen/<g> as gkm holds it, parsed under view's identity keys.
func (self *gkmFlowWorld) storedGeneration(view sidecar.GkmAuthView, generation uint64) *sidecar.GkmGeneration {
	self.t.Helper()
	generations := self.store.groupGenerations[self.groupId]
	if uint64(len(generations)) < generation {
		self.t.Fatalf("gkm holds no gen/%d", generation)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(generations[generation-1])
	if err != nil {
		self.t.Fatal(err)
	}
	parsed, err := sidecar.ParseGenRotate(encoded, self.groupId, generation, sidecar.GkmIdentityKeys(view))
	if err != nil {
		self.t.Fatal(err)
	}
	return parsed
}

// The recipients of the deliveries gkm holds of one generation, by wrap path form: s:<label> or d:delegation, with
// each one's kind.
func (self *gkmFlowWorld) deliveryRecipients(generation uint64) map[string]sidecar.GkmDeliveryKind {
	self.t.Helper()
	recipients := map[string]sidecar.GkmDeliveryKind{}
	for _, path := range self.store.wrapPaths(self.groupId, generation) {
		body, wrapType, _, err := gkmFakeDeliveryBody(self.store.pathWraps[path])
		if err != nil {
			self.t.Fatal(err)
		}
		name := "d:delegation"
		if wrapType == sidecar.GkmWrapTypeReader {
			name = "s:?"
			for _, device := range self.devices {
				if string(device.id.Bytes()) == string(body.GetRecipient()) {
					name = "s:" + device.label
				}
			}
		}
		recipients[name] = sidecar.GkmDeliveryKind(body.GetDeliveryKind())
	}
	return recipients
}

// Appends a commit to gkm as its committer staged it, past every check of the client's: what a twin's or a hostile
// leaf's upload leaves standing at epoch/<n>.
func (self *gkmFlowWorld) inject(committer *gkmWorldDevice, staged sidecar.MlsStagedCommit, generation *gkmWorldGeneration) {
	self.t.Helper()
	header := &protocol.GkmCommitHeader{}
	if err := proto.Unmarshal(staged.AuthenticatedData(), header); err != nil {
		self.t.Fatal(err)
	}
	object := &protocol.GkmEpochObject{
		Commit:   staged.Message(),
		Header:   header,
		Uploader: committer.id.Bytes(),
		TimeMs:   self.clock.Now().UnixMilli(),
	}
	if generation != nil {
		object.GenWrap = self.genWrap(staged, generation)
	}
	self.store.groupEpochs[self.groupId] = append(self.store.groupEpochs[self.groupId], object)
}

// The leaves of a device's group, by label, sorted.
func (self *gkmFlowWorld) rosterLabels(group sidecar.MlsGroup) []string {
	labels := []string{}
	for _, member := range group.Roster() {
		for _, device := range self.devices {
			if device.id == member.SidecarId {
				labels = append(labels, device.label)
			}
		}
	}
	slices.Sort(labels)
	return labels
}

// A device's group as its engine holds it now, nil for none.
func (self *gkmFlowWorld) engineGroup(device *gkmWorldDevice) sidecar.MlsGroup {
	group, err := device.mls.LoadGroup(self.groupId)
	if err != nil {
		return nil
	}
	return group
}
