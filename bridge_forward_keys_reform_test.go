// The Forwarder's generation keys past a re-form of the config's group (plan-KEYS-reform-ladder rules 7 and 8;
// bridge_forward_keys.go's comment): the new group's ladder and claims resolve through the repo's GroupForms and open,
// after a site loss too and two re-forms behind, a copy the forms do not carry is refused, and only a verified chain
// from the group held moves the group the Forwarder lists in.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"slices"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// gkm past re-forms of the config's group: the world's group as its own fake serves it until a site loss takes it,
// each group a re-form made with its ladder, its own GenRotates and its wraps, and the repo's Signed GroupForms,
// oldest first.
type testForwarderReformGkm struct {
	world *testForwarderWorld
	// the world's group, which the world's own fake serves
	oldGroupId Id

	stateLock sync.Mutex
	// the old group's objects are gone and its routes refused
	lost          bool
	forms         []*bridge.Signed
	groups        map[Id]*testForwarderReformGroup
	newestGroupId Id
	// the reads each group's routes answered, and the reads of the forms
	generationReadCounts map[Id]int
	wrapReadCounts       map[Id]int
	formsReadCount       int
}

// One group a re-form made.
type testForwarderReformGroup struct {
	generations []*bridge.Signed
	wraps       map[uint64]map[string][]*bridge.Signed
}

// The reform gkm over the world, which its Forwarders read, its forms holding the creation's form of the world's
// group.
func newTestForwarderReformGkm(world *testForwarderWorld) *testForwarderReformGkm {
	gkm := &testForwarderReformGkm{
		world:                world,
		oldGroupId:           world.groupId,
		groups:               map[Id]*testForwarderReformGroup{},
		newestGroupId:        world.groupId,
		generationReadCounts: map[Id]int{},
		wrapReadCounts:       map[Id]int{},
	}
	gkm.forms = []*bridge.Signed{world.groupForm(world.groupId, Id{}, 1)}
	world.forwardGkm = gkm
	return gkm
}

func (self *testForwarderReformGkm) Generations(ctx context.Context, repoId Id, groupId Id, since uint64) (*protocol.GkmGenerationsReply, error) {
	self.stateLock.Lock()
	self.generationReadCounts[groupId] += 1
	lost := self.lost
	self.stateLock.Unlock()
	if groupId == self.oldGroupId {
		if lost {
			return nil, &GkmError{Status: http.StatusNotFound}
		}
		return self.world.gkm.Generations(ctx, repoId, groupId, since)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	group := self.groups[groupId]
	if group == nil {
		return nil, &GkmError{Status: http.StatusNotFound}
	}
	reply := &protocol.GkmGenerationsReply{}
	for _, signed := range group.generations[min(since, uint64(len(group.generations))):] {
		reply.Generations = append(reply.Generations, proto.Clone(signed).(*bridge.Signed))
	}
	return reply, nil
}

func (self *testForwarderReformGkm) Wraps(ctx context.Context, repoId Id, groupId Id, generation uint64, query *GkmWrapsQuery) (*protocol.GkmWrapsReply, error) {
	self.stateLock.Lock()
	self.wrapReadCounts[groupId] += 1
	lost := self.lost
	self.stateLock.Unlock()
	if groupId == self.oldGroupId {
		if lost {
			return nil, &GkmError{Status: http.StatusNotFound}
		}
		return self.world.gkm.Wraps(ctx, repoId, groupId, generation, query)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	group := self.groups[groupId]
	if group == nil {
		return nil, &GkmError{Status: http.StatusNotFound}
	}
	reply := &protocol.GkmWrapsReply{}
	for _, signed := range group.wraps[generation][query.Recipient] {
		reply.Wraps = append(reply.Wraps, proto.Clone(signed).(*bridge.Signed))
	}
	return reply, nil
}

func (self *testForwarderReformGkm) Forms(ctx context.Context, repoId Id) (*protocol.GkmFormsReply, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.formsReadCount += 1
	reply := &protocol.GkmFormsReply{}
	for _, signed := range self.forms {
		reply.Forms = append(reply.Forms, proto.Clone(signed).(*bridge.Signed))
	}
	return reply, nil
}

// The reads of a group's generations and of its wraps so far.
func (self *testForwarderReformGkm) readCounts(groupId Id) (int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.generationReadCounts[groupId], self.wrapReadCounts[groupId]
}

// The group the newest form makes.
func (self *testForwarderReformGkm) newest() Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.newestGroupId
}

// The GenRotates a group holds, in order, the old group's as the world's fake holds them even after a site loss, as
// the re-former's keychain does.
func (self *testForwarderReformGkm) generationsOf(groupId Id) []*bridge.Signed {
	if groupId == self.oldGroupId {
		self.world.gkm.stateLock.Lock()
		defer self.world.gkm.stateLock.Unlock()
		return slices.Clone(self.world.gkm.generations)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.groups[groupId].generations)
}

// A site loss: the old group's objects and the repo's forms are gone, and a re-seed's form is the next.
func (self *testForwarderReformGkm) lose() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lost = true
	self.forms = nil
}

// Re-forms the newest group into groupId at the newest generation it holds, as a re-former's steps 1 to 3 leave it:
// the owner's device's GroupForm naming the group it re-forms, and the new group's ladder, the re-formed group's
// Signed GenRotates byte for byte.
func (self *testForwarderReformGkm) reform(groupId Id) {
	previousGroupId := self.newest()
	ladder := self.generationsOf(previousGroupId)
	self.reformWith(groupId, previousGroupId, ladder, uint64(len(ladder)))
}

// A re-form into groupId of previousGroupId at generation whose new group holds ladder.
func (self *testForwarderReformGkm) reformWith(groupId Id, previousGroupId Id, ladder []*bridge.Signed, generation uint64) {
	form := self.world.groupForm(groupId, previousGroupId, generation)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	group := &testForwarderReformGroup{wraps: map[uint64]map[string][]*bridge.Signed{}}
	for _, signed := range ladder {
		group.generations = append(group.generations, proto.Clone(signed).(*bridge.Signed))
	}
	self.groups[groupId] = group
	self.forms = append(self.forms, form)
	self.newestGroupId = groupId
}

// The newest group's next generation, which names it, rotated by the owner's device, with a DelegationWrap in it for
// each Delegation among recipients.
func (self *testForwarderReformGkm) rotateIn(recipients ...testForwarderRecipient) uint64 {
	self.world.t.Helper()
	groupId := self.newest()
	if groupId == self.oldGroupId {
		self.world.t.Fatal("no re-form to rotate in: the world's group rotates by world.rotate")
	}
	generation := uint64(len(self.generationsOf(groupId))) + 1
	signed := self.world.genRotateIn(groupId, self.world.net.configRepoId(), generation)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		group := self.groups[groupId]
		group.generations = append(group.generations, signed)
	}()
	for _, recipient := range recipients {
		self.wrapIn(groupId, generation, recipient)
	}
	return generation
}

// A DelegationWrap in groupId of a generation it holds, to one Delegation's reader key, signed by the owner's device:
// its body names groupId, a carried generation's too, as a re-formed group's deliveries do (rule 7).
func (self *testForwarderReformGkm) wrapIn(groupId Id, generation uint64, recipient testForwarderRecipient) {
	t := self.world.t
	t.Helper()
	signedBytes := testConfigMarshal(t, self.generationsOf(groupId)[generation-1])
	namedGroupId, err := GkmGenerationNamedGroup(signedBytes)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseGenRotate(signedBytes, namedGroupId, generation, GkmIdentityKeys(self.world.net.log.State()))
	if err != nil {
		t.Fatal(err)
	}
	key, err := OpenEvsRepoKey(parsed, testConfigSealKey(generation).repoKey)
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := SealGkmDelivery(key, &GkmDeliveryArgs{
		GroupId: groupId, Type: GkmWrapTypeDelegation, Recipient: recipient.delegationId,
		RecipientPublicKey: recipient.readerKey.PublicKey().Bytes(), Kind: GkmDeliveryStaged,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignGkmDelivery(delivery, GkmWrapTypeDelegation, gkmForwardSigner(self.world.net.owner))
	if err != nil {
		t.Fatal(err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	group := self.groups[groupId]
	if group.wraps[generation] == nil {
		group.wraps[generation] = map[string][]*bridge.Signed{}
	}
	name := forwarderWrapRecipient(recipient.delegationId)
	group.wraps[generation][name] = append(group.wraps[generation][name], signed)
}

// A Signed GroupForm of the config repo making groupId, re-forming previousGroupId at generation where it is not
// zero, signed by the owner's device at the net's state.
func (self *testForwarderWorld) groupForm(groupId Id, previousGroupId Id, generation uint64) *bridge.Signed {
	self.t.Helper()
	body := &protocol.GroupForm{RepoId: self.net.configRepoId().Bytes(), GroupId: groupId.Bytes(), Generation: generation, Auth: self.net.log.State().Pin()}
	if previousGroupId != (Id{}) {
		body.PreviousGroupId = previousGroupId.Bytes()
	}
	bodyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := gkmSign(gkmGroupFormPurpose, bridge.SignedType_SIGNED_GROUP_FORM, bodyBytes, gkmForwardSigner(self.net.owner))
	if err != nil {
		self.t.Fatal(err)
	}
	return signed
}

// A GenRotate of generation naming groupId and repoId, signed by the owner's device, its key the one the net seals that
// generation's bodies under, chained to the one below as world.rotate chains them.
func (self *testForwarderWorld) genRotateIn(groupId Id, repoId Id, generation uint64) *bridge.Signed {
	self.t.Helper()
	repoKey := testConfigSealKey(generation).repoKey
	state := self.net.log.State()
	holders := sha256.Sum256([]byte("forwarder test holders"))
	rotate := &protocol.GenRotate{
		GroupId: groupId.Bytes(), RepoId: repoId.Bytes(), Generation: generation,
		Commitment: gkmCommitment(repoId, generation, repoKey), Cause: uint32(GkmCauseSchedule),
		Auth: state.Pin(), TimeMs: state.TimeMs(), HoldersSha256: holders[:],
	}
	if 1 < generation {
		parentKey := testConfigSealKey(generation - 1).repoKey
		linkKey, err := gkmDeriveKey(repoKey, repoId, EvsKeyPurposeLink, generation, nil)
		if err != nil {
			self.t.Fatal(err)
		}
		genLink, err := gkmSeal(linkKey, parentKey, gkmGenLinkAad(repoId, generation, GkmCauseSchedule))
		if err != nil {
			self.t.Fatal(err)
		}
		rotate.ParentCommitment, rotate.Genlink = gkmCommitment(repoId, generation-1, parentKey), genLink
	}
	signed, err := SignGenRotate(rotate, gkmForwardSigner(self.net.owner))
	if err != nil {
		self.t.Fatal(err)
	}
	return signed
}

// A route of the peer's under its own rule and prefix, its body sealed to a generation, so a compile wants that
// generation's key.
func (self *testForwarderWorld) postRouteSealedTo(label string, generation uint64) {
	self.t.Helper()
	body := testBridgeSubnet(testBridgePrefix(10, 9, byte(generation), 0, 24), "site "+label)
	route := self.net.bridgeRouteAt(self.peer, testBridgeRuleId("sealed "+label), body, generation)
	self.net.mustPost(self.peer, bridge.SignedType_SIGNED_BRIDGE_ROUTE, route)
}

// The generations a status's compile waited for, ascending.
func testForwarderGenerationWaits(status ForwarderStatus) []uint64 {
	generations := []uint64{}
	for _, wait := range status.Waits {
		if wait.Kind == BridgeCompileWaitGeneration {
			generations = append(generations, wait.Generation)
		}
	}
	slices.Sort(generations)
	return generations
}

// The groups record a store holds, as group ids.
func (self *testForwarderWorld) storedGroups() []Id {
	self.t.Helper()
	groups, err := (&forwarderRecords{store: self.forwardStore}).groups(Id{})
	if err != nil {
		self.t.Fatal(err)
	}
	return append(slices.Clone(groups.past), groups.current)
}

// After the config's group is re-formed, the Forwarder lists the new group's generations through the repo's
// GroupForms: a body sealed to a generation the ladder carried, which no wrap of the old group's reached, and one sealed
// to the first generation the new group claimed both open, the carried key by the ladder from the claimed one, each
// held to the statement of the group it was claimed in; the old group is read no more; and a restart opens every key
// from the store with no read of gkm. Before, the Forwarder listed the group its hand-off named, which holds no
// generation past the form's, so the claimed generation never listed and neither body opened.
func TestAReformedConfigGroupsLadderKeysResolveAndVerify(t *testing.T) {
	world := newTestForwarderWorld(t)
	gkm := newTestForwarderReformGkm(world)
	oldGroupId := world.groupId
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	if forwarder.RepoKeyAt(1) == nil {
		t.Fatal("generation 1 did not open before the re-form")
	}

	// generation 2, claimed in the old group with no wrap the forwarding reader key reaches, is carried by the re-form;
	// generation 3 is the re-former's rotation, the new group's first claim, with its wrap there
	world.rotate()
	reformedGroupId := testConfigId("re-formed config group")
	gkm.reform(reformedGroupId)
	gkm.rotateIn(world.recipient())
	world.postRouteSealedTo("carried", 2)
	world.postRouteSealedTo("claimed", 3)
	oldGenerationReads, oldWrapReads := gkm.readCounts(oldGroupId)
	world.hint(forwarder)

	status := forwarder.Status()
	carried, claimed := forwarder.RepoKeyAt(2), forwarder.RepoKeyAt(3)
	if carried == nil || carried.GroupId() != oldGroupId || claimed == nil || claimed.GroupId() != reformedGroupId || status.GenerationCount != 3 {
		t.Fatalf("after the re-form: generation 2's key %v, generation 3's %v, status %+v", carried, claimed, status)
	}
	if waits := testForwarderGenerationWaits(status); len(waits) != 0 {
		t.Fatalf("generations still wait: %v", waits)
	}
	if !slices.Equal(world.storedGroups(), []Id{oldGroupId, reformedGroupId}) {
		t.Errorf("the groups record: %v", world.storedGroups())
	}
	if generationReads, wrapReads := gkm.readCounts(oldGroupId); generationReads != oldGenerationReads || wrapReads != oldWrapReads {
		t.Errorf("the old group was read past its re-form: %d reads of its generations, %d of its wraps", generationReads-oldGenerationReads, wrapReads-oldWrapReads)
	}
	if generationReads, wrapReads := gkm.readCounts(reformedGroupId); generationReads == 0 || wrapReads == 0 {
		t.Errorf("the new group was read %d times for generations and %d for wraps", generationReads, wrapReads)
	}

	// the restart reads each key from the store, the groups record leading its records through the form
	forwarder.Close()
	generationReads, _ := gkm.readCounts(reformedGroupId)
	formsReads := func() int {
		gkm.stateLock.Lock()
		defer gkm.stateLock.Unlock()
		return gkm.formsReadCount
	}
	formsReadsBefore := formsReads()
	restarted := world.forwarder()
	world.net.consentedMember("after the restart")
	world.hint(restarted)
	for generation := uint64(1); generation <= 3; generation += 1 {
		if restarted.RepoKeyAt(generation) == nil {
			t.Errorf("a restart holds no key of generation %d", generation)
		}
	}
	if after, _ := gkm.readCounts(reformedGroupId); after != generationReads || formsReads() != formsReadsBefore {
		t.Errorf("a restart read gkm: %d reads of generations, %d of forms", after-generationReads, formsReads()-formsReadsBefore)
	}
	if status := restarted.Status(); len(testForwarderGenerationWaits(status)) != 0 || status.CompiledPin.GetVersion() != world.net.n {
		t.Errorf("a restart's status %+v", status)
	}
}

// After a site loss took the old group's objects and the repo's forms, a Forwarder set up afresh opens the config's
// keys through the re-seed's GroupForm alone, whether its hand-off named the old group or the new one: before the
// re-former rotates, a holder's late wrap of the form's generation in the new group, whose body names the new group
// (rule 7), opens it, and the ladder opens each generation below it. The old group's routes are never asked.
func TestAReformAfterASiteLossOpensTheConfigsKeysThroughTheNewestForm(t *testing.T) {
	for _, handOffReformed := range []bool{false, true} {
		world := newTestForwarderWorld(t)
		gkm := newTestForwarderReformGkm(world)
		oldGroupId := world.groupId
		world.rotate()
		world.rotate()
		gkm.lose()
		reformedGroupId := testConfigId("re-seeded config group")
		gkm.reform(reformedGroupId)
		gkm.wrapIn(reformedGroupId, 2, world.recipient())
		world.bind(world.peer)
		world.postRouteSealedTo("carried", 2)
		world.publish()
		if handOffReformed {
			world.groupId = reformedGroupId
		}
		forwarder := world.forwarder()

		status := forwarder.Status()
		targets, inForce := forwarder.LinkTargets()
		if !inForce || !slices.Equal(targets, []Id{world.peer.sidecarId}) || status.GenerationCount != 2 || len(testForwarderGenerationWaits(status)) != 0 {
			t.Fatalf("hand-off naming the new group %t: links %v in force %t, status %+v", handOffReformed, targets, inForce, status)
		}
		for generation := uint64(1); generation <= 2; generation += 1 {
			if key := forwarder.RepoKeyAt(generation); key == nil || key.GroupId() != oldGroupId {
				t.Errorf("hand-off naming the new group %t: generation %d's key %v", handOffReformed, generation, key)
			}
		}
		if generationReads, wrapReads := gkm.readCounts(oldGroupId); generationReads != 0 || wrapReads != 0 {
			t.Errorf("hand-off naming the new group %t: the lost group was asked %d and %d times", handOffReformed, generationReads, wrapReads)
		}
		if !slices.Equal(world.storedGroups(), []Id{oldGroupId, reformedGroupId}) {
			t.Errorf("hand-off naming the new group %t: the groups record %v", handOffReformed, world.storedGroups())
		}
	}
}

// A copy in a re-formed group's ladder that the repo's forms do not carry opens nothing, though the owner's device
// signed it and a wrap of it in the new group reaches the forwarding reader key: one naming neither the old group nor
// a group of the forms the Forwarder followed, one naming the old group past the form's generation, and one of another
// repo. The list stops at it, so the generation the new group claims above it waits as well, and neither is kept. The
// honest copy, alike in all else, opens both.
func TestALadderCopyNamingNoGroupOfTheConfigsFormsIsRefused(t *testing.T) {
	cases := []struct {
		name string
		// gen/2 of the new group's ladder, from the world and the old group
		copy func(world *testForwarderWorld, oldGroupId Id) *bridge.Signed
		// the generation the new group's form carries
		formGeneration uint64
		opens          bool
	}{
		{
			name: "the old group's own",
			copy: func(world *testForwarderWorld, oldGroupId Id) *bridge.Signed {
				return world.genRotateIn(oldGroupId, world.net.configRepoId(), 2)
			},
			formGeneration: 2, opens: true,
		},
		{
			name: "naming neither the old group nor a form's group",
			copy: func(world *testForwarderWorld, oldGroupId Id) *bridge.Signed {
				return world.genRotateIn(testConfigId("no group of the config"), world.net.configRepoId(), 2)
			},
			formGeneration: 2,
		},
		{
			name: "naming the old group past the form's generation",
			copy: func(world *testForwarderWorld, oldGroupId Id) *bridge.Signed {
				return world.genRotateIn(oldGroupId, world.net.configRepoId(), 2)
			},
			formGeneration: 1,
		},
		{
			name: "of another repo",
			copy: func(world *testForwarderWorld, oldGroupId Id) *bridge.Signed {
				return world.genRotateIn(oldGroupId, testConfigId("another repo"), 2)
			},
			formGeneration: 2,
		},
	}
	for _, c := range cases {
		world := newTestForwarderWorld(t)
		gkm := newTestForwarderReformGkm(world)
		oldGroupId := world.groupId
		world.rotate(world.recipient())
		world.bind(world.peer)
		forwarder := world.forwarder()
		if forwarder.RepoKeyAt(1) == nil {
			t.Fatalf("%s: generation 1 did not open before the re-form", c.name)
		}
		reformedGroupId := testConfigId("re-formed config group")
		ladder := append(gkm.generationsOf(oldGroupId), c.copy(world, oldGroupId))
		gkm.reformWith(reformedGroupId, oldGroupId, ladder, c.formGeneration)
		gkm.wrapIn(reformedGroupId, 2, world.recipient())
		gkm.rotateIn(world.recipient())
		world.postRouteSealedTo("copied", 2)
		world.postRouteSealedTo("claimed", 3)
		world.hint(forwarder)

		status := forwarder.Status()
		storedCount := len(world.stored(forwarderGenerationPrefix))
		if c.opens {
			if forwarder.RepoKeyAt(2) == nil || forwarder.RepoKeyAt(3) == nil || status.GenerationCount != 3 || len(testForwarderGenerationWaits(status)) != 0 || storedCount != 3 {
				t.Errorf("%s: status %+v, %d generations stored", c.name, status, storedCount)
			}
			continue
		}
		if forwarder.RepoKeyAt(2) != nil || forwarder.RepoKeyAt(3) != nil || status.GenerationCount != 1 || storedCount != 1 {
			t.Errorf("%s: opened: status %+v, %d generations stored", c.name, status, storedCount)
		}
		if waits := testForwarderGenerationWaits(status); !slices.Equal(waits, []uint64{2, 3}) {
			t.Errorf("%s: the compile's generation waits %v", c.name, waits)
		}
		if _, inForce := forwarder.LinkTargets(); !inForce {
			t.Errorf("%s: a refused copy took the state out of force", c.name)
		}
	}
}

// The Forwarder moves to a re-formed group only along a chain of verified GroupForms from the group it lists in, so
// each of these leaves it listing there, the newest group's own generation opening nothing and the newest group never
// read: a newest form re-forming a group no form leads to, one re-forming the held group below the newest generation
// held, and a newest form whose signature does not verify.
func TestAReformThatDoesNotFollowFromTheHeldGroupMovesNothing(t *testing.T) {
	cases := []struct {
		name string
		// files the newest form and its group's generations past the old group's two
		reform func(world *testForwarderWorld, gkm *testForwarderReformGkm, groupId Id)
	}{
		{
			name: "a form re-forming a group no form leads to",
			reform: func(world *testForwarderWorld, gkm *testForwarderReformGkm, groupId Id) {
				gkm.reformWith(groupId, testConfigId("a group no form makes"), gkm.generationsOf(gkm.oldGroupId), 2)
				gkm.rotateIn(world.recipient())
			},
		},
		{
			name: "a form re-forming below the newest generation held",
			reform: func(world *testForwarderWorld, gkm *testForwarderReformGkm, groupId Id) {
				gkm.reformWith(groupId, gkm.oldGroupId, gkm.generationsOf(gkm.oldGroupId)[:1], 1)
				gkm.rotateIn(world.recipient())
				gkm.rotateIn(world.recipient())
			},
		},
		{
			name: "a form that does not verify",
			reform: func(world *testForwarderWorld, gkm *testForwarderReformGkm, groupId Id) {
				gkm.reform(groupId)
				gkm.rotateIn(world.recipient())
				gkm.stateLock.Lock()
				defer gkm.stateLock.Unlock()
				newest := gkm.forms[len(gkm.forms)-1]
				newest.Signature = bytes.Clone(newest.GetSignature())
				newest.Signature[0] ^= 1
			},
		},
	}
	for _, c := range cases {
		world := newTestForwarderWorld(t)
		gkm := newTestForwarderReformGkm(world)
		oldGroupId := world.groupId
		world.rotate(world.recipient())
		world.rotate(world.recipient())
		world.bind(world.peer)
		forwarder := world.forwarder()
		if forwarder.RepoKeyAt(2) == nil {
			t.Fatalf("%s: generation 2 did not open before the re-form", c.name)
		}
		reformedGroupId := testConfigId("re-formed config group")
		c.reform(world, gkm, reformedGroupId)
		world.postRouteSealedTo("claimed", 3)
		world.hint(forwarder)

		status := forwarder.Status()
		if forwarder.RepoKeyAt(3) != nil || status.GenerationCount != 2 || !slices.Equal(testForwarderGenerationWaits(status), []uint64{3}) {
			t.Errorf("%s: status %+v", c.name, status)
		}
		if generationReads, wrapReads := gkm.readCounts(reformedGroupId); generationReads != 0 || wrapReads != 0 {
			t.Errorf("%s: the newest group was read %d and %d times", c.name, generationReads, wrapReads)
		}
		if generationReads, _ := gkm.readCounts(oldGroupId); generationReads == 0 {
			t.Errorf("%s: the old group was not listed", c.name)
		}
		if len(world.stored(forwarderGroupsName)) != 0 {
			t.Errorf("%s: a groups record was kept: %v", c.name, world.storedGroups())
		}
	}
}

// Once the Forwarder follows a re-form, a gkm that serves the forms as they stood before it, the old group's form the
// newest again, moves it no further back: it lists the group it followed to, whose next claim opens, and the old group
// is read no more.
func TestAnOlderFormListMovesTheForwarderNoFurtherBack(t *testing.T) {
	world := newTestForwarderWorld(t)
	gkm := newTestForwarderReformGkm(world)
	oldGroupId := world.groupId
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	reformedGroupId := testConfigId("re-formed config group")
	gkm.reform(reformedGroupId)
	gkm.rotateIn(world.recipient())
	world.postRouteSealedTo("claimed", 2)
	world.hint(forwarder)
	if key := forwarder.RepoKeyAt(2); key == nil || key.GroupId() != reformedGroupId {
		t.Fatalf("the new group's first claim did not open: %v", key)
	}

	func() {
		gkm.stateLock.Lock()
		defer gkm.stateLock.Unlock()
		gkm.forms = gkm.forms[:1]
	}()
	gkm.rotateIn(world.recipient())
	world.postRouteSealedTo("claimed later", 3)
	oldGenerationReads, _ := gkm.readCounts(oldGroupId)
	world.hint(forwarder)
	if key := forwarder.RepoKeyAt(3); key == nil || key.GroupId() != reformedGroupId {
		t.Fatalf("the new group's next claim did not open under the older form list: %v", key)
	}
	if generationReads, _ := gkm.readCounts(oldGroupId); generationReads != oldGenerationReads {
		t.Errorf("the old group was listed again %d times", generationReads-oldGenerationReads)
	}
	if !slices.Equal(world.storedGroups(), []Id{oldGroupId, reformedGroupId}) {
		t.Errorf("the groups record: %v", world.storedGroups())
	}
}

// A Forwarder two re-forms behind follows the chain of forms to the newest group in one listing: the newest group's
// ladder carries statements of both older groups, each held to the group it was claimed in, every key opens from the
// newest claim's wrap down the ladder, the middle group is never read, and the groups record names all three, the
// newest last.
func TestAForwarderTwoReformsBehindFollowsTheChainToTheNewest(t *testing.T) {
	world := newTestForwarderWorld(t)
	gkm := newTestForwarderReformGkm(world)
	oldGroupId := world.groupId
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()

	middleGroupId, newestGroupId := testConfigId("middle config group"), testConfigId("newest config group")
	world.rotate()
	gkm.reform(middleGroupId)
	gkm.rotateIn()
	gkm.reform(newestGroupId)
	gkm.rotateIn(world.recipient())
	world.postRouteSealedTo("old", 2)
	world.postRouteSealedTo("middle", 3)
	world.postRouteSealedTo("newest", 4)
	world.hint(forwarder)

	status := forwarder.Status()
	if status.GenerationCount != 4 || len(testForwarderGenerationWaits(status)) != 0 {
		t.Fatalf("two re-forms on: status %+v", status)
	}
	for generation, groupId := range map[uint64]Id{1: oldGroupId, 2: oldGroupId, 3: middleGroupId, 4: newestGroupId} {
		if key := forwarder.RepoKeyAt(generation); key == nil || key.GroupId() != groupId {
			t.Errorf("generation %d's key %v", generation, key)
		}
	}
	if generationReads, wrapReads := gkm.readCounts(middleGroupId); generationReads != 0 || wrapReads != 0 {
		t.Errorf("the middle group was read %d and %d times", generationReads, wrapReads)
	}
	if !slices.Equal(world.storedGroups(), []Id{oldGroupId, middleGroupId, newestGroupId}) {
		t.Errorf("the groups record: %v", world.storedGroups())
	}
}
