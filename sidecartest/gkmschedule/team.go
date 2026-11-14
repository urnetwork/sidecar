package gkmschedule

// Team scale on gkmservice (KEYS-M6-03; R-KEYS-11, D-KEYS-2, D-KEYS-23, R-CTX-12; owner decisions 144, 182): the
// team directory's group, kind directory, under §7.9's leaves rule, with gkm's group client and the real MLS subset
// against gkmservice's engine, each schedule one builder a T2 test and server's T3 test run.
//
//   - FsKeysScheduleDirectoryMemberRemoval: FS-87's key legs and the key part of S4b, F9's member form. A
//     MemberRevoke drops every device of a member at one position: two leaves and a device that read by wraps. The
//     revocation's signer commits both Removes in one commit and then rotates on the clean tree; the rotation
//     reaches the leaves by its leaf_wrap and the wrapped readers, an agent and a member device no leaf has added
//     yet, by their ReaderWraps; no device of the removed member is wrapped to, and each, keeping its MLS state and
//     every ReaderKey it signed, opens nothing of that generation or of the next one however much of the store it
//     reads.
//   - FsKeysScheduleDirectoryMemberAdd: the key part of S3b, F3's member form. A MemberAdmit's devices come in at
//     one position, signed by one device: that device is the granting device, commits one Add for the device that
//     uploaded KeyPackages, whose Welcome it joins by, and writes the first wrap of the one that uploaded none; a
//     device of a member the directory's readers do not hold gets neither.
//   - FsKeysScheduleTeamSeats: §22.7's seats row at settings' admissions, 5,000 at full scale. The first 1,000 live
//     member devices by (live_since, sidecar_id) are leaf-entitled; the 1,001st reads the directory by its
//     ReaderWrap at once, with no commit; a wrapped device that signed an admission writes the new device's first
//     wrap; a wrapped device that signed a revocation rotates, by wraps to every holder, and the next leaf commit
//     removes the leaf target; that revocation moves the 1,001st into the first 1,000, where it keeps its wraps
//     until a leaf adds it, and nothing shrinks; a leaf's rotation then wraps to every holder outside the tree; and
//     members refuse a leaf's Add of a device past the first 1,000.
//
// A device of the bulk holds a row and a ReaderKey and runs no flow: what a Team's other admissions are to the
// devices a schedule drives. The rank is set by each row's live_since, which a schedule numbers.
//
// Not here: the scenario registry's S3b and S4b rows (sidecartest/scenario.go), which TEAM-M6-12 composes with its
// own MemberAdmit and MemberRevoke statements; §16's directory legs of FS-87, its plan's.

import (
	"fmt"
	"net/http"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// How many admissions a Team-scale schedule holds.
type FsKeysTeamSettings struct {
	// The live member devices reading the directory: past sidecar.GkmSeatCount by at least three, so one reads by
	// wraps, one signs as a wrapped device and one is admitted past them.
	MemberDeviceCount int
	// The tagged agents reading it, which hold no rank.
	AgentCount int
}

// Full scale: §20.4's 5,000 Team admissions.
func DefaultFsKeysTeamSettings() *FsKeysTeamSettings {
	return &FsKeysTeamSettings{MemberDeviceCount: 4900, AgentCount: 100}
}

// Reduced scale, which every test run takes: the least that holds a 1,001st device and two more.
func ReducedFsKeysTeamSettings() *FsKeysTeamSettings {
	return &FsKeysTeamSettings{MemberDeviceCount: sidecar.GkmSeatCount + 3, AgentCount: 2}
}

// A member device that uploads a ReaderKey and no KeyPackage: it reads by wraps until a leaf can add it.
func (self *FsKeysWorld) addWrappedMember(memberId sidecar.Id, label string) *FsKeysDevice {
	device := self.AddMemberOf(memberId, label)
	device.published = true
	return device
}

// Every device named holds the generation's key now, fetched from gkm at the newest state.
func (self *FsKeysWorld) holdGeneration(generation uint64, devices ...*FsKeysDevice) {
	self.t.Helper()
	for _, device := range devices {
		if device.Offline {
			// a device of the bulk takes the newest state for this read alone
			device.Take(self.Log.Tip())
		}
		if device.Mls != nil {
			// a leaf's epochs first: a leaf_wrap opens under its epoch's KEK
			self.Again(device.Label+"'s sync", func() error { return device.Client.SyncRepo(self.Ctx, self.RepoId) })
		}
		key, err := device.Client.RepoKey(self.Ctx, self.RepoId, generation)
		if err != nil || key.Generation() != generation {
			self.t.Fatalf("%s does not hold generation %d: %v", device.Label, generation, err)
		}
	}
}

// FS-87's key legs, and S4b's: see the file header.
func FsKeysScheduleDirectoryMemberRemoval(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_DIRECTORY)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	// a member device no leaf has added yet, and an agent: the wrapped readers
	w := world.addWrappedMember(world.MemberId, "w")
	g := world.AddAgent("g")
	leaving := world.NewMember()
	x := world.AddMemberOf(leaving, "x")
	y := world.AddMemberOf(leaving, "y")
	z := world.addWrappedMember(leaving, "z")
	// every sidecar of the team but a read_only one writes the directory
	world.Grant(true, a, b, w, g, x, y, z)
	world.Admin(a)
	world.Advance()
	for _, device := range []*FsKeysDevice{w, z} {
		device.PublishReaderKey()
	}
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	if labels := world.Roster(a); labels != "abxy" {
		t.Fatalf("the directory group's tree: %s", labels)
	}
	world.holdGeneration(1, a, b, w, g, x, y, z)
	epochBefore := world.NewestEpoch()

	// the MemberRevoke, which a signed: every device of the member at one position
	world.RevokeMember(leaving)
	for _, device := range []*FsKeysDevice{x, y, z} {
		world.VoidTokens(device)
	}
	view := world.Advance()
	world.Again("the signer's pending run", func() error { return a.Client.RunPending(world.Ctx, world.RepoId) })
	if epoch := world.NewestEpoch(); epoch != epochBefore+1 {
		t.Fatalf("the signer committed %d epochs for one MemberRevoke", epoch-epochBefore)
	}
	if labels := world.Roster(a); labels != "ab" {
		t.Errorf("the tree after the Removes: %s", labels)
	}
	if count := world.GenerationCount(); count != 2 {
		t.Fatalf("%d generations after the MemberRevoke", count)
	}
	generation2 := world.Generation(2)
	if sidecar.GkmCause(generation2.Rotate.GetCause()) != sidecar.GkmCauseRemove || generation2.SignerId != a.SidecarId() {
		t.Errorf("generation 2: cause %d, signed by %s", generation2.Rotate.GetCause(), generation2.SignerId)
	}
	if generation2.Rotate.GetLeafWrap() == nil {
		t.Errorf("the rotation on the clean tree carries no leaf_wrap")
	}
	if !sidecar.GkmGatePasses(view, world.RepoId, generation2.Rotate.GetAuth(), world.GenerationTime(generation2), world.Clock.Now()) {
		t.Errorf("the gate does not reopen at the REMOVE generation")
	}
	// the rotation reaches the leaves by its leaf_wrap and the wrapped readers by their wraps
	recipients := world.WrapRecipients(2)
	for _, device := range []*FsKeysDevice{w, g} {
		if !recipients[device.SidecarId()] {
			t.Errorf("no ReaderWrap of generation 2 to %s", device.Label)
		}
	}
	for _, device := range []*FsKeysDevice{x, y, z} {
		if recipients[device.SidecarId()] {
			t.Errorf("a ReaderWrap of generation 2 to %s, a device of the removed member", device.Label)
		}
	}
	world.holdGeneration(2, a, b, w, g)
	world.AgreeOnEpoch(a, b)

	// a later generation, with the removed member's devices long gone from the state
	if _, err := b.Client.RotateRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("a later rotation: %v", err)
	}
	if count := world.GenerationCount(); count != 3 {
		t.Fatalf("%d generations after the later rotation", count)
	}
	recipients = world.WrapRecipients(3)
	for _, device := range []*FsKeysDevice{x, y, z} {
		if recipients[device.SidecarId()] {
			t.Errorf("a ReaderWrap of generation 3 to %s", device.Label)
		}
		// keeping its MLS state and every ReaderKey it signed, it opens nothing past the generation it held
		if reached := world.RemovedReach(device); reached != 1 {
			t.Errorf("%s reaches generation %d", device.Label, reached)
		}
		if status := world.RawStatus(device, http.MethodGet, world.groupPath("gen"), nil, world.repoScope("r")); status != http.StatusUnauthorized && status != http.StatusForbidden {
			t.Errorf("gkm answers %s's read of the generations with %d", device.Label, status)
		}
	}
	world.holdGeneration(3, a, b, w, g)
}

// S3b's key part: see the file header.
func FsKeysScheduleDirectoryMemberAdd(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_DIRECTORY)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	world.Grant(true, a, b)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	epochBefore := world.NewestEpoch()

	// the MemberAdmit, which b signed: a device that uploads KeyPackages and one that uploads only its ReaderKey;
	// and a device of a member the directory's readers do not hold
	joining := world.NewMember()
	p := world.AddMemberOf(joining, "p")
	q := world.addWrappedMember(joining, "q")
	outsider := world.AddMemberOf(world.NewMember(), "o")
	for _, device := range []*FsKeysDevice{p, q, outsider} {
		device.row.AdmissionSigners = [][]byte{b.SidecarId().Bytes()}
	}
	world.Grant(true, p, q)
	world.Advance()
	// the outsider's ReaderKey stands at gkm too, so only the reader list keeps a wrap from it
	for _, device := range []*FsKeysDevice{q, outsider} {
		device.PublishReaderKey()
	}
	world.Publish()

	// b signed the admission: it is the granting device and acts at once, where a waits
	if _, granting, err := b.Client.Pending(world.Ctx, world.RepoId); err != nil || !granting || b.Client.PendingCommitWait(granting) != 0 {
		t.Fatalf("the admission's signer is not the granting device: %v", err)
	}
	if _, granting, err := a.Client.Pending(world.Ctx, world.RepoId); err != nil || granting || a.Client.PendingCommitWait(granting) <= 0 {
		t.Fatalf("a leaf that signed nothing does not wait: %v", err)
	}
	world.AddPending(b)
	if epoch := world.NewestEpoch(); epoch != epochBefore+1 {
		t.Fatalf("the signer committed %d epochs for one MemberAdmit", epoch-epochBefore)
	}
	if labels := world.Roster(b); labels != "abp" {
		t.Errorf("the tree after the Add: %s", labels)
	}
	if err := b.Client.DeliverFirstWrap(world.Ctx, world.RepoId, q.SidecarId()); err != nil {
		t.Fatalf("the signer's first wrap to the device with no KeyPackage: %v", err)
	}
	world.holdGeneration(1, a, b, p, q)
	if world.NewestEpoch() != epochBefore+1 {
		t.Errorf("the first wrap took a commit")
	}
	// Adds and wraps only for readers
	if recipients := world.WrapRecipients(1); recipients[outsider.SidecarId()] {
		t.Errorf("a ReaderWrap to a device that does not read the directory")
	}
	// the signer's own check wraps to no device its state does not show reading, whatever the flow answers
	b.Client.DeliverFirstWrap(world.Ctx, world.RepoId, outsider.SidecarId())
	if recipients := world.WrapRecipients(1); recipients[outsider.SidecarId()] {
		t.Errorf("gkm holds a ReaderWrap to a device that does not read the directory")
	}
	if _, err := outsider.Client.CurrentRepoKey(world.Ctx, world.RepoId); err == nil {
		t.Errorf("a device that does not read the directory holds its key")
	}
	world.AgreeOnEpoch(a, b, p)
}

// §22.7's seats row at settings' scale: see the file header.
func FsKeysScheduleTeamSeats(t FsKeysT, newWorld FsKeysNewWorld, settings *FsKeysTeamSettings) {
	if settings.MemberDeviceCount < sidecar.GkmSeatCount+3 {
		t.Fatalf("%d member devices hold no 1,001st and two more", settings.MemberDeviceCount)
	}
	world := newWorld(protocol.RepoKind_REPO_KIND_DIRECTORY)
	// the rank: a, b and c first, the bulk through the 1,000th, then w, the 1,001st, and the bulk past it
	rank := uint64(0)
	ranked := func(device *FsKeysDevice) *FsKeysDevice {
		rank += 1
		device.row.LiveSince = rank
		return device
	}
	a := ranked(world.AddMember("a", false))
	b := ranked(world.AddMember("b", false))
	c := ranked(world.AddMember("c", false))
	bulk := []*FsKeysDevice{}
	addBulk := func(count int) {
		for range count {
			device := ranked(world.addWrappedMember(world.MemberId, fmt.Sprintf("m%d", len(bulk))))
			// it runs no flow, and takes no state
			device.Offline = true
			bulk = append(bulk, device)
		}
	}
	addBulk(sidecar.GkmSeatCount - 3)
	w := ranked(world.addWrappedMember(world.MemberId, "w"))
	// the last two admissions come later: v, which w admits, and u, whose Add members refuse
	addBulk(settings.MemberDeviceCount - sidecar.GkmSeatCount - 3)
	agents := []*FsKeysDevice{}
	for index := range settings.AgentCount {
		agent := world.AddAgent(fmt.Sprintf("g%d", index))
		agent.Offline = true
		agents = append(agents, agent)
	}
	everyone := append(append([]*FsKeysDevice{a, b, c, w}, bulk...), agents...)
	world.Grant(true, everyone...)
	world.Admin(a)
	first := world.Advance()
	for _, device := range append(append([]*FsKeysDevice{w}, bulk...), agents...) {
		device.PublishReaderKey()
		device.published = true
	}
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	if labels := world.Roster(a); labels != "abc" {
		t.Fatalf("the directory group's tree: %s", labels)
	}
	admissionCount := len(everyone)

	// the 1,001st live member device reads the directory by its ReaderWrap at once, with no commit; no admission
	// meets a member-device cap
	if !sidecar.GkmLeafEntitled(first, world.RepoId, bulk[sidecar.GkmSeatCount-4].SidecarId(), world.Clock.Now()) || sidecar.GkmLeafEntitled(first, world.RepoId, w.SidecarId(), world.Clock.Now()) {
		t.Fatalf("the 1,000th device is not leaf-entitled, or the 1,001st is")
	}
	recipients := world.WrapRecipients(1)
	if len(recipients) != admissionCount-1 {
		t.Errorf("generation 1 holds %d ReaderWraps for %d admissions beside its creator", len(recipients), admissionCount)
	}
	epochBefore := world.NewestEpoch()
	world.holdGeneration(1, w, bulk[len(bulk)-1], agents[0])
	if world.NewestEpoch() != epochBefore {
		t.Errorf("the 1,001st device's read took a commit")
	}

	// a wrapped device that signed an admission writes the new device's first wrap
	v := ranked(world.addWrappedMember(world.MemberId, "v"))
	v.row.AdmissionSigners = [][]byte{w.SidecarId().Bytes()}
	world.Grant(true, v)
	world.Advance()
	v.PublishReaderKey()
	if err := w.Client.DeliverFirstWrap(world.Ctx, world.RepoId, v.SidecarId()); err != nil {
		t.Fatalf("the wrapped signer's first wrap: %v", err)
	}
	world.holdGeneration(1, v)
	if world.NewestEpoch() != epochBefore {
		t.Errorf("a wrapped signer's first wrap took a commit")
	}
	admissionCount += 1

	// a wrapped device that signed a revocation rotates, and the next leaf commit removes the leaf target
	world.Revoke(c)
	world.VoidTokens(c)
	second := world.Advance()
	key2, err := w.Client.EnsureWritable(world.Ctx, world.RepoId)
	if err != nil {
		t.Fatalf("the wrapped revoker's rotation: %v", err)
	}
	generation2 := world.Generation(2)
	if key2.Generation() != 2 || sidecar.GkmCause(generation2.Rotate.GetCause()) != sidecar.GkmCauseRemove || generation2.SignerId != w.SidecarId() {
		t.Fatalf("the wrapped revoker's rotation is generation %d, cause %d", key2.Generation(), generation2.Rotate.GetCause())
	}
	if generation2.Rotate.GetLeafWrap() != nil {
		t.Errorf("a rotator that is no leaf wrote a leaf_wrap")
	}
	if !sidecar.GkmGatePasses(second, world.RepoId, generation2.Rotate.GetAuth(), world.GenerationTime(generation2), world.Clock.Now()) {
		t.Errorf("the gate does not reopen at the wrapped revoker's generation")
	}
	if world.NewestEpoch() != epochBefore {
		t.Errorf("a wrapped revoker committed")
	}
	// a wrapped rotator wraps to every holder but itself, the tree's leaves too
	recipients = world.WrapRecipients(2)
	if recipients[c.SidecarId()] {
		t.Fatalf("a ReaderWrap of generation 2 to the revoked leaf")
	}
	if len(recipients) != admissionCount-2 {
		t.Errorf("the wrapped rotator's generation holds %d ReaderWraps for %d holders beside it", len(recipients), admissionCount-2)
	}
	for _, device := range []*FsKeysDevice{a, b, v, bulk[0], agents[0]} {
		if !recipients[device.SidecarId()] {
			t.Errorf("no ReaderWrap of generation 2 to %s", device.Label)
		}
	}
	// the leaf takes generation 2 by its ReaderWrap first: its commit carries gen/'s newest
	world.Again("the next leaf's sync", func() error { return a.Client.SyncRepo(world.Ctx, world.RepoId) })
	world.Again("the next leaf's pending run", func() error { return a.Client.RunPending(world.Ctx, world.RepoId) })
	if world.NewestEpoch() != epochBefore+1 {
		t.Fatalf("the next leaf committed %d epochs for the Remove", world.NewestEpoch()-epochBefore)
	}
	if labels := world.Roster(a); labels != "ab" {
		t.Errorf("the tree after the Remove: %s", labels)
	}
	if reached := world.RemovedReach(c); reached != 1 {
		t.Errorf("the revoked leaf reaches generation %d", reached)
	}

	// the move: the 1,001st is now among the first 1,000, keeps its wraps until a leaf adds it, and nothing shrinks
	if !sidecar.GkmLeafEntitled(second, world.RepoId, w.SidecarId(), world.Clock.Now()) || sidecar.GkmLeafEntitled(second, world.RepoId, v.SidecarId(), world.Clock.Now()) {
		t.Fatalf("the revocation moved no entitlement to the first wrapped device, or one past it")
	}
	generationCount := world.GenerationCount()
	if _, err := b.Client.EnsureWritable(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("a leaf's write after the move: %v", err)
	}
	if world.GenerationCount() != generationCount {
		t.Errorf("the move closed the gate: %d generations", world.GenerationCount())
	}
	// a leaf's rotation serves the tree by its leaf_wrap and wraps to every holder outside it
	if _, err := b.Client.RotateRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("a leaf's rotation: %v", err)
	}
	newest := uint64(world.GenerationCount())
	if generation := world.Generation(newest); generation.Rotate.GetLeafWrap() == nil {
		t.Errorf("a leaf's rotation carries no leaf_wrap")
	}
	recipients = world.WrapRecipients(newest)
	if recipients[a.SidecarId()] || recipients[b.SidecarId()] || !recipients[w.SidecarId()] || recipients[c.SidecarId()] {
		t.Errorf("a leaf's rotation wraps to the tree, to the revoked leaf, or not to the entitled device no leaf added")
	}
	if len(recipients) != admissionCount-3 {
		t.Errorf("a leaf's generation holds %d ReaderWraps for %d holders outside the tree", len(recipients), admissionCount-3)
	}
	world.holdGeneration(newest, a, b, w, v, bulk[len(bulk)-1], agents[len(agents)-1])

	// a leaf adds the entitled device once it has a KeyPackage, and its wraps end
	w.PublishKeyPackages()
	world.AddPending(a)
	if labels := world.Roster(a); labels != "abw" {
		t.Fatalf("the tree after the entitled device's Add: %s", labels)
	}
	world.Again("b's sync", func() error { return b.Client.SyncRepo(world.Ctx, world.RepoId) })
	if _, err := b.Client.RotateRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("a leaf's rotation past the Add: %v", err)
	}
	newest = uint64(world.GenerationCount())
	if recipients = world.WrapRecipients(newest); recipients[w.SidecarId()] || !recipients[v.SidecarId()] {
		t.Errorf("the rotation past the Add wraps to the new leaf, or not to the device past the first 1,000")
	}
	world.holdGeneration(newest, a, b, w, v)
	world.AgreeOnEpoch(a, b, w)

	// members refuse a leaf's Add of a device past the first 1,000; gkm, which reads no tree, takes the commit
	keyPackage, err := v.Mls.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	epoch := world.NewestEpoch()
	if status := world.InjectCommit(b, newest, [][]byte{keyPackage.Encoded}); status != http.StatusOK {
		t.Fatalf("gkm refused a commit it cannot see into: %d", status)
	}
	for _, member := range []*FsKeysDevice{a, w} {
		// the sync takes the commit as refused, whatever it answers
		member.Client.SyncRepo(world.Ctx, world.RepoId)
		if !member.RefusedBy(b) {
			t.Errorf("%s raised no refusal naming the committer: %+v", member.Label, member.Alarms)
		}
		group, err := member.Mls.LoadGroup(world.GroupId)
		if err != nil || group.Epoch() != epoch {
			t.Errorf("%s adopted the Add of a device past the first 1,000: %v", member.Label, err)
		}
	}
	if labels := world.Roster(a); labels != "abw" {
		t.Errorf("a member's tree holds a device past the first 1,000: %s", labels)
	}
}
