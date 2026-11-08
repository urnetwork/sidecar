// The conformance suite for sidecar.MlsEngine (§23.5): what gkm's client relies on of §10.4's subset, which
// sidecartest.FakeMls passes now and the real engine must pass when KEYS-M2-08 wires it in, so what was built on
// the fake keeps working on the real thing. It speaks only through the seam, and crafts by hand only messages the
// subset must refuse, whose bytes RFC 9420 §6 fixes.
//
// One rule waits on KEYS-M2-07: an external commit's header, which sidecar.ParseMlsHeader refuses outside the
// root's tests until a leaf carries credential 0xF552, so the suite reads the header of members' commits alone.
//
// A case is a plain function returning its first failure, and Run loops over them, since the cases are variations
// of one engine's behavior (connect/CODESTYLE.md:216). A failure in one does not stop the next.

package mlssuite

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Makes count engines of one test network, each its own sidecar, which read one another's KeyPackages, Welcomes and
// commits as gkm would carry them.
type NewEngines func(t *testing.T, count int) []sidecar.MlsEngine

type suiteCase struct {
	name string
	run  func(t *testing.T, newEngines NewEngines) error
}

// Runs every case on fresh engines.
func Run(t *testing.T, newEngines NewEngines) {
	t.Helper()
	for _, c := range []*suiteCase{
		{name: "create", run: caseCreate},
		{name: "welcome-join-takes-two-phases", run: caseWelcomeJoin},
		{name: "forged-group-info-joins-nothing", run: caseForgedGroupInfo},
		{name: "discard-keeps-the-epoch", run: caseDiscard},
		{name: "racing-commits-converge-on-the-winner", run: caseRace},
		{name: "remove-leaves-the-removed-with-nothing", run: caseRemove},
		{name: "commits-the-subset-refuses", run: caseRefusedCommits},
		{name: "messages-the-subset-refuses", run: caseRefusedMessages},
		{name: "a-commit-of-another-epoch", run: caseOtherEpoch},
		{name: "external-resync", run: caseExternalResync},
		{name: "key-packages", run: caseKeyPackages},
		{name: "a-replayed-welcome-moves-nothing", run: caseReplayedWelcome},
	} {
		if err := c.run(t, newEngines); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// The repo every group of the suite keys.
var suiteRepoId = sidecar.Id{0x52, 0x45, 0x50, 0x4f}

// ur_group for the suite's groups.
func suiteUrGroup() *sidecar.MlsUrGroup {
	return &sidecar.MlsUrGroup{
		NetworkId: sidecar.Id{0x4e, 0x45, 0x54},
		RepoId:    suiteRepoId,
		Kind:      protocol.RepoKind_REPO_KIND_GENERAL,
	}
}

// A fresh group id.
func suiteGroupId() sidecar.Id {
	var groupId sidecar.Id
	rand.Read(groupId[:])
	return groupId
}

// The authenticated_data a commit carries, distinct per call.
func suiteHeader(label string) []byte {
	return []byte("GkmCommitHeader " + label)
}

// Whether two exporters give the same KEK, which only members of one epoch do.
func sameKek(first sidecar.MlsExporter, second sidecar.MlsExporter) error {
	firstKek, err := sidecar.MlsKek(first, suiteRepoId)
	if err != nil {
		return err
	}
	secondKek, err := sidecar.MlsKek(second, suiteRepoId)
	if err != nil {
		return err
	}
	if !bytes.Equal(firstKek, secondKek) {
		return errors.New("two members of one epoch derive different KEKs")
	}
	return nil
}

// A creator's group with joiners added by one Add-only commit, every member at epoch 1.
func suiteGroup(t *testing.T, engines []sidecar.MlsEngine) ([]sidecar.MlsGroup, error) {
	group, err := engines[0].CreateGroup(suiteGroupId(), suiteUrGroup())
	if err != nil {
		return nil, err
	}
	if len(engines) == 1 {
		return []sidecar.MlsGroup{group}, nil
	}
	adds := [][]byte{}
	for _, engine := range engines[1:] {
		keyPackage, err := engine.CreateKeyPackage(false)
		if err != nil {
			return nil, err
		}
		adds = append(adds, keyPackage.Encoded)
	}
	staged, err := group.Commit(&sidecar.MlsCommitArgs{Adds: adds, AuthenticatedData: suiteHeader("add")})
	if err != nil {
		return nil, err
	}
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		return nil, err
	}
	welcome := staged.Welcome()
	if welcome == nil {
		return nil, errors.New("an Add left no Welcome")
	}
	adopted, err := staged.Adopt()
	if err != nil {
		return nil, err
	}
	groups := []sidecar.MlsGroup{adopted}
	for _, engine := range engines[1:] {
		pending, err := engine.JoinWelcome(welcome)
		if err != nil {
			return nil, err
		}
		joined, err := pending.Complete(groupInfo)
		if err != nil {
			return nil, err
		}
		groups = append(groups, joined)
	}
	return groups, nil
}

func caseCreate(t *testing.T, newEngines NewEngines) error {
	engine := newEngines(t, 1)[0]
	groupId := suiteGroupId()
	group, err := engine.CreateGroup(groupId, suiteUrGroup())
	if err != nil {
		return err
	}
	if group.GroupId() != groupId || group.Epoch() != 0 {
		return fmt.Errorf("group %s at epoch %d", group.GroupId(), group.Epoch())
	}
	roster := group.Roster()
	if len(roster) != 1 || roster[0].SidecarId != group.Self().SidecarId {
		return fmt.Errorf("a new group's roster %v", roster)
	}
	loaded, err := engine.LoadGroup(groupId)
	if err != nil {
		return err
	}
	if loaded.Epoch() != 0 || !bytes.Equal(loaded.EpochAuthenticator(), group.EpochAuthenticator()) {
		return errors.New("the loaded group is another")
	}
	if err := sameKek(group, loaded); err != nil {
		return err
	}
	if _, err := engine.LoadGroup(suiteGroupId()); !errors.Is(err, sidecar.ErrMlsGroupUnknown) {
		return fmt.Errorf("loading a group never joined: %v", err)
	}
	return nil
}

func caseWelcomeJoin(t *testing.T, newEngines NewEngines) error {
	engines := newEngines(t, 2)
	group, err := engines[0].CreateGroup(suiteGroupId(), suiteUrGroup())
	if err != nil {
		return err
	}
	keyPackage, err := engines[1].CreateKeyPackage(false)
	if err != nil {
		return err
	}
	staged, err := group.Commit(&sidecar.MlsCommitArgs{Adds: [][]byte{keyPackage.Encoded}, AuthenticatedData: suiteHeader("add")})
	if err != nil {
		return err
	}
	if staged.Epoch() != 1 || len(staged.Added()) != 1 {
		return fmt.Errorf("an Add to epoch %d adding %d", staged.Epoch(), len(staged.Added()))
	}
	header, err := sidecar.ParseMlsHeader(staged.Message())
	if err != nil {
		return fmt.Errorf("gkm cannot read the commit's header: %w", err)
	}
	if !bytes.Equal(header.GroupId, group.GroupId().Bytes()) || header.Epoch != 0 || header.ContentType != 3 ||
		!bytes.Equal(header.AuthenticatedData, suiteHeader("add")) {
		return fmt.Errorf("the commit's clear header %+v", header)
	}
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		return err
	}
	adopted, err := staged.Adopt()
	if err != nil {
		return err
	}

	pending, err := engines[1].JoinWelcome(staged.Welcome())
	if err != nil {
		return err
	}
	if pending.GroupId() != group.GroupId() || pending.Epoch() != 1 {
		return fmt.Errorf("a pending join of %s at %d", pending.GroupId(), pending.Epoch())
	}
	// Phase one gives KEK_1, which opens GenWrap_1, before any tree is held.
	if err := sameKek(pending, adopted); err != nil {
		return err
	}
	if _, err := engines[1].LoadGroup(group.GroupId()); !errors.Is(err, sidecar.ErrMlsGroupUnknown) {
		return fmt.Errorf("a joiner holds the group before phase two: %v", err)
	}
	joined, err := pending.Complete(groupInfo)
	if err != nil {
		return err
	}
	if joined.Epoch() != 1 || !bytes.Equal(joined.EpochAuthenticator(), adopted.EpochAuthenticator()) {
		return errors.New("the joiner's epoch is another")
	}
	if len(joined.Roster()) != 2 || len(adopted.Roster()) != 2 {
		return fmt.Errorf("rosters of %d and %d", len(joined.Roster()), len(adopted.Roster()))
	}
	return sameKek(joined, adopted)
}

func caseForgedGroupInfo(t *testing.T, newEngines NewEngines) error {
	engines := newEngines(t, 2)
	group, err := engines[0].CreateGroup(suiteGroupId(), suiteUrGroup())
	if err != nil {
		return err
	}
	olderGroupInfo, err := group.GroupInfo()
	if err != nil {
		return err
	}
	keyPackage, err := engines[1].CreateKeyPackage(false)
	if err != nil {
		return err
	}
	staged, err := group.Commit(&sidecar.MlsCommitArgs{Adds: [][]byte{keyPackage.Encoded}, AuthenticatedData: suiteHeader("add")})
	if err != nil {
		return err
	}
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		return err
	}
	if _, err := staged.Adopt(); err != nil {
		return err
	}
	pending, err := engines[1].JoinWelcome(staged.Welcome())
	if err != nil {
		return err
	}
	forged := bytes.Clone(groupInfo)
	forged[len(forged)-1] ^= 1
	if _, err := pending.Complete(forged); err == nil {
		return errors.New("a forged GroupInfo completed a join")
	}
	if _, err := pending.Complete(olderGroupInfo); err == nil {
		return errors.New("another epoch's GroupInfo completed a join")
	}
	if _, err := engines[1].LoadGroup(group.GroupId()); !errors.Is(err, sidecar.ErrMlsGroupUnknown) {
		return fmt.Errorf("a refused join left a group: %v", err)
	}
	if _, err := pending.Complete(groupInfo); err != nil {
		return fmt.Errorf("the true GroupInfo after refusals: %w", err)
	}
	return nil
}

func caseDiscard(t *testing.T, newEngines NewEngines) error {
	engine := newEngines(t, 1)[0]
	group, err := engine.CreateGroup(suiteGroupId(), suiteUrGroup())
	if err != nil {
		return err
	}
	before, err := sidecar.MlsKek(group, suiteRepoId)
	if err != nil {
		return err
	}
	staged, err := group.Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: suiteHeader("self-update")})
	if err != nil {
		return err
	}
	staged.Discard()
	loaded, err := engine.LoadGroup(group.GroupId())
	if err != nil {
		return err
	}
	after, err := sidecar.MlsKek(loaded, suiteRepoId)
	if err != nil {
		return err
	}
	if loaded.Epoch() != 0 || !bytes.Equal(before, after) {
		return errors.New("a discarded commit moved the group")
	}
	return nil
}

func caseRace(t *testing.T, newEngines NewEngines) error {
	groups, err := suiteGroup(t, newEngines(t, 2))
	if err != nil {
		return err
	}
	winner, err := groups[0].Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: suiteHeader("winner")})
	if err != nil {
		return err
	}
	loser, err := groups[1].Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: suiteHeader("loser")})
	if err != nil {
		return err
	}
	// gkm took the winner's epoch object, so its committer adopts and the loser discards and processes it (KF6).
	adopted, err := winner.Adopt()
	if err != nil {
		return err
	}
	loser.Discard()
	processed, err := groups[1].Process(winner.Message())
	if err != nil {
		return err
	}
	if processed.Committer().SidecarId != groups[0].Self().SidecarId || !bytes.Equal(processed.AuthenticatedData(), suiteHeader("winner")) {
		return errors.New("the processed commit is not the winner's")
	}
	if processed.Welcome() != nil {
		return errors.New("a received commit carries a Welcome")
	}
	follower, err := processed.Adopt()
	if err != nil {
		return err
	}
	if follower.Epoch() != 2 || !bytes.Equal(follower.EpochAuthenticator(), adopted.EpochAuthenticator()) {
		return errors.New("the loser converged on another epoch")
	}
	return sameKek(follower, adopted)
}

func caseRemove(t *testing.T, newEngines NewEngines) error {
	engines := newEngines(t, 3)
	groups, err := suiteGroup(t, engines)
	if err != nil {
		return err
	}
	removedLeaf := groups[2].Self()
	staged, err := groups[0].Commit(&sidecar.MlsCommitArgs{Removes: []uint32{removedLeaf.LeafIndex}, Path: true, AuthenticatedData: suiteHeader("remove")})
	if err != nil {
		return err
	}
	if removed := staged.Removed(); len(removed) != 1 || removed[0].SidecarId != removedLeaf.SidecarId {
		return fmt.Errorf("the Remove removes %v", removed)
	}
	adopted, err := staged.Adopt()
	if err != nil {
		return err
	}
	processed, err := groups[1].Process(staged.Message())
	if err != nil {
		return err
	}
	if removed := processed.Removed(); len(removed) != 1 || removed[0].SidecarId != removedLeaf.SidecarId {
		return fmt.Errorf("a member reads the Remove as removing %v", removed)
	}
	follower, err := processed.Adopt()
	if err != nil {
		return err
	}
	if err := sameKek(follower, adopted); err != nil {
		return err
	}
	if slices.ContainsFunc(adopted.Roster(), func(member sidecar.MlsMember) bool { return member.SidecarId == removedLeaf.SidecarId }) {
		return errors.New("the removed leaf stays in the roster")
	}

	// The removed sidecar learns of its removal and derives nothing of the new epoch.
	removedView, err := groups[2].Process(staged.Message())
	if err != nil {
		return err
	}
	if _, err := sidecar.MlsKek(removedView, suiteRepoId); err == nil {
		return errors.New("a removed leaf derived the new epoch's KEK")
	}
	if _, err := removedView.Adopt(); !errors.Is(err, sidecar.ErrMlsNotMember) {
		return fmt.Errorf("a removed leaf adopted its removal: %v", err)
	}
	if _, err := engines[2].LoadGroup(groups[0].GroupId()); !errors.Is(err, sidecar.ErrMlsGroupUnknown) {
		return fmt.Errorf("a removed leaf still holds the group: %v", err)
	}
	if _, err := groups[2].Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: suiteHeader("removed")}); err == nil {
		return errors.New("a removed leaf committed")
	}
	return nil
}

func caseRefusedCommits(t *testing.T, newEngines NewEngines) error {
	groups, err := suiteGroup(t, newEngines(t, 2))
	if err != nil {
		return err
	}
	other := groups[1].Self().LeafIndex
	refusals := map[string]*sidecar.MlsCommitArgs{
		"a Remove without a path":     {Removes: []uint32{other}, AuthenticatedData: suiteHeader("remove")},
		"a committer removing itself": {Removes: []uint32{groups[0].Self().LeafIndex}, Path: true, AuthenticatedData: suiteHeader("self")},
		"a Remove of no leaf":         {Removes: []uint32{other + 7}, Path: true, AuthenticatedData: suiteHeader("none")},
		"an Add of no KeyPackage":     {Adds: [][]byte{[]byte("not a KeyPackage")}, AuthenticatedData: suiteHeader("add")},
		"an empty commit":             {AuthenticatedData: suiteHeader("empty")},
	}
	for name, args := range refusals {
		if _, err := groups[0].Commit(args); err == nil {
			return fmt.Errorf("%s was staged", name)
		}
	}
	if groups[0].Epoch() != 1 {
		return errors.New("a refused commit moved the group")
	}
	return nil
}

// An MLSMessage framed by hand as RFC 9420 §6 fixes it: a PrivateMessage of contentType at the group's epoch, whose
// sender data and ciphertext are noise, or a PublicMessage from senderType.
func suiteFrame(group sidecar.MlsGroup, wireFormat uint16, contentType uint8, senderType uint8) []byte {
	vector := func(encoded []byte, value []byte) []byte {
		return append(append(encoded, byte(len(value))), value...)
	}
	noise := make([]byte, 32)
	rand.Read(noise)
	encoded := binary.BigEndian.AppendUint16(nil, 1)
	encoded = binary.BigEndian.AppendUint16(encoded, wireFormat)
	encoded = vector(encoded, group.GroupId().Bytes())
	encoded = binary.BigEndian.AppendUint64(encoded, group.Epoch())
	if wireFormat == 1 {
		encoded = append(encoded, senderType)
		if senderType == 1 || senderType == 2 {
			encoded = binary.BigEndian.AppendUint32(encoded, 0)
		}
		encoded = vector(encoded, nil)
		encoded = append(encoded, contentType)
		return vector(encoded, noise)
	}
	encoded = append(encoded, contentType)
	encoded = vector(encoded, nil)
	encoded = vector(encoded, noise[:16])
	return vector(encoded, noise)
}

func caseRefusedMessages(t *testing.T, newEngines NewEngines) error {
	groups, err := suiteGroup(t, newEngines(t, 2))
	if err != nil {
		return err
	}
	refusals := map[string][]byte{
		"a standalone proposal, an Update's framing": suiteFrame(groups[0], 2, 2, 0),
		"application data":                           suiteFrame(groups[0], 2, 1, 0),
		"a member's PublicMessage":                   suiteFrame(groups[0], 1, 3, 1),
		"an external sender's proposal":              suiteFrame(groups[0], 1, 2, 2),
		"a new member's proposal":                    suiteFrame(groups[0], 1, 2, 3),
		"nothing":                                    {},
	}
	for name, message := range refusals {
		if _, err := groups[1].Process(message); err == nil {
			return fmt.Errorf("%s was staged", name)
		}
		if _, err := sidecar.ParseMlsHeader(message); err == nil {
			return fmt.Errorf("gkm read %s as a commit", name)
		}
	}
	return nil
}

func caseOtherEpoch(t *testing.T, newEngines NewEngines) error {
	groups, err := suiteGroup(t, newEngines(t, 3))
	if err != nil {
		return err
	}
	ahead, err := groups[0].Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: suiteHeader("ahead")})
	if err != nil {
		return err
	}
	if _, err := ahead.Adopt(); err != nil {
		return err
	}
	processed, err := groups[1].Process(ahead.Message())
	if err != nil {
		return err
	}
	if _, err := processed.Adopt(); err != nil {
		return err
	}
	// The third member, still at epoch 1, commits there: one at epoch 2 refuses it.
	stale, err := groups[2].Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: suiteHeader("stale")})
	if err != nil {
		return err
	}
	current, err := groups[1].Process(stale.Message())
	if err == nil {
		current.Discard()
		return errors.New("a commit of epoch 1 was staged at epoch 2")
	}
	return nil
}

func caseExternalResync(t *testing.T, newEngines NewEngines) error {
	engines := newEngines(t, 2)
	groups, err := suiteGroup(t, engines)
	if err != nil {
		return err
	}
	staleLeaf := groups[1].Self()
	ahead, err := groups[0].Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: suiteHeader("ahead")})
	if err != nil {
		return err
	}
	adopted, err := ahead.Adopt()
	if err != nil {
		return err
	}
	groupInfo, err := adopted.GroupInfo()
	if err != nil {
		return err
	}
	// The second member missed epoch 2 and resyncs from its GroupInfo, removing its own old leaf (KF5).
	if _, err := engines[1].JoinExternal(groupInfo, &sidecar.MlsCommitArgs{Removes: []uint32{groups[0].Self().LeafIndex}, Path: true, AuthenticatedData: suiteHeader("resync")}); err == nil {
		return errors.New("an external commit removed another's leaf")
	}
	external, err := engines[1].JoinExternal(groupInfo, &sidecar.MlsCommitArgs{Removes: []uint32{staleLeaf.LeafIndex}, Path: true, AuthenticatedData: suiteHeader("resync")})
	if err != nil {
		return err
	}
	if external.Epoch() != 3 {
		return fmt.Errorf("a resync to epoch %d", external.Epoch())
	}
	resynced, err := external.Adopt()
	if err != nil {
		return err
	}
	processed, err := adopted.Process(external.Message())
	if err != nil {
		return err
	}
	if processed.Committer().SidecarId != staleLeaf.SidecarId {
		return errors.New("the external commit names another committer")
	}
	follower, err := processed.Adopt()
	if err != nil {
		return err
	}
	if len(follower.Roster()) != 2 {
		return fmt.Errorf("a resync left %d leaves", len(follower.Roster()))
	}
	return sameKek(follower, resynced)
}

func caseKeyPackages(t *testing.T, newEngines NewEngines) error {
	engine := newEngines(t, 1)[0]
	first, err := engine.CreateKeyPackage(false)
	if err != nil {
		return err
	}
	second, err := engine.CreateKeyPackage(false)
	if err != nil {
		return err
	}
	lastResort, err := engine.CreateKeyPackage(true)
	if err != nil {
		return err
	}
	if bytes.Equal(first.Ref, second.Ref) || bytes.Equal(first.Encoded, second.Encoded) {
		return errors.New("two KeyPackages alike")
	}
	if first.LastResort || !lastResort.LastResort {
		return errors.New("last resort misreported")
	}
	if _, err := sidecar.ParseMlsHeader(first.Encoded); err == nil {
		return errors.New("gkm read a KeyPackage as a commit")
	}
	return nil
}

// Both phases of a Welcome join.
func suiteJoin(engine sidecar.MlsEngine, welcome []byte, groupInfo []byte) (sidecar.MlsGroup, error) {
	pending, err := engine.JoinWelcome(welcome)
	if err != nil {
		return nil, err
	}
	return pending.Complete(groupInfo)
}

// A server can replay any Welcome, so one moves nothing a second time (I-16). Under a one-time KeyPackage, which has
// joined, it joins nothing; under the last-resort one, which is kept, it never takes a held group back to its epoch;
// and neither rejoins after a removal leaves the group unheld. A one-time KeyPackage joins one group, even when a
// server handed it to two and both Welcomes were opened before either joined, and the last-resort one joins any
// number (RFC 9420 §16.8; §10.6's KeyPackages). A refusal at either phase will do.
func caseReplayedWelcome(t *testing.T, newEngines NewEngines) error {
	engines := newEngines(t, 3)
	creator, oneTimeJoiner, lastResortJoiner := engines[0], engines[1], engines[2]
	oneTime, err := oneTimeJoiner.CreateKeyPackage(false)
	if err != nil {
		return err
	}
	lastResort, err := lastResortJoiner.CreateKeyPackage(true)
	if err != nil {
		return err
	}
	// two groups, each adding both KeyPackages
	createds := []sidecar.MlsGroup{}
	welcomes := [][]byte{}
	groupInfos := [][]byte{}
	for _, label := range []string{"first", "second"} {
		group, err := creator.CreateGroup(suiteGroupId(), suiteUrGroup())
		if err != nil {
			return err
		}
		add, err := group.Commit(&sidecar.MlsCommitArgs{Adds: [][]byte{oneTime.Encoded, lastResort.Encoded}, AuthenticatedData: suiteHeader(label + " add")})
		if err != nil {
			return err
		}
		groupInfo, err := add.GroupInfo()
		if err != nil {
			return err
		}
		created, err := add.Adopt()
		if err != nil {
			return err
		}
		createds = append(createds, created)
		welcomes = append(welcomes, add.Welcome())
		groupInfos = append(groupInfos, groupInfo)
	}

	// the one-time KeyPackage opens both Welcomes and joins the first it completes alone
	pendings := []sidecar.MlsPendingJoin{}
	for _, welcome := range welcomes {
		pending, err := oneTimeJoiner.JoinWelcome(welcome)
		if err != nil {
			return err
		}
		pendings = append(pendings, pending)
	}
	oneTimeMember, err := pendings[0].Complete(groupInfos[0])
	if err != nil {
		return err
	}
	if _, err := pendings[1].Complete(groupInfos[1]); err == nil {
		return errors.New("a one-time KeyPackage joined a second group")
	}
	if _, err := oneTimeJoiner.LoadGroup(createds[1].GroupId()); !errors.Is(err, sidecar.ErrMlsGroupUnknown) {
		return fmt.Errorf("a refused second join left a group: %v", err)
	}
	lastResortMember, err := suiteJoin(lastResortJoiner, welcomes[0], groupInfos[0])
	if err != nil {
		return err
	}
	if _, err := suiteJoin(lastResortJoiner, welcomes[1], groupInfos[1]); err != nil {
		return fmt.Errorf("the last-resort KeyPackage joining a second group: %w", err)
	}

	// every member of the first group at epoch 2, then its epoch-1 Welcome again
	groupId := createds[0].GroupId()
	joiners := []sidecar.MlsEngine{oneTimeJoiner, lastResortJoiner}
	joined := []sidecar.MlsGroup{oneTimeMember, lastResortMember}
	update, err := createds[0].Commit(&sidecar.MlsCommitArgs{Path: true, AuthenticatedData: suiteHeader("update")})
	if err != nil {
		return err
	}
	current, err := update.Adopt()
	if err != nil {
		return err
	}
	for _, member := range joined {
		processed, err := member.Process(update.Message())
		if err != nil {
			return err
		}
		if _, err := processed.Adopt(); err != nil {
			return err
		}
	}
	for index, engine := range joiners {
		if _, err := suiteJoin(engine, welcomes[0], groupInfos[0]); err == nil {
			return fmt.Errorf("joiner %d took a replayed Welcome", index+1)
		}
		loaded, err := engine.LoadGroup(groupId)
		if err != nil {
			return err
		}
		if loaded.Epoch() != 2 {
			return fmt.Errorf("a replayed Welcome moved joiner %d's group to epoch %d", index+1, loaded.Epoch())
		}
	}

	// both removed, so neither holds the group, and the Welcome again
	removes := []uint32{}
	for _, member := range joined {
		removes = append(removes, member.Self().LeafIndex)
	}
	remove, err := current.Commit(&sidecar.MlsCommitArgs{Removes: removes, Path: true, AuthenticatedData: suiteHeader("remove")})
	if err != nil {
		return err
	}
	if _, err := remove.Adopt(); err != nil {
		return err
	}
	for index, engine := range joiners {
		member, err := engine.LoadGroup(groupId)
		if err != nil {
			return err
		}
		processed, err := member.Process(remove.Message())
		if err != nil {
			return err
		}
		if _, err := processed.Adopt(); !errors.Is(err, sidecar.ErrMlsNotMember) {
			return fmt.Errorf("joiner %d adopted its removal: %v", index+1, err)
		}
		if _, err := suiteJoin(engine, welcomes[0], groupInfos[0]); err == nil {
			return fmt.Errorf("joiner %d took a replayed Welcome after its removal", index+1)
		}
		if _, err := engine.LoadGroup(groupId); !errors.Is(err, sidecar.ErrMlsGroupUnknown) {
			return fmt.Errorf("a replayed Welcome left removed joiner %d a group: %v", index+1, err)
		}
	}
	return nil
}
