// QD-1178's unjudged statements held to what needs no state at their pin: a statement pinned before what the reader
// retains is not judged at a state the reader no longer holds, and is still held to every rule of §11.8's refs table
// that refuses it whatever rights its signer held at that pin (evsCheckRefRulesUnjudged). A deposit or erasure ref whose
// id is not derived as the rules say, a deposit another sidecar signed, a CONSUME or BASE that writes, an owned ref
// another sidecar signed outside an admin's BASE or CLOSURE of a stream, and a creates-only ref's removal or write on a
// base refuse as they do at a judged pin, on the stand-in config and on a new device whose log starts at the newest
// base. The rules that ask the signer a right at its pin, who writes the repo and who administers it, are not judged, so
// a statement only they refuse reads, and a well-formed statement reads, on a walk as alone.

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a table statement's changes do.
type evsUnjudgedChangeShape int

const (
	// One change, creating its path on base 0.
	evsUnjudgedCreation evsUnjudgedChangeShape = iota
	// One change, writing its path on base 2, its entry not at hand to a statement read alone.
	evsUnjudgedWriteOnBase
	// One change, removing its path at 3.
	evsUnjudgedRemoval
	// A creation beside a removal at 1.
	evsUnjudgedRemovalAndCreation
)

// Whether err is the refusal want names, ErrEvsStatementRefused ending in its reason, or for an empty want no error.
func evsTestRefusedFor(err error, want string) bool {
	if want == "" {
		return err == nil
	}
	return errors.Is(err, ErrEvsStatementRefused) && strings.HasSuffix(err.Error(), ": "+want)
}

// Each rule of the refs table a statement read alone meets, through VerifyStatement on the stand-in config, judged at
// the statement's pin and unjudged (QD-1178): a rule that refuses whatever rights the signer held there refuses both
// ways, in the same words, and one that asks the signer a right there refuses only judged. An admin's BASE of its own
// stream that creates is the one rule that turns on admin both ways, removals alone for an admin and creations alone for
// anyone else, so unjudged it is refused only where both refuse. The signers: a stream owner and a writer, which write
// the repo, an admin, which writes and administers it, and an outsider and two depositors, which the state admits and
// gives no right.
func TestEvsUnjudgedStatementHeldToTheRefRulesNoRightExcuses(t *testing.T) {
	world := newEvsTestWorld(t)
	owner, admin, writer := newEvsTestSigner("stream owner"), newEvsTestSigner("repo admin"), newEvsTestSigner("writer")
	outsider, depositor, other := newEvsTestSigner("outsider"), newEvsTestSigner("depositor"), newEvsTestSigner("other depositor")
	func() {
		world.config.stateLock.Lock()
		defer world.config.stateLock.Unlock()
		for _, signer := range []*evsTestSigner{owner, admin, writer, outsider, depositor, other} {
			world.config.identityKeys[signer.sidecarId] = signer.publicKey()
		}
		world.config.writers = []Id{owner.sidecarId, admin.sidecarId, writer.sidecarId}
	}()
	repoId := world.repoId
	depositRefId, erasureRefId := EvsDepositRefId(repoId, depositor.sidecarId), EvsErasureRefId(repoId)
	anotherRepoId := evsTestId("another repo")
	general, record := protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_RECORD
	shared, owned := protocol.EvsRefKind_EVS_REF_SHARED, protocol.EvsRefKind_EVS_REF_OWNED
	deposit, erasure := protocol.EvsRefKind_EVS_REF_DEPOSIT, protocol.EvsRefKind_EVS_REF_ERASURE
	idOf := func(signer *evsTestSigner) *Id {
		sidecarId := signer.sidecarId
		return &sidecarId
	}
	cases := []struct {
		label   string
		kind    protocol.RepoKind
		signer  *evsTestSigner
		refKind protocol.EvsRefKind
		refId   Id
		owner   *Id
		flags   protocol.EvsPushFlag
		change  evsUnjudgedChangeShape
		// the state holds no row of the repo
		noRepo bool
		// the refusal's reason judged at the pin and unjudged, empty for a statement taken
		judged   string
		unjudged string
	}{
		// deposit refs
		{label: "a deposit at its depositor's id by its depositor", kind: general, signer: depositor, refKind: deposit, refId: depositRefId, owner: idOf(depositor)},
		{label: "a deposit at another depositor's id", kind: general, signer: depositor, refKind: deposit, refId: EvsDepositRefId(repoId, other.sidecarId), owner: idOf(depositor),
			judged: "a deposit ref not its depositor's", unjudged: "a deposit ref not its depositor's"},
		{label: "a deposit at its depositor's id in another repo", kind: general, signer: depositor, refKind: deposit, refId: EvsDepositRefId(anotherRepoId, depositor.sidecarId), owner: idOf(depositor),
			judged: "a deposit ref not its depositor's", unjudged: "a deposit ref not its depositor's"},
		{label: "a deposit at the main ref's id", kind: general, signer: depositor, refKind: deposit, refId: world.refId, owner: idOf(depositor),
			judged: "a deposit ref not its depositor's", unjudged: "a deposit ref not its depositor's"},
		{label: "a deposit naming no depositor", kind: general, signer: depositor, refKind: deposit, refId: depositRefId,
			judged: "a deposit ref not its depositor's", unjudged: "a deposit ref not its depositor's"},
		{label: "a deposit signed by another sidecar", kind: general, signer: outsider, refKind: deposit, refId: depositRefId, owner: idOf(depositor),
			judged: "a deposit signed by another sidecar", unjudged: "a deposit signed by another sidecar"},
		{label: "a deposit written on a base", kind: general, signer: depositor, refKind: deposit, refId: depositRefId, owner: idOf(depositor), change: evsUnjudgedWriteOnBase,
			judged: "a creates-only ref's change: a write on a base", unjudged: "a creates-only ref's change: a write on a base"},
		{label: "a deposit's removal outside a CONSUME", kind: general, signer: depositor, refKind: deposit, refId: depositRefId, owner: idOf(depositor), change: evsUnjudgedRemoval,
			judged: "a creates-only ref's change: a removal", unjudged: "a creates-only ref's change: a removal"},
		{label: "a deposit's FORCE", kind: general, signer: depositor, refKind: deposit, refId: depositRefId, owner: idOf(depositor), flags: protocol.EvsPushFlag_EVS_PUSH_FORCE,
			judged: "FORCE or DELETE on a creates-only ref", unjudged: "FORCE or DELETE on a creates-only ref"},
		{label: "a CONSUME's removals by a writer", kind: general, signer: writer, refKind: deposit, refId: depositRefId, owner: idOf(depositor), flags: protocol.EvsPushFlag_EVS_PUSH_CONSUME, change: evsUnjudgedRemoval},
		{label: "a CONSUME that writes", kind: general, signer: writer, refKind: deposit, refId: depositRefId, owner: idOf(depositor), flags: protocol.EvsPushFlag_EVS_PUSH_CONSUME,
			judged: "a CONSUME that writes", unjudged: "a CONSUME that writes"},
		{label: "a CONSUME by a sidecar that does not write the repo", kind: general, signer: outsider, refKind: deposit, refId: depositRefId, owner: idOf(depositor), flags: protocol.EvsPushFlag_EVS_PUSH_CONSUME, change: evsUnjudgedRemoval,
			judged: "a CONSUME by a sidecar that does not write the repo"},
		// the erasure ref
		{label: "an erasure push by an admin", kind: record, signer: admin, refKind: erasure, refId: erasureRefId},
		{label: "an erasure push by a sidecar that is no admin", kind: record, signer: writer, refKind: erasure, refId: erasureRefId,
			judged: "an erasure push by a non-admin"},
		{label: "an erasure push at another repo's erasure id", kind: record, signer: admin, refKind: erasure, refId: EvsErasureRefId(anotherRepoId),
			judged: "an erasure ref at another id", unjudged: "an erasure ref at another id"},
		{label: "an erasure push at the main ref's id", kind: record, signer: admin, refKind: erasure, refId: world.refId,
			judged: "an erasure ref at another id", unjudged: "an erasure ref at another id"},
		{label: "an erasure push written on a base", kind: record, signer: admin, refKind: erasure, refId: erasureRefId, change: evsUnjudgedWriteOnBase,
			judged: "a creates-only ref's change: a write on a base", unjudged: "a creates-only ref's change: a write on a base"},
		// shared refs
		{label: "a shared ref's write by a writer", kind: general, signer: writer, refKind: shared, refId: world.refId},
		{label: "a shared ref's write by a sidecar the state does not list", kind: general, signer: outsider, refKind: shared, refId: world.refId,
			judged: "a shared ref's writer the state does not list"},
		{label: "a FORCE on a shared ref by a writer that is no admin", kind: general, signer: writer, refKind: shared, refId: world.refId, flags: protocol.EvsPushFlag_EVS_PUSH_FORCE,
			judged: "FORCE or DELETE on a shared ref by a non-admin"},
		// owned refs in a general repo
		{label: "an owned ref's write by its owner", kind: general, signer: owner, refKind: owned, refId: world.refId, owner: idOf(owner)},
		{label: "an owned ref's write by its owner, which no longer writes the repo", kind: general, signer: outsider, refKind: owned, refId: world.refId, owner: idOf(outsider),
			judged: "an owned ref's sidecar no longer writes the repo"},
		{label: "an owned ref signed by another sidecar", kind: general, signer: writer, refKind: owned, refId: world.refId, owner: idOf(owner),
			judged: "an owned ref signed by another sidecar", unjudged: "an owned ref signed by another sidecar"},
		{label: "an owned ref naming no owner", kind: general, signer: owner, refKind: owned, refId: world.refId,
			judged: "an owned ref signed by another sidecar", unjudged: "an owned ref signed by another sidecar"},
		{label: "an admin's BASE of another's owned ref in a general repo", kind: general, signer: admin, refKind: owned, refId: world.refId, owner: idOf(owner), flags: protocol.EvsPushFlag_EVS_PUSH_BASE, change: evsUnjudgedRemoval,
			judged: "an owned ref signed by another sidecar", unjudged: "an owned ref signed by another sidecar"},
		// record-class streams
		{label: "a stream's creation by its owner", kind: record, signer: owner, refKind: owned, refId: world.refId, owner: idOf(owner)},
		{label: "a stream owner's write on a base, its entry not at hand", kind: record, signer: owner, refKind: owned, refId: world.refId, owner: idOf(owner), change: evsUnjudgedWriteOnBase},
		{label: "a stream owner's removal", kind: record, signer: owner, refKind: owned, refId: world.refId, owner: idOf(owner), change: evsUnjudgedRemoval,
			judged: "a creates-only ref's change: a removal", unjudged: "a creates-only ref's change: a removal"},
		{label: "a stream owner's FORCE", kind: record, signer: owner, refKind: owned, refId: world.refId, owner: idOf(owner), flags: protocol.EvsPushFlag_EVS_PUSH_FORCE,
			judged: "FORCE or DELETE on a creates-only ref", unjudged: "FORCE or DELETE on a creates-only ref"},
		{label: "an admin's BASE of another's stream, removals alone", kind: record, signer: admin, refKind: owned, refId: world.refId, owner: idOf(owner), flags: protocol.EvsPushFlag_EVS_PUSH_BASE, change: evsUnjudgedRemoval},
		{label: "an admin's BASE of another's stream that writes", kind: record, signer: admin, refKind: owned, refId: world.refId, owner: idOf(owner), flags: protocol.EvsPushFlag_EVS_PUSH_BASE,
			judged: "a BASE that writes", unjudged: "a BASE that writes"},
		{label: "a BASE of another's stream by a sidecar that is no admin", kind: record, signer: writer, refKind: owned, refId: world.refId, owner: idOf(owner), flags: protocol.EvsPushFlag_EVS_PUSH_BASE, change: evsUnjudgedRemoval,
			judged: "an owned ref signed by another sidecar"},
		{label: "a CLOSURE of another's stream by a sidecar that is no admin", kind: record, signer: writer, refKind: owned, refId: world.refId, owner: idOf(owner), flags: protocol.EvsPushFlag_EVS_PUSH_CLOSURE, change: evsUnjudgedRemoval,
			judged: "an owned ref signed by another sidecar"},
		{label: "a stream owner's BASE that creates, the owner no admin", kind: record, signer: owner, refKind: owned, refId: world.refId, owner: idOf(owner), flags: protocol.EvsPushFlag_EVS_PUSH_BASE},
		{label: "a stream owner's BASE that creates, the owner an admin", kind: record, signer: admin, refKind: owned, refId: world.refId, owner: idOf(admin), flags: protocol.EvsPushFlag_EVS_PUSH_BASE,
			judged: "a BASE that writes"},
		{label: "a stream owner's BASE that removes and creates", kind: record, signer: admin, refKind: owned, refId: world.refId, owner: idOf(admin), flags: protocol.EvsPushFlag_EVS_PUSH_BASE, change: evsUnjudgedRemovalAndCreation,
			judged: "a BASE that writes", unjudged: "a BASE that writes"},
		// the repo
		{label: "a repo the state holds no row of", kind: general, signer: writer, refKind: shared, refId: world.refId, noRepo: true,
			judged: "a repo the state does not hold", unjudged: "a repo no state the reader holds has"},
	}
	verifier := world.reader(t, evsTestId("table reader")).client.verifier
	for _, c := range cases {
		plan := evsTestPlan(t, c.signer, c.label, 2)
		plan.RepoId, plan.RefId, plan.RefKind, plan.OwnerSidecarId = repoId, c.refId, c.refKind, c.owner
		plan.Flags, plan.PathEpoch = uint32(c.flags), 1
		switch c.change {
		case evsUnjudgedCreation:
			plan.Changes = plan.Changes[:1]
		case evsUnjudgedWriteOnBase:
			plan.Changes = plan.Changes[:1]
			plan.Changes[0].BaseEntryVersion, plan.Changes[0].EntryVersion = 2, evsTestEntryVersion(t, plan, 0, 3)
		case evsUnjudgedRemoval:
			plan.Changes = plan.Changes[:1]
			plan.Changes[0].BaseEntryVersion, plan.Changes[0].EntryVersion = 3, nil
			plan.NewObjects = nil
		case evsUnjudgedRemovalAndCreation:
			// evsTestPlan's second change bases on 1
			plan.Changes[1].EntryVersion = nil
		}
		built, err := NewEvsStatementBuilder(c.signer.sign).Build(plan)
		if err != nil {
			t.Fatalf("%s: %v", c.label, err)
		}
		repo := &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: c.kind, Admins: []*protocol.AclRepoAdminRow{{SidecarId: admin.sidecarId.Bytes()}}}
		if c.noRepo {
			repo = nil
		}
		for _, unjudged := range []bool{false, true} {
			want := c.judged
			func() {
				world.config.stateLock.Lock()
				defer world.config.stateLock.Unlock()
				world.config.repo, world.config.atErr = repo, nil
				if unjudged {
					world.config.atErr, want = ErrGkmAuthNotRetained, c.unjudged
				}
			}()
			if _, err := verifier.VerifyStatement(context.Background(), built.Statement.Bytes, repoId, c.refId); !evsTestRefusedFor(err, want) {
				t.Errorf("%s, unjudged %t: %v, want %q", c.label, unjudged, err, want)
			}
		}
	}
}

// VerifyPayloadRefRules over a stream's and a deposit's changes with their entries at hand, judged at the statement's
// pin and unjudged (QD-1178), as a replaying reader and a head reader holding a version run it: a file written on a
// base, a directory delta removing a name or off its base + 1, and a deposit's write on a base refuse both ways, an
// add-only delta on the directory's newest version passes both ways, and one by a stream owner the state no longer lets
// write the repo is refused only judged.
func TestEvsUnjudgedPayloadHeldToTheCreatesOnlyRule(t *testing.T) {
	world := newEvsTestWorld(t)
	owner := world.signer.sidecarId
	world.config.repo.Kind = protocol.RepoKind_REPO_KIND_RECORD
	verifier := world.reader(t, evsTestId("payload reader")).client.verifier
	streamRefId, depositRefId := evsTestId("stream"), EvsDepositRefId(world.repoId, owner)
	directory := EvsTokenPath{evsTestToken("e")}
	entryOf := func(kind protocol.EvsEntryKind, version uint64, removedTokens [][]byte) []byte {
		entry := &protocol.EvsEntryVersion{Version: version, Kind: uint32(kind)}
		if kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
			entry.Names = &protocol.EvsNameTable{
				Names:         []*protocol.EvsName{{Token: evsTestToken("1").Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: evsTestBytes("sealed 1", 32)}},
				RemovedTokens: removedTokens,
			}
		}
		entryBytes, err := proto.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		return entryBytes
	}
	changeOf := func(baseEntryVersion uint64, entryBytes []byte) *EvsCheckedChange {
		digest := sha256.Sum256(entryBytes)
		return &EvsCheckedChange{
			Change:       &protocol.EvsChange{TokenPath: directory.Components(), BaseEntryVersion: baseEntryVersion, EntrySha256: digest[:]},
			TokenPath:    directory,
			EntryVersion: entryBytes,
		}
	}
	standing := func(path *EvsCreatesOnlyPath) func(change *EvsCheckedChange) *EvsCreatesOnlyPath {
		return func(change *EvsCheckedChange) *EvsCreatesOnlyPath {
			return path
		}
	}
	directoryAt := standing(&EvsCreatesOnlyPath{Exists: true, Directory: true, Version: 3})
	fileAt := standing(&EvsCreatesOnlyPath{Exists: true, Version: 3})
	directoryKind, fileKind := protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY, protocol.EvsEntryKind_EVS_ENTRY_FILE
	cases := []struct {
		label   string
		refKind protocol.EvsRefKind
		refId   Id
		change  *EvsCheckedChange
		pathOf  func(change *EvsCheckedChange) *EvsCreatesOnlyPath
		// the state no longer lists the stream's owner among the repo's writers
		notWriter bool
		// the refusal's reason judged at the pin and unjudged, empty for changes taken
		judged   string
		unjudged string
	}{
		{label: "a stream's file written on a base", refKind: protocol.EvsRefKind_EVS_REF_OWNED, refId: streamRefId, change: changeOf(3, entryOf(fileKind, 4, nil)), pathOf: fileAt,
			judged: "a creates-only ref's change: a file's write on a base", unjudged: "a creates-only ref's change: a file's write on a base"},
		{label: "a stream directory's delta removing a name", refKind: protocol.EvsRefKind_EVS_REF_OWNED, refId: streamRefId, change: changeOf(3, entryOf(directoryKind, 4, [][]byte{evsTestToken("0").Bytes()})), pathOf: directoryAt,
			judged: "a creates-only ref's change: a directory delta removing a name", unjudged: "a creates-only ref's change: a directory delta removing a name"},
		{label: "a stream directory's delta not at its base + 1", refKind: protocol.EvsRefKind_EVS_REF_OWNED, refId: streamRefId, change: changeOf(3, entryOf(directoryKind, 5, nil)), pathOf: directoryAt,
			judged: "a creates-only ref's change: a directory delta not at its base + 1", unjudged: "a creates-only ref's change: a directory delta not at its base + 1"},
		{label: "a stream directory's add-only delta on its newest version", refKind: protocol.EvsRefKind_EVS_REF_OWNED, refId: streamRefId, change: changeOf(3, entryOf(directoryKind, 4, nil)), pathOf: directoryAt},
		{label: "an add-only delta by a stream owner that no longer writes the repo", refKind: protocol.EvsRefKind_EVS_REF_OWNED, refId: streamRefId, change: changeOf(3, entryOf(directoryKind, 4, nil)), pathOf: directoryAt, notWriter: true,
			judged: "an owned ref's sidecar no longer writes the repo"},
		{label: "a deposit's write on a base", refKind: protocol.EvsRefKind_EVS_REF_DEPOSIT, refId: depositRefId, change: changeOf(3, entryOf(fileKind, 4, nil)),
			judged: "a creates-only ref's change: a write on a base", unjudged: "a creates-only ref's change: a write on a base"},
	}
	for _, c := range cases {
		statement := &EvsStatement{Push: &protocol.EvsPush{
			RepoId: world.repoId.Bytes(), RefId: c.refId.Bytes(), RefKind: uint32(c.refKind), OwnerSidecarId: owner.Bytes(),
			SignerSidecarId: owner.Bytes(), Auth: &bridge.AuthPin{Version: 41, Chain: evsTestBytes("auth chain", 32)},
		}}
		for _, unjudged := range []bool{false, true} {
			want := c.judged
			func() {
				world.config.stateLock.Lock()
				defer world.config.stateLock.Unlock()
				world.config.writers, world.config.atErr = []Id{owner}, nil
				if c.notWriter {
					world.config.writers = nil
				}
				if unjudged {
					world.config.atErr, want = ErrGkmAuthNotRetained, c.unjudged
				}
			}()
			err := verifier.VerifyPayloadRefRules(statement, world.repoId, c.refId, []*EvsCheckedChange{c.change}, c.pathOf)
			if !evsTestRefusedFor(err, want) {
				t.Errorf("%s, unjudged %t: %v, want %q", c.label, unjudged, err, want)
			}
		}
	}
}

// A head reader of a record-class stream whose every statement is pinned before what it retains (QD-1178), its newest
// state no longer listing the stream's owner among the repo's writers, lists a directory's add-only delta and reads the
// file it added, with no alarm, the writer rule not judged; a file then written again on a base, whose statement read
// alone passes since it cannot be told from a delta, is refused once its entry is at hand and alarmed as tampering, as
// at a judged pin (TestEvsHeadReaderHoldsAStreamVersionToTheCreatesOnlyRule).
func TestEvsUnjudgedStreamVersionHeldToTheCreatesOnlyRule(t *testing.T) {
	world := newEvsTestWorld(t)
	world.owned = true
	world.config.repo.Kind = protocol.RepoKind_REPO_KIND_RECORD
	world.push(&evsTestChange{path: "e", children: []string{"1"}}, &evsTestChange{path: "e/1", content: []byte("1")})
	world.push(&evsTestChange{path: "e", children: []string{"2"}}, &evsTestChange{path: "e/2", content: []byte("2")})
	func() {
		world.config.stateLock.Lock()
		defer world.config.stateLock.Unlock()
		world.config.atErr, world.config.writers = ErrGkmAuthNotRetained, nil
	}()
	reader := world.reader(t, evsTestId("unjudged stream reader"))
	listing, err := reader.client.Repo(world.repoId).List(context.Background(), &EvsReadArgs{Path: "e"})
	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Entries) != 2 {
		t.Fatalf("e lists %d entries", len(listing.Entries))
	}
	if content, _, err := evsTestRead(t, reader, world, "e/2"); err != nil || string(content) != "2" {
		t.Fatalf("the delta's file: %q %v", content, err)
	}
	evsTestRequireNoAlarm(t, "the stream's unjudged versions", reader)
	// e/1 written again, which evs's 5c refuses and a server that lies commits
	world.push(&evsTestChange{path: "e/1", content: []byte("written again")})
	if _, _, err := evsTestRead(t, reader, world, "e/1"); !errors.Is(err, ErrEvsStatementRefused) {
		t.Fatalf("an unjudged stream's file written on a base: %v", err)
	}
	evsTestRequireTamper(t, "an unjudged stream's file written on a base", reader, 1)
}

// On a real log, two bases folded past the pushes' pin: deposit and erasure statements pinned there are refused on a
// new device started at the newest base, and on the log's own reader, where their ref's id is not derived as §11.6 says,
// a deposit ref's from the repo and its depositor and the erasure ref's from the repo, while a deposit at its
// depositor's id and an erasure push by a writer that is no repo admin are taken, the second's admin rule not judged
// though a pin both retain refuses it. A path written before the bases reads on the new device, walk and all.
func TestEvsUnjudgedDepositAndErasureRefIdsHeldToTheirDerivation(t *testing.T) {
	retained := newEvsTestRetainedWorld(t)
	depositor := retained.net.admitMemberDevice("depositor")
	other := retained.net.admitMemberDevice("other depositor")
	written := retained.net.log.Pin()
	retained.push(&evsTestChange{path: "a.txt", content: []byte("written before the bases")})
	repoId, anotherRepoId := retained.repoId, testConfigId("another repo")
	depositorId := depositor.sidecarId
	signerOf := func(device testConfigDevice) *evsTestSigner {
		return &evsTestSigner{sidecarId: device.sidecarId, privateKey: device.key}
	}
	statementAt := func(label string, pin *bridge.AuthPin, device testConfigDevice, refKind protocol.EvsRefKind, refId Id, owner *Id) []byte {
		t.Helper()
		signer := signerOf(device)
		plan := evsTestPlan(t, signer, label, 1)
		plan.RepoId, plan.RefId, plan.RefKind, plan.OwnerSidecarId, plan.PathEpoch, plan.Auth = repoId, refId, refKind, owner, 1, pin
		built, err := NewEvsStatementBuilder(signer.sign).Build(plan)
		if err != nil {
			t.Fatal(err)
		}
		return built.Statement.Bytes
	}
	cases := []struct {
		label   string
		signer  testConfigDevice
		refKind protocol.EvsRefKind
		refId   Id
		owner   *Id
		// the refusal's reason, empty for a statement taken
		reason string
	}{
		{label: "a deposit at its depositor's id", signer: depositor, refKind: protocol.EvsRefKind_EVS_REF_DEPOSIT, refId: EvsDepositRefId(repoId, depositorId), owner: &depositorId},
		{label: "a deposit at another depositor's id", signer: depositor, refKind: protocol.EvsRefKind_EVS_REF_DEPOSIT, refId: EvsDepositRefId(repoId, other.sidecarId), owner: &depositorId,
			reason: "a deposit ref not its depositor's"},
		{label: "a deposit at its depositor's id in another repo", signer: depositor, refKind: protocol.EvsRefKind_EVS_REF_DEPOSIT, refId: EvsDepositRefId(anotherRepoId, depositorId), owner: &depositorId,
			reason: "a deposit ref not its depositor's"},
		{label: "a deposit at the main ref's id", signer: depositor, refKind: protocol.EvsRefKind_EVS_REF_DEPOSIT, refId: retained.world.refId, owner: &depositorId,
			reason: "a deposit ref not its depositor's"},
		{label: "a deposit naming no depositor", signer: depositor, refKind: protocol.EvsRefKind_EVS_REF_DEPOSIT, refId: EvsDepositRefId(repoId, depositorId),
			reason: "a deposit ref not its depositor's"},
		{label: "an erasure push by a writer that is no repo admin", signer: retained.writer, refKind: protocol.EvsRefKind_EVS_REF_ERASURE, refId: EvsErasureRefId(repoId)},
		{label: "an erasure push at another repo's erasure id", signer: retained.writer, refKind: protocol.EvsRefKind_EVS_REF_ERASURE, refId: EvsErasureRefId(anotherRepoId),
			reason: "an erasure ref at another id"},
		{label: "an erasure push at the main ref's id", signer: retained.writer, refKind: protocol.EvsRefKind_EVS_REF_ERASURE, refId: retained.world.refId,
			reason: "an erasure ref at another id"},
	}
	statements := make([][]byte, len(cases))
	for i, c := range cases {
		statements[i] = statementAt(c.label, written, c.signer, c.refKind, c.refId, c.owner)
	}

	retained.foldPast(t, written)
	device, _ := retained.started(t, "new device")
	follower := retained.follower(t, "device that kept following")
	readers := []struct {
		label  string
		reader *evsTestClient
	}{
		{label: "the new device", reader: device},
		{label: "the log's own reader", reader: follower},
	}
	for _, r := range readers {
		if _, err := r.reader.client.args.Config().At(written); !errors.Is(err, ErrGkmAuthNotRetained) {
			t.Fatalf("%s judges the statements' pin: %v", r.label, err)
		}
		for i, c := range cases {
			_, err := r.reader.client.verifier.VerifyStatement(context.Background(), statements[i], repoId, c.refId)
			if !evsTestRefusedFor(err, c.reason) {
				t.Errorf("%s: %s: %v, want %q", r.label, c.label, err, c.reason)
			}
		}
	}
	retained.requireReads(t, "the new device", device, "a.txt", "written before the bases")

	// the erasure ref's admin rule judged at a pin both retain
	judged := statementAt("judged erasure", retained.net.log.Pin(), retained.writer, protocol.EvsRefKind_EVS_REF_ERASURE, EvsErasureRefId(repoId), nil)
	_, err := follower.client.verifier.VerifyStatement(context.Background(), judged, repoId, EvsErasureRefId(repoId))
	if !evsTestRefusedFor(err, "an erasure push by a non-admin") {
		t.Errorf("an erasure push by a writer that is no repo admin at a retained pin: %v", err)
	}
}
