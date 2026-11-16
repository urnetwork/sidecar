// EVS1-M2-49's check tests (DESIGN-DETAILS 8.6's codec and builder row, 8.2.7's check(u)): each line of the check
// broken in turn by a hand-built push, from one that passes: the shape against the flags and the ref's kind, a
// creating push's sections, old_tip, the sources, the commits' oids and parents, the import over exactly the push's
// commits or the new-commit rule, the tags, the tip and descent, and the history blobs' shape. And EVS1-M6-06's
// prefix line (8.2.7, 16.2.6; QD-801), over hand-built lines whose signer is held to agents/build: the early test
// refusing a written file outside before a commit is read, its passing twins; a set pending at the pin waiting
// before anything is asked; a tag's proof among its sources and each way a source is no proof; a branch's measure
// from J or from nothing; and the late test over two trees on an op-counting source: a file written, removed, or
// replaced by a directory outside refused, the last file under the prefix removed with the directories above it
// passing, the walk from nothing stopping at the first file outside and passing a directory under the prefix whole,
// a signer named for every path reading no tree, and a tainted token path outside refused.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The objects a check test's pushes name.
type evsTestCheckWorld struct {
	repoId   Id
	refId    Id
	clientId Id
	held     map[EvsGitOid][]EvsGitOid
	// commits the world made, by name
	commits map[string]*protocol.EvsSealedCommit
	oids    map[string]EvsGitOid
}

func newEvsTestCheckWorld() *evsTestCheckWorld {
	return &evsTestCheckWorld{
		repoId: evsTestId("check repo"), refId: evsTestId("check ref"), clientId: evsTestId("check client"),
		held: map[EvsGitOid][]EvsGitOid{}, commits: map[string]*protocol.EvsSealedCommit{}, oids: map[string]EvsGitOid{},
	}
}

// A canonical commit by committer email on parents, named name.
func (self *evsTestCheckWorld) commit(t *testing.T, name string, email string, parents ...string) *protocol.EvsSealedCommit {
	t.Helper()
	ident, err := (&EvsGitIdent{Name: []byte("agent"), Email: []byte(email), TimeSeconds: 1767225600, TimeZone: "+0000"}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	commit := &EvsGitCommit{TreeOid: EvsGitEmptyTreeOid, Author: ident, Committer: ident, Message: []byte(name + "\n")}
	for _, parent := range parents {
		commit.ParentOids = append(commit.ParentOids, self.oids[parent])
	}
	object, err := commit.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sealed := &protocol.EvsSealedCommit{Object: object}
	self.commits[name] = sealed
	self.oids[name] = evsGitObjectOid(evsGitCommitKind, object)
	return sealed
}

// The client's own committer email.
func (self *evsTestCheckWorld) email() string {
	return self.clientId.String() + evsCommitterDomain
}

// A commit the reader holds already.
func (self *evsTestCheckWorld) hold(name string) {
	_, parentOids, _ := EvsGitCommitGraph(self.commits[name].GetObject())
	self.held[self.oids[name]] = parentOids
}

// An annotated tag of object, a kind.
func evsTestTag(object EvsGitOid, kind string, name string) []byte {
	return []byte(fmt.Sprintf("object %x\ntype %s\ntag %s\ntagger agent <a@example.invalid> 1767225600 +0000\n\n%s\n", object[:], kind, name, name))
}

// An UPDATE of a branch from its held tip "E" to a new commit "c2" on it: one that passes.
func (self *evsTestCheckWorld) update(t *testing.T) *EvsGitUpdateArgs {
	t.Helper()
	self.commit(t, "E", self.email())
	self.hold("E")
	c2 := self.commit(t, "c2", self.email(), "E")
	prior := self.oids["E"]
	newTip := self.oids["c2"]
	return &EvsGitUpdateArgs{
		RepoId: self.repoId, RefId: self.refId, RefName: []byte("main"),
		Statement: &EvsStatement{Push: &protocol.EvsPush{RefId: self.refId.Bytes(), ClientId: self.clientId.Bytes(), Flags: 0}},
		Payload:   &EvsCheckedPayload{},
		Metadata: &protocol.EvsSealedMetadata{
			Commits: []*protocol.EvsSealedCommit{c2},
			Git:     &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_UPDATE, OldTip: prior[:], NewTip: newTip[:]},
		},
		PriorTip: &prior,
		Held: func(oid EvsGitOid) bool {
			_, ok := self.held[oid]
			return ok
		},
		Committer: func(ctx context.Context, committer *EvsGitIdent, push *protocol.EvsPush) error {
			if string(committer.Email) != self.email() {
				return errors.New("another client's commit")
			}
			return nil
		},
		RefIdOf: func(refName []byte) (Id, error) {
			return evsTestId("check ref " + string(refName)), nil
		},
		Parents: func(ctx context.Context, oid EvsGitOid) ([]EvsGitOid, error) {
			parents, ok := self.held[oid]
			if !ok {
				return nil, ErrEvsGitObjectMissing
			}
			return parents, nil
		},
	}
}

// A change that writes a file entry, or a directory's, on base.
func evsTestCheckChange(base uint64, directory bool) *EvsCheckedChange {
	kind := protocol.EvsEntryKind_EVS_ENTRY_FILE
	if directory {
		kind = protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY
	}
	entry, _ := proto.Marshal(&protocol.EvsEntryVersion{Kind: uint32(kind)})
	return &EvsCheckedChange{Change: &protocol.EvsChange{BaseEntryVersion: base, EntrySha256: evsTestBytes("entry", 32)}, EntryVersion: entry}
}

// The pushes that pass: an UPDATE, a branch's creation with its sections, a DELETE, a REKEY, a forced rewind, a
// tag ref's creation through a tag of a tag, an import, and a held commit carried again.
func TestEvsGitCheckUpdateTakesEachShape(t *testing.T) {
	ctx := context.Background()
	for label, build := range map[string]func(world *evsTestCheckWorld) *EvsGitUpdateArgs{
		"an update": func(world *evsTestCheckWorld) *EvsGitUpdateArgs { return world.update(t) },
		"a creation": func(world *evsTestCheckWorld) *EvsGitUpdateArgs {
			args := world.update(t)
			args.PriorTip, args.Creating = nil, true
			args.Metadata.Git.OldTip = nil
			args.Metadata.Commits = []*protocol.EvsSealedCommit{world.commits["E"], world.commits["c2"]}
			delete(world.held, world.oids["E"])
			args.RefId, args.SectionRefName = evsTestId("check ref main"), []byte("main")
			args.Metadata.RefName = []byte("main")
			return args
		},
		"an overlay's creation": func(world *evsTestCheckWorld) *EvsGitUpdateArgs {
			args := world.update(t)
			args.PriorTip, args.Creating = nil, true
			args.Metadata.Git.OldTip = nil
			base := &protocol.EvsOverlay{RefId: evsTestId("base").Bytes(), Version: 4}
			args.RefId, args.SectionRefName, args.HeadBase = evsTestId("check ref agent"), []byte("agent"), base
			args.Metadata.RefName, args.Metadata.Base, args.Payload.Base = []byte("agent"), base, base
			return args
		},
		"a delete": func(world *evsTestCheckWorld) *EvsGitUpdateArgs {
			args := world.update(t)
			args.Statement.Push.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE)
			args.Metadata.Commits = nil
			args.Metadata.Git = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_DELETE, OldTip: evsTestBytes("any tip", 20)}
			return args
		},
		"a rekey": func(world *evsTestCheckWorld) *EvsGitUpdateArgs {
			args := world.update(t)
			args.Metadata.Commits = nil
			args.Metadata.Git = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_REKEY}
			args.Payload.Changes = []*EvsCheckedChange{evsTestCheckChange(3, false)}
			return args
		},
		"a forced rewind": func(world *evsTestCheckWorld) *EvsGitUpdateArgs {
			args := world.update(t)
			world.commit(t, "elsewhere", world.email())
			world.hold("elsewhere")
			tip := world.oids["elsewhere"]
			args.Statement.Push.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE)
			args.Metadata.Commits = nil
			args.Metadata.Git.NewTip = tip[:]
			return args
		},
		"a tag ref through a tag of a tag": func(world *evsTestCheckWorld) *EvsGitUpdateArgs {
			args := world.update(t)
			inner := evsTestTag(world.oids["c2"], evsGitCommitKind, "v1")
			innerOid := evsGitObjectOid(evsGitTagKind, inner)
			outer := evsTestTag(innerOid, evsGitTagKind, "v1-again")
			outerOid := evsGitObjectOid(evsGitTagKind, outer)
			args.PriorTip, args.Creating = nil, true
			args.Statement.Push.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE)
			args.RefId, args.SectionRefName = evsTestId("check ref refs/tags/v1"), []byte("refs/tags/v1")
			args.Metadata.RefName = []byte("refs/tags/v1")
			args.Metadata.Git = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_UPDATE, NewTip: outerOid[:], Tags: [][]byte{outer, inner}}
			return args
		},
		"an import of a foreign commit": func(world *evsTestCheckWorld) *EvsGitUpdateArgs {
			args := world.update(t)
			foreign := world.commit(t, "foreign", "someone@example.invalid", "E")
			tip := world.oids["foreign"]
			args.Metadata.Commits = []*protocol.EvsSealedCommit{foreign}
			args.Metadata.Git.NewTip = tip[:]
			args.Metadata.SignedImport = []byte("signed")
			list := sha256.Sum256(tip[:])
			args.Import = func(ctx context.Context, signed []byte, push *protocol.EvsPush) (*protocol.EvsImport, error) {
				return &protocol.EvsImport{RepoId: world.repoId.Bytes(), RefId: world.refId.Bytes(), TipOid: tip[:], OidListSha256: list[:], Count: 1}, nil
			}
			return args
		},
		"a held commit carried again": func(world *evsTestCheckWorld) *EvsGitUpdateArgs {
			args := world.update(t)
			// two refs pushed it at once: judged the same, held already
			world.hold("c2")
			return args
		},
	} {
		world := newEvsTestCheckWorld()
		args := build(world)
		checked, err := EvsGitCheckUpdate(ctx, args)
		if err != nil {
			t.Errorf("%s: %v", label, err)
			continue
		}
		if checked.Shape != args.Metadata.GetGit().GetShape() {
			t.Errorf("%s: shape %v", label, checked.Shape)
		}
	}
}

// Each line of the check broken by a hand-built push, each refused as ErrEvsGitUpdateRefused.
func TestEvsGitCheckUpdateRefusesEachBrokenLine(t *testing.T) {
	ctx := context.Background()
	type mutation func(world *evsTestCheckWorld, args *EvsGitUpdateArgs)
	creating := func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
		args.PriorTip, args.Creating = nil, true
		args.Metadata.Git.OldTip = nil
		args.RefId, args.SectionRefName = evsTestId("check ref main"), []byte("main")
		args.Metadata.RefName = []byte("main")
	}
	rekey := func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
		args.Metadata.Commits = nil
		args.Metadata.Git = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_REKEY}
		args.Payload.Changes = []*EvsCheckedChange{evsTestCheckChange(3, false)}
	}
	tagCreation := func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
		tag := evsTestTag(world.oids["c2"], evsGitCommitKind, "v1")
		tagOid := evsGitObjectOid(evsGitTagKind, tag)
		args.PriorTip, args.Creating = nil, true
		args.Statement.Push.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE)
		args.RefId, args.SectionRefName = evsTestId("check ref refs/tags/v1"), []byte("refs/tags/v1")
		args.Metadata.RefName = []byte("refs/tags/v1")
		args.Metadata.Git = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_UPDATE, NewTip: tagOid[:], Tags: [][]byte{tag}}
	}
	importOf := func(world *evsTestCheckWorld, args *EvsGitUpdateArgs, evsImport *protocol.EvsImport) {
		foreign := world.commit(t, "foreign", "someone@example.invalid", "E")
		tip := world.oids["foreign"]
		args.Metadata.Commits = []*protocol.EvsSealedCommit{foreign}
		args.Metadata.Git.NewTip = tip[:]
		args.Metadata.SignedImport = []byte("signed")
		list := sha256.Sum256(tip[:])
		base := &protocol.EvsImport{RepoId: world.repoId.Bytes(), RefId: world.refId.Bytes(), TipOid: tip[:], OidListSha256: list[:], Count: 1}
		proto.Merge(base, evsImport)
		args.Import = func(ctx context.Context, signed []byte, push *protocol.EvsPush) (*protocol.EvsImport, error) {
			return base, nil
		}
	}
	segmentId := evsTestBytes("history segment", 32)
	historyBlob := func(world *evsTestCheckWorld, args *EvsGitUpdateArgs, blob *protocol.EvsSealedBlob, segments [][]byte, introduced bool) {
		args.Metadata.Git.SegmentIds = segments
		args.Metadata.Git.Blobs = []*protocol.EvsSealedBlob{blob}
		if introduced {
			args.Payload.NewObjects = []*EvsNewObject{{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: segmentId}}
		}
	}
	goodBlob := func() *protocol.EvsSealedBlob {
		return &protocol.EvsSealedBlob{GitOid: evsTestBytes("blob", 20), Size: 4, FileId: evsTestBytes("file", 16), Records: []*protocol.EvsHistoryLocator{{Segment: 0, Offset: 1024, Length: 200}}}
	}
	cases := map[string]mutation{
		// every shape
		"a PATH_EPOCH with an update": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Statement.Push.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH)
		},
		"no update": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) { args.Metadata.Git = nil },
		"an unknown shape": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Metadata.Git.Shape = protocol.EvsGitShape(9)
		},
		"a creation with no sealed name": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			creating(world, args)
			args.Metadata.RefName = nil
		},
		"a creation whose name is not its section 15's": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			creating(world, args)
			args.SectionRefName = []byte("other")
		},
		"a creation whose name is another ref's": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			creating(world, args)
			args.RefId = evsTestId("check ref other")
		},
		"a creation no ref id check takes": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			creating(world, args)
			args.RefIdOf = nil
		},
		"a creation whose base is not its section 16's": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			creating(world, args)
			base := &protocol.EvsOverlay{RefId: evsTestId("base").Bytes(), Version: 4}
			args.Metadata.Base, args.HeadBase = base, base
		},
		"a creation whose base is not the head's": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			creating(world, args)
			base := &protocol.EvsOverlay{RefId: evsTestId("base").Bytes(), Version: 4}
			args.Metadata.Base, args.Payload.Base = base, base
		},
		"a name on a push that does not create": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Metadata.RefName = []byte("main")
		},
		"a base on a push that does not create": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Metadata.Base = &protocol.EvsOverlay{RefId: evsTestId("base").Bytes(), Version: 4}
		},
		"a tag ref with a base": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			tagCreation(world, args)
			base := &protocol.EvsOverlay{RefId: evsTestId("base").Bytes(), Version: 4}
			args.Metadata.Base, args.Payload.Base, args.HeadBase = base, base, base
		},
		// DELETE
		"a DELETE carrying a commit": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Statement.Push.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE)
			args.Metadata.Git = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_DELETE}
		},
		"a DELETE without its flag": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Metadata.Commits = nil
			args.Metadata.Git = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_DELETE}
		},
		"a DELETE with a new tip": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Statement.Push.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE)
			args.Metadata.Commits = nil
			args.Metadata.Git = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_DELETE, NewTip: evsTestBytes("tip", 20)}
		},
		"a DELETE with a change": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Statement.Push.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE)
			args.Metadata.Commits = nil
			args.Metadata.Git = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_DELETE}
			args.Payload.Changes = []*EvsCheckedChange{evsTestCheckChange(3, false)}
		},
		"a DELETE with a name": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Statement.Push.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE)
			args.Metadata.Commits = nil
			args.Metadata.Git = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_DELETE}
			args.Creating, args.Metadata.RefName = true, []byte("main")
		},
		// REKEY
		"a REKEY with a flag": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			rekey(world, args)
			args.Statement.Push.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE)
		},
		"a REKEY with a tip": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			rekey(world, args)
			args.Metadata.Git.NewTip = evsTestBytes("tip", 20)
		},
		"a REKEY carrying a commit": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			rekey(world, args)
			args.Metadata.Commits = []*protocol.EvsSealedCommit{world.commits["c2"]}
		},
		"a REKEY on a tag ref": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			rekey(world, args)
			args.RefName = []byte("refs/tags/v1")
		},
		"a REKEY of a ref with no tip": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			rekey(world, args)
			args.PriorTip = nil
		},
		"a REKEY of a directory": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			rekey(world, args)
			args.Payload.Changes = []*EvsCheckedChange{evsTestCheckChange(3, true)}
		},
		"a REKEY creating a path": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			rekey(world, args)
			args.Payload.Changes = []*EvsCheckedChange{evsTestCheckChange(0, false)}
		},
		// UPDATE: flags and kinds
		"an UPDATE with DELETE": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Statement.Push.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE)
		},
		"IMMUTABLE on a branch": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Statement.Push.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE)
		},
		"a tag ref's creation without IMMUTABLE": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			tagCreation(world, args)
			args.Statement.Push.Flags = 0
		},
		"a second push to a tag ref": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.RefName = []byte("refs/tags/v1")
		},
		"a tag ref with a change": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			tagCreation(world, args)
			args.Payload.Changes = []*EvsCheckedChange{evsTestCheckChange(0, false)}
		},
		// old_tip and new_tip
		"an old tip on a ref with none": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			creating(world, args)
			args.Metadata.Git.OldTip = evsTestBytes("tip", 20)
		},
		"an old tip that is not the ref's": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Metadata.Git.OldTip = evsTestBytes("tip", 20)
		},
		"no new tip": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) { args.Metadata.Git.NewTip = nil },
		// sources
		"17 sources": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			for i := range 17 {
				args.Metadata.Git.Sources = append(args.Metadata.Git.Sources, &protocol.EvsOverlay{RefId: evsTestId(fmt.Sprint("source ", i)).Bytes(), Version: 1})
			}
		},
		"a source that is the ref itself": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Metadata.Git.Sources = []*protocol.EvsOverlay{{RefId: world.refId.Bytes(), Version: 1}}
		},
		"a source at version 0": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Metadata.Git.Sources = []*protocol.EvsOverlay{{RefId: evsTestId("source").Bytes()}}
		},
		// commits
		"a commit git cannot walk": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Metadata.Commits = []*protocol.EvsSealedCommit{{Object: []byte("not a commit")}}
		},
		"a parent neither held nor carried": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			delete(world.held, world.oids["E"])
			args.PriorTip = nil
			creating(world, args)
		},
		"a parent carried after its child": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			delete(world.held, world.oids["E"])
			creating(world, args)
			args.Metadata.Commits = []*protocol.EvsSealedCommit{world.commits["c2"], world.commits["E"]}
		},
		"a commit carried twice": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Metadata.Commits = []*protocol.EvsSealedCommit{world.commits["c2"], world.commits["c2"]}
		},
		// the new-commit rule
		"a new commit that is not canonical": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			// a NUL in the author header, which git stores and the strict codec refuses
			object := bytes.Replace(world.commits["c2"].GetObject(), []byte("\ncommitter "), []byte("\x00junk\ncommitter "), 1)
			sealed := &protocol.EvsSealedCommit{Object: object}
			oid := evsGitObjectOid(evsGitCommitKind, object)
			args.Metadata.Commits = []*protocol.EvsSealedCommit{sealed}
			args.Metadata.Git.NewTip = oid[:]
		},
		"a new commit of another client": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			world.commit(t, "theirs", "someone@example.invalid", "E")
			tip := world.oids["theirs"]
			args.Metadata.Commits = []*protocol.EvsSealedCommit{world.commits["theirs"]}
			args.Metadata.Git.NewTip = tip[:]
		},
		"a new commit no committer rule takes": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Committer = nil
		},
		"a new commit carrying a raw tree": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			world.commits["c2"].Trees = []*protocol.EvsSealedTree{{Object: []byte("040000 x\x00")}}
		},
		// imports
		"an import no check takes": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			importOf(world, args, &protocol.EvsImport{})
			args.Import = nil
		},
		"an import its check refuses": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			importOf(world, args, &protocol.EvsImport{})
			args.Import = func(ctx context.Context, signed []byte, push *protocol.EvsPush) (*protocol.EvsImport, error) {
				return nil, errors.New("not a repo admin's")
			}
		},
		"an import over other commits": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			importOf(world, args, &protocol.EvsImport{OidListSha256: evsTestBytes("another list", 32)})
		},
		"an import of another count": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			importOf(world, args, &protocol.EvsImport{Count: 2})
		},
		"an import to another tip": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			importOf(world, args, &protocol.EvsImport{TipOid: evsTestBytes("tip", 20)})
		},
		"an import of another ref": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			importOf(world, args, &protocol.EvsImport{RefId: evsTestId("other ref").Bytes()})
		},
		"an import of another repo": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			importOf(world, args, &protocol.EvsImport{RepoId: evsTestId("other repo").Bytes()})
		},
		// tags
		"a tag that is not the new tip": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			tagCreation(world, args)
			args.Metadata.Git.NewTip = evsTestBytes("tip", 20)
		},
		"a tag of a blob": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			tagCreation(world, args)
			tag := evsTestTag(world.oids["c2"], evsGitBlobKind, "v1")
			tagOid := evsGitObjectOid(evsGitTagKind, tag)
			args.Metadata.Git.NewTip, args.Metadata.Git.Tags = tagOid[:], [][]byte{tag}
		},
		"a tag of a commit before the last": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			tagCreation(world, args)
			inner := evsTestTag(world.oids["c2"], evsGitCommitKind, "v1")
			outer := evsTestTag(world.oids["c2"], evsGitCommitKind, "v1-again")
			outerOid := evsGitObjectOid(evsGitTagKind, outer)
			args.Metadata.Git.NewTip, args.Metadata.Git.Tags = outerOid[:], [][]byte{outer, inner}
		},
		"a tag git cannot read": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			tagCreation(world, args)
			tag := []byte("not a tag\n")
			tagOid := evsGitObjectOid(evsGitTagKind, tag)
			args.Metadata.Git.NewTip, args.Metadata.Git.Tags = tagOid[:], [][]byte{tag}
		},
		// the tip and descent
		"a tip neither held nor carried": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			args.Metadata.Git.NewTip = evsTestBytes("tip", 20)
		},
		"a carried commit the tip does not reach": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			world.commit(t, "stray", world.email(), "E")
			args.Metadata.Commits = append(args.Metadata.Commits, world.commits["stray"])
		},
		"an update that does not descend, without FORCE": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			world.commit(t, "elsewhere", world.email())
			world.hold("elsewhere")
			tip := world.oids["elsewhere"]
			args.Metadata.Commits = nil
			args.Metadata.Git.NewTip = tip[:]
		},
		// history blobs
		"a history blob of another shape": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			blob := goodBlob()
			blob.FileId = nil
			historyBlob(world, args, blob, [][]byte{segmentId}, true)
		},
		"a history diff of two records": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			blob := goodBlob()
			blob.BaseOid = evsTestBytes("base blob", 20)
			blob.Records = append(blob.Records, blob.Records[0])
			historyBlob(world, args, blob, [][]byte{segmentId}, true)
		},
		"a history record in no segment": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			blob := goodBlob()
			blob.Records[0].Segment = 1
			historyBlob(world, args, blob, [][]byte{segmentId}, true)
		},
		"a history segment the push does not introduce": func(world *evsTestCheckWorld, args *EvsGitUpdateArgs) {
			historyBlob(world, args, goodBlob(), [][]byte{segmentId}, false)
		},
	}
	// the line each case breaks, as its refusal names it
	reasons := map[string]string{
		"17 sources":                                     "17 sources",
		"IMMUTABLE on a branch":                          "IMMUTABLE other than on a tag ref's creation",
		"a DELETE carrying a commit":                     "a DELETE that is not flag DELETE alone with nothing carried",
		"a DELETE with a change":                         "a DELETE that is not flag DELETE alone with nothing carried",
		"a DELETE with a name":                           "a ref name or base on a push that does not create its ref",
		"a DELETE with a new tip":                        "a DELETE that is not flag DELETE alone with nothing carried",
		"a DELETE without its flag":                      "a DELETE that is not flag DELETE alone with nothing carried",
		"a PATH_EPOCH with an update":                    "a PATH_EPOCH with an update",
		"a REKEY carrying a commit":                      "a REKEY with a flag, a tip or anything carried, or on a tag or a ref with no tip",
		"a REKEY creating a path":                        "a REKEY change that is no file's re-checkpoint",
		"a REKEY of a directory":                         "a REKEY change that is no file's re-checkpoint",
		"a REKEY of a ref with no tip":                   "a REKEY with a flag, a tip or anything carried, or on a tag or a ref with no tip",
		"a REKEY on a tag ref":                           "a REKEY with a flag, a tip or anything carried, or on a tag or a ref with no tip",
		"a REKEY with a flag":                            "a REKEY with a flag, a tip or anything carried, or on a tag or a ref with no tip",
		"a REKEY with a tip":                             "a REKEY with a flag, a tip or anything carried, or on a tag or a ref with no tip",
		"a base on a push that does not create":          "a ref name or base on a push that does not create its ref",
		"a carried commit the tip does not reach":        "a carried commit the tip does not reach",
		"a commit carried twice":                         "a commit carried twice",
		"a commit git cannot walk":                       "a commit git cannot walk",
		"a creation no ref id check takes":               "a creating push no ref id check takes",
		"a creation whose base is not its section 16's":  "a creating push whose base is not its section 16's and the head's",
		"a creation whose base is not the head's":        "a creating push whose base is not its section 16's and the head's",
		"a creation whose name is another ref's":         "a creating push whose ref name is another ref's",
		"a creation whose name is not its section 15's":  "a creating push whose sealed ref name is not its section 15's",
		"a creation with no sealed name":                 "a creating push whose sealed ref name is not its section 15's",
		"a history blob of another shape":                "a history blob of another shape",
		"a history diff of two records":                  "a history blob on a base with other than one record",
		"a history record in no segment":                 "a history blob in no segment of the push",
		"a history segment the push does not introduce":  "a history blob segment the push does not introduce",
		"a name on a push that does not create":          "a ref name or base on a push that does not create its ref",
		"a new commit carrying a raw tree":               "a new commit carrying a raw tree",
		"a new commit no committer rule takes":           "a new commit no committer rule takes",
		"a new commit of another client":                 "a new commit's committer: another client's commit",
		"a new commit that is not canonical":             "a new commit that is not canonical",
		"a parent carried after its child":               "a commit whose parent is neither held nor carried before it",
		"a parent neither held nor carried":              "a commit whose parent is neither held nor carried before it",
		"a second push to a tag ref":                     "a tag ref's update past its creation, or with a change",
		"a source at version 0":                          "a source that is no other ref's committed version",
		"a source that is the ref itself":                "a source that is no other ref's committed version",
		"a tag git cannot read":                          "a tag git cannot read",
		"a tag of a blob":                                "a tag of a blob",
		"a tag of a commit before the last":              "a tag of a commit before the last",
		"a tag ref with a base":                          "a tag ref with a base",
		"a tag ref with a change":                        "a tag ref's update past its creation, or with a change",
		"a tag ref's creation without IMMUTABLE":         "IMMUTABLE other than on a tag ref's creation",
		"a tag that is not the new tip":                  "a tag that is not the one before it names",
		"a tip neither held nor carried":                 "a tip that peels to a commit neither held nor carried",
		"an UPDATE with DELETE":                          "an UPDATE with flags 0x2",
		"an import its check refuses":                    "the import: not a repo admin's",
		"an import no check takes":                       "an import no check takes",
		"an import of another count":                     "an import that is not over this push's own commits",
		"an import of another ref":                       "an import that is not over this push's own commits",
		"an import of another repo":                      "an import that is not over this push's own commits",
		"an import over other commits":                   "an import that is not over this push's own commits",
		"an import to another tip":                       "an import that is not over this push's own commits",
		"an old tip on a ref with none":                  "an old tip on a ref with none",
		"an old tip that is not the ref's":               "an old tip that is not the ref's",
		"an unknown shape":                               "shape 9",
		"an update that does not descend, without FORCE": "an update that does not descend, without FORCE",
		"no new tip":                                     "an UPDATE with no new tip",
		"no update":                                      "no update",
	}
	for label, mutate := range cases {
		world := newEvsTestCheckWorld()
		args := world.update(t)
		mutate(world, args)
		_, err := EvsGitCheckUpdate(ctx, args)
		if !errors.Is(err, ErrEvsGitUpdateRefused) || reasons[label] == "" || !strings.Contains(err.Error(), reasons[label]) {
			t.Errorf("%s: %v, want %q", label, err, reasons[label])
		}
	}
	// and a history blob of the right shape passes
	world := newEvsTestCheckWorld()
	args := world.update(t)
	historyBlob(world, args, goodBlob(), [][]byte{segmentId}, true)
	if _, err := EvsGitCheckUpdate(ctx, args); err != nil {
		t.Errorf("a history blob: %v", err)
	}
}

// An object source in memory that counts its reads: the op-counting source of DESIGN-DETAILS 8.6's prefix rows.
type evsTestCountedObjects struct {
	kinds    map[EvsGitOid]string
	contents map[EvsGitOid][]byte
	reads    int
}

func newEvsTestCountedObjects() *evsTestCountedObjects {
	return &evsTestCountedObjects{kinds: map[EvsGitOid]string{}, contents: map[EvsGitOid][]byte{}}
}

func (self *evsTestCountedObjects) ReadGitObject(ctx context.Context, oid EvsGitOid) (string, []byte, error) {
	self.reads += 1
	kind, ok := self.kinds[oid]
	if !ok {
		return "", nil, ErrEvsGitObjectMissing
	}
	return kind, self.contents[oid], nil
}

// A tree of files by path, each file's content its own blob, directories nested as git builds them.
func (self *evsTestCountedObjects) tree(t *testing.T, files map[string]string) EvsGitOid {
	t.Helper()
	write := func(kind string, content []byte) EvsGitOid {
		oid := evsGitObjectOid(kind, content)
		self.kinds[oid], self.contents[oid] = kind, content
		return oid
	}
	var build func(files map[string]string) EvsGitOid
	build = func(files map[string]string) EvsGitOid {
		children := map[string]map[string]string{}
		tree := &EvsGitTree{}
		for path, content := range files {
			name, rest, nested := strings.Cut(path, "/")
			if !nested {
				tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: EvsGitModeFile, Name: []byte(name), Oid: write(evsGitBlobKind, []byte(content))})
				continue
			}
			if children[name] == nil {
				children[name] = map[string]string{}
			}
			children[name][rest] = content
		}
		for name, below := range children {
			tree.Entries = append(tree.Entries, EvsGitTreeEntry{Mode: EvsGitModeDirectory, Name: []byte(name), Oid: build(below)})
		}
		encoded, err := tree.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return write(evsGitTreeKind, encoded)
	}
	return build(files)
}

// The path key of the check world's epoch 1.
func evsTestPrefixPathKey(t *testing.T) *EvsPathKey {
	t.Helper()
	pathKey, err := NewEvsPathKey(evsTestRepoKey(evsTestId("check repo"), 1))
	if err != nil {
		t.Fatal(err)
	}
	return pathKey
}

// A path's token path under pathKey, the root's empty.
func evsTestPrefixTokens(t *testing.T, pathKey *EvsPathKey, path string) EvsTokenPath {
	t.Helper()
	if path == "" {
		return EvsTokenPath{}
	}
	names := [][]byte{}
	for _, name := range strings.Split(path, "/") {
		names = append(names, []byte(name))
	}
	tokenPath, err := EvsPathTokens(pathKey, names)
	if err != nil {
		t.Fatal(err)
	}
	return tokenPath
}

// A line whose set at 5 gives the signer prefixes, "" for every path.
func evsTestPrefixLine(t *testing.T, prefixes ...string) *EvsGitPrefixLine {
	t.Helper()
	pathKey := evsTestPrefixPathKey(t)
	line := &EvsGitPrefixLine{Verdict: AclPrefixVerdict{Outcome: AclPrefixAllowed, Reason: AclPrefixReasonNoChange, SetAt: 5}, PathKey: pathKey}
	for _, prefix := range prefixes {
		line.Prefixes = append(line.Prefixes, evsTestPrefixTokens(t, pathKey, prefix))
	}
	return line
}

// A change writing a file entry at path.
func evsTestPrefixWrite(t *testing.T, path string) *EvsCheckedChange {
	change := evsTestCheckChange(1, false)
	change.TokenPath = evsTestPrefixTokens(t, evsTestPrefixPathKey(t), path)
	return change
}

// The early test: a file entry written outside the signer's prefix refuses the push with prefix_rule before a commit is
// read (no commit's parents held, no committer asked), naming no path, which it holds no name for; the same push by a
// signer the set names for every path, one writing under the prefix, a directory's entry outside, and a line with no
// set in force each pass. A REKEY of a file outside is refused the same way.
func TestEvsGitCheckPrefixEarlyTestRefusesBeforeACommitIsRead(t *testing.T) {
	ctx := context.Background()
	asked := 0
	counted := func(args *EvsGitUpdateArgs) {
		held, committer := args.Held, args.Committer
		args.Held = func(oid EvsGitOid) bool {
			asked += 1
			return held(oid)
		}
		args.Committer = func(ctx context.Context, ident *EvsGitIdent, push *protocol.EvsPush) error {
			asked += 1
			return committer(ctx, ident, push)
		}
	}
	world := newEvsTestCheckWorld()
	args := world.update(t)
	counted(args)
	args.Prefix = evsTestPrefixLine(t, "agents/build")
	args.Payload.Changes = []*EvsCheckedChange{evsTestPrefixWrite(t, "agents/build/out"), evsTestPrefixWrite(t, "src/main.go")}
	_, err := EvsGitCheckUpdate(ctx, args)
	var refusal *EvsGitPrefixRefusal
	if !errors.As(err, &refusal) || refusal.Row != EvsGitPrefixRowWritten || refusal.Path != "" || !errors.Is(err, ErrEvsGitUpdateRefused) ||
		!errors.Is(err, ErrEvsGitPrefixRule) || strings.Contains(err.Error(), "src") || asked != 0 {
		t.Fatalf("a file written outside: %v, %d objects asked", err, asked)
	}
	passing := map[string]func(args *EvsGitUpdateArgs){
		"a signer named for every path": func(args *EvsGitUpdateArgs) { args.Prefix = evsTestPrefixLine(t, "") },
		"a write under the prefix": func(args *EvsGitUpdateArgs) {
			args.Payload.Changes = []*EvsCheckedChange{evsTestPrefixWrite(t, "agents/build/out")}
		},
		"a directory's entry outside": func(args *EvsGitUpdateArgs) {
			change := evsTestCheckChange(1, true)
			change.TokenPath = evsTestPrefixTokens(t, evsTestPrefixPathKey(t), "agents")
			args.Payload.Changes = []*EvsCheckedChange{evsTestPrefixWrite(t, "agents/build/out"), change}
		},
		"no set in force": func(args *EvsGitUpdateArgs) {
			args.Prefix = &EvsGitPrefixLine{Verdict: AclPrefixVerdict{Outcome: AclPrefixAllowed, Reason: AclPrefixReasonNoSet}}
		},
	}
	for label, mutate := range passing {
		world := newEvsTestCheckWorld()
		args := world.update(t)
		args.Prefix = evsTestPrefixLine(t, "agents/build")
		args.Payload.Changes = []*EvsCheckedChange{evsTestPrefixWrite(t, "src/main.go")}
		mutate(args)
		if checked, err := EvsGitCheckUpdate(ctx, args); err != nil || (label == "a write under the prefix" && checked.PrefixMeasure != EvsGitPrefixMeasureFromJ) {
			t.Errorf("%s: %+v %v", label, checked, err)
		}
	}
	// a REKEY re-checkpoints only under its signer's prefixes
	world = newEvsTestCheckWorld()
	args = world.update(t)
	args.Metadata.Commits = nil
	args.Metadata.Git = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_REKEY}
	rekeyed := evsTestPrefixWrite(t, "src/main.go")
	rekeyed.Change.BaseEntryVersion = 3
	args.Payload.Changes = []*EvsCheckedChange{rekeyed}
	args.Prefix = evsTestPrefixLine(t, "agents/build")
	if _, err := EvsGitCheckUpdate(ctx, args); !errors.As(err, &refusal) || refusal.Row != EvsGitPrefixRowWritten {
		t.Errorf("a REKEY of a file outside: %v", err)
	}
	args.Prefix = evsTestPrefixLine(t, "")
	if _, err := EvsGitCheckUpdate(ctx, args); err != nil {
		t.Errorf("a REKEY by a signer named for every path: %v", err)
	}
}

// A set pending or newer at u's pin is a wait, answered before anything else is asked, and never a refusal.
func TestEvsGitCheckPrefixWaitsOnASetItCannotRead(t *testing.T) {
	for _, outcome := range []AclPrefixOutcome{AclPrefixWait, AclPrefixUpdate} {
		world := newEvsTestCheckWorld()
		args := world.update(t)
		asked := 0
		args.Held = func(oid EvsGitOid) bool { asked += 1; return true }
		args.Prefix = &EvsGitPrefixLine{Verdict: AclPrefixVerdict{Outcome: outcome, SetAt: 7}}
		args.Payload.Changes = []*EvsCheckedChange{evsTestPrefixWrite(t, "src/main.go")}
		if _, err := EvsGitCheckUpdate(context.Background(), args); !errors.Is(err, ErrEvsGitPrefixWait) || errors.Is(err, ErrEvsGitUpdateRefused) || asked != 0 {
			t.Errorf("%s: %v, %d asked", outcome, err, asked)
		}
	}
}

// A tag ref's creation of "c2": its proof is a source whose ref is a shared branch and whose tip at the named version
// is the commit the tag peels to, and then no file is judged; an owned ref's version, a tag ref's, a shared branch's
// at another tip, and a tag naming no source are no proof, measured from nothing; a signer named for every path asks
// no source.
func TestEvsGitCheckPrefixTagProof(t *testing.T) {
	ctx := context.Background()
	shared, owned, tagged := evsTestId("main ref"), evsTestId("owned ref"), evsTestId("tag ref")
	tagArgs := func(world *evsTestCheckWorld, sources ...Id) (*EvsGitUpdateArgs, *int) {
		args := world.update(t)
		tag := evsTestTag(world.oids["c2"], evsGitCommitKind, "v1")
		tagOid := evsGitObjectOid(evsGitTagKind, tag)
		args.PriorTip, args.Creating = nil, true
		args.Statement.Push.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE)
		args.RefId, args.SectionRefName, args.RefName = evsTestId("check ref refs/tags/v1"), []byte("refs/tags/v1"), []byte("refs/tags/v1")
		args.Metadata.RefName = []byte("refs/tags/v1")
		args.Metadata.Git = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_UPDATE, NewTip: tagOid[:], Tags: [][]byte{tag}}
		for _, source := range sources {
			args.Metadata.Git.Sources = append(args.Metadata.Git.Sources, &protocol.EvsOverlay{RefId: source.Bytes(), Version: 3})
		}
		asked := 0
		args.SharedBranch = func(ctx context.Context, refId Id) (bool, error) {
			asked += 1
			return refId == shared, nil
		}
		return args, &asked
	}
	tipOf := func(world *evsTestCheckWorld, name string) func(ctx context.Context, source *protocol.EvsOverlay) (*EvsGitOid, error) {
		return func(ctx context.Context, source *protocol.EvsOverlay) (*EvsGitOid, error) {
			oid := world.oids[name]
			return &oid, nil
		}
	}
	world := newEvsTestCheckWorld()
	args, _ := tagArgs(world, owned, shared)
	args.SourceTip = tipOf(world, "c2")
	args.Prefix = evsTestPrefixLine(t, "agents/build")
	checked, err := EvsGitCheckUpdate(ctx, args)
	if err != nil || checked.PrefixMeasure != EvsGitPrefixMeasureNone || checked.PrefixProof == nil || Id(checked.PrefixProof.GetRefId()) != shared {
		t.Fatalf("a tag of a shared branch's tip: %+v %v", checked, err)
	}
	for label, build := range map[string]func(world *evsTestCheckWorld) *EvsGitUpdateArgs{
		"an owned ref's tip": func(world *evsTestCheckWorld) *EvsGitUpdateArgs {
			args, _ := tagArgs(world, owned)
			args.SourceTip = tipOf(world, "c2")
			return args
		},
		"a tag ref's": func(world *evsTestCheckWorld) *EvsGitUpdateArgs {
			args, _ := tagArgs(world, tagged)
			args.SourceTip = tipOf(world, "c2")
			return args
		},
		"a shared branch at another tip": func(world *evsTestCheckWorld) *EvsGitUpdateArgs {
			args, _ := tagArgs(world, shared)
			args.SourceTip = tipOf(world, "E")
			return args
		},
		"a version with no tip": func(world *evsTestCheckWorld) *EvsGitUpdateArgs {
			args, _ := tagArgs(world, shared)
			args.SourceTip = func(ctx context.Context, source *protocol.EvsOverlay) (*EvsGitOid, error) { return nil, nil }
			return args
		},
		"no source": func(world *evsTestCheckWorld) *EvsGitUpdateArgs {
			args, _ := tagArgs(world)
			args.SourceTip = tipOf(world, "c2")
			return args
		},
	} {
		world := newEvsTestCheckWorld()
		args := build(world)
		args.Prefix = evsTestPrefixLine(t, "agents/build")
		checked, err := EvsGitCheckUpdate(ctx, args)
		if err != nil || checked.PrefixMeasure != EvsGitPrefixMeasureFromNothing || checked.PrefixProof != nil {
			t.Errorf("%s: %+v %v", label, checked, err)
		}
	}
	world = newEvsTestCheckWorld()
	args, asked := tagArgs(world, owned, shared)
	args.SourceTip = tipOf(world, "c2")
	args.Prefix = evsTestPrefixLine(t, "")
	if checked, err := EvsGitCheckUpdate(ctx, args); err != nil || checked.PrefixMeasure != EvsGitPrefixMeasureNone || *asked != 0 {
		t.Errorf("a signer named for every path: %+v %v, %d asked", checked, err, *asked)
	}
}

// A branch is measured from J, which is S where it held a tip, or on its first tip over a shared branch; from nothing
// on its first tip over an owned base, or none.
func TestEvsGitCheckPrefixMeasureOfABranch(t *testing.T) {
	ctx := context.Background()
	sharedBase, ownedBase := evsTestId("main ref"), evsTestId("owned ref")
	cases := []struct {
		label   string
		heldTip bool
		base    *Id
		want    EvsGitPrefixMeasure
	}{
		{label: "a tip before", heldTip: true, want: EvsGitPrefixMeasureFromJ},
		{label: "a first tip over a shared branch", base: &sharedBase, want: EvsGitPrefixMeasureFromJ},
		{label: "a first tip over an owned branch", base: &ownedBase, want: EvsGitPrefixMeasureFromNothing},
		{label: "a first tip with no base", want: EvsGitPrefixMeasureFromNothing},
	}
	for _, c := range cases {
		world := newEvsTestCheckWorld()
		args := world.update(t)
		args.HeldTip = c.heldTip
		if !c.heldTip {
			args.PriorTip, args.Creating = nil, true
			args.Metadata.Git.OldTip = nil
			args.Metadata.Commits = []*protocol.EvsSealedCommit{world.commits["c2"]}
			args.RefId, args.SectionRefName = evsTestId("check ref feature"), []byte("feature")
			args.Metadata.RefName = []byte("feature")
			if c.base != nil {
				base := &protocol.EvsOverlay{RefId: c.base.Bytes(), Version: 2}
				args.Metadata.Base, args.HeadBase = base, base
				args.Payload.Base = base
			}
		}
		args.SharedBranch = func(ctx context.Context, refId Id) (bool, error) { return refId == sharedBase, nil }
		args.Prefix = evsTestPrefixLine(t, "agents/build")
		checked, err := EvsGitCheckUpdate(ctx, args)
		if err != nil || checked.PrefixMeasure != c.want {
			t.Errorf("%s: %+v %v", c.label, checked, err)
		}
	}
}

// The late test over two trees on an op-counting source, by a signer held to agents/build: each file that differs is
// judged and the first outside named; the directories are not, so the last file under the prefix goes with the
// directories above it; a directory under the prefix is passed whole; a signer named for every path reads no tree.
func TestEvsGitCheckPrefixTreesJudgesTheFilesThatDiffer(t *testing.T) {
	ctx := context.Background()
	base := map[string]string{"agents/build/out": "built\n", "agents/deploy/x": "deploy\n", "src/main.go": "main\n", "README": "readme\n"}
	with := func(changes map[string]string, removed ...string) map[string]string {
		files := map[string]string{}
		for path, content := range base {
			files[path] = content
		}
		for path, content := range changes {
			files[path] = content
		}
		for _, path := range removed {
			delete(files, path)
		}
		return files
	}
	cases := []struct {
		label   string
		next    map[string]string
		refused string
	}{
		{label: "a file written under the prefix", next: with(map[string]string{"agents/build/out": "again\n", "agents/build/new": "new\n"})},
		{label: "a file written outside", next: with(map[string]string{"src/main.go": "changed\n"}), refused: "src/main.go"},
		{label: "a file removed outside", next: with(nil, "README"), refused: "README"},
		{label: "a directory created over a file outside", next: with(map[string]string{"README/inner": "x\n"}, "README"), refused: "README"},
		{label: "the last file under the prefix removed, with the directories above it", next: with(nil, "agents/build/out")},
		{label: "a subtree removed outside, its first file named", next: with(nil, "agents/deploy/x", "src/main.go"), refused: "agents/deploy/x"},
	}
	for _, c := range cases {
		objects := newEvsTestCountedObjects()
		j, n := objects.tree(t, base), objects.tree(t, c.next)
		err := EvsGitCheckPrefixTrees(ctx, &EvsGitPrefixTreesArgs{Line: evsTestPrefixLine(t, "agents/build"), Measure: EvsGitPrefixMeasureFromJ, Source: objects, J: &j, N: n})
		var refusal *EvsGitPrefixRefusal
		switch {
		case c.refused == "" && err != nil:
			t.Errorf("%s: %v", c.label, err)
		case c.refused != "" && (!errors.As(err, &refusal) || refusal.Path != c.refused || refusal.Row != EvsGitPrefixRowChanged || strings.Contains(err.Error(), c.refused)):
			t.Errorf("%s: %v, want %s", c.label, err, c.refused)
		}
	}
	// from nothing: the first file outside in the tree reader's order, and the prefix's directory passed whole
	objects := newEvsTestCountedObjects()
	n := objects.tree(t, map[string]string{"agents/build/a/b/c": "c\n", "agents/build/d": "d\n", "docs/x": "x\n", "src/y": "y\n"})
	err := EvsGitCheckPrefixTrees(ctx, &EvsGitPrefixTreesArgs{Line: evsTestPrefixLine(t, "agents/build"), Measure: EvsGitPrefixMeasureFromNothing, Source: objects, N: n})
	var refusal *EvsGitPrefixRefusal
	if !errors.As(err, &refusal) || refusal.Path != "docs/x" || refusal.Row != EvsGitPrefixRowFromNothing {
		t.Fatalf("from nothing: %v", err)
	}
	// the root, agents and docs read; agents/build passed whole, src never reached
	if objects.reads != 3 {
		t.Errorf("from nothing read %d trees", objects.reads)
	}
	allowed := newEvsTestCountedObjects()
	under := allowed.tree(t, map[string]string{"agents/build/a/b/c": "c\n", "agents/build/d": "d\n"})
	if err := EvsGitCheckPrefixTrees(ctx, &EvsGitPrefixTreesArgs{Line: evsTestPrefixLine(t, "agents/build"), Measure: EvsGitPrefixMeasureFromNothing, Source: allowed, N: under}); err != nil || allowed.reads != 2 {
		t.Errorf("a whole tree under the prefix: %v, %d reads", err, allowed.reads)
	}
	// a signer named for every path reads no tree
	whole := newEvsTestCountedObjects()
	wholeTree := whole.tree(t, map[string]string{"src/y": "y\n"})
	if err := EvsGitCheckPrefixTrees(ctx, &EvsGitPrefixTreesArgs{Line: evsTestPrefixLine(t, "agents/build", ""), Measure: EvsGitPrefixMeasureFromNothing, Source: whole, N: wholeTree}); err != nil || whole.reads != 0 {
		t.Errorf("a signer named for every path: %v, %d reads", err, whole.reads)
	}
	// a tainted token path the push writes outside, judged on its token path whatever the trees say
	tainted := newEvsTestCountedObjects()
	same := tainted.tree(t, base)
	write := evsTestPrefixWrite(t, "src/main.go")
	err = EvsGitCheckPrefixTrees(ctx, &EvsGitPrefixTreesArgs{
		Line: evsTestPrefixLine(t, "agents/build"), Measure: EvsGitPrefixMeasureFromJ, Source: tainted, J: &same, N: same,
		Changes: []*EvsCheckedChange{write}, Tainted: map[string]bool{write.TokenPath.KeyString(): true},
	})
	if !errors.As(err, &refusal) || refusal.Row != EvsGitPrefixRowTainted || refusal.Path != "" {
		t.Errorf("a tainted token path outside: %v", err)
	}
	if err := EvsGitCheckPrefixTrees(ctx, &EvsGitPrefixTreesArgs{
		Line: evsTestPrefixLine(t, "agents/build"), Measure: EvsGitPrefixMeasureFromJ, Source: tainted, J: &same, N: same,
		Changes: []*EvsCheckedChange{write},
	}); err != nil {
		t.Errorf("the same write at a path no taint names, the trees unchanged: %v", err)
	}
}
