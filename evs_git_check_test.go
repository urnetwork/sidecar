// EVS1-M2-49's check tests (DESIGN-DETAILS 8.6's codec and builder row, 8.2.7's check(u)): each line of the check
// broken in turn by a hand-built push, from one that passes: the shape against the flags and the ref's kind, a
// creating push's sections, old_tip, the sources, the commits' oids and parents, the import over exactly the push's
// commits or the new-commit rule, the tags, the tip and descent, and the history blobs' shape.

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
