// EVS1-M3-01's tests of §16.6's evs effects on the stand-in (evs_world_test.go, evs_plan_test.go): Lookup finds this
// sidecar's own write or removal as the first version after base_version, by git oid and by SHA-256 of the bytes, and
// calls another sidecar's version, or another content, the action's never; FS-25's evs owner case, a crash after the
// effect, where the restarted Run finds it and pushes nothing; the effect's refusals, a final one not_done and a lost
// answer uncertain; the gate's restart Lookup from the stored CanonicalAction alone; and base_version as the write's
// CAS. The git-mode half is evs_local_write_test.go's; the receipt gate's binding is evs_receipt_gate_test.go's.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Another writer of the world: a second sidecar, with its own signer the config holds, over the same stand-in.
func (self *evsTestWriter) otherWriter(t *testing.T, label string) *evsTestWriter {
	t.Helper()
	signer := newEvsTestSigner(label)
	func() {
		self.world.config.stateLock.Lock()
		defer self.world.config.stateLock.Unlock()
		self.world.config.identityKeys[signer.sidecarId] = signer.publicKey()
		self.world.config.writers = append(self.world.config.writers, signer.sidecarId)
		self.world.config.readers = append(self.world.config.readers, signer.sidecarId)
	}()
	test := newEvsTestClient(t, self.server, newEvsTestStore(t))
	test.client.args.Gkm = self.gkm
	test.client.args.Config = func() GkmAuthView { return self.world.config }
	test.client.args.Sign = signer.sign
	identity := &SidecarIdentity{NetworkId: testNetworkId, SidecarId: signer.sidecarId, ClientId: evsTestId(label + " client")}
	test.client.args.Identity = func() *SidecarIdentity { return identity }
	return &evsTestWriter{world: self.world, server: self.server, gkm: self.gkm, test: test, repo: test.client.Repo(self.world.repoId)}
}

// The blob oid of content.
func evsTestBlobOid(t *testing.T, content []byte) *EvsGitOid {
	t.Helper()
	oid, err := EvsGitBlobOid(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	return &oid
}

// The posts the stand-in took.
func (self *evsTestPushServer) postCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.postedStatements)
}

// This sidecar's write is the first version after its base: found by its content's git oid and by SHA-256 of its
// bytes, with its push id and path version as the effect's reference; another content, or a removal asked for, is
// not the action's; a base at the newest version finds none.
func TestEvsLookupFindsItsOwnWrite(t *testing.T) {
	writer := newEvsTestWriter(t)
	content := []byte("# CLAUDE.md\nbe careful\n")
	written, err := writer.write(t, "CLAUDE.md", content)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	digest := sha256.Sum256(content)
	for name, args := range map[string]*EvsLookupArgs{
		"by oid":    {Path: "CLAUDE.md", GitOid: evsTestBlobOid(t, content)},
		"by sha256": {Path: "CLAUDE.md", ContentSha256: digest[:]},
	} {
		found, err := writer.repo.Lookup(ctx, args)
		if err != nil || found.State != EvsLookupFound || found.Version.Version != written.PathVersion ||
			found.Version.PushId != written.PushId {
			t.Fatalf("%s: %+v %v", name, found, err)
		}
		pushId, pathVersion, err := ParseEvsEffectRef(found.EffectRef())
		if err != nil || pushId != written.PushId || pathVersion != written.PathVersion {
			t.Fatalf("%s: the effect reference %v %d %v", name, pushId, pathVersion, err)
		}
	}
	other := sha256.Sum256([]byte("other content"))
	for name, args := range map[string]*EvsLookupArgs{
		"another oid":     {Path: "CLAUDE.md", GitOid: evsTestBlobOid(t, []byte("other content"))},
		"another sha256":  {Path: "CLAUDE.md", ContentSha256: other[:]},
		"not its removal": {Path: "CLAUDE.md", Remove: true},
	} {
		if found, err := writer.repo.Lookup(ctx, args); err != nil || found.State != EvsLookupOther {
			t.Fatalf("%s: %+v %v", name, found, err)
		}
	}
	if found, err := writer.repo.Lookup(ctx, &EvsLookupArgs{Path: "CLAUDE.md", BaseVersion: written.PathVersion, GitOid: evsTestBlobOid(t, content)}); err != nil || found.State != EvsLookupNone {
		t.Fatalf("at the newest version: %+v %v", found, err)
	}
	if found, err := writer.repo.Lookup(ctx, &EvsLookupArgs{Path: "AGENTS.md", GitOid: evsTestBlobOid(t, content)}); err != nil || found.State != EvsLookupNone {
		t.Fatalf("a path never written: %+v %v", found, err)
	}
	if found, err := writer.repo.Lookup(ctx, &EvsLookupArgs{Path: "CLAUDE.md", BaseVersion: written.PathVersion + 5, GitOid: evsTestBlobOid(t, content)}); err != nil || found.State != EvsLookupOther {
		t.Fatalf("a base the path never stood at: %+v %v", found, err)
	}
}

// Another sidecar's version after the base is never this action's, though its content is the same, so the action's
// push, held to the base, can never commit; and this sidecar's own second write is found only on its own base.
func TestEvsLookupAnotherSidecarsVersionIsNotTheEffect(t *testing.T) {
	writer := newEvsTestWriter(t)
	other := writer.otherWriter(t, "other agent host")
	content := []byte("hooks: on\n")
	first, err := writer.write(t, ".mcp.json", []byte("{}\n"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := other.write(t, ".mcp.json", content)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	found, err := writer.repo.Lookup(ctx, &EvsLookupArgs{Path: ".mcp.json", BaseVersion: first.PathVersion, GitOid: evsTestBlobOid(t, content)})
	if err != nil || found.State != EvsLookupOther || found.Version.PushId != second.PushId {
		t.Fatalf("another sidecar's version: %+v %v", found, err)
	}
	found, err = other.repo.Lookup(ctx, &EvsLookupArgs{Path: ".mcp.json", BaseVersion: first.PathVersion, GitOid: evsTestBlobOid(t, content)})
	if err != nil || found.State != EvsLookupFound {
		t.Fatalf("its writer's own: %+v %v", found, err)
	}
	// three versions on, the walk still finds the first after the base
	for _, text := range []string{"a", "b", "c"} {
		if _, err := writer.write(t, ".mcp.json", []byte(text)); err != nil {
			t.Fatal(err)
		}
	}
	found, err = other.repo.Lookup(ctx, &EvsLookupArgs{Path: ".mcp.json", BaseVersion: first.PathVersion, GitOid: evsTestBlobOid(t, content)})
	if err != nil || found.State != EvsLookupFound || found.Version.Version != second.PathVersion {
		t.Fatalf("under later versions: %+v %v", found, err)
	}
}

// A delete's effect is this sidecar's removal right after the base, a removal by another is not, and a write's Lookup
// after a removal by another is not its effect either.
func TestEvsLookupDeletion(t *testing.T) {
	writer := newEvsTestWriter(t)
	first, err := writer.write(t, "AGENTS.md", []byte("agents\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.write(t, "AGENTS.md", nil); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	found, err := writer.repo.Lookup(ctx, &EvsLookupArgs{Path: "AGENTS.md", BaseVersion: first.PathVersion, Remove: true})
	if err != nil || found.State != EvsLookupFound || !found.Version.Removed {
		t.Fatalf("its own removal: %+v %v", found, err)
	}
	other := writer.otherWriter(t, "other remover")
	if found, err := other.repo.Lookup(ctx, &EvsLookupArgs{Path: "AGENTS.md", BaseVersion: first.PathVersion, Remove: true}); err != nil || found.State != EvsLookupOther {
		t.Fatalf("another's removal: %+v %v", found, err)
	}
	if found, err := writer.repo.Lookup(ctx, &EvsLookupArgs{Path: "AGENTS.md", BaseVersion: first.PathVersion, GitOid: evsTestBlobOid(t, []byte("agents\n"))}); err != nil || found.State != EvsLookupOther {
		t.Fatalf("a write's lookup over a removal: %+v %v", found, err)
	}
}

// FS-25's evs owner case: the effect ran and the process died before its Outcome; the restarted Run's Lookup finds the
// version, answers its reference and sends no second push. A Run on a base another version moved past proves no
// effect and pushes nothing.
func TestEvsWriteEffectCrashAfterTheEffectFindsItAndPushesNothing(t *testing.T) {
	writer := newEvsTestWriter(t)
	content := []byte("# CLAUDE.md\n")
	writer.server.know("CLAUDE.md")
	effect := &EvsWriteEffect{Repo: writer.repo, Path: "CLAUDE.md", Content: content}
	ctx := context.Background()
	effectRef, err := effect.Run(ctx, []byte("effect key"))
	if err != nil {
		t.Fatal(err)
	}
	posts := writer.server.postCount()
	// the restart: a new client over the same stand-in runs the same effect again
	restarted := newEvsTestWriter(t)
	restarted.world, restarted.server = writer.world, writer.server
	restarted.test = newEvsTestClient(t, writer.server, newEvsTestStore(t))
	restarted.test.client.args.Gkm = writer.gkm
	restarted.test.client.args.Config = writer.test.client.args.Config
	restarted.test.client.args.Sign = writer.test.client.args.Sign
	restarted.test.client.args.Identity = writer.test.client.args.Identity
	again := &EvsWriteEffect{Repo: restarted.test.client.Repo(writer.world.repoId), Path: "CLAUDE.md", Content: content}
	againRef, err := again.Run(ctx, []byte("effect key"))
	if err != nil || !bytes.Equal(againRef, effectRef) {
		t.Fatalf("the restarted run: %x %v, first %x", againRef, err, effectRef)
	}
	if writer.server.postCount() != posts {
		t.Fatalf("the restarted run pushed again: %d posts after %d", writer.server.postCount(), posts)
	}
	// another writer moves the path, and a run on the old base proves it did nothing
	other := writer.otherWriter(t, "mover")
	if _, err := other.write(t, "CLAUDE.md", []byte("moved\n")); err != nil {
		t.Fatal(err)
	}
	posts = writer.server.postCount()
	stale := &EvsWriteEffect{Repo: writer.repo, Path: "CLAUDE.md", BaseVersion: 1, Content: []byte("late\n")}
	if _, err := stale.Run(ctx, []byte("another key")); !errors.Is(err, ErrSidecarEffectNotDone) || !errors.Is(err, ErrEvsPathMoved) {
		t.Fatalf("a run on a moved base: %v", err)
	}
	if writer.server.postCount() != posts {
		t.Fatal("a run on a moved base pushed")
	}
}

// After a refusal the effect looks again: a final 409 that left the path at its base is not_done; a 503 of unknown
// outcome past the sender's retries leaves it uncertain, the error going back as it is, and the retry then pushes; a
// delete removes the path and answers its removal.
func TestEvsWriteEffectRefusals(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.server.know("AGENTS.md")
	ctx := context.Background()
	writer.server.pushRefusals = []*evsTestRefusal{{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL, Recorded: true}}}
	effect := &EvsWriteEffect{Repo: writer.repo, Path: "AGENTS.md", Content: []byte("one\n")}
	if _, err := effect.Run(ctx, []byte("k1")); !errors.Is(err, ErrSidecarEffectNotDone) || !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL) {
		t.Fatalf("a final refusal: %v", err)
	}
	for range writer.test.client.settings.PushRetryCount + 2 {
		writer.server.pushRefusals = append(writer.server.pushRefusals, &evsTestRefusal{status: http.StatusServiceUnavailable,
			reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE, Outcome: protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN}})
	}
	if _, err := effect.Run(ctx, []byte("k2")); err == nil || errors.Is(err, ErrSidecarEffectNotDone) {
		t.Fatalf("an outcome left unknown: %v", err)
	}
	writer.server.pushRefusals = nil
	// the uncertain use's retry pushes, as nothing committed
	effectRef, err := effect.Run(ctx, []byte("k2"))
	if err != nil {
		t.Fatalf("the run after the lost answer: %v", err)
	}
	_, pathVersion, err := ParseEvsEffectRef(effectRef)
	if err != nil || pathVersion != 1 {
		t.Fatalf("the found version %d %v", pathVersion, err)
	}
	removal := &EvsWriteEffect{Repo: writer.repo, Path: "AGENTS.md", BaseVersion: 1, Remove: true}
	removedRef, err := removal.Run(ctx, []byte("k3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, removedVersion, _ := ParseEvsEffectRef(removedRef); removedVersion != 2 {
		t.Fatalf("the removal's version %d", removedVersion)
	}
	if _, _, err := writer.read(t, "AGENTS.md"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("the removed path reads %v", err)
	}
}

// base_version is the write's CAS: 0 refuses a path that stands, a base below the newest refuses, and a base at a
// removal lets the path be written again.
func TestEvsWriteBaseVersionIsTheCas(t *testing.T) {
	writer := newEvsTestWriter(t)
	if _, err := writer.write(t, "a.txt", []byte("one")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	write := func(base uint64, content []byte) error {
		path := &EvsPathWrite{Path: "a.txt", IfBaseVersion: &base}
		if content != nil {
			path.Content = bytes.NewReader(content)
		}
		_, err := writer.repo.WritePaths(ctx, &EvsWritePathsArgs{Writes: []*EvsPathWrite{path}})
		return err
	}
	if err := write(0, []byte("again")); !errors.Is(err, ErrEvsPathMoved) {
		t.Fatalf("a creation over a standing path: %v", err)
	}
	if err := write(1, []byte("two")); err != nil {
		t.Fatalf("on its base: %v", err)
	}
	if err := write(1, []byte("three")); !errors.Is(err, ErrEvsPathMoved) {
		t.Fatalf("on a base below the newest: %v", err)
	}
	if _, err := writer.write(t, "a.txt", nil); err != nil {
		t.Fatal(err)
	}
	if err := write(3, []byte("back")); err != nil {
		t.Fatalf("over the removal it read: %v", err)
	}
	if content, _, err := writer.read(t, "a.txt"); err != nil || string(content) != "back" {
		t.Fatalf("read back %q %v", content, err)
	}
}

// The gate's restart Lookup reads only the stored CanonicalAction: done with the effect's reference for this
// sidecar's write, not_done once another version holds the path, uncertain while the path stands at its base, and a
// stored action of another kind is refused.
func TestEvsEffectLookupFromTheStoredAction(t *testing.T) {
	writer := newEvsTestWriter(t)
	ctx := context.Background()
	lookup := NewEvsEffectLookup(writer.test.client)
	content := []byte("settings\n")
	digest := sha256.Sum256(content)
	action := func(kind SidecarActionKind, base uint64, contentSha256 []byte) []byte {
		encoded, err := proto.Marshal(&protocol.CanonicalAction{
			Kind: uint32(kind), Version: 1, RepoId: writer.world.repoId.Bytes(), Path: ".claude/settings.json",
			ContentSha256: contentSha256, BaseVersion: base,
		})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	stored := action(SidecarActionAgentConfigWrite, 0, digest[:])
	outcome, err := lookup(ctx, stored, []byte("key"))
	if err != nil || outcome.State != ApprovalOutcomeUncertain {
		t.Fatalf("before the effect: %+v %v", outcome, err)
	}
	written, err := writer.write(t, ".claude/settings.json", content)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err = lookup(ctx, stored, []byte("key"))
	if err != nil || outcome.State != ApprovalOutcomeDone || !bytes.Equal(outcome.EffectRef, EvsEffectRef(written.PushId, written.PathVersion)) {
		t.Fatalf("after the effect: %+v %v", outcome, err)
	}
	moved := sha256.Sum256([]byte("another write's"))
	if outcome, err := lookup(ctx, action(SidecarActionAgentConfigWrite, 0, moved[:]), []byte("key")); err != nil || outcome.State != ApprovalOutcomeNotDone {
		t.Fatalf("another content on that base: %+v %v", outcome, err)
	}
	if _, err := writer.write(t, ".claude/settings.json", nil); err != nil {
		t.Fatal(err)
	}
	if outcome, err := lookup(ctx, action(SidecarActionAgentConfigDelete, written.PathVersion, nil), []byte("key")); err != nil || outcome.State != ApprovalOutcomeDone {
		t.Fatalf("its delete: %+v %v", outcome, err)
	}
	if _, err := lookup(ctx, action(SidecarActionMail, 0, nil), []byte("key")); !errors.Is(err, ErrEvsLookupInvalid) {
		t.Fatalf("another kind: %v", err)
	}
	if _, err := lookup(ctx, []byte{0xff, 0xff}, []byte("key")); !errors.Is(err, ErrEvsLookupInvalid) {
		t.Fatalf("bytes that do not parse: %v", err)
	}
}

// A Lookup asks one thing: a write by one hash, a removal by none, and some path.
func TestEvsLookupRefusesItsArgs(t *testing.T) {
	writer := newEvsTestWriter(t)
	ctx := context.Background()
	digest := sha256.Sum256([]byte("x"))
	for name, args := range map[string]*EvsLookupArgs{
		"no path":          {GitOid: evsTestBlobOid(t, []byte("x"))},
		"no hash":          {Path: "a"},
		"both hashes":      {Path: "a", GitOid: evsTestBlobOid(t, []byte("x")), ContentSha256: digest[:]},
		"a removal's hash": {Path: "a", Remove: true, GitOid: evsTestBlobOid(t, []byte("x"))},
		"a short sha256":   {Path: "a", ContentSha256: digest[:16]},
		"no lookup at all": nil,
	} {
		if _, err := writer.repo.Lookup(ctx, args); !errors.Is(err, ErrEvsLookupInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The receipt gate's depositor runs before the read decrypts anything and sees the read's context: the purpose and run
// WithEvsReadContext set, or purpose read bound to no run where none is set (EVS1-M3-01's opened gate; FS-30's evs
// side, the receipt before any decrypt). The record's half, receipts landing on RecordReceipts, is
// evs_receipt_gate_test.go's.
func TestEvsReceiptGateDepositsWithTheReadsContextBeforeDecrypting(t *testing.T) {
	world := newEvsTestWorld(t)
	world.config.repo.Kind = protocol.RepoKind_REPO_KIND_VAULT
	world.push(&evsTestChange{path: "notes.md", content: []byte("the author's notes"), segment: true})
	readerId := evsTestId("share reader")
	world.config.readers = append(world.config.readers, readerId)
	reader := world.reader(t, readerId)
	out := &bytes.Buffer{}
	seen := []*EvsReadContext{}
	reader.client.SetReceiptDepositor(func(ctx context.Context, repoId Id, refId Id, objectIds [][]byte) error {
		if out.Len() != 0 {
			t.Error("the read decrypted before its receipt")
		}
		seen = append(seen, evsReadContextOf(ctx))
		return nil
	})
	runId := evsTestId("the run")
	ctx := WithEvsReadContext(context.Background(), &EvsReadContext{Purpose: RecordReadPurposeSearch, RunId: &runId})
	if _, err := reader.client.Repo(world.repoId).ReadHead(ctx, &EvsReadArgs{Path: "notes.md"}, out); err != nil || out.String() != "the author's notes" {
		t.Fatalf("the read %q %v", out.String(), err)
	}
	out.Reset()
	if _, err := reader.client.Repo(world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: "notes.md"}, out); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0].Purpose != RecordReadPurposeSearch || seen[0].RunId == nil || *seen[0].RunId != runId ||
		seen[1].Purpose != RecordReadPurposeRead || seen[1].RunId != nil || seen[1].NoSession {
		t.Fatalf("the receipts' contexts %+v", seen)
	}
	reader.client.SetRecordReceipts(nil)
	if _, _, err := evsTestRead(t, reader, world, "notes.md"); !errors.Is(err, ErrEvsReceiptGate) {
		t.Fatalf("no receipts bound: %v", err)
	}
}
