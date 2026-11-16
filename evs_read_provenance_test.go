// QD-851's evs half on the stand-in (evs_world_test.go, evs_plan_test.go; QD-042 at M3): a write made in a tainted run
// seals the bit in its push's provenance and a reader that asks reads it back, by ReadHead, ReadVersion and History, a
// clean run's and a write bound to no run reading untainted; a read that does not ask gives no provenance and sends
// no push read; the sealed agent rides beside the bit and reads back asserted or verified, a refused signature
// keeping the bit; §16.6's effect seals both; a push evs serves no record of, and sealed metadata from before the
// field, read unknown; and nothing a tainted write sent evs differs in shape from a clean one's. The git-mode half and
// an import's label are evs_local_provenance_test.go's.

package sidecar

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// A reader of the writer's world over its stand-in, as another sidecar's fresh client.
func (self *evsTestWriter) provenanceReader(t *testing.T, label string) *evsTestClient {
	t.Helper()
	reader := self.world.reader(t, evsTestId(label))
	reader.client.args.Gkm = self.gkm
	reader.client.args.Transport = &evsTestTransport{handler: self.server}
	reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
	return reader
}

// The reads a client sends that name a push's record, counted as they pass, each answered as if evs held no such
// record when drop is set.
type evsTestPushReads struct {
	handler http.Handler

	stateLock sync.Mutex
	count     int
	drop      bool
}

func (self *evsTestPushReads) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/read") {
		body, _ := io.ReadAll(request.Body)
		read := &protocol.EvsReadRequest{}
		if err := proto.Unmarshal(body, read); err == nil && 0 < len(read.GetPushes()) {
			self.stateLock.Lock()
			self.count += 1
			drop := self.drop
			self.stateLock.Unlock()
			if drop {
				read.Pushes = nil
				body, _ = proto.Marshal(read)
			}
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.ContentLength = int64(len(body))
	}
	self.handler.ServeHTTP(writer, request)
}

func (self *evsTestPushReads) pushReads() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.count
}

// A tainted run's write reads back tainted and a clean one's untainted, by ReadHead, ReadVersion and History; a read
// that does not ask gives no provenance and reads no push's record, and one that asks reads each push's once.
func TestEvsReadGivesTheWritingRunsTaint(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.server.know("notes.md", "plain.md", "one.md")
	ctx := context.Background()
	write := func(path string, content string, tainted bool) {
		t.Helper()
		if _, err := writer.repo.WritePaths(ctx, &EvsWritePathsArgs{Tainted: tainted, Writes: []*EvsPathWrite{
			{Path: path, Content: bytes.NewReader([]byte(content))},
		}}); err != nil {
			t.Fatal(err)
		}
	}
	write("notes.md", "words an injected page chose", true)
	write("plain.md", "the sidecar's own", false)
	if _, err := writer.repo.Write(ctx, &EvsWriteArgs{Path: "one.md", Content: strings.NewReader("one"), Size: 3, Tainted: true}); err != nil {
		t.Fatal(err)
	}
	reader := writer.provenanceReader(t, "taint reader")
	pushReads := &evsTestPushReads{handler: writer.server}
	reader.client.args.Transport = &evsTestTransport{handler: pushReads}
	reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
	repo := reader.client.Repo(writer.world.repoId)

	out := &bytes.Buffer{}
	unasked, err := repo.ReadHead(ctx, &EvsReadArgs{Path: "notes.md"}, out)
	if err != nil || unasked.Provenance != nil || out.String() != "words an injected page chose" {
		t.Fatalf("a read that did not ask: %+v %v %q", unasked, err, out.String())
	}
	if pushReads.pushReads() != 0 {
		t.Fatalf("a read that did not ask read %d push records", pushReads.pushReads())
	}
	for path, tainted := range map[string]bool{"notes.md": true, "plain.md": false, "one.md": true} {
		out.Reset()
		before := pushReads.pushReads()
		info, err := repo.ReadHead(ctx, &EvsReadArgs{Path: path, Provenance: true}, out)
		if err != nil || info.Provenance == nil {
			t.Fatalf("%s: %+v %v", path, info, err)
		}
		read := info.Provenance
		if read.Tainted != tainted || read.State != EvsProvenanceUnattributed || read.AgentId != nil || read.Imported || read.Refused {
			t.Errorf("%s: provenance %+v, tainted %t wanted", path, read, tainted)
		}
		if info.SignerSidecarId != writer.world.signer.sidecarId || out.Len() == 0 {
			t.Errorf("%s: signer %s, %d bytes", path, info.SignerSidecarId, out.Len())
		}
		if pushReads.pushReads() != before+1 {
			t.Errorf("%s: %d push reads for one version", path, pushReads.pushReads()-before)
		}
	}

	// a clean run writes over the tainted version: each version keeps its own push's bit
	write("notes.md", "words the member wrote", false)
	before := pushReads.pushReads()
	history, err := repo.History(ctx, &EvsReadArgs{Path: "notes.md", Provenance: true, Fresh: true})
	if err != nil || len(history.Versions) != 2 {
		t.Fatalf("history %+v %v", history, err)
	}
	newest, older := history.Versions[0], history.Versions[1]
	if newest.Provenance == nil || newest.Provenance.Tainted || older.Provenance == nil || !older.Provenance.Tainted {
		t.Fatalf("history's provenance: newest %+v, older %+v", newest.Provenance, older.Provenance)
	}
	if pushReads.pushReads() != before+2 {
		t.Errorf("%d push reads for two versions", pushReads.pushReads()-before)
	}
	plain, err := repo.History(ctx, &EvsReadArgs{Path: "notes.md"})
	if err != nil || len(plain.Versions) != 2 || plain.Versions[0].Provenance != nil || plain.Versions[1].Provenance != nil {
		t.Fatalf("a history that did not ask: %+v %v", plain, err)
	}
	out.Reset()
	old, err := repo.ReadVersion(ctx, &EvsReadArgs{Path: "notes.md", Version: older.Version, Provenance: true}, out)
	if err != nil || old.Provenance == nil || !old.Provenance.Tainted || out.String() != "words an injected page chose" {
		t.Fatalf("the older version: %+v %v %q", old, err, out.String())
	}
	out.Reset()
	head, err := repo.ReadHead(ctx, &EvsReadArgs{Path: "notes.md", Provenance: true}, out)
	if err != nil || head.Provenance == nil || head.Provenance.Tainted || out.String() != "words the member wrote" {
		t.Fatalf("the newest version: %+v %v %q", head, err, out.String())
	}
	if 0 < len(reader.eventsOf(SidecarEventEvsAlarm)) {
		t.Fatal("a provenance read alarmed")
	}
}

// A write made for an agent seals its id beside the run's bit: asserted with no subkey signer, verified with one, and
// a signature that does not hold alarmed and read unattributed with the bit still said; nothing sent evs holds the id.
func TestEvsReadGivesTheSealedAgent(t *testing.T) {
	cases := []struct {
		name    string
		signer  bool
		tamper  bool
		state   EvsPushProvenanceState
		refused bool
	}{
		{name: "asserted", state: EvsProvenanceAsserted},
		{name: "verified", signer: true, state: EvsProvenanceVerified},
		{name: "refused", signer: true, tamper: true, state: EvsProvenanceUnattributed, refused: true},
	}
	for _, c := range cases {
		writer := newEvsTestWriter(t)
		capture := &evsTestCapture{handler: writer.server}
		writer.test.client.http.transport = wrapSidecarApiTransport(&evsTestTransport{handler: capture})
		agent := newEvsTestAgent(t, writer.world.signer, c.name, writer.test.clock.Now().Add(time.Hour))
		if c.signer {
			writer.test.client.args.SignProvenance = agent.signer(c.tamper)
		}
		writer.server.know("a.md")
		ctx := context.Background()
		if _, err := writer.repo.WritePaths(ctx, &EvsWritePathsArgs{AgentId: &agent.agentId, Tainted: true, Writes: []*EvsPathWrite{
			{Path: "a.md", Content: bytes.NewReader([]byte("an agent's words"))},
		}}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		reader := writer.provenanceReader(t, "agent reader "+c.name)
		info, err := reader.client.Repo(writer.world.repoId).ReadHead(ctx, &EvsReadArgs{Path: "a.md", Provenance: true}, io.Discard)
		if err != nil || info.Provenance == nil {
			t.Errorf("%s: %+v %v", c.name, info, err)
			continue
		}
		read := info.Provenance
		if read.State != c.state || read.Refused != c.refused || !read.Tainted {
			t.Errorf("%s: provenance %+v", c.name, read)
		}
		if c.refused != (read.AgentId == nil) || (read.AgentId != nil && *read.AgentId != agent.agentId) {
			t.Errorf("%s: the agent %v", c.name, read.AgentId)
		}
		if alarms := len(reader.eventsOf(SidecarEventEvsAlarm)); c.refused != (alarms == 1) {
			t.Errorf("%s: %d alarms", c.name, alarms)
		}
		if capture.holds(agent.agentId.Bytes()) || capture.holds([]byte(agent.agentId.String())) {
			t.Errorf("%s: an agent id reached evs", c.name)
		}
	}
}

// §16.6's effect seals the run's bit and its agent in the push it makes, and a rerun that finds the version pushes
// nothing more.
func TestEvsWriteEffectSealsItsRunsTaintAndAgent(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.server.know("CLAUDE.md", "AGENTS.md")
	agentId := evsTestId("effect agent")
	ctx := context.Background()
	effect := &EvsWriteEffect{Repo: writer.repo, Path: "CLAUDE.md", Content: []byte("# rules\n"), Tainted: true, AgentId: &agentId}
	effectRef, err := effect.Run(ctx, []byte("effect key"))
	if err != nil {
		t.Fatal(err)
	}
	posts := writer.server.postCount()
	if again, err := effect.Run(ctx, []byte("effect key")); err != nil || !bytes.Equal(again, effectRef) || writer.server.postCount() != posts {
		t.Fatalf("a second run: %x %v, %d posts after %d", again, err, writer.server.postCount(), posts)
	}
	clean := &EvsWriteEffect{Repo: writer.repo, Path: "AGENTS.md", Content: []byte("# agents\n")}
	if _, err := clean.Run(ctx, []byte("another key")); err != nil {
		t.Fatal(err)
	}
	reader := writer.provenanceReader(t, "effect reader")
	repo := reader.client.Repo(writer.world.repoId)
	tainted, err := repo.ReadHead(ctx, &EvsReadArgs{Path: "CLAUDE.md", Provenance: true}, io.Discard)
	if err != nil || tainted.Provenance == nil || !tainted.Provenance.Tainted || tainted.Provenance.AgentId == nil ||
		*tainted.Provenance.AgentId != agentId || tainted.Provenance.State != EvsProvenanceAsserted {
		t.Fatalf("the tainted effect's version: %+v %v", tainted.Provenance, err)
	}
	untainted, err := repo.ReadHead(ctx, &EvsReadArgs{Path: "AGENTS.md", Provenance: true}, io.Discard)
	if err != nil || untainted.Provenance == nil || untainted.Provenance.Tainted || untainted.Provenance.AgentId != nil {
		t.Fatalf("the clean effect's version: %+v %v", untainted.Provenance, err)
	}
}

// A push evs serves no record of reads unknown, nil, with its content still read; and sealed metadata that holds no
// provenance, a push from before the field, reads unknown where one that holds an empty one reads untainted.
func TestEvsProvenanceUnknownReadsNil(t *testing.T) {
	writer := newEvsTestWriter(t)
	ctx := context.Background()
	if _, err := writer.write(t, "a.md", []byte("a")); err != nil {
		t.Fatal(err)
	}
	reader := writer.provenanceReader(t, "unknown reader")
	pushReads := &evsTestPushReads{handler: writer.server, drop: true}
	reader.client.args.Transport = &evsTestTransport{handler: pushReads}
	reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
	repo := reader.client.Repo(writer.world.repoId)
	out := &bytes.Buffer{}
	info, err := repo.ReadHead(ctx, &EvsReadArgs{Path: "a.md", Provenance: true}, out)
	if err != nil || info.Provenance != nil || out.String() != "a" || pushReads.pushReads() != 1 {
		t.Fatalf("a push with no record: %+v %v %q, %d push reads", info, err, out.String(), pushReads.pushReads())
	}
	history, err := repo.History(ctx, &EvsReadArgs{Path: "a.md", Provenance: true})
	if err != nil || len(history.Versions) != 1 || history.Versions[0].Provenance != nil {
		t.Fatalf("its history: %+v %v", history, err)
	}
	if 0 < len(reader.eventsOf(SidecarEventEvsAlarm)) {
		t.Fatal("a missing record alarmed")
	}

	before, err := reader.client.versionProvenance(writer.world.repoId, evsTestId("ref"), nil, &protocol.EvsSealedMetadata{})
	if err != nil || before != nil {
		t.Fatalf("sealed metadata with no provenance: %+v %v", before, err)
	}
	// with the record served, the same version's empty provenance reads untainted, not unknown
	func() {
		pushReads.stateLock.Lock()
		defer pushReads.stateLock.Unlock()
		pushReads.drop = false
	}()
	served, err := repo.ReadHead(ctx, &EvsReadArgs{Path: "a.md", Provenance: true}, io.Discard)
	if err != nil || served.Provenance == nil || served.Provenance.Tainted {
		t.Fatalf("the record served: %+v %v", served, err)
	}
}

// A tainted write and a clean one send evs requests of the same shape: the bit is sealed, and no statement field,
// flag or route says it (I-18).
func TestEvsTaintedWriteShowsEvsNothing(t *testing.T) {
	statements := map[bool]*protocol.EvsPush{}
	for _, tainted := range []bool{false, true} {
		writer := newEvsTestWriter(t)
		writer.server.know("a.md")
		var seen *protocol.EvsPush
		writer.server.onPush = func(statement *EvsStatement) {
			seen = proto.Clone(statement.Push).(*protocol.EvsPush)
		}
		if _, err := writer.repo.WritePaths(context.Background(), &EvsWritePathsArgs{Tainted: tainted, Writes: []*EvsPathWrite{
			{Path: "a.md", Content: bytes.NewReader([]byte("the same words"))},
		}}); err != nil {
			t.Fatal(err)
		}
		if seen == nil {
			t.Fatal("no statement reached the stand-in")
		}
		statements[tainted] = seen
	}
	clean, tainted := statements[false], statements[true]
	if clean.GetFlags() != tainted.GetFlags() || len(clean.GetChanges()) != len(tainted.GetChanges()) {
		t.Fatalf("a tainted push's statement differs in flags or changes: %d and %d, %d and %d",
			clean.GetFlags(), tainted.GetFlags(), len(clean.GetChanges()), len(tainted.GetChanges()))
	}
	// every field a tainted statement sets, a clean one sets too: the bit adds none
	cleanFields, taintedFields := map[string]bool{}, map[string]bool{}
	clean.ProtoReflect().Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		cleanFields[string(field.Name())] = true
		return true
	})
	tainted.ProtoReflect().Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		taintedFields[string(field.Name())] = true
		return true
	})
	for name := range taintedFields {
		if !cleanFields[name] {
			t.Errorf("a tainted statement sets %s, which a clean one does not", name)
		}
	}
	if len(cleanFields) != len(taintedFields) {
		t.Errorf("fields set: %d clean, %d tainted", len(cleanFields), len(taintedFields))
	}
}
