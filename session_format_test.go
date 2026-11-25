//go:build !ios_extension && !js

// DESIGN-COMPUTE §24.5's session wire (CTXH-M11-01): the fields as the fence numbers them, read from the descriptors;
// item_sha256 and chain_sha256 against testdata/session/vectors/, a root, a three-node path and a same_as node, with a
// part; kinds 54 and 55 registered with their classes, never indexed and refused by the team projection; Coverage's new
// codes; the caps refused past their settings; and the push interval held within its bounds. A format change
// regenerates the vectors:
//
//	go test -run '^TestSession(Item|Chain)Sha256Vectors$' . -args -update-session-vectors
//
// which is read as a format change in review. Off the js leg, which opens no files.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

var updateSessionVectors = flag.Bool("update-session-vectors", false, "rewrite testdata/session/vectors/nodes.json")

const testSessionVectorsPath = "testdata/session/vectors/nodes.json"

// One field as §24.5's fence writes it.
type testSessionWireField struct {
	name     string
	number   protoreflect.FieldNumber
	kind     protoreflect.Kind
	repeated bool
	message  protoreflect.Name
}

// Every field of every message §24.5 writes, and the fields it adds to RecordEntry, Coverage and ModelCallBody, and
// the plan's ApprovalNotice and SeqRange, by the descriptors this build registers.
func TestSessionWireFieldNumbersMatchDesign(t *testing.T) {
	cases := []struct {
		message protoreflect.ProtoMessage
		fields  []testSessionWireField
		// the message has exactly these fields; false where it holds others the design wrote before
		whole bool
	}{
		{message: &protocol.SessionEntryBody{}, whole: true, fields: []testSessionWireField{
			{name: "node_id", number: 1, kind: protoreflect.BytesKind},
			{name: "parent_node_id", number: 2, kind: protoreflect.BytesKind},
			{name: "parent_run_id", number: 3, kind: protoreflect.BytesKind},
			{name: "type", number: 4, kind: protoreflect.Uint32Kind},
			{name: "item", number: 5, kind: protoreflect.BytesKind},
			{name: "parts", number: 6, kind: protoreflect.MessageKind, repeated: true, message: "SessionPart"},
			{name: "item_sha256", number: 7, kind: protoreflect.BytesKind},
			{name: "chain_sha256", number: 8, kind: protoreflect.BytesKind},
			{name: "same_as", number: 9, kind: protoreflect.BytesKind},
			{name: "redactions", number: 10, kind: protoreflect.Uint32Kind},
			{name: "stubs", number: 11, kind: protoreflect.Uint32Kind},
			{name: "marks", number: 12, kind: protoreflect.Uint32Kind},
		}},
		{message: &protocol.SessionPart{}, whole: true, fields: []testSessionWireField{
			{name: "pointer", number: 1, kind: protoreflect.StringKind},
			{name: "sha256", number: 2, kind: protoreflect.BytesKind},
			{name: "size", number: 3, kind: protoreflect.Uint64Kind},
			{name: "media_type", number: 4, kind: protoreflect.StringKind},
			{name: "blob_entry_ids", number: 5, kind: protoreflect.BytesKind, repeated: true},
			{name: "omitted", number: 6, kind: protoreflect.BoolKind},
		}},
		{message: &protocol.SessionBlobBody{}, whole: true, fields: []testSessionWireField{
			{name: "part_sha256", number: 1, kind: protoreflect.BytesKind},
			{name: "index", number: 2, kind: protoreflect.Uint32Kind},
			{name: "count", number: 3, kind: protoreflect.Uint32Kind},
			{name: "content", number: 4, kind: protoreflect.BytesKind},
		}},
		{message: &protocol.CallContext{}, whole: true, fields: []testSessionWireField{
			{name: "input_node_id", number: 1, kind: protoreflect.BytesKind},
			{name: "output_node_ids", number: 2, kind: protoreflect.BytesKind, repeated: true},
			{name: "system_node_id", number: 3, kind: protoreflect.BytesKind},
			{name: "request_sha256", number: 4, kind: protoreflect.BytesKind},
			{name: "exact", number: 5, kind: protoreflect.BoolKind},
			{name: "renderer", number: 6, kind: protoreflect.StringKind},
			{name: "params", number: 7, kind: protoreflect.BytesKind},
			{name: "sign_in_withheld", number: 8, kind: protoreflect.BoolKind},
		}},
		{message: &protocol.ModelCallBody{}, fields: []testSessionWireField{
			{name: "context", number: 15, kind: protoreflect.MessageKind, message: "CallContext"},
		}},
		{message: &protocol.RecordEntry{}, fields: []testSessionWireField{
			{name: "body_apart", number: 6, kind: protoreflect.BoolKind},
		}},
		{message: &protocol.Coverage{}, fields: []testSessionWireField{
			{name: "bodies_dropped", number: 8, kind: protoreflect.MessageKind, repeated: true, message: "SeqRange"},
		}},
		{message: &protocol.SeqRange{}, whole: true, fields: []testSessionWireField{
			{name: "first", number: 1, kind: protoreflect.Uint64Kind},
			{name: "last", number: 2, kind: protoreflect.Uint64Kind},
		}},
		{message: &protocol.ApprovalNotice{}, whole: true, fields: []testSessionWireField{
			{name: "approval_id", number: 1, kind: protoreflect.BytesKind},
			{name: "requester_sidecar_id", number: 2, kind: protoreflect.BytesKind},
			{name: "entry_seq", number: 3, kind: protoreflect.Uint64Kind},
			{name: "not_after_millis", number: 4, kind: protoreflect.Int64Kind},
			{name: "state", number: 5, kind: protoreflect.Uint32Kind},
			{name: "kind", number: 6, kind: protoreflect.Uint32Kind},
		}},
	}
	for _, c := range cases {
		descriptor := c.message.ProtoReflect().Descriptor()
		if c.whole && descriptor.Fields().Len() != len(c.fields) {
			t.Errorf("%s holds %d fields, the design %d", descriptor.Name(), descriptor.Fields().Len(), len(c.fields))
		}
		for _, want := range c.fields {
			field := descriptor.Fields().ByNumber(want.number)
			if field == nil {
				t.Errorf("%s has no field %d", descriptor.Name(), want.number)
				continue
			}
			if field.Name() != protoreflect.Name(want.name) || field.Kind() != want.kind || field.IsList() != want.repeated {
				t.Errorf("%s.%d is %s %s repeated %v, the design's %s %s repeated %v", descriptor.Name(), want.number,
					field.Kind(), field.Name(), field.IsList(), want.kind, want.name, want.repeated)
			}
			if want.message != "" && (field.Message() == nil || field.Message().Name() != want.message) {
				t.Errorf("%s.%s holds %v, not %s", descriptor.Name(), want.name, field.Message(), want.message)
			}
		}
	}
}

// One node of the vectors, as testdata/session/vectors/nodes.json keeps it.
type testSessionVectorNode struct {
	Name string `json:"name"`
	// the index of its parent among the vectors, -1 for a root
	Parent int `json:"parent"`
	// the index of the node same_as names, -1 for a node with an item
	SameAs int    `json:"same_as"`
	Item   string `json:"item"`
	// the part the item names by reference, its bytes as text
	Parts       []*testSessionVectorPart `json:"parts,omitempty"`
	ItemSha256  string                   `json:"item_sha256"`
	ChainSha256 string                   `json:"chain_sha256"`
}

type testSessionVectorPart struct {
	Pointer string `json:"pointer"`
	Content string `json:"content"`
}

// The vectors' inputs: a root, a three-node path from it, a same_as node at the path's end naming its second node,
// and a root holding one part by reference.
func testSessionVectorInputs(t *testing.T) []*testSessionVectorNode {
	t.Helper()
	canonical := func(text string) string {
		value, err := CanonicalJson([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return string(value)
	}
	partContent := strings.Repeat("a tool's long result line\n", 8)
	partSha256 := sha256.Sum256([]byte(partContent))
	partRef := `{"pointer":"/message/content/0/text","sha256":"` + hex.EncodeToString(partSha256[:]) + `","size":` + jsonNumber(len(partContent)) + `}`
	return []*testSessionVectorNode{
		{Name: "a root", Parent: -1, SameAs: -1, Item: canonical(
			`{"type":"message","id":"0a1b2c3d","parentId":null,"timestamp":"2026-11-06T00:00:00.000Z","message":{"role":"user","content":[{"type":"text","text":"list the repo's open issues"}],"timestamp":1762387200000}}`)},
		{Name: "a path's second node", Parent: 0, SameAs: -1, Item: canonical(
			`{"type":"message","id":"1b2c3d4e","parentId":"0a1b2c3d","timestamp":"2026-11-06T00:00:01.000Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"call-1","name":"read","arguments":{"path":"issues.md"}}],"stopReason":"toolUse","timestamp":1762387201000}}`)},
		{Name: "a path's third node", Parent: 1, SameAs: -1, Item: canonical(
			`{"type":"message","id":"2c3d4e5f","parentId":"1b2c3d4e","timestamp":"2026-11-06T00:00:02.000Z","message":{"role":"toolResult","toolCallId":"call-1","toolName":"read","content":[{"type":"text","text":"1. a synthetic issue"}],"isError":false,"timestamp":1762387202000}}`)},
		{Name: "a same_as node naming the second", Parent: 2, SameAs: 1},
		{Name: "a root holding a part", Parent: -1, SameAs: -1, Item: canonical(
			`{"type":"message","id":"3d4e5f60","parentId":null,"timestamp":"2026-11-06T00:00:03.000Z","message":{"role":"toolResult","toolCallId":"call-2","toolName":"read","content":[{"type":"text","text":` + partRef + `}],"isError":false,"timestamp":1762387203000}}`),
			Parts: []*testSessionVectorPart{{Pointer: "/message/content/0/text", Content: partContent}}},
	}
}

// n in decimal.
func jsonNumber(n int) string {
	encoded, _ := json.Marshal(n)
	return string(encoded)
}

// The vectors this build makes: each node's hashes, its parent's chain before it.
func testSessionVectors(t *testing.T) []*testSessionVectorNode {
	t.Helper()
	nodes := testSessionVectorInputs(t)
	for _, node := range nodes {
		var itemSha256 [sha256.Size]byte
		if node.SameAs < 0 {
			itemSha256 = sessionItemSha256([]byte(node.Item))
		} else {
			copy(itemSha256[:], testSessionHex(t, nodes[node.SameAs].ItemSha256))
		}
		var parentChain []byte
		if 0 <= node.Parent {
			parentChain = testSessionHex(t, nodes[node.Parent].ChainSha256)
		}
		chain := sessionChainSha256(parentChain, itemSha256[:])
		node.ItemSha256 = hex.EncodeToString(itemSha256[:])
		node.ChainSha256 = hex.EncodeToString(chain[:])
	}
	return nodes
}

func testSessionHex(t *testing.T, text string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// The stored vectors, rewritten first under -update-session-vectors.
func testSessionStoredVectors(t *testing.T) []*testSessionVectorNode {
	t.Helper()
	if *updateSessionVectors {
		encoded, err := json.MarshalIndent(map[string]any{"nodes": testSessionVectors(t)}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(testSessionVectorsPath, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	content, err := os.ReadFile(testSessionVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	stored := struct {
		Nodes []*testSessionVectorNode `json:"nodes"`
	}{}
	if err := json.Unmarshal(content, &stored); err != nil {
		t.Fatal(err)
	}
	return stored.Nodes
}

// A vector as a node's body: its item and parts, hashes and ids, the part's one piece's entry id drawn from its index.
func testSessionVectorBody(t *testing.T, nodes []*testSessionVectorNode, index int) *protocol.SessionEntryBody {
	t.Helper()
	node := nodes[index]
	body := &protocol.SessionEntryBody{
		NodeId:      bytes.Repeat([]byte{byte(index + 1)}, 16),
		Type:        1,
		Item:        []byte(node.Item),
		ItemSha256:  testSessionHex(t, node.ItemSha256),
		ChainSha256: testSessionHex(t, node.ChainSha256),
	}
	if 0 <= node.Parent {
		body.ParentNodeId = bytes.Repeat([]byte{byte(node.Parent + 1)}, 16)
	}
	if 0 <= node.SameAs {
		body.SameAs = bytes.Repeat([]byte{byte(node.SameAs + 1)}, 16)
	}
	for _, part := range node.Parts {
		digest := sha256.Sum256([]byte(part.Content))
		body.Parts = append(body.Parts, &protocol.SessionPart{
			Pointer: part.Pointer, Sha256: digest[:], Size: uint64(len(part.Content)), MediaType: "text/plain; charset=utf-8",
			BlobEntryIds: [][]byte{bytes.Repeat([]byte{0xb0}, 16)},
		})
	}
	return body
}

// item_sha256 is SHA-256 of the item as recorded, its part by its reference; a same_as node's is the node's it names.
func TestSessionItemSha256Vectors(t *testing.T) {
	stored := testSessionStoredVectors(t)
	built := testSessionVectors(t)
	if len(stored) != len(built) {
		t.Fatalf("%d stored vectors and %d built", len(stored), len(built))
	}
	for i, node := range stored {
		if node.Item != built[i].Item || node.ItemSha256 != built[i].ItemSha256 {
			t.Errorf("%s: item_sha256 %s stored, %s built", node.Name, node.ItemSha256, built[i].ItemSha256)
		}
		// the definition, apart from the code that makes it
		if node.SameAs < 0 {
			digest := sha256.Sum256([]byte(node.Item))
			if hex.EncodeToString(digest[:]) != node.ItemSha256 {
				t.Errorf("%s: item_sha256 is not SHA-256 of the item as recorded", node.Name)
			}
		} else if node.Item != "" || node.ItemSha256 != stored[node.SameAs].ItemSha256 {
			t.Errorf("%s: a same_as node with an item, or another item's hash", node.Name)
		}
	}
	// the part's reference stands in its item, its bytes nowhere in it
	part := stored[4]
	if !strings.Contains(part.Item, `"pointer":"/message/content/0/text"`) || strings.Contains(part.Item, "long result line") {
		t.Errorf("the part's item does not hold it by reference: %s", part.Item)
	}
}

// chain_sha256 is SHA-256 of the parent's chain hash and the item's, a root's parent 32 zero bytes, and each vector's
// node passes the reader's check while a node off its parent or its item does not.
func TestSessionChainSha256Vectors(t *testing.T) {
	stored := testSessionStoredVectors(t)
	built := testSessionVectors(t)
	for i, node := range stored {
		if node.ChainSha256 != built[i].ChainSha256 {
			t.Errorf("%s: chain_sha256 %s stored, %s built", node.Name, node.ChainSha256, built[i].ChainSha256)
		}
		parent := make([]byte, sha256.Size)
		if 0 <= node.Parent {
			parent = testSessionHex(t, stored[node.Parent].ChainSha256)
		}
		digest := sha256.Sum256(append(parent, testSessionHex(t, node.ItemSha256)...))
		if hex.EncodeToString(digest[:]) != node.ChainSha256 {
			t.Errorf("%s: chain_sha256 is not SHA-256(parent's chain || item_sha256)", node.Name)
		}
	}
	for i, node := range stored {
		body := testSessionVectorBody(t, stored, i)
		args := &SessionNodeCheckArgs{}
		if 0 <= node.Parent {
			args.ParentChainSha256 = testSessionHex(t, stored[node.Parent].ChainSha256)
		}
		if 0 <= node.SameAs {
			args.SameAs = testSessionVectorBody(t, stored, node.SameAs)
		}
		if err := SessionNodeCheck(body, args); err != nil {
			t.Errorf("%s: %v", node.Name, err)
		}
	}

	// the third node under the root rather than its own parent, a same_as node naming another item, an item changed
	third := testSessionVectorBody(t, stored, 2)
	if err := SessionNodeCheck(third, &SessionNodeCheckArgs{ParentChainSha256: testSessionHex(t, stored[0].ChainSha256)}); !errors.Is(err, ErrSessionNodeInvalid) {
		t.Errorf("a node checked under another parent: %v", err)
	}
	sameAs := testSessionVectorBody(t, stored, 3)
	if err := SessionNodeCheck(sameAs, &SessionNodeCheckArgs{
		ParentChainSha256: testSessionHex(t, stored[2].ChainSha256), SameAs: testSessionVectorBody(t, stored, 0),
	}); !errors.Is(err, ErrSessionNodeInvalid) {
		t.Errorf("a same_as node checked against another node: %v", err)
	}
	changed := testSessionVectorBody(t, stored, 0)
	changed.Item = bytes.Replace(changed.Item, []byte("open issues"), []byte("open isSues"), 1)
	if err := SessionNodeCheck(changed, nil); !errors.Is(err, ErrSessionNodeInvalid) {
		t.Errorf("an item changed under its hash: %v", err)
	}
	// a part whose reference in the item names another size
	partNode := testSessionVectorBody(t, stored, 4)
	partNode.Parts[0].Size += 1
	if err := SessionNodeCheck(partNode, nil); !errors.Is(err, ErrSessionNodeInvalid) {
		t.Errorf("a part whose reference is not its own: %v", err)
	}
	// a node whose parent this reader has not read keeps its item's check and leaves the chain alone
	unread := testSessionVectorBody(t, stored, 2)
	if err := SessionNodeCheck(unread, &SessionNodeCheckArgs{ParentUnread: true}); err != nil {
		t.Errorf("a node whose parent is unread: %v", err)
	}
}

// A part's pieces in order make its bytes; a piece out of place, another part's or one byte off does not, and a
// restored item holds the part's text where its reference stood.
func TestSessionPartAssemblesFromItsPieces(t *testing.T) {
	content := bytes.Repeat([]byte("0123456789"), 10)
	digest := sha256.Sum256(content)
	part := &protocol.SessionPart{
		Pointer: "/message/content/0/text", Sha256: digest[:], Size: uint64(len(content)),
		BlobEntryIds: [][]byte{bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)},
	}
	pieces := []*protocol.SessionBlobBody{
		{PartSha256: digest[:], Index: 0, Count: 2, Content: content[:60]},
		{PartSha256: digest[:], Index: 1, Count: 2, Content: content[60:]},
	}
	assembled, err := SessionPartAssemble(part, pieces)
	if err != nil || !bytes.Equal(assembled, content) {
		t.Fatalf("the pieces in order: %v", err)
	}
	if _, err := SessionPartAssemble(part, []*protocol.SessionBlobBody{pieces[1], pieces[0]}); !errors.Is(err, ErrSessionPartInvalid) {
		t.Errorf("the pieces out of order: %v", err)
	}
	tampered := proto.CloneOf(pieces[1])
	tampered.Content[0] ^= 1
	if _, err := SessionPartAssemble(part, []*protocol.SessionBlobBody{pieces[0], tampered}); !errors.Is(err, ErrSessionPartInvalid) {
		t.Errorf("a piece changed: %v", err)
	}
	other := proto.CloneOf(pieces[1])
	other.PartSha256 = bytes.Repeat([]byte{9}, 32)
	if _, err := SessionPartAssemble(part, []*protocol.SessionBlobBody{pieces[0], other}); !errors.Is(err, ErrSessionPartInvalid) {
		t.Errorf("another part's piece: %v", err)
	}
	if _, err := SessionPartAssemble(&protocol.SessionPart{Omitted: true}, nil); !errors.Is(err, ErrSessionPartInvalid) {
		t.Errorf("an omitted part assembled: %v", err)
	}

	ref, err := json.Marshal(SessionPartRefOf(part))
	if err != nil {
		t.Fatal(err)
	}
	item, err := CanonicalJson([]byte(`{"message":{"content":[{"text":` + string(ref) + `,"type":"text"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := SessionItemRestore(item, []*protocol.SessionPart{part}, map[string][]byte{part.GetPointer(): content})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(restored, content) || bytes.Contains(restored, []byte(`"pointer"`)) {
		t.Errorf("the restored item: %s", restored)
	}
	kept, err := SessionItemRestore(item, []*protocol.SessionPart{part}, map[string][]byte{})
	if err != nil || !bytes.Equal(kept, item) {
		t.Errorf("a pruned part keeps its reference: %v", err)
	}
}

// RFC 6901's pointers: "~1" for "/", "~0" for "~", array indexes with no leading zero, and only into an item.
func TestSessionPointerReadsRfc6901(t *testing.T) {
	var value any
	if err := json.Unmarshal([]byte(`{"a/b":{"m~n":[10,20,30]}}`), &value); err != nil {
		t.Fatal(err)
	}
	pointer := "/" + SessionPointerEscape("a/b") + "/" + SessionPointerEscape("m~n") + "/2"
	if pointer != "/a~1b/m~0n/2" {
		t.Errorf("escaped as %q", pointer)
	}
	got, err := SessionPointerGet(value, pointer)
	if err != nil || got != float64(30) {
		t.Errorf("got %v, %v", got, err)
	}
	if err := SessionPointerSet(value, pointer, "thirty"); err != nil {
		t.Fatal(err)
	}
	if got, _ := SessionPointerGet(value, pointer); got != "thirty" {
		t.Errorf("set gave %v", got)
	}
	for _, bad := range []string{"", "a", "/a~2", "/a~", "/a~1b/m~0n/02", "/a~1b/m~0n/3", "/a~1b/m~0n/-1", "/none"} {
		if _, err := SessionPointerGet(value, bad); err == nil {
			t.Errorf("%q named a value", bad)
		}
	}
	for _, pointer := range []string{"/", "/a", "/a~0~1/0"} {
		if !RecordSessionPointerValid(pointer) {
			t.Errorf("%q refused", pointer)
		}
	}
	for _, pointer := range []string{"", "a", "/~", "/~2", "\xff"} {
		if RecordSessionPointerValid(pointer) {
			t.Errorf("%q passed", pointer)
		}
	}
}

// Kind 54 is session_entry of class capture and 55 session_blob of the new class bulk, both writable, both raw and
// body-apart, neither indexed in any log, and the team projection refuses both, so neither reaches T (I-20).
func TestSessionKindsRegisteredWithClasses(t *testing.T) {
	cases := []struct {
		kind  RecordKind
		name  string
		class RecordClass
		body  proto.Message
	}{
		{kind: RecordKindSessionEntry, name: "session_entry", class: RecordClassCapture, body: &protocol.SessionEntryBody{}},
		{kind: RecordKindSessionBlob, name: "session_blob", class: RecordClassBulk, body: &protocol.SessionBlobBody{}},
	}
	for _, c := range cases {
		if c.kind.String() != c.name || !c.kind.Writable() || c.kind.Class() != c.class || !c.kind.BodyApart() {
			t.Errorf("kind %d reads %s, class %s, writable %v, body apart %v", c.kind, c.kind, c.kind.Class(), c.kind.Writable(), c.kind.BodyApart())
		}
		if named, ok := RecordKindNamed(c.name); !ok || named != c.kind {
			t.Errorf("%s names kind %d", c.name, named)
		}
		body, ok := c.kind.NewBody()
		if !ok || proto.MessageName(body) != proto.MessageName(c.body) {
			t.Errorf("%s's body is %v", c.name, body)
		}
		if !recordKindRaw(c.kind) {
			t.Errorf("%s is not raw, so record_query would return its body unnamed", c.name)
		}
		for _, logKind := range []protocol.RepoKind{protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_RECORD, protocol.RepoKind_REPO_KIND_TEAM_RECORD} {
			if indexRecordIndexesEntry(logKind, c.kind) {
				t.Errorf("%s is indexed in a %s log", c.name, logKind)
			}
		}
		if _, err := RecordProjectForTeam(c.kind, c.body, false); !errors.Is(err, ErrRecordProjectionNone) {
			t.Errorf("%s projects to the team record: %v", c.name, err)
		}
		if RecordKindLedgerCopied(c.kind) || recordKindSendsAtOnce(c.kind) {
			t.Errorf("%s is copied to a ledger or sends at once", c.name)
		}
	}
	if RecordClassBulk.String() != "bulk" || !RecordClassBulk.Known() {
		t.Errorf("class 8 reads %s", RecordClassBulk)
	}
}

// Coverage's sources harness and gateway and its gap context_partial pass where its closed lists hold them, as does
// bodies_dropped's ascending ranges; any other code, and a range empty, from 0 or out of order, is refused.
func TestSessionCoverageCodesAccepted(t *testing.T) {
	for _, source := range []string{RecordCoverageSourceHarness, RecordCoverageSourceGateway} {
		if !RecordCoverageSourceKnown(source) {
			t.Errorf("source %s refused", source)
		}
	}
	for _, count := range []int{1, 3} {
		gap, err := RecordCoverageGap(RecordCoverageGapContextPartial, count)
		if err != nil {
			t.Fatal(err)
		}
		if code, parsed, ok := RecordCoverageGapParse(gap); !ok || code != RecordCoverageGapContextPartial || parsed != count {
			t.Errorf("%s parses as %s %d %v", gap, code, parsed, ok)
		}
	}
	coverage := &protocol.Coverage{
		Sources:       []string{RecordCoverageSourceHarness, RecordCoverageSourceGateway},
		Gaps:          []string{RecordCoverageGapContextPartial, RecordCoverageGapSpoolDrop + ":2"},
		BodiesDropped: []*protocol.SeqRange{{First: 3, Last: 3}, {First: 5, Last: 9}},
	}
	if err := RecordBodyValidate(RecordKindCoverage, coverage); err != nil {
		t.Errorf("a coverage with the new codes: %v", err)
	}
	refused := [][]*protocol.SeqRange{
		{{First: 0, Last: 2}},
		{{First: 4, Last: 3}},
		{{First: 5, Last: 9}, {First: 3, Last: 3}},
		{{First: 3, Last: 5}, {First: 5, Last: 6}},
	}
	for _, ranges := range refused {
		bad := proto.CloneOf(coverage)
		bad.BodiesDropped = ranges
		if err := RecordBodyValidate(RecordKindCoverage, bad); !errors.Is(err, ErrRecordBodyOverCap) {
			t.Errorf("bodies_dropped %v passed", ranges)
		}
	}
	for _, source := range []string{"gateway ", "Harness", "context_partial"} {
		if RecordCoverageSourceKnown(source) {
			t.Errorf("source %q passed", source)
		}
	}
}

// A session node, part and blob within RecordBodySettings' caps pass, and one past any is refused, as a writer refuses
// it before it seals and a reader at step 5.
func TestSessionCapsRefusedPastSettings(t *testing.T) {
	settings := DefaultRecordBodySettings()
	digest := bytes.Repeat([]byte{0x33}, 32)
	id := func(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }
	ids := func(count int) [][]byte {
		list := [][]byte{}
		for i := range count {
			list = append(list, id(byte(i+1)))
		}
		return list
	}
	part := func() *protocol.SessionPart {
		return &protocol.SessionPart{Pointer: "/message/content/0/text", Sha256: digest, Size: 9 * 1024 * 1024, MediaType: "text/plain", BlobEntryIds: ids(2)}
	}
	node := func() *protocol.SessionEntryBody {
		return &protocol.SessionEntryBody{
			NodeId: id(1), ParentNodeId: id(2), ParentRunId: id(3), Type: 9, Item: []byte(`{}`), ItemSha256: digest, ChainSha256: digest,
			Parts: []*protocol.SessionPart{part()}, Marks: 3,
		}
	}
	if err := RecordBodyValidate(RecordKindSessionEntry, node()); err != nil {
		t.Fatalf("a node within its caps: %v", err)
	}
	atCaps := node()
	atCaps.Item = bytes.Repeat([]byte{'x'}, settings.SessionItemByteCount)
	atCaps.Parts = nil
	for range settings.SessionPartCount {
		atCaps.Parts = append(atCaps.Parts, part())
	}
	atCaps.Parts[0].BlobEntryIds = ids(settings.SessionBlobPieceCount)
	atCaps.Parts[0].Size = settings.SessionPartWholeByteCount
	if err := RecordBodyValidate(RecordKindSessionEntry, atCaps); err != nil {
		t.Errorf("a node at its caps: %v", err)
	}
	omitted := node()
	omitted.Parts = []*protocol.SessionPart{{Pointer: "/a", Sha256: digest, Size: settings.SessionPartWholeByteCount + 1, Omitted: true}}
	if err := RecordBodyValidate(RecordKindSessionEntry, omitted); err != nil {
		t.Errorf("a part past the whole cap, omitted: %v", err)
	}
	sameAs := &protocol.SessionEntryBody{NodeId: id(1), Type: 1, ItemSha256: digest, ChainSha256: digest, SameAs: id(4)}
	if err := RecordBodyValidate(RecordKindSessionEntry, sameAs); err != nil {
		t.Errorf("a same_as node: %v", err)
	}

	refusals := []struct {
		name string
		edit func(body *protocol.SessionEntryBody)
	}{
		{name: "an item past 16 KiB", edit: func(body *protocol.SessionEntryBody) { body.Item = bytes.Repeat([]byte{'x'}, settings.SessionItemByteCount+1) }},
		{name: "65 parts", edit: func(body *protocol.SessionEntryBody) {
			for len(body.Parts) <= settings.SessionPartCount {
				body.Parts = append(body.Parts, part())
			}
		}},
		{name: "a part in nine blobs", edit: func(body *protocol.SessionEntryBody) { body.Parts[0].BlobEntryIds = ids(settings.SessionBlobPieceCount + 1) }},
		{name: "a part kept whole past 64 MiB", edit: func(body *protocol.SessionEntryBody) {
			body.Parts[0].BlobEntryIds = ids(settings.SessionBlobPieceCount)
			body.Parts[0].Size = settings.SessionPartWholeByteCount + 1
		}},
		{name: "a part past its pieces", edit: func(body *protocol.SessionEntryBody) { body.Parts[0].Size = 2*uint64(settings.BlobByteCount) + 1 }},
		{name: "a part in no blob", edit: func(body *protocol.SessionEntryBody) { body.Parts[0].BlobEntryIds = nil }},
		{name: "an omitted part naming blobs", edit: func(body *protocol.SessionEntryBody) {
			body.Parts[0].Omitted = true
			body.Parts[0].Size = settings.SessionPartWholeByteCount + 1
		}},
		{name: "a part omitted under the cap", edit: func(body *protocol.SessionEntryBody) {
			body.Parts[0].Omitted = true
			body.Parts[0].BlobEntryIds = nil
		}},
		{name: "a pointer that is none", edit: func(body *protocol.SessionEntryBody) { body.Parts[0].Pointer = "message" }},
		{name: "a media type past its bytes", edit: func(body *protocol.SessionEntryBody) {
			body.Parts[0].MediaType = strings.Repeat("m", settings.SessionMediaTypeByteCount+1)
		}},
		{name: "a short part hash", edit: func(body *protocol.SessionEntryBody) { body.Parts[0].Sha256 = digest[:31] }},
		{name: "a short blob id", edit: func(body *protocol.SessionEntryBody) { body.Parts[0].BlobEntryIds[0] = id(1)[:15] }},
		{name: "a short node id", edit: func(body *protocol.SessionEntryBody) { body.NodeId = id(1)[:15] }},
		{name: "a parent run with no parent node", edit: func(body *protocol.SessionEntryBody) { body.ParentNodeId = nil }},
		{name: "type 0", edit: func(body *protocol.SessionEntryBody) { body.Type = 0 }},
		{name: "type 10", edit: func(body *protocol.SessionEntryBody) { body.Type = 10 }},
		{name: "a third mark", edit: func(body *protocol.SessionEntryBody) { body.Marks = 4 }},
		{name: "no item and no same_as", edit: func(body *protocol.SessionEntryBody) {
			body.Item = nil
			body.Parts = nil
		}},
		{name: "a same_as node holding an item", edit: func(body *protocol.SessionEntryBody) { body.SameAs = id(5) }},
		{name: "a short chain hash", edit: func(body *protocol.SessionEntryBody) { body.ChainSha256 = nil }},
	}
	for _, refusal := range refusals {
		body := node()
		refusal.edit(body)
		if err := RecordBodyValidate(RecordKindSessionEntry, body); !errors.Is(err, ErrRecordBodyOverCap) {
			t.Errorf("%s passed: %v", refusal.name, err)
		}
	}

	blob := &protocol.SessionBlobBody{PartSha256: digest, Index: 7, Count: 8, Content: bytes.Repeat([]byte{1}, settings.BlobByteCount)}
	if err := RecordBodyValidate(RecordKindSessionBlob, blob); err != nil {
		t.Errorf("a blob at its caps: %v", err)
	}
	blobRefusals := []func(body *protocol.SessionBlobBody){
		func(body *protocol.SessionBlobBody) { body.Content = append(body.Content, 1) },
		func(body *protocol.SessionBlobBody) { body.Index = body.Count },
		func(body *protocol.SessionBlobBody) { body.Count = uint32(settings.SessionBlobPieceCount + 1) },
		func(body *protocol.SessionBlobBody) { body.Count = 0 },
		func(body *protocol.SessionBlobBody) { body.PartSha256 = nil },
	}
	for i, edit := range blobRefusals {
		body := proto.CloneOf(blob)
		edit(body)
		if err := RecordBodyValidate(RecordKindSessionBlob, body); !errors.Is(err, ErrRecordBodyOverCap) {
			t.Errorf("blob refusal %d passed", i)
		}
	}

	call := &protocol.ModelCallBody{Model: "local-gemma-3n-e4b-low", Context: &protocol.CallContext{
		InputNodeId: id(1), OutputNodeIds: [][]byte{id(2)}, SystemNodeId: id(3), RequestSha256: digest, Renderer: "harness-1",
	}}
	if err := RecordBodyValidate(RecordKindModelCall, call); err != nil {
		t.Errorf("a model call with its context: %v", err)
	}
	callRefusals := []func(context *protocol.CallContext){
		func(context *protocol.CallContext) { context.InputNodeId = nil },
		func(context *protocol.CallContext) { context.OutputNodeIds = [][]byte{id(2)[:8]} },
		func(context *protocol.CallContext) { context.RequestSha256 = digest[:16] },
		func(context *protocol.CallContext) { context.Renderer = "" },
		func(context *protocol.CallContext) { context.Renderer = strings.Repeat("r", settings.ModelCallFieldByteCount+1) },
	}
	for i, edit := range callRefusals {
		body := proto.CloneOf(call)
		edit(body.Context)
		if err := RecordBodyValidate(RecordKindModelCall, body); !errors.Is(err, ErrRecordBodyOverCap) {
			t.Errorf("call context refusal %d passed", i)
		}
	}
}

// record.session_push_secs sets the push interval within 30 s and 300 s, and no setting leaves the default, 60 s; the
// defaults fill every field.
func TestSessionSettingsPushIntervalBounded(t *testing.T) {
	settings := DefaultSessionSettings()
	cases := []struct {
		pushSecs int
		want     time.Duration
	}{
		{pushSecs: 0, want: 60 * time.Second},
		{pushSecs: -5, want: 60 * time.Second},
		{pushSecs: 10, want: 30 * time.Second},
		{pushSecs: 30, want: 30 * time.Second},
		{pushSecs: 45, want: 45 * time.Second},
		{pushSecs: 300, want: 300 * time.Second},
		{pushSecs: 1000, want: 300 * time.Second},
	}
	for _, c := range cases {
		if got := settings.PushIntervalFor(c.pushSecs); got != c.want {
			t.Errorf("record.session_push_secs %d gives %s, want %s", c.pushSecs, got, c.want)
		}
	}
	if settings.GatewayIndexWindow != 24*time.Hour || settings.NetworkCapFraction != 0.9 || settings.WarningFraction != 0.8 ||
		settings.ExpiryTargetFraction != 0.7 || settings.MemberShareMin != 0.05 || settings.MemberShareMax != 1 || settings.Body == nil {
		t.Errorf("the defaults: %+v", settings)
	}
	if settings.body().SessionItemByteCount != 16*1024 || (&SessionSettings{}).body().SessionPartCount != 64 {
		t.Error("the record's caps are not RecordBodySettings' defaults")
	}
}
