// testdata/mail/vectors.yml on every leg the root's tests run on, the sidecar_http Worker included, which is why the
// file is embedded and why this sits in the root and not beside protocol/mail.proto: a Worker has no file system.
// protoc wrote each message's bytes from its text, so a vector proves the wire and not this module's own encoder.
// Its clock and order rows hold MAIL-FORMAT.md's rules until MailHlc lands (MAIL-M7-06), and its trailer rows the
// deposit's layout until the receiver (MAIL-M7-14) writes it and ingest (MAIL-M7-15) reads it, each taking these rows
// as its own.

package sidecar

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	_ "embed"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/urnetwork/sidecar/protocol"
)

// Embedded so a Worker, which has no file system, runs these too.
//
//go:embed testdata/mail/vectors.yml
var mailVectorsYaml string

// Where protoregistry finds a vector's type.
const mailVectorPackage = "urnetwork.sidecar."

// A list item's values by key.
type mailVectorItem map[string]string

// Reads the one shape vectors.yml keeps, and stops on any other line: the root links no YAML parser, and a line this
// skipped would be a vector that never ran. A quoted scalar loses its quotes, and a block keeps its newlines.
func parseMailVectors(t *testing.T) map[string][]mailVectorItem {
	t.Helper()
	sectionItems := map[string][]mailVectorItem{}
	section := ""
	var item mailVectorItem
	blockKey := ""
	set := func(key string, value string) {
		if _, ok := item[key]; ok {
			t.Fatalf("%s repeats %s", item["name"], key)
		}
		item[key] = strings.Trim(value, `"`)
	}
	for number, line := range strings.Split(mailVectorsYaml, "\n") {
		if blockKey != "" {
			if text, ok := strings.CutPrefix(line, "      "); ok {
				item[blockKey] += text + "\n"
				continue
			}
			blockKey = ""
		}
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":"):
			section = strings.TrimSuffix(line, ":")
			item = nil
		case strings.HasPrefix(line, "  - "), strings.HasPrefix(line, "    "):
			if strings.HasPrefix(line, "  - ") {
				item = mailVectorItem{}
				sectionItems[section] = append(sectionItems[section], item)
			}
			key, value, ok := strings.Cut(line[4:], ": ")
			if !ok || item == nil || strings.HasPrefix(key, " ") {
				t.Fatalf("line %d: %q", number+1, line)
			}
			if value == "|" {
				blockKey = key
				item[key] = ""
				continue
			}
			set(key, value)
		default:
			t.Fatalf("line %d: %q", number+1, line)
		}
	}
	return sectionItems
}

// A decimal value of an item.
func mailVectorNumber(t *testing.T, item mailVectorItem, key string) uint64 {
	t.Helper()
	number, err := strconv.ParseUint(item[key], 10, 64)
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return number
}

// An item's message, from its bytes and from its text, each parsed on its own.
func mailVectorMessages(t *testing.T, item mailVectorItem) (fromBytes proto.Message, fromText proto.Message, encoded []byte) {
	t.Helper()
	messageType, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(mailVectorPackage + item["type"]))
	if err != nil {
		t.Fatalf("%s: %v", item["name"], err)
	}
	encoded, err = hex.DecodeString(item["hex"])
	if err != nil {
		t.Fatalf("%s: %v", item["name"], err)
	}
	fromBytes = messageType.New().Interface()
	if err := proto.Unmarshal(encoded, fromBytes); err != nil {
		t.Fatalf("%s: %v", item["name"], err)
	}
	fromText = messageType.New().Interface()
	if err := prototext.Unmarshal([]byte(item["text"]), fromText); err != nil {
		t.Fatalf("%s: %v", item["name"], err)
	}
	return fromBytes, fromText, encoded
}

// protoc's bytes and its text are one message here, whose encoding is those bytes again: a renumbered field, a changed
// type or a dropped one parts them. No field arrives unknown, since a vector's text names only declared fields.
func TestMailVectorsRoundTrip(t *testing.T) {
	items := parseMailVectors(t)["messages"]
	if len(items) == 0 {
		t.Fatal("no vectors")
	}
	for _, item := range items {
		fromBytes, fromText, encoded := mailVectorMessages(t, item)
		if !proto.Equal(fromBytes, fromText) {
			t.Errorf("%s: its bytes and its text differ", item["name"])
		}
		again, err := proto.MarshalOptions{Deterministic: true}.Marshal(fromBytes)
		if err != nil {
			t.Fatalf("%s: %v", item["name"], err)
		}
		if !bytes.Equal(again, encoded) {
			t.Errorf("%s: re-encoded to %x", item["name"], again)
		}
		if len(fromBytes.ProtoReflect().GetUnknown()) != 0 {
			t.Errorf("%s: holds an unknown field", item["name"])
		}
	}
}

// §15.5's bound on the one vector that writes every identifier at its width.
func TestMailVectorIngressFitsItsBound(t *testing.T) {
	for _, item := range parseMailVectors(t)["messages"] {
		if item["type"] != "MailIngress" {
			continue
		}
		_, _, encoded := mailVectorMessages(t, item)
		if len(encoded) > 1024 {
			t.Errorf("%s takes %d B", item["name"], len(encoded))
		}
	}
}

// Every message of mail.proto and every field of each is set in some vector, so a field added to the format fails
// here until its bytes are pinned.
func TestMailVectorsCoverEveryField(t *testing.T) {
	coveredFieldNames := map[protoreflect.FullName]bool{}
	var cover func(message protoreflect.Message)
	cover = func(message protoreflect.Message) {
		coveredFieldNames[message.Descriptor().FullName()] = true
		message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
			coveredFieldNames[field.FullName()] = true
			switch {
			case field.IsList() && field.Message() != nil:
				list := value.List()
				for i := range list.Len() {
					cover(list.Get(i).Message())
				}
			case field.Message() != nil:
				cover(value.Message())
			}
			return true
		})
	}
	for _, item := range parseMailVectors(t)["messages"] {
		fromBytes, _, _ := mailVectorMessages(t, item)
		cover(fromBytes.ProtoReflect())
	}
	file, err := protoregistry.GlobalFiles.FindFileByPath("protocol/mail.proto")
	if err != nil {
		t.Fatal(err)
	}
	for i := range file.Messages().Len() {
		message := file.Messages().Get(i)
		if !coveredFieldNames[message.FullName()] {
			t.Errorf("no vector holds %s", message.Name())
		}
		fields := message.Fields()
		for j := range fields.Len() {
			if !coveredFieldNames[fields.Get(j).FullName()] {
				t.Errorf("no vector sets %s", fields.Get(j).FullName())
			}
		}
	}
}

// MAIL-FORMAT.md's deposit layout (plan-MAIL-deposit-shape): the message as received, its MailDeposit, then u32be of
// that MailDeposit's length, so a reader finds the trailer from the last four bytes before reading the body. A
// receiver's evidence names the message by its SHA-256, and a same-network deposit sets only its three fields.
func TestMailVectorTrailers(t *testing.T) {
	items := parseMailVectors(t)["trailers"]
	if len(items) == 0 {
		t.Fatal("no trailers")
	}
	for _, item := range items {
		plaintext, err := hex.DecodeString(item["plaintext"])
		if err != nil || len(plaintext) < 4 {
			t.Fatalf("%s: %d B, %v", item["name"], len(plaintext), err)
		}
		depositEnd := len(plaintext) - 4
		messageEnd := depositEnd - int(binary.BigEndian.Uint32(plaintext[depositEnd:]))
		if messageEnd < 0 || uint64(messageEnd) != mailVectorNumber(t, item, "message_bytes") {
			t.Fatalf("%s: the trailer puts the message's end at %d", item["name"], messageEnd)
		}
		deposit := &protocol.MailDeposit{}
		if err := proto.Unmarshal(plaintext[messageEnd:depositEnd], deposit); err != nil {
			t.Fatalf("%s: %v", item["name"], err)
		}
		fromText := &protocol.MailDeposit{}
		if err := prototext.Unmarshal([]byte(item["text"]), fromText); err != nil {
			t.Fatalf("%s: %v", item["name"], err)
		}
		if !proto.Equal(deposit, fromText) {
			t.Errorf("%s: its trailer and its text differ", item["name"])
		}
		if deposit.Evidence == nil {
			deposit.ProtoReflect().Range(func(field protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
				if name := field.Name(); name != "version" && name != "mail_from" && name != "recipients" {
					t.Errorf("%s: a same-network deposit sets %s", item["name"], name)
				}
				return true
			})
			continue
		}
		sum := sha256.Sum256(plaintext[:messageEnd])
		if !bytes.Equal(deposit.Evidence.MessageSha256, sum[:]) {
			t.Errorf("%s: the evidence names another message", item["name"])
		}
	}
}

// MAIL-FORMAT.md's <h> and its spelling of a binary name.
func TestMailVectorNames(t *testing.T) {
	items := parseMailVectors(t)["names"]
	if len(items) == 0 {
		t.Fatal("no names")
	}
	spelling := base32.StdEncoding.WithPadding(base32.NoPadding)
	for _, item := range items {
		sum := sha256.Sum256([]byte(item["name"]))
		if h := hex.EncodeToString(sum[:1]); h != item["h"] {
			t.Errorf("%s: <h> is %s, want %s", item["name"], h, item["h"])
		}
		if item["hex"] == "" {
			continue
		}
		raw, err := hex.DecodeString(item["hex"])
		if err != nil {
			t.Fatal(err)
		}
		if name := strings.ToLower(spelling.EncodeToString(raw)); name != item["name"] {
			t.Errorf("%s spells %s", item["hex"], name)
		}
		// §11.7's name table rows hold names under 64 B, and §15.7 sizes these families by them.
		if len(item["name"]) >= 64 {
			t.Errorf("%s takes %d B", item["name"], len(item["name"]))
		}
	}
}

// MAIL-FORMAT.md's <yyyymm>, in UTC whatever this leg's zone, across a year's end.
func TestMailVectorMonths(t *testing.T) {
	items := parseMailVectors(t)["months"]
	if len(items) == 0 {
		t.Fatal("no months")
	}
	for _, item := range items {
		month := time.UnixMilli(int64(mailVectorNumber(t, item, "millis"))).UTC().Format("200601")
		if month != item["month"] {
			t.Errorf("%s is %s, want %s", item["millis"], month, item["month"])
		}
	}
}

// MAIL-FORMAT.md's tick, stopping at the top of the clock rather than wrapping below every op.
func TestMailVectorClocks(t *testing.T) {
	items := parseMailVectors(t)["clocks"]
	if len(items) == 0 {
		t.Fatal("no clocks")
	}
	tick := func(last uint64, nowMillis uint64) uint64 {
		next := last
		if last != math.MaxUint64 {
			next = last + 1
		}
		return max(nowMillis<<16, next)
	}
	for _, item := range items {
		last := mailVectorNumber(t, item, "last")
		got := tick(last, mailVectorNumber(t, item, "now"))
		if want := mailVectorNumber(t, item, "hlc"); got != want {
			t.Errorf("after %d: %d, want %d", last, got, want)
		}
	}
}

// MAIL-FORMAT.md's order, which is total, so the winner is the same read either way round.
func TestMailVectorOrders(t *testing.T) {
	items := parseMailVectors(t)["orders"]
	if len(items) == 0 {
		t.Fatal("no orders")
	}
	type op struct {
		hlc       uint64
		sidecarId []byte
		set       bool
	}
	compare := func(a op, b op) int {
		rank := func(set bool) int {
			if set {
				return 1
			}
			return 0
		}
		return cmp.Or(cmp.Compare(a.hlc, b.hlc), bytes.Compare(a.sidecarId, b.sidecarId), cmp.Compare(rank(a.set), rank(b.set)))
	}
	read := func(item mailVectorItem, side string) op {
		sidecarId, err := hex.DecodeString(item[side+"_sidecar"])
		if err != nil {
			t.Fatal(err)
		}
		return op{hlc: mailVectorNumber(t, item, side+"_hlc"), sidecarId: sidecarId, set: item[side+"_set"] == "true"}
	}
	for number, item := range items {
		a, b := read(item, "a"), read(item, "b")
		winner := "a"
		if compare(a, b) < 0 {
			winner = "b"
		}
		if winner != item["wins"] {
			t.Errorf("order %d: %s won", number, winner)
		}
		if compare(a, b) != -compare(b, a) || compare(a, b) == 0 {
			t.Errorf("order %d is not total", number)
		}
	}
}

// The comparison these vectors rest on: one byte apart, a message's bytes and text do not compare equal.
func TestMailVectorComparisonSeesAChangedByte(t *testing.T) {
	fromBytes, fromText, _ := mailVectorMessages(t, mailVectorItem{
		"name": "planted",
		"type": "MailHint",
		"hex":  "0802",
		"text": "kind: MAIL_HINT_DEPOSIT\n",
	})
	hint, ok := fromBytes.(*protocol.MailHint)
	if !ok || hint.Kind != protocol.MailHintKind_MAIL_HINT_RECEIVER_NEEDED {
		t.Fatalf("the planted bytes read as %v", fromBytes)
	}
	if proto.Equal(fromBytes, fromText) {
		t.Error("two different kinds compared equal")
	}
}
