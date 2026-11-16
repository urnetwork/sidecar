//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The names a test's visitors ask for: the endpoint's host and an alias of it, as the front holds them, lowercase.
const (
	tlsReachTestServerName = "app.abcdefghij.ur.example"
	tlsReachTestAliasName  = "docs.abcdefghij.ur.example"
)

// A record writer that keeps each draft it takes, held to the rules the real writer holds a draft to.
type tlsReachTestWriter struct {
	t      *testing.T
	drafts chan *RecordDraft
}

var _ RecordWriter = (*tlsReachTestWriter)(nil)

// A writer with room for every draft a test makes.
func newTlsReachTestWriter(t *testing.T) *tlsReachTestWriter {
	return &tlsReachTestWriter{t: t, drafts: make(chan *RecordDraft, 1024)}
}

// See RecordWriter.
func (self *tlsReachTestWriter) Append(draft *RecordDraft) ([]*RecordEntryRef, error) {
	if err := draft.check(); err != nil {
		self.t.Errorf("a draft the writer refuses: %v", err)
		return nil, err
	}
	if _, err := draft.bodyBytes(); err != nil {
		self.t.Errorf("a body the writer refuses: %v", err)
		return nil, err
	}
	self.drafts <- draft
	return []*RecordEntryRef{{}}, nil
}

// The next draft written, and its receipt, within the guard.
func (self *tlsReachTestWriter) next(t *testing.T) (*RecordDraft, *protocol.ReachReceipt) {
	t.Helper()
	select {
	case draft := <-self.drafts:
		receipt, ok := draft.Body.(*protocol.ReachReceipt)
		if !ok {
			t.Fatalf("a %T", draft.Body)
		}
		return draft, receipt
	case <-time.After(tlsFrontTestGuard):
		t.Fatal("no receipt was written")
		return nil, nil
	}
}

// Fails if a draft was written that no test has taken.
func (self *tlsReachTestWriter) none(t *testing.T) {
	t.Helper()
	select {
	case draft := <-self.drafts:
		t.Errorf("a receipt was written: %+v", draft.Body)
	default:
	}
}

// Receipts on clock into writer for one network, configure changing the settings first.
func newTlsReachTestReceipts(t *testing.T, clock Clock, writer RecordWriter, secrets SidecarSecrets, networkId Id, configure func(settings *TlsFrontSettings)) *tlsReachReceipts {
	t.Helper()
	settings := DefaultTlsFrontSettings()
	if configure != nil {
		configure(settings)
	}
	receipts, err := newTlsReachReceipts(context.Background(), &tlsReachReceiptsArgs{
		Writer:    writer,
		Settings:  settings,
		Secrets:   secrets,
		NetworkId: networkId,
		SidecarId: NewId(),
		Clock:     clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(receipts.close)
	return receipts
}

// An address's bytes, as TlsEdgeOpen's client_ip carries it.
func tlsReachTestIp(text string) []byte {
	return netip.MustParseAddr(text).AsSlice()
}

// The written receipts, by their first peer, each its own.
func tlsReachTestByPeer(t *testing.T, writer *tlsReachTestWriter, count int) map[string]*protocol.ReachReceipt {
	t.Helper()
	receipts := map[string]*protocol.ReachReceipt{}
	for range count {
		_, receipt := writer.next(t)
		if len(receipt.GetPeers()) != 1 {
			t.Fatalf("%d peers", len(receipt.GetPeers()))
		}
		receipts[string(receipt.GetPeers()[0])] = receipt
	}
	return receipts
}

// §13.7: one receipt per grant, visitor and 5 min, on a fake clock. Two addresses of one /64 are one visitor, whose
// streams and bytes add up; another /64 is another; nothing is written before the window ends; the next window is its
// own receipt, naming the same visitor by the same hash.
func TestTlsReachReceiptsCoalescePerWindow(t *testing.T) {
	clock := newTlsFrontTestClock()
	writer := newTlsReachTestWriter(t)
	receipts := newTlsReachTestReceipts(t, clock, writer, newTlsFrontTestSecrets(), NewId(), nil)
	lowGrantId := bytes.Repeat([]byte{0x01}, len(Id{}))
	grant := &TlsPublishGrant{GrantIds: [][]byte{bytes.Repeat([]byte{0x09}, len(Id{})), lowGrantId}, PolicyVersion: 7}
	windowStart := clock.Now()
	receipts.note(grant, tlsReachTestIp("2001:db8::7"), tlsReachTestServerName, 1, 0)
	// the loop has armed the window's end before the clock moves, and the notes after it share that deadline
	clock.waitArmed(t, 5*time.Minute, 1)
	receipts.note(grant, tlsReachTestIp("2001:db8::8"), tlsReachTestServerName, 1, 0)
	receipts.note(grant, tlsReachTestIp("2001:db8::7"), tlsReachTestServerName, 0, 500)
	receipts.note(&TlsPublishGrant{GrantIds: grant.GrantIds, PolicyVersion: 9}, tlsReachTestIp("2001:db8:1::7"), tlsReachTestServerName, 1, 40)

	clock.advance(5*time.Minute - time.Millisecond)
	writer.none(t)
	clock.advance(time.Millisecond)
	written := map[uint64]*RecordDraft{}
	for range 2 {
		draft, receipt := writer.next(t)
		written[receipt.GetStreamCount()] = draft
		if !bytes.Equal(receipt.GetGrantId(), lowGrantId) || receipt.GetKind() != uint32(RecordReachKindPublish) ||
			receipt.GetWindowStartMillis() != windowStart.UnixMilli() || !bytes.Equal(receipt.GetOwner(), receipts.sidecarId.Bytes()) ||
			len(receipt.GetPeers()) != 1 || len(receipt.GetPeers()[0]) != tlsReachPeerByteCount ||
			receipt.GetServerName() != tlsReachTestServerName || len(receipt.GetRelays()) != 0 {
			t.Errorf("receipt %+v", receipt)
		}
		if draft.Kind != RecordKindReach || draft.Source != RecordSourceObserved || !draft.NoSession || draft.GrantId != nil {
			t.Errorf("draft %+v", draft)
		}
	}
	one, two := written[2], written[1]
	if one == nil || two == nil {
		t.Fatalf("%d receipts by stream count, not one of 2 and one of 1", len(written))
	}
	oneReceipt, twoReceipt := one.Body.(*protocol.ReachReceipt), two.Body.(*protocol.ReachReceipt)
	if oneReceipt.GetByteCount() != 500 || oneReceipt.GetPolicyVersion() != 7 || twoReceipt.GetByteCount() != 40 || twoReceipt.GetPolicyVersion() != 9 {
		t.Errorf("counts %+v and %+v", oneReceipt, twoReceipt)
	}
	if bytes.Equal(oneReceipt.GetPeers()[0], twoReceipt.GetPeers()[0]) {
		t.Error("two visitors share a hash")
	}

	receipts.note(grant, tlsReachTestIp("2001:db8::9"), tlsReachTestServerName, 1, 0)
	clock.waitArmed(t, 5*time.Minute, 1)
	clock.advance(5 * time.Minute)
	_, next := writer.next(t)
	if next.GetWindowStartMillis() != windowStart.Add(5*time.Minute).UnixMilli() || next.GetStreamCount() != 1 ||
		!bytes.Equal(next.GetPeers()[0], oneReceipt.GetPeers()[0]) || next.GetServerName() != tlsReachTestServerName {
		t.Errorf("the next window's %+v", next)
	}
	writer.none(t)
}

// QD-850: a visitor who reaches two of the endpoint's names in one window has two receipts, each with its name and
// its own counts, under one grant, peer hash and window; a name in another case is the front's to fold, so the key
// takes it as given; and a connection with no name writes a receipt that names none. The name is never a relay.
func TestTlsReachReceiptsCoalescePerServerName(t *testing.T) {
	clock := newTlsFrontTestClock()
	writer := newTlsReachTestWriter(t)
	receipts := newTlsReachTestReceipts(t, clock, writer, newTlsFrontTestSecrets(), NewId(), nil)
	grant := &TlsPublishGrant{GrantIds: [][]byte{NewId().Bytes()}, PolicyVersion: 4}
	visitor := tlsReachTestIp("2001:db8::7")
	windowStart := clock.Now()
	receipts.note(grant, visitor, tlsReachTestServerName, 1, 0)
	// the loop has armed the window's end before the clock moves, and the notes after it share that deadline
	clock.waitArmed(t, 5*time.Minute, 1)
	receipts.note(grant, visitor, tlsReachTestAliasName, 1, 0)
	receipts.note(grant, tlsReachTestIp("2001:db8::8"), tlsReachTestServerName, 1, 0)
	receipts.note(grant, visitor, tlsReachTestServerName, 0, 700)
	receipts.note(grant, visitor, tlsReachTestAliasName, 0, 30)
	receipts.note(grant, visitor, "", 1, 5)

	clock.advance(5*time.Minute - time.Millisecond)
	writer.none(t)
	clock.advance(time.Millisecond)
	byName := map[string]*protocol.ReachReceipt{}
	var peer []byte
	for range 3 {
		_, receipt := writer.next(t)
		if byName[receipt.GetServerName()] != nil {
			t.Fatalf("two receipts for %q", receipt.GetServerName())
		}
		byName[receipt.GetServerName()] = receipt
		if receipt.GetWindowStartMillis() != windowStart.UnixMilli() || !bytes.Equal(receipt.GetGrantId(), grant.GrantIds[0]) ||
			len(receipt.GetPeers()) != 1 || len(receipt.GetRelays()) != 0 {
			t.Errorf("receipt %+v", receipt)
		}
		if peer != nil && !bytes.Equal(peer, receipt.GetPeers()[0]) {
			t.Error("one visitor has two hashes")
		}
		peer = receipt.GetPeers()[0]
	}
	writer.none(t)
	host, alias, unnamed := byName[tlsReachTestServerName], byName[tlsReachTestAliasName], byName[""]
	if host == nil || alias == nil || unnamed == nil {
		t.Fatalf("receipts for %d names, not the host, the alias and none", len(byName))
	}
	if host.GetStreamCount() != 2 || host.GetByteCount() != 700 {
		t.Errorf("the host's %+v", host)
	}
	if alias.GetStreamCount() != 1 || alias.GetByteCount() != 30 {
		t.Errorf("the alias's %+v", alias)
	}
	if unnamed.GetStreamCount() != 1 || unnamed.GetByteCount() != 5 {
		t.Errorf("the unnamed %+v", unnamed)
	}
	// a receipt that names none encodes no field 11, as a receipt written before the field did
	encoded, err := proto.Marshal(unnamed)
	if err != nil {
		t.Fatal(err)
	}
	if tlsReachTestHasField(t, encoded, 11) {
		t.Error("an unnamed receipt encodes server_name")
	}

	// a connection that ends after the close writes its own receipt, with its name
	receipts.close()
	receipts.note(grant, visitor, tlsReachTestAliasName, 0, 9)
	if _, receipt := writer.next(t); receipt.GetServerName() != tlsReachTestAliasName || receipt.GetByteCount() != 9 {
		t.Errorf("after the close %+v", receipt)
	}
	writer.none(t)
}

// Whether encoded, a message's bytes, holds a field numbered number at its top level.
func tlsReachTestHasField(t *testing.T, encoded []byte, number protowire.Number) bool {
	t.Helper()
	for 0 < len(encoded) {
		fieldNumber, wireType, tagByteCount := protowire.ConsumeTag(encoded)
		if tagByteCount < 0 {
			t.Fatal(protowire.ParseError(tagByteCount))
		}
		encoded = encoded[tagByteCount:]
		valueByteCount := protowire.ConsumeFieldValue(fieldNumber, wireType, encoded)
		if valueByteCount < 0 {
			t.Fatal(protowire.ParseError(valueByteCount))
		}
		encoded = encoded[valueByteCount:]
		if fieldNumber == number {
			return true
		}
	}
	return false
}

// QD-850's field is additive: a receipt as a writer before it encoded one, fields 1 to 10 and no 11, reads with every
// field as it was and no server name, and encodes again to the same bytes; one with the name is those bytes and
// field 11 after them, a string, so a reader before the field keeps it as an unknown field and reads the rest alike.
func TestReachReceiptWithoutServerNameReadsAsBefore(t *testing.T) {
	grantId := bytes.Repeat([]byte{0x21}, 32)
	owner := bytes.Repeat([]byte{0x31}, 16)
	approver := bytes.Repeat([]byte{0x41}, 16)
	peer := bytes.Repeat([]byte{0x51}, 16)
	relay := "edge-1.example - example-operator"
	old := []byte{}
	old = protowire.AppendBytes(protowire.AppendTag(old, 1, protowire.BytesType), grantId)
	old = protowire.AppendVarint(protowire.AppendTag(old, 2, protowire.VarintType), 7)
	old = protowire.AppendVarint(protowire.AppendTag(old, 3, protowire.VarintType), uint64(RecordReachKindPublish))
	old = protowire.AppendBytes(protowire.AppendTag(old, 4, protowire.BytesType), owner)
	old = protowire.AppendBytes(protowire.AppendTag(old, 5, protowire.BytesType), approver)
	old = protowire.AppendVarint(protowire.AppendTag(old, 6, protowire.VarintType), 1_800_000_000_000)
	old = protowire.AppendBytes(protowire.AppendTag(old, 7, protowire.BytesType), peer)
	old = protowire.AppendVarint(protowire.AppendTag(old, 8, protowire.VarintType), 3)
	old = protowire.AppendVarint(protowire.AppendTag(old, 9, protowire.VarintType), 4096)
	old = protowire.AppendString(protowire.AppendTag(old, 10, protowire.BytesType), relay)

	receipt := &protocol.ReachReceipt{}
	if err := proto.Unmarshal(old, receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.GetServerName() != "" || len(receipt.ProtoReflect().GetUnknown()) != 0 {
		t.Errorf("an old receipt reads a name or an unknown field: %+v", receipt)
	}
	if !bytes.Equal(receipt.GetGrantId(), grantId) || receipt.GetPolicyVersion() != 7 || receipt.GetKind() != uint32(RecordReachKindPublish) ||
		!bytes.Equal(receipt.GetOwner(), owner) || !bytes.Equal(receipt.GetApprover(), approver) ||
		receipt.GetWindowStartMillis() != 1_800_000_000_000 || len(receipt.GetPeers()) != 1 || !bytes.Equal(receipt.GetPeers()[0], peer) ||
		receipt.GetStreamCount() != 3 || receipt.GetByteCount() != 4096 || len(receipt.GetRelays()) != 1 || receipt.GetRelays()[0] != relay {
		t.Errorf("an old receipt reads apart: %+v", receipt)
	}
	options := proto.MarshalOptions{Deterministic: true}
	again, err := options.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, old) {
		t.Errorf("an old receipt encodes again as %x, not %x", again, old)
	}

	receipt.ServerName = tlsReachTestAliasName
	named, err := options.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	want := protowire.AppendString(protowire.AppendTag(bytes.Clone(old), 11, protowire.BytesType), tlsReachTestAliasName)
	if !bytes.Equal(named, want) {
		t.Errorf("a named receipt encodes as %x, not %x", named, want)
	}
	read := &protocol.ReachReceipt{}
	if err := proto.Unmarshal(named, read); err != nil {
		t.Fatal(err)
	}
	if read.GetServerName() != tlsReachTestAliasName || len(read.GetRelays()) != 1 || read.GetRelays()[0] != relay {
		t.Errorf("a named receipt reads %+v", read)
	}
}

// What lists a receipt's fields carries the name as server_name, never among relays: an export line's fields are the
// body by proto field name, and the SIEM formats, which keep of a body only numbers, ids and listed identifier
// strings, carry no relays and the name nowhere else.
func TestReachReceiptServerNameIsAFieldOfItsOwn(t *testing.T) {
	receipt := &protocol.ReachReceipt{
		GrantId:     bytes.Repeat([]byte{0x21}, 32),
		Kind:        uint32(RecordReachKindPublish),
		Peers:       [][]byte{bytes.Repeat([]byte{0x51}, tlsReachPeerByteCount)},
		StreamCount: 1,
		ServerName:  tlsReachTestAliasName,
	}
	fields := recordExportFields(receipt.ProtoReflect())
	if name, _ := fields["server_name"].(string); name != tlsReachTestAliasName {
		t.Errorf("an export line's server_name is %v", fields["server_name"])
	}
	if _, found := fields["relays"]; found {
		t.Errorf("an export line of a receipt with no relay lists relays: %v", fields["relays"])
	}
	for name, value := range recordExportSafeFields(fields) {
		if name == "relays" {
			t.Error("a SIEM format carries relays")
		}
		if text, ok := value.(string); ok && text == tlsReachTestAliasName && name != "server_name" {
			t.Errorf("a SIEM format carries the name as %s", name)
		}
	}
}

// §16.8's other writer of receipts, the record's own coalescer, which every endpoint but the TLS front notes to,
// sets no server name: a forward between sidecars and a visitor it keys itself both leave field 11 unwritten.
func TestRecordReachReceiptsNameNoServer(t *testing.T) {
	clock := newTlsFrontTestClock()
	writer := newTlsReachTestWriter(t)
	reach := NewRecordReach(&RecordReachArgs{Writer: writer, Clock: clock, RecordSettings: defaultSidecarRecordSettings()})
	t.Cleanup(reach.Close)
	notes := []*RecordReachNote{
		{
			Kind:        RecordReachKindForward,
			GrantId:     bytes.Repeat([]byte{0x21}, 32),
			Owner:       NewId().Bytes(),
			Peers:       [][]byte{NewId().Bytes()},
			StreamCount: 1,
			ByteCount:   100,
			Relays:      []RecordReachRelay{{Host: "relay-1.example"}},
		},
		{
			Kind:        RecordReachKindListen,
			GrantId:     bytes.Repeat([]byte{0x22}, 32),
			Owner:       NewId().Bytes(),
			Visitor:     netip.MustParseAddr("2001:db8::7"),
			StreamCount: 1,
		},
	}
	for _, note := range notes {
		if err := reach.Note(note); err != nil {
			t.Fatal(err)
		}
	}
	reach.Flush()
	for range notes {
		_, receipt := writer.next(t)
		encoded, err := proto.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		if receipt.GetServerName() != "" || tlsReachTestHasField(t, encoded, 11) {
			t.Errorf("a receipt of kind %d names a server: %+v", receipt.GetKind(), receipt)
		}
	}
	writer.none(t)
}

// I-13: no receipt holds the visitor's address, in either family, as bytes, as a mapped address or as text; the
// hash is keyed per network, so two networks name one visitor apart, and one network's restart names it alike.
func TestTlsReachReceiptsHoldNoAddress(t *testing.T) {
	clock := newTlsFrontTestClock()
	writer := newTlsReachTestWriter(t)
	secrets := newTlsFrontTestSecrets()
	networkId := NewId()
	receipts := newTlsReachTestReceipts(t, clock, writer, secrets, networkId, nil)
	grant := &TlsPublishGrant{GrantIds: [][]byte{bytes.Repeat([]byte{0x01}, 32)}}
	addresses := []string{"2001:db8::7", "192.0.2.10"}
	for _, address := range addresses {
		receipts.note(grant, tlsReachTestIp(address), tlsReachTestServerName, 1, 100)
	}
	receipts.close()
	peers := map[string]bool{}
	for range addresses {
		draft, receipt := writer.next(t)
		if !bytes.Equal(draft.GrantId, grant.GrantIds[0]) {
			t.Errorf("an activated grant's id is not the header's: %x", draft.GrantId)
		}
		body, err := proto.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			addr := netip.MustParseAddr(address)
			mapped := netip.AddrFrom16(addr.As16())
			forms := [][]byte{addr.AsSlice(), mapped.AsSlice(), []byte(address)}
			if addr.Is6() {
				// the /64 the visitor is
				forms = append(forms, addr.AsSlice()[:8])
			}
			for _, form := range forms {
				if bytes.Contains(body, form) {
					t.Errorf("a receipt holds %s", address)
				}
			}
		}
		peers[string(receipt.GetPeers()[0])] = true
	}

	other := newTlsReachTestReceipts(t, clock, writer, secrets, NewId(), nil)
	restarted := newTlsReachTestReceipts(t, clock, writer, secrets, networkId, nil)
	other.note(grant, tlsReachTestIp(addresses[0]), tlsReachTestServerName, 1, 0)
	other.close()
	if _, receipt := writer.next(t); peers[string(receipt.GetPeers()[0])] {
		t.Error("another network names the visitor alike")
	}
	restarted.note(grant, tlsReachTestIp(addresses[0]), tlsReachTestServerName, 1, 0)
	restarted.close()
	if _, receipt := writer.next(t); !peers[string(receipt.GetPeers()[0])] {
		t.Error("a restart names the visitor apart")
	}
	// bytes that are no address name no visitor and count nowhere
	restarted.note(grant, []byte{1, 2, 3}, tlsReachTestServerName, 1, 0)
	writer.none(t)
}

// A receipt is written when its grant's expiry passes, before its window ends.
func TestTlsReachReceiptsWriteAtGrantEnd(t *testing.T) {
	clock := newTlsFrontTestClock()
	writer := newTlsReachTestWriter(t)
	receipts := newTlsReachTestReceipts(t, clock, writer, newTlsFrontTestSecrets(), NewId(), nil)
	grant := &TlsPublishGrant{GrantIds: [][]byte{NewId().Bytes()}, Expires: clock.Now().Add(2 * time.Minute)}
	receipts.note(grant, tlsReachTestIp("198.51.100.4"), tlsReachTestServerName, 1, 0)
	clock.waitArmed(t, 2*time.Minute, 1)
	clock.advance(2*time.Minute - time.Millisecond)
	writer.none(t)
	clock.advance(time.Millisecond)
	if _, receipt := writer.next(t); receipt.GetStreamCount() != 1 {
		t.Errorf("%+v", receipt)
	}
}

// Past ReachReceiptMaxCount the receipts held are written early, never dropped: two held and a third arriving writes
// the two and holds the third, which the close writes.
func TestTlsReachReceiptsOverflowWritesEarly(t *testing.T) {
	clock := newTlsFrontTestClock()
	writer := newTlsReachTestWriter(t)
	receipts := newTlsReachTestReceipts(t, clock, writer, newTlsFrontTestSecrets(), NewId(), func(settings *TlsFrontSettings) {
		settings.ReachReceiptMaxCount = 2
	})
	grant := &TlsPublishGrant{GrantIds: [][]byte{NewId().Bytes()}}
	receipts.note(grant, tlsReachTestIp("198.51.100.1"), tlsReachTestServerName, 1, 0)
	receipts.note(grant, tlsReachTestIp("198.51.100.2"), tlsReachTestServerName, 1, 0)
	writer.none(t)
	receipts.note(grant, tlsReachTestIp("198.51.100.3"), tlsReachTestServerName, 1, 0)
	early := tlsReachTestByPeer(t, writer, 2)
	writer.none(t)
	receipts.close()
	held := tlsReachTestByPeer(t, writer, 1)
	for peer := range held {
		if early[peer] != nil {
			t.Error("the held receipt was written twice")
		}
	}
}

// The close writes what is held, and a connection ending after it writes its own receipt at once.
func TestTlsReachReceiptsCloseWritesWhatIsHeld(t *testing.T) {
	clock := newTlsFrontTestClock()
	writer := newTlsReachTestWriter(t)
	receipts := newTlsReachTestReceipts(t, clock, writer, newTlsFrontTestSecrets(), NewId(), nil)
	grant := &TlsPublishGrant{GrantIds: [][]byte{NewId().Bytes()}, PolicyVersion: 3}
	receipts.note(grant, tlsReachTestIp("203.0.113.5"), tlsReachTestServerName, 1, 0)
	receipts.close()
	if _, receipt := writer.next(t); receipt.GetStreamCount() != 1 {
		t.Errorf("%+v", receipt)
	}
	receipts.note(grant, tlsReachTestIp("203.0.113.5"), tlsReachTestServerName, 0, 2048)
	if _, receipt := writer.next(t); receipt.GetStreamCount() != 0 || receipt.GetByteCount() != 2048 || receipt.GetPolicyVersion() != 3 {
		t.Errorf("after the close %+v", receipt)
	}
	writer.none(t)
}

// Through the front: a visitor whose request reached the service is one stream and its bytes under the endpoint's
// grant, written by the close at the latest, naming no address; a visitor the audience check stopped is no reach.
func TestTlsFrontWritesReachReceipts(t *testing.T) {
	writer := newTlsReachTestWriter(t)
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.record = writer
	})
	response, body := tlsFrontTestDo(t, fixture.httpClient(tlsAlpnHttp11), tlsFrontTestNavigation(t, http.MethodGet, "/page"))
	if response.StatusCode != http.StatusOK || body != "backend" {
		t.Fatalf("%d %q", response.StatusCode, body)
	}
	fixture.backend.nextRequest(t)
	fixture.front.Close()
	grantId := fixture.policy.PublishGrant(tlsFrontTestName, "app", fixture.clock.Now()).GrantIds[0]
	visitor := tlsFrontTestVisitor().Addr()
	streams, byteCount := uint64(0), uint64(0)
	for streams < 1 || byteCount == 0 {
		_, receipt := writer.next(t)
		if !bytes.Equal(receipt.GetGrantId(), grantId) || !bytes.Equal(receipt.GetOwner(), fixture.sidecarId.Bytes()) || len(receipt.GetPeers()) != 1 ||
			receipt.GetServerName() != tlsFrontTestServerName || len(receipt.GetRelays()) != 0 {
			t.Fatalf("%+v", receipt)
		}
		encoded, err := proto.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, visitor.AsSlice()) || bytes.Contains(encoded, []byte(visitor.String())) {
			t.Error("a receipt holds the visitor's address")
		}
		streams += receipt.GetStreamCount()
		byteCount += receipt.GetByteCount()
	}
	if streams != 1 {
		t.Errorf("%d streams", streams)
	}

	refusedWriter := newTlsReachTestWriter(t)
	refused := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.record = refusedWriter
		fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_MEMBERS, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
	})
	if response, _ := tlsFrontTestDo(t, refused.httpClient(tlsAlpnHttp11), tlsFrontTestNavigation(t, http.MethodGet, "/page")); response.StatusCode != http.StatusFound {
		t.Fatalf("refused: %d", response.StatusCode)
	}
	refused.front.Close()
	refusedWriter.none(t)
}

// QD-850, through the front: one visitor who reaches the endpoint by its host and by an alias, in one window, has
// receipts under each name, each with that name's one stream and its bytes, under one grant and one peer hash.
func TestTlsFrontReachReceiptsNameTheServerAsked(t *testing.T) {
	writer := newTlsReachTestWriter(t)
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.record = writer
		fixture.target.ServerNames = []string{tlsFrontTestServerName, tlsReachTestAliasName}
	})
	aliasTransport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			config := &tls.Config{ServerName: tlsReachTestAliasName, NextProtos: []string{tlsAlpnHttp11}, InsecureSkipVerify: true}
			return fixture.dialTls(config, func(ticket *protocol.SocketTicket, open *protocol.TlsEdgeOpen) []byte {
				open.ServerName = tlsReachTestAliasName
				return nil
			})
		},
	}
	t.Cleanup(aliasTransport.CloseIdleConnections)
	aliasRequest := tlsFrontTestNavigation(t, http.MethodGet, "/page")
	aliasRequest.URL.Host = tlsReachTestAliasName
	aliasRequest.Host = tlsReachTestAliasName
	requests := []struct {
		client  *http.Client
		request *http.Request
	}{
		{client: fixture.httpClient(tlsAlpnHttp11), request: tlsFrontTestNavigation(t, http.MethodGet, "/page")},
		{client: &http.Client{Transport: aliasTransport}, request: aliasRequest},
	}
	for _, request := range requests {
		response, body := tlsFrontTestDo(t, request.client, request.request)
		if response.StatusCode != http.StatusOK || body != "backend" {
			t.Fatalf("%s: %d %q", request.request.Host, response.StatusCode, body)
		}
		fixture.backend.nextRequest(t)
	}
	fixture.front.Close()

	streams, byteCounts := map[string]uint64{}, map[string]uint64{}
	var peer []byte
	names := []string{tlsFrontTestServerName, tlsReachTestAliasName}
	for slices.ContainsFunc(names, func(name string) bool { return streams[name] < 1 || byteCounts[name] == 0 }) {
		_, receipt := writer.next(t)
		if !slices.Contains(names, receipt.GetServerName()) || len(receipt.GetPeers()) != 1 || len(receipt.GetRelays()) != 0 {
			t.Fatalf("%+v", receipt)
		}
		if peer != nil && !bytes.Equal(peer, receipt.GetPeers()[0]) {
			t.Error("one visitor has two hashes")
		}
		peer = receipt.GetPeers()[0]
		streams[receipt.GetServerName()] += receipt.GetStreamCount()
		byteCounts[receipt.GetServerName()] += receipt.GetByteCount()
	}
	for _, name := range names {
		if streams[name] != 1 {
			t.Errorf("%d streams under %s", streams[name], name)
		}
	}
}

// A receipt's window is at least a millisecond, and a front with no writer holds no receipts.
func TestTlsReachReceiptsSettings(t *testing.T) {
	recordSettings := defaultSidecarRecordSettings()
	recordSettings.ReachReceiptCoalesce = time.Microsecond
	if _, err := newTlsReachReceipts(context.Background(), &tlsReachReceiptsArgs{
		Writer:         newTlsReachTestWriter(t),
		RecordSettings: recordSettings,
		Settings:       DefaultTlsFrontSettings(),
		Secrets:        newTlsFrontTestSecrets(),
	}); err == nil {
		t.Error("a window under a millisecond")
	}
	receipts, err := newTlsReachReceipts(context.Background(), &tlsReachReceiptsArgs{Settings: DefaultTlsFrontSettings()})
	if err != nil || receipts != nil {
		t.Fatalf("%v %v", receipts, err)
	}
	// a nil one notes and closes as nothing
	receipts.note(&TlsPublishGrant{GrantIds: [][]byte{NewId().Bytes()}}, tlsReachTestIp("192.0.2.1"), tlsReachTestServerName, 1, 0)
	receipts.close()
	settings := DefaultTlsFrontSettings()
	settings.ReachReceiptMaxCount = 0
	if settings.validate() == nil {
		t.Error("no receipts held")
	}
}
