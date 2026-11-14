//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
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
	receipts.note(grant, tlsReachTestIp("2001:db8::7"), 1, 0)
	receipts.note(grant, tlsReachTestIp("2001:db8::8"), 1, 0)
	receipts.note(grant, tlsReachTestIp("2001:db8::7"), 0, 500)
	receipts.note(&TlsPublishGrant{GrantIds: grant.GrantIds, PolicyVersion: 9}, tlsReachTestIp("2001:db8:1::7"), 1, 40)

	clock.advance(5*time.Minute - time.Millisecond)
	writer.none(t)
	clock.advance(time.Millisecond)
	written := map[uint64]*RecordDraft{}
	for range 2 {
		draft, receipt := writer.next(t)
		written[receipt.GetStreamCount()] = draft
		if !bytes.Equal(receipt.GetGrantId(), lowGrantId) || receipt.GetKind() != uint32(RecordReachKindPublish) ||
			receipt.GetWindowStartMillis() != windowStart.UnixMilli() || !bytes.Equal(receipt.GetOwner(), receipts.sidecarId.Bytes()) ||
			len(receipt.GetPeers()) != 1 || len(receipt.GetPeers()[0]) != tlsReachPeerByteCount {
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

	receipts.note(grant, tlsReachTestIp("2001:db8::9"), 1, 0)
	clock.advance(5 * time.Minute)
	_, next := writer.next(t)
	if next.GetWindowStartMillis() != windowStart.Add(5*time.Minute).UnixMilli() || next.GetStreamCount() != 1 ||
		!bytes.Equal(next.GetPeers()[0], oneReceipt.GetPeers()[0]) {
		t.Errorf("the next window's %+v", next)
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
		receipts.note(grant, tlsReachTestIp(address), 1, 100)
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
	other.note(grant, tlsReachTestIp(addresses[0]), 1, 0)
	other.close()
	if _, receipt := writer.next(t); peers[string(receipt.GetPeers()[0])] {
		t.Error("another network names the visitor alike")
	}
	restarted.note(grant, tlsReachTestIp(addresses[0]), 1, 0)
	restarted.close()
	if _, receipt := writer.next(t); !peers[string(receipt.GetPeers()[0])] {
		t.Error("a restart names the visitor apart")
	}
	// bytes that are no address name no visitor and count nowhere
	restarted.note(grant, []byte{1, 2, 3}, 1, 0)
	writer.none(t)
}

// A receipt is written when its grant's expiry passes, before its window ends.
func TestTlsReachReceiptsWriteAtGrantEnd(t *testing.T) {
	clock := newTlsFrontTestClock()
	writer := newTlsReachTestWriter(t)
	receipts := newTlsReachTestReceipts(t, clock, writer, newTlsFrontTestSecrets(), NewId(), nil)
	grant := &TlsPublishGrant{GrantIds: [][]byte{NewId().Bytes()}, Expires: clock.Now().Add(2 * time.Minute)}
	receipts.note(grant, tlsReachTestIp("198.51.100.4"), 1, 0)
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
	receipts.note(grant, tlsReachTestIp("198.51.100.1"), 1, 0)
	receipts.note(grant, tlsReachTestIp("198.51.100.2"), 1, 0)
	writer.none(t)
	receipts.note(grant, tlsReachTestIp("198.51.100.3"), 1, 0)
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
	receipts.note(grant, tlsReachTestIp("203.0.113.5"), 1, 0)
	receipts.close()
	if _, receipt := writer.next(t); receipt.GetStreamCount() != 1 {
		t.Errorf("%+v", receipt)
	}
	receipts.note(grant, tlsReachTestIp("203.0.113.5"), 0, 2048)
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
		if !bytes.Equal(receipt.GetGrantId(), grantId) || !bytes.Equal(receipt.GetOwner(), fixture.sidecarId.Bytes()) || len(receipt.GetPeers()) != 1 {
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
	receipts.note(&TlsPublishGrant{GrantIds: [][]byte{NewId().Bytes()}}, tlsReachTestIp("192.0.2.1"), 1, 0)
	receipts.close()
	settings := DefaultTlsFrontSettings()
	settings.ReachReceiptMaxCount = 0
	if settings.validate() == nil {
		t.Error("no receipts held")
	}
}
