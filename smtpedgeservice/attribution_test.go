// §14.8's attribution (SMTP-M9-15, D-SMTP-8) on the fake store: the three confidences, the X-UR-Ref replays
// that are dropped rather than demoted, and no Received address in a stored field (§2.8 smtp-5).

package smtpedgeservice_test

import (
	"bytes"
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// Two networks sending from the shared addresses, n1's send in the log, and the join over them.
type joinWorld struct {
	t           *testing.T
	ctx         context.Context
	store       *sidecartest.FakeSmtpEdgeStore
	settings    *smtpedgeservice.SmtpEdgeSettings
	attribution *smtpedgeservice.SmtpAttribution
	networkA    sidecar.Id
	networkB    sidecar.Id
	keyA        *sidecartest.SmtpDkimFixtureKey
	keyB        *sidecartest.SmtpDkimFixtureKey
	// n1's one send, from 192.0.2.10
	send   *smtpedgeservice.SmtpSendRecord
	xUrRef string
}

const (
	joinMessageIdA = "<aaaaaaaaaaaaaaaaaaaaaaaaaa@n1.root.example>"
	joinFeedbackId = "n:p:" + testReportToken + ":urnetwork"
)

var (
	joinSendTime       = time.Date(2026, time.November, 3, 10, 0, 0, 0, time.UTC)
	joinOtherAddress   = netip.MustParseAddr("192.0.2.11")
	joinSendingAddress = netip.MustParseAddr("192.0.2.10")
)

func newJoinWorld(t *testing.T) *joinWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(joinSendTime.Add(time.Hour))
	settings := testSettings()
	settings.SendingAddresses = append(settings.SendingAddresses, smtpedgeservice.SmtpSendingAddress{Address: joinOtherAddress, HeloName: "o2.out.report.example"})
	settings.XUrRefKeys = []*smtpedgeservice.SmtpXUrRefKey{testXUrRefKey}
	self := &joinWorld{
		t:        t,
		ctx:      ctx,
		store:    sidecartest.NewFakeSmtpEdgeStore(clock, nil),
		settings: settings,
		networkA: sidecar.NewId(),
		networkB: sidecar.NewId(),
		keyA:     sidecartest.NewSmtpDkimFixtureEd25519Key("join-a", "aaaaaaaaaaaaaaaaaaaaaaaaaa", "n1.root.example"),
		keyB:     sidecartest.NewSmtpDkimFixtureEd25519Key("join-b", "bbbbbbbbbbbbbbbbbbbbbbbbbb", "n2.root.example"),
	}
	self.store.PutDkimKey(self.keyA.StoredKey(self.networkA))
	self.store.PutDkimKey(self.keyB.StoredKey(self.networkB))
	self.send = &smtpedgeservice.SmtpSendRecord{
		SendId:          bytes.Repeat([]byte{0xa1}, smtpedgeservice.SmtpSendIdByteCount),
		NetworkId:       self.networkA,
		ClientId:        sidecar.NewId(),
		SendingAddress:  joinSendingAddress,
		RecipientDomain: "receiver.example",
		MxHost:          "mx.receiver.example",
		StartTime:       joinSendTime,
		EndTime:         joinSendTime.Add(30 * time.Second),
		MessageIdHash:   smtpedgeservice.SmtpMessageIdHash(joinMessageIdA),
		XUrRefKeyId:     1,
		RecipientCount:  1,
		Result:          "sent",
	}
	self.addSend(self.send)
	xUrRef, err := smtpedgeservice.IssueSmtpXUrRef(testXUrRefKey, self.send.SendId, self.networkA, smtpedgeservice.SmtpXUrRefDay(joinSendTime))
	if err != nil {
		t.Fatal(err)
	}
	self.xUrRef = xUrRef
	attribution, err := smtpedgeservice.NewSmtpAttribution(self.store, self.store, settings, clock)
	if err != nil {
		t.Fatal(err)
	}
	self.attribution = attribution
	return self
}

func (self *joinWorld) addSend(send *smtpedgeservice.SmtpSendRecord) {
	self.t.Helper()
	if err := self.store.InsertSends(self.ctx, []*smtpedgeservice.SmtpSendRecord{send}); err != nil {
		self.t.Fatal(err)
	}
}

// A message as the MX received it: From at fromDomain, the given Message-ID and X-UR-Ref, and a Received hop
// from address at the send's time plus a minute.
func (self *joinWorld) message(fromDomain string, messageId string, xUrRef string, address netip.Addr) []byte {
	received := "Received: from o1.out.report.example ([" + address.String() + "]) by mx.receiver.example; " + joinSendTime.Add(time.Minute).Format(time.RFC1123Z)
	return (&sidecartest.SmtpFixtureMessage{
		FromDomain:  fromDomain,
		MessageId:   messageId,
		XUrRef:      xUrRef,
		FeedbackId:  joinFeedbackId,
		Subject:     "a subject",
		Body:        "a body\n",
		Date:        joinSendTime,
		ExtraFields: []string{received},
	}).Bytes()
}

// message signed under key over §14.6's fields.
func joinSign(message []byte, key *sidecartest.SmtpDkimFixtureKey) []byte {
	return sidecartest.SignSmtpDkimFixture(message, key, &sidecartest.SmtpDkimFixtureOptions{
		HeaderRelaxed: true,
		BodyRelaxed:   true,
		Headers:       []string{"from", "to", "subject", "date", "message-id", "x-ur-ref", "feedback-id"},
	})
}

// The join of a loop's report enclosing enclosed's headers.
func (self *joinWorld) join(enclosed []byte, feedbackType string) *smtpedgeservice.SmtpJoinResult {
	self.t.Helper()
	raw := sidecartest.BuildSmtpArfReport("loop.example", feedbackType, enclosed, true)
	report, err := smtpedgeservice.ParseArfReportForTest(raw, self.settings)
	if err != nil {
		self.t.Fatalf("parse: %v", err)
	}
	result, err := self.attribution.Join(self.ctx, report)
	if err != nil {
		self.t.Fatalf("join: %v", err)
	}
	return result
}

func (self *joinWorld) expect(result *smtpedgeservice.SmtpJoinResult, confidence smtpedgeservice.SmtpConfidence, networkId sidecar.Id) {
	self.t.Helper()
	if result.Confidence != confidence || result.NetworkId != networkId {
		self.t.Fatalf("joined %q to %v (dropped %q), want %q to %v", result.Confidence, result.NetworkId, result.Dropped, confidence, networkId)
	}
}

func (self *joinWorld) expectDropped(result *smtpedgeservice.SmtpJoinResult, reason string) {
	self.t.Helper()
	if result.Confidence != "" || result.Dropped != reason {
		self.t.Fatalf("joined %q (dropped %q), want dropped %q", result.Confidence, result.Dropped, reason)
	}
	if result.Complaint() != nil {
		self.t.Fatal("a dropped join leaves a row")
	}
}

// High: n1's signature verifies over the reported headers and the Received hop names its send.
func TestAttributionHighJoin(t *testing.T) {
	w := newJoinWorld(t)
	result := w.join(joinSign(w.message("n1.root.example", joinMessageIdA, w.xUrRef, joinSendingAddress), w.keyA), "abuse")
	w.expect(result, smtpedgeservice.SmtpConfidenceHigh, w.networkA)
	if !result.Confidence.Halts() || !bytes.Equal(result.Send.SendId, w.send.SendId) || result.Label != "" {
		t.Fatalf("result %+v", result)
	}
	complaint := result.Complaint()
	if complaint.JoinResult != "high" || complaint.DkimDomain != "n1.root.example" || complaint.DkimResult != smtpedgeservice.SmtpDkimResultPass ||
		complaint.XUrRef != w.xUrRef || complaint.FeedbackId != joinFeedbackId || !bytes.Equal(complaint.MessageIdHash, w.send.MessageIdHash) {
		t.Fatalf("complaint %+v", complaint)
	}

	// with no X-UR-Ref the signature's network and the Received hop still join
	result = w.join(joinSign(w.message("n1.root.example", joinMessageIdA, "", joinSendingAddress), w.keyA), "abuse")
	w.expect(result, smtpedgeservice.SmtpConfidenceHigh, w.networkA)
}

// A burner's complaint names its label, which §14.8's first row halts.
func TestAttributionBurnerJoinNamesItsLabel(t *testing.T) {
	w := newJoinWorld(t)
	burnerKey := sidecartest.NewSmtpDkimFixtureEd25519Key("join-burner", "cccccccccccccccccccccccccc", "otter-1234.n1.root.example")
	w.store.PutDkimKey(burnerKey.StoredKey(w.networkA))
	result := w.join(joinSign(w.message("otter-1234.n1.root.example", joinMessageIdA, w.xUrRef, joinSendingAddress), burnerKey), "abuse")
	w.expect(result, smtpedgeservice.SmtpConfidenceHigh, w.networkA)
	if result.Label != "otter-1234" || result.Domain != "otter-1234.n1.root.example" {
		t.Fatalf("label %q, domain %q", result.Label, result.Domain)
	}
}

// Medium: the reporter masked a signed field, so no signature verifies here, but the X-UR-Ref verifies, the
// Received hop matches its send, and the signature's d= and s= are n1's key.
func TestAttributionMediumJoin(t *testing.T) {
	w := newJoinWorld(t)
	signed := joinSign(w.message("n1.root.example", joinMessageIdA, w.xUrRef, joinSendingAddress), w.keyA)
	masked := bytes.Replace(signed, []byte("To: recipient@receiver.example"), []byte("To: xxxxxxxxx@receiver.example"), 1)
	if bytes.Equal(masked, signed) {
		t.Fatal("the fixture's To was not masked")
	}
	result := w.join(masked, "abuse")
	w.expect(result, smtpedgeservice.SmtpConfidenceMedium, w.networkA)
	if !result.Confidence.Halts() || result.DkimResult != smtpedgeservice.SmtpDkimResultFail || result.DkimDomain != "n1.root.example" {
		t.Fatalf("result %+v", result)
	}
}

// Low: nothing signed and no X-UR-Ref, but the Message-ID names one network's send from that address.
func TestAttributionLowJoinNeverHalts(t *testing.T) {
	w := newJoinWorld(t)
	result := w.join(w.message("n1.root.example", joinMessageIdA, "", joinSendingAddress), "abuse")
	w.expect(result, smtpedgeservice.SmtpConfidenceLow, w.networkA)
	if result.Confidence.Halts() || result.Complaint().JoinResult != "low" {
		t.Fatalf("result %+v", result)
	}

	// a Message-ID two networks sent from that address names neither
	w.addSend(&smtpedgeservice.SmtpSendRecord{
		SendId:          bytes.Repeat([]byte{0xb2}, smtpedgeservice.SmtpSendIdByteCount),
		NetworkId:       w.networkB,
		ClientId:        sidecar.NewId(),
		SendingAddress:  joinSendingAddress,
		RecipientDomain: "receiver.example",
		MxHost:          "mx.receiver.example",
		StartTime:       joinSendTime.Add(10 * time.Second),
		MessageIdHash:   smtpedgeservice.SmtpMessageIdHash(joinMessageIdA),
		Result:          "sent",
	})
	w.expectDropped(w.join(w.message("n1.root.example", joinMessageIdA, "", joinSendingAddress), "abuse"), smtpedgeservice.SmtpJoinDropUnjoined)
}

// §22.5's row: a report replaying n1's X-UR-Ref under n2's verifying d= is dropped, so it halts nothing, even
// with n2's own send from that address in the log; the genuine one joins n1.
func TestAttributionXUrRefReplayUnderAnotherNetworksDkimIsDropped(t *testing.T) {
	w := newJoinWorld(t)
	w.addSend(&smtpedgeservice.SmtpSendRecord{
		SendId:          bytes.Repeat([]byte{0xb3}, smtpedgeservice.SmtpSendIdByteCount),
		NetworkId:       w.networkB,
		ClientId:        sidecar.NewId(),
		SendingAddress:  joinSendingAddress,
		RecipientDomain: "receiver.example",
		MxHost:          "mx.receiver.example",
		StartTime:       joinSendTime.Add(20 * time.Second),
		MessageIdHash:   smtpedgeservice.SmtpMessageIdHash("<b@n2.root.example>"),
		Result:          "sent",
	})
	replay := w.join(joinSign(w.message("n2.root.example", "<b@n2.root.example>", w.xUrRef, joinSendingAddress), w.keyB), "abuse")
	w.expectDropped(replay, smtpedgeservice.SmtpJoinDropForeignSignature)

	genuine := w.join(joinSign(w.message("n1.root.example", joinMessageIdA, w.xUrRef, joinSendingAddress), w.keyA), "abuse")
	w.expect(genuine, smtpedgeservice.SmtpConfidenceHigh, w.networkA)
}

// A replay from another sending address than the X-UR-Ref's send left from, or hours later, is dropped.
func TestAttributionReplayFromAnotherAddressOrTimeIsDropped(t *testing.T) {
	w := newJoinWorld(t)
	w.expectDropped(w.join(joinSign(w.message("n1.root.example", joinMessageIdA, w.xUrRef, joinOtherAddress), w.keyA), "abuse"), smtpedgeservice.SmtpJoinDropReplay)

	late := bytes.Replace(
		joinSign(w.message("n1.root.example", joinMessageIdA, w.xUrRef, joinSendingAddress), w.keyA),
		[]byte(joinSendTime.Add(time.Minute).Format(time.RFC1123Z)),
		[]byte(joinSendTime.Add(3*time.Hour).Format(time.RFC1123Z)),
		1,
	)
	w.expectDropped(w.join(late, "abuse"), smtpedgeservice.SmtpJoinDropReplay)
}

// A forgery: an X-UR-Ref with no signature at all is dropped, and one whose MAC does not verify too.
func TestAttributionForgeriesAreDropped(t *testing.T) {
	w := newJoinWorld(t)
	w.expectDropped(w.join(w.message("n1.root.example", joinMessageIdA, w.xUrRef, joinSendingAddress), "abuse"), smtpedgeservice.SmtpJoinDropForeignSignature)

	// the same send_id under n2's network: a MAC that names another network
	forged, err := smtpedgeservice.IssueSmtpXUrRef(testXUrRefKey, w.send.SendId, w.networkB, smtpedgeservice.SmtpXUrRefDay(joinSendTime))
	if err != nil {
		t.Fatal(err)
	}
	w.expectDropped(w.join(joinSign(w.message("n1.root.example", joinMessageIdA, forged, joinSendingAddress), w.keyA), "abuse"), smtpedgeservice.SmtpJoinDropXUrRef)

	// no Received hop from a sending address: nothing to join against
	noReceived := (&sidecartest.SmtpFixtureMessage{FromDomain: "n1.root.example", MessageId: joinMessageIdA, XUrRef: w.xUrRef, Subject: "s", Body: "b\n", Date: joinSendTime}).Bytes()
	w.expectDropped(w.join(joinSign(noReceived, w.keyA), "abuse"), smtpedgeservice.SmtpJoinDropNoReceived)
}

// A not-spam report joins like any other, so it can cancel its complaint (§14.8; the ladder counts).
func TestAttributionNotSpamJoins(t *testing.T) {
	w := newJoinWorld(t)
	result := w.join(joinSign(w.message("n1.root.example", joinMessageIdA, w.xUrRef, joinSendingAddress), w.keyA), "not-spam")
	w.expect(result, smtpedgeservice.SmtpConfidenceHigh, w.networkA)
}

// The Received address serves the join only: no field of the row a join leaves holds it (§2.8 smtp-5).
func TestAttributionStoresNoReceivedAddress(t *testing.T) {
	w := newJoinWorld(t)
	for _, enclosed := range [][]byte{
		joinSign(w.message("n1.root.example", joinMessageIdA, w.xUrRef, joinSendingAddress), w.keyA),
		w.message("n1.root.example", joinMessageIdA, "", joinSendingAddress),
	} {
		complaint := w.join(enclosed, "abuse").Complaint()
		if complaint == nil {
			t.Fatal("no join")
		}
		value := reflect.ValueOf(complaint).Elem()
		for i := range value.NumField() {
			field := value.Field(i)
			text := ""
			switch field.Kind() {
			case reflect.String:
				text = field.String()
			case reflect.Slice:
				if bytes, ok := field.Interface().([]byte); ok {
					text = string(bytes)
					if bytesContain(bytes, joinSendingAddress.AsSlice()) {
						t.Fatalf("%s holds the Received address's octets", value.Type().Field(i).Name)
					}
				}
			}
			if strings.Contains(text, joinSendingAddress.String()) {
				t.Fatalf("%s holds the Received address", value.Type().Field(i).Name)
			}
		}
	}
}

func bytesContain(haystack []byte, needle []byte) bool {
	return 0 < len(needle) && bytes.Contains(haystack, needle)
}
