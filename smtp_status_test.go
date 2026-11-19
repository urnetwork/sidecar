//go:build !sidecar_http && !ios_extension

// SmtpStatusHold (SMTP-M9-09): HALTED and QUOTA hold until retry_after_ms and never shorten a longer hold; one naming
// no wait holds StatusHoldTimeout; CLEAR releases; a code of 0, an unknown kind or bytes that do not decode are
// dropped; other mail hints and other topics leave the hold alone.

package sidecar_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

func testStatusNotice(t *testing.T, kind protocol.SmtpStatusKind, retryAfter time.Duration) sidecar.PushNotice {
	t.Helper()
	hint, err := proto.Marshal(&protocol.SmtpStatus{Kind: uint32(kind), RetryAfterMs: uint32(retryAfter.Milliseconds())})
	if err != nil {
		t.Fatal(err)
	}
	return sidecar.PushNotice{Topic: sidecar.PushTopicMail, Kind: uint32(protocol.MessageType_SMTP_STATUS), Hint: hint}
}

func TestSmtpStatusHoldHoldsAndReleases(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := sidecar.DefaultSmtpSenderSettings()
	hold := sidecar.NewSmtpStatusHold(settings, clock)
	if held, _ := hold.Held(); held {
		t.Fatal("held from the start")
	}
	hold.Notice(testStatusNotice(t, protocol.SmtpStatusKind_SMTP_STATUS_QUOTA, 10*time.Minute))
	held, until := hold.Held()
	if !held || !until.Equal(clock.Now().Add(10*time.Minute)) {
		t.Fatalf("QUOTA: %v until %v", held, until)
	}
	// a shorter one does not shorten it
	hold.Notice(testStatusNotice(t, protocol.SmtpStatusKind_SMTP_STATUS_HALTED, time.Minute))
	if _, until := hold.Held(); !until.Equal(clock.Now().Add(10 * time.Minute)) {
		t.Errorf("shortened to %v", until)
	}
	hold.Notice(testStatusNotice(t, protocol.SmtpStatusKind_SMTP_STATUS_CLEAR, 0))
	if held, _ := hold.Held(); held {
		t.Error("held after CLEAR")
	}
	// a halt that names no wait holds a day; it ends on its own
	hold.Notice(testStatusNotice(t, protocol.SmtpStatusKind_SMTP_STATUS_HALTED, 0))
	if _, until := hold.Held(); !until.Equal(clock.Now().Add(settings.StatusHoldTimeout)) {
		t.Errorf("a halt with no wait holds until %v", until)
	}
	clock.Advance(settings.StatusHoldTimeout)
	if held, _ := hold.Held(); held {
		t.Error("held past the halt")
	}
}

func TestSmtpStatusHoldDropsProtocolErrors(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	hold := sidecar.NewSmtpStatusHold(sidecar.DefaultSmtpSenderSettings(), clock)
	hold.Notice(testStatusNotice(t, protocol.SmtpStatusKind_SMTP_STATUS_KIND_UNSPECIFIED, time.Hour))
	hold.Notice(testStatusNotice(t, protocol.SmtpStatusKind(9), time.Hour))
	hold.Notice(sidecar.PushNotice{Topic: sidecar.PushTopicMail, Kind: uint32(protocol.MessageType_SMTP_STATUS), Hint: []byte{0xff, 0xff}})
	if held, _ := hold.Held(); held || hold.DroppedCount() != 3 {
		t.Errorf("held %v after %d drops", held, hold.DroppedCount())
	}
	// another hint of topic mail, a resync, and another topic: nothing
	notice := testStatusNotice(t, protocol.SmtpStatusKind_SMTP_STATUS_HALTED, time.Hour)
	notice.Kind = uint32(protocol.MessageType_SMTP_OUTCOME)
	hold.Notice(notice)
	hold.Notice(sidecar.PushNotice{Topic: sidecar.PushTopicMail, Resync: true})
	notice = testStatusNotice(t, protocol.SmtpStatusKind_SMTP_STATUS_HALTED, time.Hour)
	notice.Topic = sidecar.PushTopicCore
	hold.Notice(notice)
	if held, _ := hold.Held(); held || hold.DroppedCount() != 3 {
		t.Errorf("held %v after %d drops", held, hold.DroppedCount())
	}
}
