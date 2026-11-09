//go:build !sidecar_http

// SmtpPinStore on a fake clock and a fake store: a pin rises, holds PinTimeout from the last send that
// reached it, refuses anything below it, then lapses; it and each domain's mode survive a restart; and
// a file that cannot be read is never read as no pins.

package sidecar_test

import (
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	testPinHost   = "mx.mail.example"
	testPinDomain = "mail.example"
)

var testPinStart = time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)

// A pin store on a fresh fake store and clock, with the default settings.
func newTestPinStore(t *testing.T) (*sidecar.SmtpPinStore, *sidecartest.FakeStore, *sidecartest.FakeClock) {
	t.Helper()
	store := sidecartest.NewFakeStore()
	clock := sidecartest.NewFakeClock(testPinStart)
	return sidecar.NewSmtpPinStore(store.Root(), sidecar.DefaultSmtpSenderSettings(), clock), store, clock
}

func testPinLevel(t *testing.T, pins *sidecar.SmtpPinStore, host string) sidecar.SmtpTlsLevel {
	t.Helper()
	pin, err := pins.Pin(host)
	if err != nil {
		t.Fatal(err)
	}
	if pin == nil {
		return sidecar.SmtpTlsLevelUnreached
	}
	return pin.Level
}

// A pin rises to a better level, holds 90 days from the send that reached it, refuses anything below
// it while it holds, and then lapses, after which the next send pins what it reaches (§14.4).
func TestSmtpPinRisesAndHoldsNinetyDaysThenLapses(t *testing.T) {
	pins, _, clock := newTestPinStore(t)
	if level := testPinLevel(t, pins, testPinHost); level != sidecar.SmtpTlsLevelUnreached {
		t.Fatalf("a pin before any send: %d", level)
	}
	if _, err := pins.Raise(testPinHost, sidecar.SmtpTlsLevelIndependentMx); err != nil {
		t.Fatal(err)
	}
	pin, err := pins.Raise(testPinHost, sidecar.SmtpTlsLevelDane)
	if err != nil || pin.Level != sidecar.SmtpTlsLevelDane || !pin.PinTime.Equal(testPinStart) {
		t.Fatalf("the rise: %+v %v", pin, err)
	}
	clock.Advance(89 * 24 * time.Hour)
	for _, level := range []sidecar.SmtpTlsLevel{sidecar.SmtpTlsLevelMtaSts, sidecar.SmtpTlsLevelIndependentMx, sidecar.SmtpTlsLevelUnauthenticated} {
		if _, err := pins.Raise(testPinHost, level); !errors.Is(err, sidecar.ErrSmtpPinBelow) {
			t.Errorf("level %d under a TL1 pin on day 89: %v", level, err)
		}
	}
	if level := testPinLevel(t, pins, testPinHost); level != sidecar.SmtpTlsLevelDane {
		t.Errorf("a refused send moved the pin: %d", level)
	}
	clock.Advance(24 * time.Hour)
	if level := testPinLevel(t, pins, testPinHost); level != sidecar.SmtpTlsLevelUnreached {
		t.Fatalf("a pin past 90 days: %d", level)
	}
	pin, err = pins.Raise(testPinHost, sidecar.SmtpTlsLevelIndependentMx)
	if err != nil || pin.Level != sidecar.SmtpTlsLevelIndependentMx || !pin.PinTime.Equal(clock.Now()) {
		t.Errorf("the send after the lapse: %+v %v", pin, err)
	}
}

// A send at the pinned level restarts its 90 days, so a host reached at TL1 now and then stays pinned.
func TestSmtpPinRefreshesAtItsLevel(t *testing.T) {
	pins, _, clock := newTestPinStore(t)
	if _, err := pins.Raise(testPinHost, sidecar.SmtpTlsLevelDane); err != nil {
		t.Fatal(err)
	}
	clock.Advance(60 * 24 * time.Hour)
	if _, err := pins.Raise(testPinHost, sidecar.SmtpTlsLevelDane); err != nil {
		t.Fatal(err)
	}
	clock.Advance(60 * 24 * time.Hour)
	pin, err := pins.Pin(testPinHost)
	if err != nil || pin == nil || pin.Level != sidecar.SmtpTlsLevelDane {
		t.Fatalf("120 days after the first send, 60 after the second: %+v %v", pin, err)
	}
	if want := testPinStart.Add(150 * 24 * time.Hour); !pin.ExpireTime(sidecar.DefaultSmtpSenderSettings().PinTimeout).Equal(want) {
		t.Errorf("expires %v, want %v", pin.ExpireTime(sidecar.DefaultSmtpSenderSettings().PinTimeout), want)
	}
}

// Names compare as DNS does: a host in another case or with a trailing dot is the same host.
func TestSmtpPinNamesCompareAsDnsDoes(t *testing.T) {
	pins, _, _ := newTestPinStore(t)
	if _, err := pins.Raise("MX.Mail.Example.", sidecar.SmtpTlsLevelDane); err != nil {
		t.Fatal(err)
	}
	if level := testPinLevel(t, pins, testPinHost); level != sidecar.SmtpTlsLevelDane {
		t.Errorf("%d", level)
	}
	if _, err := pins.Raise("mx..example", sidecar.SmtpTlsLevelDane); err == nil {
		t.Error("a host outside RFC 5321's Domain")
	}
	if _, err := pins.Raise(testPinHost, sidecar.SmtpTlsLevelUnreached); err == nil {
		t.Error("an unreached level pinned")
	}
}

// The pins and each domain's last mode survive a restart: a new store over the same files reads them.
func TestSmtpPinSurvivesARestart(t *testing.T) {
	pins, store, clock := newTestPinStore(t)
	if _, err := pins.Raise(testPinHost, sidecar.SmtpTlsLevelMtaSts); err != nil {
		t.Fatal(err)
	}
	if err := pins.RecordMode(testPinDomain, testPinHost, sidecar.SmtpModeData); err != nil {
		t.Fatal(err)
	}
	restarted := sidecar.NewSmtpPinStore(store.Root(), sidecar.DefaultSmtpSenderSettings(), clock)
	if level := testPinLevel(t, restarted, testPinHost); level != sidecar.SmtpTlsLevelMtaSts {
		t.Errorf("the pin after a restart: %d", level)
	}
	if _, err := restarted.Raise(testPinHost, sidecar.SmtpTlsLevelIndependentMx); !errors.Is(err, sidecar.ErrSmtpPinBelow) {
		t.Errorf("a downgrade after a restart: %v", err)
	}
	if mode, err := restarted.DomainMode(testPinDomain); err != nil || mode != sidecar.SmtpModeData {
		t.Errorf("the mode after a restart: %d %v", mode, err)
	}
}

// A domain's mode is its last session's, kept as long as a pin, for Check (§14.5), and a session that
// ended before its EHLO reply records nothing.
func TestSmtpPinDomainModeLastsAsAPinDoes(t *testing.T) {
	pins, _, clock := newTestPinStore(t)
	if mode, err := pins.DomainMode(testPinDomain); err != nil || mode != sidecar.SmtpModeUnknown {
		t.Fatalf("before any session: %d %v", mode, err)
	}
	if _, err := pins.Raise(testPinHost, sidecar.SmtpTlsLevelIndependentMx); err != nil {
		t.Fatal(err)
	}
	if err := pins.RecordMode(testPinDomain, testPinHost, sidecar.SmtpModeBdat); err != nil {
		t.Fatal(err)
	}
	if err := pins.RecordMode(testPinDomain, testPinHost, sidecar.SmtpModeUnknown); err != nil {
		t.Fatal(err)
	}
	if mode, _ := pins.DomainMode("MAIL.example."); mode != sidecar.SmtpModeBdat {
		t.Errorf("after a BDAT session: %d", mode)
	}
	clock.Advance(30 * 24 * time.Hour)
	if err := pins.RecordMode(testPinDomain, testPinHost, sidecar.SmtpModeData); err != nil {
		t.Fatal(err)
	}
	clock.Advance(89 * 24 * time.Hour)
	if mode, _ := pins.DomainMode(testPinDomain); mode != sidecar.SmtpModeData {
		t.Errorf("89 days after a DATA session: %d", mode)
	}
	pin, _ := pins.Pin(testPinHost)
	if pin != nil {
		t.Errorf("the level's pin outlived its 90 days: %+v", pin)
	}
	clock.Advance(24 * time.Hour)
	if mode, _ := pins.DomainMode(testPinDomain); mode != sidecar.SmtpModeUnknown {
		t.Errorf("90 days after: %d", mode)
	}
}

// Past PinMaxCount the pin closest to lapsing leaves first.
func TestSmtpPinCountIsBounded(t *testing.T) {
	store := sidecartest.NewFakeStore()
	clock := sidecartest.NewFakeClock(testPinStart)
	settings := sidecar.DefaultSmtpSenderSettings()
	settings.PinMaxCount = 2
	pins := sidecar.NewSmtpPinStore(store.Root(), settings, clock)
	for _, host := range []string{"mx1.mail.example", "mx2.mail.example", "mx3.mail.example"} {
		if _, err := pins.Raise(host, sidecar.SmtpTlsLevelDane); err != nil {
			t.Fatal(err)
		}
		clock.Advance(time.Hour)
	}
	if level := testPinLevel(t, pins, "mx1.mail.example"); level != sidecar.SmtpTlsLevelUnreached {
		t.Errorf("the oldest pin stayed past the bound: %d", level)
	}
	for _, host := range []string{"mx2.mail.example", "mx3.mail.example"} {
		if level := testPinLevel(t, pins, host); level != sidecar.SmtpTlsLevelDane {
			t.Errorf("%s: %d", host, level)
		}
	}
}

// A pin file that does not parse is a failed store, never no pins, so a downgrade cannot pass a pin it
// lost (D-CORE-15); and a write that fails leaves the pin as it was.
func TestSmtpPinStoreFailsClosed(t *testing.T) {
	for _, data := range []string{"{", `{"version":2,"pins":[]}`, `{"version":1,"pins":[{"mx_host":"MX.mail.example","level":1,"pin_time_ms":1}]}`,
		`{"version":1,"pins":[{"mx_host":"mx.mail.example","level":7,"pin_time_ms":1}]}`, `{"version":1,"pins":[null]}`} {
		store := sidecartest.NewFakeStore()
		writer, err := store.Root().Create("tls-pins")
		if err != nil {
			t.Fatal(err)
		}
		writer.Write([]byte(data))
		if err := writer.Commit(); err != nil {
			t.Fatal(err)
		}
		pins := sidecar.NewSmtpPinStore(store.Root(), sidecar.DefaultSmtpSenderSettings(), sidecartest.NewFakeClock(testPinStart))
		if _, err := pins.Pin(testPinHost); !errors.Is(err, sidecar.ErrSidecarStoreFailed) {
			t.Errorf("%s: %v", data, err)
		}
	}

	pins, store, _ := newTestPinStore(t)
	if _, err := pins.Raise(testPinHost, sidecar.SmtpTlsLevelDane); err != nil {
		t.Fatal(err)
	}
	store.FailWritesAfter(0)
	if _, err := pins.Raise("mx2.mail.example", sidecar.SmtpTlsLevelDane); !errors.Is(err, sidecartest.ErrFakeStoreWriteFailed) {
		t.Errorf("a write that failed: %v", err)
	}
	if level := testPinLevel(t, pins, "mx2.mail.example"); level != sidecar.SmtpTlsLevelUnreached {
		t.Errorf("memory took a pin the store refused: %d", level)
	}
	if level := testPinLevel(t, pins, testPinHost); level != sidecar.SmtpTlsLevelDane {
		t.Errorf("the earlier pin: %d", level)
	}
}

// The sealed file names no host in a path: what the store keeps in the clear is one fixed name.
func TestSmtpPinFileNamesNoHost(t *testing.T) {
	pins, store, _ := newTestPinStore(t)
	if _, err := pins.Raise(testPinHost, sidecar.SmtpTlsLevelDane); err != nil {
		t.Fatal(err)
	}
	if err := pins.RecordMode(testPinDomain, testPinHost, sidecar.SmtpModeBdat); err != nil {
		t.Fatal(err)
	}
	if paths := store.Paths(); len(paths) != 1 || paths[0] != "tls-pins" {
		t.Errorf("%q", paths)
	}
}
