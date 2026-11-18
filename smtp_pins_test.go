//go:build !sidecar_http

// SmtpPinStore on a fake clock and a fake store. A pin is one recipient domain's on one MX host (owner
// decision 438): a shared host pinned for one domain refuses no other, and a domain never sent to there
// carries no pin. A pin rises, holds PinTimeout from the last send that reached it for its own pair,
// refuses anything below it for that pair, then lapses. Pairs, each host's mode and each domain's mode
// survive a restart; a pin from the format before the pair key, which names no domain, is dropped and
// counted in the log; and a file that cannot be read is never read as no pins.

package sidecar_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	testPinHost        = "mx.mail.example"
	testPinOtherHost   = "mx2.mail.example"
	testPinDomain      = "mail.example"
	testPinOtherDomain = "other.example"
	testPinNewDomain   = "new.example"
)

var testPinStart = time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)

// A pin store on a fresh fake store and clock, with the default settings.
func newTestPinStore(t *testing.T) (*sidecar.SmtpPinStore, *sidecartest.FakeStore, *sidecartest.FakeClock) {
	t.Helper()
	store := sidecartest.NewFakeStore()
	clock := sidecartest.NewFakeClock(testPinStart)
	return sidecar.NewSmtpPinStore(store.Root(), sidecar.DefaultSmtpSenderSettings(), clock, nil), store, clock
}

func testPinLevel(t *testing.T, pins *sidecar.SmtpPinStore, domain string, host string) sidecar.SmtpTlsLevel {
	t.Helper()
	pin, err := pins.Pin(domain, host)
	if err != nil {
		t.Fatal(err)
	}
	if pin == nil {
		return sidecar.SmtpTlsLevelUnreached
	}
	return pin.Level
}

// Writes data as the store's pin file, as an earlier release or a damaged store left it.
func testPinWriteFile(t *testing.T, store *sidecartest.FakeStore, data string) {
	t.Helper()
	writer, err := store.Root().Create("tls-pins")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
}

// A logger that keeps every line, safe for concurrent use.
type testPinLog struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *testPinLog) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *testPinLog) Info(args ...any) {
	self.add(fmt.Sprint(args...))
}

func (self *testPinLog) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testPinLog) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testPinLog) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testPinLog) V(level int32) sidecar.Verbose {
	return testPinVerbose{log: self}
}

func (self *testPinLog) snapshot() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.lines)
}

// Every level enabled.
type testPinVerbose struct {
	log *testPinLog
}

func (self testPinVerbose) Enabled() bool {
	return true
}

func (self testPinVerbose) Info(args ...any) {
	self.log.Info(args...)
}

func (self testPinVerbose) Infof(format string, args ...any) {
	self.log.Infof(format, args...)
}

// A pin rises to a better level, holds 90 days from the send that reached it, refuses anything below
// it while it holds, and then lapses, after which the next send pins what it reaches (§14.4).
func TestSmtpPinRisesAndHoldsNinetyDaysThenLapses(t *testing.T) {
	pins, _, clock := newTestPinStore(t)
	if level := testPinLevel(t, pins, testPinDomain, testPinHost); level != sidecar.SmtpTlsLevelUnreached {
		t.Fatalf("a pin before any send: %d", level)
	}
	if _, err := pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelIndependentMx); err != nil {
		t.Fatal(err)
	}
	pin, err := pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelDane)
	if err != nil || pin.Level != sidecar.SmtpTlsLevelDane || !pin.PinTime.Equal(testPinStart) ||
		pin.RecipientDomain != testPinDomain || pin.MxHost != testPinHost {
		t.Fatalf("the rise: %+v %v", pin, err)
	}
	clock.Advance(89 * 24 * time.Hour)
	for _, level := range []sidecar.SmtpTlsLevel{sidecar.SmtpTlsLevelMtaSts, sidecar.SmtpTlsLevelIndependentMx, sidecar.SmtpTlsLevelUnauthenticated} {
		if _, err := pins.Raise(testPinDomain, testPinHost, level); !errors.Is(err, sidecar.ErrSmtpPinBelow) {
			t.Errorf("level %d under a TL1 pin on day 89: %v", level, err)
		}
	}
	if level := testPinLevel(t, pins, testPinDomain, testPinHost); level != sidecar.SmtpTlsLevelDane {
		t.Errorf("a refused send moved the pin: %d", level)
	}
	clock.Advance(24 * time.Hour)
	if level := testPinLevel(t, pins, testPinDomain, testPinHost); level != sidecar.SmtpTlsLevelUnreached {
		t.Fatalf("a pin past 90 days: %d", level)
	}
	pin, err = pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelIndependentMx)
	if err != nil || pin.Level != sidecar.SmtpTlsLevelIndependentMx || !pin.PinTime.Equal(clock.Now()) {
		t.Errorf("the send after the lapse: %+v %v", pin, err)
	}
}

// A send at the pinned level restarts its 90 days, so a host reached at TL1 now and then stays pinned.
func TestSmtpPinRefreshesAtItsLevel(t *testing.T) {
	pins, _, clock := newTestPinStore(t)
	if _, err := pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelDane); err != nil {
		t.Fatal(err)
	}
	clock.Advance(60 * 24 * time.Hour)
	if _, err := pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelDane); err != nil {
		t.Fatal(err)
	}
	clock.Advance(60 * 24 * time.Hour)
	pin, err := pins.Pin(testPinDomain, testPinHost)
	if err != nil || pin == nil || pin.Level != sidecar.SmtpTlsLevelDane {
		t.Fatalf("120 days after the first send, 60 after the second: %+v %v", pin, err)
	}
	if want := testPinStart.Add(150 * 24 * time.Hour); !pin.ExpireTime(sidecar.DefaultSmtpSenderSettings().PinTimeout).Equal(want) {
		t.Errorf("expires %v, want %v", pin.ExpireTime(sidecar.DefaultSmtpSenderSettings().PinTimeout), want)
	}
}

// Names compare as DNS does: a domain or host in another case or with a trailing dot is the same one;
// either outside RFC 5321's Domain, or an unreached level, is refused.
func TestSmtpPinNamesCompareAsDnsDoes(t *testing.T) {
	pins, _, _ := newTestPinStore(t)
	if _, err := pins.Raise("Mail.Example.", "MX.Mail.Example.", sidecar.SmtpTlsLevelDane); err != nil {
		t.Fatal(err)
	}
	if level := testPinLevel(t, pins, testPinDomain, testPinHost); level != sidecar.SmtpTlsLevelDane {
		t.Errorf("%d", level)
	}
	if _, err := pins.Raise(testPinDomain, "mx..example", sidecar.SmtpTlsLevelDane); err == nil {
		t.Error("a host outside RFC 5321's Domain")
	}
	if _, err := pins.Raise("mail..example", testPinHost, sidecar.SmtpTlsLevelDane); err == nil {
		t.Error("a domain outside RFC 5321's Domain")
	}
	if _, err := pins.Raise("", testPinHost, sidecar.SmtpTlsLevelDane); err == nil {
		t.Error("a pin with no domain")
	}
	if _, err := pins.Pin("", testPinHost); err == nil {
		t.Error("a pin asked for with no domain")
	}
	if _, err := pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelUnreached); err == nil {
		t.Error("an unreached level pinned")
	}
}

// One MX host shared by two domains (owner decision 438): domain A's TL2 there leaves domain B's TL3
// send accepted, A's own later TL3 send there is refused, and a domain never sent to carries no pin on
// the host, nor A on a host it never reached.
func TestSmtpPinIsKeptPerRecipientDomainOnASharedHost(t *testing.T) {
	pins, _, _ := newTestPinStore(t)
	if _, err := pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelMtaSts); err != nil {
		t.Fatal(err)
	}
	pin, err := pins.Raise(testPinOtherDomain, testPinHost, sidecar.SmtpTlsLevelIndependentMx)
	if err != nil || pin.Level != sidecar.SmtpTlsLevelIndependentMx || pin.RecipientDomain != testPinOtherDomain || pin.MxHost != testPinHost {
		t.Fatalf("the other domain's TL3 on the shared host: %+v %v", pin, err)
	}
	if _, err := pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelIndependentMx); !errors.Is(err, sidecar.ErrSmtpPinBelow) {
		t.Errorf("the first domain's TL3 under its TL2 pin: %v", err)
	}
	for _, c := range []struct {
		domain string
		host   string
		level  sidecar.SmtpTlsLevel
	}{
		{domain: testPinDomain, host: testPinHost, level: sidecar.SmtpTlsLevelMtaSts},
		{domain: testPinOtherDomain, host: testPinHost, level: sidecar.SmtpTlsLevelIndependentMx},
		{domain: testPinNewDomain, host: testPinHost, level: sidecar.SmtpTlsLevelUnreached},
		{domain: testPinDomain, host: testPinOtherHost, level: sidecar.SmtpTlsLevelUnreached},
	} {
		if level := testPinLevel(t, pins, c.domain, c.host); level != c.level {
			t.Errorf("%s on %s: %d, want %d", c.domain, c.host, level, c.level)
		}
	}
	// a domain never sent to there pins what it reaches, whatever the host holds for others
	if _, err := pins.Raise(testPinNewDomain, testPinHost, sidecar.SmtpTlsLevelUnauthenticated); err != nil {
		t.Errorf("a new domain at TL4 on a host pinned for others: %v", err)
	}
}

// A pin lapses PinTimeout after its own pair last reached its level: another domain reaching the same
// level on the same host later keeps that domain's pin alone.
func TestSmtpPinLapsesFromItsOwnPairsLastLevel(t *testing.T) {
	pins, _, clock := newTestPinStore(t)
	timeout := sidecar.DefaultSmtpSenderSettings().PinTimeout
	if _, err := pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelDane); err != nil {
		t.Fatal(err)
	}
	clock.Advance(30 * 24 * time.Hour)
	if _, err := pins.Raise(testPinOtherDomain, testPinHost, sidecar.SmtpTlsLevelDane); err != nil {
		t.Fatal(err)
	}
	clock.Advance(timeout - 30*24*time.Hour - time.Millisecond)
	if _, err := pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelIndependentMx); !errors.Is(err, sidecar.ErrSmtpPinBelow) {
		t.Errorf("a millisecond before the lapse: %v", err)
	}
	pin, err := pins.Pin(testPinDomain, testPinHost)
	if err != nil || pin == nil || !pin.ExpireTime(timeout).Equal(testPinStart.Add(timeout)) {
		t.Fatalf("the first domain's pin: %+v %v", pin, err)
	}
	clock.Advance(time.Millisecond)
	if level := testPinLevel(t, pins, testPinDomain, testPinHost); level != sidecar.SmtpTlsLevelUnreached {
		t.Errorf("the first domain's pin outlived its own 90 days: %d", level)
	}
	if level := testPinLevel(t, pins, testPinOtherDomain, testPinHost); level != sidecar.SmtpTlsLevelDane {
		t.Errorf("the other domain's pin: %d", level)
	}
	pin, err = pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelIndependentMx)
	if err != nil || pin.Level != sidecar.SmtpTlsLevelIndependentMx {
		t.Errorf("the first domain's send after its lapse: %+v %v", pin, err)
	}
}

// The file round-trips pairs: a new store over the same files reads each pair's level, each host's
// mode, which a pin for any domain on that host carries, and each domain's last mode; and the stored
// pins name their domain beside their host.
func TestSmtpPinFileRoundTripsPairs(t *testing.T) {
	pins, store, clock := newTestPinStore(t)
	for _, c := range []struct {
		domain string
		host   string
		level  sidecar.SmtpTlsLevel
	}{
		{domain: testPinDomain, host: testPinHost, level: sidecar.SmtpTlsLevelMtaSts},
		{domain: testPinOtherDomain, host: testPinHost, level: sidecar.SmtpTlsLevelIndependentMx},
		{domain: testPinDomain, host: testPinOtherHost, level: sidecar.SmtpTlsLevelDane},
	} {
		if _, err := pins.Raise(c.domain, c.host, c.level); err != nil {
			t.Fatal(err)
		}
	}
	if err := pins.RecordMode(testPinDomain, testPinHost, sidecar.SmtpModeData); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Hour)
	if err := pins.RecordMode(testPinOtherDomain, testPinOtherHost, sidecar.SmtpModeBdat); err != nil {
		t.Fatal(err)
	}

	restarted := sidecar.NewSmtpPinStore(store.Root(), sidecar.DefaultSmtpSenderSettings(), clock, nil)
	for _, c := range []struct {
		domain   string
		host     string
		level    sidecar.SmtpTlsLevel
		mode     sidecar.SmtpMode
		modeTime time.Time
	}{
		{domain: testPinDomain, host: testPinHost, level: sidecar.SmtpTlsLevelMtaSts, mode: sidecar.SmtpModeData, modeTime: testPinStart},
		{domain: testPinOtherDomain, host: testPinHost, level: sidecar.SmtpTlsLevelIndependentMx, mode: sidecar.SmtpModeData, modeTime: testPinStart},
		{domain: testPinDomain, host: testPinOtherHost, level: sidecar.SmtpTlsLevelDane, mode: sidecar.SmtpModeBdat, modeTime: testPinStart.Add(time.Hour)},
	} {
		pin, err := restarted.Pin(c.domain, c.host)
		if err != nil || pin == nil || pin.Level != c.level || !pin.PinTime.Equal(testPinStart) || pin.Mode != c.mode || !pin.ModeTime.Equal(c.modeTime) {
			t.Errorf("%s on %s after a restart: %+v %v", c.domain, c.host, pin, err)
		}
	}
	if level := testPinLevel(t, restarted, testPinOtherDomain, testPinOtherHost); level != sidecar.SmtpTlsLevelUnreached {
		t.Errorf("a mode pinned a level: %d", level)
	}
	if _, err := restarted.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelIndependentMx); !errors.Is(err, sidecar.ErrSmtpPinBelow) {
		t.Errorf("a downgrade after a restart: %v", err)
	}
	if _, err := restarted.Raise(testPinOtherDomain, testPinHost, sidecar.SmtpTlsLevelIndependentMx); err != nil {
		t.Errorf("the other domain's level after a restart: %v", err)
	}
	for domain, want := range map[string]sidecar.SmtpMode{testPinDomain: sidecar.SmtpModeData, testPinOtherDomain: sidecar.SmtpModeBdat} {
		if mode, err := restarted.DomainMode(domain); err != nil || mode != want {
			t.Errorf("%s's mode after a restart: %d %v", domain, mode, err)
		}
	}

	data, ok := store.Contents("tls-pins")
	if !ok {
		t.Fatal("no pin file")
	}
	file := struct {
		Pins []struct {
			Domain string `json:"domain"`
			MxHost string `json:"mx_host"`
			Level  uint32 `json:"level"`
		} `json:"pins"`
	}{}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	stored := []string{}
	for _, pin := range file.Pins {
		stored = append(stored, fmt.Sprintf("%s %s %d", pin.Domain, pin.MxHost, pin.Level))
	}
	want := []string{"mail.example mx.mail.example 2", "mail.example mx2.mail.example 1", "other.example mx.mail.example 3"}
	if !slices.Equal(stored, want) {
		t.Errorf("stored pins %q, want %q", stored, want)
	}
}

// A pin that names no recipient domain, as the format before pins were keyed by the pair stored it, is
// dropped at load, the count logged with no name in it, and binds no domain on its host; the pins
// beside it stand, and the next write leaves it out, so a restart drops nothing more.
func TestSmtpPinDropsADomainlessRecord(t *testing.T) {
	store := sidecartest.NewFakeStore()
	clock := sidecartest.NewFakeClock(testPinStart)
	settings := sidecar.DefaultSmtpSenderSettings()
	timeMs := testPinStart.UnixMilli()
	testPinWriteFile(t, store, fmt.Sprintf(`{"version":1,"pins":[`+
		`{"mx_host":"mx.mail.example","level":1,"pin_time_ms":%d,"mode":1,"mode_time_ms":%d},`+
		`{"mx_host":"mx2.mail.example","mode":2,"mode_time_ms":%d},`+
		`{"domain":"other.example","mx_host":"mx.mail.example","level":2,"pin_time_ms":%d}],`+
		`"domains":[{"domain":"mail.example","mx_host":"mx.mail.example","mode":1,"time_ms":%d}]}`,
		timeMs, timeMs, timeMs, timeMs, timeMs))
	log := &testPinLog{}
	pins := sidecar.NewSmtpPinStore(store.Root(), settings, clock, log)
	for _, domain := range []string{testPinDomain, testPinNewDomain} {
		if level := testPinLevel(t, pins, domain, testPinHost); level != sidecar.SmtpTlsLevelUnreached {
			t.Errorf("a domainless pin bound %s: %d", domain, level)
		}
	}
	if level := testPinLevel(t, pins, testPinOtherDomain, testPinHost); level != sidecar.SmtpTlsLevelMtaSts {
		t.Errorf("the pin beside it: %d", level)
	}
	if mode, err := pins.DomainMode(testPinDomain); err != nil || mode != sidecar.SmtpModeBdat {
		t.Errorf("the domain session beside it: %d %v", mode, err)
	}
	lines := log.snapshot()
	if len(lines) != 1 || !strings.Contains(lines[0], "dropped 2 ") {
		t.Fatalf("the log: %q", lines)
	}
	for _, name := range []string{"mail.example", "other.example", "mx.mail.example", "mx2.mail.example"} {
		if strings.Contains(lines[0], name) {
			t.Errorf("the log names %s: %q", name, lines[0])
		}
	}
	if _, err := pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelIndependentMx); err != nil {
		t.Errorf("a send the dropped pin would have refused: %v", err)
	}
	if lines := log.snapshot(); len(lines) != 1 {
		t.Errorf("the drop logged again: %q", lines)
	}

	restartedLog := &testPinLog{}
	restarted := sidecar.NewSmtpPinStore(store.Root(), settings, clock, restartedLog)
	if level := testPinLevel(t, restarted, testPinDomain, testPinHost); level != sidecar.SmtpTlsLevelIndependentMx {
		t.Errorf("after a restart: %d", level)
	}
	if level := testPinLevel(t, restarted, testPinOtherDomain, testPinHost); level != sidecar.SmtpTlsLevelMtaSts {
		t.Errorf("the other pin after a restart: %d", level)
	}
	if lines := restartedLog.snapshot(); len(lines) != 0 {
		t.Errorf("the write kept a domainless pin: %q", lines)
	}
}

// A domain's mode is its last session's, kept as long as a pin, for Check (§14.5), and a session that
// ended before its EHLO reply records nothing.
func TestSmtpPinDomainModeLastsAsAPinDoes(t *testing.T) {
	pins, _, clock := newTestPinStore(t)
	if mode, err := pins.DomainMode(testPinDomain); err != nil || mode != sidecar.SmtpModeUnknown {
		t.Fatalf("before any session: %d %v", mode, err)
	}
	if _, err := pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelIndependentMx); err != nil {
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
	pin, _ := pins.Pin(testPinDomain, testPinHost)
	if pin != nil {
		t.Errorf("the level's pin outlived its 90 days: %+v", pin)
	}
	clock.Advance(24 * time.Hour)
	if mode, _ := pins.DomainMode(testPinDomain); mode != sidecar.SmtpModeUnknown {
		t.Errorf("90 days after: %d", mode)
	}
}

// Past PinMaxCount the entry closest to lapsing leaves first, pins counted by pair, so one host's pins
// for many domains count one each; domains' last sessions are bounded alike.
func TestSmtpPinCountIsBoundedByPairs(t *testing.T) {
	store := sidecartest.NewFakeStore()
	clock := sidecartest.NewFakeClock(testPinStart)
	settings := sidecar.DefaultSmtpSenderSettings()
	settings.PinMaxCount = 2
	pins := sidecar.NewSmtpPinStore(store.Root(), settings, clock, nil)
	domains := []string{"d1.mail.example", "d2.mail.example", "d3.mail.example"}
	for _, domain := range domains {
		if _, err := pins.Raise(domain, testPinHost, sidecar.SmtpTlsLevelDane); err != nil {
			t.Fatal(err)
		}
		if err := pins.RecordMode(domain, testPinHost, sidecar.SmtpModeBdat); err != nil {
			t.Fatal(err)
		}
		clock.Advance(time.Hour)
	}
	if level := testPinLevel(t, pins, domains[0], testPinHost); level != sidecar.SmtpTlsLevelUnreached {
		t.Errorf("the oldest pair stayed past the bound: %d", level)
	}
	if mode, _ := pins.DomainMode(domains[0]); mode != sidecar.SmtpModeUnknown {
		t.Errorf("the oldest session stayed past the bound: %d", mode)
	}
	for _, domain := range domains[1:] {
		if level := testPinLevel(t, pins, domain, testPinHost); level != sidecar.SmtpTlsLevelDane {
			t.Errorf("%s: %d", domain, level)
		}
		if mode, _ := pins.DomainMode(domain); mode != sidecar.SmtpModeBdat {
			t.Errorf("%s's session: %d", domain, mode)
		}
	}
}

// A pin file that does not parse, or holds a record outside its form or one pair twice, is a failed
// store, never no pins, so a downgrade cannot pass a pin it lost (D-CORE-15); and a write that fails
// leaves the pins as they were.
func TestSmtpPinStoreFailsClosed(t *testing.T) {
	for _, data := range []string{
		"{",
		`{"version":2,"pins":[]}`,
		`{"version":1,"pins":[null]}`,
		`{"version":1,"pins":[{"domain":"Mail.example","mx_host":"mx.mail.example","level":1,"pin_time_ms":1}]}`,
		`{"version":1,"pins":[{"domain":"mail.example.","mx_host":"mx.mail.example","level":1,"pin_time_ms":1}]}`,
		`{"version":1,"pins":[{"domain":"mail..example","mx_host":"mx.mail.example","level":1,"pin_time_ms":1}]}`,
		`{"version":1,"pins":[{"domain":"mail.example","mx_host":"MX.mail.example","level":1,"pin_time_ms":1}]}`,
		`{"version":1,"pins":[{"domain":"mail.example","level":1,"pin_time_ms":1}]}`,
		`{"version":1,"pins":[{"domain":"mail.example","mx_host":"mx.mail.example","level":7,"pin_time_ms":1}]}`,
		`{"version":1,"pins":[{"domain":"mail.example","mx_host":"mx.mail.example","level":0,"pin_time_ms":1}]}`,
		`{"version":1,"pins":[{"domain":"mail.example","mx_host":"mx.mail.example","level":1}]}`,
		`{"version":1,"pins":[{"domain":"mail.example","mx_host":"mx.mail.example","level":1,"pin_time_ms":1},` +
			`{"domain":"mail.example","mx_host":"mx.mail.example","level":3,"pin_time_ms":2}]}`,
		`{"version":1,"modes":[null]}`,
		`{"version":1,"modes":[{"mx_host":"mx.mail.example","mode":9,"mode_time_ms":1}]}`,
		`{"version":1,"modes":[{"mx_host":"mx.mail.example","mode":1}]}`,
		`{"version":1,"modes":[{"mx_host":"mx.mail.example","mode":1,"mode_time_ms":1},{"mx_host":"mx.mail.example","mode":2,"mode_time_ms":2}]}`,
		`{"version":1,"domains":[null]}`,
		`{"version":1,"domains":[{"domain":"mail.example","mx_host":"mx.mail.example","mode":0,"time_ms":1}]}`,
		`{"version":1,"domains":[{"domain":"mail.example","mx_host":"mx.mail.example","mode":1,"time_ms":1},` +
			`{"domain":"mail.example","mx_host":"mx2.mail.example","mode":2,"time_ms":2}]}`,
	} {
		store := sidecartest.NewFakeStore()
		testPinWriteFile(t, store, data)
		pins := sidecar.NewSmtpPinStore(store.Root(), sidecar.DefaultSmtpSenderSettings(), sidecartest.NewFakeClock(testPinStart), nil)
		if _, err := pins.Pin(testPinDomain, testPinHost); !errors.Is(err, sidecar.ErrSidecarStoreFailed) {
			t.Errorf("%s: %v", data, err)
		}
	}

	pins, store, _ := newTestPinStore(t)
	if _, err := pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelDane); err != nil {
		t.Fatal(err)
	}
	store.FailWritesAfter(0)
	if _, err := pins.Raise(testPinOtherDomain, testPinHost, sidecar.SmtpTlsLevelDane); !errors.Is(err, sidecartest.ErrFakeStoreWriteFailed) {
		t.Errorf("a write that failed: %v", err)
	}
	if level := testPinLevel(t, pins, testPinOtherDomain, testPinHost); level != sidecar.SmtpTlsLevelUnreached {
		t.Errorf("memory took a pin the store refused: %d", level)
	}
	if level := testPinLevel(t, pins, testPinDomain, testPinHost); level != sidecar.SmtpTlsLevelDane {
		t.Errorf("the earlier pin: %d", level)
	}
}

// The sealed file names no host or domain in a path: what the store keeps in the clear is one fixed
// name.
func TestSmtpPinFileNamesNoHost(t *testing.T) {
	pins, store, _ := newTestPinStore(t)
	if _, err := pins.Raise(testPinDomain, testPinHost, sidecar.SmtpTlsLevelDane); err != nil {
		t.Fatal(err)
	}
	if err := pins.RecordMode(testPinDomain, testPinHost, sidecar.SmtpModeBdat); err != nil {
		t.Fatal(err)
	}
	if paths := store.Paths(); len(paths) != 1 || paths[0] != "tls-pins" {
		t.Errorf("%q", paths)
	}
}
