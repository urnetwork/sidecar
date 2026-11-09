package dnsservice_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// DnsSoaReader by hand: each NS answers the serial a test sets, or fails while set failing, and every
// read is counted.
type fakeSoaReader struct {
	readCount *sidecar.MonitorValue[int]

	stateLock sync.Mutex
	serials   map[string]uint32
	failing   map[string]bool
}

func newFakeSoaReader() *fakeSoaReader {
	return &fakeSoaReader{readCount: sidecar.NewMonitorValue(0), serials: map[string]uint32{}, failing: map[string]bool{}}
}

func (self *fakeSoaReader) set(ns string, serial uint32) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.serials[ns] = serial
}

func (self *fakeSoaReader) fail(ns string, failing bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failing[ns] = failing
}

func (self *fakeSoaReader) ReadSoa(ctx context.Context, root string, ns string) (uint32, error) {
	defer self.readCount.Update(func(count int) int { return count + 1 })
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing[ns] {
		return 0, errors.New("no answer")
	}
	serial, ok := self.serials[ns]
	if !ok {
		return 0, errors.New("no answer")
	}
	return serial, nil
}

// DnsReadyStore by hand.
type fakeReadyStore struct {
	stateLock sync.Mutex
	stopped   []string
	verdicts  []dnsservice.DnsCanaryVerdict
}

func (self *fakeReadyStore) setStopped(stopped ...string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.stopped = stopped
}

func (self *fakeReadyStore) setVerdicts(verdicts ...dnsservice.DnsCanaryVerdict) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.verdicts = verdicts
}

func (self *fakeReadyStore) StoppedNs(ctx context.Context, root string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.stopped...), nil
}

func (self *fakeReadyStore) CanaryVerdicts(ctx context.Context, root string) ([]dnsservice.DnsCanaryVerdict, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]dnsservice.DnsCanaryVerdict{}, self.verdicts...), nil
}

// A clean canary at the clock's now.
func (self *testApi) cleanCanary() {
	self.ready.setVerdicts(dnsservice.DnsCanaryVerdict{Source: dnsservice.DnsCanarySourceSite, Serial: 1, Ok: true, ReportTime: self.clock.Now()})
}

// GET ready for serial, served on its own goroutine, its answer on the channel.
func (self *testApi) askReady(t testing.TB, serial uint64) <-chan *dnsservice.DnsReadyAnswer {
	t.Helper()
	answers := make(chan *dnsservice.DnsReadyAnswer, 1)
	request := self.request(http.MethodGet, dnsservice.DnsReadyPath+"?serial="+strconv.FormatUint(serial, 10), dnsservice.DnsCallerCerts, "")
	go func() {
		recorder := self.serve(request)
		answer := &dnsservice.DnsReadyAnswer{}
		if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), answer) != nil {
			answer.Answer = "status " + strconv.Itoa(recorder.Code)
		}
		answers <- answer
	}()
	return answers
}

func (self *testApi) awaitAnswer(t testing.TB, answers <-chan *dnsservice.DnsReadyAnswer) *dnsservice.DnsReadyAnswer {
	t.Helper()
	select {
	case answer := <-answers:
		return answer
	case <-t.Context().Done():
		t.Fatal("no answer")
	}
	return nil
}

// Waits until the fake reader has served count reads in all.
func (self *fakeSoaReader) awaitReads(t testing.TB, count int) {
	t.Helper()
	for {
		current, changed := self.readCount.Get()
		if count <= current {
			return
		}
		select {
		case <-changed:
		case <-t.Context().Done():
			t.Fatalf("reads %d", current)
		}
	}
}

// Every running NS at the serial and a clean canary: ready. No verdict, or a failing one: canary_failing.
func TestDnsReadyAnswersReadyOrCanaryFailing(t *testing.T) {
	api := newTestApi(t, nil)
	api.soa.set("ns1", 5)
	api.soa.set("ns2", 6)
	if answer := api.awaitAnswer(t, api.askReady(t, 5)); answer.Answer != dnsservice.DnsReadyCanaryFailing {
		t.Errorf("no verdict: %+v", answer)
	}
	api.cleanCanary()
	api.clock.Advance(time.Second)
	if answer := api.awaitAnswer(t, api.askReady(t, 5)); answer.Answer != dnsservice.DnsReadyReady {
		t.Errorf("clean: %+v", answer)
	}
	now := api.clock.Now()
	cases := []struct {
		name     string
		verdicts []dnsservice.DnsCanaryVerdict
		want     string
	}{
		{name: "a site verdict that failed", verdicts: []dnsservice.DnsCanaryVerdict{{Source: dnsservice.DnsCanarySourceSite, Ok: false, ReportTime: now}}, want: dnsservice.DnsReadyCanaryFailing},
		{name: "a site verdict past 180 s", verdicts: []dnsservice.DnsCanaryVerdict{{Source: dnsservice.DnsCanarySourceSite, Ok: true, ReportTime: now.Add(-181 * time.Second)}}, want: dnsservice.DnsReadyCanaryFailing},
		{name: "a young outside failure", verdicts: []dnsservice.DnsCanaryVerdict{
			{Source: dnsservice.DnsCanarySourceSite, Ok: true, ReportTime: now},
			{Source: dnsservice.DnsCanarySourceOutside, Ok: false, ReportTime: now.Add(-10 * time.Second)},
		}, want: dnsservice.DnsReadyCanaryFailing},
		{name: "a stale outside failure alone", verdicts: []dnsservice.DnsCanaryVerdict{
			{Source: dnsservice.DnsCanarySourceSite, Ok: true, ReportTime: now},
			{Source: dnsservice.DnsCanarySourceOutside, Ok: false, ReportTime: now.Add(-200 * time.Second)},
		}, want: dnsservice.DnsReadyReady},
	}
	for _, c := range cases {
		api.ready.setVerdicts(c.verdicts...)
		if answer := api.awaitAnswer(t, api.askReady(t, 5)); answer.Answer != c.want {
			t.Errorf("%s: %+v", c.name, answer)
		}
	}
}

// Stale while restoring and for a serial at or below restore_serial, whatever the NS serve.
func TestDnsReadyIsStaleAcrossARestore(t *testing.T) {
	api := newTestApi(t, nil)
	api.cleanCanary()
	api.soa.set("ns1", 1)
	api.soa.set("ns2", 1)
	dump, err := api.store.TakeDump(edgeTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.store.SetRestoring(t.Context(), edgeTestRoot, true); err != nil {
		t.Fatal(err)
	}
	if answer := api.awaitAnswer(t, api.askReady(t, 1)); answer.Answer != dnsservice.DnsReadyStale {
		t.Errorf("restoring: %+v", answer)
	}
	api.store.LoadDump(edgeTestRoot, dump)
	restoreSerial, err := api.store.CommitRestore(t.Context(), edgeTestRoot, sidecar.NewId(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.store.SetRestoring(t.Context(), edgeTestRoot, false); err != nil {
		t.Fatal(err)
	}
	for _, serial := range []uint64{1, restoreSerial} {
		if answer := api.awaitAnswer(t, api.askReady(t, serial)); answer.Answer != dnsservice.DnsReadyStale || answer.RestoreSerial != restoreSerial {
			t.Errorf("serial %d: %+v", serial, answer)
		}
	}
	api.soa.set("ns1", uint32(restoreSerial+1))
	api.soa.set("ns2", uint32(restoreSerial+1))
	api.clock.Advance(time.Second)
	if answer := api.awaitAnswer(t, api.askReady(t, restoreSerial+1)); answer.Answer != dnsservice.DnsReadyReady {
		t.Errorf("above restore_serial: %+v", answer)
	}
}

// One running NS behind holds the answer; once its SOA reaches the serial the next round answers
// ready, and a hold that ends first, with an NS not answering, answers waiting.
func TestDnsReadyWaitsForEveryRunningNs(t *testing.T) {
	api := newTestApi(t, nil)
	api.cleanCanary()
	api.soa.set("ns1", 9)
	api.soa.set("ns2", 7)
	answers := api.askReady(t, 9)
	api.awaitParked(t, 1)
	api.soa.set("ns2", 9)
	// the next round is a second after the last, and runs as the clock passes it
	api.clock.Advance(time.Second)
	if answer := api.awaitAnswer(t, answers); answer.Answer != dnsservice.DnsReadyReady {
		t.Errorf("caught up: %+v", answer)
	}

	api.soa.fail("ns2", true)
	api.clock.Advance(time.Second)
	answers = api.askReady(t, 9)
	// every round in the hold finds the NS behind, and the hold's end answers
	api.awaitParked(t, 1)
	api.clock.Advance(time.Duration(api.settings.Api.ReadyHoldSeconds) * time.Second)
	answer := api.awaitAnswer(t, answers)
	if answer.Answer != dnsservice.DnsReadyWaiting {
		t.Errorf("an NS not answering: %+v", answer)
	}
}

// A stopped NS (plan-DNS-running-ns) is not counted.
func TestDnsReadyLeavesOutAStoppedNs(t *testing.T) {
	api := newTestApi(t, nil)
	api.cleanCanary()
	api.soa.set("ns1", 4)
	api.soa.fail("ns2", true)
	api.ready.setStopped("ns2")
	if answer := api.awaitAnswer(t, api.askReady(t, 4)); answer.Answer != dnsservice.DnsReadyReady {
		t.Errorf("%+v", answer)
	}
}

// RFC 1982 on the SOA's low 32 bits (plan reading 4): a serial past 2^32 reads against its low bits,
// and an SOA that wrapped reads above one that did not.
func TestDnsReadyComparesSerialsAcrossAWrap(t *testing.T) {
	api := newTestApi(t, nil)
	api.cleanCanary()
	wide := uint64(1)<<32 + 5
	api.soa.set("ns1", 7)
	api.soa.set("ns2", 7)
	if answer := api.awaitAnswer(t, api.askReady(t, wide)); answer.Answer != dnsservice.DnsReadyReady {
		t.Errorf("7 against 2^32+5: %+v", answer)
	}
	api.soa.set("ns1", 1)
	api.soa.set("ns2", 1)
	api.clock.Advance(time.Second)
	if answer := api.awaitAnswer(t, api.askReady(t, uint64(1)<<32-2)); answer.Answer != dnsservice.DnsReadyReady {
		t.Errorf("1 against 2^32-2: %+v", answer)
	}
	api.soa.set("ns1", uint32(1)<<31+10)
	api.soa.set("ns2", 10)
	api.clock.Advance(time.Second)
	answers := api.askReady(t, 10)
	// every round in the hold finds the NS behind, and the hold's end answers
	api.awaitParked(t, 1)
	api.clock.Advance(time.Duration(api.settings.Api.ReadyHoldSeconds) * time.Second)
	answer := api.awaitAnswer(t, answers)
	if answer.Answer != dnsservice.DnsReadyWaiting {
		t.Errorf("half the space away: %+v", answer)
	}
}

// A hundred orders waiting on one root cost one round of reads a second, one read for each NS.
func TestDnsReadyCoalescesSoaReads(t *testing.T) {
	api := newTestApi(t, nil)
	api.cleanCanary()
	api.soa.set("ns1", 1)
	api.soa.set("ns2", 1)
	answers := []<-chan *dnsservice.DnsReadyAnswer{}
	for range 100 {
		answers = append(answers, api.askReady(t, 2))
	}
	api.awaitParked(t, 100)
	if reads, _ := api.soa.readCount.Get(); reads != 2 {
		t.Errorf("a first round of %d reads", reads)
	}
	api.soa.set("ns1", 2)
	api.soa.set("ns2", 2)
	api.clock.Advance(time.Second)
	for _, answer := range answers {
		if got := api.awaitAnswer(t, answer); got.Answer != dnsservice.DnsReadyReady {
			t.Errorf("%+v", got)
		}
	}
	if reads, _ := api.soa.readCount.Get(); reads != 4 {
		t.Errorf("%d reads for a hundred orders over two rounds", reads)
	}
}

// The TCP reader reads a real edge's SOA: the serial the edge serves.
func TestDnsTcpSoaReaderReadsAnEdge(t *testing.T) {
	edge := newTestEdge(t, edgeTestSettings(t))
	edge.publish(t, edgeTestView(t, edge.settings, 77, edgeTestRows()))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go edge.edge.Serve(listener)
	address := netip.MustParseAddrPort(listener.Addr().String())
	reader := dnsservice.NewDnsTcpSoaReader(map[string][]netip.AddrPort{"ns1": {address}})
	serial, err := reader.ReadSoa(t.Context(), edgeTestRoot, "ns1")
	if err != nil || serial != 77 {
		t.Errorf("serial %d %v", serial, err)
	}
	if _, err := reader.ReadSoa(t.Context(), edgeTestRoot, "ns9"); err == nil {
		t.Error("an NS with no address read")
	}
	if _, err := reader.ReadSoa(t.Context(), "other.example.", "ns1"); err == nil {
		t.Error("another root's SOA read")
	}
}

func TestDnsCanaryClean(t *testing.T) {
	now := sidecartest.DefaultClockStart()
	fresh := 180 * time.Second
	if dnsservice.DnsCanaryClean(nil, now, fresh) {
		t.Error("no verdict is clean")
	}
	future := []dnsservice.DnsCanaryVerdict{{Source: dnsservice.DnsCanarySourceSite, Ok: true, ReportTime: now.Add(time.Minute)}}
	if dnsservice.DnsCanaryClean(future, now, fresh) {
		t.Error("a verdict from the future is clean")
	}
}
