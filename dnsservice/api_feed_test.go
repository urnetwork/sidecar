package dnsservice_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// GET journal for after, served on its own goroutine, its decoded answer on the channel.
func (self *testApi) askJournal(t testing.TB, after uint64) <-chan *dnsservice.DnsFeedAnswer {
	t.Helper()
	answers := make(chan *dnsservice.DnsFeedAnswer, 1)
	request := self.request(http.MethodGet, dnsservice.DnsJournalPath+"?after="+strconv.FormatUint(after, 10), dnsservice.DnsCallerEdge, "")
	go func() {
		recorder := self.serve(request)
		answer, err := dnsservice.DecodeDnsFeedAnswer(recorder.Body.Bytes())
		if recorder.Code != http.StatusOK || err != nil {
			answer = nil
		}
		answers <- answer
	}()
	return answers
}

func awaitFeedAnswer(t testing.TB, answers <-chan *dnsservice.DnsFeedAnswer) *dnsservice.DnsFeedAnswer {
	t.Helper()
	select {
	case answer := <-answers:
		if answer == nil {
			t.Fatal("no answer decoded")
		}
		return answer
	case <-t.Context().Done():
		t.Fatal("no answer")
	}
	return nil
}

// Whether answers has an answer yet.
func feedAnswered(answers <-chan *dnsservice.DnsFeedAnswer) bool {
	return len(answers) != 0
}

func (self *testApi) write(t testing.TB, label string) uint64 {
	t.Helper()
	serial, err := self.store.Write(t.Context(), &dnsservice.DnsZoneWrite{Root: edgeTestRoot, Upserts: []dnsservice.DnsRecordSet{feedTestTxt(label, label)}})
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

// Rows there already answer at once, with the interfaces and the window released now.
func TestDnsJournalAnswersRowsAtOnce(t *testing.T) {
	api := newTestApi(t, nil)
	answer := awaitFeedAnswer(t, api.askJournal(t, 0))
	if answer.Reload || len(answer.Rows) != 1 || answer.Rows[0].Serial != 1 || answer.Serial != 1 {
		t.Fatalf("answer %+v", answer)
	}
	if len(answer.Interfaces) != 2 || answer.Interfaces[0].Name != "lb-1" || answer.KeyWindow == nil || answer.KeyWindow.Root != edgeTestRoot {
		t.Errorf("interfaces %v, window %v", answer.Interfaces, answer.KeyWindow)
	}
}

// A poll at the serial holds, and a write's raise ends the hold with its row.
func TestDnsJournalHoldEndsOnARaise(t *testing.T) {
	api := newTestApi(t, nil)
	answers := api.askJournal(t, 1)
	api.awaitParked(t, 1)
	if feedAnswered(answers) {
		t.Fatal("a poll at the serial answered at once")
	}
	serial := api.write(t, "raised")
	answer := awaitFeedAnswer(t, answers)
	if len(answer.Rows) != 1 || answer.Rows[0].Serial != serial {
		t.Errorf("answer %+v", answer)
	}
}

// A raise Redis lost costs only the hold: its end reads again and finds the row. The hold is
// api.journal_hold_s, 25 s, under the lb's 30 s.
func TestDnsJournalCatchesALostRaiseAtTheHoldsEnd(t *testing.T) {
	api := newTestApi(t, nil)
	holdEnd := api.clock.Now().Add(25 * time.Second)
	answers := api.askJournal(t, 1)
	api.awaitParked(t, 1)
	pending := api.clock.PendingTimers()
	if !slicesContainTime(pending, holdEnd) {
		t.Errorf("timers %v, want one at %v", pending, holdEnd)
	}
	if _, err := api.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: sidecartest.FaultDnsRaise, Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	serial := api.write(t, "unraised")
	api.clock.Advance(24 * time.Second)
	if feedAnswered(answers) {
		t.Fatal("a lost raise ended the hold")
	}
	api.clock.Advance(time.Second)
	answer := awaitFeedAnswer(t, answers)
	if len(answer.Rows) != 1 || answer.Rows[0].Serial != serial {
		t.Errorf("answer %+v", answer)
	}
}

func slicesContainTime(times []time.Time, at time.Time) bool {
	for _, each := range times {
		if each.Equal(at) {
			return true
		}
	}
	return false
}

// A poll ahead of the serial, as an edge's is after a restore loads an older dump, holds and answers
// empty: never a reload, which would swap the edge down to the dump's zone (plan reading 8).
func TestDnsJournalHoldsAPollAheadOfTheSerial(t *testing.T) {
	api := newTestApi(t, nil)
	answers := api.askJournal(t, 40)
	api.awaitParked(t, 1)
	api.clock.Advance(25 * time.Second)
	answer := awaitFeedAnswer(t, answers)
	if answer.Reload || len(answer.Rows) != 0 || answer.Serial != 1 {
		t.Errorf("answer %+v", answer)
	}
}

// A poll the journal cannot continue answers reload: after the purge's gap, and after a restore, but
// only once the restore transaction has run.
func TestDnsJournalAnswersReloadAfterAGapAndAfterARestore(t *testing.T) {
	api := newTestApi(t, nil)
	api.write(t, "two")
	api.write(t, "three")
	if _, err := api.store.PurgeJournal(t.Context(), edgeTestRoot, api.clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if answer := awaitFeedAnswer(t, api.askJournal(t, 1)); !answer.Reload || len(answer.Rows) != 0 {
		t.Errorf("after a purge %+v", answer)
	}

	dump, err := api.store.TakeDump(edgeTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	api.write(t, "lost")
	if err := api.store.SetRestoring(t.Context(), edgeTestRoot, true); err != nil {
		t.Fatal(err)
	}
	api.store.LoadDump(edgeTestRoot, dump)
	// the dump is at 3 and the edge at 1 with no row to continue from: before the restore
	// transaction, that is no reload, and the poll holds
	answers := api.askJournal(t, 1)
	api.awaitParked(t, 1)
	if feedAnswered(answers) {
		t.Fatal("a reload before the restore transaction")
	}
	restoreSerial, err := api.store.CommitRestore(t.Context(), edgeTestRoot, sidecar.NewId(), 4)
	if err != nil {
		t.Fatal(err)
	}
	answer := awaitFeedAnswer(t, answers)
	if !answer.Reload || answer.RestoreSerial != restoreSerial || answer.Serial != restoreSerial {
		t.Errorf("after the restore transaction %+v", answer)
	}
}

// GET snapshot streams the rows at one serial, which an edge's reader takes whole.
func TestDnsSnapshotStreamsOneSerial(t *testing.T) {
	api := newTestApi(t, nil)
	serial := api.write(t, "extra")
	recorder := api.serve(api.request(http.MethodGet, dnsservice.DnsSnapshotPath, dnsservice.DnsCallerEdge, ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("%d", recorder.Code)
	}
	rows, err := dnsservice.NewDnsSnapshotReader(bytes.NewReader(recorder.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	view, err := dnsservice.NewZoneView(api.settings, rows)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range view.Rows() {
		count += 1
	}
	if view.Serial() != serial || count != len(edgeTestRows())+1 {
		t.Errorf("serial %d, %d rows", view.Serial(), count)
	}
	if recorder := api.serve(api.request(http.MethodGet, dnsservice.DnsSnapshotPath+"?root=other.example", dnsservice.DnsCallerEdge, "")); recorder.Code != http.StatusBadRequest {
		t.Errorf("another root: %d", recorder.Code)
	}
}

// POST reload-diff keeps a diff for the restore step, and refuses one that is not of this root, does
// not raise the serial, names a key that is no key, or runs past its bound.
func TestDnsReloadDiffIsKept(t *testing.T) {
	api := newTestApi(t, nil)
	diff := &dnsservice.DnsReloadDiff{
		Root:           edgeTestRoot,
		ReplacedSerial: 4,
		Serial:         4 + dnsservice.DnsRestoreSerialJump,
		Rrsets:         []dnsservice.DnsRecordKey{{Owner: "www.net1." + edgeTestRoot, Type: dns.TypeA}},
	}
	body := func(diff *dnsservice.DnsReloadDiff) string {
		data, err := json.Marshal(diff)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsReloadDiffPath, dnsservice.DnsCallerEdge, body(diff))); recorder.Code != http.StatusNoContent {
		t.Fatalf("%d %s", recorder.Code, recorder.Body.String())
	}
	diffs, err := api.store.ReloadDiffs(t.Context(), edgeTestRoot)
	if err != nil || len(diffs) != 1 || diffs[0].Serial != diff.Serial || len(diffs[0].Rrsets) != 1 {
		t.Errorf("diffs %v %v", diffs, err)
	}
	refused := []*dnsservice.DnsReloadDiff{
		{Root: "other.example.", ReplacedSerial: 1, Serial: 2},
		{Root: edgeTestRoot, ReplacedSerial: 5, Serial: 5},
		{Root: edgeTestRoot, ReplacedSerial: 1, Serial: 2, Rrsets: []dnsservice.DnsRecordKey{{Owner: "www.other.example.", Type: dns.TypeA}}},
		{Root: edgeTestRoot, ReplacedSerial: 1, Serial: 2, Rrsets: []dnsservice.DnsRecordKey{{Owner: "x." + edgeTestRoot, Type: dns.TypeRRSIG}}},
	}
	for _, refusedDiff := range refused {
		if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsReloadDiffPath, dnsservice.DnsCallerEdge, body(refusedDiff))); recorder.Code != http.StatusBadRequest {
			t.Errorf("%+v: %d", refusedDiff, recorder.Code)
		}
	}
	oversized := `{"root":"zone.example.","replaced_serial":1,"serial":2,"rrsets":[` + strings.Repeat(`{"owner":"x.zone.example.","type":1},`, api.settings.Api.DiffMaxByteCount/30) + `{"owner":"x.zone.example.","type":1}]}`
	if recorder := api.serve(api.request(http.MethodPost, dnsservice.DnsReloadDiffPath, dnsservice.DnsCallerEdge, oversized)); recorder.Code != http.StatusBadRequest {
		t.Errorf("past diff_max_bytes: %d", recorder.Code)
	}
	if diffs, _ := api.store.ReloadDiffs(t.Context(), edgeTestRoot); len(diffs) != 1 {
		t.Errorf("a refused diff was kept: %v", diffs)
	}
}

// Drain ends a hold at once with what is there.
func TestDnsApiDrainEndsHolds(t *testing.T) {
	api := newTestApi(t, nil)
	answers := api.askJournal(t, 1)
	api.awaitParked(t, 1)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		api.api.Drain()
	}()
	if answer := awaitFeedAnswer(t, answers); answer.Reload || len(answer.Rows) != 0 {
		t.Errorf("answer %+v", answer)
	}
	select {
	case <-drained:
	case <-t.Context().Done():
		t.Fatal("Drain did not return")
	}
}

// What an edge on release N reads of a block on N+1 (FS-52's T2 half): fields N does not know are
// ignored, and a row of a format N does not read stops it before anything applies.
func TestDnsFeedAnswerFromNPlusOneReadsAtN(t *testing.T) {
	answer := awaitFeedAnswer(t, newTestApi(t, nil).askJournal(t, 0))
	data, err := json.Marshal(answer)
	if err != nil {
		t.Fatal(err)
	}
	widened := bytes.Replace(data, []byte(`"format":1,`), []byte(`"format":1,"added_by_n_plus_one":{"x":[1]},`), -1)
	decoded, err := dnsservice.DecodeDnsFeedAnswer(widened)
	if err != nil || len(decoded.Rows) != 1 {
		t.Errorf("N+1's fields: %v %v", decoded, err)
	}
	newer := bytes.Replace(data, []byte(`"rows":[{"format":1`), []byte(`"rows":[{"format":2`), 1)
	if _, err := dnsservice.DecodeDnsFeedAnswer(newer); !errors.Is(err, dnsservice.ErrDnsFormatTooNew) {
		t.Errorf("N+1's row: %v", err)
	}
}
