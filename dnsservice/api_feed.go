// The feed's three routes on the block (§12.6, §12.8, D-DNS-3): what DnsFeed's HTTP client calls.
//
// GET journal?root=&after= answers the rows above after, in serial order, or reload, or, once its hold
// ends with nothing new, an empty answer. The hold lasts at most api.journal_hold_s, 25 s under the lb's
// 30 s proxy_read_timeout, and wakes at each raise of {dns}serial:<root>, which reaches the block
// through the host's one shared key-event subscriber (DnsStore.SerialRaised; never one per poll,
// server/model/peer_model.go:32-37). It rereads the store at each wake and at the hold's end, so a raise
// Redis lost costs seconds, not a write. Plan reading 8 decides reload: only for after below the serial
// with no row to continue from, a 7-day purge's gap included, and while restoring only once the restore
// transaction has run, so an edge never swaps down to a dump's older zone. Every answer names the lb
// interfaces and the key window released now.
//
// GET snapshot?root= streams one transaction's rows as wire.go's snapshot lines, so neither end
// buffers a zone; a stream cut short ends with no end line, which the edge refuses.
//
// POST reload-diff keeps an edge's diff after a reload across a restore, for §12.6's restore step.

package dnsservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// The routes' labels in the holds metric.
const (
	dnsHoldRouteJournal = "journal"
	dnsHoldRouteReady   = "ready"
)

// How a hold ended, the values of the holds metric's result label.
const (
	dnsHoldAnswered = "answered"
	dnsHoldEmpty    = "empty"
)

func (self *DnsApi) feedRoutes() []*dnsApiRoute {
	return []*dnsApiRoute{
		{method: http.MethodGet, path: DnsJournalPath, class: DnsCallerEdge, serve: self.serveJournal},
		{method: http.MethodGet, path: DnsSnapshotPath, class: DnsCallerEdge, serve: self.serveSnapshot},
		// a diff records what a reload replaced and changes no zone data, so writes: false leaves it be
		{method: http.MethodPost, path: DnsReloadDiffPath, class: DnsCallerEdge, serve: self.serveReloadDiff},
	}
}

// Writes value as JSON with status 200.
func dnsWriteJson(writer http.ResponseWriter, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		http.Error(writer, "internal error", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Write(data)
}

// A store that did not answer: 503, for the edge to back off and ask again.
func dnsStoreUnavailable(writer http.ResponseWriter) {
	writer.Header().Set("Retry-After", "1")
	http.Error(writer, "service unavailable", http.StatusServiceUnavailable)
}

func (self *DnsApi) serveJournal(writer http.ResponseWriter, request *http.Request) {
	root, ok := self.requestRoot(request)
	if !ok {
		http.Error(writer, "no such root", http.StatusBadRequest)
		return
	}
	after, err := strconv.ParseUint(request.URL.Query().Get("after"), 10, 64)
	if err != nil {
		http.Error(writer, "after is not a serial", http.StatusBadRequest)
		return
	}
	answer, err := self.journalAnswer(request, root, after)
	if err != nil {
		dnsStoreUnavailable(writer)
		return
	}
	dnsWriteJson(writer, answer)
}

// One read of the store as an answer: rows above after, or reload, or neither.
func (self *DnsApi) readJournal(request *http.Request, root string, after uint64) (*DnsFeedAnswer, error) {
	ctx := request.Context()
	state, err := self.store.RootState(ctx, root)
	if err != nil {
		return nil, err
	}
	read, err := self.store.Journal(ctx, root, after, self.settings.Api.RowLimit)
	if err != nil {
		return nil, err
	}
	answer := &DnsFeedAnswer{
		Format:        DnsFormat,
		Root:          root,
		Serial:        read.Serial,
		RestoreSerial: state.RestoreSerial,
		Reload:        read.Gap && (!state.Restoring || state.RestoreIncidentId != nil),
	}
	if !read.Gap {
		answer.Rows = read.Rows
	}
	if self.deps.Interfaces != nil {
		answer.Interfaces = self.deps.Interfaces()
	}
	if self.deps.KeyWindow != nil {
		answer.KeyWindow = self.deps.KeyWindow(root, self.clock.Now())
	}
	return answer, nil
}

// Answers at once with what is there, or holds until a raise, the hold's end, the request's end or
// Drain, rereading the store at each wake and at the end.
func (self *DnsApi) journalAnswer(request *http.Request, root string, after uint64) (*DnsFeedAnswer, error) {
	done := self.holdStarted()
	defer done()
	holdEnded := self.clock.After(dnsSeconds(self.settings.Api.JournalHoldSeconds))
	for {
		raised := self.store.SerialRaised(root)
		answer, err := self.readJournal(request, root, after)
		if err != nil {
			return nil, err
		}
		if answer.Reload || len(answer.Rows) != 0 {
			self.metrics.holds.Add(1, dnsHoldRouteJournal, dnsHoldAnswered)
			return answer, nil
		}
		ended := self.park(func() bool {
			select {
			case <-raised:
				return false
			case <-holdEnded:
			case <-self.draining:
			case <-request.Context().Done():
			}
			return true
		})
		if !ended {
			continue
		}
		if err := request.Context().Err(); err != nil {
			return nil, err
		}
		self.metrics.holds.Add(1, dnsHoldRouteJournal, dnsHoldEmpty)
		// the hold's end reads again, which is what catches a raise Redis lost
		return self.readJournal(request, root, after)
	}
}

func (self *DnsApi) serveSnapshot(writer http.ResponseWriter, request *http.Request) {
	root, ok := self.requestRoot(request)
	if !ok {
		http.Error(writer, "no such root", http.StatusBadRequest)
		return
	}
	rows, err := self.store.Snapshot(request.Context(), root)
	if err != nil {
		dnsStoreUnavailable(writer)
		return
	}
	defer rows.Close()
	writer.Header().Set("Content-Type", "application/x-ndjson")
	snapshotWriter, err := NewDnsSnapshotWriter(writer, rows.Snapshot())
	if err != nil {
		return
	}
	for {
		set, err := rows.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// no end line follows, so the edge refuses what it read
			return
		}
		if err := snapshotWriter.Write(set); err != nil {
			return
		}
	}
	snapshotWriter.Close()
}

func (self *DnsApi) serveReloadDiff(writer http.ResponseWriter, request *http.Request) {
	diff := &DnsReloadDiff{}
	decoder := json.NewDecoder(io.LimitReader(request.Body, int64(self.settings.Api.DiffMaxByteCount)+1))
	if err := decoder.Decode(diff); err != nil {
		http.Error(writer, "a diff that does not read", http.StatusBadRequest)
		return
	}
	if err := self.validateReloadDiff(diff); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if err := self.store.RecordReloadDiff(request.Context(), diff); err != nil {
		dnsStoreUnavailable(writer)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

// Whether a diff names a root served here, a reload that raised its serial, and keys of that root.
func (self *DnsApi) validateReloadDiff(diff *DnsReloadDiff) error {
	known := false
	for _, root := range self.settings.Roots {
		known = known || root == diff.Root
	}
	if !known {
		return fmt.Errorf("a diff of a root not served here")
	}
	if diff.Serial <= diff.ReplacedSerial {
		return fmt.Errorf("a diff that does not raise the serial")
	}
	for index := range diff.Rrsets {
		if err := diff.Rrsets[index].Validate(diff.Root); err != nil {
			return fmt.Errorf("a diff naming a key that is no key")
		}
	}
	return nil
}
