//go:build !ios_extension && !sidecar_http

// A device's search outcomes not yet reported (DESIGN-COMPUTE §21.8's Outcomes, D-SRCH-9, compute-11; SRCH-M13-02):
// each paid search's class, ok, provider_error, timeout or refused, counted by class alone, never with a request id, a
// time, a query or a result. The counts ride the device's next authorization request, and are dropped once the broker
// took one; a device that searches no more reports them once a day, POST compute/v1/search/outcomes, the client's run
// loop asking ReportDue.
//
// They are kept, in the network's sealed store, in a file of their own of class websearch (§5.9's file classes, the
// class proposed), so a restart reports what the last run counted. A count saturates rather than wrap. Every change is
// written before it returns: a failed write fails the call, and a count that could not be kept is logged by its caller,
// never sent. Safe for concurrent use: one stateLock over the file's reads and writes.

package sidecar

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The outcome classes (§21.8): identifiers, which the broker's hourly counts take.
const (
	WebSearchOutcomeOk            = "ok"
	WebSearchOutcomeProviderError = "provider_error"
	WebSearchOutcomeTimeout       = "timeout"
	WebSearchOutcomeRefused       = "refused"
)

// The log's place in the network's store, and its format's version: identifiers.
const (
	webSearchStoreDirectory   = "websearch"
	webSearchStoreClass       = "websearch"
	webSearchOutcomeLogName   = "outcomes.json"
	webSearchOutcomeLogFormat = 1
)

var (
	// A class the log does not count.
	ErrWebSearchOutcomeClass = errors.New("web search: no such outcome class")
)

// The log's file.
type webSearchOutcomeFile struct {
	Version       int    `json:"version"`
	Ok            uint32 `json:"ok"`
	ProviderError uint32 `json:"provider_error"`
	Timeout       uint32 `json:"timeout"`
	Refused       uint32 `json:"refused"`
	// When counts last left, by an authorization or the daily report, in Unix milliseconds; 0 for never.
	ReportedMs int64 `json:"reported_ms"`
}

// The counts as the wire carries them, nil where every one is zero.
func (self *webSearchOutcomeFile) outcomes() *protocol.SearchOutcomes {
	if self.Ok == 0 && self.ProviderError == 0 && self.Timeout == 0 && self.Refused == 0 {
		return nil
	}
	return &protocol.SearchOutcomes{Ok: self.Ok, ProviderError: self.ProviderError, Timeout: self.Timeout, Refused: self.Refused}
}

// What NewWebSearchOutcomeLog builds on.
type WebSearchOutcomeLogArgs struct {
	// Required: the directory the log's file lives in, sealed under its class.
	Store    SidecarStore
	Settings *WebSearchSettings
	// Nil reads real time.
	Clock Clock
}

// See the file header.
type WebSearchOutcomeLog struct {
	store    SidecarStore
	settings *WebSearchSettings
	clock    Clock

	stateLock sync.Mutex
}

// A log over args. Reads nothing until its first call.
func NewWebSearchOutcomeLog(args *WebSearchOutcomeLogArgs) (*WebSearchOutcomeLog, error) {
	if args == nil || args.Store == nil {
		return nil, errors.New("web search outcome log: a store")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultWebSearchSettings()
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	return &WebSearchOutcomeLog{store: args.Store, settings: settings, clock: clock}, nil
}

// The file as kept, an empty one where there is none.
func (self *WebSearchOutcomeLog) readWithLock() (*webSearchOutcomeFile, error) {
	file := &webSearchOutcomeFile{Version: webSearchOutcomeLogFormat}
	reader, err := self.store.Open(webSearchOutcomeLogName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return file, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, int64(self.settings.OutcomeLogMaxByteCount)+1))
	if err != nil {
		return nil, err
	}
	if self.settings.OutcomeLogMaxByteCount < len(data) {
		return nil, fmt.Errorf("web search outcome log: a file past %d bytes", self.settings.OutcomeLogMaxByteCount)
	}
	if err := json.Unmarshal(data, file); err != nil || file.Version != webSearchOutcomeLogFormat {
		return nil, fmt.Errorf("web search outcome log: a file that does not read")
	}
	return file, nil
}

// Writes file whole.
func (self *WebSearchOutcomeLog) writeWithLock(file *webSearchOutcomeFile) error {
	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	writer, err := self.store.Create(webSearchOutcomeLogName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// Counts one search of class.
func (self *WebSearchOutcomeLog) Add(class string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	file, err := self.readWithLock()
	if err != nil {
		return err
	}
	var count *uint32
	switch class {
	case WebSearchOutcomeOk:
		count = &file.Ok
	case WebSearchOutcomeProviderError:
		count = &file.ProviderError
	case WebSearchOutcomeTimeout:
		count = &file.Timeout
	case WebSearchOutcomeRefused:
		count = &file.Refused
	default:
		return fmt.Errorf("%w: %q", ErrWebSearchOutcomeClass, class)
	}
	if *count < math.MaxUint32 {
		*count += 1
	}
	return self.writeWithLock(file)
}

// The counts not yet reported, nil where there are none.
func (self *WebSearchOutcomeLog) Unreported() (*protocol.SearchOutcomes, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	file, err := self.readWithLock()
	if err != nil {
		return nil, err
	}
	return file.outcomes(), nil
}

// Drops sent, which the broker took, from the counts, keeping any counted since, and notes the time.
func (self *WebSearchOutcomeLog) Reported(sent *protocol.SearchOutcomes) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	file, err := self.readWithLock()
	if err != nil {
		return err
	}
	take := func(count *uint32, taken uint32) {
		*count -= min(*count, taken)
	}
	take(&file.Ok, sent.GetOk())
	take(&file.ProviderError, sent.GetProviderError())
	take(&file.Timeout, sent.GetTimeout())
	take(&file.Refused, sent.GetRefused())
	file.ReportedMs = self.clock.Now().UnixMilli()
	return self.writeWithLock(file)
}

// The counts the daily report sends now, nil where none is due: counts held and none reported for
// OutcomesReportInterval.
func (self *WebSearchOutcomeLog) ReportDue() (*protocol.SearchOutcomes, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	file, err := self.readWithLock()
	if err != nil {
		return nil, err
	}
	outcomes := file.outcomes()
	if outcomes == nil {
		return nil, nil
	}
	if file.ReportedMs != 0 && self.clock.Now().Before(time.UnixMilli(file.ReportedMs).Add(self.settings.OutcomesReportInterval)) {
		return nil, nil
	}
	return outcomes, nil
}
