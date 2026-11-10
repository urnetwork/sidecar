// evs's transfer metering (QUOTA-M2-10; §20.6's table, §11.13's transfer row): MeterTransfer wraps the router, so
// every /evs/* request counts the body bytes it brought and the body bytes it was answered with into
// UsageBatcher.AddTransfer, on meter evs, for the caller's network: the token's, never the repo's, which takes
// only stored-byte deltas. Reads, uploads and pushes count alike, a refused one's bytes and a phone's fallback
// download included, and a spent network's unpaid reads too, which api then finds no balance for (reading 5).
//
//   - The caller is known once the guard has verified the token, and it tells the meter then. A request with no
//     verified token names no network, so its bytes count for no one.
//   - Only body bytes that moved count: what the handler read of the request's body and what it wrote of the
//     reply's. Headers do not.
//   - Bytes go to the batcher as they move, every FlushByteCount of them and at the request's end, so a long
//     reply's bytes reach the open window while it streams and an unclean exit loses at most that window
//     (§20.6's loss row). Each byte is added once: this is the one place evs counts transfer (FI-13 (a)).
//
// A meter given no batcher counts nothing and passes every request through unchanged. Safe for concurrent use.

package evsservice

import (
	"io"
	"net/http"
	"sync"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

type TransferMeterSettings struct {
	// The bytes a request gathers before they go to the batcher: 64 KiB, small against a window and large
	// enough that a streamed frame costs the batcher's lock once. Non-positive sends every read and write's
	// count at once.
	FlushByteCount int64
}

func DefaultTransferMeterSettings() *TransferMeterSettings {
	return &TransferMeterSettings{
		FlushByteCount: 64 * 1024,
	}
}

// See the file header.
type transferMeter struct {
	handler  http.Handler
	usage    *UsageBatcher
	settings *TransferMeterSettings
	log      sidecar.Logger
}

// handler with every request's and reply's body bytes counted into usage for the caller's network. settings may
// be nil for the defaults, log nil to discard, and usage nil to count nothing. See the file header.
func MeterTransfer(handler http.Handler, usage *UsageBatcher, settings *TransferMeterSettings, log sidecar.Logger) http.Handler {
	if usage == nil {
		return handler
	}
	if settings == nil {
		settings = DefaultTransferMeterSettings()
	}
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	return &transferMeter{handler: handler, usage: usage, settings: settings, log: log}
}

func (self *transferMeter) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	meterWriter := &transferMeterWriter{ResponseWriter: writer, meter: self}
	meterWriter.flusher, _ = writer.(http.Flusher)
	defer meterWriter.finish()
	meteredRequest := request.WithContext(request.Context())
	if request.Body != nil {
		meteredRequest.Body = &transferMeterBody{ReadCloser: request.Body, writer: meterWriter}
	}
	self.handler.ServeHTTP(meterWriter, meteredRequest)
}

// One request's count, and its reply's writer. The body may be read off the request's goroutine, as a streamed
// upload's is, so the count is locked.
type transferMeterWriter struct {
	http.ResponseWriter
	meter   *transferMeter
	flusher http.Flusher

	stateLock sync.Mutex
	// the token's network, zero until the guard has verified one
	callerNetworkId connect.Id
	// counted and not yet handed to the batcher
	pendingByteCount int64
}

// The guard's word that the request's token verified for networkId. Only the first counts: a request has one
// token.
func (self *transferMeterWriter) setCaller(networkId connect.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.callerNetworkId == (connect.Id{}) {
		self.callerNetworkId = networkId
	}
}

// Counts byteCount body bytes that moved, and hands the batcher what has gathered once it passes the flush
// count, or whatever there is at the request's end.
func (self *transferMeterWriter) add(byteCount int64, end bool) {
	var callerNetworkId connect.Id
	var flushByteCount int64
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.pendingByteCount += byteCount
		if self.callerNetworkId == (connect.Id{}) {
			return
		}
		if end || self.meter.settings.FlushByteCount <= self.pendingByteCount {
			callerNetworkId = self.callerNetworkId
			flushByteCount = self.pendingByteCount
			self.pendingByteCount = 0
		}
	}()
	if flushByteCount <= 0 {
		return
	}
	if err := self.meter.usage.AddTransfer(callerNetworkId, flushByteCount); err != nil {
		// a closed batcher, at shutdown: under-billing only, as an unclean exit's open window is
		self.meter.log.Infof("[evs] transfer of a request not counted: %v", err)
	}
}

func (self *transferMeterWriter) finish() {
	self.add(0, true)
}

func (self *transferMeterWriter) Write(body []byte) (int, error) {
	n, err := self.ResponseWriter.Write(body)
	if 0 < n {
		self.add(int64(n), false)
	}
	return n, err
}

// The read stream flushes each frame.
func (self *transferMeterWriter) Flush() {
	if self.flusher != nil {
		self.flusher.Flush()
	}
}

// For http.ResponseController.
func (self *transferMeterWriter) Unwrap() http.ResponseWriter {
	return self.ResponseWriter
}

// The request's body, each byte read counted.
type transferMeterBody struct {
	io.ReadCloser
	writer *transferMeterWriter
}

func (self *transferMeterBody) Read(body []byte) (int, error) {
	n, err := self.ReadCloser.Read(body)
	if 0 < n {
		self.writer.add(int64(n), false)
	}
	return n, err
}

// Tells the meter serving writer, if one is, that its request's token verified for networkId. A paced writer
// stands in front of the meter's, so the chain is walked.
func meterTransferCaller(writer http.ResponseWriter, networkId connect.Id) {
	for writer != nil {
		if meterWriter, ok := writer.(*transferMeterWriter); ok {
			meterWriter.setCaller(networkId)
			return
		}
		unwrapper, ok := writer.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		writer = unwrapper.Unwrap()
	}
}
