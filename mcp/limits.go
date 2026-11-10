//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.4's bounds on one session, from SidecarMcpSettings: at most SessionCallCount calls in flight, a ninth waiting
// for a slot rather than being refused; W calls at SessionWriteRate, one past it refused at once; and each call ended
// at CallTimeout, under Codex's 60 s tool_timeout_sec. A call awaiting a person returns pending at once, so it never
// holds a slot (§16.4), and search's own session limits are MCP-M10-02's.
//
// Time is the server's Clock, so a test moves it and never sleeps. A call holds its slot until its handler returns,
// even past its timeout, so the bound is on work that actually runs; the timeout cancels the handler's context, and
// the caller is answered at once. Safe for concurrent use.

package mcp

import (
	"context"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// One session's limits.
type mcpSessionLimits struct {
	settings *sidecar.SidecarMcpSettings
	clock    sidecar.Clock
	// a token held per call in flight
	slots chan struct{}
	// called when a call finds every slot held, before it waits: a test's seam, nil otherwise
	waitHook func()

	stateLock sync.Mutex
	// W tokens left, refilled at SessionWriteRate up to its burst
	writeTokens float64
	// when writeTokens was last refilled
	writeRefillTime time.Time
}

// A session's limits, its write bucket full.
func newMcpSessionLimits(settings *sidecar.SidecarMcpSettings, clock sidecar.Clock) *mcpSessionLimits {
	return &mcpSessionLimits{
		settings:        settings,
		clock:           clock,
		slots:           make(chan struct{}, settings.SessionCallCount),
		writeTokens:     float64(settings.SessionWriteRate.Burst),
		writeRefillTime: clock.Now(),
	}
}

// Takes a slot, waiting while every one is held, until ctx ends. The answer releases it.
func (self *mcpSessionLimits) acquire(ctx context.Context) (func(), error) {
	var once sync.Once
	release := func() {
		once.Do(func() {
			<-self.slots
		})
	}
	select {
	case self.slots <- struct{}{}:
		return release, nil
	default:
	}
	if self.waitHook != nil {
		self.waitHook()
	}
	select {
	case self.slots <- struct{}{}:
		return release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Calls in flight now.
func (self *mcpSessionLimits) inFlightCount() int {
	return len(self.slots)
}

// Takes one W token, false past the rate: a token bucket of SessionWriteRate.Burst, refilled at Count an Interval.
func (self *mcpSessionLimits) admitWrite() bool {
	rate := self.settings.SessionWriteRate
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	if elapsed := now.Sub(self.writeRefillTime); 0 < elapsed {
		self.writeTokens += float64(rate.Count) * float64(elapsed) / float64(rate.Interval)
		if float64(rate.Burst) < self.writeTokens {
			self.writeTokens = float64(rate.Burst)
		}
		self.writeRefillTime = now
	}
	if self.writeTokens < 1 {
		return false
	}
	self.writeTokens -= 1
	return true
}

// Runs call under the session's bounds: a slot, then the call on its own goroutine under CallTimeout on the clock.
// The answer is the call's, or a timeout error at once when the clock passes the timeout first; the call's context
// ends then too, and its slot frees when it returns.
func (self *mcpSessionLimits) run(ctx context.Context, call func(ctx context.Context) (any, error)) (any, error) {
	callCtx, cancel := context.WithCancel(ctx)
	timedOut := make(chan struct{})
	stop := self.clock.AfterFunc(self.settings.CallTimeout, func() {
		close(timedOut)
		cancel()
	})
	release, err := self.acquire(callCtx)
	if err != nil {
		stop()
		cancel()
		select {
		case <-timedOut:
			return nil, errMcpTimeout()
		default:
		}
		return nil, err
	}
	type outcome struct {
		result any
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		defer release()
		defer cancel()
		result, err := call(callCtx)
		done <- outcome{result: result, err: err}
	}()
	select {
	case finished := <-done:
		stop()
		return finished.result, finished.err
	case <-timedOut:
		return nil, errMcpTimeout()
	}
}

// The timeout's refusal.
func errMcpTimeout() error {
	return newMcpError(McpCodeTimeout, "the call ran past its time limit", true)
}

// The W rate's refusal.
func errMcpRateLimited() error {
	return newMcpError(McpCodeRateLimited, "too many write calls in this session: wait and send it again", true)
}
