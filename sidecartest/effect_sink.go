// A component's effect for the O tools' gate tests (MCP-M3-06; plan-MCP-effect-seam): EffectSink does each effect
// once per effect key, as every §16.6 component must, keeps what it did and finds it again as its kind's Lookup, so a
// test of any O tool counts effects against uses (AU1) and drives a restart's reconcile without the real component. A
// keyless run, a standing grant's, is an effect each time. What the next run answers, whether runs wait for the test,
// and what Lookup proves of a key with no effect are the test's to set.
//
// Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/urnetwork/sidecar"
)

// A SidecarEffect and its Lookup, in memory.
type EffectSink struct {
	stateLock sync.Mutex
	// each key's effect, by key
	keyRefs map[string][]byte
	// Run's calls, and the effects that happened
	runCount    int
	effectCount int
	// what Run answers instead of the effect, nil to do it
	answer error
	// while set, a token goes to started as each Run begins and the Run waits for release to close
	started chan struct{}
	release chan struct{}
	// what Lookup answers of a key with no effect: not_done when set, else uncertain
	provesNone bool
	// the spend each Run saw on its context, in order
	spends []*sidecar.ApprovalSpend
}

var _ sidecar.SidecarEffect = (*EffectSink)(nil)

// A sink that has done nothing.
func NewEffectSink() *EffectSink {
	return &EffectSink{keyRefs: map[string][]byte{}}
}

// Does the effect once per key: a key seen before answers its reference and does nothing. Answers what SetAnswer set
// instead, doing nothing, for a key with no effect yet. Waits while Hold's release is open, or until ctx ends.
func (self *EffectSink) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	started, release := func() (chan struct{}, chan struct{}) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.started, self.release
	}()
	if started != nil {
		select {
		case started <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.runCount += 1
	if spend, ok := sidecar.ApprovalSpendFromContext(ctx); ok {
		self.spends = append(self.spends, spend)
	}
	if ref, ok := self.keyRefs[string(effectKey)]; ok && len(effectKey) != 0 {
		return bytes.Clone(ref), nil
	}
	if self.answer != nil {
		return nil, self.answer
	}
	return self.doneWithLock(effectKey), nil
}

// One more effect under effectKey, its reference.
func (self *EffectSink) doneWithLock(effectKey []byte) []byte {
	self.effectCount += 1
	ref := []byte(fmt.Sprintf("sink effect %d", self.effectCount))
	if len(effectKey) != 0 {
		self.keyRefs[string(effectKey)] = ref
	}
	return bytes.Clone(ref)
}

// The kind's Lookup over what the sink did: done with its reference for a key it did, else not_done where
// SetLookupProvesNone says the component can prove none, else uncertain.
func (self *EffectSink) Lookup(ctx context.Context, canonical []byte, effectKey []byte) (*sidecar.SidecarOutcome, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if ref, ok := self.keyRefs[string(effectKey)]; ok {
		return &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeDone, EffectRef: bytes.Clone(ref)}, nil
	}
	if self.provesNone {
		return &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeNotDone}, nil
	}
	return &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeUncertain}, nil
}

// What Run answers for a key with no effect yet: nil does the effect; an error wrapping
// sidecar.ErrSidecarEffectNotDone proves none happened; any other leaves the use uncertain.
func (self *EffectSink) SetAnswer(answer error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.answer = answer
}

// Whether Lookup proves no effect for a key the sink did nothing under.
func (self *EffectSink) SetLookupProvesNone(provesNone bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.provesNone = provesNone
}

// Makes each Run from now on wait: it sends a token on started as it begins, then waits for release, which lets
// every waiting and later Run go, the hold ending.
func (self *EffectSink) Hold() (started <-chan struct{}, release func()) {
	startedChannel := make(chan struct{})
	releaseChannel := make(chan struct{})
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.started, self.release = startedChannel, releaseChannel
	var once sync.Once
	return startedChannel, func() {
		once.Do(func() {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				if self.release == releaseChannel {
					self.started, self.release = nil, nil
				}
			}()
			close(releaseChannel)
		})
	}
}

// Takes an effect under effectKey as a process killed before its Outcome did, answering its reference.
func (self *EffectSink) DoneUnder(effectKey []byte) []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if ref, ok := self.keyRefs[string(effectKey)]; ok {
		return bytes.Clone(ref)
	}
	return self.doneWithLock(effectKey)
}

// Run's calls.
func (self *EffectSink) RunCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.runCount
}

// The effects that happened: one per key, and one per keyless run.
func (self *EffectSink) EffectCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.effectCount
}

// The spend each Run saw on its context, in order: nothing for a standing grant's run.
func (self *EffectSink) Spends() []*sidecar.ApprovalSpend {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*sidecar.ApprovalSpend{}, self.spends...)
}
