//go:build !ios_extension && !sidecar_http

// Sharing one local model (DESIGN-COMPUTE §6.5): local agents that use one model share its engine, one call at a time
// on a phone and up to two on a desktop with the memory for both, the rest waiting in arrival order between whole
// calls; the Harness reads an agent's status as waiting, naming the model, until its call's start (§20.6). Each agent
// keeps its own conversation while memory allows; past that, a waiting agent's conversation is closed and, at its turn,
// reopened from its saved messages, which every call carries whole.
//
// Two halves, one a side of the helper's protocol:
//
//   - inferEngineShare, the daemon's: a loaded model's slots, one an engine, granted in arrival order. A call holds its
//     slot from its start to its end, so a call waits between whole calls, never between tokens.
//   - inferEnginePool, the helper's: the model's engines, each running one call at a time with one live conversation,
//     since interleaved conversations on one engine lose state (#2807). A call goes to the idle engine that holds its
//     agent's conversation, else to an idle one holding none, else to the idle one used least recently, whose
//     conversation it closes, to be reopened from that agent's saved messages at its next turn.
//
// Both are safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"slices"
	"sync"
)

// One loaded model's calls: up to slots at once, the rest waiting in arrival order.
type inferEngineShare struct {
	stateLock sync.Mutex
	slots     int
	busy      int
	// each waiting call's grant, in arrival order; closed when the call holds a slot
	waiters []chan struct{}
	// a test's seam: called once a call has taken its place in line, nil otherwise
	waited func()
}

// A share of slots, at least one.
func newInferEngineShare(slots int) *inferEngineShare {
	return &inferEngineShare{slots: max(slots, 1)}
}

// Waits its turn, in arrival order, for a slot, which release frees. A call that arrives while others wait waits behind
// them even where a slot is free, so no call passes one that came first. ctx's error where ctx ends first, its place
// given up.
func (self *inferEngineShare) acquire(ctx context.Context) error {
	grant := func() chan struct{} {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.busy < self.slots && len(self.waiters) == 0 {
			self.busy += 1
			return nil
		}
		grant := make(chan struct{})
		self.waiters = append(self.waiters, grant)
		return grant
	}()
	if grant == nil {
		return nil
	}
	if self.waited != nil {
		self.waited()
	}
	select {
	case <-grant:
		return nil
	case <-ctx.Done():
	}
	waiting := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		index := slices.Index(self.waiters, grant)
		if index < 0 {
			return false
		}
		self.waiters = slices.Delete(self.waiters, index, index+1)
		return true
	}()
	if !waiting {
		// granted as ctx ended: the slot is this call's, and it gives it back
		self.release()
	}
	return ctx.Err()
}

// Frees a slot: to the first waiting call, else back to the share.
func (self *inferEngineShare) release() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < len(self.waiters) {
		grant := self.waiters[0]
		self.waiters = slices.Delete(self.waiters, 0, 1)
		// the slot passes to it, so busy stays
		close(grant)
		return
	}
	self.busy -= 1
}

// How many calls wait, for status.
func (self *inferEngineShare) waiting() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.waiters)
}

// One engine of a loaded model and its one live conversation.
type inferEngineInstance struct {
	model inferEngineModel
	// whether a call holds it
	busy bool
	// the live conversation, nil for none
	conversation inferEngineConversation
	// whose conversation it is, its mode, and a hash of what it holds
	key     string
	mode    inferEngineMode
	history [sha256.Size]byte
	// when a call last held it, on the pool's count
	used uint64
}

// Closes the live conversation, if any: after a cancel, at an eviction, and before another opens.
func (self *inferEngineInstance) closeConversation() {
	if self.conversation != nil {
		self.conversation.close()
		self.conversation = nil
		self.key = ""
	}
}

// A loaded model's engines.
type inferEnginePool struct {
	stateLock sync.Mutex
	instances []*inferEngineInstance
	// counts calls, for least recently used
	count uint64
}

// A pool over models, one engine each.
func newInferEnginePool(models []inferEngineModel) *inferEnginePool {
	pool := &inferEnginePool{}
	for _, model := range models {
		pool.instances = append(pool.instances, &inferEngineInstance{model: model})
	}
	return pool
}

// An idle engine for a call of key, now held by it: the one holding key's conversation, else one holding none, else
// the one used least recently, whose conversation the caller closes before it opens its own. nil where every engine is
// busy.
func (self *inferEnginePool) acquire(key string) *inferEngineInstance {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var chosen *inferEngineInstance
	rank := func(instance *inferEngineInstance) int {
		switch {
		case instance.conversation != nil && instance.key == key:
			return 0
		case instance.conversation == nil:
			return 1
		}
		return 2
	}
	for _, instance := range self.instances {
		if instance.busy {
			continue
		}
		if chosen == nil || rank(instance) < rank(chosen) || (rank(instance) == rank(chosen) && instance.used < chosen.used) {
			chosen = instance
		}
	}
	if chosen == nil {
		return nil
	}
	self.count += 1
	chosen.busy = true
	chosen.used = self.count
	return chosen
}

// Gives instance back.
func (self *inferEnginePool) release(instance *inferEngineInstance) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	instance.busy = false
}

// Every engine, once none is busy, for unload; nil and false while one is.
func (self *inferEnginePool) takeAll() ([]*inferEngineInstance, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if slices.ContainsFunc(self.instances, func(instance *inferEngineInstance) bool { return instance.busy }) {
		return nil, false
	}
	instances := self.instances
	self.instances = nil
	return instances, true
}
