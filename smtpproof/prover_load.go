package smtpproof

import (
	"context"
	"errors"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/urnetwork/sidecar"
)

// A prover host's shape loader (DESIGN-DETAILS 3.2.8): what bounds proving's memory. A proof needs its
// shape's compiled circuit and proving key in memory, which the loader reads from the host's cache of
// verified keys (setup_cache.go, the key's dump), and a proof's own working memory while it runs. Neither
// is measured as it goes. The loader charges them instead, and keeps to
//
//	loaded shapes x ShapeMemoryByteCount + proofs in flight x PartMemoryByteCount <= MemoryMaxByteCount
//
// A load over the budget unloads the least recently used shape no proof in flight uses, and with none
// such it waits. A proof holds its charge until it ends, and a collection runs before the charge returns,
// since the charge rests on it: proofs back to back with no collection between them were measured near
// twice a proof's memory. A shape no proof has used for ShapeIdleTimeout is unloaded, and when the last
// goes the heap is returned to the system.
//
// One loader serves every pinned key set of one Prover, so one budget bounds every send it runs. Safe
// for concurrent use.

type proverLoader struct {
	// MemoryMaxByteCount, ShapeMemoryByteCount, PartMemoryByteCount and ShapeIdleTimeout are read.
	settings *ProverSettings
	// Times an idle shape out. Tests give a fake one.
	clock sidecar.Clock
	// Runs after each proof, before its charge returns: runtime.GC.
	collect func()
	// Runs once no shape is loaded: debug.FreeOSMemory.
	freeMemory func()

	stateLock sync.Mutex
	// By key: the key set's id and the shape's name. A shape here is loaded or loading, and charged.
	shapes map[string]*loadedShape
	// Proofs that hold a charge.
	proofs int
	// Uses so far, which orders shapes by their last use.
	uses uint64
	// Closed and replaced whenever a charge returns or a shape unloads, which a waiting load watches.
	changed chan struct{}
}

// One loaded or loading shape.
type loadedShape struct {
	key string
	// Closed once the load has ended, with keys or err.
	ready chan struct{}
	keys  *shapeKeys
	err   error
	// Proofs holding it, and the use that last took it.
	proofCount int
	lastUse    uint64
	// Stops the idle timer set when its last proof ended.
	stopIdle func() bool
}

func newProverLoader(settings *ProverSettings, clock sidecar.Clock) *proverLoader {
	return &proverLoader{
		settings:   settings,
		clock:      clock,
		collect:    runtime.GC,
		freeMemory: debug.FreeOSMemory,
		shapes:     map[string]*loadedShape{},
		changed:    make(chan struct{}),
	}
}

// What a budget charges with the shapes and proofs it holds, by the rule above.
func (self *proverLoader) chargedWithLock(shapeCount int, proofCount int) int64 {
	return int64(shapeCount)*self.settings.ShapeMemoryByteCount + int64(proofCount)*self.settings.PartMemoryByteCount
}

// Wakes whatever waits for a charge to return.
func (self *proverLoader) notifyWithLock() {
	close(self.changed)
	self.changed = make(chan struct{})
}

// The least recently used loaded shape no proof holds, other than key's, or nil.
func (self *proverLoader) idleShapeWithLock(key string) *loadedShape {
	var oldest *loadedShape
	for _, shape := range self.shapes {
		if shape.key == key || 0 < shape.proofCount {
			continue
		}
		if oldest == nil || shape.lastUse < oldest.lastUse {
			oldest = shape
		}
	}
	return oldest
}

// Unloads a shape, and says whether it was the last, after which the caller returns the heap.
func (self *proverLoader) unloadWithLock(shape *loadedShape) bool {
	if self.shapes[shape.key] != shape {
		return false
	}
	delete(self.shapes, shape.key)
	if shape.stopIdle != nil {
		shape.stopIdle()
		shape.stopIdle = nil
	}
	self.notifyWithLock()
	return len(self.shapes) == 0
}

// Proves under a shape's keys, loading them by load if they are not loaded, inside the budget. A proof
// whose context ends returns at once, and its charge returns when gnark's proof, which nothing can stop,
// ends; one that waits for a charge stops waiting.
func (self *proverLoader) prove(ctx context.Context, key string, load func() (*shapeKeys, error), prove func(keys *shapeKeys) ([]byte, error)) ([]byte, error) {
	shape, err := self.acquire(ctx, key, load)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	var proof []byte
	var proveErr error
	go func() {
		defer close(done)
		defer self.release(shape)
		proof, proveErr = prove(shape.keys)
		self.collect()
	}()
	select {
	case <-done:
		return proof, proveErr
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Charges a proof and its shape, waiting while the budget cannot hold them, and loads the shape if no
// proof has. The returned shape is held until release.
func (self *proverLoader) acquire(ctx context.Context, key string, load func() (*shapeKeys, error)) (*loadedShape, error) {
	if self.settings.MemoryMaxByteCount < self.settings.ShapeMemoryByteCount+self.settings.PartMemoryByteCount {
		return nil, errors.New("smtpproof: the prover's memory budget holds no proof")
	}
	for {
		var shape *loadedShape
		loading := false
		var wait chan struct{}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			current := self.shapes[key]
			shapeCount := len(self.shapes)
			if current == nil {
				shapeCount += 1
			}
			idleCount := 0
			for _, other := range self.shapes {
				if other.key != key && other.proofCount == 0 {
					idleCount += 1
				}
			}
			// nothing is unloaded for a proof that would wait all the same
			if self.settings.MemoryMaxByteCount < self.chargedWithLock(shapeCount-idleCount, self.proofs+1) {
				wait = self.changed
				return
			}
			for self.settings.MemoryMaxByteCount < self.chargedWithLock(shapeCount, self.proofs+1) {
				// the shape this load replaces goes now, and the heap is the next shape's
				self.unloadWithLock(self.idleShapeWithLock(key))
				shapeCount -= 1
			}

			if current == nil {
				current = &loadedShape{key: key, ready: make(chan struct{})}
				self.shapes[key] = current
				loading = true
			}
			if current.stopIdle != nil {
				current.stopIdle()
				current.stopIdle = nil
			}
			self.proofs += 1
			self.uses += 1
			current.proofCount += 1
			current.lastUse = self.uses
			shape = current
		}()
		if wait != nil {
			testHookBarrier("prover_load.wait", key)
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if loading {
			keys, err := load()
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				shape.keys, shape.err = keys, err
				if err != nil {
					// a shape not cached yet may be soon, so a failed load is not kept
					delete(self.shapes, key)
					self.notifyWithLock()
				}
			}()
			close(shape.ready)
		} else {
			select {
			case <-shape.ready:
			case <-ctx.Done():
				self.release(shape)
				return nil, ctx.Err()
			}
		}
		if shape.err != nil {
			self.release(shape)
			return nil, shape.err
		}
		return shape, nil
	}
}

// Returns a proof's charge and its hold on its shape. A shape left with no proof is unloaded once it has
// stayed so for ShapeIdleTimeout, or at once when that is not positive.
func (self *proverLoader) release(shape *loadedShape) {
	freeMemory := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.proofs -= 1
		shape.proofCount -= 1
		self.notifyWithLock()
		if 0 < shape.proofCount || self.shapes[shape.key] != shape {
			return
		}
		if self.settings.ShapeIdleTimeout <= 0 {
			freeMemory = self.unloadWithLock(shape)
			return
		}
		lastUse := shape.lastUse
		shape.stopIdle = self.clock.AfterFunc(self.settings.ShapeIdleTimeout, func() {
			self.idle(shape, lastUse)
		})
	}()
	if freeMemory {
		self.freeMemory()
	}
}

// An idle timer's end: the shape goes unless a proof took it since.
func (self *proverLoader) idle(shape *loadedShape, lastUse uint64) {
	freeMemory := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if shape.proofCount != 0 || shape.lastUse != lastUse {
			return
		}
		shape.stopIdle = nil
		freeMemory = self.unloadWithLock(shape)
	}()
	if freeMemory {
		self.freeMemory()
	}
}

// What the loader holds now: its shapes' keys, and the memory it charges.
func (self *proverLoader) loaded() ([]string, int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	keys := make([]string, 0, len(self.shapes))
	for key := range self.shapes {
		keys = append(keys, key)
	}
	return keys, self.chargedWithLock(len(self.shapes), self.proofs)
}

// How a backend on a prover host proves: through the host's loader, under a key set's cached keys.
type shapeLoading struct {
	loader *proverLoader
	// Names the set's shapes among every set the loader holds: the set's id.
	prefix string
	load   func(shape *partShape) (*shapeKeys, error)
}

// Proves under shape's keys through the loader.
func (self *shapeLoading) prove(ctx context.Context, shape *partShape, prove func(keys *shapeKeys) ([]byte, error)) ([]byte, error) {
	return self.loader.prove(ctx, self.prefix+partShapeName(shape), func() (*shapeKeys, error) {
		return self.load(shape)
	}, prove)
}
