// §7.9's retain row, as one ConfigLog holds it: A_k from the retention point on, each base's (n, A_n) for
// ConfigLogSettings.BasePinRetention, the previous and current bases' rows, the ids of statements applied among the
// last 4,096 entries, and every entry's verbatim bytes from the retention point, which a base's re-application and
// the next base's fold check read. How much of that a device persists, 64 KiB on a phone and the whole tail on a
// desktop, is TEAM-M2-10's; ConfigRetained is what it persists and RestoreConfigLog starts from.
//
// Single-writer, as ConfigLog's Apply is. Nothing here creates, derives or unwraps a key, so nothing calls
// testHookSecret.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"slices"
)

// What a ConfigLog keeps, which a ConfigStateStore saves and RestoreConfigLog starts from, as a new device or a
// restarted one does (§7.9's retention row).
type ConfigRetained struct {
	// The Signed Genesis, verbatim.
	SignedGenesis []byte
	// Every entry from the retention point to the tip, verbatim, in position order.
	Entries [][]byte
	// The rows of the current and previous bases, verbatim, by rows_sha256.
	Rows map[[sha256.Size]byte][]byte
}

// Where a device keeps its ConfigRetained across restarts (§5.9's authlog/), so a restart resumes with no lower pin.
type ConfigStateStore interface {
	// What was saved for the network, or nil with no error when nothing was.
	LoadConfigRetained(networkId Id) (*ConfigRetained, error)
	// Replaces what was saved for the network.
	SaveConfigRetained(networkId Id, retained *ConfigRetained) error
}

// What this log keeps now, copied, for a ConfigStateStore.
func (self *ConfigLog) Retained() *ConfigRetained {
	retained := &ConfigRetained{
		SignedGenesis: bytes.Clone(self.signedGenesis),
		Entries:       make([][]byte, 0, len(self.kept)),
		Rows:          map[[sha256.Size]byte][]byte{},
	}
	for _, kept := range self.kept {
		retained.Entries = append(retained.Entries, bytes.Clone(kept.entryBytes))
	}
	for rowsSha256, rows := range self.baseRows {
		retained.Rows[rowsSha256] = bytes.Clone(rows)
	}
	return retained
}

// The bytes Retained would copy, the kept entries' and the base rows', which a cache of many networks' logs bounds
// itself by (AclGateCache). For the log's applying goroutine, as Retained is.
func (self *ConfigLog) RetainedByteCount() int64 {
	byteCount := int64(len(self.signedGenesis))
	for _, kept := range self.kept {
		byteCount += int64(len(kept.entryBytes))
	}
	for _, rows := range self.baseRows {
		byteCount += int64(len(rows))
	}
	return byteCount
}

// Saves what this log keeps.
func (self *ConfigLog) SaveTo(store ConfigStateStore) error {
	return store.SaveConfigRetained(self.networkId, self.Retained())
}

// Moves the retention point to a new base's: drops the entries and chain digests before it, keeps the new base's
// (n, A_n) beside those still within BasePinRetention, and the rows of the new and previous bases only. state is the
// new base's, not yet published, so its chains may still change.
func (self *ConfigLog) retainBase(state *ConfigState, rows []byte) {
	point := state.RetentionPoint()
	if self.keptFrom < point {
		dropCount := min(int(point-self.keptFrom), len(self.kept))
		self.kept = append([]*configKeptEntry(nil), self.kept[dropCount:]...)
		self.keptFrom = point
	}
	if state.chainsFrom < point && point <= state.n {
		state.chains = slices.Clone(state.chains[point-state.chainsFrom:])
		state.chainsFrom = point
	}

	basePins := []configBasePin{}
	retention := self.settings.BasePinRetention.Milliseconds()
	for _, basePin := range state.basePins {
		previous := state.previousBase != nil && basePin.n == state.previousBase.n
		if previous || (0 < retention && state.timeMs-basePin.timeMs <= retention) {
			basePins = append(basePins, basePin)
		}
	}
	state.basePins = append(basePins, configBasePin{n: state.base.n, chain: state.base.chain, timeMs: state.base.timeMs})

	baseRows := map[[sha256.Size]byte][]byte{}
	baseRows[sha256.Sum256(rows)] = bytes.Clone(rows)
	if state.previousBase != nil {
		for rowsSha256, previousRows := range self.baseRows {
			if bytes.Equal(rowsSha256[:], state.previousBase.header.GetRowsSha256()) {
				baseRows[rowsSha256] = previousRows
			}
		}
	}
	self.baseRows = baseRows
}
