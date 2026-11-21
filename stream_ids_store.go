//go:build !sidecar_http

package sidecar

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Each range holds 2^21 IDs of each parity. A 42-bit range can also carry
// the millisecond authentication time an edge's credential mint reserves.
const (
	streamIdRangeShift = 22
	maxStreamIdRange   = ^uint64(0) >> streamIdRangeShift
	// The first upgraded sidecar starts above four quadrillion unpartitioned IDs.
	firstStoredStreamIdRange uint64 = 1 << 30
)

// The upper 42 bits of a stream ID name a range reserved before use. A restart skips
// the unused suffix, keeping the receiver's existing replay check on v1.
func (self *subprotocolStreams) nextId(ctx context.Context, peer *streamPeer) (uint64, error) {
	self.rangeLock.Lock()
	defer self.rangeLock.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if self.reserveIds == nil {
		return 0, errors.New("stream: no durable ID range source")
	}
	if self.sendRange == 0 || (peer.sendRange == self.sendRange &&
		(peer.ids.exhausted || (peer.ids.next>>streamIdRangeShift) != self.sendRange)) {
		next, err := self.reserveIds(ctx)
		if err != nil {
			return 0, err
		}
		if next > maxStreamIdRange || next <= self.sendRange {
			return 0, errors.New("stream: ID range did not advance")
		}
		self.sendRange = next
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if peer.sendRange != self.sendRange {
		peer.ids.next = self.sendRange<<streamIdRangeShift | peer.ids.next&1
		peer.sendRange = self.sendRange
	}
	return peer.ids.open()
}

// The daemon holds its instance lock across processes. Serialize the store's
// read/replace across dispatchers in this process as well, including a host
// starting a replacement while its previous generation finishes closing.
var streamIdStoreLock sync.Mutex

// Commit before the first open can leave. Reread after any uncertain write.
func reserveStoredStreamIds(store SidecarStore) (uint64, error) {
	streamIdStoreLock.Lock()
	defer streamIdStoreLock.Unlock()
	const name = "stream-id-range"
	previous := firstStoredStreamIdRange - 1
	reader, err := store.Open(name)
	if err == nil {
		data, readErr := io.ReadAll(io.LimitReader(reader, 9))
		if err := errors.Join(readErr, reader.Close()); err != nil {
			return 0, err
		}
		if len(data) != 8 {
			return 0, fmt.Errorf("%w: invalid stream ID range", ErrSidecarStoreFailed)
		}
		previous = binary.BigEndian.Uint64(data)
		if previous < firstStoredStreamIdRange || maxStreamIdRange < previous {
			return 0, fmt.Errorf("%w: invalid stream ID range", ErrSidecarStoreFailed)
		}
	} else if !errors.Is(err, ErrSidecarStoreAbsent) {
		return 0, err
	}
	if previous == maxStreamIdRange {
		return 0, errStreamIdsExhausted
	}
	next := previous + 1
	writer, err := store.Create(name)
	if err != nil {
		return 0, err
	}
	defer writer.Close()
	if _, err := writer.Write(binary.BigEndian.AppendUint64(nil, next)); err != nil {
		return 0, err
	}
	if err := writer.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}
