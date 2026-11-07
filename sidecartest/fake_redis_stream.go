// FakeRedis's streams: XADD, XRANGE and the consumer groups behind §19.4's push sender.

package sidecartest

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

type fakeRedisStreamId struct {
	ms  uint64
	seq uint64
}

func (self fakeRedisStreamId) String() string {
	return fmt.Sprintf("%d-%d", self.ms, self.seq)
}

func (self fakeRedisStreamId) after(other fakeRedisStreamId) bool {
	return other.ms < self.ms || (self.ms == other.ms && other.seq < self.seq)
}

// <ms>-<seq>, or <ms>, as XRANGE and XAUTOCLAIM take. Parts compare as integers (§6.8).
func parseRedisStreamId(entryId string) (fakeRedisStreamId, error) {
	msText, seqText, hasSeq := strings.Cut(entryId, "-")
	ms, err := strconv.ParseUint(msText, 10, 64)
	if err != nil {
		return fakeRedisStreamId{}, fmt.Errorf("ERR Invalid stream ID specified: %q", entryId)
	}
	seq := uint64(0)
	if hasSeq {
		if seq, err = strconv.ParseUint(seqText, 10, 64); err != nil {
			return fakeRedisStreamId{}, fmt.Errorf("ERR Invalid stream ID specified: %q", entryId)
		}
	}
	return fakeRedisStreamId{ms: ms, seq: seq}, nil
}

type fakeRedisStreamEntry struct {
	id          fakeRedisStreamId
	fieldValues map[string][]byte
}

func (self *fakeRedisStreamEntry) reply() *sidecar.RedisStreamEntry {
	fieldValues := make(map[string][]byte, len(self.fieldValues))
	for field, value := range self.fieldValues {
		fieldValues[field] = bytes.Clone(value)
	}
	return &sidecar.RedisStreamEntry{Id: self.id.String(), FieldValues: fieldValues}
}

type fakeRedisPending struct {
	id          fakeRedisStreamId
	consumer    string
	deliveredAt time.Time
}

type fakeRedisGroup struct {
	lastDelivered fakeRedisStreamId
	pending       []*fakeRedisPending
}

type fakeRedisStreamState struct {
	entries []*fakeRedisStreamEntry
	lastId  fakeRedisStreamId
	groups  map[string]*fakeRedisGroup
}

func (self *FakeRedis) streamEntryWithLock(key string, create bool) (*fakeRedisEntry, error) {
	entry, ok := self.entries[key]
	if ok {
		if entry.kind != fakeRedisStream {
			return nil, ErrRedisWrongType
		}
		return entry, nil
	}
	if !create {
		return nil, nil
	}
	entry = &fakeRedisEntry{
		kind:   fakeRedisStream,
		stream: &fakeRedisStreamState{groups: map[string]*fakeRedisGroup{}},
	}
	self.entries[key] = entry
	return entry, nil
}

func (self *FakeRedis) streamAddWithLock(key string, maxLength int64, fieldValues map[string][]byte) (string, error) {
	entry, err := self.streamEntryWithLock(key, true)
	if err != nil {
		return "", err
	}
	stream := entry.stream
	id := fakeRedisStreamId{ms: uint64(self.clock.Now().UnixMilli())}
	if !id.after(stream.lastId) {
		id = fakeRedisStreamId{ms: stream.lastId.ms, seq: stream.lastId.seq + 1}
	}
	stream.lastId = id
	stored := make(map[string][]byte, len(fieldValues))
	for field, value := range fieldValues {
		stored[field] = bytes.Clone(value)
	}
	stream.entries = append(stream.entries, &fakeRedisStreamEntry{id: id, fieldValues: stored})

	// MAXLEN ~ drops whole nodes only, so it may keep more than maxLength and never fewer
	if 0 < maxLength {
		nodeEntryCount := self.settings.StreamNodeEntryCount
		for maxLength <= int64(len(stream.entries)-nodeEntryCount) {
			stream.entries = slices.Delete(stream.entries, 0, nodeEntryCount)
		}
	}
	close(self.streamAdded)
	self.streamAdded = make(chan struct{})
	return id.String(), nil
}

func (self *FakeRedis) StreamAdd(ctx context.Context, key string, maxLength int64, fieldValues map[string][]byte) (string, error) {
	var entryId string
	err := self.call(ctx, "xadd", []string{key}, func() error {
		var err error
		entryId, err = self.streamAddWithLock(key, maxLength, fieldValues)
		return err
	})
	if err != nil {
		return "", err
	}
	return entryId, nil
}

func (self *FakeRedis) StreamRange(ctx context.Context, key string, afterEntryId string, count int64) ([]*sidecar.RedisStreamEntry, error) {
	var after fakeRedisStreamId
	if afterEntryId != "" {
		var err error
		if after, err = parseRedisStreamId(afterEntryId); err != nil {
			return nil, err
		}
	}
	entries := []*sidecar.RedisStreamEntry{}
	err := self.call(ctx, "xrange", []string{key}, func() error {
		entry, err := self.streamEntryWithLock(key, false)
		if err != nil || entry == nil {
			return err
		}
		for _, streamEntry := range entry.stream.entries {
			if int64(len(entries)) == count {
				break
			}
			if afterEntryId == "" || streamEntry.id.after(after) {
				entries = append(entries, streamEntry.reply())
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func (self *FakeRedis) StreamGroupCreate(ctx context.Context, key string, group string) error {
	return self.call(ctx, "xgroup", []string{key}, func() error {
		entry, err := self.streamEntryWithLock(key, true)
		if err != nil {
			return err
		}
		if _, exists := entry.stream.groups[group]; !exists {
			entry.stream.groups[group] = &fakeRedisGroup{lastDelivered: entry.stream.lastId}
		}
		return nil
	})
}

func (self *FakeRedis) groupWithLock(key string, group string) (*fakeRedisEntry, *fakeRedisGroup, error) {
	entry, err := self.streamEntryWithLock(key, false)
	if err != nil {
		return nil, nil, err
	}
	if entry == nil {
		return nil, nil, ErrRedisNoGroup
	}
	groupState, ok := entry.stream.groups[group]
	if !ok {
		return nil, nil, ErrRedisNoGroup
	}
	return entry, groupState, nil
}

// New entries for consumer, up to count, each moved to the group's pending list.
func (self *FakeRedis) groupReadWithLock(key string, group string, consumer string, count int64) ([]*sidecar.RedisStreamEntry, error) {
	entry, groupState, err := self.groupWithLock(key, group)
	if err != nil {
		return nil, err
	}
	entries := []*sidecar.RedisStreamEntry{}
	for _, streamEntry := range entry.stream.entries {
		if 0 < count && int64(len(entries)) == count {
			break
		}
		if !streamEntry.id.after(groupState.lastDelivered) {
			continue
		}
		groupState.lastDelivered = streamEntry.id
		groupState.pending = append(groupState.pending, &fakeRedisPending{
			id:          streamEntry.id,
			consumer:    consumer,
			deliveredAt: self.clock.Now(),
		})
		entries = append(entries, streamEntry.reply())
	}
	return entries, nil
}

func (self *FakeRedis) StreamGroupRead(ctx context.Context, key string, group string, consumer string, count int64, block time.Duration) ([]*sidecar.RedisStreamEntry, error) {
	var timedOut <-chan time.Time
	if 0 < block {
		timedOut = self.clock.After(block)
	}
	var entries []*sidecar.RedisStreamEntry
	for {
		var added chan struct{}
		err := self.call(ctx, "xreadgroup", []string{key}, func() error {
			added = self.streamAdded
			var err error
			entries, err = self.groupReadWithLock(key, group, consumer, count)
			return err
		})
		if err != nil {
			return nil, err
		}
		if 0 < len(entries) || block <= 0 {
			return entries, nil
		}
		done := false
		self.blocking(func() {
			select {
			case <-added:
			case <-timedOut:
				done = true
			case <-ctx.Done():
				done = true
			}
		})
		stopIfDead(ctx)
		if done {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return []*sidecar.RedisStreamEntry{}, nil
		}
	}
}

func (self *FakeRedis) StreamGroupAck(ctx context.Context, key string, group string, entryIds []string) error {
	ids := make([]fakeRedisStreamId, 0, len(entryIds))
	for _, entryId := range entryIds {
		id, err := parseRedisStreamId(entryId)
		if err != nil {
			return err
		}
		ids = append(ids, id)
	}
	return self.call(ctx, "xack", []string{key}, func() error {
		_, groupState, err := self.groupWithLock(key, group)
		if err != nil {
			return err
		}
		groupState.pending = slices.DeleteFunc(groupState.pending, func(pending *fakeRedisPending) bool {
			return slices.Contains(ids, pending.id)
		})
		return nil
	})
}

func (self *FakeRedis) StreamGroupClaim(ctx context.Context, key string, group string, consumer string, minIdle time.Duration, cursor string, count int64) ([]*sidecar.RedisStreamEntry, string, error) {
	start := fakeRedisStreamId{}
	if cursor != "" {
		var err error
		if start, err = parseRedisStreamId(cursor); err != nil {
			return nil, "", err
		}
	}
	entries := []*sidecar.RedisStreamEntry{}
	nextCursor := "0-0"
	err := self.call(ctx, "xautoclaim", []string{key}, func() error {
		entry, groupState, err := self.groupWithLock(key, group)
		if err != nil {
			return err
		}
		now := self.clock.Now()
		live := map[fakeRedisStreamId]*fakeRedisStreamEntry{}
		for _, streamEntry := range entry.stream.entries {
			live[streamEntry.id] = streamEntry
		}
		// an entry trimmed from the stream leaves the pending list too (Redis 7's XAUTOCLAIM)
		groupState.pending = slices.DeleteFunc(groupState.pending, func(pending *fakeRedisPending) bool {
			_, ok := live[pending.id]
			return !ok
		})
		for _, pending := range groupState.pending {
			if start.after(pending.id) {
				continue
			}
			if 0 < count && int64(len(entries)) == count {
				nextCursor = pending.id.String()
				break
			}
			if now.Sub(pending.deliveredAt) < minIdle {
				continue
			}
			pending.consumer = consumer
			pending.deliveredAt = now
			entries = append(entries, live[pending.id].reply())
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return entries, nextCursor, nil
}

// Each group's pending ids by consumer, for a test: what is delivered and not yet acknowledged.
func (self *FakeRedis) StreamPending(key string, group string) map[string][]string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	consumerIds := map[string][]string{}
	if _, groupState, err := self.groupWithLock(key, group); err == nil {
		for _, pending := range groupState.pending {
			consumerIds[pending.consumer] = append(consumerIds[pending.consumer], pending.id.String())
		}
	}
	for consumer := range maps.Keys(consumerIds) {
		slices.Sort(consumerIds[consumer])
	}
	return consumerIds
}
