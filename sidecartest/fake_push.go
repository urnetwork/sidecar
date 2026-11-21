// ServiceHost.Push in memory (host_push.go, §6.8): what a client would have been told. It keeps a
// topic's version from lowering, as the real script does, and refuses a body past the 256 B a hint may
// carry, since that limit keeps content out of hints. Hint and HintSidecars send, so each is a write
// (hostWrite): §22.8's unknown rule loses its answer with the hint delivered, which a caller counts and
// goes on from, as host_push.go has it.

package sidecartest

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
)

// What a FakePush holds a hint to.
type FakePushSettings struct {
	// §6.8's wire limits, a hint body's 256 B among them: pushservice's, whose defaults are the protocol's.
	Format *pushservice.PushFormatSettings
}

// The protocol's limits.
func DefaultFakePushSettings() *FakePushSettings {
	return &FakePushSettings{
		Format: pushservice.DefaultPushFormatSettings(),
	}
}

// One hint as a client received it.
type FakeHint struct {
	ClientId connect.Id
	Hint     *sidecar.ClientHint
}

type FakePush struct {
	faults   *FaultQueue
	settings *FakePushSettings

	stateLock        sync.Mutex
	hints            []*FakeHint
	clientVersions   map[connect.Id]map[string]uint64
	sidecarClientIds map[connect.Id]connect.Id
	missedSidecarIds []connect.Id
}

// On the defaults.
func NewFakePush(faults *FaultQueue) *FakePush {
	return NewFakePushWithSettings(faults, nil)
}

// settings nil takes the defaults.
func NewFakePushWithSettings(faults *FaultQueue, settings *FakePushSettings) *FakePush {
	if settings == nil {
		settings = DefaultFakePushSettings()
	}
	return &FakePush{
		faults:           faults,
		settings:         settings,
		clientVersions:   map[connect.Id]map[string]uint64{},
		sidecarClientIds: map[connect.Id]connect.Id{},
	}
}

// Which client a sidecar is now, as §5's binding says.
func (self *FakePush) BindSidecar(sidecarId connect.Id, clientId connect.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sidecarClientIds[sidecarId] = clientId
}

func (self *FakePush) hintClientWithLock(clientId connect.Id, hint *sidecar.ClientHint) {
	versions, ok := self.clientVersions[clientId]
	if !ok {
		versions = map[string]uint64{}
		self.clientVersions[clientId] = versions
	}
	versions[hint.Topic] = max(versions[hint.Topic], hint.Version)
	hintCopy := *hint
	hintCopy.Body = slices.Clone(hint.Body)
	hintCopy.Version = versions[hint.Topic]
	self.hints = append(self.hints, &FakeHint{ClientId: clientId, Hint: &hintCopy})
}

func (self *FakePush) checkHint(hint *sidecar.ClientHint) error {
	if maxHintByteCount := self.settings.Format.MaxHintByteCount; maxHintByteCount < len(hint.Body) {
		return fmt.Errorf("a hint body of %d bytes, past %d", len(hint.Body), maxHintByteCount)
	}
	return nil
}

func (self *FakePush) Hint(ctx context.Context, clientIds []connect.Id, hint *sidecar.ClientHint) error {
	if err := self.checkHint(hint); err != nil {
		return err
	}
	return hostWrite(ctx, self.faults, "push.Hint", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, clientId := range clientIds {
			self.hintClientWithLock(clientId, hint)
		}
		return nil
	})
}

func (self *FakePush) HintSidecars(ctx context.Context, sidecarIds []connect.Id, hint *sidecar.ClientHint) error {
	if err := self.checkHint(hint); err != nil {
		return err
	}
	return hostWrite(ctx, self.faults, "push.HintSidecars", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, sidecarId := range sidecarIds {
			if clientId, ok := self.sidecarClientIds[sidecarId]; ok {
				self.hintClientWithLock(clientId, hint)
			} else {
				// a device mid-change: its hourly resync covers it
				self.missedSidecarIds = append(self.missedSidecarIds, sidecarId)
			}
		}
		return nil
	})
}

// What clientId was told, in order. The version in each is what the client stored by then.
func (self *FakePush) Hints(clientId connect.Id) []*sidecar.ClientHint {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	hints := []*sidecar.ClientHint{}
	for _, hint := range self.hints {
		if hint.ClientId == clientId {
			hints = append(hints, hint.Hint)
		}
	}
	return hints
}

// The client's stored version for a topic, zero if never hinted.
func (self *FakePush) Version(clientId connect.Id, topic string) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.clientVersions[clientId][topic]
}

// Sidecars no client answered for when hinted.
func (self *FakePush) MissedSidecarIds() []connect.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.missedSidecarIds)
}

// Every hint sent, for CC4's scan of push payloads.
func (self *FakePush) AllHints() []*FakeHint {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.hints)
}
