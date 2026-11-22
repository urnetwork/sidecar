// ServiceHost.ServiceClient in memory (host_client.go): a stable client per index, and a new synthetic
// jwt at each call, as a later answer may carry for the same client. Each index's client also has a stream ID
// range per ask and a stable identity seed (sidecar.EdgeClientIdentitySource), random for the source's life, so a
// pool made again on the same source is a restarted edge: the same ids and the same connect identity.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

type FakeServiceClientSettings struct {
	ApiUrl      string
	PlatformUrl string
}

func DefaultFakeServiceClientSettings() *FakeServiceClientSettings {
	return &FakeServiceClientSettings{
		ApiUrl:      "https://api.sidecartest.example",
		PlatformUrl: "wss://connect.sidecartest.example",
	}
}

type FakeServiceClientSource struct {
	faults   *FaultQueue
	settings *FakeServiceClientSettings

	stateLock    sync.Mutex
	indexClients map[int]connect.Id
	streamRanges map[int]uint64
	// each index's identity seed, drawn at its first ask
	indexSeeds map[int][]byte
	issueCount int
}

func NewFakeServiceClientSource(faults *FaultQueue, settings *FakeServiceClientSettings) *FakeServiceClientSource {
	if settings == nil {
		settings = DefaultFakeServiceClientSettings()
	}
	return &FakeServiceClientSource{faults: faults, settings: settings, indexClients: map[int]connect.Id{}, streamRanges: map[int]uint64{}, indexSeeds: map[int][]byte{}}
}

func (self *FakeServiceClientSource) ServiceClient(ctx context.Context, clientIndex int) (*sidecar.ServiceClientAuth, error) {
	if clientIndex < 0 {
		return nil, fmt.Errorf("client index %d", clientIndex)
	}
	// host_client.go: an empty url is never a success
	if self.settings.ApiUrl == "" || self.settings.PlatformUrl == "" {
		return nil, errors.New("a service client needs both urls")
	}
	var auth *sidecar.ServiceClientAuth
	err := hostCall(ctx, self.faults, "serviceclient.ServiceClient", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		clientId, ok := self.indexClients[clientIndex]
		if !ok {
			clientId = connect.NewId()
			self.indexClients[clientIndex] = clientId
		}
		self.issueCount += 1
		auth = &sidecar.ServiceClientAuth{
			ClientId:    clientId,
			ByJwt:       fmt.Sprintf("fake-platform-token-%d", self.issueCount),
			ApiUrl:      self.settings.ApiUrl,
			PlatformUrl: self.settings.PlatformUrl,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return auth, nil
}

func (self *FakeServiceClientSource) ReserveStreamIdRange(ctx context.Context, index int, clientId sidecar.Id) (uint64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if id, ok := self.indexClients[index]; !ok || sidecar.Id(id) != clientId || self.streamRanges[index] == math.MaxUint64 {
		return 0, errors.New("no stream ID range for this client")
	}
	self.streamRanges[index]++
	return self.streamRanges[index], nil
}

// The index's identity seed, the same for the source's life, for the client the source answered for it alone. See
// sidecar.EdgeClientIdentitySource. A fresh copy each call, which the caller clears.
func (self *FakeServiceClientSource) EdgeClientIdentitySeed(ctx context.Context, index int, clientId sidecar.Id) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if id, ok := self.indexClients[index]; !ok || sidecar.Id(id) != clientId {
		return nil, errors.New("no identity for this client")
	}
	seed, ok := self.indexSeeds[index]
	if !ok {
		seed = make([]byte, sidecar.EdgeClientIdentitySeedByteCount)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		self.indexSeeds[index] = seed
	}
	return bytes.Clone(seed), nil
}
