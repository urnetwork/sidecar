// ServiceHost.ServiceClient in memory (host_client.go): a stable client per index, and a new synthetic
// jwt at each call, as a later answer may carry for the same client.

package sidecartest

import (
	"context"
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
	issueCount   int
}

func NewFakeServiceClientSource(faults *FaultQueue, settings *FakeServiceClientSettings) *FakeServiceClientSource {
	if settings == nil {
		settings = DefaultFakeServiceClientSettings()
	}
	return &FakeServiceClientSource{faults: faults, settings: settings, indexClients: map[int]connect.Id{}, streamRanges: map[int]uint64{}}
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
