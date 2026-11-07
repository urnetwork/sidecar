// ServiceHost.ServiceClient in memory (host_client.go): a stable client per index, and a new synthetic
// jwt at each call, as a later answer may carry for the same client.

package sidecartest

import (
	"context"
	"fmt"
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
	issueCount   int
}

func NewFakeServiceClientSource(faults *FaultQueue, settings *FakeServiceClientSettings) *FakeServiceClientSource {
	if settings == nil {
		settings = DefaultFakeServiceClientSettings()
	}
	return &FakeServiceClientSource{faults: faults, settings: settings, indexClients: map[int]connect.Id{}}
}

func (self *FakeServiceClientSource) ServiceClient(ctx context.Context, clientIndex int) (*sidecar.ServiceClientAuth, error) {
	if clientIndex < 0 {
		return nil, fmt.Errorf("client index %d", clientIndex)
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
