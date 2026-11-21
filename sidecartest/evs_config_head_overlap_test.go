// Overlapping calls on one EvsClient for the config head reader (evs_config_head.go; evs_pin_walk.go), on
// evs_config_head_world_test.go's world: a head read whose log evs answered after another call of the same client
// read the main ref to a newer head stands, with no alarm, its raise judged against the pin as it then stands and
// placed by that read's walk, and the pin stays where the other read raised it. Before the change the head's raise
// was held to the live pin, refused as a regression with head_alarm, and the head withheld as unavailable.

package sidecartest

import (
	"bytes"
	"context"
	"maps"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
)

// A device of label on the world whose client's events are kept, as deviceOn makes one, and the events.
func configHeadWatchedDevice(world *configHeadWorld, label string) (*epochDevice, func() []sidecar.SidecarEvent) {
	world.t.Helper()
	signer := world.signers[label]
	device := &epochDevice{world: world.epochWorld, label: label, signer: signer, store: NewFakeStore().Root(), gkm: world.gkm.Client(signer.SidecarId, signer.Sign)}
	device.gkm.AuthAdvanced(world.currentView())
	identity := &sidecar.SidecarIdentity{NetworkId: world.networkId, SidecarId: signer.SidecarId, ClientId: world.clientId, Generation: 1, IdentityPublicKey: signer.PublicKey()}
	eventsLock := &sync.Mutex{}
	events := []sidecar.SidecarEvent{}
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: world.networkId,
		EvsUrl:    "https://evs.example",
		Transport: &epochTransport{world: world.epochWorld, device: device},
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			connectSidecarId := connect.Id(signer.SidecarId)
			return world.host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: connect.Id(world.networkId), ClientId: connect.Id(world.clientId), SidecarId: &connectSidecarId,
				Audience: evsservice.EvsAudience, Scopes: scopes, IssuedAt: world.clock.Now(), ExpiresAt: world.clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Sign:     sidecar.EvsSignFunction(signer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      device.gkm,
		Store:    device.store,
		Config:   func() sidecar.GkmAuthView { return world.currentView() },
		Clock:    &epochDeviceClock{clock: world.clock},
		Log:      sidecar.NewNoopLogger(),
		Settings: sidecar.DefaultEvsSettings(),
		Emit: func(event sidecar.SidecarEvent) {
			eventsLock.Lock()
			defer eventsLock.Unlock()
			events = append(events, event)
		},
	})
	if err != nil {
		world.t.Fatal(err)
	}
	world.t.Cleanup(client.Close)
	device.client = client
	device.repo = client.Repo(world.repoId)
	world.stateLock.Lock()
	world.devices = append(world.devices, device)
	world.stateLock.Unlock()
	return device, func() []sidecar.SidecarEvent {
		eventsLock.Lock()
		defer eventsLock.Unlock()
		alarms := []sidecar.SidecarEvent{}
		for _, event := range events {
			if event.Kind == sidecar.SidecarEventHeadAlarm || event.Kind == sidecar.SidecarEventEvsAlarm {
				alarms = append(alarms, event)
			}
		}
		return alarms
	}
}

// A config head read while another read of the same client pins the main ref past it: the read holds no alarm and
// answers the head saved at its version.
func TestEvsConfigHeadReaderReadAnsweredBeforeAnotherReadRaisedThePinStands(t *testing.T) {
	world := newConfigHeadWorld(t)
	device, alarms := configHeadWatchedDevice(world, "r")
	reader := world.reader(device)
	world.requireHead(reader, 1, "the first read")
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names at 2")})
	// the reader's log read of the head at 2 waits, ahead of evs, while the same client reads the ref to its newer head
	held, release := make(chan struct{}), make(chan struct{})
	var holdOnce, releaseOnce sync.Once
	let := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(let)
	world.setIntercept(func(intercepted *epochDevice, request *http.Request) error {
		if intercepted != device || request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, "/log") {
			return nil
		}
		taken := false
		holdOnce.Do(func() { taken = true })
		if taken {
			close(held)
			<-release
		}
		return nil
	})
	type read struct {
		head *sidecar.ConfigHead
		err  error
	}
	reads := make(chan read, 1)
	go func() {
		head, err := reader.ReadConfigHead(context.Background(), 2, world.chains[2][:])
		reads <- read{head: head, err: err}
	}()
	<-held
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names at 3")})
	if _, err := device.repo.ReadHead(t.Context(), &sidecar.EvsReadArgs{Path: sidecar.ConfigHeadNamesPath}, &bytes.Buffer{}); err != nil {
		t.Fatalf("the read beside it: %v", err)
	}
	if pinned := world.pinVersion(device); pinned != 3 {
		t.Fatalf("the read beside it pinned %d", pinned)
	}
	let()
	answer := <-reads
	world.setIntercept(nil)
	if answer.err != nil {
		t.Fatalf("the held read: %v", answer.err)
	}
	if want, got := world.heads[2].Files(), answer.head.Files(); !maps.EqualFunc(want, got, bytes.Equal) {
		t.Fatalf("the held read holds %v, not %v", answer.head.Paths(), world.heads[2].Paths())
	}
	if raised := alarms(); len(raised) != 0 {
		t.Errorf("alarms %v", raised)
	}
	if pinned := world.pinVersion(device); pinned != 3 {
		t.Errorf("the pin %d", pinned)
	}
}
