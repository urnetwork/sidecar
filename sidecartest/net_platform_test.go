package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

// Control the seam's own test platform refuses: it has no controller.
type testRefusingOutOfBandControl struct {
}

func (self *testRefusingOutOfBandControl) SendControl(frames []*protocol.Frame, callback connect.OobResultFunction) {
	for _, frame := range frames {
		connect.MessagePoolReturn(frame.MessageBytes)
	}
	if callback != nil {
		connect.HandleError(func() {
			callback(nil, errors.New("the seam's test platform takes no control"))
		})
	}
}

// A platform for the seam's own tests, recording what it opened and closed in order: each client a Required connect
// client with no transport, so the tests read the Net's handling of a platform and nothing of a real one, which T3's
// tests in server run on server's exchange.
type testNetPlatform struct {
	// what OpenClient answers instead of a client, nil for a client
	openErr error

	stateLock sync.Mutex
	events    []string
	clientIds []connect.Id
}

func (self *testNetPlatform) record(event string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, event)
}

func (self *testNetPlatform) Events() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

func (self *testNetPlatform) OpenClient(ctx context.Context, name string, settings *connect.ClientSettings) (*NetPlatformClient, error) {
	if self.openErr != nil {
		return nil, self.openErr
	}
	clientId := connect.NewId()
	client := connect.NewClient(ctx, clientId, &testRefusingOutOfBandControl{}, settings)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.clientIds = append(self.clientIds, clientId)
	}()
	self.record("open " + name)
	return &NetPlatformClient{
		ClientId: clientId,
		Client:   client,
		Close: func() {
			select {
			case <-client.Ctx().Done():
				self.record("close " + name + " after its cancel")
			default:
				self.record("close " + name + " while it ran")
			}
		},
	}, nil
}

func (self *testNetPlatform) Close() {
	self.record("close the platform")
}

// A Net's settings with platform built from them, counting the builds.
func testPlatformNetSettings(platform *testNetPlatform, builds *int, buildErr error) *NetSettings {
	settings := DefaultNetSettings()
	settings.Platform = func(ctx context.Context, net *Net) (NetPlatform, error) {
		*builds += 1
		if buildErr != nil {
			return nil, buildErr
		}
		return platform, nil
	}
	return settings
}

// The platform is built at the first client, once, opens every client under ids of its own, and is closed at the Net's
// end after each client is canceled and what stands beside it is closed. Its clients are not the fakes'.
func TestNetPlatformOpensTheClientsAndClosesLast(t *testing.T) {
	platform := &testNetPlatform{}
	builds := 0
	net := NewNet(t.Context(), testPlatformNetSettings(platform, &builds, nil))
	if builds != 0 {
		t.Fatalf("the platform was built %d times before a client", builds)
	}
	a, err := net.OpenClient("a", nil)
	if err != nil {
		t.Fatal(err)
	}
	b := net.AddClient("b", nil)
	if builds != 1 {
		t.Errorf("the platform was built %d times for two clients", builds)
	}
	if !slices.Equal([]connect.Id{a.ClientId, b.ClientId}, platform.clientIds) {
		t.Errorf("the clients are %s and %s, the platform gave %v", a.ClientId, b.ClientId, platform.clientIds)
	}
	if net.UsesPlatformFakes() {
		t.Error("a platform's clients count as the fakes'")
	}
	net.Close()
	want := []string{"open a", "open b", "close a after its cancel", "close b after its cancel", "close the platform"}
	if events := platform.Events(); !slices.Equal(events, want) {
		t.Errorf("the platform saw %v, want %v", events, want)
	}
	if _, err := net.OpenClient("c", nil); err == nil {
		t.Error("a closed Net opened a client")
	}
}

// A Net that opens no client builds no platform and closes none.
func TestNetWithNoClientBuildsNoPlatform(t *testing.T) {
	platform := &testNetPlatform{}
	builds := 0
	net := NewNet(t.Context(), testPlatformNetSettings(platform, &builds, nil))
	net.Close()
	if builds != 0 || len(platform.Events()) != 0 {
		t.Errorf("built %d times, saw %v", builds, platform.Events())
	}
}

// A platform that does not start fails OpenClient with its reason, every time and with no second build, and AddClient
// panics with it; a platform that refuses one client fails that OpenClient.
func TestNetPlatformFailuresReachTheCaller(t *testing.T) {
	func() {
		builds := 0
		net := NewNet(t.Context(), testPlatformNetSettings(nil, &builds, errors.New("no listener")))
		defer net.Close()
		for range 2 {
			if _, err := net.OpenClient("a", nil); err == nil || !strings.Contains(err.Error(), "no listener") {
				t.Errorf("OpenClient on a platform that did not start: %v", err)
			}
		}
		if builds != 1 {
			t.Errorf("a failed platform was built %d times", builds)
		}
		defer func() {
			if recovered := recover(); recovered == nil || !strings.Contains(fmt.Sprint(recovered), "no listener") {
				t.Errorf("AddClient on a platform that did not start: %v", recovered)
			}
		}()
		net.AddClient("b", nil)
	}()

	// one Net at a time: each installs the process's hooks
	refusing := &testNetPlatform{openErr: errors.New("auth refused")}
	builds := 0
	net := NewNet(t.Context(), testPlatformNetSettings(refusing, &builds, nil))
	defer net.Close()
	if _, err := net.OpenClient("a", nil); err == nil || !strings.Contains(err.Error(), "auth refused") {
		t.Errorf("OpenClient refused by the platform: %v", err)
	}
}

// A Net on a platform applies no link condition and no contract class, and keeps each one asked for as unapplied;
// lifting a link's conditions asks for nothing. The fakes' Net applies both.
func TestNetOnAPlatformKeepsLinksAndClassesUnapplied(t *testing.T) {
	a, b := connect.NewId(), connect.NewId()
	func() {
		builds := 0
		net := NewNet(t.Context(), testPlatformNetSettings(&testNetPlatform{}, &builds, nil))
		defer net.Close()
		net.SetLink(a, b, nil)
		if unapplied := net.Unapplied(); len(unapplied) != 0 {
			t.Errorf("lifting a link left %v", unapplied)
		}
		net.SetLink(a, b, &LinkConditions{Partition: true})
		net.SetContractClass(a, b, protocol.ContractClass_ContractClassControl)
		unapplied := net.Unapplied()
		if len(unapplied) != 2 || !strings.HasPrefix(unapplied[0], "SetLink") || !strings.HasPrefix(unapplied[1], "SetContractClass") {
			t.Errorf("unapplied %v", unapplied)
		}
	}()

	// one Net at a time: each installs the process's hooks
	fakes := newTestNet(t)
	fakes.SetLink(a, b, &LinkConditions{Partition: true})
	fakes.SetContractClass(a, b, protocol.ContractClass_ContractClassControl)
	if unapplied := fakes.Unapplied(); len(unapplied) != 0 {
		t.Errorf("the fakes' Net left %v", unapplied)
	}
	if fakes.exchange.passes(a, b) || fakes.exchange.contractClass(a, b) != protocol.ContractClass_ContractClassControl {
		t.Error("the fakes' Net did not apply the link and the class")
	}
}

// A client that is not Required panics before any platform is built (I-3).
func TestNetPlatformClientsOtherThanRequiredPanic(t *testing.T) {
	builds := 0
	net := NewNet(t.Context(), testPlatformNetSettings(&testNetPlatform{}, &builds, nil))
	defer net.Close()
	settings := netClientSettings()
	settings.EncryptionSettings.Mode = connect.EncryptionModeOpportunistic
	func() {
		defer func() {
			if recover() == nil {
				t.Error("an Opportunistic client opened on a platform")
			}
		}()
		net.OpenClient("a", settings)
	}()
	if builds != 0 {
		t.Errorf("the platform was built for a refused client")
	}
}
