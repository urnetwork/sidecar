//go:build !js

// Sidecar.Directory (directory_client.go): nil before the network and the record exist, nil while nothing binds the
// authorization state, nil in a personal network, whose log names no directory, and the one client in a team network
// whose log names one.

package sidecar

import (
	"errors"
	"testing"
)

// A Sidecar's directory is nil outside a team network with a directory, and the same client once it has one.
func TestSidecarDirectoryNilOutsideATeamNetwork(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	sidecar := &Sidecar{instance: instance, settings: validSidecarSettings()}
	if sidecar.Directory() != nil {
		t.Fatal("a directory before enrollment")
	}
	if _, err := sidecar.DirectoryClient(); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Fatalf("a client before enrollment: %v", err)
	}
	networkId := testNetworkId
	sidecar.networkId = &networkId
	sidecar.identity = &SidecarIdentity{NetworkId: networkId, SidecarId: NewId(), IdentityPublicKey: make([]byte, 32)}
	client, err := sidecar.DirectoryClient()
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.Directory() != nil {
		t.Error("a directory while nothing binds the state")
	}

	personal := newTestConfigNet(t)
	client.Bind(nil, func() DirectoryAuthView { return NewDirectoryAuthView(personal.log.State()) })
	if sidecar.Directory() != nil {
		t.Error("a directory in a personal network")
	}

	team := NewDirectoryAuthTestNetwork(t)
	client.Bind(nil, func() DirectoryAuthView { return team.View() })
	if directory := sidecar.Directory(); directory != client {
		t.Errorf("the team network's directory %p, want %p", directory, client)
	}
	if again, err := sidecar.DirectoryClient(); err != nil || again != client {
		t.Errorf("a second client: %v", err)
	}
}
