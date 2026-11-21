//go:build !sidecar_http && !ios_extension && !js

package sidecar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The same constructor the stock SDK and daemon call reads K_sock only from
// their standing, verified config follower, and follows the next signed base.
func TestHostedSocketsFollowVerifiedKeyRotation(t *testing.T) {
	world := newConfigFollowWorld(t, 1, nil)
	network := world.networks[0]
	running := world.host(network, nil)
	world.standing(running, network)
	component, err := running.NewSocketComponent(world.ctx)
	if err != nil {
		t.Fatal(err)
	}
	remove, err := running.AddComponent(component)
	if err != nil {
		component.Close()
		t.Fatal(err)
	}
	defer remove()
	if running.SocketKeyRing() != nil {
		t.Fatal("a network without socket/key supplied a ring")
	}
	initial := sidecar.NewSocketKeyFile()
	rotated, err := sidecar.RotateSocketKeyFile(initial, world.net.Clock().Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	for _, keyFile := range []*protocol.SocketKeyFile{initial, rotated} {
		wire, err := sidecar.MarshalSocketKeyFile(keyFile)
		if err != nil {
			t.Fatal(err)
		}
		network.SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
			return head.WithFile(sidecar.ConfigHeadSocketKeyPath, wire)
		})
		world.standing(running, network)
		expected, err := sidecar.NewSocketKeyRing(network.NetworkId(), keyFile, sidecar.DefaultSocketKeyRingSettings())
		if err != nil {
			t.Fatal(err)
		}
		now := world.net.Clock().Now().UnixMilli()
		paths, err := expected.RegisterTokenPaths("app/demo", now)
		if err != nil {
			t.Fatal(err)
		}
		guard := time.After(configFollowTestTimeout)
		acl := running.ConfigFollower().AclFollower()
		for {
			_, changed := acl.Local()
			if held := running.SocketKeyRing(); held != nil {
				got, err := held.RegisterTokenPaths("app/demo", now)
				if err == nil && len(got) == len(paths) && bytes.Equal(got[0], paths[0]) && bytes.Equal(got[len(got)-1], paths[len(paths)-1]) {
					break
				}
			}
			select {
			case <-changed:
			case <-guard:
				t.Fatal("the signed head's socket keys were not installed")
			}
		}
	}
	network.SaveAclPolicy([]byte(`{"grants":[{"src":["autogroup:member"],"dst":["sock:app/*"],"allow":["listen","dial"]}]}`), sidecartest.AclSaveMembers{})
	world.standing(running, network)
	api, err := world.net.Api()
	if err != nil {
		t.Fatal(err)
	}
	api.ServeService("dns", http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != sidecar.DnsZonePath || request.Header.Get("Authorization") == "" {
			http.Error(w, "missing zone token", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(&sidecar.DnsZone{NetworkId: network.NetworkId(), Label: "abcdefghij", Root: "users.example", Alias: "team"})
	}))
	var registered, found atomic.Int32
	expected, err := sidecar.NewSocketKeys(network.NetworkId(), rotated.GetCurrentKey())
	if err != nil {
		t.Fatal(err)
	}
	token, err := expected.TokenPath("app/demo")
	if err != nil {
		t.Fatal(err)
	}
	api.ServeService("sockets", http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") == "" {
			http.Error(w, "missing service token", http.StatusForbidden)
			return
		}
		switch request.URL.Path {
		case "/socket/registrations":
			var page sidecar.SocketRegistrationsArgs
			if err := json.NewDecoder(request.Body).Decode(&page); err != nil {
				http.Error(w, "invalid page", http.StatusBadRequest)
				return
			}
			statuses := make([]sidecar.SocketRegistrationStatus, len(page.Registrations))
			for i, registration := range page.Registrations {
				statuses[i] = sidecar.SocketRegistrationStatusOk
				if registration.Name != "" || len(registration.Claim) == 0 || len(registration.SealedName) == 0 {
					t.Error("application registration lacked its blinded name or signed claim")
				}
				if bytes.Equal(registration.NameToken, token) {
					registered.Add(1)
				}
			}
			json.NewEncoder(w).Encode(&sidecar.SocketRegistrationsResult{Statuses: statuses, SetVersion: page.SetVersion})
		case "/socket/find":
			var find sidecar.SocketFindArgs
			if err := json.NewDecoder(request.Body).Decode(&find); err == nil && find.Name == "" && bytes.Equal(find.NameToken, token) {
				found.Add(1)
			}
			json.NewEncoder(w).Encode(&sidecar.SocketFindResult{Error: &sidecar.SocketError{Code: sidecar.SocketErrorCodeNoListener}})
		default:
			http.NotFound(w, request)
		}
	}))
	ctx, cancel := context.WithTimeout(world.ctx, configFollowTestTimeout)
	defer cancel()
	// Wait for the local policy to reach the newest signed head before presenting the request.
	acl := running.ConfigFollower().AclFollower()
	for {
		_, changed := acl.Local()
		if running.SocketKeyRing() != nil {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	listener, err := running.Listen(ctx, "team:app/demo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := running.Dial(ctx, "app/demo", nil); !errors.Is(err, sidecar.ErrSocketNoListener) {
		t.Fatalf("lookup: %v", err)
	}
	if registered.Load() == 0 || found.Load() == 0 {
		t.Fatal("public Listen and Dial did not send the rotated token to the registry")
	}
	listener.Close()
	// Removing the head's key also requires removing any policy that names a blinded target.
	network.SaveAclPolicy([]byte(`{"grants":[]}`), sidecartest.AclSaveMembers{})
	network.SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadSocketKeyPath, nil)
	})
	world.standing(running, network)
	if running.SocketKeyRing() != nil {
		t.Fatal("the removed key still authorizes blinded socket names")
	}
}
