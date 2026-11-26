// Two networks on one engine world (enginenet.go's OpenNetwork): evs and gkm stay open to every network the world
// opens, and to one a test opened through the gates itself, so a world that opens a second network, as a second
// Bootstrap opens it, still serves the first. Each network's config writer places and reads its config repo at evs and
// publishes and reads its ReaderKey at gkm, through the Net's api transport at the services' origins, on tokens the
// Net's authenticator mints as the exchange would.

package enginenet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One request of device's sidecar in network at audience's origin, on a token of scopes: the status.
func enginesTwoNetworksCall(t *testing.T, engines *Engines, network *sidecartest.AdmissionNet, device *sidecartest.AdmissionDevice, audience string, method string, path string, body []byte, scopes ...string) int {
	t.Helper()
	net := engines.net
	sidecarId := connect.Id(device.SidecarId)
	now := net.Clock().Now()
	token := net.Fakes().Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(network.NetworkId()),
		ClientId:  connect.Id(network.Id("client of " + device.SidecarId.String())),
		SidecarId: &sidecarId,
		Audience:  audience,
		Scopes:    scopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
	})
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(t.Context(), method, engines.Api().ServiceOrigin(audience)+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := engines.Api().Transport().RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	io.Copy(io.Discard, response.Body)
	return response.StatusCode
}

// Two networks opened one after the other, each served at evs and gkm, writes and reads, and the network a test had
// opened through the gates before still admitted. On the code before, OpenNetwork replaced each service's list, so
// opening the second network closed both services to the first, whose every request answered 503, and to the network
// the test had opened.
func TestEnginesServeEvsAndGkmToEveryNetworkOpened(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	tier.AclCompile = sidecartest.AclAdmissionCompile
	alpha := sidecartest.NewAdmissionNet(t, tier)
	t.Cleanup(alpha.Close)
	bravo := sidecartest.NewAdmissionNet(t, tier)
	t.Cleanup(bravo.Close)
	engines := NewEngines(t, net, nil)

	gates := net.Fakes().Gates
	listed := connect.NewId()
	gates.OpenService(sidecar.ServiceGateEvs, listed)
	engines.OpenNetwork(alpha.NetworkId())
	engines.OpenNetwork(bravo.NetworkId())
	for _, networkId := range []sidecar.Id{alpha.NetworkId(), bravo.NetworkId()} {
		for _, service := range []string{sidecar.ServiceGateEvs, sidecar.ServiceGateGkm} {
			if gate := gates.Service(service); !gate.Admits(connect.Id(networkId)) || !gate.Writes() {
				t.Errorf("%s does not take network %s's writes", service, networkId)
			}
		}
	}
	if !gates.Service(sidecar.ServiceGateEvs).Admits(listed) {
		t.Error("opening the world's networks closed evs to the network the test opened")
	}

	for _, network := range []*sidecartest.AdmissionNet{alpha, bravo} {
		if err := engines.Sync(ctx, network.NetworkId()); err != nil {
			t.Fatal(err)
		}
		owner := network.Owner()
		configRepoId := network.ConfigRepoId()
		configR, configAdmin := enginesTestScope(configRepoId, "r"), enginesTestScope(configRepoId, "admin")
		call := func(audience string, method string, path string, body []byte, scopes ...string) int {
			t.Helper()
			return enginesTwoNetworksCall(t, engines, network, owner, audience, method, path, body, scopes...)
		}

		// evs: the config writer places the network's config repo and reads it back
		repoPath := "/evs/v1/repos/" + sidecar.EvsKeyId(configRepoId)
		if status := call(evsservice.EvsAudience, http.MethodPut, repoPath, nil, configAdmin); status != http.StatusOK {
			t.Errorf("network %s's config repo placement: %d", network.NetworkId(), status)
		}
		if status := call(evsservice.EvsAudience, http.MethodGet, repoPath, nil, configR); status != http.StatusOK {
			t.Errorf("network %s's config repo read: %d", network.NetworkId(), status)
		}

		// gkm: the same sidecar publishes its ReaderKey and reads it back, and reads its config repo's forms, none yet;
		// gkm takes a sidecar's token only with some repo's access in it (§10.6's scopes), so each carries the config's r
		now := net.Clock().Now()
		readerKey, _, err := sidecar.NewGkmReaderKey(owner.SidecarId, now, now.Add(sidecar.GkmReaderKeyLifetime), func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
			return &bridge.Signed{
				Body:      bytes.Clone(body),
				SignerId:  owner.SidecarId.Bytes(),
				Signature: ed25519.Sign(owner.Key, bridge.SignedBytes(purpose, signedType, body)),
				Type:      uint32(signedType),
			}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		readerKeyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(readerKey)
		if err != nil {
			t.Fatal(err)
		}
		if status := call(gkmservice.GkmAudience, http.MethodPost, "/gkm/reader-key", readerKeyBytes, configR); status != http.StatusOK {
			t.Errorf("network %s's ReaderKey upload: %d", network.NetworkId(), status)
		}
		if status := call(gkmservice.GkmAudience, http.MethodGet, "/gkm/reader-key/"+sidecar.EvsKeyId(owner.SidecarId), nil, configR); status != http.StatusOK {
			t.Errorf("network %s's ReaderKey read: %d", network.NetworkId(), status)
		}
		if status := call(gkmservice.GkmAudience, http.MethodGet, "/gkm/repos/"+sidecar.EvsKeyId(configRepoId)+"/forms", nil, configR); status != http.StatusOK {
			t.Errorf("network %s's config forms read: %d", network.NetworkId(), status)
		}
	}
}
