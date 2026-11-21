//go:build !sidecar_http && !ios_extension && !js

package sidecar

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// A bare address takes its label from the authenticated API of the attached
// network. A reply for another network cannot seed the component's stream targets.
func TestHostedSocketLabelsAreBoundToTheEnrolledNetwork(t *testing.T) {
	signer := newTestSocketSigner("hosted-label")
	component, err := NewSocketComponent(t.Context(), &SocketComponentArgs{
		NetworkId: testRegistrarNetworkId, Settings: DefaultSidecarSocketSettings(),
		Sign: signer.sign, Clock: newTestSocketClock(), Log: NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer component.Close()
	component.host = &Sidecar{}
	answer := SidecarLabel{NetworkId: testSocketId("another enrolled network"), Label: "abcdefghij"}
	transport := &scriptedApiTransport{answer: func(r *http.Request, _ []byte) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Path != "/sidecar/label" || r.Header.Get("Authorization") == "" {
			t.Error("expected an authenticated request for the current network label")
		}
		body, err := json.Marshal(answer)
		return syntheticResponse(r, http.StatusOK, string(body), nil), err
	}}
	api := newTestSidecarApi(t, transport)
	identity := &SidecarIdentity{NetworkId: testRegistrarNetworkId, IdentityPublicKey: signer.publicKey()}
	if err := component.Attach(&SidecarEnv{Ctx: t.Context(), SidecarApi: api, Identity: identity}); err != nil {
		t.Fatal(err)
	}
	if err := component.prepareSocketNetwork(t.Context(), ""); !errors.Is(err, ErrSocketUnavailable) {
		t.Fatalf("another network's label: %v", err)
	}
	if _, _, labels := component.current(); labels != nil {
		t.Fatal("another network installed a socket label")
	}
	answer.NetworkId = testRegistrarNetworkId
	for range 2 {
		if err := component.prepareSocketNetwork(t.Context(), ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, labels := component.current(); labels == nil || labels.Label != answer.Label || transport.requestCount() != 2 {
		t.Fatal("the immutable label from this network was not reused")
	}
}
