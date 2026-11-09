package sidecar

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// A credential prints as its kind and nothing it holds, and Erase drops the key and zeroes a bundle's seeds.
func TestEnrollCredentialPrintsNothingAndErases(t *testing.T) {
	bundle := testAuthKeyBundle()
	credential := &SidecarEnrollCredential{
		AuthKey:  testAuthKeyBearer(),
		Bundle:   bundle,
		ChildJwt: "synthetic.child.jwt",
	}
	for _, printed := range []string{
		fmt.Sprintf("%v", credential), fmt.Sprintf("%+v", credential), fmt.Sprintf("%#v", credential), credential.String(),
	} {
		if strings.Contains(printed, "ur-authkey-") || strings.Contains(printed, "synthetic.child") {
			t.Errorf("printed %q", printed)
		}
	}
	credential.Erase()
	if credential.AuthKey != "" || credential.ChildJwt != "" {
		t.Error("the key or the child token stayed")
	}
	for _, seed := range [][]byte{bundle.DelegationSigningSeed, bundle.DelegationReaderSeed} {
		for _, b := range seed {
			if b != 0 {
				t.Fatal("a seed was not zeroed")
			}
		}
	}
}

// api's codes name the refusals ur prints, and anything else is a plain refusal; none carries the server's text.
func TestEnrollRefusalsAreTyped(t *testing.T) {
	cases := []struct {
		code   string
		reason string
	}{
		{code: "no_genesis", reason: SidecarEnrollNoGenesis},
		{code: "not_preview", reason: SidecarEnrollPreview},
		{code: "rate_limited", reason: SidecarEnrollRefused},
		{code: "", reason: SidecarEnrollRefused},
	}
	for _, c := range cases {
		apiErr := &SidecarApiError{Route: "POST /network/enroll", Status: http.StatusForbidden, Code: c.code}
		enrollErr := newSidecarEnrollError(apiErr)
		if enrollErr.Reason != c.reason {
			t.Errorf("%q: reason %q, want %q", c.code, enrollErr.Reason, c.reason)
		}
		var unwrapped *SidecarApiError
		if !errors.As(enrollErr, &unwrapped) || unwrapped != apiErr {
			t.Errorf("%q: the api error does not unwrap", c.code)
		}
	}
}

// The token's network and client are read as its claims hold them, and a token missing either names none.
func TestEnrollReadsTheTokensClient(t *testing.T) {
	networkId := NewId()
	clientId := NewId()
	byJwt := testClientJwt(fmt.Sprintf(`{"network_id":%q,"client_id":%q,"device_id":"synthetic"}`, networkId, clientId))
	gotNetworkId, gotClientId, ok := sidecarJwtClient(byJwt)
	if !ok || gotNetworkId != networkId || gotClientId != clientId {
		t.Errorf("read %s %s %v", gotNetworkId, gotClientId, ok)
	}
	for _, claims := range []string{
		fmt.Sprintf(`{"client_id":%q}`, clientId),
		fmt.Sprintf(`{"network_id":%q}`, networkId),
		`{"network_id":"not an id","client_id":"not an id"}`,
	} {
		if _, _, ok := sidecarJwtClient(testClientJwt(claims)); ok {
			t.Errorf("%s named a client", claims)
		}
	}
}
