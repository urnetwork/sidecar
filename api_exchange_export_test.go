//go:build !sidecar_http && !js

// The bridge api_exchange_fake_test.go's external tests reach SidecarApi through: its constructor with a token and a
// ClientKey's proof signer installed, as the core installs them. Tests only.

package sidecar

import (
	"crypto/rand"
	"net/http"
	"time"
)

// newSidecarApi on settings and transport, presenting byJwt, with newDpopSigner's signer for the ClientKey whose seed
// is clientKeySeed on now's clock.
func NewSidecarApiWithClientKey(settings *SidecarSettings, transport http.RoundTripper, byJwt string, clientKeySeed []byte, now func() time.Time) (*SidecarApi, error) {
	api, err := newSidecarApi(settings, transport, now)
	if err != nil {
		return nil, err
	}
	signer, err := newDpopSigner(clientKeySeed, now, rand.Reader)
	if err != nil {
		return nil, err
	}
	api.SetByJwt(byJwt)
	api.setDpopSigner(signer)
	return api, nil
}
