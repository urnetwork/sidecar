//go:build sidecar_http

// NewSidecar on the sidecar_http leg (§5.4's lifecycle, §5.10's wasm row, §18.10, D-CORE-1, D-SDK-19): the page Worker's
// Sidecar, and an ephemeral quick burner's, on a leg that links no connect package. It has no components and no
// connect client: a client generation here is §6.8's long-poll, which carries `core` (sidecar_generation_http.go), and
// nothing attaches to it. What this leg keeps runs on SidecarApi and the keychain: the identity, the keychain and its
// store states, config verification, the token path (POST /sidecar/bind, GET /auth/refresh with the ClientKey's DPoP
// proof, the token exchange) and D-CORE-8's refresher, which runs because the page Worker's host gives no TokenSource.
//
// The host's Store and KeyStore are the page Worker's: IndexedDB through a SidecarStoreBackend and a non-extractable
// WebCrypto key through SidecarKeyStore, both written by §18's track in sdk/js; a quick burner's instance is on the
// memory backend, so it writes nothing anywhere. Argon2id takes this leg's cost from DefaultSidecarSettings, 19 MiB,
// t=2, p=1 (settings_http.go).
//
// A page Worker is admitted read_only (§18.8's Identity), so once its admission is in the verified state its Sign
// refuses early what verifiers refuse from it (identity_readonly.go).
//
// No file of this leg names a connect type or the root's Subprotocol (§18.10's excluded row), which make check's
// sidecar_http leg holds.

package sidecar

import (
	"context"
	"fmt"
	"net/http"
)

// A running page-Worker Sidecar on settings (D-CORE-2: there is no Start), declared without components, since none
// attaches on this leg (§5.4, §18.10). host.Store() must be a SidecarInstance's, and host.TokenSource() nil, since the
// core's own refresher keeps the token here (§18.10's leg row). The Sidecar starts Locked and leaves Locked once the
// instance opens. Close or CloseAndWait ends it; the instance stays the host's.
func NewSidecar(ctx context.Context, host SidecarHost, settings *SidecarSettings) (*Sidecar, error) {
	// validated here too, so no empty url reaches the page Worker's fetch whatever the inner call becomes
	if err := settings.validate(); err != nil {
		return nil, err
	}
	return newHttpSidecar(ctx, host, settings, nil)
}

// NewSidecar on transport, nil being this leg's fetch: a test's stands in for api. settings are validated again.
func newHttpSidecar(ctx context.Context, host SidecarHost, settings *SidecarSettings, transport http.RoundTripper) (*Sidecar, error) {
	if err := settings.validate(); err != nil {
		return nil, err
	}
	if host == nil {
		return nil, fmt.Errorf("%w: no host", errInvalidSettings)
	}
	if host.TokenSource() != nil {
		return nil, fmt.Errorf("%w: the sidecar_http leg refreshes its own token, with no host TokenSource", errInvalidSettings)
	}
	instance, networkId, ok := sidecarInstanceOfStore(host.Store())
	if !ok {
		return nil, fmt.Errorf("%w: the host's store is not a SidecarInstance's", errInvalidSettings)
	}
	self := newSidecarBase(host, settings)
	sidecarApi, err := newSidecarApi(settings, transport, self.clock.Now)
	if err != nil {
		return nil, err
	}
	self.sidecarApi = sidecarApi
	cancelCtx, cancel := context.WithCancel(ctx)
	self.start(cancelCtx, cancel, instance, networkId, &sidecarHttpLeg{sidecar: self})
	return self, nil
}
