//go:build !js && !ios && !android && !sdk_mobile_bind

// QD-924's registering device beside its readers: under the pools a reader labels an attestation presence (attestation
// refused) with, RegisterPresenceKey signs no KeyRegister carrying it, never one labelled asserted in its place, and
// takes the new key off the authenticator, while the statement those pools chain registers labelled attested. The
// pools are the test's and a release's that pins the forging CA as apple's root in their place, so each apple
// statement is refused under one and attested under the other, as the readers of config_keys_test.go label them.

package sidecar

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// RegisterPresenceKey signs nothing for an attestation a reader under its pools labels refused, and registers the one
// they chain, labelled attested as that reader labels it, under the test's pools and under swapped ones.
func TestRegisterPresenceKeySignsNothingAReaderLabelsRefused(t *testing.T) {
	cas := newTestAttestCas(t)
	swapped := cas.rootsPinningAsApple(cas.software)
	for _, c := range []struct {
		name   string
		roots  *presenceAttestationRoots
		issuer *testAttestCa
		want   PresenceLabel
	}{
		{name: "apple's own statement under the test's pools", roots: cas.roots(), want: PresenceLabelAttested},
		{name: "a forged apple statement under the test's pools", roots: cas.roots(), issuer: cas.software, want: PresenceLabelRefused},
		{name: "apple's own statement under pools pinning the forging CA", roots: swapped, want: PresenceLabelRefused},
		{name: "a forged apple statement under pools pinning the forging CA", roots: swapped, issuer: cas.software, want: PresenceLabelAttested},
	} {
		world := newTestPresenceWorld(t, bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
		var made *protocol.KeyRegister
		world.provider.attest = func(key *testPresenceKey) []byte {
			attestation := newTestAttestation(cas, key)
			attestation.issuer = c.issuer
			made = &protocol.KeyRegister{
				KeyId:       bytes.Clone(key.keyId),
				Alg:         key.alg,
				PublicKey:   bytes.Clone(key.publicKey),
				Attestation: attestation.attestation(t, "apple"),
				Purpose:     bridge.KeyPurpose_KEY_PURPOSE_PRESENCE,
			}
			return bytes.Clone(made.GetAttestation())
		}
		testAttestRootsAsRelease(t, c.roots)
		key, err := world.sidecar.RegisterPresenceKey(t.Context(), world.provider, SidecarActConfirmed, nil)
		if made == nil {
			t.Fatalf("%s: the authenticator made no key", c.name)
		}
		// what a reader under the same pools shows of the statement the authenticator gave
		if shown := PresenceKeyLabel(made, world.sidecar.clock.Now().UnixMilli()); shown != c.want {
			t.Errorf("%s: a reader shows %s; want %s", c.name, shown, c.want)
		}
		posted := postedStatements(t, world.sidecar)
		if c.want == PresenceLabelRefused {
			if !errors.Is(err, ErrPresenceKeyInvalid) || !errors.Is(err, ErrPresenceAttestation) || key != nil {
				t.Errorf("%s: %+v, %v", c.name, key, err)
			}
			if len(posted) != 0 || len(world.provider.removed) != 1 {
				t.Errorf("%s: posted %d, removed %d", c.name, len(posted), len(world.provider.removed))
			}
			continue
		}
		if err != nil || key == nil || key.Label != c.want || len(posted) != 1 || len(world.provider.removed) != 0 {
			t.Errorf("%s: %+v, %v, posted %d, removed %d", c.name, key, err, len(posted), len(world.provider.removed))
		}
	}
}
