//go:build !js

// FuzzAttestationObject (MCP-M3-08): the canonical CBOR reader and the attestation check under arbitrary bytes, seeded
// from testdata/presence/attestation's vectors. Off the js legs, whose Worker has no file system for a seed corpus.

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// Total and memory-bounded: any input gets an answer, never a panic, and what decodes holds no more items than it has
// bytes, so nothing a declared count says is allocated ahead of the bytes that back it. Each input is read as
// KeyRegister.attestation's map (QD-730) and as an attestation object over a fixed client data hash.
func FuzzAttestationObject(f *testing.F) {
	file := &presenceAttestationVectorFile{}
	if err := json.Unmarshal(presenceAttestationVectorsJson, file); err != nil {
		f.Fatal(err)
	}
	settings := testAttestSettings()
	for _, vector := range file.Vectors {
		f.Add([]byte(vector.Attestation))
		if container, err := presenceCborDecodeAll(vector.Attestation, settings.CborMaxDepth); err == nil {
			if attestationObject, ok := container.textKey(presenceAttestationObjectKey); ok {
				f.Add(bytes.Clone(attestationObject.content))
			}
		}
	}
	f.Add([]byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0xbb, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	cas := newTestAttestCas(f)
	roots := cas.roots()
	credential, _ := testAttestCredentials(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		if item, err := presenceCborDecodeAll(input, settings.CborMaxDepth); err == nil && len(input) < item.count() {
			t.Errorf("%d items from %d bytes", item.count(), len(input))
		}
		check := func(label PresenceLabel, err error) {
			if (err == nil) == (label == 0) {
				t.Errorf("label %d with error %v", label, err)
			}
			if err != nil && !errors.Is(err, ErrPresenceAttestation) {
				t.Errorf("an unnamed refusal: %v", err)
			}
		}
		check(verifyPresenceAttestation(input, credential.publicKey, roots, settings, testAttestAt))
		check(verifyPresenceAttestationObject(input, testAttestClientDataHash(), credential.publicKey, roots, settings, testAttestAt))
	})
}
