package smtpproof

import (
	"github.com/consensys/gnark/frontend"
)

// Z1 in the circuit (SPEC.md section 7): from a private secret and the edge's public handshake inputs
// to the keys of the connection. Nothing here leaves the circuit but what it binds.

// The keys a part uses, as wires. In 1.2 the IVs are the 4-octet salts.
type circuitKeys struct {
	clientKey []circuitByte
	clientIv  []circuitByte
	serverKey []circuitByte
	serverIv  []circuitByte
}

func assertBytesEqual(api frontend.API, a []circuitByte, b []circuitByte) {
	for i := range a {
		for bit := range a[i] {
			api.AssertIsEqual(a[i][bit], b[i][bit])
		}
	}
}

// Z1 for TLS 1.3. HS is bound to the disclosed SHTS through H_shts, which fixes it as the MX's by
// collision resistance (SPEC.md 9.2), and everything else follows from HS and the edge's H_sf.
//
// A part that opens no server record leaves the server's keys out: 21 compressions rather than 29.
func tls13CircuitKeys(api frontend.API, handshakeSecret []circuitByte, shtsHash []circuitByte, helloHash []circuitByte, finishedHash []circuitByte, keyBytes int, needServerKeys bool) *circuitKeys {
	secret := newCircuitHmacKey(api, handshakeSecret)
	shts := secret.expandLabel(api, "s hs traffic", helloHash, tlsSecretBytes)
	assertBytesEqual(api, sha256Sum(api, shts), shtsHash)

	derived := secret.expandLabel(api, "derived", bytesConstant(tlsEmptyHash()), tlsSecretBytes)
	master := newCircuitHmacKey(api, newCircuitHmacKey(api, derived).sum(api, bytesConstant(make([]byte, tlsSecretBytes))))

	traffic := func(label string) ([]circuitByte, []circuitByte) {
		secret := newCircuitHmacKey(api, master.expandLabel(api, label, finishedHash, tlsSecretBytes))
		return secret.expandLabel(api, "key", nil, keyBytes), secret.expandLabel(api, "iv", nil, tlsIv13Bytes)
	}
	keys := &circuitKeys{}
	keys.clientKey, keys.clientIv = traffic("c ap traffic")
	if needServerKeys {
		keys.serverKey, keys.serverIv = traffic("s ap traffic")
	}
	return keys
}
