//go:build sidecar_testhooks && !sidecar_http

package sidecar

import (
	"bytes"
	"testing"
)

// Every device key reaches the privacy harness where it is made and each time it is read back from the keychain,
// as its scalar, which is what a leak of it would carry, and the record's write sits between barriers.
func TestTlsDeviceKeyReachesTheSecretHook(t *testing.T) {
	recorder := recordHooks(t)
	clock := newTlsTestClock()
	sidecar, _ := newTlsTestSidecar(t, clock)

	if _, err := sidecar.TlsDeviceCertificate([]string{"mount.example"}); err != nil {
		t.Fatal(err)
	}
	state, secrets, err := sidecar.tlsDevice()
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := state.rotate(secrets, clock.Now(), TlsKeyRotationSuspicion)
	if err != nil {
		t.Fatal(err)
	}

	recorder.stateLock.Lock()
	defer recorder.stateLock.Unlock()
	if !recorder.kinds["tls_device_key"] {
		t.Fatal("no device key reached the hook")
	}
	for _, key := range []*TlsDeviceKey{rotated.current, rotated.pending} {
		scalar := tlsTestScalar(t, key)
		seen := 0
		for _, secret := range recorder.secrets {
			if bytes.Equal(secret, scalar) {
				seen += 1
			}
		}
		// the first key: made, read by the certificate call's second read and by the rotation's; the successor: made
		if seen == 0 {
			t.Error("a device key never reached the hook")
		}
	}
	firstSeen := 0
	firstScalar := tlsTestScalar(t, rotated.current)
	for _, secret := range recorder.secrets {
		if bytes.Equal(secret, firstScalar) {
			firstSeen += 1
		}
	}
	if firstSeen < 2 {
		t.Errorf("the first key reached the hook %d times; made and read back is at least 2", firstSeen)
	}
	for _, barrier := range []string{"tls.device_key_put.before", "tls.device_key_put.after"} {
		if !recorder.barriers[barrier] {
			t.Errorf("no %s", barrier)
		}
	}
}
