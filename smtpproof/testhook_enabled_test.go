//go:build sidecar_testhooks

// The twin of testhook_test.go: under the tag, this package's call sites reach what sidecartest
// installs through the root, so the privacy harness sees every key the TLS client derives.

package smtpproof

import (
	"bytes"
	"crypto/tls"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// Records what the hooks report. Hooks run on the client's goroutine and the server's, so this locks.
type testHookLog struct {
	stateLock   sync.Mutex
	kindSecrets map[string][]byte
	names       []string
}

func testInstallHookLog(t *testing.T) *testHookLog {
	t.Helper()
	log := &testHookLog{kindSecrets: map[string][]byte{}}
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	sidecar.SetTestHooks(&sidecar.TestHooks{
		Secret: func(kind string, secret []byte) {
			log.stateLock.Lock()
			defer log.stateLock.Unlock()
			log.kindSecrets[kind] = secret
		},
		Barrier: func(name string, key string) {
			log.stateLock.Lock()
			defer log.stateLock.Unlock()
			log.names = append(log.names, name)
		},
	})
	return log
}

func TestHooksSeeEveryTls13Secret(t *testing.T) {
	log := testInstallHookLog(t)
	pair := testHandshake(t, &tls.Config{
		Certificates: []tls.Certificate{testEcdsaCertificate(t)},
		MinVersion:   tls.VersionTLS13,
	}, testClientSettings())
	result := pair.result

	for kind, secret := range map[string][]byte{
		"tls13_hs":         result.handshakeSecret,
		"tls13_shts":       result.shts,
		"tls13_ms":         result.masterSecret,
		"tls13_client_key": result.clientKey,
		"tls13_client_iv":  result.clientIv,
		"tls13_server_key": result.serverKey,
		"tls13_server_iv":  result.serverIv,
	} {
		if !bytes.Equal(log.kindSecrets[kind], secret) {
			t.Errorf("%s: hooked %x, want %x", kind, log.kindSecrets[kind], secret)
		}
	}
	for _, kind := range []string{
		"tls_ecdhe_private", "tls_ecdhe_shared", "tls13_chts", "tls13_cats", "tls13_sats",
		"tls13_client_handshake_key", "tls13_client_handshake_iv",
		"tls13_server_handshake_key", "tls13_server_handshake_iv",
	} {
		if len(log.kindSecrets[kind]) == 0 {
			t.Errorf("%s was never hooked", kind)
		}
	}
	for _, name := range []string{"tls.handshake.before", "tls.handshake.after"} {
		if !slices.Contains(log.names, name) {
			t.Errorf("barrier %s never reached", name)
		}
	}
}

func TestHooksSeeEveryTls12Secret(t *testing.T) {
	log := testInstallHookLog(t)
	pair := testHandshake(t, &tls.Config{
		Certificates: []tls.Certificate{testEcdsaCertificate(t)},
		MaxVersion:   tls.VersionTLS12,
	}, testClientSettings())
	result := pair.result

	for kind, secret := range map[string][]byte{
		"tls12_master_secret": result.masterSecret,
		"tls12_client_key":    result.clientKey,
		"tls12_client_salt":   result.clientIv,
		"tls12_server_key":    result.serverKey,
		"tls12_server_salt":   result.serverIv,
	} {
		if !bytes.Equal(log.kindSecrets[kind], secret) {
			t.Errorf("%s: hooked %x, want %x", kind, log.kindSecrets[kind], secret)
		}
	}
}
