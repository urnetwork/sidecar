//go:build !ios_extension && !sidecar_http

// Sidecar.SecretMatcher's components' keys (QD-1449; record_secret_match_components.go), each made by its own
// component: the tls device key and its pending successor, each as its scalar, PKCS #8 bytes and PEM, the front's session
// root, and a DKIM key as its PKCS #8 bytes and PEM, matched in every encoding; no public key matches; a keychain keeping
// none holds none and gets none made; and a record that does not decode, a read the keychain fails or a view reaching no
// other namespace fails the read. record_secret_match_sidecar_test.go holds a sidecar's own matcher of them.

package sidecar

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

// The components' keys a network's keychain keeps, each made as its component makes it, by name: what is secret of
// them in each form a matcher holds, and what is public.
type testSecretMatchComponentKeys struct {
	secretForms map[string][]byte
	publicForms map[string][]byte
	// the DKIM key's record name in its namespace
	dkimKeyRecordName string
}

// Makes the tls component's device key, its pending successor and the front's session root, and smtp's DKIM key for a
// network domain, in networkId's keychain in instance, each by its component's own calls.
func newTestSecretMatchComponentKeys(t *testing.T, instance *SidecarInstance, networkId Id) *testSecretMatchComponentKeys {
	t.Helper()
	keys := &testSecretMatchComponentKeys{secretForms: map[string][]byte{}, publicForms: map[string][]byte{}}
	tlsSecrets := instance.secrets(networkId, tlsSecretsNamespace)
	now := time.Date(2026, time.November, 27, 10, 0, 0, 0, time.UTC)
	if _, err := loadOrCreateTlsDeviceKeys(tlsSecrets, now); err != nil {
		t.Fatal(err)
	}
	deviceKeys, err := rotateTlsDeviceKey(tlsSecrets, now, TlsKeyRotationScheduled)
	if err != nil || deviceKeys.pending == nil {
		t.Fatalf("no pending successor: %v", err)
	}
	for name, key := range map[string]*TlsDeviceKey{"the device key": deviceKeys.current, "its pending successor": deviceKeys.pending} {
		scalar, err := key.privateKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key.privateKey)
		if err != nil {
			t.Fatal(err)
		}
		keys.secretForms[name+"'s scalar"] = scalar
		keys.secretForms[name+"'s pkcs8"] = der
		keys.secretForms[name+"'s pem"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		keys.publicForms[name+"'s spki"] = key.Spki()
	}
	root, err := loadOrCreateTlsFrontSessionRoot(tlsSecrets)
	if err != nil {
		t.Fatal(err)
	}
	keys.secretForms["the front's session root"] = root

	dkimSecrets := instance.secrets(networkId, SmtpDkimSecretsNamespace)
	dkim := NewSmtpDkimKeys(dkimSecrets, &smtpDkimTestPublisher{}, DefaultSmtpSenderSettings(), newSmtpDkimTestClock(), nil)
	selector, err := dkim.Current(context.Background(), testDkimNetworkDomain)
	if err != nil {
		t.Fatal(err)
	}
	defer selector.Release()
	keys.dkimKeyRecordName = smtpDkimKeyRecordName(selector.Selector)
	der, err := dkimSecrets.Get(keys.dkimKeyRecordName)
	if err != nil {
		t.Fatal(err)
	}
	keys.secretForms["the dkim key's pkcs8"] = der
	keys.secretForms["the dkim key's pem"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	keys.publicForms["the dkim key as published"] = selector.PublicKey
	return keys
}

// Every key the tls and smtp components keep is held, in every form a leak would take: the device key and its pending
// successor as scalar, PKCS #8 bytes and PEM, the front's session root, and the DKIM key as its PKCS #8 bytes and PEM;
// no public key matches; and a keychain keeping none of them holds none, the read making nothing in their place.
func TestComponentKeyCredentialsHoldTlsAndDkimKeys(t *testing.T) {
	networkId := NewId()
	instance, secrets := newIdentityTestSecrets(t, networkId)
	if credentials, err := loadSidecarComponentKeyCredentials(secrets); err != nil || len(credentials) != 0 {
		t.Fatalf("a keychain keeping no component's key listed %d credentials, %v", len(credentials), err)
	}
	tlsSecrets := instance.secrets(networkId, tlsSecretsNamespace)
	for _, name := range []string{tlsDeviceKeyRecordName, tlsFrontSessionRootRecordName} {
		if _, err := tlsSecrets.Get(name); !errors.Is(err, ErrSidecarStoreAbsent) {
			t.Errorf("the read left %s in the keychain: %v", name, err)
		}
	}

	keys := newTestSecretMatchComponentKeys(t, instance, networkId)
	credentials, err := loadSidecarComponentKeyCredentials(secrets)
	if err != nil {
		t.Fatal(err)
	}
	matcher := NewSecretMatcher(credentials, nil)
	for name, secret := range keys.secretForms {
		testSecretMatchCaught(t, matcher, name, secret)
	}
	for name, public := range keys.publicForms {
		testSecretMatchNotCaught(t, matcher, name, public)
	}
}

// A component's key the keychain keeps but cannot give fails the read, so no matcher is built without it: a read the
// keychain fails, of the device key, the session root, the DKIM keys' list or a DKIM key, is its error as it is; a view
// reaching no other namespace is errSidecarKeychainUnreachable; and a record that does not decode is its component's
// format error, repeating none of the record.
func TestComponentKeyCredentialsFailClosed(t *testing.T) {
	networkId := NewId()
	instance, secrets := newIdentityTestSecrets(t, networkId)
	keys := newTestSecretMatchComponentKeys(t, instance, networkId)
	tlsSecrets := instance.secrets(networkId, tlsSecretsNamespace)
	dkimSecrets := instance.secrets(networkId, SmtpDkimSecretsNamespace)

	for _, c := range []struct {
		name     string
		failName string
		failList bool
	}{
		{name: "the device key's read", failName: tlsDeviceKeyRecordName},
		{name: "the session root's read", failName: tlsFrontSessionRootRecordName},
		{name: "the dkim keys' list", failList: true},
		{name: "a dkim key's read", failName: keys.dkimKeyRecordName},
	} {
		failing := &testSecretMatchFailingSecrets{SidecarSecrets: secrets, failName: c.failName, failList: c.failList, err: errTestSecretMatchReadFailure}
		if _, err := loadSidecarComponentKeyCredentials(failing); !errors.Is(err, errTestSecretMatchReadFailure) {
			t.Errorf("%s failing: %v", c.name, err)
		}
	}
	if _, err := loadSidecarComponentKeyCredentials(&testSecretMatchOneNamespace{SidecarSecrets: secrets}); !errors.Is(err, errSidecarKeychainUnreachable) {
		t.Errorf("a view reaching no other namespace: %v", err)
	}

	damaged := []byte("synthetic damage, no key record of a component's")
	for _, c := range []struct {
		name    string
		secrets SidecarSecrets
		record  string
		err     error
	}{
		{name: "the device key", secrets: tlsSecrets, record: tlsDeviceKeyRecordName, err: errTlsDeviceKeyFormat},
		{name: "the session root", secrets: tlsSecrets, record: tlsFrontSessionRootRecordName, err: errSidecarFrontSessionRootFormat},
		{name: "a dkim key", secrets: dkimSecrets, record: keys.dkimKeyRecordName, err: errSidecarDkimKeyFormat},
	} {
		kept, err := c.secrets.Get(c.record)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.secrets.Put(c.record, damaged); err != nil {
			t.Fatal(err)
		}
		_, err = loadSidecarComponentKeyCredentials(secrets)
		if !errors.Is(err, c.err) || !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s that does not decode: %v", c.name, err)
		} else if strings.Contains(err.Error(), string(damaged)) || strings.Contains(err.Error(), hex.EncodeToString(damaged)) {
			t.Errorf("%s: the error repeats the record", c.name)
		}
		if err := c.secrets.Put(c.record, kept); err != nil {
			t.Fatal(err)
		}
	}
}
