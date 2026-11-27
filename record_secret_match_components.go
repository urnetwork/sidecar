//go:build !ios_extension && !sidecar_http

// The keys Sidecar.SecretMatcher holds of the components the page Worker does not run (I-7, QD-1449), each read from
// this network's keychain.ur (§5.9) by its component's own decoding, and failing closed as the matcher's reads do:
//
//	tls        the device key and its pending successor (tls_key.go, §13.8), P-256: each scalar, its PKCS #8 bytes and
//	           their PEM; and the front's session root (tls_session.go, §7.8), the 32 bytes its cookie keys derive from
//	smtp-dkim  every selector's private key (smtp_dkim_keys.go, §14.6), RSA-2048: its PKCS #8 bytes, as the keychain
//	           keeps them, and their PEM
//
// No public key is held: no device key's SPKI and no published DKIM key. record_secret_match_components_http.go is the
// page Worker's twin. A read never writes: a keychain holding no device key or session root holds none here, where the
// components' own loads would make one.

package sidecar

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// The PEM block type of a PKCS #8 private key (RFC 7468 §10).
const secretMatchPkcs8PemType = "PRIVATE KEY"

var (
	// The front's session root is not its 32 bytes, so no matcher holds what the keychain keeps there.
	errSidecarFrontSessionRootFormat = fmt.Errorf("%w: the front's session root does not decode", ErrSidecarStoreFailed)
	// A DKIM key record is not a PKCS #8 key, so no matcher holds it as the key it is.
	errSidecarDkimKeyFormat = fmt.Errorf("%w: a dkim key does not decode", ErrSidecarStoreFailed)
)

// The tls and smtp-dkim namespaces' keys of the keychain secrets views, each a copy the caller clears, also where the
// error is set (the file header). None where the keychain keeps none; the keychain's own errors as they are;
// errTlsDeviceKeyFormat, errSidecarFrontSessionRootFormat or errSidecarDkimKeyFormat for a record that does not
// decode; and errSidecarKeychainUnreachable where secrets reaches no other namespace.
func loadSidecarComponentKeyCredentials(secrets SidecarSecrets) ([][]byte, error) {
	credentials := [][]byte{}
	tlsSecrets, err := sidecarKeychainNamespace(secrets, tlsSecretsNamespace)
	if err != nil {
		return credentials, err
	}
	keys, err := loadTlsDeviceKeys(tlsSecrets)
	switch {
	case errors.Is(err, ErrSidecarStoreAbsent):
	case err != nil:
		return credentials, err
	default:
		for _, key := range []*TlsDeviceKey{keys.current, keys.pending} {
			if key == nil {
				continue
			}
			held, err := tlsDeviceKeyCredentials(key)
			if err != nil {
				return credentials, err
			}
			credentials = append(credentials, held...)
		}
	}
	root, err := tlsSecrets.Get(tlsFrontSessionRootRecordName)
	switch {
	case errors.Is(err, ErrSidecarStoreAbsent):
	case err != nil:
		return credentials, err
	case len(root) != tlsFrontSessionRootByteCount:
		clear(root)
		return credentials, errSidecarFrontSessionRootFormat
	default:
		testHookSecret("tls_front_session_root", root)
		credentials = append(credentials, root)
	}
	dkimSecrets, err := sidecarKeychainNamespace(secrets, SmtpDkimSecretsNamespace)
	if err != nil {
		return credentials, err
	}
	names, err := dkimSecrets.List(smtpDkimKeyRecordPrefix)
	if err != nil {
		return credentials, err
	}
	for _, name := range names {
		der, err := dkimSecrets.Get(name)
		if errors.Is(err, ErrSidecarStoreAbsent) {
			// purged since the list, so it is kept no longer
			continue
		}
		if err != nil {
			return credentials, err
		}
		testHookSecret("dkim_private_key", der)
		credentials = append(credentials, der)
		if _, err := x509.ParsePKCS8PrivateKey(der); err != nil {
			return credentials, errSidecarDkimKeyFormat
		}
		credentials = append(credentials, pem.EncodeToMemory(&pem.Block{Type: secretMatchPkcs8PemType, Bytes: der}))
	}
	return credentials, nil
}

// A device key's private forms, each a copy the caller clears: its P-256 scalar, as the keychain keeps it, its PKCS #8
// bytes and their PEM. errTlsDeviceKeyFormat for a key that does not encode, which its decoding has already refused.
func tlsDeviceKeyCredentials(key *TlsDeviceKey) ([][]byte, error) {
	scalar, err := key.privateKey.Bytes()
	if err != nil {
		return nil, errTlsDeviceKeyFormat
	}
	der, err := x509.MarshalPKCS8PrivateKey(key.privateKey)
	if err != nil {
		clear(scalar)
		return nil, errTlsDeviceKeyFormat
	}
	return [][]byte{scalar, der, pem.EncodeToMemory(&pem.Block{Type: secretMatchPkcs8PemType, Bytes: der})}, nil
}
