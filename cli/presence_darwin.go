//go:build darwin && !ios && !sdk_mobile_bind

// The macOS ur bundle's Secure Enclave presence key as ur daemon's presence provider (MCP-M3-09; §16.6's
// ecdsa-p256-sha256 profile, D-CORE-12): a P-256 key made inside the Secure Enclave, permanent, with access control
// kSecAccessControlUserPresence and private key usage, so every signature asks for Touch ID, a paired watch or the
// login password; each assertion looks the key up through a fresh LAContext, whose reuse duration is 0 from its init,
// so no act reuses another's authentication (§16.6's countersign row), and a context that ends invalidates it. Reached
// through purego with CGO_ENABLED=0, as keychain_darwin.go reaches the keychain.
//
// key_id is 16 random bytes drawn before the key is made, its application tag network.ur.cli.presence.<key_id hex>,
// so Holds and Assert find it by its id alone. The signature is X9.62's DER over SHA-256 of the message, as the
// profile's per use and countersign rows take it. No attestation exists for a Secure Enclave key's access control on
// an unmanaged Mac, so it labels asserted (§16.6).
//
// An unsigned binary gets errSecMissingEntitlement making or finding a key, so only the signed bundle holds one
// (§4.17): every failure refuses, signing nothing.

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The Secure Enclave key's identifiers: the framework that holds LAContext, its tag's prefix, and Security's
// access-control flags and CFNumber's type for the key size.
const (
	darwinLocalAuthenticationPath             = "/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication"
	darwinPresenceTagPrefix                   = "network.ur.cli.presence."
	darwinAccessControlUserPresence    uint64 = 1 << 0
	darwinAccessControlPrivateKeyUsage uint64 = 1 << 30
	darwinCfNumberSInt32Type           int64  = 3
	darwinSecureEnclaveKeyBits         int32  = 256
)

// What the Secure Enclave key needs beyond keychain_darwin.go's: the key calls and their constants.
type darwinPresenceSecurity struct {
	keychain *darwinPuregoKeychain

	secAccessControlCreateWithFlags  func(allocator uintptr, protection uintptr, flags uint64, error *uintptr) uintptr
	secKeyCreateRandomKey            func(parameters uintptr, error *uintptr) uintptr
	secKeyCopyPublicKey              func(key uintptr) uintptr
	secKeyCopyExternalRepresentation func(key uintptr, error *uintptr) uintptr
	secKeyCreateSignature            func(key uintptr, algorithm uintptr, data uintptr, error *uintptr) uintptr
	cfNumberCreate                   func(allocator uintptr, numberType int64, value unsafe.Pointer) uintptr
	cfErrorGetCode                   func(err uintptr) int64

	kSecClassKey                                    uintptr
	kSecAttrKeyClass                                uintptr
	kSecAttrKeyClassPrivate                         uintptr
	kSecAttrKeyType                                 uintptr
	kSecAttrKeyTypeECSECPrimeRandom                 uintptr
	kSecAttrKeySizeInBits                           uintptr
	kSecAttrTokenID                                 uintptr
	kSecAttrTokenIDSecureEnclave                    uintptr
	kSecPrivateKeyAttrs                             uintptr
	kSecAttrIsPermanent                             uintptr
	kSecAttrApplicationTag                          uintptr
	kSecAttrAccessControl                           uintptr
	kSecAttrAccessibleWhenUnlockedThisDeviceOnly    uintptr
	kSecReturnRef                                   uintptr
	kSecUseAuthenticationContext                    uintptr
	kSecKeyAlgorithmECDSASignatureMessageX962SHA256 uintptr
}

var loadDarwinPresenceSecurity = sync.OnceValues(func() (*darwinPresenceSecurity, error) {
	security, err := loadDarwinSecurity()
	if err != nil {
		return nil, err
	}
	securityHandle, err := purego.Dlopen(darwinSecurityPath, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, err
	}
	coreFoundation, err := purego.Dlopen(darwinCoreFoundationPath, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, err
	}
	// LAContext's class registers with the runtime once its framework loads
	if _, err := purego.Dlopen(darwinLocalAuthenticationPath, purego.RTLD_LAZY|purego.RTLD_GLOBAL); err != nil {
		return nil, err
	}
	self := &darwinPresenceSecurity{keychain: &darwinPuregoKeychain{security: security}}
	purego.RegisterLibFunc(&self.secAccessControlCreateWithFlags, securityHandle, "SecAccessControlCreateWithFlags")
	purego.RegisterLibFunc(&self.secKeyCreateRandomKey, securityHandle, "SecKeyCreateRandomKey")
	purego.RegisterLibFunc(&self.secKeyCopyPublicKey, securityHandle, "SecKeyCopyPublicKey")
	purego.RegisterLibFunc(&self.secKeyCopyExternalRepresentation, securityHandle, "SecKeyCopyExternalRepresentation")
	purego.RegisterLibFunc(&self.secKeyCreateSignature, securityHandle, "SecKeyCreateSignature")
	purego.RegisterLibFunc(&self.cfNumberCreate, coreFoundation, "CFNumberCreate")
	purego.RegisterLibFunc(&self.cfErrorGetCode, coreFoundation, "CFErrorGetCode")
	for _, constant := range []struct {
		name   string
		target *uintptr
	}{
		{"kSecClassKey", &self.kSecClassKey},
		{"kSecAttrKeyClass", &self.kSecAttrKeyClass},
		{"kSecAttrKeyClassPrivate", &self.kSecAttrKeyClassPrivate},
		{"kSecAttrKeyType", &self.kSecAttrKeyType},
		{"kSecAttrKeyTypeECSECPrimeRandom", &self.kSecAttrKeyTypeECSECPrimeRandom},
		{"kSecAttrKeySizeInBits", &self.kSecAttrKeySizeInBits},
		{"kSecAttrTokenID", &self.kSecAttrTokenID},
		{"kSecAttrTokenIDSecureEnclave", &self.kSecAttrTokenIDSecureEnclave},
		{"kSecPrivateKeyAttrs", &self.kSecPrivateKeyAttrs},
		{"kSecAttrIsPermanent", &self.kSecAttrIsPermanent},
		{"kSecAttrApplicationTag", &self.kSecAttrApplicationTag},
		{"kSecAttrAccessControl", &self.kSecAttrAccessControl},
		{"kSecAttrAccessibleWhenUnlockedThisDeviceOnly", &self.kSecAttrAccessibleWhenUnlockedThisDeviceOnly},
		{"kSecReturnRef", &self.kSecReturnRef},
		{"kSecUseAuthenticationContext", &self.kSecUseAuthenticationContext},
		{"kSecKeyAlgorithmECDSASignatureMessageX962SHA256", &self.kSecKeyAlgorithmECDSASignatureMessageX962SHA256},
	} {
		address, err := purego.Dlsym(securityHandle, constant.name)
		if err != nil {
			return nil, err
		}
		*constant.target = *(*uintptr)(*(*unsafe.Pointer)(unsafe.Pointer(&address)))
	}
	return self, nil
})

// The Secure Enclave provider.
type darwinSecureEnclaveProvider struct {
	security    *darwinPresenceSecurity
	accessGroup string
	random      io.Reader
	log         sidecar.Logger
}

var _ sidecar.PresenceProvider = (*darwinSecureEnclaveProvider)(nil)

// The Secure Enclave provider, nil where Security or LocalAuthentication does not load.
func urPlatformPresenceProvider(stateDirectory string, ingest *sidecar.SidecarIngestSettings, log sidecar.Logger) sidecar.PresenceProvider {
	security, err := loadDarwinPresenceSecurity()
	if err != nil {
		log.Warningf("[presence]no Secure Enclave key: %s", err)
		return nil
	}
	return &darwinSecureEnclaveProvider{security: security, random: rand.Reader, log: log}
}

// The tag a key of keyId carries, as CFData, which the caller releases.
func (self *darwinSecureEnclaveProvider) tag(keyId []byte) uintptr {
	return self.security.keychain.cfData([]byte(darwinPresenceTagPrefix + hex.EncodeToString(keyId)))
}

// A CFError's code, the error released; 0 for none.
func (self *darwinSecureEnclaveProvider) errorCode(cfError uintptr) int64 {
	if cfError == 0 {
		return 0
	}
	defer self.security.keychain.security.cfRelease(cfError)
	return self.security.cfErrorGetCode(cfError)
}

// A CFData's bytes, copied.
func (self *darwinSecureEnclaveProvider) dataBytes(data uintptr) []byte {
	security := self.security.keychain.security
	length := security.cfDataGetLength(data)
	pointer := security.cfDataGetBytePtr(data)
	if length <= 0 || pointer == 0 {
		return []byte{}
	}
	value := make([]byte, length)
	copy(value, unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&pointer))), length))
	return value
}

// The private key's lookup, through laContext where it is not 0, and the CF objects to release after it.
func (self *darwinSecureEnclaveProvider) keyQuery(keyId []byte, laContext uintptr) (uintptr, []uintptr) {
	security := self.security
	keychain := security.keychain
	tag := self.tag(keyId)
	keys := []uintptr{keychain.security.kSecClass, security.kSecAttrKeyClass, security.kSecAttrApplicationTag,
		keychain.security.kSecUseDataProtectionKeychain, security.kSecReturnRef, keychain.security.kSecMatchLimit}
	values := []uintptr{security.kSecClassKey, security.kSecAttrKeyClassPrivate, tag,
		keychain.security.kCFBooleanTrue, keychain.security.kCFBooleanTrue, keychain.security.kSecMatchLimitOne}
	if laContext != 0 {
		keys = append(keys, security.kSecUseAuthenticationContext)
		values = append(values, laContext)
	}
	query := keychain.cfDictionary(keys, values)
	return query, []uintptr{tag, query}
}

// See PresenceProvider: a permanent Secure Enclave key under user presence, its id drawn first.
func (self *darwinSecureEnclaveProvider) Register(ctx context.Context) (*sidecar.PresenceKeyHandle, error) {
	security := self.security
	keychain := security.keychain
	keyId := make([]byte, 16)
	if _, err := io.ReadFull(self.random, keyId); err != nil {
		return nil, err
	}
	var cfError uintptr
	accessControl := security.secAccessControlCreateWithFlags(0, security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
		darwinAccessControlPrivateKeyUsage|darwinAccessControlUserPresence, &cfError)
	if accessControl == 0 {
		return nil, fmt.Errorf("%w: no access control, error %d", sidecar.ErrPresenceUnavailable, self.errorCode(cfError))
	}
	tag := self.tag(keyId)
	keyBits := darwinSecureEnclaveKeyBits
	keySize := security.cfNumberCreate(0, darwinCfNumberSInt32Type, unsafe.Pointer(&keyBits))
	runtime.KeepAlive(&keyBits)
	privateAttributes := keychain.cfDictionary(
		[]uintptr{security.kSecAttrIsPermanent, security.kSecAttrApplicationTag, security.kSecAttrAccessControl},
		[]uintptr{keychain.security.kCFBooleanTrue, tag, accessControl},
	)
	parameters := keychain.cfDictionary(
		[]uintptr{security.kSecAttrKeyType, security.kSecAttrKeySizeInBits, security.kSecAttrTokenID, security.kSecPrivateKeyAttrs,
			keychain.security.kSecUseDataProtectionKeychain},
		[]uintptr{security.kSecAttrKeyTypeECSECPrimeRandom, keySize, security.kSecAttrTokenIDSecureEnclave, privateAttributes,
			keychain.security.kCFBooleanTrue},
	)
	defer keychain.release([]uintptr{accessControl, tag, keySize, privateAttributes, parameters})
	privateKey := security.secKeyCreateRandomKey(parameters, &cfError)
	if privateKey == 0 {
		return nil, fmt.Errorf("%w: the Secure Enclave made no key, error %d", sidecar.ErrPresenceUnavailable, self.errorCode(cfError))
	}
	defer keychain.security.cfRelease(privateKey)
	publicKey := security.secKeyCopyPublicKey(privateKey)
	if publicKey == 0 {
		self.Remove(keyId)
		return nil, fmt.Errorf("%w: no public key", sidecar.ErrPresenceUnavailable)
	}
	defer keychain.security.cfRelease(publicKey)
	external := security.secKeyCopyExternalRepresentation(publicKey, &cfError)
	if external == 0 {
		self.Remove(keyId)
		return nil, fmt.Errorf("%w: no public key's bytes, error %d", sidecar.ErrPresenceUnavailable, self.errorCode(cfError))
	}
	defer keychain.security.cfRelease(external)
	point := self.dataBytes(external)
	if len(point) != 65 || point[0] != 0x04 {
		self.Remove(keyId)
		return nil, fmt.Errorf("%w: a public key of %d bytes", sidecar.ErrPresenceKeyInvalid, len(point))
	}
	return &sidecar.PresenceKeyHandle{KeyId: keyId, Alg: bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256, PublicKey: point}, nil
}

// Whether the key's private half is in the keychain, found without using it.
func (self *darwinSecureEnclaveProvider) Holds(keyId []byte) bool {
	query, release := self.keyQuery(keyId, 0)
	defer self.security.keychain.release(release)
	var result uintptr
	status := self.security.keychain.security.secItemCopyMatching(query, &result)
	if result != 0 {
		self.security.keychain.security.cfRelease(result)
	}
	return status == errSecSuccess
}

// See PresenceProvider: the key found through a fresh LAContext, then X9.62's DER signature over message's SHA-256,
// which asks the person; ctx's end invalidates the context, ending the prompt.
func (self *darwinSecureEnclaveProvider) Assert(ctx context.Context, keyId []byte, message []byte) (*bridge.WebAuthnEvidence, error) {
	security := self.security
	keychain := security.keychain
	laContext := objc.ID(objc.GetClass("LAContext")).Send(objc.RegisterName("new"))
	if laContext == 0 {
		return nil, fmt.Errorf("%w: no LAContext", sidecar.ErrPresenceUnavailable)
	}
	defer laContext.Send(objc.RegisterName("release"))
	reason := keychain.cfString("approve with your presence key")
	defer keychain.security.cfRelease(reason)
	laContext.Send(objc.RegisterName("setLocalizedReason:"), reason)
	invalidated := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		laContext.Send(objc.RegisterName("invalidate"))
		close(invalidated)
	})
	defer func() {
		if !stop() {
			// the invalidation started: wait for it before the context is released
			<-invalidated
		}
	}()

	query, release := self.keyQuery(keyId, uintptr(laContext))
	defer keychain.release(release)
	var privateKey uintptr
	status := keychain.security.secItemCopyMatching(query, &privateKey)
	if status != errSecSuccess || privateKey == 0 {
		if privateKey != 0 {
			keychain.security.cfRelease(privateKey)
		}
		if status == errSecItemNotFound {
			return nil, sidecar.ErrPresenceNoKey
		}
		return nil, fmt.Errorf("%w: the key's lookup answered %d", sidecar.ErrPresenceUnavailable, status)
	}
	defer keychain.security.cfRelease(privateKey)
	data := keychain.cfData(message)
	defer keychain.security.cfRelease(data)
	var cfError uintptr
	signature := security.secKeyCreateSignature(privateKey, security.kSecKeyAlgorithmECDSASignatureMessageX962SHA256, data, &cfError)
	if signature == 0 {
		if err := ctx.Err(); err != nil {
			self.errorCode(cfError)
			return nil, err
		}
		return nil, fmt.Errorf("%w: the person refused or the key failed, error %d", sidecar.ErrSidecarActPresence, self.errorCode(cfError))
	}
	defer keychain.security.cfRelease(signature)
	return &bridge.WebAuthnEvidence{KeyId: append([]byte{}, keyId...), Signature: self.dataBytes(signature)}, nil
}

// Deletes the key from the keychain, which takes it off the Secure Enclave; a key not there is no error.
func (self *darwinSecureEnclaveProvider) Remove(keyId []byte) error {
	security := self.security
	keychain := security.keychain
	tag := self.tag(keyId)
	query := keychain.cfDictionary(
		[]uintptr{keychain.security.kSecClass, security.kSecAttrKeyClass, security.kSecAttrApplicationTag, keychain.security.kSecUseDataProtectionKeychain},
		[]uintptr{security.kSecClassKey, security.kSecAttrKeyClassPrivate, tag, keychain.security.kCFBooleanTrue},
	)
	defer keychain.release([]uintptr{tag, query})
	status := keychain.security.secItemDelete(query)
	if status != errSecSuccess && status != errSecItemNotFound {
		return fmt.Errorf("the Secure Enclave key was not removed: status %d", status)
	}
	return nil
}
