//go:build darwin && !ios && !sdk_mobile_bind

// The macOS store (§5.9, D-CORE-12): U's wrap in the data protection keychain, AfterFirstUnlockThisDeviceOnly, in the
// access group a signed ur bundle's entitlements name, reached through purego with CGO_ENABLED=0. Security.framework
// and CoreFoundation are loaded once, by path, and every call holds the CF objects it makes only for the call.
//
// An unsigned binary gets errSecMissingEntitlement on this keychain, which maps to Failed; the signed bundle's run is
// the one that stores anything (§4.17).

package main

import (
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"

	"github.com/urnetwork/sidecar"
)

// The frameworks' paths, fixed by the system.
const (
	darwinSecurityPath       = "/System/Library/Frameworks/Security.framework/Security"
	darwinCoreFoundationPath = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
	// kCFStringEncodingUTF8
	darwinCfStringEncodingUtf8 = 0x08000100
	// The items' service: one per tool, so no other program's items are touched.
	darwinKeychainService = "network.ur.cli"
)

// Security.framework's and CoreFoundation's functions and constants, loaded once.
type darwinSecurity struct {
	secItemCopyMatching     func(query uintptr, result *uintptr) int32
	secItemAdd              func(attributes uintptr, result uintptr) int32
	secItemUpdate           func(query uintptr, attributesToUpdate uintptr) int32
	secItemDelete           func(query uintptr) int32
	cfDictionaryCreate      func(allocator uintptr, keys *uintptr, values *uintptr, count int64, keyCallBacks uintptr, valueCallBacks uintptr) uintptr
	cfStringCreateWithBytes func(allocator uintptr, bytes *byte, byteCount int64, encoding uint32, isExternal bool) uintptr
	cfDataCreate            func(allocator uintptr, bytes *byte, length int64) uintptr
	cfDataGetBytePtr        func(data uintptr) uintptr
	cfDataGetLength         func(data uintptr) int64
	cfRelease               func(cf uintptr)

	kSecClass                                        uintptr
	kSecClassGenericPassword                         uintptr
	kSecAttrService                                  uintptr
	kSecAttrAccount                                  uintptr
	kSecAttrAccessible                               uintptr
	kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly uintptr
	kSecAttrAccessGroup                              uintptr
	kSecUseDataProtectionKeychain                    uintptr
	kSecValueData                                    uintptr
	kSecReturnData                                   uintptr
	kSecMatchLimit                                   uintptr
	kSecMatchLimitOne                                uintptr
	kCFBooleanTrue                                   uintptr
	// addresses of the callback structs, passed as they are
	kCFTypeDictionaryKeyCallBacks   uintptr
	kCFTypeDictionaryValueCallBacks uintptr
}

var loadDarwinSecurity = sync.OnceValues(func() (*darwinSecurity, error) {
	security, err := purego.Dlopen(darwinSecurityPath, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, err
	}
	coreFoundation, err := purego.Dlopen(darwinCoreFoundationPath, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, err
	}
	self := &darwinSecurity{}
	purego.RegisterLibFunc(&self.secItemCopyMatching, security, "SecItemCopyMatching")
	purego.RegisterLibFunc(&self.secItemAdd, security, "SecItemAdd")
	purego.RegisterLibFunc(&self.secItemUpdate, security, "SecItemUpdate")
	purego.RegisterLibFunc(&self.secItemDelete, security, "SecItemDelete")
	purego.RegisterLibFunc(&self.cfDictionaryCreate, coreFoundation, "CFDictionaryCreate")
	purego.RegisterLibFunc(&self.cfStringCreateWithBytes, coreFoundation, "CFStringCreateWithBytes")
	purego.RegisterLibFunc(&self.cfDataCreate, coreFoundation, "CFDataCreate")
	purego.RegisterLibFunc(&self.cfDataGetBytePtr, coreFoundation, "CFDataGetBytePtr")
	purego.RegisterLibFunc(&self.cfDataGetLength, coreFoundation, "CFDataGetLength")
	purego.RegisterLibFunc(&self.cfRelease, coreFoundation, "CFRelease")
	// a constant is a global holding a CF reference: its symbol is the global's address
	value := func(handle uintptr, name string, target *uintptr) error {
		address, err := purego.Dlsym(handle, name)
		if err != nil {
			return err
		}
		*target = *(*uintptr)(*(*unsafe.Pointer)(unsafe.Pointer(&address)))
		return nil
	}
	address := func(handle uintptr, name string, target *uintptr) error {
		found, err := purego.Dlsym(handle, name)
		*target = found
		return err
	}
	for _, constant := range []struct {
		handle uintptr
		name   string
		target *uintptr
	}{
		{security, "kSecClass", &self.kSecClass},
		{security, "kSecClassGenericPassword", &self.kSecClassGenericPassword},
		{security, "kSecAttrService", &self.kSecAttrService},
		{security, "kSecAttrAccount", &self.kSecAttrAccount},
		{security, "kSecAttrAccessible", &self.kSecAttrAccessible},
		{security, "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly", &self.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly},
		{security, "kSecAttrAccessGroup", &self.kSecAttrAccessGroup},
		{security, "kSecUseDataProtectionKeychain", &self.kSecUseDataProtectionKeychain},
		{security, "kSecValueData", &self.kSecValueData},
		{security, "kSecReturnData", &self.kSecReturnData},
		{security, "kSecMatchLimit", &self.kSecMatchLimit},
		{security, "kSecMatchLimitOne", &self.kSecMatchLimitOne},
		{coreFoundation, "kCFBooleanTrue", &self.kCFBooleanTrue},
	} {
		if err := value(constant.handle, constant.name, constant.target); err != nil {
			return nil, err
		}
	}
	if err := address(coreFoundation, "kCFTypeDictionaryKeyCallBacks", &self.kCFTypeDictionaryKeyCallBacks); err != nil {
		return nil, err
	}
	if err := address(coreFoundation, "kCFTypeDictionaryValueCallBacks", &self.kCFTypeDictionaryValueCallBacks); err != nil {
		return nil, err
	}
	return self, nil
})

// The keychain calls through purego.
type darwinPuregoKeychain struct {
	security    *darwinSecurity
	accessGroup string
}

// A CFString of value, which the caller releases.
func (self *darwinPuregoKeychain) cfString(value string) uintptr {
	bytes := []byte(value)
	var first *byte
	if 0 < len(bytes) {
		first = &bytes[0]
	}
	reference := self.security.cfStringCreateWithBytes(0, first, int64(len(bytes)), darwinCfStringEncodingUtf8, false)
	runtime.KeepAlive(bytes)
	return reference
}

// A CFData of value, which the caller releases.
func (self *darwinPuregoKeychain) cfData(value []byte) uintptr {
	var first *byte
	if 0 < len(value) {
		first = &value[0]
	}
	reference := self.security.cfDataCreate(0, first, int64(len(value)))
	runtime.KeepAlive(value)
	return reference
}

// A CFDictionary of the pairs, which the caller releases.
func (self *darwinPuregoKeychain) cfDictionary(keys []uintptr, values []uintptr) uintptr {
	reference := self.security.cfDictionaryCreate(0, &keys[0], &values[0], int64(len(keys)),
		self.security.kCFTypeDictionaryKeyCallBacks, self.security.kCFTypeDictionaryValueCallBacks)
	runtime.KeepAlive(keys)
	runtime.KeepAlive(values)
	return reference
}

// The item's query, and the CF objects to release after it: class, service, account, the data protection keychain,
// and the access group when one is set, then extra pairs.
func (self *darwinPuregoKeychain) query(account string, extraKeys []uintptr, extraValues []uintptr) (uintptr, []uintptr) {
	security := self.security
	service := self.cfString(darwinKeychainService)
	accountString := self.cfString(account)
	release := []uintptr{service, accountString}
	keys := []uintptr{security.kSecClass, security.kSecAttrService, security.kSecAttrAccount, security.kSecUseDataProtectionKeychain}
	values := []uintptr{security.kSecClassGenericPassword, service, accountString, security.kCFBooleanTrue}
	if self.accessGroup != "" {
		group := self.cfString(self.accessGroup)
		release = append(release, group)
		keys = append(keys, security.kSecAttrAccessGroup)
		values = append(values, group)
	}
	keys = append(keys, extraKeys...)
	values = append(values, extraValues...)
	dictionary := self.cfDictionary(keys, values)
	return dictionary, append(release, dictionary)
}

// Releases every reference.
func (self *darwinPuregoKeychain) release(references []uintptr) {
	for _, reference := range references {
		if reference != 0 {
			self.security.cfRelease(reference)
		}
	}
}

// SecItemCopyMatching for the item's data. See darwinKeychainCalls.
func (self *darwinPuregoKeychain) copyData(account string) ([]byte, int32) {
	security := self.security
	query, release := self.query(account, []uintptr{security.kSecReturnData, security.kSecMatchLimit},
		[]uintptr{security.kCFBooleanTrue, security.kSecMatchLimitOne})
	defer self.release(release)
	var result uintptr
	status := security.secItemCopyMatching(query, &result)
	if status != errSecSuccess || result == 0 {
		if status == errSecSuccess {
			status = errSecItemNotFound
		}
		return nil, status
	}
	defer security.cfRelease(result)
	length := security.cfDataGetLength(result)
	pointer := security.cfDataGetBytePtr(result)
	if length <= 0 || pointer == 0 {
		return []byte{}, status
	}
	value := make([]byte, length)
	copy(value, unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&pointer))), length))
	return value, status
}

// SecItemAdd. See darwinKeychainCalls.
func (self *darwinPuregoKeychain) add(account string, value []byte) int32 {
	security := self.security
	data := self.cfData(value)
	query, release := self.query(account, []uintptr{security.kSecValueData, security.kSecAttrAccessible},
		[]uintptr{data, security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly})
	defer self.release(append(release, data))
	return security.secItemAdd(query, 0)
}

// SecItemUpdate of the item's data. See darwinKeychainCalls.
func (self *darwinPuregoKeychain) update(account string, value []byte) int32 {
	security := self.security
	query, release := self.query(account, nil, nil)
	data := self.cfData(value)
	attributes := self.cfDictionary([]uintptr{security.kSecValueData}, []uintptr{data})
	defer self.release(append(release, data, attributes))
	return security.secItemUpdate(query, attributes)
}

// SecItemDelete. See darwinKeychainCalls.
func (self *darwinPuregoKeychain) remove(account string) int32 {
	query, release := self.query(account, nil, nil)
	defer self.release(release)
	return self.security.secItemDelete(query)
}

// The data protection keychain (§5.9's macOS row). A system whose frameworks do not load has no store, and U is
// wrapped by the pass alone.
func newOsKeyStore(args *osKeyStoreArgs) (sidecar.SidecarKeyStore, osKeyStoreKind, error) {
	security, err := loadDarwinSecurity()
	if err != nil {
		return nil, osKeyStorePass, err
	}
	return &darwinKeychainStore{calls: &darwinPuregoKeychain{security: security, accessGroup: args.AccessGroup}}, osKeyStoreKeychain, nil
}
