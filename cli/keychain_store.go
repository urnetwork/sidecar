// The OS key stores that wrap U (§5.9's platform table, D-CORE-12, D-CORE-15): the macOS data protection keychain,
// Windows DPAPI, Linux's Secret Service, and on a headless Linux a 0600 key file. They live in cli/, which §4.4 allows
// for the keychain, so purego and a D-Bus client stay out of the root's module graph and out of server's, sn's and
// sdk's. newOsKeyStore picks the platform's in keychain_<os>.go.
//
// Each store maps its platform's answers onto D-CORE-15's statuses here, in code that builds on every GOOS, through an
// interface of the platform's calls, so a fake call table tests every platform's mapping on any host. The rule they
// share: a read answers Present, Absent, Locked or Failed, a write Ok, Locked or Failed, and only a store that is
// working and holds no such item answers Absent. A lock, a missing daemon, a refused entitlement, a loose file mode
// or any error is never folded into Absent, since Absent is the one answer that creates anything (D-CORE-15). No call
// panics across the host boundary (D-SDK-15): a panic in a platform call answers Failed.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/urnetwork/sidecar"
)

// What `ur daemon` opens its key store with.
type osKeyStoreArgs struct {
	// <state>/keystore: the DPAPI blobs on Windows and the key file on a headless Linux.
	Directory string
	// The data protection keychain's access group, <team>.network.ur.cli (§5.9), which a signed ur bundle's
	// entitlements name. Empty: none, as in a development build, where the keychain refuses the item anyway.
	AccessGroup string
	// A headless Linux keeps U in a 0600 key file when no Secret Service answers. False: the pass only (§5.9).
	KeyFileFallback bool
	// Nil: no logging. Never stdout.
	Log sidecar.Logger
}

// Which store wraps U, which `ur status` names, warning for a key file (§5.9).
type osKeyStoreKind string

const (
	osKeyStoreKeychain      osKeyStoreKind = "keychain"
	osKeyStoreDpapi         osKeyStoreKind = "dpapi"
	osKeyStoreSecretService osKeyStoreKind = "secret_service"
	osKeyStoreKeyFile       osKeyStoreKind = "key_file"
	// No store: the pass alone wraps U.
	osKeyStorePass osKeyStoreKind = "pass"
)

// The item names the core asks for are its own (urnetwork-sidecar-v1/unlock/...), so a store keys an item by a hash
// of the name where a name must be a file name.
func osKeyStoreItemFile(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}

// Runs call, answering failed should it panic, so no platform call panics across the host boundary (D-SDK-15).
func osKeyStoreGuard[T any](failed T, call func() T) (result T) {
	defer func() {
		if recover() != nil {
			result = failed
		}
	}()
	return call()
}

// Security.framework's OSStatus values the keychain store reads (SecBase.h).
const (
	errSecSuccess               int32 = 0
	errSecItemNotFound          int32 = -25300
	errSecDuplicateItem         int32 = -25299
	errSecInteractionNotAllowed int32 = -25308
	// An unsigned binary on the data protection keychain: Failed, and a test of the purego path skips on it.
	errSecMissingEntitlement int32 = -34018
)

// The data protection keychain's calls (§5.9's macOS row), each answering Security.framework's OSStatus. One item a
// name, in this store's service, with AfterFirstUnlockThisDeviceOnly and the access group when one is set.
type darwinKeychainCalls interface {
	// SecItemCopyMatching, returning the item's data.
	copyData(account string) ([]byte, int32)
	// SecItemAdd.
	add(account string, value []byte) int32
	// SecItemUpdate of the item's data.
	update(account string, value []byte) int32
	// SecItemDelete.
	remove(account string) int32
}

// The macOS store: errSecItemNotFound is Absent, errSecInteractionNotAllowed Locked, and anything else Failed.
type darwinKeychainStore struct {
	calls darwinKeychainCalls
}

// The value, or the status that says why not. See sidecar.SidecarKeyStore.
func (self *darwinKeychainStore) GetSecret(name string) ([]byte, sidecar.SidecarKeyStoreStatus) {
	type answer struct {
		value  []byte
		status sidecar.SidecarKeyStoreStatus
	}
	result := osKeyStoreGuard(answer{status: sidecar.SidecarKeyStoreFailed}, func() answer {
		value, status := self.calls.copyData(name)
		switch status {
		case errSecSuccess:
			return answer{value: value, status: sidecar.SidecarKeyStorePresent}
		case errSecItemNotFound:
			return answer{status: sidecar.SidecarKeyStoreAbsent}
		case errSecInteractionNotAllowed:
			return answer{status: sidecar.SidecarKeyStoreLocked}
		}
		return answer{status: sidecar.SidecarKeyStoreFailed}
	})
	return result.value, result.status
}

// Adds the item, or updates it if it is there. See sidecar.SidecarKeyStore.
func (self *darwinKeychainStore) PutSecret(name string, value []byte) sidecar.SidecarKeyStoreStatus {
	return osKeyStoreGuard(sidecar.SidecarKeyStoreFailed, func() sidecar.SidecarKeyStoreStatus {
		status := self.calls.add(name, value)
		if status == errSecDuplicateItem {
			status = self.calls.update(name, value)
		}
		return darwinKeychainWriteStatus(status)
	})
}

// Deletes the item; one not there is Ok. See sidecar.SidecarKeyStore.
func (self *darwinKeychainStore) DeleteSecret(name string) sidecar.SidecarKeyStoreStatus {
	return osKeyStoreGuard(sidecar.SidecarKeyStoreFailed, func() sidecar.SidecarKeyStoreStatus {
		status := self.calls.remove(name)
		if status == errSecItemNotFound {
			return sidecar.SidecarKeyStoreOk
		}
		return darwinKeychainWriteStatus(status)
	})
}

// A write's OSStatus as a status.
func darwinKeychainWriteStatus(status int32) sidecar.SidecarKeyStoreStatus {
	switch status {
	case errSecSuccess:
		return sidecar.SidecarKeyStoreOk
	case errSecInteractionNotAllowed:
		return sidecar.SidecarKeyStoreLocked
	}
	return sidecar.SidecarKeyStoreFailed
}

// DPAPI's calls (§5.9's Windows row): CryptProtectData and CryptUnprotectData under the user's credentials, with the
// item's name as entropy, so one item's blob cannot stand for another's.
type dpapiCalls interface {
	protect(plain []byte, entropy []byte) ([]byte, error)
	unprotect(sealed []byte, entropy []byte) ([]byte, error)
}

// The files a blob store keeps: one a name, written whole or not at all.
type osKeyStoreFiles interface {
	// The file's bytes, or an error satisfying errors.Is(err, fs.ErrNotExist) when there is none.
	read(file string) ([]byte, error)
	// Replaces the file whole, durably.
	write(file string, content []byte) error
	// Removes the file; one not there is no error.
	remove(file string) error
}

// The Windows store: a DPAPI blob a name, in the store's directory. DPAPI has no lock to report, so a failed call is
// Failed, a missing file Absent, and a blob that does not open, someone else's or a damaged one, Failed.
type dpapiStore struct {
	calls dpapiCalls
	files osKeyStoreFiles
}

// The value, or the status that says why not. See sidecar.SidecarKeyStore.
func (self *dpapiStore) GetSecret(name string) ([]byte, sidecar.SidecarKeyStoreStatus) {
	type answer struct {
		value  []byte
		status sidecar.SidecarKeyStoreStatus
	}
	result := osKeyStoreGuard(answer{status: sidecar.SidecarKeyStoreFailed}, func() answer {
		sealed, err := self.files.read(osKeyStoreItemFile(name))
		if errors.Is(err, errOsKeyStoreFileAbsent) {
			return answer{status: sidecar.SidecarKeyStoreAbsent}
		}
		if err != nil {
			return answer{status: sidecar.SidecarKeyStoreFailed}
		}
		value, err := self.calls.unprotect(sealed, []byte(name))
		if err != nil {
			return answer{status: sidecar.SidecarKeyStoreFailed}
		}
		return answer{value: value, status: sidecar.SidecarKeyStorePresent}
	})
	return result.value, result.status
}

// Seals the value and replaces the item's blob. See sidecar.SidecarKeyStore.
func (self *dpapiStore) PutSecret(name string, value []byte) sidecar.SidecarKeyStoreStatus {
	return osKeyStoreGuard(sidecar.SidecarKeyStoreFailed, func() sidecar.SidecarKeyStoreStatus {
		sealed, err := self.calls.protect(value, []byte(name))
		if err != nil {
			return sidecar.SidecarKeyStoreFailed
		}
		if err := self.files.write(osKeyStoreItemFile(name), sealed); err != nil {
			return sidecar.SidecarKeyStoreFailed
		}
		return sidecar.SidecarKeyStoreOk
	})
}

// Removes the item's blob. See sidecar.SidecarKeyStore.
func (self *dpapiStore) DeleteSecret(name string) sidecar.SidecarKeyStoreStatus {
	return osKeyStoreGuard(sidecar.SidecarKeyStoreFailed, func() sidecar.SidecarKeyStoreStatus {
		if err := self.files.remove(osKeyStoreItemFile(name)); err != nil {
			return sidecar.SidecarKeyStoreFailed
		}
		return sidecar.SidecarKeyStoreOk
	})
}

// The Secret Service's calls (§5.9's Linux desktop row), each telling a locked collection or item apart from an
// error and from absence. An error is any failure to ask: no session bus, no Secret Service, a refused call.
type secretServiceCalls interface {
	// The item's secret. found false with locked false and no error is absence.
	get(name string) (value []byte, found bool, locked bool, err error)
	// Creates or replaces the item in the default collection.
	put(name string, value []byte) (locked bool, err error)
	// Deletes the item, if there is one.
	remove(name string) (locked bool, err error)
}

// The Linux desktop store: an error is Failed, a locked collection or item Locked, and only a working, unlocked
// search that finds nothing is Absent.
type secretServiceStore struct {
	calls secretServiceCalls
}

// The value, or the status that says why not. See sidecar.SidecarKeyStore.
func (self *secretServiceStore) GetSecret(name string) ([]byte, sidecar.SidecarKeyStoreStatus) {
	type answer struct {
		value  []byte
		status sidecar.SidecarKeyStoreStatus
	}
	result := osKeyStoreGuard(answer{status: sidecar.SidecarKeyStoreFailed}, func() answer {
		value, found, locked, err := self.calls.get(name)
		switch {
		case err != nil:
			return answer{status: sidecar.SidecarKeyStoreFailed}
		case locked:
			return answer{status: sidecar.SidecarKeyStoreLocked}
		case !found:
			return answer{status: sidecar.SidecarKeyStoreAbsent}
		}
		return answer{value: value, status: sidecar.SidecarKeyStorePresent}
	})
	return result.value, result.status
}

// Creates or replaces the item. See sidecar.SidecarKeyStore.
func (self *secretServiceStore) PutSecret(name string, value []byte) sidecar.SidecarKeyStoreStatus {
	return osKeyStoreGuard(sidecar.SidecarKeyStoreFailed, func() sidecar.SidecarKeyStoreStatus {
		return secretServiceWriteStatus(self.calls.put(name, value))
	})
}

// Deletes the item. See sidecar.SidecarKeyStore.
func (self *secretServiceStore) DeleteSecret(name string) sidecar.SidecarKeyStoreStatus {
	return osKeyStoreGuard(sidecar.SidecarKeyStoreFailed, func() sidecar.SidecarKeyStoreStatus {
		return secretServiceWriteStatus(self.calls.remove(name))
	})
}

// A write's answer as a status.
func secretServiceWriteStatus(locked bool, err error) sidecar.SidecarKeyStoreStatus {
	switch {
	case err != nil:
		return sidecar.SidecarKeyStoreFailed
	case locked:
		return sidecar.SidecarKeyStoreLocked
	}
	return sidecar.SidecarKeyStoreOk
}

// A file store's answer for a file that is not there, which only the read of one says.
var errOsKeyStoreFileAbsent = errors.New("no such key store file")

// A copy, so a caller zeroing what it gave keeps nothing shared.
func osKeyStoreCopy(value []byte) []byte {
	return bytes.Clone(value)
}
