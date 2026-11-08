//go:build windows

// The Windows store (§5.9): U's wrap sealed by DPAPI under the user's credentials, CryptProtectData with the item's
// name as entropy and no UI, one blob a name in <state>\keystore. The directory sits under %LOCALAPPDATA%, whose ACL
// is the user's, so no Unix mode check applies.

package main

import (
	"io/fs"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/urnetwork/sidecar"
)

// DPAPI through golang.org/x/sys/windows.
type windowsDpapi struct{}

// A blob of value, whose memory windows owns until LocalFree.
func dpapiBlob(value []byte) *windows.DataBlob {
	blob := &windows.DataBlob{Size: uint32(len(value))}
	if 0 < len(value) {
		blob.Data = &value[0]
	}
	return blob
}

// The bytes of an output blob, copied, with the blob freed.
func dpapiTake(blob *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(blob.Data)))
	if blob.Size == 0 || blob.Data == nil {
		return []byte{}
	}
	value := make([]byte, blob.Size)
	copy(value, unsafe.Slice(blob.Data, blob.Size))
	return value
}

// CryptProtectData, no UI. See dpapiCalls.
func (self windowsDpapi) protect(plain []byte, entropy []byte) ([]byte, error) {
	out := &windows.DataBlob{}
	err := windows.CryptProtectData(dpapiBlob(plain), nil, dpapiBlob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, out)
	if err != nil {
		return nil, err
	}
	return dpapiTake(out), nil
}

// CryptUnprotectData, no UI. See dpapiCalls.
func (self windowsDpapi) unprotect(sealed []byte, entropy []byte) ([]byte, error) {
	out := &windows.DataBlob{}
	err := windows.CryptUnprotectData(dpapiBlob(sealed), nil, dpapiBlob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, out)
	if err != nil {
		return nil, err
	}
	return dpapiTake(out), nil
}

// No Unix mode on Windows: the directory's ACL is %LOCALAPPDATA%'s.
func checkOsKeyStoreFileMode(info fs.FileInfo) error {
	return nil
}

// No Unix mode on Windows.
func checkOsKeyStoreDirectoryMode(info fs.FileInfo) error {
	return nil
}

// Windows syncs no directory: a rename's metadata is the file system's to keep.
func syncOsKeyStoreDirectory(directory string) error {
	return nil
}

// DPAPI blobs in args.Directory (§5.9's Windows row).
func newOsKeyStore(args *osKeyStoreArgs) (sidecar.SidecarKeyStore, osKeyStoreKind, error) {
	return &dpapiStore{calls: windowsDpapi{}, files: &osKeyStoreDirectory{directory: args.Directory}}, osKeyStoreDpapi, nil
}
