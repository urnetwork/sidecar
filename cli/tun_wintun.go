// wintun.dll's pins (owner decision 222; QD-823), which ur tun on Windows holds a DLL to before it loads one
// (tun_windows.go's urWintunLoad), and the half of that check that is a hash alone. Both are kept off tun_windows.go's
// build constraint so the pins and each architecture's lookup are tested on every GOOS a CI leg runs, none of which is
// Windows; the signature, the file held against writers and the load itself stay in tun_windows.go.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Why ur tun on Windows refuses a wintun.dll by its hash.
var (
	// A wintun.dll is there, but no hash of the DLL is pinned for this architecture.
	errUrWintunUnpinned = errors.New("ur tun on Windows loads wintun.dll only once its SHA-256 matches a pin, and " +
		"none is pinned for this architecture's DLL, only for those ur.exe is released for, so it loads none")
	// The DLL there is not the pinned one.
	errUrWintunRefused = errors.New("the wintun.dll ur tun found is not the pinned Wintun 0.14.1, so it loads none")
)

// The pins wintun.dll is held to: windows/app/tools/fetch-deps.ps1's for Wintun 0.14.1, and the DLLs of the zip it
// pins.
type urWintunPins struct {
	// The DLL's own SHA-256, hex in either case, by GOARCH. An architecture with no pin loads no DLL.
	DllSha256 map[string]string
	// The signer certificate's SHA-1 thumbprint, hex: fetch-deps.ps1's $WintunSignerThumbprint.
	SignerThumbprint string
}

// The pins, a fresh value each call.
//
// The DLL pins come from the zip fetch-deps.ps1 pins. It fetches https://www.wintun.net/builds/wintun-0.14.1.zip and
// holds it to $WintunSha256, 07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51, then holds every
// wintun.dll in it to $WintunSignerThumbprint. A host has only the extracted DLL, never the zip, so ur tun holds the
// DLL to the hash of the zip's own member for its architecture (QD-823, question bridge-m6-06-wintun-dll-hash, option
// 1). On 2026-11-15, on the owner's go-ahead, that zip was fetched and matched $WintunSha256. Its
// wintun/bin/amd64/wintun.dll and wintun/bin/arm64/wintun.dll were hashed into the two values below, upper case as
// Get-FileHash writes them. fetch-deps.ps1 is to carry the same two as $WintunDllSha256Amd64 and $WintunDllSha256Arm64,
// the owner's step in the windows repo. amd64 and arm64 are the architectures ur.exe is released for; the zip's x86
// and arm DLLs are pinned for none.
func defaultUrWintunPins() *urWintunPins {
	return &urWintunPins{
		DllSha256: map[string]string{
			"amd64": "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE",
			"arm64": "F7BA89005544BE9D85231A9E0D5F23B2D15B3311667E2DAD0DEBD344918A3F80",
		},
		SignerThumbprint: "DF98E075A012ED8C86FBCF14854B8F9555CB3D45",
	}
}

// Holds file, path's, to goarch's DLL pin: its SHA-256, read from its start, must be the pinned one. An architecture
// with no pin refuses before the file is read. The signature comes after, on Windows alone (urWintunCheck).
func urWintunCheckDigest(file io.ReadSeeker, path string, pins *urWintunPins, goarch string) error {
	pinned := strings.ToLower(pins.DllSha256[goarch])
	if pinned == "" {
		return fmt.Errorf("%w (%s, %s)", errUrWintunUnpinned, path, goarch)
	}
	digest, err := urWintunDigest(file)
	if err != nil {
		return fmt.Errorf("%w: %s did not read (%v)", errUrWintunRefused, path, err)
	}
	if digest != pinned {
		return fmt.Errorf("%w: %s's SHA-256 is not the pinned one for %s", errUrWintunRefused, path, goarch)
	}
	return nil
}

// The SHA-256 of file, hex, read from its start.
func urWintunDigest(file io.ReadSeeker) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
