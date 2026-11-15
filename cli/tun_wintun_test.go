// wintun.dll's pins and the hash half of ur tun's check of a DLL (tun_wintun.go), on every GOOS: the pins hold the
// hashes of the amd64 and arm64 DLLs of the zip fetch-deps.ps1 pins, and its signer; a DLL of another hash, or one
// that does not read, is refused on both architectures; each architecture's lookup takes its own pin and no other;
// and an architecture with none refuses whatever it is given. tun_windows_test.go holds the rest of the load, on
// Windows: the file held against writers, the signature after the hash, and no DLL where ur tun looks.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"strings"
	"testing"
)

// The pins are the two DLLs' hashes, each a whole SHA-256, beside the signer's thumbprint, and a caller's change to
// one value reaches no other.
func TestTunWintunPinsHoldBothDlls(t *testing.T) {
	want := map[string]string{
		"amd64": "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE",
		"arm64": "F7BA89005544BE9D85231A9E0D5F23B2D15B3311667E2DAD0DEBD344918A3F80",
	}
	pins := defaultUrWintunPins()
	if !maps.Equal(pins.DllSha256, want) {
		t.Fatalf("the DLL pins %v", pins.DllSha256)
	}
	for goarch, pinned := range pins.DllSha256 {
		if digest, err := hex.DecodeString(pinned); err != nil || len(digest) != sha256.Size {
			t.Fatalf("%s's pin %q is no SHA-256: %v", goarch, pinned, err)
		}
	}
	if pins.SignerThumbprint != "DF98E075A012ED8C86FBCF14854B8F9555CB3D45" {
		t.Fatalf("the signer pin %s", pins.SignerThumbprint)
	}
	pins.DllSha256["amd64"] = strings.Repeat("00", sha256.Size)
	if again := defaultUrWintunPins(); !maps.Equal(again.DllSha256, want) {
		t.Fatalf("a caller's change reached the next pins: %v", again.DllSha256)
	}
}

// A DLL whose hash is not the pin is refused on both pinned architectures, as one that does not read is, and an
// architecture with no pin refuses before reading anything.
func TestTunWintunRefusesAnotherHash(t *testing.T) {
	pins := defaultUrWintunPins()
	for _, goarch := range []string{"amd64", "arm64"} {
		err := urWintunCheckDigest(bytes.NewReader([]byte("not wintun")), "wintun.dll", pins, goarch)
		if !errors.Is(err, errUrWintunRefused) || errors.Is(err, errUrWintunUnpinned) ||
			!strings.Contains(err.Error(), "SHA-256 is not the pinned one") {
			t.Fatalf("another hash on %s: %v", goarch, err)
		}
		// the empty file's hash is another hash too
		if err := urWintunCheckDigest(bytes.NewReader(nil), "wintun.dll", pins, goarch); !errors.Is(err, errUrWintunRefused) {
			t.Fatalf("an empty file on %s: %v", goarch, err)
		}
		unreadable := &testWintunUnreadable{}
		if err := urWintunCheckDigest(unreadable, "wintun.dll", pins, goarch); !errors.Is(err, errUrWintunRefused) ||
			!strings.Contains(err.Error(), "did not read") {
			t.Fatalf("an unreadable file on %s: %v", goarch, err)
		}
	}
	for _, goarch := range []string{"386", "arm", ""} {
		unreadable := &testWintunUnreadable{}
		err := urWintunCheckDigest(unreadable, "wintun.dll", pins, goarch)
		if !errors.Is(err, errUrWintunUnpinned) || unreadable.readCount != 0 {
			t.Fatalf("unpinned %q: %v after %d reads", goarch, err, unreadable.readCount)
		}
	}
}

// With one architecture's pin set to a DLL's hash, that architecture takes the DLL and the other, still on its own
// pin, refuses it, each way round, so neither lookup reads the other's value. The pin's case does not matter, and the
// hash is of the whole file wherever a reader left it.
func TestTunWintunLooksUpEachArchitecturesOwnPin(t *testing.T) {
	dll := []byte("a synthetic wintun.dll")
	digest := sha256.Sum256(dll)
	for _, c := range []struct {
		goarch string
		other  string
	}{
		{goarch: "amd64", other: "arm64"},
		{goarch: "arm64", other: "amd64"},
	} {
		pins := defaultUrWintunPins()
		pins.DllSha256[c.goarch] = strings.ToUpper(hex.EncodeToString(digest[:]))
		file := bytes.NewReader(dll)
		if err := urWintunCheckDigest(file, "wintun.dll", pins, c.goarch); err != nil {
			t.Fatalf("%s did not take its own pin: %v", c.goarch, err)
		}
		if err := urWintunCheckDigest(file, "wintun.dll", pins, c.other); !errors.Is(err, errUrWintunRefused) {
			t.Fatalf("%s took %s's pin: %v", c.other, c.goarch, err)
		}
		if _, err := file.Seek(int64(len(dll))/2, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if err := urWintunCheckDigest(file, "wintun.dll", pins, c.goarch); err != nil {
			t.Fatalf("%s from the middle of the file: %v", c.goarch, err)
		}
		pins.DllSha256[c.goarch] = hex.EncodeToString(digest[:])
		if err := urWintunCheckDigest(file, "wintun.dll", pins, c.goarch); err != nil {
			t.Fatalf("%s's pin in lower case: %v", c.goarch, err)
		}
	}
}

// A file whose every read fails, counting its reads.
type testWintunUnreadable struct {
	readCount int
}

func (self *testWintunUnreadable) Read(p []byte) (int, error) {
	self.readCount += 1
	return 0, errors.New("the read failed")
}

func (self *testWintunUnreadable) Seek(offset int64, whence int) (int64, error) {
	return 0, nil
}
