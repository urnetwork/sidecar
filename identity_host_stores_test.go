//go:build !js && !ios && !android && !sdk_mobile_bind

package sidecar

// D-SDK-11's clean extension version (identity_host_stores.go; TEAM-M3-01, plan-CORE-host-store-refusal #2):
// while hostStoreExtensionCleanVersion is empty every version of the extension counts, so ur refuses beside it at
// any stage; once the release that stops persisting the token sets it, a version at or past it no longer counts
// and the host passes by itself, while an older or unreadable version still refuses.

import (
	"os"
	"path/filepath"
	"testing"
)

// The constant ships empty, so every version counts until D-SDK-11's release sets it.
func TestHostStoreCountsEveryExtensionVersionUntilTheCleanRelease(t *testing.T) {
	if hostStoreExtensionCleanVersion != "" {
		t.Fatal("the clean extension version is set before D-SDK-11's release ships")
	}
	if defaultHostStoreRoots().extensionCleanVersion != hostStoreExtensionCleanVersion {
		t.Fatal("this host's roots do not carry the clean version")
	}
	for _, version := range []string{"0.1", "1.2.3", "99.0.1", "not-a-version", ""} {
		if !hostExtensionVersionPersists(version, "") {
			t.Errorf("%q does not count while the clean version is unset", version)
		}
	}
}

func TestHostStoreExtensionVersionAgainstTheCleanRelease(t *testing.T) {
	for _, c := range []struct {
		version  string
		persists bool
	}{
		{version: "2.0.0", persists: false},
		{version: "2.0", persists: false},
		{version: "2.0.1", persists: false},
		{version: "2.1", persists: false},
		{version: "10.0", persists: false},
		{version: "1.9.9", persists: true},
		{version: "1.10", persists: true},
		{version: "02.0", persists: true},
		{version: "2.0-beta", persists: true},
		{version: "", persists: true},
	} {
		if persists := hostExtensionVersionPersists(c.version, "2.0"); persists != c.persists {
			t.Errorf("%q against 2.0: persists %t, want %t", c.version, persists, c.persists)
		}
	}
}

// With a clean version set, a Chromium or Firefox install at or past it is no store, and one below it still is.
func TestHostStoreExtensionAtTheCleanReleasePasses(t *testing.T) {
	writeFile := func(path string, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name  string
		goos  string
		file  string
		body  string
		found bool
	}{
		{name: "chrome clean", goos: "darwin", file: "Library/Application Support/Google/Chrome/Default/Extensions/abcdef/2.0.0_0/manifest.json", body: `{"name":"URnetwork VPN","version":"2.0.0"}`, found: false},
		{name: "chrome older", goos: "darwin", file: "Library/Application Support/Google/Chrome/Default/Extensions/abcdef/1.9_0/manifest.json", body: `{"name":"URnetwork VPN","version":"1.9"}`, found: true},
		{name: "chrome no version", goos: "darwin", file: "Library/Application Support/Google/Chrome/Default/Extensions/abcdef/x/manifest.json", body: `{"name":"URnetwork VPN"}`, found: true},
		{name: "firefox clean", goos: "linux", file: ".mozilla/firefox/synthetic.default/extensions.json", body: `{"addons":[{"id":"urnetwork@bringyour.com","version":"2.1"}]}`, found: false},
		{name: "firefox older", goos: "linux", file: ".mozilla/firefox/synthetic.default/extensions.json", body: `{"addons":[{"id":"urnetwork@bringyour.com","version":"1.0"}]}`, found: true},
	} {
		home := t.TempDir()
		writeFile(filepath.Join(home, c.file), c.body)
		roots := &hostStoreRoots{goos: c.goos, home: home, extensionCleanVersion: "2.0"}
		if found := hostExtensionStoreFound(roots); found != c.found {
			t.Errorf("%s: found %t, want %t", c.name, found, c.found)
		}
		roots.extensionCleanVersion = ""
		if !hostExtensionStoreFound(roots) {
			t.Errorf("%s: not found with the clean version unset", c.name)
		}
	}
}
