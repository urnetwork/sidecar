//go:build !ios_extension

package sidecar

// §18.9's host table's user root (QD-1407; §12.4, §12.5's label row): the embedded table names one, a domain name the
// settings validate, which ApplyServiceUrls fills SidecarSettings.UserRoot with; a list naming none applies with no
// root; one that is not a domain name refuses the list; and the published copy leaves it out. The embedded root is
// read for its shape only and named nowhere here.

import (
	"errors"
	"strings"
	"testing"
)

// The embedded table's root fills the settings, which validate, and every copy holds it.
func TestEmbeddedHostListNamesTheUserRoot(t *testing.T) {
	list, err := SidecarHostListV1()
	if err != nil {
		t.Fatal(err)
	}
	if !isNetworkLabelRoot(list.UserRoot) {
		t.Fatal("the embedded table names no user root of lowercase labels")
	}
	settings := DefaultSidecarSettings()
	if err := list.ApplyServiceUrls(settings); err != nil {
		t.Fatal(err)
	}
	if settings.UserRoot != list.UserRoot {
		t.Fatal("the urls' fill left the user root unset")
	}
	if err := settings.validate(); err != nil {
		t.Fatalf("the embedded user root does not validate: %v", err)
	}
	again, err := SidecarHostListV1()
	if err != nil || again.UserRoot != list.UserRoot {
		t.Fatalf("a second copy's root: %v", err)
	}
	published, err := list.PublishedJson()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(published), "user_root") || strings.Contains(string(published), `"`+list.UserRoot+`"`) {
		t.Fatal("the published copy carries the user root")
	}
}

// A fixture list's root fills the settings; a list naming none fills an empty root over whatever was set and still
// applies; and a root that is not a domain name of lowercase labels refuses the whole list.
func TestHostListUserRootFillsTheSettings(t *testing.T) {
	named := strings.Replace(testSidecarHostListJson(), `"version": 1,`, `"version": 1, "user_root": "users.hosttest.example",`, 1)
	list, err := ParseSidecarHostList([]byte(named))
	if err != nil {
		t.Fatal(err)
	}
	settings := DefaultSidecarSettings()
	if err := list.ApplyServiceUrls(settings); err != nil || settings.UserRoot != "users.hosttest.example" {
		t.Fatalf("the fixture's root: %q, %v", settings.UserRoot, err)
	}

	unnamed, err := ParseSidecarHostList([]byte(testSidecarHostListJson()))
	if err != nil {
		t.Fatal(err)
	}
	if err := unnamed.ApplyServiceUrls(settings); err != nil || settings.UserRoot != "" {
		t.Fatalf("a list naming no root: %q, %v", settings.UserRoot, err)
	}
	if err := settings.validate(); err != nil {
		t.Fatalf("settings with no root: %v", err)
	}

	for _, root := range []string{"Users.hosttest.example", "users.hosttest.example.", "hosttest", "users..example", " users.example"} {
		data := strings.Replace(testSidecarHostListJson(), `"version": 1,`, `"version": 1, "user_root": "`+root+`",`, 1)
		if _, err := ParseSidecarHostList([]byte(data)); !errors.Is(err, ErrSidecarHostList) {
			t.Errorf("a user root %q: %v", root, err)
		}
	}
}
