//go:build !js

// Off the js leg, whose tests run in a Worker with no file system, where a fuzz target cannot read its
// seed corpus.

package sidecar

import (
	"strings"
	"testing"
)

// No input panics, the bearer never holds the bundle or a #, and no error holds the input.
func FuzzAuthKeyString(f *testing.F) {
	bare, _ := formatAuthKey(testAuthKeyBearer(), nil)
	full, _ := formatAuthKey(testAuthKeyBearer(), testAuthKeyBundle())
	for _, seed := range []string{"", bare, full, "urn_synthetic", full + "#", strings.ToUpper(full), "#" + full} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		authKey, err := ParseAuthKey(text)
		if err != nil {
			if authKey != nil {
				t.Fatal("a key beside an error")
			}
			if 8 <= len(text) && strings.Contains(err.Error(), text) {
				t.Fatal("the error holds the input")
			}
			return
		}
		if strings.Contains(authKey.Bearer(), "#") {
			t.Fatal("the bearer holds a #")
		}
		if _, bundleText, found := strings.Cut(text, "#"); found && bundleText != "" &&
			strings.Contains(authKey.Bearer(), bundleText) {
			t.Fatal("the bearer holds the bundle")
		}
		if (authKey.Bundle() != nil) != strings.Contains(text, "#") {
			t.Fatal("a bundle without a #, or a # without a bundle")
		}
		if strings.Contains(RedactAuthKey(text), strings.TrimPrefix(authKey.Bearer(), authKeyPrefix)) {
			t.Fatal("redaction shows the bearer")
		}
		if err := CheckAuthKeyBody([]byte(authKey.Bearer())); err != nil {
			t.Fatal("a bearer CheckAuthKeyBody refuses")
		}
	})
}
