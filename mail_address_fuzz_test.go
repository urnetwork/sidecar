//go:build !js

// FuzzMailRecipient (MAIL-M7-02, §22.6): ParseMailRecipient is total over any root and address. It never panics,
// refuses with ErrMailRecipientInvalid alone and never repeats the address, and what it accepts spells the address
// it was given, lowercase, parses again to itself and keeps its form's shape (checkMailRecipient). Off the js leg,
// whose Worker has no file system for go test's corpus reader; mail_address_test.go runs the seeds there through
// embed.

package sidecar

import (
	"testing"
)

func FuzzMailRecipient(f *testing.F) {
	f.Add(testMailRoot, "ada@k3j4h5g6f7.root.example")
	f.Add(testMailRoot, "r-k5mzq7x2@otter-4821.k3j4h5g6f7.root.example")
	f.Fuzz(func(t *testing.T, root string, address string) {
		if failure := checkMailRecipient(root, address); failure != "" {
			t.Fatalf("%q under %q: %s", address, root, failure)
		}
	})
}
