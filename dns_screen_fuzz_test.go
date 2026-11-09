//go:build !js

// FuzzScreenName (ABUSE-M5-01, §22.6): ScreenName never panics; a name ValidateDnsName refuses is
// never allowed as a draw, nor with nothing verified or reviewed unless only ValidateDnsName's length
// bound refused it; a name that is not one lowercase label, or is reserved or a word-number name, is
// denied under every facts; and a reviewer's allow turns only a review into an allow, never a deny.
// Off the js leg, whose Worker has no file system for go test's corpus reader; dns_screen_test.go runs
// the seeds there through embed.

package sidecar

import (
	"testing"
)

func FuzzScreenName(f *testing.F) {
	for _, seed := range []string{"quiet-river-lab", "paypal-support", "paypa1", "paypalsupport", "otter-4821", "xn--80ak6aa92e", "umetwork", "blog"} {
		f.Add(seed)
	}
	allDomains := testScreenAllDomains()
	f.Fuzz(func(t *testing.T, name string) {
		if failure := checkScreenName(name, allDomains); failure != "" {
			t.Fatalf("%q: %s", name, failure)
		}
	})
}
