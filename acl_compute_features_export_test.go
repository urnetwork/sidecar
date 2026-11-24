// The authorization features' seam for the external tests (package sidecar_test), which cannot reach this package's
// registrations: a test sets the features this build implements, each with its implicit fragment, until it ends.

package sidecar

import (
	"slices"
	"testing"
)

// This build's implemented features swapped for features, each with its fragment from fragments (nil for none), until
// the test ends: what every log the test builds holds a base's bits to. A test may run beside no other that does this.
func WithAuthFeaturesImplementedForTest(t testing.TB, features AuthFeature, fragments map[AuthFeature][]byte) {
	t.Helper()
	saved := authFeatureRegistrations
	t.Cleanup(func() {
		authFeatureRegistrations = saved
	})
	registrations := []*authFeatureRegistration{}
	for _, entry := range authFeatureNames {
		if features&entry.feature == 0 {
			continue
		}
		fragment := fragments[entry.feature]
		if fragment != nil {
			if err := checkAuthFeatureFragment(fragment); err != nil {
				t.Fatalf("%s's fragment: %v", entry.feature, err)
			}
		}
		registrations = append(registrations, &authFeatureRegistration{feature: entry.feature, fragment: slices.Clone(fragment)})
	}
	authFeatureRegistrations = registrations
}
