//go:build sidecar_testhooks && !ios_extension

package sidecar

import (
	"testing"
)

// The seam sdk's every-leg check calls reproduces the normalize, slot and shard vectors here as well, so a finding
// there is the sdk's module graph's and never the seam's own.
func TestHookIndexVectorsHoldInThisModule(t *testing.T) {
	if findings := TestHookIndexVectorFindings(); len(findings) != 0 {
		t.Errorf("%v", findings)
	}
	normVersion, casesVersion, unicodeVersion, textModuleVersion := TestHookIndexLinkedTables()
	if normVersion != indexNormalizerUnicodeVersion || casesVersion != indexNormalizerUnicodeVersion ||
		unicodeVersion != indexNormalizerUnicodeVersion || textModuleVersion != indexNormalizerTextModuleVersion {
		t.Errorf("linked %s %s %s %s", normVersion, casesVersion, unicodeVersion, textModuleVersion)
	}
}
