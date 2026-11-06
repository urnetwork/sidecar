//go:build sidecar_check && sidecar_size

// make size: the gates themselves, and the proof that a real build trips them. These compile and
// link, and the ios_extension leg needs Xcode, so they stay off make check. The verdicts they apply
// are proved in size_test.go, which make check does run.

package check

import (
	"encoding/hex"
	"math/rand/v2"
	"testing"
)

// §18.10, D-SDK-20: what device and protocol/bridge add to the iOS extension.
func TestSizeGateIosExtension(t *testing.T) {
	repository := openThisCheckout(t)
	baselineByteCount, withSidecarByteCount := repository.measureIosExtension(t)
	t.Logf("ios_extension leg: %d B without the device role, %d B with it, %d B added, limit %d B",
		baselineByteCount, withSidecarByteCount, withSidecarByteCount-baselineByteCount, repository.settings.iosExtensionAddedMaxByteCount)
	findings := repository.settings.iosExtensionSizeFindings(baselineByteCount, withSidecarByteCount)
	switchOn := repository.settings.switches.iosExtensionSizeGate
	if !switchOn && len(findings) == 0 {
		t.Errorf("the gate holds, so iosExtensionSizeGate should be on")
	}
	failFindings(t, "size", rowOff(t.Logf, switchOn, "iosExtensionSizeGate", findings))
}

// §18.10, D-SDK-19: the page Worker's leg, unstripped, against its goal and miss rule.
func TestSizeGateSidecarHttp(t *testing.T) {
	repository := openThisCheckout(t)
	byteCount := repository.measureSidecarHttp(t)
	t.Logf("sidecar_http js leg: %d B unstripped, goal %d B, miss gate %d B",
		byteCount, repository.settings.sidecarHttpGoalByteCount, repository.settings.sidecarHttpMissByteCount)
	findings := repository.settings.sidecarHttpSizeFindings(byteCount)
	switchOn := repository.settings.switches.sidecarHttpSizeGate
	if !switchOn && len(findings) == 0 {
		t.Errorf("the gate holds, so sidecarHttpSizeGate should be on")
	}
	failFindings(t, "size", rowOff(t.Logf, switchOn, "sidecarHttpSizeGate", findings))
}

// Text of the given size that no compression or dedup shrinks, as a Go string literal, the same on
// every run.
func plantedTable(byteCount int) string {
	generator := rand.NewChaCha8([32]byte{})
	table := make([]byte, byteCount/2)
	if _, err := generator.Read(table); err != nil {
		panic(err)
	}
	return hex.EncodeToString(table)
}

// A table reached only through an exported function: a blank import of device would drop it and
// call the leg clean, so this is what shows the probe measures the role's real cost.
func TestSizeGateFindsATablePlantedInDevice(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("device/device.go", "package device\n\nvar table = \""+plantedTable(2*1024*1024)+"\"\n\nfunc Lookup(index int) byte {\n\treturn table[index]\n}\n")
	repository := fixture.open()
	baselineByteCount, withSidecarByteCount := repository.measureIosExtension(t)
	t.Logf("%d B added", withSidecarByteCount-baselineByteCount)
	wantFindings(t, repository.settings.iosExtensionSizeFindings(baselineByteCount, withSidecarByteCount), "to the ios_extension leg, over the 1048576 B limit")
}

// The same plant on the page Worker's leg, against a goal set just above the clean tree.
func TestSizeGateFindsATablePlantedInTheRoot(t *testing.T) {
	fixture := newFixture(t)
	cleanByteCount := fixture.open().measureSidecarHttp(t)
	fixture.settings.sidecarHttpGoalByteCount = cleanByteCount + 1024*1024
	fixture.settings.sidecarHttpMissByteCount = cleanByteCount + 4*1024*1024
	fixture.write("planted.go", "package sidecar\n\nvar table = \""+plantedTable(2*1024*1024)+"\"\n\nfunc Lookup(index int) byte {\n\treturn table[index]\n}\n")
	repository := fixture.open()
	byteCount := repository.measureSidecarHttp(t)
	t.Logf("%d B clean, %d B planted", cleanByteCount, byteCount)
	wantFindings(t, repository.settings.sidecarHttpSizeFindings(byteCount), "no Gn-in has recorded the slip")
}
