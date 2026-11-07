//go:build sidecar_check

// What the rules read as policy: the named switches for the rows §4.18 starts after M0, and the
// limits and pins §4.7, §4.9, §18.10 and §11.14 set.

package check

import (
	"fmt"
)

// The named switches. A row the design starts after M0 runs when its switch is on, and each is on
// from the day its row holds, whatever milestone the design names for it, so a track cannot break
// a rule because the milestone that names it has not arrived. Turning one off stops the row failing
// and no more: the row still runs, and rowOff reports what it would have failed on, so nothing
// passes in silence. TestRowsThatStartLaterHoldNow fails a switch left off under a row that holds.
type rowSwitches struct {
	// §18.10 and §4.18, from M1: the sidecar_http js leg links no connect or gVisor package.
	// Held since M0: every root file importing connect carries !sidecar_http.
	sidecarHttpLinksNoConnect bool
	// D-SDK-20 and §4.18, from M4: the ios_extension leg links neither the root nor protocol.
	// Held since M0, by protocol/bridge alone until device/ lands, when the leg picks it up.
	iosExtensionLinksNoRoot bool
	// §4.7 and §4.18, from M10: every leg selects normalizer 1's golang.org/x/text. Held since M0:
	// connect and all four sdk modules moved to v0.43.0 ahead of the design's dates.
	xTextIsNormalizerOnes bool
	// §18.10 and §4.18, from M4: make size holds what the device role adds to 1 MiB.
	iosExtensionSizeGate bool
	// §18.10 and §4.18, from M2: make size holds the sidecar_http js leg to its goal and miss rule.
	sidecarHttpSizeGate bool
}

// Read by every rule. There is one value, from defaultCheckSettings; a test may change a copy.
type checkSettings struct {
	switches rowSwitches

	// go.mod's go line on every module (§4.7)
	goVersion string
	// the release's only tool line (§4.7)
	protocGenGoTool string
	// §11.14: one x/text module version on every leg, which the search index's headers record
	normalizerOneXTextVersion string

	// §4.7's allowed licenses, as SPDX ids. X11 is MIT's text plus only its no-advertising clause
	// (QD-240), which licensePhrases pins.
	allowedLicenses []string
	// cgo files in a third-party package, as <import path>/<file>, each with why it stands. §4.7's
	// cgo row binds this repository's packages (R-REPO-6), and a third-party file is listed here
	// so a new one needs a reader, rather than passing unseen.
	thirdPartyCgoFiles map[string]string

	// the pinned scanner, fetched with go install; a new release is a reviewed bump here
	govulncheckVersion string
	// govulncheck's -db
	vulnDatabase string
	// how many legs scan at once. Non-positive means one at a time.
	vulnScanConcurrency int
	// how many legs compile at once. Each go command already compiles its own packages in parallel,
	// so a few at once overlap only what each does alone, such as loading its modules, and a cold
	// cache holds no more compilers in memory than the machine takes. Non-positive means one at a time.
	legCompileConcurrency int

	// §18.10, D-SDK-20: the most the device role may add to the ios_extension leg, in bytes
	iosExtensionAddedMaxByteCount int64
	// §18.10, owner decision 22: the sidecar_http js leg's goal, unstripped, in bytes
	sidecarHttpGoalByteCount int64
	// §18.10's miss rule: the sdk.wasm gate the leg ships under if it still exceeds the goal at
	// M4's entry, in bytes, which no recorded slip goes past
	sidecarHttpMissByteCount int64
	// set when a Gn-in has recorded the sidecar_http leg's slip past its goal (§18.10)
	sidecarHttpGoalSlipRecorded bool
	// -iosversion in sdk/build/Makefile, which gomobile turns into -miphoneos-version-min
	iosMinimumVersion string
}

// The only source of defaults.
func defaultCheckSettings() *checkSettings {
	return &checkSettings{
		switches: rowSwitches{
			sidecarHttpLinksNoConnect: true,
			iosExtensionLinksNoRoot:   true,
			xTextIsNormalizerOnes:     true,
			iosExtensionSizeGate:      true,
			sidecarHttpSizeGate:       true,
		},
		goVersion:                 "1.27.3",
		protocGenGoTool:           "google.golang.org/protobuf/cmd/protoc-gen-go",
		normalizerOneXTextVersion: "v0.43.0",
		allowedLicenses: []string{
			"MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "MPL-2.0", "X11",
		},
		thirdPartyCgoFiles: map[string]string{
			"github.com/wlynxg/anet/android_api_level_cgo.go": "reads the Android API level; " +
				"through connect's pion stack on the gomobile android leg, which needs CGO_ENABLED=1 anyway",
		},
		govulncheckVersion:            "v1.9.0",
		vulnDatabase:                  "https://vuln.go.dev",
		vulnScanConcurrency:           8,
		legCompileConcurrency:         4,
		iosExtensionAddedMaxByteCount: 1024 * 1024,
		sidecarHttpGoalByteCount:      40 * 1024 * 1024,
		sidecarHttpMissByteCount:      74965628,
		sidecarHttpGoalSlipRecorded:   false,
		iosMinimumVersion:             "16.0",
	}
}

// One row's result under its switch: its findings when the switch is on. Off, the findings go to
// the report and the row passes, so a run says what it did not enforce.
func rowOff(report func(format string, arguments ...any), switchOn bool, name string, findings []string) []string {
	if switchOn {
		return findings
	}
	report("row %s is switched off, and would report %d findings", name, len(findings))
	for _, finding := range findings {
		report("  %s: %s", name, finding)
	}
	return nil
}

// As fmt.Sprintf; a short name keeps the rules' finding lines on one line.
func findingf(format string, arguments ...any) string {
	return fmt.Sprintf(format, arguments...)
}
