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

	// §4.7's allowed licenses, as SPDX ids, each with its text in licenseTextsDirectory. X11 is MIT's
	// text plus only its no-advertising clause (QD-240).
	allowedLicenses []string
	// the most words a license's <<...>> part takes for one copy. A holder's name is a few words, and
	// this bounds what such a part could hide, so it is no longer than a name needs.
	licenseVariableMaxWordCount int
	// how many words a finding quotes from where a license file leaves its licenses' texts
	licenseDepartureWordCount int
	// a module's words beyond its licenses' own, by module path, each read by a person and kept with
	// why it stands: what a file says of which license covers which of its files. Each passage is
	// matched as a license's text is, so a changed word fails the row until someone reads the change.
	licenseNotes map[string]licenseNote
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

	// §22.4's clock rule's exceptions (clock_rule_test.go), by file and time function, as "id.go
	// time.Now", each with the day it was granted and why. An exception that matches nothing fails, so
	// the list only shrinks.
	wallClockExceptions map[string]wallClockException
	// the test rules' exceptions (tests_rules_test.go): a real-time wait, keyed "<file> time.<function>",
	// and test data that is not synthetic, keyed "<file> <address or hostname>", each with the day it
	// was granted and why. An exception that matches nothing fails, so the lists only shrink.
	realTimeWaitExceptions map[string]testRuleException
	testDataExceptions     map[string]testRuleException
}

// What a module's license file says beyond its licenses' own words, read by a person.
type licenseNote struct {
	why string
	// each in the file's own words, as a license's text is written in licenseTextsDirectory
	passages []string
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
		licenseVariableMaxWordCount: 8,
		licenseDepartureWordCount:   12,
		licenseNotes: map[string]licenseNote{
			"gopkg.in/yaml.v3": {
				why: "says which of its files each of its two licenses covers",
				passages: []string{
					"This project is covered by two different licenses: MIT and Apache. #### MIT License #### " +
						"The following files were ported to Go from C files of libyaml, and thus are still covered by " +
						"their original MIT license, with the additional copyright staring in 2011 when the project " +
						"was ported over: apic.go emitterc.go parserc.go readerc.go scannerc.go writerc.go yamlh.go yamlprivateh.go",
					"### Apache License ### All the remaining project files are covered by the Apache license:",
				},
			},
			"gvisor.dev/gvisor": {
				why: "says that some of its files carry MIT's and BSD-3-Clause's texts below its Apache-2.0",
				passages: []string{
					"Some files carry the following license, noted at the top of each file:",
					"Some files carry the \"BSD\" license, noted at the top of each file:",
				},
			},
			"github.com/cyphar/filepath-securejoin": {
				why: "COPYING.md says which of its files each of its two licenses covers, for pkg.go.dev's " +
					"scan, and repeats both texts, which LICENSE.BSD and LICENSE.MPL-2.0 also hold",
				passages: []string{
					"## COPYING ## `SPDX-License-Identifier: BSD-3-Clause AND MPL-2.0` This project is made up of code " +
						"licensed under different licenses. Which code you use will have an impact on whether only one or " +
						"both licenses apply to your usage of this library. Note that **each file** in this project " +
						"individually has a code comment at the start describing the license of that particular file -- " +
						"this is the most accurate license information of this project; in case there is any conflict " +
						"between this document and the comment at the start of a file, the comment shall take precedence. " +
						"The only purpose of this document is to work around [a known technical limitation of " +
						"pkg.go.dev's license checking tool when dealing with non-trivial project licenses][go75067]. " +
						"[go75067]: https://go.dev/issue/75067",
					"### `BSD-3-Clause` ### At time of writing, the following files and directories are licensed under " +
						"the BSD-3-Clause license: * `doc.go` * `join*.go` * `vfs.go` * `internal/consts/*.go` " +
						"* `pathrs-lite/internal/gocompat/*.go` * `pathrs-lite/internal/kernelversion/*.go` The text of " +
						"the BSD-3-Clause license used by this project is the following (the text is also available from " +
						"the [`LICENSE.BSD`](./LICENSE.BSD) file):",
					"### `MPL-2.0` ### All other files (unless otherwise marked) are licensed under the Mozilla Public " +
						"License (version 2.0). The text of the Mozilla Public License (version 2.0) is the following " +
						"(the text is also available from the [`LICENSE.MPL-2.0`](./LICENSE.MPL-2.0) file):",
				},
			},
			"github.com/emirpasic/gods": {
				why:      "heads its second license, ISC's, with the one package that license covers",
				passages: []string{"AVL Tree:"},
			},
			"github.com/go-git/gcfg": {
				why: "breaks its copyright notice across two lines, so the notice's last word falls on a line of its " +
					"own, outside the notice line the comparison leaves out",
				passages: []string{"Authors."},
			},
			"github.com/modelcontextprotocol/go-sdk": {
				why: "says which of its contributions each of its two licenses covers, mid-way from MIT to Apache-2.0, and " +
					"that its documentation, which no build links, is CC-BY-4.0",
				passages: []string{
					"The MCP project is undergoing a licensing transition from the MIT License to the Apache License, " +
						"Version 2.0 (\"Apache-2.0\"). All new code and specification contributions to the project are " +
						"licensed under Apache-2.0. Documentation contributions (excluding specifications) are licensed under " +
						"CC-BY-4.0. Contributions for which relicensing consent has been obtained are licensed under " +
						"Apache-2.0. Contributions made by authors who originally licensed their work under the MIT License " +
						"and who have not yet granted explicit permission to relicense remain licensed under the MIT License. " +
						"No rights beyond those granted by the applicable original license are conveyed for such contributions.",
					"END OF TERMS AND CONDITIONS",
					"Creative Commons Attribution 4.0 International (CC-BY-4.0) Documentation in this project (excluding " +
						"specifications) is licensed under CC-BY-4.0. See https://creativecommons.org/licenses/by/4.0/legalcode " +
						"for the full license text.",
				},
			},
			"github.com/klauspost/compress": {
				why: "names the directories each license in its file covers",
				passages: []string{
					"Files: gzhttp/*",
					"Files: s2/cmd/internal/readahead/*",
					"Files: snappy/* Files: internal/snapref/*",
					"Files: s2/cmd/internal/filepathx/*",
				},
			},
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
		wallClockExceptions: map[string]wallClockException{
			"id.go time.Now": {
				since: "2026-11-08",
				why: "a ULID carries its minter's clock in its high bits by design (CODESTYLE's identifiers), so ids " +
					"order by real creation time and never by a test's clock",
			},
			"clock.go time.Now":          {since: "2026-11-08", why: "RealClock is the root's real time"},
			"clock.go time.After":        {since: "2026-11-08", why: "RealClock is the root's real time"},
			"clock.go time.AfterFunc":    {since: "2026-11-08", why: "RealClock is the root's real time"},
			"device/clock.go time.Now":   {since: "2026-11-08", why: "device.RealClock is the device role's real time"},
			"device/clock.go time.After": {since: "2026-11-08", why: "device.RealClock is the device role's real time"},
			"device/clock.go time.AfterFunc": {
				since: "2026-11-08",
				why:   "device.RealClock is the device role's real time",
			},
			"api_client.go time.Now": {
				since: "2026-11-08",
				why:   "SidecarApi's now defaults to real time, until CORE-M1-08's NewSidecar passes SidecarSettings.Clock",
			},
			"keys_instance.go time.Now": {
				since: "2026-11-08",
				why:   "the instance lock reads real time, until CORE-M1-08's NewSidecar passes SidecarSettings.Clock",
			},
			"keys_instance.go time.After": {
				since: "2026-11-08",
				why:   "the instance lock waits in real time, until CORE-M1-08's NewSidecar passes SidecarSettings.Clock",
			},
		},
		realTimeWaitExceptions: map[string]testRuleException{
			"sidecartest/localstack/stack_test.go time.Sleep": {
				since: "2026-11-09",
				why:   "redissuite on §22.4's local stack waits out a real Redis's own TTLs, whose clock no test can move",
			},
			"socket_stream_fake_test.go time.NewTimer": {
				since: "2026-11-09",
				why:   "the fake socket pipe honors a real deadline the code under test sets, as net.Conn's contract has it; its firing is no proof",
			},
		},
		testDataExceptions: map[string]testRuleException{
			"acl_policy_host_test.go acme.com": {
				since: "2026-11-09",
				why:   "§8's worked example names acme.com, which the test reproduces as the design writes it",
			},
			"api_hosts_test.go ur.io": {
				since: "2026-11-09",
				why:   "a path into mmm's ur.io checkout, a directory name and no host",
			},
			"check/fixture_test.go mozilla.org": {
				since: "2026-11-09",
				why:   "the MPL's own notice, which names its URL, in a fixture license",
			},
			"check/fixture_test.go www.apache.org": {
				since: "2026-11-09",
				why:   "the Apache-2.0 notice, which names its URL, in a fixture license",
			},
			"check/planted_hygiene_test.go pkg.go.dev": {
				since: "2026-11-09",
				why:   "a vulnerability report's link as govulncheck prints it, planted",
			},
			"device/bridge_table_test.go 1.0.0.0": {
				since: "2026-11-09",
				why:   "a longest-prefix lookup's boundary under 0.0.0.0/1, not a host; BRIDGE's owner moves it to documentation space where the table allows",
			},
			"device/bridge_table_test.go 128.0.0.0": {
				since: "2026-11-09",
				why:   "128.0.0.0/1's boundary in a longest-prefix lookup, not a host",
			},
			"device/bridge_table_test.go 198.51.0.0": {
				since: "2026-11-09",
				why:   "a /16 around 198.51.100.0/24 to prove the longer prefix wins, which needs space outside the documentation /24",
			},
			"device/bridge_table_test.go 198.51.101.0": {
				since: "2026-11-09",
				why:   "the /16 above's address outside the documentation /24, which the lookup must send to the /16",
			},
			"device/bridge_table_test.go 198.51.7.7": {
				since: "2026-11-09",
				why:   "the /16 above's address outside the documentation /24, which the lookup must send to the /16",
			},
			"dnsservice/copy_rows_test.go 11.22.33.44": {
				since: "2026-11-09",
				why:   "§12.7's record validator refuses documentation space, so an accepted A record needs a routable address; DNS's owner may move it to a documented test address the validator allows",
			},
			"dnsservice/edge_test.go 11.22.33.44": {
				since: "2026-11-09",
				why:   "§12.7's record validator refuses documentation space, so an accepted A record needs a routable address",
			},
			"dnsservice/sign_test.go 11.22.33.44": {
				since: "2026-11-09",
				why:   "§12.7's record validator refuses documentation space, so an accepted A record needs a routable address",
			},
			"dnsservice/validate_fuzz_test.go 2000::": {
				since: "2026-11-09",
				why:   "a fuzz seed at global unicast's first address, which §12.7's validator must accept",
			},
			"dnsservice/zone_test.go 11.22.33.44": {
				since: "2026-11-09",
				why:   "§12.7's record validator refuses documentation space, so an accepted A record needs a routable address",
			},
			"dnsservice/zone_test.go 2a0f:ffff::7": {
				since: "2026-11-09",
				why:   "§12.7's record validator refuses documentation space, so an accepted AAAA record needs a routable address",
			},
			"mxedgeservice/caps_test.go 203.0.114.1": {
				since: "2026-11-09",
				why:   "routable, one /24 past 203.0.113.0/24: MAIL's owner moves it into 203.0.113.0/24",
			},
			"mxedgeservice/closed_handshake_test.go 203.0.114.9": {
				since: "2026-11-09",
				why:   "routable, one /24 past 203.0.113.0/24: MAIL's owner moves it into 203.0.113.0/24",
			},
			"mxedgeservice/service_test.go 203.0.114.9": {
				since: "2026-11-09",
				why:   "routable, one /24 past 203.0.113.0/24: MAIL's owner moves it into 203.0.113.0/24",
			},
			"record_presence_attest_test.go ur.io": {
				since: "2026-11-09",
				why:   "§16.6's presence profile fixes ur.io as the WebAuthn relying party id, a format constant",
			},
			"record_presence_test.go app.ur.io": {
				since: "2026-11-09",
				why:   "a subdomain of §16.6's relying party id, which the profile must refuse",
			},
			"record_presence_test.go ur.io": {
				since: "2026-11-09",
				why:   "§16.6's presence profile fixes ur.io as the WebAuthn relying party id, a format constant",
			},
			"sidecarctl/cmd_certs_renew_test.go 1.1.1.1": {
				since: "2026-11-09",
				why:   "a public resolver as an operator passes lego's --dns.resolvers, checked as an argument and never dialed; TLS's owner may move it to documentation space",
			},
			"sidecarctl/cmd_certs_renew_test.go acme-v02.api.letsencrypt.org": {
				since: "2026-11-09",
				why:   "Let's Encrypt's directory as the renew command passes it, checked as an argument and never dialed",
			},
			"sidecartest/localstack/blobs_sign_test.go examplebucket.s3.amazonaws.com": {
				since: "2026-11-09",
				why:   "AWS's published Signature Version 4 example, whose host is part of the signed vector",
			},
			"tls_caa_test.go letsencrypt.org": {
				since: "2026-11-09",
				why:   "§13.8's CAA issuer domain, a format constant",
			},
			"tlsedgeservice/sni_test.go 1.2.3.4": {
				since: "2026-11-09",
				why:   "an address literal a ClientHello must not carry as SNI; TLS's owner may move it to documentation space",
			},
		},
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
