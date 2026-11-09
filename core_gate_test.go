//go:build !sidecar_http && !js

// M1's core gate (§22.5's §5 row at M1, §5.17's M1 list, §23.6's M1-out): each exit check named with the tests that
// hold it, which TestCoreM1GateRowsHaveTheirTests finds in the sources, so a check whose test is renamed, deleted or
// never written fails here rather than going unrun. Then the gate's own end to end run on the root's public API alone:
// a sidecar enrolled through sidecartest's fake api, Online on the Net's exchange, refreshed by its ClientKey's proof,
// and §22.7's S1 scan clean.
//
// What the gate cannot run here stays named in its row's open field: the daemon on linux and windows (M1-out's hand
// runs), T3's enrollment (POST /network/enroll is TEAM-M1-04's), and S1's MCP capture, since `ur mcp` relays to a
// daemon that refuses it until §16's go-sdk handler lands.

package sidecar_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One exit check and the tests that hold it, each as <directory relative to this module>.<TestName>.
type coreGateRow struct {
	check string
	tests []string
	// what of the check no test here runs, and why
	open string
}

// M1's core exit checks.
var coreM1GateRows = []coreGateRow{
	{
		check: "§22.5 §5: U's and R_n's wraps round trip, and only their own keys open them",
		tests: []string{".TestUnlockWrapRoundTrip", ".TestKeychainWrapRoundTrip", ".TestOneUnlockOpensEveryNetwork"},
	},
	{
		check: "§22.5 §5, D-CORE-15: only Absent with no recorded sidecar_id creates; Locked and Failed change nothing; a lost item is keystore_lost",
		tests: []string{
			".TestAbsentWithNothingRecordedCreatesU", ".TestAbsentWithRecordedIdCreatesNothing", ".TestLockedCreatesNothing",
			".TestFailedCreatesNothing", ".TestCorruptBytesAreFailed", ".TestLostKeychainWrapIsKeystoreLost",
		},
	},
	{
		check: "§22.5 §5, D-CORE-14: one network's keychain opens no other's",
		tests: []string{".TestOneNetworkCannotOpenAnother", ".TestAKeychainCopiedOverAnotherNetworkIsFailed"},
	},
	{
		check: "§22.5 §5, D-CORE-9: other uids refused, no secret in replies, mode grants nothing",
		tests: []string{".TestOtherUidRefused", ".TestRepliesHoldNoSecret", ".TestModeGrantsNothing"},
		open:  "the daemon on linux and windows: TestOtherUidRefused runs on darwin here, its other legs cross-compiled (M1-out's hand runs)",
	},
	{
		check: "§22.5 §5, D-CORE-7: enrollment fails closed, keeping the keychain only once admin_refused is confirmed and the binding recorded",
		tests: []string{
			".TestEnrollFailsClosedWithoutAdminRefused", ".TestKeychainPersistedOnlyAfterBind", ".TestBundleNeverSent",
			"sidecartest.TestEnrollmentFailsClosed",
		},
	},
	{
		check: "M1-out: preview_networks only (D-TRUST-3)",
		tests: []string{".TestPreviewRefusalSurfaces", "sidecartest.TestFakeApiEnrollRefusals", ".TestCoreM1GateEnrollsAndRefreshesEndToEnd"},
	},
	{
		check: "§5.6: enroll to Online through POST /network/enroll and POST /sidecar/bind",
		tests: []string{"sidecartest.TestSidecarEnrollsToOnline", ".TestCoreM1GateEnrollsAndRefreshesEndToEnd"},
		open:  "T3 enrollment: server has no POST /network/enroll until TEAM-M1-04; server/api/sidecar_identity_route_db_test.go runs bind, lookups, refresh and restore_required on server's routes",
	},
	{
		check: "D-CORE-8: a 7-day token refreshes by its ClientKey's proof across 21 days",
		tests: []string{"sidecartest.TestSidecarRefreshesAcross21Days", "sidecartest.TestFakeApiRefreshNeedsTheBoundKeysProof"},
		open:  "T3 across 21 days: server's token clock is real time, so its run refreshes once (server/api/sidecar_identity_route_db_test.go)",
	},
	{
		check: "D-CORE-8: a refused refresh is Unenrolled with identity kept, and `ur login` binds the next generation under the same sidecar_id",
		tests: []string{"sidecartest.TestRefusedRefreshThenLoginKeepsTheSidecarId", "sidecartest.TestEndedSessionUnenrollsAsSessionEnded", ".TestReenrollKeepsSidecarId"},
	},
	{
		check: "§5.6, §19.10: restore_required re-posts the newest binding, then refreshes",
		tests: []string{"sidecartest.TestRestoreRequiredRebindsAndRefreshes", "sidecartest.TestFakeApiRefreshAnswersRestoreRequiredUnbound"},
	},
	{
		check: "§22.7 S1: no token in MCP, env or logs, the capture scanning CC4 for every hooked key",
		tests: []string{"sidecartest.TestSidecarEnrollsToOnline", ".TestCoreM1GateEnrollsAndRefreshesEndToEnd"},
		open:  "MCP's capture: ur mcp relays to a daemon that refuses it until §16's handler (CORE-M1-11), so no MCP output exists to scan at M1",
	},
	{
		check: "§4.7, make check: sidecar_http links no connect or gVisor package, and the six CLI targets build",
		tests: []string{"check.TestLegs", "check.TestLegsCompileWhereTheirToolchainIs"},
	},
}

// The test functions a directory's _test.go files declare, by name.
func coreGateTestNames(t *testing.T, directory string) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	paths, err := filepath.Glob(filepath.Join(directory, "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Recv == nil && strings.HasPrefix(function.Name.Name, "Test") {
				names[function.Name.Name] = true
			}
		}
	}
	return names
}

// Every row names at least one test, and every test it names is declared where the row says.
func TestCoreM1GateRowsHaveTheirTests(t *testing.T) {
	directoryNames := map[string]map[string]bool{}
	for _, row := range coreM1GateRows {
		if len(row.tests) == 0 {
			t.Errorf("%q names no test", row.check)
		}
		for _, test := range row.tests {
			index := strings.LastIndex(test, ".")
			directory, name := test[:index], test[index+1:]
			if directory == "" {
				directory = "."
			}
			if _, err := os.Stat(directory); err != nil {
				t.Errorf("%q: %s: %s", row.check, test, err)
				continue
			}
			if directoryNames[directory] == nil {
				directoryNames[directory] = coreGateTestNames(t, directory)
			}
			if !directoryNames[directory][name] {
				t.Errorf("%q: %s is declared nowhere in %s", row.check, name, directory)
			}
		}
	}
}

// The gate on the public API alone: NewSidecar through sidecartest's Net, an auth key of a preview network the fake
// api minted, Online, a refresh by the ClientKey's proof, an enrollment outside preview_networks refused with nothing
// kept, and S1's scan clean.
func TestCoreM1GateEnrollsAndRefreshesEndToEnd(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	api, err := net.Api()
	if err != nil {
		t.Fatal(err)
	}
	previewNetworkId := net.DefaultNetworkId()
	api.SetPreviewNetworks([]sidecar.Id{previewNetworkId})

	outsider, err := net.StartSidecar("outsider", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := outsider.AwaitState(ctx, sidecar.SidecarStateUnenrolled); err != nil {
		t.Fatal(err)
	}
	if err := outsider.Enroll(ctx, sidecar.NewId()); err == nil {
		t.Fatal("a network outside preview_networks enrolled")
	}
	if records := outsider.Instance().Networks(); len(records) != 0 {
		t.Fatalf("a refused enrollment kept %d networks", len(records))
	}

	laptop, err := net.AddSidecar("laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := laptop.NetworkRecord()
	if !ok || record.NetworkId != previewNetworkId {
		t.Fatalf("record %+v", record)
	}
	count := api.ClientTokenCount(record.ClientId)
	issuedAt, expireTime, _ := api.NewestClientToken(record.ClientId)
	// the refresher's timer is in the token's window, which waiting for it before moving the clock keeps there
	windowEnd := issuedAt.Add(expireTime.Sub(issuedAt) / 2)
	for refreshed := false; !refreshed; {
		pending, added := net.Clock().WatchTimers()
		for _, at := range pending {
			if issuedAt.Add(expireTime.Sub(issuedAt)*2/5).Add(-time.Second).Before(at) && !at.After(windowEnd) {
				net.Clock().AdvanceTo(at)
				refreshed = true
			}
		}
		if !refreshed {
			select {
			case <-added:
			case <-ctx.Done():
				t.Fatal("the refresher set no timer in its window")
			}
		}
	}
	for api.ClientTokenCount(record.ClientId) <= count {
		_, minted := api.Mints()
		if count < api.ClientTokenCount(record.ClientId) {
			break
		}
		select {
		case <-minted:
		case <-ctx.Done():
			t.Fatal("no refresh")
		}
	}
	if status := laptop.Sidecar().Status(); status.State != sidecar.SidecarStateOnline || status.Generation != 1 {
		t.Errorf("status %+v", status)
	}
	if findings := net.Capture().Scan(); len(findings) != 0 {
		t.Errorf("S1: %v", findings)
	}
}
