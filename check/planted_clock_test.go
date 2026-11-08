//go:build sidecar_check

// The clock rule's planted violations, one per kind of package it binds and per way a reference
// hides, and the exceptions it allows.

package check

import (
	"testing"
)

func TestClockFailsOnAWallClockCallInTheRoot(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted.go", "package sidecar\n\nimport \"time\"\n\nfunc planted() time.Time {\n\treturn time.Now()\n}\n")
	wantFindings(t, fixture.open().wallClockFindings(t), "planted.go:6: time.Now reads the wall clock")
}

func TestClockFailsOnAWallClockCallInAnEngine(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("evsservice/planted.go", "package evsservice\n\nimport \"time\"\n\nfunc planted() {\n\ttime.Sleep(time.Second)\n}\n")
	wantFindings(t, fixture.open().wallClockFindings(t), "evsservice/planted.go:6: time.Sleep reads the wall clock")
}

func TestClockFailsOnAWallClockCallInDevice(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("device/planted.go", "package device\n\nimport \"time\"\n\nfunc planted() *time.Timer {\n\treturn time.NewTimer(time.Second)\n}\n")
	wantFindings(t, fixture.open().wallClockFindings(t), "device/planted.go:6: time.NewTimer reads the wall clock")
}

func TestClockFailsOnAWallClockCallInMcp(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("mcp/planted.go", "package mcp\n\nimport \"time\"\n\nfunc planted(start time.Time) time.Duration {\n\treturn time.Since(start)\n}\n")
	wantFindings(t, fixture.open().wallClockFindings(t), "mcp/planted.go:6: time.Since reads the wall clock")
}

// Handing the wall clock on as a value is reading it, one step later.
func TestClockFailsOnTheWallClockPassedAsAValue(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted.go", "package sidecar\n\nimport \"time\"\n\nvar plantedNow = time.Now\n")
	wantFindings(t, fixture.open().wallClockFindings(t), "planted.go:5: time.Now reads the wall clock")
}

func TestClockFailsOnAnAliasedTimeImport(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted.go", "package sidecar\n\nimport clock \"time\"\n\nfunc planted() <-chan clock.Time {\n\treturn clock.Tick(clock.Second)\n}\n")
	wantFindings(t, fixture.open().wallClockFindings(t), "planted.go:6: time.Tick reads the wall clock")
}

// id.go's exception is for time.Now in id.go alone: another function there, or the same call in
// another file, fails.
func TestClockFailsOnACallBesideAListedException(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("id.go", "package sidecar\n\nimport \"time\"\n\nfunc planted() int64 {\n\treturn time.Now().UnixMilli()\n}\n\nfunc plantedWait() {\n\ttime.Sleep(time.Millisecond)\n}\n")
	fixture.write("id_planted.go", "package sidecar\n\nimport \"time\"\n\nfunc plantedId() int64 {\n\treturn time.Now().UnixMilli()\n}\n")
	wantFindings(t, fixture.open().wallClockFindings(t),
		"id.go:10: time.Sleep reads the wall clock",
		"id_planted.go:6: time.Now reads the wall clock",
	)
}

// A file no leg compiles is read all the same.
func TestClockFailsOnACallBehindABuildTag(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("planted_other.go", "//go:build freebsd\n\npackage sidecar\n\nimport \"time\"\n\nfunc planted() {\n\t_ = time.AfterFunc(time.Second, func() {})\n}\n")
	wantFindings(t, fixture.open().wallClockFindings(t), "planted_other.go:8: time.AfterFunc reads the wall clock")
}

// The listed exception holds, tests read real time freely, and the rule binds neither cli nor
// sidecartest.
func TestClockAllowsTheListedExceptionTestsAndUnboundPackages(t *testing.T) {
	fixture := newFixture(t)
	fixture.write("id.go", "package sidecar\n\nimport \"time\"\n\nfunc planted() int64 {\n\treturn time.Now().UnixMilli()\n}\n")
	fixture.write("planted_test.go", "package sidecar\n\nimport (\n\t\"testing\"\n\t\"time\"\n)\n\nfunc TestPlanted(t *testing.T) {\n\ttime.Sleep(time.Millisecond)\n}\n")
	fixture.write("cli/planted.go", "package main\n\nimport \"time\"\n\nvar plantedStart = time.Now()\n")
	fixture.write("sidecartest/planted.go", "package sidecartest\n\nimport \"time\"\n\nvar plantedStart = time.Now()\n")
	wantFindings(t, fixture.open().wallClockFindings(t))
}

// The rule's binding by package name, nested modules' packages left out.
func TestClockRuleBindsTheRootEnginesMcpAndDevice(t *testing.T) {
	for packageName, bound := range map[string]bool{
		".": true, "evsservice": true, "evsservice/store": true, "dnsservice": true, "mcp": true, "mcp/tools": true,
		"device": true, "cli": false, "smtpproof": false, "mlsinterop": false, "sidecartest": false, "protocol": false,
		"check": false,
	} {
		if wallClockPackage(packageName) != bound {
			t.Errorf("%s: bound %t", packageName, !bound)
		}
	}
}
