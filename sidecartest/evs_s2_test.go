//go:build sidecar_testhooks

// S2 (§22.7's scenarios; §3.7's F2, write and notify; X2, I-1, I-2; EVS1-M2-42) on T2, under the privacy harness:
// sidecar.EvsClient devices write, read and list one repo through evsservice's engines on the evs world
// (sidecartest/fault's evs_world.go), with 32 random canary bytes in every user field the world writes: each file's
// content, inline and in a segment, each file's and directory's name. Every key a sidecar creates, derives or unwraps
// is a needle as well (testHookSecret). Then the scan reads what servers held, every engine handler's requests and
// answers, every object on every cluster, every Redis key and value, the engines' logs, metrics, usage, tasks and
// hints, raw and in every encoding, and must find nothing. A sidecar_leaktest build then puts a canary into the
// store in the clear and the same scan must catch it, so a scan that reads nothing cannot pass.
//
// The scenario covers F2's evs half. What it leaves to others: git through ur mount (EVS1-M2-38's local tier), a
// commit message and author fields, the hints reaching a device over connect, and T3's capture of Postgres and the
// exchange (TEST-M2-09).

package sidecartest_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/fault"
)

// S2's schedule on net: what the capture then scans.
func evsS2Run(t *testing.T, net *sidecartest.Net) {
	t.Helper()
	capture := net.Capture()
	settings := fault.DefaultEvsWorldSettings()
	settings.Capture = true
	world := fault.NewEvsWorld(net, settings)
	directory := capture.CanaryText("evs directory name")
	name := capture.CanaryText("evs file name")
	topName := capture.CanaryText("evs top-level name")
	inline := capture.Canary("evs inline content")
	segment := bytes.Repeat(capture.Canary("evs segment content"), 2*1024)
	changed := capture.Canary("evs changed content")
	small := directory + "/" + name
	big := directory + "/" + topName + ".bin"
	steps := []*fault.Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", small, inline)},
		{Actor: "writerA", Action: world.Write("writerA", big, segment)},
		{Actor: "writerB", Action: world.Write("writerB", topName, inline)},
		{Actor: "reader", Action: world.Verify("reader", small, big, topName)},
		{Actor: "reader", Action: world.VerifyListing("reader", directory, name, topName+".bin")},
		{Actor: "writerB", Action: world.Write("writerB", small, changed)},
		{Actor: "folder", Action: world.Fold("evs3")},
		{Actor: "writerA", Action: world.Remove("writerA", topName)},
		{Actor: "reader", Action: world.VerifyCached("reader", small, big, topName)},
		{Advance: 26 * time.Hour},
		{Actor: "evacuator", Action: world.Evacuate()},
		{Actor: "reader", Action: world.Verify("reader", small, big, topName)},
	}
	result := fault.Run(t.Context(), &fault.Schedule{Id: "S2", Steps: steps, Check: world.Checks()}, net)
	if result.Err != nil {
		t.Fatalf("%s", result)
	}
}

func TestS2WriteAndNotifyLeaksNothing(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	evsS2Run(t, net)
	capture := net.Capture()
	for _, class := range []sidecartest.PrivacyClass{sidecartest.PrivacyClassHandler, sidecartest.PrivacyClassObject, sidecartest.PrivacyClassRedis, sidecartest.PrivacyClassLog} {
		if capture.ItemCount(class) == 0 {
			t.Errorf("the scan read nothing of %s", class)
		}
	}
	for _, finding := range capture.Scan() {
		t.Errorf("%s", finding)
	}
	if !sidecartest.LeaksLinked {
		return
	}
	// the leak build: a canary in the store in the clear, which the same scan must find
	leak := sidecartest.LeakClasses()[sidecartest.PrivacyClassObject]
	if leak == nil {
		t.Fatal("the leak build has no object leak")
	}
	canary := capture.Canary("s2 leak")
	leak.Put(t, net, canary)
	found := false
	for _, finding := range capture.Scan() {
		found = found || strings.Contains(finding.String(), "s2 leak")
	}
	if !found {
		t.Fatal("S2's scan missed a canary leaked into the store")
	}
}
