package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The bench's small case, in CI time: two sends of each mode on one leg through its gate and a scripted MX, with
// sidecartest's prover and verifier standing in for a key set's, which no CI run can set up. It prints the host,
// each row's percentiles beside its failures, and a unit's row for each shape a send took.
func TestBenchRunsASmallCaseAndPrintsAUnitsRow(t *testing.T) {
	world := &benchWorld{
		prover:   sidecartest.NewFakeSmtpProver(sidecartest.DefaultFakeSmtpProverSettings()),
		verifier: sidecartest.NewFakeSmtpProofVerifier(nil),
	}
	var out bytes.Buffer
	code := run(context.Background(), []string{"-runs", "2", "-legs", "tls13-chacha", "-modes", "bdat,data", "-data-bytes", "8192"}, &out, world)
	text := out.String()
	if code != 0 {
		t.Fatalf("exit %d: %s", code, text)
	}
	t.Log("\n" + text)
	for _, want := range []string{
		"host: ",
		"tls13-chacha bdat: 2 runs, 0 failed",
		"tls13-chacha data: 2 runs, 0 failed",
		"unit key-v0304-chacha20-c2: ",
		"peak resident: ",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in:\n%s", want, text)
		}
	}
}

func TestBenchRefusesWhatItCannotRun(t *testing.T) {
	for _, args := range [][]string{
		{"-runs", "0"},
		{"-legs", "tls11-rc4"},
		{"-modes", "lmtp"},
		{"-recipients", "0"},
		{},
	} {
		var out bytes.Buffer
		if code := run(context.Background(), args, &out, nil); code != 64 {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}

func TestBenchPercentilesAreNearestRank(t *testing.T) {
	values := []float64{9, 1, 8, 2, 7, 3, 6, 4, 5, 10}
	got := benchPercentilesOf(values)
	if got.P50 != 5 || got.P95 != 10 || got.Max != 10 {
		t.Errorf("%+v", got)
	}
	if benchPercentilesOf(nil) != nil {
		t.Error("percentiles of nothing")
	}
}
