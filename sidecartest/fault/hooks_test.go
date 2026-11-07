//go:build sidecar_testhooks

// Schedules through the real seams: a site in the root and one in device/ reach the driver, since NewNet
// installs on both. Without the tag no site reaches it, which is why these need it.

package fault

import (
	"context"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestAScheduleHoldsARootBarrierAndAKeySeesTheCapture(t *testing.T) {
	net := newRunNet(t)
	steps := 0
	wantPass(t, Run(t.Context(), &Schedule{
		Id: "toy-root-site",
		Steps: []*Step{
			{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
				sidecar.TestHookSecret("K_test", []byte("synthetic-test-key-bytes"))
				sidecar.TestHookBarrier("evs.head_cas.before", "01JTESTREPO")
				steps += 1
				return nil
			}, Await: sidecartest.BarrierSite("evs.head_cas.before", "01JTESTREPO")},
			{Actor: "observer", Action: func(ctx context.Context, net *Net) error {
				if steps != 0 {
					t.Error("ran past a held barrier")
				}
				return nil
			}},
			{Release: []string{sidecartest.BarrierSite("evs.head_cas.before", "01JTESTREPO")}},
			{Actor: "writerA", Join: true},
		},
	}, net))
	if steps != 1 {
		t.Errorf("steps %d", steps)
	}
	net.Capture().AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "log", Body: []byte("synthetic-test-key-bytes")})
	if hits := net.Capture().Scan(); len(hits) == 0 || hits[0].Needle != "K_test" {
		t.Errorf("hits %v", hits)
	}
}
