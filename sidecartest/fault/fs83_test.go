//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

package fault

import (
	"context"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// FS-83 on T2, one explorer seed: its steps hold no barrier, so a seed reorders nothing.
func TestFs83(t *testing.T) {
	settings := DefaultRuleSettings()
	settings.Seeds = settings.Seeds[:1]
	RunRow(t, "FS-83", "", settings)
}

// One search on a fresh team with plant on m's own indexers, before run first, held to FI-24: the mutant's schedule.
func fs83Mutant(label string, before func(ctx context.Context, team *sidecartest.SearchRemoteTeam) error, plant func(team *sidecartest.SearchRemoteTeam) func(handle sidecar.SubprotocolHandler) sidecar.SubprotocolHandler) *Schedule {
	state := &fs83State{}
	return &Schedule{Id: "FS-83 " + label, Check: []Invariant{FI(24)}, Steps: []*Step{
		{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
			tier, err := net.AdmissionTier()
			if err != nil {
				return err
			}
			state.team, err = sidecartest.NewSearchRemoteTeam(ctx, &sidecartest.SearchRemoteTeamArgs{Tier: tier, Documents: fs83Documents})
			return err
		}},
		{Actor: "mPhone", Action: func(ctx context.Context, net *Net) error {
			if before != nil {
				if err := before(ctx, state.team); err != nil {
					return err
				}
			}
			for _, indexer := range []string{"m desktop", "m nas"} {
				state.team.Indexers[indexer].Plant(plant(state.team))
			}
			_, err := state.search(ctx, net, label)
			return err
		}},
		{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
			state.team.Close()
			return nil
		}},
	}}
}

// D-TEST-16's first regression: an indexer whose page answers in fewer bytes than its step. FI-24 fails it on the
// reply's size, where the same search unplanted passes.
func TestFs83CatchesAnEarlyShortReply(t *testing.T) {
	short := func(team *sidecartest.SearchRemoteTeam) func(handle sidecar.SubprotocolHandler) sidecar.SubprotocolHandler {
		return func(handle sidecar.SubprotocolHandler) sidecar.SubprotocolHandler {
			return func(ctx context.Context, request *sidecar.SubprotocolRequest) ([]byte, error) {
				reply, err := handle(ctx, request)
				if err != nil || len(reply) < 1024 {
					return reply, err
				}
				// the reply cut to its first kilobyte: what an early answer of a short page sends
				return reply[:1024], nil
			}
		}
	}
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	result := Run(t.Context(), fs83Mutant("an early short reply", nil, short), net)
	if result.Err == nil || !strings.Contains(result.Err.Error(), "a reply of 1024 B") {
		t.Fatalf("an early short reply passed FI-24: %v", result)
	}
}

// D-TEST-16's second regression: an indexer that syncs its index before it answers. With a push its index has not
// seen, the sync reads evs while the search runs, and FI-24 fails it on the indexer's requests.
func TestFs83CatchesASyncBeforeAnswering(t *testing.T) {
	syncFirst := func(team *sidecartest.SearchRemoteTeam) func(handle sidecar.SubprotocolHandler) sidecar.SubprotocolHandler {
		return func(handle sidecar.SubprotocolHandler) sidecar.SubprotocolHandler {
			return func(ctx context.Context, request *sidecar.SubprotocolRequest) ([]byte, error) {
				for _, name := range []string{"m desktop", "m nas"} {
					if err := team.Indexers[name].Device.Sync(ctx); err != nil {
						return nil, err
					}
				}
				return handle(ctx, request)
			}
		}
	}
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	// a push the indexers have not synced, which the mutant's sync then reads
	pushed := func(ctx context.Context, team *sidecartest.SearchRemoteTeam) error {
		return team.Worlds["m vault"].PushDocuments(ctx, team.Id("m first"), team.Net.Clock().Now(), []*sidecar.SearchTestDocument{
			{Path: "notes/m-vault/later.md", Version: 1, Title: "a later note", Text: "the harbor again"},
		})
	}
	result := Run(t.Context(), fs83Mutant("a sync before answering", pushed, syncFirst), net)
	if result.Err == nil || !strings.Contains(result.Err.Error(), "evs read") {
		t.Fatalf("a sync before answering passed FI-24: %v", result)
	}
}
