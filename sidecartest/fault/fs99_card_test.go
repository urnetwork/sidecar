//go:build sidecar_testhooks

package fault

// FS-99's cards case on T2 (fs99_cards_evs.go): the row's format-2 case under the explorer's seeds, and its mutant.

import (
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFs99Cards(t *testing.T) {
	RunRow(t, "FS-99", "cards", nil)
}

// §7.8's directory rule gone: where X's tokens carry what its client asks for, evs takes its ERASE of A's card's keys,
// and the case fails at that step.
func TestFs99CardsMutantExchangeMintingXAdminFails(t *testing.T) {
	ctx := t.Context()
	net := sidecartest.NewNet(ctx, nil)
	defer net.Close()
	settings := DefaultFs99CardsSettings()
	settings.Mutant = true
	schedule := Fs99CardsOnEvsOf(net, settings)
	schedule.Id = "FS-99's cards mutant"
	result := Run(ctx, schedule, net)
	if result.Err == nil {
		t.Fatal("the mutant passed")
	}
	if !strings.Contains(result.Err.Error(), "was not refused") {
		t.Fatalf("the mutant failed elsewhere: %v", result.Err)
	}
}
