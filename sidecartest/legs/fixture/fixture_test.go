//go:build sidecar_legs_fixture

// The every-leg runner's own fixture (TEST-M1-07): a test that passes on every leg, and a vector whose
// bytes are planted to differ on wasm, so a run over two legs shows a mismatch failing the one leg it
// happened on and naming it. Only legs_test.go builds it, under its tag.

package fixture

import (
	"runtime"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest/vector"
)

func TestFixturePasses(t *testing.T) {
	if runtime.GOOS == "" {
		t.Fatal("no GOOS")
	}
}

func TestFixtureVector(t *testing.T) {
	expected := []vector.Expected{{Name: "planted", Output: []byte("the same on every leg")}}
	settings := &vector.Settings{Maxprocs: []int{1, 16}, Repeats: 2, Zones: []string{"UTC"}, Locales: []string{"C"}}
	vector.Check(t, settings, expected, func() ([]vector.Case, error) {
		output := "the same on every leg"
		if runtime.GOARCH == "wasm" {
			output = "planted on wasm"
		}
		return []vector.Case{{Name: "planted", Output: []byte(output)}}, nil
	})
}
