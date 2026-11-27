package main

import (
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// ur status's fronts lines (DESIGN-COMPUTE §8.5, §21.7; GW-M12-03): none while no port is held; a warning while no
// recorder is set, since every call is refused (IC-19); the calls running and kept; and hosted search's warnings.
func TestUrGatewayFrontsLines(t *testing.T) {
	if lines := urGatewayFrontsLines(&sidecar.GatewayServerStatus{}, &sidecar.GatewayFrontsStatus{}); len(lines) != 0 {
		t.Errorf("lines with no port held: %v", lines)
	}
	held := &sidecar.GatewayServerStatus{Port: 21000, Hold: true, Serving: true}
	lines := urGatewayFrontsLines(held, &sidecar.GatewayFrontsStatus{
		Running:              2,
		Kept:                 3,
		HostedSearchWarnings: []string{"codex sent hosted web search 4 times"},
	})
	text := strings.Join(lines, "\n")
	for _, want := range []string{"model calls are refused", "2 call(s) running, 3 answer(s) kept", "warning:  codex sent hosted web search"} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in:\n%s", want, text)
		}
	}
	if lines := urGatewayFrontsLines(held, &sidecar.GatewayFrontsStatus{Recording: true}); len(lines) != 0 {
		t.Errorf("lines for a quiet gateway: %v", lines)
	}
}
