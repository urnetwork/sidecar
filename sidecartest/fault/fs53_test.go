package fault

// FS-53 on T2 (EVSB-M2-11): the registered case (fs53.go) under every rule §22.8 gives the row. It awaits no barrier,
// so it runs on both legs; under sidecar_testhooks, the leg the gate runs, the explorer's seeds order the instances'
// barriers and FI-1 opens every record for the reader.

import (
	"testing"
)

func TestFs53(t *testing.T) {
	RunRow(t, "FS-53", "", nil)
}
