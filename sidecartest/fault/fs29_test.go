// FS-29 on T2 (MCP-M3-24): the registered case under every rule §22.8 gives the row. It holds no barrier, so it runs on
// both legs.

package fault

import (
	"testing"
)

func TestFs29(t *testing.T) {
	RunRow(t, "FS-29", "", nil)
}
