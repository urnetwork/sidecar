//go:build sidecar_testhooks

// FS-68 on T2 (EVS2-M10-31): the transitions, the registered case, and each further clause (fs68.go) under every rule
// §22.8 gives the row. The lock clause holds an evs instance at a barrier, so this needs the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs68(t *testing.T) {
	RunRow(t, "FS-68", "", nil)
}

func TestFs68Rules(t *testing.T) {
	RunRegisteredClause(t, "FS-68", "rules", nil)
}

func TestFs68PlatformRule(t *testing.T) {
	RunRegisteredClause(t, "FS-68", "platform rule", nil)
}

func TestFs68Config(t *testing.T) {
	RunRegisteredClause(t, "FS-68", "config", nil)
}

func TestFs68Mailcfg(t *testing.T) {
	RunRegisteredClause(t, "FS-68", "mailcfg", nil)
}

func TestFs68Lock(t *testing.T) {
	RunRegisteredClause(t, "FS-68", "lock", nil)
}
