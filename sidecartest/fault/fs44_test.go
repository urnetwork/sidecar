package fault

// FS-44 on T2 (QUOTA-M2-13): the registered case and the clauses of fs44.go, each under every rule §22.8 gives the row,
// on the Net's fake Quota. No schedule here holds a barrier, so these run on both legs.

import (
	"testing"
)

func TestFs44(t *testing.T) {
	RunRow(t, "FS-44", "", nil)
}

func TestFs44LostResponseRetried(t *testing.T) {
	RunRegisteredClause(t, "FS-44", "lost response retried", nil)
}

func TestFs44KilledWithAnAppliedBatchUnanswered(t *testing.T) {
	RunRegisteredClause(t, "FS-44", "killed with an applied batch unanswered", nil)
}

func TestFs44DrainLosesNothing(t *testing.T) {
	RunRegisteredClause(t, "FS-44", "drain loses nothing", nil)
}

func TestFs44ApiUnavailableElevenMinutes(t *testing.T) {
	RunRegisteredClause(t, "FS-44", "api unavailable eleven minutes", nil)
}

func TestFs44EdgeKilledBeforeItsPost(t *testing.T) {
	RunRegisteredClause(t, "FS-44", "edge killed before its post", nil)
}

func TestFs44TwoHostsOnOneBalance(t *testing.T) {
	RunRegisteredClause(t, "FS-44", "two hosts on one balance", nil)
}
