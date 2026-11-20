package fault

// FS-45 on T2 (QUOTA-M2-13): the registered case and the clauses of fs45.go, each under every rule §22.8 gives the row,
// on the relayed reservation rule's twin over the Net's fake Quota. No schedule here holds a barrier, so these run on
// both legs.

import (
	"testing"
)

func TestFs45(t *testing.T) {
	RunRow(t, "FS-45", "", nil)
}

func TestFs45StreamBoundPairIsUnaffected(t *testing.T) {
	RunRegisteredClause(t, "FS-45", "stream-bound pair is unaffected", nil)
}

func TestFs45OneDebitPerContract(t *testing.T) {
	RunRegisteredClause(t, "FS-45", "one debit per contract", nil)
}

func TestFs45RedisLossOverAdmitsByTheOutstandingGrants(t *testing.T) {
	RunRegisteredClause(t, "FS-45", "redis loss over-admits by the outstanding grants", nil)
}
