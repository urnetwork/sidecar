//go:build sidecar_testhooks

package evsservice

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// An unrelated commit wins after step 5 and just before the conditional head write. Only the signed
// precondition prevents the disjoint push from committing on the retry.
func TestPushExactHeadRechecksAfterCasConflict(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "seed")
	token := fixture.token(fixture.check.signerId)
	confirmed := fixture.plan()
	confirmed.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_EXACT_HEAD)
	fixture.create(confirmed, "confirmed")
	body := fixture.body(confirmed)
	other := fixture.plan()
	fixture.create(other, "elsewhere")
	otherBody := fixture.body(other)
	reached := atBarrierOnce(t, BarrierHeadCasBefore, barrierRefKey(fixture.check.repoId, fixture.check.refId), func() {
		fixture.requireCommitted(fixture.post(token, otherBody), 2)
	})
	requireRefusal(t, fixture.post(token, body), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
	if head := fixture.head(); *reached != 1 || head.Version() != 2 || !bytes.Equal(head.Head.GetPushId(), other.PushId.Bytes()) {
		t.Fatalf("CAS attempted %d times; head %v", *reached, head.Head)
	}
}
