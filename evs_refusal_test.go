// The two codes owner decision 411 adds to §11.8's table (question evs1-m2-07-placement-refusal-code, QD-927), so
// every answer of evs's but a 200 carries a code: REPO_PLACED, the placement's 409, and UNAUTHENTICATED, every route's
// 401.

package sidecar

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// REPO_PLACED is 409 and final, UNAUTHENTICATED 401 and refuses nothing; neither is a code a head's record may hold,
// so neither is recorded nor decoded from a head, and each has its own number in its range.
func TestEvsRefusalTableHoldsRepoPlacedAndUnauthenticated(t *testing.T) {
	statementSha256 := sha256.Sum256([]byte("statement"))
	cases := []struct {
		code           protocol.EvsRefusalCode
		number         int
		status         int
		refusesNothing bool
	}{
		{code: protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED, number: 76, status: http.StatusConflict},
		{code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAUTHENTICATED, number: 137, status: http.StatusUnauthorized, refusesNothing: true},
	}
	for _, c := range cases {
		if int(c.code) != c.number {
			t.Errorf("%s is %d, want %d", c.code, c.code, c.number)
		}
		if status, ok := EvsRefusalStatus(c.code); !ok || status != c.status {
			t.Errorf("%s answers %d (%t), want %d", c.code, status, ok, c.status)
		}
		if EvsRefusalRecordable(c.code) || EvsRefusalRefusesNothing(c.code) != c.refusesNothing {
			t.Errorf("%s: recordable %t, refuses nothing %t", c.code, EvsRefusalRecordable(c.code), EvsRefusalRefusesNothing(c.code))
		}
		if _, err := NewEvsRefusal(evsTestId("push"), statementSha256, c.code, 1000); !errors.Is(err, ErrEvsRefusalInvalid) {
			t.Errorf("%s recorded: %v", c.code, err)
		}
		record, err := NewEvsRefusal(evsTestId("push"), statementSha256, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE, 1000)
		if err != nil {
			t.Fatal(err)
		}
		encoded := record.Encode()
		binary.BigEndian.PutUint16(encoded[10:12], uint16(c.code))
		if _, err := DecodeEvsRefusal(encoded); !errors.Is(err, ErrEvsRefusalInvalid) {
			t.Errorf("a head's record holding %s decoded: %v", c.code, err)
		}
	}
	// only code 0 is outside the table, so no answer but a 200 goes out without a code
	if _, ok := EvsRefusalStatus(protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED); ok {
		t.Error("code 0 has a status")
	}
	for number, name := range protocol.EvsRefusalCode_name {
		if _, ok := EvsRefusalStatus(protocol.EvsRefusalCode(number)); !ok && number != 0 {
			t.Errorf("%s has no status", name)
		}
	}
}

// IsEvsRepoPlaced finds REPO_PLACED however it is wrapped, and no other 409: STATEMENT_MISSING's lifecycle 409 keeps
// the id, and a 409 whose code is not believed is no placement.
func TestIsEvsRepoPlacedTellsThePlacementFromALifecycle409(t *testing.T) {
	placed := &EvsError{Status: http.StatusConflict, Code: protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED}
	if !IsEvsRepoPlaced(placed) || !IsEvsRepoPlaced(fmt.Errorf("creating: %w", placed)) {
		t.Error("REPO_PLACED not found")
	}
	for _, err := range []error{
		&EvsError{Status: http.StatusConflict, Code: protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING},
		&EvsError{Status: http.StatusConflict},
		&EvsError{Status: http.StatusForbidden, Code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE},
		ErrEvsUnauthorized,
		nil,
	} {
		if IsEvsRepoPlaced(err) {
			t.Errorf("%v read as REPO_PLACED", err)
		}
	}
}
