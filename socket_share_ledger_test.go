//go:build !sidecar_http && !ios_extension && !js

// §9.9's share record (socket_share_ledger.go): rows fold in the sharer's order and any other reads as a failure, a
// record survives a reopen of the store, sealed under its class so its secret is never on the medium in the clear, and
// a share is finished by a Remove or by a Done for each use.

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// A record that add would write, its secret named by label.
func testShareRecord(token string, uses uint32) *socketShareRecord {
	return &socketShareRecord{
		Token:        token,
		Path:         "/synthetic/data.bin",
		Size:         4,
		MtimeNanos:   1,
		Sha256:       bytes.Repeat([]byte{0x11}, 32),
		Secret:       bytes.Repeat([]byte{0x77}, socketShareSecretByteCount),
		Uses:         uses,
		ExpireMillis: 1_000_000,
	}
}

// One row's bytes, as appendSocketShareRow writes them.
func testShareRowBytes(t *testing.T, body socketShareRowBody) []byte {
	t.Helper()
	encodedBody, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(&socketShareRow{Kind: body.socketShareRowKind(), Body: encodedBody})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// Folds rows into a fresh state, the first error ending it.
func testShareFold(t *testing.T, rows ...[]byte) (*socketShareState, error) {
	t.Helper()
	state := newSocketShareState()
	for _, encoded := range rows {
		row := &socketShareRow{}
		if err := json.Unmarshal(encoded, row); err != nil {
			return nil, err
		}
		if err := state.apply(row); err != nil {
			return nil, err
		}
	}
	return state, nil
}

// The sharer's order folds; every row it would not write after those before it is a failure, never a skip.
func TestShareLedgerFoldsTheSharersOrder(t *testing.T) {
	token := "abcdefghijklmnopqrstuvwxyz"
	share := testShareRowBytes(t, testShareRecord(token, 2))
	getA, getB := testSocketId("get a"), testSocketId("get b")
	getter := testSocketId("getter")
	reserveA := testShareRowBytes(t, &socketShareReserve{GetId: getA, UseIndex: 0, GetterSidecarId: getter, Millis: 1})
	reserveB := testShareRowBytes(t, &socketShareReserve{GetId: getB, UseIndex: 1, GetterSidecarId: getter, Millis: 2})
	doneA := testShareRowBytes(t, &socketShareDoneRow{GetId: getA, Millis: 3})
	doneB := testShareRowBytes(t, &socketShareDoneRow{GetId: getB, Millis: 4})
	state, err := testShareFold(t, share, reserveA, doneA, reserveB)
	if err != nil || len(state.reserves) != 2 || state.remaining() != 0 || state.finished() {
		t.Fatalf("%+v %v", state, err)
	}
	if state, err := testShareFold(t, share, reserveA, doneA, reserveB, doneB); err != nil || !state.finished() {
		t.Errorf("two Dones of two uses: %v", err)
	}
	if state, err := testShareFold(t, share, testShareRowBytes(t, &socketShareRemove{Millis: 5})); err != nil || !state.finished() {
		t.Errorf("a Remove: %v", err)
	}
	unlimited, err := testShareFold(t, testShareRowBytes(t, testShareRecord(token, 0)), reserveA, doneA)
	if err != nil || unlimited.finished() || unlimited.remaining() != -1 {
		t.Errorf("an unlimited share: %v", err)
	}

	refused := map[string][][]byte{
		"a reserve first":         {reserveA},
		"two share rows":          {share, share},
		"a skipped use index":     {share, reserveB},
		"a get_id reserved twice": {share, reserveA, testShareRowBytes(t, &socketShareReserve{GetId: getA, UseIndex: 1, GetterSidecarId: getter})},
		"a done never reserved":   {share, doneA},
		"a done twice":            {share, reserveA, doneA, doneA},
		"no getter":               {share, testShareRowBytes(t, &socketShareReserve{GetId: getA, UseIndex: 0})},
		"an unknown row":          {share, []byte(`{"row":"refund","body":{}}`)},
		"a secret cut short": {testShareRowBytes(t, &socketShareRecord{Token: token, Path: "/p", Size: 1, Sha256: bytes.Repeat([]byte{1}, 32),
			Secret: []byte("short"), ExpireMillis: 1})},
		"a token of another form": {testShareRowBytes(t, testShareRecord("not-a-token", 1))},
	}
	for name, rows := range refused {
		if _, err := testShareFold(t, rows...); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A record survives the store's reopen through the instance, reads back whole, and holds its secret only sealed: the
// medium never carries it in the clear. Deleting it leaves nothing.
func TestShareLedgerSurvivesReopenSealed(t *testing.T) {
	instance, backend, _ := enrolledInstance(t)
	ledger, err := newSocketShareLedger(instance.Store(&testNetworkId))
	if err != nil {
		t.Fatal(err)
	}
	token := "abcdefghijklmnopqrstuvwxyz"
	log, err := ledger.log(token)
	if err != nil {
		t.Fatal(err)
	}
	state := newSocketShareState()
	record := testShareRecord(token, 1)
	if err := appendSocketShareRow(log, state, record); err != nil {
		t.Fatal(err)
	}
	if err := appendSocketShareRow(log, state, &socketShareReserve{GetId: testSocketId("get"), UseIndex: 0, GetterSidecarId: testSocketId("getter"), Millis: 1}); err != nil {
		t.Fatal(err)
	}
	reopened, err := newSocketShareLedger(instance.Store(&testNetworkId))
	if err != nil {
		t.Fatal(err)
	}
	read, err := reopened.read(token)
	if err != nil || len(read.reserves) != 1 || !bytes.Equal(read.share.Secret, record.Secret) {
		t.Fatalf("%+v %v", read, err)
	}
	if tokens, err := reopened.tokens(); err != nil || len(tokens) != 1 || tokens[0] != token {
		t.Errorf("tokens %q %v", tokens, err)
	}
	for path, content := range backendSnapshot(t, backend) {
		if bytes.Contains(content, record.Secret) {
			t.Errorf("%s holds the secret in the clear", path)
		}
	}
	if err := reopened.remove(token); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.read(token); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("after the delete: %v", err)
	}
	if err := reopened.remove(token); err != nil {
		t.Errorf("a second delete: %v", err)
	}
}
