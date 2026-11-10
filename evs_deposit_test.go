// EVS1-M2-29's root tests: §16.8's read-receipt gate fails closed until a depositor is installed, and then deposits
// before anything a read names is decrypted, a refused deposit refusing the read; a writer reads with no receipt. The
// deposits' end-to-end cases, FS-23's M2 case on T2, are sidecartest/evs_deposit_test.go's.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The receipt gate over a mailbox: a reader that does not write it is refused with no depositor; a depositor sees the
// read's objects before they are decrypted and the read goes on; a depositor's refusal refuses the read; and a
// writer reads without one.
func TestEvsReceiptGate(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "", children: []string{"m"}}, &evsTestChange{path: "m", content: []byte("mail"), segment: true})
	world.config.repo.Kind = protocol.RepoKind_REPO_KIND_MAILBOX
	readerId := evsTestId("receipt reader")
	world.config.readers = append(world.config.readers, readerId)
	reader := world.reader(t, readerId)
	if _, _, err := evsTestRead(t, reader, world, "m"); !errors.Is(err, ErrEvsReceiptGate) {
		t.Fatalf("no depositor: %v", err)
	}
	deposited := [][][]byte{}
	reader.client.SetReceiptDepositor(func(ctx context.Context, repoId Id, refId Id, objectIds [][]byte) error {
		deposited = append(deposited, objectIds)
		return nil
	})
	content, _, err := evsTestRead(t, reader, world, "m")
	if err != nil || !bytes.Equal(content, []byte("mail")) || len(deposited) != 1 || len(deposited[0]) != 1 {
		t.Fatalf("with a depositor: %q %v, %d receipts", content, err, len(deposited))
	}
	refused := errors.New("evs answered 429")
	reader.client.SetReceiptDepositor(func(ctx context.Context, repoId Id, refId Id, objectIds [][]byte) error { return refused })
	if _, _, err := evsTestRead(t, reader, world, "m"); !errors.Is(err, ErrEvsReceiptGate) || !errors.Is(err, refused) {
		t.Fatalf("a refused receipt: %v", err)
	}
	writer := world.reader(t, world.signer.sidecarId)
	writer.client.SetReceiptDepositor(nil)
	if _, _, err := evsTestRead(t, writer, world, "m"); err != nil {
		t.Fatalf("a writer: %v", err)
	}
}
