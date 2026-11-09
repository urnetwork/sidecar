package evsservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

func testReceiptKey(keyId uint32, issueFrom time.Time) *ReceiptKey {
	key := sha256.Sum256([]byte{byte(keyId)})
	return &ReceiptKey{KeyId: keyId, Key: key[:], IssueFrom: issueFrom}
}

func testReceiptKeys(t testing.TB, keys ...*ReceiptKey) *ReceiptKeys {
	t.Helper()
	receiptKeys, err := NewReceiptKeys(keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	return receiptKeys
}

// Check h: a receipt for this repo by the push's signer under 24 h old passes; another repo's, another signer's, a
// forged one and one 24 h old do not.
func TestUploadReceiptCheckH(t *testing.T) {
	start := governorTestStart()
	keys := testReceiptKeys(t, testReceiptKey(1, start.Add(-time.Hour)))
	repoId := testIdFrom("receipt repo")
	signer := testIdFrom("receipt signer")
	segmentId := sha256.Sum256([]byte("segment"))
	receipt, err := IssueUploadReceipt(keys, repoId, segmentId, 4096, start, signer, false, start)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckUploadReceipt(keys, receipt, repoId, signer, start.Add(24*time.Hour-time.Millisecond)); err != nil {
		t.Fatalf("a receipt just under 24 h: %v", err)
	}
	if err := CheckUploadReceipt(keys, receipt, repoId, signer, start.Add(24*time.Hour)); !errors.Is(err, ErrUploadReceiptStale) {
		t.Fatalf("a receipt 24 h old: %v", err)
	}
	if err := CheckUploadReceipt(keys, receipt, testIdFrom("other repo"), signer, start); !errors.Is(err, ErrUploadReceiptInvalid) {
		t.Fatalf("another repo's: %v", err)
	}
	if err := CheckUploadReceipt(keys, receipt, repoId, testIdFrom("other signer"), start); !errors.Is(err, ErrUploadReceiptInvalid) {
		t.Fatalf("another signer's: %v", err)
	}
	forged := proto.Clone(receipt).(*protocol.EvsUploadReceipt)
	forged.UploadMs += 1
	if err := CheckUploadReceipt(keys, forged, repoId, signer, start); !errors.Is(err, ErrUploadReceiptInvalid) {
		t.Fatalf("a forged upload_ms: %v", err)
	}
	unkeyed := proto.Clone(receipt).(*protocol.EvsUploadReceipt)
	unkeyed.KeyId = 9
	if err := CheckUploadReceipt(keys, unkeyed, repoId, signer, start); !errors.Is(err, ErrUploadReceiptInvalid) {
		t.Fatalf("a key evs never held: %v", err)
	}
}

// Keys rotate: the newest issues, and the previous verifies for 48 h past the rotation, then no longer.
func TestUploadReceiptKeysRotate(t *testing.T) {
	start := governorTestStart()
	rotation := start.Add(30 * 24 * time.Hour)
	keys := testReceiptKeys(t, testReceiptKey(1, start), testReceiptKey(2, rotation))
	repoId := testIdFrom("receipt repo")
	signer := testIdFrom("receipt signer")
	segmentId := sha256.Sum256([]byte("segment"))
	before, err := IssueUploadReceipt(keys, repoId, segmentId, 1, rotation.Add(-time.Minute), signer, false, rotation.Add(-time.Minute))
	if err != nil || before.GetKeyId() != 1 {
		t.Fatalf("before the rotation: %v %v", before, err)
	}
	after, err := IssueUploadReceipt(keys, repoId, segmentId, 1, rotation, signer, false, rotation)
	if err != nil || after.GetKeyId() != 2 {
		t.Fatalf("after the rotation: %v %v", after, err)
	}
	if err := CheckUploadReceipt(keys, before, repoId, signer, rotation.Add(time.Hour)); err != nil {
		t.Fatalf("the previous key an hour after: %v", err)
	}
	// past 48 h the previous key no longer verifies, a receipt it issued long past adoption anyway
	if _, ok := keys.verifying(1, rotation.Add(48*time.Hour)); ok {
		t.Fatal("the previous key verifies 48 h past the rotation")
	}
	if _, err := NewReceiptKeys([]*ReceiptKey{testReceiptKey(1, start), testReceiptKey(1, rotation)}, nil); err == nil {
		t.Fatal("one key id twice")
	}
	if _, err := NewReceiptKeys([]*ReceiptKey{{KeyId: 1, Key: []byte("short")}}, nil); err == nil {
		t.Fatal("a short key")
	}
}

// testdata/evs/receipt/'s vector pins the mac's input layout. EVS_RECEIPT_VECTORS_WRITE=1 rewrites it.
type receiptVector struct {
	KeyHex     string `json:"key_hex"`
	ReceiptHex string `json:"receipt_hex"`
	MacHex     string `json:"mac_hex"`
}

func buildReceiptVector(t testing.TB) (*ReceiptKeys, *protocol.EvsUploadReceipt, sidecar.Id, sidecar.Id, time.Time) {
	issued := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	keys := testReceiptKeys(t, testReceiptKey(7, issued.Add(-time.Hour)))
	repoId := testIdFrom("vector repo")
	signer := testIdFrom("vector signer")
	segmentId := sha256.Sum256([]byte("vector segment"))
	receipt, err := IssueUploadReceipt(keys, repoId, segmentId, 1088*1024, issued, signer, false, issued)
	if err != nil {
		t.Fatal(err)
	}
	return keys, receipt, repoId, signer, issued
}

func TestUploadReceiptVectors(t *testing.T) {
	keys, receipt, repoId, signer, issued := buildReceiptVector(t)
	receiptBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := keys.verifying(7, issued)
	got := &receiptVector{KeyHex: hex.EncodeToString(key.Key), ReceiptHex: hex.EncodeToString(receiptBytes), MacHex: hex.EncodeToString(receipt.GetMac())}
	path := filepath.Join("..", "testdata", "evs", "receipt", "receipt_vector.json")
	if os.Getenv("EVS_RECEIPT_VECTORS_WRITE") == "1" {
		encoded, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wantBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := &receiptVector{}
	if err := json.Unmarshal(wantBytes, want); err != nil {
		t.Fatal(err)
	}
	if *got != *want {
		t.Fatalf("the vector moved: got %+v, want %+v", got, want)
	}
	if err := CheckUploadReceipt(keys, receipt, repoId, signer, issued); err != nil {
		t.Fatal(err)
	}
}

// §22.6's FuzzEvsUploadReceipt: tampering fails before adoption. Any bytes that decode to a receipt passing check h
// carry the issued receipt's fields and mac exactly.
func FuzzEvsUploadReceipt(f *testing.F) {
	keys, receipt, repoId, signer, issued := buildReceiptVector(f)
	receiptBytes, err := proto.Marshal(receipt)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(receiptBytes)
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded := &protocol.EvsUploadReceipt{}
		if err := proto.Unmarshal(data, decoded); err != nil {
			return
		}
		if err := CheckUploadReceipt(keys, decoded, repoId, signer, issued); err != nil {
			return
		}
		same := bytes.Equal(decoded.GetRepoId(), receipt.GetRepoId()) && bytes.Equal(decoded.GetSegmentId(), receipt.GetSegmentId()) &&
			decoded.GetPaddedSize() == receipt.GetPaddedSize() && decoded.GetUploadMs() == receipt.GetUploadMs() &&
			bytes.Equal(decoded.GetUploaderSidecarId(), receipt.GetUploaderSidecarId()) && decoded.GetKeyId() == receipt.GetKeyId() &&
			decoded.GetVersionless() == receipt.GetVersionless() && bytes.Equal(decoded.GetMac(), receipt.GetMac())
		if !same {
			t.Fatalf("a tampered receipt passed check h: %v", decoded)
		}
	})
}
