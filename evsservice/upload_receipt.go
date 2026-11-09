// Upload receipts (§11.13's receipt, push and keys rows, D-EVS-34; EVSB-M2-09): a segment PUT that stores, or finds,
// its segment answers an EvsUploadReceipt, unsigned and MAC'd under evs's receipt key, and nothing is written to the
// metadata cluster. A push and each part carry one receipt per new segment, and step 5's check h, CheckUploadReceipt,
// adopts a segment only with a receipt whose mac is valid, for this repo, whose uploader is the push's signer and
// whose upload_ms is under 24 h old by evs's clock: parts at part time, and their records keep their receipts, whose
// age the seal checks again (EVS1-M2-11, EVS1-M2-13).
//
// The mac is the first 16 B of HMAC-SHA256 under the key key_id names over fields 1-6 and 8, encoded at fixed
// widths so no two receipts share an input:
//
//	"UR evs 1.0 upload receipt" | repo_id 16 | segment_id 32 | padded_size u64 | upload_ms i64 |
//	uploader_sidecar_id 16 | key_id u32 | versionless u8
//
// Receipt keys (upload_keys.go) rotate monthly, the previous kept 48 h; losing one only makes pending uploads
// re-upload.

package evsservice

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The mac's domain, and its width.
const (
	uploadReceiptMacDomain    = "UR evs 1.0 upload receipt"
	uploadReceiptMacByteCount = 16
	receiptKeyByteCount       = 32
)

var (
	// A receipt that does not verify: a mac under no key evs holds, another repo's, another signer's, or a field
	// out of shape. The push is refused as tampering, before anything is adopted.
	ErrUploadReceiptInvalid = errors.New("evs upload receipt invalid")
	// A receipt 24 h old or more: the push's segment is gone for adoption (409 SEGMENT_GONE), and the client
	// re-uploads.
	ErrUploadReceiptStale = errors.New("evs upload receipt past its age")
)

// The mac's input for receipt, as the file header lays it out.
func uploadReceiptMacInput(receipt *protocol.EvsUploadReceipt) []byte {
	input := make([]byte, 0, len(uploadReceiptMacDomain)+16+32+8+8+16+4+1)
	input = append(input, uploadReceiptMacDomain...)
	input = append(input, receipt.GetRepoId()...)
	input = append(input, receipt.GetSegmentId()...)
	input = binary.BigEndian.AppendUint64(input, receipt.GetPaddedSize())
	input = binary.BigEndian.AppendUint64(input, uint64(receipt.GetUploadMs()))
	input = append(input, receipt.GetUploaderSidecarId()...)
	input = binary.BigEndian.AppendUint32(input, receipt.GetKeyId())
	if receipt.GetVersionless() {
		input = append(input, 1)
	} else {
		input = append(input, 0)
	}
	return input
}

// The mac under key.
func uploadReceiptMac(key []byte, receipt *protocol.EvsUploadReceipt) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(uploadReceiptMacInput(receipt))
	return mac.Sum(nil)[:uploadReceiptMacByteCount]
}

// A receipt for a segment of repoId stored at uploadTime by uploaderId, MAC'd under the key issuing at now.
func IssueUploadReceipt(keys *ReceiptKeys, repoId sidecar.Id, segmentId [32]byte, paddedSize uint64, uploadTime time.Time, uploaderId sidecar.Id, versionless bool, now time.Time) (*protocol.EvsUploadReceipt, error) {
	key, ok := keys.issuing(now)
	if !ok {
		return nil, errors.New("no receipt key issues now")
	}
	receipt := &protocol.EvsUploadReceipt{
		RepoId:            slices.Clone(repoId[:]),
		SegmentId:         slices.Clone(segmentId[:]),
		PaddedSize:        paddedSize,
		UploadMs:          uploadTime.UnixMilli(),
		UploaderSidecarId: slices.Clone(uploaderId[:]),
		KeyId:             key.KeyId,
		Versionless:       versionless,
	}
	receipt.Mac = uploadReceiptMac(key.Key, receipt)
	return receipt, nil
}

// Check h (§11.8; §11.13's push row): see the file header. ErrUploadReceiptStale for one 24 h old or more, else
// ErrUploadReceiptInvalid for any other failure. now is evs's clock.
func CheckUploadReceipt(keys *ReceiptKeys, receipt *protocol.EvsUploadReceipt, repoId sidecar.Id, signerSidecarId sidecar.Id, now time.Time) error {
	if receipt == nil || len(receipt.GetRepoId()) != 16 || len(receipt.GetSegmentId()) != 32 || len(receipt.GetUploaderSidecarId()) != 16 ||
		len(receipt.GetMac()) != uploadReceiptMacByteCount {
		return fmt.Errorf("%w: a field out of shape", ErrUploadReceiptInvalid)
	}
	key, ok := keys.verifying(receipt.GetKeyId(), now)
	if !ok {
		return fmt.Errorf("%w: key %d does not verify", ErrUploadReceiptInvalid, receipt.GetKeyId())
	}
	if !hmac.Equal(uploadReceiptMac(key.Key, receipt), receipt.GetMac()) {
		return fmt.Errorf("%w: mac", ErrUploadReceiptInvalid)
	}
	if sidecar.Id(receipt.GetRepoId()) != repoId {
		return fmt.Errorf("%w: another repo's", ErrUploadReceiptInvalid)
	}
	if sidecar.Id(receipt.GetUploaderSidecarId()) != signerSidecarId {
		return fmt.Errorf("%w: another signer's", ErrUploadReceiptInvalid)
	}
	if keys.settings.AdoptMaxAge <= now.Sub(time.UnixMilli(receipt.GetUploadMs())) {
		return fmt.Errorf("%w: uploaded %s ago", ErrUploadReceiptStale, now.Sub(time.UnixMilli(receipt.GetUploadMs())))
	}
	return nil
}
