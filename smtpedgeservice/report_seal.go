// The sealed copy of a report (§14.8, owner decisions 78 and 437): the raw bytes under the network mail key, the
// newest drop key of the repo §15.8 names (D-KEYS-17), kept in smtp_complaint.sealed_report for 30 days, which only
// the network's own readers can open. HPKE-XWing as gkm's deliveries are (QD-441): KEM 0x647a, HKDF-SHA256,
// AES-128-GCM, base mode, through crypto/hpke's Sender. The raw bytes stream through it in chunks of
// SmtpEdgeSettings.ReportSealChunkByteCount, the intake's one pass feeding them to the reporter's body hash in the
// same loop, so they are read once and held whole by no one but the caller.
//
//	sealed_report  u8(1) || enc (1,120 B) || ct_0 || ... || ct_k
//	ct_i           the context's i-th Seal(aad_i, chunk_i): chunk_i is 65,536 B but the last, which holds
//	               0 to 65,536 B, so an empty report is one empty final chunk
//	aad_i          u8(1) || network_id (16 B) || u64be(arrival ms) || u8(1 for the last chunk, else 0)
//	info           "UR smtp 1.0 report"
//
// The context's sequence orders the chunks, the final flag ends them, and the network and arrival bind a copy to its
// row, so a copy moved to another row does not open. The key comes from SmtpReportKeySource, which a block serves
// from api's gate read surface (report_key_source.go, plan-SMTP-report-seal-key): until a network's mailbox has a
// drop key api verifies, there is nothing to seal to, and the raw bytes are dropped unread.
//
// The seal creates no key of its own outside crypto/hpke, so nothing here passes through testHookSecret.

package smtpedgeservice

import (
	"context"
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

const (
	smtpSealVersion = 1
	smtpSealInfo    = "UR smtp 1.0 report"
	// X-Wing's encapsulation.
	smtpSealEncapsulationByteCount = 1120
	// AES-128-GCM's tag.
	smtpSealTagByteCount = 16
)

// A sealed copy that does not open: the wrong key, another row's copy, or bytes changed.
var ErrSmtpSealedReportOpen = errors.New("smtp sealed report does not open")

// Where the intake learns a network's mail key: in a block, api's gate read surface (SmtpReportKeyGateSource,
// plan-SMTP-report-seal-key decided as its option 1), which verifies the key against the network's rows before it
// answers. Safe for concurrent use.
type SmtpReportKeySource interface {
	// The network mail key's X-Wing public key, newest generation only, so a removed reader is never sealed to
	// (D-KEYS-17). nil and no error when the network has none to seal to: no mailbox yet, as every network before
	// M7, or a newest drop key that fails a check. An error when the source cannot tell now, so the report is taken
	// again later rather than dropped.
	ReportSealKey(ctx context.Context, networkId sidecar.Id) ([]byte, error)
}

// One copy's associated data for a chunk.
func smtpSealAad(networkId sidecar.Id, arrival time.Time, final bool) []byte {
	aad := make([]byte, 0, 1+16+8+1)
	aad = append(aad, smtpSealVersion)
	aad = append(aad, networkId[:]...)
	aad = binary.BigEndian.AppendUint64(aad, uint64(arrival.UnixMilli()))
	if final {
		return append(aad, 1)
	}
	return append(aad, 0)
}

// One copy being sealed, chunk by chunk. Not safe for concurrent use.
type smtpReportSealer struct {
	sender         *hpke.Sender
	networkId      sidecar.Id
	arrival        time.Time
	chunkByteCount int
	sealed         []byte
	// The chunk being filled, at most one chunk's worth: a full chunk is sealed only once a further
	// byte shows it is not the last.
	pending []byte
	failed  error
}

// A sealer to publicKey, sized for byteCount octets of report, in chunks of chunkByteCount.
func newSmtpReportSealer(publicKey []byte, networkId sidecar.Id, arrival time.Time, byteCount int, chunkByteCount int) (*smtpReportSealer, error) {
	if chunkByteCount <= 0 {
		return nil, errors.New("smtp report seal: no chunk size")
	}
	key, err := hpke.MLKEM768X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("smtp report seal: the mail key: %w", err)
	}
	encapsulation, sender, err := hpke.NewSender(key, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(smtpSealInfo))
	if err != nil {
		return nil, fmt.Errorf("smtp report seal: hpke setup: %w", err)
	}
	chunkCount := byteCount/chunkByteCount + 1
	sealed := make([]byte, 0, 1+len(encapsulation)+byteCount+chunkCount*smtpSealTagByteCount)
	sealed = append(sealed, smtpSealVersion)
	sealed = append(sealed, encapsulation...)
	return &smtpReportSealer{
		sender:         sender,
		networkId:      networkId,
		arrival:        arrival,
		chunkByteCount: chunkByteCount,
		sealed:         sealed,
		pending:        make([]byte, 0, min(byteCount, chunkByteCount)),
	}, nil
}

// Seals one chunk.
func (self *smtpReportSealer) sealChunk(chunk []byte, final bool) {
	if self.failed != nil {
		return
	}
	ciphertext, err := self.sender.Seal(smtpSealAad(self.networkId, self.arrival, final), chunk)
	if err != nil {
		self.failed = err
		return
	}
	self.sealed = append(self.sealed, ciphertext...)
}

// Takes the report's next octets. A failure surfaces at finish.
func (self *smtpReportSealer) Write(data []byte) (int, error) {
	count := len(data)
	for 0 < len(data) {
		if len(self.pending) == self.chunkByteCount {
			self.sealChunk(self.pending, false)
			self.pending = self.pending[:0]
		}
		take := min(self.chunkByteCount-len(self.pending), len(data))
		self.pending = append(self.pending, data[:take]...)
		data = data[take:]
	}
	return count, nil
}

// Seals the last chunk and returns the copy.
func (self *smtpReportSealer) finish() ([]byte, error) {
	self.sealChunk(self.pending, true)
	self.pending = nil
	if self.failed != nil {
		return nil, fmt.Errorf("smtp report seal: %w", self.failed)
	}
	return self.sealed, nil
}

// A sealed copy's raw bytes, opened with the network mail key's private half for the row it belongs to, in chunks
// of chunkByteCount. Readers open copies on their own devices (§15.8); this is the format's other half, kept beside
// the sealer so the two cannot drift.
func openSmtpSealedReport(privateKey hpke.PrivateKey, networkId sidecar.Id, arrival time.Time, sealed []byte, chunkByteCount int) ([]byte, error) {
	if chunkByteCount <= 0 || len(sealed) < 1+smtpSealEncapsulationByteCount+smtpSealTagByteCount || sealed[0] != smtpSealVersion {
		return nil, ErrSmtpSealedReportOpen
	}
	recipient, err := hpke.NewRecipient(sealed[1:1+smtpSealEncapsulationByteCount], privateKey, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(smtpSealInfo))
	if err != nil {
		return nil, ErrSmtpSealedReportOpen
	}
	ciphertext := sealed[1+smtpSealEncapsulationByteCount:]
	blockByteCount := chunkByteCount + smtpSealTagByteCount
	raw := make([]byte, 0, len(ciphertext))
	for 0 < len(ciphertext) {
		final := len(ciphertext) <= blockByteCount
		block := ciphertext[:min(blockByteCount, len(ciphertext))]
		if len(block) < smtpSealTagByteCount {
			return nil, ErrSmtpSealedReportOpen
		}
		plaintext, err := recipient.Open(smtpSealAad(networkId, arrival, final), block)
		if err != nil {
			return nil, ErrSmtpSealedReportOpen
		}
		raw = append(raw, plaintext...)
		ciphertext = ciphertext[len(block):]
	}
	return raw, nil
}
