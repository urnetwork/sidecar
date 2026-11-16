// The values the edge issues for each preamble it accepts (D-SMTP-6, §14.6): send_id, X-UR-Ref and
// Feedback-ID, at plan-SMTP-small-readings#3's and #4's exact widths, so the sidecar knows every
// header's length before the edge answers (plan-SMTP-preamble-byte-count), and
// testdata/smtp/x-ur-ref's vectors fix the bytes.
//
//	X-UR-Ref:    1.<base32(key_id ‖ send_id[12] ‖ HMAC-SHA256(key, send_id ‖ network_id ‖ day)[0:8])>
//	Feedback-ID: <class>:<tier>:<nettoken>:urnetwork
//
// The edge reads the network from the ticket, never from the sidecar, so a sidecar can neither name
// another network in a reference nor replay one under it: the MAC covers send_id, the network id and
// the UTC day (§22.5's X-UR-Ref MAC). A reference has exactly one textual form, lowercase and with the
// last character's unused bits clear, so a report cannot present one send under two names.
//
// The widths here are the encoding's layout, fixed with its version, not limits a deployment chooses,
// so they stay constants as smtp_frame.go's header layout does. X-UR-Ref keys come from vault through
// SmtpEdgeSettings.XUrRefKeys, by key_id, so a rotation overlaps: the edge issues under
// XUrRefIssueKeyId and verifies under any key it holds. A key is hooked once, as the edge takes it
// (testHookSecret), and never reaches a log, a metric or an answer.

package smtpedgeservice

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

// X-UR-Ref's layout (plan-SMTP-small-readings#3).
const (
	// The version, ahead of the base32.
	smtpXUrRefPrefix = "1."
	// send_id: 12 random octets, which the send record keys by (§2.8 smtp-3).
	SmtpSendIdByteCount = 12
	// The truncated HMAC-SHA256.
	smtpXUrRefMacByteCount = 8
	// key_id ‖ send_id ‖ MAC.
	smtpXUrRefByteCount = 1 + SmtpSendIdByteCount + smtpXUrRefMacByteCount
)

// Feedback-ID's layout (plan-SMTP-small-readings#4): the class, tier and token, then this.
const smtpFeedbackIdSuffix = ":urnetwork"

// Feedback-ID's classes: network mail, and a burner's, whose token is its network's (plan-SMTP-net-token).
const (
	smtpFeedbackClassNetwork = "n"
	smtpFeedbackClassBurner  = "b"
)

// QuotaLimits.Tier's names (§20.5) and the letter Feedback-ID gives each.
const (
	smtpTierCommunity = "free"
	smtpTierPro       = "pro"
	smtpTierTeam      = "team"
)

var smtpFeedbackTierLetters = map[string]string{
	smtpTierCommunity: "c",
	smtpTierPro:       "p",
	smtpTierTeam:      "t",
}

// The lowercase unpadded base32 every issued value uses (RFC 4648 §6's alphabet, lowercased).
var smtpBase32Lower = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

var (
	// An X-UR-Ref that does not verify: malformed, under a key the edge does not hold, or with a MAC
	// that does not match the network and day.
	ErrSmtpXUrRefInvalid = errors.New("x-ur-ref invalid")
	// An issued value whose inputs are malformed: a key, send_id, tier or token of the wrong form.
	ErrSmtpIssueRefused = errors.New("smtp issue refused")
)

// One X-UR-Ref key, by its id.
type SmtpXUrRefKey struct {
	// 1 to 255: the reference's first octet.
	KeyId uint8
	// At least SmtpEdgeSettings.XUrRefKeyMinByteCount random octets. Never logged (I-7).
	Key []byte
}

// An X-UR-Ref's octets, which ParseSmtpXUrRef gives before any MAC is checked, so attribution can find
// the send its send_id names and then verify it under that send's network and day (SMTP-M9-15).
type SmtpXUrRef struct {
	KeyId uint8
	// SmtpSendIdByteCount octets.
	SendId []byte
	// smtpXUrRefMacByteCount octets.
	Mac []byte
}

// The UTC day t falls on, counted from the Unix epoch, as the MAC covers it: SmtpSendDay as a u32.
func SmtpXUrRefDay(t time.Time) uint32 {
	day := SmtpSendDay(t)
	if day < 0 {
		return 0
	}
	return uint32(day)
}

// A fresh send_id: SmtpSendIdByteCount octets from crypto/rand.
func NewSmtpSendId() ([]byte, error) {
	sendId := make([]byte, SmtpSendIdByteCount)
	if _, err := rand.Read(sendId); err != nil {
		return nil, err
	}
	return sendId, nil
}

// HMAC-SHA256(key, send_id ‖ network_id ‖ day)[0:8].
func smtpXUrRefMac(key []byte, sendId []byte, networkId sidecar.Id, day uint32) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(sendId)
	mac.Write(networkId[:])
	var dayOctets [4]byte
	binary.BigEndian.PutUint32(dayOctets[:], day)
	mac.Write(dayOctets[:])
	return mac.Sum(nil)[:smtpXUrRefMacByteCount]
}

// The reference's text.
func (self *SmtpXUrRef) String() string {
	raw := make([]byte, 0, smtpXUrRefByteCount)
	raw = append(raw, self.KeyId)
	raw = append(raw, self.SendId...)
	raw = append(raw, self.Mac...)
	return smtpXUrRefPrefix + smtpBase32Lower.EncodeToString(raw)
}

// The X-UR-Ref for one send of networkId on day, under key.
func IssueSmtpXUrRef(key *SmtpXUrRefKey, sendId []byte, networkId sidecar.Id, day uint32) (string, error) {
	if key == nil || key.KeyId == 0 || len(key.Key) == 0 {
		return "", fmt.Errorf("%w: no key", ErrSmtpIssueRefused)
	}
	if len(sendId) != SmtpSendIdByteCount {
		return "", fmt.Errorf("%w: a %d-octet send_id", ErrSmtpIssueRefused, len(sendId))
	}
	if networkId == (sidecar.Id{}) {
		return "", fmt.Errorf("%w: no network", ErrSmtpIssueRefused)
	}
	ref := &SmtpXUrRef{KeyId: key.KeyId, SendId: sendId, Mac: smtpXUrRefMac(key.Key, sendId, networkId, day)}
	return ref.String(), nil
}

// The reference's octets, refusing anything but its one canonical form. Nothing here checks the MAC.
func ParseSmtpXUrRef(text string) (*SmtpXUrRef, error) {
	if len(text) != len(smtpXUrRefPrefix)+smtpBase32Lower.EncodedLen(smtpXUrRefByteCount) || text[:len(smtpXUrRefPrefix)] != smtpXUrRefPrefix {
		return nil, fmt.Errorf("%w: not version 1's form", ErrSmtpXUrRefInvalid)
	}
	encoded := text[len(smtpXUrRefPrefix):]
	raw, err := smtpBase32Lower.DecodeString(encoded)
	if err != nil || len(raw) != smtpXUrRefByteCount {
		return nil, fmt.Errorf("%w: not base32", ErrSmtpXUrRefInvalid)
	}
	// the decoder ignores the last character's unused bits, so a second spelling would decode alike
	if smtpBase32Lower.EncodeToString(raw) != encoded {
		return nil, fmt.Errorf("%w: not the canonical form", ErrSmtpXUrRefInvalid)
	}
	return &SmtpXUrRef{
		KeyId:  raw[0],
		SendId: raw[1 : 1+SmtpSendIdByteCount],
		Mac:    raw[1+SmtpSendIdByteCount:],
	}, nil
}

// The reference, verified under whichever of keys its key_id names, for networkId on day. A key the
// edge no longer holds, another network or another day all fail alike.
func VerifySmtpXUrRef(keys []*SmtpXUrRefKey, text string, networkId sidecar.Id, day uint32) (*SmtpXUrRef, error) {
	ref, err := ParseSmtpXUrRef(text)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if key == nil || key.KeyId != ref.KeyId || len(key.Key) == 0 {
			continue
		}
		if hmac.Equal(smtpXUrRefMac(key.Key, ref.SendId, networkId, day), ref.Mac) {
			return ref, nil
		}
		return nil, fmt.Errorf("%w: the MAC does not match", ErrSmtpXUrRefInvalid)
	}
	return nil, fmt.Errorf("%w: a key id the edge does not hold", ErrSmtpXUrRefInvalid)
}

// The Feedback-ID for a network's mail, or with burner a burner's, whose token is its network's
// (plan-SMTP-net-token). tier is QuotaLimits.Tier and netToken the network's report_token.
func IssueSmtpFeedbackId(burner bool, tier string, netToken string) (string, error) {
	letter, ok := smtpFeedbackTierLetters[tier]
	if !ok {
		return "", fmt.Errorf("%w: a tier this build does not know", ErrSmtpIssueRefused)
	}
	if !smtpReportTokenPattern.MatchString(netToken) {
		return "", fmt.Errorf("%w: a network token not of report_token's form", ErrSmtpIssueRefused)
	}
	class := smtpFeedbackClassNetwork
	if burner {
		class = smtpFeedbackClassBurner
	}
	return class + ":" + letter + ":" + netToken + smtpFeedbackIdSuffix, nil
}

// The edge's issuing state: the keys it holds, by id, and the one it issues under.
type smtpIssuer struct {
	keys     []*SmtpXUrRefKey
	issueKey *SmtpXUrRefKey
}

// The issuer settings name, or nil when they hold no X-UR-Ref key, which leaves the edge not ready.
// Each key is hooked as the edge takes it.
func newSmtpIssuer(settings *SmtpEdgeSettings) *smtpIssuer {
	issuer := &smtpIssuer{}
	for _, key := range settings.XUrRefKeys {
		if key == nil {
			continue
		}
		testHookSecret("smtp_x_ur_ref_key", key.Key)
		issuer.keys = append(issuer.keys, key)
		if int(key.KeyId) == settings.XUrRefIssueKeyId {
			issuer.issueKey = key
		}
	}
	if issuer.issueKey == nil {
		return nil
	}
	return issuer
}

// What one accepted preamble carries out: a fresh send_id and the two headers it names.
type smtpIssued struct {
	SendId     []byte
	XUrRef     string
	FeedbackId string
	// The X-UR-Ref key's id, which the send record keeps (§2.8 smtp-3).
	KeyId uint8
}

// A send's issued values, at now's UTC day.
func (self *smtpIssuer) issue(networkId sidecar.Id, burner bool, tier string, netToken string, now time.Time) (*smtpIssued, error) {
	feedbackId, err := IssueSmtpFeedbackId(burner, tier, netToken)
	if err != nil {
		return nil, err
	}
	sendId, err := NewSmtpSendId()
	if err != nil {
		return nil, err
	}
	xUrRef, err := IssueSmtpXUrRef(self.issueKey, sendId, networkId, SmtpXUrRefDay(now))
	if err != nil {
		return nil, err
	}
	return &smtpIssued{SendId: sendId, XUrRef: xUrRef, FeedbackId: feedbackId, KeyId: self.issueKey.KeyId}, nil
}
