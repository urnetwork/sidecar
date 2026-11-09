// The keys evs MACs upload receipts under (§11.13's keys row, §19.4; EVSB-M2-09): evs configuration from its
// secret files, rotated monthly. The newest key whose IssueFrom has passed issues, and a key keeps verifying until
// KeyRetainAfterRotation past the next key's IssueFrom, so a receipt issued just before a rotation still adopts
// within its 24 h; losing a key only makes pending uploads re-upload. Keys leave the process only as macs, and
// testHookSecret sees each as it is loaded.

package evsservice

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

type UploadReceiptSettings struct {
	// A push adopts a segment only with a receipt under this old: 24 h (I-EVS-5).
	AdoptMaxAge time.Duration
	// An upload finding its segment stored this long ago answers SEGMENT_STALE, so the client re-seals: 23 h.
	ExistingMaxAge time.Duration
	// A key keeps verifying this long after the next key starts issuing: 48 h (§19.4).
	KeyRetainAfterRotation time.Duration
}

func DefaultUploadReceiptSettings() *UploadReceiptSettings {
	return &UploadReceiptSettings{
		AdoptMaxAge:            24 * time.Hour,
		ExistingMaxAge:         23 * time.Hour,
		KeyRetainAfterRotation: 48 * time.Hour,
	}
}

// One receipt key: its id, its 32 B, and when it starts issuing.
type ReceiptKey struct {
	KeyId     uint32
	Key       []byte
	IssueFrom time.Time
}

// evs's receipt keys, newest issuing. Immutable once built; a host rereading its secret file builds a new one.
// Safe for concurrent use.
type ReceiptKeys struct {
	settings *UploadReceiptSettings
	// by IssueFrom
	keys []*ReceiptKey
}

// The keys of evs's secret file, checked: distinct ids, 32 B each. testHookSecret sees each, as it is loaded.
// settings may be nil for the defaults.
func NewReceiptKeys(keys []*ReceiptKey, settings *UploadReceiptSettings) (*ReceiptKeys, error) {
	if settings == nil {
		settings = DefaultUploadReceiptSettings()
	}
	sorted := []*ReceiptKey{}
	for _, key := range keys {
		if len(key.Key) != receiptKeyByteCount {
			return nil, fmt.Errorf("receipt key %d of %d bytes", key.KeyId, len(key.Key))
		}
		if slices.ContainsFunc(sorted, func(other *ReceiptKey) bool { return other.KeyId == key.KeyId }) {
			return nil, fmt.Errorf("receipt key %d twice", key.KeyId)
		}
		testHookSecret("evs_receipt_key", key.Key)
		sorted = append(sorted, &ReceiptKey{KeyId: key.KeyId, Key: slices.Clone(key.Key), IssueFrom: key.IssueFrom})
	}
	if len(sorted) == 0 {
		return nil, errors.New("no receipt key")
	}
	slices.SortFunc(sorted, func(a *ReceiptKey, b *ReceiptKey) int { return a.IssueFrom.Compare(b.IssueFrom) })
	return &ReceiptKeys{settings: settings, keys: sorted}, nil
}

// The secret file's JSON: {"keys": [{"key_id": 1, "key": "<base64 of 32 B>", "issue_from_ms": <unix ms>}, ...]}.
func ParseReceiptKeys(data []byte, settings *UploadReceiptSettings) (*ReceiptKeys, error) {
	file := &struct {
		Keys []struct {
			KeyId       uint32 `json:"key_id"`
			Key         string `json:"key"`
			IssueFromMs int64  `json:"issue_from_ms"`
		} `json:"keys"`
	}{}
	if err := json.Unmarshal(data, file); err != nil {
		return nil, err
	}
	keys := []*ReceiptKey{}
	for _, entry := range file.Keys {
		key, err := base64.StdEncoding.DecodeString(entry.Key)
		if err != nil {
			return nil, fmt.Errorf("receipt key %d: %w", entry.KeyId, err)
		}
		keys = append(keys, &ReceiptKey{KeyId: entry.KeyId, Key: key, IssueFrom: time.UnixMilli(entry.IssueFromMs)})
	}
	return NewReceiptKeys(keys, settings)
}

// The key that issues at now: the newest whose IssueFrom has passed.
func (self *ReceiptKeys) issuing(now time.Time) (*ReceiptKey, bool) {
	var issuing *ReceiptKey
	for _, key := range self.keys {
		if !now.Before(key.IssueFrom) {
			issuing = key
		}
	}
	return issuing, issuing != nil
}

// The key keyId names, while it still verifies at now: from its IssueFrom until KeyRetainAfterRotation past the
// next key's.
func (self *ReceiptKeys) verifying(keyId uint32, now time.Time) (*ReceiptKey, bool) {
	for i, key := range self.keys {
		if key.KeyId != keyId {
			continue
		}
		if now.Before(key.IssueFrom) {
			return nil, false
		}
		if i+1 < len(self.keys) && !now.Before(self.keys[i+1].IssueFrom.Add(self.settings.KeyRetainAfterRotation)) {
			return nil, false
		}
		return key, true
	}
	return nil, false
}
