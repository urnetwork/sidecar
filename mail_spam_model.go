//go:build !ios_extension

// s/model's naive Bayes filter (§15.9; MAIL-M7-12): one file per mailbox, which its people's spam and not-spam
// verdicts train, and which readers score each message by at ingest. mox's junk filter keeps per-word rows in a
// database, which neither a page Worker nor a single s/model file can hold (plan-MAIL-mox-subset#2), so this is a small
// filter of its own: a message's features hash into 4,096 buckets, and the model counts, per bucket, the spam and the
// not-spam messages trained that held a feature there, beside how many of each were trained. Its size is fixed, so
// it stays under MailSpamModelMaxByteCount however much it learns, and its counts are halved once more messages are
// trained than the settings keep, so it follows a mailbox's mail as it changes.
//
// The bytes are MailSpamModel (mail.proto): version 1, then counts as MAIL-FORMAT.md's s/model section states. The
// file is sealed under §11 like every mailbox file, so a bucket's count says nothing to a server. Versioned for now,
// as every format-1 file is; MAIL-M10-01 makes it versionless at format 2 (§15.7's s/model row).
//
// Features are the subject's and the first text part's words, the From domain and the attachments' media types,
// lowercased, each counted once a message. A feature's bucket is FNV-1a over its text, so every leg puts it in the
// same one. On every leg. Package-level functions are safe for concurrent use; MailSpamModel is not.

package sidecar

import (
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// MAIL-FORMAT.md's s/model. Format values.
const (
	MailSpamModelBucketCount = 4096
	// version 1's counts: the two message counts, then the buckets' spam counts, then their not-spam counts
	mailSpamModelCountCount = 2 + 2*MailSpamModelBucketCount
	mailSpamModelVersion    = 1
	// A count is held below this, three varint bytes, so a model takes at most about 24 KiB.
	mailSpamCountLimit = 1024 * 1024
	// What a reader takes of s/model.
	MailSpamModelMaxByteCount = 64 * 1024
)

// Bytes that are no s/model a reader can use: not a MailSpamModel, another version, counts of another length, or a
// bucket counting more messages than were trained.
var ErrMailSpamModelInvalid = errors.New("mail spam model invalid")

// One mailbox's filter. Not safe for concurrent use.
type MailSpamModel struct {
	spamMessageCount uint32
	hamMessageCount  uint32
	spamBuckets      []uint32
	hamBuckets       []uint32
}

// A filter that has learned nothing.
func NewMailSpamModel() *MailSpamModel {
	return &MailSpamModel{
		spamBuckets: make([]uint32, MailSpamModelBucketCount),
		hamBuckets:  make([]uint32, MailSpamModelBucketCount),
	}
}

// A filter from s/model's bytes, or ErrMailSpamModelInvalid.
func ParseMailSpamModel(content []byte) (*MailSpamModel, error) {
	if MailSpamModelMaxByteCount < len(content) {
		return nil, fmt.Errorf("%w: %d bytes", ErrMailSpamModelInvalid, len(content))
	}
	message := &protocol.MailSpamModel{}
	if err := proto.Unmarshal(content, message); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMailSpamModelInvalid, err)
	}
	if message.GetVersion() != mailSpamModelVersion {
		return nil, fmt.Errorf("%w: version %d", ErrMailSpamModelInvalid, message.GetVersion())
	}
	counts := message.GetCounts()
	if len(counts) != mailSpamModelCountCount {
		return nil, fmt.Errorf("%w: %d counts", ErrMailSpamModelInvalid, len(counts))
	}
	model := &MailSpamModel{
		spamMessageCount: counts[0],
		hamMessageCount:  counts[1],
		spamBuckets:      slices.Clone(counts[2 : 2+MailSpamModelBucketCount]),
		hamBuckets:       slices.Clone(counts[2+MailSpamModelBucketCount:]),
	}
	for bucket := range MailSpamModelBucketCount {
		// a feature is counted once a message, so a bucket never counts more messages than were trained
		if model.spamMessageCount < model.spamBuckets[bucket] || model.hamMessageCount < model.hamBuckets[bucket] {
			return nil, fmt.Errorf("%w: bucket %d past its class", ErrMailSpamModelInvalid, bucket)
		}
	}
	if mailSpamCountLimit <= model.spamMessageCount || mailSpamCountLimit <= model.hamMessageCount {
		return nil, fmt.Errorf("%w: a count past its limit", ErrMailSpamModelInvalid)
	}
	return model, nil
}

// s/model's bytes, the same for the same counts on every leg.
func (self *MailSpamModel) Marshal() ([]byte, error) {
	counts := make([]uint32, 0, mailSpamModelCountCount)
	counts = append(counts, self.spamMessageCount, self.hamMessageCount)
	counts = append(counts, self.spamBuckets...)
	counts = append(counts, self.hamBuckets...)
	return proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.MailSpamModel{Version: mailSpamModelVersion, Counts: counts})
}

// How many spam and not-spam messages it learned from.
func (self *MailSpamModel) MessageCounts() (spamCount uint32, hamCount uint32) {
	return self.spamMessageCount, self.hamMessageCount
}

// Learns, or with retract unlearns, one message of its class from its buckets, each counted once. Counts stay at or
// above 0 and below their limit, and once more than trainedMaxCount messages are counted every count is halved, so
// what was learned long ago weighs less. Unlearning after a halving takes away what is left, never more.
func (self *MailSpamModel) learn(buckets []uint16, spam bool, retract bool, trainedMaxCount uint32) {
	messageCount, bucketCounts := &self.hamMessageCount, self.hamBuckets
	if spam {
		messageCount, bucketCounts = &self.spamMessageCount, self.spamBuckets
	}
	step := func(count *uint32) {
		switch {
		case retract && 0 < *count:
			*count -= 1
		case !retract && *count < mailSpamCountLimit-1:
			*count += 1
		}
	}
	step(messageCount)
	for _, bucket := range buckets {
		step(&bucketCounts[bucket])
		// a bucket never counts more messages than its class, as after a halving and a retraction
		bucketCounts[bucket] = min(bucketCounts[bucket], *messageCount)
	}
	if 0 < trainedMaxCount && trainedMaxCount < self.spamMessageCount+self.hamMessageCount {
		self.spamMessageCount /= 2
		self.hamMessageCount /= 2
		for bucket := range MailSpamModelBucketCount {
			self.spamBuckets[bucket] = min(self.spamBuckets[bucket]/2, self.spamMessageCount)
			self.hamBuckets[bucket] = min(self.hamBuckets[bucket]/2, self.hamMessageCount)
		}
	}
}

// A feature's bucket.
func mailSpamBucket(feature string) uint16 {
	hash := fnv.New32a()
	hash.Write([]byte(feature))
	return uint16(hash.Sum32() % MailSpamModelBucketCount)
}

// A message's distinct feature buckets, in the order first met, from its walk: the subject's and the first text
// part's words, the From domain and the attachments' media types. Words are runs of letters and digits, lowercased;
// those under 2 or past TokenMaxByteCount bytes, and those of digits alone, which vary message by message, are
// passed over. At most FeatureMaxCount, from the first TextMaxByteCount bytes of text.
func mailSpamFeatures(parsed *MailParsed, settings *MailSpamSettings) []uint16 {
	buckets := []uint16{}
	seen := make(map[uint16]bool, settings.FeatureMaxCount)
	add := func(feature string) bool {
		if settings.FeatureMaxCount <= len(buckets) {
			return false
		}
		bucket := mailSpamBucket(feature)
		if !seen[bucket] {
			seen[bucket] = true
			buckets = append(buckets, bucket)
		}
		return true
	}
	words := func(prefix string, text string) {
		start := -1
		letters := false
		emit := func(end int) bool {
			word := text[start:end]
			if !letters || len(word) < settings.TokenMinByteCount || settings.TokenMaxByteCount < len(word) {
				return true
			}
			return add(prefix + strings.ToLower(word))
		}
		for index, character := range text {
			if unicode.IsLetter(character) || unicode.IsDigit(character) {
				if start < 0 {
					start, letters = index, false
				}
				letters = letters || unicode.IsLetter(character)
				continue
			}
			if 0 <= start && !emit(index) {
				return
			}
			start = -1
		}
		if 0 <= start {
			emit(len(text))
		}
	}
	if parsed.FromDomain != "" {
		add("f:" + strings.ToLower(parsed.FromDomain))
	}
	for _, attachment := range parsed.Attachments {
		add("a:" + strings.ToLower(attachment.GetType()))
	}
	words("s:", parsed.Subject)
	text := parsed.Text
	if settings.TextMaxByteCount < len(text) {
		// cut on a rune's start, so the last word is never half a character
		cut := settings.TextMaxByteCount
		for 0 < cut && !utf8.RuneStart(text[cut]) {
			cut -= 1
		}
		text = text[:cut]
	}
	words("t:", text)
	return buckets
}
