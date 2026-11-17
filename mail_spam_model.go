//go:build !ios_extension

// s/model's naive Bayes filter (§15.9; MAIL-M7-12): one file per mailbox, which its people's spam and not-spam
// verdicts train, and which readers score each message by at ingest. mox's junk filter keeps per-word rows in a
// database, which neither a page Worker nor a single s/model file can hold (plan-MAIL-mox-subset#2), so this is a small
// filter of its own: a message's features hash into 4,096 buckets, and the model counts, per bucket, the spam and the
// not-spam messages trained that held a feature there, beside how many of each were trained. Its size is fixed, so
// it stays under the format's MaxByteCount however much it learns, and its counts are halved once more messages are
// trained than the settings keep, so it follows a mailbox's mail as it changes. The format's limits are
// MailSpamModelSettings' fields, their defaults the format's values (QD-702).
//
// The bytes are MailSpamModel (mail.proto): version 1, then counts as MAIL-FORMAT.md's s/model section states. The
// file is sealed under §11 like every mailbox file, so a bucket's count says nothing to a server. Only its newest
// version is ever used, so it is written versionless, versioning 1, by the mail component's reserved writer (§15.7's
// s/model row, §11.7's choose row; MAIL-M10-01): each write is mailSpamModelWrite's, which the store over evs writes
// "off" in the format2 gate, so a model a format-1 writer left versioned turns versionless at its next write, and
// versioned (0) in a locked mailbox, where §11.7 refuses a 1; outside the gate every version is 0, as format 1 writes.
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

// MAIL-FORMAT.md's s/model version, the one a reader takes.
const mailSpamModelVersion = 1

// s/model's format limits (MAIL-FORMAT.md's s/model section): the format's own values, every reader's and writer's
// alike, so changing one is a format change that no device makes alone (QD-702).
type MailSpamModelSettings struct {
	// The buckets a model's features hash into: 4,096, at most 2^32. Its counts are the two message counts, then each
	// bucket's spam count, then each one's not-spam count.
	BucketCount int
	// Every count is held below it: 2^20, three varint bytes, so a model takes at most about 24 KiB.
	CountLimit uint32
	// The most bytes of s/model a reader takes: 64 KiB, past the most a model of the format's counts encodes to.
	MaxByteCount int
}

// The format's values, a fresh value each call.
func DefaultMailSpamModelSettings() *MailSpamModelSettings {
	return &MailSpamModelSettings{BucketCount: 4096, CountLimit: 1024 * 1024, MaxByteCount: 64 * 1024}
}

// version 1's counts: the two message counts, then the buckets' spam counts, then their not-spam counts.
func (self *MailSpamModelSettings) countCount() int {
	return 2 + 2*max(self.BucketCount, 0)
}

// Bytes that are no s/model a reader can use: not a MailSpamModel, another version, counts of another length, or a
// bucket counting more messages than were trained.
var ErrMailSpamModelInvalid = errors.New("mail spam model invalid")

// One mailbox's filter. Not safe for concurrent use.
type MailSpamModel struct {
	settings         *MailSpamModelSettings
	spamMessageCount uint32
	hamMessageCount  uint32
	spamBuckets      []uint32
	hamBuckets       []uint32
}

// A filter that has learned nothing, of the format settings give; nil takes DefaultMailSpamModelSettings.
func NewMailSpamModel(settings *MailSpamModelSettings) *MailSpamModel {
	if settings == nil {
		settings = DefaultMailSpamModelSettings()
	}
	return &MailSpamModel{
		settings:    settings,
		spamBuckets: make([]uint32, max(settings.BucketCount, 0)),
		hamBuckets:  make([]uint32, max(settings.BucketCount, 0)),
	}
}

// A filter from s/model's bytes held to the format settings give, nil the default, or ErrMailSpamModelInvalid.
func ParseMailSpamModel(content []byte, settings *MailSpamModelSettings) (*MailSpamModel, error) {
	if settings == nil {
		settings = DefaultMailSpamModelSettings()
	}
	if settings.MaxByteCount < len(content) {
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
	if settings.BucketCount <= 0 || len(counts) != settings.countCount() {
		return nil, fmt.Errorf("%w: %d counts", ErrMailSpamModelInvalid, len(counts))
	}
	model := &MailSpamModel{
		settings:         settings,
		spamMessageCount: counts[0],
		hamMessageCount:  counts[1],
		spamBuckets:      slices.Clone(counts[2 : 2+settings.BucketCount]),
		hamBuckets:       slices.Clone(counts[2+settings.BucketCount:]),
	}
	for bucket := range settings.BucketCount {
		// a feature is counted once a message, so a bucket never counts more messages than were trained
		if model.spamMessageCount < model.spamBuckets[bucket] || model.hamMessageCount < model.hamBuckets[bucket] {
			return nil, fmt.Errorf("%w: bucket %d past its class", ErrMailSpamModelInvalid, bucket)
		}
	}
	if settings.CountLimit <= model.spamMessageCount || settings.CountLimit <= model.hamMessageCount {
		return nil, fmt.Errorf("%w: a count past its limit", ErrMailSpamModelInvalid)
	}
	return model, nil
}

// The write of s/model's content held to the version its writer read, 0 where it read none: the reserved writer's, so
// its version is versionless where §11.7 lets it be (see the file header).
func mailSpamModelWrite(content []byte, ifVersion uint64) *mailStoreWrite {
	return &mailStoreWrite{Path: MailSpamModelPath, Content: content, IfVersion: ifVersion, Reserved: EvsReservedMailModel}
}

// s/model's bytes, the same for the same counts on every leg.
func (self *MailSpamModel) Marshal() ([]byte, error) {
	counts := make([]uint32, 0, 2+len(self.spamBuckets)+len(self.hamBuckets))
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
// what was learned long ago weighs less. Unlearning after a halving takes away what is left, never more. A bucket past
// the model's, which only another format's features name, is passed over.
func (self *MailSpamModel) learn(buckets []uint32, spam bool, retract bool, trainedMaxCount uint32) {
	messageCount, bucketCounts := &self.hamMessageCount, self.hamBuckets
	if spam {
		messageCount, bucketCounts = &self.spamMessageCount, self.spamBuckets
	}
	step := func(count *uint32) {
		switch {
		case retract && 0 < *count:
			*count -= 1
		case !retract && uint64(*count)+1 < uint64(self.settings.CountLimit):
			*count += 1
		}
	}
	step(messageCount)
	for _, bucket := range buckets {
		if len(bucketCounts) <= int(bucket) {
			continue
		}
		step(&bucketCounts[bucket])
		// a bucket never counts more messages than its class, as after a halving and a retraction
		bucketCounts[bucket] = min(bucketCounts[bucket], *messageCount)
	}
	if 0 < trainedMaxCount && trainedMaxCount < self.spamMessageCount+self.hamMessageCount {
		self.spamMessageCount /= 2
		self.hamMessageCount /= 2
		for bucket := range self.spamBuckets {
			self.spamBuckets[bucket] = min(self.spamBuckets[bucket]/2, self.spamMessageCount)
			self.hamBuckets[bucket] = min(self.hamBuckets[bucket]/2, self.hamMessageCount)
		}
	}
}

// A feature's bucket among bucketCount.
func mailSpamBucket(feature string, bucketCount int) uint32 {
	hash := fnv.New32a()
	hash.Write([]byte(feature))
	return hash.Sum32() % uint32(max(bucketCount, 1))
}

// A message's distinct feature buckets, in the order first met, from its walk: the subject's and the first text
// part's words, the From domain and the attachments' media types. Words are runs of letters and digits, lowercased;
// those under 2 or past TokenMaxByteCount bytes, and those of digits alone, which vary message by message, are
// passed over. At most FeatureMaxCount, from the first TextMaxByteCount bytes of text, among the format's buckets.
func mailSpamFeatures(parsed *MailParsed, settings *MailSpamSettings) []uint32 {
	bucketCount := settings.model().BucketCount
	buckets := []uint32{}
	seen := make(map[uint32]bool, settings.FeatureMaxCount)
	add := func(feature string) bool {
		if settings.FeatureMaxCount <= len(buckets) {
			return false
		}
		bucket := mailSpamBucket(feature, bucketCount)
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
