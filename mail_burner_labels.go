//go:build !ios_extension

// §15.9's burner labels (R-MAIL-6, R-MAIL-7, D-MAIL-7, I-14; MAIL-M8-01): a burner is <name>@<blabel>.<net>.<root>
// under the wildcard MX, and <blabel> a word-number label such as otter-4821 (^[a-z]+-[0-9]{4}$), which §12.7 and §7.7
// refuse as DNS owners and client names, so nothing a person publishes shadows the wildcard there.
//
//	draw     a use's candidates come from a DRBG keyed with its effect_key (§15.8, D-MCP-11): HMAC-SHA256 in counter
//	         mode, block j = HMAC(effect_key, "urnetwork-sidecar-v1/burner-label" ‖ 0x00 ‖ u32be(j)), its bytes taken
//	         two at a time and rejection-sampled into a word of mail_burner_words.txt and a number below 10,000, so
//	         every label is equally likely and a retry or a restart's Lookup draws the same candidates in the same
//	         order, and takes the burner its first run made, never a second label. A standing grant's use has no key,
//	         so its seed is random: nothing reconciles it
//	skip     a candidate the network publishes a host at is passed over, and so is one drawn twice; a burned or
//	         removed label is passed over by mailcfg itself, which creates a burner only where its path never stood
//	         (MailConfig.CreateBurnerRecord), so a label is never reissued
//
// The word list is embedded: changing it changes what a key draws, so it is appended to, never reordered. Nothing here
// logs a label (I-13). Package-level functions are safe for concurrent use, and so is MailBurnerLabels.

package sidecar

import (
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

//go:embed mail_burner_words.txt
var mailBurnerWordsText string

// The DRBG's label, ahead of its 0x00 (the file header's draw row).
const mailBurnerLabelDrbgLabel = "urnetwork-sidecar-v1/burner-label"

// The numbers a label takes: four digits, below this. A format value (§15.9's ^[a-z]+-[0-9]{4}$).
const mailBurnerLabelNumberCount = 10000

// What MailBurnerLabels was given cannot draw a label.
var ErrMailBurnerLabelsInvalid = errors.New("mail burner labels: invalid")

// The embedded word list, read once: each line that is a lowercase ASCII word, comments and blanks left out.
var mailBurnerWords = sync.OnceValue(func() []string {
	words := []string{}
	for _, line := range strings.Split(mailBurnerWordsText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if mailBurnerWordValid(line) {
			words = append(words, line)
		}
	}
	return words
})

// Whether word is one a label may take: lowercase ASCII letters only, so <word>-<four digits> is a word-number label.
func mailBurnerWordValid(word string) bool {
	return word != "" && word == dnsAsciiLower(word) && IsWordNumberDnsLabel(word+"-0000")
}

// The words a label draws from.
func MailBurnerWords() []string {
	return slices.Clone(mailBurnerWords())
}

// What burners are tuned by (MAIL-M8-01). Every value must be positive.
type MailBurnerSettings struct {
	// How far back mail_burner_creates_per_day counts creations: a day.
	CreatesWindow time.Duration
	// The most bytes of a site a burner is made for, past which it is refused: a URL's practical bound.
	SiteMaxByteCount int
	// The draws a label drawer makes for each candidate it answers before it stops, so a network publishing hosts
	// at nearly every label still ends (mail_burner_labels.go).
	DrawsPerCandidate int
}

// The one default.
func DefaultMailBurnerSettings() *MailBurnerSettings {
	return &MailBurnerSettings{
		CreatesWindow:     24 * time.Hour,
		SiteMaxByteCount:  2048,
		DrawsPerCandidate: 64,
	}
}

// Whether every value is in range.
func (self *MailBurnerSettings) valid() bool {
	return self != nil && 0 < self.CreatesWindow && 0 < self.SiteMaxByteCount && 0 < self.DrawsPerCandidate
}

// The burner settings, the defaults where none were set.
func (self *MailClient) burnerSettings() *MailBurnerSettings {
	if self.settings.Burner != nil {
		return self.settings.Burner
	}
	return DefaultMailBurnerSettings()
}

// What NewMailBurnerLabels builds on.
type MailBurnerLabelsArgs struct {
	// The candidates one draw answers: mailcfg tries at most MailConfigSettings.BurnerCandidateMaxCount of them.
	CandidateCount int
	// The draws made for each candidate before a draw stops short (MailBurnerSettings.DrawsPerCandidate).
	DrawsPerCandidate int
	// The labels directly under the network's apex that it publishes a host at, read at each draw; nil for none.
	PublishedHosts func() []string
	// The words, nil for the embedded list. A test's own list.
	Words []string
}

// A network's burner label drawer: Draw is its MailBurnerLabelsFunction. See the file header.
type MailBurnerLabels struct {
	words          []string
	candidateCount int
	// the draws made before a draw stops short
	drawCount      int
	publishedHosts func() []string
}

// A drawer over args.
func NewMailBurnerLabels(args *MailBurnerLabelsArgs) (*MailBurnerLabels, error) {
	if args == nil || args.CandidateCount <= 0 || args.DrawsPerCandidate <= 0 {
		return nil, fmt.Errorf("%w: no candidate or draw count", ErrMailBurnerLabelsInvalid)
	}
	words := args.Words
	if words == nil {
		words = mailBurnerWords()
	}
	if len(words) == 0 || 65536 < len(words) {
		return nil, fmt.Errorf("%w: a word list of %d words", ErrMailBurnerLabelsInvalid, len(words))
	}
	for _, word := range words {
		if !mailBurnerWordValid(word) {
			return nil, fmt.Errorf("%w: a word that is no lowercase ASCII word", ErrMailBurnerLabelsInvalid)
		}
	}
	return &MailBurnerLabels{
		words: slices.Clone(words), candidateCount: args.CandidateCount, drawCount: args.CandidateCount * args.DrawsPerCandidate,
		publishedHosts: args.PublishedHosts,
	}, nil
}

// The DRBG's byte stream for a key (the file header's draw row).
type mailBurnerDrbg struct {
	key    []byte
	block  uint32
	buffer []byte
}

// The next two bytes as a number.
func (self *mailBurnerDrbg) next16() uint16 {
	if len(self.buffer) < 2 {
		mac := hmac.New(sha256.New, self.key)
		mac.Write([]byte(mailBurnerLabelDrbgLabel))
		mac.Write([]byte{0})
		mac.Write(binary.BigEndian.AppendUint32(nil, self.block))
		self.block += 1
		self.buffer = append(self.buffer, mac.Sum(nil)...)
	}
	value := binary.BigEndian.Uint16(self.buffer)
	self.buffer = self.buffer[2:]
	return value
}

// A number below count, every one equally likely: two bytes at a time, those past the largest multiple of count drawn
// again.
func (self *mailBurnerDrbg) below(count int) int {
	limit := 65536 - 65536%count
	for {
		if value := int(self.next16()); value < limit {
			return value % count
		}
	}
}

// The candidate labels of a use whose effect key is effectKey, in the order to try (the file header's draw and skip
// rows). An empty key draws from a random seed.
func (self *MailBurnerLabels) Draw(effectKey []byte) []string {
	key := effectKey
	if len(key) == 0 {
		key = make([]byte, sha256.Size)
		// never fails: since Go 1.24 a broken system generator crashes the program instead
		cryptorand.Read(key)
	}
	shadowed := map[string]bool{}
	if self.publishedHosts != nil {
		for _, host := range self.publishedHosts() {
			shadowed[dnsAsciiLower(host)] = true
		}
	}
	drbg := &mailBurnerDrbg{key: key}
	labels := make([]string, 0, self.candidateCount)
	// a bound on draws, so a network publishing hosts at nearly every label still ends: far past any real chance
	for draw := 0; len(labels) < self.candidateCount && draw < self.drawCount; draw += 1 {
		word := self.words[drbg.below(len(self.words))]
		label := fmt.Sprintf("%s-%04d", word, drbg.below(mailBurnerLabelNumberCount))
		if shadowed[label] || slices.Contains(labels, label) {
			continue
		}
		labels = append(labels, label)
	}
	return labels
}

// The labels directly under zone's apex that it publishes a record at: what a burner label must not shadow.
func mailBurnerPublishedLabels(zone *DnsZone) []string {
	if zone == nil {
		return []string{}
	}
	apex := strings.TrimSuffix(dnsAsciiLower(zone.Label+"."+zone.Root), ".")
	labels := []string{}
	for _, recordSet := range zone.RecordSets {
		name := strings.TrimSuffix(dnsAsciiLower(recordSet.Name), ".")
		host, ok := strings.CutSuffix(name, "."+apex)
		if !ok || host == "" {
			continue
		}
		parts := strings.Split(host, ".")
		if label := parts[len(parts)-1]; !slices.Contains(labels, label) {
			labels = append(labels, label)
		}
	}
	return labels
}

// The bound binding's published hosts at each draw, none while nothing is bound.
func (self *MailClient) publishedHosts() []string {
	binding := func() *MailBinding {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.binding
	}()
	if binding == nil || binding.PublishedHosts == nil {
		return nil
	}
	return binding.PublishedHosts()
}

// The drawer a MailConfig the client builds creates burners with, nil where the settings give none.
func (self *MailClient) burnerLabels() MailBurnerLabelsFunction {
	labels, err := NewMailBurnerLabels(&MailBurnerLabelsArgs{
		CandidateCount:    max(self.settings.Config.BurnerCandidateMaxCount, 1),
		DrawsPerCandidate: self.burnerSettings().DrawsPerCandidate,
		PublishedHosts:    self.publishedHosts,
	})
	if err != nil {
		return nil
	}
	return labels.Draw
}
