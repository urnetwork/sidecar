// §12.5's names under a root (X5, R-DNS-6, Q-DNS-2): the label every network gets, the rules an
// alias or a new network name meets, and the reserved list. On every leg, with no connect and no
// miekg/dns, because §7.7's signers refuse reserved client names on sidecar_http too.
//
// The reserved list is dns_reserved_labels.txt, §12.5's block as data, and the brands its confusable
// rule protects are dns_brand_labels.txt: both are embedded, so a binary carries the list it was built
// with and a release check (bringyourctl release-preflight) holds services.yml's host labels to it.
// A brand is a reserved label too, as §12.5's block has its brand line.
//
// Each predicate folds ASCII case, since DNS does. ValidateDnsName does not: it takes a name as
// ValidateNetworkName leaves it, lowercase.

package sidecar

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

//go:embed dns_reserved_labels.txt
var dnsReservedLabelsText string

//go:embed dns_brand_labels.txt
var dnsBrandLabelsText string

// A network's label (owner decision 14): its first character a letter, then nine letters or digits,
// about 51 bits. A format value.
const (
	dnsLabelByteCount  = 10
	dnsLabelFirstBytes = "abcdefghijklmnopqrstuvwxyz"
	dnsLabelRestBytes  = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// The random bytes one draw reads. A draw keeps a byte only below the largest multiple of its
// alphabet's size, so that every character is equally likely, and needs ten kept bytes: 64 fall
// short only with probability far below 2^-200. Not a tunable: the draw is a function of these bytes,
// so a fixed reader gives a fixed label.
const dnsLabelDrawByteCount = 64

// The lengths ValidateNetworkName allows (server/model/network_model.go).
const (
	dnsNameMinByteCount = 5
	dnsNameMaxByteCount = 50
)

// The longest DNS label, by RFC 1035 §2.3.4.
const dnsNameLabelMaxByteCount = 63

var (
	// Not 5 to 50 lowercase letters, digits and dashes: what ValidateNetworkName leaves.
	ErrDnsNameInvalid = errors.New("name must be 5 to 50 lowercase letters, digits and dashes")
	// A dash at either end, which Let's Encrypt's Boulder refuses in a name.
	ErrDnsNameEdgeHyphen = errors.New("name must not start or end with a dash")
	// Two dashes as the third and fourth characters, which keeps out xn-- and IDNA homographs.
	ErrDnsNameHyphens34 = errors.New("name must not have two dashes as its third and fourth characters")
	// A label of §12.5's reserved list, exact or by a pattern.
	ErrDnsNameReserved = errors.New("name is reserved")
	// A - token that reads as a brand after §12.5's mapping.
	ErrDnsNameBrandConfusable = errors.New("name is confusable with a brand")
	// A label draw that the reserved or brand rule refuses. The caller draws again, as it does when
	// the label is taken (owner decision 97).
	ErrDnsLabelDrawRefused = errors.New("dns label draw refused")
)

// The two embedded lists, parsed once.
type dnsReservedList struct {
	// every exact label, brands included
	exactLabels map[string]bool
	// sorted, for ReservedDnsLabels
	sortedLabels []string
	// as written, in file order
	patterns []string
	// "main-" for main-*
	prefixPatterns []string
	// "-lb" for *-lb
	suffixPatterns []string
	// each brand's mapped form (dnsBrandSkeleton)
	brandSkeletons map[string]bool
}

var dnsReserved = mustParseDnsReservedList(dnsReservedLabelsText, dnsBrandLabelsText)

// The data lines of one embedded list: trimmed, without blanks and comments.
func dnsListLines(text string) []string {
	lines := []string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// Whether every byte is a lowercase letter, a digit or one of extra.
func isDnsLowerBytes(text string, extra string) bool {
	for index := range len(text) {
		character := text[index]
		if !('a' <= character && character <= 'z') && !('0' <= character && character <= '9') && strings.IndexByte(extra, character) == -1 {
			return false
		}
	}
	return true
}

// Whether label is a lowercase LDH label: letters, digits and inner dashes, at most 63 bytes.
func isDnsLowerLdhLabel(label string) bool {
	if label == "" || dnsNameLabelMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	return isDnsLowerBytes(label, "-")
}

// Parses both lists. The files are this package's own, so a line that breaks the format is a build
// mistake, which panics at init rather than serving a list that is not the one written.
func mustParseDnsReservedList(reservedText string, brandText string) *dnsReservedList {
	list, err := parseDnsReservedList(reservedText, brandText)
	if err != nil {
		panic(err)
	}
	return list
}

func parseDnsReservedList(reservedText string, brandText string) (*dnsReservedList, error) {
	list := &dnsReservedList{
		exactLabels:    map[string]bool{},
		brandSkeletons: map[string]bool{},
	}
	for _, line := range dnsListLines(reservedText) {
		switch {
		case strings.Count(line, "*") == 0:
			if !isDnsLowerLdhLabel(line) {
				return nil, fmt.Errorf("dns_reserved_labels.txt: %q is not a lowercase label", line)
			}
			if list.exactLabels[line] {
				return nil, fmt.Errorf("dns_reserved_labels.txt: %q repeats", line)
			}
			list.exactLabels[line] = true
		case strings.Count(line, "*") == 1 && 1 < len(line) && strings.HasPrefix(line, "*"):
			suffix := line[1:]
			if !isDnsLowerBytes(suffix, "-") || dnsNameLabelMaxByteCount <= len(suffix) || suffix[len(suffix)-1] == '-' {
				return nil, fmt.Errorf("dns_reserved_labels.txt: %q is not a pattern", line)
			}
			if slices.Contains(list.patterns, line) {
				return nil, fmt.Errorf("dns_reserved_labels.txt: %q repeats", line)
			}
			list.patterns = append(list.patterns, line)
			list.suffixPatterns = append(list.suffixPatterns, suffix)
		case strings.Count(line, "*") == 1 && 1 < len(line) && strings.HasSuffix(line, "*"):
			prefix := line[:len(line)-1]
			if !isDnsLowerBytes(prefix, "-") || dnsNameLabelMaxByteCount <= len(prefix) || prefix[0] == '-' {
				return nil, fmt.Errorf("dns_reserved_labels.txt: %q is not a pattern", line)
			}
			if slices.Contains(list.patterns, line) {
				return nil, fmt.Errorf("dns_reserved_labels.txt: %q repeats", line)
			}
			list.patterns = append(list.patterns, line)
			list.prefixPatterns = append(list.prefixPatterns, prefix)
		default:
			return nil, fmt.Errorf("dns_reserved_labels.txt: %q is neither a label nor a pattern", line)
		}
	}
	brands := map[string]bool{}
	for _, line := range dnsListLines(brandText) {
		if line == "" || dnsNameLabelMaxByteCount < len(line) || !isDnsLowerBytes(line, "") {
			return nil, fmt.Errorf("dns_brand_labels.txt: %q is not a brand of letters and digits", line)
		}
		if brands[line] {
			return nil, fmt.Errorf("dns_brand_labels.txt: %q repeats", line)
		}
		brands[line] = true
		// a brand is reserved, as §12.5's block lists URnetwork's own and the curated ones
		list.exactLabels[line] = true
		list.brandSkeletons[dnsBrandSkeleton(line)] = true
	}
	for label := range list.exactLabels {
		list.sortedLabels = append(list.sortedLabels, label)
	}
	slices.Sort(list.sortedLabels)
	return list, nil
}

// ASCII lowercase, leaving every other byte as it is, invalid UTF-8 included.
func dnsAsciiLower(text string) string {
	for index := range len(text) {
		if 'A' <= text[index] && text[index] <= 'Z' {
			lowered := []byte(text)
			for lowerIndex := index; lowerIndex < len(lowered); lowerIndex += 1 {
				if 'A' <= lowered[lowerIndex] && lowered[lowerIndex] <= 'Z' {
					lowered[lowerIndex] += 'a' - 'A'
				}
			}
			return string(lowered)
		}
	}
	return text
}

// §12.5's mapping of one token: 0 to o, 1 to l, 3 to e, 5 to s, then rn to m. Two tokens that map
// alike read alike, so a brand and a token are compared by their mapped forms.
func dnsBrandSkeleton(token string) string {
	mapped := strings.Map(func(character rune) rune {
		switch character {
		case '0':
			return 'o'
		case '1':
			return 'l'
		case '3':
			return 'e'
		case '5':
			return 's'
		}
		return character
	}, token)
	return strings.ReplaceAll(mapped, "rn", "m")
}

// Every exact label of the reserved list, brands included, sorted. A copy.
func ReservedDnsLabels() []string {
	return slices.Clone(dnsReserved.sortedLabels)
}

// Every pattern of the reserved list as written, such as "*-lb" and "main-*", in the file's order.
// * stands for any run of characters, the empty one included. A copy.
func ReservedDnsPatterns() []string {
	return slices.Clone(dnsReserved.patterns)
}

// Whether label is reserved: one of the list's labels, or matched by one of its patterns.
func IsReservedDnsLabel(label string) bool {
	label = dnsAsciiLower(label)
	if dnsReserved.exactLabels[label] {
		return true
	}
	for _, prefix := range dnsReserved.prefixPatterns {
		if strings.HasPrefix(label, prefix) {
			return true
		}
	}
	for _, suffix := range dnsReserved.suffixPatterns {
		if strings.HasSuffix(label, suffix) {
			return true
		}
	}
	return false
}

// Whether one of name's - tokens reads as a brand after §12.5's mapping (0 to o, 1 to l, 3 to e, 5 to
// s, rn to m), as paypa1 and paypal-help do, and as urnetw0rk and umetwork do.
func IsBrandConfusableDnsName(name string) bool {
	for _, token := range strings.Split(dnsAsciiLower(name), "-") {
		if token != "" && dnsReserved.brandSkeletons[dnsBrandSkeleton(token)] {
			return true
		}
	}
	return false
}

// Whether label has §12.7's word-number shape, letters, a dash and four digits, which burners keep
// (owner decision 32): no owner, client name or scope label takes one.
func IsWordNumberDnsLabel(label string) bool {
	label = dnsAsciiLower(label)
	word, number, ok := strings.Cut(label, "-")
	if !ok || word == "" || len(number) != 4 {
		return false
	}
	for index := range len(word) {
		if word[index] < 'a' || 'z' < word[index] {
			return false
		}
	}
	for index := range len(number) {
		if number[index] < '0' || '9' < number[index] {
			return false
		}
	}
	return true
}

// §12.5's rule for an alias and a new network name (§7.12), as ValidateNetworkName leaves the name:
// 5 to 50 lowercase letters, digits and dashes; no dash at either end, which Boulder refuses; no
// dashes as the third and fourth characters, so no xn-- and no IDNA homograph; not reserved; and no
// token confusable with a brand. Returns one of the ErrDnsName errors, the first rule broken.
func ValidateDnsName(name string) error {
	if len(name) < dnsNameMinByteCount || dnsNameMaxByteCount < len(name) || !isDnsLowerBytes(name, "-") {
		return ErrDnsNameInvalid
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return ErrDnsNameEdgeHyphen
	}
	if name[2:4] == "--" {
		return ErrDnsNameHyphens34
	}
	if IsReservedDnsLabel(name) {
		return ErrDnsNameReserved
	}
	if IsBrandConfusableDnsName(name) {
		return ErrDnsNameBrandConfusable
	}
	return nil
}

// Draws a network label (owner decision 14): [a-z][a-z0-9]{9} from random, each character equally
// likely. random is crypto/rand.Reader outside tests; nothing about a network, and never its id,
// whose ULID shows when it was made ([R:server-identity] §2.11), goes into a label.
//
// A draw the reserved or brand rule refuses answers ErrDnsLabelDrawRefused and the caller draws again,
// as it does for a label already taken, so the caller's loop is the one place a bound on redraws lives.
// A reader that fails or ends answers its error.
func NewDnsLabel(random io.Reader) (string, error) {
	if random == nil {
		return "", errors.New("dns label: no random source")
	}
	randomBytes := make([]byte, dnsLabelDrawByteCount)
	if _, err := io.ReadFull(random, randomBytes); err != nil {
		return "", fmt.Errorf("dns label: %w", err)
	}
	label := make([]byte, 0, dnsLabelByteCount)
	for _, randomByte := range randomBytes {
		alphabet := dnsLabelRestBytes
		if len(label) == 0 {
			alphabet = dnsLabelFirstBytes
		}
		// the largest multiple of the alphabet's size that a byte can reach, below which every
		// character is drawn equally often
		limit := 256 - 256%len(alphabet)
		if limit <= int(randomByte) {
			continue
		}
		label = append(label, alphabet[int(randomByte)%len(alphabet)])
		if len(label) == dnsLabelByteCount {
			break
		}
	}
	if len(label) < dnsLabelByteCount {
		return "", ErrDnsLabelDrawRefused
	}
	if IsReservedDnsLabel(string(label)) || IsBrandConfusableDnsName(string(label)) {
		return "", ErrDnsLabelDrawRefused
	}
	return string(label), nil
}
