//go:build !ios_extension

// §21.6's screen of new names (R-ABUSE-3, D-ABUSE-1, D-ABUSE-4, Q-ABUSE-4; owner decisions 14 and
// 97). Brands enter only through names a network creates: aliases, record owners, published hosts
// and burner From domains. ScreenName applies §12.5's brand rule and §21.6's Names paragraph to each
// such name, and to each label draw, as one pure function on every leg with no connect import, since
// dnsservice and smtpedgeservice call it and neither may import server. Clients run it as a courtesy,
// and every server gate runs it again, because a modified sidecar skips sidecar-side controls (§21.4).
//
// It screens at creation only. A name already live is never screened again here, so a list change
// withdraws nothing; the CT watch compares live names with the current lists (ABUSE-M5-13). §15.9's
// burner word list skips these lists, so a burner's own draw never calls it.
//
// The rules, in order, the first that decides answering:
//
//   - The name is one DNS label as a gate stores it: 1 to 63 lowercase letters, digits and dashes,
//     no dash at either end, and no two dashes as its third and fourth characters, which keeps out
//     xn-- and the IDNA homographs §12.5's mapping cannot read. Anything else denies, a dotted name
//     included: a caller screens each label of a longer name.
//   - With nil facts, a label draw, the name must also pass ValidateDnsName, since a draw lands
//     directly under <root> beside aliases (§12.5). A host or record owner may be shorter than a
//     network name, so a network's facts do not bring ValidateDnsName's length bound.
//   - §12.5's reserved block, dns_reserved_labels.txt, denies, whatever the facts.
//   - A word-number name (§12.7) denies, since those stay burners' (owner decision 32).
//   - Each - token is read for brands and keywords (screenList.readToken): as a brand or keyword
//     after §12.5's mapping (0 to o, 1 to l, 3 to e, 5 to s, rn to m), or as a run of them written
//     together, as paypalsupport is.
//   - A token reading as one of URnetwork's own names, which the reserved block lists among its
//     brands, denies: no verified domain or reviewer's allow lets a network use them.
//   - A brand with a keyword (login, secure, verify, account, support, wallet, update) goes to review;
//     it denies on probation, or with nil facts, which have no network to hold a name for, and allows
//     once a reviewer has allowed the name (ScreenFacts.ReviewAllowed).
//   - A brand otherwise denies unless the network verified one of the brand's domains, every brand
//     the name reads as counting.
//   - Anything else allows.
//
// Two readings of ABUSE-M5-01's rule list. Its reserved rule is §12.5's block, not IsReservedDnsLabel,
// which counts every curated brand reserved and so would deny paypal with paypal's domain verified,
// which §21.6 allows. And a brand with a keyword goes to review before the brand rule can deny it:
// §21.6 sends brand-plus-keyword names to review rather than refusing them until the network
// verifies the brand, as plan-ABUSE-review-held-names reads it (the owner took its option 1 over
// option 3), so paypal-support goes to review, refused on probation.
//
// The lists are dns_screen_brands.txt, which gives each brand of dns_brand_labels.txt its domains,
// and dns_reserved_labels.txt, embedded and parsed once, so ScreenName is safe for concurrent use.

package sidecar

import (
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strings"
)

//go:embed dns_screen_brands.txt
var dnsScreenBrandsText string

// The longest domain name in text form, by RFC 1035 §2.3.4's 255 octets on the wire.
const dnsDomainMaxByteCount = 253

// §21.6's keywords, which make a name holding a brand a brand-plus-keyword name. The design's list,
// a fact of the policy rather than a tunable.
var screenKeywords = []string{"login", "secure", "verify", "account", "support", "wallet", "update"}

// One of ScreenName's three answers. The zero value denies, so a verdict left unset refuses.
type ScreenVerdict int

const (
	// The name is refused. A label draw redraws; a gate answers that the name is not available.
	ScreenVerdictDeny ScreenVerdict = iota
	// The name waits for a person: the gate refuses it and opens a case, and a reviewer's allow
	// lets a retry pass (ABUSE-M5-08, plan-ABUSE-review-held-names).
	ScreenVerdictReview
	// The name may be created.
	ScreenVerdictAllow
)

// deny, review or allow, the vectors' and logs' word for a verdict.
func (self ScreenVerdict) String() string {
	switch self {
	case ScreenVerdictDeny:
		return "deny"
	case ScreenVerdictReview:
		return "review"
	case ScreenVerdictAllow:
		return "allow"
	}
	return fmt.Sprintf("ScreenVerdict(%d)", int(self))
}

// What a gate knows about the network creating a name: ABUSE-M5-08's ScreenFactsForNetwork on the
// server, the client's own view as a courtesy. A nil *ScreenFacts is a label draw, which has no
// network behind it yet.
type ScreenFacts struct {
	// The network's verified domains (§7.6, network_domain), any case, a trailing dot ignored. A
	// brand's name is allowed only when one of the brand's own domains is here exactly: a subdomain
	// does not count, since a subdomain may be delegated to someone who is not the brand.
	VerifiedDomains []string
	// The network is on probation (§21.7), or restricted, which takes probation's limits: no name is
	// held for review, so a review verdict denies instead.
	Probation bool
	// A reviewer allowed this name for this network: an abuse_action of kind screen_allow naming
	// both (ABUSE-M5-08). It turns a review into an allow and changes no other verdict.
	ReviewAllowed bool
}

// One brand of the screen's list and the domains whose verification lets a network use it.
type ScreenBrand struct {
	// as dns_brand_labels.txt writes it: lowercase letters and digits
	Brand string
	// lowercase, in dns_screen_brands.txt's order. Empty for URnetwork's own names, which nothing
	// unlocks, and for a brand the file has not given a domain yet.
	Domains []string
}

// The screen's brands, sorted by brand: every brand of dns_brand_labels.txt and of
// dns_screen_brands.txt, with its domains. A copy.
func ScreenBrands() []ScreenBrand {
	brands := []ScreenBrand{}
	for _, name := range dnsScreenList.sortedBrandNames {
		brand := dnsScreenList.nameBrands[name]
		brands = append(brands, ScreenBrand{
			Brand:   brand.name,
			Domains: slices.Clone(brand.domains),
		})
	}
	return brands
}

// Screens name, a label a network creates or a label draw, under facts, which are nil for a draw.
// The file's header gives the rules.
func ScreenName(name string, facts *ScreenFacts) ScreenVerdict {
	if !isDnsLowerLdhLabel(name) || (4 <= len(name) && name[2:4] == "--") {
		return ScreenVerdictDeny
	}
	if facts == nil && ValidateDnsName(name) != nil {
		return ScreenVerdictDeny
	}
	if dnsScreenList.isReserved(name) || IsWordNumberDnsLabel(name) {
		return ScreenVerdictDeny
	}
	brands := []*screenBrand{}
	keyword := false
	for _, token := range strings.Split(name, "-") {
		brands, keyword = dnsScreenList.readToken(token, brands, keyword)
	}
	if len(brands) == 0 {
		return ScreenVerdictAllow
	}
	for _, brand := range brands {
		if brand.sealed {
			return ScreenVerdictDeny
		}
	}
	if keyword {
		switch {
		case facts == nil || facts.Probation:
			return ScreenVerdictDeny
		case facts.ReviewAllowed:
			return ScreenVerdictAllow
		default:
			return ScreenVerdictReview
		}
	}
	if facts == nil {
		return ScreenVerdictDeny
	}
	for _, brand := range brands {
		if !facts.verifiesBrand(brand) {
			return ScreenVerdictDeny
		}
	}
	return ScreenVerdictAllow
}

// Whether one of the network's verified domains is one of brand's domains.
func (self *ScreenFacts) verifiesBrand(brand *screenBrand) bool {
	for _, verifiedDomain := range self.VerifiedDomains {
		verifiedDomain = strings.TrimSuffix(dnsAsciiLower(verifiedDomain), ".")
		if slices.Contains(brand.domains, verifiedDomain) {
			return true
		}
	}
	return false
}

// The screen's lists, parsed once from the three embedded files.
type screenList struct {
	// §12.5's block alone: dns_reserved_labels.txt, without the curated brands
	reserved *dnsReservedList
	// every brand by its label
	nameBrands map[string]*screenBrand
	// nameBrands' keys, sorted, for ScreenBrands
	sortedBrandNames []string
	// what a token's text is read as, each brand's and each keyword's mapped form, by its first
	// byte and sorted within it, so a reader tries only the forms that can start where it stands
	firstBytePieces [256][]*screenPiece
}

// One brand and what lets a name use it.
type screenBrand struct {
	name string
	// lowercase, in the file's order
	domains []string
	// one of §12.5's reserved labels, URnetwork's own: nothing lets a name use it
	sealed bool
}

// One mapped form a token, or part of a token, may be.
type screenPiece struct {
	// the form, dnsBrandSkeleton of a brand or a keyword
	skeleton string
	// the brands of that form, more than one only if two brands map alike
	brands []*screenBrand
	// whether the form is one of the keywords
	keyword bool
}

var dnsScreenList = mustParseScreenList(dnsScreenBrandsText, dnsBrandLabelsText, dnsReservedLabelsText)

// Parses the lists. The files are this package's own, so a line that breaks dns_screen_brands.txt's
// format is a build mistake, which panics at init rather than screening with a list that is not the
// one written. Whether the two brand files agree is a test's, TestScreenBrandsCoverTheBrandLabels,
// so a brand added to one file and not the other still screens: it is in the list either way.
func mustParseScreenList(screenText string, brandText string, reservedText string) *screenList {
	list, err := parseScreenList(screenText, brandText, reservedText)
	if err != nil {
		panic(err)
	}
	return list
}

// The lists, or the first line that breaks dns_screen_brands.txt's format: a brand that is not
// lowercase letters and digits, a domain that is not a lowercase name of two or more labels, a
// domain twice on one line, or a brand on two lines. A brand of dns_brand_labels.txt with no line
// here has no domain; a sealed brand's domains are dropped, since nothing unlocks it.
func parseScreenList(screenText string, brandText string, reservedText string) (*screenList, error) {
	reserved, err := parseDnsReservedList(reservedText, "")
	if err != nil {
		return nil, err
	}
	list := &screenList{
		reserved:   reserved,
		nameBrands: map[string]*screenBrand{},
	}
	isBrandName := func(name string) bool {
		return name != "" && len(name) <= dnsNameLabelMaxByteCount && isDnsLowerBytes(name, "")
	}
	for _, name := range dnsListLines(brandText) {
		if !isBrandName(name) {
			return nil, fmt.Errorf("dns_brand_labels.txt: %q is not a brand of letters and digits", name)
		}
		list.nameBrands[name] = &screenBrand{name: name}
	}
	lineBrandNames := map[string]bool{}
	for _, line := range dnsListLines(screenText) {
		fields := strings.Fields(line)
		name := fields[0]
		if !isBrandName(name) {
			return nil, fmt.Errorf("dns_screen_brands.txt: %q is not a brand of letters and digits", name)
		}
		if lineBrandNames[name] {
			return nil, fmt.Errorf("dns_screen_brands.txt: %q repeats", name)
		}
		lineBrandNames[name] = true
		brand, ok := list.nameBrands[name]
		if !ok {
			brand = &screenBrand{name: name}
			list.nameBrands[name] = brand
		}
		for _, domain := range fields[1:] {
			if !isScreenDomain(domain) {
				return nil, fmt.Errorf("dns_screen_brands.txt: %q's %q is not a lowercase domain", name, domain)
			}
			if slices.Contains(brand.domains, domain) {
				return nil, fmt.Errorf("dns_screen_brands.txt: %q's %q repeats", name, domain)
			}
			brand.domains = append(brand.domains, domain)
		}
	}
	skeletonPieces := map[string]*screenPiece{}
	piece := func(skeleton string) *screenPiece {
		if skeletonPiece, ok := skeletonPieces[skeleton]; ok {
			return skeletonPiece
		}
		skeletonPiece := &screenPiece{skeleton: skeleton}
		skeletonPieces[skeleton] = skeletonPiece
		return skeletonPiece
	}
	for name, brand := range list.nameBrands {
		if list.isReserved(name) {
			brand.sealed = true
			brand.domains = nil
		}
		brandPiece := piece(dnsBrandSkeleton(name))
		brandPiece.brands = append(brandPiece.brands, brand)
		list.sortedBrandNames = append(list.sortedBrandNames, name)
	}
	slices.Sort(list.sortedBrandNames)
	for _, keyword := range screenKeywords {
		piece(dnsBrandSkeleton(keyword)).keyword = true
	}
	if len(list.nameBrands) == 0 {
		return nil, errors.New("dns_screen_brands.txt: no brands")
	}
	pieces := []*screenPiece{}
	for _, skeletonPiece := range skeletonPieces {
		slices.SortFunc(skeletonPiece.brands, func(a *screenBrand, b *screenBrand) int {
			return strings.Compare(a.name, b.name)
		})
		pieces = append(pieces, skeletonPiece)
	}
	slices.SortFunc(pieces, func(a *screenPiece, b *screenPiece) int {
		return strings.Compare(a.skeleton, b.skeleton)
	})
	// a mapped form is never empty: the mapping keeps a byte for every byte, and rn for two
	for _, skeletonPiece := range pieces {
		firstByte := skeletonPiece.skeleton[0]
		list.firstBytePieces[firstByte] = append(list.firstBytePieces[firstByte], skeletonPiece)
	}
	return list, nil
}

// Whether domain is a lowercase name of two or more LDH labels, at most 253 bytes, as a brand's line
// writes one.
func isScreenDomain(domain string) bool {
	if dnsDomainMaxByteCount < len(domain) {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !isDnsLowerLdhLabel(label) {
			return false
		}
	}
	return true
}

// Whether label is in §12.5's block: one of its labels, or matched by one of its patterns. The
// curated brands are not in it; they are the brand rule's.
func (self *screenList) isReserved(label string) bool {
	if self.reserved.exactLabels[label] {
		return true
	}
	for _, prefix := range self.reserved.prefixPatterns {
		if strings.HasPrefix(label, prefix) {
			return true
		}
	}
	for _, suffix := range self.reserved.suffixPatterns {
		if strings.HasSuffix(label, suffix) {
			return true
		}
	}
	return false
}

// Adds to brands what one - token reads as, and answers whether it or an earlier token reads as a
// keyword. The token is read after §12.5's mapping, as the brand rule reads it: as a brand or a
// keyword when its mapped form is one, and as every brand and keyword of every way its mapped form
// splits into brands and keywords written together, as paypalsupport splits into paypal and
// support. A token that does not split so, pineapple say, reads as nothing, so a brand inside an
// ordinary word, or a short brand such as ur inside secure, counts for nothing.
func (self *screenList) readToken(token string, brands []*screenBrand, keyword bool) ([]*screenBrand, bool) {
	skeleton := dnsBrandSkeleton(token)
	count := len(skeleton)
	if count == 0 {
		return brands, keyword
	}
	// whether skeleton[:index] splits into pieces, and whether skeleton[index:] does
	prefixSplits := make([]bool, count+1)
	suffixSplits := make([]bool, count+1)
	prefixSplits[0] = true
	for index := range count {
		if !prefixSplits[index] {
			continue
		}
		for _, piece := range self.firstBytePieces[skeleton[index]] {
			if strings.HasPrefix(skeleton[index:], piece.skeleton) {
				prefixSplits[index+len(piece.skeleton)] = true
			}
		}
	}
	if !prefixSplits[count] {
		return brands, keyword
	}
	suffixSplits[count] = true
	for index := count - 1; 0 <= index; index -= 1 {
		for _, piece := range self.firstBytePieces[skeleton[index]] {
			if strings.HasPrefix(skeleton[index:], piece.skeleton) && suffixSplits[index+len(piece.skeleton)] {
				suffixSplits[index] = true
				break
			}
		}
	}
	// a piece counts when some whole split of the token holds it
	for index := range count {
		if !prefixSplits[index] {
			continue
		}
		for _, piece := range self.firstBytePieces[skeleton[index]] {
			if !strings.HasPrefix(skeleton[index:], piece.skeleton) || !suffixSplits[index+len(piece.skeleton)] {
				continue
			}
			for _, brand := range piece.brands {
				if !slices.Contains(brands, brand) {
					brands = append(brands, brand)
				}
			}
			keyword = keyword || piece.keyword
		}
	}
	return brands, keyword
}
