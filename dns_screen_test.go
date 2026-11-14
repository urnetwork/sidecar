// §21.6's screen (ABUSE-M5-01; QD-807), T1 on every leg: testdata/dns/screen.json's vectors for both
// entry points, each rule with its twin; the reserved block never allowed as a name whatever the
// facts, and allowed as a host in a network's zone, www, api, status and login among it, while
// §12.7's owners stay refused there; every curated brand needing its own domain and every brand with
// a keyword going to review; URnetwork's own names never unlocked; a host and a name screening alike
// outside the block and §12.7's table; how the facts may move a verdict, over a corpus of brands,
// keywords and words; and the lists' agreement with dns_brand_labels.txt. The vectors and fuzz seeds
// are embedded, since the page Worker's leg has no file system to read them from.

package sidecar

import (
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"
)

//go:embed testdata/dns/screen.json testdata/fuzz/FuzzScreenName
var testDnsScreenFiles embed.FS

// One vector's facts. verified_brands expands to those brands' domains as ScreenBrands lists them,
// * to every brand's, so the vectors hold no real domain.
type testScreenFacts struct {
	VerifiedBrands  []string `json:"verified_brands"`
	VerifiedDomains []string `json:"verified_domains"`
	Probation       bool     `json:"probation"`
	ReviewAllowed   bool     `json:"review_allowed"`
	ScopeLabels     []string `json:"scope_labels"`
}

// One vector of screen.json. Facts null is a label draw to ScreenName and nothing known to
// ScreenHost.
type testScreenCase struct {
	Name string `json:"name"`
	// name or empty for ScreenName, host for ScreenHost
	Screen  string           `json:"screen"`
	Facts   *testScreenFacts `json:"facts"`
	Verdict string           `json:"verdict"`
	Why     string           `json:"why"`
}

// The vectors' words for the verdicts.
var testScreenVerdicts = map[string]ScreenVerdict{
	"deny":   ScreenVerdictDeny,
	"review": ScreenVerdictReview,
	"allow":  ScreenVerdictAllow,
}

// The vectors' words for the entry points.
var testScreens = map[string]func(string, *ScreenFacts) ScreenVerdict{
	"":     ScreenName,
	"name": ScreenName,
	"host": ScreenHost,
}

// Every domain of every brand, which verifies whatever can be verified.
func testScreenAllDomains() []string {
	domains := []string{}
	for _, brand := range ScreenBrands() {
		domains = append(domains, brand.Domains...)
	}
	return domains
}

// The domains of the named brand, or a test failure for a brand the list lacks.
func testScreenBrandDomains(t *testing.T, name string) []string {
	t.Helper()
	for _, brand := range ScreenBrands() {
		if brand.Brand == name {
			return brand.Domains
		}
	}
	t.Fatalf("no brand %q", name)
	return nil
}

func testScreenCases(t *testing.T) []testScreenCase {
	t.Helper()
	data, err := testDnsScreenFiles.ReadFile("testdata/dns/screen.json")
	if err != nil {
		t.Fatal(err)
	}
	vectors := struct {
		Cases []testScreenCase `json:"cases"`
	}{}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) < 60 {
		t.Fatalf("%d vectors", len(vectors.Cases))
	}
	return vectors.Cases
}

// Each vector's verdict through its entry point, and every rule has a deny and a twin that is not;
// both entry points have vectors.
func TestScreenVectors(t *testing.T) {
	screenCounts := map[string]int{}
	for _, c := range testScreenCases(t) {
		want, ok := testScreenVerdicts[c.Verdict]
		if !ok {
			t.Fatalf("%q: unknown verdict %q", c.Name, c.Verdict)
		}
		screen, ok := testScreens[c.Screen]
		if !ok {
			t.Fatalf("%q: unknown screen %q", c.Name, c.Screen)
		}
		var facts *ScreenFacts
		if c.Facts != nil {
			facts = &ScreenFacts{
				VerifiedDomains: slices.Clone(c.Facts.VerifiedDomains),
				Probation:       c.Facts.Probation,
				ReviewAllowed:   c.Facts.ReviewAllowed,
				ScopeLabels:     slices.Clone(c.Facts.ScopeLabels),
			}
			for _, name := range c.Facts.VerifiedBrands {
				if name == "*" {
					facts.VerifiedDomains = append(facts.VerifiedDomains, testScreenAllDomains()...)
					continue
				}
				facts.VerifiedDomains = append(facts.VerifiedDomains, testScreenBrandDomains(t, name)...)
			}
		}
		if got := screen(c.Name, facts); got != want {
			t.Errorf("screen %q of %q under %+v = %s, want %s (%s)", c.Screen, c.Name, c.Facts, got, want, c.Why)
		}
		screenCounts[c.Screen] += 1
	}
	if screenCounts["host"] < 40 {
		t.Fatalf("%d host vectors", screenCounts["host"])
	}
}

// Every combination of the facts that can bear on a verdict: none, every domain verified, review
// allowed and probation.
func testScreenFactsSet() []*ScreenFacts {
	factsSet := []*ScreenFacts{}
	for _, domains := range [][]string{nil, testScreenAllDomains()} {
		for _, probation := range []bool{false, true} {
			for _, reviewAllowed := range []bool{false, true} {
				factsSet = append(factsSet, &ScreenFacts{
					VerifiedDomains: domains,
					Probation:       probation,
					ReviewAllowed:   reviewAllowed,
				})
			}
		}
	}
	return factsSet
}

// §12.5's block as names: each of its labels, and each pattern at its shortest instance and a longer
// one.
func testScreenReservedForms(t *testing.T) []string {
	t.Helper()
	forms := dnsListLines(dnsReservedLabelsText)
	forms = slices.DeleteFunc(forms, func(line string) bool {
		return strings.Contains(line, "*")
	})
	for _, pattern := range ReservedDnsPatterns() {
		for _, fill := range []string{"x", "plenty"} {
			forms = append(forms, strings.Replace(pattern, "*", fill, 1))
		}
	}
	if len(forms) < 80 {
		t.Fatalf("%d reserved forms", len(forms))
	}
	return forms
}

// The plan's "reserved (IsReservedDnsLabel)" is §12.5's block: IsReservedDnsLabel counts the curated
// brands too, and those are the brand rule's. Each of the block's labels, and each pattern at its
// shortest instance and a longer one, is denied under every facts and as a draw, so a label or an
// alias is never www or api (QD-807 keeps this).
func TestScreenNameNeverAllowsTheReservedBlock(t *testing.T) {
	forms := testScreenReservedForms(t)
	factsSet := append(testScreenFactsSet(), nil)
	for _, form := range forms {
		for _, facts := range factsSet {
			if verdict := ScreenName(form, facts); verdict != ScreenVerdictDeny {
				t.Errorf("ScreenName(%q, %+v) = %s", form, facts, verdict)
			}
		}
	}
	// the only labels IsReservedDnsLabel counts that the screen's block does not are curated brands
	for _, label := range ReservedDnsLabels() {
		if dnsScreenList.isReserved(label) {
			continue
		}
		brand, ok := dnsScreenList.nameBrands[label]
		if !ok || brand.sealed {
			t.Errorf("%q is reserved, but neither in the block nor a curated brand", label)
		}
	}
}

// QD-807: inside a network's zone §12.5's block does not apply. Each of its forms that is neither one
// of §12.7's system hosts nor URnetwork's own allows as a host under every facts, nothing known
// included, while it stays denied as a name; www, api, status and login are among them. The rest stay
// denied as hosts too: mail, mx and mta-sts by §12.7's table, URnetwork's five by the brand rule.
func TestScreenHostAllowsTheReservedBlockInTheZone(t *testing.T) {
	factsSet := append(testScreenFactsSet(), nil)
	allowedForms := []string{}
	for _, form := range testScreenReservedForms(t) {
		brand := dnsScreenList.nameBrands[form]
		kept := slices.Contains(screenZoneSystemHosts, form) || (brand != nil && brand.sealed)
		for _, facts := range factsSet {
			hostVerdict := ScreenHost(form, facts)
			switch {
			case kept && hostVerdict != ScreenVerdictDeny:
				t.Errorf("ScreenHost(%q, %+v) = %s, want deny", form, facts, hostVerdict)
			case !kept && hostVerdict != ScreenVerdictAllow:
				t.Errorf("ScreenHost(%q, %+v) = %s, want allow", form, facts, hostVerdict)
			}
			if verdict := ScreenName(form, facts); verdict != ScreenVerdictDeny {
				t.Errorf("ScreenName(%q, %+v) = %s", form, facts, verdict)
			}
		}
		if !kept {
			allowedForms = append(allowedForms, form)
		}
	}
	for _, host := range []string{"www", "api", "status", "login", "x-lb", "main-plenty"} {
		if !slices.Contains(allowedForms, host) {
			t.Errorf("%q is not among the block's forms a host may take", host)
		}
	}
	if len(allowedForms) < 70 {
		t.Fatalf("only %d of the block's forms allow as hosts", len(allowedForms))
	}
}

// §12.7's owner table in a network's zone: the system hosts b, mx, mail and mta-sts, a word-number
// label, an underscore owner, * and @ deny as hosts under every facts, nothing known included, and so
// does each of the network's scope labels, in any case, beside a host that is none. The system hosts
// are §12.7's four, the same as mail_address.go's zone labels.
func TestScreenHostKeepsSection127sOwners(t *testing.T) {
	if !slices.Equal(screenZoneSystemHosts, []string{"b", "mx", "mail", "mta-sts"}) {
		t.Fatalf("system hosts %v", screenZoneSystemHosts)
	}
	if !slices.Equal(slices.Sorted(slices.Values(screenZoneSystemHosts)), slices.Sorted(slices.Values(mailZoneRefusedLabels))) {
		t.Fatalf("system hosts %v, mail's zone labels %v", screenZoneSystemHosts, mailZoneRefusedLabels)
	}
	owners := slices.Concat(screenZoneSystemHosts, []string{
		"otter-4821", "a-0000", "_dmarc", "_acme-challenge", "_mta-sts", "_domainkey", "_note", "*", "@",
	})
	factsSet := append(testScreenFactsSet(), nil)
	for _, owner := range owners {
		for _, facts := range factsSet {
			if verdict := ScreenHost(owner, facts); verdict != ScreenVerdictDeny {
				t.Errorf("ScreenHost(%q, %+v) = %s", owner, facts, verdict)
			}
		}
	}
	for _, facts := range testScreenFactsSet() {
		facts.ScopeLabels = []string{"sales", "East"}
		for _, scopeLabel := range []string{"sales", "east"} {
			if verdict := ScreenHost(scopeLabel, facts); verdict != ScreenVerdictDeny {
				t.Errorf("scope label %q under %+v = %s", scopeLabel, facts, verdict)
			}
		}
		if verdict := ScreenHost("west", facts); verdict != ScreenVerdictAllow {
			t.Errorf("west beside scopes %v = %s", facts.ScopeLabels, verdict)
		}
		// the name screen reads no scope labels
		if verdict := ScreenName("sales", facts); verdict != ScreenVerdictAllow {
			t.Errorf("ScreenName(sales) beside scopes %v = %s", facts.ScopeLabels, verdict)
		}
	}
}

// Over the corpus, a host answers what checkScreenHost holds: like a name under every network's facts
// outside §12.5's block and §12.7's table, as the brand rules answer inside the block, and with nil
// facts as with nothing known on probation; and the facts move a host's verdict one way, as a name's.
func TestScreenHostMatchesScreenNameOutsideTheBlock(t *testing.T) {
	names := testScreenCorpus()
	allDomains := testScreenAllDomains()
	differNames := []string{}
	for _, name := range names {
		if failure := checkScreenHost(name, allDomains); failure != "" {
			t.Errorf("%q: %s", name, failure)
		}
		if ScreenHost(name, &ScreenFacts{}) != ScreenName(name, &ScreenFacts{}) {
			differNames = append(differNames, name)
		}
	}
	// the corpus's reserved words alone differ, so the properties are not held vacuously; joined to
	// another token they are no label of the block, and screen alike
	for _, name := range []string{"www", "login", "status"} {
		if !slices.Contains(differNames, name) {
			t.Errorf("%q screens alike as a host and a name", name)
		}
	}
	if slices.Contains(differNames, "www-login") {
		t.Error("www-login screens differently as a host and a name")
	}
}

// Every curated brand: denied as a name with nothing verified, a mapped spelling of it too; allowed
// with each one of its own domains, in any case and with a trailing dot; denied with a subdomain of
// one, a lookalike, or a domain only other brands list.
func TestScreenNameCuratedBrandsNeedTheirOwnDomain(t *testing.T) {
	mappedCount := 0
	for _, brand := range ScreenBrands() {
		if dnsScreenList.nameBrands[brand.Brand].sealed {
			continue
		}
		if len(brand.Domains) == 0 {
			t.Errorf("%q has no domain", brand.Brand)
			continue
		}
		// a spelling that maps back to the brand, where one of the mapping's letters is in it
		mapped := strings.NewReplacer("o", "0", "l", "1", "e", "3", "s", "5").Replace(brand.Brand)
		names := []string{brand.Brand, brand.Brand + "-cloud", "my-" + brand.Brand}
		if mapped != brand.Brand {
			names = append(names, mapped)
			mappedCount += 1
		}
		for _, name := range names {
			if verdict := ScreenName(name, &ScreenFacts{}); verdict != ScreenVerdictDeny {
				t.Errorf("ScreenName(%q) with nothing verified = %s", name, verdict)
			}
			if verdict := ScreenName(name, nil); verdict != ScreenVerdictDeny {
				t.Errorf("ScreenName(%q) as a draw = %s", name, verdict)
			}
			for _, domain := range brand.Domains {
				for _, form := range []string{domain, strings.ToUpper(domain) + "."} {
					if verdict := ScreenName(name, &ScreenFacts{VerifiedDomains: []string{form}}); verdict != ScreenVerdictAllow {
						t.Errorf("ScreenName(%q) with %q verified = %s", name, form, verdict)
					}
				}
				refusedDomains := []string{"shop." + domain, domain + ".example", strings.ReplaceAll(domain, ".", "-") + ".example"}
				for _, refusedDomain := range refusedDomains {
					if verdict := ScreenName(name, &ScreenFacts{VerifiedDomains: []string{refusedDomain}}); verdict != ScreenVerdictDeny {
						t.Errorf("ScreenName(%q) with %q verified = %s", name, refusedDomain, verdict)
					}
				}
			}
			otherDomains := slices.DeleteFunc(testScreenAllDomains(), func(domain string) bool {
				return slices.Contains(brand.Domains, domain)
			})
			if verdict := ScreenName(name, &ScreenFacts{VerifiedDomains: otherDomains, ReviewAllowed: true}); verdict != ScreenVerdictDeny {
				t.Errorf("ScreenName(%q) with only other brands' domains verified = %s", name, verdict)
			}
		}
	}
	if mappedCount < 30 {
		t.Fatalf("only %d brands have a mapped spelling", mappedCount)
	}
}

// Every curated brand with every keyword, in either order, apart or written together: review with
// nothing known, refused on probation and as a draw, allowed once reviewed, and the brand's domain
// skipping no review.
func TestScreenNameBrandPlusKeywordGoesToReview(t *testing.T) {
	count := 0
	for _, brand := range ScreenBrands() {
		if dnsScreenList.nameBrands[brand.Brand].sealed {
			continue
		}
		for _, keyword := range screenKeywords {
			names := []string{
				brand.Brand + "-" + keyword,
				keyword + "-" + brand.Brand,
				brand.Brand + keyword,
				keyword + brand.Brand,
				"my-" + brand.Brand + "-" + keyword + "-desk",
			}
			for _, name := range names {
				count += 1
				checks := []struct {
					facts *ScreenFacts
					want  ScreenVerdict
				}{
					{facts: &ScreenFacts{}, want: ScreenVerdictReview},
					{facts: &ScreenFacts{VerifiedDomains: brand.Domains}, want: ScreenVerdictReview},
					{facts: &ScreenFacts{Probation: true}, want: ScreenVerdictDeny},
					{facts: nil, want: ScreenVerdictDeny},
					{facts: &ScreenFacts{ReviewAllowed: true}, want: ScreenVerdictAllow},
					{facts: &ScreenFacts{Probation: true, ReviewAllowed: true}, want: ScreenVerdictDeny},
				}
				for _, check := range checks {
					if verdict := ScreenName(name, check.facts); verdict != check.want {
						t.Errorf("ScreenName(%q, %+v) = %s, want %s", name, check.facts, verdict, check.want)
					}
				}
			}
		}
	}
	if count < 1000 {
		t.Fatalf("%d names", count)
	}
}

// URnetwork's own names, which §12.5's block reserves, are denied as a name, a token, a mapped token
// or written together with a keyword, under every facts: no domain unlocks them and no review.
func TestScreenNameNeverUnlocksUrnetworksOwnNames(t *testing.T) {
	sealedCount := 0
	factsSet := append(testScreenFactsSet(), nil)
	for _, brand := range ScreenBrands() {
		if !dnsScreenList.nameBrands[brand.Brand].sealed {
			continue
		}
		sealedCount += 1
		if len(brand.Domains) != 0 {
			t.Errorf("%q lists domains, which nothing reads", brand.Brand)
		}
		names := []string{
			brand.Brand,
			brand.Brand + "-cloud",
			"the-" + brand.Brand + "-site",
			brand.Brand + "-support",
			"login-" + brand.Brand,
			brand.Brand + "wallet",
			strings.ReplaceAll(brand.Brand, "m", "rn"),
			strings.ReplaceAll(brand.Brand, "rn", "m") + "-team",
		}
		for _, name := range names {
			for _, facts := range factsSet {
				if verdict := ScreenName(name, facts); verdict != ScreenVerdictDeny {
					t.Errorf("ScreenName(%q, %+v) = %s", name, facts, verdict)
				}
			}
		}
	}
	if sealedCount != 5 {
		t.Fatalf("%d of URnetwork's names, want §12.5's five", sealedCount)
	}
}

// A corpus for the facts' properties: every brand, every keyword, and words that hold a brand or a
// keyword without being one, reserved labels and a word-number name, each alone and in pairs joined
// by a dash and written together, with a mapped spelling of each brand alone.
func testScreenCorpus() []string {
	tokens := []string{"river", "cloud", "my", "your", "pineapple", "secures", "groups", "www", "login", "status", "otter-4821", "a", "x1"}
	for _, brand := range ScreenBrands() {
		tokens = append(tokens, brand.Brand)
	}
	tokens = append(tokens, screenKeywords...)
	slices.Sort(tokens)
	tokens = slices.Compact(tokens)
	names := slices.Clone(tokens)
	for _, brand := range ScreenBrands() {
		names = append(names, strings.NewReplacer("o", "0", "l", "1").Replace(brand.Brand))
	}
	for _, first := range tokens {
		for _, second := range tokens {
			names = append(names, first+"-"+second, first+second)
		}
	}
	return names
}

// How the facts may move a verdict, over the corpus, from each facts the others vary: a reviewer's
// allow turns a review into an allow and changes nothing else, so it never turns a deny into an
// allow; probation never raises a verdict; verifying every domain never lowers one; and with nil
// facts no name goes to review.
func TestScreenNameFactsMoveVerdictsOneWay(t *testing.T) {
	names := testScreenCorpus()
	if len(names) < 9000 {
		t.Fatalf("%d names", len(names))
	}
	allDomains := testScreenAllDomains()
	counts := map[ScreenVerdict]int{}
	for _, name := range names {
		if failure := checkScreenFacts(ScreenName, name, allDomains); failure != "" {
			t.Errorf("%q: %s", name, failure)
		}
		counts[ScreenName(name, &ScreenFacts{})] += 1
	}
	// the corpus reaches all three verdicts, so the properties are not held vacuously
	for _, verdict := range []ScreenVerdict{ScreenVerdictDeny, ScreenVerdictReview, ScreenVerdictAllow} {
		if counts[verdict] < 100 {
			t.Errorf("only %d names %s", counts[verdict], verdict)
		}
	}
}

// What a facts property name breaks through screen, ScreenName or ScreenHost, or empty when it
// breaks none. allDomains verifies every brand.
func checkScreenFacts(screen func(string, *ScreenFacts) ScreenVerdict, name string, allDomains []string) string {
	if verdict := screen(name, nil); verdict == ScreenVerdictReview {
		return "nil facts went to review"
	}
	for _, domains := range [][]string{nil, allDomains} {
		for _, probation := range []bool{false, true} {
			without := screen(name, &ScreenFacts{VerifiedDomains: domains, Probation: probation})
			with := screen(name, &ScreenFacts{VerifiedDomains: domains, Probation: probation, ReviewAllowed: true})
			if with != without && !(without == ScreenVerdictReview && with == ScreenVerdictAllow) {
				return "a reviewer's allow turned " + without.String() + " into " + with.String()
			}
		}
		for _, reviewAllowed := range []bool{false, true} {
			standard := screen(name, &ScreenFacts{VerifiedDomains: domains, ReviewAllowed: reviewAllowed})
			probation := screen(name, &ScreenFacts{VerifiedDomains: domains, Probation: true, ReviewAllowed: reviewAllowed})
			if standard < probation {
				return "probation raised " + standard.String() + " to " + probation.String()
			}
		}
	}
	for _, probation := range []bool{false, true} {
		for _, reviewAllowed := range []bool{false, true} {
			unverified := screen(name, &ScreenFacts{Probation: probation, ReviewAllowed: reviewAllowed})
			verified := screen(name, &ScreenFacts{VerifiedDomains: allDomains, Probation: probation, ReviewAllowed: reviewAllowed})
			if verified < unverified {
				return "verifying lowered " + unverified.String() + " to " + verified.String()
			}
		}
	}
	return ""
}

// What name breaks of the host screen's properties, or empty when it breaks none. allDomains verifies
// every brand.
//   - A name that is not one lowercase label, or has dashes as its third and fourth characters, or is
//     one of §12.7's system hosts or a word-number name, denies as a host under every facts, nil
//     included, and any other denies as one of the network's scope labels.
//   - Any other name answers as a host what the brand rules answer, under every facts, so §12.5's
//     block never denies a host by itself; outside the block, a host and a name answer alike under
//     every network's facts.
//   - nil facts answer as nothing known on probation, and the facts move a host's verdict as
//     TestScreenNameFactsMoveVerdictsOneWay says of a name's.
func checkScreenHost(name string, allDomains []string) string {
	factsSet := append(testScreenFactsSet(), nil)
	shapeBroken := !isDnsLowerLdhLabel(name) || (4 <= len(name) && name[2:4] == "--")
	if shapeBroken || slices.Contains(screenZoneSystemHosts, name) || IsWordNumberDnsLabel(name) {
		for _, facts := range factsSet {
			if verdict := ScreenHost(name, facts); verdict != ScreenVerdictDeny {
				return "a host every facts must deny was " + verdict.String()
			}
		}
		return ""
	}
	if verdict := ScreenHost(name, &ScreenFacts{VerifiedDomains: allDomains, ScopeLabels: []string{"other", strings.ToUpper(name)}}); verdict != ScreenVerdictDeny {
		return "a scope label was " + verdict.String() + " as a host"
	}
	for _, facts := range factsSet {
		host := ScreenHost(name, facts)
		if brands := dnsScreenList.screenBrands(name, facts); host != brands {
			return "a host was " + host.String() + " where the brand rules answer " + brands.String()
		}
		if facts != nil && !dnsScreenList.isReserved(name) {
			if screened := ScreenName(name, facts); screened != host {
				return "outside §12.5's block, a host was " + host.String() + " and a name " + screened.String()
			}
		}
	}
	if nothingKnown, probation := ScreenHost(name, nil), ScreenHost(name, &ScreenFacts{Probation: true}); nothingKnown != probation {
		return "a host with nil facts was " + nothingKnown.String() + ", on probation " + probation.String()
	}
	return checkScreenFacts(ScreenHost, name, allDomains)
}

// Every brand of dns_brand_labels.txt has a line in dns_screen_brands.txt and no other brand does,
// each curated brand with a domain and URnetwork's five with none; ScreenBrands is sorted and a copy.
func TestScreenBrandsCoverTheBrandLabels(t *testing.T) {
	labelBrands := dnsListLines(dnsBrandLabelsText)
	lineBrands := []string{}
	for _, line := range dnsListLines(dnsScreenBrandsText) {
		fields := strings.Fields(line)
		lineBrands = append(lineBrands, fields[0])
		sealed := dnsScreenList.isReserved(fields[0])
		if sealed && len(fields) != 1 {
			t.Errorf("%q is URnetwork's and lists domains", fields[0])
		}
		if !sealed && len(fields) < 2 {
			t.Errorf("%q lists no domain", fields[0])
		}
	}
	slices.Sort(labelBrands)
	slices.Sort(lineBrands)
	if !slices.Equal(labelBrands, lineBrands) {
		t.Fatalf("dns_brand_labels.txt holds\n%v\nand dns_screen_brands.txt\n%v", labelBrands, lineBrands)
	}
	brands := ScreenBrands()
	names := []string{}
	for _, brand := range brands {
		names = append(names, brand.Brand)
	}
	if !slices.Equal(names, labelBrands) {
		t.Fatalf("ScreenBrands is\n%v\nwant\n%v", names, labelBrands)
	}
	// a copy, so a caller cannot change the list
	for index := range brands {
		if 0 < len(brands[index].Domains) {
			brands[index].Domains[0] = "changed.example"
			if ScreenBrands()[index].Domains[0] == "changed.example" {
				t.Fatal("ScreenBrands shares its domains with callers")
			}
			break
		}
	}
}

// §21.6's seven keywords, word for word.
func TestScreenKeywordsAreTheDesigns(t *testing.T) {
	want := []string{"login", "secure", "verify", "account", "support", "wallet", "update"}
	if !slices.Equal(screenKeywords, want) {
		t.Fatalf("keywords %v, want %v", screenKeywords, want)
	}
}

// A line that breaks dns_screen_brands.txt's format refuses the whole list; a brand only one file
// holds is still a brand; a sealed brand's domains are dropped.
func TestScreenListRefusesMalformedLines(t *testing.T) {
	refused := []string{
		"Brand brand.example\n",
		"has-dash brand.example\n",
		"brand Brand.example\n",
		"brand example\n",
		"brand brand..example\n",
		"brand -brand.example\n",
		"brand brand.example.\n",
		"brand brand_x.example\n",
		"brand brand.example brand.example\n",
		"brand brand.example\nbrand other.example\n",
		"brand " + strings.Repeat("a", 64) + ".example\n",
		"brand " + strings.Repeat(strings.Repeat("a", 60)+".", 5) + "example\n",
	}
	for _, screenText := range refused {
		if _, err := parseScreenList(screenText, "brand\n", "www\n"); err == nil {
			t.Errorf("parsed %q", screenText)
		}
	}
	if _, err := parseScreenList("", "Upper\n", "www\n"); err == nil {
		t.Error("parsed a brand label that is not lowercase")
	}
	if _, err := parseScreenList("", "", "www\n"); err == nil {
		t.Error("parsed no brands")
	}
	list, err := parseScreenList("# a comment\n\n  alpha  alpha.example   alpha-pay.example \nbeta\nwww www.example\n", "alpha\ngamma\nwww\n", "www\n")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(list.sortedBrandNames, []string{"alpha", "beta", "gamma", "www"}) {
		t.Fatalf("brands %v", list.sortedBrandNames)
	}
	if alpha := list.nameBrands["alpha"]; alpha.sealed || !slices.Equal(alpha.domains, []string{"alpha.example", "alpha-pay.example"}) {
		t.Fatalf("alpha: %+v", alpha)
	}
	if beta := list.nameBrands["beta"]; beta.sealed || len(beta.domains) != 0 {
		t.Fatalf("beta: %+v", beta)
	}
	if www := list.nameBrands["www"]; !www.sealed || len(www.domains) != 0 {
		t.Fatalf("www: %+v", www)
	}
}

// The words a verdict prints as.
func TestScreenVerdictString(t *testing.T) {
	for word, verdict := range testScreenVerdicts {
		if verdict.String() != word {
			t.Errorf("%d prints %q, want %q", int(verdict), verdict.String(), word)
		}
	}
	if !strings.Contains(ScreenVerdict(7).String(), "7") {
		t.Errorf("an unknown verdict prints %q", ScreenVerdict(7).String())
	}
	var verdict ScreenVerdict
	if verdict != ScreenVerdictDeny {
		t.Fatal("the zero verdict does not deny")
	}
}

// What name breaks of FuzzScreenName's properties, or empty when it breaks none. allDomains verifies
// every brand.
//   - A name ValidateDnsName refuses is never allowed as a draw, and, with nothing verified or
//     reviewed, never allowed unless ValidateDnsName's length bound alone refused it, since a host
//     may be shorter than a network name.
//   - Under every facts, a name that is not one lowercase label, or has an edge dash, or dashes as
//     its third and fourth characters, or is in §12.5's block, or is a word-number name, denies.
//   - The facts move verdicts only as TestScreenNameFactsMoveVerdictsOneWay says.
//   - As a host, it holds checkScreenHost's properties.
func checkScreenName(name string, allDomains []string) string {
	validateErr := ValidateDnsName(name)
	if verdict := ScreenName(name, nil); validateErr != nil && verdict != ScreenVerdictDeny {
		return "a draw ValidateDnsName refuses was " + verdict.String()
	}
	lengthAlone := errors.Is(validateErr, ErrDnsNameInvalid) && isDnsLowerBytes(name, "-")
	if verdict := ScreenName(name, &ScreenFacts{}); validateErr != nil && !lengthAlone && verdict == ScreenVerdictAllow {
		return "a name ValidateDnsName refuses (" + validateErr.Error() + ") was allowed"
	}
	shapeBroken := !isDnsLowerLdhLabel(name) || (4 <= len(name) && name[2:4] == "--")
	if shapeBroken || dnsScreenList.isReserved(name) || IsWordNumberDnsLabel(name) {
		for _, facts := range testScreenFactsSet() {
			if verdict := ScreenName(name, facts); verdict != ScreenVerdictDeny {
				return "a name every facts must deny was " + verdict.String()
			}
		}
	}
	if failure := checkScreenFacts(ScreenName, name, allDomains); failure != "" {
		return failure
	}
	return checkScreenHost(name, allDomains)
}

// The seeds hold the fuzz target's properties on every leg: go test runs them through FuzzScreenName
// only where a file system lets it read them, and the Worker has none.
func TestScreenNameFuzzSeedsHold(t *testing.T) {
	const directory = "testdata/fuzz/FuzzScreenName"
	entries, err := fs.ReadDir(testDnsScreenFiles, directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 10 {
		t.Fatalf("%d seeds", len(entries))
	}
	allDomains := testScreenAllDomains()
	for _, entry := range entries {
		seed, err := testDnsScreenFiles.ReadFile(directory + "/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		// the corpus files' format is FuzzValidateDnsName's, one string a file
		if failure := checkScreenName(testDnsNameSeed(t, entry.Name(), seed), allDomains); failure != "" {
			t.Errorf("%s: %s", entry.Name(), failure)
		}
	}
}
