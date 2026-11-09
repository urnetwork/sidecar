// §21.6's screen (ABUSE-M5-01), T1 on every leg: testdata/dns/screen.json's vectors, each rule with
// its twin; the reserved block never allowed whatever the facts; every curated brand needing its
// own domain and every brand with a keyword going to review; URnetwork's own names never unlocked;
// how the facts may move a verdict, over a corpus of brands, keywords and words; and the lists'
// agreement with dns_brand_labels.txt. The vectors and fuzz seeds are embedded, since the page
// Worker's leg has no file system to read them from.

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
}

// One vector of screen.json. Facts null is a label draw.
type testScreenCase struct {
	Name    string           `json:"name"`
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

// Each vector's verdict, and every rule has a deny and a twin that is not.
func TestScreenNameVectors(t *testing.T) {
	for _, c := range testScreenCases(t) {
		want, ok := testScreenVerdicts[c.Verdict]
		if !ok {
			t.Fatalf("%q: unknown verdict %q", c.Name, c.Verdict)
		}
		var facts *ScreenFacts
		if c.Facts != nil {
			facts = &ScreenFacts{
				VerifiedDomains: slices.Clone(c.Facts.VerifiedDomains),
				Probation:       c.Facts.Probation,
				ReviewAllowed:   c.Facts.ReviewAllowed,
			}
			for _, name := range c.Facts.VerifiedBrands {
				if name == "*" {
					facts.VerifiedDomains = append(facts.VerifiedDomains, testScreenAllDomains()...)
					continue
				}
				facts.VerifiedDomains = append(facts.VerifiedDomains, testScreenBrandDomains(t, name)...)
			}
		}
		if got := ScreenName(c.Name, facts); got != want {
			t.Errorf("ScreenName(%q, %+v) = %s, want %s (%s)", c.Name, c.Facts, got, want, c.Why)
		}
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

// The plan's "reserved (IsReservedDnsLabel)" is §12.5's block: IsReservedDnsLabel counts the curated
// brands too, and those are the brand rule's. Each of the block's labels, and each pattern at its
// shortest instance and a longer one, is denied under every facts and as a draw.
func TestScreenNameNeverAllowsTheReservedBlock(t *testing.T) {
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
		if failure := checkScreenNameFacts(name, allDomains); failure != "" {
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

// What a facts property name breaks, or empty when it breaks none. allDomains verifies every brand.
func checkScreenNameFacts(name string, allDomains []string) string {
	if verdict := ScreenName(name, nil); verdict == ScreenVerdictReview {
		return "a draw went to review"
	}
	for _, domains := range [][]string{nil, allDomains} {
		for _, probation := range []bool{false, true} {
			without := ScreenName(name, &ScreenFacts{VerifiedDomains: domains, Probation: probation})
			with := ScreenName(name, &ScreenFacts{VerifiedDomains: domains, Probation: probation, ReviewAllowed: true})
			if with != without && !(without == ScreenVerdictReview && with == ScreenVerdictAllow) {
				return "a reviewer's allow turned " + without.String() + " into " + with.String()
			}
		}
		for _, reviewAllowed := range []bool{false, true} {
			standard := ScreenName(name, &ScreenFacts{VerifiedDomains: domains, ReviewAllowed: reviewAllowed})
			probation := ScreenName(name, &ScreenFacts{VerifiedDomains: domains, Probation: true, ReviewAllowed: reviewAllowed})
			if standard < probation {
				return "probation raised " + standard.String() + " to " + probation.String()
			}
		}
	}
	for _, probation := range []bool{false, true} {
		for _, reviewAllowed := range []bool{false, true} {
			unverified := ScreenName(name, &ScreenFacts{Probation: probation, ReviewAllowed: reviewAllowed})
			verified := ScreenName(name, &ScreenFacts{VerifiedDomains: allDomains, Probation: probation, ReviewAllowed: reviewAllowed})
			if verified < unverified {
				return "verifying lowered " + unverified.String() + " to " + verified.String()
			}
		}
	}
	return ""
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
	return checkScreenNameFacts(name, allDomains)
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
