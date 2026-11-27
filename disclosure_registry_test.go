//go:build !ios_extension && !sidecar_http

// The disclosure registry (CTRUST-M11-01) on a fixture store built from testdata/disclosure/: §2.8's ids, the version-1
// texts held to DESIGN-COMPUTE.md byte for byte, which ids ask, the locale's fallback, and a registry with no policy or
// with an entry it refuses.
//
// testdata/disclosure/disclosures.json is the fixture disclosures line. Its English texts are DESIGN-COMPUTE.md's
// version 1, each fence's wrapped lines joined with a space, the enclave form filled with each provider's <inside> line
// and the connect form with each service's <revocation> line, connect:custom's <service> worded generically (QD-1440);
// its one translation is a test translation. With
// SIDECAR_REGENERATE_DISCLOSURE_FIXTURE=1, TestComputeDisclosureTextsVersion1 writes the English texts again from the
// design, keeping each entry's version, grace, instant and translations.

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The fixture line's file.
var testDisclosureFixturePath = filepath.Join("testdata", "disclosure", "disclosures.json")

// What the fixture fills support:urnetwork's <retention> with: a test value, not any agreement's words (§28.13).
const testDisclosureRetention = "30 days"

// The fixture's disclosures line.
func testDisclosureFixture(t testing.TB) []*ComputePolicyDisclosure {
	t.Helper()
	data, err := os.ReadFile(testDisclosureFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	disclosures := []*ComputePolicyDisclosure{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&disclosures); err != nil {
		t.Fatal(err)
	}
	return disclosures
}

// A policy at version 3 carrying the fixture's line, its TEE providers Chutes and the three enclave providers, all AP,
// and its direct providers engy and SayGM, labeled none.
func testDisclosurePolicy(t testing.TB) *ComputePolicy {
	t.Helper()
	return &ComputePolicy{
		Version: 3,
		Providers: []*ComputePolicyProvider{
			{Id: "chutes", Label: ComputeLabelAp},
			{Id: "hippius", Label: ComputeLabelAp},
			{Id: "lium", Label: ComputeLabelAp},
			{Id: "cathedral", Label: ComputeLabelAp},
		},
		Direct: ComputePolicyDirectLine{Providers: []*ComputePolicyDirect{
			{Slug: "engy", Models: []*ComputePolicyDirectModel{{Model: "glm-5.2"}}},
			{Slug: "saygm", Models: []*ComputePolicyDirectModel{{Model: "kimi-k2-tee"}}},
		}},
		Disclosures: testDisclosureFixture(t),
	}
}

// A source a test sets the newest policy of.
type testDisclosureSource struct {
	policy *ComputePolicy
}

func (self *testDisclosureSource) Newest() *ComputePolicy {
	return self.policy
}

// A registry over source with the default settings.
func newTestDisclosureRegistry(t testing.TB, source ComputeDisclosureSource) *ComputeDisclosureRegistry {
	t.Helper()
	registry, err := NewComputeDisclosureRegistry(&ComputeDisclosureRegistryArgs{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

// One disclosure's text as a design fence writes it.
type testDisclosureDesignText struct {
	header  string
	summary string
	exposed []string
	private []string
}

// The fences of language text in the section of DESIGN-COMPUTE.md whose heading starts with heading.
func testDisclosureDesignFences(t *testing.T, design string, heading string) []string {
	t.Helper()
	start := strings.Index(design, "\n"+heading)
	if start < 0 {
		t.Fatalf("DESIGN-COMPUTE.md has no section %q", heading)
	}
	section := design[start+1:]
	if end := regexp.MustCompile(`\n#{2,3} `).FindStringIndex(section[len(heading):]); end != nil {
		section = section[:len(heading)+end[0]]
	}
	fences := []string{}
	for {
		open := strings.Index(section, "```text\n")
		if open < 0 {
			return fences
		}
		section = section[open+len("```text\n"):]
		close := strings.Index(section, "```")
		if close < 0 {
			t.Fatalf("section %q has an unclosed fence", heading)
		}
		fences = append(fences, section[:close])
		section = section[close+3:]
	}
}

// A fence's disclosures, each item's wrapped lines joined with a space: by header line (a text with none under the
// key ""), and the fill lists after them (<inside>, by provider; <revocation>, by service), name to line.
func testDisclosureDesignParse(t *testing.T, fence string) (map[string]*testDisclosureDesignText, map[string]map[string]string) {
	t.Helper()
	texts := map[string]*testDisclosureDesignText{}
	fills := map[string]map[string]string{}
	var text *testDisclosureDesignText
	section := ""
	// the fill list being read, and the name of its last line, which a continuation joins
	fill, fillName := "", ""
	var last *string
	for _, line := range strings.Split(fence, "\n") {
		switch {
		case strings.Contains(line, " · version "):
			text = &testDisclosureDesignText{header: line}
			texts[strings.SplitN(line, " · ", 2)[0]] = text
			section, last = "header", nil
		case strings.HasPrefix(line, "Summary: "):
			text.summary = strings.TrimPrefix(line, "Summary: ")
			section, last = "summary", &text.summary
		case line == "Could be exposed" || line == "Private":
			if text == nil {
				text = &testDisclosureDesignText{}
				texts[""] = text
			}
			section, last = line, nil
		case strings.HasSuffix(line, ", by provider:") || strings.HasSuffix(line, ", by service:"):
			fill = strings.SplitN(line, ",", 2)[0]
			fills[fill] = map[string]string{}
			section, last = "fill", nil
		case line == "":
			last = nil
		case strings.HasPrefix(line, "- "):
			item := strings.TrimPrefix(line, "- ")
			switch section {
			case "Could be exposed":
				text.exposed = append(text.exposed, item)
				last = &text.exposed[len(text.exposed)-1]
			case "Private":
				text.private = append(text.private, item)
				last = &text.private[len(text.private)-1]
			case "fill":
				name, value, found := strings.Cut(item, ": ")
				if !found {
					t.Fatalf("a fill line without its name: %q", line)
				}
				// "Hippius (CPU, AMD SEV-SNP)" names Hippius
				name, _, _ = strings.Cut(name, " (")
				fills[fill][name] = value
				fillName, last = name, nil
			default:
				t.Fatalf("an item outside a list: %q", line)
			}
		case strings.HasPrefix(line, "  "):
			more := strings.TrimSpace(line)
			if section == "fill" {
				fills[fill][fillName] += " " + more
				continue
			}
			if last == nil {
				t.Fatalf("a continuation with no item: %q", line)
			}
			*last += " " + more
		default:
			if section == "summary" && last != nil {
				*last += " " + line
				continue
			}
			t.Fatalf("a fence line this parse does not know: %q", line)
		}
	}
	return texts, fills
}

// The first letter raised to a capital: a fill that opens a list item.
func testDisclosureCapital(text string) string {
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

// text with each placeholder replaced.
func testDisclosureFilled(text *testDisclosureDesignText, replacements map[string]string) *testDisclosureDesignText {
	fill := func(value string) string {
		for placeholder, replacement := range replacements {
			value = strings.ReplaceAll(value, placeholder, replacement)
		}
		return value
	}
	filled := &testDisclosureDesignText{header: fill(text.header), summary: fill(text.summary)}
	for _, item := range text.exposed {
		filled.exposed = append(filled.exposed, fill(item))
	}
	for _, item := range text.private {
		filled.private = append(filled.private, fill(item))
	}
	return filled
}

// Version 1 of each id the fixture carries, from DESIGN-COMPUTE.md: §2.8's four inference texts and the enclave form
// filled for each provider, §21.6's search, §25.12's connect form for Google and Microsoft, and for connect:custom with
// <service> worded generically (QD-1440, question ctrust-m11-01-connect-custom-text), §26.6's listeners, §27.11's
// automatic approvals and §28.13's support with the fixture's retention.
func testDisclosureDesignVersion1(t *testing.T) map[string]*testDisclosureDesignText {
	t.Helper()
	data, err := os.ReadFile("DESIGN-COMPUTE.md")
	if err != nil {
		t.Fatal(err)
	}
	design := string(data)
	version1 := map[string]*testDisclosureDesignText{}

	fences := testDisclosureDesignFences(t, design, "### 2.8 ")
	if len(fences) != 1 {
		t.Fatalf("§2.8 holds %d text fences, want 1", len(fences))
	}
	texts, fills := testDisclosureDesignParse(t, fences[0])
	for _, id := range []string{"inference:local", "inference:chutes", "inference:engy", "inference:saygm"} {
		if texts[id] == nil {
			t.Fatalf("§2.8 holds no %s", id)
		}
		version1[id] = texts[id]
	}
	enclave := texts["enclave:<provider>"]
	if enclave == nil || len(fills["<inside>"]) != 3 {
		t.Fatalf("§2.8's enclave form %v, its <inside> lines %v", enclave, fills["<inside>"])
	}
	for name, inside := range fills["<inside>"] {
		// <inside> fills the middle of a sentence, so its list line's closing period goes
		version1["enclave:"+strings.ToLower(name)] = testDisclosureFilled(enclave, map[string]string{
			"<provider>": name, "<inside>": strings.TrimSuffix(inside, "."),
		})
	}

	fences = testDisclosureDesignFences(t, design, "### 21.6 ")
	texts, _ = testDisclosureDesignParse(t, fences[0])
	search := texts[""]
	if search == nil || search.summary != "" {
		t.Fatalf("§21.6's text %v", search)
	}
	// §21.6's text has no Summary line; its To the UI row gives "the disclosure's one-line summary", which DESIGN-UI.md's
	// T12 repeats
	toTheUi := regexp.MustCompile(`the disclosure's one-line summary, "([^"]+)"`).FindStringSubmatch(design)
	if toTheUi == nil {
		t.Fatal("§21.6 names no one-line summary")
	}
	search.summary = toTheUi[1]
	version1["search:parallel"] = search

	fences = testDisclosureDesignFences(t, design, "### 25.12 ")
	texts, fills = testDisclosureDesignParse(t, fences[0])
	connect := texts["connect:<service>"]
	if connect == nil {
		t.Fatal("§25.12 holds no connect form")
	}
	for _, name := range []string{"Google", "Microsoft"} {
		revocation, found := fills["<revocation>"][name]
		if !found {
			t.Fatalf("§25.12 holds no <revocation> line for %s", name)
		}
		version1["connect:"+strings.ToLower(name)] = testDisclosureFilled(connect, map[string]string{
			"<service>": name, "<revocation>": testDisclosureCapital(revocation),
		})
	}
	// connect:custom names no service: <service> worded generically, as QD-1440 answers with its examples, "your account
	// at a service you added yourself" and "that service", an item's first word raised to a capital, and its own
	// <revocation> line
	custom := ""
	for name, revocation := range fills["<revocation>"] {
		if strings.HasPrefix(name, "connect:custom") {
			custom = revocation
		}
	}
	if custom == "" {
		t.Fatal("§25.12 holds no <revocation> line for connect:custom")
	}
	generic := testDisclosureFilled(connect, map[string]string{
		"your <service> account": "your account at a service you added yourself", "<revocation>": testDisclosureCapital(custom),
	})
	for i, item := range generic.exposed {
		generic.exposed[i] = testDisclosureCapital(strings.ReplaceAll(item, "<service>", "that service"))
	}
	for i, item := range generic.private {
		generic.private[i] = testDisclosureCapital(strings.ReplaceAll(item, "<service>", "that service"))
	}
	generic.summary = strings.ReplaceAll(generic.summary, "<service>", "that service")
	version1["connect:custom"] = generic

	for heading, id := range map[string]string{"### 26.6 ": "listeners:publish", "### 27.11 ": "approvals:auto", "### 28.13 ": "support:urnetwork"} {
		found := false
		for _, fence := range testDisclosureDesignFences(t, design, heading) {
			if !strings.Contains(fence, "\nCould be exposed\n") {
				// another of the section's fences, such as §26.6's repo kind
				continue
			}
			texts, _ = testDisclosureDesignParse(t, fence)
			if text := texts[id]; text != nil {
				version1[id] = testDisclosureFilled(text, map[string]string{"<retention>": testDisclosureRetention})
				found = true
			}
		}
		if !found {
			t.Fatalf("%s holds no %s", heading, id)
		}
	}
	return version1
}

// Each fixture text is its section's version 1, byte for byte, the three enclave texts the one form filled with each
// provider's line; each header's asks words are the registry's.
func TestComputeDisclosureTextsVersion1(t *testing.T) {
	version1 := testDisclosureDesignVersion1(t)
	if os.Getenv("SIDECAR_REGENERATE_DISCLOSURE_FIXTURE") == "1" {
		testDisclosureRegenerateFixture(t, version1)
	}
	fixture := testDisclosureFixture(t)
	ids := []string{}
	for _, entry := range fixture {
		ids = append(ids, entry.Id)
		want := version1[entry.Id]
		if want == nil {
			t.Errorf("the fixture carries %s, which no section's version 1 gives", entry.Id)
			continue
		}
		english := entry.English()
		if entry.Version != 1 || entry.Revision != 0 || english == nil || entry.Locales[0] != english {
			t.Errorf("%s: version %d revision %d, English first %v", entry.Id, entry.Version, entry.Revision, english != nil)
			continue
		}
		if english.Summary != want.summary {
			t.Errorf("%s's summary\n%q\nwant\n%q", entry.Id, english.Summary, want.summary)
		}
		if !slices.Equal(english.Exposed, want.exposed) {
			t.Errorf("%s's could be exposed\n%q\nwant\n%q", entry.Id, english.Exposed, want.exposed)
		}
		if !slices.Equal(english.Private, want.private) {
			t.Errorf("%s's private\n%q\nwant\n%q", entry.Id, english.Private, want.private)
		}
	}
	for id := range version1 {
		if !slices.Contains(ids, id) {
			t.Errorf("the fixture lacks %s", id)
		}
	}

	// the header's asks words are the design's header lines' last part
	registry := newTestDisclosureRegistry(t, &testDisclosureSource{policy: testDisclosurePolicy(t)})
	for id, text := range version1 {
		if text.header == "" {
			continue
		}
		view, err := registry.View(id, "")
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(text.header, " · ")
		if view.AsksText != parts[len(parts)-1] {
			t.Errorf("%s asks %q, the design's header %q", id, view.AsksText, parts[len(parts)-1])
		}
	}
}

// Writes the fixture's English texts from version1, keeping each entry's version, grace, instant and translations, and
// an entry for each id version1 gives that the fixture lacks.
func testDisclosureRegenerateFixture(t *testing.T, version1 map[string]*testDisclosureDesignText) {
	t.Helper()
	fixture := []*ComputePolicyDisclosure{}
	if _, err := os.Stat(testDisclosureFixturePath); err == nil {
		fixture = testDisclosureFixture(t)
	}
	// §2.8's order, then search, connect, listeners, approvals and support
	order := []string{
		"inference:local", "inference:chutes", "inference:engy", "inference:saygm",
		"enclave:hippius", "enclave:lium", "enclave:cathedral",
		"search:parallel", "connect:google", "connect:microsoft", "connect:custom",
		"listeners:publish", "approvals:auto", "support:urnetwork",
	}
	regenerated := []*ComputePolicyDisclosure{}
	for _, id := range order {
		text := version1[id]
		if text == nil {
			t.Fatalf("no version 1 of %s", id)
		}
		english := &ComputePolicyDisclosureText{Locale: computePolicyEnglish, Summary: text.summary, Exposed: text.exposed, Private: text.private}
		entry := &ComputePolicyDisclosure{Id: id, Version: 1, GraceDays: 14, SinceMs: 1796083200000, Locales: []*ComputePolicyDisclosureText{english}}
		if index := slices.IndexFunc(fixture, func(held *ComputePolicyDisclosure) bool { return held.Id == id }); 0 <= index {
			held := fixture[index]
			entry.Version, entry.Revision, entry.GraceDays, entry.SinceMs = held.Version, held.Revision, held.GraceDays, held.SinceMs
			entry.Locales = append(entry.Locales, held.Locales[1:]...)
		}
		regenerated = append(regenerated, entry)
	}
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(regenerated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(testDisclosureFixturePath, buffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Each family parses; an unknown family, capitals, an empty or oversize slug, a space and a trailing colon are refused,
// as is a second id of a family §2.8 names one of.
func TestComputeDisclosureIdParse(t *testing.T) {
	settings := DefaultComputeDisclosureSettings()
	for _, text := range []string{
		"search:parallel", "inference:local", "inference:chutes", "inference:engy-2", "enclave:hippius", "connect:google",
		"connect:custom", "listeners:publish", "approvals:auto", "support:urnetwork",
		"inference:" + strings.Repeat("a", settings.IdSlugMaxByteCount),
	} {
		id, err := ParseComputeDisclosureId(text, settings)
		if err != nil || id.String() != text {
			t.Errorf("%q: %v, %v", text, id, err)
		}
	}
	for _, text := range []string{
		"", "search", "weather:today", "Search:parallel", "inference:Chutes", "inference:", "inference:chutes ",
		"inference:chu tes", "search:parallel:", "inference:-engy", "inference:engy-", "inference:en--gy",
		"inference:" + strings.Repeat("a", settings.IdSlugMaxByteCount+1), "listeners:all", "approvals:manual",
		"support:recurd", ":parallel", "inference:é",
	} {
		if _, err := ParseComputeDisclosureId(text, settings); !errors.Is(err, ErrComputeDisclosureIdInvalid) {
			t.Errorf("%q: %v, want refused", text, err)
		}
	}
	// the error never repeats what it was given
	if _, err := ParseComputeDisclosureId("inference:SECRETTEXT", settings); err == nil || strings.Contains(err.Error(), "SECRETTEXT") {
		t.Errorf("an error that repeats its input: %v", err)
	}
	// a non-positive bound refuses every id
	if _, err := ParseComputeDisclosureId("search:parallel", &ComputeDisclosureSettings{}); err == nil {
		t.Error("a zero slug bound took an id")
	}
}

// engy and SayGM ask, their -tee names included, since the id is the provider's; Chutes and local do not; enclave,
// search, connect, listeners, approvals:auto and support do.
func TestComputeDisclosureAsks(t *testing.T) {
	registry := newTestDisclosureRegistry(t, &testDisclosureSource{policy: testDisclosurePolicy(t)})
	for id, want := range map[string]struct {
		asks  bool
		label ComputeLabel
	}{
		"inference:local":   {asks: false, label: ComputeLabelLocal},
		"inference:chutes":  {asks: false, label: ComputeLabelAp},
		"inference:engy":    {asks: true, label: ComputeLabelNone},
		"inference:saygm":   {asks: true, label: ComputeLabelNone},
		"enclave:hippius":   {asks: true, label: ComputeLabelAp},
		"enclave:lium":      {asks: true, label: ComputeLabelAp},
		"enclave:cathedral": {asks: true, label: ComputeLabelAp},
		"search:parallel":   {asks: true},
		"connect:google":    {asks: true},
		"connect:microsoft": {asks: true},
		"listeners:publish": {asks: true},
		"approvals:auto":    {asks: true},
		"support:urnetwork": {asks: true},
	} {
		disclosure, err := registry.Disclosure(id)
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		if disclosure.Asks != want.asks || disclosure.Label != want.label {
			t.Errorf("%s asks %v label %q, want %v %q", id, disclosure.Asks, disclosure.Label, want.asks, want.label)
		}
	}
	// a model's disclosure is its provider's: SayGM's -tee model asks under inference:saygm
	settings := DefaultInferSettings()
	for name, want := range map[string]bool{"saygm-kimi-k2-tee-high": true, "engy-glm-5.2-high": true, "chutes-qwen3.8-27b-tee-high": false, "local-gemma-4-e4b-off": false} {
		model, err := InferParseModelName(name, settings)
		if err != nil {
			t.Fatal(err)
		}
		disclosure, err := registry.Disclosure(string(ComputeDisclosureFamilyInference) + ":" + model.Provider)
		if err != nil || disclosure.Asks != want {
			t.Errorf("%s: %v asks %v, want %v", name, err, disclosure != nil && disclosure.Asks, want)
		}
	}
	// a provider the policy names nowhere asks, the closed side, and labels nothing
	policy := testDisclosurePolicy(t)
	policy.Direct.Providers = nil
	unlisted := newTestDisclosureRegistry(t, &testDisclosureSource{policy: policy})
	if disclosure, err := unlisted.Disclosure("inference:engy"); err != nil || !disclosure.Asks || disclosure.Label != "" {
		t.Errorf("an unlisted provider: %v, %+v", err, disclosure)
	}
}

// The person's locale where the policy has it, matched by tag and then by language, else English, never mixed.
func TestComputeDisclosureLocaleFallback(t *testing.T) {
	registry := newTestDisclosureRegistry(t, &testDisclosureSource{policy: testDisclosurePolicy(t)})
	disclosure, err := registry.Disclosure("inference:local")
	if err != nil {
		t.Fatal(err)
	}
	german := disclosure.Entry.Text("de")
	english := disclosure.Entry.English()
	if german == nil || english == nil {
		t.Fatal("the fixture's inference:local lacks its English or its test translation")
	}
	for locale, want := range map[string]*ComputePolicyDisclosureText{
		"":                              english,
		"en":                            english,
		"en-US":                         english,
		"de":                            german,
		"DE":                            german,
		"de-AT":                         german,
		"de_DE.UTF-8":                   german,
		"de_DE@euro":                    german,
		"fr":                            english,
		"fr-CA":                         english,
		"C":                             english,
		"POSIX":                         english,
		"d":                             english,
		"de-":                           english,
		"not a tag":                     english,
		"de-" + strings.Repeat("a", 40): english,
	} {
		if got := disclosure.Text(locale); got != want {
			t.Errorf("%q shows %q, want %q", locale, got.Locale, want.Locale)
		}
	}
	// a view in German is German whole; an id without a translation is English whole
	view, err := registry.View("inference:local", "de-CH")
	if err != nil {
		t.Fatal(err)
	}
	if view.Locale != "de" || view.Summary != german.Summary || !slices.Equal(view.Exposed, german.Exposed) || !slices.Equal(view.Private, german.Private) {
		t.Errorf("the German view mixes locales: %+v", view)
	}
	view, err = registry.View("inference:engy", "de-CH")
	if err != nil {
		t.Fatal(err)
	}
	engy := testDisclosurePolicy(t).Disclosure("inference:engy").English()
	if view.Locale != "en" || view.Summary != engy.Summary || !slices.Equal(view.Exposed, engy.Exposed) {
		t.Errorf("an id with no translation: %+v", view)
	}
	// a translation the registry does not take falls back to English whole
	policy := testDisclosurePolicy(t)
	policy.Disclosure("inference:local").Text("de").Summary = "zwei\nZeilen"
	broken := newTestDisclosureRegistry(t, &testDisclosureSource{policy: policy})
	if line, err := broken.Line("inference:local", "de"); err != nil || line != english.Summary {
		t.Errorf("a broken translation shows %q, %v", line, err)
	}
}

// With no verified policy the registry answers policy_unavailable and renders nothing; once a policy arrives it reads
// it, and a newer one replaces it.
func TestComputeDisclosureNoSource(t *testing.T) {
	source := &testDisclosureSource{}
	registry := newTestDisclosureRegistry(t, source)
	if _, err := registry.Disclosures(); !errors.Is(err, ErrComputeDisclosurePolicyUnavailable) {
		t.Errorf("Disclosures: %v", err)
	}
	if line, err := registry.Line("inference:local", ""); !errors.Is(err, ErrComputeDisclosurePolicyUnavailable) || line != "" {
		t.Errorf("Line: %q, %v", line, err)
	}
	if list, err := registry.List(""); !errors.Is(err, ErrComputeDisclosurePolicyUnavailable) || list != nil {
		t.Errorf("List: %v, %v", list, err)
	}
	if _, err := registry.HarnessTexts("").Text(t.Context(), "inference:engy", 1); !errors.Is(err, ErrComputeDisclosurePolicyUnavailable) {
		t.Errorf("Text: %v", err)
	}
	if !strings.HasPrefix(ErrComputeDisclosurePolicyUnavailable.Error(), ComputeDisclosureCodePolicyUnavailable) {
		t.Errorf("the error does not lead with its code: %v", ErrComputeDisclosurePolicyUnavailable)
	}
	if _, err := NewComputeDisclosureRegistry(&ComputeDisclosureRegistryArgs{}); err == nil {
		t.Error("a registry with no source")
	}

	source.policy = testDisclosurePolicy(t)
	list, err := registry.List("")
	if err != nil || list.PolicyVersion != 3 || len(list.Disclosures) != len(source.policy.Disclosures) {
		t.Fatalf("a policy arrived: %v, %+v", err, list)
	}
	newer := testDisclosurePolicy(t)
	newer.Version = 4
	newer.Disclosures = newer.Disclosures[:1]
	source.policy = newer
	if list, err = registry.List(""); err != nil || list.PolicyVersion != 4 || len(list.Disclosures) != 1 {
		t.Errorf("a newer policy: %v, %+v", err, list)
	}
	if _, err := registry.Disclosure("search:parallel"); !errors.Is(err, ErrComputeDisclosureNotCarried) {
		t.Errorf("an id the policy no longer carries: %v", err)
	}
}

// An entry without an English summary, with English not first, with an empty item, still holding a form's
// placeholder, of version 0 or outside §2.8's ids is refused, saying why, and the others stand.
func TestComputeDisclosureRefusesMissingSummary(t *testing.T) {
	cases := map[string]func(entry *ComputePolicyDisclosure){
		"no English summary": func(entry *ComputePolicyDisclosure) { entry.Locales[0].Summary = "  " },
		"a two-line summary": func(entry *ComputePolicyDisclosure) { entry.Locales[0].Summary = "one\ntwo" },
		"English not first": func(entry *ComputePolicyDisclosure) {
			entry.Locales = []*ComputePolicyDisclosureText{{Locale: "de", Summary: "Zusammenfassung."}}
		},
		"no locale":            func(entry *ComputePolicyDisclosure) { entry.Locales = nil },
		"an empty item":        func(entry *ComputePolicyDisclosure) { entry.Locales[0].Exposed = append(entry.Locales[0].Exposed, " ") },
		"an unfilled form":     func(entry *ComputePolicyDisclosure) { entry.Locales[0].Private[0] = "<provider> itself reads it." },
		"version 0":            func(entry *ComputePolicyDisclosure) { entry.Version = 0 },
		"an id outside §2.8's": func(entry *ComputePolicyDisclosure) { entry.Id = "weather:today" },
	}
	for name, change := range cases {
		policy := testDisclosurePolicy(t)
		entry := policy.Disclosure("search:parallel")
		change(entry)
		registry := newTestDisclosureRegistry(t, &testDisclosureSource{policy: policy})
		disclosure, err := registry.Disclosure("search:parallel")
		switch {
		case entry.Id != "search:parallel":
			if !errors.Is(err, ErrComputeDisclosureNotCarried) {
				t.Errorf("%s: %v", name, err)
			}
		case !errors.Is(err, ErrComputeDisclosureRefused) || disclosure != nil:
			t.Errorf("%s: %v, %v", name, disclosure, err)
		}
		if line, err := registry.Line("search:parallel", ""); err == nil || line != "" {
			t.Errorf("%s: a refused entry's line %q", name, line)
		}
		disclosures, err := registry.Disclosures()
		if err != nil || len(disclosures) != len(policy.Disclosures)-1 {
			t.Errorf("%s: the others: %d of %d, %v", name, len(disclosures), len(policy.Disclosures), err)
		}
	}
}

// The fixture line is a disclosures line the real format takes: in a policy signed by the test compute-policy key and
// verified by a production build's verifier, every entry renders, each locale's text equal to the fixture's byte for
// byte.
func TestComputeDisclosureFixtureVerifies(t *testing.T) {
	fixture, err := os.ReadFile(testDisclosureFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	members := map[string]json.RawMessage{}
	if err := json.Unmarshal(testAttestPolicyDocument(t), &members); err != nil {
		t.Fatal(err)
	}
	members["disclosures"] = json.RawMessage(fixture)
	document, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := testAttestVerifyDocument(t, document)
	if err != nil {
		t.Fatal(err)
	}
	registry := newTestDisclosureRegistry(t, &testDisclosureSource{policy: policy})
	disclosures, err := registry.Disclosures()
	if err != nil {
		t.Fatal(err)
	}
	want := testDisclosureFixture(t)
	if len(disclosures) != len(want) {
		t.Fatalf("%d of the fixture's %d render", len(disclosures), len(want))
	}
	for i, disclosure := range disclosures {
		for _, text := range want[i].Locales {
			got := disclosure.Text(text.Locale)
			if got.Locale != text.Locale || got.Summary != text.Summary || !slices.Equal(got.Exposed, text.Exposed) || !slices.Equal(got.Private, text.Private) {
				t.Errorf("%s in %s does not render as the fixture holds it", want[i].Id, text.Locale)
			}
		}
	}
}
