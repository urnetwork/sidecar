// §16.7's redactor (record_redact.go): recall 1.0 on testdata/redact's synthetic corpus with false positives capped,
// an auth key's bundle covered whole, markers stable under one key and only under it, idempotence, PII by the harness
// config, and time linear in a 1 MiB adversarial line, counted by the work the rules do.

package sidecar

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	mathrand "math/rand/v2"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// testdata/redact/corpus.json, compiled in, so the js leg reads it too.
//
//go:embed testdata/redact/corpus.json
var redactTestCorpusJson []byte

// The corpus: synthetic positives as templates and benign negatives.
type redactTestCorpus struct {
	Comment          string `json:"comment"`
	FalsePositiveCap int    `json:"false_positive_cap"`
	Positives        []struct {
		Rule string `json:"rule"`
		Text string `json:"text"`
	} `json:"positives"`
	Negatives []string `json:"negatives"`
}

// The corpus, which must decode.
func loadRedactTestCorpus(t *testing.T) *redactTestCorpus {
	t.Helper()
	corpus := &redactTestCorpus{}
	if err := json.Unmarshal(redactTestCorpusJson, corpus); err != nil {
		t.Fatal(err)
	}
	return corpus
}

// The corpus's character classes.
var redactTestClasses = map[string]string{
	"alnum":    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	"lower":    "abcdefghijklmnopqrstuvwxyz0123456789",
	"upper":    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	"letters":  "abcdefghijklmnopqrstuvwxyz",
	"hex":      "0123456789abcdef",
	"b32":      "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
	"b32lower": "abcdefghijklmnopqrstuvwxyz234567",
	"b64":      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
	"b64url":   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
	"digits":   "0123456789",
	"age":      "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L",
}

var redactTestPlaceholder = regexp.MustCompile(`\{([a-z0-9]+):([0-9]+)\}`)

// A corpus text expanded from its seed: every placeholder filled, and the secret's span between « and ».
func expandRedactTestText(t *testing.T, text string, seed uint64) (string, int, int) {
	t.Helper()
	random := mathrand.New(mathrand.NewPCG(seed, 0x5eed))
	expanded := redactTestPlaceholder.ReplaceAllStringFunc(text, func(placeholder string) string {
		groups := redactTestPlaceholder.FindStringSubmatch(placeholder)
		class, ok := redactTestClasses[groups[1]]
		if !ok {
			t.Fatalf("class %s", groups[1])
		}
		count, _ := strconv.Atoi(groups[2])
		out := make([]byte, count)
		for i := range out {
			out[i] = class[random.IntN(len(class))]
		}
		return string(out)
	})
	start := strings.Index(expanded, "«")
	if start < 0 {
		return expanded, -1, -1
	}
	expanded = strings.Replace(expanded, "«", "", 1)
	end := strings.Index(expanded, "»")
	expanded = strings.Replace(expanded, "»", "", 1)
	return expanded, start, end
}

// A redactor with a key from crypto/rand.
func newTestRedactor(t *testing.T) *Redactor {
	t.Helper()
	redactor, err := NewRedactor(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return redactor
}

// Every rule compiles, and every id is a marker's form.
func TestRedactRulesCompile(t *testing.T) {
	marker := regexp.MustCompile(`^[a-z0-9-]+$`)
	for _, compiled := range redactCompiledRules() {
		if !marker.MatchString(compiled.rule.id) {
			t.Errorf("rule id %q", compiled.rule.id)
		}
		for _, keyword := range compiled.rule.keywords {
			if keyword != strings.ToLower(keyword) {
				t.Errorf("%s: keyword %q is not lowercase", compiled.rule.id, keyword)
			}
		}
	}
}

// Recall 1.0 on the synthetic corpus: each positive's secret leaves the text, and a match of its rule covers it; no
// negative redacts more than the cap allows.
func TestRedactorRecall(t *testing.T) {
	corpus := loadRedactTestCorpus(t)
	redactor := newTestRedactor(t)
	for i, positive := range corpus.Positives {
		text, start, end := expandRedactTestText(t, positive.Text, uint64(i+1))
		secret := text[start:end]
		redacted, matches := redactor.Redact([]byte(text))
		if bytes.Contains(redacted, []byte(secret)) {
			t.Errorf("%s: the secret survived in %q", positive.Rule, redacted)
		}
		covered := slices.ContainsFunc(matches, func(match RedactMatch) bool {
			return match.Rule == positive.Rule && match.Start <= start && end <= match.End
		})
		if !covered {
			t.Errorf("%s: no match of the rule covers the secret: %+v", positive.Rule, matches)
		}
		if !bytes.Contains(redacted, []byte("[REDACTED:"+positive.Rule+":")) {
			t.Errorf("%s: no marker of the rule in %q", positive.Rule, redacted)
		}
	}
	falsePositiveCount := 0
	for _, negative := range corpus.Negatives {
		if _, matches := redactor.Redact([]byte(negative)); len(matches) != 0 {
			falsePositiveCount += 1
			t.Logf("false positive %+v in %q", matches, negative)
		}
	}
	if corpus.FalsePositiveCap < falsePositiveCount {
		t.Errorf("%d false positives, cap %d", falsePositiveCount, corpus.FalsePositiveCap)
	}
	covered := map[string]bool{}
	for _, positive := range corpus.Positives {
		covered[positive.Rule] = true
	}
	for _, id := range []string{"private-key", "jwt", "ur-authkey", "urn-api-key", "ur-oauth-secret", "high-entropy",
		"pii-email", "pii-phone"} {
		if !covered[id] {
			t.Errorf("the corpus holds no case of %s", id)
		}
	}
}

// An auth key's client-only bundle is covered with its bearer, as one marker (§7.8).
func TestAuthKeyBundleRedactedWhole(t *testing.T) {
	text, _, _ := expandRedactTestText(t, "token ur-authkey-{b32lower:26}-{b32lower:52}#{b64url:180} end", 7)
	bundle := text[strings.Index(text, "#"):strings.Index(text, " end")]
	redacted, matches := newTestRedactor(t).Redact([]byte(text))
	if len(matches) != 1 || matches[0].Rule != "ur-authkey" {
		t.Fatalf("matches %+v", matches)
	}
	if bytes.Contains(redacted, []byte(bundle[1:])) || bytes.Contains(redacted, []byte("#")) {
		t.Errorf("the bundle survived: %q", redacted)
	}
	if !strings.HasPrefix(string(redacted), "token [REDACTED:ur-authkey:") || !strings.HasSuffix(string(redacted), "] end") {
		t.Errorf("redacted %q", redacted)
	}
}

// The same secret under one key reads as one marker; another key, or the next epoch, gives another.
func TestMarkerStablePerKey(t *testing.T) {
	text, start, end := expandRedactTestText(t, "a=«ghp_{alnum:36}» b=ghp_", 3)
	secret := text[start:end]
	text = text + secret[len("ghp_"):]
	redactor := newTestRedactor(t)
	redacted, matches := redactor.Redact([]byte(text))
	if len(matches) != 2 {
		t.Fatalf("matches %+v", matches)
	}
	markers := regexp.MustCompile(`\[REDACTED:github-pat:[0-9a-f]{8}\]`).FindAll(redacted, -1)
	if len(markers) != 2 || !bytes.Equal(markers[0], markers[1]) {
		t.Fatalf("markers %q", markers)
	}
	other, _ := newTestRedactor(t).Redact([]byte(text))
	if bytes.Equal(other, redacted) {
		t.Error("another key gave the same marker")
	}
	if err := redactor.Rotate(rand.Reader); err != nil {
		t.Fatal(err)
	}
	if rotated, _ := redactor.Redact([]byte(text)); bytes.Equal(rotated, redacted) {
		t.Error("a rotated key gave the same marker")
	}
}

func TestRedactIsIdempotent(t *testing.T) {
	corpus := loadRedactTestCorpus(t)
	redactor := newTestRedactor(t)
	for i, positive := range corpus.Positives {
		text, _, _ := expandRedactTestText(t, positive.Text, uint64(i+1))
		once, _ := redactor.Redact([]byte(text))
		twice, matches := redactor.Redact(once)
		if !bytes.Equal(once, twice) || len(matches) != 0 {
			t.Errorf("%s: a second pass changed %q to %q (%+v)", positive.Rule, once, twice, matches)
		}
		shared, _ := redactor.RedactShared([]byte(text))
		if again, matches := redactor.RedactShared(shared); !bytes.Equal(shared, again) || len(matches) != 0 {
			t.Errorf("%s: a second shared pass changed %q", positive.Rule, shared)
		}
	}
}

// Shared text takes the marker with no HMAC; Scan rewrites nothing and reports no PII; PII off leaves PII alone.
func TestRedactSharedScanAndPii(t *testing.T) {
	text, _, _ := expandRedactTestText(t, "mail alice@example.com the key ghp_{alnum:36} now", 5)
	redactor := newTestRedactor(t)
	shared, _ := redactor.RedactShared([]byte(text))
	if string(shared) != "mail [REDACTED:pii-email] the key [REDACTED:github-pat] now" {
		t.Errorf("shared %q", shared)
	}
	scanned := redactor.Scan([]byte(text))
	if len(scanned) != 1 || scanned[0].Rule != "github-pat" {
		t.Errorf("scan %+v", scanned)
	}
	redactor.SetPiiHashing(false)
	redacted, matches := redactor.Redact([]byte(text))
	if len(matches) != 1 || !bytes.Contains(redacted, []byte("alice@example.com")) {
		t.Errorf("with PII off: %q, %+v", redacted, matches)
	}
}

// No match, and so no error or log built from one, carries the value it covers.
func TestRedactMatchesCarryNoValue(t *testing.T) {
	text, start, end := expandRedactTestText(t, "STRIPE_KEY=«sk_live_{alnum:24}»\n", 11)
	_, matches := newTestRedactor(t).Redact([]byte(text))
	if printed := fmt.Sprintf("%+v %v", matches, matches); strings.Contains(printed, text[start:end]) {
		t.Errorf("a match prints its value: %s", printed)
	}
}

// A 1 MiB line built to wake every rule and near-miss each: the redactor hands its regexes at most one pass of the
// text per rule, RE2 makes each pass linear, and the line redacts whole.
func TestLinearTime(t *testing.T) {
	unit := "key=abcdefghi curl -H x ey eyJ.eyJ ghp_ AKIA @ + sk_live_ urn_ ur-authkey- -----BEGIN PRIVATE KEY----- " +
		"token: x [REDACTED:jwt] passwd=ab s. hvs. xoxb- glpat- "
	line := []byte(strings.Repeat(unit, 1024*1024/len(unit)+1)[:1024*1024])
	matches, work := findRedactMatches(line, true)
	ruleCount := len(redactCompiledRules())
	if ruleCount*len(line) < work {
		t.Errorf("work %d over %d rules' single pass of %d bytes", work, ruleCount, len(line))
	}
	redacted, _ := newTestRedactor(t).Redact(line)
	if len(redacted) == 0 {
		t.Error("nothing came back")
	}
	t.Logf("%d matches, %d bytes of regex work", len(matches), work)
}
