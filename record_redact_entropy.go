// §16.7's high-entropy assignments: a value assigned to a name that says key, token, secret, password, credential or
// auth, whose characters carry more than 3.5 bits each. The pattern and the floor are gitleaks v8.30.1's
// generic-api-key (MIT; credited in NOTICE), with its two short allowlists: a value of letters, dots, dashes and
// underscores alone is an identifier, and a name such as api_version or public_key names no secret. gitleaks' list of
// stopwords is left out, so this rule errs toward redacting, which costs a word of transcript and never a secret.

package sidecar

import (
	"math"
)

// The high-entropy assignment rule, beside redactRules.
var redactEntropyRule = &redactRule{
	id:       "high-entropy",
	keywords: []string{"access", "api", "auth", "key", "credential", "creds", "passwd", "password", "secret", "token"},
	pattern: "(?i)(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \\t\\w.-]{0,20})" +
		"[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([\\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})" +
		redactTokenEnd,
	entropy:    3.5,
	allow:      []string{"^[a-zA-Z_.-]+$"},
	allowMatch: redactEntropyNameAllow,
}

// Names an assignment may carry that are no secret's, from gitleaks' generic-api-key allowlist, held against the
// whole match.
var redactEntropyNameAllow = []string{
	"(?i)(?:access(?:ibility|or)|access[_.-]?id|random[_.-]?access|api[_.-]?(?:id|name|version)|rapid|capital|author|" +
		"(?:credentials?[_.-]?id|withCredentials)|(?:bucket|foreign|hot|idx|natural|primary|pub(?:lic)?|schema|sequence)" +
		"[_.-]?key|key[_.-]?(?:alias|board|code|frame|id|length|name|pair|press(?:ed)?|ring|selector|signature|size|" +
		"stone|storetype|word|up|down|left|right)|key(?:store|tab)[_.-]?(?:file|path)|(?:secret)[_.-]?(?:length|name|size)|" +
		"(?:csrf)[_.-]?token|(?:api|credentials|token)[_.-]?(?:endpoint|ur[il])|public[_.-]?token|(?:key|token)[_.-]?file)",
}

// Shannon entropy in bits a character, over the text's runes, as gitleaks computes it.
func redactShannonEntropy(text []byte) float64 {
	if len(text) == 0 {
		return 0
	}
	runeCounts := map[rune]int{}
	runeCount := 0
	for _, r := range string(text) {
		runeCounts[r] += 1
		runeCount += 1
	}
	entropy := 0.0
	for _, count := range runeCounts {
		frequency := float64(count) / float64(runeCount)
		entropy -= frequency * math.Log2(frequency)
	}
	return entropy
}
