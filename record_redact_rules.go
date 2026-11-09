// §16.7's redactor rules, as data: a rule is a row, and a new one needs no code. Most are a subset of gitleaks v8.30.1's
// config/gitleaks.toml (MIT, Copyright (c) 2019 Zachary Rice; credited in NOTICE), copied with their ids, regexes,
// keywords and entropy floors, chosen for the credentials a coding agent's transcript, tool calls and shell
// commands are likely to carry. To them §16.7 adds PEM private keys, JWTs, URnetwork's own formats (urn_ API keys,
// ur-authkey- auth keys with any #bundle, and ur_sk_ OAuth secrets), high-entropy assignments
// (record_redact_entropy.go), and, while the harness config hashes PII (QD-116's default), email addresses and E.164
// phone numbers.
//
// Every regex is RE2, so a match costs time linear in the text, and runs only when one of its keywords is in the
// lowercased text.

package sidecar

// One redaction rule.
type redactRule struct {
	// The marker's rule name, [a-z0-9-].
	id string
	// Lowercase strings any of which must appear in the lowercased text for the regex to run. Empty: it always runs.
	keywords []string
	pattern  string
	// The capture group holding the secret. 0 takes the first non-empty group, or the whole match when the pattern
	// has none, as gitleaks reads its rules.
	secretGroup int
	// The least Shannon entropy, in bits a character, a secret must pass; 0 checks none. A secret at or under it is
	// not one, as gitleaks reads its rules.
	entropy float64
	// Patterns a secret matching any of is not one.
	allow []string
	// Patterns a whole match containing a match of any of is not a secret: a name that says what it holds is none.
	allowMatch []string
	// A PII rule: run only while the harness config hashes PII, and never by Scan, since PII is no credential.
	pii bool
}

// gitleaks' trailing delimiter, which keeps a token from matching inside a longer word.
const redactTokenEnd = "(?:[\\x60'\"\\s;]|\\\\[nr]|$)"

// The rules, in the order a marker's rule is chosen where two overlap: §16.7's own first.
var redactRules = []*redactRule{
	// §16.7's PEM blocks: a private key's whole block, BEGIN to END, from gitleaks' private-key
	{
		id:       "private-key",
		keywords: []string{"-----begin"},
		pattern:  "(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\\s\\S-]{64,}?KEY(?: BLOCK)?-----",
	},
	// one a payload cut before its END: the header and the base64 that follows it
	{
		id:       "private-key",
		keywords: []string{"-----begin"},
		pattern:  "(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[A-Za-z0-9+/=\\s:,-]{16,}",
	},
	// §16.7's JWTs, gitleaks' jwt
	{
		id:       "jwt",
		keywords: []string{"ey"},
		pattern:  "\\b(ey[a-zA-Z0-9]{17,}\\.ey[a-zA-Z0-9\\/\\\\_-]{17,}\\.(?:[a-zA-Z0-9\\/\\\\_-]{10,}={0,2})?)" + redactTokenEnd,
		entropy:  3,
	},
	// URnetwork's auth key with any client-only #bundle, whole (§7.8): ur-authkey-<id>-<secret>[#<bundle>]
	{
		id:       "ur-authkey",
		keywords: []string{"ur-authkey-"},
		pattern:  "ur-authkey-[A-Za-z0-9_#-]+",
	},
	// URnetwork's API key (§7.8)
	{
		id:       "urn-api-key",
		keywords: []string{"urn_"},
		pattern:  "\\burn_[A-Za-z0-9_-]{8,}",
	},
	// URnetwork's OAuth client secret (§7.8)
	{
		id:       "ur-oauth-secret",
		keywords: []string{"ur_sk_"},
		pattern:  "\\bur_sk_[A-Za-z0-9_-]{8,}",
	},

	// gitleaks v8.30.1's rules
	{
		id:       "aws-access-token",
		keywords: []string{"a3t", "akia", "asia", "abia", "acca"},
		pattern:  "\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\\b",
		entropy:  3,
		allow:    []string{".+EXAMPLE$"},
	},
	{id: "github-pat", keywords: []string{"ghp_"}, pattern: "ghp_[0-9a-zA-Z]{36}", entropy: 3},
	{id: "github-fine-grained-pat", keywords: []string{"github_pat_"}, pattern: "github_pat_\\w{82}", entropy: 3},
	{id: "github-oauth", keywords: []string{"gho_"}, pattern: "gho_[0-9a-zA-Z]{36}", entropy: 3},
	{id: "github-app-token", keywords: []string{"ghu_", "ghs_"}, pattern: "(?:ghu|ghs)_[0-9a-zA-Z]{36}", entropy: 3},
	{id: "github-refresh-token", keywords: []string{"ghr_"}, pattern: "ghr_[0-9a-zA-Z]{36}", entropy: 3},
	{id: "gitlab-pat", keywords: []string{"glpat-"}, pattern: "glpat-[\\w-]{20}", entropy: 3},
	{
		id:       "gitlab-pat-routable",
		keywords: []string{"glpat-"},
		pattern:  "\\bglpat-[0-9a-zA-Z_-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
		entropy:  4,
	},
	{id: "gitlab-ptt", keywords: []string{"glptt-"}, pattern: "glptt-[0-9a-f]{40}", entropy: 3},
	{id: "gitlab-rrt", keywords: []string{"gr1348941"}, pattern: "GR1348941[\\w-]{20}", entropy: 3},
	{id: "slack-bot-token", keywords: []string{"xoxb"}, pattern: "xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", entropy: 3},
	{
		id:       "slack-user-token",
		keywords: []string{"xoxp-", "xoxe-"},
		pattern:  "xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}",
		entropy:  2,
	},
	{id: "slack-app-token", keywords: []string{"xapp"}, pattern: "(?i)xapp-\\d-[A-Z0-9]+-\\d+-[a-z0-9]+", entropy: 2},
	{
		id:       "slack-webhook-url",
		keywords: []string{"hooks.slack.com"},
		pattern:  "(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",
	},
	{
		id:       "slack-config-access-token",
		keywords: []string{"xoxe.xoxb-", "xoxe.xoxp-"},
		pattern:  "(?i)xoxe.xox[bp]-\\d-[A-Z0-9]{163,166}",
		entropy:  2,
	},
	{
		id:       "stripe-access-token",
		keywords: []string{"sk_test", "sk_live", "sk_prod", "rk_test", "rk_live", "rk_prod"},
		pattern:  "\\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})" + redactTokenEnd,
		entropy:  2,
	},
	{
		id:       "openai-api-key",
		keywords: []string{"t3blbkfj"},
		pattern: "\\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|" +
			"[A-Za-z0-9_-]{58})\\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})" + redactTokenEnd,
		entropy: 3,
	},
	{
		id:       "anthropic-api-key",
		keywords: []string{"sk-ant-api03"},
		pattern:  "\\b(sk-ant-api03-[a-zA-Z0-9_\\-]{93}AA)" + redactTokenEnd,
	},
	{
		id:       "anthropic-admin-api-key",
		keywords: []string{"sk-ant-admin01"},
		pattern:  "\\b(sk-ant-admin01-[a-zA-Z0-9_\\-]{93}AA)" + redactTokenEnd,
	},
	{id: "gcp-api-key", keywords: []string{"aiza"}, pattern: "\\b(AIza[\\w-]{35})" + redactTokenEnd, entropy: 4},
	{id: "npm-access-token", keywords: []string{"npm_"}, pattern: "(?i)\\b(npm_[a-z0-9]{36})" + redactTokenEnd, entropy: 2},
	{id: "pypi-upload-token", keywords: []string{"pypi-ageichlwas5vcmc"}, pattern: "pypi-AgEIcHlwaS5vcmc[\\w-]{50,1000}", entropy: 3},
	{
		id:       "sendgrid-api-token",
		keywords: []string{"sg."},
		pattern:  "\\b(SG\\.(?i)[a-z0-9=_\\-\\.]{66})" + redactTokenEnd,
		entropy:  2,
	},
	{id: "twilio-api-key", keywords: []string{"sk"}, pattern: "SK[0-9a-fA-F]{32}", entropy: 3},
	{
		id:       "huggingface-access-token",
		keywords: []string{"hf_"},
		pattern:  "\\b(hf_(?i:[a-z]{34}))" + redactTokenEnd,
		entropy:  2,
	},
	{
		id:       "huggingface-organization-api-token",
		keywords: []string{"api_org_"},
		pattern:  "\\b(api_org_(?i:[a-z]{34}))" + redactTokenEnd,
		entropy:  2,
	},
	{id: "digitalocean-pat", keywords: []string{"dop_v1_"}, pattern: "\\b(dop_v1_[a-f0-9]{64})" + redactTokenEnd, entropy: 3},
	{id: "digitalocean-access-token", keywords: []string{"doo_v1_"}, pattern: "\\b(doo_v1_[a-f0-9]{64})" + redactTokenEnd, entropy: 3},
	{id: "digitalocean-refresh-token", keywords: []string{"dor_v1_"}, pattern: "(?i)\\b(dor_v1_[a-f0-9]{64})" + redactTokenEnd},
	{id: "databricks-api-token", keywords: []string{"dapi"}, pattern: "\\b(dapi[a-f0-9]{32}(?:-\\d)?)" + redactTokenEnd, entropy: 3},
	{id: "shopify-access-token", keywords: []string{"shpat_"}, pattern: "shpat_[a-fA-F0-9]{32}", entropy: 2},
	{id: "shopify-custom-access-token", keywords: []string{"shpca_"}, pattern: "shpca_[a-fA-F0-9]{32}", entropy: 2},
	{id: "shopify-private-app-access-token", keywords: []string{"shppa_"}, pattern: "shppa_[a-fA-F0-9]{32}", entropy: 2},
	{id: "shopify-shared-secret", keywords: []string{"shpss_"}, pattern: "shpss_[a-fA-F0-9]{32}", entropy: 2},
	{id: "age-secret-key", keywords: []string{"age-secret-key-1"}, pattern: "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"},
	{
		id:       "hashicorp-tf-api-token",
		keywords: []string{"atlasv1"},
		pattern:  "(?i)[a-z0-9]{14}\\.(?-i:atlasv1)\\.[a-z0-9\\-_=]{60,70}",
		entropy:  3.5,
	},
	{
		id:       "vault-service-token",
		keywords: []string{"hvs.", "s."},
		pattern:  "\\b((?:hvs\\.[\\w-]{90,120}|s\\.(?i:[a-z0-9]{24})))" + redactTokenEnd,
		entropy:  3.5,
		allow:    []string{"s\\.[A-Za-z]{24}"},
	},
	{id: "vault-batch-token", keywords: []string{"hvb."}, pattern: "\\b(hvb\\.[\\w-]{138,300})" + redactTokenEnd, entropy: 4},
	{id: "doppler-api-token", keywords: []string{"dp.pt."}, pattern: "dp\\.pt\\.(?i)[a-z0-9]{43}", entropy: 2},
	{id: "linear-api-key", keywords: []string{"lin_api_"}, pattern: "lin_api_(?i)[a-z0-9]{40}", entropy: 2},
	{
		id:       "postman-api-token",
		keywords: []string{"pmak-"},
		pattern:  "\\b(PMAK-(?i)[a-f0-9]{24}\\-[a-f0-9]{34})" + redactTokenEnd,
		entropy:  3,
	},
	{id: "pulumi-api-token", keywords: []string{"pul-"}, pattern: "\\b(pul-[a-f0-9]{40})" + redactTokenEnd, entropy: 2},
	{id: "sentry-user-token", keywords: []string{"sntryu_"}, pattern: "\\b(sntryu_[a-f0-9]{64})" + redactTokenEnd, entropy: 3.5},
	{
		id:       "grafana-cloud-api-token",
		keywords: []string{"glc_"},
		pattern:  "(?i)\\b(glc_[A-Za-z0-9+/]{32,400}={0,3})" + redactTokenEnd,
		entropy:  3,
	},
	{
		id:       "grafana-service-account-token",
		keywords: []string{"glsa_"},
		pattern:  "(?i)\\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})" + redactTokenEnd,
		entropy:  3,
	},
	{id: "perplexity-api-key", keywords: []string{"pplx-"}, pattern: "\\b(pplx-[a-zA-Z0-9]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$|\\b)", entropy: 4},
	{id: "rubygems-api-token", keywords: []string{"rubygems_"}, pattern: "\\b(rubygems_[a-f0-9]{48})" + redactTokenEnd, entropy: 2},
	{id: "heroku-api-key-v2", keywords: []string{"hrku-aa"}, pattern: "\\b((HRKU-AA[0-9a-zA-Z_-]{58}))" + redactTokenEnd, entropy: 4},
	{
		id:       "flyio-access-token",
		keywords: []string{"fo1_", "fm1", "fm2_"},
		pattern:  "\\b((?:fo1_[\\w-]{43}|fm1[ar]_[a-zA-Z0-9+\\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\\/]{100,}={0,3}))" + redactTokenEnd,
		entropy:  4,
	},
	{
		id:       "1password-service-account-token",
		keywords: []string{"ops_"},
		pattern:  "ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}",
		entropy:  4,
	},
	{
		id:       "planetscale-api-token",
		keywords: []string{"pscale_tkn_"},
		pattern:  "\\b(pscale_tkn_(?i)[\\w=\\.-]{32,64})" + redactTokenEnd,
		entropy:  3,
	},
	{
		id:       "planetscale-password",
		keywords: []string{"pscale_pw_"},
		pattern:  "(?i)\\b(pscale_pw_(?i)[\\w=\\.-]{32,64})" + redactTokenEnd,
		entropy:  3,
	},
	{id: "prefect-api-token", keywords: []string{"pnu_"}, pattern: "\\b(pnu_[a-zA-Z0-9]{36})" + redactTokenEnd, entropy: 2},
	{
		id:       "curl-auth-header",
		keywords: []string{"curl"},
		pattern: "\\bcurl\\b(?:.*?|.*?(?:[\\r\\n]{1,2}.*?){1,5})[ \\t\\n\\r](?:-H|--header)(?:=|[ \\t]{0,5})(?:\"(?i)(?:" +
			"Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|" +
			"([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))\"|'(?i)(?:" +
			"Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|" +
			"([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))')(?:\\B|\\s|\\z)",
		entropy: 2.75,
	},
	{
		id:       "curl-auth-user",
		keywords: []string{"curl"},
		pattern: "\\bcurl\\b(?:.*|.*(?:[\\r\\n]{1,2}.*){1,5})[ \\t\\n\\r](?:-u|--user)(?:=|[ \\t]{0,5})(\"(:[^\"]{3,}|" +
			"[^:\"]{3,}:|[^:\"]{3,}:[^\"]{3,})\"|'([^:']{3,}:[^']{3,})'|((?:\"[^\"]{3,}\"|'[^']{3,}'|[\\w$@.-]+):" +
			"(?:\"[^\"]{3,}\"|'[^']{3,}'|[\\w${}@.-]+)))(?:\\s|\\z)",
		entropy: 2,
		allow: []string{
			"[^:]+:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\\*+|x+)",
			"['\"]?<[^>]+>['\"]?:['\"]?<[^>]+>|<[^:]+:[^>]+>['\"]?",
			"['\"]?[^:]+['\"]?:['\"]?\\$(?:\\d|\\w+|\\{(?:\\d|\\w+)})['\"]?",
		},
	},

	// PII, while the harness config hashes it (QD-116): email addresses and E.164 phone numbers
	{
		id:       "pii-email",
		keywords: []string{"@"},
		pattern:  "[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}",
		pii:      true,
	},
	{
		id:       "pii-phone",
		keywords: []string{"+"},
		pattern:  "(?:^|[^0-9A-Za-z+])(\\+[1-9][0-9]{6,14})\\b",
		pii:      true,
	},
}
