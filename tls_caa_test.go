// §13.8's CAA at <root>: every account of every CA, each record in RFC 8659's grammar with RFC 8657's two parameters,
// and every input that would leave <root> open or the zone unreadable refused. Account URIs are synthetic.

package sidecar

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Account URIs of the three CAs, as an ACME directory would name them, under .example.
const (
	testCaaLetsEncryptAccountA = "https://acme.letsencrypt.example/acme/acct/1001"
	testCaaLetsEncryptAccountB = "https://acme.letsencrypt.example/acme/acct/2002"
	testCaaGtsAccount          = "https://dv.acme.gts.example/v2/acct/3003"
	testCaaZeroSslAccount      = "https://acme.zerossl.example/v2/DV90/account/4004"
)

func TestTlsRootCaaRecordsNameEveryAccountOfEveryCa(t *testing.T) {
	records, err := TlsRootCaaRecords(map[string][]string{
		// out of order and once twice, which changes nothing
		TlsCaaIssuerLetsEncrypt: {testCaaLetsEncryptAccountB, testCaaLetsEncryptAccountA, testCaaLetsEncryptAccountB},
		TlsCaaIssuerGts:         {testCaaGtsAccount},
		TlsCaaIssuerZeroSsl:     {testCaaZeroSslAccount},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`0 issue "letsencrypt.org; accounturi=https://acme.letsencrypt.example/acme/acct/1001; validationmethods=dns-01"`,
		`0 issue "letsencrypt.org; accounturi=https://acme.letsencrypt.example/acme/acct/2002; validationmethods=dns-01"`,
		`0 issuewild "letsencrypt.org; accounturi=https://acme.letsencrypt.example/acme/acct/1001; validationmethods=dns-01"`,
		`0 issuewild "letsencrypt.org; accounturi=https://acme.letsencrypt.example/acme/acct/2002; validationmethods=dns-01"`,
		`0 issue "pki.goog; accounturi=https://dv.acme.gts.example/v2/acct/3003; validationmethods=dns-01"`,
		`0 issuewild "pki.goog; accounturi=https://dv.acme.gts.example/v2/acct/3003; validationmethods=dns-01"`,
		`0 issue "sectigo.com; accounturi=https://acme.zerossl.example/v2/DV90/account/4004; validationmethods=dns-01"`,
		`0 issuewild "sectigo.com; accounturi=https://acme.zerossl.example/v2/DV90/account/4004; validationmethods=dns-01"`,
	}
	if !slices.Equal(records, want) {
		t.Errorf("records\n%s", strings.Join(records, "\n"))
	}
}

// Each record read back by RFC 8659 §4.1.1's grammar, as a CA's checker reads it: flags 0, a tag, and a quoted value of
// an issuer domain and parameters, with exactly one accounturi and validationmethods dns-01 (RFC 8657 §3, §4).
func TestTlsRootCaaRecordsReadBackAsCaasDo(t *testing.T) {
	records, err := TlsRootCaaRecords(map[string][]string{
		TlsCaaIssuerLetsEncrypt: {testCaaLetsEncryptAccountA, testCaaLetsEncryptAccountB},
		TlsCaaIssuerGts:         {testCaaGtsAccount},
		TlsCaaIssuerZeroSsl:     {testCaaZeroSslAccount},
	})
	if err != nil {
		t.Fatal(err)
	}
	issuerTagAccounts := map[string]map[string][]string{}
	for _, record := range records {
		flags, rest, _ := strings.Cut(record, " ")
		tag, quoted, _ := strings.Cut(rest, " ")
		if flags != "0" || (tag != "issue" && tag != "issuewild") {
			t.Errorf("%s: flags %q tag %q", record, flags, tag)
			continue
		}
		value, quotedWhole := strings.CutPrefix(quoted, `"`)
		value, closed := strings.CutSuffix(value, `"`)
		if !quotedWhole || !closed || strings.ContainsAny(value, "\"\\") {
			t.Errorf("%s: the value is not one plain quoted string", record)
			continue
		}
		parts := strings.Split(value, ";")
		issuer := strings.TrimSpace(parts[0])
		accountUris := []string{}
		validationMethods := []string{}
		for _, parameter := range parts[1:] {
			key, parameterValue, found := strings.Cut(strings.TrimSpace(parameter), "=")
			switch {
			case !found:
				t.Errorf("%s: parameter %q", record, parameter)
			case key == "accounturi":
				accountUris = append(accountUris, parameterValue)
			case key == "validationmethods":
				validationMethods = append(validationMethods, parameterValue)
			default:
				t.Errorf("%s: parameter %q", record, key)
			}
		}
		if len(accountUris) != 1 || !slices.Equal(validationMethods, []string{"dns-01"}) {
			t.Errorf("%s: accounturi %q validationmethods %q", record, accountUris, validationMethods)
			continue
		}
		if issuerTagAccounts[issuer] == nil {
			issuerTagAccounts[issuer] = map[string][]string{}
		}
		issuerTagAccounts[issuer][tag] = append(issuerTagAccounts[issuer][tag], accountUris[0])
	}
	want := map[string][]string{
		TlsCaaIssuerLetsEncrypt: {testCaaLetsEncryptAccountA, testCaaLetsEncryptAccountB},
		TlsCaaIssuerGts:         {testCaaGtsAccount},
		TlsCaaIssuerZeroSsl:     {testCaaZeroSslAccount},
	}
	for issuer, accountUris := range want {
		// issue and issuewild alike, since every name is reached through a wildcard or beside one
		for _, tag := range []string{"issue", "issuewild"} {
			if !slices.Equal(issuerTagAccounts[issuer][tag], accountUris) {
				t.Errorf("%s %s: %q", issuer, tag, issuerTagAccounts[issuer][tag])
			}
		}
	}
	if len(issuerTagAccounts) != len(want) {
		t.Errorf("issuers %v", issuerTagAccounts)
	}
}

// A CA with no account yet is left out, so it can issue nothing under <root> rather than anything.
func TestTlsRootCaaRecordsLeaveACaWithoutAccountsOut(t *testing.T) {
	records, err := TlsRootCaaRecords(map[string][]string{
		TlsCaaIssuerLetsEncrypt: {testCaaLetsEncryptAccountA},
		TlsCaaIssuerGts:         {},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if !strings.Contains(record, `"letsencrypt.org;`) {
			t.Errorf("record %s", record)
		}
	}
	if len(records) != 2 {
		t.Errorf("%d records", len(records))
	}
}

// What would leave <root> open to every CA, name a CA §13.8 does not, or not read back as one value, and an error that
// never repeats the input (I-13).
func TestTlsRootCaaRecordsRefuseWhatCannotStand(t *testing.T) {
	cases := []map[string][]string{
		nil,
		{},
		{TlsCaaIssuerLetsEncrypt: nil, TlsCaaIssuerGts: {}},
		{"digicert.example": {testCaaLetsEncryptAccountA}},
		{TlsCaaIssuerLetsEncrypt: {testCaaLetsEncryptAccountA}, "LETSENCRYPT.ORG": {testCaaLetsEncryptAccountB}},
		{TlsCaaIssuerLetsEncrypt: {""}},
		{TlsCaaIssuerLetsEncrypt: {"http://acme.letsencrypt.example/acme/acct/1001"}},
		{TlsCaaIssuerLetsEncrypt: {"https:///acme/acct/1001"}},
		{TlsCaaIssuerLetsEncrypt: {"https://user@acme.letsencrypt.example/acme/acct/1001"}},
		{TlsCaaIssuerLetsEncrypt: {"https://acme.letsencrypt.example/acme/acct/1001; validationmethods=http-01"}},
		{TlsCaaIssuerLetsEncrypt: {`https://acme.letsencrypt.example/acme/acct/1001"`}},
		{TlsCaaIssuerLetsEncrypt: {`https://acme.letsencrypt.example/acme\acct/1001`}},
		{TlsCaaIssuerLetsEncrypt: {"https://acme.letsencrypt.example/acme/acct/10 01"}},
		{TlsCaaIssuerLetsEncrypt: {"https://acme.letsencrypt.example/acme/acct/1001\n"}},
		{TlsCaaIssuerLetsEncrypt: {"https://acme.letsencrypt.example/acme/acct/é"}},
		// one bad account spoils the set, so a record is never silently dropped
		{TlsCaaIssuerLetsEncrypt: {testCaaLetsEncryptAccountA}, TlsCaaIssuerGts: {"gts-account-3003"}},
	}
	for _, c := range cases {
		records, err := TlsRootCaaRecords(c)
		if !errors.Is(err, ErrTlsCaaRecords) || records != nil {
			t.Errorf("%q: %q %v", c, records, err)
			continue
		}
		for _, accountUris := range c {
			for _, accountUri := range accountUris {
				if accountUri != "" && strings.Contains(err.Error(), accountUri) {
					t.Errorf("the error repeats %q", accountUri)
				}
			}
		}
	}
}
