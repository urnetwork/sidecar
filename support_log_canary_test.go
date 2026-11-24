//go:build !ios_extension && !sidecar_http

// The support log's canary corpus (DESIGN-COMPUTE §28.7, §18's Support row): strings and ids that stand for content,
// driven through every input the support log takes, every field of every code the registry declares and every word of
// a bundle's header, must leave no byte in any ring or bundle. A component that writes codes adds its own inputs to
// testSupportLogCanaryDrivers in its own test file, where it drives the corpus through them into a ring this file
// then scans.

package sidecar

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Strings that stand for what a log must never hold: a message, a secret, a path, a host, an address, a name, a
// query, text in other scripts. Each is long and odd enough that finding it anywhere is no accident.
var testSupportLogCanaryStrings = []string{
	"CANARY-message: the build fails when I run make in my project",
	"CANARY-secret-sk-ant-api03-Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lz",
	"/Users/canary-person/Documents/CANARY-taxes-2026.pdf",
	"https://canary-internal.example/CANARY/path?token=CANARYQUERY",
	"canary-person+CANARY@example.com",
	"203.0.113.77:CANARY",
	"2001:db8::cafe:CANARY",
	"CANARY-repo-name-billing-audit",
	"CANARY-agent-name-release-bot",
	"Подробности CANARY-ошибки на русском",
	"失败的原因 CANARY 是什么",
	"CANARY\x00with\nnewlines\tand\x1bcontrols",
	"hunter2-CANARY-password",
	"1.0-CANARYSUFFIX",
	strings.Repeat("CANARY-long-", 40),
}

// Ids that stand for objects: 16 random-looking bytes each, fixed so the test repeats.
var testSupportLogCanaryIds = [][]byte{
	{0x43, 0x41, 0x4e, 0x41, 0x52, 0x59, 0x01, 0x9a, 0x7c, 0x3e, 0x55, 0xd1, 0x08, 0xb2, 0x6f, 0xe4},
	{0x9f, 0x2b, 0x77, 0x10, 0xc4, 0x3d, 0xa8, 0x51, 0xe6, 0x0b, 0x92, 0x4f, 0x13, 0x88, 0xdc, 0x25},
	{0x01, 0x93, 0x5a, 0x2e, 0x7b, 0x44, 0x7c, 0x10, 0x8a, 0x5d, 0x39, 0xee, 0x61, 0x02, 0xf7, 0xab},
}

// A component's driver: it writes the corpus through its own inputs into log.
type testSupportLogCanaryDriver struct {
	name  string
	drive func(t *testing.T, log *SupportLog)
}

// Every component's driver. The support log's own, below, drives every field of every code; a component that writes
// codes appends its own from its test file's init.
var testSupportLogCanaryDrivers = []*testSupportLogCanaryDriver{
	{name: "support_log", drive: testSupportLogCanaryDriveRegistry},
}

// Every code with every field it declares, each field fed each canary its type takes: a token every id and every
// string's bytes, a version every string, and an enum, a count, a duration, a size and a boolean their whole range's
// edges, which no canary reaches but through their Go types. Fields a code does not declare ride along too, so a
// refusal path is driven as well.
func testSupportLogCanaryDriveRegistry(t *testing.T, log *SupportLog) {
	for _, code := range SupportLogCodes() {
		row := supportLogRegistry.codes[code]
		for _, number := range append(row.fields, SupportLogFieldNumber(1), SupportLogFieldNumber(10)) {
			field := supportLogRegistry.fields[number]
			fields := []SupportLogField{}
			switch field.fieldType {
			case supportLogFieldTypeToken:
				for _, id := range testSupportLogCanaryIds {
					fields = append(fields, supportLogTokenField(number, id))
				}
				for _, text := range testSupportLogCanaryStrings {
					fields = append(fields, supportLogTokenField(number, []byte(text)))
				}
			case supportLogFieldTypeVersion:
				for _, text := range testSupportLogCanaryStrings {
					fields = append(fields, supportLogVersionField(number, text))
				}
			case supportLogFieldTypeEnum:
				for value := range uint32(len(supportLogRegistry.enums[field.enum]) + 2) {
					fields = append(fields, supportLogEnumField(number, value))
				}
			case supportLogFieldTypeCount:
				fields = append(fields, supportLogCountField(number, 0x4341_4e41_5259), supportLogCountField(number, -1))
			case supportLogFieldTypeDuration:
				fields = append(fields, supportLogDurationField(number, 0x4341_4e41*time.Millisecond))
			case supportLogFieldTypeSize:
				fields = append(fields, supportLogSizeField(number, 0x4341_4e41_5259))
			case supportLogFieldTypeBoolean:
				fields = append(fields, supportLogBooleanField(number, true), supportLogBooleanField(number, false))
			}
			for _, field := range fields {
				log.Event(code, field)
			}
		}
	}
}

// Each form a canary could take in bytes: itself, its case changes and, for an id, its hex, base64 and the halves of
// its hex.
func testSupportLogCanaryForms() [][]byte {
	forms := [][]byte{}
	for _, text := range testSupportLogCanaryStrings {
		forms = append(forms, []byte(text), []byte(strings.ToLower(text)), []byte(strings.ToUpper(text)))
		// a word of it alone, as a renderer might split it
		for _, word := range strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || r == '/' || r == '?' || r == '=' }) {
			if 8 <= len(word) {
				forms = append(forms, []byte(word))
			}
		}
	}
	forms = append(forms, []byte("CANARY"), []byte("canary"))
	for _, id := range testSupportLogCanaryIds {
		encoded := hex.EncodeToString(id)
		forms = append(forms, id, []byte(encoded), []byte(strings.ToUpper(encoded)), []byte(encoded[:16]), []byte(encoded[16:]),
			[]byte(base64.StdEncoding.EncodeToString(id)), []byte(base64.RawURLEncoding.EncodeToString(id)))
	}
	return forms
}

// What of the corpus data holds, by form.
func testSupportLogCanaryFindings(where string, data []byte) []string {
	findings := []string{}
	for _, form := range testSupportLogCanaryForms() {
		if bytes.Contains(data, form) {
			findings = append(findings, fmt.Sprintf("%s holds %q", where, form))
		}
	}
	return findings
}

func TestSupportLogCanaryCorpusLeavesNoByteInARingOrABundle(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "CANARY-state-directory")
	clock := newSupportLogTestClock()
	log := openTestSupportLog(t, directory, nil, clock)
	for _, driver := range testSupportLogCanaryDrivers {
		driver.drive(t, log)
		clock.advance(time.Minute)
	}
	host := &SupportLogBundleHost{
		Version:        testSupportLogCanaryStrings[13],
		Channel:        testSupportLogCanaryStrings[8],
		HarnessVersion: testSupportLogCanaryStrings[0],
		GatewayVersion: testSupportLogCanaryStrings[2],
	}
	bundle, err := log.Bundle(&SupportLogBundleArgs{Host: host})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Document.Header.Channel != "other" || bundle.Document.Header.Version != "invalid" {
		t.Fatalf("the header reads %+v", bundle.Document.Header)
	}
	if bundle.Document.Header.Events < 100 {
		t.Fatalf("the corpus wrote only %d events", bundle.Document.Header.Events)
	}
	log.Close()

	findings := []string{}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == supportLogKeyFileName {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		findings = append(findings, testSupportLogCanaryFindings("ring "+entry.Name(), data)...)
	}
	findings = append(findings, testSupportLogCanaryFindings("the bundle's bytes", bundle.Bytes)...)
	opened, err := SupportLogBundleOpen(bundle.Bytes, 64*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(bundle.Bytes))
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	findings = append(findings, testSupportLogCanaryFindings("the bundle's JSON", decompressed)...)
	rendered := []byte{}
	for _, event := range opened.Events {
		rendered = fmt.Appendf(rendered, "%v\n", *event)
	}
	rendered = fmt.Appendf(rendered, "%+v\n", *opened.Header)
	findings = append(findings, testSupportLogCanaryFindings("the bundle's document", rendered)...)
	for _, finding := range findings {
		t.Error(finding)
	}
}

// The corpus finds what it is meant to: a ring a test writes a canary into by hand fails the scan.
func TestSupportLogCanaryScanFindsAPlantedCanary(t *testing.T) {
	for _, planted := range [][]byte{
		[]byte(testSupportLogCanaryStrings[1]),
		[]byte(strings.ToLower(testSupportLogCanaryStrings[0])),
		[]byte(hex.EncodeToString(testSupportLogCanaryIds[1])),
		[]byte(base64.StdEncoding.EncodeToString(testSupportLogCanaryIds[2])),
		testSupportLogCanaryIds[0],
	} {
		data := append([]byte("segment bytes "), planted...)
		if len(testSupportLogCanaryFindings("planted", data)) == 0 {
			t.Errorf("the scan misses %q", planted)
		}
	}
	if findings := testSupportLogCanaryFindings("clean", []byte(`{"t":1764000000,"component":"daemon","code":"started"}`)); len(findings) != 0 {
		t.Errorf("the scan finds %v in clean text", findings)
	}
}
