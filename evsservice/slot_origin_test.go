// DESIGN-DETAILS 14.6's unit tests of the origin (slot_origin.go): both forms encode and parse back, the size bound
// holds both ways, every malformed value reads as no statement's, and equality is on the statement's name alone.

package evsservice

import (
	"math"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A push's origin with every field set apart from the others.
func slotOriginTestPush() EvsSlotOrigin {
	return EvsSlotOrigin{
		Kind:            EvsSlotOriginPush,
		PushId:          testId("origin push"),
		StatementPrefix: [16]byte(testId("origin statement")),
		RefId:           testId("origin ref"),
		SignerSidecarId: testId("origin signer"),
		BaseVersion:     41,
		PathEpoch:       3,
		GitMode:         true,
	}
}

func TestSlotOriginEncodesAndParsesBothForms(t *testing.T) {
	maxByteCount := DefaultEvsSettings().SlotOriginMaxByteCount
	push := slotOriginTestPush()
	value := push.Encode()
	want := "1.p." + sidecar.EvsKeyId(push.PushId) + "." + sidecar.EvsKeyId(sidecar.Id(push.StatementPrefix)) + "." + sidecar.EvsKeyId(push.RefId) + "." +
		sidecar.EvsKeyId(push.SignerSidecarId) + ".41.3.g"
	if value != want {
		t.Fatalf("encoded %q, want %q", value, want)
	}
	metadata, err := push.Metadata(maxByteCount)
	if err != nil || len(metadata) != 1 || metadata[EvsSlotOriginMetadataKey] != value {
		t.Fatalf("metadata %v %v", metadata, err)
	}
	if parsed := ParseEvsSlotOrigin(metadata, maxByteCount); parsed != push {
		t.Fatalf("parsed %+v, want %+v", parsed, push)
	}
	file := push
	file.GitMode = false
	if parsed := ParseEvsSlotOrigin(map[string]string{EvsSlotOriginMetadataKey: file.Encode()}, maxByteCount); parsed != file || !strings.HasSuffix(file.Encode(), ".f") {
		t.Fatalf("a file-mode origin parsed as %+v", parsed)
	}

	reseeded := EvsSlotOriginReseeded()
	if reseeded.Encode() != "1.r" {
		t.Fatalf("a re-seed's origin %q", reseeded.Encode())
	}
	if parsed := ParseEvsSlotOrigin(map[string]string{EvsSlotOriginMetadataKey: "1.r"}, maxByteCount); parsed.Kind != EvsSlotOriginReseed {
		t.Fatalf("1.r parsed as %+v", parsed)
	}
	if metadata, err := (EvsSlotOrigin{}).Metadata(maxByteCount); metadata != nil || err != nil {
		t.Fatalf("none's metadata %v %v", metadata, err)
	}
	if (EvsSlotOrigin{}).Encode() != "" {
		t.Fatal("none encodes to a value")
	}
}

// A statement's origin: its push id, the first 16 bytes of its hash, its ref, signer, base, declared epoch and mode.
func TestSlotOriginOfAStatement(t *testing.T) {
	statement := &sidecar.EvsStatement{
		Sha256: [32]byte(append(testId("hash high").Bytes(), testId("hash low").Bytes()...)),
		Push: &protocol.EvsPush{
			PushId: testId("statement push").Bytes(), RefId: testId("statement ref").Bytes(), SignerSidecarId: testId("statement signer").Bytes(),
			BaseVersion: 9, PathEpoch: 2, RefMode: uint32(protocol.EvsRefMode_EVS_REF_FILE),
		},
	}
	origin, err := EvsSlotOriginOf(statement)
	if err != nil {
		t.Fatal(err)
	}
	if origin.Kind != EvsSlotOriginPush || origin.PushId != testId("statement push") || origin.StatementPrefix != [16]byte(testId("hash high")) ||
		origin.RefId != testId("statement ref") || origin.SignerSidecarId != testId("statement signer") || origin.BaseVersion != 9 ||
		origin.PathEpoch != 2 || origin.GitMode {
		t.Fatalf("origin %+v", origin)
	}
	if !origin.IsStatement(testId("statement push"), [16]byte(testId("hash high"))) || origin.IsStatement(testId("statement push"), [16]byte(testId("hash low"))) {
		t.Fatal("IsStatement compares other than the push id and prefix")
	}
	statement.Push.RefMode = 0
	if _, err := EvsSlotOriginOf(statement); err == nil {
		t.Fatal("a statement of no ref mode has an origin")
	}
	statement.Push.RefMode = uint32(protocol.EvsRefMode_EVS_REF_GIT)
	statement.Push.SignerSidecarId = []byte{1}
	if _, err := EvsSlotOriginOf(statement); err == nil {
		t.Fatal("a statement whose signer is not 16 bytes has an origin")
	}
}

// The bound: the longest version-1 value fits 190 B, a value past the bound is no statement's when read and is
// refused when written, and the settings hold the bound at or above the longest value.
func TestSlotOriginSizeBound(t *testing.T) {
	settings := DefaultEvsSettings()
	longest := EvsSlotOrigin{Kind: EvsSlotOriginPush, BaseVersion: math.MaxUint64, PathEpoch: math.MaxUint64}
	value := longest.Encode()
	if len(value) != evsSlotOriginLongestByteCount() || settings.SlotOriginMaxByteCount < len(value) || 190 < len(value) {
		t.Fatalf("the longest origin is %d B, the bound %d", len(value), settings.SlotOriginMaxByteCount)
	}
	if parsed := ParseEvsSlotOrigin(map[string]string{EvsSlotOriginMetadataKey: value}, len(value)); parsed != longest {
		t.Fatalf("the longest origin at its own bound parsed as %+v", parsed)
	}
	if parsed := ParseEvsSlotOrigin(map[string]string{EvsSlotOriginMetadataKey: value}, len(value)-1); parsed.Kind != EvsSlotOriginNone {
		t.Fatal("an origin past the bound parsed")
	}
	if _, err := longest.Metadata(len(value) - 1); err == nil {
		t.Fatal("an origin past the bound was written")
	}
	settings.SlotOriginMaxByteCount = len(value) - 1
	if err := settings.Validate(); err == nil {
		t.Fatal("a bound below the longest origin validated")
	}
}

// Every malformed value reads as none, the closed direction: never taken, never deleted by evacuation.
func TestSlotOriginMalformedValuesAreNone(t *testing.T) {
	maxByteCount := DefaultEvsSettings().SlotOriginMaxByteCount
	good := slotOriginTestPush().Encode()
	fields := strings.Split(good, ".")
	with := func(index int, value string) string {
		changed := append([]string{}, fields...)
		changed[index] = value
		return strings.Join(changed, ".")
	}
	malformed := []string{
		"",
		"1",
		"1.",
		"2.r",
		"1.r.",
		"1.r.0",
		"1.x",
		"1.p",
		with(0, "2"),
		with(1, "r"),
		with(2, strings.ToUpper(fields[2])),
		with(2, fields[2][:31]),
		with(2, fields[2]+"0"),
		with(3, "zz"+fields[3][2:]),
		with(4, ""),
		with(5, fields[5][1:]),
		with(6, "041"),
		with(6, "-1"),
		with(6, "18446744073709551616"),
		with(7, "+3"),
		with(7, "three"),
		with(8, "x"),
		with(8, "G"),
		good + ".1",
		strings.Join(fields[:8], "."),
		" " + good,
	}
	for _, value := range malformed {
		if parsed := ParseEvsSlotOrigin(map[string]string{EvsSlotOriginMetadataKey: value}, maxByteCount); parsed.Kind != EvsSlotOriginNone {
			t.Errorf("%q parsed as %+v", value, parsed)
		}
	}
	for _, metadata := range []map[string]string{nil, {}, {"entry-state": good}, {"Origin": good}} {
		if parsed := ParseEvsSlotOrigin(metadata, maxByteCount); parsed.Kind != EvsSlotOriginNone {
			t.Errorf("%v parsed as %+v", metadata, parsed)
		}
	}
}

// Equality is the statement's name, compared as parsed fields: the other fields do not enter it, and none and a
// re-seed's are no statement's.
func TestSlotOriginSameStatement(t *testing.T) {
	push := slotOriginTestPush()
	other := push
	other.BaseVersion, other.PathEpoch, other.GitMode, other.RefId = 1, 1, false, testId("another ref")
	if !push.SameStatement(other) || !other.SameStatement(push) {
		t.Fatal("one statement's origins differ by a field past its name")
	}
	renamed := push
	renamed.StatementPrefix[0] ^= 1
	if push.SameStatement(renamed) {
		t.Fatal("two statement prefixes compare equal")
	}
	repushed := push
	repushed.PushId = testId("another push")
	if push.SameStatement(repushed) {
		t.Fatal("two push ids compare equal")
	}
	for _, origin := range []EvsSlotOrigin{{}, EvsSlotOriginReseeded()} {
		if push.SameStatement(origin) || origin.SameStatement(push) || origin.SameStatement(origin) {
			t.Fatalf("%+v is a statement's", origin)
		}
	}
}

// The settle age's floor and the rounds: SlotSettleAge at least 2 s, SlotWriteRoundCount positive, and Resolve's
// statement life past both time checks.
func TestSlotSettingsHoldTheirFloors(t *testing.T) {
	if err := DefaultEvsSettings().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, adjust := range []func(settings *EvsSettings){
		func(settings *EvsSettings) { settings.SlotSettleAge = settings.SlotSettleAge - 1 },
		func(settings *EvsSettings) { settings.SlotWriteRoundCount = 0 },
		func(settings *EvsSettings) { settings.ResolveStatementLife = settings.SealTimeBound },
		func(settings *EvsSettings) { settings.ResolveStatementLife = settings.PushTimeBound },
	} {
		settings := DefaultEvsSettings()
		adjust(settings)
		if err := settings.Validate(); err == nil {
			t.Errorf("settings %+v validated", settings)
		}
	}
}
