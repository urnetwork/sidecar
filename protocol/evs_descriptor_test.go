// FS-72's lint: format 1's reserved numbers, read from evs.proto's descriptors, equal the decided list, none for
// keep-last-n (§11.6, D-PHASE-9). That format-1 code refuses each in use is the code's to prove, with EVS1's tasks.
// §11.9's read states are off this list because no section numbers them, and §11.8's batch format, the kind-5
// header and the provenance's tainted bit are off it because none of them is protobuf.

package protocol

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// Declared, never left out: format 1 parses each and refuses it as needing format 2, so a field dropped here would
// arrive as an unknown field and pass.
func TestFormatOneDeclaresFormatTwosFields(t *testing.T) {
	cases := []struct {
		message string
		field   protoreflect.Name
		number  protoreflect.FieldNumber
	}{
		{message: "EvsPush", field: "drop_sha256", number: 33},
		{message: "EvsPush", field: "index_epoch", number: 34},
		{message: "EvsHead", field: "index_epoch", number: 24},
		{message: "EvsEntryVersion", field: "versioning", number: 14},
		{message: "EvsLocator", field: "staged", number: 6},
		{message: "EvsUploadReceipt", field: "versionless", number: 8},
	}
	for _, c := range cases {
		field := testMessage(t, c.message).Fields().ByName(c.field)
		if field == nil {
			t.Errorf("%s.%s is missing", c.message, c.field)
			continue
		}
		if field.Number() != c.number {
			t.Errorf("%s.%s is %d, want %d", c.message, c.field, field.Number(), c.number)
		}
	}
}

// The values format 1 refuses or ignores, by their numbers. EvsPush.flags, EvsEntryVersion.versioning and
// EvsLocator.kind are uint32 on the wire, so these enums are the only place the numbers can drift.
func TestFormatOneReservesFormatTwosValues(t *testing.T) {
	cases := []struct {
		name   string
		got    int32
		number int32
	}{
		{name: "the DROP flag", got: int32(EvsPushFlag_EVS_PUSH_DROP), number: 256},
		{name: "the CUT flag", got: int32(EvsPushFlag_EVS_PUSH_CUT), number: 512},
		{name: "a versionless segment", got: int32(EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), number: 5},
		{name: "a versionless file", got: int32(EvsVersioning_EVS_VERSIONING_VERSIONLESS), number: 1},
		{name: "an index file", got: int32(EvsVersioning_EVS_VERSIONING_INDEX), number: 2},
		{name: "window bit 4", got: int32(EvsWindowFlag_EVS_WINDOW_VERSIONLESS_REPLACED), number: 1 << 4},
		{name: "window bit 5", got: int32(EvsWindowFlag_EVS_WINDOW_DROP), number: 1 << 5},
	}
	for _, c := range cases {
		if c.got != c.number {
			t.Errorf("%s is %d, want %d", c.name, c.got, c.number)
		}
	}
}

// §11.8's entry row: bits 16-31 hold the change count, so no flag may reach them, and each is one bit.
func TestWindowFlagsStayBelowTheChangeCount(t *testing.T) {
	for number, name := range EvsWindowFlag_name {
		if number == 0 {
			continue
		}
		if number&(number-1) != 0 || number >= 1<<16 {
			t.Errorf("%s is %#x", name, number)
		}
	}
}

// EvsPush.flags is a bit set: a value of two bits would read as two flags.
func TestPushFlagsAreOneBitEach(t *testing.T) {
	for number, name := range EvsPushFlag_name {
		if number != 0 && number&(number-1) != 0 {
			t.Errorf("%s is %#x", name, number)
		}
	}
}

// The list, exactly: anything reserved past it is a number no decision took, and anything missing from it a number
// a later field could reuse. EvsPush's 21 moved into auth, and EvsHead's 10 likewise; EvsLocator's 3 and 4 wait
// for a format readers learn first.
func TestFormatOneReservesOnlyTheDecidedNumbers(t *testing.T) {
	file := testFile(t, "protocol/evs.proto")
	want := map[protoreflect.Name][]int32{"EvsPush": {21}, "EvsHead": {10}}
	messages := file.Messages()
	for i := range messages.Len() {
		message := messages.Get(i)
		got := testReservedNumbers(message.ReservedRanges())
		if !slices.Equal(got, testSorted(want[message.Name()])) {
			t.Errorf("%s reserves %v, want %v", message.Name(), got, want[message.Name()])
		}
	}
	wantEnums := map[protoreflect.Name][]int32{"EvsLocatorKind": {3, 4}}
	enums := file.Enums()
	for i := range enums.Len() {
		enum := enums.Get(i)
		got := testEnumReservedNumbers(enum.ReservedRanges())
		if !slices.Equal(got, testSorted(wantEnums[enum.Name()])) {
			t.Errorf("%s reserves %v, want %v", enum.Name(), got, wantEnums[enum.Name()])
		}
	}
}

// Owner decisions 165 and 167: versionless means head-only, so field 15 is neither used nor held back.
func TestEntryVersionHasNoFieldFifteen(t *testing.T) {
	message := testMessage(t, "EvsEntryVersion")
	if message.Fields().ByNumber(15) != nil {
		t.Error("field 15 is in use")
	}
	if message.ReservedRanges().Has(15) {
		t.Error("field 15 is reserved")
	}
}
