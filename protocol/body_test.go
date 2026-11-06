// §22.6's every-body target. Every message this module registers decodes however a peer or a store encoded it, and
// re-encodes to one canonical form: seeds hold reordered, repeated, unknown, packed and unpacked fields and
// non-minimal varints. protobuf's encoding is not canonical, which is why signatures here cover received bytes
// (D-TEST-4; TestRecordHeaderWithUnknownFieldAndKindVerifies).

package protocol

import (
	"bytes"
	"cmp"
	"fmt"
	"hash/crc32"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// Deep enough to reach every message type from any other. A cycle would stop here, and none exists today.
const testFillDepth = 5

// Above no real field number, so an encoding holding it is always unknown.
const testUnknownFieldNumber = protowire.Number(9999)

func testBodyTypes(t testing.TB) []protoreflect.MessageType {
	types := []protoreflect.MessageType{}
	protoregistry.GlobalTypes.RangeMessages(func(messageType protoreflect.MessageType) bool {
		descriptor := messageType.Descriptor()
		if descriptor.ParentFile().Package() == testProtoPackage && !descriptor.IsMapEntry() {
			types = append(types, messageType)
		}
		return true
	})
	slices.SortFunc(types, func(a, b protoreflect.MessageType) int {
		return cmp.Compare(a.Descriptor().FullName(), b.Descriptor().FullName())
	})
	// The floor keeps a filter that matched nothing from passing every loop below.
	if len(types) < 200 {
		t.Fatalf("found %d message types", len(types))
	}
	return types
}

// A value no proto3 encoding omits, so a field filled here always reaches the wire.
func testValue(field protoreflect.FieldDescriptor, seed int) protoreflect.Value {
	number := int(field.Number()) + seed
	switch field.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(int32(number))
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(number))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(int64(number))
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(uint64(number))
	case protoreflect.EnumKind:
		values := field.Enum().Values()
		return protoreflect.ValueOfEnum(values.Get(values.Len() - 1).Number())
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(fmt.Sprintf("value %d", number))
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes(bytes.Repeat([]byte{byte(number)}, 16))
	}
	panic(fmt.Sprintf("%s has kind %s", field.FullName(), field.Kind()))
}

// Sets every field, with two elements in each list, so an encoding shows every field of the message.
func testFill(message protoreflect.Message, depth int) {
	fields := message.Descriptor().Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		switch {
		case field.IsMap():
			message.Mutable(field).Map().Set(testValue(field.MapKey(), 1).MapKey(), testValue(field.MapValue(), 1))
		case field.IsList():
			list := message.Mutable(field).List()
			for seed := range 2 {
				if field.Message() == nil {
					list.Append(testValue(field, seed+1))
					continue
				}
				element := list.NewElement()
				if depth > 0 {
					testFill(element.Message(), depth-1)
				}
				list.Append(element)
			}
		case field.Message() != nil:
			nested := message.Mutable(field).Message()
			if depth > 0 {
				testFill(nested, depth-1)
			}
		default:
			message.Set(field, testValue(field, 1))
		}
	}
}

func testFilled(messageType protoreflect.MessageType) proto.Message {
	message := messageType.New()
	testFill(message, testFillDepth)
	return message.Interface()
}

func testEncode(t testing.TB, message proto.Message) []byte {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatalf("%s: %v", message.ProtoReflect().Descriptor().Name(), err)
	}
	return encoded
}

// An encoding's top-level fields, each a whole record: tag and value.
func testSplitFields(t testing.TB, encoded []byte) [][]byte {
	fields := [][]byte{}
	for rest := encoded; len(rest) > 0; {
		_, _, length := protowire.ConsumeField(rest)
		if length < 0 {
			t.Fatalf("a field does not parse: %v", protowire.ParseError(length))
		}
		fields = append(fields, rest[:length])
		rest = rest[length:]
	}
	return fields
}

// Highest numbers first. Stable, so a repeated field keeps its order and the body still means the same.
func testReordered(t testing.TB, encoded []byte) []byte {
	fields := testSplitFields(t, encoded)
	slices.SortStableFunc(fields, func(a, b []byte) int {
		numberA, _, _ := protowire.ConsumeTag(a)
		numberB, _, _ := protowire.ConsumeTag(b)
		return cmp.Compare(numberB, numberA)
	})
	return bytes.Join(fields, nil)
}

// Each top-level varint one byte longer than it need be, a form every parser must accept and no encoder writes.
func testNonMinimal(t testing.TB, encoded []byte) []byte {
	rewritten := []byte{}
	for _, field := range testSplitFields(t, encoded) {
		number, wireType, tagLength := protowire.ConsumeTag(field)
		if wireType != protowire.VarintType {
			rewritten = append(rewritten, field...)
			continue
		}
		value, _ := protowire.ConsumeVarint(field[tagLength:])
		padded := protowire.AppendVarint(nil, value)
		if len(padded) < 10 {
			padded[len(padded)-1] |= 0x80
			padded = append(padded, 0x00)
		}
		rewritten = protowire.AppendTag(rewritten, number, protowire.VarintType)
		rewritten = append(rewritten, padded...)
	}
	return rewritten
}

// Each packed list of varints written one element at a time, which a proto3 parser must take as the same list.
func testUnpacked(t testing.TB, descriptor protoreflect.MessageDescriptor, encoded []byte) []byte {
	rewritten := []byte{}
	for _, record := range testSplitFields(t, encoded) {
		number, wireType, tagLength := protowire.ConsumeTag(record)
		field := descriptor.Fields().ByNumber(number)
		if wireType != protowire.BytesType || field == nil || !field.IsPacked() {
			rewritten = append(rewritten, record...)
			continue
		}
		packed, _ := protowire.ConsumeBytes(record[tagLength:])
		for len(packed) > 0 {
			value, length := protowire.ConsumeVarint(packed)
			if length < 0 {
				t.Fatalf("%s: a packed value does not parse", field.FullName())
			}
			rewritten = protowire.AppendTag(rewritten, number, protowire.VarintType)
			rewritten = protowire.AppendVarint(rewritten, value)
			packed = packed[length:]
		}
	}
	return rewritten
}

func testUnknownField() []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, testUnknownFieldNumber, protowire.VarintType), 7)
}

// Nothing is lost between a full message and its encoding: a field this drops or renumbers cannot survive it.
func TestEveryBodyRoundTrips(t *testing.T) {
	for _, messageType := range testBodyTypes(t) {
		message := testFilled(messageType)
		encoded := testEncode(t, message)
		decoded := messageType.New().Interface()
		if err := proto.Unmarshal(encoded, decoded); err != nil {
			t.Errorf("%s: %v", messageType.Descriptor().Name(), err)
			continue
		}
		if !proto.Equal(message, decoded) {
			t.Errorf("%s changed on the wire", messageType.Descriptor().Name())
		}
		if !bytes.Equal(testEncode(t, decoded), encoded) {
			t.Errorf("%s re-encoded differently", messageType.Descriptor().Name())
		}
		set := 0
		decoded.ProtoReflect().Range(func(protoreflect.FieldDescriptor, protoreflect.Value) bool {
			set++
			return true
		})
		if want := messageType.Descriptor().Fields().Len(); set != want {
			t.Errorf("%s came back with %d of %d fields", messageType.Descriptor().Name(), set, want)
		}
	}
}

// §22.6's seeds as assertions: three encodings no writer here produces, each the same message, and each differing
// from the canonical bytes wherever its message gives it a field to differ on.
func TestEveryBodyDecodesAlikeHoweverEncoded(t *testing.T) {
	differed := map[string]int{}
	for _, messageType := range testBodyTypes(t) {
		message := testFilled(messageType)
		canonical := testEncode(t, message)
		variants := map[string][]byte{
			"reordered":   testReordered(t, canonical),
			"non-minimal": testNonMinimal(t, canonical),
			"unpacked":    testUnpacked(t, messageType.Descriptor(), canonical),
		}
		for variant, encoded := range variants {
			if !bytes.Equal(encoded, canonical) {
				differed[variant]++
			}
			decoded := messageType.New().Interface()
			if err := proto.Unmarshal(encoded, decoded); err != nil {
				t.Errorf("%s %s: %v", messageType.Descriptor().Name(), variant, err)
				continue
			}
			if !proto.Equal(message, decoded) {
				t.Errorf("%s %s decoded differently", messageType.Descriptor().Name(), variant)
			}
			if !bytes.Equal(testEncode(t, decoded), canonical) {
				t.Errorf("%s %s did not re-encode to the canonical bytes", messageType.Descriptor().Name(), variant)
			}
		}
	}
	// A variant that never changed a byte would prove nothing about the parser.
	for _, variant := range []string{"reordered", "non-minimal", "unpacked"} {
		if differed[variant] == 0 {
			t.Errorf("no message's %s encoding differed", variant)
		}
	}
}

// A repeated singular field means its last value, and the same body twice is a body: repeated fields double,
// singular ones stand, and the result re-encodes stably. Nothing here refuses it, so a verifier must hash what it
// received.
func TestEveryBodyTakesARepeatedField(t *testing.T) {
	for _, messageType := range testBodyTypes(t) {
		canonical := testEncode(t, testFilled(messageType))
		decoded := messageType.New().Interface()
		if err := proto.Unmarshal(append(slices.Clone(canonical), canonical...), decoded); err != nil {
			t.Errorf("%s: %v", messageType.Descriptor().Name(), err)
			continue
		}
		encoded := testEncode(t, decoded)
		again := messageType.New().Interface()
		if err := proto.Unmarshal(encoded, again); err != nil {
			t.Errorf("%s: %v", messageType.Descriptor().Name(), err)
			continue
		}
		if !proto.Equal(decoded, again) {
			t.Errorf("%s changed when re-encoded", messageType.Descriptor().Name())
		}
	}
}

// Readers keep what they cannot name (§16.8), so a newer writer's field survives an older reader's pass.
func TestEveryBodyKeepsUnknownFields(t *testing.T) {
	unknown := testUnknownField()
	for _, messageType := range testBodyTypes(t) {
		canonical := testEncode(t, testFilled(messageType))
		decoded := messageType.New().Interface()
		if err := proto.Unmarshal(append(slices.Clone(canonical), unknown...), decoded); err != nil {
			t.Errorf("%s: %v", messageType.Descriptor().Name(), err)
			continue
		}
		if !bytes.Equal(decoded.ProtoReflect().GetUnknown(), unknown) {
			t.Errorf("%s dropped an unknown field", messageType.Descriptor().Name())
		}
		if !bytes.HasSuffix(testEncode(t, decoded), unknown) {
			t.Errorf("%s did not write it back", messageType.Descriptor().Name())
		}
	}
}

// Decoding never panics, and whatever decodes has one canonical form that decodes to the same message. name picks
// the message, and a mutated name still lands on one, so a run spends its time in decoders.
func FuzzBody(f *testing.F) {
	types := testBodyTypes(f)
	typesByName := map[string]protoreflect.MessageType{}
	for _, messageType := range types {
		name := string(messageType.Descriptor().Name())
		typesByName[name] = messageType
		canonical := testEncode(f, testFilled(messageType))
		f.Add(name, canonical)
		f.Add(name, testReordered(f, canonical))
		f.Add(name, testNonMinimal(f, canonical))
		f.Add(name, testUnpacked(f, messageType.Descriptor(), canonical))
		f.Add(name, append(slices.Clone(canonical), canonical...))
		f.Add(name, append(slices.Clone(canonical), testUnknownField()...))
	}
	f.Fuzz(func(t *testing.T, name string, body []byte) {
		messageType := typesByName[name]
		if messageType == nil {
			messageType = types[crc32.ChecksumIEEE([]byte(name))%uint32(len(types))]
		}
		message := messageType.New().Interface()
		if proto.Unmarshal(body, message) != nil {
			return
		}
		encoded := testEncode(t, message)
		decoded := messageType.New().Interface()
		if err := proto.Unmarshal(encoded, decoded); err != nil {
			t.Fatalf("%s: its own encoding does not decode: %v", messageType.Descriptor().Name(), err)
		}
		if !proto.Equal(message, decoded) {
			t.Fatalf("%s changed when re-encoded", messageType.Descriptor().Name())
		}
		if !bytes.Equal(testEncode(t, decoded), encoded) {
			t.Fatalf("%s has two canonical forms", messageType.Descriptor().Name())
		}
	})
}
