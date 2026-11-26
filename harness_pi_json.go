//go:build !ios_extension && !sidecar_http

// Pi's JSON as the Harness reads and writes it (DESIGN-COMPUTE §7.3, D-HARN-1): Pi's event JSON, RPC lines and session
// entries are JavaScript objects written by JSON.stringify, so the Harness keeps their members in the order written
// and their names as Pi spells them (assistantMessageEvent, firstKeptEntryId, toolResult), never re-cased to
// CODESTYLE. A member another build wrote that this one does not know is kept where it stood and passed on.
//
// Values are written as JSON.stringify writes them: no HTML escaping, and U+2028 and U+2029 as themselves, where Go's
// encoder escapes all five; numbers as Go's encoder writes float64, which is ES6's form.
//
// A harnessPiObject is a value: callers copy it before changing it where another holds it.

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// A member that is not a JSON object where one was asked.
var errHarnessPiNotObject = errors.New("not a JSON object")

// One member of an object, in the order written.
type harnessPiField struct {
	name  string
	value json.RawMessage
}

// A JSON object whose members keep their order and their unknown names.
type harnessPiObject []*harnessPiField

// v as JSON.stringify writes it: Go's encoder without HTML escaping, with U+2028 and U+2029 unescaped.
func harnessPiMarshal(v any) (json.RawMessage, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	encoded := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	return harnessPiUnescapeSeparators(encoded), nil
}

// encoded with every U+2028 and U+2029 escape inside a string written as the character, which JSON.stringify does not
// escape. A backslash escape is copied whole, so an escaped backslash before the letters u2028 stays as it was.
func harnessPiUnescapeSeparators(encoded []byte) json.RawMessage {
	if !bytes.Contains(encoded, []byte(`\u202`)) {
		return json.RawMessage(bytes.Clone(encoded))
	}
	out := make([]byte, 0, len(encoded))
	inString := false
	for i := 0; i < len(encoded); i += 1 {
		c := encoded[i]
		switch {
		case !inString:
			if c == '"' {
				inString = true
			}
			out = append(out, c)
		case c == '"':
			inString = false
			out = append(out, c)
		case c == '\\' && i+1 < len(encoded):
			if encoded[i+1] == 'u' && i+5 < len(encoded) {
				escape := string(encoded[i : i+6])
				switch escape {
				case "\\u2028":
					out = utf8.AppendRune(out, 0x2028)
					i += 5
					continue
				case "\\u2029":
					out = utf8.AppendRune(out, 0x2029)
					i += 5
					continue
				}
				out = append(out, encoded[i:i+6]...)
				i += 5
				continue
			}
			out = append(out, encoded[i:i+2]...)
			i += 1
		default:
			out = append(out, c)
		}
	}
	return out
}

// raw compacted, with its strings as JSON.stringify writes them, so a value read from another writer is written back
// in Pi's form. Refuses what is not JSON.
func harnessPiCompact(raw []byte) (json.RawMessage, error) {
	if !json.Valid(raw) {
		return nil, errors.New("not JSON")
	}
	trimmed := bytes.TrimSpace(raw)
	switch {
	case bytes.HasPrefix(trimmed, []byte("{")):
		// an object keeps its members' order, which a map would lose
		object := harnessPiObject{}
		if err := object.UnmarshalJSON(trimmed); err != nil {
			return nil, err
		}
		return object.MarshalJSON()
	case bytes.HasPrefix(trimmed, []byte("[")):
		elements := []json.RawMessage{}
		if err := json.Unmarshal(trimmed, &elements); err != nil {
			return nil, err
		}
		compacted := make([]json.RawMessage, 0, len(elements))
		for _, element := range elements {
			c, err := harnessPiCompact(element)
			if err != nil {
				return nil, err
			}
			compacted = append(compacted, c)
		}
		return harnessPiMarshalArray(compacted), nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	// numbers as written, so a large integer keeps its digits
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return harnessPiMarshal(value)
}

// The array of elements, each already JSON.
func harnessPiMarshalArray(elements []json.RawMessage) json.RawMessage {
	out := []byte{'['}
	for i, element := range elements {
		if 0 < i {
			out = append(out, ',')
		}
		out = append(out, element...)
	}
	return append(out, ']')
}

// The member named name, or nil.
func (self harnessPiObject) get(name string) json.RawMessage {
	for _, field := range self {
		if field.name == name {
			return field.value
		}
	}
	return nil
}

// Whether the object holds name.
func (self harnessPiObject) has(name string) bool {
	return self.get(name) != nil
}

// Decodes the member named name into v; false where there is none or it does not decode.
func (self harnessPiObject) decode(name string, v any) bool {
	value := self.get(name)
	if value == nil {
		return false
	}
	return json.Unmarshal(value, v) == nil
}

// The member's string, or empty.
func (self harnessPiObject) str(name string) string {
	text := ""
	self.decode(name, &text)
	return text
}

// Sets name to value's JSON where it stands, or appends it.
func (self *harnessPiObject) set(name string, value any) error {
	encoded, err := harnessPiMarshal(value)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	self.setRaw(name, encoded)
	return nil
}

// Sets name to raw, already JSON, where it stands, or appends it.
func (self *harnessPiObject) setRaw(name string, raw json.RawMessage) {
	for _, field := range *self {
		if field.name == name {
			field.value = raw
			return
		}
	}
	*self = append(*self, &harnessPiField{name: name, value: raw})
}

// Removes name, if it is there.
func (self *harnessPiObject) remove(name string) {
	kept := (*self)[:0]
	for _, field := range *self {
		if field.name != name {
			kept = append(kept, field)
		}
	}
	*self = kept
}

// A copy whose members a change to it leaves the original's alone.
func (self harnessPiObject) clone() harnessPiObject {
	cloned := make(harnessPiObject, 0, len(self))
	for _, field := range self {
		cloned = append(cloned, &harnessPiField{name: field.name, value: bytes.Clone(field.value)})
	}
	return cloned
}

// The members' names, in order.
func (self harnessPiObject) names() []string {
	names := make([]string, 0, len(self))
	for _, field := range self {
		names = append(names, field.name)
	}
	return names
}

// The object, its members in order.
func (self harnessPiObject) MarshalJSON() ([]byte, error) {
	out := []byte{'{'}
	for i, field := range self {
		if 0 < i {
			out = append(out, ',')
		}
		name, err := harnessPiMarshal(field.name)
		if err != nil {
			return nil, err
		}
		out = append(out, name...)
		out = append(out, ':')
		if field.value == nil {
			out = append(out, "null"...)
		} else {
			out = append(out, field.value...)
		}
	}
	return append(out, '}'), nil
}

// Reads an object's members in order, each value compacted to Pi's form. A name written twice keeps its first place
// and its last value, as JSON.parse does.
func (self *harnessPiObject) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return errHarnessPiNotObject
	}
	object := harnessPiObject{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return errHarnessPiNotObject
		}
		raw := json.RawMessage{}
		if err := decoder.Decode(&raw); err != nil {
			return err
		}
		value, err := harnessPiCompact(raw)
		if err != nil {
			return err
		}
		object.setRaw(name, value)
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if decoder.More() {
		return errHarnessPiNotObject
	}
	*self = object
	return nil
}
