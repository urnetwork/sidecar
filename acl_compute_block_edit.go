// Editing the compute block's disclosures in place (DESIGN-COMPUTE §2.8, §16.4; CO-41; CACL-M12-03), for
// CTRUST-M12-02's network acknowledgments: SetComputeBlockDisclosure adds or replaces one entry of compute.disclosures
// and RemoveComputeBlockDisclosure takes one out, in a document's source or in a network with no document's block-alone
// record (ConfigHeadComputePath), leaving every other byte as written, comments, spacing, trailing commas and key order
// included, so an Owner's or Admin's acknowledgment changes nothing else a person wrote.
//
//	set      an entry that stands has its value's bytes replaced; one that does not is added after the object's last
//	         member, or after its opening brace where it has none; a disclosures key, or a compute key, that does not
//	         stand is added the same way, holding the one entry; an empty source becomes a block-alone record
//	remove   the entry's key and value go, with the comma that separated it from a neighbour; an entry that does not
//	         stand leaves the source as it was
//
// Every edit is read back through ParseAclPolicy, so no edit answers a source the readers would refuse. The positions
// come from the standardized text, whose offsets are the source's (aclStandardizeHujson).
//
// On every leg, as the parse is. Package-level functions, safe for concurrent use; the caller's source is not changed.

package sidecar

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
)

// An edit whose input or whose outcome is no compute block's: a source that does not parse, a compute or disclosures
// value that is no object, an id that is no disclosure's, or a statement that is not standard base64.
var ErrAclComputeEditInvalid = errors.New("compute block edit")

// One member of a JSON object in the standardized text: its key, decoded, the offset its key starts at and the span of
// its value.
type aclComputeEditMember struct {
	key        string
	keyStart   int
	valueStart int
	valueEnd   int
}

// One object in the standardized text: the offset of its opening and closing braces, and its members in order.
type aclComputeEditObject struct {
	open    int
	close   int
	members []aclComputeEditMember
}

// The member keyed key, nil for none.
func (self *aclComputeEditObject) member(key string) *aclComputeEditMember {
	index := slices.IndexFunc(self.members, func(member aclComputeEditMember) bool { return member.key == key })
	if index < 0 {
		return nil
	}
	return &self.members[index]
}

// A scanner over standardized text that json.Valid passed, so it meets only well-formed JSON.
type aclComputeEditScanner struct {
	text []byte
}

// The offset of the first byte at or after i that is no JSON whitespace.
func (self *aclComputeEditScanner) skipSpace(i int) int {
	for i < len(self.text) && (self.text[i] == ' ' || self.text[i] == '\t' || self.text[i] == '\n' || self.text[i] == '\r') {
		i += 1
	}
	return i
}

// The offset after the value starting at i.
func (self *aclComputeEditScanner) skipValue(i int) int {
	switch self.text[i] {
	case '"':
		return aclSkipJsonString(self.text, i)
	case '{', '[':
		depth := 0
		for j := i; j < len(self.text); {
			switch self.text[j] {
			case '"':
				j = aclSkipJsonString(self.text, j)
				continue
			case '{', '[':
				depth += 1
			case '}', ']':
				depth -= 1
				if depth == 0 {
					return j + 1
				}
			}
			j += 1
		}
		return len(self.text)
	}
	j := i
	for j < len(self.text) && !bytes.ContainsRune([]byte(",}] \t\r\n"), rune(self.text[j])) {
		j += 1
	}
	return j
}

// The object starting at i, its members' keys decoded.
func (self *aclComputeEditScanner) object(i int) (*aclComputeEditObject, error) {
	if i >= len(self.text) || self.text[i] != '{' {
		return nil, ErrAclComputeEditInvalid
	}
	object := &aclComputeEditObject{open: i}
	j := self.skipSpace(i + 1)
	for j < len(self.text) && self.text[j] != '}' {
		if self.text[j] == ',' {
			j = self.skipSpace(j + 1)
			continue
		}
		keyEnd := aclSkipJsonString(self.text, j)
		key := ""
		if err := json.Unmarshal(self.text[j:keyEnd], &key); err != nil {
			return nil, ErrAclComputeEditInvalid
		}
		colon := self.skipSpace(keyEnd)
		if colon >= len(self.text) || self.text[colon] != ':' {
			return nil, ErrAclComputeEditInvalid
		}
		valueStart := self.skipSpace(colon + 1)
		valueEnd := self.skipValue(valueStart)
		object.members = append(object.members, aclComputeEditMember{key: key, keyStart: j, valueStart: valueStart, valueEnd: valueEnd})
		j = self.skipSpace(valueEnd)
	}
	if j >= len(self.text) {
		return nil, ErrAclComputeEditInvalid
	}
	object.close = j
	return object, nil
}

// A JSON member, "key": value, as an edit writes one.
func aclComputeEditMemberText(key string, value []byte) []byte {
	encoded, _ := json.Marshal(key)
	return append(append(encoded, ": "...), value...)
}

// source with text inserted at offset.
func aclComputeEditInsert(source []byte, offset int, text []byte) []byte {
	edited := slices.Clone(source[:offset])
	edited = append(edited, text...)
	return append(edited, source[offset:]...)
}

// source with member added to object: after its last member's value, or after its opening brace.
func aclComputeEditAdd(source []byte, object *aclComputeEditObject, member []byte) []byte {
	if len(object.members) == 0 {
		return aclComputeEditInsert(source, object.open+1, member)
	}
	last := object.members[len(object.members)-1]
	return aclComputeEditInsert(source, last.valueEnd, append([]byte(", "), member...))
}

// The source's top-level object, its compute member's object and that one's disclosures member's object, each nil
// where it does not stand; and the scanner. An error for a source that does not parse as HuJSON, or a compute or
// disclosures value that is no object.
func aclComputeEditLocate(source []byte) (*aclComputeEditObject, *aclComputeEditObject, *aclComputeEditObject, error) {
	standard, err := aclStandardizeHujson(source)
	if err != nil {
		return nil, nil, nil, errors.Join(ErrAclComputeEditInvalid, err)
	}
	if !json.Valid(standard) {
		return nil, nil, nil, ErrAclComputeEditInvalid
	}
	scanner := &aclComputeEditScanner{text: standard}
	top, err := scanner.object(scanner.skipSpace(0))
	if err != nil {
		return nil, nil, nil, err
	}
	computeMember := top.member("compute")
	if computeMember == nil {
		return top, nil, nil, nil
	}
	compute, err := scanner.object(computeMember.valueStart)
	if err != nil {
		return nil, nil, nil, err
	}
	disclosuresMember := compute.member("disclosures")
	if disclosuresMember == nil {
		return top, compute, nil, nil
	}
	disclosures, err := scanner.object(disclosuresMember.valueStart)
	if err != nil {
		return nil, nil, nil, err
	}
	return top, compute, disclosures, nil
}

// Refuses an id that is no disclosure's and a statement that is not standard base64 within its bound, as the parse
// would.
func aclComputeEditCheck(id string, statement *string) error {
	settings := DefaultAclComputeBlockSettings()
	if !aclComputeDisclosureId(id, settings) {
		return errors.Join(ErrAclComputeEditInvalid, errors.New("not a disclosure id"))
	}
	if statement == nil {
		return nil
	}
	if *statement == "" || settings.DisclosureStatementMaxByteCount < len(*statement) {
		return errors.Join(ErrAclComputeEditInvalid, errors.New("a statement outside its bound"))
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(*statement); err != nil {
		return errors.Join(ErrAclComputeEditInvalid, errors.New("a statement that is not standard base64"))
	}
	return nil
}

// Holds an edit's outcome to what every reader parses.
func aclComputeEditParsed(edited []byte) ([]byte, error) {
	if _, err := ParseAclPolicy(edited); err != nil {
		return nil, errors.Join(ErrAclComputeEditInvalid, err)
	}
	return edited, nil
}

// source, a document's or a block-alone record's, with compute.disclosures' entry id set to statement, the network's
// signed disclosure-ack in standard base64, every other byte as written; an empty source gives a block-alone record
// holding the one entry. ErrAclComputeEditInvalid for an id, a statement or a source the parse would refuse.
func SetComputeBlockDisclosure(source []byte, id string, statement string) ([]byte, error) {
	if err := aclComputeEditCheck(id, &statement); err != nil {
		return nil, err
	}
	value, _ := json.Marshal(statement)
	entry := aclComputeEditMemberText(id, value)
	if len(bytes.TrimSpace(source)) == 0 {
		record := append([]byte(`{"compute": {"disclosures": {`), entry...)
		return aclComputeEditParsed(append(record, "}}}\n"...))
	}
	top, compute, disclosures, err := aclComputeEditLocate(source)
	if err != nil {
		return nil, err
	}
	var edited []byte
	switch {
	case compute == nil:
		block := append(append([]byte(`{"disclosures": {`), entry...), "}}"...)
		edited = aclComputeEditAdd(source, top, aclComputeEditMemberText("compute", block))
	case disclosures == nil:
		edited = aclComputeEditAdd(source, compute, aclComputeEditMemberText("disclosures", append(append([]byte("{"), entry...), '}')))
	default:
		if member := disclosures.member(id); member != nil {
			edited = slices.Concat(source[:member.valueStart], value, source[member.valueEnd:])
		} else {
			edited = aclComputeEditAdd(source, disclosures, entry)
		}
	}
	return aclComputeEditParsed(edited)
}

// source with compute.disclosures' entry id taken out with the comma beside it, every other byte as written; source
// as it was where no such entry stands. ErrAclComputeEditInvalid for an id or a source the parse would refuse.
func RemoveComputeBlockDisclosure(source []byte, id string) ([]byte, error) {
	if err := aclComputeEditCheck(id, nil); err != nil {
		return nil, err
	}
	_, _, disclosures, err := aclComputeEditLocate(source)
	if err != nil {
		return nil, err
	}
	if disclosures == nil {
		return aclComputeEditParsed(slices.Clone(source))
	}
	index := slices.IndexFunc(disclosures.members, func(member aclComputeEditMember) bool { return member.key == id })
	if index < 0 {
		return aclComputeEditParsed(slices.Clone(source))
	}
	member := disclosures.members[index]
	start, end := member.keyStart, member.valueEnd
	switch {
	case index+1 < len(disclosures.members):
		// up to the next entry's key, the comma between them with it
		end = disclosures.members[index+1].keyStart
	case 0 < index:
		// from the previous entry's value, the comma before this one with it; a trailing comma after it stays, as
		// HuJSON allows
		start = disclosures.members[index-1].valueEnd
	default:
		// the one entry: its trailing comma too, the one comma between it and the closing brace, which the
		// standardized text blanked and the source keeps
		if comma := bytes.IndexByte(source[member.valueEnd:disclosures.close], ','); 0 <= comma {
			comma += member.valueEnd
			return aclComputeEditParsed(slices.Concat(source[:start], source[end:comma], source[comma+1:]))
		}
	}
	return aclComputeEditParsed(slices.Concat(source[:start], source[end:]))
}
