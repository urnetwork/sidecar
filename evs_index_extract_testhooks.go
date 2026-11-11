//go:build sidecar_testhooks && !ios_extension

// Extractor 1's seam for SearchOracle's cross check (DESIGN-DETAILS 11.6; SEARCH-M10-43): FuzzExtractOracleEqualsIndex
// and TestExtractOracleEqualsIndexOnCorpus in sidecartest hold the oracle's extractor, written apart, to this one on
// any bytes. The seam is called from a test file there, never from an oracle file, so the oracle imports no index code.
//
// Nothing here holds or derives a key. Only the sidecar_testhooks build has it, which no release leg is (§22.4).

package sidecar

// One document as extractor 1 gives it: its chunk number, its five text fields as normalizer 1 is given them (a
// file's field 4 its title, one SP and its path), and its row's values after the row's own trimming.
type TestHookIndexDocument struct {
	Chunk uint32
	// By §11.14's number less one: subject, from, to, title, body.
	Fields [5][]byte
	// The row's locator, its subject, from, to and title, and the source's length in bytes.
	Locator   string
	Subject   string
	From      string
	To        string
	Title     string
	ByteCount uint64
	// Whether the document's key set passes its cap, so it has no entry (D6); its row's values are then empty.
	Skipped bool
}

// The documents extractor 1 gives content at path, as mail when mail is set and else as a file, on
// DefaultIndexFormatSettings and this build's normalizer 1; false for a binary file, and for a build whose tables are
// not normalizer 1's.
func TestHookIndexExtract(mail bool, path []byte, content []byte) ([]TestHookIndexDocument, bool) {
	settings := DefaultIndexFormatSettings()
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return nil, false
	}
	var documents []*IndexDocument
	if mail {
		documents = indexExtractMail(path, content, settings)
	} else {
		var ok bool
		if documents, ok = indexExtractFile(path, content, settings); !ok {
			return nil, false
		}
	}
	extracted := []TestHookIndexDocument{}
	for _, document := range documents {
		hooked := TestHookIndexDocument{Chunk: document.Chunk}
		for _, field := range document.textFields() {
			if field.number < indexFieldSubject || indexFieldBody < field.number {
				continue
			}
			value := []byte{}
			buffer := make([]byte, 4096)
			for {
				byteCount, err := field.text.Read(buffer)
				value = append(value, buffer[:byteCount]...)
				if err != nil {
					break
				}
			}
			hooked.Fields[field.number-1] = value
		}
		prepared, err := document.prepare(normalizer, false, Id{})
		if err != nil {
			return nil, false
		}
		if prepared.skipped {
			hooked.Skipped = true
		} else {
			hooked.Locator = prepared.row.locator
			hooked.Subject = prepared.row.fields[indexFieldSubject]
			hooked.From = prepared.row.fields[indexFieldFrom]
			hooked.To = prepared.row.fields[indexFieldTo]
			hooked.Title = prepared.row.fields[indexFieldTitle]
			hooked.ByteCount = prepared.row.byteCount
		}
		extracted = append(extracted, hooked)
	}
	return extracted, true
}
