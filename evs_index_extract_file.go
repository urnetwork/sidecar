//go:build !ios_extension

// Extractor 1 for files (§11.14's extract and documents rows; DESIGN-DETAILS 11.2.3's D2 and 11.2.4): a text file's
// title (S4), indexed with its path in field 4 as the title, one SP and the path's bytes, and its text in field 5, one
// document per chunk (D4). A binary gives no document, so a version that turns binary is a tombstone at its version,
// the writer's to write.

package sidecar

// D2: the documents of one file version at path, one per chunk of its text, each carrying the title, or false for a
// binary. Field 4 holds the title alone, and the document's text puts the path after it (IndexDocument.textFields), so
// a row shows the title and never the path. Version, provenance and the row's attributes are the caller's to set. A
// chunk's body is a view of content, or of its UTF-16 decoding, never a copy.
func indexExtractFile(path []byte, content []byte, settings *IndexFormatSettings) ([]*IndexDocument, bool) {
	text, ok := indexSniff(content, settings)
	if !ok {
		return nil, false
	}
	title := []byte(indexTitle(text, settings))
	documents := []*IndexDocument{}
	for chunk, body := range indexChunks(text, settings) {
		document := &IndexDocument{
			Kind:      IndexDocFile,
			Name:      path,
			Chunk:     uint32(chunk),
			ByteCount: uint64(len(content)),
		}
		document.Fields[indexFieldTitle] = title
		document.Fields[indexFieldBody] = body
		documents = append(documents, document)
	}
	return documents, true
}
