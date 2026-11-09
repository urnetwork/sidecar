// Extractor 1 for files (§11.14's extract and documents rows): a text file's title, its first heading or line, at most
// 80 B, indexed with the path, and its text as the body, one document per 1 MiB of text, each with the next 256 B. A
// binary gives no document, so a version that turns binary is a tombstone at its version, the writer's to write.

package sidecar

// The documents of one file version at path: one per chunk of its text, each carrying the title and path, or false
// for a binary. Version, provenance and the row's attributes are the caller's to set. A chunk's body is a view of
// content, or of its UTF-16 decoding, never a copy.
func indexExtractFile(path []byte, content []byte) ([]*IndexDocument, bool) {
	text, ok := indexSniff(content)
	if !ok {
		return nil, false
	}
	title := []byte(indexTitle(text))
	documents := []*IndexDocument{}
	for chunk, body := range indexChunks(text) {
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
