//go:build sidecar_testhooks

// mls_*'s decoders of a GroupInfo and a ratchet tree, for mlsinterop's §22.6 targets, which hold them to mls-go's
// and tmc/mls's (D-TEST-4). The root imports no peer, so the comparison lives in mlsinterop, and nothing exported
// reads either structure alone: JoinExternal and Complete go on to judge what they decode, and their errors do not
// say which step refused. Each function here decodes as every leg does, so a basic credential is refused as in
// production, and returns the decoded value's encoding, which the subset's canonical decoding makes the input again.
//
// Nothing here holds or derives a key. Only the sidecar_testhooks build has these, which no release leg is
// (§22.4).

package sidecar

// An MLSMessage holding a GroupInfo, decoded as JoinExternal and Complete decode one, then encoded again.
func MlsTestDecodeGroupInfo(encoded []byte) ([]byte, error) {
	decoded := &mlsGroupInfo{}
	if err := mlsUnmarshalMessageOf(encoded, mlsWireFormatGroupInfo, decoded); err != nil {
		return nil, err
	}
	return mlsMarshalMessageOf(mlsWireFormatGroupInfo, decoded)
}

// A ratchet_tree extension's data, decoded under production's tree settings as a full GroupInfo's tree is, then
// encoded again. Decoding reads no key as a suite's, so one call serves trees of either suite.
func MlsTestDecodeRatchetTree(encoded []byte) ([]byte, error) {
	tree, err := decodeMlsRatchetTree(mlsSuite, defaultMlsTreeSettings(), encoded)
	if err != nil {
		return nil, err
	}
	return mlsMarshal(tree)
}
