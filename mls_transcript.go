//go:build !ios_extension

// The transcript hashes (RFC 9420 §8.2), which chain every commit a group adopts into its GroupContext,
// and the confirmation tag (RFC §6.1) that proves both sides reached the same epoch.
//
// A commit moves the two hashes in turn. Its signature enters the confirmed hash, the confirmed hash
// enters the GroupContext that keys the new epoch, and that epoch's confirmation key tags the confirmed
// hash, which then enters the interim hash the next commit starts from. So a signature comes before
// its tag, and mls_framing.go keeps them apart for this reason.

package sidecar

// ConfirmedTranscriptHashInput (RFC §8.2), a commit's bytes up to its confirmation tag.
func (self *mlsAuthenticatedContent) confirmedTranscriptHashInput() ([]byte, error) {
	encoder := &mlsEncoder{}
	encoder.writeUint16(self.wireFormat)
	self.content.encode(encoder)
	encoder.writeVector(self.auth.signature)
	return encoder.finish()
}

// confirmed_transcript_hash_[epoch] (RFC §8.2). The input is the encoded
// ConfirmedTranscriptHashInput of the commit that starts the epoch.
func (self *mlsCipherSuite) nextConfirmedTranscriptHash(interimTranscriptHash []byte, confirmedTranscriptHashInput []byte) []byte {
	return self.hash(append(append([]byte{}, interimTranscriptHash...), confirmedTranscriptHashInput...))
}

// interim_transcript_hash_[epoch] (RFC §8.2), whose InterimTranscriptHashInput is the tag as a MAC<V>.
func (self *mlsCipherSuite) nextInterimTranscriptHash(confirmedTranscriptHash []byte, confirmationTag []byte) ([]byte, error) {
	encoder := &mlsEncoder{}
	encoder.writeFixed(confirmedTranscriptHash)
	encoder.writeVector(confirmationTag)
	encoded, err := encoder.finish()
	if err != nil {
		return nil, err
	}
	return self.hash(encoded), nil
}

// The confirmation_tag of RFC §6.1: confirmation_key over the confirmed transcript hash.
func (self *mlsCipherSuite) confirmationTag(confirmationKey []byte, confirmedTranscriptHash []byte) []byte {
	return self.mac(confirmationKey, confirmedTranscriptHash)
}

// In constant time, once the commit's own epoch gives confirmationKey (RFC §12.4.2).
func (self *mlsCipherSuite) verifyConfirmationTag(confirmationKey []byte, confirmedTranscriptHash []byte, confirmationTag []byte) bool {
	return self.verifyMac(confirmationKey, confirmedTranscriptHash, confirmationTag)
}
