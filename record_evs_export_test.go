//go:build !ios_extension

// The bridge record_evs_test.go's row codec reaches evs's object-key wrap through: a 32 B row wrapped under fek_g and
// opened as one of evs's object keys, the width evs's slot format holds while RECORD.md's 64 B rows wait on question
// record-m2-01-slot-row-salt. Tests only.

package sidecar

import (
	"bytes"
)

// row, 32 B, as the 72 B wrapped-key block of an object key under fek.
func EvsWrapTestObjectKey(fek *EvsFekKey, row []byte) ([]byte, error) {
	return EvsWrapObjectKey(fek, evsObjectKeyOf(bytes.Clone(row)))
}

// The 32 B row a wrapped-key block holds under fek.
func EvsUnwrapTestObjectKey(fek *EvsFekKey, wrapped []byte) ([]byte, error) {
	objectKey, err := EvsUnwrapObjectKey(fek, wrapped)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(objectKey.key), nil
}
