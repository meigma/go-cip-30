package cip30

import "errors"

// Errors returned when a DataSignature cannot be processed. They wrap the
// lower-level cause with %w so callers can match them with [errors.Is].
//
// A returned error always means the input could not be decoded — it is distinct
// from a signature that was checked and found invalid, which is reported in the
// Result without an error.
var (
	// ErrInvalidSignatureHex indicates the Signature field was not valid hex.
	ErrInvalidSignatureHex = errors.New("cip30: signature is not valid hex")
	// ErrInvalidKeyHex indicates the Key field was not valid hex.
	ErrInvalidKeyHex = errors.New("cip30: key is not valid hex")
	// ErrDecodeSignature indicates the COSE_Sign1 structure was malformed.
	ErrDecodeSignature = errors.New("cip30: cannot decode COSE_Sign1")
	// ErrDecodeKey indicates the COSE_Key structure was malformed.
	ErrDecodeKey = errors.New("cip30: cannot decode COSE_Key")
)
