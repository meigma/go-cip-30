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
	// ErrDecodeAddress indicates a supplied or embedded address could not be
	// decoded (bad bech32/hex, unsupported type such as Byron, or truncated).
	ErrDecodeAddress = errors.New("cip30: cannot decode address")
	// ErrConflictingAddress indicates both WithAddress and WithEmbeddedAddress
	// were configured. They are mutually exclusive; this is caller misuse and so
	// is reported as unprocessable input rather than a failed check.
	ErrConflictingAddress = errors.New("cip30: WithAddress and WithEmbeddedAddress are mutually exclusive")
	// ErrNoEmbeddedAddress indicates WithEmbeddedAddress was requested but the
	// COSE_Sign1 protected header carried no "address" field.
	ErrNoEmbeddedAddress = errors.New("cip30: signature has no embedded address")
)
