package cip30

import (
	"crypto/subtle"
	"encoding/hex"
)

// digest computes the expected payload bytes for an expected message, mirroring
// the reference verifier's convention.
//
//   - not hashed: the raw message bytes.
//   - hashed and the message is all-hex (even length, only [0-9a-fA-F]): the
//     hex-decoded bytes, treating the message as an already-computed
//     blake2b-224 digest.
//   - hashed and the message is not hex: blake2b-224(message).
//
// The is-hex guard means a raw message that happens to be all-hex is treated as
// pre-hashed; this is deliberate reference parity (see [WithMessage]).
func digest(message []byte, hashed bool) []byte {
	if !hashed {
		return message
	}
	if decoded, ok := decodeHexDigest(message); ok {
		return decoded
	}
	return keyHash224(message)
}

// decodeHexDigest reports whether message is an even-length all-hex string and,
// if so, returns its decoded bytes. It approximates the reference's
// /^[0-9a-fA-F]+$/ guard but additionally requires an even length so the string
// is decodable as bytes.
//
// This deliberately diverges from the reference for an ODD-length all-hex
// message: the reference's regex accepts it and compares it as a raw string,
// while here it is not treated as a pre-computed digest and falls through to
// blake2b-224(message). The final verdict is unchanged for any realistic input —
// an odd-length string can never equal an even-length hex-encoded payload, and
// the hashed path yields unrelated bytes — so the only effect is which mismatch
// path a hostile odd-length input takes.
func decodeHexDigest(message []byte) ([]byte, bool) {
	if len(message) == 0 || len(message)%2 != 0 {
		return nil, false
	}
	for _, b := range message {
		isDigit := b >= '0' && b <= '9'
		isLower := b >= 'a' && b <= 'f'
		isUpper := b >= 'A' && b <= 'F'
		if !isDigit && !isLower && !isUpper {
			return nil, false
		}
	}
	decoded, err := hex.DecodeString(string(message))
	if err != nil {
		return nil, false
	}
	return decoded, true
}

// bytesEqual reports whether two byte slices are equal. The comparison is
// constant-time defensively; payloads and digests here are not secret.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
