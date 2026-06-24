package cip30

import "encoding/hex"

// Shared hex-building helpers for the package's tests. They live here, in a
// neutral file, rather than in fuzz_test.go so the deterministic functional and
// robustness tests do not reach into the fuzz file for them; both draw from this
// common location.

// zeros returns a string of n ASCII '0' characters, used to build hex payloads
// of an exact byte length (n hex digits = n/2 bytes).
func zeros(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '0'
	}
	return string(b)
}

// sign1WithSig builds a hex COSE_Sign1 array whose signature element is the given
// hex bytes, reusing the primary vector's protected header and an empty payload.
// It is used to seed off-by-one signature lengths (63/65 bytes).
func sign1WithSig(sigHex string) string {
	// 84                                    array(4)
	// 582a a2 0127 67"address" 581d e1...    protected header bstr (42 bytes)
	// a0                                     unprotected {}
	// 40                                     payload h''
	// then signature: 0x58 <len> <bytes>
	const prefix = "84" +
		"582aa201276761646472657373581de118987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281" +
		"a0" +
		"40"
	return prefix + bstrHeader(len(sigHex)/2) + sigHex
}

// sign1WithEmbeddedAddress builds a hex COSE_Sign1 whose protected header is
// {alg:-8, "address": <rawAddrHex>}, with an empty payload (h”) and a zero
// 64-byte signature. The signature never verifies; the helper exists to drive the
// embedded-address decode path with an arbitrary (often non-canonical) address.
// The protected-header byte-string length is computed from the address so the
// CBOR stays well-formed as the address length varies.
func sign1WithEmbeddedAddress(rawAddrHex string) string {
	// protected map: a2 0127 67"address" <bstr addr>. "address" is a 7-byte text
	// string (0x67); the address itself is a CBOR byte string.
	protected := "a201276761646472657373" + bstrHeader(len(rawAddrHex)/2) + rawAddrHex
	// 84 <bstr protected> a0 40 <bstr 64-byte sig>
	return "84" + bstrHeader(len(protected)/2) + protected +
		"a0" + "40" + bstrHeader(64) + zeros(2*64)
}

// keyWithX builds a hex COSE_Key whose x value is the given hex bytes, used to
// seed off-by-one public-key lengths (31/33 bytes).
func keyWithX(xHex string) string {
	// a4 0101 0327 2006 2158 <len> <x>
	const prefix = "a401010327200621"
	return prefix + bstrHeader(len(xHex)/2) + xHex
}

// bstrHeader returns the hex of the CBOR byte-string head for a payload of n
// bytes. The result is hex so it concatenates with the hex seed strings that are
// later hex-decoded. It covers the sizes the seeds need.
func bstrHeader(n int) string {
	switch {
	case n < 24:
		return hex.EncodeToString([]byte{byte(0x40 + n)})
	case n < 256:
		return hex.EncodeToString([]byte{0x58, byte(n)})
	default:
		return hex.EncodeToString([]byte{0x59, byte(n >> 8), byte(n)})
	}
}
