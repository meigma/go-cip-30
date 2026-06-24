package cip30

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDigest exercises the reference-parity digest convention directly: the
// raw, pre-hashed-hex, and hash-the-plaintext branches plus the is-hex guard's
// surprising corner where an all-hex plaintext is treated as a digest.
func TestDigest(t *testing.T) {
	helloHashHex := blake2b224Hex("Hello world")
	helloHash, err := hex.DecodeString(helloHashHex)
	if err != nil {
		t.Fatalf("decoding fixture digest: %v", err)
	}

	tests := []struct {
		name    string
		message string
		hashed  bool
		want    []byte
	}{
		{
			name:    "returns the raw message when not hashed",
			message: "Hello world",
			hashed:  false,
			want:    []byte("Hello world"),
		},
		{
			name:    "hashes a non-hex message with blake2b-224 when hashed",
			message: "Hello world",
			hashed:  true,
			want:    helloHash,
		},
		{
			name:    "treats an all-hex message as a precomputed digest when hashed",
			message: helloHashHex,
			hashed:  true,
			want:    helloHash,
		},
		{
			name:    "hashes an odd-length hex-looking message rather than decoding it",
			message: "abc", // odd length: not a valid digest, so it is hashed
			hashed:  true,
			want:    keyHash224([]byte("abc")),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := digest([]byte(tc.message), tc.hashed)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestDecodeHexDigest pins the is-hex guard the reference uses: even-length,
// all-hex, non-empty strings decode; everything else does not.
func TestDecodeHexDigest(t *testing.T) {
	tests := []struct {
		name    string
		message string
		wantOK  bool
	}{
		{name: "accepts lowercase hex", message: "deadbeef", wantOK: true},
		{name: "accepts uppercase hex", message: "DEADBEEF", wantOK: true},
		{name: "rejects an empty string", message: "", wantOK: false},
		{name: "rejects odd-length hex", message: "abc", wantOK: false},
		{name: "rejects non-hex characters", message: "Hello world", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := decodeHexDigest([]byte(tc.message))
			assert.Equal(t, tc.wantOK, ok)
		})
	}
}
