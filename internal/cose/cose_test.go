package cose

import (
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// primaryVectorSig is the COSE_Sign1 of the canonical stake-key vector
// (index.test.ts): payload "Augusta Ada King, Countess of Lovelace", not hashed.
const primaryVectorSig = "84582aa201276761646472657373581de118987c1612069d4080a0eb247820cb987fea81bddeaafdd41f9962" +
	"81a166686173686564f458264175677573746120416461204b696e672c20436f756e74657373206f66204c6f76656c" +
	"61636558401712458b19f606b322982f6290c78529a235b56c0f1cec4f24b12a8660b40cd37f4c5440a465754089c46" +
	"2ed4b0d613bffaee3d1833516569fda4852f42a4a0f"

// primaryVectorKey is the COSE_Key for the primary vector: x = b89526...420c6.
const primaryVectorKey = "a4010103272006215820b89526fd6bf4ba737c55ea90670d16a27f8de6cc1982349b3b676705a2f420c6"

// expectedProtectedHex is the verbatim protected-header content: a CBOR map
// {alg:-8, "address":0xe1...}. The verifier must reuse these bytes unchanged.
const expectedProtectedHex = "a201276761646472657373581de118987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281"

const expectedKeyHex = "b89526fd6bf4ba737c55ea90670d16a27f8de6cc1982349b3b676705a2f420c6"

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err, "fixture hex must decode")
	return b
}

func TestDecodeSign1PrimaryVector(t *testing.T) {
	sign1, err := DecodeSign1(mustDecodeHex(t, primaryVectorSig))
	require.NoError(t, err, "primary vector must decode")

	assert.Equal(t, mustDecodeHex(t, expectedProtectedHex), sign1.ProtectedRaw,
		"protected header must be reused verbatim")
	assert.Equal(t, []byte("Augusta Ada King, Countess of Lovelace"), sign1.Payload,
		"payload must be the raw message bytes")
	assert.Len(t, sign1.Signature, 64, "Ed25519 signature is 64 bytes")
	assert.False(t, sign1.Hashed, "this vector is not hashed")
	assert.Equal(t, int64(-8), sign1.Alg, "alg must be EdDSA (-8)")
	require.Len(t, sign1.Address, 29, "stake address is 29 bytes (1 header + 28 hash)")
	assert.Equal(t, byte(0xe1), sign1.Address[0], "address begins with the 0xe1 header byte")
}

func TestDecodeKeyPrimaryVector(t *testing.T) {
	x, err := DecodeKey(mustDecodeHex(t, primaryVectorKey))
	require.NoError(t, err, "primary COSE_Key must decode")
	assert.Equal(t, mustDecodeHex(t, expectedKeyHex), x, "x must be the 32-byte Ed25519 public key")
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	require.NoError(t, err, "fixture must marshal")
	return b
}

// sign1Bytes assembles a COSE_Sign1 array from its four elements. The protected
// header is supplied as a Go map and embedded as a byte string (its own CBOR
// encoding), mirroring the on-the-wire shape DecodeSign1 expects.
func sign1Bytes(t *testing.T, protected map[any]any, unprotected, payload, signature any) []byte {
	t.Helper()
	protectedRaw := mustMarshal(t, protected)
	return mustMarshal(t, []any{protectedRaw, unprotected, payload, signature})
}

// validProtected is the protected header of the primary vector: {alg:-8,
// "address":<29 bytes>}. Cases below mutate it to exercise one failure at a time.
func validProtected() map[any]any {
	return map[any]any{
		uint64(labelAlg): algEdDSA,
		headerAddress:    make([]byte, 29),
	}
}

func validSignature() []byte { return make([]byte, ed25519SigSize) }

// TestDecodeSign1Rejects exercises the typed error paths of DecodeSign1 at the
// package boundary: every malformed shape an attacker can submit must return a
// matchable sentinel and never panic.
func TestDecodeSign1Rejects(t *testing.T) {
	emptyUnprotected := map[any]any{}

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{
			name: "rejects CBOR that is not a 4-element array",
			data: mustMarshal(t, []any{1, 2, 3}),
			want: ErrInvalidSign1,
		},
		{
			name: "rejects CBOR that is not an array at all",
			data: mustMarshal(t, map[any]any{uint64(1): 2}),
			want: ErrInvalidSign1,
		},
		{
			name: "rejects a protected header that is not a byte string",
			// element[0] is an int, not a bstr wrapping a map.
			data: mustMarshal(t, []any{1, emptyUnprotected, []byte("p"), validSignature()}),
			want: ErrInvalidProtected,
		},
		{
			name: "rejects a protected header whose content is not a map",
			// element[0] is a bstr, but its content decodes as an int.
			data: mustMarshal(t, []any{mustMarshal(t, 1), emptyUnprotected, []byte("p"), validSignature()}),
			want: ErrInvalidProtected,
		},
		{
			name: "rejects a protected header missing alg",
			data: sign1Bytes(t, map[any]any{headerAddress: make([]byte, 29)},
				emptyUnprotected, []byte("p"), validSignature()),
			want: ErrInvalidProtected,
		},
		{
			name: "rejects a protected address that is not a byte string",
			data: sign1Bytes(t, map[any]any{uint64(labelAlg): algEdDSA, headerAddress: "not-bytes"},
				emptyUnprotected, []byte("p"), validSignature()),
			want: ErrInvalidProtected,
		},
		{
			name: "rejects a non-EdDSA algorithm",
			data: sign1Bytes(t, map[any]any{uint64(labelAlg): -7},
				emptyUnprotected, []byte("p"), validSignature()),
			want: ErrUnsupportedAlg,
		},
		{
			name: "rejects an unprotected header that is not a map",
			data: sign1Bytes(t, validProtected(), 42, []byte("p"), validSignature()),
			want: ErrInvalidUnprotected,
		},
		{
			name: "rejects an unprotected hashed flag that is not a bool",
			data: sign1Bytes(t, validProtected(), map[any]any{headerHashed: "yes"},
				[]byte("p"), validSignature()),
			want: ErrInvalidUnprotected,
		},
		{
			name: "rejects a payload that is not a byte string",
			data: sign1Bytes(t, validProtected(), emptyUnprotected, 99, validSignature()),
			want: ErrInvalidPayload,
		},
		{
			name: "rejects a signature that is not a byte string",
			data: sign1Bytes(t, validProtected(), emptyUnprotected, []byte("p"), "not-bytes"),
			want: ErrInvalidSignature,
		},
		{
			name: "rejects a signature that is not 64 bytes",
			data: sign1Bytes(t, validProtected(), emptyUnprotected, []byte("p"), make([]byte, 32)),
			want: ErrInvalidSignatureLen,
		},
		{
			name: "rejects a duplicate key in the protected header",
			// Two alg entries (a2 01 27 01 26) wrapped as the protected bstr.
			data: mustMarshal(t, []any{
				[]byte{0xa2, 0x01, 0x27, 0x01, 0x26},
				emptyUnprotected, []byte("p"), validSignature(),
			}),
			want: ErrInvalidProtected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeSign1(tc.data)
			require.Error(t, err, "malformed input must error")
			assert.ErrorIs(t, err, tc.want, "error must match the documented sentinel")
		})
	}
}

// TestDecodeKeyRejects exercises the typed error paths of DecodeKey: an attacker
// can submit any COSE_Key, so each wrong field must surface a matchable sentinel.
func TestDecodeKeyRejects(t *testing.T) {
	validKey := func() map[any]any {
		return map[any]any{
			uint64(1): keyTypeOKP,
			uint64(3): algEdDSA,
			int64(-1): curveEd25519,
			int64(-2): make([]byte, ed25519KeySize),
		}
	}

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{
			name: "rejects a COSE_Key that is not a map",
			data: mustMarshal(t, []any{1, 2}),
			want: ErrInvalidKey,
		},
		{
			name: "rejects a duplicate key in the COSE_Key",
			// {1:1, 1:1}: duplicate kty label.
			data: []byte{0xa2, 0x01, 0x01, 0x01, 0x01},
			want: ErrInvalidKey,
		},
		{
			name: "rejects a key type that is not OKP",
			data: func() []byte { k := validKey(); k[uint64(1)] = 2; return mustMarshal(t, k) }(),
			want: ErrUnsupportedKeyType,
		},
		{
			name: "rejects a key algorithm that is not EdDSA",
			data: func() []byte { k := validKey(); k[uint64(3)] = -7; return mustMarshal(t, k) }(),
			want: ErrUnsupportedAlg,
		},
		{
			name: "rejects a curve that is not Ed25519",
			data: func() []byte { k := validKey(); k[int64(-1)] = 1; return mustMarshal(t, k) }(),
			want: ErrUnsupportedCurve,
		},
		{
			name: "rejects a public key that is not 32 bytes",
			data: func() []byte { k := validKey(); k[int64(-2)] = make([]byte, 16); return mustMarshal(t, k) }(),
			want: ErrInvalidPublicKeyLen,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeKey(tc.data)
			require.Error(t, err, "malformed key must error")
			assert.ErrorIs(t, err, tc.want, "error must match the documented sentinel")
		})
	}
}

// TestSigStructureEmptyPayloadEndsWithEmptyByteString locks down a security
// invariant: an empty payload must encode as the empty byte string 0x40, never
// as CBOR null 0xf6. fxamacker encodes a nil []byte as null by default,
// so SigStructure must normalize it. This is the one internal byte-exactness
// test worth asserting directly.
func TestSigStructureEmptyPayloadEndsWithEmptyByteString(t *testing.T) {
	protectedRaw := mustDecodeHex(t, expectedProtectedHex)

	for _, payload := range [][]byte{nil, {}} {
		structure, err := SigStructure(protectedRaw, payload)
		require.NoError(t, err, "Sig_structure must marshal")
		require.NotEmpty(t, structure, "Sig_structure must not be empty")
		assert.Equal(t, byte(0x40), structure[len(structure)-1],
			"empty payload must encode as h'' (0x40), not null (0xf6)")
	}
}
