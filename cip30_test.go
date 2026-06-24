package cip30

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validKeyHex is a well-formed COSE_Key, reused by negative cases that need one
// valid field so the other field is the sole cause of failure.
const validKeyHex = "a4010103272006215820b89526fd6bf4ba737c55ea90670d16a27f8de6cc1982349b3b676705a2f420c6"

// TestParseRejects asserts the error-vs-invalid contract at the public boundary:
// an input that cannot be processed must return a nil Signature and an error
// matchable with [errors.Is], distinct from a signature that verifies to false.
func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		sig  DataSignature
		want error
	}{
		{
			name: "rejects a signature field that is not valid hex",
			sig:  DataSignature{Signature: "zz", Key: validKeyHex},
			want: ErrInvalidSignatureHex,
		},
		{
			name: "rejects a key field that is not valid hex",
			sig:  DataSignature{Signature: "84", Key: "zz"},
			want: ErrInvalidKeyHex,
		},
		{
			name: "rejects a COSE_Sign1 that is malformed CBOR",
			// 0x84 declares a 4-element array but no elements follow.
			sig:  DataSignature{Signature: "84", Key: validKeyHex},
			want: ErrDecodeSignature,
		},
		{
			name: "rejects a COSE_Key that is malformed CBOR",
			// A valid COSE_Sign1, but the key is an empty map (missing fields).
			sig: DataSignature{
				Signature: "84582aa201276761646472657373581de118987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281a166686173686564f458264175677573746120416461204b696e672c20436f756e74657373206f66204c6f76656c61636558401712458b19f606b322982f6290c78529a235b56c0f1cec4f24b12a8660b40cd37f4c5440a465754089c462ed4b0d613bffaee3d1833516569fda4852f42a4a0f",
				Key:       "a0",
			},
			want: ErrDecodeKey,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := Parse(tc.sig)
			require.ErrorIs(t, err, tc.want, "error must match the documented sentinel")
			assert.Nil(t, parsed, "no Signature is returned on a processing error")

			result, err := Verify(tc.sig)
			require.ErrorIs(t, err, tc.want, "Verify error must match the documented sentinel")
			assert.Nil(t, result, "no Result is returned on a processing error")
		})
	}
}

// goldenVector is one signature-only case ported from the TypeScript reference
// (ref/cardano-verify-datasignature/index.test.ts). No message or address is
// supplied, so the expected outcome is purely the Ed25519 signature verdict.
type goldenVector struct {
	name      string
	key       string
	signature string
	wantValid bool
}

func (v goldenVector) dataSignature() DataSignature {
	return DataSignature{Signature: v.signature, Key: v.key}
}

// TestGoldenVectorsSignatureOnly runs the four signature-only golden vectors
// through both Parse(...).Verify() and the top-level Verify(...), asserting the
// same verdict and that identity fields are populated regardless of outcome.
func TestGoldenVectorsSignatureOnly(t *testing.T) {
	// Four golden vectors from index.test.ts that need no message or address.
	vectors := []goldenVector{
		{
			name:      "valid stake-key signature with embedded plaintext payload",
			key:       "a4010103272006215820b89526fd6bf4ba737c55ea90670d16a27f8de6cc1982349b3b676705a2f420c6",
			signature: "84582aa201276761646472657373581de118987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281a166686173686564f458264175677573746120416461204b696e672c20436f756e74657373206f66204c6f76656c61636558401712458b19f606b322982f6290c78529a235b56c0f1cec4f24b12a8660b40cd37f4c5440a465754089c462ed4b0d613bffaee3d1833516569fda4852f42a4a0f",
			wantValid: true,
		},
		{
			name:      "valid stake-key signature with hashed payload",
			key:       "a40101032720062158209be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27",
			signature: "84582aa201276761646472657373581de0c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73fa166686173686564f5581c40843181253eb1ff2258ab39c3463ec0edf5e713b73c5482c0ca798f5840a4cdec07ba8c1184aa74d1c3516fc6602a35d2db847510cf98c102653c15c7664f136314f920150a081870aef77ed49780ca58873bd5d62e744b968a89435906",
			wantValid: true,
		},
		{
			name:      "valid payment-key signature",
			key:       "a4010103272006215820472be3f30b51ead6d020e0d370774861e242ca23eaca2f4eff4ddb8eaa3abefd",
			signature: "845846a20127676164647265737358390197cab94302b6d471d54db7052335dbfcf980f8dfc924dd1777ee784a18987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281a166686173686564f44b48656c6c6f20576f726c645840b65cb33e107a692605a479811a8405e44eeac5217c6ef92b79c221c2309305ec2db927fb75a7d197602e1eb2e663dae227aa7c0510b6484f5591b2b4bd47b70d",
			wantValid: true,
		},
		{
			name:      "null payload fails verification",
			key:       "a40101032720062158209be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27",
			signature: "84582aa201276761646472657373581de0c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73fa166686173686564f4f658400a0dd23e867292a4c2eb692f63016e3f61294686f672065fcc377f665cff6b25c430619060b536073cfd2355ab6c6bcec9d7ecbfb588f7b0aa5967f1b8559300",
			wantValid: false,
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			ds := v.dataSignature()

			signature, err := Parse(ds)
			require.NoError(t, err, "well-formed vector must parse")
			require.Len(t, signature.PublicKey, 32, "public key must be 32 bytes")
			assert.Len(t, signature.KeyHash(), 28, "key hash is blake2b-224 (28 bytes)")
			assert.Equal(t, v.wantValid, signature.Verify(),
				"Parse().Verify() must match the reference verdict")

			result, err := Verify(ds)
			require.NoError(t, err, "a checked-but-invalid signature is not an error")
			require.NotNil(t, result, "Verify must return a Result when there is no error")
			assert.Equal(t, v.wantValid, result.SignatureValid,
				"Verify must match the reference verdict")
			assert.Equal(t, v.wantValid, result.Valid(), "Valid() reflects the signature result in phase 1")

			assert.Equal(t, signature.PublicKey, result.PublicKey, "Result carries the parsed public key")
			assert.Equal(t, signature.KeyHash(), result.KeyHash, "Result carries the key hash")
			assert.Len(t, result.KeyHash, 28, "Result key hash is 28 bytes")
		})
	}
}
