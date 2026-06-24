package cip30

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rawRewardAddr is the e1 reward address embedded in the primary stake vector,
// hex-encoded: the canonical 29 bytes (header 0xe1 + the 28-byte stake key hash).
// The signer's key hashes to this stake credential, so the canonical form
// matches — which is what makes the non-canonical variants below a binding
// concern rather than a harmless decode failure.
const rawRewardAddr = "e118987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281"

// TestVerifyRejectsNonCanonicalAddress confirms that address byte-strings which
// decode to a key hash belonging to the signer but whose shape is not canonical
// CIP-19 — extra trailing bytes beyond the credential window, or a pointer header
// carrying no chain pointer — are unprocessable input, not a check that ran and
// matched. Before the fix these reached Result.Valid() == true. Each shape is
// exercised on both address paths: caller-supplied (WithAddress, raw hex) and
// self-asserted in the COSE_Sign1 protected header (WithEmbeddedAddress).
func TestVerifyRejectsNonCanonicalAddress(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{
			name: "reward address with trailing bytes",
			// Canonical reward is exactly 29 bytes; append one trailing byte.
			addr: rawRewardAddr + "00",
		},
		{
			name: "pointer header without a chain pointer",
			// Type-4 pointer header (0x41) over the 28-byte payment hash and nothing
			// else — the bare "missing pointer payload" shape from the finding.
			addr: "41" + rawRewardAddr[2:],
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("supplied via WithAddress", func(t *testing.T) {
				result, err := Verify(
					DataSignature{Signature: sigStakePlain, Key: keyStake},
					WithAddress(tc.addr),
				)
				require.ErrorIs(t, err, ErrDecodeAddress,
					"a non-canonical supplied address must surface ErrDecodeAddress")
				assert.Nil(t, result, "no Result is returned when the address cannot be processed")
			})

			t.Run("embedded in the protected header", func(t *testing.T) {
				result, err := Verify(
					DataSignature{Signature: sign1WithEmbeddedAddress(tc.addr), Key: validKeyHex},
					WithEmbeddedAddress(),
				)
				require.ErrorIs(t, err, ErrDecodeAddress,
					"a non-canonical embedded address must surface ErrDecodeAddress")
				assert.Nil(t, result, "no Result is returned when the address cannot be processed")
			})
		})
	}
}
