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

// TestVerifyReportsReservedNetworkAsUnknown confirms that an address with a
// reserved CIP-19 network tag (a header nibble other than 0/1, reachable only on
// raw or embedded input) is reported as NetworkUnknown rather than collapsed to
// Testnet. The credential still belongs to the signer, so the address check
// passes — the remediation is accurate reporting, not rejection. Mirrors the
// finding's probe, which reported network=Testnet for a reward address tagged 2.
func TestVerifyReportsReservedNetworkAsUnknown(t *testing.T) {
	// The e1 reward address with its network nibble changed from 1 to a reserved
	// value of 2 (header 0xe2). The 28-byte stake credential is unchanged and still
	// hashes from the signing key, so it matches via the stake credential.
	reservedAddr := "e2" + rawRewardAddr[2:]

	t.Run("supplied via WithAddress", func(t *testing.T) {
		result, err := Verify(
			DataSignature{Signature: sigStakePlain, Key: keyStake},
			WithAddress(reservedAddr),
		)
		require.NoError(t, err, "a reserved network tag is accepted, not a decode error")
		require.NotNil(t, result.Address)
		assert.True(t, result.Address.Matched, "the stake credential still matches the signer")
		assert.Equal(t, CredentialStake, result.Address.MatchedVia)
		assert.Equal(t, NetworkUnknown, result.Address.Network,
			"a reserved network nibble is reported as NetworkUnknown, not collapsed to Testnet")
		assert.True(t, result.Valid(), "signature is valid and the address matched")
	})

	t.Run("embedded in the protected header", func(t *testing.T) {
		// sign1WithEmbeddedAddress carries a zero signature, so SignatureValid (and
		// thus Valid) is false here; the point is that the embedded address decodes
		// and reports its reserved network accurately.
		result, err := Verify(
			DataSignature{Signature: sign1WithEmbeddedAddress(reservedAddr), Key: validKeyHex},
			WithEmbeddedAddress(),
		)
		require.NoError(t, err, "a reserved embedded network tag is accepted, not a decode error")
		require.NotNil(t, result.Address)
		assert.True(t, result.Address.Matched, "the embedded stake credential still matches the signer")
		assert.Equal(t, CredentialStake, result.Address.MatchedVia)
		assert.Equal(t, NetworkUnknown, result.Address.Network,
			"a reserved embedded network nibble is reported as NetworkUnknown")
	})
}

// TestNetworkUnknownString pins the string form of the reserved-network value.
func TestNetworkUnknownString(t *testing.T) {
	assert.Equal(t, "Unknown", NetworkUnknown.String())
}
