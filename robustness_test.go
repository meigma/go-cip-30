package cip30

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// addrNetworkMismatch is a valid bech32 string whose mainnet "addr" HRP wraps a
// header byte with a testnet (nibble 0) network tag: 0x60 is an enterprise type
// (6) over network 0, encoded under the mainnet prefix. The decoder must accept
// the bech32 yet reject the address because the HRP disagrees with the header
// nibble. It is shared with the FuzzVerify seed corpus.
const addrNetworkMismatch = "addr1vqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkl09mf"

// TestVerifyRejectsNetworkMismatch pins the network-mismatch reject path
// deterministically: a bech32 address whose human-readable prefix implies one
// network while its header nibble encodes another must surface ErrDecodeAddress
// (wrapping the address layer's ErrNetworkMismatch), never a silent false match
// against the unrelated signing key.
func TestVerifyRejectsNetworkMismatch(t *testing.T) {
	result, err := Verify(
		DataSignature{Signature: sigStakePlain, Key: keyStake},
		WithAddress(addrNetworkMismatch),
	)
	require.ErrorIs(t, err, ErrDecodeAddress,
		"a bech32 HRP that disagrees with the header network must error")
	assert.Nil(t, result, "no Result accompanies a processing error")
}

// TestVerifyRejectsUnsupportedAddressType asserts an explicit WithAddress carrying
// a structurally-decodable but unsupported address type (Byron) is a processing
// error, distinct from a check that ran and missed.
func TestVerifyRejectsUnsupportedAddressType(t *testing.T) {
	byronHex := "80" + strings.Repeat("00", 28) // type-8 Byron header + payload
	result, err := Verify(
		DataSignature{Signature: sigStakePlain, Key: keyStake},
		WithAddress(byronHex),
	)
	require.ErrorIs(t, err, ErrDecodeAddress, "a Byron address is unsupported and must error")
	assert.Nil(t, result)
}

// TestVerifyNeverPanicsOnHostileAddresses is a focused, deterministic companion
// to FuzzVerify: a sweep of hostile address strings against a valid signature must
// each either decode-and-miss or return ErrDecodeAddress, but never panic and
// never wrongly match. It pins the boundary shapes the reviewers enumerated.
func TestVerifyNeverPanicsOnHostileAddresses(t *testing.T) {
	hostile := []struct {
		name string
		addr string
	}{
		{"empty", ""},
		{"one-byte header only", "00"},
		{"odd-length hex", "abc"},
		{"header plus one byte", "0000"},
		{"200-byte raw blob", strings.Repeat("00", 200)},
		{"Byron header", "80" + strings.Repeat("00", 28)},
		{"unknown type 9", "90" + strings.Repeat("00", 28)},
		{"not bech32 or hex", "definitely not an address"},
	}

	for _, tc := range hostile {
		t.Run(tc.name, func(t *testing.T) {
			// Must not panic regardless of outcome.
			result, err := Verify(
				DataSignature{Signature: sigStakePlain, Key: keyStake},
				WithAddress(tc.addr),
			)
			if err != nil {
				require.ErrorIs(t, err, ErrDecodeAddress, "an undecodable address surfaces ErrDecodeAddress")
				assert.Nil(t, result, "no Result accompanies a processing error")
				return
			}
			// If it decoded, it must not have matched the unrelated key, and the
			// verdict must be a clean false rather than a spurious success.
			require.NotNil(t, result.Address)
			assert.False(t, result.Address.Matched, "a hostile address must not match the signing key")
		})
	}
}

// TestVerifyScriptCredentialWindowEqualsKeyHash is the security boundary: a
// type-15 reward-SCRIPT address whose 28-byte window is byte-for-byte the signing
// key's hash must still report MatchedVia=None, since a script credential can
// never be satisfied by a key. This mirrors a fuzz seed as a pinned assertion.
func TestVerifyScriptCredentialWindowEqualsKeyHash(t *testing.T) {
	sig, err := Parse(DataSignature{Signature: sigStakePlain, Key: keyStake})
	require.NoError(t, err)

	// 0xf1 = type 15 (reward script) / mainnet; payload = the signing key's hash.
	raw := append([]byte{0xf1}, sig.KeyHash()...)
	result, err := Verify(
		DataSignature{Signature: sigStakePlain, Key: keyStake},
		WithAddress(hex.EncodeToString(raw)),
	)
	require.NoError(t, err, "a type-15 address decodes; the match simply fails")
	require.NotNil(t, result.Address)
	assert.False(t, result.Address.Matched, "a script credential can never equal a key hash")
	assert.Equal(t, CredentialNone, result.Address.MatchedVia)
	assert.Equal(t, AddressReward, result.Address.Type)
}
