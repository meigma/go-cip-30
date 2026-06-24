package cip30

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyWithEmbeddedAddress checks the signer's self-asserted protected
// header address against the key — the path the reference verifier has no
// coverage for. The primary vector embeds the e1 reward address, whose stake
// credential is the signing key's hash.
func TestVerifyWithEmbeddedAddress(t *testing.T) {
	result, err := Verify(
		DataSignature{Signature: sigStakePlain, Key: keyStake},
		WithEmbeddedAddress(),
	)
	require.NoError(t, err, "the embedded address must decode and process")
	require.NotNil(t, result.Address, "WithEmbeddedAddress populates Result.Address")

	assert.True(t, result.Valid(), "the key hash matches the embedded reward address")
	assert.True(t, result.Address.Matched)
	assert.Equal(t, CredentialStake, result.Address.MatchedVia, "the reward address matches via its stake key")
	assert.Equal(t, AddressEmbedded, result.Address.Source, "the address came from the protected header")
	assert.Equal(t, AddressReward, result.Address.Type)
	assert.Equal(t, Mainnet, result.Address.Network)
}

// TestVerifyWithEmbeddedAddressBase confirms the embedded base address path: the
// payment-key vector embeds a type-0 base address whose payment credential is the
// signing key, so it matches even under strict mode.
func TestVerifyWithEmbeddedAddressBase(t *testing.T) {
	result, err := Verify(
		DataSignature{Signature: sigPaymentHelloWorld, Key: keyPayment},
		WithEmbeddedAddress(),
		StrictAddress(),
	)
	require.NoError(t, err)
	require.NotNil(t, result.Address)

	assert.True(t, result.Valid(), "the embedded base address matches the payment key")
	assert.Equal(t, CredentialPayment, result.Address.MatchedVia)
	assert.Equal(t, AddressEmbedded, result.Address.Source)
	assert.True(t, result.Address.Strict)
}

// TestVerifyRejectsConflictingAddressOptions asserts that combining WithAddress
// and WithEmbeddedAddress is unprocessable input, not a silent precedence rule.
func TestVerifyRejectsConflictingAddressOptions(t *testing.T) {
	result, err := Verify(
		DataSignature{Signature: sigStakePlain, Key: keyStake},
		WithAddress(stakeReward),
		WithEmbeddedAddress(),
	)
	require.ErrorIs(t, err, ErrConflictingAddress, "mutually exclusive options must error")
	assert.Nil(t, result, "no Result is returned on caller misuse")
}

// TestVerifyRejectsUndecodableAddress asserts an address that cannot be decoded
// is a processing error from Verify, distinct from a check that ran and missed.
func TestVerifyRejectsUndecodableAddress(t *testing.T) {
	result, err := Verify(
		DataSignature{Signature: sigStakePlain, Key: keyStake},
		WithAddress("not-a-real-address"),
	)
	require.ErrorIs(t, err, ErrDecodeAddress, "an undecodable address must surface ErrDecodeAddress")
	assert.Nil(t, result, "no Result is returned when the address cannot be processed")
}

// TestMatchesAddressRejectsUndecodableAddress asserts the Signature method
// surfaces the same typed error as the one-shot Verify.
func TestMatchesAddressRejectsUndecodableAddress(t *testing.T) {
	sig, err := Parse(DataSignature{Signature: sigStakePlain, Key: keyStake})
	require.NoError(t, err)

	check, err := sig.MatchesAddress("not-a-real-address")
	require.ErrorIs(t, err, ErrDecodeAddress)
	assert.Nil(t, check)
}

// TestMatchesAddressStrict exercises the Signature method directly with the only
// option that is meaningful there, confirming strict mode flips a stake-only
// base match to a failure while still reporting MatchedVia.
func TestMatchesAddressStrict(t *testing.T) {
	sig, err := Parse(DataSignature{Signature: sigStakePlain, Key: keyStake})
	require.NoError(t, err)

	defaultCheck, err := sig.MatchesAddress(addrBasePayment)
	require.NoError(t, err)
	assert.True(t, defaultCheck.Matched, "default accepts the stake key of a base address")
	assert.Equal(t, CredentialStake, defaultCheck.MatchedVia)

	strictCheck, err := sig.MatchesAddress(addrBasePayment, StrictAddress())
	require.NoError(t, err)
	assert.False(t, strictCheck.Matched, "strict rejects a stake-only match")
	assert.Equal(t, CredentialStake, strictCheck.MatchedVia, "MatchedVia still records the stake match")
	assert.True(t, strictCheck.Strict)
}

// TestMatchesAddressAcceptsHexInput accepts a hex-encoded raw address (CIP-30
// allows either bech32 or hex) and matches it the same way as the bech32 form.
func TestMatchesAddressAcceptsHexInput(t *testing.T) {
	sig, err := Parse(DataSignature{Signature: sigStakePlain, Key: keyStake})
	require.NoError(t, err)

	// The raw bytes of the e1 reward address, hex-encoded.
	const rawHex = "e118987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281"
	check, err := sig.MatchesAddress(rawHex)
	require.NoError(t, err, "a hex raw address must be accepted")
	assert.True(t, check.Matched)
	assert.Equal(t, CredentialStake, check.MatchedVia)
	assert.Equal(t, AddressReward, check.Type)
}

// TestMatchesAddressScriptCredentialNeverMatches is the security check that a
// script-hash credential can never be satisfied by a key hash, even when the
// raw bytes of the script hash happen to equal the key hash. We synthesize a
// reward-script address (type 15) whose 28-byte payload IS the signing key's
// hash; it must still report MatchedVia=None.
func TestMatchesAddressScriptCredentialNeverMatches(t *testing.T) {
	sig, err := Parse(DataSignature{Signature: sigStakePlain, Key: keyStake})
	require.NoError(t, err)

	// Header 0xf1 = type 15 (reward script) / mainnet, payload = the key hash.
	raw := append([]byte{0xf1}, sig.KeyHash()...)
	check, err := sig.MatchesAddress(hex.EncodeToString(raw))
	require.NoError(t, err, "a type-15 address still decodes")
	assert.False(t, check.Matched, "a script credential can never equal a key hash")
	assert.Equal(t, CredentialNone, check.MatchedVia)
	assert.Equal(t, AddressReward, check.Type)
}

// TestMatchesAddressBaseScriptStakeNeverMatches confirms that the script
// delegation part of a base address (type 2) cannot be satisfied by a stake key.
func TestMatchesAddressBaseScriptStakeNeverMatches(t *testing.T) {
	sig, err := Parse(DataSignature{Signature: sigStakePlain, Key: keyStake})
	require.NoError(t, err)

	// Header 0x20 = type 2 (payment key + stake SCRIPT) / mainnet. Payment part is
	// 28 zero bytes; the delegation part is set to the signing key's hash, which is
	// a script credential here and so must not match.
	raw := []byte{0x20}
	raw = append(raw, make([]byte, 28)...)
	raw = append(raw, sig.KeyHash()...)

	check, err := sig.MatchesAddress(hex.EncodeToString(raw))
	require.NoError(t, err)
	assert.False(t, check.Matched, "the delegation part is a script hash, not a key")
	assert.Equal(t, CredentialNone, check.MatchedVia)
	assert.Equal(t, AddressBase, check.Type)
}
