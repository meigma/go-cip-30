package cip30

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sign1NoEmbeddedAddress is a well-formed COSE_Sign1 whose protected header is
// {alg:-8} only — it carries no "address" field. The signature bytes are zero, so
// it never verifies; it exists only to exercise the embedded-address paths that
// depend on the header, not on signature validity.
const sign1NoEmbeddedAddress = "8443a10127a04770" +
	"61796c6f6164" + // payload "payload"
	"5840" + // 64-byte signature follows
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000"

// TestSign1NoEmbeddedAddressFixture pins the provenance of the
// sign1NoEmbeddedAddress fixture: it must parse cleanly yet carry no embedded
// protected-header address, which is what TestVerifyEmbeddedAddressMissing
// depends on. This keeps the hand-built CBOR honest if it is ever edited.
func TestSign1NoEmbeddedAddressFixture(t *testing.T) {
	sig, err := Parse(DataSignature{Signature: sign1NoEmbeddedAddress, Key: validKeyHex})
	require.NoError(t, err, "the no-address fixture must still be a well-formed COSE_Sign1")
	assert.Empty(t, sig.Address, "the fixture carries no embedded protected-header address")
}

// TestVerifyEmbeddedAddressMissing asserts the documented contract for
// WithEmbeddedAddress when the signer embedded no address: it is unprocessable
// input (ErrNoEmbeddedAddress), not a silent false verdict, since the caller
// explicitly asked to check an address that does not exist.
func TestVerifyEmbeddedAddressMissing(t *testing.T) {
	result, err := Verify(
		DataSignature{Signature: sign1NoEmbeddedAddress, Key: validKeyHex},
		WithEmbeddedAddress(),
	)
	require.ErrorIs(t, err, ErrNoEmbeddedAddress,
		"requesting an embedded address that is absent must surface ErrNoEmbeddedAddress")
	assert.Nil(t, result, "no Result is returned when the requested check cannot be processed")
}

// TestVerifyEmbeddedAddressUndecodable asserts that an embedded protected-header
// address whose raw bytes do not parse (here a Byron header) is reported as a
// processing error wrapping ErrDecodeAddress, never a panic or a false verdict.
func TestVerifyEmbeddedAddressUndecodable(t *testing.T) {
	// A COSE_Sign1 whose protected header is {alg:-8, "address": h'80...'}, where
	// the 0x80 header byte is a Byron (type 8) address the decoder rejects. The
	// signature is zero (irrelevant: the embedded-address decode fails first).
	//   84  array(4)
	//   582a <protected: a2 0127 67"address" 581d 80<28 zeros>>
	//   a0   unprotected {}
	//   47 7061796c6f6164  payload bstr(7) "payload"
	//   5840 <64 zero bytes>  signature
	sign1 := "84582aa201276761646472657373581d80" + zeros(2*28) +
		"a0477061796c6f6164" + "5840" + zeros(2*64)

	result, err := Verify(
		DataSignature{Signature: sign1, Key: validKeyHex},
		WithEmbeddedAddress(),
	)
	require.ErrorIs(t, err, ErrDecodeAddress,
		"an undecodable embedded address must surface ErrDecodeAddress")
	assert.Nil(t, result)
}
