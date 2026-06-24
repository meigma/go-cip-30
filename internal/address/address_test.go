package address

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encodeBech32 re-encodes raw address bytes under an arbitrary HRP, used to
// construct a deliberately network-inconsistent address for negative testing.
func encodeBech32(t *testing.T, hrp string, raw []byte) string {
	t.Helper()
	conv, err := bech32.ConvertBits(raw, 8, 5, true)
	require.NoError(t, err)
	encoded, err := bech32.Encode(hrp, conv)
	require.NoError(t, err)
	return encoded
}

// CIP-19 test vectors (CIP-0019 "Test Vectors" section) plus the golden-vector
// addresses from the cardano-verify-datasignature reference. Each bech32 string
// is paired with the structure Decode must extract.
const (
	// mainnetType0 is the CIP-19 type-00 base address: payment key + stake key.
	mainnetType0 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
	// mainnetType1 is the CIP-19 type-01 base address: payment SCRIPT + stake key.
	mainnetType1 = "addr1z8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gten0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs9yc0hh"
	// mainnetType6 is the CIP-19 type-06 enterprise address: payment key only.
	mainnetType6 = "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"
	// mainnetType7 is the CIP-19 type-07 enterprise address: payment SCRIPT only.
	mainnetType7 = "addr1w8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcyjy7wx"
	// mainnetType14 is the CIP-19 type-14 reward address: stake key.
	mainnetType14 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
	// mainnetType15 is the CIP-19 type-15 reward address: stake SCRIPT.
	mainnetType15 = "stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5"
	// testnetType0 is the CIP-19 type-00 base address on testnet.
	testnetType0 = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae"
	// testnetType14 is the CIP-19 type-14 reward address on testnet.
	testnetType14 = "stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn"
)

func mustHash(t *testing.T, h []byte) string {
	t.Helper()
	require.Len(t, h, hashSize, "a credential hash is 28 bytes")
	return hex.EncodeToString(h)
}

func TestDecode(t *testing.T) {
	tests := []struct {
		name           string
		addr           string
		wantType       Type
		wantNetwork    Network
		wantPayment    bool
		wantPaymentSc  bool
		wantStake      bool
		wantStakeSc    bool
		assertSpecific func(t *testing.T, a *Address)
	}{
		{
			name:        "extracts payment and stake credentials from a base address",
			addr:        mainnetType0,
			wantType:    TypeBasePaymentKeyStakeKey,
			wantNetwork: Mainnet,
			wantPayment: true,
			wantStake:   true,
			assertSpecific: func(t *testing.T, a *Address) {
				assert.False(t, a.Payment.IsScript, "type 0 payment is a key hash")
				assert.False(t, a.Stake.IsScript, "type 0 stake is a key hash")
				assert.NotEqual(t, mustHash(t, a.Payment.Hash), mustHash(t, a.Stake.Hash),
					"payment and stake parts are distinct slices")
			},
		},
		{
			name:          "marks the payment part of a script base address as a script",
			addr:          mainnetType1,
			wantType:      TypeBaseScriptStakeKey,
			wantNetwork:   Mainnet,
			wantPayment:   true,
			wantPaymentSc: true,
			wantStake:     true,
			wantStakeSc:   false,
		},
		{
			name:        "extracts only the payment credential from an enterprise address",
			addr:        mainnetType6,
			wantType:    TypeEnterpriseKey,
			wantNetwork: Mainnet,
			wantPayment: true,
			wantStake:   false,
			assertSpecific: func(t *testing.T, a *Address) {
				assert.Nil(t, a.Stake.Hash, "enterprise addresses carry no stake hash")
			},
		},
		{
			name:          "marks an enterprise script address payment as a script",
			addr:          mainnetType7,
			wantType:      TypeEnterpriseScript,
			wantNetwork:   Mainnet,
			wantPayment:   true,
			wantPaymentSc: true,
			wantStake:     false,
		},
		{
			name:        "extracts the stake credential from a reward address",
			addr:        mainnetType14,
			wantType:    TypeRewardKey,
			wantNetwork: Mainnet,
			wantPayment: false,
			wantStake:   true,
			assertSpecific: func(t *testing.T, a *Address) {
				assert.Nil(t, a.Payment.Hash, "reward addresses carry no payment hash")
				assert.False(t, a.Stake.IsScript, "type 14 stake is a key hash")
			},
		},
		{
			name:        "marks a reward script address stake as a script that cannot key-match",
			addr:        mainnetType15,
			wantType:    TypeRewardScript,
			wantNetwork: Mainnet,
			wantPayment: false,
			wantStake:   true,
			wantStakeSc: true,
		},
		{
			name:        "reads the testnet network nibble of a base address",
			addr:        testnetType0,
			wantType:    TypeBasePaymentKeyStakeKey,
			wantNetwork: Testnet,
			wantPayment: true,
			wantStake:   true,
		},
		{
			name:        "reads the testnet network nibble of a reward address",
			addr:        testnetType14,
			wantType:    TypeRewardKey,
			wantNetwork: Testnet,
			wantPayment: false,
			wantStake:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(tc.addr)
			require.NoError(t, err, "a valid CIP-19 address must decode")

			assert.Equal(t, tc.wantType, got.Type, "address type")
			assert.Equal(t, tc.wantNetwork, got.Network, "network nibble")

			if tc.wantPayment {
				require.NotNil(t, got.Payment.Hash, "payment credential present")
				assert.Len(t, got.Payment.Hash, hashSize)
				assert.Equal(t, tc.wantPaymentSc, got.Payment.IsScript, "payment script flag")
			} else {
				assert.Nil(t, got.Payment.Hash, "payment credential absent")
			}

			if tc.wantStake {
				require.NotNil(t, got.Stake.Hash, "stake credential present")
				assert.Len(t, got.Stake.Hash, hashSize)
				assert.Equal(t, tc.wantStakeSc, got.Stake.IsScript, "stake script flag")
			} else {
				assert.Nil(t, got.Stake.Hash, "stake credential absent")
			}

			if tc.assertSpecific != nil {
				tc.assertSpecific(t, got)
			}
		})
	}
}

// TestDecodeAcceptsHexInput confirms a raw address may be supplied as hex, not
// only bech32, and decodes to the same structure.
func TestDecodeAcceptsHexInput(t *testing.T) {
	bech32Decoded, err := Decode(mainnetType14)
	require.NoError(t, err)

	hexInput := hex.EncodeToString(bech32Decoded.Raw)
	hexDecoded, err := Decode(hexInput)
	require.NoError(t, err, "hex-encoded raw bytes must be accepted")

	assert.Equal(t, bech32Decoded.Type, hexDecoded.Type)
	assert.Equal(t, bech32Decoded.Network, hexDecoded.Network)
	assert.Equal(t, bech32Decoded.Stake.Hash, hexDecoded.Stake.Hash)
}

func TestDecodeRejects(t *testing.T) {
	// A valid type-0 base address payload (header + 56 bytes) reused for the
	// network-mismatch and truncation cases.
	validBaseRaw, err := Decode(mainnetType0)
	require.NoError(t, err)

	tests := []struct {
		name string
		addr string
		want error
	}{
		{
			name: "rejects empty input",
			addr: "",
			want: ErrEmpty,
		},
		{
			name: "rejects a string that is neither bech32 nor hex",
			addr: "definitely not an address!!",
			want: ErrInvalidBech32,
		},
		{
			name: "rejects a Byron address type",
			// Header 0x80 = type 8 (Byron), followed by arbitrary bytes.
			addr: "80" + hex.EncodeToString(make([]byte, 28)),
			want: ErrUnsupportedType,
		},
		{
			name: "rejects an unknown address type",
			// Header 0x90 = type 9, which CIP-19 does not define.
			addr: "90" + hex.EncodeToString(make([]byte, 28)),
			want: ErrUnsupportedType,
		},
		{
			name: "rejects a truncated base address",
			// Type-0 header but only a single payload byte: too short for raw[1:29].
			addr: "0000",
			want: ErrTooShort,
		},
		{
			name: "rejects a base address missing its delegation hash",
			// Type-0 header with exactly 28 payload bytes: enough for payment, short
			// for the delegation hash at raw[29:57].
			addr: "00" + hex.EncodeToString(make([]byte, 28)),
			want: ErrTooShort,
		},
		{
			name: "rejects an empty raw address",
			addr: "",
			want: ErrEmpty,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(tc.addr)
			require.ErrorIs(t, err, tc.want, "error must match the documented sentinel")
			assert.Nil(t, got, "no Address is returned on a decode error")
		})
	}

	t.Run("rejects an oversized base address without panicking", func(t *testing.T) {
		oversized := append([]byte{}, validBaseRaw.Raw...)
		oversized = append(oversized, make([]byte, 100)...)
		// Oversized input must not panic; it parses (extra bytes are ignored) and the
		// credentials are still the first 56 payload bytes.
		got, err := Parse(oversized)
		require.NoError(t, err, "extra trailing bytes are tolerated, not a panic")
		assert.Equal(t, validBaseRaw.Payment.Hash, got.Payment.Hash)
	})
}

// TestDecodeRejectsNetworkMismatch builds a bech32 string whose HRP claims a
// different network than the header nibble and asserts it is rejected rather
// than silently trusting the header.
func TestDecodeRejectsNetworkMismatch(t *testing.T) {
	// Re-encode the mainnet reward address payload under the testnet "stake_test"
	// HRP so the prefix (testnet) disagrees with the header nibble (mainnet).
	mainnetReward, err := Decode(mainnetType14)
	require.NoError(t, err)

	mismatched := encodeBech32(t, hrpTestnetStake, mainnetReward.Raw)
	got, err := Decode(mismatched)
	require.ErrorIs(t, err, ErrNetworkMismatch, "a prefix/header network mismatch must be rejected")
	assert.Nil(t, got)
}

// TestDecodeRejectsHRPTypeMismatch checks that a valid Cardano payload cannot
// be re-labeled with the wrong bech32 class or an arbitrary HRP before matching.
func TestDecodeRejectsHRPTypeMismatch(t *testing.T) {
	mainnetReward, err := Decode(mainnetType14)
	require.NoError(t, err)
	mainnetBase, err := Decode(mainnetType0)
	require.NoError(t, err)

	tests := []struct {
		name string
		hrp  string
		raw  []byte
		want error
	}{
		{
			name: "rejects reward payload under payment hrp",
			hrp:  hrpMainnetPayment,
			raw:  mainnetReward.Raw,
			want: ErrHRPMismatch,
		},
		{
			name: "rejects base payload under stake hrp",
			hrp:  hrpMainnetStake,
			raw:  mainnetBase.Raw,
			want: ErrHRPMismatch,
		},
		{
			name: "rejects unknown hrp",
			hrp:  "notcardano",
			raw:  mainnetReward.Raw,
			want: ErrInvalidBech32,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(encodeBech32(t, tc.hrp, tc.raw))
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, got)
		})
	}
}

// TestParseRejectsShortRaw checks the raw-bytes entry point (used for the
// embedded header address) bounds-checks before slicing.
func TestParseRejectsShortRaw(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want error
	}{
		{name: "rejects zero-length raw", raw: []byte{}, want: ErrTooShort},
		{name: "rejects a reward header with no payload", raw: []byte{0xe1}, want: ErrTooShort},
		{name: "rejects a Byron raw header", raw: append([]byte{0x80}, make([]byte, 28)...), want: ErrUnsupportedType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.raw)
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, got)
		})
	}
}
