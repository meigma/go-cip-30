package cip30

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Golden vectors ported from ref/cardano-verify-datasignature/index.test.ts.
// The keys and signatures are shared across several cases, so they are named
// once here and reused below.
const (
	// keyStake (b89526...) hashes to 18987c..., the DELEGATION/stake credential of
	// addrBasePayment and the stake credential of stakeReward / the embedded e1
	// reward address.
	keyStake = "a4010103272006215820b89526fd6bf4ba737c55ea90670d16a27f8de6cc1982349b3b676705a2f420c6"
	// keyPayment (472be3...) hashes to 97cab9..., the PAYMENT credential of
	// addrBasePayment.
	keyPayment = "a4010103272006215820472be3f30b51ead6d020e0d370774861e242ca23eaca2f4eff4ddb8eaa3abefd"
	// keyHashedStake (9be513...) hashes to c13582..., the stake credential of the
	// e0 reward address embedded in the hashed/null-payload vectors.
	keyHashedStake = "a40101032720062158209be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27"
	// keyEnterprise (755b01...) hashes to 7863b5..., the payment credential of
	// addrEnterprise.
	keyEnterprise = "a4010103272006215820755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9"

	// sigStakePlain is the primary vector: embedded plaintext payload "Augusta
	// Ada King, Countess of Lovelace", hashed=false, embedded e1 reward address.
	sigStakePlain = "84582aa201276761646472657373581de118987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281a166686173686564f458264175677573746120416461204b696e672c20436f756e74657373206f66204c6f76656c61636558401712458b19f606b322982f6290c78529a235b56c0f1cec4f24b12a8660b40cd37f4c5440a465754089c462ed4b0d613bffaee3d1833516569fda4852f42a4a0f"
	// sigHashedEmbedded carries an embedded blake2b-224 digest payload of "Hello
	// world", hashed=true.
	sigHashedEmbedded = "84582aa201276761646472657373581de0c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73fa166686173686564f5581c40843181253eb1ff2258ab39c3463ec0edf5e713b73c5482c0ca798f5840a4cdec07ba8c1184aa74d1c3516fc6602a35d2db847510cf98c102653c15c7664f136314f920150a081870aef77ed49780ca58873bd5d62e744b968a89435906"
	// sigPaymentHelloWorld is signed with the payment key over embedded "Hello
	// World", hashed=false, embedded base address (01...).
	sigPaymentHelloWorld = "845846a20127676164647265737358390197cab94302b6d471d54db7052335dbfcf980f8dfc924dd1777ee784a18987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281a166686173686564f44b48656c6c6f20576f726c645840b65cb33e107a692605a479811a8405e44eeac5217c6ef92b79c221c2309305ec2db927fb75a7d197602e1eb2e663dae227aa7c0510b6484f5591b2b4bd47b70d"
	// sigPaymentLowerHello is signed with the payment key over embedded "hello
	// world" (lowercase), embedded base address.
	sigPaymentLowerHello = "845846a20127676164647265737358390197cab94302b6d471d54db7052335dbfcf980f8dfc924dd1777ee784a18987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281a166686173686564f44b68656c6c6f20776f726c645840d1a116c02d6ea035928f85ae59b7181f2b1cc31e673e1d890a5f92d6d3def81d667664ac091b42bd746dcd60b1a735b6c0ecceaa6672434ecf719b380db87808"
	// sigNullPayload has a CBOR null payload (0xf6), hashed=false.
	sigNullPayload = "84582aa201276761646472657373581de0c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73fa166686173686564f4f658400a0dd23e867292a4c2eb692f63016e3f61294686f672065fcc377f665cff6b25c430619060b536073cfd2355ab6c6bcec9d7ecbfb588f7b0aa5967f1b8559300"
	// sigEnterprise is signed over embedded "Hello world" with an enterprise
	// address embedded in the header.
	sigEnterprise = "84582aa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8a166686173686564f44b48656c6c6f20776f726c645840fc58155f0cee05bc00e7299af1df1f159ac82a46a055786b259657934eff346eec81349d4678ceabc79f213c66a2bdbfd4ea5d9ebdc630bee5ac9cce75cfc001"

	// addrBasePayment is a mainnet base address (type 0). Its payment credential
	// is 97cab9... (keyPayment) and its delegation credential is 18987c...
	// (keyStake).
	addrBasePayment = "addr1qxtu4w2rq2mdguw4fkms2ge4m070nq8cmlyjfhghwlh8sjscnp7pvysxn4qgpg8ty3uzpjuc0l4gr0w74t7ag8uev2qseuyw6u"
	// stakeReward is a mainnet reward address (type 14) for the stake credential
	// 18987c... (keyStake).
	stakeReward = "stake1uyvfslqkzgrf6syq5r4jg7pqewv8l65phh024lw5r7vk9qgznhyty"
	// stakeTestWrong is an unrelated testnet reward address used as a mismatch.
	stakeTestWrong = "stake_test1uzmggtulkyt5df9rpmqvh9acuc4etr5vntehx65nq2uz2mg8293u0"
	// addrWrongBech32 is a DIFFERENT mainnet base address whose credentials match
	// neither keyPayment nor keyStake; used for the corrected mismatch test.
	addrWrongBech32 = "addr1qykeu08ymqftykmddg8fuc2d78huz8aa48afk00twn7ye65zq5rvkr89ftn4tvj39dk0xxzk6un9apujewr2lj2wppeqxsygwc"
	// addrEnterprise is a mainnet enterprise address (type 6) for keyEnterprise.
	addrEnterprise = "addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d"
)

// blake2b224Hex returns the lowercase hex blake2b-224 digest of s, matching the
// reference's blake2bHex(message, undefined, 28) used to pre-hash a message.
func blake2b224Hex(s string) string {
	return hex.EncodeToString(keyHash224([]byte(s)))
}

// goldenCase is a unified golden vector that may carry an expected message,
// an expected address, and strict/embedded flags, with the verdict the
// reference (or its corrected intent) requires.
type goldenCase struct {
	name      string
	key       string
	signature string

	// message, when non-nil, supplies WithMessage.
	message []byte

	// address, when non-empty, supplies WithAddress.
	address string
	// embedded requests WithEmbeddedAddress instead of WithAddress.
	embedded bool
	// strict requests StrictAddress.
	strict bool

	wantValid bool

	// assertSignatureValid, when true, asserts Result.SignatureValid equals
	// wantSignatureValid independently of the overall verdict (e.g. a valid
	// signature with a mismatched address).
	assertSignatureValid bool
	wantSignatureValid   bool

	// assertMessage / assertAddress run extra structured assertions when set.
	assertMessage func(t *testing.T, m *MessageCheck)
	assertAddress func(t *testing.T, a *AddressCheck)
}

func TestGoldenVectors(t *testing.T) {
	cases := []goldenCase{
		{
			name:      "signature only verifies the primary stake-key vector",
			key:       keyStake,
			signature: sigStakePlain,
			wantValid: true,
		},
		{
			name:      "raw message inside the signature matches the embedded payload",
			key:       keyStake,
			signature: sigStakePlain,
			message:   []byte("Augusta Ada King, Countess of Lovelace"),
			wantValid: true,
			assertMessage: func(t *testing.T, m *MessageCheck) {
				assert.True(t, m.Matched, "embedded plaintext payload matches the message")
				assert.False(t, m.Hashed, "primary vector is not hashed")
			},
		},
		{
			name:      "wrong message with stake address fails on the message",
			key:       keyStake,
			signature: sigStakePlain,
			message:   []byte("!Augusta Ada King, Countess of Lovelace!"),
			address:   stakeReward,
			wantValid: false,
			// The signature itself is valid; the message check is what fails.
			assertSignatureValid: true,
			wantSignatureValid:   true,
			assertMessage: func(t *testing.T, m *MessageCheck) {
				assert.False(t, m.Matched, "altered message must not match the payload")
			},
			assertAddress: func(t *testing.T, a *AddressCheck) {
				assert.True(t, a.Matched, "the stake address still matches the key")
				assert.Equal(t, CredentialStake, a.MatchedVia)
			},
		},
		{
			name:                 "wrong message alone fails on the message",
			key:                  keyStake,
			signature:            sigStakePlain,
			message:              []byte("!Augusta Ada King, Countess of Lovelace!"),
			wantValid:            false,
			assertSignatureValid: true,
			wantSignatureValid:   true,
			assertMessage: func(t *testing.T, m *MessageCheck) {
				assert.False(t, m.Matched, "altered message must not match")
			},
		},
		{
			name:                 "unrelated testnet reward address fails on the address",
			key:                  keyStake,
			signature:            sigStakePlain,
			address:              stakeTestWrong,
			wantValid:            false,
			assertSignatureValid: true,
			wantSignatureValid:   true,
			assertAddress: func(t *testing.T, a *AddressCheck) {
				assert.False(t, a.Matched, "the key hash is not this address's stake credential")
				assert.Equal(t, CredentialNone, a.MatchedVia)
				assert.Equal(t, AddressReward, a.Type)
				assert.Equal(t, Testnet, a.Network)
			},
		},
		{
			name:      "base address matches the stake key by default",
			key:       keyStake,
			signature: sigStakePlain,
			address:   addrBasePayment,
			wantValid: true,
			assertAddress: func(t *testing.T, a *AddressCheck) {
				assert.True(t, a.Matched, "default policy accepts the delegation key of a base address")
				assert.Equal(t, CredentialStake, a.MatchedVia, "the key is the base address's stake credential")
				assert.False(t, a.Strict)
				assert.Equal(t, AddressSupplied, a.Source)
				assert.Equal(t, AddressBase, a.Type)
				assert.Equal(t, Mainnet, a.Network)
			},
		},
		{
			name:                 "base address stake-only match is rejected under strict",
			key:                  keyStake,
			signature:            sigStakePlain,
			address:              addrBasePayment,
			strict:               true,
			wantValid:            false,
			assertSignatureValid: true,
			wantSignatureValid:   true,
			assertAddress: func(t *testing.T, a *AddressCheck) {
				assert.False(t, a.Matched, "strict mode demands the payment credential")
				assert.Equal(t, CredentialStake, a.MatchedVia, "MatchedVia still reports the stake match")
				assert.True(t, a.Strict)
			},
		},
		{
			name:      "base address matches the payment key under strict",
			key:       keyPayment,
			signature: sigPaymentHelloWorld,
			address:   addrBasePayment,
			strict:    true,
			wantValid: true,
			assertAddress: func(t *testing.T, a *AddressCheck) {
				assert.True(t, a.Matched, "the payment key satisfies even strict mode")
				assert.Equal(t, CredentialPayment, a.MatchedVia)
				assert.True(t, a.Strict)
			},
		},
		{
			name:      "base address matches the payment key by default",
			key:       keyPayment,
			signature: sigPaymentLowerHello,
			address:   addrBasePayment,
			wantValid: true,
			assertAddress: func(t *testing.T, a *AddressCheck) {
				assert.True(t, a.Matched)
				assert.Equal(t, CredentialPayment, a.MatchedVia)
			},
		},
		{
			// Reference test ~line 96 has a known bug: it passes the address in the
			// message positional slot, so it never actually checks the address. We
			// port the CORRECTED intent: verify the signature against a DIFFERENT
			// address via WithAddress and expect an address mismatch.
			name:                 "payment-key signature against a different address mismatches",
			key:                  keyPayment,
			signature:            sigPaymentHelloWorld,
			address:              addrWrongBech32,
			wantValid:            false,
			assertSignatureValid: true,
			wantSignatureValid:   true,
			assertAddress: func(t *testing.T, a *AddressCheck) {
				assert.False(t, a.Matched, "the key matches neither credential of the wrong address")
				assert.Equal(t, CredentialNone, a.MatchedVia)
			},
		},
		{
			name:      "null payload alone fails the signature",
			key:       keyHashedStake,
			signature: sigNullPayload,
			wantValid: false,
		},
		{
			name:      "detached plaintext message reconstructs the signed bytes",
			key:       keyHashedStake,
			signature: sigNullPayload,
			message:   []byte("Hello world"),
			wantValid: true,
			assertMessage: func(t *testing.T, m *MessageCheck) {
				assert.True(t, m.Matched, "the detached message is proven by the signature")
				assert.False(t, m.Hashed, "this vector is not hashed")
			},
		},
		{
			name:      "hashed flag with plaintext message verifies the digest payload",
			key:       keyHashedStake,
			signature: sigNullPayload,
			message:   []byte("Hello world"),
			wantValid: true,
			assertMessage: func(t *testing.T, m *MessageCheck) {
				assert.True(t, m.Matched)
			},
		},
		{
			name:      "hashed flag with pre-hashed hex message matches the embedded digest",
			key:       keyHashedStake,
			signature: sigHashedEmbedded,
			message:   []byte(blake2b224Hex("Hello world")),
			wantValid: true,
			assertMessage: func(t *testing.T, m *MessageCheck) {
				assert.True(t, m.Matched, "the hex digest matches the embedded payload")
				assert.True(t, m.Hashed, "the unprotected hashed flag is set")
			},
		},
		{
			name:      "enterprise address matches the payment key",
			key:       keyEnterprise,
			signature: sigEnterprise,
			message:   []byte("Hello world"),
			address:   addrEnterprise,
			wantValid: true,
			assertMessage: func(t *testing.T, m *MessageCheck) {
				assert.True(t, m.Matched)
			},
			assertAddress: func(t *testing.T, a *AddressCheck) {
				assert.True(t, a.Matched)
				assert.Equal(t, CredentialPayment, a.MatchedVia, "enterprise addresses match only the payment key")
				assert.Equal(t, AddressEnterprise, a.Type)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Verify(tc.dataSignature(), tc.options()...)
			require.NoError(t, err, "a well-formed vector must process without error")
			require.NotNil(t, result, "Verify returns a Result when there is no error")

			assert.Equal(t, tc.wantValid, result.Valid(), "overall verdict must match the reference intent")

			if tc.assertSignatureValid {
				assert.Equal(t, tc.wantSignatureValid, result.SignatureValid,
					"signature verdict must be independent of the failed check")
			}

			if tc.message != nil {
				require.NotNil(t, result.Message, "WithMessage must populate Result.Message")
			} else {
				assert.Nil(t, result.Message, "Result.Message is nil without WithMessage")
			}
			if tc.assertMessage != nil {
				tc.assertMessage(t, result.Message)
			}

			if tc.address != "" {
				require.NotNil(t, result.Address, "WithAddress must populate Result.Address")
				assert.Equal(t, AddressSupplied, result.Address.Source)
			} else {
				assert.Nil(t, result.Address, "Result.Address is nil without an address option")
			}
			if tc.assertAddress != nil {
				tc.assertAddress(t, result.Address)
			}
		})
	}
}

func (tc goldenCase) dataSignature() DataSignature {
	return DataSignature{Signature: tc.signature, Key: tc.key}
}

func (tc goldenCase) options() []VerifyOption {
	var opts []VerifyOption
	if tc.message != nil {
		opts = append(opts, WithMessage(tc.message))
	}
	if tc.address != "" {
		opts = append(opts, WithAddress(tc.address))
	}
	if tc.embedded {
		opts = append(opts, WithEmbeddedAddress())
	}
	if tc.strict {
		opts = append(opts, StrictAddress())
	}
	return opts
}
