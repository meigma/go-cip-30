package cip30

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureManifest is the committed testdata/fixtures/manifest.json produced by
// scripts/gen-fixtures.sh (moon run gen-fixtures). Reading it needs no external
// tool, so the functional suite runs unchanged in CI.
type fixtureManifest struct {
	// Mnemonic is the fixed throwaway test mnemonic the keys derive from. It is
	// recorded for provenance only and is not used by the tests.
	Mnemonic string    `json:"mnemonic"`
	Fixtures []fixture `json:"fixtures"`
}

// fixture is one real CIP-30 vector produced by cardano-signer.
//
// Its expected verdict is NOT computed by this library (that would be circular):
// it comes from the signing construction plus cardano-signer's own verify
// --cip30 oracle, recorded in DerivedFrom and Oracle. The test below is the
// system under test; this struct is the oracle's recorded answer.
type fixture struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	CoseSign1Hex string `json:"coseSign1Hex"`
	CoseKeyHex   string `json:"coseKeyHex"`

	// Message is the plaintext that was signed (provenance for positive cases).
	Message string `json:"message"`
	// MessageOverride, when set, is a deliberately different message the test
	// hands the library instead of Message — the wrong-message negative case.
	MessageOverride *string `json:"messageOverride"`

	// ExpectAddress, when non-nil, is the address the library should check with
	// WithAddress.
	ExpectAddress *string `json:"expectAddress"`

	// ExpectValid is the verdict Verify().Valid() must return.
	ExpectValid bool `json:"expectValid"`
	// Hashed records whether the signature used the hashed convention.
	Hashed bool `json:"hashed"`
	// Oracle is cardano-signer's independent verdict ("true"/"false").
	Oracle string `json:"oracle"`
	// DerivedFrom documents how ExpectValid was obtained without this library.
	DerivedFrom string `json:"derivedFrom"`
}

// dataSignature returns the DataSignature a caller would receive from a wallet.
func (f fixture) dataSignature() DataSignature {
	return DataSignature{Signature: f.CoseSign1Hex, Key: f.CoseKeyHex}
}

// checkMessage is the message the library is handed: the override for the
// wrong-message case, otherwise the originally-signed message.
func (f fixture) checkMessage() string {
	if f.MessageOverride != nil {
		return *f.MessageOverride
	}
	return f.Message
}

// options builds the Verify options for the fixture: always WithMessage, plus
// WithAddress when the fixture pins an address to check.
func (f fixture) options() []VerifyOption {
	opts := []VerifyOption{WithMessage([]byte(f.checkMessage()))}
	if f.ExpectAddress != nil {
		opts = append(opts, WithAddress(*f.ExpectAddress))
	}
	return opts
}

// loadFixtures reads the committed fixture manifest. It is a fatal test error if
// the manifest is missing or malformed, since the functional suite cannot run
// without it.
func loadFixtures(t *testing.T) fixtureManifest {
	t.Helper()

	path := filepath.Join("testdata", "fixtures", "manifest.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err, "the committed fixture manifest must be present (run moon run gen-fixtures)")

	var manifest fixtureManifest
	require.NoError(t, json.Unmarshal(data, &manifest), "fixture manifest must be valid JSON")
	require.NotEmpty(t, manifest.Fixtures, "fixture manifest must contain fixtures")
	return manifest
}

// fixtureByName returns the named fixture from the manifest, failing the test if
// it is absent. It keeps a dedicated single-fixture test from re-implementing the
// linear scan that TestFunctionalFixtures already iterates over.
func fixtureByName(t *testing.T, manifest fixtureManifest, name string) fixture {
	t.Helper()
	for _, f := range manifest.Fixtures {
		if f.Name == name {
			return f
		}
	}
	require.FailNowf(t, "fixture not found", "the %q fixture must be present in the manifest", name)
	return fixture{}
}

// TestFunctionalFixtures runs Verify over every committed cardano-signer fixture
// and asserts the expected verdict. The fixtures are real CIP-30 signatures whose
// verdicts were derived independently of this library (signing construction +
// cardano-signer verify --cip30), so agreement here is genuine cross-validation.
func TestFunctionalFixtures(t *testing.T) {
	manifest := loadFixtures(t)

	for _, f := range manifest.Fixtures {
		t.Run(f.Name, func(t *testing.T) {
			result, err := Verify(f.dataSignature(), f.options()...)
			require.NoError(t, err, "a real cardano-signer fixture must process without error")
			require.NotNil(t, result, "Verify returns a Result when there is no error")

			assert.Equal(t, f.ExpectValid, result.Valid(),
				"our verdict must match the independently-derived expectation (%s)", f.DerivedFrom)

			// The message check is always requested, so it is always populated.
			require.NotNil(t, result.Message, "WithMessage must populate Result.Message")
			assert.Equal(t, f.Hashed, result.Message.Hashed,
				"the hashed flag must reflect the fixture's signing convention")

			if f.ExpectAddress != nil {
				require.NotNil(t, result.Address, "WithAddress must populate Result.Address")
				assert.Equal(t, AddressSupplied, result.Address.Source)
				if f.ExpectValid {
					// Every positive address fixture signs over the key's own address,
					// so the match is genuine: an enterprise/base address via the
					// payment credential, a reward address via the stake credential.
					assert.True(t, result.Address.Matched, "a positive fixture's address must match the key")
					switch result.Address.Type {
					case AddressReward:
						assert.Equal(t, CredentialStake, result.Address.MatchedVia,
							"a reward address matches via its stake credential")
					case AddressEnterprise:
						assert.Equal(t, CredentialPayment, result.Address.MatchedVia,
							"an enterprise address matches via its payment credential")
					case AddressBase, AddressPointer:
						// The current fixture matrix has no base/pointer positive case
						// (base coverage lives in the committed golden vectors); accept
						// any non-None credential here without pinning which one.
						assert.NotEqual(t, CredentialNone, result.Address.MatchedVia)
					}
				}
			} else {
				assert.Nil(t, result.Address, "Result.Address is nil without WithAddress")
			}
		})
	}
}

// TestFunctionalDetachedHashed pins the section-7 correctness case explicitly:
// a DETACHED + HASHED signature must verify true through our reconstruction of
// the raw 28-byte blake2b-224(message). The reference verifier instead hashes the
// UTF-8 bytes of the hex digest (an apparent, untested bug); this fixture, signed
// and oracle-confirmed by cardano-signer, proves our divergence is the correct
// behavior.
func TestFunctionalDetachedHashed(t *testing.T) {
	manifest := loadFixtures(t)

	f := fixtureByName(t, manifest, "detached_hashed")
	require.True(t, f.Hashed, "the fixture must use the hashed convention")
	require.Equal(t, "true", f.Oracle, "cardano-signer must independently verify this fixture")

	// Reconstruct through WithMessage: the detached payload is rebuilt from the
	// message as the raw blake2b-224 digest, and the signature proves it.
	result, err := Verify(f.dataSignature(), WithMessage([]byte(f.Message)))
	require.NoError(t, err)
	assert.True(t, result.SignatureValid,
		"the detached+hashed signature must verify through our correct-path reconstruction")
	assert.True(t, result.Valid())
	require.NotNil(t, result.Message)
	assert.True(t, result.Message.Matched, "the reconstructed digest matches the signed bytes")
	assert.True(t, result.Message.Hashed)

	// A wrong message must reconstruct different bytes and fail, confirming the
	// match is the message's, not an accident of the detached path.
	wrong, err := Verify(f.dataSignature(), WithMessage([]byte("a different message")))
	require.NoError(t, err)
	assert.False(t, wrong.Valid(), "a wrong message must not verify against the detached+hashed signature")
}
