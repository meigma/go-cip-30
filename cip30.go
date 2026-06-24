package cip30

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/blake2b"

	"github.com/meigma/go-cip-30/internal/address"
	"github.com/meigma/go-cip-30/internal/cose"
)

// keyHashSize is the length in bytes of a blake2b-224 key-hash credential
// (CIP-19): 224 bits / 8 = 28 bytes.
const keyHashSize = 28

// DataSignature is the result of a CIP-30 signData() call. Both fields are
// hex-encoded CBOR, exactly as a wallet returns them.
type DataSignature struct {
	// Signature is hex(cbor<COSE_Sign1>): the signed structure and signature.
	Signature string
	// Key is hex(cbor<COSE_Key>): the signer's Ed25519 public key.
	Key string
}

// Signature is a decoded, not-yet-verified CIP-30 data signature.
//
// Decoding proves nothing about authenticity; call Verify to check the
// signature. Address in particular is self-asserted by the signer.
type Signature struct {
	// PublicKey is the 32-byte Ed25519 public key from the COSE_Key x(-2) value.
	PublicKey ed25519.PublicKey

	// Payload is the embedded signed payload, or nil when the signature is
	// detached (the COSE payload was CBOR null or an empty byte string).
	Payload []byte

	// Hashed reports whether the payload is a blake2b-224 digest of the message
	// rather than the raw message (the unprotected "hashed" flag).
	Hashed bool

	// Address is the raw, self-asserted address from the COSE_Sign1 protected
	// header. It is signed but attacker-chosen, so it must not be treated as a
	// verified identity; bind the key to an address independently before trusting
	// it. Note this differs from Result.Address, which is a verified *AddressCheck
	// outcome rather than raw bytes.
	Address []byte

	// protectedRaw holds the protected-header bytes exactly as received. They are
	// reused verbatim in the Sig_structure and never re-encoded.
	protectedRaw []byte

	// signature is the 64-byte Ed25519 signature.
	signature []byte
}

// Result reports what Verify checked.
//
// Use Valid for the overall verdict. PublicKey and KeyHash identify the signer
// regardless of the signature outcome.
type Result struct {
	// SignatureValid reports whether the Ed25519 signature verified against the
	// reconstructed Sig_structure.
	SignatureValid bool

	// Message reports the message check, or nil when WithMessage was not supplied.
	Message *MessageCheck

	// Address reports the address check, or nil when neither WithAddress nor
	// WithEmbeddedAddress was supplied. Note this differs from Signature.Address,
	// which is raw self-asserted bytes rather than a verified outcome.
	Address *AddressCheck

	// PublicKey is the 32-byte Ed25519 public key from the COSE_Key.
	PublicKey ed25519.PublicKey

	// KeyHash is blake2b-224(PublicKey): the 28-byte credential used to match a
	// Cardano address or persist as a stable identity.
	KeyHash []byte
}

// verifyConfig holds the options applied to a Verify call.
type verifyConfig struct {
	// message is the expected plaintext to check the payload against.
	message []byte
	// hasMessage records that WithMessage was supplied (distinct from an empty
	// message, which is a valid value to check).
	hasMessage bool

	// address is the caller-supplied bech32 or hex address to match.
	address string
	// hasAddress records that WithAddress was supplied.
	hasAddress bool

	// useEmbedded records that WithEmbeddedAddress was supplied: check the
	// address from the signer's protected header instead of a supplied one.
	useEmbedded bool

	// strict records that StrictAddress was supplied: a base-address stake-only
	// match becomes a failure.
	strict bool
}

// VerifyOption configures a Verify call. Options are applied in order.
type VerifyOption func(*verifyConfig)

// WithMessage checks the signed payload against the expected message.
//
// Following the reference verifier: when the COSE_Sign1 sets unprotected
// "hashed": true, the message is hashed with blake2b-224 before comparison
// UNLESS it is already an all-hex string, which is treated as a pre-computed
// digest (an is-hex guard). When the COSE_Sign1 carries no embedded payload
// (detached), the message reconstructs the signed bytes so the signature check
// still runs — the message is then proven by the signature itself.
func WithMessage(message []byte) VerifyOption {
	return func(c *verifyConfig) {
		c.message = message
		c.hasMessage = true
	}
}

// WithAddress checks that the signing key hash matches a key-hash credential of
// the given address.
//
// Per CIP-30 the address may be bech32 (addr/stake, mainnet or _test) OR
// hex-encoded raw bytes; both are accepted. The default policy mirrors the
// reference verifier: for a base address EITHER the payment OR the delegation
// (stake) credential is accepted, and AddressCheck.MatchedVia reports which.
// Reward addresses match only their stake key; enterprise addresses only their
// payment key. Mutually exclusive with WithEmbeddedAddress.
func WithAddress(addr string) VerifyOption {
	return func(c *verifyConfig) {
		c.address = addr
		c.hasAddress = true
	}
}

// WithEmbeddedAddress checks the key against the address embedded in the
// COSE_Sign1 protected header — the address the signer itself claimed — rather
// than a caller-supplied one.
//
// The credential logic and StrictAddress apply identically; the result carries
// Source=AddressEmbedded. Use this when the signature is the identity ("which
// address signed?"): it closes the impersonation vector of trusting
// Signature.Address unverified. Mutually exclusive with WithAddress.
//
// Security: like WithAddress, the DEFAULT policy still matches a base address via
// its delegation (stake) key (MatchedVia=Stake), which proves control of the
// delegation key only, NOT the address's funds. An attacker who controls key K
// can embed a "mangled" base address whose payment credential is a victim's and
// whose stake credential is K's hash, and the default match then reports
// Matched=true. Require StrictAddress (or inspect MatchedVia) to demand
// payment-key control. See the [Result] and [AddressCheck] notes on the
// mangled-address threat.
func WithEmbeddedAddress() VerifyOption {
	return func(c *verifyConfig) {
		c.useEmbedded = true
	}
}

// StrictAddress tightens WithAddress / WithEmbeddedAddress so a base address must
// match its PAYMENT credential.
//
// A stake-only match becomes a failure (Matched=false, MatchedVia=Stake,
// Strict=true), proving control of the address's funds rather than merely its
// delegation. It has no effect on enterprise or reward addresses, whose only
// key-hash credential is unambiguous.
func StrictAddress() VerifyOption {
	return func(c *verifyConfig) {
		c.strict = true
	}
}

// applyOptions builds a verifyConfig and rejects mutually exclusive choices.
//
// Configuring both WithAddress and WithEmbeddedAddress is caller misuse — there
// is no single address to check — so it is reported as unprocessable input
// rather than producing a misleading verdict.
func applyOptions(opts []VerifyOption) (verifyConfig, error) {
	var cfg verifyConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.hasAddress && cfg.useEmbedded {
		return verifyConfig{}, ErrConflictingAddress
	}
	return cfg, nil
}

// Parse decodes a DataSignature into its COSE components without verifying it.
//
// It hex-decodes both fields and decodes the COSE_Sign1 and COSE_Key
// structures. A non-nil error means the input could not be processed (bad hex or
// CBOR, wrong key/signature length, unsupported algorithm/key type/curve);
// callers should not inspect the returned Signature in that case.
func Parse(sig DataSignature) (*Signature, error) {
	sigBytes, err := hex.DecodeString(sig.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignatureHex, err)
	}
	keyBytes, err := hex.DecodeString(sig.Key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKeyHex, err)
	}

	sign1, err := cose.DecodeSign1(sigBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeSignature, err)
	}
	publicKey, err := cose.DecodeKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeKey, err)
	}

	return &Signature{
		PublicKey:    ed25519.PublicKey(publicKey),
		Payload:      sign1.Payload,
		Hashed:       sign1.Hashed,
		Address:      sign1.Address,
		protectedRaw: sign1.ProtectedRaw,
		signature:    sign1.Signature,
	}, nil
}

// Verify reports whether the Ed25519 signature is valid.
//
// It reconstructs the COSE Sig_structure from the verbatim protected-header
// bytes and the embedded payload (an empty byte string when the payload is
// detached) and checks it with the public key. It returns false rather than
// panicking on a malformed key or signature length.
func (s *Signature) Verify() bool {
	return s.verifyPayload(s.Payload)
}

// verifyPayload checks the signature against an explicitly chosen payload.
//
// For an embedded payload this is Signature.Payload; for a detached signature it
// is the bytes reconstructed from an expected message. The Phase-1 length guards
// are kept so hostile input cannot panic [ed25519.Verify].
func (s *Signature) verifyPayload(payload []byte) bool {
	if len(s.PublicKey) != ed25519.PublicKeySize || len(s.signature) != ed25519.SignatureSize {
		return false
	}

	sigStructure, err := cose.SigStructure(s.protectedRaw, payload)
	if err != nil {
		return false
	}
	return ed25519.Verify(s.PublicKey, sigStructure, s.signature)
}

// detached reports whether the signature has no embedded payload (the COSE
// payload was CBOR null or an empty byte string), so the signed bytes must be
// reconstructed from an expected message.
func (s *Signature) detached() bool {
	return len(s.Payload) == 0
}

// VerifyMessage checks the signed payload against an expected message and
// reports the outcome.
//
// When the signature is detached the message reconstructs the signed bytes and
// the result is the signature verdict (a wrong message yields wrong bytes and
// fails verification). Otherwise the embedded payload is compared against the
// expected message, honoring the hashed/digest convention (see WithMessage).
func (s *Signature) VerifyMessage(message []byte) *MessageCheck {
	if s.detached() {
		// The message IS the signed payload; the signature itself proves it. Use
		// the correct raw blake2b-224(message) (or hex-decoded digest) for the
		// hashed case. This deliberately diverges from the reference, which for a
		// detached+hashed payload hashes the UTF-8 bytes of the hex digest — an
		// apparent bug it has no test for. We follow the spec-correct path.
		payload := digest(message, s.Hashed)
		return &MessageCheck{Hashed: s.Hashed, Matched: s.verifyPayload(payload)}
	}
	return &MessageCheck{
		Hashed:  s.Hashed,
		Matched: bytesEqual(s.Payload, digest(message, s.Hashed)),
	}
}

// MatchesAddress checks the signing key hash against an address and reports how
// it matched.
//
// The address may be bech32 or hex-encoded raw bytes (see WithAddress). Only
// StrictAddress is meaningful among the options. It returns a typed error
// (matchable with [errors.Is], wrapping ErrDecodeAddress) when the address
// cannot be decoded — distinct from a check that ran and did not match.
func (s *Signature) MatchesAddress(addr string, opts ...VerifyOption) (*AddressCheck, error) {
	cfg, err := applyOptions(opts)
	if err != nil {
		return nil, err
	}

	decoded, err := address.Decode(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeAddress, err)
	}

	check := matchAddress(decoded, s.KeyHash(), cfg.strict)
	check.Source = AddressSupplied
	return check, nil
}

// KeyHash returns blake2b-224(PublicKey): the 28-byte credential to compare
// against a Cardano address or persist as a stable identity.
func (s *Signature) KeyHash() []byte {
	return keyHash224(s.PublicKey)
}

// matchEmbeddedAddress checks the key hash against the signer's embedded
// protected-header address. It returns ErrNoEmbeddedAddress when the header
// carried no address, and ErrDecodeAddress when those raw bytes do not parse.
func (s *Signature) matchEmbeddedAddress(strict bool) (*AddressCheck, error) {
	if len(s.Address) == 0 {
		return nil, ErrNoEmbeddedAddress
	}
	decoded, err := address.Parse(s.Address)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeAddress, err)
	}
	check := matchAddress(decoded, s.KeyHash(), strict)
	check.Source = AddressEmbedded
	return check, nil
}

// Verify checks the Ed25519 signature of a DataSignature and returns a Result
// describing the outcome.
//
// A non-nil error means the input could not be processed (bad hex or CBOR, wrong
// key/signature length, unsupported algorithm/key type/curve), which is distinct
// from a signature that ran and was found invalid — that is reported in the
// Result with SignatureValid set to false and a nil error.
func Verify(sig DataSignature, opts ...VerifyOption) (*Result, error) {
	cfg, err := applyOptions(opts)
	if err != nil {
		return nil, err
	}

	signature, err := Parse(sig)
	if err != nil {
		return nil, err
	}

	result := &Result{
		SignatureValid: signature.signatureValid(cfg),
		Message:        nil,
		Address:        nil,
		PublicKey:      signature.PublicKey,
		KeyHash:        signature.KeyHash(),
	}

	if cfg.hasMessage {
		result.Message = signature.VerifyMessage(cfg.message)
		// A detached message reconstructs the signed bytes, so its match verdict
		// already equals SignatureValid computed above; nothing more to reconcile.
	}

	if cfg.hasAddress || cfg.useEmbedded {
		check, err := signature.addressCheck(cfg)
		if err != nil {
			return nil, err
		}
		result.Address = check
	}

	return result, nil
}

// signatureValid runs the Ed25519 check, reconstructing the payload from the
// expected message when the signature is detached so the verdict reflects the
// message that was actually supplied.
func (s *Signature) signatureValid(cfg verifyConfig) bool {
	if cfg.hasMessage && s.detached() {
		return s.verifyPayload(digest(cfg.message, s.Hashed))
	}
	return s.Verify()
}

// addressCheck runs the configured address check (supplied or embedded).
//
// It bypasses the public MatchesAddress option round-trip: Verify already holds a
// fully-applied verifyConfig, so the strict flag is passed straight through to
// matchAddress rather than re-entering applyOptions.
func (s *Signature) addressCheck(cfg verifyConfig) (*AddressCheck, error) {
	if cfg.useEmbedded {
		return s.matchEmbeddedAddress(cfg.strict)
	}

	decoded, err := address.Decode(cfg.address)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeAddress, err)
	}
	check := matchAddress(decoded, s.KeyHash(), cfg.strict)
	check.Source = AddressSupplied
	return check, nil
}

// Valid is the overall verdict: the signature verified AND every requested check
// passed. A nil sub-check means that check was not requested and so does not gate
// the result.
func (r *Result) Valid() bool {
	if !r.SignatureValid {
		return false
	}
	if r.Message != nil && !r.Message.Matched {
		return false
	}
	if r.Address != nil && !r.Address.Matched {
		return false
	}
	return true
}

// keyHash224 computes blake2b-224 of the given bytes. blake2b has no New224
// constructor, so the 28-byte size is requested explicitly. It is used both for
// the public-key credential and to hash a message under the "hashed" convention.
func keyHash224(data []byte) []byte {
	h, err := blake2b.New(keyHashSize, nil)
	if err != nil {
		// New only errors on an out-of-range size or a key argument; the constant
		// 28-byte size with a nil key cannot fail.
		panic(fmt.Sprintf("cip30: blake2b.New(%d): %v", keyHashSize, err))
	}
	h.Write(data)
	return h.Sum(nil)
}
