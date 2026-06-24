package cip30

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/blake2b"

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
	// it.
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

	// PublicKey is the 32-byte Ed25519 public key from the COSE_Key.
	PublicKey ed25519.PublicKey

	// KeyHash is blake2b-224(PublicKey): the 28-byte credential used to match a
	// Cardano address or persist as a stable identity.
	KeyHash []byte
}

// verifyConfig holds the options applied to a Verify call.
//
// It is intentionally empty in this phase; message and address checking are
// added later. The plumbing exists now so the public Verify signature stays
// stable as options arrive.
type verifyConfig struct{}

// VerifyOption configures a Verify call. Options are applied in order.
type VerifyOption func(*verifyConfig)

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
	if len(s.PublicKey) != ed25519.PublicKeySize || len(s.signature) != ed25519.SignatureSize {
		return false
	}

	sigStructure, err := cose.SigStructure(s.protectedRaw, s.Payload)
	if err != nil {
		return false
	}
	return ed25519.Verify(s.PublicKey, sigStructure, s.signature)
}

// KeyHash returns blake2b-224(PublicKey): the 28-byte credential to compare
// against a Cardano address or persist as a stable identity.
func (s *Signature) KeyHash() []byte {
	return keyHash(s.PublicKey)
}

// Verify checks the Ed25519 signature of a DataSignature and returns a Result
// describing the outcome.
//
// A non-nil error means the input could not be processed (bad hex or CBOR, wrong
// key/signature length, unsupported algorithm/key type/curve), which is distinct
// from a signature that ran and was found invalid — that is reported in the
// Result with SignatureValid set to false and a nil error.
func Verify(sig DataSignature, opts ...VerifyOption) (*Result, error) {
	signature, err := Parse(sig)
	if err != nil {
		return nil, err
	}

	var cfg verifyConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Result{
		SignatureValid: signature.Verify(),
		PublicKey:      signature.PublicKey,
		KeyHash:        signature.KeyHash(),
	}, nil
}

// Valid reports the overall verdict. In this phase that is the signature result;
// later phases also require every requested check to pass.
func (r *Result) Valid() bool {
	return r.SignatureValid
}

// keyHash computes blake2b-224 of the public key. blake2b has no New224
// constructor, so the 28-byte size is requested explicitly.
func keyHash(publicKey ed25519.PublicKey) []byte {
	h, err := blake2b.New(keyHashSize, nil)
	if err != nil {
		// New only errors on an out-of-range size or a key argument; the constant
		// 28-byte size with a nil key cannot fail.
		panic(fmt.Sprintf("cip30: blake2b.New(%d): %v", keyHashSize, err))
	}
	h.Write(publicKey)
	return h.Sum(nil)
}
