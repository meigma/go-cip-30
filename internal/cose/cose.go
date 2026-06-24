// Package cose decodes the COSE structures used by a CIP-30 data signature and
// assembles the COSE Sig_structure that the Ed25519 signature is computed over.
//
// It is the single place in the module that depends on a CBOR codec
// (github.com/fxamacker/cbor/v2); the domain logic in package cip30 works only
// with the plain Go values this package returns. Per CIP-8 / RFC 8152, the
// protected header bytes are part of what is signed, so this package never
// re-encodes them: it returns the verbatim wire bytes and decodes a separate,
// read-only copy to read the header fields.
package cose

import (
	"errors"
	"fmt"
	"math"

	"github.com/fxamacker/cbor/v2"
)

// COSE algorithm, key-type, and curve values (RFC 8152, CIP-8/CIP-30).
const (
	algEdDSA     = -8 // alg(1) = EdDSA
	keyTypeOKP   = 1  // kty(1) = OKP
	curveEd25519 = 6  // crv(-1) = Ed25519
)

// COSE_Sign1 protected/unprotected header labels (CIP-8 extensions for the
// string-keyed labels).
const (
	labelAlg      = 1         // protected: algorithm identifier
	headerAddress = "address" // protected: raw Cardano address bytes (CIP-8 extension)
	headerHashed  = "hashed"  // unprotected: payload is a blake2b-224 digest (CIP-8 extension)
)

// sigContextSignature1 is the COSE context string for a single signer
// (COSE_Sign1), used as the first element of the Sig_structure.
const sigContextSignature1 = "Signature1"

// strictDecMode is the single CBOR decode policy used for every Unmarshal in
// this package. It rejects duplicate map keys (DupMapKeyEnforcedAPF): the
// default fxamacker mode accepts them silently and, worse, resolves them
// inconsistently between decode targets (a map[any]any keeps the LAST value
// while a keyasint struct keeps the FIRST). CIP-8 / RFC 8152 require COSE map
// keys to be unique, so a duplicate-key input is malformed; accepting it would
// let one verifier read different header fields (alg, "address", kty, x) than a
// stricter peer — an interpretation-ambiguity surface. Building the mode once
// keeps the decode policy in a single auditable place rather than relying on
// library defaults.
//
// Duplicate keys cannot change the signature verdict (that is computed over the
// verbatim protected-header bytes), so this is hardening, not a verdict fix.
//
//nolint:gochecknoglobals // an immutable decode policy built once and shared, the idiomatic fxamacker pattern
var strictDecMode = mustStrictDecMode()

// mustStrictDecMode builds the package decode mode. The options are constant, so
// construction cannot fail; a failure would be a programming error.
func mustStrictDecMode() cbor.DecMode {
	mode, err := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("cose: building strict CBOR decode mode: %v", err))
	}
	return mode
}

const (
	ed25519KeySize = 32 // raw Ed25519 public key length
	ed25519SigSize = 64 // Ed25519 signature length
	coseSign1Len   = 4  // COSE_Sign1 is a fixed 4-element array
)

// Errors returned when a COSE structure does not match the shape CIP-30
// requires. They are wrapped with %w so callers can match them with [errors.Is].
var (
	// ErrInvalidSign1 indicates the COSE_Sign1 CBOR was not a 4-element array.
	ErrInvalidSign1 = errors.New("cose: COSE_Sign1 is not a 4-element array")
	// ErrInvalidProtected indicates the protected header was not a decodable map.
	ErrInvalidProtected = errors.New("cose: invalid protected header")
	// ErrInvalidUnprotected indicates the unprotected header was not a decodable map.
	ErrInvalidUnprotected = errors.New("cose: invalid unprotected header")
	// ErrUnsupportedAlg indicates the protected header alg was not EdDSA.
	ErrUnsupportedAlg = errors.New("cose: unsupported algorithm (want EdDSA)")
	// ErrInvalidPayload indicates the payload element was not a byte string or null.
	ErrInvalidPayload = errors.New("cose: payload is not a byte string")
	// ErrInvalidSignature indicates the signature element was not a byte string.
	ErrInvalidSignature = errors.New("cose: signature is not a byte string")
	// ErrInvalidSignatureLen indicates the signature was not 64 bytes.
	ErrInvalidSignatureLen = errors.New("cose: signature is not 64 bytes")
	// ErrInvalidKey indicates the COSE_Key was not a decodable map.
	ErrInvalidKey = errors.New("cose: invalid COSE_Key")
	// ErrUnsupportedKeyType indicates the COSE_Key kty was not OKP.
	ErrUnsupportedKeyType = errors.New("cose: unsupported key type (want OKP)")
	// ErrUnsupportedCurve indicates the COSE_Key crv was not Ed25519.
	ErrUnsupportedCurve = errors.New("cose: unsupported curve (want Ed25519)")
	// ErrInvalidPublicKeyLen indicates the COSE_Key x value was not 32 bytes.
	ErrInvalidPublicKeyLen = errors.New("cose: public key is not 32 bytes")
)

// Sign1 is a decoded COSE_Sign1 data signature.
//
// ProtectedRaw holds the protected-header bytes exactly as received; they are
// the bytes signed over and must never be re-encoded. The remaining fields are
// read from a separate, read-only decode of those same bytes.
type Sign1 struct {
	// ProtectedRaw is the verbatim CBOR content of the protected header
	// (element[0] of the COSE_Sign1 array). It is reused as-is inside the
	// Sig_structure; re-marshalling it, even canonically, can break otherwise
	// valid signatures.
	ProtectedRaw []byte

	// Payload is the signed payload bytes, or nil when the COSE payload was CBOR
	// null (0xf6) or an empty byte string (0x40). A detached payload is the
	// caller's signal to reconstruct the signed bytes from an expected message.
	Payload []byte

	// Signature is the 64-byte Ed25519 signature (element[3]).
	Signature []byte

	// Alg is the algorithm identifier from the protected header. Decoding
	// requires it to be EdDSA(-8).
	Alg int64

	// Address is the raw, self-asserted Cardano address from the protected
	// "address" header, or nil when absent. It is signed but attacker-chosen, so
	// it must not be treated as a verified identity.
	Address []byte

	// Hashed reports the unprotected "hashed" flag: the payload is a
	// blake2b-224 digest of the message rather than the message itself. Defaults
	// to false when the header is absent.
	Hashed bool
}

// coseKey is the typed view of a COSE_Key map. Every label is an integer, so it
// decodes cleanly with keyasint tags (unlike the mixed-key protected header).
type coseKey struct {
	Kty int64  `cbor:"1,keyasint"`
	Alg int64  `cbor:"3,keyasint"`
	Crv int64  `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
}

// DecodeSign1 decodes a CBOR-encoded COSE_Sign1 data signature.
//
// It returns a typed error (matchable with [errors.Is]) when the structure is
// not a 4-element array, the protected header is undecodable, the algorithm is
// not EdDSA, or the signature is not 64 bytes. The protected header bytes are
// preserved verbatim in Sign1.ProtectedRaw.
func DecodeSign1(data []byte) (*Sign1, error) {
	var elements []cbor.RawMessage
	if err := strictDecMode.Unmarshal(data, &elements); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSign1, err)
	}
	if len(elements) != coseSign1Len {
		return nil, fmt.Errorf("%w: got %d elements", ErrInvalidSign1, len(elements))
	}

	// element[0]: the protected header, a CBOR byte string whose CONTENT is
	// itself a CBOR map. Unmarshalling into []byte yields that content verbatim.
	var protectedRaw []byte
	if err := strictDecMode.Unmarshal(elements[0], &protectedRaw); err != nil {
		return nil, fmt.Errorf("%w: protected header is not a byte string: %w", ErrInvalidProtected, err)
	}

	alg, address, err := decodeProtected(protectedRaw)
	if err != nil {
		return nil, err
	}
	if alg != algEdDSA {
		return nil, fmt.Errorf("%w: got %d", ErrUnsupportedAlg, alg)
	}

	hashed, err := decodeHashed(elements[1])
	if err != nil {
		return nil, err
	}

	// element[2]: payload, either a byte string or CBOR null. A nil/empty result
	// signals a detached payload to the caller.
	var payload []byte
	if err := strictDecMode.Unmarshal(elements[2], &payload); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPayload, err)
	}

	var signature []byte
	if err := strictDecMode.Unmarshal(elements[3], &signature); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	if len(signature) != ed25519SigSize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidSignatureLen, len(signature))
	}

	return &Sign1{
		ProtectedRaw: protectedRaw,
		Payload:      payload,
		Signature:    signature,
		Alg:          alg,
		Address:      address,
		Hashed:       hashed,
	}, nil
}

// decodeProtected reads alg and the optional raw "address" from the protected
// header. The header has mixed key types (integer 1, text "address"), so it is
// decoded into map[any]any and the integer types are normalized when read.
func decodeProtected(raw []byte) (int64, []byte, error) {
	var header map[any]any
	if err := strictDecMode.Unmarshal(raw, &header); err != nil {
		return 0, nil, fmt.Errorf("%w: %w", ErrInvalidProtected, err)
	}

	alg, ok := asInt64(header[uint64(labelAlg)])
	if !ok {
		return 0, nil, fmt.Errorf("%w: missing or non-integer alg", ErrInvalidProtected)
	}

	var address []byte
	if v, present := header[headerAddress]; present {
		bytes, ok := v.([]byte)
		if !ok {
			return 0, nil, fmt.Errorf("%w: address is not a byte string", ErrInvalidProtected)
		}
		address = bytes
	}

	return alg, address, nil
}

// decodeHashed reads the unprotected "hashed" flag, defaulting to false when the
// map or the key is absent.
func decodeHashed(raw cbor.RawMessage) (bool, error) {
	var header map[any]any
	if err := strictDecMode.Unmarshal(raw, &header); err != nil {
		return false, fmt.Errorf("%w: %w", ErrInvalidUnprotected, err)
	}

	v, present := header[headerHashed]
	if !present {
		return false, nil
	}
	hashed, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%w: %q is not a bool", ErrInvalidUnprotected, headerHashed)
	}
	return hashed, nil
}

// DecodeKey decodes a CBOR-encoded COSE_Key and returns the raw 32-byte Ed25519
// public key.
//
// It validates kty=OKP(1), alg=EdDSA(-8), crv=Ed25519(6), and len(x)==32,
// returning a typed error (matchable with [errors.Is]) otherwise.
func DecodeKey(data []byte) ([]byte, error) {
	var key coseKey
	if err := strictDecMode.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	if key.Kty != keyTypeOKP {
		return nil, fmt.Errorf("%w: got %d", ErrUnsupportedKeyType, key.Kty)
	}
	if key.Alg != algEdDSA {
		return nil, fmt.Errorf("%w: got %d", ErrUnsupportedAlg, key.Alg)
	}
	if key.Crv != curveEd25519 {
		return nil, fmt.Errorf("%w: got %d", ErrUnsupportedCurve, key.Crv)
	}
	if len(key.X) != ed25519KeySize {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidPublicKeyLen, len(key.X))
	}
	return key.X, nil
}

// SigStructure assembles and CBOR-encodes the COSE Sig_structure that the
// Ed25519 signature is verified against.
//
// It builds ["Signature1", protectedRaw (bstr), external_aad (empty bstr),
// payload (bstr)] per CIP-8 / RFC 8152. external_aad is always the empty byte
// string for CIP-30, and a nil payload is normalized to an empty byte string so
// it encodes as 0x40 (empty bstr) rather than 0xf6 (CBOR null).
func SigStructure(protectedRaw, payload []byte) ([]byte, error) {
	if payload == nil {
		payload = []byte{}
	}
	structure := []any{
		sigContextSignature1,
		protectedRaw,
		[]byte{}, // external_aad: always empty for CIP-30
		payload,
	}
	encoded, err := cbor.Marshal(structure)
	if err != nil {
		return nil, fmt.Errorf("cose: marshalling Sig_structure: %w", err)
	}
	return encoded, nil
}

// asInt64 normalizes a CBOR-decoded integer to int64. When decoding into
// interface{}, fxamacker returns non-negative integers as uint64 and negative
// ones as int64, so both shapes must be handled. A uint64 above [math.MaxInt64]
// (only reachable from hostile input) is rejected rather than wrapped negative.
func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	default:
		return 0, false
	}
}
