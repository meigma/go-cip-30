package cip30

import (
	"crypto/subtle"
	"fmt"

	"github.com/meigma/go-cip-30/internal/address"
)

// Credential names which part of an address the signing key hash matched.
//
// This is the MatchedVia vocabulary reported in an [AddressCheck]. It is
// distinct from the per-part credential of package internal/address: this enum
// records the outcome of a match (which side won), while that struct holds a
// single address part's hash and script flag.
type Credential uint8

const (
	// CredentialNone means no key-hash credential of the address matched.
	CredentialNone Credential = iota
	// CredentialPayment means the key hash matched the address's payment key hash.
	CredentialPayment
	// CredentialStake means the key hash matched the delegation key hash of a
	// base address or the stake key hash of a reward address.
	CredentialStake
)

// String returns the credential name (None, Payment, or Stake).
func (c Credential) String() string {
	switch c {
	case CredentialNone:
		return "None"
	case CredentialPayment:
		return "Payment"
	case CredentialStake:
		return "Stake"
	default:
		return fmt.Sprintf("Credential(%d)", uint8(c))
	}
}

// AddressSource records where the checked address came from.
type AddressSource uint8

const (
	// AddressSupplied means the address came from WithAddress: one the caller
	// independently expects.
	AddressSupplied AddressSource = iota
	// AddressEmbedded means the address came from the COSE_Sign1 protected
	// "address" header — the address the signer itself claimed.
	AddressEmbedded
)

// String returns the source name (Supplied or Embedded).
func (s AddressSource) String() string {
	switch s {
	case AddressSupplied:
		return "Supplied"
	case AddressEmbedded:
		return "Embedded"
	default:
		return fmt.Sprintf("AddressSource(%d)", uint8(s))
	}
}

// AddressType is the CIP-19 address category the check ran against.
type AddressType uint8

const (
	// AddressBase is a base address (CIP-19 types 0-3): payment + delegation.
	AddressBase AddressType = iota
	// AddressPointer is a pointer address (types 4-5): payment + chain pointer.
	// Pointer addresses are rejected as unsupported during decoding (see
	// internal/address), so a successful check never reports this category; it is
	// retained for API stability and completeness of the CIP-19 vocabulary.
	AddressPointer
	// AddressEnterprise is an enterprise address (types 6-7): payment only.
	AddressEnterprise
	// AddressReward is a reward/stake address (types 14-15): a stake credential.
	AddressReward
)

// String returns the address type name.
func (t AddressType) String() string {
	switch t {
	case AddressBase:
		return "Base"
	case AddressPointer:
		return "Pointer"
	case AddressEnterprise:
		return "Enterprise"
	case AddressReward:
		return "Reward"
	default:
		return fmt.Sprintf("AddressType(%d)", uint8(t))
	}
}

// Network is the Cardano network the address belongs to.
type Network uint8

const (
	// Testnet is any Cardano test network (header network nibble 0).
	Testnet Network = iota
	// Mainnet is the Cardano mainnet (header network nibble 1).
	Mainnet
)

// String returns the network name (Mainnet or Testnet).
func (n Network) String() string {
	switch n {
	case Mainnet:
		return "Mainnet"
	case Testnet:
		return "Testnet"
	default:
		return fmt.Sprintf("Network(%d)", uint8(n))
	}
}

// MessageCheck reports the outcome of a WithMessage check.
type MessageCheck struct {
	// Matched reports whether the signed payload equals the expected message
	// (after the hashed/digest convention is applied). For a detached payload it
	// is the signature verdict, since the message itself reconstructs the signed
	// bytes.
	Matched bool

	// Hashed reports whether the payload was compared as a blake2b-224 digest of
	// the message rather than the raw message (the unprotected "hashed" flag).
	Hashed bool
}

// AddressCheck reports the outcome of a WithAddress or WithEmbeddedAddress check.
type AddressCheck struct {
	// Matched reports whether the key hash satisfied the address under the active
	// (default or strict) policy.
	Matched bool

	// MatchedVia records which credential the key hash matched, or
	// CredentialNone when nothing matched. It is reported even when Matched is
	// false (e.g. a stake-only match rejected under StrictAddress).
	MatchedVia Credential

	// Strict reports whether StrictAddress was in force: a base-address stake-only
	// match is a failure under strict mode.
	Strict bool

	// Source records whether the address was caller-supplied or taken from the
	// signer's embedded protected header.
	Source AddressSource

	// Type is the CIP-19 category of the checked address.
	Type AddressType

	// Network is the network the checked address belongs to.
	//
	// For a bech32 address the network nibble is cross-checked against the
	// human-readable prefix. For raw hex or an embedded protected-header address
	// there is no prefix to check against, so Network is taken verbatim from the
	// header nibble and is informational only — Matched does not depend on it, so
	// callers must not treat Network as a trust boundary for raw/embedded input.
	Network Network
}

// matchAddress compares a key hash against a decoded address under the active
// policy and reports how it matched.
//
// Per CIP-19 only key-hash credentials can equal a public key's hash; script
// credentials (odd payment types; the delegation part of base types 2/3; reward
// type 15) can never match and so leave MatchedVia at None. A base address's
// delegation (stake) key is accepted by default but rejected under strict mode,
// which demands control of the payment key. A reward address's only credential
// is its stake key, so a stake match always counts there.
func matchAddress(addr *address.Address, keyHash []byte, strict bool) *AddressCheck {
	// Source is left at its zero value here; every caller sets it explicitly to
	// AddressSupplied or AddressEmbedded after the match, since matchAddress does
	// not know where the address came from.
	check := &AddressCheck{
		Matched:    false,
		MatchedVia: CredentialNone,
		Strict:     strict,
		Type:       addressType(addr.Type),
		Network:    network(addr.Network),
	}

	switch {
	case credentialMatches(addr.Payment, keyHash):
		// Even Shelley payment types (0,2,4,6) carry a payment key hash.
		check.MatchedVia = CredentialPayment
		check.Matched = true
	case isReward(addr.Type) && credentialMatches(addr.Stake, keyHash):
		// A reward address's stake credential is its only key, so it always counts.
		check.MatchedVia = CredentialStake
		check.Matched = true
	case isBase(addr.Type) && credentialMatches(addr.Stake, keyHash):
		// Base-address delegation-key fallback: accepted by default, rejected when
		// strict, which requires proof of payment-key (funds) control.
		check.MatchedVia = CredentialStake
		check.Matched = !strict
	}

	return check
}

// credentialMatches reports whether a key-hash credential equals keyHash. A nil
// hash (absent part) or a script credential never matches; the byte comparison
// is constant-time defensively, though the hashes are not secret.
func credentialMatches(cred address.Credential, keyHash []byte) bool {
	if cred.Hash == nil || cred.IsScript {
		return false
	}
	return subtle.ConstantTimeCompare(cred.Hash, keyHash) == 1
}

// isBase reports whether a CIP-19 type carries a base-address delegation
// credential at raw[29:57] (types 0 and 1 have a StakeKeyHash).
func isBase(t address.Type) bool {
	return t == address.TypeBasePaymentKeyStakeKey || t == address.TypeBaseScriptStakeKey
}

// isReward reports whether a CIP-19 type is a reward (stake) address.
func isReward(t address.Type) bool {
	return t == address.TypeRewardKey || t == address.TypeRewardScript
}

// addressType maps a CIP-19 numeric type to the public AddressType category.
func addressType(t address.Type) AddressType {
	switch t {
	case address.TypeBasePaymentKeyStakeKey, address.TypeBaseScriptStakeKey,
		address.TypeBasePaymentKeyScript, address.TypeBaseScriptScript:
		return AddressBase
	case address.TypePointerKey, address.TypePointerScript:
		return AddressPointer
	case address.TypeEnterpriseKey, address.TypeEnterpriseScript:
		return AddressEnterprise
	case address.TypeRewardKey, address.TypeRewardScript:
		return AddressReward
	case address.TypeByron:
		// Byron never reaches here: address.Parse rejects it before a match runs.
		return AddressBase
	default:
		return AddressBase
	}
}

// network maps the internal address network to the public Network.
func network(n address.Network) Network {
	if n == address.Mainnet {
		return Mainnet
	}
	return Testnet
}
