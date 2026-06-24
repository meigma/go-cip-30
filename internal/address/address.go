// Package address decodes Cardano addresses per CIP-19 into their header,
// network, type, and payment/stake credentials.
//
// It is the single place in the module that depends on a bech32 codec
// (github.com/btcsuite/btcd/btcutil/bech32); the domain logic in package cip30
// works only with the plain Go values this package returns. The package is a
// pure CIP-19 decoder: it extracts credentials and validates structural
// invariants (length, network nibble, known type) but holds no matching
// policy — deciding whether a key hash satisfies an address (payment vs stake,
// strict mode) lives in the root cip30 package.
package address

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

// Network is the network nibble of an address header (the low four bits).
type Network uint8

const (
	// Testnet is network nibble 0: any Cardano test network.
	Testnet Network = 0
	// Mainnet is network nibble 1: the Cardano mainnet.
	Mainnet Network = 1
)

// Type is the address type, the high four bits of the header byte. Shelley
// addresses are types 0-7, reward (stake) addresses are 14-15, and Byron is 8.
type Type uint8

// Address types per CIP-19. The numeric value equals header>>4.
const (
	// TypeBasePaymentKeyStakeKey is type 0: payment key hash + stake key hash.
	TypeBasePaymentKeyStakeKey Type = 0
	// TypeBaseScriptStakeKey is type 1: payment script hash + stake key hash.
	TypeBaseScriptStakeKey Type = 1
	// TypeBasePaymentKeyScript is type 2: payment key hash + stake script hash.
	TypeBasePaymentKeyScript Type = 2
	// TypeBaseScriptScript is type 3: payment script hash + stake script hash.
	TypeBaseScriptScript Type = 3
	// TypePointerKey is type 4: payment key hash + chain pointer.
	TypePointerKey Type = 4
	// TypePointerScript is type 5: payment script hash + chain pointer.
	TypePointerScript Type = 5
	// TypeEnterpriseKey is type 6: payment key hash, no stake part.
	TypeEnterpriseKey Type = 6
	// TypeEnterpriseScript is type 7: payment script hash, no stake part.
	TypeEnterpriseScript Type = 7
	// TypeByron is type 8: a legacy Byron (bootstrap) address.
	TypeByron Type = 8
	// TypeRewardKey is type 14: a reward address holding a stake key hash.
	TypeRewardKey Type = 14
	// TypeRewardScript is type 15: a reward address holding a stake script hash.
	TypeRewardScript Type = 15
)

// Credential sizes and address offsets per CIP-19.
const (
	// hashSize is the length of a blake2b-224 credential hash in bytes.
	hashSize = 28
	// headerSize is the single header byte that precedes the payload.
	headerSize = 1
	// paymentLen is the minimum raw length to carry a payment/stake credential
	// at raw[1:29]: a header byte plus one 28-byte hash.
	paymentLen = headerSize + hashSize
	// baseLen is the minimum raw length for a base address carrying both a
	// payment hash at raw[1:29] and a delegation hash at raw[29:57].
	baseLen = headerSize + 2*hashSize
)

// Header-byte bit layout per CIP-19: the high nibble is the type, the low
// nibble the network tag.
const (
	// typeShift moves the high nibble (address type) down to the low bits.
	typeShift = 4
	// networkMask selects the low nibble (network tag).
	networkMask = 0x0f
)

// Bech32 conversion widths: Cardano addresses are stored as 5-bit groups that
// must be regrouped into 8-bit bytes.
const (
	bech32BitsFrom = 5
	bech32BitsTo   = 8
)

// Bech32 human-readable prefixes per CIP-5. Reward (stake) addresses use the
// "stake" prefix; all other Shelley addresses use "addr".
const (
	hrpMainnetPayment = "addr"
	hrpTestnetPayment = "addr_test"
	hrpMainnetStake   = "stake"
	hrpTestnetStake   = "stake_test"
)

// Errors returned when an address cannot be decoded. They are wrapped with %w so
// callers can match them with [errors.Is].
var (
	// ErrEmpty indicates the input string was empty.
	ErrEmpty = errors.New("address: empty input")
	// ErrInvalidBech32 indicates the input was not decodable bech32. Decode also
	// surfaces it (wrapping the bech32 error) for a string that is neither bech32
	// nor hex, since an address-shaped string is far likelier to be a mistyped
	// bech32 address than mistyped hex.
	ErrInvalidBech32 = errors.New("address: invalid bech32")
	// ErrTooShort indicates the raw address was shorter than its header requires.
	ErrTooShort = errors.New("address: raw address too short for its type")
	// ErrUnsupportedType indicates a Byron or otherwise unknown address type.
	ErrUnsupportedType = errors.New("address: unsupported address type")
	// ErrNetworkMismatch indicates the bech32 HRP disagreed with the header
	// network nibble (e.g. a "stake_test" prefix over a mainnet header byte).
	ErrNetworkMismatch = errors.New("address: bech32 prefix disagrees with header network")
)

// Credential is one part of an address — its payment or stake credential.
//
// A nil Hash means the part is absent for this address type (e.g. enterprise
// and pointer addresses have no inline stake credential). IsScript records
// whether the hash is a script hash, which can never equal a key hash and so
// can never be satisfied by a signing key.
type Credential struct {
	// Hash is the 28-byte blake2b-224 credential hash, or nil when the part is
	// absent for this address type.
	Hash []byte

	// IsScript reports whether the credential is a script hash rather than a key
	// hash. A script credential can never match a public key's hash.
	IsScript bool
}

// Address is a decoded CIP-19 address.
//
// It records the raw bytes, the parsed header fields, and the payment and stake
// credentials. It carries no matching policy; callers compare a key hash against
// Payment.Hash or Stake.Hash and apply their own rules.
type Address struct {
	// Raw is the decoded address bytes: the header byte followed by the payload.
	Raw []byte

	// Header is the first byte: the high nibble is Type, the low nibble Network.
	Header byte

	// Network is the network nibble (header & 0x0f).
	Network Network

	// Type is the address type (header >> 4).
	Type Type

	// Payment is the payment credential (raw[1:29]) for Shelley address types,
	// or an absent credential for reward addresses.
	Payment Credential

	// Stake is the stake/delegation credential: the delegation part of a base
	// address (raw[29:57]) or the stake credential of a reward address
	// (raw[1:29]). It is absent for enterprise and pointer addresses.
	Stake Credential
}

// Decode decodes an address supplied as either bech32 (addr/addr_test/stake/
// stake_test) or hex-encoded raw bytes.
//
// Bech32 is tried first; a non-bech32 string is then tried as hex. When the
// input is bech32, the human-readable prefix's network is checked against the
// header network nibble and a mismatch is rejected. It returns a typed error
// (matchable with [errors.Is]) for empty, undecodable, unsupported-type, or
// too-short input, never a panic.
func Decode(addr string) (*Address, error) {
	if addr == "" {
		return nil, ErrEmpty
	}

	hrp, raw, bech32Err := decodeBech32(addr)
	if bech32Err == nil {
		parsed, err := Parse(raw)
		if err != nil {
			return nil, err
		}
		if err := checkHRPNetwork(hrp, parsed.Network); err != nil {
			return nil, err
		}
		return parsed, nil
	}

	raw, hexErr := hex.DecodeString(addr)
	if hexErr != nil {
		// Neither encoding accepted the input. Surface the bech32 error, since an
		// address-shaped string is far likelier to be a mistyped bech32 address
		// than mistyped hex.
		return nil, fmt.Errorf("%w: %w", ErrInvalidBech32, bech32Err)
	}
	return Parse(raw)
}

// Parse decodes raw address bytes (header byte plus payload) into an Address.
//
// This is the entry point for the embedded protected-header "address", which is
// raw bytes rather than bech32. It bounds-checks every slice against the address
// type and returns a typed error (matchable with [errors.Is]) for unsupported
// types or truncated input — it never panics on hostile input.
//
// Only the credential window for the address type is interpreted; the length
// guards are minimums, so any trailing bytes beyond the credentials are ignored
// rather than rejected. This tolerates non-canonical padded input without
// affecting a match, which compares only the fixed 28-byte credential windows.
func Parse(raw []byte) (*Address, error) {
	if len(raw) < headerSize {
		return nil, fmt.Errorf("%w: empty raw address", ErrTooShort)
	}

	header := raw[0]
	addrType := Type(header >> typeShift)
	network := Network(header & networkMask)

	addr := &Address{
		Raw:     raw,
		Header:  header,
		Network: network,
		Type:    addrType,
		Payment: Credential{Hash: nil, IsScript: false},
		Stake:   Credential{Hash: nil, IsScript: false},
	}

	switch addrType {
	case TypeBasePaymentKeyStakeKey, TypeBaseScriptStakeKey,
		TypeBasePaymentKeyScript, TypeBaseScriptScript:
		if err := addr.fillBase(); err != nil {
			return nil, err
		}
	case TypePointerKey, TypePointerScript,
		TypeEnterpriseKey, TypeEnterpriseScript:
		if err := addr.fillPaymentOnly(); err != nil {
			return nil, err
		}
	case TypeRewardKey, TypeRewardScript:
		if err := addr.fillReward(); err != nil {
			return nil, err
		}
	case TypeByron:
		return nil, fmt.Errorf("%w: Byron (type 8)", ErrUnsupportedType)
	default:
		return nil, fmt.Errorf("%w: type %d", ErrUnsupportedType, addrType)
	}

	return addr, nil
}

// fillBase populates both credentials of a base address (types 0-3): payment at
// raw[1:29] and delegation at raw[29:57]. The payment script-ness follows the
// odd/even type rule; the delegation script-ness follows the type's high bit
// within the base group (types 2,3 carry a stake script).
func (a *Address) fillBase() error {
	if len(a.Raw) < baseLen {
		return fmt.Errorf("%w: base address has %d bytes, want >= %d", ErrTooShort, len(a.Raw), baseLen)
	}
	a.Payment = Credential{Hash: a.Raw[headerSize:paymentLen], IsScript: paymentIsScript(a.Type)}
	a.Stake = Credential{Hash: a.Raw[paymentLen:baseLen], IsScript: baseStakeIsScript(a.Type)}
	return nil
}

// fillPaymentOnly populates the payment credential of an enterprise or pointer
// address (types 4-7) at raw[1:29]. These types carry no inline stake key hash,
// so Stake is left absent.
func (a *Address) fillPaymentOnly() error {
	if len(a.Raw) < paymentLen {
		return fmt.Errorf("%w: address has %d bytes, want >= %d", ErrTooShort, len(a.Raw), paymentLen)
	}
	a.Payment = Credential{Hash: a.Raw[headerSize:paymentLen], IsScript: paymentIsScript(a.Type)}
	return nil
}

// fillReward populates the stake credential of a reward address (types 14-15) at
// raw[1:29]. A reward address has no payment part, so Payment is left absent.
func (a *Address) fillReward() error {
	if len(a.Raw) < paymentLen {
		return fmt.Errorf("%w: reward address has %d bytes, want >= %d", ErrTooShort, len(a.Raw), paymentLen)
	}
	a.Stake = Credential{Hash: a.Raw[headerSize:paymentLen], IsScript: a.Type == TypeRewardScript}
	return nil
}

// paymentIsScript reports whether the payment part of a Shelley type is a script
// hash. Per CIP-19 the odd payment types (1,3,5,7) use a ScriptHash.
func paymentIsScript(t Type) bool {
	return t%2 == 1
}

// baseStakeIsScript reports whether the delegation part of a base address is a
// script hash. Per CIP-19 base types 2 and 3 carry a stake ScriptHash; types 0
// and 1 carry a StakeKeyHash.
func baseStakeIsScript(t Type) bool {
	return t == TypeBasePaymentKeyScript || t == TypeBaseScriptScript
}

// decodeBech32 decodes a bech32 string into its HRP and 8-bit payload bytes.
//
// It uses DecodeNoLimit because Cardano addresses exceed BIP-173's 90-character
// cap, then converts the 5-bit groups back to 8-bit bytes.
func decodeBech32(addr string) (string, []byte, error) {
	hrp, data, err := bech32.DecodeNoLimit(addr)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrInvalidBech32, err)
	}
	raw, err := bech32.ConvertBits(data, bech32BitsFrom, bech32BitsTo, false)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrInvalidBech32, err)
	}
	return hrp, raw, nil
}

// checkHRPNetwork verifies the bech32 prefix's implied network matches the
// header nibble. The "stake"/"stake_test" prefixes are reward addresses and the
// "addr"/"addr_test" prefixes are payment addresses; "_test" means testnet.
//
// This guards against an address whose human-readable prefix claims one network
// while its header byte encodes another — an inconsistency we reject rather than
// silently trust the header over the prefix the user saw.
func checkHRPNetwork(hrp string, network Network) error {
	var want Network
	switch hrp {
	case hrpMainnetPayment, hrpMainnetStake:
		want = Mainnet
	case hrpTestnetPayment, hrpTestnetStake:
		want = Testnet
	default:
		// An unrecognized HRP is not a network we can cross-check; accept the
		// header's own nibble rather than guessing. Unknown HRPs that are not real
		// Cardano prefixes will still fail elsewhere (e.g. wrong payload length).
		return nil
	}
	if want != network {
		return fmt.Errorf("%w: prefix %q implies network %d, header says %d",
			ErrNetworkMismatch, hrp, want, network)
	}
	return nil
}
