package cip30

import (
	"testing"
)

// FuzzVerify drives the full public surface — Verify with both optional checks
// and Parse — against arbitrary inputs and asserts only that it never panics.
//
// Every field an attacker controls is fuzzed: the two hex strings of a
// DataSignature, the expected message, and the address. The library's contract
// is that hostile input yields a typed error or a false verdict, never a crash
// (DESIGN.md sections 7, 10): a panic on attacker input is a denial-of-service
// defect. The seed corpus below pairs the golden vectors with the malformed
// shapes the Phase-2 review enumerated so replaying the seeds under `go test`
// exercises them deterministically; `-fuzz` then explores beyond them.
func FuzzVerify(f *testing.F) {
	addSeeds(f)

	f.Fuzz(func(t *testing.T, sigHex, keyHex, message, addr string) {
		ds := DataSignature{Signature: sigHex, Key: keyHex}

		// The full one-shot surface: signature plus both optional checks. A
		// returned error or Result is fine; a panic is a test failure (the fuzz
		// engine reports any panic as a crasher).
		_, _ = Verify(ds, WithMessage([]byte(message)), WithAddress(addr))

		// The embedded-address and strict paths reach code WithAddress does not
		// (matchEmbeddedAddress, the strict branch), so fuzz them too.
		_, _ = Verify(ds, WithMessage([]byte(message)), WithEmbeddedAddress())
		_, _ = Verify(ds, WithEmbeddedAddress(), StrictAddress())

		// The lower-level entry point and the Signature methods, when parsing
		// succeeds, must also stay panic-free on hostile follow-on calls.
		if sig, err := Parse(ds); err == nil {
			_ = sig.Verify()
			_ = sig.VerifyMessage([]byte(message))
			_, _ = sig.MatchesAddress(addr)
			_, _ = sig.MatchesAddress(addr, StrictAddress())

			// Parsing must be deterministic: the key hash of a successfully parsed
			// signature does not depend on hidden state. A divergence would point to
			// aliasing of the input buffer, which is worth catching during fuzzing.
			if !bytesEqual(sig.KeyHash(), sig.KeyHash()) {
				t.Fatalf("KeyHash is not deterministic for a parsed signature")
			}
		}
	})
}

// addSeeds registers the fuzz seed corpus: the golden vectors first, then the
// hostile shapes. Each f.Add tuple is (sigHex, keyHex, message, addr).
func addSeeds(f *testing.F) {
	f.Helper()

	// A well-formed COSE_Key reused as the key half of malformed-signature seeds
	// so the signature side is the sole malformed input.
	const goodKey = "a4010103272006215820b89526fd6bf4ba737c55ea90670d16a27f8de6cc1982349b3b676705a2f420c6"

	// --- golden vectors: real, valid CIP-30 signatures ---
	goldenSeeds := []struct{ sig, key, msg, addr string }{
		{sigStakePlain, keyStake, "Augusta Ada King, Countess of Lovelace", stakeReward},
		{sigStakePlain, keyStake, "", addrBasePayment},
		{sigHashedEmbedded, keyHashedStake, blake2b224Hex("Hello world"), ""},
		{sigPaymentHelloWorld, keyPayment, "Hello World", addrBasePayment},
		{sigPaymentLowerHello, keyPayment, "hello world", addrBasePayment},
		{sigNullPayload, keyHashedStake, "Hello world", ""},
		{sigEnterprise, keyEnterprise, "Hello world", addrEnterprise},
	}
	for _, s := range goldenSeeds {
		f.Add(s.sig, s.key, s.msg, s.addr)
	}

	// --- malformed hex strings ---
	f.Add("", "", "", "")                  // all empty
	f.Add("zz", goodKey, "m", "")          // non-hex signature
	f.Add(sigStakePlain, "zz", "m", "")    // non-hex key
	f.Add("8", goodKey, "m", "")           // odd-length hex (one nibble)
	f.Add("abc", goodKey, "m", "")         // odd-length hex
	f.Add(goodKey, sigStakePlain, "m", "") // swapped key/sig: both valid hex, wrong shapes

	// --- truncated / over-arity COSE_Sign1 arrays (len 0,1,3,5) ---
	f.Add("80", goodKey, "m", "")           // [] empty array
	f.Add("81f6", goodKey, "m", "")         // [null] arity 1
	f.Add("83f6f6f6", goodKey, "m", "")     // [null,null,null] arity 3
	f.Add("85f6f6f6f6f6", goodKey, "m", "") // arity 5
	f.Add("84", goodKey, "m", "")           // header claims 4 elements, none follow

	// --- payload as the wrong CBOR major type, signature as wrong type ---
	// [bstr(protected{alg,addr}), {}, text"x", bstr64]: payload is text, not bstr.
	f.Add(
		"84582aa201276761646472657373581de118987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281a0617858400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		goodKey,
		"m",
		"",
	)

	// --- duplicate-key maps (protected header and COSE_Key) ---
	// [bstr(a2 01 27 01 26) {} bstr("p") bstr64]: the protected header has two alg
	// entries (labels 0x01 -> -8 and 0x01 -> -7), which strict decoding must reject
	// rather than resolve ambiguously.
	//   84              array(4)
	//   45 a201270126   bstr(5) holding {1:-8, 1:-7}
	//   a0              unprotected {}
	//   4170            bstr(1) "p"
	//   5840 <64 zeros> signature
	f.Add("8445a201270126a041705840"+zeros(128), goodKey, "m", "")
	f.Add(sigStakePlain, "a201010101", "m", "") // COSE_Key with a duplicate label {1:1,1:1}

	// --- 63 / 65-byte signatures (off-by-one Ed25519 length) ---
	f.Add(sign1WithSig(zeros(2*63)), goodKey, "m", "") // 63-byte sig
	f.Add(sign1WithSig(zeros(2*65)), goodKey, "m", "") // 65-byte sig

	// --- 31 / 33-byte COSE_Key x ---
	f.Add(sigStakePlain, keyWithX(zeros(2*31)), "m", "") // 31-byte x
	f.Add(sigStakePlain, keyWithX(zeros(2*33)), "m", "") // 33-byte x

	// --- hostile addresses ---
	addrSeeds := []string{
		"",                   // empty
		"00",                 // 1-byte raw (header only, too short)
		"abc",                // odd-length hex / not bech32
		"00" + zeros(2*1),    // header + 1 byte: too short for a credential
		zeros(2 * 200),       // 200-byte raw blob
		"80" + zeros(2*28),   // Byron header 0x80 (type 8)
		"90" + zeros(2*28),   // unknown type 9
		"f1" + zeros(2*28),   // type 15 reward script (script hash can't key-match)
		"20" + zeros(2*56),   // type 2 base: payment key + stake script
		"not-a-real-address", // neither bech32 nor hex
		// An addr_test-prefixed string with a bad bech32 checksum: it exercises the
		// bech32 decode + HRP path and must fail the checksum without panicking. (The
		// deterministic network-mismatch reject path — a valid bech32 whose HRP
		// disagrees with the header nibble — is pinned in robustness_test.go.)
		"addr_test1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8",
		// A valid bech32 with a mainnet "addr" HRP wrapping a testnet (nibble 0)
		// header byte: the genuine network-mismatch case, which must decode then
		// reject as ErrNetworkMismatch.
		addrNetworkMismatch,
	}
	for _, a := range addrSeeds {
		f.Add(sigStakePlain, keyStake, "Augusta Ada King, Countess of Lovelace", a)
	}

	// A type-15 script address whose 28-byte window equals a key hash must still
	// be MatchedVia=None; fuzz it against the matching key to exercise that guard.
	f.Add(sigStakePlain, keyStake, "", "f1"+stakeKeyHashHex)
	// A type-2 base whose stake (script) window equals the key hash: also None.
	f.Add(sigStakePlain, keyStake, "", "20"+zeros(2*28)+stakeKeyHashHex)
}

// stakeKeyHashHex is the hex of blake2b-224 of keyStake's public key (18987c...),
// reused to build script-address seeds whose hash window equals a real key hash.
const stakeKeyHashHex = "18987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281"
