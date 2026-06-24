package cip30_test

import (
	"fmt"

	cip30 "github.com/meigma/go-cip-30"
)

// ExampleVerify verifies a data signature together with the message it was
// expected to sign. The signature and key are exactly what a wallet's
// api.signData(address, payload) returns: hex-encoded CBOR.
func ExampleVerify() {
	ds := cip30.DataSignature{
		Signature: "84582aa201276761646472657373581de118987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281a166686173686564f458264175677573746120416461204b696e672c20436f756e74657373206f66204c6f76656c61636558401712458b19f606b322982f6290c78529a235b56c0f1cec4f24b12a8660b40cd37f4c5440a465754089c462ed4b0d613bffaee3d1833516569fda4852f42a4a0f",
		Key:       "a4010103272006215820b89526fd6bf4ba737c55ea90670d16a27f8de6cc1982349b3b676705a2f420c6",
	}

	result, err := cip30.Verify(ds, cip30.WithMessage([]byte("Augusta Ada King, Countess of Lovelace")))
	if err != nil {
		// Unprocessable input: bad hex/CBOR, wrong lengths, unsupported algorithm.
		fmt.Println(err)
		return
	}

	fmt.Println("valid:", result.Valid())
	fmt.Printf("key hash: %x\n", result.KeyHash)
	// Output:
	// valid: true
	// key hash: 18987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281
}

// ExampleVerify_withAddress binds the signing key to an address the caller
// expects, and requires control of the address's payment credential via
// StrictAddress.
func ExampleVerify_withAddress() {
	ds := cip30.DataSignature{
		Signature: "845846a20127676164647265737358390197cab94302b6d471d54db7052335dbfcf980f8dfc924dd1777ee784a18987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281a166686173686564f44b48656c6c6f20576f726c645840b65cb33e107a692605a479811a8405e44eeac5217c6ef92b79c221c2309305ec2db927fb75a7d197602e1eb2e663dae227aa7c0510b6484f5591b2b4bd47b70d",
		Key:       "a4010103272006215820472be3f30b51ead6d020e0d370774861e242ca23eaca2f4eff4ddb8eaa3abefd",
	}

	result, err := cip30.Verify(
		ds,
		cip30.WithMessage([]byte("Hello World")),
		cip30.WithAddress(
			"addr1qxtu4w2rq2mdguw4fkms2ge4m070nq8cmlyjfhghwlh8sjscnp7pvysxn4qgpg8ty3uzpjuc0l4gr0w74t7ag8uev2qseuyw6u",
		),
		cip30.StrictAddress(),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("valid:", result.Valid())
	fmt.Println("matched via:", result.Address.MatchedVia)
	fmt.Println("strict:", result.Address.Strict)
	// Output:
	// valid: true
	// matched via: Payment
	// strict: true
}

// ExampleParse decodes a data signature once and then runs several checks
// against the resulting Signature.
func ExampleParse() {
	ds := cip30.DataSignature{
		Signature: "84582aa201276761646472657373581de118987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281a166686173686564f458264175677573746120416461204b696e672c20436f756e74657373206f66204c6f76656c61636558401712458b19f606b322982f6290c78529a235b56c0f1cec4f24b12a8660b40cd37f4c5440a465754089c462ed4b0d613bffaee3d1833516569fda4852f42a4a0f",
		Key:       "a4010103272006215820b89526fd6bf4ba737c55ea90670d16a27f8de6cc1982349b3b676705a2f420c6",
	}

	sig, err := cip30.Parse(ds)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("signature valid:", sig.Verify())
	fmt.Println("message matches:", sig.VerifyMessage([]byte("Augusta Ada King, Countess of Lovelace")).Matched)
	fmt.Printf("key hash: %x\n", sig.KeyHash())
	// Output:
	// signature valid: true
	// message matches: true
	// key hash: 18987c1612069d4080a0eb247820cb987fea81bddeaafdd41f996281
}
