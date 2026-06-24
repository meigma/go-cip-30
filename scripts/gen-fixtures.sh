#!/usr/bin/env bash
#
# gen-fixtures.sh regenerates the committed CIP-30 functional test fixtures in
# testdata/fixtures/ using cardano-signer as an independent signing tool and
# verification oracle.
#
# THROWAWAY TEST KEYS ONLY. Every key here is derived from a fixed, public test
# mnemonic checked into this script. These keys hold no value, guard nothing, and
# exist solely to produce reproducible test vectors. NEVER use them for anything
# real.
#
# Reproducibility: keys are derived deterministically from the fixed mnemonic
# below, so re-running this script reproduces the same addresses and (because
# Ed25519 signing over a fixed message is deterministic) the same signatures.
#
# Anti-circularity: each fixture's expected verdict is NOT computed by this
# library. It is derived from (a) the signing parameters we control — we signed
# message M with key K over address A, so Verify(sig, WithMessage(M),
# WithAddress(A)) must be true; a wrong message or a foreign address must be
# false — and (b) cardano-signer's own "verify --cip30" run as an independent
# oracle. This script cross-checks every positive fixture against that oracle and
# fails loudly if the oracle disagrees.
#
# Run from the repo root via:  moon run gen-fixtures
set -euo pipefail

# Fixed public test mnemonic. Throwaway; see header.
readonly MNEMONIC="test walk nut penalty hip pave soap entry language right filter choice"

readonly OUT_DIR="testdata/fixtures"
readonly WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$OUT_DIR"

signer() { proto run cardano-signer -- "$@"; }

# json_get FILE JQ_PATH — read a value from a JSON file with python3 (no jq dep).
json_get() {
	python3 -c "import json,sys; d=json.load(open(sys.argv[1]));
keys=sys.argv[2].split('.');
v=d
for k in keys: v=v[k]
print(v)" "$1" "$2"
}

# Derive the deterministic keys/addresses we sign with.
signer keygen --path payment --mnemonics "$MNEMONIC" \
	--json-extended --out-file "$WORK_DIR/payment.json" >/dev/null
signer keygen --path payment --testnet --mnemonics "$MNEMONIC" \
	--json-extended --out-file "$WORK_DIR/payment_testnet.json" >/dev/null
signer keygen --path stake --mnemonics "$MNEMONIC" \
	--json-extended --out-file "$WORK_DIR/stake.json" >/dev/null

PAYMENT_SK=$(json_get "$WORK_DIR/payment.json" secretKey)
PAYMENT_ADDR=$(json_get "$WORK_DIR/payment.json" address)
PAYMENT_TESTNET_SK=$(json_get "$WORK_DIR/payment_testnet.json" secretKey)
PAYMENT_TESTNET_ADDR=$(json_get "$WORK_DIR/payment_testnet.json" address)
STAKE_SK=$(json_get "$WORK_DIR/stake.json" secretKey)
STAKE_ADDR=$(json_get "$WORK_DIR/stake.json" address)

# A foreign mainnet enterprise address that belongs to NEITHER test key. It is
# the cardano-verify-datasignature reference's enterprise address (its own
# unrelated keyEnterprise); cardano-signer verify rejects it for our test key, so
# it is a genuine wrong-address case. Used for the wrong-address negative fixture.
readonly FOREIGN_ADDR="addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d"

# fixtures collects per-fixture JSON objects appended into the manifest array.
FIXTURES=()

# emit NAME DESC SK SIGN_ADDR MESSAGE EXPECT_ADDR EXPECT_VALID DERIVED [SIGN_FLAGS...]
#   NAME         fixture id
#   DESC         human description
#   SK           secret key to sign with
#   SIGN_ADDR    address embedded by the signer (also the address we verify against
#                unless EXPECT_ADDR overrides it)
#   MESSAGE      the plaintext data signed
#   EXPECT_ADDR  the address our library should check with WithAddress; "" to omit
#   EXPECT_VALID true|false expected verdict of our library's Verify
#   DERIVED      a short note on how the expected verdict was derived
#   SIGN_FLAGS   extra flags passed to "sign --cip30" (e.g. --hashed --nopayload)
emit() {
	local name="$1" desc="$2" sk="$3" sign_addr="$4" message="$5"
	local expect_addr="$6" expect_valid="$7" derived="$8"
	shift 8
	local sign_flags=("$@")

	# cardano-signer needs --testnet whenever the address is a testnet address; the
	# network is unambiguous from the bech32 prefix, so detect it rather than
	# threading another parameter through every call site.
	local net_flags=()
	if [[ "$sign_addr" == addr_test* || "$sign_addr" == stake_test* ]]; then
		net_flags=(--testnet)
	fi

	local sig_json="$WORK_DIR/$name.json"
	signer sign --cip30 --data "$message" --secret-key "$sk" --address "$sign_addr" \
		"${net_flags[@]}" "${sign_flags[@]}" --json-extended --out-file "$sig_json" >/dev/null

	local cose_sign1 cose_key is_hashed
	cose_sign1=$(json_get "$sig_json" output.COSE_Sign1_hex)
	cose_key=$(json_get "$sig_json" output.COSE_Key_hex)
	is_hashed=$(json_get "$sig_json" isHashed)

	# Oracle cross-check: run cardano-signer's own verify --cip30 as an independent
	# verifier and require it to agree with the expected verdict. For positive
	# fixtures it must verify the as-signed message+address true. For negative
	# fixtures we feed the oracle the SAME wrong input our library is handed (the
	# override message, or the foreign address), and require it to reject — proving
	# the negative is genuinely wrong and not a quirk of our verifier.
	local oracle_data="${ORACLE_MESSAGE:-$message}"
	local oracle_addr="${ORACLE_ADDRESS:-$sign_addr}"
	local oracle
	if signer verify --cip30 --cose-sign1 "$cose_sign1" --cose-key "$cose_key" \
		--data "$oracle_data" --address "$oracle_addr" "${net_flags[@]}" --json >/dev/null 2>&1; then
		oracle="true"
	else
		oracle="false"
	fi
	if [[ "$oracle" != "$expect_valid" ]]; then
		echo "ORACLE DISAGREES for $name: expected $expect_valid, cardano-signer said $oracle" >&2
		exit 1
	fi

	local addr_field="null"
	[[ -n "$expect_addr" ]] && addr_field="\"$expect_addr\""

	FIXTURES+=("$(python3 -c "
import json,sys
print(json.dumps({
  'name': sys.argv[1],
  'description': sys.argv[2],
  'coseSign1Hex': sys.argv[3],
  'coseKeyHex': sys.argv[4],
  'message': sys.argv[5],
  'expectAddress': (sys.argv[6] if sys.argv[6] else None),
  'expectValid': sys.argv[7] == 'true',
  'hashed': sys.argv[8] == 'true',
  'oracle': sys.argv[9],
  'derivedFrom': sys.argv[10],
}, indent=2))" \
		"$name" "$desc" "$cose_sign1" "$cose_key" "$message" \
		"$expect_addr" "$expect_valid" "$is_hashed" "$oracle" "$derived")")
}

MSG="Augusta Ada King, Countess of Lovelace"

# --- Positive fixtures (signed as-described; oracle-confirmed) -------------
emit plain_enterprise_mainnet \
	"Plaintext payment-key signature, mainnet enterprise address." \
	"$PAYMENT_SK" "$PAYMENT_ADDR" "$MSG" "$PAYMENT_ADDR" true \
	"signed M with payment key over its own mainnet enterprise address; cardano-signer verify --cip30 = true"

emit plain_enterprise_testnet \
	"Plaintext payment-key signature, testnet enterprise address." \
	"$PAYMENT_TESTNET_SK" "$PAYMENT_TESTNET_ADDR" "$MSG" "$PAYMENT_TESTNET_ADDR" true \
	"signed M with testnet payment key over its own enterprise address; cardano-signer verify --cip30 = true"

emit hashed_embedded \
	"Hashed (blake2b-224) payload embedded in the COSE_Sign1." \
	"$PAYMENT_SK" "$PAYMENT_ADDR" "$MSG" "$PAYMENT_ADDR" true \
	"signed --hashed M; embedded payload is blake2b-224(M); cardano-signer verify --cip30 = true" \
	--hashed

emit detached_plain \
	"Detached plaintext signature (no embedded payload)." \
	"$PAYMENT_SK" "$PAYMENT_ADDR" "$MSG" "$PAYMENT_ADDR" true \
	"signed --nopayload M; payload reconstructed from M; cardano-signer verify --cip30 = true" \
	--nopayload

emit detached_hashed \
	"Detached AND hashed signature: the section-7 correctness case. Our verifier reconstructs the raw 28-byte blake2b-224(M), diverging from the reference's apparent UTF-8-of-hex-digest bug." \
	"$PAYMENT_SK" "$PAYMENT_ADDR" "$MSG" "$PAYMENT_ADDR" true \
	"signed --hashed --nopayload M; payload reconstructed as raw blake2b-224(M); cardano-signer verify --cip30 = true (confirms our divergence from the reference is correct)" \
	--hashed --nopayload

emit reward_stake_mainnet \
	"Plaintext stake-key signature, mainnet reward (stake) address." \
	"$STAKE_SK" "$STAKE_ADDR" "$MSG" "$STAKE_ADDR" true \
	"signed M with stake key over its own reward address; matches via the stake credential; cardano-signer verify --cip30 = true"

# --- Negative fixtures (valid signature, deliberately wrong check) ---------
# These reuse the plaintext enterprise signature but hand OUR library a wrong
# message / foreign address. The signature stays valid; the requested check must
# fail, so Verify().Valid() must be false. Derivation is the construction itself
# (a different message can't equal the signed payload; a foreign address shares
# neither credential of the signing key), and each is cross-checked against the
# oracle: cardano-signer is fed the SAME wrong input and must also reject.
readonly WRONG_MESSAGE="this is not the message that was signed"

# The oracle verifies the override message against the (correct) signing address,
# so only the message mismatch drives the rejection.
ORACLE_MESSAGE="$WRONG_MESSAGE" emit negative_wrong_message \
	"Valid signature checked against the WRONG message: Valid() must be false." \
	"$PAYMENT_SK" "$PAYMENT_ADDR" "$MSG" "" false \
	"valid sig, but we hand the library a different message at test time (see messageOverride); cardano-signer verify with that wrong --data = false"

# The oracle verifies the originally-signed message against the foreign address,
# so only the address mismatch drives the rejection.
ORACLE_ADDRESS="$FOREIGN_ADDR" emit negative_wrong_address \
	"Valid signature checked against a FOREIGN address: Valid() must be false." \
	"$PAYMENT_SK" "$PAYMENT_ADDR" "$MSG" "$FOREIGN_ADDR" false \
	"valid sig, but the foreign address shares neither credential of the signing key; cardano-signer verify --address <foreign> = false"

# Assemble the manifest. The negative_wrong_message fixture carries a distinct
# messageOverride so the test knows which (wrong) message to hand the library;
# its top-level message stays the originally-signed text for provenance.
OVERRIDE_MESSAGE="$WRONG_MESSAGE" python3 -c "
import json,os,sys
fixtures=[json.loads(x) for x in sys.argv[1:]]
for f in fixtures:
    if f['name']=='negative_wrong_message':
        f['messageOverride']=os.environ['OVERRIDE_MESSAGE']
manifest={
  'comment': 'CIP-30 functional test fixtures generated by scripts/gen-fixtures.sh from a fixed throwaway test mnemonic. Expected verdicts derive from the signing construction and cardano-signer verify --cip30 (the independent oracle), never from this library. Do not edit by hand; re-run moon run gen-fixtures.',
  'mnemonic': '$MNEMONIC',
  'fixtures': fixtures,
}
open('$OUT_DIR/manifest.json','w').write(json.dumps(manifest, indent=2)+'\n')
print('wrote $OUT_DIR/manifest.json with %d fixtures' % len(fixtures))
" "${FIXTURES[@]}"
