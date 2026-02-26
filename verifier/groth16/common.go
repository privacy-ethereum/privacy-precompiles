package groth16

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	bn254Groth16 "github.com/privacy-ethereum/privacy-precompiles/verifier/groth16/bn254"
)

// Groth16CurveParams defines curve-specific configuration parameters
// required for Groth16 proof verification.
//
// These parameters are used to:
//   - validate input byte lengths
//   - parse proofs and verifying keys correctly
//   - calculate gas costs for the verification precompile
//
// Each supported curve must define its own parameter set.
type Groth16CurveParams struct {
	proofSize             int // Expected byte size of a serialized Groth16 proof
	vkSize                int // Expected byte size of a serialized verifying key
	g1Size                int // Byte size of a single G1 point
	singlePublicInputSize int // Byte size of a single public input field element
	baseGas               int // Base gas cost for executing Groth16 verification
}

// SolidityGroth16ByteParser defines the interface for parsing Groth16
// artifacts serialized in Solidity-compatible byte format.
//
// Implementations are curve-specific and are responsible for decoding:
//   - Groth16 proofs
//   - Groth16 verifying keys
//   - Public witness inputs
//
// The parser must validate structural correctness and return an error
// if the provided byte slice is malformed.
type SolidityGroth16ByteParser interface {
	// ParseProof parses a serialized Groth16 proof from the provided byte slice.
	ParseProof(data []byte) (groth16.Proof, error)

	// ParseVerifyingKey parses a serialized verifying key from the provided
	// byte slice. The numberOfPublicInputs parameter is required to validate
	// the expected IC (input commitment) length.
	ParseVerifyingKey(data []byte, numberOfPublicInputs int) (groth16.VerifyingKey, error)

	// ParsePublicWitness parses serialized public inputs into a gnark witness
	// compatible with the specified curve.
	ParsePublicWitness(data []byte, numberOfPublicInputs int) (witness.Witness, error)
}

// Groth16Params maps supported elliptic curves to their corresponding
// Groth16 verification parameters.
//
// Each entry defines the expected serialization sizes and gas costs
// required for verification on that curve.
var Groth16Params = map[ecc.ID]Groth16CurveParams{
	ecc.BN254: {
		proofSize:             bn254Groth16.BN254Groth16ProofSize,
		vkSize:                bn254Groth16.BN254Groth16VerifyVerifyingKeySize,
		g1Size:                bn254Groth16.BN254Groth16G1Size,
		singlePublicInputSize: bn254Groth16.BN254Groth16SinglePublicInputSize,
		baseGas:               bn254Groth16.BN254Groth16VerifyBaseGas,
	},
}

// SolidityProofParsers maps supported curves to their corresponding
// Solidity-compatible Groth16 byte parsers.
//
// Each parser implementation handles curve-specific decoding logic.
var SolidityProofParsers = map[ecc.ID]SolidityGroth16ByteParser{
	ecc.BN254: &bn254Groth16.SolidityBN254Parser{},
}

// Groth16Verify represents a Groth16 verification precompile
// bound to a specific elliptic curve and input parser.
type Groth16Verify struct {
	curveID ecc.ID
	parser  SolidityGroth16ByteParser
}

// NewGroth16BN254Verify creates a Groth16Verify instance configured for the
// BN254 curve.
//
// It initializes the verifier with the BN254 curve identifier and the
// corresponding Solidity proof byte parser, enabling verification of
// Groth16 proofs generated over the BN254 curve.
//
// The returned verifier expects proofs and public inputs encoded according
// to the BN254 Solidity format. Verification will fail if the provided proof
// or parameters do not match the BN254 curve.
func NewGroth16BN254Verify() *Groth16Verify {
	parser := SolidityProofParsers[ecc.BN254]
	return newGroth16Verify(ecc.BN254, parser)
}

// newGroth16Verify returns a Groth16Verify instance configured for
// the given curve and byte parser.
//
// The curveID must correspond to a curve supported by the underlying
// Groth16 parameters. Verification should return an error if the
// curve is unsupported.
func newGroth16Verify(curveID ecc.ID, parser SolidityGroth16ByteParser) *Groth16Verify {
	return &Groth16Verify{curveID: curveID, parser: parser}
}
