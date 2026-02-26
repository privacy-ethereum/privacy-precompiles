package groth16

import (
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
	babyjubjubAdd "github.com/privacy-ethereum/privacy-precompiles/babyjubjub/add"
	babyjubjubMul "github.com/privacy-ethereum/privacy-precompiles/babyjubjub/mul"
	"github.com/privacy-ethereum/privacy-precompiles/common"
	"github.com/privacy-ethereum/privacy-precompiles/utils"
)

// Name returns the human-readable identifier of the Groth16
// verification precompile.
//
// The name is derived from the configured curve and follows
// the format:
//
//	<CurveName>Groth16Verify
//
// Example:
//
//	BN254Groth16Verify
func (c *Groth16Verify) Name() string {
	return fmt.Sprintf("%sGroth16Verify", c.curveID.String())
}

// RequiredGas returns the gas cost required to execute the
// Groth16 verification precompile.
//
// The total gas cost consists of:
//   - A fixed curve-specific base cost.
//   - An additional per-public-input cost.
//
// The per-public-input cost approximates the cost of computing
// the linear combination of input commitments and is derived from
// BabyJubJub addition and multiplication gas constants.
//
// If the curve is unsupported, this function returns 0.
func (c *Groth16Verify) RequiredGas(input []byte) uint64 {
	params, ok := Groth16Params[c.curveID]

	if !ok {
		return 0
	}

	numberOfPublicInputs := c.calculateNumberOfPublicInputs(input, &params)

	operationsCost := babyjubjubAdd.BabyJubJubCurveAddGas + babyjubjubMul.BabyJubJubCurveMulGas

	return uint64(params.baseGas) + operationsCost*uint64(numberOfPublicInputs)
}

// Run executes Groth16 proof verification for the provided input.
//
// Expected input layout:
//
//	[ Proof || VerifyingKey || PublicInputs ]
//
// Where:
//   - Proof is a curve-specific fixed-size serialized Groth16 proof.
//   - VerifyingKey includes fixed elements plus (n+1) G1 IC points.
//   - PublicInputs contains n serialized field elements.
//
// Execution steps:
//  1. Recover from unexpected panics and convert them to
//     ErrorPanicGroth16Verify.
//  2. Validate that the curve is supported.
//  3. Validate total input length and structural alignment.
//  4. Extract proof, verifying key, and public witness slices.
//  5. Parse proof, verifying key, and witness using the
//     curve-specific Solidity parser.
//  6. Execute groth16.Verify.
//  7. Return 1 if verification succeeds, 0 if it fails.
//
// Return value:
//   - []byte{1} if the proof is valid.
//   - []byte{0} if the proof is invalid.
//   - An error if the input is malformed or unsupported.
//
// Strict validation is enforced to prevent malformed calldata,
// excessive memory usage, or denial-of-service vectors.
func (c *Groth16Verify) Run(input []byte) (ret []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			ret = nil
			err = ErrorPanicGroth16Verify
		}
	}()

	length := len(input)
	params, ok := Groth16Params[c.curveID]

	if !ok {
		return nil, ErrorGroth16VerifyUnsupportedCurve
	}

	minInputSize := params.proofSize + params.vkSize

	if length < minInputSize {
		return nil, ErrorGroth16VerifyInvalidInputLength
	}

	numberOfPublicInputs := c.calculateNumberOfPublicInputs(input, &params)

	if numberOfPublicInputs <= 0 || numberOfPublicInputs > Groth16MaxPublicInputs {
		return nil, ErrorGroth16VerifyInvalidInputLength
	}

	vkTotalSize :=
		params.vkSize +
			params.g1Size*(numberOfPublicInputs+1)
	proofAndVkSize := params.proofSize + vkTotalSize

	proofBytes, _ := utils.SafeSlice(input, 0, params.proofSize)
	vkBytes, _ := utils.SafeSlice(input, params.proofSize, proofAndVkSize)
	publicWitnessBytes, _ := utils.SafeSlice(input, proofAndVkSize, proofAndVkSize+numberOfPublicInputs*params.singlePublicInputSize)

	proof, err := c.parser.ParseProof(proofBytes)

	if err != nil {
		return nil, ErrorGroth16VerifyInvalidProof
	}

	vk, err := c.parser.ParseVerifyingKey(vkBytes, numberOfPublicInputs)

	if err != nil {
		return nil, ErrorGroth16VerifyInvalidVerifyingKey
	}

	publicWitness, err := c.parser.ParsePublicWitness(publicWitnessBytes, numberOfPublicInputs)

	if err != nil {
		return nil, ErrorGroth16VerifyInvalidPublicWitness
	}

	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		return []byte{0}, nil
	}

	return []byte{1}, nil
}

// calculateNumberOfPublicInputs returns the number of public inputs
// encoded in the serialized Groth16 verification payload. No validation is performed.
func (c *Groth16Verify) calculateNumberOfPublicInputs(input []byte, params *Groth16CurveParams) int {
	length := len(input)

	return (length - params.proofSize - params.vkSize - params.g1Size) / (params.g1Size + params.singlePublicInputSize)
}

// Ensure Groth16Verify implements the common.Precompile interface.
var _ common.Precompile = (*Groth16Verify)(nil)
