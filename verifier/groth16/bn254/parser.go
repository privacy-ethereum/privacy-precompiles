package bn254

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/privacy-ethereum/privacy-precompiles/common"
	"github.com/privacy-ethereum/privacy-precompiles/utils"
)

// SolidityBN254Parser implements SolidityGroth16ByteParser for the BN254 curve.
//
// It is responsible for decoding Solidity-compatible byte encodings of:
//   - Groth16 proofs
//   - Groth16 verifying keys
//   - Public witness inputs
//
// All elements are expected to be encoded in uncompressed affine form,
// using big-endian field element representation.
type SolidityBN254Parser struct{}

// ParseG1 parses a BN254 G1 affine point from data starting at the given offset.
//
// The expected encoding is:
//   - 32 bytes X coordinate (big-endian)
//   - 32 bytes Y coordinate (big-endian)
//
// It writes the parsed point into destination and returns the new offset.
// An error is returned if the byte slice is out of bounds.
func ParseG1(
	data []byte,
	offset int,
	destination *bn254.G1Affine,
) (int, error) {
	if slice, ok := utils.SafeSlice(data, offset, offset+BN254Groth16FieldSize); ok {
		destination.X.SetBytes(slice)
	} else {
		return offset, common.ErrorInvalidG1
	}

	if slice, ok := utils.SafeSlice(data, offset+BN254Groth16FieldSize, offset+2*BN254Groth16FieldSize); ok {
		destination.Y.SetBytes(slice)
	} else {
		return offset, common.ErrorInvalidG1
	}

	return offset + BN254Groth16G1Size, nil
}

// ParseG2 parses a BN254 G2 affine point from data starting at the given offset.
//
// The expected encoding is:
//   - 32 bytes X.A1
//   - 32 bytes X.A0
//   - 32 bytes Y.A1
//   - 32 bytes Y.A0
//
// Each component is a field element encoded in big-endian format.
// The function writes the parsed point into destination and returns
// the updated offset. An error is returned if the byte slice is invalid.
func ParseG2(
	data []byte,
	offset int,
	destination *bn254.G2Affine,
) (int, error) {
	if slice, ok := utils.SafeSlice(data, offset, offset+BN254Groth16FieldSize); ok {
		destination.X.A1.SetBytes(slice)
	} else {
		return offset, common.ErrorInvalidG2
	}

	if slice, ok := utils.SafeSlice(data, offset+BN254Groth16FieldSize, offset+2*BN254Groth16FieldSize); ok {
		destination.X.A0.SetBytes(slice)
	} else {
		return offset, common.ErrorInvalidG2
	}

	if slice, ok := utils.SafeSlice(data, offset+2*BN254Groth16FieldSize, offset+3*BN254Groth16FieldSize); ok {
		destination.Y.A1.SetBytes(slice)
	} else {
		return offset, common.ErrorInvalidG2
	}

	if slice, ok := utils.SafeSlice(data, offset+3*BN254Groth16FieldSize, offset+BN254Groth16G2Size); ok {
		destination.Y.A0.SetBytes(slice)
	} else {
		return offset, common.ErrorInvalidG2
	}

	return offset + BN254Groth16G2Size, nil
}

// ParseProof parses a serialized Groth16 proof over BN254.
//
// The expected layout is:
//   - G1 element Ar
//   - G2 element Bs
//   - G1 element Krs
//
// Each element must be encoded in uncompressed affine form.
// An error is returned if parsing fails at any step.
func (p *SolidityBN254Parser) ParseProof(data []byte) (groth16.Proof, error) {
	var proof groth16bn254.Proof
	var err error
	var offset int = 0

	offset, err = ParseG1(data, offset, &proof.Ar)

	if err != nil {
		return nil, err
	}

	offset, err = ParseG2(data, offset, &proof.Bs)

	if err != nil {
		return nil, err
	}

	_, err = ParseG1(data, offset, &proof.Krs)

	if err != nil {
		return nil, err
	}

	return &proof, nil
}

// ParseVerifyingKey parses a serialized Groth16 verifying key over BN254.
//
// The expected layout is:
//   - G1 Alpha
//   - G2 Beta
//   - G2 Gamma
//   - G2 Delta
//   - (numberOfPublicInputs + 1) G1 elements for the IC (input commitments)
//
// After parsing, vk.Precompute() is called to prepare internal pairing
// values (e.g., gammaNeg, deltaNeg). An error is returned if parsing or
// precomputation fails.
func (p *SolidityBN254Parser) ParseVerifyingKey(data []byte, numberOfPublicInputs int) (groth16.VerifyingKey, error) {
	var vk groth16bn254.VerifyingKey
	var err error
	var offset int = 0

	offset, err = ParseG1(data, offset, &vk.G1.Alpha)

	if err != nil {
		return nil, err
	}

	offset, err = ParseG2(data, offset, &vk.G2.Beta)

	if err != nil {
		return nil, err
	}

	offset, err = ParseG2(data, offset, &vk.G2.Gamma)

	if err != nil {
		return nil, err
	}

	offset, err = ParseG2(data, offset, &vk.G2.Delta)

	if err != nil {
		return nil, err
	}

	vk.G1.K = make([]bn254.G1Affine, numberOfPublicInputs+1)

	for index := range vk.G1.K {
		offset, err = ParseG1(data, offset, &vk.G1.K[index])

		if err != nil {
			return nil, err
		}
	}

	// Precompute the necessary values (e, gammaNeg, deltaNeg)
	if err := vk.Precompute(); err != nil {
		// Cannot fail through this parser
		// Alpha and Beta points are checked before calling precompute function
		return nil, err
	}

	return &vk, nil
}

// ParsePublicWitness parses serialized public inputs into a gnark Witness
// compatible with the specified curve.
//
// Each public input must be encoded as a 32-byte big-endian field element.
// The numberOfPublicInputs parameter defines how many inputs are expected.
//
// The parsed inputs are streamed into the witness using a channel and
// populated via w.Fill(). An error is returned if any slice is invalid
// or if witness construction fails.
func (p *SolidityBN254Parser) ParsePublicWitness(
	data []byte,
	numberOfPublicInputs int,
) (witness.Witness, error) {
	publicWitness, _ := witness.New(ecc.BN254.ScalarField())

	channel := make(chan any, numberOfPublicInputs)
	offset := 0

	for range numberOfPublicInputs {
		if slice, ok := utils.SafeSlice(data, offset, offset+BN254Groth16FieldSize); ok {
			channel <- new(big.Int).SetBytes(slice)
		} else {
			return nil, errors.New("invalid slice")
		}

		offset += BN254Groth16FieldSize
	}

	close(channel)

	if err := publicWitness.Fill(numberOfPublicInputs, 0, channel); err != nil {
		// Cannot fail through this parser
		// 1. Channel always contains exactly numberOfPublicInputs elements
		// 2. All elements are *big.Int, set always succeeds (SetBigInt reduces modulo field)
		return nil, err
	}

	return publicWitness, nil
}
