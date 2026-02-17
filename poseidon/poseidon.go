package poseidon

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/privacy-ethereum/privacy-precompiles/common"
	commonUtils "github.com/privacy-ethereum/privacy-precompiles/utils"
)

// Poseidon implements the Poseidon hash precompile.
//
// It satisfies the common.Precompile interface and can be used in a generic
// precompile execution framework to compute Poseidon hashes over a sequence
// of field elements.
type Poseidon struct{}

// Name returns the human-readable name of the precompile.
func (c *Poseidon) Name() string {
	return "Poseidon"
}

// RequiredGas returns the gas cost of executing this precompile.
//
// Gas is calculated as:
//
//	PoseidonBaseGas + (number_of_words * PoseidonPerWordGas)
//
// Where each word is a 32-byte field element.
func (c *Poseidon) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+(PoseidonInputWordSize-1))/
		PoseidonInputWordSize*PoseidonPerWordGas +
		PoseidonBaseGas
}

// Run executes the Poseidon hash precompile.
//
// The input must consist of N field elements encoded as:
//
//	e1 || e2 || ... || eN
//
// Where:
//   - Each element is a big-endian integer padded to PoseidonInputWordSize bytes.
//   - 1 <= N <= PoseidonMaxParams.
//   - The total input length must be a multiple of PoseidonInputWordSize.
//
// Run performs the following steps:
//  1. Validates input length and parameter bounds.
//  2. Parses each field element using commonUtils.ReadField.
//  3. Computes the Poseidon hash over the parsed elements.
//  4. Returns the resulting field element encoded as a 32-byte big-endian value.
//
// Returns an error if:
//   - The input length is zero.
//   - The input length is not a multiple of PoseidonInputWordSize.
//   - The number of elements exceeds PoseidonMaxParams.
//   - The underlying Poseidon hash function returns an error.
func (c *Poseidon) Run(input []byte) ([]byte, error) {
	if len(input) == 0 || len(input)%PoseidonInputWordSize != 0 {
		return nil, ErrorPoseidonInvalidInputLength
	}

	length := len(input) / PoseidonInputWordSize

	if length > PoseidonMaxParams {
		return nil, ErrorPoseidonInvalidInputLength
	}

	elements := make([]*big.Int, length)

	for index := range length {
		element, _ := commonUtils.ReadField(
			input,
			index*PoseidonInputWordSize,
			PoseidonInputWordSize,
		)

		elements[index] = element
	}

	hash, err := poseidon.Hash(elements)

	if err != nil {
		return nil, err
	}

	return hash.FillBytes(make([]byte, PoseidonInputWordSize)), nil
}

// Ensure Poseidon implements the common.Precompile interface.
var _ common.Precompile = (*Poseidon)(nil)
