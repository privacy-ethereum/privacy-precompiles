package mul

import "github.com/privacy-ethereum/privacy-precompiles/babyjubjub/utils"

// BabyJubJub mul precompile constants for Ethereum-like execution.
const (
	// BabyJubJubMulInputSize defines the fixed byte length of the input
	// to the BabyJubJub curve scalar multiplication precompile.
	//
	// The input consists of:
	//   - One affine point serialized as X || Y
	//   - One scalar field element
	//
	// Each coordinate and the scalar are big-endian field elements padded
	// to utils.BabyJubJubFieldByteSize bytes.
	//
	// Total layout:
	//   X || Y || scalar
	BabyJubJubMulInputSize = 3 * utils.BabyJubJubFieldByteSize

	// BabyJubJubMulOutputSize defines the fixed byte length of the output
	// of the BabyJubJub scalar multiplication precompile.
	//
	// The output is a single affine point serialized as:
	//   X || Y
	BabyJubJubMulOutputSize = utils.BabyJubJubAffinePointSize

	// BabyJubJubMulGas is the gas cost estimate for executing the
	// BabyJubJub scalar multiplication precompile in Ethereum.
	BabyJubJubMulGas uint64 = 14400
)
