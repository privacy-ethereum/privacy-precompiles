package add

import "github.com/privacy-ethereum/privacy-precompiles/babyjubjub/utils"

// BabyJubJub add precompile constants for Ethereum-like execution.
const (
	// BabyJubJubAddInputSize defines the fixed byte length of the input
	// to the BabyJubJub curve addition precompile. The input consists of
	// two affine points serialized as X || Y || X || Y.
	BabyJubJubAddInputSize = 2 * utils.BabyJubJubAffinePointSize

	// BabyJubJubAddOutputSize defines the fixed byte length of the output
	// of the BabyJubJub curve addition precompile. The output is a single
	// affine point serialized as X || Y.
	BabyJubJubAddOutputSize = utils.BabyJubJubAffinePointSize

	// BabyJubJubAddGas is the gas cost estimate for executing the
	// BabyJubJub addition precompile in Ethereum.
	BabyJubJubAddGas = 12300
)
