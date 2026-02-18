package add

import "github.com/privacy-ethereum/privacy-precompiles/babyjubjub/utils"

// BabyJubJub add precompile constants for Ethereum-like execution.
const (
	// BabyJubJubCurveAddInputSize defines the fixed byte length of the input
	// to the BabyJubJub curve addition precompile. The input consists of
	// two affine points serialized as X || Y || X || Y.
	BabyJubJubCurveAddInputSize = 2 * utils.BabyJubJubCurveAffinePointSize

	// BabyJubJubCurveAddOutputSize defines the fixed byte length of the output
	// of the BabyJubJub curve addition precompile. The output is a single
	// affine point serialized as X || Y.
	BabyJubJubCurveAddOutputSize = utils.BabyJubJubCurveAffinePointSize

	// BabyJubJubCurveAddGas is the gas cost estimate for executing the
	// BabyJubJub addition precompile in Ethereum.
	BabyJubJubCurveAddGas uint64 = 12300
)
