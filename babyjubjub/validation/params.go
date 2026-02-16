package on_curve

import "github.com/privacy-ethereum/privacy-precompiles/babyjubjub/utils"

// BabyJubJubValidatePoint precompile constants for Ethereum-like execution.
const (
	// BabyJubJubCurveValidatePointInputSize defines the fixed byte length of the input
	// to the BabyJubJub point validation precompile. The input consists of a
	// single affine point serialized as X || Y, where each coordinate is a
	// big-endian field element padded to utils.BabyJubJubFieldByteSize bytes.
	//
	// This precompile is used to check whether a given point:
	//   - lies on the BabyJubJub curve
	//   - optionally lies in the correct prime-order subgroup
	BabyJubJubCurveValidatePointInputSize = utils.BabyJubJubCurveAffinePointSize

	// BabyJubJubCurveValidatePointGas is the estimated gas cost for executing
	// the BabyJubJub point validation precompile in Ethereum.
	//
	// This is a fixed cost, since validation involves only a small number
	// of curve checks.
	BabyJubJubCurveValidatePointGas uint64 = 10000
)
