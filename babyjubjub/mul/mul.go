package mul

import (
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/privacy-ethereum/privacy-precompiles/babyjubjub/utils"
	"github.com/privacy-ethereum/privacy-precompiles/common"
)

// BabyJubJubCurveMul implements the BabyJubJub scalar multiplication precompile.
//
// It satisfies the common.Precompile interface and can be used in a generic
// precompile execution framework.
type BabyJubJubCurveMul struct{}

// Name returns the human-readable name of the precompile.
func (c *BabyJubJubCurveMul) Name() string {
	return "BabyJubJubMul"
}

// RequiredGas returns the fixed gas cost of executing this precompile.
//
// For BabyJubJub scalar multiplication, the gas cost is BabyJubJubMulGas.
func (c *BabyJubJubCurveMul) RequiredGas(input []byte) uint64 {
	return BabyJubJubCurveMulGas
}

// Run executes the BabyJubJub scalar multiplication precompile.
//
// The input must be exactly BabyJubJubMulInputSize bytes, which encode:
//
//	x || y || scalar
//
// Where:
//   - (x, y) is an affine point on the BabyJubJub curve.
//   - scalar is a field element encoded as a big-endian integer padded
//     to BabyJubJubFieldByteSize bytes.
//
// Run performs the following steps:
//  1. Parses the affine point from input using utils.ReadAffinePoint.
//  2. Validates that the point lies on the BabyJubJub curve and in the
//     correct subgroup.
//  3. Parses the scalar using utils.ReadField.
//  4. Reduces the scalar modulo the BabyJubJub subgroup order.
//  5. Computes scalar multiplication in projective coordinates.
//  6. Returns the resulting affine point serialized with utils.MarshalPoint.
//
// Returns an error if:
//   - The input length is incorrect.
//   - The point is invalid, not on the curve, or not in the subgroup.
func (c *BabyJubJubCurveMul) Run(input []byte) ([]byte, error) {
	if len(input) != BabyJubJubCurveMulInputSize {
		return nil, utils.ErrorBabyJubJubCurveInvalidInputLength
	}

	point, _ := utils.ReadAffinePoint(input, 0)

	if !point.InCurve() {
		return nil, utils.ErrorBabyJubJubCurvePointNotOnCurve
	}

	if !point.InSubGroup() {
		return nil, utils.ErrorBabyJubJubCurvePointNotInSubgroup
	}

	offset := utils.BabyJubJubCurveAffinePointSize
	scalar, _ := utils.ReadField(input, offset)
	scalar = scalar.Mod(scalar, babyjub.SubOrder)

	return utils.MarshalPoint(babyjub.NewPoint().Mul(scalar, point)), nil
}

// Ensure BabyJubJubCurveMul implements the common.Precompile interface.
var _ common.Precompile = (*BabyJubJubCurveMul)(nil)
