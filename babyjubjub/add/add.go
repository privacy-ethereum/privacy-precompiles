package add

import (
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/privacy-ethereum/privacy-precompiles/babyjubjub/utils"
	"github.com/privacy-ethereum/privacy-precompiles/common"
)

// BabyJubJubCurveAdd implements the BabyJubJub point addition precompile.
//
// It satisfies the common.Precompile interface and can be used in a generic
// precompile execution framework.
type BabyJubJubCurveAdd struct{}

// Name returns the human-readable name of the precompile.
func (c *BabyJubJubCurveAdd) Name() string {
	return "BabyJubJubCurveAdd"
}

// RequiredGas returns the fixed gas cost of executing this precompile.
//
// For BabyJubJub point addition, the gas cost is BabyJubJubAddGas.
func (c *BabyJubJubCurveAdd) RequiredGas(input []byte) uint64 {
	return BabyJubJubCurveAddGas
}

// Run executes the BabyJubJub point addition precompile.
//
// The input must be exactly BabyJubJubAddInputSize bytes, which encode two
// affine points in the format:
//
//	x1 || y1 || x2 || y2
//
// Each coordinate is a big-endian field element padded to BabyJubJubFieldByteSize bytes.
//
// Run performs the following steps:
//  1. Parses the two points from input using utils.ReadAffinePoint.
//  2. Validates that both points lie on the BabyJubJub curve and in the
//     correct subgroup.
//  3. Adds the points in projective coordinates.
//  4. Returns the resulting affine point serialized with utils.MarshalPoint.
//
// Returns an error if:
//   - The input length is incorrect.
//   - Any point is invalid, not on the curve, or not in the subgroup.
func (c *BabyJubJubCurveAdd) Run(input []byte) ([]byte, error) {
	if len(input) != BabyJubJubCurveAddInputSize {
		return nil, utils.ErrorBabyJubJubCurveInvalidInputLength
	}

	point1, _ := utils.ReadAffinePoint(input, 0)
	point2, _ := utils.ReadAffinePoint(input, 1)

	if !point1.InSubGroup() || !point2.InSubGroup() {
		return nil, utils.ErrorBabyJubJubCurveInvalidPoint
	}

	result := babyjub.NewPoint().Projective().Add(point1.Projective(), point2.Projective()).Affine()

	return utils.MarshalPoint(result), nil
}

// Ensure BabyJubJubCurveAdd implements the common.Precompile interface.
var _ common.Precompile = (*BabyJubJubCurveAdd)(nil)
