package on_curve

import (
	"github.com/privacy-ethereum/privacy-precompiles/babyjubjub/utils"
	"github.com/privacy-ethereum/privacy-precompiles/common"
)

// BabyJubJubCurveValidatePoint implements a BabyJubJub point validation precompile.
//
// It satisfies the common.Precompile interface and can be used in a generic
// precompile execution framework to verify points before performing curve operations.
//
// The precompile checks that a given affine point lies:
//  1. On the BabyJubJub curve.
//  2. In the correct prime-order subgroup.
//
// This is useful for validating user input or ensuring security before
// arithmetic operations such as addition or scalar multiplication.
type BabyJubJubCurveValidatePoint struct{}

// Name returns the human-readable name of the precompile.
func (c *BabyJubJubCurveValidatePoint) Name() string {
	return "BabyJubJubCurveValidatePoint"
}

// RequiredGas returns the fixed gas cost of executing this precompile.
//
// For BabyJubJub point validation, the gas cost is BabyJubJubValidatePointGas.
func (c *BabyJubJubCurveValidatePoint) RequiredGas(input []byte) uint64 {
	return BabyJubJubCurveValidatePointGas
}

// Run executes the BabyJubJub point validation precompile.
//
// The input must be exactly BabyJubJubValidatePointInputSize bytes, which
// encode a single affine point in the format:
//
//	x || y
//
// Each coordinate is a big-endian field element padded to
// utils.BabyJubJubFieldByteSize bytes.
//
// Run performs the following steps:
//  1. Parses the point from input using utils.ReadAffinePoint.
//  2. Checks whether the point lies on the BabyJubJub curve.
//  3. Checks whether the point is in the prime-order subgroup.
//  4. Returns 1 if the point is valid, 0 otherwise.
//
// Returns an error if:
//   - The input length is incorrect.
//   - The point encoding is invalid.
func (c *BabyJubJubCurveValidatePoint) Run(input []byte) ([]byte, error) {
	if len(input) != BabyJubJubCurveValidatePointInputSize {
		return nil, utils.ErrorBabyJubJubCurveInvalidInputLength
	}

	point, _ := utils.ReadAffinePoint(input, 0)

	if point.InCurve() && point.InSubGroup() {
		return []byte{1}, nil
	}

	return []byte{0}, nil
}

// Ensure BabyJubJubValidatePoint implements the common.Precompile interface.
var _ common.Precompile = (*BabyJubJubCurveValidatePoint)(nil)
