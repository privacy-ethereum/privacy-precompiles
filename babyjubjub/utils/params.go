package utils

import "errors"

// BabyJubJub common precompile constants for Ethereum-like execution.
const (
	// BabyJubJubCurveFieldByteSize defines the fixed byte length of a field element
	// in the BabyJubJub elliptic curve. Each coordinate (X or Y) is represented
	// as a big-endian byte array of this size.
	BabyJubJubCurveFieldByteSize = 32

	// BabyJubJubCurveAffinePointSize defines the total byte length of an affine
	// point on the BabyJubJub curve. It is simply two field elements concatenated:
	// X || Y.
	BabyJubJubCurveAffinePointSize = 2 * BabyJubJubCurveFieldByteSize
)

// Predefined errors used for BabyJubJub curve operations.
var (
	// ErrorBabyJubJubCurvePointInvalid is returned when a point cannot be parsed
	// or is otherwise invalid.
	ErrorBabyJubJubCurvePointInvalid = errors.New("invalid point")

	// ErrorBabyJubJubCurveInvalidInputLength is returned when the input slice
	// length does not match the expected size (e.g., point or field element size).
	ErrorBabyJubJubCurveInvalidInputLength = errors.New("invalid input length")

	// ErrorBabyJubJubCurvePointNotOnCurve is returned when a point does not
	// satisfy the BabyJubJub curve equation.
	ErrorBabyJubJubCurvePointNotOnCurve = errors.New("point not on curve")

	// ErrorBabyJubJubCurvePointNotInSubgroup is returned when a point is not
	// in the correct subgroup of the BabyJubJub curve.
	ErrorBabyJubJubCurvePointNotInSubgroup = errors.New("point not in subgroup")
)
