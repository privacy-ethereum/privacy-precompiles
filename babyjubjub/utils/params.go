package utils

import "errors"

// BabyJubJub common precompile constants for Ethereum-like execution.
const (
	// BabyJubJubFieldByteSize defines the fixed byte length of a field element
	// in the BabyJubJub elliptic curve. Each coordinate (X or Y) is represented
	// as a big-endian byte array of this size.
	BabyJubJubFieldByteSize = 32

	// BabyJubJubAffinePointSize defines the total byte length of an affine
	// point on the BabyJubJub curve. It is simply two field elements concatenated:
	// X || Y.
	BabyJubJubAffinePointSize = 2 * BabyJubJubFieldByteSize
)

// Predefined errors used for BabyJubJub curve operations.
var (
	// ErrorBabyJubJubPointInvalid is returned when a point cannot be parsed
	// or is otherwise invalid.
	ErrorBabyJubJubPointInvalid = errors.New("invalid point")

	// ErrorBabyJubJubInvalidInputLength is returned when the input slice
	// length does not match the expected size (e.g., point or field element size).
	ErrorBabyJubJubInvalidInputLength = errors.New("invalid input length")

	// ErrorBabyJubJubPointNotOnCurve is returned when a point does not
	// satisfy the BabyJubJub curve equation.
	ErrorBabyJubJubPointNotOnCurve = errors.New("point not on curve")

	// ErrorBabyJubJubPointNotInSubgroup is returned when a point is not
	// in the correct subgroup of the BabyJubJub curve.
	ErrorBabyJubJubPointNotInSubgroup = errors.New("point not in subgroup")
)
