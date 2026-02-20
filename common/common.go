package common

import "errors"

// Precompile defines the common interface for all Ethereum precompiles
type Precompile interface {
	// Name returns the precompile's name
	Name() string

	// Run executes the precompile logic on the given input bytes
	// Returns output bytes or an error if execution fails
	Run(input []byte) ([]byte, error)

	// RequiredGas returns the estimated gas for executing this precompile
	RequiredGas(input []byte) uint64
}

var (
	// ErrorInvalidG1 is returned when a serialized G1 point
	// is malformed, out of bounds, or fails structural validation
	// during parsing.
	//
	// This error typically indicates:
	//   - Incorrect byte length
	//   - Invalid field element encoding
	//   - Corrupted or truncated calldata
	ErrorInvalidG1 = errors.New("invalid G1 point")

	// ErrorInvalidG2 is returned when a serialized G2 point
	// is malformed, out of bounds, or fails structural validation
	// during parsing.
	//
	// This error typically indicates:
	//   - Incorrect byte length
	//   - Invalid field component encoding
	//   - Corrupted or truncated calldata
	ErrorInvalidG2 = errors.New("invalid G2 point")
)
