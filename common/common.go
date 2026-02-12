package common

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
