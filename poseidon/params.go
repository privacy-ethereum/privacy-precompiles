package poseidon

import "errors"

// Poseidon hash precompile constants
const (
	// PoseidonInputWordSize defines the fixed byte length of a single
	// Poseidon input field element.
	//
	// Each element must be encoded as a big-endian field element padded
	// to 32 bytes.
	PoseidonInputWordSize = 32

	// PoseidonMaxParams defines the maximum number of field elements
	// accepted by the Poseidon precompile in a single invocation.
	PoseidonMaxParams = 16

	// PoseidonBaseGas defines the fixed base gas cost for executing
	// the Poseidon hash precompile, independent of input size.
	PoseidonBaseGas uint64 = 600

	// PoseidonPerWordGas defines the gas cost charged per input
	// field element (word) provided to the precompile.
	//
	// Total gas cost is calculated as:
	//
	//	PoseidonBaseGas + (number_of_words * PoseidonPerWordGas)
	PoseidonPerWordGas uint64 = 5400
)

var (
	// ErrorPoseidonInvalidInputLength is returned when the input to the
	// Poseidon precompile does not conform to the expected format.
	//
	// This occurs when:
	//   - The input length is zero.
	//   - The input length is not a multiple of PoseidonInputWordSize.
	//   - The number of input words exceeds PoseidonMaxParams.
	ErrorPoseidonInvalidInputLength = errors.New("invalid input length")
)
