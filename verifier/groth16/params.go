package groth16

import "errors"

// Groth16 Verifier precompile constants
const (
	// Groth16MaxPublicInputs defines the maximum number of public inputs
	// supported by the Groth16 verification precompile.
	//
	// This limit is enforced to:
	//   - bound memory usage
	//   - prevent excessive gas consumption
	//   - mitigate potential denial-of-service vectors
	//
	// If the number of provided public inputs exceeds this value,
	// verification must fail.
	Groth16MaxPublicInputs = 64
)

var (
	// ErrorGroth16VerifyUnsupportedCurve is returned when the provided
	// verifying key references a curve that is not supported by
	// the Groth16 verification precompile.
	ErrorGroth16VerifyUnsupportedCurve = errors.New("unsupported curve")

	// ErrorPanicGroth16Verify is returned when an unexpected panic occurs
	// during Groth16 verification.
	//
	// This error indicates an internal failure and should never happen
	// during normal execution. It is used to safely recover from panics
	// and surface them as execution errors.
	ErrorPanicGroth16Verify = errors.New("panic during Groth16 verification")

	// ErrorGroth16VerifyInvalidInputLength is returned when the input
	// byte length provided to the Groth16 verification precompile
	// does not match the expected format.
	//
	// This typically indicates malformed calldata.
	ErrorGroth16VerifyInvalidInputLength = errors.New("invalid input length")

	// ErrorGroth16VerifyInvalidProof is returned when the provided
	// Groth16 proof fails cryptographic verification.
	//
	// This means the proof is either malformed or does not correspond
	// to the supplied public inputs and verifying key.
	ErrorGroth16VerifyInvalidProof = errors.New("invalid proof")

	// ErrorGroth16VerifyInvalidVerifyingKey is returned when the provided
	// verifying key is malformed, inconsistent, or fails structural
	// validation checks required for Groth16 verification.
	ErrorGroth16VerifyInvalidVerifyingKey = errors.New("invalid verifying key")

	// ErrorGroth16VerifyInvalidPublicWitness is returned when the
	// provided public inputs (public witness) are malformed or exceed
	// the maximum allowed number of inputs.
	ErrorGroth16VerifyInvalidPublicWitness = errors.New("invalid public witness")
)
