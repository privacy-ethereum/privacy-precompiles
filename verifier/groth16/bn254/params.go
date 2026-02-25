package bn254

// BN254 Groth16 Verifier precompile constants
const (
	// BN254Groth16VerifyBaseGas defines the base gas cost for executing
	// the Groth16 verification precompile over the BN254 curve.
	//
	// The value is fixed and does not include additional dynamic costs
	// related to public input processing.
	BN254Groth16VerifyBaseGas = 220000

	// BN254Groth16ProofSize defines the expected byte size of a serialized
	// Groth16 proof over BN254.
	//
	// A Groth16 proof consists of:
	//   - G1 element A
	//   - G2 element B
	//   - G1 element C
	//
	// Each element is encoded in uncompressed affine form.
	BN254Groth16ProofSize = 256

	// BN254Groth16VerifyVerifyingKeySize defines the expected byte size
	// of a serialized Groth16 verifying key over BN254.
	//
	// This includes:
	//   - Alpha (G1)
	//   - Beta (G2)
	//   - Gamma (G2)
	//   - Delta (G2)
	//
	// Additional IC elements corresponding to public inputs may be
	// appended dynamically depending on the circuit.
	BN254Groth16VerifyVerifyingKeySize = 448

	// BN254Groth16G1Size defines the byte size of a serialized BN254
	// G1 affine point in uncompressed form.
	//
	// A G1 point consists of two field elements (X, Y),
	// each occupying 32 bytes.
	BN254Groth16G1Size = 64

	// BN254Groth16G2Size defines the byte size of a serialized BN254
	// G2 affine point in uncompressed form.
	//
	// A G2 point consists of two field elements (X, Y),
	// where each field element contains two 32-byte field elements.
	BN254Groth16G2Size = 128

	// BN254Groth16SinglePublicInputSize defines the byte size of a single
	// public input field element for BN254.
	//
	// Each public input is encoded as a 32-byte big-endian field element.
	BN254Groth16SinglePublicInputSize = 32

	// BN254Groth16FieldSize defines the byte size of a single base field
	// element in BN254.
	//
	// BN254 operates over a 254-bit prime field, which is encoded using
	// 32 bytes in big-endian representation.
	BN254Groth16FieldSize = 32
)
