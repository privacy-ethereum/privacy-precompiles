package eddsa

import (
	"errors"

	"github.com/privacy-ethereum/privacy-precompiles/babyjubjub/utils"
)

// BabyJubJub EdDSA precompile constants
const (
	// BabyJubJubCurveEdDSAVerifyInputSize defines the fixed byte length of the input
	// to the BabyJubJub EdDSA signature verification precompile.
	//
	// The input consists of:
	//   - Public key point A serialized as Ax || Ay
	//   - Signature point R8 serialized as R8x || R8y
	//   - Signature scalar S
	//   - Message hash (field element)
	//
	// Each coordinate and scalar is encoded as a big-endian field element
	// padded to utils.BabyJubJubCurveFieldByteSize bytes.
	//
	// Total layout:
	//   Ax || Ay || R8x || R8y || S || M
	//
	// Where:
	//   - A  = public key (affine point)
	//   - R8 = signature curve point
	//   - S  = signature scalar
	//   - M  = message hash (field element)
	//
	// Total size:
	//   6 * utils.BabyJubJubCurveFieldByteSize
	BabyJubJubCurveEdDSAVerifyInputSize = 6 * utils.BabyJubJubCurveFieldByteSize

	// BabyJubJubCurveEdDSAVerifyGas defines the fixed gas cost for executing the
	// BabyJubJub EdDSA signature verification precompile in an
	// Ethereum-like execution environment.
	//
	// This cost reflects:
	//   - Curve point validation
	//   - Subgroup checks
	//   - Scalar range validation
	//   - One fixed-base scalar multiplication
	//   - One variable-base scalar multiplication
	//   - Curve additions
	//   - Final equality verification
	//
	// The gas value is constant because the input size is fixed.
	BabyJubJubCurveEdDSAVerifyGas uint64 = 270000
)

var (
	// ErrorBabyJubJubCurveEdDSAVerifyInvalidInputLength is returned when the input
	// byte slice does not exactly match BabyJubJubCurveEdDSAVerifyInputSize.
	ErrorBabyJubJubCurveEdDSAVerifyInvalidInputLength = errors.New("invalid input length")

	// ErrorBabyJubJubCurveEdDSAVerifyPublicKeyIsNotOnCurve is returned when the
	// provided public key point is not a valid BabyJubJub curve point.
	ErrorBabyJubJubCurveEdDSAVerifyPublicKeyIsNotOnCurve = errors.New("public key is not on curve")

	// ErrorBabyJubJubCurveEdDSAVerifyR8IsNotOnCurve is returned when the R8 point
	// in the signature is not a valid BabyJubJub curve point.
	ErrorBabyJubJubCurveEdDSAVerifyR8IsNotOnCurve = errors.New("r8 is not on curve")

	// ErrorBabyJubJubCurveEdDSAVerifyInvalidS is returned when the signature scalar S
	// is greater than or equal to the BabyJubJub subgroup order.
	ErrorBabyJubJubCurveEdDSAVerifyInvalidS = errors.New("s is greater than suborder")
)
