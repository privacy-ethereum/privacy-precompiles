package eddsa

import (
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/privacy-ethereum/privacy-precompiles/babyjubjub/utils"
	"github.com/privacy-ethereum/privacy-precompiles/common"
	commonUtils "github.com/privacy-ethereum/privacy-precompiles/utils"
)

// BabyJubJubCurveEdDSAVerify implements the BabyJubJub EdDSA signature verification precompile.
//
// It satisfies the common.Precompile interface and can be used in a generic
// precompile execution framework to verify signatures over the BabyJubJub curve
// using the Poseidon hash.
type BabyJubJubCurveEdDSAVerify struct{}

// Name returns the human-readable name of the precompile.
func (c *BabyJubJubCurveEdDSAVerify) Name() string {
	return "BabyJubJubEdDSAVerify"
}

// RequiredGas returns the fixed gas cost of executing this precompile.
//
// The gas is fixed at BabyJubJubCurveEdDSAVerifyGas because the input size is constant
// and verification steps (point validation, scalar check, Poseidon hash) are
// deterministic.
func (c *BabyJubJubCurveEdDSAVerify) RequiredGas(input []byte) uint64 {
	return BabyJubJubCurveEdDSAVerifyGas
}

// Run executes the EdDSA signature verification precompile.
//
// The input must be exactly BabyJubJubCurveEdDSAVerifyInputSize bytes, which encode:
//
//	Ax || Ay || R8x || R8y || S || M
//
// Where:
//   - (Ax, Ay) is the public key point (affine coordinates) on the BabyJubJub curve.
//   - (R8x, R8y) is the signature point R8.
//   - S is the signature scalar.
//   - M is the message hash (field element).
//
// Each coordinate or scalar is encoded as a big-endian field element, padded
// to utils.BabyJubJubCurveFieldByteSize bytes.
//
// Run performs the following steps:
//  1. Validates that the input length equals BabyJubJubCurveEdDSAVerifyInputSize.
//  2. Parses the public key point and verifies it lies on the curve.
//  3. Parses the R8 signature point and verifies it lies on the curve.
//  4. Parses the signature scalar S and verifies it is smaller than the subgroup order.
//  5. Parses the message field element M.
//  6. Verifies the signature using Poseidon-based BabyJubJub EdDSA.
//  7. Returns []byte{1} if the signature is valid, []byte{0} otherwise.
//
// Returns an error if:
//   - The input length is invalid.
//   - The public key or R8 points are not on the BabyJubJub curve.
//   - The signature scalar S is invalid.
func (c *BabyJubJubCurveEdDSAVerify) Run(input []byte) ([]byte, error) {
	if len(input) != BabyJubJubCurveEdDSAVerifyInputSize {
		return nil, ErrorBabyJubJubCurveEdDSAVerifyInvalidInputLength
	}

	offset := 0

	publicKeyX, offset := commonUtils.ReadField(input, offset, utils.BabyJubJubCurveFieldByteSize)
	publicKeyY, offset := commonUtils.ReadField(input, offset, utils.BabyJubJubCurveFieldByteSize)

	publicKeyPoint := babyjub.Point{
		X: publicKeyX,
		Y: publicKeyY,
	}

	if !publicKeyPoint.InCurve() || !publicKeyPoint.InSubGroup() {
		return nil, ErrorBabyJubJubCurveEdDSAVerifyPublicKeyIsNotOnCurve
	}

	r8X, offset := commonUtils.ReadField(input, offset, utils.BabyJubJubCurveFieldByteSize)
	r8Y, offset := commonUtils.ReadField(input, offset, utils.BabyJubJubCurveFieldByteSize)

	R8 := babyjub.Point{
		X: r8X,
		Y: r8Y,
	}

	if !R8.InCurve() || !R8.InSubGroup() {
		return nil, ErrorBabyJubJubCurveEdDSAVerifyR8IsNotOnCurve
	}

	S, offset := commonUtils.ReadField(input, offset, utils.BabyJubJubCurveFieldByteSize)

	if S.Cmp(babyjub.SubOrder) >= 0 {
		return nil, ErrorBabyJubJubCurveEdDSAVerifyInvalidS
	}

	message, _ := commonUtils.ReadField(input, offset, utils.BabyJubJubCurveFieldByteSize)

	signature := &babyjub.Signature{R8: &R8, S: S}
	publicKey := &babyjub.PublicKey{X: publicKeyPoint.X, Y: publicKeyPoint.Y}

	if publicKey.VerifyPoseidon(message, signature) {
		return []byte{1}, nil
	}

	return []byte{0}, nil
}

// Ensure BabyJubJubCurveEdDSAVerify implements the common.Precompile interface.
var _ common.Precompile = (*BabyJubJubCurveEdDSAVerify)(nil)
