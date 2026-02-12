package utils

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/privacy-ethereum/privacy-precompiles/utils"
)

// readAffinePoint returns the affine BabyJubJub curve point at the given index
// from the precompile input buffer.
//
// The input is interpreted as a sequence of affine points encoded as:
//
//	x || y
//
// where each coordinate is a fixed-width, big-endian field element of
// babyJubJubFieldByteSize bytes.
//
// The index parameter selects which affine point to read:
//
//	index = 0 → first point  (bytes [0 : babyJubJubAffinePointSize])
//	index = 1 → second point (bytes [babyJubJubAffinePointSize : 2*babyJubJubAffinePointSize])
//
// readAffinePoint does not validate that the returned point lies on the curve
// or in the correct subgroup. Callers must perform any required validation.
func ReadAffinePoint(input []byte, index int) (*babyjub.Point, error) {
	offset := index * BabyJubJubAffinePointSize

	x, offset := ReadField(input, offset)
	y, _ := ReadField(input, offset)

	if x == nil || y == nil {
		return nil, ErrorBabyJubJubPointInvalid
	}

	return &babyjub.Point{
		X: x,
		Y: y,
	}, nil
}

// readField returns the BabyJubJub field element encoded at the given byte
// offset in the precompile input buffer, along with the next unread offset.
//
// The input is interpreted as a sequence of fixed-width, big-endian field
// elements, each encoded in babyJubJubFieldByteSize bytes.
//
// If the requested range is out of bounds, readField returns (nil, offset).
//
// The returned value is not reduced modulo the field modulus and is not
// validated against field bounds. Callers are responsible for enforcing any
// required invariants.
func ReadField(input []byte, offset int) (*big.Int, int) {
	slice, ok := utils.SafeSlice(input, offset, offset+BabyJubJubFieldByteSize)

	if !ok {
		return nil, offset
	}

	return new(big.Int).SetBytes(slice), offset + BabyJubJubFieldByteSize
}

// marshalPoint serializes an affine BabyJubJub curve point into the fixed-size
// byte encoding expected by the BabyJubJub add precompile.
//
// The output format is:
//
//	x || y
//
// where each coordinate is encoded as a big-endian field element padded to
// babyJubJubFieldByteSize bytes. The returned slice is always exactly
// babyJubJubAddOutputSize bytes long.
//
// The caller must ensure that point is non-nil and in affine coordinates.
func MarshalPoint(point *babyjub.Point) []byte {
	output := make([]byte, BabyJubJubAffinePointSize)
	xBytes := point.X.FillBytes(make([]byte, BabyJubJubFieldByteSize))
	yBytes := point.Y.FillBytes(make([]byte, BabyJubJubFieldByteSize))

	copy(output[0:BabyJubJubFieldByteSize], xBytes)
	copy(output[BabyJubJubFieldByteSize:BabyJubJubAffinePointSize], yBytes)

	return output
}

// UnmarshalPoint deserializes a byte slice into a BabyJubJub affine point.
//
// The input must be exactly BabyJubJubAffinePointSize bytes, encoded as:
//
//	x || y
//
// where each coordinate is a big-endian field element of BabyJubJubFieldByteSize bytes.
//
// Returns an error if the input is too short or otherwise invalid.
func UnmarshalPoint(input []byte) (*babyjub.Point, error) {
	if len(input) != BabyJubJubAffinePointSize {
		return nil, ErrorBabyJubJubPointInvalid
	}

	xBytes := input[0:BabyJubJubFieldByteSize]
	yBytes := input[BabyJubJubFieldByteSize:BabyJubJubAffinePointSize]

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &babyjub.Point{
		X: x,
		Y: y,
	}, nil
}
