package utils

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
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
	offset := index * BabyJubJubCurveAffinePointSize

	x, offset := utils.ReadField(input, offset, BabyJubJubCurveFieldByteSize)
	y, _ := utils.ReadField(input, offset, BabyJubJubCurveFieldByteSize)

	if x == nil || y == nil {
		return nil, ErrorBabyJubJubCurvePointInvalid
	}

	return &babyjub.Point{
		X: x,
		Y: y,
	}, nil
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
	output := make([]byte, BabyJubJubCurveAffinePointSize)
	xBytes := point.X.FillBytes(make([]byte, BabyJubJubCurveFieldByteSize))
	yBytes := point.Y.FillBytes(make([]byte, BabyJubJubCurveFieldByteSize))

	copy(output[0:BabyJubJubCurveFieldByteSize], xBytes)
	copy(output[BabyJubJubCurveFieldByteSize:BabyJubJubCurveAffinePointSize], yBytes)

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
	if len(input) != BabyJubJubCurveAffinePointSize {
		return nil, ErrorBabyJubJubCurvePointInvalid
	}

	xBytes := input[0:BabyJubJubCurveFieldByteSize]
	yBytes := input[BabyJubJubCurveFieldByteSize:BabyJubJubCurveAffinePointSize]

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &babyjub.Point{
		X: x,
		Y: y,
	}, nil
}

// BabyJubJubPointGenerator returns a gopter generator for valid BabyJubJub affine points.
//
// Each generated point is computed by multiplying a small random scalar `n`
// (generated as a uint64) with the BabyJubJub base point `B8`. This ensures
// that the resulting point lies in the correct subgroup.
//
// The generator is used with property-based tests to produce random,
// valid points for testing arithmetic operations on the BabyJubJub curve.
func BabyJubJubPointGenerator() gopter.Gen {
	return gen.UInt64().Map(func(n uint64) *babyjub.Point {
		scalar := new(big.Int).SetUint64(n)
		return babyjub.NewPoint().Mul(scalar, babyjub.B8)
	})
}

// ScalarGenerator returns a Gopter generator for random scalars modulo the BabyJubJub subgroup order.
// Each generated scalar is a 32-byte big-endian integer reduced modulo `babyjub.SubOrder`.
func ScalarGenerator() gopter.Gen {
	return gen.SliceOfN(32, gen.UInt8()).Map(func(bytes []byte) *big.Int {
		x := new(big.Int).SetBytes(bytes)

		return x.Mod(x, babyjub.SubOrder)
	})
}
