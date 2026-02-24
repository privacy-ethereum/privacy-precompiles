package bn254

import (
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/privacy-ethereum/privacy-precompiles/babyjubjub/utils"
)

// G1AffineGenerator returns a gopter generator for random BN254 G1 affine points.
// It generates two uint64 values and maps them to the X and Y coordinates of a G1Affine point.
func G1AffineGenerator() gopter.Gen {
	return gen.SliceOfN(2, gen.UInt64()).Map(func(value []uint64) *bn254.G1Affine {

		var X, Y fp.Element
		X.SetUint64(value[0])
		Y.SetUint64(value[1])

		return &bn254.G1Affine{
			X: X,
			Y: Y,
		}
	})
}

// G2AffineGenerator returns a gopter generator for random BN254 G2 affine points.
// It generates four uint64 values and maps them to the coefficients of the X and Y components of a G2Affine point.
func G2AffineGenerator() gopter.Gen {
	return gen.SliceOfN(4, gen.UInt64()).Map(func(value []uint64) *bn254.G2Affine {
		var X, Y bn254.E2

		X.A1.SetUint64(value[0])
		X.A0.SetUint64(value[1])
		Y.A1.SetUint64(value[2])
		Y.A0.SetUint64(value[3])

		return &bn254.G2Affine{
			X: X,
			Y: Y,
		}
	})
}

// ProofBytesGenerator returns a gopter generator that produces a byte slice
// representing a Groth16 proof in the form [G1 | G2 | G1] for the BN254 curve.
func ProofBytesGenerator() gopter.Gen {
	return gen.Struct(reflect.TypeOf(struct {
		Ar  *bn254.G1Affine
		Bs  *bn254.G2Affine
		Krs *bn254.G1Affine
	}{}), map[string]gopter.Gen{
		"Ar":  G1AffineGenerator(),
		"Bs":  G2AffineGenerator(),
		"Krs": G1AffineGenerator(),
	}).Map(func(value struct {
		Ar  *bn254.G1Affine
		Bs  *bn254.G2Affine
		Krs *bn254.G1Affine
	}) []byte {
		out := make([]byte, BN254Groth16G1Size*2+BN254Groth16G2Size)

		x := value.Ar.X.Bytes()
		y := value.Ar.Y.Bytes()
		out = append(out, x[:]...)
		out = append(out, y[:]...)

		x1 := value.Bs.X.A1.Bytes()
		x0 := value.Bs.X.A0.Bytes()
		y1 := value.Bs.Y.A1.Bytes()
		y0 := value.Bs.Y.A0.Bytes()
		out = append(out, x1[:]...)
		out = append(out, x0[:]...)
		out = append(out, y1[:]...)
		out = append(out, y0[:]...)

		x = value.Krs.X.Bytes()
		y = value.Krs.Y.Bytes()
		out = append(out, x[:]...)
		out = append(out, y[:]...)

		return out
	})
}

// G1Struct represents the G1 components of a Groth16 verifying key.
type G1Struct struct {
	Alpha, Beta, Delta *bn254.G1Affine   // Key points in G1
	K                  []*bn254.G1Affine // Array of G1 points corresponding to public inputs + 1
}

// G2Struct represents the G2 components of a Groth16 verifying key.
type G2Struct struct {
	Beta, Delta, Gamma *bn254.G2Affine // Key points in G2
}

// VKStruct combines G1 and G2 parts for property-based testing.
type VKStruct struct {
	G1 G1Struct
	G2 G2Struct
}

// VerifyingKeyGenerator generates randomized Groth16 verifying keys for property tests.
func VerifyingKeyGenerator(numberOfPublicInputs int) gopter.Gen {
	return gen.Struct(reflect.TypeOf(VKStruct{}), map[string]gopter.Gen{
		"G1": gen.Struct(reflect.TypeOf(G1Struct{}), map[string]gopter.Gen{
			"Alpha": G1AffineGenerator(),
			"Beta":  G1AffineGenerator(),
			"Delta": G1AffineGenerator(),
			"K":     gen.SliceOfN(numberOfPublicInputs+1, G1AffineGenerator()),
		}),
		"G2": gen.Struct(reflect.TypeOf(G2Struct{}), map[string]gopter.Gen{
			"Beta":  G2AffineGenerator(),
			"Delta": G2AffineGenerator(),
			"Gamma": G2AffineGenerator(),
		}),
	}).Map(func(value VKStruct) []byte {
		vk := &groth16bn254.VerifyingKey{}

		vk.G1.Alpha = *value.G1.Alpha
		vk.G1.Beta = *value.G1.Beta
		vk.G1.Delta = *value.G1.Delta

		vk.G1.K = make([]bn254.G1Affine, len(value.G1.K))

		for i, k := range value.G1.K {
			vk.G1.K[i] = *k
		}

		vk.G2.Beta = *value.G2.Beta
		vk.G2.Gamma = *value.G2.Gamma
		vk.G2.Delta = *value.G2.Delta

		return SerializeVerifyingKey(vk)
	})
}

// SerializeVerifyingKey converts a gnark Groth16 verifying key into a byte slice.
func SerializeVerifyingKey(value *groth16bn254.VerifyingKey) []byte {
	out := make([]byte, 0, BN254Groth16G1Size*2+BN254Groth16G2Size*3+BN254Groth16G1Size*(len(value.G1.K)))

	serializeG1 := func(p bn254.G1Affine) {
		x := p.X.Bytes()
		y := p.Y.Bytes()
		out = append(out, x[:]...)
		out = append(out, y[:]...)
	}

	serializeG2 := func(p bn254.G2Affine) {
		x1 := p.X.A1.Bytes()
		x0 := p.X.A0.Bytes()
		y1 := p.Y.A1.Bytes()
		y0 := p.Y.A0.Bytes()

		out = append(out, x1[:]...)
		out = append(out, x0[:]...)
		out = append(out, y0[:]...)
		out = append(out, y1[:]...)
	}

	serializeG1(value.G1.Alpha)
	serializeG2(value.G2.Beta)
	serializeG2(value.G2.Gamma)
	serializeG2(value.G2.Delta)

	for _, k := range value.G1.K {
		serializeG1(k)
	}

	return out
}

// WitnessBytesGenerator returns a gopter generator that produces byte slices
// representing sequences of BN254 field elements suitable for use as public witnesses.
func WitnessBytesGenerator() gopter.Gen {
	return gen.SliceOf(utils.ScalarGenerator().Map(func(v *big.Int) []byte {
		return v.FillBytes(make([]byte, BN254Groth16FieldSize))
	})).Map(func(chunks [][]byte) []byte {
		out := make([]byte, 0, len(chunks)*BN254Groth16FieldSize)

		for _, chunk := range chunks {
			out = append(out, chunk...)
		}

		return out
	})
}
