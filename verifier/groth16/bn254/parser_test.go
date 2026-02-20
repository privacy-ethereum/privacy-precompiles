package bn254

import (
	"bytes"
	"errors"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/privacy-ethereum/privacy-precompiles/babyjubjub/utils"
	"github.com/privacy-ethereum/privacy-precompiles/common"
	"github.com/stretchr/testify/assert"
)

func TestParseG1(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		offset         int
		expectedPoint  *bn254.G1Affine
		expectedOffset int
		expectedError  error
	}{
		{
			name:           "normal g1 parse",
			data:           utils.MarshalPoint(babyjub.NewPoint()),
			offset:         0,
			expectedOffset: BN254Groth16G1Size,
			expectedPoint: func() *bn254.G1Affine {
				point := &bn254.G1Affine{}
				_, _ = point.X.SetString("0")
				_, _ = point.Y.SetString("1")

				return point
			}(),
		},
		{
			name:           "normal g1 parse with offset",
			data:           append(utils.MarshalPoint(babyjub.NewPoint()), utils.MarshalPoint(babyjub.NewPoint())...),
			offset:         BN254Groth16G1Size,
			expectedOffset: 2 * BN254Groth16G1Size,
			expectedPoint: func() *bn254.G1Affine {
				point := &bn254.G1Affine{}
				_, _ = point.X.SetString("0")
				_, _ = point.Y.SetString("1")

				return point
			}(),
		},
		{
			name:           "invalid g1 parse for first part",
			data:           []byte{},
			offset:         0,
			expectedOffset: 0,
			expectedError:  common.ErrorInvalidG1,
		},
		{
			name:           "invalid g1 parse for second part",
			data:           make([]byte, BN254Groth16FieldSize),
			offset:         0,
			expectedOffset: 0,
			expectedError:  common.ErrorInvalidG1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			destination := &bn254.G1Affine{}
			offset, err := ParseG1(tt.data, tt.offset, destination)

			if tt.expectedError != nil {
				assert.NotNil(t, err)
				assert.Equal(t, tt.expectedError, err)

				return
			}

			assert.Nil(t, err)
			assert.Equal(t, tt.expectedOffset, offset)
			assert.Equal(t, tt.expectedPoint, destination)
		})
	}
}

func TestParseG1Properties(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("ParseG1 returns correct G1 affine point", prop.ForAll(
		func(point *bn254.G1Affine) bool {
			destination := bn254.G1Affine{}
			data := point.Marshal()

			result, err := ParseG1(data, 0, &destination)

			if err != nil {
				return false
			}

			return result == BN254Groth16G1Size && bytes.Equal(data, destination.Marshal())
		},
		G1AffineGenerator(),
	))

	properties.TestingRun(t)
}

func TestParseG2(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		offset         int
		expectedPoint  *bn254.G2Affine
		expectedOffset int
		expectedError  error
	}{
		{
			name:           "normal g2 parse",
			data:           append(utils.MarshalPoint(babyjub.NewPoint()), utils.MarshalPoint(babyjub.NewPoint())...),
			offset:         0,
			expectedOffset: BN254Groth16G2Size,
			expectedPoint: func() *bn254.G2Affine {
				point := &bn254.G2Affine{}
				_, _ = point.X.A1.SetString("0")
				_, _ = point.X.A0.SetString("1")
				_, _ = point.Y.A1.SetString("0")
				_, _ = point.Y.A0.SetString("1")

				return point
			}(),
		},
		{
			name: "normal g2 parse with offset",
			data: append(
				append(
					utils.MarshalPoint(babyjub.NewPoint()),
					utils.MarshalPoint(babyjub.NewPoint())...,
				),
				append(
					utils.MarshalPoint(babyjub.NewPoint()),
					utils.MarshalPoint(babyjub.NewPoint())...,
				)...,
			),
			offset:         BN254Groth16G2Size,
			expectedOffset: 2 * BN254Groth16G2Size,
			expectedPoint: func() *bn254.G2Affine {
				point := &bn254.G2Affine{}
				_, _ = point.X.A1.SetString("0")
				_, _ = point.X.A0.SetString("1")
				_, _ = point.Y.A1.SetString("0")
				_, _ = point.Y.A0.SetString("1")

				return point
			}(),
		},
		{
			name:           "invalid g2 parse for first part",
			data:           []byte{},
			offset:         0,
			expectedOffset: 0,
			expectedError:  common.ErrorInvalidG2,
		},
		{
			name:           "invalid g2 parse for second part",
			data:           make([]byte, BN254Groth16FieldSize),
			offset:         0,
			expectedOffset: 0,
			expectedError:  common.ErrorInvalidG2,
		},
		{
			name:           "invalid g2 parse for third part",
			data:           make([]byte, 2*BN254Groth16FieldSize),
			offset:         0,
			expectedOffset: 0,
			expectedError:  common.ErrorInvalidG2,
		},
		{
			name:           "invalid g2 parse for last part",
			data:           make([]byte, 3*BN254Groth16FieldSize),
			offset:         0,
			expectedOffset: 0,
			expectedError:  common.ErrorInvalidG2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			destination := &bn254.G2Affine{}
			offset, err := ParseG2(tt.data, tt.offset, destination)

			if tt.expectedError != nil {
				assert.NotNil(t, err)
				assert.Equal(t, tt.expectedError, err)

				return
			}

			assert.Nil(t, err)
			assert.Equal(t, tt.expectedOffset, offset)
			assert.Equal(t, tt.expectedPoint, destination)
		})
	}
}

func TestParseG2Properties(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("ParseG2 returns correct G2 affine point", prop.ForAll(
		func(point *bn254.G2Affine) bool {
			destination := bn254.G2Affine{}
			data := point.Marshal()
			result, err := ParseG2(data, 0, &destination)

			if err != nil {
				return false
			}

			return result == BN254Groth16G2Size && bytes.Equal(data, destination.Marshal())
		},
		G2AffineGenerator(),
	))

	properties.TestingRun(t)
}

func TestParseProof(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		expected      groth16.Proof
		expectedError error
	}{
		{
			name: "normal proof parse",
			data: func() []byte {
				points := make([]byte, 0)
				for i := 0; i < 4; i++ {
					points = append(points, utils.MarshalPoint(babyjub.NewPoint())...)
				}

				return points
			}(),
			expected: func() groth16.Proof {
				var proof groth16bn254.Proof

				_, _ = ParseG1(utils.MarshalPoint(babyjub.NewPoint()), 0, &proof.Ar)
				_, _ = ParseG2(append(utils.MarshalPoint(babyjub.NewPoint()), utils.MarshalPoint(babyjub.NewPoint())...), 0, &proof.Bs)
				_, _ = ParseG1(utils.MarshalPoint(babyjub.NewPoint()), 0, &proof.Krs)

				return &proof
			}(),
		},
		{
			name:          "invalid proof parse (Ar)",
			data:          []byte{},
			expectedError: errors.New("invalid G1 point"),
		},
		{
			name:          "invalid proof parse (Bs)",
			data:          utils.MarshalPoint(babyjub.NewPoint()),
			expectedError: errors.New("invalid G2 point"),
		},
		{
			name: "invalid proof parse (Krs)",
			data: func() []byte {
				points := make([]byte, 0)
				for i := 0; i < 3; i++ {
					points = append(points, utils.MarshalPoint(babyjub.NewPoint())...)
				}

				return points
			}(),
			expectedError: errors.New("invalid G1 point"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := SolidityBN254Parser{}
			proof, err := parser.ParseProof(tt.data)

			if tt.expectedError != nil {
				assert.NotNil(t, err)
				assert.Equal(t, tt.expectedError, err)

				return
			}

			assert.Nil(t, err)
			assert.Equal(t, tt.expected, proof)
		})
	}
}

func TestParseProofProperties(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("ParseProof returns correct Groth16 proof", prop.ForAll(
		func(input []byte) bool {
			parser := SolidityBN254Parser{}

			proof1, err := parser.ParseProof(input)

			if err != nil {
				return false
			}

			serialized1 := proof1.(*groth16bn254.Proof).MarshalSolidity()
			proof2, err := parser.ParseProof(serialized1)

			if err != nil {
				return false
			}

			serialized2 := proof2.(*groth16bn254.Proof).MarshalSolidity()

			return bytes.Equal(serialized1, serialized2)
		},
		ProofBytesGenerator(),
	))

	properties.TestingRun(t)
}

func TestParseVerifyingKey(t *testing.T) {
	tests := []struct {
		name                 string
		data                 []byte
		numberOfPublicInputs int
		expected             groth16.VerifyingKey
		expectedError        error
	}{
		{
			name: "normal verifying key parse",
			data: func() []byte {
				points := make([]byte, 0)
				for i := 0; i < 9; i++ {
					points = append(points, utils.MarshalPoint(babyjub.NewPoint())...)
				}

				return points
			}(),
			numberOfPublicInputs: 1,
			expected: func() groth16.VerifyingKey {
				var vk groth16bn254.VerifyingKey

				_, _ = ParseG1(utils.MarshalPoint(babyjub.NewPoint()), 0, &vk.G1.Alpha)
				_, _ = ParseG2(append(utils.MarshalPoint(babyjub.NewPoint()), utils.MarshalPoint(babyjub.NewPoint())...), 0, &vk.G2.Beta)
				_, _ = ParseG2(append(utils.MarshalPoint(babyjub.NewPoint()), utils.MarshalPoint(babyjub.NewPoint())...), 0, &vk.G2.Gamma)
				_, _ = ParseG2(append(utils.MarshalPoint(babyjub.NewPoint()), utils.MarshalPoint(babyjub.NewPoint())...), 0, &vk.G2.Delta)

				vk.G1.K = make([]bn254.G1Affine, 2)

				for index := range vk.G1.K {
					_, _ = ParseG1(utils.MarshalPoint(babyjub.NewPoint()), 0, &vk.G1.K[index])
				}

				_ = vk.Precompute()

				return &vk
			}(),
		},
		{
			name: "verifying key parse with zero public inputs",
			data: func() []byte {
				points := make([]byte, 0)
				for i := 0; i < 8; i++ {
					points = append(points, utils.MarshalPoint(babyjub.NewPoint())...)
				}

				return points
			}(),
			numberOfPublicInputs: 0,
			expected: func() groth16.VerifyingKey {
				var vk groth16bn254.VerifyingKey

				_, _ = ParseG1(utils.MarshalPoint(babyjub.NewPoint()), 0, &vk.G1.Alpha)
				_, _ = ParseG2(append(utils.MarshalPoint(babyjub.NewPoint()), utils.MarshalPoint(babyjub.NewPoint())...), 0, &vk.G2.Beta)
				_, _ = ParseG2(append(utils.MarshalPoint(babyjub.NewPoint()), utils.MarshalPoint(babyjub.NewPoint())...), 0, &vk.G2.Gamma)
				_, _ = ParseG2(append(utils.MarshalPoint(babyjub.NewPoint()), utils.MarshalPoint(babyjub.NewPoint())...), 0, &vk.G2.Delta)

				vk.G1.K = make([]bn254.G1Affine, 1)

				for index := range vk.G1.K {
					_, _ = ParseG1(utils.MarshalPoint(babyjub.NewPoint()), 0, &vk.G1.K[index])
				}

				_ = vk.Precompute()

				return &vk
			}(),
		},
		{
			name:                 "invalid verifying key parse with empty data",
			data:                 []byte{},
			numberOfPublicInputs: 1,
			expectedError:        common.ErrorInvalidG1,
		},
		{
			name: "invalid verifying key parse with empty beta point",
			data: func() []byte {
				points := make([]byte, 0)
				for i := 0; i < 1; i++ {
					points = append(points, utils.MarshalPoint(babyjub.NewPoint())...)
				}

				return points
			}(),
			numberOfPublicInputs: 1,
			expectedError:        common.ErrorInvalidG2,
		},
		{
			name: "invalid verifying key parse with empty gamma point",
			data: func() []byte {
				points := make([]byte, 0)
				for i := 0; i < 3; i++ {
					points = append(points, utils.MarshalPoint(babyjub.NewPoint())...)
				}

				return points
			}(),
			numberOfPublicInputs: 1,
			expectedError:        common.ErrorInvalidG2,
		},
		{
			name: "invalid verifying key parse with empty delta point",
			data: func() []byte {
				points := make([]byte, 0)
				for i := 0; i < 5; i++ {
					points = append(points, utils.MarshalPoint(babyjub.NewPoint())...)
				}

				return points
			}(),
			numberOfPublicInputs: 1,
			expectedError:        common.ErrorInvalidG2,
		},
		{
			name: "invalid verifying key parse with empty k point",
			data: func() []byte {
				points := make([]byte, 0)
				for i := 0; i < 8; i++ {
					points = append(points, utils.MarshalPoint(babyjub.NewPoint())...)
				}

				return points
			}(),
			numberOfPublicInputs: 1,
			expectedError:        common.ErrorInvalidG1,
		},
		{
			name: "invalid verifying key parse with greater number of public inputs",
			data: func() []byte {
				points := make([]byte, 0)
				for i := 0; i < 9; i++ {
					points = append(points, utils.MarshalPoint(babyjub.NewPoint())...)
				}

				return points
			}(),
			numberOfPublicInputs: 2,
			expectedError:        common.ErrorInvalidG1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := SolidityBN254Parser{}
			proof, err := parser.ParseVerifyingKey(tt.data, tt.numberOfPublicInputs)

			if tt.expectedError != nil {
				assert.NotNil(t, err)
				assert.Equal(t, tt.expectedError, err)

				return
			}

			assert.Nil(t, err)
			assert.Equal(t, tt.expected, proof)
		})
	}
}

func TestParseVerifyingKeyProperties(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)
	max := 64

	for index := range max {
		properties.Property("ParseVerifyingKey returns correct verifying key", prop.ForAll(
			func(input []byte) bool {
				parser := SolidityBN254Parser{}

				verifyingKey1, err := parser.ParseVerifyingKey(input, index)

				if err != nil {
					return false
				}

				serialized1 := SerializeVerifyingKey(verifyingKey1.(*groth16bn254.VerifyingKey))
				verifyingKey2, err := parser.ParseVerifyingKey(serialized1, index)

				if err != nil {
					return false
				}

				return !verifyingKey1.IsDifferent(verifyingKey2)
			},
			VerifyingKeyGenerator(index),
		))
	}

	properties.TestingRun(t)
}

func TestParsePublicWitness(t *testing.T) {
	tests := []struct {
		name                 string
		data                 []byte
		numberOfPublicInputs int
		witness              witness.Witness
		expectedError        error
	}{
		{
			name:                 "normal public witness parse",
			data:                 make([]byte, BN254Groth16FieldSize),
			numberOfPublicInputs: 1,
			witness: func() witness.Witness {
				w, _ := witness.New(ecc.BN254.ScalarField())

				data := append(
					[]byte{
						0, 0, 0, 1, // nbPublic
						0, 0, 0, 0, // nbSecret
						0, 0, 0, 1, // vector length
					},
					make([]byte, BN254Groth16FieldSize)..., // 32-byte zero field element
				)

				_ = w.UnmarshalBinary(data)

				return w
			}(),
		},
		{
			name:                 "public witness parse with zero public inputs",
			data:                 []byte{},
			numberOfPublicInputs: 0,
			witness: func() witness.Witness {
				w, _ := witness.New(ecc.BN254.ScalarField())

				data := []byte{
					0, 0, 0, 0, // nbPublic
					0, 0, 0, 0, // nbSecret
					0, 0, 0, 0, // vector length
				}

				_ = w.UnmarshalBinary(data)

				return w
			}(),
		},
		{
			name:                 "invalid public witness parse with greater number of public inputs",
			data:                 make([]byte, BN254Groth16FieldSize),
			numberOfPublicInputs: 2,
			expectedError:        errors.New("invalid slice"),
		},
		{
			name:                 "invalid public witness parse with empty input",
			data:                 []byte{},
			numberOfPublicInputs: 1,
			expectedError:        errors.New("invalid slice"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := SolidityBN254Parser{}
			result, err := parser.ParsePublicWitness(tt.data, tt.numberOfPublicInputs)

			if tt.expectedError != nil {
				assert.NotNil(t, err)
				assert.Equal(t, tt.expectedError, err)

				return
			}

			assert.Nil(t, err)
			assert.Equal(t, tt.witness, result)
		})
	}
}

func TestParsePublicWitnessProperties(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("ParsePublicWitness returns correct public witness", prop.ForAll(
		func(input []byte) bool {
			if len(input) == 0 || len(input)%BN254Groth16FieldSize != 0 {
				return true
			}

			parser := SolidityBN254Parser{}

			result, err := parser.ParsePublicWitness(input, len(input)/BN254Groth16FieldSize)

			if err != nil {
				return false
			}

			parsed, err := result.MarshalBinary()

			if err != nil {
				return false
			}

			return bytes.Equal(input, parsed[12:])
		},
		WitnessBytesGenerator(),
	))

	properties.TestingRun(t)
}
