package mul

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/privacy-ethereum/privacy-precompiles/babyjubjub/utils"
	"github.com/stretchr/testify/assert"
)

func TestBabyJubJubCurveMulName(t *testing.T) {
	precompile := BabyJubJubCurveMul{}

	expected := "BabyJubJubMul"
	actual := precompile.Name()

	assert.Equal(t, expected, actual)
}

func TestScalarMul(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expected      *babyjub.Point
		expectedError error
	}{
		{
			name: "B8 scalar multiplication with 0",
			input: append(
				utils.MarshalPoint(babyjub.B8),
				big.NewInt(0).FillBytes(make([]byte, utils.BabyJubJubFieldByteSize))...,
			),
			expected: babyjub.NewPoint(),
		},
		{
			name: "B8 scalar multiplication with 1",
			input: append(
				utils.MarshalPoint(babyjub.B8),
				big.NewInt(1).FillBytes(make([]byte, utils.BabyJubJubFieldByteSize))...,
			),
			expected: &babyjub.Point{X: babyjub.B8.X, Y: babyjub.B8.Y},
		},
		{
			name: "B8 scalar multiplication with non-zero scalar",
			input: append(
				utils.MarshalPoint(babyjub.B8),
				big.NewInt(1234).FillBytes(make([]byte, utils.BabyJubJubFieldByteSize))...,
			),
			expected: &babyjub.Point{
				X: func() *big.Int {
					x := new(big.Int)
					x.SetString("4880901335776166390443888589907570248644423541468541082967598048550539024543", 10)

					return x
				}(),

				Y: func() *big.Int {
					y := new(big.Int)
					y.SetString("6509666988291764283313685078036329297907336602650572952945826675203643401307", 10)

					return y
				}(),
			},
		},
		{
			name:          "invalid input length",
			input:         []byte{0x00},
			expectedError: utils.ErrorBabyJubJubInvalidInputLength,
		},
		{
			name: "invalid point encoding",
			input: append(
				utils.MarshalPoint(babyjub.B8),
				big.NewInt(0).FillBytes(make([]byte, utils.BabyJubJubFieldByteSize))...,
			)[:BabyJubJubMulInputSize-1],
			expectedError: utils.ErrorBabyJubJubInvalidInputLength,
		},
		{
			name: "point is not on curve",
			input: append(
				utils.MarshalPoint(&babyjub.Point{X: big.NewInt(123), Y: big.NewInt(456)}),
				big.NewInt(9000).FillBytes(make([]byte, utils.BabyJubJubFieldByteSize))...,
			),
			expectedError: utils.ErrorBabyJubJubPointNotOnCurve,
		},
		{
			name:          "empty input",
			input:         []byte{},
			expectedError: utils.ErrorBabyJubJubInvalidInputLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			precompile := BabyJubJubCurveMul{}

			actual, err := precompile.Run(tt.input)
			gas := precompile.RequiredGas(tt.input)

			if tt.expectedError != nil {
				assert.NotNil(t, err)
				assert.Equal(t, tt.expectedError, err)

				return
			}

			assert.Nil(t, err)

			point, err := utils.UnmarshalPoint(actual)

			assert.Nil(t, err)
			assert.Equal(t, BabyJubJubMulGas, gas)
			assert.Equal(t, true, point.X.Cmp(tt.expected.X) == 0 && point.Y.Cmp(tt.expected.Y) == 0)
		})
	}
}

func TestRunProperties(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("Run returns correct scalar multiplication for valid point and random scalar", prop.ForAll(
		func(point *babyjub.Point, scalar *big.Int) bool {
			precompile := BabyJubJubCurveMul{}

			input := append(utils.MarshalPoint(point), scalar.FillBytes(make([]byte, utils.BabyJubJubFieldByteSize))...)
			result, err := precompile.Run(input)

			if err != nil {
				return false
			}

			expected := point.Mul(scalar, point)

			return bytes.Equal(result, utils.MarshalPoint(expected))
		},
		utils.BabyJubJubPointGenerator(),
		utils.ScalarGenerator(),
	))

	properties.TestingRun(t)
}
