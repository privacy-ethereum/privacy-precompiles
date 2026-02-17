package add

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

func TestBabyJubJubCurveAddName(t *testing.T) {
	precompile := BabyJubJubCurveAdd{}

	expected := "BabyJubJubAdd"
	actual := precompile.Name()

	assert.Equal(t, expected, actual)
}

func TestAddPoints(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expected      *babyjub.Point
		expectedError error
	}{
		{
			name: "normal add",
			input: append(
				utils.MarshalPoint(&babyjub.Point{X: big.NewInt(0), Y: big.NewInt(1)}),
				utils.MarshalPoint(&babyjub.Point{X: big.NewInt(0), Y: big.NewInt(1)})...,
			),
			expected: &babyjub.Point{X: big.NewInt(0), Y: big.NewInt(1)},
		},
		{
			name:          "invalid input length",
			input:         []byte{0x00},
			expectedError: utils.ErrorBabyJubJubInvalidInputLength,
		},
		{
			name: "invalid first point encoding",
			input: append(
				make([]byte, utils.BabyJubJubAffinePointSize),
				make([]byte, utils.BabyJubJubAffinePointSize)...,
			)[:BabyJubJubAddInputSize-1],
			expectedError: utils.ErrorBabyJubJubInvalidInputLength,
		},
		{
			name: "points not on curve",
			input: append(
				utils.MarshalPoint(&babyjub.Point{X: big.NewInt(123), Y: big.NewInt(456)}),
				utils.MarshalPoint(&babyjub.Point{X: big.NewInt(789), Y: big.NewInt(101)})...,
			),
			expectedError: utils.ErrorBabyJubJubPointNotOnCurve,
		},
		{
			name:          "input too short",
			input:         make([]byte, BabyJubJubAddInputSize-1),
			expectedError: utils.ErrorBabyJubJubInvalidInputLength,
		},
		{
			name:          "empty input",
			input:         []byte{},
			expectedError: utils.ErrorBabyJubJubInvalidInputLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			precompile := BabyJubJubCurveAdd{}

			actual, err := precompile.Run(tt.input)
			gas := precompile.RequiredGas(tt.input)

			if tt.expectedError != nil {
				assert.Equal(t, tt.expectedError, err)

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			assert.Equal(t, true, bytes.Equal(actual, utils.MarshalPoint(tt.expected)))
			assert.Equal(t, BabyJubJubAddGas, gas)
		})
	}
}

func TestRunProperties(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("Run returns correct sum of two valid points", prop.ForAll(
		func(p1, p2 *babyjub.Point) bool {
			precompile := BabyJubJubCurveAdd{}

			input := append(utils.MarshalPoint(p1), utils.MarshalPoint(p2)...)
			result, err := precompile.Run(input)

			if err != nil {
				return false
			}

			expected := babyjub.NewPoint().Projective().Add(p1.Projective(), p2.Projective()).Affine()

			return bytes.Equal(result, utils.MarshalPoint(expected))
		},
		utils.BabyJubJubPointGenerator(),
		utils.BabyJubJubPointGenerator(),
	))

	properties.TestingRun(t)
}
