package validation

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

func TestBabyJubJubCurveValidatePointName(t *testing.T) {
	precompile := BabyJubJubCurveValidatePoint{}

	expected := "BabyJubJubCurveValidatePoint"

	assert.Equal(t, expected, precompile.Name())
}

func TestValidatePoint(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expected      []byte
		expectedError error
	}{
		{
			name:     "valid point",
			input:    utils.MarshalPoint(babyjub.NewPoint()),
			expected: []byte{1},
		},
		{
			name:          "empty input",
			input:         []byte{},
			expectedError: utils.ErrorBabyJubJubCurveInvalidInputLength,
		},
		{
			name:          "invalid point",
			input:         utils.MarshalPoint(babyjub.B8)[:BabyJubJubCurveValidatePointInputSize-1],
			expectedError: utils.ErrorBabyJubJubCurveInvalidInputLength,
		},
		{
			name:     "valid base point",
			input:    utils.MarshalPoint(babyjub.B8),
			expected: []byte{1},
		},
		{
			name: "valid random point",
			input: utils.MarshalPoint(
				babyjub.NewPoint().Mul(
					big.NewInt(12345),
					babyjub.B8,
				),
			),
			expected: []byte{1},
		},
		{
			name: "all-zero point",
			input: func() []byte {
				zero := &babyjub.Point{X: big.NewInt(0), Y: big.NewInt(0)}
				return utils.MarshalPoint(zero)
			}(),
			expected: []byte{0},
		},
		{
			name:     "point is not on curve",
			input:    utils.MarshalPoint(&babyjub.Point{X: big.NewInt(123), Y: big.NewInt(456)}),
			expected: []byte{0},
		},
		{
			name: "point is not in subgroup",
			input: func() []byte {
				point := &babyjub.Point{
					X: big.NewInt(0),
					Y: new(big.Int).Sub(utils.FieldPrime, big.NewInt(1)), // p - 1 == -1 mod p
				}

				return utils.MarshalPoint(point)
			}(),
			expected: []byte{0},
		},
		{
			name: "max field values (invalid point)",
			input: func() []byte {
				max := big.NewInt(0).Sub(babyjub.Order, big.NewInt(1))
				p := &babyjub.Point{X: max, Y: max}

				return utils.MarshalPoint(p)
			}(),
			expected: []byte{0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			precompile := BabyJubJubCurveValidatePoint{}

			actual, err := precompile.Run(tt.input)
			gas := precompile.RequiredGas(tt.input)

			if tt.expectedError != nil {
				assert.NotNil(t, err)
				assert.Equal(t, tt.expectedError, err)

				return
			}

			assert.Nil(t, err)
			assert.Equal(t, BabyJubJubCurveValidatePointGas, gas)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestRunProperties(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("Run returns correct validation result for valid point", prop.ForAll(
		func(point *babyjub.Point) bool {
			precompile := BabyJubJubCurveValidatePoint{}

			result, err := precompile.Run(utils.MarshalPoint(point))

			if err != nil {
				return false
			}

			return bytes.Equal(result, []byte{1})
		},
		utils.BabyJubJubPointGenerator(),
	))

	properties.TestingRun(t)
}
