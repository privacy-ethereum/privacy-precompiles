package poseidon

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/privacy-ethereum/privacy-precompiles/babyjubjub/utils"
	"github.com/stretchr/testify/assert"
)

func TestBabyJubJubCurveMulName(t *testing.T) {
	precompile := Poseidon{}

	expected := "Poseidon"
	actual := precompile.Name()

	assert.Equal(t, expected, actual)
}

func TestPoseidonHash(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expected      []byte
		expectedGas   uint64
		expectedError error
	}{
		{
			name:        "normal poseidon hash",
			input:       make([]byte, PoseidonInputWordSize),
			expected:    []byte{42, 9, 169, 253, 147, 197, 144, 194, 107, 145, 239, 251, 178, 73, 159, 7, 232, 247, 170, 18, 226, 180, 148, 10, 58, 237, 36, 17, 203, 101, 225, 28},
			expectedGas: PoseidonBaseGas + PoseidonPerWordGas,
		},
		{
			name:          "poseidon hash of empty input",
			input:         []byte{},
			expectedError: ErrorPoseidonInvalidInputLength,
		},
		{
			name:          "poseidon hash invalid input length",
			input:         make([]byte, PoseidonInputWordSize-1),
			expectedError: ErrorPoseidonInvalidInputLength,
		},
		{
			name:          "poseidon hash of invalid",
			input:         make([]byte, PoseidonInputWordSize*(PoseidonMaxParams+1)),
			expectedError: ErrorPoseidonInvalidInputLength,
		},
		{
			name: "poseidon hash max field value",
			input: []byte{
				0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
				0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
				0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
				0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
			},
			expectedError: errors.New("inputs values not inside Finite Field"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			precompile := Poseidon{}

			actual, err := precompile.Run(tt.input)
			gas := precompile.RequiredGas(tt.input)

			if tt.expectedError != nil {
				assert.NotNil(t, err)
				assert.Equal(t, tt.expectedError, err)

				return
			}

			assert.Nil(t, err)
			assert.Equal(t, tt.expected, actual)
			assert.Equal(t, tt.expectedGas, gas)
		})
	}
}

func TestRunProperties(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("Run returns correct deterministic poseidon hash for valid field elements", prop.ForAll(
		func(scalars []*big.Int) bool {
			if len(scalars) == 0 || len(scalars) > PoseidonMaxParams {
				return true
			}

			precompile := Poseidon{}
			input := prepareInput(scalars)

			result1, err1 := precompile.Run(input)
			result2, err2 := precompile.Run(input)

			if err1 != nil || err2 != nil {
				return false
			}

			return bytes.Equal(result1, result2)
		},
		gen.SliceOf(utils.ScalarGenerator()),
	))

	properties.Property("Run returns correct poseidon hash for chaining poseidon hash", prop.ForAll(
		func(scalars []*big.Int) bool {
			if len(scalars) == 0 || len(scalars) > PoseidonMaxParams {
				return true
			}

			precompile := Poseidon{}
			input := prepareInput(scalars)

			result1, err1 := precompile.Run(input)
			result2, err2 := precompile.Run(result1)

			if err1 != nil || err2 != nil {
				return false
			}

			return !bytes.Equal(result1, result2)
		},
		gen.SliceOf(utils.ScalarGenerator()),
	))

	properties.Property(
		"Gas increases with word count",
		prop.ForAll(
			func(words uint8) bool {
				if words == 0 {
					return true
				}

				precompile := Poseidon{}
				input := make([]byte, int(words)*PoseidonInputWordSize)

				gas := precompile.RequiredGas(input)

				expected :=
					uint64(words)*PoseidonPerWordGas +
						PoseidonBaseGas

				return gas == expected
			},
			gen.UInt8(),
		),
	)

	properties.TestingRun(t)
}

func prepareInput(scalars []*big.Int) []byte {
	input := make([]byte, 0, len(scalars)*PoseidonInputWordSize)

	for _, scalar := range scalars {
		buffer := make([]byte, PoseidonInputWordSize)
		scalar.FillBytes(buffer)
		input = append(input, buffer...)
	}

	return input
}
