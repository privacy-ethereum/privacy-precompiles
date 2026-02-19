package eddsa

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

func TestBabyJubJubEdDSAName(t *testing.T) {
	precompile := BabyJubJubCurveEdDSAVerify{}

	expected := "BabyJubJubEdDSAVerify"
	actual := precompile.Name()

	assert.Equal(t, expected, actual)
}

func TestEdDSAVerify(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expected      []byte
		expectedError error
	}{
		{
			name:     "valid signature",
			input:    prepareInput(),
			expected: []byte{1},
		},
		{
			name: "invalid signature",
			input: func() []byte {
				input := prepareInput()
				input[len(input)-1] ^= 0x01

				return input
			}(),
			expected: []byte{0},
		},
		{
			name:          "empty input",
			input:         []byte{},
			expectedError: ErrorBabyJubJubCurveEdDSAVerifyInvalidInputLength,
		},
		{
			name:          "invalid input length",
			input:         prepareInput()[1:],
			expectedError: ErrorBabyJubJubCurveEdDSAVerifyInvalidInputLength,
		},
		{
			name: "invalid public key",
			input: func() []byte {
				input := prepareInput()

				mock := make([]byte, utils.BabyJubJubCurveFieldByteSize)
				start := 0
				end := start + utils.BabyJubJubCurveFieldByteSize

				copy(input[start:end], mock)
				copy(input[end:end+utils.BabyJubJubCurveFieldByteSize], mock)

				return input
			}(),
			expectedError: ErrorBabyJubJubCurveEdDSAVerifyPublicKeyIsNotOnCurve,
		},
		{
			name: "invalid R8 point (not on curve)",
			input: func() []byte {
				input := prepareInput()

				mock := make([]byte, utils.BabyJubJubCurveFieldByteSize)
				start := utils.BabyJubJubCurveAffinePointSize
				end := start + utils.BabyJubJubCurveFieldByteSize

				copy(input[start:end], mock)
				copy(input[end:end+utils.BabyJubJubCurveFieldByteSize], mock)

				return input
			}(),
			expectedError: ErrorBabyJubJubCurveEdDSAVerifyR8IsNotOnCurve,
		},
		{
			name: "invalid R8 point (not in subgroup)",
			input: func() []byte {
				input := prepareInput()
				pointBytes := utils.MarshalPoint(&babyjub.Point{
					X: big.NewInt(0),
					Y: new(big.Int).Sub(utils.FieldPrime, big.NewInt(1)), // p - 1 == -1 mod p
				})
				start := utils.BabyJubJubCurveAffinePointSize
				end := start + utils.BabyJubJubCurveFieldByteSize

				copy(input[start:end], pointBytes)
				copy(input[end:end+utils.BabyJubJubCurveFieldByteSize], pointBytes)

				return input
			}(),
			expectedError: ErrorBabyJubJubCurveEdDSAVerifyR8IsNotOnCurve,
		},
		{
			name: "invalid S",
			input: func() []byte {
				input := prepareInput()

				start := utils.BabyJubJubCurveAffinePointSize + 2*utils.BabyJubJubCurveFieldByteSize
				end := start + utils.BabyJubJubCurveFieldByteSize

				copy(input[start:end], babyjub.SubOrder.Bytes())

				return input
			}(),
			expectedError: ErrorBabyJubJubCurveEdDSAVerifyInvalidS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			precompile := BabyJubJubCurveEdDSAVerify{}

			actual, err := precompile.Run(tt.input)
			gas := precompile.RequiredGas(tt.input)

			if tt.expectedError != nil {
				assert.NotNil(t, err)
				assert.Equal(t, tt.expectedError, err)

				return
			}

			assert.Nil(t, err)
			assert.Equal(t, BabyJubJubCurveEdDSAVerifyGas, gas)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestRunProperties(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("Run returns correct signature verification result", prop.ForAll(
		func(privateKey *babyjub.PrivateKey, R8 *babyjub.Point, scalar, message *big.Int) bool {
			precompile := BabyJubJubCurveEdDSAVerify{}

			publicKey := privateKey.Public()
			signature := privateKey.SignPoseidon(message)
			input := packedInput(publicKey, signature, message)

			result, err := precompile.Run(input)

			if err != nil {
				return false
			}

			return bytes.Equal(result, []byte{1})
		},
		utils.PrivateKeyGenerator(),
		utils.BabyJubJubPointGenerator(),
		utils.ScalarGenerator(),
		utils.ScalarGenerator(),
	))
}

func prepareInput() []byte {
	privateKey := func() babyjub.PrivateKey {
		var key babyjub.PrivateKey
		big.NewInt(1234).FillBytes(key[:])

		return key
	}()

	message := big.NewInt(1234)
	publicKey := privateKey.Public()
	signature := privateKey.SignPoseidon(message)

	return packedInput(publicKey, signature, message)
}

func packedInput(publicKey *babyjub.PublicKey, signature *babyjub.Signature, message *big.Int) []byte {
	publicKeyBytes := append(
		publicKey.X.Bytes(),
		publicKey.Y.Bytes()...,
	)
	r8Bytes := utils.MarshalPoint(signature.R8)
	sBytes := signature.S.Bytes()
	messageBytes := message.FillBytes(make([]byte, utils.BabyJubJubCurveFieldByteSize))

	return append(
		append(append(publicKeyBytes, r8Bytes...), sBytes...),
		messageBytes...,
	)
}
