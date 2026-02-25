package groth16

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/privacy-ethereum/privacy-precompiles/verifier/groth16/bn254"
	"github.com/stretchr/testify/assert"
)

type onePublicInputCircuit struct {
	X frontend.Variable `gnark:",public"`
}

type twoPublicInputCircuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
}

type invalidProofParser struct{}

func (c *invalidProofParser) ParseProof(data []byte) (groth16.Proof, error) {
	return nil, ErrorGroth16VerifyInvalidProof
}

func (c *invalidProofParser) ParseVerifyingKey(data []byte, numberOfPublicInputs int) (groth16.VerifyingKey, error) {
	return nil, nil
}

func (c *invalidProofParser) ParsePublicWitness(data []byte, numberOfPublicInputs int) (witness.Witness, error) {
	return nil, nil
}

type invalidVerifyingKeyParser struct{}

func (c *invalidVerifyingKeyParser) ParseProof(data []byte) (groth16.Proof, error) {
	return nil, nil
}

func (c *invalidVerifyingKeyParser) ParseVerifyingKey(data []byte, numberOfPublicInputs int) (groth16.VerifyingKey, error) {
	return nil, ErrorGroth16VerifyInvalidVerifyingKey
}

func (c *invalidVerifyingKeyParser) ParsePublicWitness(data []byte, numberOfPublicInputs int) (witness.Witness, error) {
	return nil, nil
}

type invalidPublicWitnessParser struct{}

func (c *invalidPublicWitnessParser) ParseProof(data []byte) (groth16.Proof, error) {
	return nil, nil
}

func (c *invalidPublicWitnessParser) ParseVerifyingKey(data []byte, numberOfPublicInputs int) (groth16.VerifyingKey, error) {
	return nil, nil
}

func (c *invalidPublicWitnessParser) ParsePublicWitness(data []byte, numberOfPublicInputs int) (witness.Witness, error) {
	return nil, ErrorGroth16VerifyInvalidPublicWitness
}

type panicParser struct{}

func (c *panicParser) ParseProof(data []byte) (groth16.Proof, error) {
	panic("ParseProof called")
}

func (c *panicParser) ParseVerifyingKey(data []byte, numberOfPublicInputs int) (groth16.VerifyingKey, error) {
	return nil, nil
}

func (c *panicParser) ParsePublicWitness(data []byte, numberOfPublicInputs int) (witness.Witness, error) {
	return nil, nil
}

func (c *onePublicInputCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, 1)

	return nil
}

func (c *twoPublicInputCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, 1)
	api.AssertIsEqual(c.Y, 2)

	return nil
}

const (
	defaultMinSize = bn254.BN254Groth16ProofSize + bn254.BN254Groth16VerifyVerifyingKeySize + 2*bn254.BN254Groth16G1Size + bn254.BN254Groth16FieldSize
)

func TestGroth16Name(t *testing.T) {
	precompile := NewGroth16BN254Verify()

	expected := "bn254Groth16Verify"
	actual := precompile.Name()

	assert.Equal(t, expected, actual)
}

func TestGroth16UnsupportedCurve(t *testing.T) {
	parser := SolidityProofParsers[ecc.BN254]
	precompile := newGroth16Verify(ecc.BLS12_377, parser)

	result, err := precompile.Run([]byte{})
	gas := precompile.RequiredGas([]byte{})

	assert.Nil(t, result)
	assert.Equal(t, ErrorGroth16VerifyUnsupportedCurve, err)
	assert.Equal(t, uint64(0), gas)
}

func TestGroth16InvalidProofParse(t *testing.T) {
	parser := &invalidProofParser{}
	precompile := newGroth16Verify(ecc.BN254, parser)

	result, err := precompile.Run(make([]byte, defaultMinSize))

	assert.Nil(t, result)
	assert.Equal(t, ErrorGroth16VerifyInvalidProof, err)
}

func TestGroth16InvalidVerifyingKeyParse(t *testing.T) {
	parser := &invalidVerifyingKeyParser{}
	precompile := newGroth16Verify(ecc.BN254, parser)

	result, err := precompile.Run(make([]byte, defaultMinSize))

	assert.Nil(t, result)
	assert.Equal(t, ErrorGroth16VerifyInvalidVerifyingKey, err)
}

func TestGroth16InvalidPublicWitnessParse(t *testing.T) {
	parser := &invalidPublicWitnessParser{}
	precompile := newGroth16Verify(ecc.BN254, parser)

	result, err := precompile.Run(make([]byte, defaultMinSize))

	assert.Nil(t, result)
	assert.Equal(t, ErrorGroth16VerifyInvalidPublicWitness, err)
}

func TestGroth16Panic(t *testing.T) {
	parser := &panicParser{}
	precompile := newGroth16Verify(ecc.BN254, parser)

	result, err := precompile.Run(make([]byte, defaultMinSize))

	assert.Nil(t, result)
	assert.Equal(t, ErrorPanicGroth16Verify, err)
}

func TestGroth16(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expected      []byte
		expectedGas   uint64
		expectedError error
	}{
		{
			name: "valid groth16 bn254 proof (1 public input)",
			input: func() []byte {
				assignment := &onePublicInputCircuit{X: 1}
				ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &onePublicInputCircuit{})
				pk, vk, _ := groth16.Setup(ccs)
				witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
				witnessPublic, _ := witness.Public()

				proof, err := groth16.Prove(ccs, pk, witness)
				assert.Nil(t, err)

				err = groth16.Verify(proof, vk, witnessPublic)
				assert.Nil(t, err)

				proofBytes := bn254.SerializeProof(proof.(*groth16bn254.Proof))
				vkBytes := bn254.SerializeVerifyingKey(vk.(*groth16bn254.VerifyingKey))
				witnessBytes, _ := witnessPublic.MarshalBinary()

				return append(append(proofBytes, vkBytes...), witnessBytes[12:]...)
			}(),
			expected:    []byte{1},
			expectedGas: 246700,
		},
		{
			name: "valid groth16 bn254 proof (2 public inputs)",
			input: func() []byte {
				assignment := &twoPublicInputCircuit{X: 1, Y: 2}
				ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &twoPublicInputCircuit{})
				pk, vk, _ := groth16.Setup(ccs)
				witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
				witnessPublic, _ := witness.Public()

				proof, err := groth16.Prove(ccs, pk, witness)
				assert.Nil(t, err)

				err = groth16.Verify(proof, vk, witnessPublic)
				assert.Nil(t, err)

				proofBytes := bn254.SerializeProof(proof.(*groth16bn254.Proof))
				vkBytes := bn254.SerializeVerifyingKey(vk.(*groth16bn254.VerifyingKey))
				witnessBytes, _ := witnessPublic.MarshalBinary()

				return append(append(proofBytes, vkBytes...), witnessBytes[12:]...)
			}(),
			expected:    []byte{1},
			expectedGas: 273400,
		},
		{
			name: "invalid groth16 bn254 proof",
			input: func() []byte {
				assignment := &onePublicInputCircuit{X: 1}
				ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &onePublicInputCircuit{})
				pk, vk, _ := groth16.Setup(ccs)
				witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
				witnessPublic, _ := witness.Public()

				proof, err := groth16.Prove(ccs, pk, witness)
				assert.Nil(t, err)

				err = groth16.Verify(proof, vk, witnessPublic)
				assert.Nil(t, err)

				proofBytes := bn254.SerializeProof(proof.(*groth16bn254.Proof))
				proofBytes[len(proofBytes)-1] ^= 1
				vkBytes := bn254.SerializeVerifyingKey(vk.(*groth16bn254.VerifyingKey))
				vkBytes[len(vkBytes)-1] ^= 1
				witnessBytes, _ := witnessPublic.MarshalBinary()
				witnessBytes[len(witnessBytes)-1] ^= 1

				return append(append(proofBytes, vkBytes...), witnessBytes[12:]...)
			}(),
			expected:    []byte{0},
			expectedGas: 246700,
		},
		{
			name:          "not enough min length",
			input:         make([]byte, bn254.BN254Groth16ProofSize+bn254.BN254Groth16VerifyVerifyingKeySize-1),
			expectedError: ErrorGroth16VerifyInvalidInputLength,
			expectedGas:   0,
		},
		{
			name:          "remaining is not divisible by field size",
			input:         make([]byte, bn254.BN254Groth16ProofSize+bn254.BN254Groth16VerifyVerifyingKeySize+1),
			expectedError: ErrorGroth16VerifyInvalidInputLength,
			expectedGas:   0,
		},
		{
			name:          "zero public inputs",
			input:         make([]byte, bn254.BN254Groth16ProofSize+bn254.BN254Groth16VerifyVerifyingKeySize),
			expectedError: ErrorGroth16VerifyInvalidInputLength,
			expectedGas:   0,
		},
		{
			name: "max public inputs",
			input: func() []byte {
				fixedSize := bn254.BN254Groth16ProofSize + bn254.BN254Groth16VerifyVerifyingKeySize + bn254.BN254Groth16G1Size
				icSize := (Groth16MaxPublicInputs + 1) * bn254.BN254Groth16G1Size
				publicWitnessSize := (Groth16MaxPublicInputs + 1) * bn254.BN254Groth16FieldSize

				return make([]byte, fixedSize+icSize+publicWitnessSize)
			}(),
			expectedError: ErrorGroth16VerifyInvalidInputLength,
			expectedGas:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			precompile := NewGroth16BN254Verify()

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

	properties.Property("Run returns correct verification result", prop.ForAll(
		func(data *bn254.CircuitGeneratorStruct) bool {
			precompile := NewGroth16BN254Verify()

			ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, data.Circuit)
			pk, vk, _ := groth16.Setup(ccs)
			witness, _ := frontend.NewWitness(data.Assignment, ecc.BN254.ScalarField())
			witnessPublic, _ := witness.Public()

			proof, err := groth16.Prove(ccs, pk, witness)
			assert.Nil(t, err)

			err = groth16.Verify(proof, vk, witnessPublic)
			assert.Nil(t, err)

			proofBytes := bn254.SerializeProof(proof.(*groth16bn254.Proof))
			vkBytes := bn254.SerializeVerifyingKey(vk.(*groth16bn254.VerifyingKey))
			witnessBytes, _ := witnessPublic.MarshalBinary()

			input := append(append(proofBytes, vkBytes...), witnessBytes[12:]...)

			result, err := precompile.Run(input)

			if err != nil {
				return false
			}

			return bytes.Equal(result, []byte{1})
		},
		bn254.CircuitGenerator(),
	))

	properties.TestingRun(t)
}

func TestRequiredGasProperties(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	buildInputSize := func(numberOfPublicInputs int) int {
		fixedSize := bn254.BN254Groth16ProofSize +
			bn254.BN254Groth16VerifyVerifyingKeySize +
			bn254.BN254Groth16G1Size

		icSize := numberOfPublicInputs * bn254.BN254Groth16G1Size
		publicWitnessSize := numberOfPublicInputs * bn254.BN254Groth16FieldSize

		return fixedSize + icSize + publicWitnessSize
	}

	properties.Property("Run returns correct gas calculation result", prop.ForAll(
		func(numberOfPublicInputs int) bool {
			precompile := NewGroth16BN254Verify()

			gas1 := precompile.RequiredGas(make([]byte, buildInputSize(numberOfPublicInputs)))
			gas2 := precompile.RequiredGas(make([]byte, buildInputSize(numberOfPublicInputs)))

			return gas1 == gas2
		},
		gen.IntRange(1, Groth16MaxPublicInputs),
	))

	properties.Property("Gas increases with more public inputs", prop.ForAll(
		func(n1, n2 int) bool {
			if n1 > n2 {
				n1, n2 = n2, n1
			}

			precompile := NewGroth16BN254Verify()

			gas1 := precompile.RequiredGas(make([]byte, buildInputSize(n1)))
			gas2 := precompile.RequiredGas(make([]byte, buildInputSize(n2)))

			return gas2 >= gas1
		},
		gen.IntRange(1, Groth16MaxPublicInputs),
		gen.IntRange(1, Groth16MaxPublicInputs),
	))

	properties.TestingRun(t)
}
