package utils

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/stretchr/testify/assert"
)

func TestMarshalPoint(t *testing.T) {
	tests := []struct {
		name     string
		point    *babyjub.Point
		expected []byte
	}{
		{
			"normal marshal",
			&babyjub.Point{X: big.NewInt(0), Y: big.NewInt(1)},
			func() []byte {
				bytes := make([]byte, BabyJubJubCurveAffinePointSize)
				bytes[BabyJubJubCurveAffinePointSize-1] = 1

				return bytes
			}(),
		},
		{
			"zero point",
			&babyjub.Point{X: big.NewInt(0), Y: big.NewInt(0)},
			func() []byte {
				return make([]byte, BabyJubJubCurveAffinePointSize)
			}(),
		},
		{
			"max field values",
			&babyjub.Point{
				X: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 252), big.NewInt(1)),
				Y: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 252), big.NewInt(1)),
			},
			func() []byte {
				bytes := make([]byte, BabyJubJubCurveAffinePointSize)
				max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 252), big.NewInt(1))

				yBytes := max.FillBytes(make([]byte, BabyJubJubCurveFieldByteSize))
				copy(bytes[BabyJubJubCurveFieldByteSize:], yBytes)

				xBytes := max.FillBytes(make([]byte, BabyJubJubCurveFieldByteSize))
				copy(bytes[:BabyJubJubCurveFieldByteSize], xBytes)

				return bytes
			}(),
		},
		{
			"small non-zero values",
			&babyjub.Point{X: big.NewInt(5), Y: big.NewInt(10)},
			func() []byte {
				bytes := make([]byte, BabyJubJubCurveAffinePointSize)

				copy(bytes[BabyJubJubCurveFieldByteSize-1:BabyJubJubCurveFieldByteSize], big.NewInt(5).Bytes())
				copy(bytes[BabyJubJubCurveAffinePointSize-1:BabyJubJubCurveAffinePointSize], big.NewInt(10).Bytes())

				return bytes
			}(),
		},
		{
			"both small X and Y",
			&babyjub.Point{X: big.NewInt(1), Y: big.NewInt(1)},
			func() []byte {
				bytes := make([]byte, BabyJubJubCurveAffinePointSize)

				bytes[BabyJubJubCurveFieldByteSize-1] = 1
				bytes[BabyJubJubCurveAffinePointSize-1] = 1

				return bytes
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := MarshalPoint(tt.point)

			assert.Equal(t, true, bytes.Equal(actual, tt.expected))
		})

		t.Run(tt.name, func(t *testing.T) {
			actual, err := UnmarshalPoint(tt.expected)

			assert.Nil(t, err)
			assert.Equal(t, true, actual.X.Cmp(tt.point.X) == 0 && actual.Y.Cmp(tt.point.Y) == 0)
		})
	}
}

func TestUnmarshalPointInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty slice", []byte{}},
		{"too short", make([]byte, BabyJubJubCurveAffinePointSize-1)},
		{"too long", make([]byte, BabyJubJubCurveAffinePointSize+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalPoint(tt.data)

			assert.NotNil(t, err)
		})
	}
}

func TestMarshalProperties(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("Marshal and Unmarshal are inverse operations", prop.ForAll(
		func(data []byte) bool {
			point, err := UnmarshalPoint(data)
			actual := MarshalPoint(point)

			if err != nil {
				return false
			}

			return bytes.Equal(actual, data)
		},
		gen.SliceOfN(BabyJubJubCurveAffinePointSize, gen.UInt8()),
	))

	properties.TestingRun(t)
}

func TestReadField(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		offset         int
		expectedData   *big.Int
		expectedOffset int
		expectNil      bool
	}{
		{
			name:           "normal read zero",
			data:           make([]byte, BabyJubJubCurveFieldByteSize),
			offset:         0,
			expectedData:   big.NewInt(0),
			expectedOffset: BabyJubJubCurveFieldByteSize,
			expectNil:      false,
		},
		{
			name:           "normal read small number",
			data:           append(make([]byte, BabyJubJubCurveFieldByteSize-1), 5),
			offset:         0,
			expectedData:   big.NewInt(5),
			expectedOffset: BabyJubJubCurveFieldByteSize,
			expectNil:      false,
		},
		{
			name: "offset in the middle of longer slice",
			data: append(make([]byte, 10), func() []byte {
				bytes := make([]byte, BabyJubJubCurveFieldByteSize)
				bytes[BabyJubJubCurveFieldByteSize-1] = 1

				return bytes
			}()...),
			offset:         10,
			expectedData:   big.NewInt(1),
			expectedOffset: 10 + BabyJubJubCurveFieldByteSize,
			expectNil:      false,
		},

		{
			name:      "slice too short",
			data:      make([]byte, BabyJubJubCurveFieldByteSize-1),
			offset:    0,
			expectNil: true,
		},
		{
			name:      "offset negative",
			data:      make([]byte, BabyJubJubCurveFieldByteSize),
			offset:    -1,
			expectNil: true,
		},
		{
			name:      "offset beyond slice length",
			data:      make([]byte, BabyJubJubCurveFieldByteSize),
			offset:    BabyJubJubCurveFieldByteSize + 1,
			expectNil: true,
		},
		{
			name:           "large number",
			data:           append(make([]byte, BabyJubJubCurveFieldByteSize-1), 0xFF),
			offset:         0,
			expectedData:   big.NewInt(0xFF),
			expectedOffset: BabyJubJubCurveFieldByteSize,
			expectNil:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, offset := ReadField(tt.data, tt.offset)

			if tt.expectNil {
				assert.Nil(t, actual)

				return
			}

			assert.NotNil(t, actual)
			assert.Equal(t, true, new(big.Int).SetBytes(tt.data).Cmp(tt.expectedData) == 0 && offset == tt.expectedOffset)
		})
	}
}

func TestReadFieldProperties(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("ReadField returns correct value and offset", prop.ForAll(
		func(data []byte, offset int) bool {
			// Skip offsets that are invalid
			if offset < 0 || offset > len(data) {
				return true
			}

			actual, newOffset := ReadField(data, offset)

			if len(data)-offset < BabyJubJubCurveFieldByteSize {
				return actual == nil
			}

			expected := new(big.Int).SetBytes(data[offset : offset+BabyJubJubCurveFieldByteSize])

			if actual == nil || actual.Cmp(expected) != 0 || newOffset != offset+BabyJubJubCurveFieldByteSize {
				return false
			}

			return true
		},
		gen.SliceOfN(BabyJubJubCurveFieldByteSize*10, gen.UInt8()),
		gen.IntRange(0, 9),
	))

	properties.TestingRun(t)
}

func TestReadAffinePoint(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		index     int
		expected  *babyjub.Point
		expectErr bool
	}{
		{
			name:      "normal read zero",
			data:      make([]byte, BabyJubJubCurveAffinePointSize),
			index:     0,
			expected:  &babyjub.Point{X: big.NewInt(0), Y: big.NewInt(0)},
			expectErr: false,
		},
		{
			name: "non-zero X and Y",
			data: func() []byte {
				bytes := make([]byte, BabyJubJubCurveAffinePointSize)
				bytes[BabyJubJubCurveFieldByteSize-1] = 5
				bytes[BabyJubJubCurveAffinePointSize-1] = 10

				return bytes
			}(),
			index: 0,
			expected: &babyjub.Point{
				X: big.NewInt(5),
				Y: big.NewInt(10),
			},
			expectErr: false,
		},
		{
			name: "second point in slice",
			data: func() []byte {
				bytes := make([]byte, 2*BabyJubJubCurveAffinePointSize)
				bytes[BabyJubJubCurveAffinePointSize+BabyJubJubCurveFieldByteSize+BabyJubJubCurveFieldByteSize-1] = 1

				return bytes
			}(),
			index: 1,
			expected: &babyjub.Point{
				X: big.NewInt(0),
				Y: big.NewInt(1),
			},
			expectErr: false,
		},
		{
			name:      "negative index",
			data:      make([]byte, BabyJubJubCurveAffinePointSize),
			index:     -1,
			expectErr: true,
		},
		{
			name:      "slice too short",
			data:      make([]byte, BabyJubJubCurveAffinePointSize-1),
			index:     0,
			expectErr: true,
		},
		{
			name:      "index beyond slice",
			data:      make([]byte, BabyJubJubCurveAffinePointSize),
			index:     1,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := ReadAffinePoint(tt.data, tt.index)

			if tt.expectErr {
				assert.NotNil(t, err)

				return
			}

			assert.Nil(t, err)
			assert.Equal(t, true, actual.X.Cmp(tt.expected.X) == 0 && actual.Y.Cmp(tt.expected.Y) == 0)
		})
	}
}

func TestGeneratePoint(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("Generated points are valid subgroup points", prop.ForAll(
		func(p *babyjub.Point) bool {
			return p != nil && p.InSubGroup() && p.InCurve()
		},
		BabyJubJubPointGenerator(),
	))

	properties.TestingRun(t)
}

func TestGenerateScalar(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("Generated scalar are valid", prop.ForAll(
		func(scalar *big.Int) bool {
			return scalar != nil && scalar.Cmp(babyjub.SubOrder) < 0
		},
		ScalarGenerator(),
	))

	properties.TestingRun(t)
}
