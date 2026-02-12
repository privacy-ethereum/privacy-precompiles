package utils

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
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
				bytes := make([]byte, BabyJubJubAffinePointSize)
				bytes[BabyJubJubAffinePointSize-1] = 1

				return bytes
			}(),
		},
		{
			"zero point",
			&babyjub.Point{X: big.NewInt(0), Y: big.NewInt(0)},
			func() []byte {
				return make([]byte, BabyJubJubAffinePointSize)
			}(),
		},
		{
			"max field values",
			&babyjub.Point{
				X: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 252), big.NewInt(1)),
				Y: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 252), big.NewInt(1)),
			},
			func() []byte {
				bytes := make([]byte, BabyJubJubAffinePointSize)
				max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 252), big.NewInt(1))

				yBytes := max.FillBytes(make([]byte, BabyJubJubFieldByteSize))
				copy(bytes[BabyJubJubFieldByteSize:], yBytes)

				xBytes := max.FillBytes(make([]byte, BabyJubJubFieldByteSize))
				copy(bytes[:BabyJubJubFieldByteSize], xBytes)

				return bytes
			}(),
		},
		{
			"small non-zero values",
			&babyjub.Point{X: big.NewInt(5), Y: big.NewInt(10)},
			func() []byte {
				bytes := make([]byte, BabyJubJubAffinePointSize)

				copy(bytes[BabyJubJubFieldByteSize-1:BabyJubJubFieldByteSize], big.NewInt(5).Bytes())
				copy(bytes[BabyJubJubAffinePointSize-1:BabyJubJubAffinePointSize], big.NewInt(10).Bytes())

				return bytes
			}(),
		},
		{
			"both small X and Y",
			&babyjub.Point{X: big.NewInt(1), Y: big.NewInt(1)},
			func() []byte {
				bytes := make([]byte, BabyJubJubAffinePointSize)

				bytes[BabyJubJubFieldByteSize-1] = 1
				bytes[BabyJubJubAffinePointSize-1] = 1

				return bytes
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := MarshalPoint(tt.point)

			if !bytes.Equal(actual, tt.expected) {
				t.Errorf("MarshalPoint(%v) = %v; expected %v",
					tt.point, actual, tt.expected)
			}
		})

		t.Run(tt.name, func(t *testing.T) {
			actual, err := UnmarshalPoint(tt.expected)

			if err != nil {
				t.Errorf("UnmarshalPoint error: %v", err)
			}

			if actual.X.Cmp(tt.point.X) != 0 || actual.Y.Cmp(tt.point.Y) != 0 {
				t.Errorf("UnmarshalPoint(%v) = %v; expected %v",
					tt.expected, actual, tt.point)
			}
		})
	}
}

func TestUnmarshalPointInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty slice", []byte{}},
		{"too short", make([]byte, BabyJubJubAffinePointSize-1)},
		{"too long", make([]byte, BabyJubJubAffinePointSize+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			point, err := UnmarshalPoint(tt.data)

			if err == nil {
				t.Errorf("UnmarshalPoint(%v) = %v; expected error", tt.data, point)
			}
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
		gen.SliceOfN(BabyJubJubAffinePointSize, gen.UInt8()),
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
			data:           make([]byte, BabyJubJubFieldByteSize),
			offset:         0,
			expectedData:   big.NewInt(0),
			expectedOffset: BabyJubJubFieldByteSize,
			expectNil:      false,
		},
		{
			name:           "normal read small number",
			data:           append(make([]byte, BabyJubJubFieldByteSize-1), 5),
			offset:         0,
			expectedData:   big.NewInt(5),
			expectedOffset: BabyJubJubFieldByteSize,
			expectNil:      false,
		},
		{
			name: "offset in the middle of longer slice",
			data: append(make([]byte, 10), func() []byte {
				bytes := make([]byte, BabyJubJubFieldByteSize)
				bytes[BabyJubJubFieldByteSize-1] = 1

				return bytes
			}()...),
			offset:         10,
			expectedData:   big.NewInt(1),
			expectedOffset: 10 + BabyJubJubFieldByteSize,
			expectNil:      false,
		},

		{
			name:      "slice too short",
			data:      make([]byte, BabyJubJubFieldByteSize-1),
			offset:    0,
			expectNil: true,
		},
		{
			name:      "offset negative",
			data:      make([]byte, BabyJubJubFieldByteSize),
			offset:    -1,
			expectNil: true,
		},
		{
			name:      "offset beyond slice length",
			data:      make([]byte, BabyJubJubFieldByteSize),
			offset:    BabyJubJubFieldByteSize + 1,
			expectNil: true,
		},
		{
			name:           "large number",
			data:           append(make([]byte, BabyJubJubFieldByteSize-1), 0xFF),
			offset:         0,
			expectedData:   big.NewInt(0xFF),
			expectedOffset: BabyJubJubFieldByteSize,
			expectNil:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, offset := ReadField(tt.data, tt.offset)

			if tt.expectNil {
				if actual != nil {
					t.Errorf("ReadField(%v, %d) = %v; expected nil", tt.data, tt.offset, actual)
				}

				return
			}

			if actual == nil {
				t.Errorf("ReadField(%v, %d); expected %v",
					tt.data, tt.offset, tt.expectedData)
			}

			bytes := new(big.Int).SetBytes(tt.data)

			if bytes.Cmp(tt.expectedData) != 0 || offset != tt.expectedOffset {
				t.Errorf(
					"ReadField(%v, %d) = (%v, %d); expected (%v, %d)",
					tt.data,
					tt.offset,
					actual,
					offset,
					tt.expectedData,
					tt.expectedOffset,
				)
			}

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

			if len(data)-offset < BabyJubJubFieldByteSize {
				return actual == nil
			}

			expected := new(big.Int).SetBytes(data[offset : offset+BabyJubJubFieldByteSize])

			if actual == nil || actual.Cmp(expected) != 0 || newOffset != offset+BabyJubJubFieldByteSize {
				return false
			}

			return true
		},
		gen.SliceOfN(BabyJubJubFieldByteSize*10, gen.UInt8()),
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
			data:      make([]byte, BabyJubJubAffinePointSize),
			index:     0,
			expected:  &babyjub.Point{X: big.NewInt(0), Y: big.NewInt(0)},
			expectErr: false,
		},
		{
			name: "non-zero X and Y",
			data: func() []byte {
				bytes := make([]byte, BabyJubJubAffinePointSize)
				bytes[BabyJubJubFieldByteSize-1] = 5
				bytes[BabyJubJubAffinePointSize-1] = 10

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
				bytes := make([]byte, 2*BabyJubJubAffinePointSize)
				bytes[BabyJubJubAffinePointSize+BabyJubJubFieldByteSize+BabyJubJubFieldByteSize-1] = 1

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
			data:      make([]byte, BabyJubJubAffinePointSize),
			index:     -1,
			expectErr: true,
		},
		{
			name:      "slice too short",
			data:      make([]byte, BabyJubJubAffinePointSize-1),
			index:     0,
			expectErr: true,
		},
		{
			name:      "index beyond slice",
			data:      make([]byte, BabyJubJubAffinePointSize),
			index:     1,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := ReadAffinePoint(tt.data, tt.index)

			if tt.expectErr {
				if err == nil {
					t.Errorf("ReadAffinePoint(%v, %d); expected error but got %v", tt.data, tt.index, actual)
				}

				return
			}

			if err != nil {
				t.Errorf("ReadAffinePoint(%v, %d); expected %v",
					tt.data, tt.index, tt.expected)
			}

			if actual.X.Cmp(tt.expected.X) != 0 || actual.Y.Cmp(tt.expected.Y) != 0 {
				t.Errorf(
					"ReadAffinePoint(%v, %d) = %v; expected %v",
					tt.data,
					tt.index,
					actual,
					tt.expected,
				)
			}

		})
	}
}
