package utils

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/stretchr/testify/assert"
)

func TestSafeSlice(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		start    int
		end      int
		expected []byte
		isValid  bool
	}{
		{"normal slice", []byte{1, 2, 3, 4, 5}, 1, 3, []byte{2, 3}, true},
		{"start = 0", []byte{1, 2, 3}, 0, 2, []byte{1, 2}, true},
		{"end = len(data)", []byte{1, 2, 3}, 1, 3, []byte{2, 3}, true},
		{"start = end", []byte{1, 2, 3}, 2, 2, []byte{}, true},
		{"start < 0", []byte{1, 2, 3}, -1, 2, nil, false},
		{"end < 0", []byte{1, 2, 3}, 0, -1, nil, false},
		{"start > end", []byte{1, 2, 3}, 2, 1, nil, false},
		{"end > len(data)", []byte{1, 2, 3}, 1, 5, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, ok := SafeSlice(tt.data, tt.start, tt.end)

			assert.Equal(t, tt.isValid, ok)
			assert.Equal(t, true, bytes.Equal(actual, tt.expected))
		})
	}
}

func TestSafeSliceProperties(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	properties := gopter.NewProperties(parameters)

	properties.Property("SafeSlice never panics and output length is correct", prop.ForAll(
		func(data []byte, start, end int) bool {
			slice, ok := SafeSlice(data, start, end)

			if !ok {
				return slice == nil
			}

			return len(slice) == end-start
		},
		gen.SliceOf(gen.UInt8()),
		gen.IntRange(-1000000, 1000000),
		gen.IntRange(-1000000, 1000000),
	))

	properties.TestingRun(t)
}

const (
	fieldByteSize = 32
)

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
			data:           make([]byte, fieldByteSize),
			offset:         0,
			expectedData:   big.NewInt(0),
			expectedOffset: fieldByteSize,
			expectNil:      false,
		},
		{
			name:           "normal read small number",
			data:           append(make([]byte, fieldByteSize-1), 5),
			offset:         0,
			expectedData:   big.NewInt(5),
			expectedOffset: fieldByteSize,
			expectNil:      false,
		},
		{
			name: "offset in the middle of longer slice",
			data: append(make([]byte, 10), func() []byte {
				bytes := make([]byte, fieldByteSize)
				bytes[fieldByteSize-1] = 1

				return bytes
			}()...),
			offset:         10,
			expectedData:   big.NewInt(1),
			expectedOffset: 10 + fieldByteSize,
			expectNil:      false,
		},

		{
			name:      "slice too short",
			data:      make([]byte, fieldByteSize-1),
			offset:    0,
			expectNil: true,
		},
		{
			name:      "offset negative",
			data:      make([]byte, fieldByteSize),
			offset:    -1,
			expectNil: true,
		},
		{
			name:      "offset beyond slice length",
			data:      make([]byte, fieldByteSize),
			offset:    fieldByteSize + 1,
			expectNil: true,
		},
		{
			name:           "large number",
			data:           append(make([]byte, fieldByteSize-1), 0xFF),
			offset:         0,
			expectedData:   big.NewInt(0xFF),
			expectedOffset: fieldByteSize,
			expectNil:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, offset := ReadField(tt.data, tt.offset, fieldByteSize)

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

			actual, newOffset := ReadField(data, offset, fieldByteSize)

			if len(data)-offset < fieldByteSize {
				return actual == nil
			}

			expected := new(big.Int).SetBytes(data[offset : offset+fieldByteSize])

			if actual == nil || actual.Cmp(expected) != 0 || newOffset != offset+fieldByteSize {
				return false
			}

			return true
		},
		gen.SliceOfN(fieldByteSize*10, gen.UInt8()),
		gen.IntRange(0, 9),
	))

	properties.TestingRun(t)
}
