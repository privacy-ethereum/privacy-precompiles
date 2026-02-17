package utils

import (
	"bytes"
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
